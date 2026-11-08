"""Per-execution Linux network namespace with a default-deny egress allowlist.

This is the privileged plumbing behind ``LinuxNamespaceEgressEnforcer``. It is
isolated here so that the only component needing elevated capability is small,
auditable and swappable:

* :class:`DirectNetnsProvisioner` runs ``ip``/``nft`` itself and therefore needs
  ``CAP_NET_ADMIN`` (in practice, root). Suitable for a dedicated scan host.
* :class:`HelperNetnsProvisioner` delegates the four privileged operations to an
  external helper executable over a **narrow, typed** request, so the
  application process itself stays unprivileged. See
  ``scripts/gryphon_egress_helper.py``.

What the namespace guarantees, and why it is shaped this way:

* ``policy drop`` on the ``output`` hook — the default is to send nothing.
* Exactly the addresses the gateway already resolved and pinned are accepted,
  restricted to the ports the tool declared (or every port, for tools such as
  ``naabu`` that legitimately scan the port range).
* **DNS is deliberately not accepted.** The gateway resolves before the intent
  record commits and hands the tool literals; a tool that re-resolves — the
  descriptors say six of seven do — hits ``policy drop``. That is what makes DNS
  rebinding unreachable rather than merely checked.
* Raw packets are contained too: nftables' ``output`` hook filters
  locally-generated traffic, including the SYN packets ``naabu`` builds itself.
  This is why an HTTP/SOCKS proxy is not an acceptable substitute.
* **IPv6 destinations are not accepted.** The namespace is IPv4-only, so an
  IPv6 address in the pinned set is simply never allowlisted and is dropped by
  the default policy. If the pinned set contains *no* IPv4 address, setup fails
  closed rather than establishing a context that can reach nothing.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from gryphon.logging_config import get_logger
from gryphon.tooling.reasons import EgressUnavailableError

logger = get_logger(__name__)

#: Every namespace this layer creates carries this prefix, so a crash can be
#: reaped unambiguously without touching namespaces owned by anything else.
NETNS_PREFIX = "gryphon-"
#: Private pool carved into /30 point-to-point links, one per live execution.
POOL_CIDR = "10.77.0.0/16"
#: nftables table names (inside the namespace, and on the host for NAT).
NFT_TABLE = "gryphon"
NAT_TABLE = "gryphon_nat"
#: Named nftables counters inside the namespace (observable containment).
COUNTER_ALLOWED = "allowed"
COUNTER_DROPPED = "dropped"
#: Bound on every privileged command; setup must not hang an execution.
COMMAND_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class NamespacePlan:
    """The addressing plan for one execution's namespace."""

    namespace: str
    host_interface: str
    peer_interface: str
    host_address: str
    namespace_address: str
    prefix_length: int
    index: int

    @property
    def argv_prefix(self) -> tuple[str, ...]:
        return ("ip", "netns", "exec", self.namespace)


def plan_for(index: int, namespace: str) -> NamespacePlan:
    """Derive a /30 point-to-point plan for ``index`` within :data:`POOL_CIDR`."""
    pool = ipaddress.ip_network(POOL_CIDR)
    block = ipaddress.ip_network((int(pool.network_address) + index * 4, 30))
    hosts = list(block.hosts())
    return NamespacePlan(
        namespace=namespace,
        # Interface names are capped at 15 characters by the kernel.
        host_interface=f"gryv{index}",
        peer_interface=f"gryp{index}",
        host_address=str(hosts[0]),
        namespace_address=str(hosts[1]),
        prefix_length=30,
        index=index,
    )


class AddressPool:
    """Hands out distinct /30 indices and reclaims them on teardown."""

    def __init__(self, capacity: int = 4096) -> None:
        self._free = list(range(1, capacity + 1))
        self._lock = asyncio.Lock()

    async def acquire(self) -> int:
        async with self._lock:
            if not self._free:
                raise EgressUnavailableError("no free egress address block")
            return self._free.pop(0)

    async def release(self, index: int) -> None:
        async with self._lock:
            if index not in self._free:
                self._free.append(index)


# -----------------------------------------------------------------------------
# Rule rendering
# -----------------------------------------------------------------------------
def split_allowlist(allowlist: Sequence[str]) -> tuple[list[str], list[str]]:
    """Partition the pinned addresses into (IPv4, non-IPv4)."""
    v4: list[str] = []
    other: list[str] = []
    for entry in allowlist:
        try:
            address = ipaddress.ip_address(entry)
        except ValueError:
            other.append(entry)
            continue
        (v4 if address.version == 4 else other).append(entry)
    return v4, other


def render_namespace_ruleset(allowlist_v4: Sequence[str], ports: Sequence[int]) -> str:
    """Render the default-deny egress ruleset applied inside the namespace.

    Every value is re-parsed here rather than trusted: this text becomes an
    nftables program, so an unvalidated string would be rule injection. Both the
    in-process path and the privileged helper render through this function.
    """
    if not allowlist_v4:
        raise EgressUnavailableError("no IPv4 destination to allowlist; refusing to establish")
    try:
        addresses = ", ".join(
            sorted({str(ipaddress.IPv4Address(entry)) for entry in allowlist_v4})
        )
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise EgressUnavailableError("egress allowlist must contain IPv4 literals only") from exc
    try:
        checked_ports = sorted({int(p) for p in ports})
    except (TypeError, ValueError) as exc:
        raise EgressUnavailableError("egress ports must be integers") from exc
    if any(p < 1 or p > 65535 for p in checked_ports):
        raise EgressUnavailableError("egress ports must be within 1-65535")
    if checked_ports:
        port_set = ", ".join(str(p) for p in checked_ports)
        accept = (
            f"    ip daddr {{ {addresses} }} tcp dport {{ {port_set} }} "
            f"counter name \"{COUNTER_ALLOWED}\" accept\n"
            f"    ip daddr {{ {addresses} }} udp dport {{ {port_set} }} "
            f"counter name \"{COUNTER_ALLOWED}\" accept\n"
        )
    else:
        # Tools that legitimately sweep ports (naabu) are contained by
        # destination, not by port.
        accept = (
            f"    ip daddr {{ {addresses} }} counter name \"{COUNTER_ALLOWED}\" accept\n"
        )
    # Named counters make containment observable: `dropped` rising means a tool
    # tried to reach something outside its pinned destination set.
    return (
        f"add table inet {NFT_TABLE}\n"
        f"flush table inet {NFT_TABLE}\n"
        f"table inet {NFT_TABLE} {{\n"
        f"  counter {COUNTER_ALLOWED} {{ }}\n"
        f"  counter {COUNTER_DROPPED} {{ }}\n"
        f"  chain output {{\n"
        f"    type filter hook output priority filter; policy drop;\n"
        f"    oifname \"lo\" accept\n"
        f"    ct state established,related accept\n"
        f"{accept}"
        f"    counter name \"{COUNTER_DROPPED}\" drop\n"
        f"  }}\n"
        f"}}\n"
    )


def counters_command(plan: NamespacePlan) -> Command:
    """Read the namespace's table back as JSON (counters included)."""
    return (
        [
            "ip", "netns", "exec", plan.namespace,
            "nft", "-j", "list", "table", "inet", NFT_TABLE,
        ],
        None,
    )


def parse_counters(raw: str) -> dict[str, int]:
    """Extract ``{counter name: packets}`` from ``nft -j list table`` output."""
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    counters: dict[str, int] = {}
    for item in document.get("nftables", []):
        counter = item.get("counter") if isinstance(item, dict) else None
        if isinstance(counter, dict) and "name" in counter:
            counters[str(counter["name"])] = int(counter.get("packets", 0))
    return counters


def render_nat_ruleset() -> str:
    """Render the host-side masquerade for the pool (idempotent to re-apply)."""
    return (
        f"add table ip {NAT_TABLE}\n"
        f"flush table ip {NAT_TABLE}\n"
        f"table ip {NAT_TABLE} {{\n"
        f"  chain postrouting {{\n"
        f"    type nat hook postrouting priority srcnat; policy accept;\n"
        f"    ip saddr {POOL_CIDR} counter masquerade\n"
        f"  }}\n"
        f"}}\n"
    )


# -----------------------------------------------------------------------------
# Command sequences
# -----------------------------------------------------------------------------
Command = tuple[list[str], str | None]  # (argv, stdin)


def setup_commands(
    plan: NamespacePlan, allowlist_v4: Sequence[str], ports: Sequence[int]
) -> list[Command]:
    ns, host_if, peer_if = plan.namespace, plan.host_interface, plan.peer_interface
    cidr = f"/{plan.prefix_length}"
    return [
        (["ip", "netns", "add", ns], None),
        (["ip", "link", "add", host_if, "type", "veth", "peer", "name", peer_if], None),
        (["ip", "link", "set", peer_if, "netns", ns], None),
        (["ip", "addr", "add", plan.host_address + cidr, "dev", host_if], None),
        (["ip", "link", "set", host_if, "up"], None),
        (["ip", "-n", ns, "addr", "add", plan.namespace_address + cidr, "dev", peer_if], None),
        (["ip", "-n", ns, "link", "set", peer_if, "up"], None),
        (["ip", "-n", ns, "link", "set", "lo", "up"], None),
        (["ip", "-n", ns, "route", "add", "default", "via", plan.host_address], None),
        (
            ["ip", "netns", "exec", ns, "nft", "-f", "-"],
            render_namespace_ruleset(allowlist_v4, ports),
        ),
    ]


def verify_commands(plan: NamespacePlan) -> list[Command]:
    """Read the ruleset back; a context whose policy is not drop is unusable."""
    return [(["ip", "netns", "exec", plan.namespace, "nft", "list", "table", "inet", NFT_TABLE], None)]


def teardown_commands(plan: NamespacePlan) -> list[Command]:
    # Deleting the namespace takes the peer interface and its rules with it; the
    # host-side veth is removed explicitly in case the namespace is already gone.
    return [
        (["ip", "netns", "delete", plan.namespace], None),
        (["ip", "link", "delete", plan.host_interface], None),
    ]


# -----------------------------------------------------------------------------
# Privileged execution
# -----------------------------------------------------------------------------
class PrivilegedRunner(Protocol):
    async def run(self, argv: Sequence[str], *, stdin: str | None = None) -> str: ...


class RootCommandRunner:
    """Runs ``ip``/``nft`` directly; requires CAP_NET_ADMIN (in practice root)."""

    async def run(self, argv: Sequence[str], *, stdin: str | None = None) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if stdin else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise EgressUnavailableError(f"cannot execute {argv[0]}: {exc}") from exc
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(stdin.encode() if stdin else None),
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            proc.kill()
            raise EgressUnavailableError(f"{argv[0]} timed out") from exc
        if proc.returncode != 0:
            detail = err.decode(errors="replace").strip() or f"exit {proc.returncode}"
            raise EgressUnavailableError(f"{' '.join(argv[:3])}: {detail}")
        return out.decode(errors="replace")


class NetnsProvisioner(Protocol):
    async def prepare_host(self) -> None: ...
    async def setup(
        self, plan: NamespacePlan, allowlist_v4: Sequence[str], ports: Sequence[int]
    ) -> None: ...
    async def teardown(self, plan: NamespacePlan) -> None: ...
    async def list_namespaces(self) -> list[str]: ...
    async def counters(self, plan: NamespacePlan) -> dict[str, int]: ...


class DirectNetnsProvisioner:
    """Programs namespaces in-process. Needs CAP_NET_ADMIN."""

    def __init__(self, runner: PrivilegedRunner | None = None) -> None:
        self._runner = runner or RootCommandRunner()
        self._host_prepared = False
        self._prepare_lock = asyncio.Lock()

    async def prepare_host(self) -> None:
        async with self._prepare_lock:
            if self._host_prepared:
                return
            await self._runner.run(["nft", "-f", "-"], stdin=render_nat_ruleset())
            self._host_prepared = True

    async def setup(
        self, plan: NamespacePlan, allowlist_v4: Sequence[str], ports: Sequence[int]
    ) -> None:
        for argv, stdin in setup_commands(plan, allowlist_v4, ports):
            await self._runner.run(argv, stdin=stdin)
        for argv, stdin in verify_commands(plan):
            rendered = await self._runner.run(argv, stdin=stdin)
            if "policy drop" not in rendered:
                raise EgressUnavailableError("egress ruleset did not load with a drop policy")

    async def teardown(self, plan: NamespacePlan) -> None:
        for argv, stdin in teardown_commands(plan):
            try:
                await self._runner.run(argv, stdin=stdin)
            except EgressUnavailableError:
                # Teardown is best-effort and idempotent: a missing object means
                # the work is already done. Leaks are swept by reap_stale().
                continue

    async def counters(self, plan: NamespacePlan) -> dict[str, int]:
        argv, stdin = counters_command(plan)
        return parse_counters(await self._runner.run(argv, stdin=stdin))

    async def list_namespaces(self) -> list[str]:
        raw = await self._runner.run(["ip", "-json", "netns", "list"])
        try:
            entries = json.loads(raw or "[]")
        except json.JSONDecodeError:
            return [line.split()[0] for line in raw.splitlines() if line.strip()]
        return [e.get("name", "") for e in entries if isinstance(e, dict)]


class HelperNetnsProvisioner:
    """Delegates the privileged operations to a narrow external helper.

    The helper receives one JSON request per operation on stdin and is the only
    component that needs elevated capability. Request shapes:

    ``{"op": "prepare_host"}``
    ``{"op": "setup", "plan": {...}, "allowlist": [...], "ports": [...]}``
    ``{"op": "teardown", "plan": {...}}``
    ``{"op": "list"}`` → ``{"namespaces": [...]}``
    """

    def __init__(self, helper_path: str, runner: PrivilegedRunner | None = None) -> None:
        self._helper = helper_path
        self._runner = runner or RootCommandRunner()

    async def _call(self, payload: dict) -> dict:
        raw = await self._runner.run([self._helper], stdin=json.dumps(payload))
        try:
            response = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise EgressUnavailableError("egress helper returned malformed JSON") from exc
        if not response.get("ok", False):
            raise EgressUnavailableError(f"egress helper: {response.get('error', 'failed')}")
        return response

    async def prepare_host(self) -> None:
        await self._call({"op": "prepare_host"})

    async def setup(
        self, plan: NamespacePlan, allowlist_v4: Sequence[str], ports: Sequence[int]
    ) -> None:
        await self._call(
            {
                "op": "setup",
                "plan": plan.__dict__,
                "allowlist": list(allowlist_v4),
                "ports": list(ports),
            }
        )

    async def teardown(self, plan: NamespacePlan) -> None:
        try:
            await self._call({"op": "teardown", "plan": plan.__dict__})
        except EgressUnavailableError:
            return

    async def counters(self, plan: NamespacePlan) -> dict[str, int]:
        response = await self._call({"op": "counters", "plan": plan.__dict__})
        return {str(k): int(v) for k, v in (response.get("counters") or {}).items()}

    async def list_namespaces(self) -> list[str]:
        response = await self._call({"op": "list"})
        return list(response.get("namespaces", []))


async def reap_stale_namespaces(provisioner: NetnsProvisioner) -> list[str]:
    """Delete namespaces left behind by a crash. Safe to run at startup."""
    try:
        names = await provisioner.list_namespaces()
    except EgressUnavailableError:
        return []
    reaped: list[str] = []
    for name in names:
        if not name.startswith(NETNS_PREFIX):
            continue
        # The index cannot be recovered from the name, and does not need to be:
        # deleting the namespace plus its host-side veth is all that is required.
        await provisioner.teardown(
            NamespacePlan(
                namespace=name,
                host_interface="",
                peer_interface="",
                host_address="",
                namespace_address="",
                prefix_length=30,
                index=-1,
            )
        )
        reaped.append(name)
    if reaped:
        logger.warning("egress_namespaces_reaped", count=len(reaped))
    return reaped


def tooling_available() -> bool:
    """True when both privileged CLIs this module drives are present."""
    return shutil.which("ip") is not None and shutil.which("nft") is not None
