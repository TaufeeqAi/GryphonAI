"""Containment proofs for the per-execution egress namespace.

The rule-rendering, addressing, fail-closed and privileged-helper-validation
tests run anywhere. The real containment proofs require Linux with
``CAP_NET_ADMIN`` and are skipped otherwise.

**No external host is ever contacted.** The deny path is proven by the
namespace's own nftables ``dropped`` counter — the packet dies in the kernel, so
nothing leaves the machine. The allow path is proven against a listener on the
host side of the execution's own veth pair.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import socket
import subprocess
import sys

import pytest

from gryphon.tooling.destination import netns as N
from gryphon.tooling.destination.egress import (
    EgressHandle,
    LinuxNamespaceEgressEnforcer,
    NullEgressEnforcer,
)
from gryphon.tooling.reasons import EgressUnavailableError

pytestmark = pytest.mark.security

_LINUX_ROOT = (
    platform.system() == "Linux"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
    and N.tooling_available()
)
requires_netns = pytest.mark.skipif(
    not _LINUX_ROOT, reason="needs Linux with CAP_NET_ADMIN and the ip/nft binaries"
)

#: Reserved documentation addresses. Allowlisted or not, no host exists there;
#: the dropped one never leaves the kernel.
PINNED = "203.0.113.9"
NOT_PINNED = "198.51.100.9"


# =============================================================================
# Rule rendering — the text that becomes the kernel's policy
# =============================================================================
def test_default_policy_is_drop_and_dns_is_not_allowlisted() -> None:
    ruleset = N.render_namespace_ruleset([PINNED], [80, 443])
    assert "policy drop" in ruleset
    assert PINNED in ruleset
    # 53 must not appear: the gateway pins addresses, so a tool that re-resolves
    # is meant to hit the drop rule.
    assert "53" not in ruleset.replace("203.0.113.9", "")
    assert ruleset.count("counter name \"dropped\" drop") == 1


def test_without_declared_ports_containment_is_by_destination_only() -> None:
    # naabu legitimately sweeps ports; it is contained by destination instead.
    ruleset = N.render_namespace_ruleset([PINNED], [])
    assert f"ip daddr {{ {PINNED} }} counter name \"allowed\" accept" in ruleset
    assert "dport" not in ruleset


def test_rule_rendering_rejects_injection_and_bad_input() -> None:
    with pytest.raises(EgressUnavailableError):
        N.render_namespace_ruleset(["203.0.113.9 } ; accept #"], [443])
    with pytest.raises(EgressUnavailableError):
        N.render_namespace_ruleset(["not-an-address"], [443])
    with pytest.raises(EgressUnavailableError):
        N.render_namespace_ruleset([], [443])
    with pytest.raises(EgressUnavailableError):
        N.render_namespace_ruleset([PINNED], [70000])


def test_plan_is_a_point_to_point_30_inside_the_pool() -> None:
    plan = N.plan_for(1, "gryphon-aabbccddeeff")
    pool = ipaddress.ip_network(N.POOL_CIDR)
    assert plan.prefix_length == 30
    assert ipaddress.ip_address(plan.host_address) in pool
    assert ipaddress.ip_address(plan.namespace_address) in pool
    assert plan.host_address != plan.namespace_address
    # Kernel interface names are capped at 15 characters.
    assert len(plan.host_interface) <= 15 and len(plan.peer_interface) <= 15
    assert plan.argv_prefix == ("ip", "netns", "exec", "gryphon-aabbccddeeff")


async def test_address_pool_hands_out_distinct_blocks_and_reclaims() -> None:
    pool = N.AddressPool(capacity=3)
    taken = {await pool.acquire() for _ in range(3)}
    assert len(taken) == 3
    with pytest.raises(EgressUnavailableError):
        await pool.acquire()
    await pool.release(next(iter(taken)))
    assert await pool.acquire() in taken


def test_split_allowlist_separates_containable_addresses() -> None:
    v4, other = N.split_allowlist([PINNED, "2606:4700::1111", "nonsense"])
    assert v4 == [PINNED]
    assert len(other) == 2


# =============================================================================
# Fail-closed behaviour of the enforcer (no privileges needed)
# =============================================================================
class _StubProvisioner:
    """Records calls; optionally fails setup to exercise the rollback path."""

    def __init__(self, *, fail_setup: bool = False) -> None:
        self.fail_setup = fail_setup
        self.setups: list[N.NamespacePlan] = []
        self.teardowns: list[str] = []

    async def prepare_host(self) -> None:
        return None

    async def setup(self, plan, allowlist_v4, ports) -> None:
        self.setups.append(plan)
        if self.fail_setup:
            raise EgressUnavailableError("nft refused the ruleset")

    async def teardown(self, plan) -> None:
        self.teardowns.append(plan.namespace)

    async def counters(self, plan) -> dict[str, int]:
        return {}

    async def list_namespaces(self) -> list[str]:
        return []


def _forced_enforcer(provisioner, *, capacity: int = 4) -> LinuxNamespaceEgressEnforcer:
    """An enforcer with the host probe satisfied, for platform-free testing."""
    enforcer = LinuxNamespaceEgressEnforcer(provisioner, pool=N.AddressPool(capacity=capacity))
    enforcer._capable = True  # noqa: SLF001 - the probe is what we are bypassing
    return enforcer


async def test_establish_without_a_containable_address_fails_closed() -> None:
    stub = _StubProvisioner()
    enforcer = _forced_enforcer(stub)
    with pytest.raises(EgressUnavailableError):
        await enforcer.establish(["2606:4700::1111"], [443])
    # Nothing was created, so nothing had to be torn down.
    assert stub.setups == []


async def test_setup_failure_tears_down_and_reclaims_the_block() -> None:
    stub = _StubProvisioner(fail_setup=True)
    enforcer = _forced_enforcer(stub, capacity=1)
    with pytest.raises(EgressUnavailableError):
        await enforcer.establish([PINNED], [443])
    assert len(stub.teardowns) == 1
    # The single address block was returned to the pool, not leaked.
    with pytest.raises(EgressUnavailableError):
        await enforcer.establish(["2606:4700::1111"], [443])  # fails for another reason
    stub.fail_setup = False
    handle = await enforcer.establish([PINNED], [443])
    assert handle.enforcing is True


async def test_handle_wraps_the_child_into_the_namespace() -> None:
    enforcer = _forced_enforcer(_StubProvisioner())
    handle = await enforcer.establish([PINNED], [443])
    wrapped = handle.wrap_argv(["/opt/gryphon/bin/httpx", "-u", PINNED])
    assert wrapped[:3] == ["ip", "netns", "exec"]
    assert wrapped[3].startswith(N.NETNS_PREFIX)
    assert wrapped[4:] == ["/opt/gryphon/bin/httpx", "-u", PINNED]
    # Only containable addresses are reported as allowlisted.
    assert handle.allowlist == (PINNED,)


async def test_unenforced_enforcer_is_marked_non_enforcing() -> None:
    handle = await NullEgressEnforcer().establish([PINNED], [443])
    assert handle.enforcing is False
    assert handle.wrap_argv(["x"]) == ["x"]


# =============================================================================
# The privileged helper validates before it acts
# =============================================================================
def test_helper_refuses_namespaces_and_values_it_does_not_own() -> None:
    from scripts.gryphon_egress_helper import (
        RequestRejected,
        _validate_allowlist,
        _validate_plan,
        _validate_ports,
    )

    good = N.plan_for(7, "gryphon-0123456789ab").__dict__
    assert _validate_plan(good, require_addressing=True).index == 7

    for bad in (
        {**good, "namespace": "default"},
        {**good, "namespace": "../../etc"},
        {**good, "host_interface": "eth0"},
        {**good, "host_address": "8.8.8.8"},
        {**good, "prefix_length": 8},
        {**good, "index": 0},
    ):
        with pytest.raises(RequestRejected):
            _validate_plan(bad, require_addressing=True)

    with pytest.raises(RequestRejected):
        _validate_allowlist(["203.0.113.9 } ; accept #"])
    with pytest.raises(RequestRejected):
        _validate_allowlist([])
    with pytest.raises(RequestRejected):
        _validate_ports([0])
    with pytest.raises(RequestRejected):
        _validate_ports([True])
    assert _validate_ports([80, 443]) == [80, 443]


# =============================================================================
# Real containment — Linux with CAP_NET_ADMIN
# =============================================================================
def _connect_from_namespace(namespace: str, host: str, port: int, timeout: float = 2.0):
    snippet = (
        "import socket, sys\n"
        "s = socket.socket()\n"
        "s.settimeout(float(sys.argv[3]))\n"
        "try:\n"
        "    s.connect((sys.argv[1], int(sys.argv[2])))\n"
        "    print('connected')\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__)\n"
        "    sys.exit(1)\n"
    )
    return subprocess.run(
        ["ip", "netns", "exec", namespace, sys.executable, "-c", snippet,
         host, str(port), str(timeout)],
        capture_output=True,
        text=True,
        timeout=timeout + 15,
        check=False,
    )


@requires_netns
async def test_namespace_drops_a_destination_that_was_not_pinned() -> None:
    enforcer = LinuxNamespaceEgressEnforcer()
    handle = await enforcer.establish([PINNED], [443])
    try:
        result = _connect_from_namespace(handle.context_id, NOT_PINNED, 443)
        assert result.returncode != 0, "a non-pinned destination must not be reachable"
        counters = await enforcer.counters(handle)
        # The proof: the kernel counted our packet on the drop rule.
        assert counters.get(N.COUNTER_DROPPED, 0) > 0, counters
    finally:
        await enforcer.teardown(handle)


@requires_netns
async def test_namespace_allows_exactly_the_pinned_destination() -> None:
    # Driven at the provisioner level so the test controls the addressing and can
    # put a listener at an allowlisted address without any external traffic.
    provisioner = N.DirectNetnsProvisioner()
    plan = N.plan_for(900, "gryphon-ab0000000900")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        await provisioner.prepare_host()
        await provisioner.setup(plan, [plan.host_address], [8099])
        listener.bind((plan.host_address, 8099))
        listener.listen(8)  # the handshake completes in the kernel; no accept needed

        allowed = _connect_from_namespace(plan.namespace, plan.host_address, 8099)
        assert allowed.returncode == 0, allowed.stdout + allowed.stderr

        counters = await provisioner.counters(plan)
        assert counters.get(N.COUNTER_ALLOWED, 0) > 0, counters
    finally:
        listener.close()
        await provisioner.teardown(plan)


@requires_netns
async def test_teardown_removes_the_namespace_and_its_host_interface() -> None:
    enforcer = LinuxNamespaceEgressEnforcer()
    handle = await enforcer.establish([PINNED], [443])
    namespace = handle.context_id
    assert namespace in subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True, check=False
    ).stdout
    await enforcer.teardown(handle)

    listed = subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True, check=False
    ).stdout
    assert namespace not in listed
    links = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True, check=False).stdout
    assert "gryv" not in links, "the host-side veth was left behind"


@requires_netns
async def test_reap_deletes_namespaces_left_by_a_crash() -> None:
    orphan = "gryphon-dead0000beef"
    subprocess.run(["ip", "netns", "add", orphan], check=True)
    enforcer = LinuxNamespaceEgressEnforcer()
    reaped = await enforcer.reap()
    assert orphan in reaped
    assert orphan not in subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True, check=False
    ).stdout


@requires_netns
async def test_the_runner_launches_the_tool_inside_the_namespace() -> None:
    """End-to-end: the real runner, the real handle, a real contained process."""
    from gryphon.tooling.tools.runner import SafeSubprocessRunner

    enforcer = LinuxNamespaceEgressEnforcer()
    handle = await enforcer.establish([PINNED], [443])
    try:
        runner = SafeSubprocessRunner(max_stdout_bytes=1 << 20)
        result = await runner.run(
            binary_path=shutil.which("ip") or "/sbin/ip",
            argv=["-o", "addr", "show"],
            timeout_seconds=15,
            egress_handle=handle,
        )
        # Inside the namespace the only addresses are loopback and its own /30 end.
        plan, _ = enforcer._live[handle.context_id]  # noqa: SLF001 - asserting isolation
        assert plan.namespace_address in result.stdout
        assert "eth0" not in result.stdout, "the child saw the host's network stack"
    finally:
        await enforcer.teardown(handle)


@requires_netns
def test_the_stub_is_gone_capability_probe_now_passes() -> None:
    """On a capable host the enforcer must report itself usable."""
    assert LinuxNamespaceEgressEnforcer().capable is True
