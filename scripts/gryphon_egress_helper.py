"""Privileged egress helper — the ONLY component that needs CAP_NET_ADMIN.

Install this where the unprivileged application can execute it with elevated
capability (a narrow sudoers entry for this exact path, a systemd service, or
file capabilities), and point the application at it:

    GRYPHON_EGRESS_HELPER_PATH=/opt/gryphon/bin/gryphon-egress-helper

It reads one JSON request on stdin and writes one JSON response on stdout:

    {"op": "prepare_host"}
    {"op": "setup", "plan": {...}, "allowlist": ["93.184.216.34"], "ports": [80, 443]}
    {"op": "teardown", "plan": {...}}
    {"op": "counters", "plan": {...}}       -> {"ok": true, "counters": {...}}
    {"op": "list"}                          -> {"ok": true, "namespaces": [...]}

Because this runs privileged, **every field is validated here** before any
command runs: the namespace name must be one this layer owns, the interfaces
must match the generated pattern, the addresses must fall inside the private
pool, and the allowlist must contain IPv4 literals only. A request that does not
conform is refused — it is never partially applied.

    printf '{"op":"list"}' | sudo python -m scripts.gryphon_egress_helper
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import sys
from typing import Any

from gryphon.tooling.destination.netns import (
    NETNS_PREFIX,
    POOL_CIDR,
    DirectNetnsProvisioner,
    NamespacePlan,
)
from gryphon.tooling.reasons import EgressUnavailableError

_NAMESPACE_RE = re.compile(rf"^{re.escape(NETNS_PREFIX)}[0-9a-f]{{6,32}}$")
_INTERFACE_RE = re.compile(r"^gry[vp][0-9]{1,6}$")
_POOL = ipaddress.ip_network(POOL_CIDR)


class RequestRejected(Exception):
    """The request did not conform; nothing was applied."""


def _validate_namespace(name: Any) -> str:
    if not isinstance(name, str) or not _NAMESPACE_RE.match(name):
        raise RequestRejected("namespace is not one this helper owns")
    return name


def _validate_plan(raw: Any, *, require_addressing: bool) -> NamespacePlan:
    if not isinstance(raw, dict):
        raise RequestRejected("plan must be an object")
    namespace = _validate_namespace(raw.get("namespace"))

    if not require_addressing:
        # Teardown by name only (used by the reaper for a crashed execution).
        return NamespacePlan(
            namespace=namespace,
            host_interface="",
            peer_interface="",
            host_address="",
            namespace_address="",
            prefix_length=30,
            index=-1,
        )

    for key in ("host_interface", "peer_interface"):
        value = raw.get(key)
        if not isinstance(value, str) or not _INTERFACE_RE.match(value):
            raise RequestRejected(f"{key} does not match the generated pattern")
    for key in ("host_address", "namespace_address"):
        try:
            address = ipaddress.ip_address(raw.get(key, ""))
        except ValueError as exc:
            raise RequestRejected(f"{key} is not an IP address") from exc
        if address not in _POOL:
            raise RequestRejected(f"{key} is outside the private pool {POOL_CIDR}")
    if raw.get("prefix_length") != 30:
        raise RequestRejected("prefix_length must be 30")
    index = raw.get("index")
    if not isinstance(index, int) or not 1 <= index <= 65535:
        raise RequestRejected("index out of range")

    return NamespacePlan(
        namespace=namespace,
        host_interface=raw["host_interface"],
        peer_interface=raw["peer_interface"],
        host_address=raw["host_address"],
        namespace_address=raw["namespace_address"],
        prefix_length=30,
        index=index,
    )


def _validate_allowlist(raw: Any) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise RequestRejected("allowlist must be a non-empty list")
    if len(raw) > 64:
        raise RequestRejected("allowlist is too large")
    addresses: list[str] = []
    for entry in raw:
        try:
            addresses.append(str(ipaddress.IPv4Address(entry)))
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise RequestRejected("allowlist must contain IPv4 literals only") from exc
    return addresses


def _validate_ports(raw: Any) -> list[int]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RequestRejected("ports must be a list")
    if len(raw) > 128:
        raise RequestRejected("too many ports")
    ports: list[int] = []
    for entry in raw:
        if not isinstance(entry, int) or isinstance(entry, bool) or not 1 <= entry <= 65535:
            raise RequestRejected("ports must be integers within 1-65535")
        ports.append(entry)
    return ports


async def handle(request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    provisioner = DirectNetnsProvisioner()

    if op == "prepare_host":
        await provisioner.prepare_host()
        return {"ok": True}

    if op == "setup":
        plan = _validate_plan(request.get("plan"), require_addressing=True)
        allowlist = _validate_allowlist(request.get("allowlist"))
        ports = _validate_ports(request.get("ports"))
        await provisioner.setup(plan, allowlist, ports)
        return {"ok": True, "namespace": plan.namespace}

    if op == "teardown":
        raw = request.get("plan") or {}
        has_addressing = bool(raw.get("host_interface"))
        plan = _validate_plan(raw, require_addressing=has_addressing)
        await provisioner.teardown(plan)
        return {"ok": True}

    if op == "counters":
        plan = _validate_plan(request.get("plan"), require_addressing=True)
        return {"ok": True, "counters": await provisioner.counters(plan)}

    if op == "list":
        return {"ok": True, "namespaces": await provisioner.list_namespaces()}

    raise RequestRejected(f"unknown op {op!r}")


def main() -> None:
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"ok": False, "error": "malformed request"}))
        sys.exit(2)
    if not isinstance(request, dict):
        print(json.dumps({"ok": False, "error": "request must be an object"}))
        sys.exit(2)

    try:
        response = asyncio.run(handle(request))
    except RequestRejected as exc:
        print(json.dumps({"ok": False, "error": f"rejected: {exc}"}))
        sys.exit(3)
    except EgressUnavailableError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        sys.exit(4)
    except Exception as exc:  # noqa: BLE001 - never leak a traceback from a privileged tool
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}"}))
        sys.exit(5)
    print(json.dumps(response))


if __name__ == "__main__":
    main()
