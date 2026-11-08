"""Destination ranges, resolve-then-pin, and rebinding containment."""

from __future__ import annotations

import ipaddress

import pytest

from gryphon.auth.scope import canonicalize_target
from gryphon.tooling.destination.guard import DestinationDenied, DestinationGuard, PinnedDestinations
from gryphon.tooling.destination.ranges import classify, is_denied
from gryphon.tooling.reasons import ToolReasonCode

pytestmark = pytest.mark.unit


class _FakeResolver:
    def __init__(self, addresses: list[str]) -> None:
        self._addrs = [ipaddress.ip_address(a) for a in addresses]

    async def resolve(self, host: str):
        return list(self._addrs)


@pytest.mark.parametrize(
    "addr,category",
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.1", "private"),
        ("192.168.1.1", "private"),
        ("169.254.169.254", "metadata"),
        ("169.254.1.1", "link_local"),
        ("100.64.0.1", "cgnat"),
        ("::1", "loopback"),
        ("fd00:ec2::254", "metadata"),
        ("93.184.216.34", "public"),
    ],
)
def test_classify(addr: str, category: str) -> None:
    assert classify(ipaddress.ip_address(addr)) == category
    assert is_denied(ipaddress.ip_address(addr)) == (category != "public")


@pytest.mark.asyncio
async def test_bind_public_pins_address() -> None:
    guard = DestinationGuard(_FakeResolver(["93.184.216.34"]))
    pinned = await guard.bind(canonicalize_target("app.example.com"), ports=(443,))
    assert isinstance(pinned, PinnedDestinations)
    assert pinned.addresses == ("93.184.216.34",)


@pytest.mark.asyncio
async def test_bind_private_denied() -> None:
    guard = DestinationGuard(_FakeResolver(["10.1.2.3"]))
    denied = await guard.bind(canonicalize_target("internal.example.com"), ports=(443,))
    assert isinstance(denied, DestinationDenied)
    assert denied.reason_code is ToolReasonCode.DESTINATION_DENIED


@pytest.mark.asyncio
async def test_bind_unresolvable_denied() -> None:
    guard = DestinationGuard(_FakeResolver([]))
    denied = await guard.bind(canonicalize_target("nope.example.com"), ports=())
    assert isinstance(denied, DestinationDenied)
    assert denied.reason_code is ToolReasonCode.DESTINATION_UNRESOLVABLE


@pytest.mark.asyncio
async def test_rebinding_redirect_outside_pin_blocked() -> None:
    guard = DestinationGuard(_FakeResolver(["93.184.216.34"]))
    pinned = await guard.bind(canonicalize_target("app.example.com"), ports=(443,))
    assert isinstance(pinned, PinnedDestinations)
    # A re-resolution / redirect to a different public IP is NOT in the pin set.
    assert guard.validate_redirect("93.184.216.99", pinned) is False
    # A redirect to a private address is denied outright.
    assert guard.validate_redirect("10.0.0.5", pinned) is False
    # The pinned address itself is allowed.
    assert guard.validate_redirect("93.184.216.34", pinned) is True
