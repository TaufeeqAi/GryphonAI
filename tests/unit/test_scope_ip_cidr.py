"""IP / CIDR scope policy v1 (§11.3, SEC-006)."""

from __future__ import annotations

import pytest

from gryphon.auth.scope import (
    ScopeEntry,
    ScopeResult,
    canonicalize_cidr,
    canonicalize_target,
    evaluate,
)
from gryphon.constants import TargetType
from gryphon.errors import ScopeEvaluationError

pytestmark = pytest.mark.unit


def _ip_scope(target: str) -> tuple[ScopeEntry, ...]:
    return (ScopeEntry(target_type=TargetType.IP, target=target),)


def _cidr_scope(target: str) -> tuple[ScopeEntry, ...]:
    return (ScopeEntry(target_type=TargetType.CIDR, target=target),)


def test_exact_ip_match() -> None:
    scope = _ip_scope("203.0.113.7")
    assert evaluate(scope, canonicalize_target("203.0.113.7"), None).result is ScopeResult.MATCH
    assert evaluate(scope, canonicalize_target("203.0.113.8"), None).result is ScopeResult.NO_MATCH


def test_cidr_contains_address() -> None:
    scope = _cidr_scope("203.0.113.0/24")
    assert evaluate(scope, canonicalize_target("203.0.113.200"), None).result is ScopeResult.MATCH
    assert evaluate(scope, canonicalize_target("203.0.114.1"), None).result is ScopeResult.NO_MATCH


def test_cidr_rejects_host_bits_set_no_widening() -> None:
    # 203.0.113.1/24 has host bits set; strict parsing refuses to widen it.
    with pytest.raises(ScopeEvaluationError):
        canonicalize_cidr("203.0.113.1/24")
    with pytest.raises(ScopeEvaluationError):
        ScopeEntry(target_type=TargetType.CIDR, target="203.0.113.1/24")


def test_ipv6_exact_and_zone_id_rejected() -> None:
    scope = _ip_scope("2001:db8::1")
    assert evaluate(scope, canonicalize_target("2001:db8::1"), None).result is ScopeResult.MATCH
    with pytest.raises(ScopeEvaluationError):
        canonicalize_target("fe80::1%eth0")


def test_ipv4_mapped_ipv6_does_not_cross_families() -> None:
    # An IPv4 scope entry must NOT match the mapped-IPv6 form and vice versa.
    ipv4_scope = _ip_scope("203.0.113.7")
    assert (
        evaluate(ipv4_scope, canonicalize_target("::ffff:203.0.113.7"), None).result
        is ScopeResult.NO_MATCH
    )


def test_cidr_does_not_match_other_family() -> None:
    scope = _cidr_scope("203.0.113.0/24")
    assert (
        evaluate(scope, canonicalize_target("2001:db8::1"), None).result is ScopeResult.NO_MATCH
    )
