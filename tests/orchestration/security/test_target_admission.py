"""Target admission: the dangling-subdomain attack, and the amplification cap.

The attack these tests encode is routine in external testing and lands exactly
on the seam this layer spans:

    A wildcard grant covers ``*.example.com``. A stale record —
    ``old-cdn.example.com`` — still exists but now points at an address
    somebody else owns. The name matches the grant, so scope says yes. The
    destination guard resolves and pins that address, so containment says yes.
    Every control behaves as specified, and active scan traffic reaches a
    stranger.

Scope is granted over names; containment is enforced over addresses. Only this
layer sees both, so only this layer can refuse when they disagree.
"""

from __future__ import annotations

import pytest

from gryphon.orchestration.admission import TargetAdmission
from gryphon.orchestration.constants import ExclusionReason
from tests.orchestration.conftest import (
    ESTATE_CIDR,
    NOW,
    OUTSIDE_ESTATE,
    SEED_TARGET,
    StubResolver,
)

pytestmark = pytest.mark.security


def _admission(resolver: StubResolver, **overrides) -> TargetAdmission:
    kwargs = dict(
        resolver=resolver,
        attested_estate_cidrs=(ESTATE_CIDR,),
        discovered_target_cap=10,
        strict_address_attestation=True,
    )
    kwargs.update(overrides)
    return TargetAdmission(**kwargs)


async def _admit(admission: TargetAdmission, discovered: list[str], scope_entries):
    return await admission.admit(
        discovered=discovered,
        seed_target=SEED_TARGET,
        discovered_by="subdomain_discovery",
        scope_entries=scope_entries,
        now=NOW,
    )


@pytest.mark.asyncio
async def test_in_estate_target_is_admitted(scope_entries) -> None:
    resolver = StubResolver({"good.example.com": ["203.0.113.10"]})
    result = await _admit(_admission(resolver), ["good.example.com"], scope_entries)
    assert [t.canonical_target for t in result.admitted] == ["good.example.com"]
    assert not result.excluded


@pytest.mark.asyncio
async def test_dangling_subdomain_is_refused(scope_entries) -> None:
    """In scope by name, pointing at a stranger. Refused, not scanned."""
    resolver = StubResolver({"old-cdn.example.com": [OUTSIDE_ESTATE]})
    result = await _admit(_admission(resolver), ["old-cdn.example.com"], scope_entries)
    assert not result.admitted
    assert [e.reason for e in result.excluded] == [ExclusionReason.ADDRESS_UNATTESTED]
    assert OUTSIDE_ESTATE in result.excluded[0].detail


@pytest.mark.asyncio
async def test_mixed_round_robin_is_refused_entirely(scope_entries) -> None:
    """One bad address disqualifies the name.

    A record returning both an in-estate and an out-of-estate address would
    otherwise let traffic reach the stranger on a later connection, since the
    tool re-resolves independently of our check.
    """
    resolver = StubResolver(
        {"mixed.example.com": ["203.0.113.20", OUTSIDE_ESTATE]}
    )
    result = await _admit(_admission(resolver), ["mixed.example.com"], scope_entries)
    assert not result.admitted
    assert result.excluded[0].reason is ExclusionReason.ADDRESS_UNATTESTED


@pytest.mark.asyncio
async def test_out_of_scope_discovery_is_refused_before_planning(scope_entries) -> None:
    """Discovery can return anything; a wildcard grant is not the internet.

    Refused here rather than denied call-by-call later, so it never enters the
    coverage denominator and cannot make a healthy scan look full of gaps.
    """
    resolver = StubResolver({"evil.attacker.test": ["203.0.113.30"]})
    result = await _admit(_admission(resolver), ["evil.attacker.test"], scope_entries)
    assert not result.admitted
    assert result.excluded[0].reason is ExclusionReason.INVALID


@pytest.mark.asyncio
async def test_unresolvable_target_is_excluded_not_scanned(scope_entries) -> None:
    resolver = StubResolver({})
    result = await _admit(_admission(resolver), ["gone.example.com"], scope_entries)
    assert not result.admitted
    assert result.excluded[0].reason is ExclusionReason.UNRESOLVABLE


@pytest.mark.asyncio
async def test_unconfigured_estate_refuses_everything_in_strict_mode(
    scope_entries,
) -> None:
    """With nothing to attest against, failing closed is the honest choice.

    Admitting everything would leave the control present in the code and absent
    in effect — the worst of both.
    """
    resolver = StubResolver({"good.example.com": ["203.0.113.10"]})
    admission = _admission(resolver, attested_estate_cidrs=())
    assert admission.attestation_configured is False
    result = await _admit(admission, ["good.example.com"], scope_entries)
    assert not result.admitted
    assert result.excluded[0].reason is ExclusionReason.ADDRESS_UNATTESTED


@pytest.mark.asyncio
async def test_non_strict_mode_admits_an_unattested_address(scope_entries) -> None:
    """Documented escape hatch for development; refused in production config."""
    resolver = StubResolver({"dev.example.com": [OUTSIDE_ESTATE]})
    admission = _admission(resolver, strict_address_attestation=False)
    result = await _admit(admission, ["dev.example.com"], scope_entries)
    assert [t.canonical_target for t in result.admitted] == ["dev.example.com"]


@pytest.mark.asyncio
async def test_cap_halts_for_review_instead_of_fanning_out(scope_entries) -> None:
    """Discovery output is attacker-influenceable; a cap bounds the blast radius."""
    hosts = [f"h{i}.example.com" for i in range(25)]
    resolver = StubResolver({h: ["203.0.113.40"] for h in hosts})
    result = await _admit(_admission(resolver, discovered_target_cap=10), hosts, scope_entries)
    assert result.halted_for_review
    assert result.discovered_count == 25
    assert not result.admitted
    # Nothing was resolved: we stopped before doing any work.
    assert resolver.calls == []


@pytest.mark.asyncio
async def test_provenance_records_why_a_target_was_scanned(scope_entries) -> None:
    """The chain of custody: tool, seed, time, and what we attested against."""
    resolver = StubResolver({"good.example.com": ["203.0.113.10"]})
    result = await _admit(_admission(resolver), ["good.example.com"], scope_entries)
    provenance = result.admitted[0].provenance
    assert provenance["discovered_by"] == "subdomain_discovery"
    assert provenance["seed_target"] == SEED_TARGET
    assert provenance["resolved_addresses"] == ["203.0.113.10"]
    assert provenance["attested_against"] == [ESTATE_CIDR]
    assert provenance["discovered_at"] == NOW.isoformat()


@pytest.mark.asyncio
async def test_duplicates_collapse_deterministically(scope_entries) -> None:
    """Stable ordering matters: a plan item's position feeds its identity.

    An unstable admitted order would change downstream execution identities
    between an original run and a resumed one, which the enforcement layer
    would read as new work.
    """
    resolver = StubResolver({"dup.example.com": ["203.0.113.50"]})
    discovered = ["dup.example.com", "DUP.example.com", " dup.example.com "]
    first = await _admit(_admission(resolver), discovered, scope_entries)
    second = await _admit(_admission(resolver), discovered, scope_entries)
    assert len(first.admitted) == 1
    assert [t.canonical_target for t in first.admitted] == [
        t.canonical_target for t in second.admitted
    ]


@pytest.mark.asyncio
async def test_exclusion_histogram_reports_causes(scope_entries) -> None:
    resolver = StubResolver(
        {
            "ok.example.com": ["203.0.113.10"],
            "bad.example.com": [OUTSIDE_ESTATE],
        }
    )
    result = await _admit(
        _admission(resolver),
        ["ok.example.com", "bad.example.com", "gone.example.com"],
        scope_entries,
    )
    assert result.exclusion_histogram == {
        ExclusionReason.ADDRESS_UNATTESTED.value: 1,
        ExclusionReason.UNRESOLVABLE.value: 1,
    }
