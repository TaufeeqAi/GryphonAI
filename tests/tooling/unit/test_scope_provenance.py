"""Scope is re-derived from the grant receipt; a widened capability is rejected."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gryphon.auth.scope import ScopeEntry, scope_digest
from gryphon.constants import TargetType
from gryphon.tooling.enforcement.scope_provenance import (
    ProvenanceFailure,
    ScopeProvenance,
    rederive_scope,
)
from gryphon.tooling.reasons import ToolReasonCode

pytestmark = pytest.mark.unit


class _FakeReceipt:
    def __init__(self, entries, *, claims_digest="cd", scope_dig=None, max_depth="standard") -> None:
        self.scope = [e.canonical_dict() for e in entries]
        self.scope_digest = scope_dig if scope_dig is not None else scope_digest(entries)
        self.claims_digest = claims_digest
        self.scope_policy_version = "1"
        self.max_scan_depth = max_depth
        self.issuer_kid = "grant-kid"
        self.expires_at = datetime(2026, 9, 1, tzinfo=timezone.utc)


class _FakeSession:
    def __init__(self, receipt) -> None:
        self._receipt = receipt

    async def get(self, _model, _key):
        return self._receipt


def _entries():
    return (ScopeEntry(target_type=TargetType.DOMAIN, target="app.example.com"),)


@pytest.mark.asyncio
async def test_happy_rederive() -> None:
    entries = _entries()
    session = _FakeSession(_FakeReceipt(entries))
    prov = await rederive_scope(
        session, grant_id="g", expected_claims_digest="cd", expected_scope_digest=scope_digest(entries)
    )
    assert isinstance(prov, ScopeProvenance)
    assert prov.scope_entries[0].target == "app.example.com"


@pytest.mark.asyncio
async def test_widened_capability_rejected() -> None:
    entries = _entries()
    session = _FakeSession(_FakeReceipt(entries))
    prov = await rederive_scope(
        session, grant_id="g", expected_claims_digest="cd", expected_scope_digest="a-widened-digest"
    )
    assert isinstance(prov, ProvenanceFailure)
    assert prov.reason_code is ToolReasonCode.SCOPE_PROVENANCE_MISMATCH


@pytest.mark.asyncio
async def test_missing_receipt() -> None:
    prov = await rederive_scope(
        _FakeSession(None), grant_id="g", expected_claims_digest="cd", expected_scope_digest=None
    )
    assert isinstance(prov, ProvenanceFailure)
    assert prov.reason_code is ToolReasonCode.RECEIPT_MISSING


@pytest.mark.asyncio
async def test_claims_digest_mismatch() -> None:
    session = _FakeSession(_FakeReceipt(_entries(), claims_digest="other"))
    prov = await rederive_scope(
        session, grant_id="g", expected_claims_digest="cd", expected_scope_digest=None
    )
    assert isinstance(prov, ProvenanceFailure)
    assert prov.reason_code is ToolReasonCode.RECEIPT_MISMATCH


@pytest.mark.asyncio
async def test_tampered_receipt_scope_digest() -> None:
    # The stored scope does not match its own recorded digest → tampered row.
    session = _FakeSession(_FakeReceipt(_entries(), scope_dig="deadbeef"))
    prov = await rederive_scope(
        session, grant_id="g", expected_claims_digest="cd", expected_scope_digest="deadbeef"
    )
    assert isinstance(prov, ProvenanceFailure)
    assert prov.reason_code is ToolReasonCode.RECEIPT_MISMATCH
