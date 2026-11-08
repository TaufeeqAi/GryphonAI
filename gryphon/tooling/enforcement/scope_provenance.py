"""Scope provenance — re-derive the authorized scope from the grant receipt.

This is the mechanism that makes a widened capability unusable: the gateway never
trusts a credential's scope. It loads the committed issuance receipt, verifies
the claims digest, rebuilds the canonical scope with the *same* policy the grant
was signed under, and recomputes the digest to detect receipt tampering.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.auth.scope import ScopeEntry, scope_digest
from gryphon.constants import ScanDepth
from gryphon.db.repositories.grants import GrantRepository
from gryphon.tooling.reasons import ToolReasonCode


@dataclass(frozen=True)
class ScopeProvenance:
    scope_entries: tuple[ScopeEntry, ...]
    scope_digest: str
    scope_policy_version: str
    grant_max_depth: ScanDepth
    issuer_kid: str


@dataclass(frozen=True)
class ProvenanceFailure:
    reason_code: ToolReasonCode
    detail: str = ""


async def rederive_scope(
    session: AsyncSession,
    *,
    grant_id: str,
    expected_claims_digest: str,
    expected_scope_digest: str | None = None,
) -> ScopeProvenance | ProvenanceFailure:
    """Load the receipt and re-derive the authorized scope, or fail closed."""
    receipt = await GrantRepository(session).get_by_grant_id(grant_id)
    if receipt is None:
        return ProvenanceFailure(ToolReasonCode.RECEIPT_MISSING, "grant receipt not found")
    if receipt.claims_digest != expected_claims_digest:
        return ProvenanceFailure(ToolReasonCode.RECEIPT_MISMATCH, "claims digest mismatch")

    try:
        entries = tuple(ScopeEntry(**entry) for entry in receipt.scope)
    except Exception:
        return ProvenanceFailure(ToolReasonCode.RECEIPT_MISMATCH, "receipt scope unparsable")

    recomputed = scope_digest(entries)
    if recomputed != receipt.scope_digest:
        # The stored receipt scope does not match its own digest: tampered row.
        return ProvenanceFailure(ToolReasonCode.RECEIPT_MISMATCH, "receipt scope digest mismatch")

    if expected_scope_digest is not None and expected_scope_digest != receipt.scope_digest:
        # The credential referenced a different scope than the grant actually holds.
        return ProvenanceFailure(
            ToolReasonCode.SCOPE_PROVENANCE_MISMATCH, "credential scope digest mismatch"
        )

    try:
        grant_max_depth = ScanDepth(receipt.max_scan_depth)
    except ValueError:
        return ProvenanceFailure(ToolReasonCode.DEPTH_INVALID, "grant max depth invalid")

    return ScopeProvenance(
        scope_entries=entries,
        scope_digest=receipt.scope_digest,
        scope_policy_version=receipt.scope_policy_version,
        grant_max_depth=grant_max_depth,
        issuer_kid=receipt.issuer_kid,
    )
