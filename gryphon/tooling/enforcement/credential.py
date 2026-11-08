"""Credential normalization (CHG-009 conditional capability).

Both the cross-process capability path and the in-process permit path normalize
to one :class:`AdmittedReference`, so the gateway decides identically regardless
of how authority arrived. The in-process path creates no serialized capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from gryphon.auth.results import AuthorizedPermit
from gryphon.constants import ScanDepth
from gryphon.tooling.capability.claims import VerifiedCapability
from gryphon.tooling.constants import CredentialSource, ToolId


@dataclass(frozen=True)
class AdmittedReference:
    scan_run_id: str
    grant_id: str
    claims_digest: str
    scope_digest: str | None
    effective_scan_depth: ScanDepth
    tool_id: ToolId
    execution_id: str
    source: CredentialSource
    capability_id: str | None = None
    nonce: str | None = None
    capability_expires_at: datetime | None = None


def from_verified_capability(verified: VerifiedCapability) -> AdmittedReference:
    claims = verified.claims
    return AdmittedReference(
        scan_run_id=claims.scan_run_id,
        grant_id=claims.grant_id,
        claims_digest=claims.claims_digest,
        scope_digest=claims.scope_digest,
        effective_scan_depth=claims.effective_scan_depth,
        tool_id=claims.tool_id,
        execution_id=claims.execution_id,
        source=CredentialSource.CAPABILITY,
        capability_id=claims.capability_id,
        nonce=claims.nonce,
        capability_expires_at=datetime.fromtimestamp(claims.exp, tz=timezone.utc),
    )


def from_permit(
    permit: AuthorizedPermit, tool_id: ToolId, execution_id: str
) -> AdmittedReference:
    return AdmittedReference(
        scan_run_id=permit.scan_run_id,
        grant_id=permit.grant_id,
        claims_digest=permit.claims_digest,
        scope_digest=None,  # in-process: re-derived from the receipt, no cross-check needed
        effective_scan_depth=permit.effective_scan_depth,
        tool_id=tool_id,
        execution_id=execution_id,
        source=CredentialSource.PERMIT,
    )
