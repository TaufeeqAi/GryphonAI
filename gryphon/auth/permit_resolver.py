"""Re-resolve an in-process permit from committed admission records.

An orchestrated scan outlives the process that admitted it: it resumes after a
crash, and it may be taken over by a new owner. Both need the permit again,
and neither may re-decide authorization.

Re-resolution lives **here**, in the authorization layer, for two reasons.
First, minting a permit is this layer's privilege — the permit's constructor is
guarded precisely so no other component can manufacture authority — and
re-resolution is minting. Second, "is this authorization still live?" is an
authorization question; answering it elsewhere would create a second opinion
about the one thing the system must have exactly one opinion about.

This is a *read* of a committed decision, not a new decision. It re-mints only
when the recorded admission is ALLOW **and** the authorization behind it is
still live right now:

* the ``scan_runs`` row is a committed ALLOW admission;
* the grant receipt exists and its claims digest is intact;
* the grant is within its validity window at ``now``;
* the grant's signer key is *still* in the trust store.

The last two matter most. A committed admission is immutable and says nothing
about current trust, so an operator who revokes a signing key — the only
revocation mechanism this system has — would otherwise find the revocation
silently ineffective against a scan already in flight, which is worse than no
revocation at all. Checked here, on every resolution, revocation and expiry
both stop in-flight work.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.auth.results import AuthorizedPermit, mint_permit
from gryphon.clock import ensure_utc
from gryphon.constants import DecisionStatus, ScanDepth, ScanRunStatus
from gryphon.db.models.scan_run import ScanRun
from gryphon.db.repositories.audit import AuditRepository
from gryphon.db.repositories.grants import GrantRepository


class PermitResolutionReason(str, Enum):
    """Why re-resolution failed.

    Deliberately local rather than added to the published admission reason
    codes: those describe *deciding* an admission, and these describe *reading*
    one back. Keeping them apart avoids overloading a signed contract surface
    with a different meaning, and avoids an upward dependency from this layer
    onto its consumers.
    """

    NO_ADMISSION = "NO_ADMISSION"
    ADMISSION_NOT_AUTHORIZED = "ADMISSION_NOT_AUTHORIZED"
    RECEIPT_MISSING = "RECEIPT_MISSING"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    GRANT_NOT_YET_VALID = "GRANT_NOT_YET_VALID"
    KID_UNTRUSTED = "KID_UNTRUSTED"


@dataclass(frozen=True, slots=True)
class PermitUnavailable:
    """Why a live permit could not be resolved. Never carries authority."""

    reason_code: PermitResolutionReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ResolvedPermit:
    """A re-resolved permit plus the grant facts a caller needs for deadlines."""

    permit: AuthorizedPermit
    grant_expires_at: datetime
    grant_max_depth: ScanDepth
    issuer_kid: str


async def resolve_admitted_permit(
    session: AsyncSession,
    *,
    scan_run_id: str,
    trust: TrustedKeyStore,
    now: datetime,
) -> ResolvedPermit | PermitUnavailable:
    """Re-mint the permit for a committed ALLOW admission, or fail closed."""
    now = ensure_utc(now)

    run: ScanRun | None = await session.get(ScanRun, scan_run_id)
    if run is None:
        return PermitUnavailable(PermitResolutionReason.NO_ADMISSION, "no admission record")
    # Compared case-insensitively against the enum's own value: the column is
    # free text, and a mismatch here would fail an authorized scan closed.
    if (run.decision or "").strip().lower() != DecisionStatus.ALLOW.value.lower():
        return PermitUnavailable(
            PermitResolutionReason.ADMISSION_NOT_AUTHORIZED,
            f"admission decision is {run.decision}",
        )
    if run.status != ScanRunStatus.AUTHORIZED_ADMITTED.value:
        return PermitUnavailable(
            PermitResolutionReason.ADMISSION_NOT_AUTHORIZED, f"admission status is {run.status}"
        )
    if not run.grant_id or not run.canonical_target or not run.effective_depth:
        return PermitUnavailable(
            PermitResolutionReason.ADMISSION_NOT_AUTHORIZED, "admission record is incomplete"
        )

    grant = await GrantRepository(session).get_by_grant_id(run.grant_id)
    if grant is None:
        return PermitUnavailable(PermitResolutionReason.RECEIPT_MISSING, "grant receipt not found")

    # Liveness. A committed admission is not a standing authorization.
    if ensure_utc(grant.expires_at) <= now:
        return PermitUnavailable(PermitResolutionReason.GRANT_EXPIRED, "grant has expired")
    if ensure_utc(grant.not_before) > now:
        return PermitUnavailable(PermitResolutionReason.GRANT_NOT_YET_VALID, "grant is not yet valid")
    if grant.issuer_kid not in trust.trusted_kids:
        return PermitUnavailable(
            PermitResolutionReason.KID_UNTRUSTED,
            f"signer {grant.issuer_kid} is no longer trusted",
        )

    try:
        effective_depth = ScanDepth(run.effective_depth)
        grant_max_depth = ScanDepth(grant.max_scan_depth)
    except ValueError:
        return PermitUnavailable(PermitResolutionReason.ADMISSION_NOT_AUTHORIZED, "depth value unrecognized")

    # Defence in depth: the recorded effective depth can never exceed the
    # grant's own ceiling, whatever the admission row says.
    effective_depth = ScanDepth.clamp(effective_depth, grant_max_depth)

    audit_row = await AuditRepository(session).get_by_scan_run_id(scan_run_id)

    permit = mint_permit(
        scan_run_id=run.scan_run_id,
        grant_id=run.grant_id,
        canonical_target=run.canonical_target,
        effective_scan_depth=effective_depth,
        claims_digest=grant.claims_digest,
        scope_policy_version=run.scope_policy_version or grant.scope_policy_version,
        admitted_at=ensure_utc(run.decided_at),
        audit_event_id=audit_row.event_id if audit_row is not None else "",
    )
    return ResolvedPermit(
        permit=permit,
        grant_expires_at=ensure_utc(grant.expires_at),
        grant_max_depth=grant_max_depth,
        issuer_kid=grant.issuer_kid,
    )
