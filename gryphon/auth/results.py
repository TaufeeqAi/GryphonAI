"""Authorization decision result types (§11.4).

Only the Authorization Service may mint an :class:`AuthorizedPermit`, and only
after the scan-run + audit transaction commits. The permit is an in-process,
immutable object — never a cross-process capability or wire token (§9.3). Caller
JSON cannot deserialize one (SEC-015 / INV-022): construction requires a
module-private guard object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from gryphon.constants import ScanDepth
from gryphon.errors import ReasonCode

_PERMIT_GUARD = object()


@dataclass(frozen=True)
class AuthorizedPermit:
    """Proof of a committed ALLOW admission. Mintable only post-commit."""

    scan_run_id: str
    grant_id: str
    canonical_target: str
    effective_scan_depth: ScanDepth
    claims_digest: str
    scope_policy_version: str
    admitted_at: datetime
    audit_event_id: str
    _guard: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._guard is not _PERMIT_GUARD:
            raise TypeError("AuthorizedPermit may only be minted by the Authorization Service")


def mint_permit(
    *,
    scan_run_id: str,
    grant_id: str,
    canonical_target: str,
    effective_scan_depth: ScanDepth,
    claims_digest: str,
    scope_policy_version: str,
    admitted_at: datetime,
    audit_event_id: str,
) -> AuthorizedPermit:
    """Internal factory. Imported only by the Authorization Service."""
    return AuthorizedPermit(
        scan_run_id=scan_run_id,
        grant_id=grant_id,
        canonical_target=canonical_target,
        effective_scan_depth=effective_scan_depth,
        claims_digest=claims_digest,
        scope_policy_version=scope_policy_version,
        admitted_at=admitted_at,
        audit_event_id=audit_event_id,
        _guard=_PERMIT_GUARD,
    )


@dataclass(frozen=True)
class DeniedDecision:
    """A committed DENY admission."""

    scan_run_id: str
    reason_code: ReasonCode
    audit_event_id: str | None


@dataclass(frozen=True)
class UnknownOutcome:
    """An uncertain outcome. NEVER a permit; never protected work (§15)."""

    scan_run_id: str | None
    reason_code: ReasonCode
    retry_after_reconciliation: bool


@dataclass(frozen=True)
class AdmissionReplayReceipt:
    """An observation of a prior admission (§11.4).

    Deliberately carries no permit and cannot start work. Returned when the same
    idempotency key + request hash is replayed.
    """

    scan_run_id: str
    stored_status: str
    audit_event_id: str | None


#: The full set of possible admission results.
AuthorizationResult = (
    AuthorizedPermit | DeniedDecision | UnknownOutcome | AdmissionReplayReceipt
)
