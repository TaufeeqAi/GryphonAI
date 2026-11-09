"""The authority touchpoint — the one place the live permit is reached.

Every protected call in this layer goes through here. Concentrating authority in
a single function buys three things that a permit passed around between nodes
cannot:

* **Authorization is a precondition, not a position.** The pipeline's entry gate
  is a topological check: it runs once, at the start of a graph. But an
  authorization is a *window*, and a scan can easily outlive it — a long run, a
  rate-limited target, a resume hours later. Checking here, immediately before
  each call, means a scan physically cannot outrun its grant. It also means
  strengthening authorization later (per-stage consent, tighter windows) is an
  additive change to one function instead of new graph edges.
* **Both credential paths get the same check.** The enforcement layer attaches
  its liveness re-check to minting a cross-process capability. The in-process
  path mints nothing, so without a deliberate check here that path would skip
  revocation and expiry entirely — and the in-process path is the one a
  single-host deployment uses by default. One predicate, both paths, recorded
  per call.
* **Authority has a minimum lifetime.** The permit is resolved per call and
  dropped when the call returns. It is never stored in graph state, never
  cached across a stage, and never held across an await that does not need it.

The deadline rule is per-item rather than a global safety margin: a call is
dispatched only if ``now + the tool's own hard deadline`` still falls inside the
grant. A dispatched tool cannot be recalled when authorization ends — only
killed — so the question that matters is whether *this* call can finish in time,
not whether the scan as a whole started early enough.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.auth.permit_resolver import (
    PermitUnavailable,
    ResolvedPermit,
    resolve_admitted_permit,
)
from gryphon.clock import Clock, ensure_utc
from gryphon.db.session import Database
from gryphon.logging_config import get_logger
from gryphon.orchestration.reasons import (
    AuthorizationPreconditionFailed,
    OrchestrationReasonCode,
)
from gryphon.tooling.constants import CredentialSource, ToolId, ToolOutcome
from gryphon.tooling.enforcement.service import ToolExecutionService
from gryphon.tooling.execution.aggregate import ToolExecutionResult
from gryphon.tooling.tools.catalog import descriptor_for

logger = get_logger(__name__)

#: Reasons a resolution failure maps to, so the layer reports stable codes.
_RESOLUTION_REASONS: dict[str, OrchestrationReasonCode] = {
    "NO_ADMISSION": OrchestrationReasonCode.NO_ADMISSION,
    "ADMISSION_NOT_AUTHORIZED": OrchestrationReasonCode.ADMISSION_NOT_AUTHORIZED,
    "RECEIPT_MISSING": OrchestrationReasonCode.RECEIPT_MISMATCH,
    "GRANT_EXPIRED": OrchestrationReasonCode.GRANT_EXPIRED,
    "GRANT_NOT_YET_VALID": OrchestrationReasonCode.ADMISSION_NOT_AUTHORIZED,
    "KID_UNTRUSTED": OrchestrationReasonCode.KID_UNTRUSTED,
}


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """What a caller may know about the live authorization.

    Carries facts needed for planning and deadlines — never the permit itself,
    so a context can be logged or folded into a decision without leaking
    authority.
    """

    scan_run_id: str
    canonical_target: str
    effective_depth: str
    policy_version: str
    grant_expires_at: datetime

    def latest_dispatch_for(self, hard_deadline_seconds: float) -> datetime:
        """The last instant a call with this deadline may start."""
        return self.grant_expires_at - timedelta(seconds=hard_deadline_seconds)


class AuthorityTouchpoint:
    """Resolves authority, enforces the per-call precondition, and dispatches."""

    def __init__(
        self,
        *,
        database: Database,
        clock: Clock,
        grant_trust: TrustedKeyStore,
        execution_service: ToolExecutionService,
        credential_source: CredentialSource = CredentialSource.PERMIT,
    ) -> None:
        self._db = database
        self._clock = clock
        self._trust = grant_trust
        self._service = execution_service
        self._credential_source = credential_source

    @property
    def credential_path(self) -> str:
        """Which credential posture is in force. Recorded on every call.

        Exposed deliberately: this is a security-relevant deployment choice, and
        an abstraction that *hides* which of two postures is live is how a test
        suite goes green on the path that happens to be configured in CI while
        the other path skips a check.
        """
        return self._credential_source.value

    async def resolve(self, scan_run_id: str) -> ResolvedPermit:
        """Re-resolve the live permit, or raise a precondition failure.

        Raises rather than returns a union because no caller in this layer has a
        legitimate way to continue without authority.
        """
        now = self._clock.now()
        try:
            async with self._db.session() as session:
                resolution = await resolve_admitted_permit(
                    session, scan_run_id=scan_run_id, trust=self._trust, now=now
                )
        except (OperationalError, DBAPIError) as exc:
            raise AuthorizationPreconditionFailed(
                OrchestrationReasonCode.DB_UNAVAILABLE, "admission records unreachable"
            ) from exc

        if isinstance(resolution, PermitUnavailable):
            reason = _RESOLUTION_REASONS.get(
                resolution.reason_code.value,
                OrchestrationReasonCode.ADMISSION_NOT_AUTHORIZED,
            )
            logger.info(
                "authority_precondition_failed",
                scan_run_id=scan_run_id,
                reason_code=reason.value,
                detail=resolution.detail,
            )
            raise AuthorizationPreconditionFailed(reason, resolution.detail)
        return resolution

    async def context(self, scan_run_id: str) -> AuthorizationContext:
        """Resolve once to obtain planning facts, dropping the permit after."""
        resolved = await self.resolve(scan_run_id)
        return AuthorizationContext(
            scan_run_id=scan_run_id,
            canonical_target=resolved.permit.canonical_target,
            effective_depth=resolved.permit.effective_scan_depth.value,
            policy_version=resolved.permit.scope_policy_version,
            grant_expires_at=resolved.grant_expires_at,
        )

    def assert_within_window(
        self,
        *,
        resolved: ResolvedPermit,
        hard_deadline_seconds: float,
        now: datetime | None = None,
    ) -> None:
        """Refuse a call that could still be running after the grant expires."""
        instant = ensure_utc(now or self._clock.now())
        latest = resolved.grant_expires_at - timedelta(seconds=hard_deadline_seconds)
        if instant > latest:
            raise AuthorizationPreconditionFailed(
                OrchestrationReasonCode.AUTHORIZATION_WINDOW_EXCEEDED,
                f"a {hard_deadline_seconds:g}s call cannot complete before "
                f"{resolved.grant_expires_at.isoformat()}",
            )

    async def dispatch(
        self,
        *,
        scan_run_id: str,
        tool_id: ToolId,
        execution_id: str,
        canonical_target: str,
        path: str | None = None,
        requested_depth: str | None = None,
        timeout_override_seconds: float | None = None,
    ) -> ToolExecutionResult:
        """Run one protected call under a freshly checked authorization.

        The stored ``execution_id`` is passed through unchanged: it was derived
        once at plan commit and is never recomputed here. That is what makes a
        retry or a re-walked step return the recorded outcome instead of
        contacting the target a second time.
        """
        resolved = await self.resolve(scan_run_id)
        descriptor = descriptor_for(tool_id)
        hard_deadline = timeout_override_seconds or descriptor.timeout_seconds
        self.assert_within_window(resolved=resolved, hard_deadline_seconds=hard_deadline)

        logger.info(
            "protected_call_dispatch",
            scan_run_id=scan_run_id,
            tool_id=tool_id.value,
            execution_id=execution_id,
            credential_path=self.credential_path,
        )
        result = await self._service.execute_with_permit(
            resolved.permit,
            tool_id,
            execution_id,
            canonical_target,
            path=path,
            requested_depth=requested_depth,
        )
        logger.info(
            "protected_call_outcome",
            scan_run_id=scan_run_id,
            tool_id=tool_id.value,
            execution_id=execution_id,
            outcome=result.outcome.value,
            reason_code=result.reason_code,
            replayed=result.replayed,
            credential_path=self.credential_path,
        )
        return result

    async def recorded_outcome(
        self, *, scan_run_id: str, tool_id: ToolId, execution_id: str, canonical_target: str
    ) -> ToolExecutionResult:
        """Read back what the enforcement layer recorded for an identity.

        Used by reconciliation. Presenting a known identity returns its stored
        outcome and starts nothing, so this resolves uncertainty from recorded
        evidence rather than by contacting the target again to "find out".
        """
        return await self.dispatch(
            scan_run_id=scan_run_id,
            tool_id=tool_id,
            execution_id=execution_id,
            canonical_target=canonical_target,
        )


def is_indeterminate(result: ToolExecutionResult) -> bool:
    """Whether an outcome leaves open the possibility that traffic occurred."""
    return result.outcome is ToolOutcome.UNKNOWN
