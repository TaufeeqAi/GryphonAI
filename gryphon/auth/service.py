"""Authorization decision and scan admission (BND-05).

This is the ONLY Phase 1 decision authority (§12). It implements the normative
admission sequence (§9.2): idempotency lookup → JWS verification → target/path
canonicalization → issuance-receipt match → scope evaluation → depth clamp →
one atomic ``scan_runs`` + signed-audit transaction → typed result.

Invariants enforced here:

* ALLOW is impossible until the scan-run and audit rows commit; the permit is
  minted only post-commit (SEC-010 / INV-012).
* UNKNOWN is never success and never a permit (SEC-011 / INV-013).
* A replayed idempotency key returns a non-executable receipt, never a second
  admission (INV-014); a different request hash conflicts (INV-015).
* No caller boolean, deserialized grant or cache can create ALLOW (SEC-009/015).
"""

from __future__ import annotations

import asyncio
import random
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.auth.audit_signer import AuditSigner
from gryphon.auth.authorization_token import GrantVerifier, VerificationFailure
from gryphon.auth.idempotency import (
    hash_idempotency_key,
    scan_request_hash,
    validate_idempotency_key,
)
from gryphon.auth.results import (
    AdmissionReplayReceipt,
    AuthorizationResult,
    DeniedDecision,
    UnknownOutcome,
    mint_permit,
)
from gryphon.auth.scope import (
    CanonicalTarget,
    ScopeResult,
    canonicalize_path,
    canonicalize_target,
    evaluate,
)
from gryphon.clock import Clock
from gryphon.constants import DecisionStatus, ScanDepth, ScanRunStatus
from gryphon.db.errors import classify, is_unique_violation
from gryphon.db.repositories.audit import AuditRepository
from gryphon.db.repositories.grants import GrantRepository
from gryphon.db.repositories.scan_runs import ScanRunRepository
from gryphon.db.session import Database
from gryphon.errors import (
    IdempotencyConflictError,
    ReasonCode,
    ScopeEvaluationError,
    ValidationError,
)
from gryphon.logging_config import get_logger
from gryphon.settings import Settings

logger = get_logger(__name__)

_MAX_DISPLAY_CHARS = 256


@dataclass(frozen=True)
class ScanAdmissionRequest:
    """A bounded scan-admission request (§9.2.1).

    ``requested_depth`` is the raw requested value. A missing value is defaulted
    to ``standard`` ONLY by the trusted API/CLI adapter, never in the core (§11.6).
    """

    target: str
    token: str
    requested_depth: str
    idempotency_key: str
    path: str | None = None


@dataclass
class _Decision:
    status: DecisionStatus
    reason_code: ReasonCode
    authorization_valid: bool
    scope_check_passed: bool
    grant_id: str | None = None
    claims_digest: str | None = None
    canonical_target: str | None = None
    canonical_path: str | None = None
    effective_depth: ScanDepth | None = None
    requested_by: str | None = None
    organization: str | None = None
    scope_policy_version: str | None = None


def _safe_display(value: str | None) -> str | None:
    """Bounded, control-char-free representation for storage (§21.1 / §22.1)."""
    if value is None:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        from gryphon.canonical import sha256_hex_text

        return f"<nonprintable:sha256:{sha256_hex_text(value)[:16]}>"
    if len(value) > _MAX_DISPLAY_CHARS:
        from gryphon.canonical import sha256_hex_text

        return value[:_MAX_DISPLAY_CHARS] + f"…<sha256:{sha256_hex_text(value)[:16]}>"
    return value


class AuthorizationService:
    """Coordinates verification, scope, receipt lookup and atomic admission."""

    def __init__(
        self,
        *,
        verifier: GrantVerifier,
        audit_signer: AuditSigner,
        database: Database,
        settings: Settings,
        clock: Clock,
    ) -> None:
        self._verifier = verifier
        self._audit = audit_signer
        self._db = database
        self._settings = settings
        self._clock = clock

    # -- public API ----------------------------------------------------------
    async def authorize_scan(self, request: ScanAdmissionRequest) -> AuthorizationResult:
        """Admit or deny one scan request; return a typed result (§11.4)."""
        # The idempotency key must be valid to key any outcome at all; without a
        # usable key we cannot record a denial, so this is an operational reject.
        validate_idempotency_key(request.idempotency_key)
        key_hash = hash_idempotency_key(request.idempotency_key)
        req_hash = scan_request_hash(
            token=request.token,
            target=request.target,
            path=request.path,
            requested_depth=request.requested_depth,
        )

        attempts = self._settings.db_max_retries + 1
        for attempt in range(attempts):
            try:
                return await self._attempt(request, key_hash, req_hash)
            except IdempotencyConflictError:
                raise
            except IntegrityError as exc:
                if is_unique_violation(exc):
                    replay = await self._reconcile_replay(key_hash, req_hash)
                    if replay is not None:
                        return replay
                    raise IdempotencyConflictError("idempotency key reused with different request")
                raise
            except (OperationalError, DBAPIError) as exc:
                reason, retryable = classify(exc)
                if retryable and attempt < attempts - 1:
                    await asyncio.sleep(self._backoff(attempt))
                    continue
                # Commit may have succeeded then the response/connection was lost.
                replay = await self._safe_reconcile_replay(key_hash, req_hash)
                if replay is not None:
                    return replay
                logger.warning("admission_unresolved", reason_code=reason.value)
                return UnknownOutcome(
                    scan_run_id=None, reason_code=reason, retry_after_reconciliation=True
                )

        # Unreachable: loop either returns or raises.
        return UnknownOutcome(
            scan_run_id=None,
            reason_code=ReasonCode.COMMIT_OUTCOME_UNKNOWN,
            retry_after_reconciliation=True,
        )

    # -- one attempt (single transaction) ------------------------------------
    async def _attempt(
        self, request: ScanAdmissionRequest, key_hash: str, req_hash: str
    ) -> AuthorizationResult:
        now = self._clock.now()
        async with self._db.session() as session:
            async with session.begin():
                scan_runs = ScanRunRepository(session)

                # (§9.2.3) Idempotency lookup before any mutation.
                existing = await scan_runs.get_by_idempotency_hash(key_hash)
                if existing is not None:
                    if existing.request_hash != req_hash:
                        raise IdempotencyConflictError("same key, different request")
                    audit = await AuditRepository(session).get_by_scan_run_id(existing.scan_run_id)
                    logger.info("admission_replay", scan_run_id=existing.scan_run_id)
                    return AdmissionReplayReceipt(
                        scan_run_id=existing.scan_run_id,
                        stored_status=existing.status,
                        audit_event_id=audit.event_id if audit else None,
                    )

                # Compute the decision (pure verify/scope + receipt read in-tx).
                decision = await self._compute_decision(session, request, now)

                scan_run_id = str(uuid.uuid4())
                is_allow = decision.status is DecisionStatus.ALLOW
                status = (
                    ScanRunStatus.AUTHORIZED_ADMITTED
                    if is_allow
                    else ScanRunStatus.DENIED_AUDITED
                )

                audit_event = self._audit.sign_scan_admission(
                    scan_run_id=scan_run_id,
                    decision=decision.status,
                    reason_code=decision.reason_code,
                    authorization_valid=decision.authorization_valid,
                    scope_check_passed=decision.scope_check_passed,
                    target_requested=_safe_display(request.target),
                    canonical_target=decision.canonical_target,
                    path_requested=_safe_display(request.path),
                    grant_id=decision.grant_id,
                    requested_by=decision.requested_by,
                    organization=decision.organization,
                    scope_policy_version=decision.scope_policy_version,
                    timestamp=now,
                )

                scan_runs.add(
                    scan_run_id=scan_run_id,
                    decision=decision.status,
                    status=status,
                    reason_code=decision.reason_code,
                    idempotency_key_hash=key_hash,
                    request_hash=req_hash,
                    decided_at=now,
                    grant_id=decision.grant_id,
                    target_requested=_safe_display(request.target),
                    canonical_target=decision.canonical_target,
                    path_requested=_safe_display(request.path),
                    canonical_path=decision.canonical_path,
                    requested_depth=request.requested_depth,
                    effective_depth=(
                        decision.effective_depth.value if decision.effective_depth else None
                    ),
                    scope_policy_version=decision.scope_policy_version,
                )
                # Flush the scan_run BEFORE the audit insert so the audit FK
                # (scan_run_id -> scan_runs) is satisfied. This is a flush within
                # the open transaction, not a commit: atomicity is preserved —
                # both rows still commit together or not at all (§22.2).
                await session.flush()
                AuditRepository(session).append_admission(
                    audit_event,
                    decision=decision.status,
                    reason_code=decision.reason_code,
                    authorization_valid=decision.authorization_valid,
                    scope_check_passed=decision.scope_check_passed,
                    target_requested=_safe_display(request.target),
                    canonical_target=decision.canonical_target,
                    path_requested=_safe_display(request.path),
                    grant_id=decision.grant_id,
                    requested_by=decision.requested_by,
                    organization=decision.organization,
                    scope_policy_version=decision.scope_policy_version,
                )

                # Build the result inside the transaction, but do not return it
                # until the block exits and the commit has succeeded (SEC-010).
                if is_allow:
                    result: AuthorizationResult = mint_permit(
                        scan_run_id=scan_run_id,
                        grant_id=decision.grant_id or "",
                        canonical_target=decision.canonical_target or "",
                        effective_scan_depth=decision.effective_depth or ScanDepth.PASSIVE,
                        claims_digest=decision.claims_digest or "",
                        scope_policy_version=decision.scope_policy_version or "",
                        admitted_at=now,
                        audit_event_id=audit_event.event_id,
                    )
                else:
                    result = DeniedDecision(
                        scan_run_id=scan_run_id,
                        reason_code=decision.reason_code,
                        audit_event_id=audit_event.event_id,
                    )

            # Transaction committed: only now is the outcome observable.
            logger.info(
                "admission_allow" if is_allow else "admission_deny",
                scan_run_id=scan_run_id,
                grant_id=decision.grant_id,
                audit_event_id=audit_event.event_id,
                reason_code=decision.reason_code.value,
            )
            return result

    # -- decision computation ------------------------------------------------
    async def _compute_decision(
        self, session: AsyncSession, request: ScanAdmissionRequest, now: datetime
    ) -> _Decision:
        # 1) Verify the token (pure, fail-closed).
        verified = self._verifier.verify(request.token, now)
        if isinstance(verified, VerificationFailure):
            return _Decision(
                status=DecisionStatus.DENY,
                reason_code=verified.reason_code,
                authorization_valid=False,
                scope_check_passed=False,
            )
        claims = verified.claims

        # 2) Canonicalize target/path (pure, fail-closed on ambiguity).
        try:
            canonical_target: CanonicalTarget = canonicalize_target(request.target)
            canonical_path = (
                canonicalize_path(request.path) if request.path is not None else None
            )
        except ScopeEvaluationError as exc:
            return _Decision(
                status=DecisionStatus.DENY,
                reason_code=exc.reason_code,
                authorization_valid=False,
                scope_check_passed=False,
                grant_id=claims.grant_id,
                claims_digest=verified.claims_digest,
                requested_by=claims.granted_to,
                organization=claims.organization,
                scope_policy_version=claims.scope_policy_version,
            )

        # 3) Load and match the immutable issuance receipt (§9.2.9).
        receipt = await GrantRepository(session).get_by_grant_id(claims.grant_id)
        base = _Decision(
            status=DecisionStatus.DENY,
            reason_code=ReasonCode.INTERNAL_ERROR,
            authorization_valid=False,
            scope_check_passed=False,
            grant_id=claims.grant_id,
            claims_digest=verified.claims_digest,
            canonical_target=canonical_target.text,
            canonical_path=canonical_path,
            requested_by=claims.granted_to,
            organization=claims.organization,
            scope_policy_version=claims.scope_policy_version,
        )
        if receipt is None:
            base.reason_code = ReasonCode.RECEIPT_MISSING
            return base
        if (
            receipt.claims_digest != verified.claims_digest
            or receipt.issuer_kid != verified.signer_kid
            or receipt.scope_policy_version != claims.scope_policy_version
        ):
            base.reason_code = ReasonCode.RECEIPT_MISMATCH
            return base

        # 4) Scope evaluation (§9.2.10). Exclusions override positive matches.
        scope_decision = evaluate(claims.scope, canonical_target, canonical_path)
        if scope_decision.result is ScopeResult.NO_MATCH:
            base.reason_code = ReasonCode.SCOPE_NO_MATCH
            return base
        if scope_decision.result is ScopeResult.EXCLUDED:
            base.reason_code = ReasonCode.SCOPE_EXCLUDED
            return base

        # 5) Effective scan depth clamp (§9.2.11). Unknown requested value denies.
        try:
            requested_depth = ScanDepth(request.requested_depth)
        except ValueError:
            base.reason_code = ReasonCode.DEPTH_INVALID
            base.scope_check_passed = True  # scope matched; depth is what failed
            return base
        effective = ScanDepth.clamp(requested_depth, claims.max_scan_depth)

        # 6) ALLOW.
        return _Decision(
            status=DecisionStatus.ALLOW,
            reason_code=ReasonCode.ADMITTED,
            authorization_valid=True,
            scope_check_passed=True,
            grant_id=claims.grant_id,
            claims_digest=verified.claims_digest,
            canonical_target=canonical_target.text,
            canonical_path=canonical_path,
            effective_depth=effective,
            requested_by=claims.granted_to,
            organization=claims.organization,
            scope_policy_version=claims.scope_policy_version,
        )

    # -- reconciliation ------------------------------------------------------
    async def _reconcile_replay(
        self, key_hash: str, req_hash: str
    ) -> AdmissionReplayReceipt | None:
        """Fresh-session lookup after an uncertain outcome (§23.1)."""
        async with self._db.session() as session:
            existing = await ScanRunRepository(session).get_by_idempotency_hash(key_hash)
            if existing is None or existing.request_hash != req_hash:
                return None
            audit = await AuditRepository(session).get_by_scan_run_id(existing.scan_run_id)
            return AdmissionReplayReceipt(
                scan_run_id=existing.scan_run_id,
                stored_status=existing.status,
                audit_event_id=audit.event_id if audit else None,
            )

    async def _safe_reconcile_replay(
        self, key_hash: str, req_hash: str
    ) -> AdmissionReplayReceipt | None:
        try:
            return await self._reconcile_replay(key_hash, req_hash)
        except (OperationalError, DBAPIError):
            return None  # DB still unreachable; remain UNKNOWN

    @staticmethod
    def _backoff(attempt: int) -> float:
        base = 0.05 * (2**attempt)
        return min(base + random.uniform(0, 0.05), 1.0)  # noqa: S311 - jitter, not crypto
