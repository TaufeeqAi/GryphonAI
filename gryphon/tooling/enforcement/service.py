"""Tool execution service — the transport-agnostic enforcement + saga.

Implements the normative sequence: verify/normalize the credential, re-derive
the authorized scope from the grant receipt, evaluate scope + depth + descriptor
policy, acquire an aggregate budget, resolve-and-pin the destination, establish
an OS egress context, commit a durable intent record, run the pinned binary, and
commit the outcome + signed audit. No target traffic precedes the intent commit;
UNKNOWN is never success.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from gryphon.auth.results import AuthorizedPermit
from gryphon.auth.scope import (
    CanonicalTarget,
    ScopeResult,
    canonicalize_path,
    canonicalize_target,
    evaluate,
)
from gryphon.clock import Clock
from gryphon.constants import ScanDepth
from gryphon.db.repositories.capability_consumption import CapabilityConsumptionRepository
from gryphon.db.repositories.tool_audit import ToolInvocationAuditRepository
from gryphon.db.repositories.tool_execution import ToolExecutionRepository
from gryphon.db.session import Database
from gryphon.errors import ScopeEvaluationError
from gryphon.logging_config import get_logger
from gryphon.tooling.audit.builder import SignedToolAuditEvent, ToolAuditBuilder
from gryphon.tooling.capability.verifier import CapabilityFailure, CapabilityVerifier
from gryphon.tooling.constants import (
    MAX_RESULT_RECORDS,
    CredentialSource,
    ExecutionState,
    TargetContactState,
    ToolId,
    ToolOutcome,
)
from gryphon.tooling.destination.egress import EgressEnforcer, EgressHandle
from gryphon.tooling.destination.guard import DestinationDenied, DestinationGuard, PinnedDestinations
from gryphon.tooling.enforcement.budgets import BudgetManager
from gryphon.tooling.enforcement.credential import (
    AdmittedReference,
    from_permit,
    from_verified_capability,
)
from gryphon.tooling.enforcement.scope_provenance import ProvenanceFailure, rederive_scope
from gryphon.tooling.execution.aggregate import TargetOutcome, ToolExecutionResult
from gryphon.tooling.idutil import validate_execution_id
from gryphon.tooling.reasons import (
    EgressUnavailableError,
    EnforcementDenied,
    ToolReasonCode,
)
from gryphon.tooling.settings import ToolingSettings
from gryphon.tooling.tools.argbuilders import build_argv
from gryphon.tooling.tools.catalog import build_result, descriptor_for
from gryphon.tooling.tools.runner import SafeSubprocessRunner
from gryphon.tooling.tools.sanitize import parse_jsonl

logger = get_logger(__name__)


class BinaryResolver(Protocol):
    def resolve(self, tool_id: ToolId) -> str | None: ...


@dataclass
class _Gate:
    """Internal pre-flight decision (the gateway part of the service)."""

    admitted: AdmittedReference
    canonical_target: CanonicalTarget
    canonical_path: str | None
    effective_depth: ScanDepth
    scope_policy_version: str


class ToolExecutionService:
    def __init__(
        self,
        *,
        verifier: CapabilityVerifier,
        database: Database,
        clock: Clock,
        budgets: BudgetManager,
        destination_guard: DestinationGuard,
        egress_enforcer: EgressEnforcer,
        runner: SafeSubprocessRunner,
        audit_builder: ToolAuditBuilder,
        binary_resolver: BinaryResolver,
        settings: ToolingSettings,
    ) -> None:
        self._verifier = verifier
        self._db = database
        self._clock = clock
        self._budgets = budgets
        self._guard = destination_guard
        self._egress = egress_enforcer
        self._runner = runner
        self._audit = audit_builder
        self._bin = binary_resolver
        self._settings = settings

    # -- public entry points -------------------------------------------------
    async def execute_with_capability(
        self,
        capability_wire: bytes | str | dict,
        tool_id: ToolId,
        target: str,
        *,
        path: str | None = None,
        requested_depth: str | None = None,
    ) -> ToolExecutionResult:
        now = self._clock.now()
        verified = self._verifier.verify(capability_wire, tool_id, now)
        if isinstance(verified, CapabilityFailure):
            return await self._denial(
                scan_run_id=None,
                execution_id="«unverified»",
                tool_id=tool_id,
                reason_code=verified.reason_code,
                canonical_target=None,
            )
        admitted = from_verified_capability(verified)
        return await self._execute(admitted, tool_id, target, path, requested_depth)

    async def execute_with_permit(
        self,
        permit: AuthorizedPermit,
        tool_id: ToolId,
        execution_id: str,
        target: str,
        *,
        path: str | None = None,
        requested_depth: str | None = None,
    ) -> ToolExecutionResult:
        try:
            validate_execution_id(execution_id)
        except EnforcementDenied as exc:
            return await self._denial(
                scan_run_id=permit.scan_run_id,
                execution_id=execution_id,
                tool_id=tool_id,
                reason_code=exc.reason_code,
                canonical_target=None,
            )
        admitted = from_permit(permit, tool_id, execution_id)
        return await self._execute(admitted, tool_id, target, path, requested_depth)

    # -- shared pipeline -----------------------------------------------------
    async def _execute(
        self,
        admitted: AdmittedReference,
        tool_id: ToolId,
        target: str,
        path: str | None,
        requested_depth: str | None,
    ) -> ToolExecutionResult:
        # Pre-flight decision (verify/scope/depth/descriptor).
        gate = await self._decide(admitted, tool_id, target, path, requested_depth)
        if isinstance(gate, EnforcementDenied):
            return await self._denial(
                scan_run_id=admitted.scan_run_id,
                execution_id=admitted.execution_id,
                tool_id=tool_id,
                reason_code=gate.reason_code,
                canonical_target=None,
            )

        descriptor = descriptor_for(tool_id)

        # Idempotency pre-check: a known execution_id returns its stored outcome.
        try:
            async with self._db.session() as session:
                existing = await ToolExecutionRepository(session).get(admitted.execution_id)
        except (OperationalError, DBAPIError):
            return await self._denial(
                admitted.scan_run_id, admitted.execution_id, tool_id,
                ToolReasonCode.DB_UNAVAILABLE, gate.canonical_target.text,
            )
        if existing is not None:
            return self._result_from_record(existing, tool_id, replayed=True)

        # Aggregate budget (fail fast, never exhaust).
        if not self._budgets.breaker.allow(admitted.scan_run_id):
            return await self._denial(
                admitted.scan_run_id, admitted.execution_id, tool_id,
                ToolReasonCode.BREAKER_OPEN, gate.canonical_target.text,
            )
        try:
            async with self._budgets.lease(admitted.scan_run_id):
                return await self._run_within_budget(admitted, tool_id, gate, descriptor)
        except EnforcementDenied as exc:
            return await self._denial(
                admitted.scan_run_id, admitted.execution_id, tool_id,
                exc.reason_code, gate.canonical_target.text,
            )

    async def _run_within_budget(self, admitted, tool_id, gate, descriptor) -> ToolExecutionResult:
        if descriptor.is_passive:
            # Passive tools do not contact the target; they are allowlisted to
            # their declared external sources, not target-pinned (CHG-022).
            pinned = PinnedDestinations(
                target=gate.canonical_target.text, addresses=(), ports=()
            )
        else:
            # Destination bind (resolve + pin). No target traffic yet (DNS only).
            pinned = await self._guard.bind(gate.canonical_target, descriptor.required_ports)
            if isinstance(pinned, DestinationDenied):
                return await self._denial(
                    admitted.scan_run_id, admitted.execution_id, tool_id,
                    pinned.reason_code, gate.canonical_target.text,
                )

        # Establish the OS egress context, or fail closed.
        try:
            egress_handle = await self._egress.establish(list(pinned.addresses), list(pinned.ports))
        except EgressUnavailableError:
            return await self._denial(
                admitted.scan_run_id, admitted.execution_id, tool_id,
                ToolReasonCode.EGRESS_UNAVAILABLE, gate.canonical_target.text,
            )

        try:
            # Durable INTENT commit (+ CAS consume for the capability path).
            intent = await self._commit_intent(admitted, tool_id, gate, pinned)
            if isinstance(intent, ToolExecutionResult):
                return intent  # replay / conflict / operational failure

            # Side effect: run the pinned binary inside the egress context.
            result = await self._run_tool(admitted, tool_id, gate, descriptor, egress_handle)
            return result
        finally:
            await self._egress.teardown(egress_handle)

    # -- decision ------------------------------------------------------------
    async def _decide(
        self, admitted, tool_id, target, path, requested_depth
    ) -> _Gate | EnforcementDenied:
        try:
            descriptor_for(tool_id)
        except Exception:
            return EnforcementDenied(ToolReasonCode.DESCRIPTOR_MISSING)

        # Canonicalize target/path with the authorization core's policy v1.
        try:
            ctarget = canonicalize_target(target)
            cpath = canonicalize_path(path) if path is not None else None
        except ScopeEvaluationError as exc:
            return EnforcementDenied(exc.reason_code)

        # Depth: requested clamped to the credential's effective depth.
        if requested_depth is None:
            requested = admitted.effective_scan_depth
        else:
            try:
                requested = ScanDepth(requested_depth)
            except ValueError:
                return EnforcementDenied(ToolReasonCode.DEPTH_INVALID)
        effective = ScanDepth.clamp(requested, admitted.effective_scan_depth)

        # Re-derive authorized scope from the grant receipt (grant-rooted).
        try:
            async with self._db.session() as session:
                prov = await rederive_scope(
                    session,
                    grant_id=admitted.grant_id,
                    expected_claims_digest=admitted.claims_digest,
                    expected_scope_digest=admitted.scope_digest,
                )
        except (OperationalError, DBAPIError):
            return EnforcementDenied(ToolReasonCode.DB_UNAVAILABLE)
        if isinstance(prov, ProvenanceFailure):
            return EnforcementDenied(prov.reason_code)

        # Clamp depth against the grant's own maximum (defense in depth).
        effective = ScanDepth.clamp(effective, prov.grant_max_depth)

        # Scope membership against the re-derived scope; exclusions win.
        decision = evaluate(prov.scope_entries, ctarget, cpath)
        if decision.result is ScopeResult.NO_MATCH:
            return EnforcementDenied(ToolReasonCode.SCOPE_NO_MATCH)
        if decision.result is ScopeResult.EXCLUDED:
            return EnforcementDenied(ToolReasonCode.SCOPE_EXCLUDED)
        if decision.result is ScopeResult.INVALID_INPUT:
            return EnforcementDenied(ToolReasonCode.SCOPE_INVALID_INPUT)

        return _Gate(
            admitted=admitted,
            canonical_target=ctarget,
            canonical_path=cpath,
            effective_depth=effective,
            scope_policy_version=prov.scope_policy_version,
        )

    # -- intent transaction --------------------------------------------------
    async def _commit_intent(
        self, admitted, tool_id, gate, pinned: PinnedDestinations
    ) -> SignedToolAuditEvent | ToolExecutionResult:
        now = self._clock.now()
        descriptor = descriptor_for(tool_id)
        pinned_summary = ",".join(pinned.addresses)
        intent_event = self._audit.intent(
            scan_run_id=admitted.scan_run_id,
            execution_id=admitted.execution_id,
            tool_id=tool_id,
            capability_id=admitted.capability_id,
            canonical_target=gate.canonical_target.text,
            pinned_summary=pinned_summary,
            effective_depth=gate.effective_depth.value,
            descriptor_version=descriptor.descriptor_version,
            external_disclosure=descriptor.is_passive,
            timestamp=now,
        )
        try:
            async with self._db.session() as session:
                async with session.begin():
                    if admitted.source is CredentialSource.CAPABILITY and admitted.capability_id:
                        CapabilityConsumptionRepository(session).stage(
                            capability_id=admitted.capability_id,
                            nonce=admitted.nonce or "",
                            scan_run_id=admitted.scan_run_id,
                            execution_id=admitted.execution_id,
                            expires_at=admitted.capability_expires_at or now,
                        )
                    ToolExecutionRepository(session).add(
                        execution_id=admitted.execution_id,
                        scan_run_id=admitted.scan_run_id,
                        tool_id=tool_id.value,
                        credential_source=admitted.source.value,
                        state=ExecutionState.ADMITTED.value,
                        intent_committed_at=now,
                        capability_id=admitted.capability_id,
                        canonical_target=gate.canonical_target.text,
                        pinned_destinations=list(pinned.addresses),
                        effective_depth=gate.effective_depth.value,
                    )
                    ToolInvocationAuditRepository(session).append(
                        event_id=intent_event.event_id,
                        event_type="intent",
                        event_schema_version=intent_event.payload["event_schema_version"],
                        scan_run_id=admitted.scan_run_id,
                        execution_id=admitted.execution_id,
                        tool_id=tool_id.value,
                        payload=intent_event.payload,
                        payload_digest=intent_event.payload_digest,
                        signer_kid=intent_event.signer_kid,
                        signature=intent_event.signature_b64,
                        capability_id=admitted.capability_id,
                        decision="ALLOW",
                        reason_code=ToolReasonCode.ADMITTED.value,
                        canonical_target=gate.canonical_target.text,
                        pinned_destinations_summary=pinned_summary,
                        external_disclosure=descriptor.is_passive,
                        descriptor_version=descriptor.descriptor_version,
                    )
            logger.info(
                "tool_execution_admitted",
                scan_run_id=admitted.scan_run_id,
                execution_id=admitted.execution_id,
                tool_id=tool_id.value,
            )
            return intent_event
        except IntegrityError:
            # A concurrent/duplicate capability or execution_id won the race.
            async with self._db.session() as session:
                existing = await ToolExecutionRepository(session).get(admitted.execution_id)
            if existing is not None:
                return self._result_from_record(existing, tool_id, replayed=True)
            return await self._denial(
                admitted.scan_run_id, admitted.execution_id, tool_id,
                ToolReasonCode.CAPABILITY_REPLAYED, gate.canonical_target.text,
            )
        except (OperationalError, DBAPIError):
            # No subprocess has run; no target traffic occurred.
            return await self._denial(
                admitted.scan_run_id, admitted.execution_id, tool_id,
                ToolReasonCode.INTENT_COMMIT_FAILED, gate.canonical_target.text,
            )

    # -- run + outcome -------------------------------------------------------
    async def _run_tool(
        self, admitted, tool_id, gate, descriptor, egress_handle: EgressHandle
    ) -> ToolExecutionResult:
        binary_path = self._bin.resolve(tool_id)
        now = self._clock.now()
        if binary_path is None:
            return await self._finalize(
                admitted, tool_id, gate, ToolOutcome.FAILED,
                ToolReasonCode.READINESS_FAILED, None, False, False,
            )

        argv = build_argv(tool_id, descriptor, gate.canonical_target.text, gate.effective_depth)
        run = await self._runner.run(
            binary_path=binary_path,
            argv=argv,
            timeout_seconds=min(descriptor.timeout_seconds, self._settings.subprocess_default_timeout_seconds),
            egress_handle=egress_handle,
        )

        if run.outcome is ToolOutcome.TIMED_OUT:
            self._budgets.breaker.record_failure(admitted.scan_run_id)
            return await self._finalize(
                admitted, tool_id, gate, ToolOutcome.TIMED_OUT,
                ToolReasonCode.TOOL_TIMED_OUT, None, False, False,
            )
        if run.outcome is ToolOutcome.FAILED:
            self._budgets.breaker.record_failure(admitted.scan_run_id)
            return await self._finalize(
                admitted, tool_id, gate, ToolOutcome.FAILED,
                ToolReasonCode.TOOL_FAILED, None, False, False,
            )

        parsed = parse_jsonl(run.stdout, max_records=MAX_RESULT_RECORDS)
        self._budgets.breaker.record_success(admitted.scan_run_id)
        result_model = build_result(tool_id, gate.canonical_target.text, parsed)
        degraded = parsed.degraded
        truncated = run.stdout_truncated or parsed.truncated
        reason = ToolReasonCode.OUTPUT_DEGRADED if degraded else ToolReasonCode.COMPLETED
        return await self._finalize(
            admitted, tool_id, gate,
            ToolOutcome.COMPLETED if not degraded else ToolOutcome.FAILED,
            reason, result_model, truncated, degraded, record_count=1,
        )

    async def _finalize(
        self, admitted, tool_id, gate, outcome: ToolOutcome, reason: ToolReasonCode,
        result_model, truncated: bool, degraded: bool, record_count: int | None = None,
    ) -> ToolExecutionResult:
        now = self._clock.now()
        per_target = [{"target": gate.canonical_target.text,
                       "state": (TargetContactState.CONTACTED.value if not descriptor_for(tool_id).is_passive
                                 else TargetContactState.NOT_CONTACTED.value)}]
        outcome_event = self._audit.outcome(
            scan_run_id=admitted.scan_run_id,
            execution_id=admitted.execution_id,
            tool_id=tool_id,
            outcome=outcome,
            reason_code=reason.value,
            record_count=record_count,
            timestamp=now,
        )
        state_map = {
            ToolOutcome.COMPLETED: ExecutionState.COMPLETED,
            ToolOutcome.TIMED_OUT: ExecutionState.TIMED_OUT,
            ToolOutcome.FAILED: ExecutionState.FAILED,
            ToolOutcome.UNKNOWN: ExecutionState.UNKNOWN,
        }
        audit_event_id = outcome_event.event_id
        try:
            async with self._db.session() as session:
                async with session.begin():
                    row = await ToolExecutionRepository(session).get(admitted.execution_id)
                    if row is not None:
                        ToolExecutionRepository.apply_outcome(
                            row,
                            state=state_map.get(outcome, ExecutionState.FAILED).value,
                            outcome=outcome.value,
                            reason_code=reason.value,
                            outcome_at=now,
                            record_count=record_count,
                            per_target=per_target,
                            truncated=truncated,
                            degraded=degraded,
                        )
                    ToolInvocationAuditRepository(session).append(
                        event_id=outcome_event.event_id,
                        event_type="outcome",
                        event_schema_version=outcome_event.payload["event_schema_version"],
                        scan_run_id=admitted.scan_run_id,
                        execution_id=admitted.execution_id,
                        tool_id=tool_id.value,
                        payload=outcome_event.payload,
                        payload_digest=outcome_event.payload_digest,
                        signer_kid=outcome_event.signer_kid,
                        signature=outcome_event.signature_b64,
                        capability_id=admitted.capability_id,
                        outcome=outcome.value,
                        reason_code=reason.value,
                        canonical_target=gate.canonical_target.text,
                    )
        except (OperationalError, DBAPIError):
            # Side effect happened; the committed intent record proves possible
            # traffic. The observable outcome is UNKNOWN, never success.
            logger.warning("tool_outcome_commit_unknown", execution_id=admitted.execution_id)
            return ToolExecutionResult(
                scan_run_id=admitted.scan_run_id,
                execution_id=admitted.execution_id,
                tool_id=tool_id,
                outcome=ToolOutcome.UNKNOWN,
                reason_code=ToolReasonCode.COMMIT_OUTCOME_UNKNOWN.value,
                audit_event_id=None,
            )

        records = (result_model,) if (outcome is ToolOutcome.COMPLETED and result_model is not None) else ()
        return ToolExecutionResult(
            scan_run_id=admitted.scan_run_id,
            execution_id=admitted.execution_id,
            tool_id=tool_id,
            outcome=outcome,
            reason_code=reason.value,
            records=records,
            per_target=tuple(
                TargetOutcome(target=pt["target"], state=TargetContactState(pt["state"]))
                for pt in per_target
            ),
            truncated=truncated,
            degraded=degraded,
            audit_event_id=audit_event_id,
        )

    # -- helpers -------------------------------------------------------------
    async def _denial(
        self, scan_run_id: str | None, execution_id: str, tool_id: ToolId,
        reason_code: ToolReasonCode, canonical_target: str | None,
    ) -> ToolExecutionResult:
        now = self._clock.now()
        if scan_run_id is not None:
            event = self._audit.denial(
                scan_run_id=scan_run_id,
                execution_id=execution_id,
                tool_id=tool_id,
                reason_code=reason_code.value,
                canonical_target=canonical_target,
                timestamp=now,
            )
            try:
                async with self._db.session() as session:
                    async with session.begin():
                        ToolInvocationAuditRepository(session).append(
                            event_id=event.event_id,
                            event_type="outcome",
                            event_schema_version=event.payload["event_schema_version"],
                            scan_run_id=scan_run_id,
                            execution_id=execution_id,
                            tool_id=tool_id.value,
                            payload=event.payload,
                            payload_digest=event.payload_digest,
                            signer_kid=event.signer_kid,
                            signature=event.signature_b64,
                            decision="DENY",
                            reason_code=reason_code.value,
                            outcome=ToolOutcome.DENIED.value,
                            canonical_target=canonical_target,
                        )
            except (OperationalError, DBAPIError, IntegrityError):
                logger.warning("denial_audit_unavailable", reason_code=reason_code.value)
        logger.info("tool_execution_denied", execution_id=execution_id, reason_code=reason_code.value)
        return ToolExecutionResult(
            scan_run_id=scan_run_id,
            execution_id=execution_id,
            tool_id=tool_id,
            outcome=ToolOutcome.DENIED,
            reason_code=reason_code.value,
        )

    def _result_from_record(self, row, tool_id: ToolId, *, replayed: bool) -> ToolExecutionResult:
        try:
            outcome = ToolOutcome(row.outcome) if row.outcome else ToolOutcome.UNKNOWN
        except ValueError:
            outcome = ToolOutcome.UNKNOWN
        return ToolExecutionResult(
            scan_run_id=row.scan_run_id,
            execution_id=row.execution_id,
            tool_id=tool_id,
            outcome=outcome,
            reason_code=row.reason_code or ToolReasonCode.ADMITTED.value,
            truncated=bool(row.truncated),
            degraded=bool(row.degraded),
            replayed=replayed,
        )
