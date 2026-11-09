"""The public surface: claim, run, settle.

``invoke`` is also ``resume``. There is one code path for starting a scan and
for continuing one, and it runs on every invocation — so the recovery path is
exercised constantly instead of being the rarely-run branch that is wrong when
it finally matters.

The sequence:

1. Resolve authority and derive the effective deadline, which the grant always
   wins.
2. Claim the scan under a **fenced lease**. A first claim, a takeover of an
   expired lease, or a refusal — never two owners executing.
3. Heartbeat in the background while the graph runs, so a live owner is not
   mistaken for a dead one.
4. Run the compiled graph. Covered work is re-walked as no-ops; pending work is
   dispatched.
5. Record the terminal state the report decided, fenced on the claim epoch.

A scan that is already terminal returns its recorded result marked
``replayed``, with the original timestamps. Idempotency and operational
semantics are different questions — "give me the same answer" and "tell me
about now" — and conflating them is how a weeks-old report gets presented as
today's.
"""

from __future__ import annotations

import asyncio
import os
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.logging_config import get_logger
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.constants import (
    GRAPH_VERSION,
    ClaimResult,
    ScanLifecycleState,
)
from gryphon.orchestration.graph import compile_graph
from gryphon.orchestration.identity import new_execution_salt
from gryphon.orchestration.ledger import (
    OrchestrationAuditRepository,
    ReportRepository,
    ScanLifecycleRepository,
)
from gryphon.orchestration.nodes.report import final_state_or_default
from gryphon.orchestration.reasons import (
    AuthorizationPreconditionFailed,
    OrchestrationReasonCode,
    StaleClaimError,
)
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.state import initial_state

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """The result of invoking a scan.

    Wide enough to express every state the system can actually be in, so a
    caller never has to query the ledger to find out what happened. A narrow
    return type is how consumers end up coupled to storage.
    """

    scan_run_id: str
    terminal_state: ScanLifecycleState
    reason_code: str
    claim_epoch: int
    report_id: str | None = None
    planned: int = 0
    covered: int = 0
    gaps: int = 0
    integrity: int = 0
    #: True when this call returned a previously recorded result rather than
    #: performing work. Carries the original timestamps.
    replayed: bool = False
    completed_at: datetime | None = None

    @property
    def executed(self) -> bool:
        return not self.replayed

    @property
    def is_clean_completion(self) -> bool:
        """Completed with every planned item accounted for."""
        return self.terminal_state is ScanLifecycleState.COMPLETED


def default_owner_id() -> str:
    """Identify this process as a lease holder."""
    return f"{socket.gethostname()}:{os.getpid()}"


class ScanOrchestrator:
    """Runs and resumes one scan at a time, under a fenced lease."""

    def __init__(
        self,
        *,
        runtime: ScanRuntime,
        audit: OrchestrationAuditBuilder | None = None,
        owner_id: str | None = None,
    ) -> None:
        self._runtime = runtime
        self._audit = audit or runtime.audit
        self._owner_id = owner_id or default_owner_id()

    @property
    def owner_id(self) -> str:
        return self._owner_id

    async def invoke(
        self, scan_run_id: str, *, initiated_by: str
    ) -> ScanOutcome:
        """Run or resume ``scan_run_id``. Never starts a second scan."""
        runtime = self._runtime

        # 1. Authority first, so an unauthorized or expired scan never even
        #    claims a lease. The gate node re-checks; this is the cheap refusal.
        try:
            resolved = await runtime.touchpoint.resolve(scan_run_id)
        except AuthorizationPreconditionFailed as exc:
            await self._audit_gate_denial(
                scan_run_id, exc.reason_code, initiated_by, exc.detail
            )
            return ScanOutcome(
                scan_run_id=scan_run_id,
                terminal_state=ScanLifecycleState.HALTED_UNAUTHORIZED,
                reason_code=exc.reason_code.value,
                claim_epoch=0,
            )

        deadline = runtime.effective_deadline(
            grant_expires_at=resolved.grant_expires_at
        )

        # 2. Claim under a fenced lease.
        try:
            async with runtime.database.session() as session:
                async with session.begin():
                    claim = await ScanLifecycleRepository(session).claim_start(
                        scan_run_id=scan_run_id,
                        owner_id=self._owner_id,
                        lease_seconds=runtime.settings.scan_lease_seconds,
                        initiated_by=initiated_by,
                        execution_salt=new_execution_salt(),
                        policy_version=resolved.permit.scope_policy_version,
                        graph_version=GRAPH_VERSION,
                        deadline_at=deadline,
                    )
        except (OperationalError, DBAPIError):
            return ScanOutcome(
                scan_run_id=scan_run_id,
                terminal_state=ScanLifecycleState.FAILED,
                reason_code=OrchestrationReasonCode.DB_UNAVAILABLE.value,
                claim_epoch=0,
            )

        if claim.result is ClaimResult.ALREADY_RUNNING:
            logger.info(
                "scan_already_running",
                scan_run_id=scan_run_id,
                lease_expires_at=str(claim.lease_expires_at),
            )
            return ScanOutcome(
                scan_run_id=scan_run_id,
                terminal_state=claim.state or ScanLifecycleState.RUNNING,
                reason_code=OrchestrationReasonCode.ALREADY_RUNNING.value,
                claim_epoch=claim.claim_epoch,
            )
        if claim.result is ClaimResult.ALREADY_TERMINAL:
            return await self._recorded_result(scan_run_id, claim.claim_epoch)

        await self._audit_scan_start(
            scan_run_id=scan_run_id,
            initiated_by=initiated_by,
            claim=claim,
            deadline=deadline,
            policy_version=resolved.permit.scope_policy_version,
        )
        if claim.result is ClaimResult.TAKEOVER:
            logger.warning(
                "scan_taken_over",
                scan_run_id=scan_run_id,
                claim_epoch=claim.claim_epoch,
                owner_id=self._owner_id,
            )

        # 3-5. Heartbeat while the graph runs, then settle.
        heartbeat = asyncio.create_task(
            self._heartbeat(scan_run_id, claim.claim_epoch)
        )
        try:
            return await self._run_graph(
                scan_run_id=scan_run_id,
                claim_epoch=claim.claim_epoch,
                initiated_by=initiated_by,
            )
        finally:
            heartbeat.cancel()
            # Await the cancellation so the task cannot renew a lease after the
            # owner has stopped working — a zombie heartbeat would keep an
            # abandoned scan looking alive and block the sweeper indefinitely.
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass

    async def _run_graph(
        self, *, scan_run_id: str, claim_epoch: int, initiated_by: str
    ) -> ScanOutcome:
        runtime = self._runtime
        compiled = compile_graph(runtime, initiated_by=initiated_by)
        state = initial_state(scan_run_id, claim_epoch)

        try:
            final = await compiled.ainvoke(state)
        except Exception as exc:  # a node raised: the scan fails, truthfully
            logger.exception(
                "scan_graph_failed", scan_run_id=scan_run_id, error=type(exc).__name__
            )
            await self._settle(
                scan_run_id,
                claim_epoch,
                ScanLifecycleState.FAILED,
                OrchestrationReasonCode.CONFIGURATION_INVALID.value,
            )
            return ScanOutcome(
                scan_run_id=scan_run_id,
                terminal_state=ScanLifecycleState.FAILED,
                reason_code=OrchestrationReasonCode.CONFIGURATION_INVALID.value,
                claim_epoch=claim_epoch,
            )

        terminal = _terminal_from(final)
        reason = str(final.get("reason_code") or OrchestrationReasonCode.OK.value)
        report_id = final.get("report_id")
        await self._settle(
            scan_run_id, claim_epoch, terminal, reason, report_id=report_id
        )
        return ScanOutcome(
            scan_run_id=scan_run_id,
            terminal_state=terminal,
            reason_code=reason,
            claim_epoch=claim_epoch,
            report_id=report_id,
            planned=int(final.get("planned_count", 0)),
            covered=int(final.get("covered_count", 0)),
            gaps=int(final.get("gap_count", 0)),
            integrity=int(final.get("integrity_count", 0)),
        )

    async def _heartbeat(self, scan_run_id: str, claim_epoch: int) -> None:
        """Renew the lease until cancelled, or stop if the claim is superseded."""
        interval = self._runtime.settings.scan_heartbeat_seconds
        lease = self._runtime.settings.scan_lease_seconds
        while True:
            await asyncio.sleep(interval)
            try:
                async with self._runtime.database.session() as session:
                    async with session.begin():
                        alive = await ScanLifecycleRepository(session).heartbeat(
                            scan_run_id=scan_run_id,
                            claim_epoch=claim_epoch,
                            lease_seconds=lease,
                        )
            except (OperationalError, DBAPIError):
                # A transient failure is not proof of loss; the lease has slack
                # for several missed beats before anyone may take over.
                continue
            if not alive:
                logger.warning(
                    "lease_lost", scan_run_id=scan_run_id, claim_epoch=claim_epoch
                )
                return

    async def _settle(
        self,
        scan_run_id: str,
        claim_epoch: int,
        state: ScanLifecycleState,
        reason_code: str,
        *,
        report_id: str | None = None,
    ) -> None:
        """Record the terminal (or non-terminal halt) state, fenced."""
        event = self._audit.lifecycle_transition(
            scan_run_id=scan_run_id,
            from_state=ScanLifecycleState.RUNNING.value,
            to_state=state.value,
            reason_code=reason_code,
            claim_epoch=claim_epoch,
            coverage=None,
            timestamp=self._runtime.clock.now(),
        )
        try:
            async with self._runtime.database.session() as session:
                async with session.begin():
                    await ScanLifecycleRepository(session).transition(
                        scan_run_id=scan_run_id,
                        claim_epoch=claim_epoch,
                        state=state,
                        reason_code=reason_code,
                        report_id=report_id,
                    )
                    OrchestrationAuditRepository(session).append(
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_schema_version=event.payload["event_schema_version"],
                        scan_run_id=scan_run_id,
                        decision="TRANSITION",
                        reason_code=reason_code,
                        claim_epoch=claim_epoch,
                        payload=event.payload,
                        payload_digest=event.payload_digest,
                        signer_kid=event.signer_kid,
                        signature=event.signature_b64,
                    )
        except StaleClaimError:
            # Another owner took over while we were working. Our fencing token
            # is dead, so our conclusion is not ours to record.
            logger.warning(
                "settle_refused_stale_claim",
                scan_run_id=scan_run_id,
                claim_epoch=claim_epoch,
            )
        except (OperationalError, DBAPIError):
            logger.warning("settle_failed", scan_run_id=scan_run_id)

    async def _recorded_result(
        self, scan_run_id: str, claim_epoch: int
    ) -> ScanOutcome:
        """Return a finished scan's recorded result, marked as a replay."""
        async with self._runtime.database.session() as session:
            lifecycle = await ScanLifecycleRepository(session).get(scan_run_id)
            report = await ReportRepository(session).latest_for_scan(scan_run_id)

        state = ScanLifecycleState.FAILED
        reason = OrchestrationReasonCode.ALREADY_TERMINAL.value
        if lifecycle is not None:
            try:
                state = ScanLifecycleState(lifecycle.state)
            except ValueError:  # pragma: no cover
                state = ScanLifecycleState.FAILED
            reason = lifecycle.reason_code or reason

        return ScanOutcome(
            scan_run_id=scan_run_id,
            terminal_state=state,
            reason_code=reason,
            claim_epoch=claim_epoch,
            report_id=report.report_id if report else None,
            covered=report.covered if report else 0,
            planned=report.denominator if report else 0,
            replayed=True,
            completed_at=lifecycle.terminal_at if lifecycle else None,
        )

    async def _audit_scan_start(
        self,
        *,
        scan_run_id: str,
        initiated_by: str,
        claim: Any,
        deadline: datetime,
        policy_version: str,
    ) -> None:
        event = self._audit.scan_start(
            scan_run_id=scan_run_id,
            initiated_by=initiated_by,
            claim_epoch=claim.claim_epoch,
            claim_result=claim.result.value,
            deadline_at=deadline,
            policy_version=policy_version,
            graph_version=GRAPH_VERSION,
            timestamp=self._runtime.clock.now(),
        )
        await self._append_event(event, scan_run_id, initiated_by, claim.claim_epoch)

    async def _audit_gate_denial(
        self,
        scan_run_id: str,
        reason: OrchestrationReasonCode,
        initiated_by: str,
        detail: str,
    ) -> None:
        event = self._audit.gate(
            scan_run_id=scan_run_id,
            decision="DENY",
            reason_code=reason.value,
            initiated_by=initiated_by,
            timestamp=self._runtime.clock.now(),
            detail=detail or None,
        )
        await self._append_event(event, scan_run_id, initiated_by, None, decision="DENY")

    async def _append_event(
        self,
        event: Any,
        scan_run_id: str,
        initiated_by: str,
        claim_epoch: int | None,
        *,
        decision: str | None = None,
    ) -> None:
        try:
            async with self._runtime.database.session() as session:
                async with session.begin():
                    OrchestrationAuditRepository(session).append(
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_schema_version=event.payload["event_schema_version"],
                        scan_run_id=scan_run_id,
                        decision=decision,
                        initiated_by=initiated_by,
                        claim_epoch=claim_epoch,
                        payload=event.payload,
                        payload_digest=event.payload_digest,
                        signer_kid=event.signer_kid,
                        signature=event.signature_b64,
                    )
        except (OperationalError, DBAPIError):
            logger.warning("orchestration_audit_unavailable", scan_run_id=scan_run_id)


def _terminal_from(final: dict[str, Any]) -> ScanLifecycleState:
    """Decide the terminal state from the graph's final state.

    A halt recorded before the report node (an unauthorized resume, a cap
    exceeded) is preserved; otherwise the report node's coverage-derived state
    is authoritative.
    """
    if final.get("halted") and not final.get("terminal_state"):
        reason = str(final.get("reason_code") or "")
        if reason == OrchestrationReasonCode.TARGET_CAP_EXCEEDED.value:
            return ScanLifecycleState.HALTED_FOR_REVIEW
        return ScanLifecycleState.HALTED_UNAUTHORIZED
    return final_state_or_default(final)  # type: ignore[arg-type]
