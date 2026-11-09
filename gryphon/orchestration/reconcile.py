"""Reconciliation — resolving uncertainty from records, and *terminating*.

When a call's outcome never commits — the process died between the enforcement
layer's intent record and its outcome record — the honest state is "traffic may
have reached the target, and we do not know what happened". That is the one
outcome a scanner must never round up to success.

But "never upgrade to success" and "an item must be accounted for before the
scan can finish" together create a trap: an outcome that will *never* resolve
leaves the scan unable to progress and unable to complete. A permanently
indeterminate item is not hypothetical — it is the documented consequence of a
crash in that window.

The way out is to distinguish two things that are easy to conflate:

    resolved to a known outcome      vs.      resolved as permanently unknown

Only the first was ever modelled. This module adds the second: after a bounded
window, an item that is still indeterminate is terminally classified
``UNRESOLVED_POSSIBLY_CONTACTED``. That classification is durable, is never
retried, is never re-contacted, and counts as a declared coverage gap. The scan
can then finish — truthfully, with the gap named — instead of stalling forever.

Reconciliation never contacts a target to find out what happened. It presents
the item's **stored** identity to the enforcement layer, which returns the
recorded outcome and starts nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.clock import Clock
from gryphon.db.session import Database
from gryphon.logging_config import get_logger
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.constants import PlanItemState
from gryphon.orchestration.coverage import item_state_for
from gryphon.orchestration.ledger import (
    OrchestrationAuditRepository,
    PlanRepository,
)
from gryphon.orchestration.reasons import (
    AuthorizationPreconditionFailed,
    OrchestrationReasonCode,
)
from gryphon.orchestration.settings import OrchestrationSettings
from gryphon.orchestration.touchpoint import AuthorityTouchpoint
from gryphon.tooling.constants import ToolId, ToolOutcome

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """What one reconciliation pass examined and concluded."""

    examined: int
    resolved: int
    unresolved: int

    @property
    def made_progress(self) -> bool:
        return self.resolved > 0 or self.unresolved > 0


class Reconciler:
    """Resolves indeterminate items from recorded evidence, in bounded time."""

    def __init__(
        self,
        *,
        database: Database,
        clock: Clock,
        touchpoint: AuthorityTouchpoint,
        audit: OrchestrationAuditBuilder,
        settings: OrchestrationSettings,
    ) -> None:
        self._db = database
        self._clock = clock
        self._touchpoint = touchpoint
        self._audit = audit
        self._settings = settings

    async def reconcile(
        self, *, scan_run_id: str, claim_epoch: int
    ) -> ReconciliationReport:
        """Resolve every indeterminate item for this scan.

        Two passes in one: items whose outcome *has* since been recorded are
        settled from that record; items still indeterminate past the window are
        terminally classified. Both are durable, so the pass is idempotent and
        the next one has strictly less to do.
        """
        async with self._db.session() as session:
            pending = await PlanRepository(session).indeterminate_items(
                scan_run_id=scan_run_id
            )
        if not pending:
            return ReconciliationReport(examined=0, resolved=0, unresolved=0)

        window = self._settings.reconciliation_window_seconds
        async with self._db.session() as session:
            overdue_rows = await PlanRepository(session).indeterminate_items(
                scan_run_id=scan_run_id, older_than_seconds=window
            )
        overdue = {row.plan_item_id for row in overdue_rows}

        resolved = 0
        unresolved = 0

        for item in pending:
            recorded_state: PlanItemState | None = None
            outcome_value: str | None = None
            reason_value: str | None = None
            audit_event_id: str | None = None

            # Ask the enforcement layer what it recorded for this identity. A
            # known identity returns its stored outcome and starts nothing.
            try:
                result = await self._touchpoint.recorded_outcome(
                    scan_run_id=scan_run_id,
                    tool_id=ToolId(item.tool_id),
                    execution_id=item.execution_id,
                    canonical_target=item.canonical_target,
                )
            except AuthorizationPreconditionFailed as exc:
                # Authority is gone. We cannot read back through the gateway, so
                # the item stays indeterminate until the window closes — and
                # then it is classified, not retried.
                logger.info(
                    "reconcile_authority_unavailable",
                    scan_run_id=scan_run_id,
                    execution_id=item.execution_id,
                    reason_code=exc.reason_code.value,
                )
                result = None

            if result is not None and result.outcome is not ToolOutcome.UNKNOWN:
                recorded_state = item_state_for(result.outcome, result.reason_code)
                outcome_value = result.outcome.value
                reason_value = result.reason_code
                audit_event_id = result.audit_event_id
                resolved += 1
            elif item.plan_item_id in overdue:
                # Still indeterminate past the window. Terminal classification:
                # possibly contacted, never retried, declared as a gap.
                recorded_state = PlanItemState.UNRESOLVED_POSSIBLY_CONTACTED
                outcome_value = ToolOutcome.UNKNOWN.value
                reason_value = (
                    OrchestrationReasonCode.UNRESOLVED_POSSIBLY_CONTACTED.value
                )
                unresolved += 1
            else:
                # Inside the window: leave it, and look again next pass.
                continue

            try:
                async with self._db.session() as session:
                    async with session.begin():
                        await PlanRepository(session).settle_item(
                            plan_item_id=item.plan_item_id,
                            claim_epoch=claim_epoch,
                            state=recorded_state,
                            outcome=outcome_value,
                            reason_code=reason_value,
                            audit_event_id=audit_event_id,
                        )
            except (OperationalError, DBAPIError):
                logger.warning(
                    "reconcile_settle_failed",
                    scan_run_id=scan_run_id,
                    execution_id=item.execution_id,
                )

        report = ReconciliationReport(
            examined=len(pending), resolved=resolved, unresolved=unresolved
        )
        await self._audit_pass(
            scan_run_id=scan_run_id, claim_epoch=claim_epoch, report=report
        )
        logger.info(
            "reconcile_complete",
            scan_run_id=scan_run_id,
            examined=report.examined,
            resolved=report.resolved,
            unresolved_possibly_contacted=report.unresolved,
        )
        return report

    async def _audit_pass(
        self, *, scan_run_id: str, claim_epoch: int, report: ReconciliationReport
    ) -> None:
        event = self._audit.reconciliation(
            scan_run_id=scan_run_id,
            examined=report.examined,
            resolved=report.resolved,
            unresolved=report.unresolved,
            claim_epoch=claim_epoch,
            timestamp=self._clock.now(),
        )
        try:
            async with self._db.session() as session:
                async with session.begin():
                    OrchestrationAuditRepository(session).append(
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_schema_version=event.payload["event_schema_version"],
                        scan_run_id=scan_run_id,
                        reason_code=OrchestrationReasonCode.RECONCILE_REQUIRED.value,
                        claim_epoch=claim_epoch,
                        payload=event.payload,
                        payload_digest=event.payload_digest,
                        signer_kid=event.signer_kid,
                        signature=event.signature_b64,
                    )
        except (OperationalError, DBAPIError):
            logger.warning("reconcile_audit_unavailable", scan_run_id=scan_run_id)
