"""The report node — reconcile, fold, assemble, attest.

The last node does four things in a deliberate order, and the order is the
point:

1. **Reconcile** any indeterminate outcome, so nothing uncertain is silently
   folded into a result. An item whose fate is still unknown past the window is
   terminally classified as possibly-contacted, which bounds reconciliation
   instead of letting the scan stall.
2. **Fold coverage** and derive the terminal state from it. "Reached the end of
   the graph" is not the completion criterion; accounting for the planned work
   is.
3. **Assemble** the report as a pure function over corroborated evidence,
   dropping any finding whose producing execution this scan never recorded.
4. **Attest** it: persist the immutable artifact and a signed audit event
   carrying its content digest, in one transaction.

If the audit cannot be written the report is *not* emitted and the scan ends
``report_pending``. That is a deliberate fail-closed choice on attestation
rather than on work: the scanning already happened and its findings are safe in
the ledger, but an unattested deliverable is one nobody can later prove was
ours, so we would rather hand over nothing than hand over that.
"""

from __future__ import annotations

from typing import Callable

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.logging_config import get_logger
from gryphon.orchestration.constants import REPORT_SCHEMA_VERSION, ScanLifecycleState, ScanStage
from gryphon.orchestration.coverage import fold
from gryphon.orchestration.engine import _classify
from gryphon.orchestration.ledger import (
    OrchestrationAuditRepository,
    PlanRepository,
    RawFindingRepository,
    ReportRepository,
    ScanLifecycleRepository,
)
from gryphon.orchestration.reasons import OrchestrationReasonCode
from gryphon.orchestration.report import assemble, terminal_state_for
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.state import ScanGraphState

logger = get_logger(__name__)


def build_report_node(
    runtime: ScanRuntime, *, initiated_by: str
) -> Callable[[ScanGraphState], object]:
    """Build the report node closure."""

    async def report_node(state: ScanGraphState) -> ScanGraphState:
        scan_run_id = state["scan_run_id"]
        claim_epoch = int(state["claim_epoch"])

        # 1. Resolve uncertainty before anything is summarized.
        await runtime.reconciler.reconcile(
            scan_run_id=scan_run_id, claim_epoch=claim_epoch
        )

        async with runtime.database.session() as session:
            items = await PlanRepository(session).items_for_scan(scan_run_id)
            findings = await RawFindingRepository(session).for_scan(scan_run_id)
            lifecycle = await ScanLifecycleRepository(session).get(scan_run_id)

        # 2. Coverage decides the terminal state.
        coverage = fold([_classify(row) for row in items])
        terminal, reason = terminal_state_for(
            coverage, coverage_failure_floor=runtime.settings.coverage_failure_floor
        )
        # A halt recorded earlier in the pipeline is more specific than the
        # coverage fold; keep it rather than overwriting it with a generic gap.
        halt_reason = state.get("reason_code")
        if state.get("halted") and halt_reason:
            reason = halt_reason

        # 3. Assemble from corroborated evidence only.
        assembled = assemble(
            scan_run_id=scan_run_id,
            terminal_state=terminal,
            reason_code=reason,
            coverage=coverage,
            findings=findings,
            plan_items=items,
            generated_at=runtime.clock.now(),
            initiated_by=initiated_by,
            policy_version=lifecycle.policy_version if lifecycle else "",
            coverage_failure_floor=runtime.settings.coverage_failure_floor,
        )

        # 4. Persist and attest atomically.
        event = runtime.audit.report_emitted(
            scan_run_id=scan_run_id,
            report_id=assembled.report_id,
            report_digest=assembled.report_digest,
            report_schema_version=REPORT_SCHEMA_VERSION,
            terminal_state=assembled.terminal_state.value,
            covered=coverage.covered,
            denominator=coverage.denominator,
            finding_count=assembled.finding_count,
            claim_epoch=claim_epoch,
            timestamp=runtime.clock.now(),
        )
        try:
            async with runtime.database.session() as session:
                async with session.begin():
                    ReportRepository(session).add(
                        report_id=assembled.report_id,
                        scan_run_id=scan_run_id,
                        report_schema_version=REPORT_SCHEMA_VERSION,
                        report_digest=assembled.report_digest,
                        body=assembled.body,
                        terminal_state=assembled.terminal_state.value,
                        covered=coverage.covered,
                        denominator=coverage.denominator,
                        finding_count=assembled.finding_count,
                        audit_event_id=event.event_id,
                    )
                    OrchestrationAuditRepository(session).append(
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_schema_version=event.payload["event_schema_version"],
                        scan_run_id=scan_run_id,
                        stage=ScanStage.REPORT.value,
                        decision="EMIT",
                        reason_code=assembled.terminal_state.value,
                        claim_epoch=claim_epoch,
                        payload=event.payload,
                        payload_digest=event.payload_digest,
                        signer_kid=event.signer_kid,
                        signature=event.signature_b64,
                    )
        except (OperationalError, DBAPIError):
            logger.warning("report_emit_failed", scan_run_id=scan_run_id)
            return ScanGraphState(
                stage=ScanStage.REPORT.value,
                terminal_state=assembled.terminal_state.value,
                reason_code=OrchestrationReasonCode.AUDIT_UNAVAILABLE.value,
            )

        if assembled.integrity_failure:
            logger.warning(
                "scan_integrity_failure",
                scan_run_id=scan_run_id,
                dropped=assembled.dropped_uncorroborated,
                scope_disagreements=coverage.integrity,
            )

        logger.info(
            "report_emitted",
            scan_run_id=scan_run_id,
            report_id=assembled.report_id,
            terminal_state=assembled.terminal_state.value,
            covered=coverage.covered,
            denominator=coverage.denominator,
            findings=assembled.finding_count,
        )
        return ScanGraphState(
            stage=ScanStage.REPORT.value,
            report_id=assembled.report_id,
            terminal_state=assembled.terminal_state.value,
            reason_code=reason,
            covered_count=coverage.covered,
            gap_count=coverage.gap,
            integrity_count=coverage.integrity,
            planned_count=coverage.planned,
        )

    return report_node


def final_state_or_default(state: ScanGraphState) -> ScanLifecycleState:
    """Read the terminal state the report decided, defaulting to FAILED.

    Defaulting to failure is intentional: if the report node did not record a
    state, we do not know the scan succeeded, and an unknown outcome must never
    present as a good one.
    """
    raw = state.get("terminal_state")
    if not raw:
        return ScanLifecycleState.FAILED
    try:
        return ScanLifecycleState(raw)
    except ValueError:  # pragma: no cover
        return ScanLifecycleState.FAILED
