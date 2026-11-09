"""The data-driven stage node.

One node factory serves all four pipeline stages. What varies between them
(which tools, where targets come from, how much coverage is required to
advance) is described by the step table, so the differences are inspectable
data rather than four divergent code paths.

A stage runs its steps strictly in order, because the steps within a stage are
genuinely dependent — DNS resolution needs discovered names; HTTP probing is
meaningful only after port discovery has recorded what is open. Within a step,
items fan out under a bounded semaphore.

Every step is also idempotent at the stage level: a re-entered stage finds its
plans committed and its settled items terminal, so it re-walks them as cheap
no-ops and dispatches only what remains.
"""

from __future__ import annotations

from typing import Callable, Sequence

from gryphon.logging_config import get_logger
from gryphon.orchestration.constants import STEP_PLAN, ScanStage
from gryphon.orchestration.ledger import ScanLifecycleRepository
from gryphon.orchestration.plan import PlannedTarget
from gryphon.orchestration.reasons import (
    AuthorizationPreconditionFailed,
    OrchestrationReasonCode,
)
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.state import ScanGraphState

logger = get_logger(__name__)


def steps_for(stage: ScanStage) -> tuple:
    """The ordered steps of one stage, from the step table."""
    return tuple(spec for spec in STEP_PLAN if spec.stage is stage)


def build_stage_node(
    runtime: ScanRuntime, stage: ScanStage
) -> Callable[[ScanGraphState], object]:
    """Build a node that runs every step of ``stage`` in order."""
    specs = steps_for(stage)

    async def run_stage(state: ScanGraphState) -> ScanGraphState:
        scan_run_id = state["scan_run_id"]
        claim_epoch = int(state["claim_epoch"])

        try:
            context = await runtime.touchpoint.context(scan_run_id)
        except AuthorizationPreconditionFailed as exc:
            # Authority disappeared mid-scan (revoked key, expired grant). Stop
            # here rather than attempting work that cannot be authorized.
            logger.info(
                "stage_halted_unauthorized",
                scan_run_id=scan_run_id,
                stage=stage.value,
                reason_code=exc.reason_code.value,
            )
            return ScanGraphState(
                halted=True, stage=stage.value, reason_code=exc.reason_code.value
            )

        execution_salt, admitted_hosts = await _scan_facts(runtime, scan_run_id)

        covered = 0
        gaps = 0
        integrity = 0
        planned = 0
        halt_reason: str | None = None

        for spec in specs:
            await runtime.engine.ensure_plan(
                spec,
                scan_run_id=scan_run_id,
                claim_epoch=claim_epoch,
                context=context,
                execution_salt=execution_salt,
                admitted_hosts=admitted_hosts,
            )
            result = await runtime.engine.run_step(
                spec, scan_run_id=scan_run_id, claim_epoch=claim_epoch, context=context
            )
            planned += result.coverage.planned
            covered += result.coverage.covered
            gaps += result.coverage.gap
            integrity += result.coverage.integrity

            if result.halt_reason is not None:
                halt_reason = result.halt_reason.value
                break
            if result.saturated:
                # The enforcement layer is shedding load. Leave the remaining
                # items PLANNED: a later invocation or the sweeper picks them up
                # once the cool-down lapses, and the coverage block shows the
                # pending work rather than pretending it was done.
                halt_reason = OrchestrationReasonCode.BREAKER_COOLDOWN.value
                break
            if not result.may_advance:
                logger.info(
                    "step_below_coverage_policy",
                    scan_run_id=scan_run_id,
                    step=spec.step,
                    covered_fraction=result.coverage.covered_fraction,
                    required=spec.min_coverage_to_proceed,
                )
                halt_reason = OrchestrationReasonCode.RECONCILE_REQUIRED.value
                break

        await _advance_phase(runtime, scan_run_id, claim_epoch, stage)

        update = ScanGraphState(
            stage=stage.value,
            planned_count=int(state.get("planned_count", 0)) + planned,
            covered_count=int(state.get("covered_count", 0)) + covered,
            gap_count=int(state.get("gap_count", 0)) + gaps,
            integrity_count=int(state.get("integrity_count", 0)) + integrity,
        )
        if halt_reason is not None:
            update["reason_code"] = halt_reason
        return update

    return run_stage


async def _scan_facts(
    runtime: ScanRuntime, scan_run_id: str
) -> tuple[str, Sequence[PlannedTarget]]:
    """Read the scan's salt and its admitted hosts from the ledger.

    Both come from durable records rather than from graph state: the salt is a
    secret that must never enter state, and the admitted host set must survive a
    crash unchanged or a resumed plan would derive different identities.

    The host set is read from the admitted-target table, not from raw discovery
    evidence. Only attested targets may be actively scanned, so planning from
    discovery output directly would bypass admission entirely.
    """
    from gryphon.orchestration.ledger import AdmittedTargetRepository

    async with runtime.database.session() as session:
        row = await ScanLifecycleRepository(session).get(scan_run_id)
        admitted_rows = await AdmittedTargetRepository(session).for_scan(scan_run_id)

    salt = row.execution_salt if row is not None else ""
    admitted = [
        PlannedTarget(
            canonical_target=item.canonical_target,
            provenance=dict(item.provenance or {}),
        )
        for item in admitted_rows
    ]
    return salt, admitted


async def _advance_phase(
    runtime: ScanRuntime, scan_run_id: str, claim_epoch: int, stage: ScanStage
) -> None:
    """Raise the monotonic progress mark; it can only move forward."""
    async with runtime.database.session() as session:
        async with session.begin():
            await ScanLifecycleRepository(session).advance_phase(
                scan_run_id=scan_run_id, claim_epoch=claim_epoch, phase_reached=stage.order
            )
