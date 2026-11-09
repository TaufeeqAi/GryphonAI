"""The step engine — plan once, dispatch, settle, fold.

One function describes this layer's whole execution model:

    if no plan exists for this step, build and commit one;
    then dispatch its pending items, settle each recorded outcome,
    persist the evidence, and fold coverage.

Running it again is safe and is the *same* code path as running it the first
time. There is no separate resume routine to be subtly wrong, untested or — as
happens with a lock that cannot detect its holder's death — unreachable
precisely when it is needed. A re-entered step finds its plan already committed,
finds most items already settled, and dispatches only what is still pending;
each pending item presents its stored identity, so an item that in fact
completed returns its recorded outcome rather than contacting the target again.

Concurrency within a step is bounded and deliberately unambitious. The
enforcement layer owns the real budgets (per-scan concurrency, token bucket,
circuit breaker); this layer adds only a local semaphore so it cannot queue
more work than it can account for. Results write distinct ledger rows, so
parallel dispatch needs no shared mutable object and therefore no merge rules —
the class of bug where two branches race to update one accumulated result
simply has nowhere to occur.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Sequence

from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from gryphon.clock import Clock
from gryphon.constants import ScanDepth
from gryphon.db.models.scan_plan import PlanItem
from gryphon.db.session import Database
from gryphon.logging_config import get_logger
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.constants import (
    PlanItemState,
    StepSpec,
)
from gryphon.orchestration.coverage import (
    ClassifiedItem,
    StepCoverage,
    fold,
    is_retryable,
    is_saturation,
    item_state_for,
)
from gryphon.orchestration.ledger import (
    OrchestrationAuditRepository,
    PlanRepository,
    RawFindingRepository,
    ScanLifecycleRepository,
)
from gryphon.orchestration.plan import (
    BuiltPlan,
    PlannedTarget,
    build_plan,
    ledger_schema_version,
    targets_for,
)
from gryphon.orchestration.projection import observations_from, rows_for
from gryphon.orchestration.reasons import (
    AuthorizationPreconditionFailed,
    OrchestrationReasonCode,
)
from gryphon.orchestration.settings import OrchestrationSettings
from gryphon.orchestration.touchpoint import AuthorityTouchpoint, AuthorizationContext
from gryphon.tooling.constants import ToolId, ToolOutcome
from gryphon.tooling.execution.aggregate import ToolExecutionResult

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class StepResult:
    """What one step accomplished, and whether the pipeline may advance."""

    spec: StepSpec
    coverage: StepCoverage
    #: Set when the step could not proceed at all (authorization, budget).
    halt_reason: OrchestrationReasonCode | None = None
    saturated: bool = False

    @property
    def may_advance(self) -> bool:
        """Whether the declared partial-result policy is satisfied."""
        if self.halt_reason is not None:
            return False
        if self.coverage.pending > 0:
            return False
        return self.coverage.covered_fraction >= self.spec.min_coverage_to_proceed


class StepEngine:
    """Executes one planned step against the enforcement boundary."""

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

    # -- planning -------------------------------------------------------------
    async def ensure_plan(
        self,
        spec: StepSpec,
        *,
        scan_run_id: str,
        claim_epoch: int,
        context: AuthorizationContext,
        execution_salt: str,
        admitted_hosts: Sequence[PlannedTarget] = (),
    ) -> int:
        """Commit this step's plan if it is not already committed.

        Returns the number of planned items. Idempotent: a committed plan is
        never rebuilt, which is what guarantees a resumed step keeps the
        identities it started with.
        """
        async with self._db.session() as session:
            existing = await PlanRepository(session).get_plan(
                scan_run_id=scan_run_id, stage=spec.stage.value, step=spec.step
            )
            if existing is not None:
                return existing.item_count

            evidence = await RawFindingRepository(session).for_scan(scan_run_id)

        targets = targets_for(
            spec,
            admitted_target=context.canonical_target,
            admitted_hosts=admitted_hosts,
            evidence=evidence,
        )
        built = build_plan(
            spec,
            scan_run_id=scan_run_id,
            targets=targets,
            execution_salt=execution_salt,
            policy_version=context.policy_version,
            effective_depth=ScanDepth(context.effective_depth),
        )
        await self._commit_plan(built, spec=spec, claim_epoch=claim_epoch)
        return built.item_count

    async def _commit_plan(
        self, built: BuiltPlan, *, spec: StepSpec, claim_epoch: int
    ) -> None:
        """Commit the plan, its items and the intent audit event atomically.

        All three together: a plan whose items did not land would leave work
        whose identities were never recorded, and an unaudited plan would leave
        target selection unaccountable.
        """
        now = self._clock.now()
        event = self._audit.plan_committed(
            scan_run_id=built.scan_run_id,
            stage=built.stage,
            step=built.step,
            tool_id=built.tool_id,
            plan_generation=built.plan_generation,
            plan_digest=built.plan_digest,
            item_count=built.item_count,
            claim_epoch=claim_epoch,
            timestamp=now,
        )
        try:
            async with self._db.session() as session:
                async with session.begin():
                    await PlanRepository(session).commit_plan(
                        plan_id=built.plan_id,
                        scan_run_id=built.scan_run_id,
                        stage=built.stage,
                        step=built.step,
                        tool_id=built.tool_id,
                        plan_generation=built.plan_generation,
                        plan_digest=built.plan_digest,
                        policy_version=built.policy_version,
                        ledger_schema_version=ledger_schema_version(),
                        min_coverage_to_proceed=built.min_coverage_to_proceed,
                        claim_epoch=claim_epoch,
                        items=built.items,
                    )
                    OrchestrationAuditRepository(session).append(
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_schema_version=event.payload["event_schema_version"],
                        scan_run_id=built.scan_run_id,
                        stage=built.stage,
                        step=built.step,
                        decision="PLAN",
                        reason_code=OrchestrationReasonCode.PLAN_COMMITTED.value,
                        claim_epoch=claim_epoch,
                        payload=event.payload,
                        payload_digest=event.payload_digest,
                        signer_kid=event.signer_kid,
                        signature=event.signature_b64,
                    )
        except IntegrityError:
            # A concurrent owner committed the same generation first. Both
            # computed the same identities from the same inputs, so the
            # committed plan is equivalent and this one is simply redundant.
            logger.info(
                "plan_already_committed",
                scan_run_id=built.scan_run_id,
                stage=built.stage,
                step=built.step,
            )
        logger.info(
            "plan_committed",
            scan_run_id=built.scan_run_id,
            stage=built.stage,
            step=built.step,
            tool_id=built.tool_id,
            items=built.item_count,
            plan_digest=built.plan_digest,
        )

    # -- execution ------------------------------------------------------------
    async def run_step(
        self,
        spec: StepSpec,
        *,
        scan_run_id: str,
        claim_epoch: int,
        context: AuthorizationContext,
    ) -> StepResult:
        """Dispatch every pending item in this step, then fold coverage."""
        semaphore = asyncio.Semaphore(self._settings.max_step_concurrency)
        saturated = False
        halt_reason: OrchestrationReasonCode | None = None

        while True:
            if await self._cooldown_active(scan_run_id):
                saturated = True
                break
            if await self._decision_budget_exhausted(scan_run_id):
                halt_reason = OrchestrationReasonCode.DECISION_BUDGET_EXHAUSTED
                break

            batch = await self._take_batch(spec, scan_run_id=scan_run_id, claim_epoch=claim_epoch)
            if not batch:
                break

            outcomes = await asyncio.gather(
                *(
                    self._dispatch_one(
                        item, spec=spec, scan_run_id=scan_run_id,
                        claim_epoch=claim_epoch, semaphore=semaphore,
                    )
                    for item in batch
                ),
                return_exceptions=True,
            )
            for outcome in outcomes:
                if isinstance(outcome, AuthorizationPreconditionFailed):
                    # Authorization is gone or the window has closed. Stop the
                    # whole step: every remaining item would fail identically,
                    # and retrying would only burn budget and audit rows.
                    halt_reason = outcome.reason_code
                elif isinstance(outcome, BaseException):
                    logger.warning(
                        "step_dispatch_error",
                        scan_run_id=scan_run_id,
                        step=spec.step,
                        error=type(outcome).__name__,
                    )
                elif outcome is _SATURATED:
                    saturated = True
            if halt_reason is not None or saturated:
                break

        coverage = await self.coverage_for_step(spec, scan_run_id=scan_run_id)
        return StepResult(
            spec=spec, coverage=coverage, halt_reason=halt_reason, saturated=saturated
        )

    async def _take_batch(
        self, spec: StepSpec, *, scan_run_id: str, claim_epoch: int
    ) -> list[PlanItem]:
        """Claim the next batch of pending items and mark them dispatched.

        The claim and the state change share one transaction so a crash between
        them cannot leave an item claimed-but-not-dispatched.
        """
        limit = self._settings.max_step_concurrency
        taken: list[PlanItem] = []
        try:
            async with self._db.session() as session:
                async with session.begin():
                    repo = PlanRepository(session)
                    rows = await repo.claim_items(
                        scan_run_id=scan_run_id,
                        stage=spec.stage.value,
                        step=spec.step,
                        limit=limit,
                    )
                    for row in rows:
                        if await repo.mark_dispatched(
                            plan_item_id=row.plan_item_id, claim_epoch=claim_epoch
                        ):
                            taken.append(_snapshot(row))
        except (OperationalError, DBAPIError):
            logger.warning("plan_item_claim_failed", scan_run_id=scan_run_id, step=spec.step)
            return []
        return taken

    async def _dispatch_one(
        self,
        item: PlanItem,
        *,
        spec: StepSpec,
        scan_run_id: str,
        claim_epoch: int,
        semaphore: asyncio.Semaphore,
    ) -> object:
        """Run one item through the touchpoint and record what came back."""
        async with semaphore:
            result = await self._touchpoint.dispatch(
                scan_run_id=scan_run_id,
                tool_id=ToolId(item.tool_id),
                execution_id=item.execution_id,
                canonical_target=item.canonical_target,
                path=item.target_path,
                requested_depth=item.effective_depth,
            )

        await self._settle(
            item, spec=spec, result=result, scan_run_id=scan_run_id, claim_epoch=claim_epoch
        )

        if is_saturation(result.reason_code):
            await self._enter_cooldown(scan_run_id, claim_epoch)
            return _SATURATED
        return None

    async def _settle(
        self,
        item: PlanItem,
        *,
        spec: StepSpec,
        result: ToolExecutionResult,
        scan_run_id: str,
        claim_epoch: int,
    ) -> None:
        """Record the outcome, persist evidence, or queue a bounded retry."""
        # A retryable failure with attempts remaining goes back to the queue
        # with its identity untouched, so a call that actually completed returns
        # its recorded outcome instead of running a second time.
        if (
            is_retryable(result.outcome, result.reason_code)
            and item.attempts < self._settings.max_attempts_per_item
        ):
            async with self._db.session() as session:
                async with session.begin():
                    await PlanRepository(session).reset_to_planned(
                        plan_item_id=item.plan_item_id, claim_epoch=claim_epoch
                    )
            return

        state = item_state_for(result.outcome, result.reason_code)
        rows = (
            rows_for(
                observations=observations_from(ToolId(item.tool_id), result.records),
                scan_run_id=scan_run_id,
                plan_item_id=item.plan_item_id,
                execution_id=item.execution_id,
                audit_event_id=result.audit_event_id,
                stage=spec.stage.value,
                step=spec.step,
                tool_id=ToolId(item.tool_id),
            )
            if result.outcome is ToolOutcome.COMPLETED
            else []
        )

        try:
            async with self._db.session() as session:
                async with session.begin():
                    await PlanRepository(session).settle_item(
                        plan_item_id=item.plan_item_id,
                        claim_epoch=claim_epoch,
                        state=state,
                        outcome=result.outcome.value,
                        reason_code=result.reason_code,
                        audit_event_id=result.audit_event_id,
                        record_count=result.record_count(),
                    )
                    if rows:
                        await RawFindingRepository(session).append_many(rows)
                    await ScanLifecycleRepository(session).note_decisions(
                        scan_run_id=scan_run_id, claim_epoch=claim_epoch, count=1
                    )
        except (OperationalError, DBAPIError):
            # The call already happened; the enforcement layer's committed
            # intent record is the authoritative evidence that traffic may have
            # occurred. Leaving the item non-terminal routes it to
            # reconciliation, which is correct: never upgrade to success.
            logger.warning(
                "plan_item_settle_failed",
                scan_run_id=scan_run_id,
                execution_id=item.execution_id,
            )

    # -- budgets --------------------------------------------------------------
    async def _cooldown_active(self, scan_run_id: str) -> bool:
        async with self._db.session() as session:
            row = await ScanLifecycleRepository(session).get(scan_run_id)
        if row is None or row.cooldown_until is None:
            return False
        return self._clock.now() < row.cooldown_until

    async def _enter_cooldown(self, scan_run_id: str, claim_epoch: int) -> None:
        """Stop calling for a while rather than retrying into a wall.

        A breaker-open outcome retried immediately is how one flapping target
        turns into thousands of signed audit rows and a lot of wasted signing.
        """
        async with self._db.session() as session:
            async with session.begin():
                await ScanLifecycleRepository(session).set_cooldown(
                    scan_run_id=scan_run_id,
                    claim_epoch=claim_epoch,
                    seconds=self._settings.breaker_cooldown_seconds,
                )
        logger.info(
            "scan_cooldown_entered",
            scan_run_id=scan_run_id,
            seconds=self._settings.breaker_cooldown_seconds,
        )

    async def _decision_budget_exhausted(self, scan_run_id: str) -> bool:
        async with self._db.session() as session:
            row = await ScanLifecycleRepository(session).get(scan_run_id)
        if row is None:
            return False
        return row.decision_count >= self._settings.max_decisions_per_scan

    # -- coverage -------------------------------------------------------------
    async def coverage_for_step(
        self, spec: StepSpec, *, scan_run_id: str
    ) -> StepCoverage:
        """Fold this step's recorded items into coverage."""
        async with self._db.session() as session:
            items = await PlanRepository(session).items_for_step(
                scan_run_id=scan_run_id, stage=spec.stage.value, step=spec.step
            )
        classified = [_classify(row) for row in items]
        folded = fold(classified)
        if folded.steps:
            return folded.steps[0]
        return StepCoverage(
            stage=spec.stage.value,
            step=spec.step,
            tool_id=spec.tool_id.value,
            planned=0,
            covered=0,
            gap=0,
            integrity=0,
            excluded=0,
            pending=0,
        )


#: Sentinel returned by a dispatch that hit saturation.
_SATURATED = object()


def _classify(row: PlanItem) -> ClassifiedItem:
    """Project a ledger row into the minimal shape coverage needs."""
    outcome: ToolOutcome | None
    try:
        outcome = ToolOutcome(row.outcome) if row.outcome else None
    except ValueError:  # pragma: no cover - defensive against a hand-edited row
        outcome = None
    try:
        state = PlanItemState(row.state)
    except ValueError:  # pragma: no cover
        state = PlanItemState.PLANNED
    return ClassifiedItem(
        stage=row.stage,
        step=row.step,
        tool_id=row.tool_id,
        state=state,
        outcome=outcome,
        reason_code=row.reason_code,
    )


def _snapshot(row: PlanItem) -> PlanItem:
    """Detach the fields a dispatch needs from the session that loaded them.

    Dispatch runs concurrently in its own tasks, and a session must not be
    shared across tasks, so the dispatcher works from a plain value object
    rather than a live ORM instance.
    """
    detached = PlanItem(
        plan_item_id=row.plan_item_id,
        plan_id=row.plan_id,
        scan_run_id=row.scan_run_id,
        stage=row.stage,
        step=row.step,
        seq=row.seq,
        tool_id=row.tool_id,
        execution_id=row.execution_id,
        request_digest=row.request_digest,
        attempt_epoch=row.attempt_epoch,
        attempts=row.attempts,
        canonical_target=row.canonical_target,
        target_path=row.target_path,
        effective_depth=row.effective_depth,
        provenance=dict(row.provenance or {}),
        state=row.state,
        outcome=row.outcome,
        reason_code=row.reason_code,
        claim_epoch=row.claim_epoch,
    )
    return detached
