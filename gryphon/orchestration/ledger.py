"""Work-ledger repositories — the only source of truth this layer owns.

Every durable fact this layer owns lives here: the fenced scan claim, committed
step plans, plan items and their recorded outcomes, append-only evidence, the
immutable report, and the signed decision audit.

Two conventions run through the module and both are load-bearing:

* **The database clock decides time.** Lease expiry is evaluated with
  ``func.now()`` inside the statement, never against a process clock. On a
  single host the database is the one clock every participant shares, so
  comparing a local ``datetime`` against a stored deadline would reintroduce
  the skew question the lease exists to answer.
* **Every mutating write is fenced.** Writes carry ``claim_epoch`` in the
  ``WHERE`` clause. A zero row count is not a lost update to retry — it means
  *this process no longer owns the scan* and must stop. Leases alone cannot
  provide that: they infer death from silence, and a lease shorter than the work
  silently produces two owners.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Sequence

from sqlalchemy import func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.db.models.raw_finding import RawFinding
from gryphon.db.models.scan_lifecycle import ScanLifecycle
from gryphon.db.models.scan_plan import AdmittedScanTarget, PlanItem, ScanPlan
from gryphon.db.models.scan_report import OrchestrationAudit, ScanReport
from gryphon.orchestration.constants import (
    FIRST_CLAIM_EPOCH,
    ClaimResult,
    PlanItemState,
    ScanLifecycleState,
)
from gryphon.orchestration.reasons import StaleClaimError


@dataclass(frozen=True, slots=True)
class ClaimOutcome:
    """Result of an execution-start claim attempt."""

    result: ClaimResult
    claim_epoch: int
    state: ScanLifecycleState | None = None
    lease_expires_at: datetime | None = None

    @property
    def owns(self) -> bool:
        """Whether the caller may execute."""
        return self.result in (ClaimResult.CLAIMED, ClaimResult.TAKEOVER)


class ScanLifecycleRepository:
    """The fenced scan claim and scan-level progress."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, scan_run_id: str) -> ScanLifecycle | None:
        return await self._session.get(ScanLifecycle, scan_run_id)

    async def claim_start(
        self,
        *,
        scan_run_id: str,
        owner_id: str,
        lease_seconds: float,
        initiated_by: str,
        execution_salt: str,
        policy_version: str,
        graph_version: str,
        deadline_at: datetime,
    ) -> ClaimOutcome:
        """Claim this scan, or report who holds it.

        Three paths, in order: a first claim (insert wins), a live lease held by
        someone else (refuse), or an expired lease (take over by bumping the
        fencing epoch). The epoch bump is a compare-and-set on the epoch we
        observed, so two simultaneous takeovers cannot both succeed.
        """
        lease_interval = timedelta(seconds=lease_seconds)

        # Path 1 — first claim. Insert-or-nothing keeps this a single statement.
        stmt = (
            pg_insert(ScanLifecycle)
            .values(
                scan_run_id=scan_run_id,
                state=ScanLifecycleState.RUNNING.value,
                phase_reached=0,
                owner_id=owner_id,
                claim_epoch=FIRST_CLAIM_EPOCH,
                lease_expires_at=func.now() + lease_interval,
                heartbeat_at=func.now(),
                execution_salt=execution_salt,
                policy_version=policy_version,
                graph_version=graph_version,
                initiated_by=initiated_by,
                deadline_at=deadline_at,
                decision_count=0,
                started_at=func.now(),
            )
            .on_conflict_do_nothing(index_elements=[ScanLifecycle.scan_run_id])
            .returning(ScanLifecycle.claim_epoch)
        )
        inserted = (await self._session.execute(stmt)).scalar_one_or_none()
        if inserted is not None:
            return ClaimOutcome(result=ClaimResult.CLAIMED, claim_epoch=int(inserted))

        # Path 2/3 — a row exists. Decide against the database clock.
        row = await self._session.get(ScanLifecycle, scan_run_id)
        if row is None:  # pragma: no cover - the insert conflicted, so it exists
            return ClaimOutcome(result=ClaimResult.ALREADY_RUNNING, claim_epoch=0)

        state = _lifecycle_state(row.state)
        if state is not None and state.is_terminal:
            return ClaimOutcome(
                result=ClaimResult.ALREADY_TERMINAL, claim_epoch=row.claim_epoch, state=state
            )

        observed_epoch = row.claim_epoch
        takeover = (
            update(ScanLifecycle)
            .where(
                ScanLifecycle.scan_run_id == scan_run_id,
                ScanLifecycle.claim_epoch == observed_epoch,
                # Only an EXPIRED lease may be taken. A live owner is untouched.
                ScanLifecycle.lease_expires_at.isnot(None),
                ScanLifecycle.lease_expires_at <= func.now(),
            )
            .values(
                owner_id=owner_id,
                claim_epoch=ScanLifecycle.claim_epoch + 1,
                lease_expires_at=func.now() + lease_interval,
                heartbeat_at=func.now(),
                state=ScanLifecycleState.RUNNING.value,
            )
            .returning(ScanLifecycle.claim_epoch)
        )
        new_epoch = (await self._session.execute(takeover)).scalar_one_or_none()
        if new_epoch is not None:
            return ClaimOutcome(result=ClaimResult.TAKEOVER, claim_epoch=int(new_epoch))

        return ClaimOutcome(
            result=ClaimResult.ALREADY_RUNNING,
            claim_epoch=observed_epoch,
            state=state,
            lease_expires_at=row.lease_expires_at,
        )

    async def heartbeat(
        self, *, scan_run_id: str, claim_epoch: int, lease_seconds: float
    ) -> bool:
        """Renew the lease. ``False`` means the claim was superseded — stop."""
        stmt = (
            update(ScanLifecycle)
            .where(
                ScanLifecycle.scan_run_id == scan_run_id,
                ScanLifecycle.claim_epoch == claim_epoch,
            )
            .values(
                lease_expires_at=func.now() + timedelta(seconds=lease_seconds),
                heartbeat_at=func.now(),
            )
        )
        return (await self._session.execute(stmt)).rowcount == 1

    async def transition(
        self,
        *,
        scan_run_id: str,
        claim_epoch: int,
        state: ScanLifecycleState,
        reason_code: str | None = None,
        report_id: str | None = None,
        coverage_note: str | None = None,
    ) -> None:
        """Move the scan to ``state``, fenced on ``claim_epoch``.

        A terminal transition also releases the lease, so nothing can later
        mistake a finished scan for abandoned work.
        """
        values: dict[str, Any] = {"state": state.value, "reason_code": reason_code}
        if report_id is not None:
            values["report_id"] = report_id
        if coverage_note is not None:
            values["coverage_note"] = coverage_note
        if state.is_terminal:
            values["terminal_at"] = func.now()
            values["lease_expires_at"] = None
            values["owner_id"] = None
        stmt = (
            update(ScanLifecycle)
            .where(
                ScanLifecycle.scan_run_id == scan_run_id,
                ScanLifecycle.claim_epoch == claim_epoch,
            )
            .values(**values)
        )
        if (await self._session.execute(stmt)).rowcount != 1:
            current = await self._session.get(ScanLifecycle, scan_run_id)
            raise StaleClaimError(
                scan_run_id, claim_epoch, current.claim_epoch if current else -1
            )

    async def advance_phase(
        self, *, scan_run_id: str, claim_epoch: int, phase_reached: int
    ) -> None:
        """Raise the monotonic progress high-water mark. Never lowers it."""
        stmt = (
            update(ScanLifecycle)
            .where(
                ScanLifecycle.scan_run_id == scan_run_id,
                ScanLifecycle.claim_epoch == claim_epoch,
                ScanLifecycle.phase_reached < phase_reached,
            )
            .values(phase_reached=phase_reached)
        )
        await self._session.execute(stmt)

    async def note_decisions(
        self, *, scan_run_id: str, claim_epoch: int, count: int
    ) -> int | None:
        """Add to the global decision counter; returns the new total."""
        stmt = (
            update(ScanLifecycle)
            .where(
                ScanLifecycle.scan_run_id == scan_run_id,
                ScanLifecycle.claim_epoch == claim_epoch,
            )
            .values(decision_count=ScanLifecycle.decision_count + count)
            .returning(ScanLifecycle.decision_count)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def set_cooldown(
        self, *, scan_run_id: str, claim_epoch: int, seconds: float
    ) -> None:
        """Refuse further calls for this scan until the cool-down elapses."""
        stmt = (
            update(ScanLifecycle)
            .where(
                ScanLifecycle.scan_run_id == scan_run_id,
                ScanLifecycle.claim_epoch == claim_epoch,
            )
            .values(cooldown_until=func.now() + timedelta(seconds=seconds))
        )
        await self._session.execute(stmt)

    async def find_reclaimable(self, *, limit: int = 50) -> Sequence[ScanLifecycle]:
        """Non-terminal scans whose lease has expired — abandoned work.

        This is what makes recovery an event rather than a hope: without it an
        abandoned scan waits for a human to notice.
        """
        stmt = (
            select(ScanLifecycle)
            .where(
                ScanLifecycle.state.in_(
                    [
                        ScanLifecycleState.RUNNING.value,
                        ScanLifecycleState.RECONCILING.value,
                    ]
                ),
                ScanLifecycle.lease_expires_at.isnot(None),
                ScanLifecycle.lease_expires_at <= func.now(),
            )
            .order_by(ScanLifecycle.lease_expires_at)
            .limit(limit)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def find_overdue(self, *, limit: int = 50) -> Sequence[ScanLifecycle]:
        """Non-terminal scans past their effective deadline."""
        stmt = (
            select(ScanLifecycle)
            .where(
                ScanLifecycle.state.in_(
                    [
                        ScanLifecycleState.RUNNING.value,
                        ScanLifecycleState.RECONCILING.value,
                        ScanLifecycleState.HALTED_FOR_REVIEW.value,
                    ]
                ),
                ScanLifecycle.deadline_at <= func.now(),
            )
            .limit(limit)
        )
        return (await self._session.execute(stmt)).scalars().all()


class PlanRepository:
    """Committed step plans and their items."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_plan(
        self, *, scan_run_id: str, stage: str, step: str
    ) -> ScanPlan | None:
        """Return the newest committed generation for this step, if any."""
        stmt = (
            select(ScanPlan)
            .where(
                ScanPlan.scan_run_id == scan_run_id,
                ScanPlan.stage == stage,
                ScanPlan.step == step,
            )
            .order_by(ScanPlan.plan_generation.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def commit_plan(
        self,
        *,
        plan_id: str,
        scan_run_id: str,
        stage: str,
        step: str,
        tool_id: str,
        plan_generation: int,
        plan_digest: str,
        policy_version: str,
        ledger_schema_version: str,
        min_coverage_to_proceed: float,
        claim_epoch: int,
        items: list[dict[str, Any]],
    ) -> None:
        """Stage a plan and its items for one atomic commit.

        The caller commits; plan and items land together or not at all. A
        half-written plan would leave items whose identities were never recorded,
        which is the one thing the stored-identity design cannot tolerate.

        The plan row is flushed before its items: the items carry a foreign key
        to it, and without an explicit flush the unit of work is free to order
        the inserts the other way round.
        """
        self._session.add(
            ScanPlan(
                plan_id=plan_id,
                scan_run_id=scan_run_id,
                stage=stage,
                step=step,
                tool_id=tool_id,
                plan_generation=plan_generation,
                plan_digest=plan_digest,
                policy_version=policy_version,
                ledger_schema_version=ledger_schema_version,
                item_count=len(items),
                min_coverage_to_proceed=min_coverage_to_proceed,
                claim_epoch=claim_epoch,
            )
        )
        await self._session.flush()
        if items:
            self._session.add_all(PlanItem(**item) for item in items)
            await self._session.flush()

    async def claim_items(
        self, *, scan_run_id: str, stage: str, step: str, limit: int
    ) -> Sequence[PlanItem]:
        """Take up to ``limit`` pending items for dispatch.

        ``FOR UPDATE SKIP LOCKED`` lets the owner's concurrent dispatchers share
        one step's queue without blocking each other or double-taking a row.
        """
        stmt = (
            select(PlanItem)
            .where(
                PlanItem.scan_run_id == scan_run_id,
                PlanItem.stage == stage,
                PlanItem.step == step,
                PlanItem.state == PlanItemState.PLANNED.value,
            )
            .order_by(PlanItem.seq)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def mark_dispatched(
        self, *, plan_item_id: str, claim_epoch: int
    ) -> bool:
        """Move an item to DISPATCHED. ``False`` means another owner has it."""
        stmt = (
            update(PlanItem)
            .where(
                PlanItem.plan_item_id == plan_item_id,
                PlanItem.state == PlanItemState.PLANNED.value,
            )
            .values(
                state=PlanItemState.DISPATCHED.value,
                dispatched_at=func.now(),
                claim_epoch=claim_epoch,
                attempts=PlanItem.attempts + 1,
            )
        )
        return (await self._session.execute(stmt)).rowcount == 1

    async def settle_item(
        self,
        *,
        plan_item_id: str,
        claim_epoch: int,
        state: PlanItemState,
        outcome: str | None,
        reason_code: str | None,
        audit_event_id: str | None = None,
        record_count: int | None = None,
    ) -> None:
        """Record an item's recorded outcome, fenced on ``claim_epoch``."""
        values: dict[str, Any] = {
            "state": state.value,
            "outcome": outcome,
            "reason_code": reason_code,
            "audit_event_id": audit_event_id,
            "record_count": record_count,
            "claim_epoch": claim_epoch,
        }
        if state.is_terminal:
            values["settled_at"] = func.now()
        stmt = (
            update(PlanItem)
            .where(
                PlanItem.plan_item_id == plan_item_id,
                PlanItem.claim_epoch <= claim_epoch,
            )
            .values(**values)
        )
        await self._session.execute(stmt)

    async def reset_to_planned(self, *, plan_item_id: str, claim_epoch: int) -> None:
        """Return a dispatched item to the queue for a bounded retry.

        The stored execution identity is deliberately untouched: a retry
        presents the *same* identity, so a call that in fact completed returns
        its recorded outcome instead of running again.
        """
        stmt = (
            update(PlanItem)
            .where(
                PlanItem.plan_item_id == plan_item_id,
                PlanItem.state == PlanItemState.DISPATCHED.value,
            )
            .values(state=PlanItemState.PLANNED.value, claim_epoch=claim_epoch)
        )
        await self._session.execute(stmt)

    async def items_for_scan(self, scan_run_id: str) -> Sequence[PlanItem]:
        stmt = (
            select(PlanItem)
            .where(PlanItem.scan_run_id == scan_run_id)
            .order_by(PlanItem.stage, PlanItem.step, PlanItem.seq)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def items_for_step(
        self, *, scan_run_id: str, stage: str, step: str
    ) -> Sequence[PlanItem]:
        stmt = (
            select(PlanItem)
            .where(
                PlanItem.scan_run_id == scan_run_id,
                PlanItem.stage == stage,
                PlanItem.step == step,
            )
            .order_by(PlanItem.seq)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def indeterminate_items(
        self, *, scan_run_id: str, older_than_seconds: float | None = None
    ) -> Sequence[PlanItem]:
        """Dispatched items with no recorded settlement — possible traffic.

        Optionally restricted to those dispatched longer ago than the
        reconciliation window, which is what bounds reconciliation and stops
        ``RECONCILING`` becoming an absorbing state.
        """
        stmt = select(PlanItem).where(
            PlanItem.scan_run_id == scan_run_id,
            PlanItem.state == PlanItemState.DISPATCHED.value,
        )
        if older_than_seconds is not None:
            stmt = stmt.where(
                PlanItem.dispatched_at
                <= func.now() - timedelta(seconds=older_than_seconds)
            )
        return (await self._session.execute(stmt.order_by(PlanItem.seq))).scalars().all()


class AdmittedTargetRepository:
    """Admitted discovered targets (append-only planning decisions)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(self, rows: list[dict[str, Any]]) -> int:
        """Record admissions idempotently; returns the number newly recorded.

        Idempotent so a re-run of admission after a crash converges on the same
        admitted set instead of growing it — which would change downstream plan
        ordering and therefore downstream execution identities.
        """
        if not rows:
            return 0
        stmt = (
            pg_insert(AdmittedScanTarget)
            .values(rows)
            .on_conflict_do_nothing(constraint="uq_admitted_target_identity")
        )
        return (await self._session.execute(stmt)).rowcount or 0

    async def for_scan(self, scan_run_id: str) -> Sequence[AdmittedScanTarget]:
        stmt = (
            select(AdmittedScanTarget)
            .where(AdmittedScanTarget.scan_run_id == scan_run_id)
            .order_by(AdmittedScanTarget.canonical_target)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def count_for_scan(self, scan_run_id: str) -> int:
        stmt = (
            select(func.count())
            .select_from(AdmittedScanTarget)
            .where(AdmittedScanTarget.scan_run_id == scan_run_id)
        )
        return int((await self._session.execute(stmt)).scalar_one())


class RawFindingRepository:
    """Append-only evidence."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append_many(self, rows: list[dict[str, Any]]) -> int:
        """Insert evidence idempotently; returns the number newly recorded.

        ``ON CONFLICT DO NOTHING`` on (execution_id, finding_key) makes
        re-folding one execution's results safe, which is what lets a step be
        re-walked after a crash without duplicating what it found.
        """
        if not rows:
            return 0
        stmt = (
            pg_insert(RawFinding)
            .values(rows)
            .on_conflict_do_nothing(constraint="uq_raw_finding_identity")
        )
        return (await self._session.execute(stmt)).rowcount or 0

    async def for_scan(self, scan_run_id: str) -> Sequence[RawFinding]:
        stmt = (
            select(RawFinding)
            .where(RawFinding.scan_run_id == scan_run_id)
            .order_by(RawFinding.stage, RawFinding.step, RawFinding.finding_key)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def count_for_scan(self, scan_run_id: str) -> int:
        stmt = select(func.count()).select_from(RawFinding).where(
            RawFinding.scan_run_id == scan_run_id
        )
        return int((await self._session.execute(stmt)).scalar_one())


class ReportRepository:
    """Immutable report artifacts."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(
        self,
        *,
        report_id: str,
        scan_run_id: str,
        report_schema_version: str,
        report_digest: str,
        body: dict[str, Any],
        terminal_state: str,
        covered: int,
        denominator: int,
        finding_count: int,
        audit_event_id: str | None,
    ) -> None:
        self._session.add(
            ScanReport(
                report_id=report_id,
                scan_run_id=scan_run_id,
                report_schema_version=report_schema_version,
                report_digest=report_digest,
                body=body,
                terminal_state=terminal_state,
                covered=covered,
                denominator=denominator,
                finding_count=finding_count,
                audit_event_id=audit_event_id,
            )
        )

    async def get(self, report_id: str) -> ScanReport | None:
        return await self._session.get(ScanReport, report_id)

    async def latest_for_scan(self, scan_run_id: str) -> ScanReport | None:
        stmt = (
            select(ScanReport)
            .where(ScanReport.scan_run_id == scan_run_id)
            .order_by(ScanReport.generated_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()


class OrchestrationAuditRepository:
    """Append-only signed decision events."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        event_schema_version: str,
        payload: dict[str, Any],
        payload_digest: str,
        signer_kid: str,
        signature: str,
        scan_run_id: str | None = None,
        decision: str | None = None,
        reason_code: str | None = None,
        stage: str | None = None,
        step: str | None = None,
        initiated_by: str | None = None,
        claim_epoch: int | None = None,
    ) -> None:
        self._session.add(
            OrchestrationAudit(
                event_id=event_id,
                event_type=event_type,
                event_schema_version=event_schema_version,
                scan_run_id=scan_run_id,
                decision=decision,
                reason_code=reason_code,
                stage=stage,
                step=step,
                initiated_by=initiated_by,
                claim_epoch=claim_epoch,
                payload=payload,
                payload_digest=payload_digest,
                signer_kid=signer_kid,
                signature=signature,
            )
        )

    async def for_scan(self, scan_run_id: str) -> Sequence[OrchestrationAudit]:
        stmt = (
            select(OrchestrationAudit)
            .where(OrchestrationAudit.scan_run_id == scan_run_id)
            .order_by(OrchestrationAudit.recorded_at)
        )
        return (await self._session.execute(stmt)).scalars().all()


def _lifecycle_state(value: str | None) -> ScanLifecycleState | None:
    if value is None:
        return None
    try:
        return ScanLifecycleState(value)
    except ValueError:  # pragma: no cover - defensive against a hand-edited row
        return None
