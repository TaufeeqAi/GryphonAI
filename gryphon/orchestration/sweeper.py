"""The recovery sweeper — the agent that makes recovery happen.

Reconciliation semantics without an agent to run them is a recurring trap in
this codebase's history: the rules were specified, and then nothing was
responsible for applying them, so recovery only occurred when a human happened
to invoke something. At one concurrent scan that is invisible. At scheduled
re-scanning it is a backlog that grows forever, silently.

So this is a real component with its own lifecycle. On each pass it looks for:

* **abandoned scans** — non-terminal with an expired lease, i.e. an owner that
  died. It takes them over and resumes them, which is just a normal invocation.
* **overdue scans** — past their effective deadline. Aborted, truthfully, rather
  than left running past the authorization that permitted them.

The sweeper is itself lease-protected: it takes over a scan the same fenced way
any owner does, so it can never race the live owner it was meant to replace.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.logging_config import get_logger
from gryphon.orchestration.constants import ScanLifecycleState
from gryphon.orchestration.ledger import ScanLifecycleRepository
from gryphon.orchestration.orchestrator import ScanOrchestrator
from gryphon.orchestration.reasons import OrchestrationReasonCode, StaleClaimError
from gryphon.orchestration.runtime import ScanRuntime

logger = get_logger(__name__)

#: Caller recorded for work the sweeper initiates on its own account.
SWEEPER_IDENTITY = "recovery-sweeper"


@dataclass(frozen=True, slots=True)
class SweepReport:
    """What one sweep found and did."""

    reclaimed: int
    aborted_overdue: int

    @property
    def acted(self) -> bool:
        return self.reclaimed > 0 or self.aborted_overdue > 0


class RecoverySweeper:
    """Periodically reclaims abandoned scans and retires overdue ones."""

    def __init__(
        self, *, runtime: ScanRuntime, orchestrator: ScanOrchestrator
    ) -> None:
        self._runtime = runtime
        self._orchestrator = orchestrator

    async def sweep_once(self, *, limit: int = 25) -> SweepReport:
        """Run a single pass. Safe to call concurrently with live scans."""
        aborted = await self._retire_overdue(limit=limit)
        reclaimed = await self._reclaim_abandoned(limit=limit)
        report = SweepReport(reclaimed=reclaimed, aborted_overdue=aborted)
        if report.acted:
            logger.info(
                "sweep_complete",
                reclaimed=report.reclaimed,
                aborted_overdue=report.aborted_overdue,
            )
        return report

    async def run_forever(self, *, stop: asyncio.Event | None = None) -> None:
        """Sweep on the configured interval until stopped."""
        interval = self._runtime.settings.sweeper_interval_seconds
        while True:
            if stop is not None and stop.is_set():
                return
            try:
                await self.sweep_once()
            except Exception as exc:  # a sweep must never kill the sweeper
                logger.warning("sweep_failed", error=type(exc).__name__)
            try:
                if stop is None:
                    await asyncio.sleep(interval)
                else:
                    await asyncio.wait_for(stop.wait(), timeout=interval)
                    return
            except asyncio.TimeoutError:
                continue

    # -- passes ---------------------------------------------------------------
    async def _reclaim_abandoned(self, *, limit: int) -> int:
        """Resume scans whose owner died.

        Resuming is an ordinary invocation: the orchestrator takes over via the
        fenced claim, the graph re-enters at the gate, covered work is re-walked
        as no-ops and pending work is dispatched.
        """
        try:
            async with self._runtime.database.session() as session:
                candidates = await ScanLifecycleRepository(session).find_reclaimable(
                    limit=limit
                )
                ids = [(row.scan_run_id, row.initiated_by) for row in candidates]
        except (OperationalError, DBAPIError):
            return 0

        reclaimed = 0
        for scan_run_id, original_initiator in ids:
            logger.info("reclaiming_abandoned_scan", scan_run_id=scan_run_id)
            try:
                outcome = await self._orchestrator.invoke(
                    scan_run_id, initiated_by=original_initiator or SWEEPER_IDENTITY
                )
            except Exception as exc:
                logger.warning(
                    "reclaim_failed",
                    scan_run_id=scan_run_id,
                    error=type(exc).__name__,
                )
                continue
            if outcome.reason_code != OrchestrationReasonCode.ALREADY_RUNNING.value:
                reclaimed += 1
        return reclaimed

    async def _retire_overdue(self, *, limit: int) -> int:
        """Abort scans past their effective deadline.

        The deadline already incorporates the grant's expiry, so this is the
        backstop that stops work outliving the authorization even if no owner is
        alive to notice.
        """
        try:
            async with self._runtime.database.session() as session:
                overdue = await ScanLifecycleRepository(session).find_overdue(limit=limit)
                rows = [(r.scan_run_id, r.claim_epoch) for r in overdue]
        except (OperationalError, DBAPIError):
            return 0

        retired = 0
        for scan_run_id, claim_epoch in rows:
            try:
                async with self._runtime.database.session() as session:
                    async with session.begin():
                        await ScanLifecycleRepository(session).transition(
                            scan_run_id=scan_run_id,
                            claim_epoch=claim_epoch,
                            state=ScanLifecycleState.ABORTED_DEADLINE,
                            reason_code=OrchestrationReasonCode.SCAN_DEADLINE_EXCEEDED.value,
                        )
                retired += 1
                logger.info("scan_aborted_deadline", scan_run_id=scan_run_id)
            except StaleClaimError:
                # A live owner advanced the scan between our read and our write.
                continue
            except (OperationalError, DBAPIError):
                continue
        return retired
