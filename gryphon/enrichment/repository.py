"""Database access for the enrichment layer.

Every write here is one of three shapes:

* a **keyed insert** (``ON CONFLICT DO NOTHING``) followed, where content could
  differ, by a **read-back** that compares what is stored with what was meant to
  be stored — so a retried write is a no-op and a *different* write under the
  same identity is an :class:`IdentityConflictError`, never a silent keep-first;
* a **compare-and-set** on the slot lease or a pass's lifecycle row, fenced by
  ``claim_epoch`` and evaluated against the **database clock**;
* nothing else. There are no deletes and no updates of append-only rows.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.db.models import (
    AcquisitionAttempt,
    EgressLedger,
    EnrichmentAudit,
    EnrichmentPass,
    EnrichmentReport,
    EnrichmentSlot,
    FindingEnrichment,
    FindingPriority,
    IntelSnapshot,
    IntelSnapshotRevocation,
    RawFinding,
    ScanRun,
)
from gryphon.enrichment.audit import SignedEnrichmentEvent
from gryphon.enrichment.constants import (
    ENRICHMENT_SLOT_ID,
    AttemptResult,
    EnrichmentEventType,
    PassState,
)
from gryphon.enrichment.derive import AssertionRecord, PriorityRecord
from gryphon.enrichment.reasons import IdentityConflictError

_BATCH = 500
_COMPARED_ASSERTION_FIELDS = (
    "status",
    "reason",
    "remediation_class",
    "value",
    "value_schema_version",
    "snapshot_id",
    "asserted_by",
    "snapshot_age_s",
)


def _chunks(
    rows: Sequence[dict[str, Any]], size: int = _BATCH
) -> Iterable[Sequence[dict[str, Any]]]:
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


class EnrichmentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    @property
    def session(self) -> AsyncSession:
        return self._session

    async def db_now(self) -> datetime:
        return (await self._session.execute(select(func.now()))).scalar_one()

    # -- snapshots ------------------------------------------------------------
    def _not_revoked(self) -> ColumnElement[bool]:
        revoked = select(IntelSnapshotRevocation.snapshot_id).where(
            IntelSnapshotRevocation.snapshot_id == IntelSnapshot.snapshot_id
        )
        return ~revoked.exists()

    async def newest_snapshot(self, source: str) -> IntelSnapshot | None:
        stmt = (
            select(IntelSnapshot)
            .where(IntelSnapshot.source == source, self._not_revoked())
            .order_by(IntelSnapshot.order_key.desc(), IntelSnapshot.accepted_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_snapshot(self, snapshot_id: str) -> IntelSnapshot | None:
        return await self._session.get(IntelSnapshot, snapshot_id)

    async def is_revoked(self, snapshot_id: str) -> bool:
        stmt = select(IntelSnapshotRevocation.revocation_id).where(
            IntelSnapshotRevocation.snapshot_id == snapshot_id
        )
        return (await self._session.execute(stmt.limit(1))).first() is not None

    async def last_confirmed_at(self, snapshot: IntelSnapshot) -> datetime:
        """When acquisition last confirmed this snapshot is the newest published."""
        stmt = select(func.max(AcquisitionAttempt.finished_at)).where(
            AcquisitionAttempt.snapshot_id == snapshot.snapshot_id,
            AcquisitionAttempt.result.in_(
                (AttemptResult.ACCEPTED.value, AttemptResult.UNCHANGED.value)
            ),
        )
        confirmed = (await self._session.execute(stmt)).scalar_one_or_none()
        return max(confirmed, snapshot.accepted_at) if confirmed else snapshot.accepted_at

    async def kev_snapshots_since(
        self, since: datetime, before_order_key: str
    ) -> list[IntelSnapshot]:
        """KEV snapshots accepted since ``since``, plus the newest one before them.

        Ordered oldest first, excluding revoked snapshots, all strictly older (by
        order key) than the pinned one.
        """
        window = (
            await self._session.execute(
                select(IntelSnapshot)
                .where(
                    IntelSnapshot.source == "KEV",
                    IntelSnapshot.accepted_at >= since,
                    IntelSnapshot.order_key < before_order_key,
                    self._not_revoked(),
                )
                .order_by(IntelSnapshot.order_key)
            )
        ).scalars().all()
        previous = (
            await self._session.execute(
                select(IntelSnapshot)
                .where(
                    IntelSnapshot.source == "KEV",
                    IntelSnapshot.accepted_at < since,
                    IntelSnapshot.order_key < before_order_key,
                    self._not_revoked(),
                )
                .order_by(IntelSnapshot.order_key.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        return ([previous] if previous else []) + list(window)

    async def insert_snapshot(self, values: dict[str, Any]) -> bool:
        stmt = (
            pg_insert(IntelSnapshot)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["snapshot_id"])
            .returning(IntelSnapshot.snapshot_id)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def insert_revocation(self, values: dict[str, Any]) -> None:
        self._session.add(IntelSnapshotRevocation(**values))

    async def recent_attempts(self, source: str, limit: int) -> list[AcquisitionAttempt]:
        stmt = (
            select(AcquisitionAttempt)
            .where(AcquisitionAttempt.source == source)
            .order_by(AcquisitionAttempt.finished_at.desc())
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def insert_attempt(self, values: dict[str, Any]) -> None:
        self._session.add(AcquisitionAttempt(**values))

    async def insert_ledger(self, rows: Sequence[dict[str, Any]]) -> None:
        for chunk in _chunks(rows):
            await self._session.execute(pg_insert(EgressLedger).values(list(chunk)))

    # -- the slot (system-wide lease) -----------------------------------------
    async def claim_slot(self, holder: str, lease_seconds: float) -> int | None:
        """Take the slot if it is free or its lease has expired. Returns the epoch."""
        stmt = (
            update(EnrichmentSlot)
            .where(
                EnrichmentSlot.slot == ENRICHMENT_SLOT_ID,
                or_(
                    EnrichmentSlot.holder.is_(None),
                    EnrichmentSlot.lease_expires_at <= func.now(),
                ),
            )
            .values(
                holder=holder,
                claim_epoch=EnrichmentSlot.claim_epoch + 1,
                lease_expires_at=func.now() + timedelta(seconds=lease_seconds),
            )
            .returning(EnrichmentSlot.claim_epoch)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def slot_state(self) -> EnrichmentSlot | None:
        return await self._session.get(EnrichmentSlot, ENRICHMENT_SLOT_ID, populate_existing=True)

    async def renew_slot(self, holder: str, epoch: int, lease_seconds: float) -> bool:
        stmt = (
            update(EnrichmentSlot)
            .where(
                EnrichmentSlot.slot == ENRICHMENT_SLOT_ID,
                EnrichmentSlot.holder == holder,
                EnrichmentSlot.claim_epoch == epoch,
            )
            .values(lease_expires_at=func.now() + timedelta(seconds=lease_seconds))
            .returning(EnrichmentSlot.slot)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def release_slot(self, holder: str, epoch: int) -> None:
        await self._session.execute(
            update(EnrichmentSlot)
            .where(
                EnrichmentSlot.slot == ENRICHMENT_SLOT_ID,
                EnrichmentSlot.holder == holder,
                EnrichmentSlot.claim_epoch == epoch,
            )
            .values(holder=None, lease_expires_at=None)
        )

    # -- upstream reads (SELECT only) -----------------------------------------
    async def scan_exists(self, scan_run_id: str) -> bool:
        stmt = select(ScanRun.scan_run_id).where(ScanRun.scan_run_id == scan_run_id)
        return (await self._session.execute(stmt)).first() is not None

    async def missing_evidence(self, scan_run_id: str, finding_ids: Sequence[str]) -> set[str]:
        """Finding ids the verified report names but the evidence table lacks."""
        wanted = set(finding_ids)
        present: set[str] = set()
        ordered = sorted(wanted)
        for start in range(0, len(ordered), _BATCH):
            chunk = ordered[start : start + _BATCH]
            rows = await self._session.execute(
                select(RawFinding.finding_id).where(
                    RawFinding.scan_run_id == scan_run_id, RawFinding.finding_id.in_(chunk)
                )
            )
            present.update(rows.scalars().all())
        return wanted - present

    # -- passes ---------------------------------------------------------------
    async def open_pass(self, scan_run_id: str) -> EnrichmentPass | None:
        stmt = (
            select(EnrichmentPass)
            .where(
                EnrichmentPass.scan_run_id == scan_run_id,
                EnrichmentPass.state.in_((PassState.PLANNED.value, PassState.RUNNING.value)),
            )
            .order_by(EnrichmentPass.created_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_pass(self, pass_id: str) -> EnrichmentPass | None:
        return await self._session.get(EnrichmentPass, pass_id, populate_existing=True)

    async def passes_for_scan(self, scan_run_id: str) -> list[EnrichmentPass]:
        stmt = (
            select(EnrichmentPass)
            .where(EnrichmentPass.scan_run_id == scan_run_id)
            .order_by(EnrichmentPass.created_at)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def latest_complete_pass(self, scan_run_id: str) -> EnrichmentPass | None:
        stmt = (
            select(EnrichmentPass)
            .where(
                EnrichmentPass.scan_run_id == scan_run_id,
                EnrichmentPass.state == PassState.COMPLETE.value,
            )
            .order_by(EnrichmentPass.completed_at.desc(), EnrichmentPass.pass_id.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def insert_pass(self, values: dict[str, Any]) -> None:
        self._session.add(EnrichmentPass(**values))
        await self._session.flush()

    async def transition_pass(
        self,
        pass_id: str,
        *,
        epoch: int,
        expected_states: tuple[PassState, ...],
        **values: Any,
    ) -> bool:
        """Compare-and-set a pass's lifecycle row; False means fenced out."""
        stmt = (
            update(EnrichmentPass)
            .where(
                EnrichmentPass.pass_id == pass_id,
                EnrichmentPass.claim_epoch == epoch,
                EnrichmentPass.state.in_(tuple(s.value for s in expected_states)),
            )
            .values(**values)
            .returning(EnrichmentPass.pass_id)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def adopt_pass(self, pass_id: str, *, new_epoch: int) -> bool:
        """Re-fence an unfinished pass to the epoch of the slot just claimed."""
        stmt = (
            update(EnrichmentPass)
            .where(
                EnrichmentPass.pass_id == pass_id,
                EnrichmentPass.state.in_((PassState.PLANNED.value, PassState.RUNNING.value)),
                EnrichmentPass.claim_epoch < new_epoch,
            )
            .values(claim_epoch=new_epoch)
            .returning(EnrichmentPass.pass_id)
        )
        return (await self._session.execute(stmt)).first() is not None

    # -- outputs --------------------------------------------------------------
    async def insert_assertions(
        self, pass_id: str, scan_run_id: str, records: Sequence[AssertionRecord]
    ) -> None:
        rows = [
            {"pass_id": pass_id, "scan_run_id": scan_run_id, **r.as_payload()} for r in records
        ]
        for chunk in _chunks(rows):
            await self._session.execute(
                pg_insert(FindingEnrichment)
                .values(list(chunk))
                .on_conflict_do_nothing(index_elements=["pass_id", "finding_id", "source"])
            )
        stored = {
            (row.finding_id, row.source): row
            for row in (
                await self._session.execute(
                    select(FindingEnrichment).where(FindingEnrichment.pass_id == pass_id)
                )
            ).scalars()
        }
        for record in records:
            row = stored.get((record.finding_id, record.source))
            expected = record.as_payload()
            if row is None or any(
                getattr(row, name) != expected[name] for name in _COMPARED_ASSERTION_FIELDS
            ):
                raise IdentityConflictError(
                    f"assertion ({record.finding_id}, {record.source}) differs from the stored row"
                )

    async def insert_priorities(
        self, pass_id: str, scan_run_id: str, records: Sequence[PriorityRecord]
    ) -> None:
        rows = [
            {
                "pass_id": pass_id,
                "scan_run_id": scan_run_id,
                "finding_id": r.finding_id,
                "observed_severity": r.observed_severity,
                "priority": r.priority,
                "rationale": list(r.rationale),
                "policy_digest": r.policy_digest,
            }
            for r in records
        ]
        for chunk in _chunks(rows):
            await self._session.execute(
                pg_insert(FindingPriority)
                .values(list(chunk))
                .on_conflict_do_nothing(index_elements=["pass_id", "finding_id"])
            )
        stored = {
            row.finding_id: row
            for row in (
                await self._session.execute(
                    select(FindingPriority).where(FindingPriority.pass_id == pass_id)
                )
            ).scalars()
        }
        for record in records:
            row = stored.get(record.finding_id)
            if (
                row is None
                or row.priority != record.priority
                or row.policy_digest != record.policy_digest
                or row.rationale != list(record.rationale)
            ):
                raise IdentityConflictError(
                    f"priority for {record.finding_id} differs from the stored row"
                )

    async def insert_report(self, values: dict[str, Any]) -> None:
        self._session.add(EnrichmentReport(**values))

    def add_event(
        self, event: SignedEnrichmentEvent, *, initiated_by: str,
        scan_run_id: str | None = None, pass_id: str | None = None,
    ) -> None:
        self._session.add(
            EnrichmentAudit(
                event_id=event.event_id,
                event_type=event.event_type,
                event_schema_version=str(event.payload["event_schema_version"]),
                scan_run_id=scan_run_id,
                pass_id=pass_id,
                initiated_by=initiated_by,
                payload=event.payload,
                payload_digest=event.payload_digest,
                signer_kid=event.signer_kid,
                signature=event.signature_b64,
            )
        )

    async def latest_report(self, scan_run_id: str) -> EnrichmentReport | None:
        stmt = (
            select(EnrichmentReport)
            .join(EnrichmentPass, EnrichmentPass.pass_id == EnrichmentReport.pass_id)
            .where(
                EnrichmentReport.scan_run_id == scan_run_id,
                EnrichmentPass.state == PassState.COMPLETE.value,
            )
            .order_by(EnrichmentPass.completed_at.desc(), EnrichmentPass.pass_id.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def report_event(self, report: EnrichmentReport) -> EnrichmentAudit | None:
        stmt = select(EnrichmentAudit).where(
            EnrichmentAudit.event_id == report.audit_event_id,
            EnrichmentAudit.event_type == EnrichmentEventType.ENRICHMENT_REPORT_EMITTED.value,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def priorities_for_pass(self, pass_id: str) -> list[FindingPriority]:
        stmt = select(FindingPriority).where(FindingPriority.pass_id == pass_id)
        return list((await self._session.execute(stmt)).scalars().all())
