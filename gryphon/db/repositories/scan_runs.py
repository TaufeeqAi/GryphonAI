"""Scan-run admission repository (BND-05).

``scan_runs`` is the sole Phase 1 admission identity. Uniqueness on
``idempotency_key_hash`` enforces one row per logical admission (INV-010/014).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.constants import DecisionStatus, ScanRunStatus
from gryphon.db.models.scan_run import ScanRun
from gryphon.errors import ReasonCode


class ScanRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_idempotency_hash(self, idempotency_hash: str) -> ScanRun | None:
        stmt = select(ScanRun).where(ScanRun.idempotency_key_hash == idempotency_hash)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    def add(
        self,
        *,
        scan_run_id: str,
        decision: DecisionStatus,
        status: ScanRunStatus,
        reason_code: ReasonCode,
        idempotency_key_hash: str,
        request_hash: str,
        decided_at: datetime,
        grant_id: str | None = None,
        target_requested: str | None = None,
        canonical_target: str | None = None,
        path_requested: str | None = None,
        canonical_path: str | None = None,
        requested_depth: str | None = None,
        effective_depth: str | None = None,
        scope_policy_version: str | None = None,
    ) -> ScanRun:
        """Stage a terminal admission row for insertion (no commit)."""
        row = ScanRun(
            scan_run_id=scan_run_id,
            grant_id=grant_id,
            target_requested=target_requested,
            canonical_target=canonical_target,
            path_requested=path_requested,
            canonical_path=canonical_path,
            requested_depth=requested_depth,
            effective_depth=effective_depth,
            decision=decision.value,
            status=status.value,
            reason_code=reason_code.value,
            scope_policy_version=scope_policy_version,
            idempotency_key_hash=idempotency_key_hash,
            request_hash=request_hash,
            decided_at=decided_at,
        )
        self._session.add(row)
        return row
