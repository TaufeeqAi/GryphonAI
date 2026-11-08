"""Execution-aggregate repository (idempotent by ``execution_id``)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.db.models.tool_execution import ToolExecution


class ToolExecutionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, execution_id: str) -> ToolExecution | None:
        return await self._session.get(ToolExecution, execution_id)

    def add(
        self,
        *,
        execution_id: str,
        scan_run_id: str,
        tool_id: str,
        credential_source: str,
        state: str,
        intent_committed_at: datetime,
        reason_code: str | None = None,
        capability_id: str | None = None,
        canonical_target: str | None = None,
        pinned_destinations: list | None = None,
        requested_depth: str | None = None,
        effective_depth: str | None = None,
    ) -> ToolExecution:
        row = ToolExecution(
            execution_id=execution_id,
            scan_run_id=scan_run_id,
            tool_id=tool_id,
            credential_source=credential_source,
            state=state,
            reason_code=reason_code,
            capability_id=capability_id,
            canonical_target=canonical_target,
            pinned_destinations=pinned_destinations,
            requested_depth=requested_depth,
            effective_depth=effective_depth,
            intent_committed_at=intent_committed_at,
            per_target=[],
        )
        self._session.add(row)
        return row

    @staticmethod
    def apply_outcome(
        row: ToolExecution,
        *,
        state: str,
        outcome: str,
        reason_code: str,
        outcome_at: datetime,
        record_count: int | None = None,
        per_target: list | None = None,
        truncated: bool = False,
        degraded: bool = False,
    ) -> None:
        row.state = state
        row.outcome = outcome
        row.reason_code = reason_code
        row.outcome_at = outcome_at
        row.record_count = record_count
        if per_target is not None:
            row.per_target = per_target
        row.truncated = truncated
        row.degraded = degraded
