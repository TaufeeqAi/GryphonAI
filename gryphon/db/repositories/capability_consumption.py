"""Capability consumption repository — the compare-and-set that gates spawning."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.db.models.capability_consumption import CapabilityConsumption


class CapabilityConsumptionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def stage(
        self,
        *,
        capability_id: str,
        nonce: str,
        scan_run_id: str,
        execution_id: str,
        expires_at: datetime,
    ) -> None:
        """Stage the single-use consumption row inside the intent transaction.

        The unique primary key on ``capability_id`` is the compare-and-set: if
        the capability was already consumed, the transaction's commit raises a
        unique violation and the caller reconciles (the row that committed won;
        the loser MUST NOT spawn). Staging (no flush) keeps consumption, the
        intent row and the intent audit in one atomic commit.
        """
        self._session.add(
            CapabilityConsumption(
                capability_id=capability_id,
                nonce=nonce,
                scan_run_id=scan_run_id,
                execution_id=execution_id,
                expires_at=expires_at,
            )
        )

    async def exists(self, capability_id: str) -> bool:
        return (await self._session.get(CapabilityConsumption, capability_id)) is not None
