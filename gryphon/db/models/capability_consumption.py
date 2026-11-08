"""``capability_consumption`` — authoritative single-use nonce state.

A unique insert on ``capability_id`` is the compare-and-set that gates spawning
(CHG-005). This is PostgreSQL, never a cache (CHG-006): absence here means "not
consumed", and a cache could not provide that guarantee. Append-only.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class CapabilityConsumption(Base):
    __tablename__ = "capability_consumption"

    capability_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    consumed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
