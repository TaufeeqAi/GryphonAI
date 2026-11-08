"""``tool_execution`` — the Execution aggregate (idempotent by ``execution_id``).

A sibling of the authorization tables; the authorization schema is untouched.
Unlike the append-only audit, this row is UPDATEd across its lifecycle
(ADMITTED → RUNNING → outcome) by the runtime role.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class ToolExecution(Base):
    __tablename__ = "tool_execution"

    execution_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False, index=True
    )
    tool_id: Mapped[str] = mapped_column(String(32), nullable=False)
    capability_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    credential_source: Mapped[str] = mapped_column(String(16), nullable=False)

    canonical_target: Mapped[str | None] = mapped_column(Text, nullable=True)
    pinned_destinations: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    requested_depth: Mapped[str | None] = mapped_column(String(16), nullable=True)
    effective_depth: Mapped[str | None] = mapped_column(String(16), nullable=True)

    state: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    per_target: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    degraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    intent_committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    outcome_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
