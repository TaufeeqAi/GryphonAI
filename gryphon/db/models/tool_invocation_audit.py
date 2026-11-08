"""``tool_invocation_audit`` — signed, append-only tool-call audit events.

Dedicated sibling table; the authorization audit table is never overloaded
(CHG-017). Intent and outcome events are both recorded and signed; runtime-role
UPDATE/DELETE are rejected by trigger + privilege, reusing the authorization
core's append-only controls.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class ToolInvocationAudit(Base):
    __tablename__ = "tool_invocation_audit"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)  # intent | outcome
    event_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False, index=True
    )
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    tool_id: Mapped[str] = mapped_column(String(32), nullable=False)
    capability_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    decision: Mapped[str | None] = mapped_column(String(8), nullable=True)   # ALLOW | DENY
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)

    canonical_target: Mapped[str | None] = mapped_column(Text, nullable=True)
    pinned_destinations_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    external_disclosure: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    descriptor_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_kid: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
