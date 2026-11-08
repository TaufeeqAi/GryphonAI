"""``scan_runs`` — the single Phase 1 admission/operation identity (§22.1).

There is no parallel ``authorization_admissions`` table (§6.3, INV-010). Phase 1
persists only terminal admission outcomes (ALLOW / DENY). Phase 3 may add
execution-lifecycle columns in a forward migration but MUST preserve this stable
``scan_run_id`` (§14.2).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class ScanRun(Base):
    __tablename__ = "scan_runs"

    # Server-generated canonical UUID text; never caller-supplied.
    scan_run_id: Mapped[str] = mapped_column(String(36), primary_key=True)

    # Nullable: invalid-token denials may have no known grant.
    grant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("authorization_grants.grant_id"), nullable=True, index=True
    )

    target_requested: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_target: Mapped[str | None] = mapped_column(Text, nullable=True)
    path_requested: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    requested_depth: Mapped[str | None] = mapped_column(String(16), nullable=True)
    effective_depth: Mapped[str | None] = mapped_column(String(16), nullable=True)

    decision: Mapped[str] = mapped_column(String(8), nullable=False)  # ALLOW | DENY
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    scope_policy_version: Mapped[str | None] = mapped_column(String(16), nullable=True)

    idempotency_key_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
