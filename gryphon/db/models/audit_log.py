"""``authorization_audit_log`` — signed, append-only audit event (§22.1, BND-06).

The ``payload`` column stores the exact RFC 8785 canonical dict that was signed;
``payload_digest`` and ``signature`` let a verifier detect tampering of retained
rows (SEC-013). Runtime-role UPDATE/DELETE/TRUNCATE are denied by privilege +
trigger (§22.3); this ORM model never issues them.

Immutability qualification (§19.5): this detects runtime-role tampering, not a
PostgreSQL superuser/owner deletion or a full backup rollback.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class AuthorizationAuditLog(Base):
    __tablename__ = "authorization_audit_log"

    # Database identity.
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Signed event identity (unique).
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    event_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)

    # Admission events reference their scan_run_id; issuance events leave it NULL.
    scan_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=True, index=True
    )
    grant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    # Safe, bounded representations (never verbatim control-char / oversized input).
    target_requested: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_target: Mapped[str | None] = mapped_column(Text, nullable=True)
    path_requested: Mapped[str | None] = mapped_column(Text, nullable=True)

    authorization_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    scope_check_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    decision: Mapped[str | None] = mapped_column(String(8), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)

    requested_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    organization: Mapped[str | None] = mapped_column(String(320), nullable=True)
    scope_policy_version: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Exact signed canonical payload + integrity fields.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_kid: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
