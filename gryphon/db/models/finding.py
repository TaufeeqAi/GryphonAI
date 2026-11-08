"""``findings`` — master-plan finding schema (§22.1).

Phase 1 does NOT create findings from scans; it supplies the schema for later
producers (Phases 4–5). Enumerations are validated at the domain boundary; the
master defaults (``verification_status=unverified``, ``remediation_status=open``,
empty ``compliance_frameworks``) are preserved. ``scan_run_id`` is a
string-compatible canonical UUID to preserve the master model shape.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Location
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    subdomain: Mapped[str | None] = mapped_column(String(512), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Classification
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Verification (NodeZero pattern: proof not theory)
    verification_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unverified", server_default="unverified"
    )
    verification_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    proof_of_concept: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_artifact_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Exploit-chain linkage (schema only; no Phase 1 producer — §34)
    exploit_chain_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    chain_position: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Compliance mapping
    compliance_frameworks: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    # Remediation tracking
    remediation_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="open", server_default="open"
    )
    remediation_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    tool_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
