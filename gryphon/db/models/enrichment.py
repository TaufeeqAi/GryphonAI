"""Enrichment tables — accepted snapshots, passes, assertions and the deliverable.

Two kinds of table, and the distinction is the security model:

* **Append-only** (row triggers reject UPDATE/DELETE; a statement trigger rejects
  TRUNCATE): ``intel_snapshot``, ``intel_snapshot_revocation``,
  ``acquisition_attempt``, ``egress_ledger``, ``finding_enrichment``,
  ``finding_priority``, ``enrichment_report``, ``enrichment_audit``.
  Revoking a snapshot is a new row, never an edit.
* **Lifecycle** (column-scoped UPDATE only): ``enrichment_slot`` — the single
  system-wide lease that serializes passes — and ``enrichment_pass``.

Assertions are keyed ``(pass_id, finding_id, source)`` and bound to their scan
twice over: to the pass's scan by a composite FK, and to the evidence row's scan
by a composite FK onto ``raw_finding(scan_run_id, finding_id)``. An assertion
cannot attach one engagement's finding to another engagement's scan.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class IntelSnapshot(Base):
    """An accepted, content-addressed public snapshot (KEV catalog, EPSS file)."""

    __tablename__ = "intel_snapshot"
    __table_args__ = (Index("ix_intel_snapshot_source_order", "source", "order_key"),)

    #: ``<SOURCE>:<label>@sha256:<raw digest>`` — a label is never an identity.
    snapshot_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    label: Mapped[str] = mapped_column(String(64), nullable=False)
    order_key: Mapped[str] = mapped_column(String(96), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    meta_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fetched_from: Mapped[str] = mapped_column(String(128), nullable=False)
    acceptance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IntelSnapshotRevocation(Base):
    __tablename__ = "intel_snapshot_revocation"

    revocation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(
        String(160), ForeignKey("intel_snapshot.snapshot_id"), nullable=False, index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_by: Mapped[str] = mapped_column(String(128), nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AcquisitionAttempt(Base):
    """One acquisition attempt of one source: the freshness and breaker record."""

    __tablename__ = "acquisition_attempt"
    __table_args__ = (Index("ix_acquisition_attempt_source_time", "source", "finished_at"),)

    attempt_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    pass_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_class: Mapped[str | None] = mapped_column(String(16), nullable=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    egress_posture: Mapped[str] = mapped_column(String(16), nullable=False)
    initiated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EgressLedger(Base):
    """One outbound request. Carries no engagement-derived value, by construction."""

    __tablename__ = "egress_ledger"

    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    host: Mapped[str] = mapped_column(String(128), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_received: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    outcome_class: Mapped[str] = mapped_column(String(16), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    finished_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EnrichmentSlot(Base):
    """The single system-wide lease: at most one pass (or refresh) runs at a time."""

    __tablename__ = "enrichment_slot"

    slot: Mapped[str] = mapped_column(String(16), primary_key=True)
    holder: Mapped[str | None] = mapped_column(String(80), nullable=True)
    claim_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class EnrichmentPass(Base):
    """The unit of work. Pins its inputs once; completes exactly once."""

    __tablename__ = "enrichment_pass"
    __table_args__ = (
        UniqueConstraint("pass_id", "scan_run_id", name="uq_enrichment_pass_scan"),
        Index("ix_enrichment_pass_scan_state", "scan_run_id", "state"),
    )

    pass_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(48), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    base_report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    base_report_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    plan_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pins: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    manifest: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    claim_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FindingEnrichment(Base):
    """One attributed assertion: what one source said about one finding, in one pass."""

    __tablename__ = "finding_enrichment"
    __table_args__ = (
        ForeignKeyConstraint(
            ["pass_id", "scan_run_id"],
            ["enrichment_pass.pass_id", "enrichment_pass.scan_run_id"],
            name="fk_finding_enrichment_pass_scan",
        ),
        ForeignKeyConstraint(
            ["scan_run_id", "finding_id"],
            ["raw_finding.scan_run_id", "raw_finding.finding_id"],
            name="fk_finding_enrichment_evidence",
        ),
        # Named by the metadata convention: ck_finding_enrichment_<name>.
        CheckConstraint(
            "snapshot_id IS NOT NULL OR reason IN ('no_accepted_snapshot', 'dataset_unavailable')",
            name="snapshot",
        ),
        CheckConstraint(
            "status IN ('ENRICHED', 'NOT_APPLICABLE', 'UNAVAILABLE')",
            name="status",
        ),
    )

    pass_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(240), nullable=True)
    remediation_class: Mapped[str | None] = mapped_column(String(16), nullable=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    value_schema_version: Mapped[str] = mapped_column(String(8), nullable=False)
    snapshot_id: Mapped[str | None] = mapped_column(String(240), nullable=True)
    asserted_by: Mapped[str] = mapped_column(String(24), nullable=False)
    snapshot_age_s: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class FindingPriority(Base):
    """The derived priority of one finding in one pass, with its named reasons."""

    __tablename__ = "finding_priority"
    __table_args__ = (
        ForeignKeyConstraint(
            ["pass_id", "scan_run_id"],
            ["enrichment_pass.pass_id", "enrichment_pass.scan_run_id"],
            name="fk_finding_priority_pass_scan",
        ),
        ForeignKeyConstraint(
            ["scan_run_id", "finding_id"],
            ["raw_finding.scan_run_id", "raw_finding.finding_id"],
            name="fk_finding_priority_evidence",
        ),
    )

    pass_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    observed_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    rationale: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    policy_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EnrichmentReport(Base):
    """The enrichment deliverable. Immutable; attested by a signed event."""

    __tablename__ = "enrichment_report"

    report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    pass_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("enrichment_pass.pass_id"), nullable=False, unique=True
    )
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="ENRICHMENT")
    base_report_id: Mapped[str] = mapped_column(String(64), nullable=False)
    base_report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    report_schema_version: Mapped[str] = mapped_column(String(8), nullable=False)
    body: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EnrichmentAudit(Base):
    """Signed enrichment events (enrichment key). Append-only."""

    __tablename__ = "enrichment_audit"
    __table_args__ = (Index("ix_enrichment_audit_scan", "scan_run_id", "event_type"),)

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    event_schema_version: Mapped[str] = mapped_column(String(8), nullable=False)
    scan_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    pass_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_kid: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
