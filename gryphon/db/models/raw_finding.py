"""``raw_finding`` — append-only observed evidence, with provenance.

This layer produces *evidence*: what a tool observed. It never produces meaning
or truth, and this table's shape is what keeps that boundary real.

Two decisions carry weight:

* **Append-only.** Later layers attach enrichment and verification as separate,
  attributed rows; they cannot mutate evidence. Otherwise the first component to
  write ``verified = true`` onto the observation makes its assertion
  authoritative over the observation itself, and the distinction becomes
  unrecoverable — you can no longer tell what was *seen* from what was *claimed*.
* **Provenance is mandatory.** Every row carries the ``execution_id`` and the
  enforcement layer's ``audit_event_id``, so the report can corroborate each
  finding against a signed execution record. A deliverable assembled from a
  mutable store nothing cross-checks is a deliverable anything with write access
  can author.

``verification_status`` and ``enrichment_status`` are NOT NULL with explicit
not-performed defaults, so a report cannot omit the assurance level and let a
reader assume more than was done. This is a sibling of the master-plan
``findings`` table (which remains the enriched/verified surface for later
layers); the authorization schema is untouched.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
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


class RawFinding(Base):
    __tablename__ = "raw_finding"
    __table_args__ = (
        # Idempotent recording: re-folding one execution's results cannot
        # duplicate evidence, which is what makes a retried or re-walked step
        # safe to repeat.
        UniqueConstraint("execution_id", "finding_key", name="uq_raw_finding_identity"),
        Index("ix_raw_finding_scan", "scan_run_id", "stage", "step"),
    )

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False, index=True
    )

    # -- provenance (mandatory) ----------------------------------------------
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    #: Signed enforcement-layer audit event that recorded the producing outcome.
    audit_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    plan_item_id: Mapped[str] = mapped_column(String(64), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    step: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Stable within one execution; dedupes identical observations.
    finding_key: Mapped[str] = mapped_column(String(128), nullable=False)

    # -- observation ----------------------------------------------------------
    canonical_target: Mapped[str] = mapped_column(Text, nullable=False)
    observation_type: Mapped[str] = mapped_column(String(48), nullable=False)
    #: Bounded, sanitized tool output. Produced by the enforcement layer's
    #: projection, not raw stdout.
    observation: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # -- assurance (explicit, never implied) ---------------------------------
    verification_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="NOT_VERIFIED", server_default="NOT_VERIFIED"
    )
    enrichment_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="NOT_PERFORMED", server_default="NOT_PERFORMED"
    )

    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
