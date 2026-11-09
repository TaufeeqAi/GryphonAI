"""``scan_report`` and ``orchestration_audit`` — the deliverable and its record.

``scan_report`` is immutable and append-only. A report is what a client
actually receives, so it is stored once and never edited; a correction is a new
row. It carries its own content digest, and a signed ``orchestration_audit``
event carries that same digest.

That indirection is deliberate. Signing the report with the audit key would mix
key purposes — the upstream layers keep grant, audit and capability keys
separate precisely so that a compromise of one does not forge the others — and
inventing a fourth key would mean inventing a fourth verifier, when a signature
nobody verifies is ritual rather than assurance. Carrying the digest inside an
audit event that an existing verifier already checks gives the same tamper
evidence with no new key and no new trust path.

``orchestration_audit`` is the accountability record for this layer's own
decisions: the gate, the committed plans, target admission, lifecycle
transitions, reconciliation and operator commands. The upstream layers audit
"was this authorized?" and "was this call enforced?"; neither records *why this
host was chosen*, which is the one question only this layer can answer. Logs are
diagnostic and may be lost; this table is not.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class ScanReport(Base):
    """An emitted report artifact. Immutable; a correction is a new row."""

    __tablename__ = "scan_report"

    report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False, index=True
    )
    report_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Digest over the canonical report body. Attested by a signed audit event.
    report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The report body: summary, coverage block, assurance block, findings.
    body: Mapped[dict] = mapped_column(JSONB, nullable=False)
    #: Denormalized for cheap listing without parsing the body.
    terminal_state: Mapped[str] = mapped_column(String(40), nullable=False)
    covered: Mapped[int] = mapped_column(Integer, nullable=False)
    denominator: Mapped[int] = mapped_column(Integer, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Audit event that attests this report's digest.
    audit_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OrchestrationAudit(Base):
    """Signed, append-only orchestration decision events."""

    __tablename__ = "orchestration_audit"
    __table_args__ = (Index("ix_orchestration_audit_scan", "scan_run_id", "event_type"),)

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    event_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Nullable: a gate denial may be recorded for a scan id that has no
    #: lifecycle row yet, and a refused invocation must still be accountable.
    scan_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    step: Mapped[str | None] = mapped_column(String(64), nullable=True)
    initiated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    claim_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)

    #: Canonical signed payload, its digest, and the signature over it.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_kid: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
