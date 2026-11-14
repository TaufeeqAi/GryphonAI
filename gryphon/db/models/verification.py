"""Verification tables — the pass, its pinned inputs, observations and verdicts.

Three kinds of table, and the difference between them is the security model:

* **Lifecycle** (column-scoped UPDATE; DELETE rejected per row):
  ``verification_pass``. Its state, lease, epochs and outcome move. Nothing
  else about a pass ever moves.
* **Append-only** (UPDATE/DELETE rejected per row, TRUNCATE per statement):
  ``verification_pass_pin``, ``verification_observation``,
  ``finding_verification``, ``verification_retraction``,
  ``verification_report``, ``verification_audit``. Withdrawing a verifier emits
  a retraction row; it never edits the verdict that rested on it, because a
  proof that has been taken back is a different fact from a proof that was
  never made.
* **Range-partitioned monthly** (and append-only): ``verification_observation``
  and ``finding_verification``. Partitioning them from the first migration is
  deliberate — retrofitting partitions under append-only, trigger-protected,
  signed rows means moving exactly the rows that must not move.

Five decisions carry weight:

* **Pins live in their own write-once table.** The pin row is the provenance
  root of every append-only row in the pass: the registry, extractor, estate,
  resolver and feature digests the plan was derived from, plus the base report
  it adjudicates. If it could be rewritten, published work would stop being
  traceable to the inputs that produced it. Its primary key *is* the write-once
  guarantee — a second insert collides instead of overwriting — and no role
  holds UPDATE on it at all.
* **A verdict is bound to its scan twice over.** ``finding_verification``
  carries a composite foreign key to the pass's scan and another onto
  ``raw_finding(scan_run_id, finding_id)``. One engagement's finding therefore
  cannot be attached to another engagement's scan, whatever a caller passes.
* **``subject_key`` is NOT NULL.** A ``raw_finding`` id is unique per scan, so
  without a subject identity two scans of the same unchanged exposure share
  nothing to join on and "is Monday's confirmed exposure still there?" has no
  answer. It is written from the first migration because adding an identity
  underneath append-only signed rows later is the expensive path.
* **Claim time comes from the database.** Every timestamp here defaults to
  ``func.now()``, which is evaluated by PostgreSQL inside the INSERT. A
  default computed when the Python object was constructed would record the
  writer's wall clock, and the lease, the deadline rule and the supersession
  order in the read view are all comparisons against one clock.
* **The pass salt never leaves these rows.** It keys observation identities and
  control locators, so a target that could predict it could special-case the
  controls. It appears in no view, and the read view below is built from the
  verdict table alone.

Two consequences of partitioning are visible in the keys and are not
negotiable in PostgreSQL: a unique constraint on a partitioned table must
contain the partition key, so the contract's ``UNIQUE (execution_id)`` and
``PRIMARY KEY (pass_id, finding_id)`` are declared here with the partition
column appended, and the narrow form is created per partition by the migration.
Within one retention month — which is the window in which a resumed pass can
replay an identity — the narrow form is exactly the contract's.

The CHECK constraints spell out the closed sets that
:mod:`gryphon.verification.constants` defines. They are written as literals, as
in the other model modules, so that the schema has no import dependency on the
layer that writes it; the two must be changed together, and the readiness check
compares the deployed constraints against the same enums.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base

#: States in which a pass still owns its scan. The partial unique index below
#: uses the same three, which is what makes "one open pass per scan" a database
#: fact rather than a convention two concurrent callers might both respect. The
#: members are listed in sorted order, as the migration's shared facts list
#: them, so a schema built from this metadata and one built by the migration end
#: up with the same index definition rather than two that merely behave alike.
_OPEN_STATES = "'BLOCKED', 'PLANNED', 'RUNNING'"


class VerificationPass(Base):
    """One fenced, leased pass over one scan's findings.

    The lease columns and ``claim_epoch`` exist because a lost process must be
    recoverable without two owners: the next caller waits for the lease to
    lapse, adopts the pass at a higher epoch, and every later write is fenced on
    that epoch. ``cancellation_epoch`` is the stop control — advancing it makes
    the gateway refuse the next dispatch — and ``adoption_count`` bounds
    recovery, because a pass whose own work kills the process that adopts it
    would otherwise be adopted forever by a queue of identical workers, each one
    re-contacting the same hosts.
    """

    __tablename__ = "verification_pass"
    __table_args__ = (
        # One logical command, one pass, permanently: a repeated command after a
        # lost response returns the original pass instead of sending traffic
        # again. A NULL key is a caller declining idempotency, and PostgreSQL
        # treats NULLs as distinct, so such passes never collide with each other.
        UniqueConstraint("scan_run_id", "request_key", name="uq_verification_pass_request_key"),
        # Trivially true (pass_id is the key). It exists so derived rows can
        # carry a composite foreign key binding each one to its own scan.
        UniqueConstraint("pass_id", "scan_run_id", name="uq_verification_pass_scan"),
        # One open pass per scan. Declared here as well as in the migration
        # because the first migration builds every model table on a fresh
        # database, and an index that existed only in the migration would be
        # absent from any schema built straight from the metadata.
        Index(
            "uq_verification_pass_open",
            "scan_run_id",
            unique=True,
            postgresql_where=text(f"state IN ({_OPEN_STATES})"),
        ),
        Index("ix_verification_pass_scan_state", "scan_run_id", "state"),
        # Named by the metadata convention: ck_verification_pass_<name>.
        CheckConstraint(
            "state IN ('PLANNED', 'RUNNING', 'BLOCKED', 'COMPLETE', 'REFUSED', 'ABANDONED')",
            name="state",
        ),
        CheckConstraint(
            "outcome IS NULL OR outcome IN ('VERIFIED', 'VERIFIED_WITH_GAPS', "
            "'VERIFICATION_DEGRADED', 'NOTHING_TO_VERIFY')",
            name="outcome",
        ),
        CheckConstraint(
            "ordering_basis IS NULL OR ordering_basis IN "
            "('enrichment_priority', 'observed_severity')",
            name="ordering_basis",
        ),
        CheckConstraint(
            "enrichment_context IS NULL OR enrichment_context IN "
            "('verified', 'absent', 'unverified', 'superseded')",
            name="enrichment_context",
        ),
        # An epoch that could go backwards is not a fencing token.
        CheckConstraint(
            "claim_epoch >= 0 AND cancellation_epoch >= 0 AND adoption_count >= 0",
            name="epochs",
        ),
    )

    pass_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False
    )
    #: The caller's idempotency key for this command, as presented.
    request_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # -- lease and fencing ----------------------------------------------------
    holder: Mapped[str | None] = mapped_column(String(80), nullable=True)
    claim_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Advanced by an operator stop. A dispatch presenting a lower value is
    #: refused by the gateway, which is what makes stopping a real control
    #: rather than a request this process is free to ignore.
    cancellation_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    adoption_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # -- lifecycle ------------------------------------------------------------
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(48), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # -- inputs and attribution -----------------------------------------------
    #: Keys this pass's observation identities and control locators. Never
    #: selected into a view, a report, a log line or telemetry.
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    #: Which ordering decided what got dropped when a budget ran out.
    ordering_basis: Mapped[str | None] = mapped_column(String(24), nullable=True)
    #: How the optional enrichment report was used. A superseded one is
    #: recorded, not treated as a failure.
    enrichment_context: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: The findings this pass covers, when it covers a subset. NULL means the
    #: whole scan, so a subset pass can never be mistaken for a full one.
    scope: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(128), nullable=False)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VerificationPassPin(Base):
    """The pinned inputs of one pass. Written once; never updated.

    Every digest here was resolved before the first observation, so the whole
    pass is explainable against one set of inputs. Pins live apart from the
    lifecycle row precisely so that the role which must update a state has no
    privilege that could move them.
    """

    __tablename__ = "verification_pass_pin"

    #: Also the write-once guarantee: a second insert for the same pass
    #: collides on this key, and the append-only trigger refuses the UPDATE
    #: that would otherwise be the next thing a caller tried.
    pass_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("verification_pass.pass_id"), primary_key=True
    )
    pins: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    registry_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    extractor_set_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The addresses attested at pin time. Contact with anything else is refused.
    estate_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    resolver_set_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The gateway feature set this pass was planned against. A gateway missing
    #: one of them later is a different gateway.
    feature_set_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    base_report_id: Mapped[str] = mapped_column(String(64), nullable=False)
    base_report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    enrichment_report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enrichment_report_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    written_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class VerificationObservation(Base):
    """One settled observation identity and the gateway execution it used.

    A row is written when an observation settles — or when the gateway refused
    before committing intent — and never before: the table is append-only, so a
    pre-dispatch row could not later be completed with its outcome. A resumed
    pass re-derives its plan from the pins and presents the same
    ``execution_id``, which is why that identity is unique and why the envelope
    digest is stored beside it: "same identity, different request" has to be a
    detectable conflict rather than an article of faith.

    ``possibly_applied`` is durable on purpose. A transport failure is not a
    rollback; the target may have processed the request before the response
    failed, and that uncertainty must survive into the next pass instead of
    being forgotten the moment a new identity is generated.
    """

    __tablename__ = "verification_observation"
    __table_args__ = (
        ForeignKeyConstraint(
            ["pass_id", "scan_run_id"],
            ["verification_pass.pass_id", "verification_pass.scan_run_id"],
            name="fk_verification_observation_pass_scan",
        ),
        # The contract's UNIQUE (execution_id), in the only form PostgreSQL
        # allows on a partitioned table. The migration adds the narrow
        # UNIQUE (execution_id) to each partition.
        UniqueConstraint(
            "execution_id", "settled_at", name="uq_verification_observation_execution"
        ),
        Index("ix_verification_observation_pass", "pass_id", "finding_id"),
        CheckConstraint("role IN ('primary', 'control')", name="role"),
        CheckConstraint(
            "outcome_class IN ('OBSERVED', 'REFUSED_POLICY', 'REFUSED_CAPACITY', "
            "'WORLD_FACT', 'TIMED_OUT', 'FAILED', 'OBSERVATION_LOST')",
            name="outcome_class",
        ),
        CheckConstraint("control_index >= 0", name="control_index"),
        {"postgresql_partition_by": "RANGE (settled_at)"},
    )

    observation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: Part of the key because a partitioned table's key must contain its
    #: partition column, and the database clock supplies it.
    settled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), primary_key=True, server_default=func.now()
    )
    pass_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    verifier_id: Mapped[str] = mapped_column(String(96), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    control_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: The gateway-facing identity of this contact, derived from the whole
    #: canonical envelope and keyed by the pass salt.
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False)
    envelope_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    outcome_class: Mapped[str] = mapped_column(String(24), nullable=False)
    #: The gateway's stable reason code. Never free text.
    reason_code: Mapped[str] = mapped_column(String(48), nullable=False)
    possibly_applied: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: Transport and body completeness, with the bound that stopped the read.
    #: An observation that is not whole can never support a negative claim.
    completeness: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    #: Digest of the typed facts the observer returned. The facts themselves
    #: stay with the gateway; no body or header value crosses into this layer.
    facts_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    peer_address: Mapped[str | None] = mapped_column(String(64), nullable=True)


class FindingVerification(Base):
    """The verdict: one finding's outcome in one pass.

    The justification CHECK is the honest-negatives rule in the schema: a
    CONFIRMED verdict carries no justification, and every other status carries
    one. Without it a report could publish "not reproduced" with nothing saying
    whether the subject was gone, the access refused, or the measurement
    truncated — and those three lead an operator to three different actions.

    ``asserted_by`` is pinned to the deterministic verifier. A model may
    annotate what is already unverified; it may not author a row here, and the
    constraint is what makes that a property of the database rather than a
    property of the code path that happens to write it.
    """

    __tablename__ = "finding_verification"
    __table_args__ = (
        ForeignKeyConstraint(
            ["pass_id", "scan_run_id"],
            ["verification_pass.pass_id", "verification_pass.scan_run_id"],
            name="fk_finding_verification_pass_scan",
        ),
        ForeignKeyConstraint(
            ["scan_run_id", "finding_id"],
            ["raw_finding.scan_run_id", "raw_finding.finding_id"],
            name="fk_finding_verification_evidence",
        ),
        Index("ix_finding_verification_subject", "scan_run_id", "subject_key"),
        Index("ix_finding_verification_pass", "pass_id"),
        CheckConstraint(
            "status IN ('CONFIRMED', 'REFUTED', 'NOT_REPRODUCED', 'INCONCLUSIVE', 'UNSUPPORTED')",
            name="status",
        ),
        CheckConstraint(
            "(status = 'CONFIRMED' AND justification IS NULL) "
            "OR (status <> 'CONFIRMED' AND justification IS NOT NULL)",
            name="justification",
        ),
        CheckConstraint("asserted_by = 'deterministic_verifier'", name="asserted_by"),
        {"postgresql_partition_by": "RANGE (observed_at)"},
    )

    pass_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: Part of the key because a partitioned table's key must contain its
    #: partition column. The migration adds the contract's narrow
    #: PRIMARY KEY (pass_id, finding_id) to each partition as a unique index.
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), primary_key=True, server_default=func.now()
    )
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    #: The identity of the thing this claim is about, stable across scans.
    subject_key: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False)
    justification: Mapped[str | None] = mapped_column(String(40), nullable=True)
    #: NULL only where no verifier was registered for the class.
    verifier_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    #: The registry this verdict was decided under — including the registry
    #: decisions (no verifier, unreviewed class) that produce UNSUPPORTED.
    registry_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The decision-table row that produced the status. Recorded so a verdict
    #: can be re-read against the table it came from.
    rule: Mapped[int] = mapped_column(Integer, nullable=False)
    matched_predicates: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    #: What the controls said: how many were requested, observed and complete,
    #: whether they agreed, and whether the primary was distinguishable.
    control_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: The declared evidence projection — typed facts only — with its digest, so
    #: a stored projection that no longer matches is detectable.
    projection: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    projection_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    asserted_by: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default="deterministic_verifier"
    )


class VerificationRetraction(Base):
    """A withdrawn verifier version's effect on a verdict that cited it.

    Retraction is an appended row rather than an edit because the two facts are
    different: a verdict that was never made, and a verdict that was made and
    has since been taken back. The read view surfaces the second as RETRACTED.

    There is deliberately no foreign key to the verdict. A partitioned verdict
    table cannot offer a parent-level unique key on ``(pass_id, finding_id)``
    alone, so the reference is carried by those columns and by the foreign key
    to the pass, which binds the retraction to a real pass of a real scan.
    """

    __tablename__ = "verification_retraction"

    verifier_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    pass_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("verification_pass.pass_id"), primary_key=True
    )
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    #: The named reviewer who withdrew the version. A digest is integrity, not
    #: authority, so the person is recorded too.
    approved_by: Mapped[str] = mapped_column(String(128), nullable=False)
    withdrawn_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class VerificationReport(Base):
    """The verification deliverable. Immutable; attested by a signed event."""

    __tablename__ = "verification_report"

    report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    pass_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("verification_pass.pass_id"), nullable=False, unique=True
    )
    scan_run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    body: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(8), nullable=False)

    #: The inputs this deliverable adjudicates, cited by id *and* digest: a
    #: reader can tell which base report a verdict was made against.
    base_report_id: Mapped[str] = mapped_column(String(64), nullable=False)
    base_report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    enrichment_report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enrichment_report_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Which verifier versions produced the verdicts, so a later withdrawal can
    #: find every report that rested on the withdrawn one.
    verifier_versions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    ordering_basis: Mapped[str] = mapped_column(String(24), nullable=False)

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class VerificationAudit(Base):
    """Signed verification events (verification key). Append-only.

    ``scan_run_id`` and ``pass_id`` carry no foreign key: a refusal that
    happened before a pass row could be written still has to be recordable, and
    an event that cannot be written is an event that did not happen.
    """

    __tablename__ = "verification_audit"
    __table_args__ = (Index("ix_verification_audit_scan", "scan_run_id", "event_type"),)

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    event_schema_version: Mapped[str] = mapped_column(String(8), nullable=False)
    scan_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    pass_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_kid: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
