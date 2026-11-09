"""``scan_plan`` and ``plan_item`` — the committed record of intended work.

This is the abstraction whose absence produced most of this layer's known
failure modes at review time. With it, six things stop being hard:

* **Coverage** is arithmetic, because ``planned`` finally exists to divide by.
* **Replay determinism** is a storage property: a re-entered node re-reads
  rows instead of recomputing a target list, and recomputation is where
  nondeterminism (wall clock, set iteration order, a changed upstream view)
  enters and silently produces a *different* execution identity — i.e. a second
  real scan.
* **Attempt accounting** has an obvious home (``attempt_epoch``).
* **Provenance** has a column, so "why was this host scanned?" is answerable.
* **Resume corroboration** is a query, not a guess.
* **Fan-out merge** is trivial: concurrent work writes distinct rows, so there
  is no shared mutable object to need merge semantics at all.

A step's plan is computed once, committed in one transaction, and never
recomputed. ``plan_item`` rows are both the work queue and the coverage record.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
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


class ScanPlan(Base):
    """One committed step plan. Append-only: a correction is a new generation."""

    __tablename__ = "scan_plan"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "stage",
            "step",
            "plan_generation",
            name="uq_scan_plan_identity",
        ),
    )

    plan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False, index=True
    )
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    step: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Incremented by an explicit, audited replan. Generation 1 is the first.
    plan_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    tool_id: Mapped[str] = mapped_column(String(32), nullable=False)

    #: Digest over the ordered item set. Proves a resumed plan is the same plan.
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False)
    ledger_schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Declared partial-result policy for this step, recorded with the plan so
    #: the coverage decision can be audited against the policy in force.
    min_coverage_to_proceed: Mapped[float] = mapped_column(
        nullable=False, default=0.0, server_default="0"
    )
    #: Fencing token of the owner that committed this plan.
    claim_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)

    committed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AdmittedScanTarget(Base):
    """A discovered target cleared for active scanning, with its provenance.

    Its own table rather than an evidence row, because it is a different kind of
    fact: a *planning decision* this layer made, not something a tool observed.
    Filing it as evidence would also break the report's corroboration rule —
    every finding must trace to a producing execution, and admission runs no
    tool, so an admission "finding" would be dropped as uncorroborated and raise
    a spurious integrity failure.

    Append-only. Re-running admission after a crash must reproduce the same
    admitted set, or a replanned step would derive different execution
    identities and the enforcement layer would treat re-walked work as new.
    """

    __tablename__ = "admitted_target"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id", "canonical_target", name="uq_admitted_target_identity"
        ),
    )

    admitted_target_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False, index=True
    )
    canonical_target: Mapped[str] = mapped_column(Text, nullable=False)
    #: Addresses the name resolved to at admission time.
    addresses: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    #: Discovering tool, seed, time, and what the addresses were attested
    #: against. The answer to "why was this host scanned?".
    provenance: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    admitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PlanItem(Base):
    """One unit of planned work: one tool, one target, one stored identity."""

    __tablename__ = "plan_item"
    __table_args__ = (
        UniqueConstraint("execution_id", name="uq_plan_item_execution_id"),
        UniqueConstraint("plan_id", "seq", name="uq_plan_item_plan_seq"),
        # The work queue is "PLANNED rows for this scan, in order".
        Index("ix_plan_item_queue", "scan_run_id", "state", "stage", "step", "seq"),
    )

    plan_item_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    plan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_plan.plan_id"), nullable=False, index=True
    )
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), nullable=False, index=True
    )
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    step: Mapped[str] = mapped_column(String(64), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_id: Mapped[str] = mapped_column(String(32), nullable=False)

    # -- identity (computed once, at plan commit; never recomputed) ----------
    #: The enforcement-layer execution identity. Read on every dispatch, retry
    #: and resume — the reason a re-executed step cannot start a second scan.
    execution_id: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Digest of the canonical request (argv included), so two genuinely
    #: different calls on one target can never share an identity.
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Advances only via an audited replan of an item proven not to have
    #: contacted its target — never on an indeterminate outcome.
    attempt_epoch: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    # -- target ---------------------------------------------------------------
    canonical_target: Mapped[str] = mapped_column(Text, nullable=False)
    target_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    effective_depth: Mapped[str] = mapped_column(String(16), nullable=False)
    #: How this target came to be scanned: discovering tool, seed, time, and the
    #: addresses it was attested against. The chain of custody for the scan.
    provenance: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    # -- recorded outcome (a cache of the enforcement layer, which wins) -----
    state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    #: Enforcement-layer audit event for the recorded outcome. The link that
    #: lets the report corroborate a finding against signed evidence.
    audit_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Fencing token of the owner that last advanced this item.
    claim_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    dispatched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
