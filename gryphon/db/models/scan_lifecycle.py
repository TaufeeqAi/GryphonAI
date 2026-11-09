"""``scan_lifecycle`` — the fenced scan claim and scan-level progress.

The single source of truth for "is this scan running, under whom, and how far
has it got". A sibling table: the authorization schema is untouched.

Three columns carry the recovery design, and they exist because a plain
``state = 'RUNNING'`` row cannot tell a live owner from a dead one — so a crash
would otherwise leave the scan unrunnable *and* unfinishable forever, consuming
the client's authorization:

* ``owner_id`` / ``lease_expires_at`` — a lease, so an abandoned scan becomes
  reclaimable on a timer instead of needing a human.
* ``claim_epoch`` — a monotonic fencing token. Every ledger write carries it, so
  a process that was presumed dead and then wakes up (a long stop-the-world
  pause, a stopped container) cannot mutate a scan a new owner has taken over.
  A lease alone cannot provide this: leases distinguish slow from dead only by
  guessing, and a lease shorter than the work creates two owners.
* ``phase_reached`` — monotonic, so progress can only move forward and a resumed
  invocation can be checked against recorded reality.

``execution_salt`` is secret and lives only here: it keys the derivation of
every execution identity, which is what makes those identities unpredictable to
anyone who does not hold the scan. It is never logged, reported, or placed in
graph state.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class ScanLifecycle(Base):
    __tablename__ = "scan_lifecycle"

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.scan_run_id"), primary_key=True
    )

    # -- lifecycle ------------------------------------------------------------
    state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    #: Monotonic high-water mark of pipeline progress. Never decreases.
    phase_reached: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    # -- fenced lease ---------------------------------------------------------
    owner_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Monotonic fencing token. A write presenting a lower epoch is rejected.
    claim_epoch: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # -- authority + identity material ---------------------------------------
    #: Secret, per-scan KDF salt for execution identities. Never exported.
    execution_salt: Mapped[str] = mapped_column(String(128), nullable=False)
    #: The scope-policy/canonicalizer version pinned for this scan's lifetime,
    #: so an upstream policy bump cannot silently re-identify in-flight work.
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Graph topology version that last advanced this scan (observability only;
    #: no checkpoint exists, so a version change never wedges a scan).
    graph_version: Mapped[str] = mapped_column(String(16), nullable=False)

    # -- accountability -------------------------------------------------------
    #: The authenticated local caller that started this scan. "Who started
    #: this?" is the first question in any incident review.
    initiated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Effective deadline: min(configured, grant expiry - margin). The grant
    #: always wins, so a scan cannot outrun its authorization.
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Cool-down floor set by a saturation/breaker outcome; no calls before it.
    cooldown_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Count of enforcement-layer decisions issued, against the global budget.
    decision_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    # -- outputs --------------------------------------------------------------
    report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    coverage_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
