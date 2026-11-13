"""0004 enrichment layer — accepted snapshots, passes, assertions, deliverable.

Adds ten sibling tables and one view without changing any upstream table's
columns:

* ``intel_snapshot`` / ``intel_snapshot_revocation`` — accepted, content-addressed
  public snapshots; revocation is an appended row.
* ``acquisition_attempt`` / ``egress_ledger`` — freshness, breaker and exposure
  accounting for every outbound request.
* ``enrichment_slot`` / ``enrichment_pass`` — the single system-wide lease and the
  fenced, pinned unit of work.
* ``finding_enrichment`` / ``finding_priority`` — attributed assertions and
  derived priorities, keyed per pass.
* ``enrichment_report`` / ``enrichment_audit`` — the deliverable and its signed
  attestation (dedicated enrichment key).
* ``finding_enrichment_view`` — the read surface (newest COMPLETE pass per scan).

The one upstream touch is additive: a UNIQUE constraint on
``raw_finding(scan_run_id, finding_id)``, trivially satisfied because
``finding_id`` is already the primary key. It lets assertions carry a composite
foreign key that binds each one to its own scan's evidence. The constraint is
declared on the ``RawFinding`` model too — the first migration builds every ORM
table on a fresh database, enrichment tables included, so the referenced
uniqueness must exist there; the ``ALTER`` here is idempotent and covers
databases migrated from the previous revision.

Privileges are granted to the dedicated ``gryphon_enrichment`` role, which this
migration ensures exists (created NOLOGIN when missing; if the migrator may not
create roles, the migration fails rather than skipping the grants). The role
gets SELECT on the upstream tables it reads, INSERT on its append-only tables,
column-scoped UPDATE on its two lifecycle tables, and nothing else — no DELETE,
no TRUNCATE, no DDL, and no write on any upstream table. Every append-only table
rejects UPDATE/DELETE per row and TRUNCATE per statement.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from gryphon.db import models  # noqa: F401  (registers tables on Base.metadata)
from gryphon.db.base import Base
from gryphon.enrichment import schema

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Creation order respects foreign keys.
_NEW_TABLES = (
    "intel_snapshot",
    "intel_snapshot_revocation",
    "acquisition_attempt",
    "egress_ledger",
    "enrichment_slot",
    "enrichment_pass",
    "finding_enrichment",
    "finding_priority",
    "enrichment_report",
    "enrichment_audit",
)


def _new_tables() -> list:
    return [Base.metadata.tables[name] for name in _NEW_TABLES]


def upgrade() -> None:
    op.execute(schema.ENSURE_ROLE)
    op.execute(schema.ADD_EVIDENCE_UNIQUE)
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, tables=_new_tables())
    op.execute(schema.SEED_SLOT)
    op.execute(schema.CREATE_TRUNCATE_FUNCTION)
    for statement in schema.trigger_statements():
        op.execute(statement)
    op.execute(schema.CREATE_VIEW)
    for statement in schema.grant_statements():
        op.execute(statement)


def downgrade() -> None:
    for statement in schema.revoke_statements():
        op.execute(statement)
    op.execute(schema.DROP_VIEW)
    for statement in schema.drop_trigger_statements():
        op.execute(statement)
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind, tables=list(reversed(_new_tables())))
    op.execute(schema.DROP_TRUNCATE_FUNCTION)
    op.execute(schema.DROP_EVIDENCE_UNIQUE)
    # The role is cluster-level and may own sessions elsewhere; it is left in
    # place for an operator to drop deliberately.
