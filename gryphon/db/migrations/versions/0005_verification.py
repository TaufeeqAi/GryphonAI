"""0005 verification layer — passes, pinned inputs, observations, verdicts.

Adds seven sibling tables, their monthly partitions, one read view and one
database role without changing any upstream table's columns:

* ``verification_pass`` — the fenced, leased unit of work. One open pass per
  scan is a partial unique index, not a convention; one pass per
  ``(scan_run_id, request_key)`` is what makes a repeated command after a lost
  response return the original pass instead of sending traffic again.
* ``verification_pass_pin`` — the pinned inputs, written once. Separate from
  the lifecycle row so that the role which must update a state holds no
  privilege that could move the provenance root.
* ``verification_observation`` — one settled observation identity and the
  gateway execution it used.
* ``finding_verification`` — the verdict, bound to its scan twice over.
* ``verification_retraction`` — a withdrawn verifier version's effect, appended.
* ``verification_report`` / ``verification_audit`` — the deliverable and its
  signed attestation (dedicated verification key).
* ``finding_verification_view`` — the read surface: newest *determinate*
  verdict per subject, with the last attempt in its own columns.

Every fragment of DDL and the whole privilege matrix come from
:mod:`gryphon.verification.schema`, which readiness also reads. That is the
point of the arrangement: readiness establishes what *exists* rather than which
script ran, so the statements it checks and the statements that built the
schema have to be one text and not two that agree today.

Four things here are deliberate.

**Every DDL command is its own execute().** asyncpg prepares every statement and
PostgreSQL cannot prepare a string holding more than one command. The previous
revision was rewritten for this reason; a multi-command string looks correct in
review and fails only against the async driver.

**Constraints that another table's foreign key depends on are declared on the
ORM models as well as in the shared facts.** The first migration builds every
model table with ``create_all`` on a fresh database — verification tables
included — so a unique constraint that existed only in this script would be
missing from any schema built straight from the metadata, and the composite
foreign keys that bind a verdict to its own scan's evidence would be
unbuildable. The same reasoning covers the partial unique index, which the model
carries and this migration also creates idempotently so both paths converge.

**The two highest-volume append-only tables are range-partitioned monthly from
the start.** Partitioning them later would mean rewriting the rows that must not
move: append-only, trigger-protected and cited by signed reports. Partition
creation stays an operational task, and it takes three statements rather than
one — the partition, the narrow unique key the parent cannot carry, and its own
TRUNCATE guard, because PostgreSQL clones row-level triggers onto new partitions
but not statement-level ones. This migration creates the catch-all partitions
and a year of months starting from the month the *database* reports, so a
migrator host with a skewed clock cannot name the wrong month. Retention is
declared in the shared facts rather than retrofitted.

**The role gets exactly the contract's privilege matrix**, and the absences are
stated as well as the grants: nothing grants a verification role write access to
upstream evidence or to the gateway's own ledger, and the hardening revokes make
that a statement this migration re-asserts rather than an accident of history. A
grant added by hand between deployments is removed by the next one.

The append-only trigger function and the truncate guard are reused from the
earlier revisions unchanged — deliberately not redefined here, so the deployed
bodies keep matching the fingerprints readiness compares them against.

One item of §22.2 is *not* here. The competing ``findings`` placeholder is left
in place: renaming it needs its ORM model and repository to move in the same
change, and a migration that renamed the table out from under them would break
callers that still work. Readiness reports the cleanup as advisory, so it stays
visible instead of silently assumed. The chain placeholder, which defines no
table in the current metadata, is dropped where an older database still has it.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date
from typing import Final

import sqlalchemy as sa
from alembic import op
from sqlalchemy import Table
from sqlalchemy.engine import Connection

from gryphon.db import models  # noqa: F401  (registers tables on Base.metadata)
from gryphon.db.base import Base
from gryphon.verification import schema

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: One key for every GRYPHON migration ('GRYPHON' in ASCII): two concurrent
#: upgrades must serialize rather than race through the same DDL. The lock is
#: transaction-scoped, so the commit that ends the migration releases it.
_MIGRATION_LOCK_KEY: Final[int] = 0x47525950484F4E
_ADVISORY_LOCK: Final[str] = f"SELECT pg_advisory_xact_lock({_MIGRATION_LOCK_KEY});"

#: The month boundaries come from the database clock, never from this process's.
_MONTH_QUERY: Final[str] = (
    "SELECT to_char(date_trunc('month', now() AT TIME ZONE 'UTC'), 'YYYY-MM-DD')"
)

#: Partitions are enumerated from the catalog rather than from the names this
#: revision happened to create: a downgrade that runs in a later month, or after
#: an operator added the next year's partitions, must still leave nothing behind.
#: ``format(%I)`` quotes the catalog name it was handed.
_DROP_PARTITIONS: Final[str] = """
DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname IN ('verification_observation', 'finding_verification')
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
    END LOOP;
END
$$;
"""


def _new_tables() -> list[Table]:
    return [Base.metadata.tables[name] for name in schema.VERIFICATION_TABLES]


def _database_month(bind: Connection) -> date:
    """The first day of the month according to the database."""
    return date.fromisoformat(str(bind.execute(sa.text(_MONTH_QUERY)).scalar_one()))


def upgrade() -> None:
    op.execute(_ADVISORY_LOCK)
    op.execute(schema.ENSURE_ROLE)
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, tables=_new_tables())
    op.execute(schema.CREATE_OPEN_PASS_INDEX)
    for statement in schema.default_partition_statements():
        op.execute(statement)
    for statement in schema.monthly_partition_statements(start=_database_month(bind)):
        op.execute(statement)
    # After the partitions exist, so the row-level guards are cloned onto them.
    for statement in schema.trigger_statements():
        op.execute(statement)
    op.execute(schema.CREATE_VIEW)
    # The retired placeholders: no privilege is left on the legacy evidence
    # table, and the empty chain placeholder goes where a database still has it.
    op.execute(schema.REVOKE_LEGACY_FINDINGS)
    op.execute(schema.DROP_CHAIN_PLACEHOLDER)
    for statement in schema.grant_statements():
        op.execute(statement)
    for statement in schema.hardening_statements():
        op.execute(statement)


def downgrade() -> None:
    op.execute(_ADVISORY_LOCK)
    for statement in schema.revoke_statements():
        op.execute(statement)
    op.execute(schema.DROP_VIEW)
    for statement in schema.drop_trigger_statements():
        op.execute(statement)
    op.execute(_DROP_PARTITIONS)
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind, tables=list(reversed(_new_tables())))
    op.execute(schema.DROP_OPEN_PASS_INDEX)
    # The role is cluster-level and may own sessions elsewhere; it is left in
    # place for an operator to drop deliberately. The append-only trigger
    # function and the truncate guard belong to earlier revisions and are left
    # alone: other layers' tables still depend on them.
