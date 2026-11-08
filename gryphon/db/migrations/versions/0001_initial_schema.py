"""0001 initial schema — grants, scan_runs, findings, audit + append-only controls.

Creates the Phase 1 relational core from the ORM metadata (single source of
truth for table shape), then layers the database-enforced controls the ORM alone
cannot provide (§22.3):

* an append-only trigger rejecting UPDATE/DELETE on ``authorization_audit_log``
  and ``authorization_grants`` (INV-007/017);
* least-privilege grants to the ``gryphon_runtime`` role: SELECT/INSERT only,
  with UPDATE/DELETE/TRUNCATE revoked (SEC-012).

Migrations are forward-only for audit-bearing data by default (§22.4). The
downgrade exists for development convenience and DESTROYS audit evidence; it is
not an ordinary production rollback path.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from gryphon.db import models  # noqa: F401  (registers tables on Base.metadata)
from gryphon.db.base import Base

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TRIGGER_FUNCTION = """
CREATE OR REPLACE FUNCTION gryphon_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'append-only table: % is not permitted on %', TG_OP, TG_TABLE_NAME
        USING ERRCODE = '0A000';
END;
$$ LANGUAGE plpgsql;
"""

# asyncpg prepares every statement and PostgreSQL cannot prepare a string with
# multiple commands, so each trigger is issued as its own op.execute() (§22.3).
_TRIGGER_AUDIT = """
CREATE TRIGGER trg_authorization_audit_log_no_mutation
    BEFORE UPDATE OR DELETE ON authorization_audit_log
    FOR EACH ROW EXECUTE FUNCTION gryphon_reject_mutation();
"""

_TRIGGER_GRANTS = """
CREATE TRIGGER trg_authorization_grants_no_mutation
    BEFORE UPDATE OR DELETE ON authorization_grants
    FOR EACH ROW EXECUTE FUNCTION gryphon_reject_mutation();
"""

# Least-privilege runtime grants, applied only if the role exists (the role is
# created by scripts/init_db_roles.sql at first boot).
_RUNTIME_GRANTS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_runtime') THEN
        GRANT USAGE ON SCHEMA public TO gryphon_runtime;
        GRANT SELECT, INSERT ON
            authorization_grants, scan_runs, authorization_audit_log, findings
            TO gryphon_runtime;
        REVOKE UPDATE, DELETE, TRUNCATE ON
            authorization_grants, scan_runs, authorization_audit_log, findings
            FROM gryphon_runtime;
        -- The runtime role must read the Alembic revision for its readiness
        -- check (§22.4). SELECT only; it can never write the version table.
        IF to_regclass('public.alembic_version') IS NOT NULL THEN
            GRANT SELECT ON alembic_version TO gryphon_runtime;
        END IF;
    END IF;
END
$$;
"""

_REVOKE_GRANTS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_runtime') THEN
        REVOKE ALL ON
            authorization_grants, scan_runs, authorization_audit_log, findings
            FROM gryphon_runtime;
    END IF;
END
$$;
"""


def upgrade() -> None:
    bind = op.get_bind()
    # Tables, PKs, FKs, unique and ordinary indexes from the ORM metadata.
    Base.metadata.create_all(bind=bind)
    # Database-enforced append-only controls + least-privilege grants.
    op.execute(_TRIGGER_FUNCTION)
    op.execute(_TRIGGER_AUDIT)
    op.execute(_TRIGGER_GRANTS)
    op.execute(_RUNTIME_GRANTS)


def downgrade() -> None:
    # DESTRUCTIVE for audit evidence — development only (§22.4).
    op.execute("DROP TRIGGER IF EXISTS trg_authorization_audit_log_no_mutation ON authorization_audit_log;")
    op.execute("DROP TRIGGER IF EXISTS trg_authorization_grants_no_mutation ON authorization_grants;")
    op.execute(_REVOKE_GRANTS)
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
    op.execute("DROP FUNCTION IF EXISTS gryphon_reject_mutation();")
