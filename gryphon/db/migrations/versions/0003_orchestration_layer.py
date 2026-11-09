"""0003 orchestration layer — work ledger, evidence, report, decision audit.

Adds seven sibling tables without touching the authorization or tool-execution
schemas:

* ``scan_lifecycle``      — the fenced scan claim and scan-level progress.
* ``scan_plan``           — committed step plans (append-only).
* ``plan_item``           — planned work and its recorded outcome (UPDATEable).
* ``admitted_target``     — discovered targets cleared for active scanning.
* ``raw_finding``         — observed evidence with provenance (append-only).
* ``scan_report``         — emitted report artifacts (append-only, immutable).
* ``orchestration_audit`` — signed decision events (append-only).

Append-only controls reuse the authorization core's ``gryphon_reject_mutation``
trigger function, so immutability is enforced by the database rather than by
convention in application code.

Two grant sets are issued, and the distinction matters:

* ``gryphon_runtime`` — the existing single-process role. It gets SELECT/INSERT
  on everything here, and UPDATE only on the two tables with a real lifecycle
  (``scan_lifecycle`` for the lease and progress, ``plan_item`` for dispatch and
  settlement). It gets **no** UPDATE or DELETE on the append-only tables.

* ``gryphon_orchestrator`` — an optional, more restricted role for running this
  layer separately. It additionally gets **no write access to the admission
  tables**, which is what structurally prevents anything at or above this layer
  from manufacturing its own authorization. A future scheduler that could create
  admissions would become a second authorization authority, and the product's
  central claim is that nothing is scanned without a signed human
  authorization. Created only if the role exists; the code-level equivalent is
  asserted by test regardless.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from gryphon.db import models  # noqa: F401  (registers tables on Base.metadata)
from gryphon.db.base import Base

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW_TABLES = (
    "scan_lifecycle",
    "scan_plan",
    "plan_item",
    "admitted_target",
    "raw_finding",
    "scan_report",
    "orchestration_audit",
)

#: Tables whose rows are facts, not state: once written they never change.
_APPEND_ONLY = (
    "scan_plan",
    "admitted_target",
    "raw_finding",
    "scan_report",
    "orchestration_audit",
)

# One statement per execute(). The async driver prepares each statement, and a
# prepared statement cannot carry multiple commands.
_TRIGGERS = tuple(
    f"CREATE TRIGGER trg_{table}_no_mutation "
    f"BEFORE UPDATE OR DELETE ON {table} "
    f"FOR EACH ROW EXECUTE FUNCTION gryphon_reject_mutation();"
    for table in _APPEND_ONLY
)

_DROP_TRIGGERS = tuple(
    f"DROP TRIGGER IF EXISTS trg_{table}_no_mutation ON {table};"
    for table in _APPEND_ONLY
)

_RUNTIME_GRANTS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_runtime') THEN
        GRANT SELECT, INSERT ON
            scan_lifecycle, scan_plan, plan_item, admitted_target,
            raw_finding, scan_report, orchestration_audit
            TO gryphon_runtime;
        -- Only these two have a lifecycle: the lease/progress row, and the
        -- plan item as it moves from planned to dispatched to settled.
        GRANT UPDATE ON scan_lifecycle, plan_item TO gryphon_runtime;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_orchestrator') THEN
        GRANT SELECT, INSERT ON
            scan_lifecycle, scan_plan, plan_item, admitted_target,
            raw_finding, scan_report, orchestration_audit
            TO gryphon_orchestrator;
        GRANT UPDATE ON scan_lifecycle, plan_item TO gryphon_orchestrator;
        -- Consume admissions and grants; never create or alter one.
        GRANT SELECT ON scan_runs, authorization_grants, authorization_audit_log
            TO gryphon_orchestrator;
        REVOKE INSERT, UPDATE, DELETE ON scan_runs FROM gryphon_orchestrator;
        REVOKE INSERT, UPDATE, DELETE ON authorization_grants
            FROM gryphon_orchestrator;
        -- Read the enforcement layer's records to reconcile outcomes.
        GRANT SELECT ON tool_execution, tool_invocation_audit
            TO gryphon_orchestrator;
    END IF;
END
$$;
"""

_REVOKE_GRANTS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_runtime') THEN
        REVOKE ALL ON
            scan_lifecycle, scan_plan, plan_item, admitted_target,
            raw_finding, scan_report, orchestration_audit
            FROM gryphon_runtime;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_orchestrator') THEN
        REVOKE ALL ON
            scan_lifecycle, scan_plan, plan_item, admitted_target,
            raw_finding, scan_report, orchestration_audit
            FROM gryphon_orchestrator;
    END IF;
END
$$;
"""


def _new_tables() -> list:
    return [Base.metadata.tables[name] for name in _NEW_TABLES]


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, tables=_new_tables())
    for statement in _TRIGGERS:
        op.execute(statement)
    op.execute(_RUNTIME_GRANTS)


def downgrade() -> None:
    for statement in _DROP_TRIGGERS:
        op.execute(statement)
    op.execute(_REVOKE_GRANTS)
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind, tables=_new_tables())
