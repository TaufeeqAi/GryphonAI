"""0002 tool execution layer — execution aggregate, capability consumption, tool audit.

Adds three sibling tables without touching the authorization schema (CHG-017):

* ``tool_execution``          — the Execution aggregate (UPDATEable lifecycle).
* ``capability_consumption``  — authoritative single-use nonce CAS (append-only).
* ``tool_invocation_audit``   — signed tool-call events (append-only).

Append-only controls reuse the authorization core's ``gryphon_reject_mutation``
trigger function. Runtime grants are least-privilege: SELECT/INSERT on all three,
UPDATE only on ``tool_execution`` (its lifecycle), and no UPDATE/DELETE/TRUNCATE
on the two append-only tables.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from gryphon.db import models  # noqa: F401  (registers tables on Base.metadata)
from gryphon.db.base import Base

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NEW_TABLES = ("tool_execution", "capability_consumption", "tool_invocation_audit")

_TRIGGER_AUDIT = """
CREATE TRIGGER trg_tool_invocation_audit_no_mutation
    BEFORE UPDATE OR DELETE ON tool_invocation_audit
    FOR EACH ROW EXECUTE FUNCTION gryphon_reject_mutation();
"""

_TRIGGER_CONSUMPTION = """
CREATE TRIGGER trg_capability_consumption_no_mutation
    BEFORE UPDATE OR DELETE ON capability_consumption
    FOR EACH ROW EXECUTE FUNCTION gryphon_reject_mutation();
"""

_RUNTIME_GRANTS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_runtime') THEN
        GRANT SELECT, INSERT ON
            tool_execution, capability_consumption, tool_invocation_audit
            TO gryphon_runtime;
        -- The execution aggregate transitions state; the append-only tables do not.
        GRANT UPDATE ON tool_execution TO gryphon_runtime;
        REVOKE UPDATE, DELETE, TRUNCATE ON
            capability_consumption, tool_invocation_audit
            FROM gryphon_runtime;
        REVOKE DELETE, TRUNCATE ON tool_execution FROM gryphon_runtime;
    END IF;
END
$$;
"""

_REVOKE_GRANTS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gryphon_runtime') THEN
        REVOKE ALL ON
            tool_execution, capability_consumption, tool_invocation_audit
            FROM gryphon_runtime;
    END IF;
END
$$;
"""


def _new_tables() -> list:
    return [Base.metadata.tables[name] for name in _NEW_TABLES]


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, tables=_new_tables())
    op.execute(_TRIGGER_AUDIT)
    op.execute(_TRIGGER_CONSUMPTION)
    op.execute(_RUNTIME_GRANTS)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_tool_invocation_audit_no_mutation ON tool_invocation_audit;")
    op.execute("DROP TRIGGER IF EXISTS trg_capability_consumption_no_mutation ON capability_consumption;")
    op.execute(_REVOKE_GRANTS)
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind, tables=_new_tables())
