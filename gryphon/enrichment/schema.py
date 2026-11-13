"""Schema facts shared by the migration and by readiness.

Keeping the DDL fragments and the expected privilege matrix in one module means
readiness checks *exactly* what the migration created: tables, enabled triggers,
the trigger functions' bodies, the view, and the role's privileges. A revision
number proves only that a script ran; these facts prove what exists.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

from gryphon.enrichment.constants import DATABASE_ROLE, ENRICHMENT_SLOT_ID

APPEND_ONLY_TABLES: Final[tuple[str, ...]] = (
    "intel_snapshot",
    "intel_snapshot_revocation",
    "acquisition_attempt",
    "egress_ledger",
    "finding_enrichment",
    "finding_priority",
    "enrichment_report",
    "enrichment_audit",
)
LIFECYCLE_TABLES: Final[tuple[str, ...]] = ("enrichment_slot", "enrichment_pass")
ENRICHMENT_TABLES: Final[tuple[str, ...]] = (*LIFECYCLE_TABLES, *APPEND_ONLY_TABLES)
#: Upstream tables this layer reads. It writes none of them.
UPSTREAM_READ_TABLES: Final[tuple[str, ...]] = (
    "scan_report",
    "orchestration_audit",
    "scan_lifecycle",
    "scan_runs",
    "authorization_grants",
    "raw_finding",
)
VIEW_NAME: Final[str] = "finding_enrichment_view"

#: Lifecycle columns the enrichment role may UPDATE. Nothing else is updatable.
PASS_UPDATABLE_COLUMNS: Final[tuple[str, ...]] = (
    "state",
    "outcome",
    "reason",
    "detail",
    "base_report_id",
    "base_report_digest",
    "plan_digest",
    "pins",
    "manifest",
    "claim_epoch",
    "completed_at",
)
SLOT_UPDATABLE_COLUMNS: Final[tuple[str, ...]] = ("holder", "claim_epoch", "lease_expires_at")

#: The upstream append-only function (created by the first migration). Readiness
#: compares the deployed body against this text, so a replaced function is caught.
REJECT_MUTATION_BODY: Final[str] = """
BEGIN
    RAISE EXCEPTION 'append-only table: % is not permitted on %', TG_OP, TG_TABLE_NAME
        USING ERRCODE = '0A000';
END;
"""
REJECT_TRUNCATE_BODY: Final[str] = """
BEGIN
    RAISE EXCEPTION 'append-only table: TRUNCATE is not permitted on %', TG_TABLE_NAME
        USING ERRCODE = '0A000';
END;
"""

CREATE_TRUNCATE_FUNCTION: Final[str] = (
    "CREATE OR REPLACE FUNCTION gryphon_reject_truncate() RETURNS trigger AS $$"
    + REJECT_TRUNCATE_BODY
    + "$$ LANGUAGE plpgsql;"
)
DROP_TRUNCATE_FUNCTION: Final[str] = "DROP FUNCTION IF EXISTS gryphon_reject_truncate();"

ENSURE_ROLE: Final[str] = f"""
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{DATABASE_ROLE}') THEN
        -- Created without LOGIN: an operator enables login with a secret from
        -- their secret manager. If this migration lacks the privilege to create
        -- a role, CREATE ROLE raises and the migration fails — grants are never
        -- silently skipped.
        CREATE ROLE {DATABASE_ROLE} NOLOGIN;
    END IF;
END
$$;
"""

#: Idempotent: a database built from the full ORM metadata already has it (the
#: model declares it); one migrated from the previous revision gets it here.
ADD_EVIDENCE_UNIQUE: Final[str] = """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_raw_finding_scan_finding'
          AND conrelid = 'raw_finding'::regclass
    ) THEN
        ALTER TABLE raw_finding ADD CONSTRAINT uq_raw_finding_scan_finding
            UNIQUE (scan_run_id, finding_id);
    END IF;
END
$$;
"""
DROP_EVIDENCE_UNIQUE: Final[str] = (
    "ALTER TABLE raw_finding DROP CONSTRAINT IF EXISTS uq_raw_finding_scan_finding;"
)

SEED_SLOT: Final[str] = (
    "INSERT INTO enrichment_slot (slot, holder, claim_epoch, lease_expires_at) "
    f"VALUES ('{ENRICHMENT_SLOT_ID}', NULL, 0, NULL) ON CONFLICT (slot) DO NOTHING;"
)

CREATE_VIEW: Final[str] = f"""
CREATE VIEW {VIEW_NAME} AS
WITH latest AS (
    SELECT DISTINCT ON (p.scan_run_id)
           p.pass_id, p.scan_run_id, p.completed_at, p.outcome
    FROM enrichment_pass p
    WHERE p.state = 'COMPLETE'
    ORDER BY p.scan_run_id, p.completed_at DESC, p.pass_id DESC
)
SELECT l.scan_run_id,
       l.pass_id,
       l.completed_at,
       l.outcome AS pass_outcome,
       fp.finding_id,
       fp.observed_severity,
       fp.priority,
       fp.rationale,
       fp.policy_digest,
       (SELECT jsonb_object_agg(
                   fe.source,
                   jsonb_build_object(
                       'status', fe.status,
                       'reason', fe.reason,
                       'value', fe.value,
                       'snapshot_id', fe.snapshot_id,
                       'asserted_by', fe.asserted_by,
                       'snapshot_age_s', fe.snapshot_age_s))
          FROM finding_enrichment fe
         WHERE fe.pass_id = fp.pass_id AND fe.finding_id = fp.finding_id) AS sources
FROM latest l
JOIN finding_priority fp ON fp.pass_id = l.pass_id;
"""
DROP_VIEW: Final[str] = f"DROP VIEW IF EXISTS {VIEW_NAME};"


def trigger_statements() -> tuple[str, ...]:
    """One statement per execute(): the async driver cannot prepare multiples."""
    statements: list[str] = []
    for table in APPEND_ONLY_TABLES:
        statements.append(
            f"CREATE TRIGGER trg_{table}_no_mutation BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION gryphon_reject_mutation();"
        )
    for table in LIFECYCLE_TABLES:
        statements.append(
            f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION gryphon_reject_mutation();"
        )
    for table in ENRICHMENT_TABLES:
        statements.append(
            f"CREATE TRIGGER trg_{table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION gryphon_reject_truncate();"
        )
    return tuple(statements)


def drop_trigger_statements() -> tuple[str, ...]:
    statements: list[str] = []
    for table in APPEND_ONLY_TABLES:
        statements.append(f"DROP TRIGGER IF EXISTS trg_{table}_no_mutation ON {table};")
    for table in LIFECYCLE_TABLES:
        statements.append(f"DROP TRIGGER IF EXISTS trg_{table}_no_delete ON {table};")
    for table in ENRICHMENT_TABLES:
        statements.append(f"DROP TRIGGER IF EXISTS trg_{table}_no_truncate ON {table};")
    return tuple(statements)


def grant_statements() -> tuple[str, ...]:
    role = DATABASE_ROLE
    writable = ", ".join(t for t in ENRICHMENT_TABLES if t != "enrichment_slot")
    return (
        f"DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO {role}', "
        "current_database()); END $$;",
        f"GRANT USAGE ON SCHEMA public TO {role};",
        f"GRANT SELECT ON {', '.join(UPSTREAM_READ_TABLES)} TO {role};",
        f"GRANT SELECT ON {', '.join(ENRICHMENT_TABLES)}, {VIEW_NAME} TO {role};",
        f"GRANT INSERT ON {writable} TO {role};",
        f"GRANT UPDATE ({', '.join(PASS_UPDATABLE_COLUMNS)}) ON enrichment_pass TO {role};",
        f"GRANT UPDATE ({', '.join(SLOT_UPDATABLE_COLUMNS)}) ON enrichment_slot TO {role};",
        # Writers of other layers get no write path into enrichment tables.
        "DO $$ DECLARE r text; BEGIN "
        "FOREACH r IN ARRAY ARRAY['gryphon_runtime', 'gryphon_orchestrator'] LOOP "
        "IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN "
        f"EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON {', '.join(ENRICHMENT_TABLES)}"
        " FROM %I', r); END IF; END LOOP; END $$;",
    )


def revoke_statements() -> tuple[str, ...]:
    role = DATABASE_ROLE
    return (
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
        f"'{role}') THEN EXECUTE 'REVOKE ALL ON {', '.join(ENRICHMENT_TABLES)} FROM {role}'; "
        f"EXECUTE 'REVOKE SELECT ON {', '.join(UPSTREAM_READ_TABLES)} FROM {role}'; "
        "END IF; END $$;",
    )


#: Expected privileges of the enrichment role: (table, privilege) → granted?
def expected_table_privileges() -> dict[tuple[str, str], bool]:
    expected: dict[tuple[str, str], bool] = {}
    for table in UPSTREAM_READ_TABLES:
        expected[(table, "SELECT")] = True
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            expected[(table, privilege)] = False
    for table in ENRICHMENT_TABLES:
        expected[(table, "SELECT")] = True
        expected[(table, "INSERT")] = table != "enrichment_slot"
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            expected[(table, privilege)] = False
    return expected


def expected_column_updates() -> dict[tuple[str, str], bool]:
    return {
        **{("enrichment_pass", c): True for c in PASS_UPDATABLE_COLUMNS},
        **{("enrichment_slot", c): True for c in SLOT_UPDATABLE_COLUMNS},
        ("enrichment_pass", "scan_run_id"): False,
        ("enrichment_pass", "initiated_by"): False,
        ("enrichment_pass", "created_at"): False,
    }


def function_fingerprint(body: str) -> str:
    """Whitespace-insensitive fingerprint of a function body."""
    return hashlib.sha256(re.sub(r"\s+", " ", body).strip().encode()).hexdigest()


EXPECTED_FUNCTION_FINGERPRINTS: Final[dict[str, str]] = {
    "gryphon_reject_mutation": function_fingerprint(REJECT_MUTATION_BODY),
    "gryphon_reject_truncate": function_fingerprint(REJECT_TRUNCATE_BODY),
}
