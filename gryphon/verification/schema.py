"""Schema facts shared by the migration and by readiness.

Keeping the DDL fragments and the expected privilege matrix in one module means
readiness checks *exactly* what the migration created: the tables, their monthly
partitions and each partition's narrow unique key, the partial unique index that
allows one open pass per scan, the view, that every append-only trigger is
present **and enabled**, that the trigger functions' bodies are still the ones
this code expects, and the dedicated role's privileges — including every
privilege that must be **absent**. A revision number proves only that a script
ran; these facts prove what exists.

Three facts here are not restatements of the contract's table list, and each one
is a consequence of how PostgreSQL works rather than a preference:

* **Unique keys on the partitioned tables carry the partition key.** A unique
  constraint on a range-partitioned table must contain its partition column, so
  the parent carries ``UNIQUE (execution_id, settled_at)`` and
  ``PRIMARY KEY (pass_id, finding_id, observed_at)``, and the narrow form the
  contract states is a unique index on each partition — in force within the
  month in which a resumed pass replays an identity. The authoritative dedupe
  for a contact is the gateway's own durable record, not this index.
* **The truncate guard is also attached to every partition.** Row-level triggers
  are cloned onto existing partitions and onto partitions attached later;
  statement-level TRUNCATE triggers are not. A partition created without its own
  guard could be truncated on its own while the parent looked protected, so
  readiness checks every partition rather than assuming the parent covers them.
* **The role may read ``alembic_version``.** Readiness runs as the verification
  role and the schema barrier is one of the facts it must establish. Without
  that grant the barrier check reports "unreadable" on a correctly migrated
  database, which is the least useful possible answer.

The trigger function bodies are restated here rather than imported from the
layer that first created them: readiness compares the *deployed* body against
this text, so this module must say what it expects without depending on another
layer to say it.
"""

from __future__ import annotations

import hashlib
import re
from datetime import date
from typing import Final

from gryphon.verification.constants import DATABASE_ROLE, OPEN_PASS_STATES

#: The revision this layer's DDL lands in. Readiness compares the deployed
#: revision against it exactly: the facts below describe one revision, so a
#: database one step ahead or behind is refused rather than probed piecemeal.
EXPECTED_ALEMBIC_REVISION: Final[str] = "0005"
BARRIER_TABLE: Final[str] = "alembic_version"

LIFECYCLE_TABLES: Final[tuple[str, ...]] = ("verification_pass",)
APPEND_ONLY_TABLES: Final[tuple[str, ...]] = (
    "verification_pass_pin",
    "verification_observation",
    "finding_verification",
    "verification_retraction",
    "verification_report",
    "verification_audit",
)
#: Creation order respects foreign keys.
VERIFICATION_TABLES: Final[tuple[str, ...]] = (*LIFECYCLE_TABLES, *APPEND_ONLY_TABLES)

#: Write-once: one row per pass, inserted once and never updated. The pin row is
#: the provenance root of every verdict in the pass; if it could move, work
#: already published would become unexplainable.
WRITE_ONCE_TABLES: Final[tuple[str, ...]] = ("verification_pass_pin",)

#: Range-partitioned monthly from the first migration, with the column each is
#: partitioned on. Both default to the database clock. Partitioning these later
#: would mean rewriting append-only rows that signed reports already cite.
PARTITION_KEY_BY_TABLE: Final[dict[str, str]] = {
    "verification_observation": "settled_at",
    "finding_verification": "observed_at",
}
PARTITIONED_TABLES: Final[tuple[str, ...]] = tuple(PARTITION_KEY_BY_TABLE)

#: The narrow unique key each partition carries — the contract's key, in the
#: only place PostgreSQL can enforce it on a partitioned table.
PARTITION_UNIQUE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "verification_observation": ("execution_id",),
    "finding_verification": ("pass_id", "finding_id"),
}

#: A default partition exists so a row whose timestamp falls outside every
#: declared month is still written. Retention cannot tier a catch-all, so
#: readiness still expects real monthly partitions and warns when they run out.
DEFAULT_PARTITION_SUFFIX: Final[str] = "default"

#: Retention floor per partitioned table, in months, declared rather than
#: retrofitted. An observation's facts must outlive every verdict citing them,
#: so observation partitions are retired no earlier than verdict partitions.
#: This role holds no DELETE and no DDL: retiring a partition is always a
#: deliberate act by someone else.
RETENTION_MONTHS: Final[dict[str, int]] = {
    "verification_observation": 36,
    "finding_verification": 36,
}

#: How many months of partitions a management run creates ahead of itself, and
#: how many must still exist before readiness stops warning.
PARTITION_HORIZON_MONTHS: Final[int] = 12
PARTITION_WARN_MONTHS: Final[int] = 2

#: Upstream tables this layer reads. It writes none of them. The deliberate
#: omissions matter as much as the entries: no gateway audit ledger, no platform
#: audit log, and no capability material.
UPSTREAM_READ_TABLES: Final[tuple[str, ...]] = (
    "scan_runs",
    "authorization_grants",
    "scan_report",
    "orchestration_audit",
    "raw_finding",
    "admitted_target",
    "enrichment_report",
    "enrichment_audit",
    "finding_enrichment_view",
    # Read-back only: the record of an execution this layer did not create.
    "tool_execution",
    BARRIER_TABLE,
)

VIEW_NAME: Final[str] = "finding_verification_view"

#: Lifecycle columns the verification role may UPDATE, and nothing else. Pins
#: and the manifest are absent on purpose: they live in the write-once table, so
#: there is no column-level path to editing them even for this role.
#: ``adoption_count`` is updatable in addition to the columns the contract names
#: because bounded recovery is counted in the same statement that advances the
#: epoch — counting it separately would let a process that dies between two
#: statements adopt a pass without being counted.
PASS_UPDATABLE_COLUMNS: Final[tuple[str, ...]] = (
    "state",
    "outcome",
    "reason",
    "detail",
    "holder",
    "claim_epoch",
    "cancellation_epoch",
    "lease_expires_at",
    "completed_at",
    "adoption_count",
)

#: Columns whose UPDATE privilege must be *absent*. These are the facts about
#: how the work was admitted: its identity, the caller's request key, the
#: per-pass salt that keys every observation identity, and who asked. A layer
#: that could edit them could rewrite its own authority after the fact.
PASS_FROZEN_COLUMNS: Final[tuple[str, ...]] = (
    "pass_id",
    "scan_run_id",
    "request_key",
    "salt",
    "initiated_by",
    "started_at",
)
#: Append-only columns sampled for an UPDATE-absence check: the grants a
#: well-meaning operator would be most tempted to add while debugging.
APPEND_ONLY_FROZEN_COLUMNS: Final[tuple[tuple[str, str], ...]] = (
    ("verification_pass_pin", "pins"),
    ("verification_pass_pin", "manifest"),
    ("finding_verification", "status"),
    ("finding_verification", "justification"),
    ("finding_verification", "projection"),
    ("verification_observation", "outcome_class"),
    ("verification_observation", "possibly_applied"),
)

#: Unique keys readiness checks by *column set* rather than by name, so a model
#: that spells a constraint differently still satisfies the fact.
EXPECTED_UNIQUE_COLUMNS: Final[dict[str, tuple[frozenset[str], ...]]] = {
    "verification_pass": (
        frozenset({"pass_id"}),
        frozenset({"scan_run_id", "request_key"}),
        frozenset({"pass_id", "scan_run_id"}),
    ),
    "verification_pass_pin": (frozenset({"pass_id"}),),
    "verification_observation": (frozenset({"execution_id", "settled_at"}),),
    "finding_verification": (frozenset({"pass_id", "finding_id", "observed_at"}),),
    "verification_report": (frozenset({"report_id"}), frozenset({"pass_id"})),
}

#: Tables this role must hold no INSERT, UPDATE, DELETE or TRUNCATE on: every
#: table owned by the layers before this one, and every table the gateway
#: writes. The second group is INV-P5-021 — the component that writes the
#: gateway's ledger must not be the component whose claims that ledger
#: adjudicates — and the first is how evidence and claims stay distinguishable.
GATEWAY_TABLES: Final[tuple[str, ...]] = (
    "tool_execution",
    "tool_invocation_audit",
    "capability_consumption",
)
UPSTREAM_OWNED_TABLES: Final[tuple[str, ...]] = (
    "authorization_grants",
    "authorization_audit_log",
    "scan_runs",
    "scan_lifecycle",
    "scan_plan",
    "plan_item",
    "admitted_target",
    "scan_report",
    "orchestration_audit",
    "raw_finding",
    # The retired competing schema, under both names: a database migrated from
    # an earlier revision still carries the original one.
    "findings",
    "legacy_findings",
    "exploit_chain",
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
    BARRIER_TABLE,
)
FORBIDDEN_WRITE_TABLES: Final[tuple[str, ...]] = (
    *UPSTREAM_OWNED_TABLES,
    *(t for t in GATEWAY_TABLES if t not in UPSTREAM_OWNED_TABLES),
)

#: Tables this role must not even read. Reading them is not needed, and each
#: would hand a compromised verifier something it should never hold: another
#: key's signed audit lane, the gateway's own ledger, or capability material.
NO_READ_TABLES: Final[tuple[str, ...]] = (
    "authorization_audit_log",
    "tool_invocation_audit",
    "capability_consumption",
    "legacy_findings",
)

WRITE_PRIVILEGES: Final[tuple[str, ...]] = ("INSERT", "UPDATE", "DELETE", "TRUNCATE")

#: Roles that write other layers' rows. None gets a write path into verification
#: tables: a verdict must be attributable to this layer alone.
OTHER_WRITER_ROLES: Final[tuple[str, ...]] = (
    "gryphon_runtime",
    "gryphon_orchestrator",
    "gryphon_enrichment",
)

# =============================================================================
# Trigger functions
# =============================================================================

#: The platform's append-only function, created by the first migration and
#: reused unchanged. Readiness compares the deployed body against this text, so
#: a replaced function is caught rather than assumed.
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


def function_fingerprint(body: str) -> str:
    """Whitespace-insensitive fingerprint of a function body."""
    return hashlib.sha256(re.sub(r"\s+", " ", body).strip().encode()).hexdigest()


EXPECTED_FUNCTION_FINGERPRINTS: Final[dict[str, str]] = {
    "gryphon_reject_mutation": function_fingerprint(REJECT_MUTATION_BODY),
    "gryphon_reject_truncate": function_fingerprint(REJECT_TRUNCATE_BODY),
}

# =============================================================================
# Role and DDL
# =============================================================================

ENSURE_ROLE: Final[str] = f"""
DO $$
BEGIN
    IF to_regrole('{DATABASE_ROLE}') IS NULL THEN
        -- Created without LOGIN: an operator enables login with a secret from
        -- their secret manager. If this migration lacks the privilege to create
        -- a role, CREATE ROLE raises and the migration fails — grants are never
        -- silently skipped.
        CREATE ROLE {DATABASE_ROLE} NOLOGIN;
    END IF;
END
$$;
"""

#: One PLANNED, RUNNING or BLOCKED pass per scan — a partial unique index rather
#: than application logic, because two processes asking "is a pass open?" before
#: inserting would both see no row. Declared on the model as well, since the
#: first migration builds every model table on a fresh database; created here
#: idempotently so both paths converge.
OPEN_PASS_INDEX: Final[str] = "uq_verification_pass_open"  # noqa: S105 - index name
_OPEN_STATE_LITERAL: Final[str] = ", ".join(
    f"'{state.value}'" for state in sorted(OPEN_PASS_STATES, key=lambda s: s.value)
)
CREATE_OPEN_PASS_INDEX: Final[str] = (
    f"CREATE UNIQUE INDEX IF NOT EXISTS {OPEN_PASS_INDEX} "
    "ON verification_pass (scan_run_id) "
    f"WHERE state IN ({_OPEN_STATE_LITERAL});"
)
DROP_OPEN_PASS_INDEX: Final[str] = f"DROP INDEX IF EXISTS {OPEN_PASS_INDEX};"

#: Retiring the competing schema (CHG-P5-038): the placeholder findings table
#: keeps its rows under a name that says what they are, with no privileges left
#: on it, and the empty chain placeholder goes. Both statements are idempotent,
#: so a database built from the full ORM metadata and one migrated from an
#: earlier revision end in the same state.
RENAME_LEGACY_FINDINGS: Final[str] = """
DO $$
BEGIN
    IF to_regclass('findings') IS NOT NULL AND to_regclass('legacy_findings') IS NULL THEN
        ALTER TABLE findings RENAME TO legacy_findings;
    END IF;
END
$$;
"""
RESTORE_LEGACY_FINDINGS: Final[str] = """
DO $$
BEGIN
    IF to_regclass('legacy_findings') IS NOT NULL AND to_regclass('findings') IS NULL THEN
        ALTER TABLE legacy_findings RENAME TO findings;
    END IF;
END
$$;
"""
REVOKE_LEGACY_FINDINGS: Final[str] = """
DO $$ DECLARE r text; BEGIN
    IF to_regclass('legacy_findings') IS NULL THEN
        RETURN;
    END IF;
    FOREACH r IN ARRAY ARRAY['gryphon_runtime', 'gryphon_orchestrator',
                             'gryphon_enrichment', 'gryphon_verification'] LOOP
        IF to_regrole(r) IS NOT NULL THEN
            EXECUTE format('REVOKE ALL ON legacy_findings FROM %I', r);
        END IF;
    END LOOP;
END $$;
"""
DROP_CHAIN_PLACEHOLDER: Final[str] = "DROP TABLE IF EXISTS exploit_chain;"

#: The read surface. A later INCONCLUSIVE must never hide an earlier CONFIRMED,
#: which is the whole point of this view: the primary columns carry the newest
#: *determinate* verdict for a subject, the last attempt gets its own columns
#: whatever its status, and a retraction surfaces as RETRACTED rather than as a
#: deletion. ``revision`` is how many verdicts the subject has accumulated in
#: this scan, so a reader can tell a first answer from a re-verified one. The
#: pass salt is absent by construction: the view is built from the verdict table
#: alone and never joins the pass row that holds it.
CREATE_VIEW: Final[str] = """
CREATE VIEW finding_verification_view AS
WITH verdict AS (
    SELECT fv.scan_run_id,
           fv.subject_key,
           fv.finding_id,
           fv.pass_id,
           fv.status,
           fv.justification,
           fv.verifier_id,
           fv.registry_digest,
           fv.rule,
           fv.matched_predicates,
           fv.control_summary,
           fv.projection,
           fv.projection_digest,
           fv.asserted_by,
           fv.observed_at,
           fv.status IN ('CONFIRMED', 'REFUTED', 'NOT_REPRODUCED') AS determinate,
           EXISTS (
               SELECT 1
                 FROM verification_retraction r
                WHERE r.pass_id = fv.pass_id
                  AND r.finding_id = fv.finding_id
           ) AS retracted,
           count(*) OVER (PARTITION BY fv.scan_run_id, fv.subject_key) AS revision
      FROM finding_verification fv
),
settled AS (
    SELECT DISTINCT ON (scan_run_id, subject_key) *
      FROM verdict
     ORDER BY scan_run_id, subject_key, determinate DESC, observed_at DESC, pass_id DESC
),
attempt AS (
    SELECT DISTINCT ON (scan_run_id, subject_key)
           scan_run_id, subject_key, pass_id, status, justification, observed_at
      FROM verdict
     ORDER BY scan_run_id, subject_key, observed_at DESC, pass_id DESC
)
SELECT s.scan_run_id,
       s.subject_key,
       s.finding_id,
       s.pass_id,
       CASE WHEN s.retracted THEN 'RETRACTED' ELSE s.status END AS status,
       s.status AS verdict_status,
       s.justification,
       s.verifier_id,
       s.registry_digest,
       s.rule,
       s.matched_predicates,
       s.control_summary,
       s.projection,
       s.projection_digest,
       s.asserted_by,
       s.determinate,
       s.retracted,
       s.revision,
       s.observed_at AS as_of,
       a.status AS last_attempt_status,
       a.justification AS last_attempt_justification,
       a.observed_at AS last_attempt_at,
       a.pass_id AS last_attempt_pass_id,
       NULL::text AS human_disposition,
       NULL::text AS advisory_label
  FROM settled s
  JOIN attempt a
    ON a.scan_run_id = s.scan_run_id
   AND a.subject_key = s.subject_key;
"""
DROP_VIEW: Final[str] = f"DROP VIEW IF EXISTS {VIEW_NAME};"


# =============================================================================
# Partitions
# =============================================================================


def partition_name(table: str, year: int, month: int) -> str:
    """The name of one monthly partition. Shared, so readiness can look for it."""
    return f"{table}_{year:04d}_{month:02d}"


def default_partition(table: str) -> str:
    return f"{table}_{DEFAULT_PARTITION_SUFFIX}"


def partition_unique_index(partition: str) -> str:
    """The narrow unique index one partition carries."""
    return f"uq_{partition}_identity"


def partition_truncate_trigger(partition: str) -> str:
    """The statement-level guard one partition carries; parents cannot clone it."""
    return f"trg_{partition}_no_truncate"


def month_start(year: int, month: int) -> date:
    return date(year, month, 1)


def next_month(year: int, month: int) -> tuple[int, int]:
    return (year + 1, 1) if month == 12 else (year, month + 1)


def month_sequence(start: date, months: int) -> tuple[tuple[int, int], ...]:
    """``months`` consecutive (year, month) pairs beginning with ``start``'s."""
    if months < 1:
        return ()
    out: list[tuple[int, int]] = []
    year, month = start.year, start.month
    for _ in range(months):
        out.append((year, month))
        year, month = next_month(year, month)
    return tuple(out)


def partition_statements(*, table: str, name: str, bounds: str) -> tuple[str, ...]:
    """The three statements one partition needs.

    The unique index is the contract's narrow key, which the parent cannot
    carry: PostgreSQL requires a partitioned table's unique constraints to
    contain its partition key. The TRUNCATE guard is per partition because
    statement-level triggers are not cloned — only row-level ones are — so a
    partition created without one could be truncated on its own while the parent
    stayed protected. One statement per execute(): the async driver cannot
    prepare a string holding more than one command.
    """
    unique_columns = ", ".join(PARTITION_UNIQUE_COLUMNS[table])
    return (
        f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF {table} {bounds};",
        f"CREATE UNIQUE INDEX IF NOT EXISTS {partition_unique_index(name)} "
        f"ON {name} ({unique_columns});",
        f"CREATE TRIGGER {partition_truncate_trigger(name)} BEFORE TRUNCATE ON {name} "
        "FOR EACH STATEMENT EXECUTE FUNCTION gryphon_reject_truncate();",
    )


def month_bounds(year: int, month: int) -> str:
    """A month's range bound, with an explicit offset.

    The literal pins UTC rather than leaving the boundary to the session's time
    zone: a partition whose edge moves with a client setting is a partition that
    can reject a row the database clock just produced.
    """
    lower = month_start(year, month)
    upper = month_start(*next_month(year, month))
    return f"FOR VALUES FROM ('{lower} 00:00:00+00') TO ('{upper} 00:00:00+00')"


def monthly_partition_statements(
    *, start: date, months: int = PARTITION_HORIZON_MONTHS
) -> tuple[str, ...]:
    """Monthly partitions for every partitioned table, from ``start``."""
    statements: list[str] = []
    for table in PARTITIONED_TABLES:
        for year, month in month_sequence(start, months):
            statements.extend(
                partition_statements(
                    table=table,
                    name=partition_name(table, year, month),
                    bounds=month_bounds(year, month),
                )
            )
    return tuple(statements)


def default_partition_statements() -> tuple[str, ...]:
    """The catch-all partitions, so a row outside every month is still written."""
    statements: list[str] = []
    for table in PARTITIONED_TABLES:
        statements.extend(
            partition_statements(table=table, name=default_partition(table), bounds="DEFAULT")
        )
    return tuple(statements)


def drop_partition_statements(
    *, start: date, months: int = PARTITION_HORIZON_MONTHS
) -> tuple[str, ...]:
    statements: list[str] = []
    for table in PARTITIONED_TABLES:
        statements.append(f"DROP TABLE IF EXISTS {default_partition(table)};")
        for year, month in month_sequence(start, months):
            statements.append(f"DROP TABLE IF EXISTS {partition_name(table, year, month)};")
    return tuple(statements)


def required_partitions(today: date, *, months: int = 1) -> tuple[str, ...]:
    """Monthly partition names that should exist for writes from ``today``."""
    return tuple(
        partition_name(table, year, month)
        for table in PARTITIONED_TABLES
        for year, month in month_sequence(today, months)
    )


# =============================================================================
# Triggers
# =============================================================================


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
    for table in VERIFICATION_TABLES:
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
    for table in VERIFICATION_TABLES:
        statements.append(f"DROP TRIGGER IF EXISTS trg_{table}_no_truncate ON {table};")
    return tuple(statements)


def expected_triggers() -> dict[str, str]:
    """Trigger name → table, exactly as the migration creates them.

    Partition-level guards are not here: their names depend on which months
    exist, so readiness derives them from the partitions it actually finds.
    """
    triggers: dict[str, str] = {}
    for table in APPEND_ONLY_TABLES:
        triggers[f"trg_{table}_no_mutation"] = table
    for table in LIFECYCLE_TABLES:
        triggers[f"trg_{table}_no_delete"] = table
    for table in VERIFICATION_TABLES:
        triggers[f"trg_{table}_no_truncate"] = table
    return triggers


# =============================================================================
# Grants
# =============================================================================


def grant_statements() -> tuple[str, ...]:
    role = DATABASE_ROLE
    own = ", ".join(VERIFICATION_TABLES)
    upstream = ", ".join(t for t in UPSTREAM_READ_TABLES if t != BARRIER_TABLE)
    return (
        f"DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO {role}', "
        "current_database()); END $$;",
        f"GRANT USAGE ON SCHEMA public TO {role};",
        f"GRANT SELECT ON {upstream} TO {role};",
        f"GRANT SELECT ON {own}, {VIEW_NAME} TO {role};",
        # INSERT on the pass, the write-once pin row and every append-only table.
        f"GRANT INSERT ON {own} TO {role};",
        f"GRANT UPDATE ({', '.join(PASS_UPDATABLE_COLUMNS)}) ON verification_pass TO {role};",
        # Readiness is a barrier, and the revision it compares against lives in
        # this table. SELECT only: the role can never write its own revision.
        f"DO $$ BEGIN IF to_regclass('public.{BARRIER_TABLE}') IS NOT NULL THEN "
        f"GRANT SELECT ON {BARRIER_TABLE} TO {role}; END IF; END $$;",
        # Writers of other layers get no write path into verification tables:
        # the component whose claims these rows hold is the only one that may
        # author them.
        "DO $$ DECLARE r text; BEGIN "
        f"FOREACH r IN ARRAY ARRAY[{', '.join(repr(r) for r in OTHER_WRITER_ROLES)}] LOOP "
        "IF to_regrole(r) IS NOT NULL THEN "
        f"EXECUTE format('REVOKE {', '.join(WRITE_PRIVILEGES)} ON {own} FROM %I', r); "
        "END IF; END LOOP; END $$;",
    )


def hardening_statements() -> tuple[str, ...]:
    """Absences made explicit rather than inherited.

    Nothing grants these privileges, so each REVOKE is a no-op on a correct
    database — which is the point: the matrix readiness asserts is stated in the
    migration too, and a grant added by hand between deployments is removed by
    the next one instead of surviving quietly.
    """
    role = DATABASE_ROLE
    return (
        "DO $$ DECLARE t text; BEGIN "
        f"FOREACH t IN ARRAY ARRAY[{', '.join(repr(t) for t in FORBIDDEN_WRITE_TABLES)}] LOOP "
        "IF to_regclass(t) IS NOT NULL THEN "
        f"EXECUTE format('REVOKE {', '.join(WRITE_PRIVILEGES)} ON %I FROM {role}', t); "
        "END IF; END LOOP; END $$;",
        "DO $$ DECLARE t text; BEGIN "
        f"FOREACH t IN ARRAY ARRAY[{', '.join(repr(t) for t in NO_READ_TABLES)}] LOOP "
        "IF to_regclass(t) IS NOT NULL THEN "
        f"EXECUTE format('REVOKE SELECT ON %I FROM {role}', t); "
        "END IF; END LOOP; END $$;",
    )


def revoke_statements() -> tuple[str, ...]:
    role = DATABASE_ROLE
    upstream = ", ".join(t for t in UPSTREAM_READ_TABLES if t != BARRIER_TABLE)
    return (
        f"DO $$ BEGIN IF to_regrole('{role}') IS NOT NULL THEN "
        f"EXECUTE 'REVOKE ALL ON {', '.join(VERIFICATION_TABLES)}, {VIEW_NAME} FROM {role}'; "
        f"EXECUTE 'REVOKE ALL ON {upstream} FROM {role}'; "
        f"IF to_regclass('public.{BARRIER_TABLE}') IS NOT NULL THEN "
        f"EXECUTE 'REVOKE ALL ON {BARRIER_TABLE} FROM {role}'; END IF; "
        "END IF; END $$;",
    )


# =============================================================================
# The privilege matrix
# =============================================================================


def expected_table_privileges() -> dict[tuple[str, str], bool]:
    """(table, privilege) → granted?

    The ``False`` entries are the ones that matter. A role that happens to hold
    what it needs is not least-privileged; a role that *cannot* write upstream
    evidence or the gateway's ledger is, and only an absence check establishes
    that.
    """
    expected: dict[tuple[str, str], bool] = {}
    for table in FORBIDDEN_WRITE_TABLES:
        for privilege in WRITE_PRIVILEGES:
            expected[(table, privilege)] = False
    for table in UPSTREAM_READ_TABLES:
        expected[(table, "SELECT")] = True
        for privilege in WRITE_PRIVILEGES:
            expected[(table, privilege)] = False
    for table in NO_READ_TABLES:
        expected[(table, "SELECT")] = False
    for table in VERIFICATION_TABLES:
        expected[(table, "SELECT")] = True
        expected[(table, "INSERT")] = True
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            expected[(table, privilege)] = False
    expected[(VIEW_NAME, "SELECT")] = True
    for privilege in ("INSERT", "UPDATE", "DELETE"):
        expected[(VIEW_NAME, privilege)] = False
    return expected


def expected_column_updates() -> dict[tuple[str, str], bool]:
    """(table, column) → may this role UPDATE it?

    Column-scoped UPDATE is the whole of this role's mutability, so both halves
    are asserted: the lifecycle columns it needs, and the identity, salt and
    provenance columns it must never be able to move.
    """
    expected: dict[tuple[str, str], bool] = {
        ("verification_pass", column): True for column in PASS_UPDATABLE_COLUMNS
    }
    for column in PASS_FROZEN_COLUMNS:
        expected[("verification_pass", column)] = False
    for table, column in APPEND_ONLY_FROZEN_COLUMNS:
        expected[(table, column)] = False
    return expected
