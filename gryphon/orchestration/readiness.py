"""Readiness checks for the orchestration layer.

Answers one question before a scan is ever attempted: *would this deployment
enforce what it claims to enforce?* Each check is a thing that can be wrong in a
way a scan would not obviously reveal — a missing table, a graph built with
persistence, an unattested estate, a runtime role that can rewrite schema, a
tracing variable left set in a shell.

Checks are advisory outside production and fatal inside it, which matches the
rest of the codebase: a developer should be able to run the pipeline on a
laptop, and production should refuse to run half-configured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text

from gryphon.db.session import Database
from gryphon.orchestration.constants import (
    GRAPH_VERSION,
    PLANNED_TOOLS,
    REPORT_SCHEMA_VERSION,
    STEP_PLAN,
)
from gryphon.orchestration.graph import topology
from gryphon.orchestration.settings import (
    TELEMETRY_ENV_VARS,
    OrchestrationSettings,
    assert_telemetry_disabled,
)
from gryphon.orchestration.state import ScanGraphState, assert_state_schema_is_closed
from gryphon.tooling.constants import ToolId

#: Tables this layer owns. Absent means the migration has not been applied.
REQUIRED_TABLES: tuple[str, ...] = (
    "scan_lifecycle",
    "scan_plan",
    "plan_item",
    "admitted_target",
    "raw_finding",
    "scan_report",
    "orchestration_audit",
)

#: Append-only tables that must carry a mutation-rejecting trigger.
APPEND_ONLY_TABLES: tuple[str, ...] = (
    "raw_finding",
    "scan_report",
    "orchestration_audit",
    "admitted_target",
    "scan_plan",
)


@dataclass(frozen=True, slots=True)
class Check:
    """One readiness check result."""

    name: str
    passed: bool
    detail: str = ""
    fatal: bool = True
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """The full readiness picture."""

    checks: tuple[Check, ...]
    environment: str

    @property
    def ready(self) -> bool:
        return all(c.passed or not c.fatal for c in self.checks)

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.passed)


async def check_orchestration_readiness(
    *, database: Database, settings: OrchestrationSettings
) -> ReadinessReport:
    """Run every readiness check."""
    prod = settings.environment == "prod"
    checks: list[Check] = []

    # -- the state contract ---------------------------------------------------
    try:
        assert_state_schema_is_closed()
        checks.append(
            Check(
                "graph_state_closed",
                True,
                "graph state carries only primitives; no authority type",
                details={"fields": sorted(ScanGraphState.__annotations__)},
            )
        )
    except Exception as exc:
        checks.append(Check("graph_state_closed", False, str(exc)))

    # -- no persistence in the graph -----------------------------------------
    topo = topology()
    checks.append(
        Check(
            "graph_has_no_checkpointer",
            topo["checkpointer"] is None,
            "the compiled graph persists nothing; the ledger is the authority",
            details={"graph_version": GRAPH_VERSION, "nodes": topo["nodes"]},
        )
    )

    # -- the step plan covers the catalog exactly ----------------------------
    missing = sorted(t.value for t in ToolId if t not in PLANNED_TOOLS)
    duplicated = len(STEP_PLAN) != len({(s.tool_id, s.step) for s in STEP_PLAN})
    checks.append(
        Check(
            "step_plan_complete",
            not missing and not duplicated,
            "every tool is assigned to exactly one step"
            if not missing
            else f"unassigned tools: {', '.join(missing)}",
            details={"stages": topo["stages"]},
        )
    )

    # -- telemetry ------------------------------------------------------------
    try:
        assert_telemetry_disabled()
        checks.append(
            Check(
                "telemetry_disabled",
                True,
                "no third-party tracing variable is set",
                details={"watched": list(TELEMETRY_ENV_VARS)},
            )
        )
    except Exception as exc:
        checks.append(Check("telemetry_disabled", False, str(exc)))

    # -- target attestation ---------------------------------------------------
    attested = bool(settings.attested_estate_cidrs)
    checks.append(
        Check(
            "address_attestation_configured",
            attested,
            "an attested estate is configured for discovered targets"
            if attested
            else "no attested estate: discovered targets cannot be actively "
            "scanned under strict attestation",
            fatal=prod,
            details={
                "strict": settings.strict_address_attestation,
                "cidr_count": len(settings.attested_estate_cidrs),
            },
        )
    )

    # -- caller authentication ------------------------------------------------
    socket_ok = bool(settings.control_socket_path) and bool(
        settings.control_allowed_uids
    )
    checks.append(
        Check(
            "caller_authentication_configured",
            socket_ok,
            "a control socket with a peer-uid allowlist is configured"
            if socket_ok
            else "no authenticated control socket; CLI identity only",
            fatal=prod,
        )
    )

    # -- schema ---------------------------------------------------------------
    checks.extend(await _schema_checks(database, prod=prod))

    # -- least privilege ------------------------------------------------------
    checks.append(await _privilege_check(database, prod=prod))

    return ReadinessReport(checks=tuple(checks), environment=settings.environment)


async def _schema_checks(database: Database, *, prod: bool) -> list[Check]:
    """Verify the ledger exists and its append-only tables are protected."""
    checks: list[Check] = []
    try:
        async with database.session() as session:
            present = set(
                (
                    await session.execute(
                        text(
                            "SELECT table_name FROM information_schema.tables "
                            "WHERE table_schema = current_schema()"
                        )
                    )
                )
                .scalars()
                .all()
            )
            triggers = set(
                (
                    await session.execute(
                        text(
                            "SELECT event_object_table FROM information_schema.triggers "
                            "WHERE trigger_schema = current_schema()"
                        )
                    )
                )
                .scalars()
                .all()
            )
    except Exception as exc:
        return [Check("ledger_schema_present", False, f"schema unreadable: {exc}")]

    missing_tables = [t for t in REQUIRED_TABLES if t not in present]
    checks.append(
        Check(
            "ledger_schema_present",
            not missing_tables,
            "every ledger table exists"
            if not missing_tables
            else f"missing tables: {', '.join(missing_tables)} (run the migration)",
            details={"required": list(REQUIRED_TABLES)},
        )
    )

    unprotected = [
        t for t in APPEND_ONLY_TABLES if t in present and t not in triggers
    ]
    checks.append(
        Check(
            "append_only_triggers_present",
            not unprotected,
            "append-only tables reject mutation"
            if not unprotected
            else f"no mutation-rejecting trigger on: {', '.join(unprotected)}",
            details={"append_only": list(APPEND_ONLY_TABLES)},
        )
    )
    return checks


async def _privilege_check(database: Database, *, prod: bool) -> Check:
    """Assert the runtime role cannot execute DDL.

    A role that can create a table can also drop the trigger that makes the
    audit append-only, which would let a compromise of this process dismantle
    the record that is supposed to detect it.
    """
    try:
        async with database.session() as session:
            result = await session.execute(
                text("SELECT has_schema_privilege(current_user, current_schema(), 'CREATE')")
            )
            can_create = bool(result.scalar_one())
    except Exception as exc:
        return Check(
            "runtime_role_has_no_ddl",
            False,
            f"privilege could not be determined: {exc}",
            fatal=prod,
        )
    return Check(
        "runtime_role_has_no_ddl",
        not can_create,
        "the runtime role cannot create objects"
        if not can_create
        else "the runtime role holds CREATE on the schema; it can drop the "
        "append-only triggers that protect the audit",
        fatal=prod,
        details={"report_schema_version": REPORT_SCHEMA_VERSION},
    )
