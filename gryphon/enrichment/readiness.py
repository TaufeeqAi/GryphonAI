"""Readiness for the enrichment layer — by facts, not by revision numbers.

A migration revision proves only that a script once ran. These checks inspect
what exists *now*: the tables and the view, that every append-only trigger is
present **and enabled**, that the trigger functions' bodies are the ones this
code expects, the dedicated role's exact privilege matrix (including what it
must *not* hold), the seeded slot, the verified reference data, the policy, the
signing key, the egress posture, the artifact store and the process's own
import graph.

Checks are advisory outside production and fatal inside it, matching the rest
of the codebase: a developer can run the layer on a laptop; production refuses
to run half-configured.
"""

from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

from gryphon.db.session import Database
from gryphon.enrichment.constants import DATABASE_ROLE, ENRICHMENT_SLOT_ID, NETWORK_SOURCES
from gryphon.enrichment.reference import DatasetUnavailable, ReferenceData, load_reference
from gryphon.enrichment.repository import EnrichmentRepository
from gryphon.enrichment.schema import (
    APPEND_ONLY_TABLES,
    ENRICHMENT_TABLES,
    EXPECTED_FUNCTION_FINGERPRINTS,
    LIFECYCLE_TABLES,
    VIEW_NAME,
    expected_column_updates,
    expected_table_privileges,
    function_fingerprint,
)

if TYPE_CHECKING:  # pragma: no cover
    from gryphon.enrichment.bootstrap import EnrichmentServices

#: Modules that must never be loaded in the parent (key-holding) process.
FORBIDDEN_PARENT_MODULES: tuple[str, ...] = (
    "http.client",
    "httpx",
    "httpcore",
    "urllib3",
    "requests",
    "aiohttp",
    "langgraph",
    "gryphon.orchestration",
)


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    passed: bool
    detail: str = ""
    fatal: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "fatal": self.fatal,
            "detail": self.detail,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    checks: tuple[Check, ...]
    environment: str

    @property
    def ready(self) -> bool:
        return all(c.passed or not c.fatal for c in self.checks)

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.passed)

    def as_payload(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "environment": self.environment,
            "checks": [c.as_payload() for c in self.checks],
        }


def expected_triggers() -> dict[str, str]:
    """Trigger name → table, exactly as the migration creates them."""
    triggers: dict[str, str] = {}
    for table in APPEND_ONLY_TABLES:
        triggers[f"trg_{table}_no_mutation"] = table
    for table in LIFECYCLE_TABLES:
        triggers[f"trg_{table}_no_delete"] = table
    for table in ENRICHMENT_TABLES:
        triggers[f"trg_{table}_no_truncate"] = table
    return triggers


def import_graph_check(modules: dict[str, Any] | None = None) -> Check:
    loaded = modules if modules is not None else sys.modules
    present = sorted(
        name
        for name in FORBIDDEN_PARENT_MODULES
        if name in loaded or any(m.startswith(name + ".") for m in loaded)
    )
    return Check(
        "parent_import_graph_clean",
        not present,
        "no HTTP client or orchestration module is loaded in the key-holding process"
        if not present
        else f"forbidden modules loaded: {', '.join(present)}",
        details={"forbidden": list(FORBIDDEN_PARENT_MODULES)},
    )


def configuration_checks(services: EnrichmentServices, *, prod: bool) -> list[Check]:
    """Checks that need no database."""
    checks: list[Check] = [import_graph_check()]
    es = services.settings

    signer_kid = services.audit.kid
    trusted = signer_kid in services.trust.trusted_kids
    configured = bool((es.trusted_public_keys.get(signer_kid) or "").strip())
    checks.append(
        Check(
            "signing_key_dedicated",
            trusted and (configured or not prod),
            f"enrichment attestations are signed with {signer_kid!r}"
            if trusted and (configured or not prod)
            else "the enrichment kid is not in the configured trusted key map",
            details={"kid": signer_kid, "configured_in_trust_map": configured},
        )
    )

    checks.append(
        Check(
            "caller_allowlist_configured",
            bool(es.allowed_uids),
            "enrichment callers are restricted to an allowlist of uids"
            if es.allowed_uids
            else "no caller allowlist: any local user may run enrichment",
            fatal=prod,
            details={"allowed_uids": list(es.allowed_uids)},
        )
    )

    enforcer = services.enforcer
    enforcing = bool(enforcer.enforcing)
    capable = bool(getattr(enforcer, "capable", enforcing))
    checks.append(
        Check(
            "egress_enforced",
            enforcing and capable,
            "acquisition runs inside an enforced, allowlisted network namespace"
            if enforcing and capable
            else (
                "egress is unenforced: acquisition traffic is not contained"
                if not enforcing
                else "the egress enforcer cannot establish a context on this host; "
                "acquisition will fail and snapshots will only age"
            ),
            fatal=prod,
            details={"posture": services.posture, "allowed_hosts": list(es.allowed_hosts)},
        )
    )

    checks.append(
        Check(
            "policy_loaded",
            True,
            f"priority policy {services.policy.label} ({services.policy.short_digest})",
            details={
                "digest": services.policy.digest,
                "epss_threshold": services.policy.epss_threshold,
                "calibrated_models": sorted(services.policy.calibrated_models),
            },
        )
    )

    reference = load_reference(es.reference_dir)
    checks.append(_reference_check(reference))

    checks.append(_artifact_store_check(services))
    checks.append(
        Check(
            "templates_pinned",
            bool(es.templates_digest),
            "template-asserted CVSS cites a pinned template set"
            if es.templates_digest
            else "the template set is unpinned; CVSS assertions say so",
            fatal=False,
        )
    )
    return checks


def _reference_check(reference: ReferenceData | DatasetUnavailable) -> Check:
    if isinstance(reference, DatasetUnavailable):
        return Check(
            "reference_data_verified",
            False,
            f"ATT&CK reference data unavailable: {reference.reason} "
            "(run the provisioning script; ATT&CK assertions will be UNAVAILABLE)",
            fatal=False,
        )
    return Check(
        "reference_data_verified",
        True,
        f"CTID {reference.mapping_version} translated to ATT&CK {reference.attack_version}",
        details={"snapshot_id": reference.snapshot_id},
    )


def _artifact_store_check(services: EnrichmentServices) -> Check:
    root = services.artifacts.root
    try:
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=root, prefix=".probe-", delete=True):
            pass
    except OSError as exc:
        return Check("artifact_store_writable", False, f"{root}: {exc}")
    return Check("artifact_store_writable", True, str(root))


async def database_checks(
    database: Database, services: EnrichmentServices, *, prod: bool
) -> list[Check]:
    try:
        async with database.session() as session:
            current_user = (await session.execute(text("SELECT current_user"))).scalar_one()
            role_exists = (
                await session.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": DATABASE_ROLE}
                )
            ).first() is not None
            relations = set(
                (
                    await session.execute(
                        text(
                            "SELECT c.relname FROM pg_class c JOIN pg_namespace n "
                            "ON n.oid = c.relnamespace WHERE n.nspname = current_schema() "
                            "AND c.relkind IN ('r', 'v')"
                        )
                    )
                ).scalars()
            )
            trigger_rows = (
                await session.execute(
                    text(
                        "SELECT t.tgname, c.relname, t.tgenabled FROM pg_trigger t "
                        "JOIN pg_class c ON c.oid = t.tgrelid "
                        "JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE NOT t.tgisinternal AND n.nspname = current_schema()"
                    )
                )
            ).all()
            function_rows = (
                await session.execute(
                    text(
                        "SELECT p.proname, p.prosrc FROM pg_proc p "
                        "WHERE p.proname = ANY(:names)"
                    ),
                    {"names": list(EXPECTED_FUNCTION_FINGERPRINTS)},
                )
            ).all()
            privileges: dict[tuple[str, str], bool] = {}
            columns: dict[tuple[str, str], bool] = {}
            can_create = None
            if role_exists:
                for (table, privilege) in expected_table_privileges():
                    if table not in relations:
                        continue
                    privileges[(table, privilege)] = bool(
                        (
                            await session.execute(
                                text("SELECT has_table_privilege(:r, :t, :p)"),
                                {"r": DATABASE_ROLE, "t": table, "p": privilege},
                            )
                        ).scalar_one()
                    )
                for (table, column) in expected_column_updates():
                    if table not in relations:
                        continue
                    columns[(table, column)] = bool(
                        (
                            await session.execute(
                                text("SELECT has_column_privilege(:r, :t, :c, 'UPDATE')"),
                                {"r": DATABASE_ROLE, "t": table, "c": column},
                            )
                        ).scalar_one()
                    )
                can_create = bool(
                    (
                        await session.execute(
                            text("SELECT has_schema_privilege(:r, current_schema(), 'CREATE')"),
                            {"r": DATABASE_ROLE},
                        )
                    ).scalar_one()
                )
            slot = (
                await EnrichmentRepository(session).slot_state()
                if "enrichment_slot" in relations
                else None
            )
            freshness = await _freshness(session, services) if "intel_snapshot" in relations else {}
    except Exception as exc:
        return [Check("database_reachable", False, f"{type(exc).__name__}: {exc}")]

    checks: list[Check] = [
        Check("database_reachable", True, f"connected as {current_user}"),
        Check(
            "dedicated_role",
            current_user == DATABASE_ROLE,
            f"the enrichment process authenticates as {DATABASE_ROLE}"
            if current_user == DATABASE_ROLE
            else f"connected as {current_user!r}, not the dedicated {DATABASE_ROLE!r} role",
            fatal=prod,
        ),
    ]

    missing = [t for t in (*ENRICHMENT_TABLES, VIEW_NAME) if t not in relations]
    checks.append(
        Check(
            "schema_present",
            not missing,
            "every enrichment table and the read view exist"
            if not missing
            else f"missing: {', '.join(missing)} (apply the migrations)",
        )
    )

    present = {(name, table): enabled for name, table, enabled in trigger_rows}
    problems: list[str] = []
    for name, table in expected_triggers().items():
        state = present.get((name, table))
        if state is None:
            problems.append(f"{name} missing")
        elif state == "D":
            problems.append(f"{name} disabled")
    checks.append(
        Check(
            "append_only_triggers_enabled",
            not problems,
            "every append-only and no-truncate trigger exists and is enabled"
            if not problems
            else "; ".join(problems[:8]),
            details={"expected": len(expected_triggers())},
        )
    )

    deployed = {name: function_fingerprint(src) for name, src in function_rows}
    drift = [
        name
        for name, expected in EXPECTED_FUNCTION_FINGERPRINTS.items()
        if deployed.get(name) != expected
    ]
    checks.append(
        Check(
            "trigger_functions_unaltered",
            not drift,
            "trigger function bodies match this code"
            if not drift
            else f"function body differs or is missing: {', '.join(drift)}",
        )
    )

    if not role_exists:
        checks.append(Check("role_privileges_exact", False, f"role {DATABASE_ROLE} does not exist"))
    else:
        wrong = [
            f"{table}.{privilege}={'granted' if privileges[(table, privilege)] else 'missing'}"
            for (table, privilege), expected in expected_table_privileges().items()
            if (table, privilege) in privileges and privileges[(table, privilege)] != expected
        ]
        wrong += [
            f"{table}({column}).UPDATE={'granted' if columns[(table, column)] else 'missing'}"
            for (table, column), expected in expected_column_updates().items()
            if (table, column) in columns and columns[(table, column)] != expected
        ]
        if can_create:
            wrong.append("schema.CREATE=granted")
        checks.append(
            Check(
                "role_privileges_exact",
                not wrong,
                f"{DATABASE_ROLE} holds exactly its write set and no upstream write"
                if not wrong
                else "; ".join(wrong[:10]),
                details={"checked": len(privileges) + len(columns)},
            )
        )

    checks.append(
        Check(
            "slot_seeded",
            slot is not None,
            f"slot {ENRICHMENT_SLOT_ID!r} present"
            if slot
            else "the enrichment slot row is missing",
        )
    )

    for source, info in freshness.items():
        checks.append(
            Check(
                f"snapshot_fresh_{source.lower()}",
                bool(info.get("snapshot_id")) and not info.get("stale"),
                (
                    f"{info['snapshot_id']} age {info['age_s']}s"
                    if info.get("snapshot_id")
                    else "no accepted snapshot yet (run a refresh)"
                ),
                fatal=False,
                details=info,
            )
        )
    return checks


async def _freshness(session: Any, services: EnrichmentServices) -> dict[str, dict[str, Any]]:
    repo = EnrichmentRepository(session)
    out: dict[str, dict[str, Any]] = {}
    for source in NETWORK_SOURCES:
        newest = await repo.newest_snapshot(source.value)
        if newest is None:
            out[source.value] = {"snapshot_id": None}
            continue
        age = await services.snapshots.age_seconds(repo, newest)
        max_age = int(services.settings.max_age_seconds(source.value))
        out[source.value] = {
            "snapshot_id": newest.snapshot_id,
            "age_s": age,
            "max_age_s": max_age,
            "stale": age > max_age,
        }
    return out


async def check_enrichment_readiness(services: EnrichmentServices) -> ReadinessReport:
    prod = services.core.environment == "prod"
    checks = configuration_checks(services, prod=prod)
    checks.extend(await database_checks(services.database, services, prod=prod))
    return ReadinessReport(checks=tuple(checks), environment=services.core.environment)
