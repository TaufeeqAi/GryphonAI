"""Readiness by facts: the parts that must hold without a database.

Four properties are exercised here, each for a reason:

* the **import-graph walker**, against fixture modules, because the claim "this
  layer holds no network client" is a claim about what the package imports and
  nothing else proves it;
* **key custody**, because a process that can load another purpose's private key
  can attest its own inputs, and a key in an environment file is as reachable as
  one exported into the shell;
* the **privilege matrix**, because its ``False`` entries — no upstream write, no
  gateway write, no UPDATE on a pin — are the whole of least privilege, and an
  expectation table that drifted would pass every behavioural test;
* the **feature-set comparison and the judgement of facts**, because a missing
  enforcement feature and a disabled trigger must be refusals rather than
  warnings, and proving that must not need a running gateway or a server.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from gryphon.tooling.gateway.protocol import Welcome
from gryphon.verification.constants import (
    DATABASE_ROLE,
    DETERMINATE_STATUSES,
    REQUIRED_GATEWAY_FEATURES,
)
from gryphon.verification.readiness import (
    FORBIDDEN_LOADED_MODULES,
    VERIFICATION_PACKAGE_ROOT,
    Check,
    DatabaseFacts,
    ReadinessReport,
    dotenv_assigned_names,
    effective_posture,
    facts_checks,
    foreign_signing_keys,
    gateway_checks,
    import_graph_check,
    key_custody_check,
    loaded_module_check,
    missing_gateway_features,
    scan_import_graph,
)
from gryphon.verification.schema import (
    APPEND_ONLY_FROZEN_COLUMNS,
    CREATE_VIEW,
    EXPECTED_ALEMBIC_REVISION,
    EXPECTED_FUNCTION_FINGERPRINTS,
    EXPECTED_UNIQUE_COLUMNS,
    FORBIDDEN_WRITE_TABLES,
    GATEWAY_TABLES,
    NO_READ_TABLES,
    OPEN_PASS_INDEX,
    PARTITION_KEY_BY_TABLE,
    PARTITION_UNIQUE_COLUMNS,
    PARTITION_WARN_MONTHS,
    PARTITIONED_TABLES,
    PASS_FROZEN_COLUMNS,
    PASS_UPDATABLE_COLUMNS,
    REJECT_MUTATION_BODY,
    UPSTREAM_READ_TABLES,
    VERIFICATION_TABLES,
    VIEW_NAME,
    default_partition,
    default_partition_statements,
    expected_column_updates,
    expected_table_privileges,
    expected_triggers,
    function_fingerprint,
    grant_statements,
    hardening_statements,
    month_sequence,
    monthly_partition_statements,
    next_month,
    partition_name,
    partition_truncate_trigger,
    partition_unique_index,
    trigger_statements,
)

pytestmark = pytest.mark.unit

TODAY = date(2026, 11, 14)

#: The nine lifecycle columns the contract names. The deployed grant adds
#: ``adoption_count``, which is counted in the statement that advances the epoch.
CONTRACT_UPDATABLE_COLUMNS = (
    "state",
    "outcome",
    "reason",
    "detail",
    "holder",
    "claim_epoch",
    "cancellation_epoch",
    "lease_expires_at",
    "completed_at",
)


def _named(checks: Iterable[Check], name: str) -> Check:
    for check in checks:
        if check.name == name:
            return check
    raise AssertionError(f"no check named {name!r}")


def _partition_set(partitions: Mapping[str, frozenset[str]]) -> frozenset[str]:
    found: set[str] = set()
    for names in partitions.values():
        found |= set(names)
    return frozenset(found)


# =============================================================================
# The import graph
# =============================================================================

_CLEAN_MODULE = """
from __future__ import annotations

import asyncio
import hashlib
from urllib.parse import urlsplit

from gryphon.tooling.gateway.client import GatewayClient
from gryphon.tooling.observation.facts import ObservationFacts
"""

_DIRTY_MODULE = """
from __future__ import annotations

import socket
import httpx

from gryphon.orchestration.graph import build
from gryphon import orchestration


def late() -> None:
    import subprocess  # noqa: S404
"""


def _package(root: Path, **modules: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "__init__.py").write_text("", encoding="utf-8")
    for name, body in modules.items():
        (root / f"{name}.py").write_text(body, encoding="utf-8")
    return root


def test_clean_package_has_no_violations(tmp_path: Path) -> None:
    root = _package(tmp_path / "pkg", clean=_CLEAN_MODULE)
    assert scan_import_graph(root) == ()


def test_urllib_parse_is_allowed_but_urllib_request_is_not(tmp_path: Path) -> None:
    root = _package(
        tmp_path / "pkg",
        parse="from urllib.parse import urlsplit\n",
        fetch="import urllib.request\n",
    )
    found = {v.imported for v in scan_import_graph(root)}
    assert found == {"urllib.request"}


def test_every_forbidden_form_is_caught(tmp_path: Path) -> None:
    root = _package(tmp_path / "pkg", dirty=_DIRTY_MODULE)
    found = {v.imported for v in scan_import_graph(root)}
    assert found == {
        "socket",
        "httpx",
        "gryphon.orchestration.graph",
        "gryphon.orchestration",
        "subprocess",
    }


def test_a_relative_import_is_not_a_violation(tmp_path: Path) -> None:
    root = _package(tmp_path / "pkg", local="from . import clean\nfrom .clean import x\n")
    assert scan_import_graph(root) == ()


def test_an_unreadable_module_is_reported_not_skipped(tmp_path: Path) -> None:
    root = _package(tmp_path / "pkg", broken="def (:\n")
    violations = scan_import_graph(root)
    assert len(violations) == 1
    assert "unreadable" in violations[0].imported


def test_a_violation_names_its_file_and_line(tmp_path: Path) -> None:
    root = _package(tmp_path / "pkg", dirty="import asyncio\nimport httpx\n")
    check = import_graph_check(root)
    assert check.passed is False
    assert check.fatal is True
    assert "dirty.py:2 imports httpx" in check.detail


def test_the_shipped_package_imports_no_client_and_no_orchestration() -> None:
    violations = scan_import_graph(VERIFICATION_PACKAGE_ROOT)
    assert violations == (), [v.describe() for v in violations]


@pytest.mark.parametrize(
    "loaded",
    [
        ("httpx",),
        ("gryphon.orchestration.graph",),
        ("gryphon.tooling.enforcement.service",),
        ("http.client",),
    ],
)
def test_loaded_forbidden_modules_fail_the_process_check(loaded: tuple[str, ...]) -> None:
    check = loaded_module_check({"asyncio", *loaded})
    assert check.passed is False


def test_the_two_permitted_sockets_do_not_fail_the_process_check() -> None:
    """``socket`` and ``ssl`` arrive with the driver and the gateway client."""
    assert "socket" not in FORBIDDEN_LOADED_MODULES
    assert loaded_module_check({"asyncio", "socket", "ssl", "asyncpg", "sqlalchemy"}).passed


# =============================================================================
# Key custody
# =============================================================================


def test_a_foreign_signing_key_in_the_environment_is_reported() -> None:
    reachable = foreign_signing_keys({"GRYPHON_AUDIT_SIGNING_KEY_HEX": "ab" * 32})
    assert reachable == ("GRYPHON_AUDIT_SIGNING_KEY_HEX",)


def test_a_blank_assignment_is_not_a_reachable_key() -> None:
    assert foreign_signing_keys({"GRYPHON_GRANT_SIGNING_KEY_HEX": "   "}) == ()


def test_a_key_hidden_in_an_env_file_is_still_reachable(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\n"
        "GRYPHON_VERIFICATION_KID=verification-1\n"
        "GRYPHON_ENRICHMENT_SIGNING_KEY_HEX=cd00\n"
        "GRYPHON_CAPABILITY_SIGNING_KEY_HEX=\n",
        encoding="utf-8",
    )
    assert "GRYPHON_ENRICHMENT_SIGNING_KEY_HEX" in dotenv_assigned_names(env_file)
    assert "GRYPHON_CAPABILITY_SIGNING_KEY_HEX" not in dotenv_assigned_names(env_file)
    check = key_custody_check({}, env_file=env_file)
    assert check.passed is False
    assert check.fatal is True
    assert "GRYPHON_ENRICHMENT_SIGNING_KEY_HEX" in check.detail


def test_custody_passes_with_only_the_verification_key(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("GRYPHON_VERIFICATION_SIGNING_KEY_HEX=ab00\n", encoding="utf-8")
    assert key_custody_check({"GRYPHON_VERIFICATION_KID": "v1"}, env_file=env_file).passed


# =============================================================================
# The privilege matrix
# =============================================================================


def test_no_upstream_or_gateway_table_is_writable() -> None:
    expected = expected_table_privileges()
    for table in FORBIDDEN_WRITE_TABLES:
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert expected[(table, privilege)] is False, (table, privilege)


def test_the_gateway_ledger_is_read_only_or_unreadable() -> None:
    """INV-P5-021: the component whose claims the ledger adjudicates cannot write it."""
    expected = expected_table_privileges()
    for table in GATEWAY_TABLES:
        assert expected[(table, "INSERT")] is False
    assert expected[("tool_execution", "SELECT")] is True
    assert expected[("tool_invocation_audit", "SELECT")] is False


def test_own_tables_are_insert_only() -> None:
    expected = expected_table_privileges()
    for table in VERIFICATION_TABLES:
        assert expected[(table, "SELECT")] is True
        assert expected[(table, "INSERT")] is True
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            assert expected[(table, privilege)] is False
    assert expected[(VIEW_NAME, "SELECT")] is True


def test_upstream_reads_are_granted_and_never_more() -> None:
    expected = expected_table_privileges()
    for table in UPSTREAM_READ_TABLES:
        assert expected[(table, "SELECT")] is True
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert expected[(table, privilege)] is False


def test_the_read_set_and_the_no_read_set_do_not_overlap() -> None:
    assert not set(NO_READ_TABLES) & set(UPSTREAM_READ_TABLES)
    assert not set(NO_READ_TABLES) & set(VERIFICATION_TABLES)


def test_only_lifecycle_columns_are_updatable() -> None:
    columns = expected_column_updates()
    assert all(columns[("verification_pass", c)] for c in PASS_UPDATABLE_COLUMNS)
    for frozen in PASS_FROZEN_COLUMNS:
        assert columns[("verification_pass", frozen)] is False
        assert frozen not in PASS_UPDATABLE_COLUMNS


def test_the_updatable_set_is_the_contract_list_plus_the_adoption_counter() -> None:
    assert set(PASS_UPDATABLE_COLUMNS) == {*CONTRACT_UPDATABLE_COLUMNS, "adoption_count"}


def test_pins_and_the_manifest_are_not_updatable_anywhere() -> None:
    """They live in the write-once table, so there is no column-scoped path at all."""
    assert "pins" not in PASS_UPDATABLE_COLUMNS
    assert "manifest" not in PASS_UPDATABLE_COLUMNS
    columns = expected_column_updates()
    for table, column in APPEND_ONLY_FROZEN_COLUMNS:
        assert columns[(table, column)] is False, (table, column)


def test_the_salt_and_the_request_key_can_never_be_updated() -> None:
    columns = expected_column_updates()
    assert columns[("verification_pass", "salt")] is False
    assert columns[("verification_pass", "request_key")] is False


def test_grants_never_name_delete_or_truncate_for_the_role() -> None:
    for statement in grant_statements():
        if f"TO {DATABASE_ROLE}" in statement:
            assert "DELETE" not in statement and "TRUNCATE" not in statement


def test_hardening_revokes_name_every_forbidden_table() -> None:
    statements = "".join(hardening_statements())
    for table in FORBIDDEN_WRITE_TABLES:
        assert f"'{table}'" in statements, table
    for table in NO_READ_TABLES:
        assert f"'{table}'" in statements, table


# =============================================================================
# Schema facts
# =============================================================================


def test_triggers_cover_every_table_one_statement_each() -> None:
    statements = trigger_statements()
    assert len(statements) == len(expected_triggers())
    assert all(s.count(";") == 1 for s in statements)
    for name in expected_triggers():
        assert any(name in s for s in statements)


def test_every_partition_gets_a_narrow_key_and_its_own_truncate_guard() -> None:
    statements = monthly_partition_statements(start=date(2026, 12, 1), months=2)
    # Two months by two tables, each needing three statements.
    assert len(statements) == 12
    assert all(s.count(";") == 1 for s in statements)
    for table in PARTITIONED_TABLES:
        name = partition_name(table, 2026, 12)
        columns = ", ".join(PARTITION_UNIQUE_COLUMNS[table])
        assert any(f"PARTITION OF {table} " in s and name in s for s in statements)
        assert any(
            f"{partition_unique_index(name)} ON {name} ({columns})" in s for s in statements
        )
        assert any(partition_truncate_trigger(name) in s for s in statements)
    assert any("verification_observation_2027_01" in s for s in statements)


def test_the_month_bound_pins_utc() -> None:
    """A boundary that moved with a session's time zone could reject a fresh row."""
    statements = monthly_partition_statements(start=date(2026, 11, 1), months=1)
    bounds = next(s for s in statements if "PARTITION OF" in s)
    assert "FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00')" in bounds


def test_a_default_partition_exists_so_an_out_of_range_row_is_still_written() -> None:
    statements = default_partition_statements()
    for table in PARTITIONED_TABLES:
        assert any(
            f"{default_partition(table)} PARTITION OF {table} DEFAULT" in s for s in statements
        )


def test_month_sequence_crosses_a_year_boundary() -> None:
    assert month_sequence(date(2026, 11, 30), 3) == ((2026, 11), (2026, 12), (2027, 1))
    assert next_month(2026, 12) == (2027, 1)


def test_the_view_hides_the_salt_and_tells_the_truth_about_retraction() -> None:
    assert "verification_pass" not in CREATE_VIEW
    assert "salt" not in CREATE_VIEW
    assert "'RETRACTED'" in CREATE_VIEW
    for status in DETERMINATE_STATUSES:
        assert f"'{status.value}'" in CREATE_VIEW
    assert "last_attempt_status" in CREATE_VIEW
    assert "human_disposition" in CREATE_VIEW
    assert "advisory_label" in CREATE_VIEW


def test_fingerprints_are_whitespace_insensitive_but_content_sensitive() -> None:
    assert function_fingerprint(REJECT_MUTATION_BODY) == function_fingerprint(
        "  " + REJECT_MUTATION_BODY.replace("\n", "\n    ")
    )
    assert function_fingerprint(REJECT_MUTATION_BODY.replace("RAISE", "-- RAISE")) != (
        EXPECTED_FUNCTION_FINGERPRINTS["gryphon_reject_mutation"]
    )


def test_the_restated_mutation_body_matches_the_deployed_function() -> None:
    """Readiness compares bodies, so a restatement that drifted would prove nothing."""
    first = importlib.import_module("gryphon.db.migrations.versions.0001_initial_schema")
    body = str(first._TRIGGER_FUNCTION).split("$$")[1]
    assert function_fingerprint(body) == EXPECTED_FUNCTION_FINGERPRINTS["gryphon_reject_mutation"]


def test_a_partitioned_parents_key_contains_its_partition_column() -> None:
    """PostgreSQL cannot enforce a unique key on a partitioned table without it."""
    for table, column in PARTITION_KEY_BY_TABLE.items():
        for columns in EXPECTED_UNIQUE_COLUMNS[table]:
            assert column in columns, (table, columns)
        # The narrow form the contract states lives on each partition instead.
        assert column not in PARTITION_UNIQUE_COLUMNS[table]


# =============================================================================
# The gateway feature set and the posture
# =============================================================================


def _welcome(**overrides: Any) -> Welcome:
    payload: dict[str, Any] = {
        "protocol_version": "1",
        "feature_set": frozenset(REQUIRED_GATEWAY_FEATURES),
        "descriptor_versions": {"http.response.summary": "1"},
        "extractor_set_digest": "a" * 64,
        "sanitizer_ruleset_digest": "b" * 64,
        "binary_digests": {"observer": "c" * 64},
    }
    payload.update(overrides)
    return Welcome(**payload)


def test_a_complete_feature_set_is_satisfied() -> None:
    assert missing_gateway_features(REQUIRED_GATEWAY_FEATURES) == ()
    assert missing_gateway_features({*REQUIRED_GATEWAY_FEATURES, "extra_thing"}) == ()


def test_a_missing_feature_is_named() -> None:
    advertised = set(REQUIRED_GATEWAY_FEATURES) - {"epoch_fencing"}
    assert missing_gateway_features(advertised) == ("epoch_fencing",)


@pytest.mark.parametrize(
    ("welcome", "posture"),
    [
        (None, "UNENFORCED"),
        (_welcome(), "ENFORCED"),
        (_welcome(feature_set=frozenset({"epoch_fencing"})), "UNENFORCED"),
        (_welcome(extractor_set_digest=""), "UNENFORCED"),
        (_welcome(sanitizer_ruleset_digest="  "), "UNENFORCED"),
    ],
)
def test_the_posture_is_derived_from_observed_facts(
    welcome: Welcome | None, posture: str
) -> None:
    assert effective_posture(welcome) == posture


@dataclass(frozen=True)
class _Settings:
    egress_posture: str = "enforced"
    gateway_connect_timeout_seconds: float = 1.0


@dataclass(frozen=True)
class _Services:
    gateway_socket: Path
    settings: _Settings = _Settings()


async def test_a_missing_feature_fails_and_is_never_a_warning(tmp_path: Path) -> None:
    socket_path = tmp_path / "gatewayd.sock"
    socket_path.write_bytes(b"")
    welcome = _welcome(feature_set=frozenset(REQUIRED_GATEWAY_FEATURES) - {"sealed_observer"})

    async def handshake() -> Welcome:
        return welcome

    checks = await gateway_checks(
        _Services(gateway_socket=socket_path),  # type: ignore[arg-type]
        prod=False,
        handshake=handshake,
    )
    feature_check = _named(checks, "gateway_feature_set_complete")
    assert feature_check.passed is False
    assert feature_check.fatal is True
    assert "sealed_observer" in feature_check.detail
    posture = _named(checks, "egress_posture_observed")
    assert posture.passed is False
    assert "declares ENFORCED" in posture.detail


async def test_a_complete_handshake_passes_and_pins_the_digest(tmp_path: Path) -> None:
    socket_path = tmp_path / "gatewayd.sock"
    socket_path.write_bytes(b"")
    welcome = _welcome()

    async def handshake() -> Welcome:
        return welcome

    checks = await gateway_checks(
        _Services(gateway_socket=socket_path),  # type: ignore[arg-type]
        prod=True,
        handshake=handshake,
    )
    assert all(c.passed for c in checks), [c.detail for c in checks if not c.passed]
    assert welcome.digest[:16] in _named(checks, "gateway_feature_set_complete").detail


async def test_an_absent_socket_is_fatal_in_production_only(tmp_path: Path) -> None:
    services = _Services(gateway_socket=tmp_path / "missing.sock")
    for prod in (True, False):
        checks = await gateway_checks(services, prod=prod, handshake=None)  # type: ignore[arg-type]
        socket_check = _named(checks, "gateway_socket_present")
        assert socket_check.passed is False
        assert socket_check.fatal is prod
        # The feature set could not be established, which is a FAIL either way.
        assert _named(checks, "gateway_feature_set_complete").passed is False


# =============================================================================
# Judging the database facts
# =============================================================================


def _healthy_facts(**overrides: Any) -> DatabaseFacts:
    """Facts from a database that is exactly what the migration created."""
    relations: dict[str, str] = {t: "r" for t in VERIFICATION_TABLES}
    relations.update({t: "p" for t in PARTITIONED_TABLES})
    relations.update({t: "r" for t in UPSTREAM_READ_TABLES})
    relations[VIEW_NAME] = "v"
    relations["legacy_findings"] = "r"

    columns: dict[str, frozenset[str]] = {}
    for table, column in expected_column_updates():
        columns[table] = columns.get(table, frozenset()) | {column}

    months = month_sequence(TODAY, PARTITION_WARN_MONTHS)
    partitions: dict[str, frozenset[str]] = {
        table: frozenset(
            {default_partition(table), *(partition_name(table, y, m) for y, m in months)}
        )
        for table in PARTITIONED_TABLES
    }

    triggers: dict[tuple[str, str], str] = {
        (name, table): "O" for name, table in expected_triggers().items()
    }
    unique_indexes: dict[str, tuple[frozenset[str], ...]] = {
        table: tuple(keys) for table, keys in EXPECTED_UNIQUE_COLUMNS.items()
    }
    for parent, children in partitions.items():
        for child in children:
            # Row-level guards are cloned onto every partition; the statement
            # level guard and the narrow key are created with the partition.
            triggers[(f"trg_{parent}_no_mutation", child)] = "O"
            triggers[(partition_truncate_trigger(child), child)] = "O"
            unique_indexes[child] = (frozenset(PARTITION_UNIQUE_COLUMNS[parent]),)

    facts = DatabaseFacts(
        current_user=DATABASE_ROLE,
        session_user=DATABASE_ROLE,
        today=TODAY,
        revision=EXPECTED_ALEMBIC_REVISION,
        role_exists=True,
        relations=relations,
        owners={table: "gryphon_migrator" for table in relations},
        columns=columns,
        partitions=partitions,
        triggers=triggers,
        functions=dict(EXPECTED_FUNCTION_FINGERPRINTS),
        unique_indexes=unique_indexes,
        partial_unique_index_names=frozenset({OPEN_PASS_INDEX}),
        privileges={
            key: value
            for key, value in expected_table_privileges().items()
            if key[0] in relations
        },
        column_updates={
            key: value
            for key, value in expected_column_updates().items()
            if key[0] in relations
        },
        can_create_schema=False,
        role_flags={"rolsuper": False, "rolcreaterole": False, "rolbypassrls": False},
        memberships=(),
        privileged_roles=(),
        search_path="public",
        security_definers=(),
    )
    return replace(facts, **overrides)


def test_a_correctly_migrated_database_is_ready() -> None:
    checks = facts_checks(_healthy_facts(), prod=True)
    report = ReadinessReport(checks=tuple(checks), environment="prod")
    assert report.ready is True, [c.name for c in report.failures]
    assert report.as_payload()["ready"] is True


def test_the_payload_names_every_check() -> None:
    checks = tuple(facts_checks(_healthy_facts(), prod=False))
    report = ReadinessReport(checks=checks, environment="dev")
    payload = report.as_payload()
    assert {c["name"] for c in payload["checks"]} == {c.name for c in report.checks}
    fields = {"name", "passed", "fatal", "detail", "details"}
    assert all(fields <= set(c) for c in payload["checks"])


@pytest.mark.parametrize(
    ("name", "overrides"),
    [
        ("schema_revision_exact", {"revision": "0004"}),
        ("schema_revision_exact", {"revision": None}),
        ("open_pass_index_partial_unique", {"partial_unique_index_names": frozenset()}),
        ("custody_single_role", {"session_user": "postgres"}),
        ("custody_single_role", {"memberships": ("gryphon_runtime",)}),
        ("custody_single_role", {"privileged_roles": ("pg_write_all_data",)}),
        ("custody_search_path_restricted", {"search_path": '"$user", public'}),
        ("custody_no_security_definer", {"security_definers": ("public.escalate",)}),
        (
            "custody_not_owner_not_superuser",
            {"role_flags": {"rolsuper": True, "rolcreaterole": False}},
        ),
    ],
)
def test_a_broken_fact_fails_exactly_its_check(name: str, overrides: dict[str, Any]) -> None:
    checks = facts_checks(_healthy_facts(**overrides), prod=True)
    failed = _named(checks, name)
    assert failed.passed is False
    assert failed.fatal is True
    others = [c.name for c in checks if not c.passed and c.name != name]
    assert others == [], others


def test_the_role_owning_its_own_tables_is_a_custody_failure() -> None:
    facts = _healthy_facts()
    owners = dict(facts.owners)
    owners["finding_verification"] = DATABASE_ROLE
    check = _named(
        facts_checks(replace(facts, owners=owners), prod=True),
        "custody_not_owner_not_superuser",
    )
    assert check.passed is False
    assert "finding_verification" in check.detail


def test_a_disabled_trigger_on_a_partition_fails() -> None:
    facts = _healthy_facts()
    triggers = dict(facts.triggers)
    partition = sorted(facts.partitions["finding_verification"])[0]
    triggers[("trg_finding_verification_no_mutation", partition)] = "D"
    check = _named(
        facts_checks(replace(facts, triggers=triggers), prod=True),
        "append_only_triggers_enabled",
    )
    assert check.passed is False
    assert "disabled" in check.detail


def test_a_partition_without_its_truncate_guard_fails() -> None:
    facts = _healthy_facts()
    partition = sorted(facts.partitions["verification_observation"])[0]
    triggers = {
        key: value
        for key, value in facts.triggers.items()
        if key[0] != partition_truncate_trigger(partition)
    }
    check = _named(
        facts_checks(replace(facts, triggers=triggers), prod=True),
        "append_only_triggers_enabled",
    )
    assert check.passed is False
    assert partition in check.detail


def test_a_partition_without_the_narrow_unique_key_fails() -> None:
    facts = _healthy_facts()
    partition = partition_name("verification_observation", TODAY.year, TODAY.month)
    unique = {k: v for k, v in facts.unique_indexes.items() if k != partition}
    check = _named(
        facts_checks(replace(facts, unique_indexes=unique), prod=True),
        "partition_narrow_keys_present",
    )
    assert check.passed is False
    assert "execution_id" in check.detail


def test_a_replaced_trigger_function_is_caught() -> None:
    functions = dict(EXPECTED_FUNCTION_FINGERPRINTS)
    functions["gryphon_reject_mutation"] = "0" * 64
    check = _named(
        facts_checks(_healthy_facts(functions=functions), prod=True),
        "trigger_functions_unaltered",
    )
    assert check.passed is False
    assert "gryphon_reject_mutation" in check.detail


@pytest.mark.parametrize(
    "granted",
    [("raw_finding", "INSERT"), ("tool_execution", "INSERT"), ("enrichment_report", "UPDATE")],
)
def test_one_stray_upstream_grant_fails_the_matrix(granted: tuple[str, str]) -> None:
    facts = _healthy_facts()
    privileges = dict(facts.privileges)
    privileges[granted] = True
    check = _named(
        facts_checks(replace(facts, privileges=privileges), prod=True), "role_privileges_exact"
    )
    assert check.passed is False
    assert granted[0] in check.detail


def test_an_update_grant_on_a_pin_fails_the_matrix() -> None:
    facts = _healthy_facts()
    column_updates = dict(facts.column_updates)
    column_updates[("verification_pass_pin", "pins")] = True
    check = _named(
        facts_checks(replace(facts, column_updates=column_updates), prod=True),
        "role_privileges_exact",
    )
    assert check.passed is False
    assert "verification_pass_pin" in check.detail


def test_schema_create_on_the_working_schema_fails_the_matrix() -> None:
    check = _named(
        facts_checks(_healthy_facts(can_create_schema=True), prod=True), "role_privileges_exact"
    )
    assert check.passed is False
    assert "schema.CREATE=granted" in check.detail


def test_a_missing_unique_key_fails() -> None:
    facts = _healthy_facts()
    unique = dict(facts.unique_indexes)
    unique["verification_pass"] = tuple(
        columns for columns in unique["verification_pass"] if "request_key" not in columns
    )
    check = _named(
        facts_checks(replace(facts, unique_indexes=unique), prod=True), "unique_keys_present"
    )
    assert check.passed is False
    assert "request_key" in check.detail


def test_the_default_partition_keeps_writes_possible_but_warns() -> None:
    """A catch-all accepts the row; retention cannot tier it, so it is a warning."""
    facts = _healthy_facts()
    only_default = {
        table: frozenset({default_partition(table)}) for table in PARTITIONED_TABLES
    }
    kept = _partition_set(only_default)
    dropped = _partition_set(facts.partitions) - kept
    triggers = {
        key: value for key, value in facts.triggers.items() if key[1] not in dropped
    }
    unique = {
        table: keys for table, keys in facts.unique_indexes.items() if table not in dropped
    }
    checks = facts_checks(
        replace(facts, partitions=only_default, triggers=triggers, unique_indexes=unique),
        prod=True,
    )
    assert _named(checks, "partition_write_path_present").passed is True
    horizon = _named(checks, "partition_horizon")
    assert horizon.passed is False
    assert horizon.fatal is False
    assert ReadinessReport(checks=tuple(checks), environment="prod").ready is True


def test_no_partition_at_all_is_fatal() -> None:
    facts = _healthy_facts()
    checks = facts_checks(replace(facts, partitions={}), prod=True)
    missing = _named(checks, "partition_write_path_present")
    assert missing.passed is False
    assert missing.fatal is True
    assert "verification_observation" in missing.detail


def test_a_missing_matrix_column_is_a_schema_failure_not_a_privilege_one() -> None:
    facts = _healthy_facts()
    columns = dict(facts.columns)
    columns["verification_pass"] = columns["verification_pass"] - {"salt"}
    checks = facts_checks(replace(facts, columns=columns), prod=True)
    assert _named(checks, "expected_columns_present").passed is False
    assert _named(checks, "role_privileges_exact").passed is True


def test_the_retired_schema_is_reported_without_blocking_a_start() -> None:
    facts = _healthy_facts()
    relations = dict(facts.relations)
    relations["findings"] = "r"
    relations["exploit_chain"] = "r"
    checks = facts_checks(replace(facts, relations=relations), prod=True)
    check = _named(checks, "legacy_evidence_retired")
    assert check.passed is False
    assert check.fatal is False
    assert "findings" in check.detail
    assert ReadinessReport(checks=tuple(checks), environment="prod").ready is True


def test_a_missing_role_fails_the_matrix_outright() -> None:
    check = _named(
        facts_checks(
            _healthy_facts(role_exists=False, privileges={}, column_updates={}), prod=True
        ),
        "role_privileges_exact",
    )
    assert check.passed is False
    assert DATABASE_ROLE in check.detail
