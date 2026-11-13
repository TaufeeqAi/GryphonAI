"""The schema facts readiness checks are exactly the ones the migration creates."""

from __future__ import annotations

import pytest

from gryphon.db import models  # noqa: F401  (registers tables)
from gryphon.db.base import Base
from gryphon.enrichment.readiness import expected_triggers
from gryphon.enrichment.schema import (
    APPEND_ONLY_TABLES,
    ENRICHMENT_TABLES,
    EXPECTED_FUNCTION_FINGERPRINTS,
    LIFECYCLE_TABLES,
    PASS_UPDATABLE_COLUMNS,
    REJECT_MUTATION_BODY,
    SLOT_UPDATABLE_COLUMNS,
    UPSTREAM_READ_TABLES,
    expected_column_updates,
    expected_table_privileges,
    function_fingerprint,
    grant_statements,
    trigger_statements,
)

pytestmark = pytest.mark.security


def test_every_enrichment_table_is_mapped() -> None:
    for table in ENRICHMENT_TABLES:
        assert table in Base.metadata.tables, table


def test_no_upstream_table_is_writable() -> None:
    expected = expected_table_privileges()
    for table in UPSTREAM_READ_TABLES:
        assert expected[(table, "SELECT")] is True
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert expected[(table, privilege)] is False


def test_enrichment_tables_are_insert_only_except_lifecycle_columns() -> None:
    expected = expected_table_privileges()
    for table in ENRICHMENT_TABLES:
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            assert expected[(table, privilege)] is False
    assert expected[("enrichment_slot", "INSERT")] is False
    columns = expected_column_updates()
    assert all(columns[("enrichment_pass", c)] for c in PASS_UPDATABLE_COLUMNS)
    assert all(columns[("enrichment_slot", c)] for c in SLOT_UPDATABLE_COLUMNS)
    for immutable in ("scan_run_id", "initiated_by", "created_at"):
        assert columns[("enrichment_pass", immutable)] is False
        assert immutable not in PASS_UPDATABLE_COLUMNS


def test_updatable_pass_columns_exist() -> None:
    table = Base.metadata.tables["enrichment_pass"]
    assert set(PASS_UPDATABLE_COLUMNS) <= set(table.columns.keys())


def test_triggers_cover_every_table_one_statement_each() -> None:
    statements = trigger_statements()
    assert len(statements) == len(expected_triggers())
    assert all(s.count(";") == 1 for s in statements)
    for name in expected_triggers():
        assert any(name in s for s in statements)
    assert len(APPEND_ONLY_TABLES) + len(LIFECYCLE_TABLES) == len(ENRICHMENT_TABLES)


def test_grants_never_name_delete_or_truncate_for_the_role() -> None:
    for statement in grant_statements():
        if "TO gryphon_enrichment" in statement:
            assert "DELETE" not in statement and "TRUNCATE" not in statement


def test_fingerprints_are_whitespace_insensitive_but_content_sensitive() -> None:
    assert function_fingerprint(REJECT_MUTATION_BODY) == function_fingerprint(
        "  " + REJECT_MUTATION_BODY.replace("\n", "\n    ")
    )
    assert function_fingerprint(REJECT_MUTATION_BODY.replace("RAISE", "-- RAISE")) != (
        EXPECTED_FUNCTION_FINGERPRINTS["gryphon_reject_mutation"]
    )


def test_upstream_mutation_function_matches_the_first_migration() -> None:
    """The enrichment triggers reuse the upstream function: its body must be the same."""
    import importlib

    first = importlib.import_module("gryphon.db.migrations.versions.0001_initial_schema")
    source: str = first._TRIGGER_FUNCTION
    body = source.split("$$")[1]
    assert function_fingerprint(body) == EXPECTED_FUNCTION_FINGERPRINTS["gryphon_reject_mutation"]
