"""Readiness against a real database, where its facts actually come from.

The unit suite feeds :mod:`gryphon.verification.readiness` hand-built facts and
checks the reasoning over them. That is the right shape for the reasoning, and
it cannot see the bug these tests exist for.

PostgreSQL's ``relkind`` and ``tgenabled`` are the single-byte ``"char"`` type,
which asyncpg returns as **bytes**. Compared against ``str`` they are silently
unequal — ``b'D' == "D"`` is just ``False``. So the probe reported a correctly
built schema as the wrong relation kind, and, far worse, its append-only
trigger check could never observe a *disabled* trigger: the branch that would
have reported one was unreachable, and the check passed on a database whose
guarantees had been switched off.

Nothing about that is visible without a live connection, which is why it lived
through a green suite. These tests hold the types at the boundary and prove the
disabled case is now detected.

Skipped without ``GRYPHON_TEST_DATABASE_URL``. That database is reset.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from gryphon.verification.readiness import gather_database_facts, schema_barrier_checks

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_TEST_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark.append(
    pytest.mark.skipif(not _TEST_URL, reason="GRYPHON_TEST_DATABASE_URL not set")
)

#: One append-only trigger, on a table that is not partitioned, so the test can
#: switch it off and back on without touching a partition hierarchy.
_TABLE = "verification_report"
_TRIGGER = "trg_verification_report_no_mutation"


@pytest.fixture(scope="module")
def _migrated() -> None:
    os.environ["GRYPHON_MIGRATION_DATABASE_URL"] = _TEST_URL  # type: ignore[assignment]
    os.environ["GRYPHON_DATABASE_URL"] = _TEST_URL  # type: ignore[assignment]
    from gryphon.settings import get_settings

    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", "gryphon/db/migrations")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@pytest.fixture
async def engine(_migrated: None) -> AsyncIterator[AsyncEngine]:
    created = create_async_engine(_TEST_URL, poolclass=NullPool)  # type: ignore[arg-type]
    try:
        yield created
    finally:
        await created.dispose()


async def _facts(engine: AsyncEngine):
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        return await gather_database_facts(session)


def _check(checks, name):
    return next(c for c in checks if c.name == name)


async def test_relation_kinds_arrive_as_text_not_bytes(engine: AsyncEngine) -> None:
    """The boundary, held directly.

    ``b'p'`` is not ``'p'``, and every comparison downstream is written against
    the string.
    """
    facts = await _facts(engine)

    assert facts.relations, "no relations were read at all"
    for name, kind in facts.relations.items():
        assert isinstance(kind, str), f"{name} relkind is {type(kind).__name__}, not str"
        assert kind in {"r", "v", "p"}, f"{name} has unexpected relkind {kind!r}"


async def test_trigger_states_arrive_as_text_not_bytes(engine: AsyncEngine) -> None:
    facts = await _facts(engine)

    assert facts.triggers, "no triggers were read at all"
    for key, state in facts.triggers.items():
        assert isinstance(state, str), f"{key} tgenabled is {type(state).__name__}, not str"


async def test_the_partitioned_parents_are_recognized_as_partitioned(
    engine: AsyncEngine,
) -> None:
    """What the bytes comparison got wrong first: a correct schema read as broken."""
    facts = await _facts(engine)
    check = _check(schema_barrier_checks(facts), "schema_present")

    assert check.passed, check.detail
    assert facts.relations["verification_observation"] == "p"
    assert facts.relations["finding_verification"] == "p"


async def test_a_disabled_append_only_trigger_is_detected(engine: AsyncEngine) -> None:
    """The one that matters.

    Before the cast, this branch was unreachable: the probe compared bytes to a
    string, so it certified a database whose append-only guarantee was off.
    """
    from gryphon.verification.readiness import _trigger_checks

    async with engine.begin() as conn:
        await conn.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE TRIGGER {_TRIGGER}"))
    try:
        facts = await _facts(engine)
        check = _check(_trigger_checks(facts), "append_only_triggers_enabled")

        assert not check.passed, "a disabled append-only trigger must not read as enabled"
        assert _TRIGGER in check.detail
        assert "disabled" in check.detail
    finally:
        async with engine.begin() as conn:
            await conn.execute(sa.text(f"ALTER TABLE {_TABLE} ENABLE TRIGGER {_TRIGGER}"))

    restored = _check(_trigger_checks(await _facts(engine)), "append_only_triggers_enabled")
    assert restored.passed, restored.detail
