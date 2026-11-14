"""The verification schema against a live PostgreSQL — migration, guards, view.

Nothing here goes through the engine or the repository: these tests assert what
the *database* enforces, because that is the layer that still holds when a
caller reaches it with raw SQL. Each one names the failure it prevents:

* a verdict or an observation that could be edited after publication;
* a pin manifest that could move, making published work unexplainable;
* two concurrent passes both believing they own one scan;
* a later INCONCLUSIVE quietly replacing an earlier CONFIRMED in the read view;
* the pass salt — which keys observation identities and control locators —
  leaking through a view.

WARNING: like every database-gated suite here, this resets the schema of
``GRYPHON_TEST_DATABASE_URL`` (downgrade base → upgrade head).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from gryphon.db.models import (
    FindingVerification,
    RawFinding,
    ScanRun,
    VerificationObservation,
    VerificationPass,
    VerificationPassPin,
    VerificationRetraction,
)

_OWNER_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_OWNER_URL is None, reason="GRYPHON_TEST_DATABASE_URL not set"),
]

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)
CALLER = "cli:uid:1000"
DIGEST = "0" * 64

_PARTITIONS_OF = sa.text(
    "SELECT c.relname FROM pg_inherits i "
    "JOIN pg_class c ON c.oid = i.inhrelid "
    "JOIN pg_class p ON p.oid = i.inhparent "
    "WHERE p.relname = :parent ORDER BY 1"
)
#: ``relkind`` is PostgreSQL's single-byte "char"; cast so the driver hands back
#: text rather than bytes. 'p' is a partitioned table, 'r' a plain one, 'v' a view.
_RELKIND = sa.text(
    "SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'public' AND c.relname = :name"
)
_TRIGGERS_ON = sa.text(
    "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal "
    "AND tgrelid = CAST(:name AS regclass) ORDER BY 1"
)
_VIEW_COLUMNS_NAMED = sa.text(
    "SELECT c.table_name FROM information_schema.columns c "
    "JOIN information_schema.views v ON v.table_name = c.table_name "
    "WHERE c.column_name = :column"
)


def _alembic() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", "gryphon/db/migrations")
    return cfg


@pytest.fixture(scope="module")
def _migrated() -> None:
    os.environ["GRYPHON_MIGRATION_DATABASE_URL"] = _OWNER_URL  # type: ignore[assignment]
    os.environ["GRYPHON_DATABASE_URL"] = _OWNER_URL  # type: ignore[assignment]
    from gryphon.settings import get_settings

    get_settings.cache_clear()
    cfg = _alembic()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@pytest.fixture
async def engine(_migrated: None) -> AsyncIterator[AsyncEngine]:
    created = create_async_engine(_OWNER_URL, poolclass=NullPool)  # type: ignore[arg-type]
    try:
        yield created
    finally:
        await created.dispose()


async def _seed_scan(conn: AsyncConnection) -> tuple[str, str]:
    """One admitted scan and one piece of evidence for a verdict to attach to."""
    scan_run_id = str(uuid.uuid4())
    finding_id = hashlib.sha256(scan_run_id.encode()).hexdigest()[:48]
    await conn.execute(
        sa.insert(ScanRun).values(
            scan_run_id=scan_run_id,
            decision="ALLOW",
            status="ADMITTED",
            idempotency_key_hash=secrets.token_hex(32),
            request_hash=secrets.token_hex(32),
            decided_at=NOW,
        )
    )
    await conn.execute(
        sa.insert(RawFinding).values(
            finding_id=finding_id,
            scan_run_id=scan_run_id,
            execution_id=f"exec-{finding_id[:8]}",
            plan_item_id="plan-1",
            stage="vulnerability",
            step="nuclei",
            tool_id="nuclei",
            finding_key=finding_id[:32],
            canonical_target="app.example.com",
            observation_type="exposed-dotenv",
            observation={},
        )
    )
    return scan_run_id, finding_id


async def _open_pass(
    conn: AsyncConnection,
    *,
    scan_run_id: str,
    state: str = "RUNNING",
    request_key: str | None = None,
) -> str:
    pass_id = uuid.uuid4().hex
    await conn.execute(
        sa.insert(VerificationPass).values(
            pass_id=pass_id,
            scan_run_id=scan_run_id,
            request_key=request_key,
            state=state,
            salt=secrets.token_bytes(32),
            initiated_by=CALLER,
        )
    )
    return pass_id


async def _verdict(
    conn: AsyncConnection,
    *,
    pass_id: str,
    scan_run_id: str,
    finding_id: str,
    subject_key: str,
    status: str,
    justification: str | None,
    observed_at: datetime,
) -> None:
    await conn.execute(
        sa.insert(FindingVerification).values(
            pass_id=pass_id,
            finding_id=finding_id,
            observed_at=observed_at,
            scan_run_id=scan_run_id,
            subject_key=subject_key,
            status=status,
            justification=justification,
            verifier_id="exposed-dotenv@1.0.0",
            registry_digest=DIGEST,
            rule=4,
            matched_predicates=["dotenv_grammar"],
            projection={"status_class": 2},
            projection_digest=DIGEST,
            asserted_by="deterministic_verifier",
        )
    )


async def _observation(
    conn: AsyncConnection, *, pass_id: str, scan_run_id: str, finding_id: str
) -> str:
    execution_id = secrets.token_hex(32)
    await conn.execute(
        sa.insert(VerificationObservation).values(
            observation_id=secrets.token_hex(32),
            pass_id=pass_id,
            scan_run_id=scan_run_id,
            finding_id=finding_id,
            verifier_id="exposed-dotenv@1.0.0",
            role="primary",
            control_index=0,
            execution_id=execution_id,
            envelope_digest=DIGEST,
            outcome_class="OBSERVED",
            reason_code="ok",
            completeness={"transport_complete": True, "body_complete": True},
            facts_digest=DIGEST,
        )
    )
    return execution_id


# -- the schema barrier ---------------------------------------------------------


async def test_migration_creates_and_removes_every_object(engine: AsyncEngine) -> None:
    """Down to the previous revision and back leaves the schema as it was.

    A migration that cannot be reversed cannot be rehearsed, and the objects
    this one adds are not only tables: partitions, triggers, a view and a role's
    privileges each have to come and go with it.
    """
    cfg = _alembic()
    async with engine.begin() as conn:
        assert (await conn.execute(_RELKIND, {"name": "finding_verification"})).scalar() == "p"
        partitions = (
            (await conn.execute(_PARTITIONS_OF, {"parent": "verification_observation"}))
            .scalars()
            .all()
        )
        assert "verification_observation_default" in partitions
        assert len(partitions) >= 2, partitions
        # Row guards are cloned onto every partition; the TRUNCATE guard is not
        # cloned by PostgreSQL, so the migration creates one per partition.
        for partition in partitions:
            names = (await conn.execute(_TRIGGERS_ON, {"name": partition})).scalars().all()
            assert "trg_verification_observation_no_mutation" in names
            assert f"trg_{partition}_no_truncate" in names
        # The privileges that must be ABSENT are part of the matrix: pins and
        # the manifest are write-once, and the salt is never updatable.
        absent = await conn.execute(
            sa.text(
                "SELECT has_table_privilege('gryphon_verification', "
                "       'verification_pass_pin', 'UPDATE') AS pin_update, "
                "       has_table_privilege('gryphon_verification', "
                "       'finding_verification', 'DELETE') AS verdict_delete, "
                "       has_column_privilege('gryphon_verification', "
                "       'verification_pass', 'salt', 'UPDATE') AS salt_update, "
                "       has_column_privilege('gryphon_verification', "
                "       'verification_pass', 'state', 'UPDATE') AS state_update"
            )
        )
        row = absent.one()
        assert row.pin_update is False
        assert row.verdict_delete is False
        assert row.salt_update is False
        assert row.state_update is True

    # Alembic's env runs the migration with asyncio.run(), which cannot nest
    # inside this test's loop; a worker thread gives it a loop of its own.
    await asyncio.to_thread(command.downgrade, cfg, "0004")
    async with engine.begin() as conn:
        for name in ("verification_pass", "finding_verification", "finding_verification_view"):
            assert (await conn.execute(_RELKIND, {"name": name})).scalar() is None
        # The enrichment layer's view and guard function survive untouched.
        assert (await conn.execute(_RELKIND, {"name": "finding_enrichment_view"})).scalar() == "v"

    await asyncio.to_thread(command.upgrade, cfg, "head")
    async with engine.begin() as conn:
        assert (await conn.execute(_RELKIND, {"name": "finding_verification_view"})).scalar() == "v"
        assert (await conn.execute(_RELKIND, {"name": "verification_observation"})).scalar() == "p"


# -- append-only ----------------------------------------------------------------


async def test_append_only_tables_reject_update_and_delete(engine: AsyncEngine) -> None:
    """A published verdict or observation can never be edited into another one."""
    async with engine.begin() as conn:
        scan_run_id, finding_id = await _seed_scan(conn)
        pass_id = await _open_pass(conn, scan_run_id=scan_run_id)
        await _verdict(
            conn,
            pass_id=pass_id,
            scan_run_id=scan_run_id,
            finding_id=finding_id,
            subject_key="s" * 64,
            status="CONFIRMED",
            justification=None,
            observed_at=NOW,
        )
        await _observation(conn, pass_id=pass_id, scan_run_id=scan_run_id, finding_id=finding_id)

    for statement in (
        "UPDATE finding_verification SET status = 'REFUTED'",
        "DELETE FROM finding_verification",
        "UPDATE verification_observation SET outcome_class = 'OBSERVED'",
        "DELETE FROM verification_observation",
        "DELETE FROM verification_pass",
    ):
        with pytest.raises(DBAPIError):
            async with engine.begin() as conn:
                await conn.execute(sa.text(statement))

    # The lifecycle row still moves: that is the one table with an UPDATE path.
    async with engine.begin() as conn:
        await conn.execute(
            sa.update(VerificationPass)
            .where(VerificationPass.pass_id == pass_id)
            .values(state="COMPLETE", outcome="VERIFIED", completed_at=sa.func.now())
        )
        state = await conn.execute(
            sa.select(VerificationPass.state).where(VerificationPass.pass_id == pass_id)
        )
        assert state.scalar() == "COMPLETE"


async def test_truncate_is_refused_including_a_single_partition(engine: AsyncEngine) -> None:
    """Emptying a table is not an edit the guard misses — nor is emptying a month."""
    async with engine.begin() as conn:
        partitions = (
            (await conn.execute(_PARTITIONS_OF, {"parent": "finding_verification"}))
            .scalars()
            .all()
        )
    assert partitions
    for statement in (
        "TRUNCATE finding_verification",
        "TRUNCATE verification_pass_pin",
        "TRUNCATE verification_audit",
        f"TRUNCATE {partitions[0]}",
    ):
        with pytest.raises(DBAPIError):
            async with engine.begin() as conn:
                await conn.execute(sa.text(statement))


# -- write-once pins ------------------------------------------------------------


async def test_pins_are_written_once(engine: AsyncEngine) -> None:
    """The provenance root of a pass cannot move after the first write."""
    values = {
        "pins": {"registry": DIGEST},
        "manifest": {"findings": 1},
        "registry_digest": DIGEST,
        "extractor_set_digest": DIGEST,
        "estate_digest": DIGEST,
        "resolver_set_digest": DIGEST,
        "feature_set_digest": DIGEST,
        "base_report_id": "rpt-1",
        "base_report_digest": DIGEST,
    }
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan(conn)
        pass_id = await _open_pass(conn, scan_run_id=scan_run_id)
        await conn.execute(sa.insert(VerificationPassPin).values(pass_id=pass_id, **values))

    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                sa.insert(VerificationPassPin).values(
                    pass_id=pass_id, **{**values, "manifest": {"findings": 99}}
                )
            )

    with pytest.raises(DBAPIError):
        async with engine.begin() as conn:
            await conn.execute(
                sa.text("UPDATE verification_pass_pin SET estate_digest = 'moved'")
            )


# -- one open pass per scan -----------------------------------------------------


async def test_only_one_open_pass_per_scan(engine: AsyncEngine) -> None:
    """Two processes cannot both believe they own one scan's verification."""
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan(conn)
        first = await _open_pass(conn, scan_run_id=scan_run_id, state="PLANNED")

    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await _open_pass(conn, scan_run_id=scan_run_id, state="RUNNING")

    # A BLOCKED pass still owns the scan: waiting for a dependency is not
    # finishing, and a second pass would re-contact the same hosts.
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await _open_pass(conn, scan_run_id=scan_run_id, state="BLOCKED")

    async with engine.begin() as conn:
        await conn.execute(
            sa.update(VerificationPass)
            .where(VerificationPass.pass_id == first)
            .values(state="COMPLETE", completed_at=sa.func.now())
        )
        second = await _open_pass(conn, scan_run_id=scan_run_id, state="RUNNING")
        assert second != first


async def test_one_request_key_maps_to_one_pass(engine: AsyncEngine) -> None:
    """A repeated command after a lost response must not start a second pass."""
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan(conn)
        await _open_pass(conn, scan_run_id=scan_run_id, state="COMPLETE", request_key="key-1")

    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await _open_pass(conn, scan_run_id=scan_run_id, state="COMPLETE", request_key="key-1")


# -- the read view --------------------------------------------------------------


async def test_view_prefers_a_determinate_verdict_over_a_later_inconclusive(
    engine: AsyncEngine,
) -> None:
    """A later "we could not tell" must never hide an earlier proof.

    Both verdicts stay; the primary columns carry the determinate one, the last
    attempt occupies its own columns, and a retraction surfaces as RETRACTED
    rather than removing anything.
    """
    subject_key = secrets.token_hex(32)
    async with engine.begin() as conn:
        scan_run_id, finding_id = await _seed_scan(conn)
        confirmed_pass = await _open_pass(conn, scan_run_id=scan_run_id, state="COMPLETE")
        await _verdict(
            conn,
            pass_id=confirmed_pass,
            scan_run_id=scan_run_id,
            finding_id=finding_id,
            subject_key=subject_key,
            status="CONFIRMED",
            justification=None,
            observed_at=NOW,
        )
        later_pass = await _open_pass(conn, scan_run_id=scan_run_id, state="COMPLETE")
        await _verdict(
            conn,
            pass_id=later_pass,
            scan_run_id=scan_run_id,
            finding_id=finding_id,
            subject_key=subject_key,
            status="INCONCLUSIVE",
            justification="rate_limited",
            observed_at=NOW + timedelta(days=1),
        )

    async with engine.connect() as conn:
        row = (
            await conn.execute(
                sa.text(
                    "SELECT * FROM finding_verification_view "
                    "WHERE scan_run_id = :scan AND subject_key = :subject"
                ),
                {"scan": scan_run_id, "subject": subject_key},
            )
        ).one()
    assert row.status == "CONFIRMED"
    assert row.verdict_status == "CONFIRMED"
    assert row.justification is None
    assert row.pass_id == confirmed_pass
    assert row.determinate is True
    assert row.retracted is False
    assert row.revision == 2
    assert row.last_attempt_status == "INCONCLUSIVE"
    assert row.last_attempt_justification == "rate_limited"
    assert row.last_attempt_pass_id == later_pass
    assert row.as_of < row.last_attempt_at

    # Withdrawing the verifier retracts the proof; it does not edit it.
    async with engine.begin() as conn:
        await conn.execute(
            sa.insert(VerificationRetraction).values(
                verifier_id="exposed-dotenv@1.0.0",
                pass_id=confirmed_pass,
                finding_id=finding_id,
                reason="predicate unsound on compressed bodies",
                approved_by="reviewer@example.com",
            )
        )
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                sa.text(
                    "SELECT status, verdict_status, retracted FROM finding_verification_view "
                    "WHERE scan_run_id = :scan AND subject_key = :subject"
                ),
                {"scan": scan_run_id, "subject": subject_key},
            )
        ).one()
    assert row.status == "RETRACTED"
    assert row.verdict_status == "CONFIRMED"
    assert row.retracted is True


async def test_no_view_exposes_a_pass_salt(engine: AsyncEngine) -> None:
    """The salt keys observation identities; a target that knew it could cheat.

    Asserted across every view in the schema rather than only the verification
    one, because the rule is that it leaves the pass row for nothing.
    """
    async with engine.connect() as conn:
        leaking = (await conn.execute(_VIEW_COLUMNS_NAMED, {"column": "salt"})).scalars().all()
        assert leaking == []
        columns = (
            await conn.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'finding_verification_view'"
                )
            )
        ).scalars().all()
    assert "subject_key" in columns
    assert "salt" not in columns
