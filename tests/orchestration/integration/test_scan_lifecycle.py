"""Lease, fencing, idempotency and recovery against PostgreSQL.

These cover the failure modes that only appear with a real database and a real
clock: a crashed owner, a zombie that wakes up after being replaced, two callers
racing for the same scan, and a re-invocation that must not scan anything twice.

Gated on a database URL and skipped without one. A fake runner stands in for the
tool binaries; no target traffic occurs.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.claims import IssuanceRequest
from gryphon.auth.scope import ScopeEntry
from gryphon.auth.service import ScanAdmissionRequest
from gryphon.bootstrap import build_services
from gryphon.clock import SystemClock
from gryphon.constants import ScanDepth, TargetType
from gryphon.orchestration.constants import (
    ClaimResult,
    PlanItemState,
    ScanLifecycleState,
)
from gryphon.orchestration.identity import new_execution_salt
from gryphon.orchestration.ledger import (
    PlanRepository,
    RawFindingRepository,
    ScanLifecycleRepository,
)
from gryphon.orchestration.reasons import StaleClaimError
from gryphon.settings import Settings

_OWNER_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_OWNER_URL is None, reason="GRYPHON_TEST_DATABASE_URL not set"),
]


def _hex(k: ed25519.Ed25519PrivateKey) -> tuple[str, str]:
    return (
        k.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex(),
        k.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        .hex(),
    )


@pytest.fixture(scope="module")
def keyset() -> dict:
    grant_priv, grant_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    audit_priv, audit_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    return {
        "grant_priv": grant_priv,
        "grant_pub": grant_pub,
        "audit_priv": audit_priv,
        "audit_pub": audit_pub,
    }


@pytest.fixture(scope="module")
def _migrated(keyset) -> None:
    from alembic import command
    from alembic.config import Config

    os.environ["GRYPHON_MIGRATION_DATABASE_URL"] = _OWNER_URL  # type: ignore[arg-type]
    os.environ["GRYPHON_DATABASE_URL"] = _OWNER_URL  # type: ignore[arg-type]
    from gryphon.settings import get_settings

    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", "gryphon/db/migrations")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


def _settings(keyset) -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        issuer="gryphon-test-issuer",
        audience="gryphon-test-audience",
        grant_signing_key_hex=keyset["grant_priv"],
        grant_kid="grant-test",
        grant_trusted_public_keys={"grant-test": keyset["grant_pub"]},
        audit_signing_key_hex=keyset["audit_priv"],
        audit_kid="audit-test",
        audit_trusted_public_keys={"audit-test": keyset["audit_pub"]},
        database_url=_OWNER_URL,
        migration_database_url=_OWNER_URL,
    )


@pytest.fixture
async def admitted(keyset, _migrated):
    """Admit a scan through the real authorization core and yield its services."""
    services = build_services(_settings(keyset), clock=SystemClock())
    now = services.clock.now()
    issued = await services.issuer.issue_grant(
        IssuanceRequest(
            organization="GRYPHON Orchestration Tests",
            granted_by="operator@example.com",
            granted_to="tester@example.com",
            scope=(ScopeEntry(target_type=TargetType.DOMAIN, target="app.example.com"),),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(hours=2),
            max_scan_depth=ScanDepth.STANDARD,
            written_authorization_ref="SOW-orchestration-tests",
        ),
        idempotency_key=secrets.token_hex(16),
    )
    result = await services.authorization_service.authorize_scan(
        ScanAdmissionRequest(
            target="app.example.com",
            token=issued.token,
            requested_depth="standard",
            idempotency_key=secrets.token_hex(16),
        )
    )
    yield services, result.scan_run_id
    await services.database.dispose()


async def _claim(services, scan_run_id: str, owner: str, lease: float = 60.0):
    async with services.database.session() as session:
        async with session.begin():
            return await ScanLifecycleRepository(session).claim_start(
                scan_run_id=scan_run_id,
                owner_id=owner,
                lease_seconds=lease,
                initiated_by="test",
                execution_salt=new_execution_salt(),
                policy_version="1",
                graph_version="1",
                deadline_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )


# -- the claim ----------------------------------------------------------------
@pytest.mark.asyncio
async def test_first_claim_wins(admitted) -> None:
    services, scan_run_id = admitted
    outcome = await _claim(services, scan_run_id, "owner-a")
    assert outcome.result is ClaimResult.CLAIMED
    assert outcome.claim_epoch == 1
    assert outcome.owns


@pytest.mark.asyncio
async def test_second_caller_is_refused_while_the_lease_is_live(admitted) -> None:
    """Exactly one owner executes. The loser does not run the scan."""
    services, scan_run_id = admitted
    first = await _claim(services, scan_run_id, "owner-a")
    second = await _claim(services, scan_run_id, "owner-b")
    assert first.owns
    assert second.result is ClaimResult.ALREADY_RUNNING
    assert not second.owns


@pytest.mark.asyncio
async def test_concurrent_claims_produce_exactly_one_owner(admitted) -> None:
    """The race a duplicate invocation creates."""
    services, scan_run_id = admitted
    results = await asyncio.gather(
        *(_claim(services, scan_run_id, f"owner-{i}") for i in range(6))
    )
    assert sum(1 for r in results if r.owns) == 1


@pytest.mark.asyncio
async def test_expired_lease_is_takeable_and_bumps_the_epoch(admitted) -> None:
    """A crashed owner must not wedge the scan forever.

    Without takeover, a single crash leaves the row RUNNING, every resume is
    refused, and the client's authorization is consumed with no supported way
    to recover it.
    """
    services, scan_run_id = admitted
    first = await _claim(services, scan_run_id, "owner-a", lease=0.5)
    await asyncio.sleep(1.0)
    second = await _claim(services, scan_run_id, "owner-b")
    assert first.claim_epoch == 1
    assert second.result is ClaimResult.TAKEOVER
    assert second.claim_epoch == 2


@pytest.mark.asyncio
async def test_concurrent_takeovers_produce_exactly_one_winner(admitted) -> None:
    services, scan_run_id = admitted
    await _claim(services, scan_run_id, "owner-a", lease=0.5)
    await asyncio.sleep(1.0)
    results = await asyncio.gather(
        *(_claim(services, scan_run_id, f"taker-{i}") for i in range(5))
    )
    assert sum(1 for r in results if r.result is ClaimResult.TAKEOVER) == 1


@pytest.mark.asyncio
async def test_terminal_scan_is_not_reclaimed(admitted) -> None:
    """Terminal is terminal: a finished scan is never restarted."""
    services, scan_run_id = admitted
    claim = await _claim(services, scan_run_id, "owner-a")
    async with services.database.session() as session:
        async with session.begin():
            await ScanLifecycleRepository(session).transition(
                scan_run_id=scan_run_id,
                claim_epoch=claim.claim_epoch,
                state=ScanLifecycleState.COMPLETED,
                reason_code="OK",
            )
    again = await _claim(services, scan_run_id, "owner-b")
    assert again.result is ClaimResult.ALREADY_TERMINAL
    assert not again.owns


# -- fencing ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_superseded_owner_cannot_transition_the_scan(admitted) -> None:
    """The zombie case: a presumed-dead owner wakes up and tries to finish.

    A lease infers death from silence, so a long pause or a stopped container
    looks identical to a crash. The fencing epoch is what makes the stale
    owner's writes impossible rather than merely unlikely.
    """
    services, scan_run_id = admitted
    stale = await _claim(services, scan_run_id, "owner-a", lease=0.5)
    await asyncio.sleep(1.0)
    fresh = await _claim(services, scan_run_id, "owner-b")
    assert fresh.claim_epoch > stale.claim_epoch

    with pytest.raises(StaleClaimError):
        async with services.database.session() as session:
            async with session.begin():
                await ScanLifecycleRepository(session).transition(
                    scan_run_id=scan_run_id,
                    claim_epoch=stale.claim_epoch,
                    state=ScanLifecycleState.COMPLETED,
                    reason_code="OK",
                )

    async with services.database.session() as session:
        row = await ScanLifecycleRepository(session).get(scan_run_id)
    assert row.state == ScanLifecycleState.RUNNING.value


@pytest.mark.asyncio
async def test_superseded_owner_loses_its_heartbeat(admitted) -> None:
    """A stale heartbeat must not keep an abandoned scan looking alive."""
    services, scan_run_id = admitted
    stale = await _claim(services, scan_run_id, "owner-a", lease=0.5)
    await asyncio.sleep(1.0)
    await _claim(services, scan_run_id, "owner-b")

    async with services.database.session() as session:
        async with session.begin():
            alive = await ScanLifecycleRepository(session).heartbeat(
                scan_run_id=scan_run_id,
                claim_epoch=stale.claim_epoch,
                lease_seconds=60.0,
            )
    assert alive is False


@pytest.mark.asyncio
async def test_live_owner_renews_its_lease(admitted) -> None:
    services, scan_run_id = admitted
    claim = await _claim(services, scan_run_id, "owner-a", lease=5.0)
    async with services.database.session() as session:
        async with session.begin():
            alive = await ScanLifecycleRepository(session).heartbeat(
                scan_run_id=scan_run_id,
                claim_epoch=claim.claim_epoch,
                lease_seconds=60.0,
            )
    assert alive is True


# -- progress is monotonic ----------------------------------------------------
@pytest.mark.asyncio
async def test_phase_reached_never_moves_backwards(admitted) -> None:
    """Monotonic progress is what lets a resume be checked against reality."""
    services, scan_run_id = admitted
    claim = await _claim(services, scan_run_id, "owner-a")
    repo_args = {"scan_run_id": scan_run_id, "claim_epoch": claim.claim_epoch}

    async with services.database.session() as session:
        async with session.begin():
            await ScanLifecycleRepository(session).advance_phase(
                **repo_args, phase_reached=4
            )
    async with services.database.session() as session:
        async with session.begin():
            await ScanLifecycleRepository(session).advance_phase(
                **repo_args, phase_reached=2
            )
    async with services.database.session() as session:
        row = await ScanLifecycleRepository(session).get(scan_run_id)
    assert row.phase_reached == 4


# -- recovery discovery -------------------------------------------------------
@pytest.mark.asyncio
async def test_abandoned_scan_is_discoverable(admitted) -> None:
    """The sweeper needs to find abandoned work without being told about it."""
    services, scan_run_id = admitted
    await _claim(services, scan_run_id, "owner-a", lease=0.5)
    await asyncio.sleep(1.0)
    async with services.database.session() as session:
        reclaimable = await ScanLifecycleRepository(session).find_reclaimable()
    assert scan_run_id in [r.scan_run_id for r in reclaimable]


@pytest.mark.asyncio
async def test_live_scan_is_not_reported_as_abandoned(admitted) -> None:
    services, scan_run_id = admitted
    await _claim(services, scan_run_id, "owner-a", lease=120.0)
    async with services.database.session() as session:
        reclaimable = await ScanLifecycleRepository(session).find_reclaimable()
    assert scan_run_id not in [r.scan_run_id for r in reclaimable]


@pytest.mark.asyncio
async def test_overdue_scan_is_discoverable(admitted) -> None:
    """The backstop that stops work outliving its authorization."""
    services, scan_run_id = admitted
    async with services.database.session() as session:
        async with session.begin():
            await ScanLifecycleRepository(session).claim_start(
                scan_run_id=scan_run_id,
                owner_id="owner-a",
                lease_seconds=120.0,
                initiated_by="test",
                execution_salt=new_execution_salt(),
                policy_version="1",
                graph_version="1",
                deadline_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
    async with services.database.session() as session:
        overdue = await ScanLifecycleRepository(session).find_overdue()
    assert scan_run_id in [r.scan_run_id for r in overdue]


# -- the plan ledger ----------------------------------------------------------
@pytest.mark.asyncio
async def test_committed_plan_is_a_work_queue(admitted) -> None:
    services, scan_run_id = admitted
    claim = await _claim(services, scan_run_id, "owner-a")
    items = [
        {
            "plan_item_id": f"item-{i}",
            "plan_id": "plan-1",
            "scan_run_id": scan_run_id,
            "stage": "recon",
            "step": "subdomain_discovery",
            "seq": i,
            "tool_id": "subfinder",
            "execution_id": secrets.token_hex(32),
            "request_digest": secrets.token_hex(32),
            "attempt_epoch": 0,
            "attempts": 0,
            "canonical_target": f"h{i}.example.com",
            "target_path": None,
            "effective_depth": "standard",
            "provenance": {"source": "test"},
            "state": PlanItemState.PLANNED.value,
            "claim_epoch": 0,
        }
        for i in range(3)
    ]
    async with services.database.session() as session:
        async with session.begin():
            await PlanRepository(session).commit_plan(
                plan_id="plan-1",
                scan_run_id=scan_run_id,
                stage="recon",
                step="subdomain_discovery",
                tool_id="subfinder",
                plan_generation=1,
                plan_digest=secrets.token_hex(32),
                policy_version="1",
                ledger_schema_version="1",
                min_coverage_to_proceed=0.0,
                claim_epoch=claim.claim_epoch,
                items=items,
            )

    async with services.database.session() as session:
        async with session.begin():
            claimed = await PlanRepository(session).claim_items(
                scan_run_id=scan_run_id,
                stage="recon",
                step="subdomain_discovery",
                limit=2,
            )
            assert len(claimed) == 2
            for row in claimed:
                assert await PlanRepository(session).mark_dispatched(
                    plan_item_id=row.plan_item_id, claim_epoch=claim.claim_epoch
                )

    # A dispatched item is no longer in the queue, so no second worker takes it.
    async with services.database.session() as session:
        remaining = await PlanRepository(session).claim_items(
            scan_run_id=scan_run_id,
            stage="recon",
            step="subdomain_discovery",
            limit=10,
        )
    assert len(remaining) == 1


@pytest.mark.asyncio
async def test_settled_item_records_its_outcome(admitted) -> None:
    services, scan_run_id = admitted
    claim = await _claim(services, scan_run_id, "owner-a")
    execution_id = secrets.token_hex(32)
    item = {
        "plan_item_id": "settle-1",
        "plan_id": "plan-s",
        "scan_run_id": scan_run_id,
        "stage": "scan",
        "step": "vulnerability_scan",
        "seq": 0,
        "tool_id": "nuclei",
        "execution_id": execution_id,
        "request_digest": secrets.token_hex(32),
        "attempt_epoch": 0,
        "attempts": 0,
        "canonical_target": "app.example.com",
        "target_path": None,
        "effective_depth": "standard",
        "provenance": {},
        "state": PlanItemState.DISPATCHED.value,
        "claim_epoch": claim.claim_epoch,
    }
    async with services.database.session() as session:
        async with session.begin():
            await PlanRepository(session).commit_plan(
                plan_id="plan-s",
                scan_run_id=scan_run_id,
                stage="scan",
                step="vulnerability_scan",
                tool_id="nuclei",
                plan_generation=1,
                plan_digest=secrets.token_hex(32),
                policy_version="1",
                ledger_schema_version="1",
                min_coverage_to_proceed=0.0,
                claim_epoch=claim.claim_epoch,
                items=[item],
            )
    async with services.database.session() as session:
        async with session.begin():
            await PlanRepository(session).settle_item(
                plan_item_id="settle-1",
                claim_epoch=claim.claim_epoch,
                state=PlanItemState.COMPLETED,
                outcome="COMPLETED",
                reason_code="COMPLETED",
                audit_event_id="audit-x",
                record_count=1,
            )
    async with services.database.session() as session:
        rows = await PlanRepository(session).items_for_scan(scan_run_id)
    settled = next(r for r in rows if r.plan_item_id == "settle-1")
    assert settled.state == PlanItemState.COMPLETED.value
    assert settled.audit_event_id == "audit-x"
    assert settled.settled_at is not None


@pytest.mark.asyncio
async def test_evidence_insert_is_idempotent(admitted) -> None:
    """Re-folding one execution's results must not duplicate what it found.

    This is what makes a re-walked step safe after a crash.
    """
    services, scan_run_id = admitted
    await _claim(services, scan_run_id, "owner-a")
    row = {
        "finding_id": "f-dup",
        "scan_run_id": scan_run_id,
        "execution_id": "exec-dup",
        "audit_event_id": "audit-dup",
        "plan_item_id": "item-dup",
        "stage": "scan",
        "step": "vulnerability_scan",
        "tool_id": "nuclei",
        "finding_key": "key-dup",
        "canonical_target": "app.example.com",
        "observation_type": "vulnerability",
        "observation": {"template_id": "t"},
        "severity": "HIGH",
        "title": "dup",
        "port": None,
        "url": None,
        "verification_status": "NOT_VERIFIED",
        "enrichment_status": "NOT_PERFORMED",
    }
    async with services.database.session() as session:
        async with session.begin():
            first = await RawFindingRepository(session).append_many([row])
    async with services.database.session() as session:
        async with session.begin():
            second = await RawFindingRepository(session).append_many([row])
    async with services.database.session() as session:
        count = await RawFindingRepository(session).count_for_scan(scan_run_id)
    assert first == 1
    assert second == 0
    assert count == 1
