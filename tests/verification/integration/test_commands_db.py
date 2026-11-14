"""A whole verification pass, end to end, against a real PostgreSQL.

This is the test whose absence let the layer ship with no way to run it at all.
Every other suite exercised a part — the judge, the protocol, the repository —
and each part was right, while nothing assembled them and the operator CLI
raised ``AttributeError`` on its first line of real work.

So these drive the commands exactly as the CLI does: claim a pass, pin inputs,
plan, observe, judge, publish, and read the deliverable back. The gateway is a
stand-in rather than a socket, because this layer must be runnable without one
on any platform — and because what is under test here is the composition, not
the transport, which has its own suite.

Skipped without ``GRYPHON_TEST_DATABASE_URL``. That database is reset.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from gryphon.auth.key_provider import Ed25519SigningKey, KeyMaterial, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.db.models.raw_finding import RawFinding
from gryphon.db.models.scan_report import OrchestrationAudit, ScanReport
from gryphon.db.models.scan_run import ScanRun
from gryphon.db.models.verification import (
    FindingVerification,
    VerificationAudit,
    VerificationPass,
    VerificationReport,
)
from gryphon.db.session import Database
from gryphon.settings import Settings
from gryphon.tooling.gateway.protocol import ObserveReply, ObserveRequest, Welcome
from gryphon.tooling.observation.extractors import EXTRACTOR_SET_DIGEST
from gryphon.verification.audit import VerificationAuditBuilder
from gryphon.verification.commands import VerificationCommands
from gryphon.verification.constants import (
    ObservationRole,
    OutcomeClass,
    PassOutcome,
    PassState,
    VerdictStatus,
)
from gryphon.verification.evaluator import ProofEvaluator
from gryphon.verification.identity import CallerIdentity
from gryphon.verification.reasons import PassBusy, RequestKeyConflict
from gryphon.verification.registry import VerifierRegistry
from gryphon.verification.settings import VerificationSettings
from tests.verification.conftest import http_facts

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_TEST_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark.append(
    pytest.mark.skipif(not _TEST_URL, reason="GRYPHON_TEST_DATABASE_URL not set")
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


# =============================================================================
# Fixtures
# =============================================================================


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


@pytest.fixture
def audit_key() -> tuple[Ed25519SigningKey, TrustedKeyStore]:
    """The orchestration layer's key: this layer verifies with it, never signs."""
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(kid="audit-test", _private=private)
    return signer, TrustedKeyStore({"audit-test": private.public_key()})


@pytest.fixture
def verification_signer() -> Ed25519SigningKey:
    private = ed25519.Ed25519PrivateKey.generate()
    return Ed25519SigningKey(kid="verification-test", _private=private)


# =============================================================================
# The stand-in gateway
# =============================================================================


@dataclass
class _Recorded:
    request: ObserveRequest


class _FakeGateway:
    """Answers every planned contact, and remembers what it was asked.

    The primary gets dotenv facts with a secret shape; the controls get a 404
    with nothing in it. That is the shape of a genuine exposure: the file is
    there and its siblings are not, which is what separates a real finding from
    a host that answers 200 to everything.
    """

    def __init__(self, *, welcome_digest: str = "feature-set-test") -> None:
        self.seen: list[_Recorded] = []
        self.welcome = Welcome(
            protocol_version="1",
            feature_set=frozenset(
                {
                    "authority_at_contact",
                    "destination_pinning",
                    "envelope_conflict_refusal",
                    "purpose_binding",
                    "cancellation_epoch",
                    "sealed_observation",
                }
            ),
            descriptor_versions={
                "http.response.summary": "httpx/1.12.0",
                "dns.answer": "dnsx/1.3.1",
            },
            extractor_set_digest=EXTRACTOR_SET_DIGEST,
            sanitizer_ruleset_digest="sanitizer-test",
            binary_digests={"httpx": "0" * 64},
        )
        self._welcome_digest = welcome_digest

    def assert_pin(self, pinned_digest: str) -> None:
        if pinned_digest != self.welcome.digest:
            raise AssertionError("the gateway's feature set changed mid-pass")

    async def observe(self, request: ObserveRequest) -> ObserveReply:
        self.seen.append(_Recorded(request))
        if request.role is ObservationRole.PRIMARY:
            facts = http_facts(secret_counts={"aws_access_key_id": 1}, digest_salt="real")
        else:
            # Both controls answer identically. Giving them different bodies
            # would be a host answering its own siblings inconsistently, which
            # the decision table reads as ``controls_disagree`` — correctly, and
            # it caught exactly that when this stand-in first got it wrong.
            facts = http_facts(
                status=404,
                content_type="text/html",
                body="<html>not found</html>",
                with_dotenv=False,
            )
        return ObserveReply(
            outcome=OutcomeClass.OBSERVED,
            reason_code="ADMITTED",
            execution_id=request.execution_id,
            facts=facts.as_payload(),
            completeness=facts.completeness,
            peer_address="203.0.113.10",
        )


class _UnavailableGateway:
    """A gateway that cannot be reached at all."""

    async def observe(self, request: ObserveRequest) -> ObserveReply:  # pragma: no cover
        raise AssertionError("must not be reached")


def _factory(gateway: Any) -> Any:
    @asynccontextmanager
    async def connect() -> AsyncIterator[Any]:
        gateway.welcome  # noqa: B018 - the handshake is what makes a welcome exist
        yield gateway

    return connect


def _failing_factory() -> Any:
    from gryphon.verification.constants import BlockedReason
    from gryphon.verification.reasons import GatewayUnavailable

    @asynccontextmanager
    async def connect() -> AsyncIterator[Any]:  # pragma: no cover - raises first
        raise GatewayUnavailable(
            BlockedReason.GATEWAY_UNAVAILABLE, "cannot connect to the gateway: refused"
        )
        yield None

    return connect


# =============================================================================
# Seeding
# =============================================================================


async def _seed_scan_with_report(
    conn: AsyncConnection, audit_signer: Ed25519SigningKey
) -> tuple[str, str]:
    """An admitted scan, a terminal signed report, and one finding in it."""
    scan_run_id = str(uuid.uuid4())
    finding_id = hashlib.sha256(scan_run_id.encode()).hexdigest()[:48]

    await conn.execute(
        sa.insert(ScanRun).values(
            scan_run_id=scan_run_id,
            decision="ALLOW",
            status="COMPLETED",
            idempotency_key_hash=secrets.token_hex(32),
            request_hash=secrets.token_hex(32),
            decided_at=NOW,
        )
    )

    # The verdict table has a foreign key to the evidence: a verification may
    # only ever be recorded against a finding that actually exists. So the
    # report's finding has to have its evidence row, exactly as a real scan
    # would have written it.
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
            canonical_target="app.example.test",
            observation_type="exposed_config",
            observation={"template_id": "laravel-env"},
        )
    )

    body = {
        "scan_run_id": scan_run_id,
        "report_schema_version": "1",
        "terminal_state": "COMPLETED",
        "reason_code": "COMPLETED",
        "integrity": {"failed": False},
        "findings": [
            {
                "finding_id": finding_id,
                "observation_type": "exposed_config",
                "canonical_target": "app.example.test",
                "url": "https://app.example.test/.env",
                "severity": "high",
                "observation": {"template_id": "laravel-env"},
            }
        ],
    }
    digest = sha256_hex(canonical_json_bytes(body))
    report_id = f"rep-{finding_id[:16]}"
    await conn.execute(
        sa.insert(ScanReport).values(
            report_id=report_id,
            scan_run_id=scan_run_id,
            report_schema_version="1",
            report_digest=digest,
            body=body,
            terminal_state="COMPLETED",
            covered=1,
            denominator=1,
            finding_count=1,
            generated_at=NOW,
        )
    )

    payload = {
        "event_schema_version": "1",
        "event_type": "report_emitted",
        "scan_run_id": scan_run_id,
        "report_digest": digest,
        "signer_kid": audit_signer.kid,
    }
    canonical = canonical_json_bytes(payload)
    await conn.execute(
        sa.insert(OrchestrationAudit).values(
            event_id=f"evt-{finding_id[:16]}",
            event_type="report_emitted",
            event_schema_version="1",
            scan_run_id=scan_run_id,
            payload=payload,
            payload_digest=sha256_hex(canonical),
            signer_kid=audit_signer.kid,
            signature=base64.standard_b64encode(audit_signer.sign(canonical)).decode("ascii"),
            recorded_at=NOW,
        )
    )
    return scan_run_id, finding_id


def _commands(
    *,
    audit_trust: TrustedKeyStore,
    signer: Ed25519SigningKey,
    gateway: Any,
    factory: Any | None = None,
) -> VerificationCommands:
    core = Settings(database_url=_TEST_URL)  # type: ignore[arg-type]
    settings = VerificationSettings(
        database_url=_TEST_URL,  # type: ignore[arg-type]
        gateway_socket_path=Path("/tmp/not-used-by-this-test.sock"),
        pass_lease_seconds=60.0,
        pass_heartbeat_seconds=15.0,
    )
    from gryphon.clock import SystemClock

    return VerificationCommands(
        database=Database(core.model_copy(update={"database_url": _TEST_URL})),
        settings=settings,
        clock=SystemClock(),
        registry=VerifierRegistry.load(
            settings.registry_file, trust=TrustedKeyStore({}), require_signature=False
        ),
        evaluator=ProofEvaluator(),
        audit=VerificationAuditBuilder(signer),
        attestation_trust=TrustedKeyStore({signer.kid: signer.public_key()}),
        enrichment_trust=TrustedKeyStore({}),
        gateway_socket=settings.gateway_socket_path,
        keys=KeyMaterial(
            grant_signer=None,
            grant_trust=TrustedKeyStore({}),
            audit_signer=None,
            audit_trust=audit_trust,
        ),
        gateway_factory=factory or _factory(gateway),
    )


CALLER = CallerIdentity(uid=1000, label="cli:uid:1000")


# =============================================================================
# The pass
# =============================================================================


async def test_a_pass_runs_from_a_signed_report_to_a_signed_deliverable(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """The whole path, which nothing exercised before.

    Asserts the deliverable exists, is attested, and says what it found — and
    that the verdict rests on a measurement the stand-in gateway actually made.
    """
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, finding_id = await _seed_scan_with_report(conn, audit_signer)

    gateway = _FakeGateway()
    commands = _commands(audit_trust=audit_trust, signer=verification_signer, gateway=gateway)
    try:
        result = await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
    finally:
        await commands._database.dispose()

    assert result.state is PassState.COMPLETE, result.reason
    assert result.outcome is PassOutcome.VERIFIED
    assert result.report_id is not None
    assert result.verdicts == 1
    assert result.counts.get(VerdictStatus.CONFIRMED.value) == 1

    # One primary and two controls actually reached the gateway.
    roles = [r.request.role for r in gateway.seen]
    assert roles.count(ObservationRole.PRIMARY) == 1
    assert roles.count(ObservationRole.CONTROL) == 2
    assert all(r.request.purpose == "verification" for r in gateway.seen)

    async with engine.begin() as conn:
        report = (
            await conn.execute(
                sa.select(VerificationReport).where(
                    VerificationReport.scan_run_id == scan_run_id
                )
            )
        ).first()
        verdicts = (
            await conn.execute(
                sa.select(FindingVerification.finding_id, FindingVerification.status)
            )
        ).all()
        events = (
            await conn.execute(
                sa.select(VerificationAudit.event_type, VerificationAudit.signer_kid)
            )
        ).all()

    assert report is not None
    assert [v[0] for v in verdicts] == [finding_id]
    assert verdicts[0][1] == VerdictStatus.CONFIRMED.value
    assert ("verification_report_emitted", verification_signer.kid) in [
        (e[0], e[1]) for e in events
    ]


async def test_the_same_request_key_returns_the_same_pass_and_sends_nothing(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """The property the key exists for: a retry costs the estate nothing."""
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, audit_signer)

    gateway = _FakeGateway()
    commands = _commands(audit_trust=audit_trust, signer=verification_signer, gateway=gateway)
    try:
        first = await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
        contacts_after_first = len(gateway.seen)
        second = await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
    finally:
        await commands._database.dispose()

    assert first.state is PassState.COMPLETE
    assert second.pass_id == first.pass_id
    assert second.returned is True
    assert second.report_id == first.report_id
    assert len(gateway.seen) == contacts_after_first, "a retry must not re-contact the target"


async def test_a_reused_key_with_a_different_request_is_refused(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """Ambiguity is refused rather than guessed at: the caller may believe either."""
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, finding_id = await _seed_scan_with_report(conn, audit_signer)

    gateway = _FakeGateway()
    commands = _commands(audit_trust=audit_trust, signer=verification_signer, gateway=gateway)
    try:
        await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
        with pytest.raises(RequestKeyConflict):
            await commands.start(
                scan_run_id, request_key="run-1", caller=CALLER, only=(finding_id,)
            )
    finally:
        await commands._database.dispose()


async def test_an_unreachable_gateway_blocks_the_pass_rather_than_judging(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """Our outage must not be published as the client's ambiguity.

    A pass that could not reach its gateway writes BLOCKED and no verdicts. The
    alternative — a report full of INCONCLUSIVE — reads to a client as "we
    looked and could not tell", which is a statement about their estate.
    """
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, audit_signer)

    commands = _commands(
        audit_trust=audit_trust,
        signer=verification_signer,
        gateway=_UnavailableGateway(),
        factory=_failing_factory(),
    )
    try:
        result = await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
    finally:
        await commands._database.dispose()

    assert result.state is PassState.BLOCKED
    assert result.reason == "gateway_unavailable"

    async with engine.begin() as conn:
        verdicts = (
            await conn.execute(
                sa.select(sa.func.count())
                .select_from(FindingVerification)
                .where(FindingVerification.pass_id == result.pass_id)
            )
        ).scalar_one()
        blocked = (
            await conn.execute(
                sa.select(VerificationAudit.event_type).where(
                    VerificationAudit.scan_run_id == scan_run_id
                )
            )
        ).scalars().all()

    assert verdicts == 0
    assert "verification_pass_blocked" in blocked


async def test_a_refused_input_refuses_the_pass_and_says_why(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """A report nobody attested is not verifiable material."""
    _, audit_trust = audit_key
    other = ed25519.Ed25519PrivateKey.generate()
    stranger = Ed25519SigningKey(kid="not-trusted", _private=other)

    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, stranger)

    gateway = _FakeGateway()
    commands = _commands(audit_trust=audit_trust, signer=verification_signer, gateway=gateway)
    try:
        result = await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
    finally:
        await commands._database.dispose()

    assert result.state is PassState.REFUSED
    assert result.reason == "report_unverified"
    assert gateway.seen == [], "a refused pass sends no traffic"


async def test_the_report_is_reverified_before_it_is_served(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """Serving is the last moment a tampered row can still be caught."""
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, audit_signer)

    commands = _commands(
        audit_trust=audit_trust, signer=verification_signer, gateway=_FakeGateway()
    )
    try:
        await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
        served = await commands.report(scan_run_id)
        assert served is not None
        assert served.verification.verified is True

        # Alter the stored body after publication. The append-only trigger
        # refuses this outright — that is the first line of defence, and it is
        # tested elsewhere. Disabling it here as the *owner* is what an actor
        # with more privilege than the verification role, or a restored backup,
        # would effectively amount to; the point of this test is that the digest
        # check still catches it at the moment of serving.
        async with engine.begin() as conn:
            await conn.execute(sa.text("ALTER TABLE verification_report DISABLE TRIGGER USER"))
            await conn.execute(
                sa.update(VerificationReport)
                .where(VerificationReport.scan_run_id == scan_run_id)
                .values(body={"tampered": True})
            )
            await conn.execute(sa.text("ALTER TABLE verification_report ENABLE TRIGGER USER"))

        tampered = await commands.report(scan_run_id)
    finally:
        await commands._database.dispose()

    assert tampered is not None
    assert tampered.verification.verified is False
    assert tampered.verification.reason


async def test_stop_advances_the_cancellation_epoch_without_the_lease(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """Stopping is a safety control, not an ownership question."""
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, audit_signer)

    commands = _commands(
        audit_trust=audit_trust,
        signer=verification_signer,
        gateway=_UnavailableGateway(),
        factory=_failing_factory(),
    )
    try:
        # A blocked pass is still open, so there is something to stop.
        await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
        async with engine.begin() as conn:
            before = (
                await conn.execute(
                    sa.select(VerificationPass.cancellation_epoch).where(
                        VerificationPass.scan_run_id == scan_run_id
                    )
                )
            ).scalar_one()

        stopped = await commands.stop(scan_run_id, caller=CALLER, detail="operator said so")

        async with engine.begin() as conn:
            after = (
                await conn.execute(
                    sa.select(VerificationPass.cancellation_epoch).where(
                        VerificationPass.scan_run_id == scan_run_id
                    )
                )
            ).scalar_one()
    finally:
        await commands._database.dispose()

    assert stopped is not None
    assert stopped.stopped is True
    assert after == before + 1


async def test_status_reports_an_open_pass_and_its_history(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, audit_signer)

    commands = _commands(
        audit_trust=audit_trust, signer=verification_signer, gateway=_FakeGateway()
    )
    try:
        await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
        status = await commands.status(scan_run_id)
    finally:
        await commands._database.dispose()

    payload = status.as_payload()
    assert payload["scan_run_id"] == scan_run_id
    assert len(payload["history"]) == 1
    assert payload["history"][0]["state"] == PassState.COMPLETE.value
    # A completed pass holds no slot, so it is history, not an open pass.
    assert payload["open_passes"] == []


async def test_a_second_runner_is_told_the_slot_is_busy(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """Two processes on one client's estate is the thing the lease prevents."""
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, audit_signer)

    # Open a pass under a live lease, and leave it open.
    from gryphon.verification.repository import VerificationRepository

    commands = _commands(
        audit_trust=audit_trust, signer=verification_signer, gateway=_FakeGateway()
    )
    try:
        async with commands._database.session() as session:
            repo = VerificationRepository(session)
            await repo.claim_pass(
                scan_run_id,
                "someone-elses-key",
                holder="another-process",
                lease_seconds=600.0,
                initiated_by="cli:uid:999",
            )
            await session.commit()

        with pytest.raises(PassBusy):
            await commands.start(scan_run_id, request_key="run-1", caller=CALLER)
    finally:
        await commands._database.dispose()


async def test_a_blocked_pass_resumes_under_the_same_key_once_the_gateway_returns(
    engine: AsyncEngine, audit_key, verification_signer
) -> None:
    """The recovery story: block, then finish, without a second pass.

    A dependency outage must cost the operator a retry, not a new pass and not a
    second round of traffic to the client. The same request key picks the same
    pass back up and drives it to COMPLETE.
    """
    audit_signer, audit_trust = audit_key
    async with engine.begin() as conn:
        scan_run_id, _ = await _seed_scan_with_report(conn, audit_signer)

    down = _commands(
        audit_trust=audit_trust,
        signer=verification_signer,
        gateway=_UnavailableGateway(),
        factory=_failing_factory(),
    )
    try:
        blocked = await down.start(scan_run_id, request_key="run-1", caller=CALLER)
    finally:
        await down._database.dispose()
    assert blocked.state is PassState.BLOCKED

    gateway = _FakeGateway()
    back_up = _commands(audit_trust=audit_trust, signer=verification_signer, gateway=gateway)
    try:
        finished = await back_up.start(scan_run_id, request_key="run-1", caller=CALLER)
    finally:
        await back_up._database.dispose()

    assert finished.state is PassState.COMPLETE, finished.reason
    assert finished.pass_id == blocked.pass_id, "a resumed pass keeps its identity"
    assert finished.resumed is True
    assert finished.counts.get(VerdictStatus.CONFIRMED.value) == 1
