"""A whole scan, end to end, through the real graph and the real enforcement layer.

A fake runner stands in for the tool binaries and a stub resolver for DNS, so
no packet leaves the host — but everything above that is real: the compiled
graph, the authorization gate, the fenced claim, the committed plans, the stored
identities, the enforcement gateway's saga, coverage, and the attested report.

The assertions that matter most here are the ones a unit test cannot make:

* a second invocation of a finished scan performs **zero** further tool
  executions, which is the property crash-resume safety rests on;
* a scan whose authorization has been revoked halts at the gate having run
  nothing;
* the report is corroborated against the enforcement layer's own records.
"""

from __future__ import annotations

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
from gryphon.db.models.tool_execution import ToolExecution
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.admission import TargetAdmission
from gryphon.orchestration.constants import ScanLifecycleState
from gryphon.orchestration.engine import StepEngine
from gryphon.orchestration.ledger import (
    OrchestrationAuditRepository,
    PlanRepository,
    RawFindingRepository,
    ReportRepository,
)
from gryphon.orchestration.orchestrator import ScanOrchestrator
from gryphon.orchestration.reconcile import Reconciler
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.settings import OrchestrationSettings
from gryphon.orchestration.sweeper import RecoverySweeper
from gryphon.orchestration.touchpoint import AuthorityTouchpoint
from gryphon.settings import Settings
from gryphon.tooling.audit.builder import ToolAuditBuilder
from gryphon.tooling.capability.verifier import CapabilityVerifier
from gryphon.tooling.constants import ToolId, ToolOutcome
from gryphon.tooling.destination.guard import DestinationGuard
from gryphon.tooling.destination.egress import EgressHandle
from gryphon.tooling.enforcement.budgets import BudgetManager
from gryphon.tooling.enforcement.service import ToolExecutionService
from gryphon.tooling.provisioning.manifest import StaticBinaryResolver
from gryphon.tooling.settings import ToolingSettings
from gryphon.tooling.tools.runner import RunResult
from sqlalchemy import func, select

_OWNER_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_OWNER_URL is None, reason="GRYPHON_TEST_DATABASE_URL not set"),
]

SEED = "app.example.com"
# A routable public address, as the tool-execution layer tests use: the
# destination guard rejects reserved/documentation ranges, which is correct
# behaviour. No traffic is sent -- the runner and the egress context are
# doubles -- so this address is never contacted.
ESTATE = "93.184.216.0/24"
IN_ESTATE = "93.184.216.34"


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


# -- doubles ------------------------------------------------------------------
class _StubResolver:
    """Everything resolves inside the attested estate. No DNS."""

    async def resolve(self, host: str):
        import ipaddress

        return [ipaddress.ip_address(IN_ESTATE)]


class _AllowEgress:
    enforcing = True

    async def establish(self, allowlist, ports):
        return EgressHandle(
            context_id="test", allowlist=tuple(allowlist), ports=tuple(ports),
            enforcing=True,
        )

    async def teardown(self, handle):
        return None


class _CountingRunner:
    """Canned per-tool output. Counts every invocation so we can assert zero."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run(self, *, binary_path: str, argv, **kwargs) -> RunResult:
        tool = os.path.basename(binary_path)
        self.calls.append(tool)
        return RunResult(
            outcome=ToolOutcome.COMPLETED,
            exit_code=0,
            stdout=_OUTPUT.get(tool, ""),
            stderr="",
            stdout_truncated=False,
        )


#: Minimal, realistic JSONL per tool. Shapes match the layer's projections.
_OUTPUT = {
    "subfinder": '{"host":"api.example.com","source":"crtsh"}',
    "dnsx": '{"host":"api.example.com","a":["93.184.216.34"]}',
    "naabu": '{"host":"api.example.com","ip":"93.184.216.34","port":8080}',
    "httpx": (
        '{"url":"https://api.example.com","input":"api.example.com",'
        '"status_code":200,"title":"API","host":"api.example.com","failed":false}'
    ),
    "tlsx": (
        '{"host":"api.example.com","port":"443","probe_status":true,'
        '"tls_version":"tls13","subject_cn":"api.example.com",'
        '"issuer_cn":"Example CA","not_after":"2027-01-01T00:00:00Z"}'
    ),
    "katana": (
        '{"timestamp":"2026-06-01T00:00:00Z",'
        '"request":{"method":"GET","endpoint":"https://api.example.com/login"},'
        '"response":{"status_code":200}}'
    ),
    "nuclei": (
        '{"template-id":"exposed-panel","info":{"name":"Exposed Panel",'
        '"severity":"medium"},"matched-at":"https://api.example.com/login"}'
    ),
}


@pytest.fixture(scope="module")
def keyset() -> dict:
    grant_priv, grant_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    audit_priv, audit_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    cap_priv, cap_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    return {
        "grant_priv": grant_priv, "grant_pub": grant_pub,
        "audit_priv": audit_priv, "audit_pub": audit_pub,
        "cap_priv": cap_priv, "cap_pub": cap_pub,
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


def _tooling_settings(keyset) -> ToolingSettings:
    return ToolingSettings(
        _env_file=None,
        environment="test",
        capability_signing_key_hex=keyset["cap_priv"],
        capability_kid="cap-test",
        capability_trusted_public_keys={"cap-test": keyset["cap_pub"]},
        egress_mode="unenforced",
        allow_unenforced_egress=True,
    )


@pytest.fixture
async def scan_env(keyset, _migrated, tmp_path):
    """A complete, wired runtime with a counting runner and no real network."""
    auth = build_services(_settings(keyset), clock=SystemClock())
    ts = _tooling_settings(keyset)

    # Fake binaries: present on disk so the resolver finds them, never executed.
    paths = {}
    for tool in ToolId:
        binary = tmp_path / tool.value
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        paths[tool] = str(binary)

    runner = _CountingRunner()
    service = ToolExecutionService(
        verifier=CapabilityVerifier(
            auth.key_material.grant_trust, clock_skew=timedelta(seconds=30)
        ),
        database=auth.database,
        clock=auth.clock,
        budgets=BudgetManager(ts, auth.clock),
        destination_guard=DestinationGuard(_StubResolver()),
        egress_enforcer=_AllowEgress(),
        runner=runner,
        audit_builder=ToolAuditBuilder(auth.key_material.audit_signer),
        binary_resolver=StaticBinaryResolver(paths=paths),
        settings=ts,
    )

    os_settings = OrchestrationSettings(
        _env_file=None,
        environment="test",
        attested_estate_cidrs=(ESTATE,),
        discovered_target_cap=50,
        max_step_concurrency=2,
    )
    audit = OrchestrationAuditBuilder(auth.key_material.audit_signer)
    touchpoint = AuthorityTouchpoint(
        database=auth.database,
        clock=auth.clock,
        grant_trust=auth.key_material.grant_trust,
        execution_service=service,
    )
    runtime = ScanRuntime(
        database=auth.database,
        clock=auth.clock,
        settings=os_settings,
        touchpoint=touchpoint,
        engine=StepEngine(
            database=auth.database, clock=auth.clock, touchpoint=touchpoint,
            audit=audit, settings=os_settings,
        ),
        reconciler=Reconciler(
            database=auth.database, clock=auth.clock, touchpoint=touchpoint,
            audit=audit, settings=os_settings,
        ),
        admission=TargetAdmission(
            resolver=_StubResolver(),
            attested_estate_cidrs=(ESTATE,),
            discovered_target_cap=50,
            strict_address_attestation=True,
        ),
        audit=audit,
    )
    orchestrator = ScanOrchestrator(runtime=runtime, audit=audit, owner_id="e2e-owner")

    now = auth.clock.now()
    issued = await auth.issuer.issue_grant(
        IssuanceRequest(
            organization="GRYPHON E2E",
            granted_by="owner@example.com",
            granted_to="tester@example.com",
            scope=(
                ScopeEntry(target_type=TargetType.DOMAIN, target=SEED),
                ScopeEntry(target_type=TargetType.DOMAIN_WILDCARD, target="*.example.com"),
            ),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(hours=4),
            max_scan_depth=ScanDepth.STANDARD,
            written_authorization_ref="SOW-e2e",
        ),
        idempotency_key=secrets.token_hex(16),
    )
    admitted = await auth.authorization_service.authorize_scan(
        ScanAdmissionRequest(
            target=SEED,
            token=issued.token,
            requested_depth="standard",
            idempotency_key=secrets.token_hex(16),
        )
    )
    yield auth, runtime, orchestrator, runner, admitted.scan_run_id
    await auth.database.dispose()


async def _execution_count(auth, scan_run_id: str) -> int:
    async with auth.database.session() as session:
        return int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(ToolExecution)
                    .where(ToolExecution.scan_run_id == scan_run_id)
                )
            ).scalar_one()
        )


# -- the happy path -----------------------------------------------------------
@pytest.mark.asyncio
async def test_a_whole_scan_runs_and_reports(scan_env) -> None:
    auth, runtime, orchestrator, runner, scan_run_id = scan_env

    outcome = await orchestrator.invoke(scan_run_id, initiated_by="cli:test")

    assert outcome.terminal_state in (
        ScanLifecycleState.COMPLETED,
        ScanLifecycleState.COMPLETED_WITH_GAPS,
    ), outcome.reason_code
    assert outcome.report_id
    assert not outcome.replayed
    # Every stage ran at least one tool.
    assert {"subfinder", "dnsx", "naabu", "httpx"} <= set(runner.calls)

    async with auth.database.session() as session:
        report = await ReportRepository(session).latest_for_scan(scan_run_id)
        findings = await RawFindingRepository(session).for_scan(scan_run_id)
        events = await OrchestrationAuditRepository(session).for_scan(scan_run_id)

    assert report is not None
    assert report.report_digest
    # Coverage is mandatory and present.
    assert "coverage" in report.body
    assert report.body["coverage"]["denominator"] >= 1
    # Assurance is declared, not implied.
    assert report.body["assurance"]["verification"] == "NOT_VERIFIED"
    # Evidence was recorded with provenance.
    assert findings
    assert all(f.execution_id for f in findings)
    # The decision trail exists: gate, start, plans, admission, report.
    kinds = {e.event_type for e in events}
    assert {"gate", "scan_start", "plan_committed", "target_admission", "report_emitted"} <= kinds


@pytest.mark.asyncio
async def test_port_discovery_precedes_the_http_probe_in_practice(scan_env) -> None:
    """The ordering correction, observed in a real run rather than in the table."""
    _auth, _runtime, orchestrator, runner, scan_run_id = scan_env
    await orchestrator.invoke(scan_run_id, initiated_by="cli:test")
    assert runner.calls.index("naabu") < runner.calls.index("httpx")


@pytest.mark.asyncio
async def test_report_digest_is_attested_by_a_signed_event(scan_env) -> None:
    """The deliverable's tamper evidence uses the existing audit key and verifier."""
    auth, _runtime, orchestrator, _runner, scan_run_id = scan_env
    await orchestrator.invoke(scan_run_id, initiated_by="cli:test")

    async with auth.database.session() as session:
        report = await ReportRepository(session).latest_for_scan(scan_run_id)
        events = await OrchestrationAuditRepository(session).for_scan(scan_run_id)

    emitted = [e for e in events if e.event_type == "report_emitted"]
    assert len(emitted) == 1
    assert emitted[0].payload["report_digest"] == report.report_digest
    assert emitted[0].signer_kid == "audit-test"
    assert emitted[0].signature


# -- the property crash-resume rests on ---------------------------------------
@pytest.mark.asyncio
async def test_reinvoking_a_finished_scan_runs_no_tool_again(scan_env) -> None:
    """Replay must return the recorded result, not repeat the scan.

    This is the single most important behavioural guarantee in the layer: a
    re-invocation — whether from an operator, a retry wrapper, or the recovery
    sweeper — must never cause a second real scan.
    """
    auth, _runtime, orchestrator, runner, scan_run_id = scan_env

    first = await orchestrator.invoke(scan_run_id, initiated_by="cli:test")
    executions_after_first = await _execution_count(auth, scan_run_id)
    calls_after_first = len(runner.calls)
    assert executions_after_first > 0

    second = await orchestrator.invoke(scan_run_id, initiated_by="cli:test")

    assert second.replayed is True
    assert second.report_id == first.report_id
    assert len(runner.calls) == calls_after_first, "a tool ran again on replay"
    assert await _execution_count(auth, scan_run_id) == executions_after_first


@pytest.mark.asyncio
async def test_resuming_a_partially_complete_scan_does_not_redo_covered_work(
    scan_env,
) -> None:
    """Interrupt after the first stage, resume, and assert no duplicate contact.

    Simulated by running the graph once (which completes), then clearing the
    lease so the scan looks abandoned, and resuming. Covered items are re-walked
    as no-ops because each presents its stored identity.
    """
    auth, _runtime, orchestrator, runner, scan_run_id = scan_env

    await orchestrator.invoke(scan_run_id, initiated_by="cli:test")
    baseline = await _execution_count(auth, scan_run_id)

    # Force the scan back to a resumable state with an expired lease.
    async with auth.database.session() as session:
        async with session.begin():
            await session.execute(
                __import__("sqlalchemy").text(
                    "UPDATE scan_lifecycle SET state='RUNNING', terminal_at=NULL, "
                    "lease_expires_at = now() - interval '1 hour', owner_id='dead' "
                    "WHERE scan_run_id = :sid"
                ),
                {"sid": scan_run_id},
            )

    resumed = await orchestrator.invoke(scan_run_id, initiated_by="cli:test")

    assert resumed.claim_epoch >= 2, "the resume should have taken over the lease"
    assert await _execution_count(auth, scan_run_id) == baseline, (
        "resume created new executions; stored identities were not reused"
    )


# -- authorization is a window ------------------------------------------------
@pytest.mark.asyncio
async def test_revoked_signing_key_halts_the_scan_at_the_gate(scan_env) -> None:
    """Revocation must reach an in-flight scan, not just new admissions.

    A committed admission is immutable and says nothing about current trust, so
    without a liveness re-check the only revocation mechanism available would be
    silently ineffective against work already under way.
    """
    auth, runtime, orchestrator, runner, scan_run_id = scan_env

    # Empty the trust store: the grant's signer is no longer trusted.
    auth.key_material.grant_trust._keys.clear()  # type: ignore[attr-defined]

    outcome = await orchestrator.invoke(scan_run_id, initiated_by="cli:test")

    assert outcome.terminal_state is ScanLifecycleState.HALTED_UNAUTHORIZED
    assert outcome.reason_code == "KID_UNTRUSTED"
    assert runner.calls == [], "a tool ran after the gate denied the scan"
    assert await _execution_count(auth, scan_run_id) == 0


@pytest.mark.asyncio
async def test_gate_denial_is_audited(scan_env) -> None:
    auth, _runtime, orchestrator, _runner, scan_run_id = scan_env
    auth.key_material.grant_trust._keys.clear()  # type: ignore[attr-defined]

    await orchestrator.invoke(scan_run_id, initiated_by="cli:test")

    async with auth.database.session() as session:
        events = await OrchestrationAuditRepository(session).for_scan(scan_run_id)
    denials = [e for e in events if e.event_type == "gate" and e.decision == "DENY"]
    assert denials, "a refusal must still be accountable"
    assert denials[0].signature


# -- recovery -----------------------------------------------------------------
@pytest.mark.asyncio
async def test_sweeper_reclaims_an_abandoned_scan(scan_env) -> None:
    """Recovery happens on a timer, not when a human remembers."""
    auth, runtime, orchestrator, _runner, scan_run_id = scan_env
    sweeper = RecoverySweeper(runtime=runtime, orchestrator=orchestrator)

    # A scan claimed by an owner that never came back.
    async with auth.database.session() as session:
        async with session.begin():
            await session.execute(
                __import__("sqlalchemy").text(
                    "INSERT INTO scan_lifecycle (scan_run_id, state, phase_reached, "
                    "owner_id, claim_epoch, lease_expires_at, execution_salt, "
                    "policy_version, graph_version, initiated_by, deadline_at, "
                    "decision_count, started_at, created_at) VALUES "
                    "(:sid, 'RUNNING', 0, 'dead-owner', 1, now() - interval '1 hour', "
                    ":salt, '1', '1', 'cli:test', now() + interval '1 hour', 0, "
                    "now(), now())"
                ),
                {"sid": scan_run_id, "salt": "ab" * 32},
            )

    report = await sweeper.sweep_once()
    assert report.reclaimed >= 1


@pytest.mark.asyncio
async def test_sweeper_retires_an_overdue_scan(scan_env) -> None:
    """The backstop that stops work outliving its authorization window."""
    auth, runtime, orchestrator, _runner, scan_run_id = scan_env
    sweeper = RecoverySweeper(runtime=runtime, orchestrator=orchestrator)

    async with auth.database.session() as session:
        async with session.begin():
            await session.execute(
                __import__("sqlalchemy").text(
                    "INSERT INTO scan_lifecycle (scan_run_id, state, phase_reached, "
                    "owner_id, claim_epoch, lease_expires_at, execution_salt, "
                    "policy_version, graph_version, initiated_by, deadline_at, "
                    "decision_count, started_at, created_at) VALUES "
                    "(:sid, 'RUNNING', 0, 'owner', 1, now() + interval '1 hour', "
                    ":salt, '1', '1', 'cli:test', now() - interval '1 minute', 0, "
                    "now(), now())"
                ),
                {"sid": scan_run_id, "salt": "ab" * 32},
            )

    report = await sweeper.sweep_once()
    assert report.aborted_overdue >= 1

    async with auth.database.session() as session:
        from gryphon.orchestration.ledger import ScanLifecycleRepository

        row = await ScanLifecycleRepository(session).get(scan_run_id)
    assert row.state == ScanLifecycleState.ABORTED_DEADLINE.value
