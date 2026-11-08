"""End-to-end execution saga against PostgreSQL 16 (gated on a DB URL).

Covers: migration 0002, intent→outcome commit, idempotent replay, out-of-scope
denial, grant-rooted scope re-derivation, capability consumption, and
egress-unavailable fail-closed. A FakeRunner stands in for the real binary (the
real subprocess path is covered elsewhere); no network traffic occurs.
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
from gryphon.clock import FixedClock
from gryphon.constants import ScanDepth, TargetType
from gryphon.settings import Settings
from gryphon.tooling.audit.builder import ToolAuditBuilder
from gryphon.tooling.capability.issuer import CapabilityIssuer
from gryphon.tooling.capability.keys import build_capability_key_material
from gryphon.tooling.capability.verifier import CapabilityVerifier
from gryphon.tooling.constants import ToolId, ToolOutcome
from gryphon.tooling.destination.guard import DestinationGuard
from gryphon.tooling.enforcement.budgets import BudgetManager
from gryphon.tooling.enforcement.service import ToolExecutionService
from gryphon.tooling.execution.aggregate import ToolExecutionResult
from gryphon.tooling.provisioning.manifest import StaticBinaryResolver
from gryphon.tooling.settings import ToolingSettings
from gryphon.tooling.tools.runner import RunResult

_OWNER_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_OWNER_URL is None, reason="GRYPHON_TEST_DATABASE_URL not set"),
]

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _hex(k: ed25519.Ed25519PrivateKey) -> tuple[str, str]:
    return (
        k.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex(),
        k.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ).hex(),
    )


class _FakeResolver:
    async def resolve(self, host: str):
        import ipaddress

        return [ipaddress.ip_address("93.184.216.34")]


class _UnavailableEgress:
    """Refuses to establish a context, so the gateway must fail closed."""

    enforcing = True

    async def establish(self, allowlist, ports):
        from gryphon.tooling.reasons import EgressUnavailableError

        raise EgressUnavailableError("test: egress context withheld")

    async def teardown(self, handle):
        return None


class _FakeEgress:
    enforcing = True

    async def establish(self, allowlist, ports):
        from gryphon.tooling.destination.egress import EgressHandle

        return EgressHandle(context_id="fake", allowlist=tuple(allowlist), ports=tuple(ports), enforcing=True)

    async def teardown(self, handle):
        return None


class _FakeRunner:
    """Returns canned JSONL without spawning a process."""

    def __init__(self, stdout: str, outcome: ToolOutcome = ToolOutcome.COMPLETED) -> None:
        self._stdout = stdout
        self._outcome = outcome

    async def run(self, **kwargs) -> RunResult:
        return RunResult(
            outcome=self._outcome,
            exit_code=0 if self._outcome is ToolOutcome.COMPLETED else 1,
            stdout=self._stdout,
            stderr="",
            stdout_truncated=False,
        )


@pytest.fixture(scope="module")
def keyset() -> dict:
    grant_priv, grant_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    audit_priv, audit_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    cap_priv, cap_pub = _hex(ed25519.Ed25519PrivateKey.generate())
    return locals()


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
    )


async def _admit_permit(auth):
    now = auth.clock.now()
    issued = await auth.issuer.issue_grant(
        IssuanceRequest(
            organization="Org",
            granted_by="owner@example.com",
            granted_to="tester@example.com",
            scope=(ScopeEntry(target_type=TargetType.DOMAIN, target="app.example.com"),),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(days=30),
            max_scan_depth=ScanDepth.AGGRESSIVE,
            written_authorization_ref="SOW-1",
        ),
        idempotency_key=secrets.token_hex(16),
    )
    result = await auth.authorization_service.authorize_scan(
        ScanAdmissionRequest(
            target="app.example.com",
            token=issued.token,
            requested_depth="standard",
            idempotency_key=secrets.token_hex(16),
        )
    )
    return result  # AuthorizedPermit


def _service(keyset, auth, *, runner, egress, ts) -> ToolExecutionService:
    cap_material = build_capability_key_material(ts)
    verifier = CapabilityVerifier(cap_material.trust, clock_skew=timedelta(seconds=30))
    return ToolExecutionService(
        verifier=verifier,
        database=auth.database,
        clock=auth.clock,
        budgets=BudgetManager(ts, auth.clock),
        destination_guard=DestinationGuard(_FakeResolver()),
        egress_enforcer=egress,
        runner=runner,
        audit_builder=ToolAuditBuilder(auth.key_material.audit_signer),
        binary_resolver=StaticBinaryResolver(paths={t: "/bin/true" for t in ToolId}),
        settings=ts,
    )


@pytest.fixture
async def wired(_migrated, keyset):
    settings = _settings(keyset)
    auth = build_services(settings, clock=FixedClock(instant=NOW))
    yield auth, keyset
    await auth.dispose()


@pytest.mark.asyncio
async def test_permit_path_completes_and_is_idempotent(wired) -> None:
    auth, keyset = wired
    ts = _tooling_settings(keyset)
    stdout = '{"host":"a.app.example.com","source":"ct"}\n{"host":"b.app.example.com"}'
    svc = _service(keyset, auth, runner=_FakeRunner(stdout), egress=_FakeEgress(), ts=ts)
    permit = await _admit_permit(auth)
    exec_id = "exec-" + secrets.token_hex(16)

    first = await svc.execute_with_permit(permit, ToolId.SUBFINDER, exec_id, "app.example.com")
    assert isinstance(first, ToolExecutionResult)
    assert first.outcome is ToolOutcome.COMPLETED
    assert first.records and first.records[0].total_found == 2

    # Idempotent replay: same execution_id returns the stored outcome, no re-run.
    second = await svc.execute_with_permit(permit, ToolId.SUBFINDER, exec_id, "app.example.com")
    assert second.replayed is True
    assert second.outcome is ToolOutcome.COMPLETED


@pytest.mark.asyncio
async def test_out_of_scope_denied(wired) -> None:
    auth, keyset = wired
    ts = _tooling_settings(keyset)
    svc = _service(keyset, auth, runner=_FakeRunner(""), egress=_FakeEgress(), ts=ts)
    permit = await _admit_permit(auth)
    result = await svc.execute_with_permit(
        permit, ToolId.SUBFINDER, "exec-" + secrets.token_hex(16), "evil.example.net"
    )
    assert result.outcome is ToolOutcome.DENIED
    assert result.reason_code == "SCOPE_NO_MATCH"


@pytest.mark.asyncio
async def test_capability_path_and_replay(wired) -> None:
    auth, keyset = wired
    ts = _tooling_settings(keyset)
    stdout = '{"host":"a.app.example.com"}'
    svc = _service(keyset, auth, runner=_FakeRunner(stdout), egress=_FakeEgress(), ts=ts)
    permit = await _admit_permit(auth)
    issuer = CapabilityIssuer(
        signing_key=build_capability_key_material(ts).signer,
        grant_trust=auth.key_material.grant_trust,
        database=auth.database,
        clock=auth.clock,
        ttl_seconds=120,
    )
    exec_id = "exec-" + secrets.token_hex(16)
    cap = await issuer.mint(permit, ToolId.SUBFINDER, exec_id)
    import json

    wire = json.dumps(cap.to_wire()).encode()
    first = await svc.execute_with_capability(wire, ToolId.SUBFINDER, "app.example.com")
    assert first.outcome is ToolOutcome.COMPLETED
    # Re-presenting the same capability (same execution_id) returns the stored outcome.
    second = await svc.execute_with_capability(wire, ToolId.SUBFINDER, "app.example.com")
    assert second.replayed is True


@pytest.mark.asyncio
async def test_egress_unavailable_denies_before_any_run(wired) -> None:
    auth, keyset = wired
    ts = _tooling_settings(keyset)
    # With no egress context an active tool cannot run on ANY host, and no
    # execution intent row is created. Withheld rather than inferred from the
    # platform, so this holds on a capable Linux host too.
    svc = _service(keyset, auth, runner=_FakeRunner(""), egress=_UnavailableEgress(), ts=ts)
    permit = await _admit_permit(auth)
    exec_id = "exec-" + secrets.token_hex(16)
    result = await svc.execute_with_permit(permit, ToolId.HTTPX, exec_id, "app.example.com")
    assert result.outcome is ToolOutcome.DENIED
    assert result.reason_code == "EGRESS_UNAVAILABLE"

    # No subprocess ran and no intent row exists for this execution.
    from gryphon.db.repositories.tool_execution import ToolExecutionRepository

    async with auth.database.session() as session:
        row = await ToolExecutionRepository(session).get(exec_id)
    assert row is None
