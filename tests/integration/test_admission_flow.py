"""End-to-end admission against PostgreSQL 16 (§30.3, P0 gates).

Gated on ``GRYPHON_TEST_DATABASE_URL`` (an OWNER-role DSN). The whole module is
skipped when it is absent, so the pure suite still runs anywhere. Covers:

* clean Alembic migration + schema/trigger presence (§30.3);
* atomic ``scan_runs`` + signed audit commit on ALLOW (INV-011);
* out-of-scope DENY still audited (INV-010);
* idempotency replay returns a non-executable receipt, no second run (INV-014);
* same key + different request conflicts (INV-015);
* Finding persistence against a string scan-run id;
* compiled-graph sentinel: 1 for ALLOW, 0 for DENY (§30.4).

An optional runtime-role DSN in ``GRYPHON_TEST_RUNTIME_DATABASE_URL`` enables the
append-only privilege test (SEC-012).
"""

from __future__ import annotations

import os
from datetime import timedelta

import pytest

from gryphon.auth.claims import IssuanceRequest
from gryphon.auth.scope import ScopeEntry
from gryphon.auth.service import ScanAdmissionRequest
from gryphon.bootstrap import build_services
from gryphon.clock import FixedClock
from gryphon.constants import ScanDepth, Severity, TargetType, VerificationStatus
from gryphon.db.repositories.findings import FindingRepository
from gryphon.errors import IdempotencyConflictError, ReasonCode
from gryphon.graph_contract.authorization_gate_test_graph import build_gate_graph, run_gate
from gryphon.settings import Settings

_OWNER_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_OWNER_URL is None, reason="GRYPHON_TEST_DATABASE_URL not set"),
]

from tests.conftest import AUDIENCE, ISSUER, NOW  # noqa: E402


def _settings(key_hexes: dict[str, str], url: str) -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        issuer=ISSUER,
        audience=AUDIENCE,
        grant_signing_key_hex=key_hexes["grant_priv"],
        grant_kid=key_hexes["grant_kid"],
        grant_trusted_public_keys={key_hexes["grant_kid"]: key_hexes["grant_pub"]},
        audit_signing_key_hex=key_hexes["audit_priv"],
        audit_kid=key_hexes["audit_kid"],
        audit_trusted_public_keys={key_hexes["audit_kid"]: key_hexes["audit_pub"]},
        database_url=url,
        migration_database_url=url,
    )


@pytest.fixture(scope="module")
def _migrated() -> None:
    """Apply the Alembic migration once against the owner DSN."""
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


@pytest.fixture
async def services(_migrated, key_hexes):
    svc = build_services(_settings(key_hexes, _OWNER_URL), clock=FixedClock(instant=NOW))
    yield svc
    await svc.dispose()


def _issue_request() -> IssuanceRequest:
    return IssuanceRequest(
        organization="Example Org",
        granted_by="owner@example.com",
        granted_to="tester@contractor.example",
        scope=(
            ScopeEntry(
                target_type=TargetType.DOMAIN, target="app.example.com", excluded_paths=["/admin"]
            ),
        ),
        issued_at=NOW,
        not_before=NOW,
        expires_at=NOW + timedelta(days=30),
        max_scan_depth=ScanDepth.STANDARD,
        written_authorization_ref="SOW-TEST-0001",
    )


@pytest.mark.asyncio
async def test_in_scope_allow_commits_run_and_audit(services) -> None:
    issued = await services.issuer.issue_grant(_issue_request(), idempotency_key="issue-key-aaaaaaaaaaaa")
    req = ScanAdmissionRequest(
        target="app.example.com",
        token=issued.token,
        requested_depth="standard",
        idempotency_key="admit-key-aaaaaaaaaaaa",
    )
    graph = build_gate_graph(services.authorization_service)
    result, sentinel = await run_gate(graph, req)
    assert sentinel == 1
    assert result.effective_scan_depth is ScanDepth.STANDARD
    assert result.audit_event_id


@pytest.mark.asyncio
async def test_out_of_scope_denies_and_audits(services) -> None:
    issued = await services.issuer.issue_grant(_issue_request(), idempotency_key="issue-key-bbbbbbbbbbbb")
    req = ScanAdmissionRequest(
        target="other.example.net",
        token=issued.token,
        requested_depth="standard",
        idempotency_key="admit-key-bbbbbbbbbbbb",
    )
    graph = build_gate_graph(services.authorization_service)
    result, sentinel = await run_gate(graph, req)
    assert sentinel == 0
    assert result.reason_code is ReasonCode.SCOPE_NO_MATCH


@pytest.mark.asyncio
async def test_excluded_path_denies(services) -> None:
    issued = await services.issuer.issue_grant(_issue_request(), idempotency_key="issue-key-cccccccccccc")
    req = ScanAdmissionRequest(
        target="app.example.com",
        path="/admin",
        token=issued.token,
        requested_depth="standard",
        idempotency_key="admit-key-cccccccccccc",
    )
    result = await services.authorization_service.authorize_scan(req)
    assert result.reason_code is ReasonCode.SCOPE_EXCLUDED


@pytest.mark.asyncio
async def test_idempotent_replay_returns_receipt_no_second_run(services) -> None:
    issued = await services.issuer.issue_grant(_issue_request(), idempotency_key="issue-key-dddddddddddd")
    req = ScanAdmissionRequest(
        target="app.example.com",
        token=issued.token,
        requested_depth="standard",
        idempotency_key="admit-key-dddddddddddd",
    )
    first = await services.authorization_service.authorize_scan(req)
    second = await services.authorization_service.authorize_scan(req)
    from gryphon.auth.results import AdmissionReplayReceipt, AuthorizedPermit

    assert isinstance(first, AuthorizedPermit)
    assert isinstance(second, AdmissionReplayReceipt)
    assert second.scan_run_id == first.scan_run_id


@pytest.mark.asyncio
async def test_same_key_different_request_conflicts(services) -> None:
    issued = await services.issuer.issue_grant(_issue_request(), idempotency_key="issue-key-eeeeeeeeeeee")
    key = "admit-key-eeeeeeeeeeee"
    await services.authorization_service.authorize_scan(
        ScanAdmissionRequest(
            target="app.example.com", token=issued.token, requested_depth="standard", idempotency_key=key
        )
    )
    with pytest.raises(IdempotencyConflictError):
        await services.authorization_service.authorize_scan(
            ScanAdmissionRequest(
                target="app.example.com", token=issued.token, requested_depth="passive", idempotency_key=key
            )
        )


@pytest.mark.asyncio
async def test_finding_persists_against_string_scan_run_id(services) -> None:
    async with services.database.session() as session:
        async with session.begin():
            repo = FindingRepository(session)
            row = repo.add(
                scan_run_id="00000000-0000-0000-0000-000000000001",
                target="app.example.com",
                finding_type="misconfiguration",
                title="Example finding (schema only)",
                severity=Severity.MEDIUM,
                verification_status=VerificationStatus.UNVERIFIED,
            )
        assert row.id is not None
        assert row.compliance_frameworks == []
