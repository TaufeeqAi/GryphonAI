"""The enrichment layer against a live PostgreSQL — migrations, privileges, passes.

A fake acquisition launcher (running the real acceptance code on synthetic
files) and a stub resolver stand in for the network, so nothing leaves the host.
Everything else is real: the migration, the append-only triggers, the dedicated
role's privileges, the slot lease, the fenced pass, the verified base report
(signed by the audit key exactly as the orchestration layer signs it), the
signed enrichment report and the read view.

WARNING: like every DB-gated suite here, this resets the schema of
``GRYPHON_TEST_DATABASE_URL`` (downgrade base → upgrade head).
"""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from gryphon.auth.claims import IssuanceRequest
from gryphon.auth.key_provider import Ed25519SigningKey
from gryphon.auth.scope import ScopeEntry
from gryphon.auth.service import ScanAdmissionRequest
from gryphon.bootstrap import build_services
from gryphon.clock import SystemClock
from gryphon.constants import ScanDepth, TargetType
from gryphon.db.models import (
    AcquisitionAttempt,
    EgressLedger,
    EnrichmentAudit,
    EnrichmentPass,
    OrchestrationAudit,
    RawFinding,
    ScanReport,
)
from gryphon.enrichment.acquisition import __main__ as child
from gryphon.enrichment.acquisition.acceptance import LastAccepted, accept_epss, accept_kev
from gryphon.enrichment.bootstrap import EnrichmentServices, build_enrichment_services
from gryphon.enrichment.constants import PassState
from gryphon.enrichment.identity import CallerIdentity
from gryphon.enrichment.readiness import check_enrichment_readiness
from gryphon.enrichment.reasons import SlotBusy
from gryphon.enrichment.repository import EnrichmentRepository
from gryphon.enrichment.selfcheck import synthetic_epss_file, synthetic_kev_catalog, tiny_reference
from gryphon.enrichment.settings import EnrichmentSettings
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.identity import content_digest
from gryphon.settings import Settings
from gryphon.tooling.destination.egress import EgressHandle
from gryphon.tooling.settings import ToolingSettings
from tests.enrichment.conftest import nuclei_finding, report_body

_OWNER_URL = os.environ.get("GRYPHON_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_OWNER_URL is None, reason="GRYPHON_TEST_DATABASE_URL not set"),
]

CALLER = CallerIdentity(uid=1000, label="cli:uid:1000")
PINNED = "93.184.216.34"


def _hex(key: ed25519.Ed25519PrivateKey) -> tuple[str, str]:
    return (
        key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                          serialization.NoEncryption()).hex(),
        key.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw).hex(),
    )


@pytest.fixture(scope="module")
def keyset() -> dict[str, str]:
    out: dict[str, str] = {}
    for name in ("grant", "audit", "enrichment"):
        out[f"{name}_priv"], out[f"{name}_pub"] = _hex(ed25519.Ed25519PrivateKey.generate())
    return out


@pytest.fixture(scope="module")
def workdir(tmp_path_factory) -> Path:
    """One artifact store for the module: snapshots outlive a single test."""
    return tmp_path_factory.mktemp("enrichment")


@pytest.fixture(scope="module")
def _migrated() -> None:
    from alembic import command
    from alembic.config import Config

    os.environ["GRYPHON_MIGRATION_DATABASE_URL"] = _OWNER_URL  # type: ignore[assignment]
    os.environ["GRYPHON_DATABASE_URL"] = _OWNER_URL  # type: ignore[assignment]
    from gryphon.settings import get_settings

    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", "gryphon/db/migrations")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


def _core(keyset: dict[str, str], *, trust_grant: bool = True) -> Settings:
    grant_trust = {"grant-test": keyset["grant_pub"]} if trust_grant else {
        "grant-rotated": _hex(ed25519.Ed25519PrivateKey.generate())[1]
    }
    return Settings(
        _env_file=None,
        environment="test",
        issuer="gryphon-test-issuer",
        audience="gryphon-test-audience",
        grant_signing_key_hex=keyset["grant_priv"] if trust_grant else None,
        grant_kid="grant-test" if trust_grant else None,
        grant_trusted_public_keys=grant_trust,
        audit_signing_key_hex=keyset["audit_priv"],
        audit_kid="audit-test",
        audit_trusted_public_keys={"audit-test": keyset["audit_pub"]},
        database_url=_OWNER_URL,
        migration_database_url=_OWNER_URL,
    )


# -- doubles ----------------------------------------------------------------------
class _Resolver:
    async def resolve(self, host: str):
        return [ipaddress.ip_address(PINNED)]


class _Egress:
    enforcing = True

    async def establish(self, allowlist, ports):
        return EgressHandle(context_id="test", allowlist=tuple(allowlist), ports=tuple(ports),
                            enforcing=True)

    async def teardown(self, handle):
        return None


class FakeLauncher:
    """Runs the real acceptance code on synthetic files instead of downloading.

    Each instance publishes a *newer* KEV catalog (snapshots are content-addressed
    and a revoked snapshot stays revoked, so tests sharing the database need
    distinct catalogs to stay independent of order).
    """

    _generation = itertools.count(0)

    def __init__(self) -> None:
        day = 10 + next(self._generation)
        self.payloads: dict[str, bytes | None] = {
            "KEV": synthetic_kev_catalog(
                include=("CVE-2024-11111",),
                catalog_version=f"2026.10.{day:02d}",
                date_released=f"2026-10-{day:02d}T15:00:00Z",
            ),
            "EPSS": synthetic_epss_file(overrides={"CVE-2024-22222": (0.75, 0.97)}),
        }
        self.runs = 0

    async def run(self, request: dict[str, Any], staging: Path) -> dict[str, Any]:
        self.runs += 1
        assert set(request["addresses"]) <= {"www.cisa.gov", "epss.empiricalsecurity.com"}
        results: dict[str, Any] = {}
        for source in request["sources"]:
            raw = self.payloads.get(source)
            record = {"host": "www.cisa.gov" if source == "KEV" else "epss.empiricalsecurity.com",
                      "path": "/synthetic", "address": PINNED, "started_at": "t0",
                      "finished_at": "t1", "status": 200 if raw else 503,
                      "bytes_received": len(raw or b""),
                      "outcome_class": "OK" if raw else "TRANSIENT", "detail": None}
            if raw is None:
                results[source] = {"status": "rejected", "reason": "http 503",
                                   "remediation_class": "TRANSIENT", "requests": [record]}
                continue
            last = LastAccepted.from_payload(request["last"].get(source))
            accepted = accept_kev(raw, last) if source == "KEV" else accept_epss(raw, last)
            files = child._write(staging, accepted, raw)
            results[source] = {
                "status": "accepted", "label": accepted.label, "order_key": accepted.order_key,
                "entry_count": accepted.entry_count, "byte_size": accepted.byte_size,
                "content_sha256": accepted.content_sha256,
                "normalized_sha256": accepted.normalized_sha256,
                "fetched_from": record["host"], "requests": [record], **files,
            }
        return {"format_version": "1", "results": results}


def _services(keyset, tmp_path: Path, launcher: FakeLauncher, *, trust_grant: bool = True,
              reference=True) -> EnrichmentServices:
    es = EnrichmentSettings(
        _env_file=None,
        database_url=_OWNER_URL,
        signing_key_hex=keyset["enrichment_priv"],
        kid="enrichment-test",
        trusted_public_keys={"enrichment-test": keyset["enrichment_pub"]},
        artifact_dir=tmp_path / "artifacts",
        reference_dir=tmp_path / "reference",
    )
    return build_enrichment_services(
        settings=_core(keyset, trust_grant=trust_grant),
        enrichment_settings=es,
        tooling_settings=ToolingSettings(_env_file=None, environment="test"),
        enforcer=_Egress(),
        launcher=launcher,
        resolver=_Resolver(),
        reference_loader=(lambda: tiny_reference()) if reference else None,
    )


async def _admit_and_report(keyset, *, findings: list[dict[str, Any]], tamper: bool = False) -> str:
    """Admit a scan through the real authorization core; record evidence and its report."""
    services = build_services(_core(keyset), clock=SystemClock())
    try:
        now = services.clock.now()
        issued = await services.issuer.issue_grant(
            IssuanceRequest(
                organization="GRYPHON Enrichment Tests",
                granted_by="operator@example.com",
                granted_to="tester@example.com",
                scope=(ScopeEntry(target_type=TargetType.DOMAIN, target="app.example.com"),),
                issued_at=now, not_before=now, expires_at=now + timedelta(hours=2),
                max_scan_depth=ScanDepth.STANDARD,
                written_authorization_ref="SOW-enrichment-tests",
            ),
            idempotency_key=secrets.token_hex(16),
        )
        admitted = await services.authorization_service.authorize_scan(
            ScanAdmissionRequest(target="app.example.com", token=issued.token,
                                 requested_depth="standard",
                                 idempotency_key=secrets.token_hex(16))
        )
        scan_run_id = admitted.scan_run_id
        rows = []
        for finding in findings:
            finding["finding_id"] = hashlib.sha256(
                f"{scan_run_id}|{finding['finding_id']}".encode()
            ).hexdigest()[:48]
            rows.append(RawFinding(
                finding_id=finding["finding_id"], scan_run_id=scan_run_id,
                execution_id=f"exec-{finding['finding_id'][:8]}", audit_event_id=None,
                plan_item_id="plan-1", stage="vulnerability", step="nuclei", tool_id="nuclei",
                finding_key=finding["finding_id"][:32], canonical_target="app.example.com",
                observation_type="vulnerability", observation=finding["observation"],
                severity=finding["severity"], title=finding["title"],
            ))
        body = report_body(findings, scan_run_id=scan_run_id)
        digest = content_digest(body)
        report_id = f"{scan_run_id[:8]}-rpt-{digest[:16]}"
        signer = Ed25519SigningKey(
            kid="audit-test",
            _private=ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keyset["audit_priv"])),
        )
        event = OrchestrationAuditBuilder(signer).report_emitted(
            scan_run_id=scan_run_id, report_id=report_id, report_digest=digest,
            report_schema_version="1", terminal_state="COMPLETED", covered=1, denominator=1,
            finding_count=len(findings), claim_epoch=1, timestamp=now,
        )
        stored_body = dict(body, summary={"observation_count": 999}) if tamper else body
        async with services.database.session() as session, session.begin():
            session.add_all(rows)
            await session.flush()
            session.add(ScanReport(
                report_id=report_id, scan_run_id=scan_run_id, report_schema_version="1",
                report_digest=digest, body=stored_body, terminal_state="COMPLETED", covered=1,
                denominator=1, finding_count=len(findings), audit_event_id=event.event_id,
            ))
            session.add(OrchestrationAudit(
                event_id=event.event_id, event_type=event.event_type,
                event_schema_version=str(event.payload["event_schema_version"]),
                scan_run_id=scan_run_id, payload=event.payload,
                payload_digest=event.payload_digest, signer_kid=event.signer_kid,
                signature=event.signature_b64,
            ))
        return scan_run_id
    finally:
        await services.database.dispose()


def _findings() -> list[dict[str, Any]]:
    return [
        nuclei_finding("f-kev", cves=["cve-2024-11111"], severity="low", cvss=9.8),
        nuclei_finding("f-epss", cves=list("CVE-2024-22222"), severity="medium"),
        nuclei_finding("f-none", cves=["CVE-2024-33333"], severity="high"),
    ]


# -- tests --------------------------------------------------------------------------
async def test_readiness_facts_hold_after_migration(keyset, _migrated, workdir) -> None:
    services = _services(keyset, workdir, FakeLauncher())
    try:
        report = await check_enrichment_readiness(services)
    finally:
        await services.dispose()
    checks = {c.name: c for c in report.checks}
    for name in ("database_reachable", "schema_present", "append_only_triggers_enabled",
                 "trigger_functions_unaltered", "role_privileges_exact", "slot_seeded"):
        assert checks[name].passed, (name, checks[name].detail)


async def test_end_to_end_pass_is_attested_and_explained(keyset, _migrated, workdir) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings())
    launcher = FakeLauncher()
    services = _services(keyset, workdir, launcher)
    try:
        result = await services.engine.run_pass(scan_run_id, caller=CALLER)
        assert result.state == "COMPLETE", result
        assert result.outcome == "ENRICHED"
        assert set(result.acquisitions) == {"KEV", "EPSS"}
        assert all(v["acquired"] == "ACCEPTED" for v in result.acquisitions.values())

        served = await services.engine.report(scan_run_id)
        assert served is not None and served.verification.verified
        by_priority = {f["observed_severity"]: f["priority"] for f in served.body["findings"]}
        assert by_priority == {"LOW": "CRITICAL", "MEDIUM": "HIGH", "HIGH": "HIGH"}
        assert served.body["base_report"]["report_digest"]

        async with services.database.session() as session:
            view = (await session.execute(
                text("SELECT finding_id, priority, sources FROM finding_enrichment_view "
                     "WHERE scan_run_id = :s"), {"s": scan_run_id})).all()
            assert len(view) == 3
            assert all(set(row.sources) == {"KEV", "EPSS", "CVSS_TEMPLATE", "ATTACK_CTID"}
                       for row in view)
            ledger = (await session.execute(select(EgressLedger))).scalars().all()
            assert {row.address for row in ledger} == {PINNED}
            events = (await session.execute(select(EnrichmentAudit.event_type))).scalars().all()
            assert {"snapshot_accepted", "enrichment_report_emitted"} <= set(events)
            evidence = (await session.execute(
                select(RawFinding.enrichment_status).where(RawFinding.scan_run_id == scan_run_id)
            )).scalars().all()
            # Evidence is never written: its status still says what the scan observed.
            assert set(evidence) == {"NOT_PERFORMED"}

        # A second pass needs no acquisition (snapshots are fresh) and supersedes in the view.
        again = await services.engine.run_pass(scan_run_id, caller=CALLER)
        assert again.state == "COMPLETE" and again.acquisitions == {}
        assert launcher.runs == 1
        status = await services.engine.status(scan_run_id)
        assert [p["state"] for p in status["scan"]["passes"]] == ["COMPLETE", "COMPLETE"]
        assert status["scan"]["latest_report"]["pass_id"] == again.pass_id
    finally:
        await services.dispose()


async def test_failure_is_staleness_and_revocation_is_degradation(
    keyset, _migrated, workdir
) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings())
    launcher = FakeLauncher()
    services = _services(keyset, workdir, launcher)
    try:
        assert (await services.engine.run_pass(scan_run_id, caller=CALLER)).outcome == "ENRICHED"
        launcher.payloads = {"KEV": None, "EPSS": None}
        summary = await services.engine.refresh(caller=CALLER)
        assert {v.acquired for v in summary.statuses.values()} == {"REJECTED"}
        # A failed refresh writes nothing: the pass derives against what was accepted.
        assert (await services.engine.run_pass(scan_run_id, caller=CALLER)).outcome == "ENRICHED"

        status = await services.engine.status()
        kev_id = status["sources"]["KEV"]["snapshot_id"]
        assert await services.engine.revoke_snapshot(kev_id, reason="test", caller=CALLER)
        assert not await services.engine.revoke_snapshot(kev_id, reason="again", caller=CALLER)
        degraded = await services.engine.run_pass(scan_run_id, caller=CALLER)
        assert degraded.outcome == "ENRICHMENT_DEGRADED"
        served = await services.engine.report(scan_run_id)
        kev = [f["sources"]["KEV"] for f in served.body["findings"]]
        assert {k["status"] for k in kev} == {"UNAVAILABLE"}
        async with services.database.session() as session:
            attempts = (await session.execute(select(AcquisitionAttempt.result))).scalars().all()
            assert "REJECTED" in attempts
    finally:
        await services.dispose()


async def test_untrusted_grant_signer_is_refused_and_audited(keyset, _migrated, workdir) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings())
    services = _services(keyset, workdir, FakeLauncher(), trust_grant=False)
    try:
        result = await services.engine.run_pass(scan_run_id, caller=CALLER)
        assert result.state == "REFUSED" and result.reason == "grant_signer_untrusted"
        async with services.database.session() as session:
            row = await session.get(EnrichmentPass, result.pass_id)
            assert row.state == "REFUSED"
            events = (await session.execute(
                select(EnrichmentAudit.event_type).where(EnrichmentAudit.pass_id == result.pass_id)
            )).scalars().all()
            assert events == ["pass_refused"]
    finally:
        await services.dispose()


async def test_tampered_base_report_is_refused(keyset, _migrated, workdir) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings(), tamper=True)
    services = _services(keyset, workdir, FakeLauncher())
    try:
        result = await services.engine.run_pass(scan_run_id, caller=CALLER)
        assert result.state == "REFUSED" and result.reason == "report_unverified"
    finally:
        await services.dispose()


async def test_slot_is_single_flight(keyset, _migrated, workdir) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings())
    services = _services(keyset, workdir, FakeLauncher())
    try:
        async with services.database.session() as session, session.begin():
            epoch = await EnrichmentRepository(session).claim_slot("someone-else", 300)
        assert epoch is not None
        with pytest.raises(SlotBusy):
            await services.engine.run_pass(scan_run_id, caller=CALLER)
        async with services.database.session() as session, session.begin():
            await EnrichmentRepository(session).release_slot("someone-else", epoch)
    finally:
        await services.dispose()


async def test_crashed_pass_resumes_from_its_pins_and_old_holder_is_fenced(
    keyset, _migrated, workdir, monkeypatch
) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings())
    services = _services(keyset, workdir, FakeLauncher())
    try:
        engine = services.engine

        async def crash(*args, **kwargs):
            raise RuntimeError("simulated crash after pinning")

        monkeypatch.setattr(engine, "_publish", crash)
        with pytest.raises(RuntimeError):
            await engine.run_pass(scan_run_id, caller=CALLER)
        monkeypatch.undo()

        async with services.database.session() as session:
            (stuck,) = (await session.execute(
                select(EnrichmentPass).where(EnrichmentPass.scan_run_id == scan_run_id)
            )).scalars().all()
        assert stuck.state == "RUNNING" and stuck.pins["KEV"]["snapshot_id"]
        old_epoch = stuck.claim_epoch

        resumed = await engine.run_pass(scan_run_id, caller=CALLER)
        assert resumed.state == "COMPLETE" and resumed.resumed
        assert resumed.pass_id == stuck.pass_id

        async with services.database.session() as session, session.begin():
            row = await session.get(EnrichmentPass, stuck.pass_id)
            assert row.pins == stuck.pins  # the same pins, never re-chosen
            assert row.claim_epoch > old_epoch
            fenced = await EnrichmentRepository(session).transition_pass(
                stuck.pass_id, epoch=old_epoch, expected_states=(PassState.COMPLETE,),
                state="ABANDONED",
            )
            assert fenced is False
    finally:
        await services.dispose()


async def test_operator_abort_of_a_dead_pass(keyset, _migrated, workdir, monkeypatch) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings())
    services = _services(keyset, workdir, FakeLauncher())
    try:
        async def crash(*args, **kwargs):
            raise RuntimeError("simulated crash")

        monkeypatch.setattr(services.engine, "_publish", crash)
        with pytest.raises(RuntimeError):
            await services.engine.run_pass(scan_run_id, caller=CALLER)
        monkeypatch.undo()
        result = await services.engine.abort(scan_run_id, caller=CALLER, detail="test abort")
        assert result is not None and result.state == "ABANDONED"
        assert result.reason == "operator_abort"
        assert await services.engine.abort(scan_run_id, caller=CALLER) is None
    finally:
        await services.dispose()


async def test_append_only_tables_reject_mutation(keyset, _migrated, workdir) -> None:
    scan_run_id = await _admit_and_report(keyset, findings=_findings())
    services = _services(keyset, workdir, FakeLauncher())
    try:
        await services.engine.run_pass(scan_run_id, caller=CALLER)
        for statement in (
            "UPDATE intel_snapshot SET label = 'x'",
            "DELETE FROM finding_enrichment",
            "UPDATE finding_priority SET priority = 'LOW'",
            "DELETE FROM enrichment_audit",
            "TRUNCATE enrichment_report CASCADE",
            "DELETE FROM enrichment_pass",
        ):
            async with services.database.session() as session:
                with pytest.raises(DBAPIError):
                    async with session.begin():
                        await session.execute(text(statement))
    finally:
        await services.dispose()


async def test_dedicated_role_cannot_write_upstream_or_delete(keyset, _migrated, workdir) -> None:
    services = _services(keyset, workdir, FakeLauncher())
    try:
        # The allowed reads first: if the test role cannot assume the enrichment
        # role, every "permission denied" below would pass for the wrong reason.
        async with services.database.session() as session:
            try:
                async with session.begin():
                    await session.execute(text("SET LOCAL ROLE gryphon_enrichment"))
                    await session.execute(text("SELECT count(*) FROM raw_finding"))
                    await session.execute(text("SELECT count(*) FROM finding_enrichment_view"))
            except DBAPIError as exc:
                pytest.skip(f"cannot assume gryphon_enrichment here: {exc}")
        for statement in (
            "UPDATE raw_finding SET enrichment_status = 'ENRICHED'",
            "INSERT INTO scan_report (report_id) VALUES ('x')",
            "DELETE FROM intel_snapshot",
            "UPDATE enrichment_pass SET scan_run_id = scan_run_id",
            "CREATE TABLE enrichment_backdoor (id int)",
        ):
            async with services.database.session() as session:
                with pytest.raises(DBAPIError, match="permission denied"):
                    async with session.begin():
                        await session.execute(text("SET LOCAL ROLE gryphon_enrichment"))
                        await session.execute(text(statement))
    finally:
        await services.dispose()
