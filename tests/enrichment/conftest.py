"""Shared fixtures for the enrichment layer tests.

Everything here is synthetic and offline: no DNS, no network, no real
intelligence. Database-backed tests live under ``integration/`` and are gated on
``GRYPHON_TEST_DATABASE_URL``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes
from gryphon.clock import FixedClock
from gryphon.enrichment.audit import EnrichmentAuditBuilder
from gryphon.enrichment.policy import Policy, load_policy
from gryphon.enrichment.reader import ReportMaterial, report_content_digest
from gryphon.enrichment.selfcheck import tiny_reference

NOW = datetime(2026, 11, 13, 9, 0, 0, tzinfo=UTC)
SCAN_RUN_ID = "11111111-2222-4333-8444-555555555555"
SYNTHETIC_MODEL = "v2026.06.15"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(instant=NOW)


@pytest.fixture(scope="session")
def policy() -> Policy:
    return load_policy()


@pytest.fixture
def enrichment_key() -> tuple[Ed25519SigningKey, TrustedKeyStore]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(kid="enrichment-test", _private=private)
    return signer, TrustedKeyStore({"enrichment-test": private.public_key()})


@pytest.fixture
def enrichment_audit(enrichment_key) -> EnrichmentAuditBuilder:
    return EnrichmentAuditBuilder(enrichment_key[0])


@pytest.fixture
def audit_key() -> tuple[Ed25519SigningKey, TrustedKeyStore]:
    """Stands in for the deployment's *audit* key (orchestration attestations)."""
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(kid="audit-test", _private=private)
    return signer, TrustedKeyStore({"audit-test": private.public_key()})


@pytest.fixture
def reference():
    return tiny_reference()


def nuclei_finding(
    finding_id: str,
    *,
    cves: Any,
    severity: str | None = "medium",
    cvss: Any = None,
    tags: tuple[str, ...] = (),
) -> dict[str, Any]:
    """A finding entry shaped exactly like the orchestration report's findings."""
    return {
        "finding_id": finding_id,
        "observation_type": "vulnerability",
        "canonical_target": "app.example.com",
        "title": f"synthetic {finding_id}",
        "severity": severity,
        "port": None,
        "url": "https://app.example.com/",
        "observation": {
            "template_id": f"synthetic-{finding_id}",
            "name": f"synthetic {finding_id}",
            "severity": severity,
            "matched_url": "https://app.example.com/",
            "description": "synthetic",
            "cve_ids": cves,
            "cvss_score": cvss,
            "tags": list(tags),
            "reference": [],
        },
        "verification_status": "NOT_VERIFIED",
        "enrichment_status": "NOT_PERFORMED",
        "provenance": {
            "execution_id": "exec-1",
            "audit_event_id": "evt-1",
            "stage": "vulnerability",
            "step": "nuclei",
            "tool_id": "nuclei",
        },
    }


def report_body(
    findings: list[dict[str, Any]],
    *,
    scan_run_id: str = SCAN_RUN_ID,
    terminal_state: str = "COMPLETED",
    reason_code: str | None = "OK",
    integrity_failed: bool = False,
    schema: str = "1",
) -> dict[str, Any]:
    """A base report body with the orchestration layer's shape."""
    return {
        "report_schema_version": schema,
        "graph_version": "1",
        "scan_run_id": scan_run_id,
        "generated_at": NOW.isoformat(),
        "initiated_by": "cli:uid:1000",
        "policy_version": "1",
        "terminal_state": terminal_state,
        "reason_code": reason_code,
        "coverage": {"planned": 1, "covered": 1},
        "assurance": {"verification": "NOT_VERIFIED", "enrichment": "NOT_PERFORMED"},
        "integrity": {
            "uncorroborated_findings_dropped": 0,
            "scope_disagreements": 0,
            "failed": integrity_failed,
        },
        "summary": {"observation_count": len(findings)},
        "findings": findings,
        "narrative": None,
        "compliance": [],
    }


def signed_report_event(
    signer: Ed25519SigningKey, *, scan_run_id: str, report_id: str, digest: str
) -> tuple[dict[str, Any], str, str, str]:
    """A ``report_emitted`` attestation signed exactly as the orchestration layer signs it."""
    from gryphon.orchestration.audit import OrchestrationAuditBuilder

    event = OrchestrationAuditBuilder(signer).report_emitted(
        scan_run_id=scan_run_id,
        report_id=report_id,
        report_digest=digest,
        report_schema_version="1",
        terminal_state="COMPLETED",
        covered=1,
        denominator=1,
        finding_count=1,
        claim_epoch=1,
        timestamp=NOW,
    )
    return event.payload, event.payload_digest, event.signer_kid, event.signature_b64


@pytest.fixture
def make_material(audit_key) -> Callable[..., ReportMaterial]:
    def _make(
        body: dict[str, Any],
        *,
        scan_run_id: str = SCAN_RUN_ID,
        sign: bool = True,
        digest: str | None = None,
        schema: str = "1",
        signer: Ed25519SigningKey | None = None,
    ) -> ReportMaterial:
        actual = report_content_digest(body)
        stored = digest or actual
        events: tuple[tuple[dict[str, Any], str, str, str], ...] = ()
        if sign:
            events = (
                signed_report_event(
                    signer or audit_key[0],
                    scan_run_id=scan_run_id,
                    report_id=f"{scan_run_id[:8]}-rpt-{stored[:16]}",
                    digest=stored,
                ),
            )
        return ReportMaterial(
            report_id=f"{scan_run_id[:8]}-rpt-{stored[:16]}",
            scan_run_id=scan_run_id,
            report_schema_version=schema,
            report_digest=stored,
            body=body,
            events=events,
        )

    return _make


def canonical_size(obj: Any) -> int:
    return len(canonical_json_bytes(obj))
