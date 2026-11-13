"""The deliverable: body, identity, signed attestation, verification on read."""

from __future__ import annotations

import pytest

from gryphon.enrichment.audit import verify_event
from gryphon.enrichment.cve import extract_subjects
from gryphon.enrichment.derive import DerivationInputs, derive
from gryphon.enrichment.publish import (
    build_report_body,
    declared_limitations,
    manifest_digest,
    report_digest,
    report_id_for,
    verify_report,
)
from gryphon.enrichment.reader import verify_report_material
from gryphon.enrichment.reference import DatasetUnavailable
from tests.enrichment.conftest import NOW, SCAN_RUN_ID, nuclei_finding, report_body

pytestmark = pytest.mark.unit


@pytest.fixture
def published(policy, reference, make_material, audit_key, enrichment_audit):
    findings = [nuclei_finding("f1", cves=["CVE-2024-11111"], severity="low", cvss=9.8)]
    verified = verify_report_material(make_material(report_body(findings)), audit_key[1])
    extraction = extract_subjects(verified.findings)
    derivation = derive(
        DerivationInputs(
            subjects=tuple(extraction.subjects), kev=None, epss=None, reference=reference,
            template_snapshot_id="TEMPLATES:unpinned", policy=policy,
        )
    )
    manifest = {"pins": {"policy": policy.digest}}
    body = build_report_body(
        scan_run_id=SCAN_RUN_ID, pass_id="p1", initiated_by="cli:uid:1000", generated_at=NOW,
        verified=verified, derivation=derivation, extraction=extraction, policy=policy,
        sources_meta={}, manifest=manifest,
        limitations=declared_limitations(templates_pinned=False, posture="ENFORCED",
                                         reference=reference),
    )
    digest = report_digest(body)
    event = enrichment_audit.report_emitted(
        scan_run_id=SCAN_RUN_ID, pass_id="p1", report_id=report_id_for(SCAN_RUN_ID, digest),
        report_digest=digest, derivations_digest=derivation.digest,
        manifest_digest=manifest_digest(manifest), base_report_digest=verified.report_digest,
        outcome=derivation.outcome.value, initiated_by="cli:uid:1000", timestamp=NOW,
    )
    return body, digest, event, verified


def test_body_cites_the_base_report_and_never_claims_verification(published) -> None:
    body, _, _, verified = published
    assert body["kind"] == "ENRICHMENT"
    assert body["base_report"]["report_digest"] == verified.report_digest
    assert body["assurance"]["verification"] == "NOT_VERIFIED"
    assert "as observed when the scan ran" in body["assurance"]["base_report_enrichment_status"]
    assert body["outcome"] == "ENRICHMENT_DEGRADED"
    assert body["findings"][0]["elevated"] is False


def test_report_identity_is_derived_from_its_digest(published) -> None:
    _, digest, event, _ = published
    assert report_id_for(SCAN_RUN_ID, digest) == f"11111111-enr-{digest[:16]}"
    assert event.payload["report_id"].endswith(digest[:16])


def test_report_verifies_and_tamper_is_detected(published, enrichment_key) -> None:
    body, digest, event, _ = published
    trust = enrichment_key[1]
    kwargs = dict(event_payload=event.payload, event_payload_digest=event.payload_digest,
                  signer_kid=event.signer_kid, signature=event.signature_b64, trust=trust)
    assert verify_report(body=body, stored_digest=digest, **kwargs).verified

    tampered = dict(body, outcome="ENRICHED")
    result = verify_report(body=tampered, stored_digest=digest, **kwargs)
    assert not result.verified and "digest" in result.reason

    result = verify_report(body=body, stored_digest=digest, **{**kwargs, "event_payload": None})
    assert not result.verified and "attestation" in result.reason

    other = dict(event.payload, report_digest="0" * 64)
    result = verify_report(body=body, stored_digest=digest, **{**kwargs, "event_payload": other})
    assert not result.verified


def test_enrichment_events_verify_with_the_shared_verifier(
    enrichment_audit, enrichment_key
) -> None:
    event = enrichment_audit.snapshot_accepted(
        snapshot_id="KEV:x@sha256:" + "a" * 64, source="KEV", label="x", entry_count=1,
        model_version=None, initiated_by="cli:uid:0", timestamp=NOW,
    )
    assert event.payload["event_type"] == "snapshot_accepted"
    assert event.payload["occurred_at"] == NOW.isoformat()
    assert verify_event(payload=event.payload, payload_digest=event.payload_digest,
                        signer_kid=event.signer_kid, signature_b64=event.signature_b64,
                        trust=enrichment_key[1])


def test_declared_limitations_are_explicit(reference) -> None:
    limits = declared_limitations(templates_pinned=False, posture="UNENFORCED",
                                  reference=DatasetUnavailable("x"))
    assert "templates_unpinned" in limits
    assert "egress_posture=UNENFORCED" in limits
    assert "attack_reference_unavailable" in limits
    assert "nvd_not_used" in limits
    pinned = declared_limitations(templates_pinned=True, posture="ENFORCED", reference=reference)
    assert "templates_unpinned" not in pinned
    assert any(item.startswith("attack_coverage_kev_cves_only@") for item in pinned)
