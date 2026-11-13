"""The base report is verified, never trusted — and the two layers agree on digests."""

from __future__ import annotations

import pytest

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.enrichment.constants import RefusalReason
from gryphon.enrichment.reader import (
    Refusal,
    VerifiedReport,
    report_content_digest,
    verify_report_material,
)
from tests.enrichment.conftest import SCAN_RUN_ID, nuclei_finding, report_body

pytestmark = pytest.mark.unit

FINDINGS = [nuclei_finding("f1", cves=["CVE-2021-44228"])]


def test_valid_report_verifies(make_material, audit_key) -> None:
    verified = verify_report_material(make_material(report_body(FINDINGS)), audit_key[1])
    assert isinstance(verified, VerifiedReport)
    assert verified.findings[0]["finding_id"] == "f1"
    assert verified.as_reference()["terminal_state"] == "COMPLETED"


def test_digest_matches_the_orchestration_layer() -> None:
    from gryphon.orchestration.identity import content_digest

    body = report_body(FINDINGS)
    assert report_content_digest(body) == content_digest(body)


def _refusal(result) -> RefusalReason:
    assert isinstance(result, Refusal), result
    return result.reason


def test_tampered_body_is_refused(make_material, audit_key) -> None:
    material = make_material(report_body(FINDINGS))
    material.body["findings"][0]["severity"] = "critical"
    result = verify_report_material(material, audit_key[1])
    assert _refusal(result) is RefusalReason.REPORT_UNVERIFIED


def test_unsigned_report_is_refused(make_material, audit_key) -> None:
    material = make_material(report_body(FINDINGS), sign=False)
    result = verify_report_material(material, audit_key[1])
    assert _refusal(result) is RefusalReason.REPORT_UNVERIFIED


def test_attestation_by_an_untrusted_key_is_refused(make_material, enrichment_key) -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    material = make_material(report_body(FINDINGS))
    other = TrustedKeyStore({"audit-test": ed25519.Ed25519PrivateKey.generate().public_key()})
    assert _refusal(verify_report_material(material, other)) is RefusalReason.REPORT_UNVERIFIED


def test_attestation_for_another_digest_is_refused(make_material, audit_key) -> None:
    body = report_body(FINDINGS)
    material = make_material(body)
    forged = make_material(report_body([]))  # signed, but for a different body
    mixed = type(material)(
        report_id=material.report_id, scan_run_id=material.scan_run_id,
        report_schema_version="1", report_digest=material.report_digest,
        body=body, events=forged.events,
    )
    assert _refusal(verify_report_material(mixed, audit_key[1])) is RefusalReason.REPORT_UNVERIFIED


def test_body_naming_another_scan_is_refused(make_material, audit_key) -> None:
    body = report_body(FINDINGS, scan_run_id="99999999-2222-4333-8444-555555555555")
    material = make_material(body)  # stored under SCAN_RUN_ID
    assert material.scan_run_id == SCAN_RUN_ID
    result = verify_report_material(material, audit_key[1])
    assert _refusal(result) is RefusalReason.REPORT_UNVERIFIED


def test_unsupported_schema_is_refused(make_material, audit_key) -> None:
    material = make_material(report_body(FINDINGS, schema="2"), schema="2")
    assert _refusal(verify_report_material(material, audit_key[1])) is (
        RefusalReason.REPORT_SCHEMA_UNSUPPORTED
    )


@pytest.mark.parametrize("state", ["RUNNING", "RECONCILING", "HALTED_FOR_REVIEW"])
def test_non_terminal_scan_is_refused(make_material, audit_key, state: str) -> None:
    material = make_material(report_body(FINDINGS, terminal_state=state))
    result = verify_report_material(material, audit_key[1])
    assert _refusal(result) is RefusalReason.SCAN_NOT_TERMINAL


@pytest.mark.parametrize(
    ("reason_code", "failed"),
    [("SCAN_INTEGRITY_FAILURE", False), ("SCOPE_DISAGREEMENT", False), ("OK", True)],
)
def test_integrity_failure_is_refused(make_material, audit_key, reason_code, failed) -> None:
    body = report_body(FINDINGS, terminal_state="FAILED", reason_code=reason_code,
                       integrity_failed=failed)
    assert _refusal(verify_report_material(make_material(body), audit_key[1])) is (
        RefusalReason.SCAN_INTEGRITY_FAILED
    )


@pytest.mark.parametrize(
    "state", ["COMPLETED_WITH_GAPS", "ABORTED_DEADLINE", "HALTED_UNAUTHORIZED"]
)
def test_terminal_non_clean_states_are_enrichable(make_material, audit_key, state: str) -> None:
    material = make_material(report_body(FINDINGS, terminal_state=state, reason_code="X"))
    assert isinstance(verify_report_material(material, audit_key[1]), VerifiedReport)


def test_malformed_findings_are_refused(make_material, audit_key) -> None:
    body = report_body(FINDINGS)
    body["findings"] = [{"no_id": True}]
    assert _refusal(verify_report_material(make_material(body), audit_key[1])) is (
        RefusalReason.REPORT_UNVERIFIED
    )
