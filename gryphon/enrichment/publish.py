"""The enrichment deliverable: report body, identity, attestation and verification.

The enrichment report is a separate artifact. It cites the base scan report by
id and digest and never modifies it; the base report remains the default
deliverable. Its digest is attested by an ``enrichment_report_emitted`` event
signed with the dedicated enrichment key, and :func:`verify_report` re-checks
both before a report is ever served.

The body states the *effective* enrichment assurance. It cites the base
report's ``NOT_PERFORMED`` as what was observed when the scan ran — evidence
status columns are never read as current.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import ensure_utc
from gryphon.enrichment.audit import verify_event
from gryphon.enrichment.constants import ENRICHMENT_REPORT_SCHEMA_VERSION, PassOutcome
from gryphon.enrichment.cve import ExtractionResult
from gryphon.enrichment.derive import Derivation
from gryphon.enrichment.policy import Policy
from gryphon.enrichment.reader import VerifiedReport
from gryphon.enrichment.reference import DatasetUnavailable, ReferenceData


def manifest_digest(manifest: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(manifest))


def report_digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def declared_limitations(
    *,
    templates_pinned: bool,
    posture: str,
    reference: ReferenceData | DatasetUnavailable,
) -> list[str]:
    """Structural limits stated in every report, so readers cannot assume more."""
    limits = [
        "cvss_is_template_asserted",
        "nvd_not_used",
        "severity_filter_upstream",
        "cvss_vector_unavailable",
        f"egress_posture={posture}",
    ]
    if isinstance(reference, ReferenceData):
        limits.append(f"attack_coverage_kev_cves_only@{reference.mapping_version}")
    else:
        limits.append("attack_reference_unavailable")
    if not templates_pinned:
        limits.append("templates_unpinned")
    return sorted(limits)


def build_report_body(
    *,
    scan_run_id: str,
    pass_id: str,
    initiated_by: str,
    generated_at: datetime,
    verified: VerifiedReport,
    derivation: Derivation,
    extraction: ExtractionResult,
    policy: Policy,
    sources_meta: dict[str, Any],
    manifest: dict[str, Any],
    limitations: list[str],
) -> dict[str, Any]:
    by_finding: dict[str, dict[str, Any]] = {}
    for a in derivation.assertions:
        by_finding.setdefault(a.finding_id, {})[a.source] = {
            "status": a.status,
            "reason": a.reason,
            "value": a.value,
            "snapshot_id": a.snapshot_id,
            "asserted_by": a.asserted_by,
        }
    findings = [
        {
            "finding_id": p.finding_id,
            "observed_severity": p.observed_severity,
            "priority": p.priority,
            "elevated": p.priority != p.observed_severity,
            "rationale": list(p.rationale),
            "sources": by_finding.get(p.finding_id, {}),
        }
        for p in derivation.priorities
    ]
    performed = derivation.outcome is not PassOutcome.NOTHING_TO_ENRICH
    return {
        "enrichment_report_schema_version": ENRICHMENT_REPORT_SCHEMA_VERSION,
        "kind": "ENRICHMENT",
        "scan_run_id": scan_run_id,
        "pass_id": pass_id,
        "generated_at": ensure_utc(generated_at).isoformat(),
        "initiated_by": initiated_by,
        "base_report": verified.as_reference(),
        "assurance": {
            "enrichment": "PERFORMED" if performed else "NOTHING_TO_ENRICH",
            "verification": "NOT_VERIFIED",
            "base_report_enrichment_status": "NOT_PERFORMED (as observed when the scan ran)",
            "statement": (
                "Public intelligence attributed to accepted snapshots and pinned reference data. "
                "Priorities are advisory and derived; evidence is unchanged."
            ),
        },
        "outcome": derivation.outcome.value,
        "policy": {"digest": policy.digest, "label": policy.label},
        "sources": sources_meta,
        "coverage": derivation.coverage,
        "extraction": extraction.as_payload(),
        "declared_limitations": limitations,
        "derivations_digest": derivation.digest,
        "manifest": manifest,
        "findings": findings,
    }


def report_id_for(scan_run_id: str, digest: str) -> str:
    return f"{scan_run_id[:8]}-enr-{digest[:16]}"


@dataclass(frozen=True)
class ReportVerification:
    verified: bool
    reason: str | None


def verify_report(
    *,
    body: dict[str, Any],
    stored_digest: str,
    event_payload: dict[str, Any] | None,
    event_payload_digest: str | None,
    signer_kid: str | None,
    signature: str | None,
    trust: TrustedKeyStore,
) -> ReportVerification:
    """Recompute the report digest and verify its signed attestation."""
    digest = report_digest(body)
    if digest != stored_digest:
        return ReportVerification(False, "report body does not match its digest")
    if event_payload is None or event_payload_digest is None or not signer_kid or not signature:
        return ReportVerification(False, "no attestation event")
    if event_payload.get("report_digest") != digest:
        return ReportVerification(False, "attestation names a different digest")
    if not verify_event(
        payload=event_payload,
        payload_digest=event_payload_digest,
        signer_kid=signer_kid,
        signature_b64=signature,
        trust=trust,
    ):
        return ReportVerification(False, "attestation signature does not verify")
    return ReportVerification(True, None)
