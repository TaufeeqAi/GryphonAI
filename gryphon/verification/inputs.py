"""The verified input boundary: nothing is observed for an unverified finding.

Garbage in would be "verified" garbage out, so the admissible set is derived
from an attested artifact and never from a convenient table read. Four things
are checked before a single request is planned:

1. the base report's digest is **recomputed** from its stored body, not trusted;
2. a ``report_emitted`` event attests that digest under a signature this process
   can verify but **cannot produce**;
3. the scan reached a terminal state and did not fail on integrity;
4. consent still holds — the grant's signer key is still trusted, which is this
   platform's only revocation mechanism.

The second point is the one that changed in this revision and the one worth
stating plainly. The attestation is verified against the **orchestration
attestation** trust store, which holds a public key whose private half lives in
another process. If this layer held that private key, a compromise here would be
enough to fabricate a base report *and* mint the attestation that makes it look
genuine — a verifier marking its own homework. Key separation by identity does
not prevent that; key separation by custody does.

The enrichment report is treated differently on purpose. It is optional context
(it only orders work), so a failure to verify it drops the context and records
why. It never refuses a pass, and — since this revision — a *superseded* report
does not abandon one either: a routine upstream refresh is not a reason to throw
away traffic a client has already paid for.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from gryphon.auth.audit_signer import verify_audit_event
from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.verification.constants import (
    BASE_REPORT_EVENT_TYPE,
    INTEGRITY_FAILURE_REASONS,
    NON_TERMINAL_SCAN_STATES,
    SUPPORTED_BASE_REPORT_SCHEMA_VERSIONS,
    SUPPORTED_ENRICHMENT_REPORT_SCHEMA_VERSIONS,
    EnrichmentContext,
    RefusalReason,
)
from gryphon.verification.registry import Finding


@dataclass(frozen=True, slots=True)
class Refusal:
    """A pass that will not start, with a reason fit for a signed event."""

    reason: RefusalReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ReportRef:
    """A verified artifact this pass will cite by identity and digest."""

    report_id: str
    report_digest: str
    schema_version: str


@dataclass(frozen=True, slots=True)
class AttestedEvent:
    """One candidate attestation, as stored."""

    payload: dict[str, Any]
    payload_digest: str
    signer_kid: str
    signature_b64: str


@dataclass(frozen=True, slots=True)
class BaseReportMaterial:
    """Everything needed to verify a base report, read but not yet trusted."""

    scan_run_id: str
    report_id: str
    report_digest: str
    report_schema_version: str
    body: dict[str, Any]
    events: Sequence[AttestedEvent]


@dataclass(frozen=True, slots=True)
class EnrichmentMaterial:
    """The optional enrichment report, read but not yet trusted."""

    report_id: str
    report_digest: str
    report_schema_version: str
    body: dict[str, Any]
    events: Sequence[AttestedEvent]
    #: True when a newer COMPLETE enrichment report exists for this scan.
    superseded: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedInput:
    """The admissible set, plus context when it could be verified."""

    base: ReportRef
    findings: tuple[Finding, ...]
    enrichment: ReportRef | None
    priorities: dict[str, str]
    enrichment_context: EnrichmentContext
    terminal_state: str


def report_content_digest(body: dict[str, Any]) -> str:
    """The digest the orchestration layer computes, recomputed here.

    Same function, same canonicalization, deliberately re-implemented through
    the shared helper rather than imported from the orchestration package: that
    package carries a graph runtime whose dependency closure contains an HTTP
    client, and this layer must not be able to open a socket to a target even by
    accident.
    """
    return sha256_hex(canonical_json_bytes(body))


def _attested(
    *,
    digest: str,
    scan_run_id: str,
    events: Sequence[AttestedEvent],
    trust: TrustedKeyStore,
    event_type: str,
) -> bool:
    """Whether a signed event vouches for this exact digest.

    Each candidate is checked in full — the event's own payload digest, the scan
    it names, the digest it attests, and the signature — because any one of
    those passing alone proves nothing.
    """
    for event in events:
        payload = event.payload
        if payload.get("event_type") not in (None, event_type):
            continue
        if payload.get("report_digest") != digest:
            continue
        if payload.get("scan_run_id") != scan_run_id:
            continue
        if sha256_hex(canonical_json_bytes(payload)) != event.payload_digest:
            continue
        if verify_audit_event(payload, event.signature_b64, event.signer_kid, trust):
            return True
    return False


def verify_base_report(
    material: BaseReportMaterial, attestation_trust: TrustedKeyStore
) -> tuple[ReportRef, str, tuple[dict[str, Any], ...]] | Refusal:
    """Pure verification of the base report. Returns its ref, state and findings."""
    if material.report_schema_version not in SUPPORTED_BASE_REPORT_SCHEMA_VERSIONS:
        return Refusal(
            RefusalReason.REPORT_SCHEMA_UNSUPPORTED,
            f"report schema {material.report_schema_version!r} is not supported",
        )

    digest = report_content_digest(material.body)
    if digest != material.report_digest:
        return Refusal(RefusalReason.REPORT_UNVERIFIED, "report body does not match its digest")
    if material.body.get("scan_run_id") != material.scan_run_id:
        return Refusal(RefusalReason.REPORT_UNVERIFIED, "report body names a different scan")

    if not _attested(
        digest=digest,
        scan_run_id=material.scan_run_id,
        events=material.events,
        trust=attestation_trust,
        event_type=BASE_REPORT_EVENT_TYPE,
    ):
        return Refusal(
            RefusalReason.REPORT_UNVERIFIED,
            "no attestation with a trusted signature vouches for this report's digest",
        )

    terminal_state = material.body.get("terminal_state")
    if not isinstance(terminal_state, str) or terminal_state in NON_TERMINAL_SCAN_STATES:
        return Refusal(RefusalReason.SCAN_NOT_TERMINAL, f"scan state is {terminal_state!r}")

    reason_code = material.body.get("reason_code")
    integrity = material.body.get("integrity") or {}
    if not isinstance(integrity, dict):
        return Refusal(RefusalReason.REPORT_UNVERIFIED, "report integrity block is malformed")
    if reason_code in INTEGRITY_FAILURE_REASONS or integrity.get("failed") is True:
        return Refusal(RefusalReason.SCAN_INTEGRITY_FAILED, "the scan failed on integrity")

    raw_findings = material.body.get("findings")
    if not isinstance(raw_findings, list) or not all(
        isinstance(f, dict) and isinstance(f.get("finding_id"), str) for f in raw_findings
    ):
        return Refusal(RefusalReason.REPORT_UNVERIFIED, "report findings are malformed")

    ref = ReportRef(
        report_id=material.report_id,
        report_digest=digest,
        schema_version=material.report_schema_version,
    )
    return ref, terminal_state, tuple(raw_findings)


def verify_enrichment(
    material: EnrichmentMaterial | None,
    enrichment_trust: TrustedKeyStore,
    scan_run_id: str,
) -> tuple[ReportRef | None, dict[str, str], EnrichmentContext]:
    """Verify the optional context. Never refuses a pass.

    A superseded report is still valid and attested, so it is used and the fact
    is recorded. Abandoning a traffic-bearing pass because an upstream layer
    refreshed on its own schedule would mean re-sending observations that had
    already completed — paying twice, in traffic against a client's host, for an
    upstream event that changed nothing about the findings.
    """
    if material is None:
        return None, {}, EnrichmentContext.ABSENT

    if material.report_schema_version not in SUPPORTED_ENRICHMENT_REPORT_SCHEMA_VERSIONS:
        return None, {}, EnrichmentContext.UNVERIFIED

    digest = report_content_digest(material.body)
    if digest != material.report_digest:
        return None, {}, EnrichmentContext.UNVERIFIED
    if not _attested(
        digest=digest,
        scan_run_id=scan_run_id,
        events=material.events,
        trust=enrichment_trust,
        event_type="enrichment_report_emitted",
    ):
        return None, {}, EnrichmentContext.UNVERIFIED

    priorities = _priorities_from(material.body)
    ref = ReportRef(
        report_id=material.report_id,
        report_digest=digest,
        schema_version=material.report_schema_version,
    )
    context = (
        EnrichmentContext.SUPERSEDED if material.superseded else EnrichmentContext.VERIFIED
    )
    return ref, priorities, context


def _priorities_from(body: dict[str, Any]) -> dict[str, str]:
    """Pull finding_id -> priority out of a verified enrichment report body."""
    out: dict[str, str] = {}
    findings = body.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue
            finding_id = item.get("finding_id")
            priority = item.get("priority")
            if isinstance(finding_id, str) and isinstance(priority, str):
                out[finding_id] = priority
    return out


def findings_from(raw: Sequence[dict[str, Any]]) -> tuple[Finding, ...]:
    """Project the verified report body's findings into what this layer needs.

    Only fields with a defined meaning are carried forward. A finding whose
    canonical target is missing cannot be re-observed at all, so it is dropped
    here and surfaces as UNSUPPORTED rather than failing later at dispatch.
    """
    out: list[Finding] = []
    for item in raw:
        finding_id = item.get("finding_id")
        target = item.get("canonical_target")
        if not isinstance(finding_id, str) or not isinstance(target, str) or not target:
            continue
        observation = item.get("observation")
        template_id: str | None = None
        if isinstance(observation, dict):
            candidate = observation.get("template_id")
            if isinstance(candidate, str) and candidate:
                template_id = candidate
        port = item.get("port")
        out.append(
            Finding(
                finding_id=finding_id,
                observation_type=str(item.get("observation_type") or ""),
                canonical_target=target,
                template_id=template_id,
                url=(str(item["url"]) if isinstance(item.get("url"), str) else None),
                port=(int(port) if isinstance(port, int) else None),
                severity=(
                    str(item["severity"]) if isinstance(item.get("severity"), str) else None
                ),
            )
        )
    return tuple(out)
