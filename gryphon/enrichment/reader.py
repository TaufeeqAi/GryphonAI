"""Report reader & verifier: the only way evidence enters this layer.

Before anything is derived, the base scan report is verified here rather than
trusted:

1. its ``report_schema_version`` must be one this layer understands;
2. its body is re-digested (RFC 8785 canonical JSON, SHA-256) and must equal the
   stored ``report_digest``;
3. a ``report_emitted`` audit event for the scan must carry that digest, its
   payload must match its own recorded digest, and its signature must verify
   against the deployment's trusted audit keys;
4. the scan must not have failed on integrity, and must be terminal;
5. the grant behind the scan must still be signed by a *trusted* key — removing
   a signer from the trust store is the system's revocation mechanism, so a
   revoked engagement is never processed further.

The admissible findings are exactly those in the verified body. The evidence
table is never consulted to decide what to enrich: a row the report rejected for
lack of provenance must not reappear here.

The pure core (:func:`verify_report_material`) takes plain values so it can be
tested exhaustively without a database.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.auth.audit_signer import verify_audit_event
from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.db.models import AuthorizationGrant, OrchestrationAudit, ScanReport, ScanRun
from gryphon.enrichment.constants import (
    BASE_REPORT_EVENT_TYPE,
    INTEGRITY_FAILURE_REASONS,
    NON_TERMINAL_SCAN_STATES,
    SUPPORTED_BASE_REPORT_SCHEMA_VERSIONS,
    RefusalReason,
)


def report_content_digest(body: dict[str, Any]) -> str:
    """The report digest: SHA-256 over the RFC 8785 canonical body.

    Identical to the orchestration layer's ``content_digest`` (pinned by test);
    re-implemented here so this process never imports that package.
    """
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


@dataclass(frozen=True)
class ReportMaterial:
    """Plain values loaded from the base report row and its attestations."""

    report_id: str
    scan_run_id: str
    report_schema_version: str
    report_digest: str
    body: dict[str, Any]
    #: Candidate attestations: (payload, payload_digest, signer_kid, signature).
    events: tuple[tuple[dict[str, Any], str, str, str], ...]


@dataclass(frozen=True)
class VerifiedReport:
    report_id: str
    report_digest: str
    scan_run_id: str
    report_schema_version: str
    terminal_state: str
    reason_code: str | None
    findings: tuple[dict[str, Any], ...]

    def as_reference(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "report_digest": self.report_digest,
            "report_schema_version": self.report_schema_version,
            "terminal_state": self.terminal_state,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class Refusal:
    reason: RefusalReason
    detail: str


def verify_report_material(
    material: ReportMaterial, audit_trust: TrustedKeyStore
) -> VerifiedReport | Refusal:
    """Pure verification of a base report and its signed attestation."""
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

    attested = False
    for payload, payload_digest, signer_kid, signature in material.events:
        if payload.get("report_digest") != digest:
            continue
        if payload.get("scan_run_id") != material.scan_run_id:
            continue
        if sha256_hex(canonical_json_bytes(payload)) != payload_digest:
            continue
        if verify_audit_event(payload, signature, signer_kid, audit_trust):
            attested = True
            break
    if not attested:
        return Refusal(
            RefusalReason.REPORT_UNVERIFIED,
            "no report_emitted event with a valid signature attests this report's digest",
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

    findings = material.body.get("findings")
    if not isinstance(findings, list) or not all(
        isinstance(f, dict) and isinstance(f.get("finding_id"), str) for f in findings
    ):
        return Refusal(RefusalReason.REPORT_UNVERIFIED, "report findings are malformed")
    return VerifiedReport(
        report_id=material.report_id,
        report_digest=digest,
        scan_run_id=material.scan_run_id,
        report_schema_version=material.report_schema_version,
        terminal_state=terminal_state,
        reason_code=reason_code if isinstance(reason_code, str) else None,
        findings=tuple(findings),
    )


class ReportReader:
    """Loads, verifies and consent-checks a scan's base report."""

    def __init__(self, *, audit_trust: TrustedKeyStore, grant_trust: TrustedKeyStore) -> None:
        self._audit_trust = audit_trust
        self._grant_trust = grant_trust

    async def load_material(self, session: AsyncSession, scan_run_id: str) -> ReportMaterial | None:
        row = (
            await session.execute(
                select(ScanReport)
                .where(ScanReport.scan_run_id == scan_run_id)
                .order_by(ScanReport.generated_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        events = (
            await session.execute(
                select(OrchestrationAudit).where(
                    OrchestrationAudit.scan_run_id == scan_run_id,
                    OrchestrationAudit.event_type == BASE_REPORT_EVENT_TYPE,
                )
            )
        ).scalars().all()
        return ReportMaterial(
            report_id=row.report_id,
            scan_run_id=row.scan_run_id,
            report_schema_version=row.report_schema_version,
            report_digest=row.report_digest,
            body=dict(row.body),
            events=tuple(
                (dict(e.payload), e.payload_digest, e.signer_kid, e.signature) for e in events
            ),
        )

    async def check_consent(self, session: AsyncSession, scan_run_id: str) -> Refusal | None:
        """Refuse when the grant's signer is no longer trusted (revocation)."""
        grant_kid = (
            await session.execute(
                select(AuthorizationGrant.issuer_kid)
                .join(ScanRun, ScanRun.grant_id == AuthorizationGrant.grant_id)
                .where(ScanRun.scan_run_id == scan_run_id)
            )
        ).scalar_one_or_none()
        if grant_kid is None:
            return Refusal(
                RefusalReason.GRANT_SIGNER_UNTRUSTED, "no grant is recorded for this scan"
            )
        if grant_kid not in self._grant_trust.trusted_kids:
            return Refusal(
                RefusalReason.GRANT_SIGNER_UNTRUSTED,
                f"grant signer {grant_kid} is no longer trusted",
            )
        return None

    async def verify(self, session: AsyncSession, scan_run_id: str) -> VerifiedReport | Refusal:
        material = await self.load_material(session, scan_run_id)
        if material is None:
            return Refusal(RefusalReason.REPORT_UNVERIFIED, "no report exists for this scan")
        verified = verify_report_material(material, self._audit_trust)
        if isinstance(verified, Refusal):
            return verified
        refusal = await self.check_consent(session, scan_run_id)
        return refusal or verified
