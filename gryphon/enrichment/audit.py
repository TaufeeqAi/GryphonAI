"""Signed enrichment audit events.

Events have the same shape as the upstream signed events — a canonical (RFC
8785) payload, its digest, the signer's kid and an Ed25519 signature — and are
verified with the same verifier function. They are signed with the **dedicated
enrichment key**, never the audit, grant or capability keys: a compromise of the
enrichment process can then forge enrichment attestations at worst, and nothing
upstream.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from gryphon.auth.audit_signer import verify_audit_event
from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import ensure_utc
from gryphon.enrichment.constants import ENRICHMENT_AUDIT_EVENT_SCHEMA_VERSION, EnrichmentEventType


@dataclass(frozen=True, slots=True)
class SignedEnrichmentEvent:
    event_id: str
    event_type: str
    payload: dict[str, Any]
    payload_digest: str
    signer_kid: str
    signature_b64: str


class EnrichmentAuditBuilder:
    """Builds and signs enrichment events with the enrichment key."""

    def __init__(self, signing_key: Ed25519SigningKey) -> None:
        self._key = signing_key

    @property
    def kid(self) -> str:
        return self._key.kid

    def _sign(self, payload: dict[str, Any]) -> SignedEnrichmentEvent:
        canonical = canonical_json_bytes(payload)
        signature = self._key.sign(canonical)
        return SignedEnrichmentEvent(
            event_id=payload["event_id"],
            event_type=payload["event_type"],
            payload=payload,
            payload_digest=sha256_hex(canonical),
            signer_kid=self._key.kid,
            signature_b64=base64.standard_b64encode(signature).decode("ascii"),
        )

    @staticmethod
    def _base(
        event_type: EnrichmentEventType,
        *,
        timestamp: datetime,
        initiated_by: str,
        scan_run_id: str | None = None,
        pass_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "event_id": str(uuid4()),
            "event_type": event_type.value,
            "event_schema_version": ENRICHMENT_AUDIT_EVENT_SCHEMA_VERSION,
            "occurred_at": ensure_utc(timestamp).isoformat(),
            "initiated_by": initiated_by,
            "scan_run_id": scan_run_id,
            "pass_id": pass_id,
        }

    def pass_refused(
        self, *, scan_run_id: str, pass_id: str, reason: str, detail: str | None,
        initiated_by: str, timestamp: datetime,
    ) -> SignedEnrichmentEvent:
        payload = self._base(
            EnrichmentEventType.PASS_REFUSED, timestamp=timestamp, initiated_by=initiated_by,
            scan_run_id=scan_run_id, pass_id=pass_id,
        )
        payload.update({"reason": reason, "detail": detail})
        return self._sign(payload)

    def pass_abandoned(
        self, *, scan_run_id: str, pass_id: str, reason: str, detail: str | None,
        initiated_by: str, timestamp: datetime,
    ) -> SignedEnrichmentEvent:
        payload = self._base(
            EnrichmentEventType.PASS_ABANDONED, timestamp=timestamp, initiated_by=initiated_by,
            scan_run_id=scan_run_id, pass_id=pass_id,
        )
        payload.update({"reason": reason, "detail": detail})
        return self._sign(payload)

    def snapshot_accepted(
        self, *, snapshot_id: str, source: str, label: str, entry_count: int,
        model_version: str | None, initiated_by: str, timestamp: datetime,
    ) -> SignedEnrichmentEvent:
        payload = self._base(
            EnrichmentEventType.SNAPSHOT_ACCEPTED, timestamp=timestamp, initiated_by=initiated_by
        )
        payload.update(
            {"snapshot_id": snapshot_id, "source": source, "label": label,
             "entry_count": entry_count, "model_version": model_version}
        )
        return self._sign(payload)

    def snapshot_revoked(
        self, *, snapshot_id: str, reason: str, initiated_by: str, timestamp: datetime
    ) -> SignedEnrichmentEvent:
        payload = self._base(
            EnrichmentEventType.SNAPSHOT_REVOKED, timestamp=timestamp, initiated_by=initiated_by
        )
        payload.update({"snapshot_id": snapshot_id, "reason": reason})
        return self._sign(payload)

    def report_emitted(
        self, *, scan_run_id: str, pass_id: str, report_id: str, report_digest: str,
        derivations_digest: str, manifest_digest: str, base_report_digest: str, outcome: str,
        initiated_by: str, timestamp: datetime,
    ) -> SignedEnrichmentEvent:
        """Attest the enrichment report (and through it, the pass) by digest."""
        payload = self._base(
            EnrichmentEventType.ENRICHMENT_REPORT_EMITTED, timestamp=timestamp,
            initiated_by=initiated_by, scan_run_id=scan_run_id, pass_id=pass_id,
        )
        payload.update(
            {
                "report_id": report_id,
                "report_digest": report_digest,
                "derivations_digest": derivations_digest,
                "manifest_digest": manifest_digest,
                "base_report_digest": base_report_digest,
                "outcome": outcome,
            }
        )
        return self._sign(payload)


def verify_event(
    *, payload: dict[str, Any], payload_digest: str, signer_kid: str, signature_b64: str,
    trust: TrustedKeyStore,
) -> bool:
    """True iff the stored digest matches the payload and the signature verifies."""
    if sha256_hex(canonical_json_bytes(payload)) != payload_digest:
        return False
    return verify_audit_event(payload, signature_b64, signer_kid, trust)
