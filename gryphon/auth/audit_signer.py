"""Audit event building, signing and verification (BND-06).

Every admission attempt (ALLOW or DENY) and every grant issuance produces a
signed audit event. Events are serialized with RFC 8785 JCS before hashing and
signing; the signature covers the event schema version, id/type and the complete
canonical payload (§22.1). The audit key is DISTINCT from the grant-signing key
(SEC-014 / INV-019).

This module produces the signed artifact; durable append-only persistence and
the DB-role controls that make it immutable to the runtime role live in the
repository + migration (§22.3).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import ensure_utc
from gryphon.constants import AUDIT_EVENT_SCHEMA_VERSION, AuditEventType, DecisionStatus
from gryphon.errors import ReasonCode


@dataclass(frozen=True)
class SignedAuditEvent:
    """A signed audit event ready for append-only persistence."""

    event_id: str
    event_type: AuditEventType
    scan_run_id: str | None
    payload: dict[str, Any]
    payload_digest: str
    signer_kid: str
    signature_b64: str

    @property
    def signature_bytes(self) -> bytes:
        return base64.standard_b64decode(self.signature_b64)


def _iso(instant: datetime) -> str:
    return ensure_utc(instant).isoformat()


class AuditSigner:
    """Builds and signs canonical audit events with the dedicated audit key."""

    def __init__(self, signing_key: Ed25519SigningKey) -> None:
        self._key = signing_key

    @property
    def kid(self) -> str:
        return self._key.kid

    def _sign_payload(
        self, event_type: AuditEventType, scan_run_id: str | None, payload: dict[str, Any]
    ) -> SignedAuditEvent:
        canonical = canonical_json_bytes(payload)
        digest = sha256_hex(canonical)
        signature = self._key.sign(canonical)
        return SignedAuditEvent(
            event_id=payload["event_id"],
            event_type=event_type,
            scan_run_id=scan_run_id,
            payload=payload,
            payload_digest=digest,
            signer_kid=self._key.kid,
            signature_b64=base64.standard_b64encode(signature).decode("ascii"),
        )

    def sign_scan_admission(
        self,
        *,
        scan_run_id: str,
        decision: DecisionStatus,
        reason_code: ReasonCode,
        authorization_valid: bool,
        scope_check_passed: bool,
        target_requested: str,
        canonical_target: str | None,
        path_requested: str | None,
        grant_id: str | None,
        requested_by: str | None,
        organization: str | None,
        scope_policy_version: str | None,
        timestamp: datetime,
    ) -> SignedAuditEvent:
        """Build + sign a scan-admission audit event (references its scan_run_id)."""
        payload: dict[str, Any] = {
            "event_id": str(uuid4()),
            "event_type": AuditEventType.SCAN_ADMISSION.value,
            "event_schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "scan_run_id": scan_run_id,
            "grant_id": grant_id,
            "decision": decision.value,
            "reason_code": reason_code.value,
            "authorization_valid": authorization_valid,
            "scope_check_passed": scope_check_passed,
            "target_requested": target_requested,
            "canonical_target": canonical_target,
            "path_requested": path_requested,
            "requested_by": requested_by,
            "organization": organization,
            "scope_policy_version": scope_policy_version,
            "signer_kid": self._key.kid,
            "timestamp": _iso(timestamp),
        }
        return self._sign_payload(AuditEventType.SCAN_ADMISSION, scan_run_id, payload)

    def sign_grant_issuance(
        self,
        *,
        grant_id: str,
        jti: str,
        issuer_kid: str,
        organization: str,
        granted_by: str,
        granted_to: str,
        claims_digest: str,
        scope_digest: str,
        scope_policy_version: str,
        timestamp: datetime,
    ) -> SignedAuditEvent:
        """Build + sign a grant-issuance audit event (scan_run_id is NULL)."""
        payload: dict[str, Any] = {
            "event_id": str(uuid4()),
            "event_type": AuditEventType.GRANT_ISSUANCE.value,
            "event_schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "scan_run_id": None,
            "grant_id": grant_id,
            "jti": jti,
            "issuer_kid": issuer_kid,
            "organization": organization,
            "granted_by": granted_by,
            "granted_to": granted_to,
            "claims_digest": claims_digest,
            "scope_digest": scope_digest,
            "scope_policy_version": scope_policy_version,
            "signer_kid": self._key.kid,
            "timestamp": _iso(timestamp),
        }
        return self._sign_payload(AuditEventType.GRANT_ISSUANCE, None, payload)


def verify_audit_event(
    payload: dict[str, Any],
    signature_b64: str,
    signer_kid: str,
    trust_store: TrustedKeyStore,
) -> bool:
    """Return True iff the signature matches the canonical payload (tamper check).

    Used by audit-integrity verification and the SEC-013 tamper tests.
    """
    public_key = trust_store.get(signer_kid)
    if public_key is None:
        return False
    canonical = canonical_json_bytes(payload)
    try:
        public_key.verify(base64.standard_b64decode(signature_b64), canonical)
        return True
    except (InvalidSignature, ValueError):
        return False
