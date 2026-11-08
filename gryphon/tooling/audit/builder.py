"""Build and sign tool-invocation audit events."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from gryphon.auth.key_provider import Ed25519SigningKey
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import ensure_utc
from gryphon.tooling.constants import TOOL_AUDIT_EVENT_SCHEMA_VERSION, ToolId, ToolOutcome


@dataclass(frozen=True)
class SignedToolAuditEvent:
    event_id: str
    event_type: str  # "intent" | "outcome"
    payload: dict[str, Any]
    payload_digest: str
    signer_kid: str
    signature_b64: str


class ToolAuditBuilder:
    """Signs canonical tool-audit payloads with the audit key."""

    def __init__(self, audit_key: Ed25519SigningKey) -> None:
        self._key = audit_key

    @property
    def kid(self) -> str:
        return self._key.kid

    def _sign(self, event_type: str, payload: dict[str, Any]) -> SignedToolAuditEvent:
        canonical = canonical_json_bytes(payload)
        digest = sha256_hex(canonical)
        signature = self._key.sign(canonical)
        return SignedToolAuditEvent(
            event_id=payload["event_id"],
            event_type=event_type,
            payload=payload,
            payload_digest=digest,
            signer_kid=self._key.kid,
            signature_b64=base64.standard_b64encode(signature).decode("ascii"),
        )

    def intent(
        self,
        *,
        scan_run_id: str,
        execution_id: str,
        tool_id: ToolId,
        capability_id: str | None,
        canonical_target: str | None,
        pinned_summary: str | None,
        effective_depth: str,
        descriptor_version: str,
        external_disclosure: bool,
        timestamp: datetime,
    ) -> SignedToolAuditEvent:
        payload: dict[str, Any] = {
            "event_id": str(uuid4()),
            "event_type": "intent",
            "event_schema_version": TOOL_AUDIT_EVENT_SCHEMA_VERSION,
            "scan_run_id": scan_run_id,
            "execution_id": execution_id,
            "tool_id": tool_id.value,
            "capability_id": capability_id,
            "decision": "ALLOW",
            "canonical_target": canonical_target,
            "pinned_destinations_summary": pinned_summary,
            "effective_scan_depth": effective_depth,
            "descriptor_version": descriptor_version,
            "external_disclosure": external_disclosure,
            "signer_kid": self._key.kid,
            "timestamp": ensure_utc(timestamp).isoformat(),
        }
        return self._sign("intent", payload)

    def outcome(
        self,
        *,
        scan_run_id: str,
        execution_id: str,
        tool_id: ToolId,
        outcome: ToolOutcome,
        reason_code: str,
        record_count: int | None,
        timestamp: datetime,
    ) -> SignedToolAuditEvent:
        payload: dict[str, Any] = {
            "event_id": str(uuid4()),
            "event_type": "outcome",
            "event_schema_version": TOOL_AUDIT_EVENT_SCHEMA_VERSION,
            "scan_run_id": scan_run_id,
            "execution_id": execution_id,
            "tool_id": tool_id.value,
            "outcome": outcome.value,
            "reason_code": reason_code,
            "record_count": record_count,
            "signer_kid": self._key.kid,
            "timestamp": ensure_utc(timestamp).isoformat(),
        }
        return self._sign("outcome", payload)

    def denial(
        self,
        *,
        scan_run_id: str | None,
        execution_id: str,
        tool_id: ToolId,
        reason_code: str,
        canonical_target: str | None,
        timestamp: datetime,
    ) -> SignedToolAuditEvent:
        payload: dict[str, Any] = {
            "event_id": str(uuid4()),
            "event_type": "outcome",
            "event_schema_version": TOOL_AUDIT_EVENT_SCHEMA_VERSION,
            "scan_run_id": scan_run_id,
            "execution_id": execution_id,
            "tool_id": tool_id.value,
            "outcome": ToolOutcome.DENIED.value,
            "decision": "DENY",
            "reason_code": reason_code,
            "canonical_target": canonical_target,
            "signer_kid": self._key.kid,
            "timestamp": ensure_utc(timestamp).isoformat(),
        }
        return self._sign("outcome", payload)
