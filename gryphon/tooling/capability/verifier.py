"""Capability verification (gateway side).

Pins the algorithm to Ed25519, resolves the ``kid`` only against the configured
trust store, verifies the signature over the exact canonical claims, and checks
schema version, tool match and the temporal window with a bounded skew that
never extends expiry. Verifiers hold only public keys and cannot mint.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature

from gryphon.canonical import canonical_json_bytes, strict_json_loads
from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.tooling.capability.claims import (
    CapabilityClaims,
    VerifiedCapability,
    make_verified,
)
from gryphon.tooling.constants import (
    CAPABILITY_ALGORITHM,
    MAX_CAPABILITY_BYTES,
    SUPPORTED_CAPABILITY_SCHEMA_VERSIONS,
    ToolId,
)
from gryphon.tooling.reasons import ToolReasonCode


@dataclass(frozen=True)
class CapabilityFailure:
    reason_code: ToolReasonCode
    detail: str = ""


class CapabilityVerifier:
    def __init__(self, trust_store: TrustedKeyStore, *, clock_skew: timedelta) -> None:
        self._trust = trust_store
        self._skew = clock_skew

    def verify(
        self, wire: bytes | str | dict[str, Any], expected_tool_id: ToolId, now: datetime
    ) -> VerifiedCapability | CapabilityFailure:
        try:
            return self._verify(wire, expected_tool_id, now)
        except Exception:  # defensive: never leak internals
            return CapabilityFailure(ToolReasonCode.CAPABILITY_MALFORMED, "verification error")

    def _verify(
        self, wire: bytes | str | dict[str, Any], expected_tool_id: ToolId, now: datetime
    ) -> VerifiedCapability | CapabilityFailure:
        if isinstance(wire, (bytes, str)):
            raw = wire.encode("utf-8") if isinstance(wire, str) else wire
            if len(raw) > MAX_CAPABILITY_BYTES:
                return CapabilityFailure(ToolReasonCode.CAPABILITY_TOO_LARGE, "capability too large")
            try:
                obj = strict_json_loads(raw)
            except Exception:
                return CapabilityFailure(ToolReasonCode.CAPABILITY_MALFORMED, "invalid json")
        elif isinstance(wire, dict):
            obj = dict(wire)
        else:  # pragma: no cover
            return CapabilityFailure(ToolReasonCode.CAPABILITY_MALFORMED, "unsupported wire type")

        binding = obj.pop("binding", None)
        if not isinstance(binding, str) or not binding:
            return CapabilityFailure(ToolReasonCode.CAPABILITY_MALFORMED, "missing binding")

        try:
            claims = CapabilityClaims.model_validate(obj)
        except Exception:
            return CapabilityFailure(ToolReasonCode.CAPABILITY_MALFORMED, "invalid claims")

        if claims.capability_schema_version not in SUPPORTED_CAPABILITY_SCHEMA_VERSIONS:
            return CapabilityFailure(
                ToolReasonCode.CAPABILITY_SCHEMA_UNSUPPORTED, "unsupported schema version"
            )
        if claims.algorithm != CAPABILITY_ALGORITHM:
            return CapabilityFailure(
                ToolReasonCode.CAPABILITY_ALGORITHM_UNSUPPORTED, "algorithm not permitted"
            )

        public_key = self._trust.get(claims.kid)
        if public_key is None:
            return CapabilityFailure(ToolReasonCode.CAPABILITY_KID_UNKNOWN, "kid not trusted")

        signing_input = canonical_json_bytes(claims.to_canonical_payload())
        try:
            signature = base64.standard_b64decode(binding)
            public_key.verify(signature, signing_input)
        except (InvalidSignature, ValueError):
            return CapabilityFailure(ToolReasonCode.CAPABILITY_SIGNATURE_INVALID, "signature invalid")

        if claims.tool_id is not expected_tool_id:
            return CapabilityFailure(ToolReasonCode.CAPABILITY_TOOL_MISMATCH, "tool mismatch")

        now_epoch = int(now.timestamp())
        if now_epoch >= claims.exp:
            return CapabilityFailure(ToolReasonCode.CAPABILITY_EXPIRED, "capability expired")
        if claims.iat - now_epoch > int(self._skew.total_seconds()):
            return CapabilityFailure(
                ToolReasonCode.CAPABILITY_NOT_YET_VALID, "capability not yet valid"
            )

        return make_verified(claims)
