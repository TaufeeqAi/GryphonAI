"""Idempotency key validation and canonical request hashing (§17).

The caller's idempotency key is NEVER treated as authorization. Only a
cryptographic hash of the key is stored (§17.1). The scan-admission request hash
is computed BEFORE signature verification over bounded request-identity fields —
including the SHA-256 of the exact compact JWS bytes — so an idempotency lookup
can precede verification without trusting the token payload.
"""

from __future__ import annotations

from typing import Any

from gryphon.canonical import canonical_json_bytes, sha256_hex, sha256_hex_text
from gryphon.constants import (
    DEPLOYMENT_NAMESPACE,
    MAX_IDEMPOTENCY_KEY_BYTES,
    MIN_IDEMPOTENCY_KEY_BYTES,
    REQUEST_SCHEMA_VERSION,
)
from gryphon.errors import ReasonCode, ValidationError


def validate_idempotency_key(key: str) -> None:
    """Enforce idempotency-key bounds (§21.1).

    True entropy is the caller's responsibility; Phase 1 enforces a length floor
    sufficient to *carry* 128 bits and a hard ceiling, and rejects trivially
    low-entropy keys (a single repeated byte/character).
    """
    if not isinstance(key, str) or not key:
        raise ValidationError(ReasonCode.IDEMPOTENCY_KEY_INVALID, "missing idempotency key")
    raw = key.encode("utf-8")
    if len(raw) < MIN_IDEMPOTENCY_KEY_BYTES:
        raise ValidationError(
            ReasonCode.IDEMPOTENCY_KEY_INVALID, "idempotency key below minimum length"
        )
    if len(raw) > MAX_IDEMPOTENCY_KEY_BYTES:
        raise ValidationError(ReasonCode.IDEMPOTENCY_KEY_INVALID, "idempotency key too long")
    if len(set(key)) <= 1:
        raise ValidationError(ReasonCode.IDEMPOTENCY_KEY_INVALID, "idempotency key lacks entropy")


def hash_idempotency_key(key: str) -> str:
    """Return the stored SHA-256 hex of the idempotency key (never the raw key)."""
    return sha256_hex_text(key)


def scan_request_hash(
    *, token: str, target: str, path: str | None, requested_depth: str
) -> str:
    """Canonical request-identity hash for scan admission (§17.1)."""
    identity: dict[str, Any] = {
        "namespace": DEPLOYMENT_NAMESPACE,
        "token_sha256": sha256_hex_text(token),
        "target": target,
        "path": path,
        "requested_depth": requested_depth,
        "request_schema_version": REQUEST_SCHEMA_VERSION,
    }
    return sha256_hex(canonical_json_bytes(identity))


def issuance_request_hash(payload: dict[str, Any]) -> str:
    """Canonical hash of the claims-defining issuance request (§17.2)."""
    return sha256_hex(canonical_json_bytes(payload))
