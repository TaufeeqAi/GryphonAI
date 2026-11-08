"""Compact-JWS grant signer and verifier (BND-02).

This is the only token parser in GRYPHON (§6.3 forbids a second envelope). The
verifier:

* pins the algorithm to ``EdDSA`` — a token header can never negotiate it
  (SEC-002 / INV-003);
* resolves ``kid`` only against the configured trusted-key store, and refuses
  ``jku`` / ``x5u`` / ``jwk`` / ``crit`` headers (no remote key material);
* computes ``claims_digest`` over the EXACT decoded payload bytes (§22.1);
* parses those bytes with the strict loader (duplicate member names and
  non-finite numbers are rejected — §9.2.4);
* validates issuer, audience, schema/policy versions and the temporal window
  against an injected UTC clock, where clock skew NEVER extends ``exp`` (§11.2).

``VerifiedGrant`` can only be minted inside :meth:`GrantVerifier.verify`; caller
JSON cannot deserialize one (SEC-015 / INV-022).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import jwt
from jwt.api_jws import PyJWS

from gryphon.auth.claims import GrantClaims
from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex, strict_json_loads
from gryphon.constants import (
    JWS_ALGORITHM,
    JWS_TYP,
    MAX_JWS_BYTES,
    SUPPORTED_CLAIMS_SCHEMA_VERSIONS,
    SUPPORTED_SCOPE_POLICY_VERSIONS,
)
from gryphon.errors import ReasonCode, ValidationError

_GUARD = object()
_FORBIDDEN_HEADERS = ("jku", "x5u", "jwk", "x5c", "crit")
_jws = PyJWS()  # default algorithm registry includes EdDSA when cryptography is present


@dataclass(frozen=True)
class VerifiedGrant:
    """An authenticated, validated grant. Minted only by :class:`GrantVerifier`."""

    claims: GrantClaims
    claims_digest: str
    signer_kid: str
    _guard: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._guard is not _GUARD:
            raise TypeError("VerifiedGrant cannot be constructed directly")

    @property
    def grant_id(self) -> str:
        return self.claims.grant_id

    @property
    def jti(self) -> str:
        return self.claims.jti


@dataclass(frozen=True)
class VerificationFailure:
    """A stable verification failure. Carries no crypto/parser internals."""

    reason_code: ReasonCode
    detail: str = ""


class GrantSigner:
    """Signs canonical grant claims into a compact JWS (BND-01)."""

    def __init__(self, signing_key: Ed25519SigningKey) -> None:
        self._key = signing_key

    @property
    def kid(self) -> str:
        return self._key.kid

    def sign(self, claims: GrantClaims) -> str:
        """Return the deterministic compact JWS for ``claims``.

        Determinism (same claims + same key → same token) supports response-loss
        reissuance (§17.2); it relies on the canonical JSON payload.
        """
        payload = canonical_json_bytes(claims.to_jws_payload())
        return _jws.encode(
            payload,
            self._key._private,  # noqa: SLF001 - envelope adapter owns the raw key
            algorithm=JWS_ALGORITHM,
            headers={"typ": JWS_TYP, "kid": self._key.kid},
        )

    def claims_digest(self, claims: GrantClaims) -> str:
        """SHA-256 of the exact canonical payload bytes that will be signed."""
        return sha256_hex(canonical_json_bytes(claims.to_jws_payload()))


class GrantVerifier:
    """Verifies compact-JWS grants against configured trust and policy (BND-02)."""

    def __init__(
        self,
        trust_store: TrustedKeyStore,
        *,
        expected_issuer: str,
        expected_audience: str,
        clock_skew: timedelta,
    ) -> None:
        self._trust = trust_store
        self._issuer = expected_issuer
        self._audience = expected_audience
        self._skew = clock_skew

    def verify(self, token: str, now: datetime) -> VerifiedGrant | VerificationFailure:
        """Verify a token at instant ``now``. Returns a grant or a stable failure."""
        try:
            return self._verify(token, now)
        except ValidationError as exc:
            return VerificationFailure(exc.reason_code, exc.detail)
        except jwt.InvalidSignatureError:
            return VerificationFailure(ReasonCode.TOKEN_SIGNATURE_INVALID, "signature invalid")
        except jwt.exceptions.PyJWTError:
            return VerificationFailure(ReasonCode.TOKEN_MALFORMED, "malformed token")
        except Exception:  # defensive: never leak internals
            return VerificationFailure(ReasonCode.INTERNAL_ERROR, "verification error")

    # -- internals -----------------------------------------------------------
    def _verify(self, token: str, now: datetime) -> VerifiedGrant:
        if not token:
            raise ValidationError(ReasonCode.TOKEN_MISSING, "no token presented")
        if len(token.encode("utf-8")) > MAX_JWS_BYTES:
            raise ValidationError(ReasonCode.TOKEN_TOO_LARGE, "token exceeds size bound")

        try:
            header = _jws.get_unverified_header(token)
        except jwt.exceptions.PyJWTError as exc:
            raise ValidationError(ReasonCode.TOKEN_MALFORMED, "unreadable JOSE header") from exc

        for forbidden in _FORBIDDEN_HEADERS:
            if forbidden in header:
                raise ValidationError(
                    ReasonCode.TOKEN_HEADER_INVALID, f"forbidden JOSE header {forbidden!r}"
                )
        if header.get("typ") != JWS_TYP:
            raise ValidationError(ReasonCode.TOKEN_HEADER_INVALID, "unexpected typ")
        if header.get("alg") != JWS_ALGORITHM:
            raise ValidationError(ReasonCode.TOKEN_ALGORITHM_UNSUPPORTED, "algorithm not permitted")

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValidationError(ReasonCode.TOKEN_HEADER_INVALID, "missing kid")
        public_key = self._trust.get(kid)
        if public_key is None:
            raise ValidationError(ReasonCode.TOKEN_KID_UNKNOWN, "kid not trusted")

        # Signature verification over the exact signing input; algorithm pinned.
        decoded = _jws.decode_complete(token, key=public_key, algorithms=[JWS_ALGORITHM])
        payload_bytes: bytes = decoded["payload"]
        claims_digest = sha256_hex(payload_bytes)

        payload = strict_json_loads(payload_bytes)
        claims = GrantClaims.from_jws_payload(payload)

        # -- Policy / version / identity --------------------------------------
        if claims.schema_version not in SUPPORTED_CLAIMS_SCHEMA_VERSIONS:
            raise ValidationError(ReasonCode.CLAIMS_SCHEMA_UNSUPPORTED, "unsupported schema_version")
        if claims.scope_policy_version not in SUPPORTED_SCOPE_POLICY_VERSIONS:
            raise ValidationError(ReasonCode.SCOPE_POLICY_UNSUPPORTED, "unsupported scope_policy_version")
        if claims.iss != self._issuer:
            raise ValidationError(ReasonCode.ISSUER_UNTRUSTED, "issuer mismatch")
        if claims.aud != self._audience:
            raise ValidationError(ReasonCode.AUDIENCE_MISMATCH, "audience mismatch")

        # -- Temporal window (skew never extends exp; §11.2) ------------------
        if now >= claims.exp:
            raise ValidationError(ReasonCode.TOKEN_EXPIRED, "token expired")
        if claims.nbf - now > self._skew:
            raise ValidationError(ReasonCode.TOKEN_NOT_YET_VALID, "token not yet valid")
        if claims.iat - now > self._skew:
            raise ValidationError(ReasonCode.CLAIMS_INVALID, "iat unreasonably in the future")

        return VerifiedGrant(
            claims=claims,
            claims_digest=claims_digest,
            signer_kid=kid,
            _guard=_GUARD,
        )
