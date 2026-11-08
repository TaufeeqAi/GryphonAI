"""Grant signing + verification (BND-02, SEC-002/003, INV-003/004/005/006)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from jwt.api_jws import PyJWS

from gryphon.auth.authorization_token import GrantVerifier, VerificationFailure, VerifiedGrant
from gryphon.canonical import canonical_json_bytes
from gryphon.errors import ReasonCode

pytestmark = pytest.mark.unit

_UTC = timezone.utc
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=_UTC)
_jws = PyJWS()


def test_roundtrip_sign_verify(make_token, verifier) -> None:
    token = make_token()
    result = verifier.verify(token, NOW)
    assert isinstance(result, VerifiedGrant)
    assert result.grant_id == "grant-0001"
    assert len(result.claims_digest) == 64


def test_wrong_key_fails(make_token, key_material) -> None:
    token = make_token()
    from gryphon.auth.key_provider import TrustedKeyStore

    stranger = ed25519.Ed25519PrivateKey.generate().public_key()
    bad_store = TrustedKeyStore({"grant-test": stranger})
    verifier = GrantVerifier(
        bad_store, expected_issuer="gryphon-test-issuer",
        expected_audience="gryphon-test-audience", clock_skew=timedelta(seconds=60),
    )
    result = verifier.verify(token, NOW)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_SIGNATURE_INVALID


def test_tampered_payload_fails(make_token, verifier) -> None:
    token = make_token()
    header, payload, sig = token.split(".")
    tampered = f"{header}.{payload[:-2] + ('AA' if payload[-2:] != 'AA' else 'BB')}.{sig}"
    result = verifier.verify(tampered, NOW)
    assert isinstance(result, VerificationFailure)


def test_unknown_kid_rejected(make_claims, key_material) -> None:
    # Sign with grant key but advertise an untrusted kid in the header.
    payload = canonical_json_bytes(make_claims().to_jws_payload())
    token = _jws.encode(
        payload, key_material.grant_signer._private, algorithm="EdDSA",
        headers={"typ": "JWT", "kid": "unknown-kid"},
    )
    verifier = GrantVerifier(
        key_material.grant_trust, expected_issuer="gryphon-test-issuer",
        expected_audience="gryphon-test-audience", clock_skew=timedelta(seconds=60),
    )
    result = verifier.verify(token, NOW)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_KID_UNKNOWN


def test_algorithm_confusion_rejected(make_claims, key_material, verifier) -> None:
    # Craft an unsigned 'none' token; the EdDSA pin must reject it.
    payload = canonical_json_bytes(make_claims().to_jws_payload())
    token = _jws.encode(payload, None, algorithm="none", headers={"typ": "JWT", "kid": "grant-test"})
    result = verifier.verify(token, NOW)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_ALGORITHM_UNSUPPORTED


def test_forbidden_header_rejected(make_claims, key_material, verifier) -> None:
    payload = canonical_json_bytes(make_claims().to_jws_payload())
    token = _jws.encode(
        payload, key_material.grant_signer._private, algorithm="EdDSA",
        headers={"typ": "JWT", "kid": "grant-test", "jku": "https://evil.example/keys"},
    )
    result = verifier.verify(token, NOW)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_HEADER_INVALID


def test_duplicate_claim_rejected(key_material, verifier) -> None:
    # Hand-craft a payload with a duplicate member name and sign it correctly.
    raw = b'{"iss":"a","iss":"b"}'
    token = _jws.encode(
        raw, key_material.grant_signer._private, algorithm="EdDSA",
        headers={"typ": "JWT", "kid": "grant-test"},
    )
    result = verifier.verify(token, NOW)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_DUPLICATE_CLAIM


def test_expiry_is_exclusive_now_equals_exp(make_token, verifier) -> None:
    token = make_token()  # exp = NOW + 7 days
    exp_instant = NOW + timedelta(days=7)
    result = verifier.verify(token, exp_instant)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_EXPIRED


def test_not_yet_valid(make_token, verifier) -> None:
    token = make_token(nbf=NOW + timedelta(hours=1))
    result = verifier.verify(token, NOW)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_NOT_YET_VALID


def test_issuer_and_audience_mismatch(make_token, verifier) -> None:
    assert verifier.verify(make_token(iss="evil"), NOW).reason_code is ReasonCode.ISSUER_UNTRUSTED
    assert (
        verifier.verify(make_token(aud="other"), NOW).reason_code is ReasonCode.AUDIENCE_MISMATCH
    )


def test_oversized_token_rejected(make_token, verifier) -> None:
    token = make_token()
    oversized = token + ("A" * (64 * 1024))
    result = verifier.verify(oversized, NOW)
    assert isinstance(result, VerificationFailure)
    assert result.reason_code is ReasonCode.TOKEN_TOO_LARGE


def test_missing_token_rejected(verifier) -> None:
    assert verifier.verify("", NOW).reason_code is ReasonCode.TOKEN_MISSING


def test_deterministic_token(make_claims, grant_signer) -> None:
    claims = make_claims()
    assert grant_signer.sign(claims) == grant_signer.sign(claims)
