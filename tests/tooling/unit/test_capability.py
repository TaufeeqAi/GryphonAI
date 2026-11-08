"""Capability signing/verification (asymmetric, full-canonical binding)."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.tooling.capability.claims import VerifiedCapability
from gryphon.tooling.capability.verifier import CapabilityFailure, CapabilityVerifier
from gryphon.tooling.constants import ToolId
from gryphon.tooling.reasons import ToolReasonCode
from tests.tooling.conftest import NOW

pytestmark = pytest.mark.unit


def test_roundtrip(verifier, make_capability_wire) -> None:
    wire = make_capability_wire(tool_id=ToolId.NUCLEI)
    result = verifier.verify(wire, ToolId.NUCLEI, NOW)
    assert isinstance(result, VerifiedCapability)
    assert result.claims.tool_id is ToolId.NUCLEI


def test_tampered_field_fails(verifier, make_capability_wire) -> None:
    wire = make_capability_wire()
    obj = json.loads(wire)
    obj["effective_scan_depth"] = "aggressive"  # escalate an unsigned-looking field
    result = verifier.verify(json.dumps(obj).encode(), ToolId.NUCLEI, NOW)
    assert isinstance(result, CapabilityFailure)
    assert result.reason_code is ToolReasonCode.CAPABILITY_SIGNATURE_INVALID


def test_extra_member_rejected(verifier, make_capability_wire) -> None:
    obj = json.loads(make_capability_wire())
    obj["injected"] = "x"
    result = verifier.verify(json.dumps(obj).encode(), ToolId.NUCLEI, NOW)
    assert isinstance(result, CapabilityFailure)
    assert result.reason_code is ToolReasonCode.CAPABILITY_MALFORMED


def test_wrong_tool_rejected(verifier, make_capability_wire) -> None:
    wire = make_capability_wire(tool_id=ToolId.SUBFINDER)
    result = verifier.verify(wire, ToolId.NUCLEI, NOW)
    assert isinstance(result, CapabilityFailure)
    assert result.reason_code is ToolReasonCode.CAPABILITY_TOOL_MISMATCH


def test_expired_rejected(verifier, make_capability_wire) -> None:
    iat = int(NOW.timestamp()) - 1000
    wire = make_capability_wire(iat=iat, exp=iat + 60)  # expired well before NOW
    result = verifier.verify(wire, ToolId.NUCLEI, NOW)
    assert isinstance(result, CapabilityFailure)
    assert result.reason_code is ToolReasonCode.CAPABILITY_EXPIRED


def test_unknown_kid_rejected(verifier, make_capability_wire) -> None:
    stranger = Ed25519SigningKey(kid="stranger", _private=ed25519.Ed25519PrivateKey.generate())
    wire = make_capability_wire(signer=stranger)  # signed by an untrusted key/kid
    result = verifier.verify(wire, ToolId.NUCLEI, NOW)
    assert isinstance(result, CapabilityFailure)
    assert result.reason_code is ToolReasonCode.CAPABILITY_KID_UNKNOWN


def test_wrong_key_same_kid_signature_invalid(make_capability_wire, signing_key) -> None:
    # A verifier that trusts the kid but with a DIFFERENT public key rejects the sig.
    other_pub = ed25519.Ed25519PrivateKey.generate().public_key()
    verifier = CapabilityVerifier(
        TrustedKeyStore({signing_key.kid: other_pub}),
        clock_skew=__import__("datetime").timedelta(seconds=30),
    )
    result = verifier.verify(make_capability_wire(), ToolId.NUCLEI, NOW)
    assert isinstance(result, CapabilityFailure)
    assert result.reason_code is ToolReasonCode.CAPABILITY_SIGNATURE_INVALID


def test_oversized_rejected(verifier, make_capability_wire) -> None:
    wire = make_capability_wire()
    oversized = wire[:-1] + b'"' + b"A" * (8 * 1024) + b'"}'
    result = verifier.verify(oversized, ToolId.NUCLEI, NOW)
    assert isinstance(result, CapabilityFailure)
    assert result.reason_code is ToolReasonCode.CAPABILITY_TOO_LARGE


def test_verified_capability_not_constructible() -> None:
    with pytest.raises(TypeError):
        VerifiedCapability(claims=None)  # type: ignore[arg-type]
