"""Key separation, audit tamper-evidence and redaction (SEC-013/014/016)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.audit_signer import AuditSigner, verify_audit_event
from gryphon.constants import DecisionStatus
from gryphon.errors import KeyConfigurationError, ReasonCode
from gryphon.logging_config import _redact_processor
from gryphon.settings import Settings

pytestmark = pytest.mark.security


def _hex(k: ed25519.Ed25519PrivateKey) -> tuple[str, str]:
    return (
        k.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex(),
        k.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ).hex(),
    )


def test_identical_grant_and_audit_key_rejected() -> None:
    priv, pub = _hex(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(KeyConfigurationError):
        Settings(
            _env_file=None,
            environment="test",
            grant_signing_key_hex=priv,
            grant_kid="k",
            grant_trusted_public_keys={"k": pub},
            audit_signing_key_hex=priv,  # SAME key — must be rejected
            audit_kid="k2",
            audit_trusted_public_keys={"k2": pub},
        )


def test_production_requires_key_material() -> None:
    with pytest.raises(KeyConfigurationError):
        Settings(_env_file=None, environment="prod")


def test_audit_event_tamper_is_detectable(audit_signer: AuditSigner, key_material) -> None:
    event = audit_signer.sign_scan_admission(
        scan_run_id="run-1",
        decision=DecisionStatus.DENY,
        reason_code=ReasonCode.SCOPE_NO_MATCH,
        authorization_valid=False,
        scope_check_passed=False,
        target_requested="app.example.com",
        canonical_target="app.example.com",
        path_requested=None,
        grant_id=None,
        requested_by=None,
        organization=None,
        scope_policy_version="1",
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )
    # Intact event verifies.
    assert verify_audit_event(
        event.payload, event.signature_b64, event.signer_kid, key_material.audit_trust
    )
    # Mutating any payload field breaks verification.
    tampered = dict(event.payload)
    tampered["decision"] = DecisionStatus.ALLOW.value
    assert not verify_audit_event(
        tampered, event.signature_b64, event.signer_kid, key_material.audit_trust
    )
    # The grant trust store (different key) cannot verify an audit signature.
    assert not verify_audit_event(
        event.payload, event.signature_b64, event.signer_kid, key_material.grant_trust
    )


def test_log_redaction_masks_secrets() -> None:
    event = {
        "event": "admission",
        "authorization_token": "eyJ-secret",
        "grant_signing_key_hex": "deadbeef",
        "scan_run_id": "run-1",
    }
    out = _redact_processor(None, "info", dict(event))
    assert out["authorization_token"] == "«redacted»"
    assert out["grant_signing_key_hex"] == "«redacted»"
    assert out["scan_run_id"] == "run-1"  # safe correlation field preserved
