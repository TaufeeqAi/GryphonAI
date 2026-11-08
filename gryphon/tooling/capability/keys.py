"""Capability key material — distinct from the grant and audit keys.

The issuer holds the capability **private** key; verifiers (the gateway) hold
only the **public** key and can never mint. Reuses the authorization core's
``Ed25519SigningKey`` / ``TrustedKeyStore`` so the signing semantics are shared.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.constants import ED25519_PRIVATE_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES
from gryphon.tooling.reasons import ToolingConfigurationError
from gryphon.tooling.settings import ToolingSettings


def _private_from_hex(hex_value: str) -> ed25519.Ed25519PrivateKey:
    raw = bytes.fromhex(hex_value.strip())
    if len(raw) != ED25519_PRIVATE_KEY_BYTES:
        raise ToolingConfigurationError("capability signing key must be 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def _public_from_hex(hex_value: str) -> ed25519.Ed25519PublicKey:
    raw = bytes.fromhex(hex_value.strip())
    if len(raw) != ED25519_PUBLIC_KEY_BYTES:
        raise ToolingConfigurationError("capability trusted public key must be 32 bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


@dataclass(frozen=True)
class CapabilityKeyMaterial:
    signer: Ed25519SigningKey | None
    trust: TrustedKeyStore


def build_capability_key_material(settings: ToolingSettings) -> CapabilityKeyMaterial:
    """Materialize the capability signer (if configured) and the trust store."""
    keys: dict[str, ed25519.Ed25519PublicKey] = {}
    for kid, pub_hex in settings.capability_trusted_public_keys.items():
        if pub_hex:
            keys[kid] = _public_from_hex(pub_hex)

    signer: Ed25519SigningKey | None = None
    if settings.capability_signing_key_hex and settings.capability_kid:
        signer = Ed25519SigningKey(
            kid=settings.capability_kid,
            _private=_private_from_hex(settings.capability_signing_key_hex.get_secret_value()),
        )
        keys.setdefault(signer.kid, signer.public_key())

    return CapabilityKeyMaterial(signer=signer, trust=TrustedKeyStore(keys))
