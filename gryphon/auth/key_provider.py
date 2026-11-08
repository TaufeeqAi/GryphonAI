"""Key resolution and signing boundary (BND-02, §19.4, §26).

The verifier receives ONLY trusted public keys and a ``kid`` map. A token can
never add a key or choose a remote key URL (SEC-002). Signing keys live behind a
narrow interface so a future HSM/KMS provider can replace the env-backed one
without changing grant semantics (§26).

The grant-signing key and the audit-signing key are built from distinct config
fields; their distinctness is enforced at settings validation (SEC-014).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.constants import ED25519_PRIVATE_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES
from gryphon.errors import KeyConfigurationError
from gryphon.settings import Settings


@runtime_checkable
class SigningKey(Protocol):
    """Minimal signing interface. ``kid`` identifies the public half."""

    @property
    def kid(self) -> str: ...

    def sign(self, data: bytes) -> bytes: ...

    def public_key_raw_hex(self) -> str: ...


@dataclass(frozen=True)
class Ed25519SigningKey:
    """Env/local Ed25519 signing key (demo/local deployment; §19.4)."""

    kid: str
    _private: ed25519.Ed25519PrivateKey

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._private.public_key()

    def public_key_raw_hex(self) -> str:
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()


class TrustedKeyStore:
    """Immutable snapshot of trusted public keys keyed by ``kid``."""

    def __init__(self, keys: dict[str, ed25519.Ed25519PublicKey]) -> None:
        self._keys = dict(keys)

    def get(self, kid: str) -> ed25519.Ed25519PublicKey | None:
        return self._keys.get(kid)

    @property
    def trusted_kids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def verify(self, kid: str, signature: bytes, data: bytes) -> bool:
        """Return True iff ``signature`` is valid for ``data`` under trusted ``kid``."""
        key = self._keys.get(kid)
        if key is None:
            return False
        try:
            key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


# -----------------------------------------------------------------------------
# Construction helpers
# -----------------------------------------------------------------------------
def _private_from_hex(hex_value: str, label: str) -> ed25519.Ed25519PrivateKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise KeyConfigurationError(f"{label} is not valid hex") from exc
    if len(raw) != ED25519_PRIVATE_KEY_BYTES:
        raise KeyConfigurationError(f"{label} must be {ED25519_PRIVATE_KEY_BYTES} bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def _public_from_hex(hex_value: str, label: str) -> ed25519.Ed25519PublicKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise KeyConfigurationError(f"{label} is not valid hex") from exc
    if len(raw) != ED25519_PUBLIC_KEY_BYTES:
        raise KeyConfigurationError(f"{label} must be {ED25519_PUBLIC_KEY_BYTES} bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def _trust_store_from_map(mapping: dict[str, str], label: str) -> TrustedKeyStore:
    keys: dict[str, ed25519.Ed25519PublicKey] = {}
    for kid, pub_hex in mapping.items():
        if not pub_hex:
            continue  # empty placeholder (non-prod .env); skipped
        keys[kid] = _public_from_hex(pub_hex, f"{label} public key {kid!r}")
    return TrustedKeyStore(keys)


@dataclass(frozen=True)
class KeyMaterial:
    """Resolved key providers for a running service."""

    grant_signer: Ed25519SigningKey | None
    grant_trust: TrustedKeyStore
    audit_signer: Ed25519SigningKey | None
    audit_trust: TrustedKeyStore


def build_key_material(settings: Settings) -> KeyMaterial:
    """Build signing/verification providers from validated settings.

    Settings validation has already enforced hex validity, key-pair consistency
    and grant/audit distinctness; this only materializes the objects.
    """
    grant_signer = None
    if settings.grant_signing_key_hex and settings.grant_kid:
        grant_signer = Ed25519SigningKey(
            kid=settings.grant_kid,
            _private=_private_from_hex(
                settings.grant_signing_key_hex.get_secret_value(), "grant signing key"
            ),
        )
    audit_signer = None
    if settings.audit_signing_key_hex and settings.audit_kid:
        audit_signer = Ed25519SigningKey(
            kid=settings.audit_kid,
            _private=_private_from_hex(
                settings.audit_signing_key_hex.get_secret_value(), "audit signing key"
            ),
        )

    grant_trust = _trust_store_from_map(settings.grant_trusted_public_keys, "grant")
    audit_trust = _trust_store_from_map(settings.audit_trusted_public_keys, "audit")

    # Ensure a configured signer's own public key is trusted (its tokens verify).
    if grant_signer is not None and grant_signer.kid not in grant_trust.trusted_kids:
        grant_trust = TrustedKeyStore(
            {
                **{k: grant_trust.get(k) for k in grant_trust.trusted_kids},  # type: ignore[dict-item]
                grant_signer.kid: grant_signer.public_key(),
            }
        )
    if audit_signer is not None and audit_signer.kid not in audit_trust.trusted_kids:
        audit_trust = TrustedKeyStore(
            {
                **{k: audit_trust.get(k) for k in audit_trust.trusted_kids},  # type: ignore[dict-item]
                audit_signer.kid: audit_signer.public_key(),
            }
        )

    return KeyMaterial(
        grant_signer=grant_signer,
        grant_trust=grant_trust,
        audit_signer=audit_signer,
        audit_trust=audit_trust,
    )
