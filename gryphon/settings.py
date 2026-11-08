"""Immutable, validated configuration (§28, SEC-004, INV-019/020).

Fail-closed rules enforced here:

* In ``prod`` the grant-signing key, grant ``kid``, audit-signing key and audit
  ``kid`` are REQUIRED. No ephemeral production key is ever generated (§28.1).
* The grant-signing key and audit-signing key MUST be distinct — compared by
  public-key fingerprint, not by raw string (SEC-014 / INV-019).
* Every configured signing key's public half MUST appear in the matching
  trusted-key map under its ``kid`` (so the issuer's own tokens verify).
* All key hex MUST decode to a valid 32-byte Ed25519 key or startup fails.

Secrets use :class:`pydantic.SecretStr`; their values never render in logs or
``repr`` (§21.2).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gryphon.constants import ED25519_PRIVATE_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES
from gryphon.errors import KeyConfigurationError


def _load_private_key(hex_value: str, label: str) -> ed25519.Ed25519PrivateKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise KeyConfigurationError(f"{label} is not valid hex") from exc
    if len(raw) != ED25519_PRIVATE_KEY_BYTES:
        raise KeyConfigurationError(
            f"{label} must be {ED25519_PRIVATE_KEY_BYTES} bytes, got {len(raw)}"
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(hex_value: str, label: str) -> ed25519.Ed25519PublicKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise KeyConfigurationError(f"{label} is not valid hex") from exc
    if len(raw) != ED25519_PUBLIC_KEY_BYTES:
        raise KeyConfigurationError(
            f"{label} must be {ED25519_PUBLIC_KEY_BYTES} bytes, got {len(raw)}"
        )
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def _public_raw_hex(key: ed25519.Ed25519PublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


class Settings(BaseSettings):
    """Typed GRYPHON configuration, loaded from environment / ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="GRYPHON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # ---- Deployment profile -------------------------------------------------
    environment: Literal["dev", "test", "prod"] = "dev"

    # ---- Issuer / audience policy ------------------------------------------
    issuer: str = "gryphon-local-operator"
    audience: str = "gryphon-authorization-service"

    # ---- Grant signing / verification keys ---------------------------------
    grant_signing_key_hex: SecretStr | None = None
    grant_kid: str | None = None
    grant_trusted_public_keys: dict[str, str] = Field(default_factory=dict)

    # ---- Audit signing / verification keys (DISTINCT) ----------------------
    audit_signing_key_hex: SecretStr | None = None
    audit_kid: str | None = None
    audit_trusted_public_keys: dict[str, str] = Field(default_factory=dict)

    # ---- Temporal policy ----------------------------------------------------
    clock_skew_seconds: int = Field(default=60, ge=0, le=600)

    # ---- Database -----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://gryphon_runtime:runtime_pw@localhost:5432/gryphon"
    migration_database_url: str | None = None

    # ---- Bounded deadlines (finite; §16) -----------------------------------
    db_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    db_statement_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    request_deadline_seconds: float = Field(default=15.0, gt=0, le=120)
    db_max_retries: int = Field(default=2, ge=0, le=5)

    # ---- Provisioned-only dependency (never authorization truth) ------------
    redis_url: str | None = None

    # ------------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.environment == "prod"

    @model_validator(mode="after")
    def _validate_security_configuration(self) -> "Settings":
        prod = self.environment == "prod"

        if prod:
            missing = [
                name
                for name, value in (
                    ("GRYPHON_GRANT_SIGNING_KEY_HEX", self.grant_signing_key_hex),
                    ("GRYPHON_GRANT_KID", self.grant_kid),
                    ("GRYPHON_AUDIT_SIGNING_KEY_HEX", self.audit_signing_key_hex),
                    ("GRYPHON_AUDIT_KID", self.audit_kid),
                )
                if not value
            ]
            if missing:
                raise KeyConfigurationError(
                    "production requires key material; missing: " + ", ".join(missing)
                )

        grant_fpr = self._validate_key_pair(
            self.grant_signing_key_hex,
            self.grant_kid,
            self.grant_trusted_public_keys,
            "grant",
        )
        audit_fpr = self._validate_key_pair(
            self.audit_signing_key_hex,
            self.audit_kid,
            self.audit_trusted_public_keys,
            "audit",
        )

        # SEC-014 / INV-019: grant and audit signing keys must be distinct.
        if grant_fpr is not None and audit_fpr is not None and grant_fpr == audit_fpr:
            raise KeyConfigurationError(
                "grant-signing and audit-signing keys must be distinct (identical fingerprint)"
            )
        return self

    def _validate_key_pair(
        self,
        signing_key_hex: SecretStr | None,
        kid: str | None,
        trusted: dict[str, str],
        label: str,
    ) -> str | None:
        """Validate configured key material; return the signing public fingerprint."""
        # Every trusted public key must be a valid Ed25519 public key.
        for trusted_kid, pub_hex in trusted.items():
            if not pub_hex:
                # Placeholder in .env.example; tolerated only outside prod.
                if self.environment == "prod":
                    raise KeyConfigurationError(
                        f"{label} trusted key {trusted_kid!r} has empty public key in prod"
                    )
                continue
            _load_public_key(pub_hex, f"{label} trusted public key {trusted_kid!r}")

        if not signing_key_hex:
            return None

        private_key = _load_private_key(signing_key_hex.get_secret_value(), f"{label} signing key")
        public_fpr = _public_raw_hex(private_key.public_key())

        if kid:
            configured = trusted.get(kid)
            if configured:
                if configured.strip().lower() != public_fpr.lower():
                    raise KeyConfigurationError(
                        f"{label} trusted public key for kid {kid!r} does not match its signing key"
                    )
            elif self.environment == "prod":
                raise KeyConfigurationError(
                    f"{label} signing kid {kid!r} is not present in its trusted public key map"
                )
        return public_fpr


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached)."""
    return Settings()  # type: ignore[call-arg]
