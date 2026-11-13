"""Fail-closed configuration for the enrichment layer.

Security-relevant values are code constants; a setting may only *narrow* them.
The egress host list can be reduced but never extended, maximum ages can be
shortened but are capped at seven days, and in production a signing key that
the trust store recognizes is mandatory.

Every field is read from ``GRYPHON_ENRICHMENT_*`` environment variables (or
``.env``). The enrichment process connects to the database with its *own* role,
never the shared runtime role, so it can write only enrichment tables.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.constants import ED25519_PRIVATE_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES
from gryphon.enrichment.constants import ALLOWED_HOSTS
from gryphon.enrichment.reasons import EnrichmentConfigurationError

_MAX_AGE_CAP_HOURS = 7 * 24


class EnrichmentSettings(BaseSettings):
    """Typed, frozen configuration for the enrichment layer."""

    model_config = SettingsConfigDict(
        env_prefix="GRYPHON_ENRICHMENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    #: DSN for the dedicated ``gryphon_enrichment`` role.
    database_url: str = (
        "postgresql+asyncpg://gryphon_enrichment:enrichment_pw@localhost:5432/gryphon"
    )

    # -- attestation key (dedicated purpose: enrichment artifacts only) -------
    signing_key_hex: SecretStr | None = None
    kid: str | None = None
    trusted_public_keys: dict[str, str] = Field(default_factory=dict)

    # -- storage ----------------------------------------------------------------
    artifact_dir: Path = Path("var/enrichment/artifacts")
    reference_dir: Path = Path("var/enrichment/reference")
    #: Override of the packaged Policy v1 file. Any change is a new policy digest.
    policy_path: Path | None = None
    #: Digest of the nuclei template set that produced the evidence, once the
    #: tool-execution layer pins and records it. Until then: ``unpinned``.
    templates_digest: str | None = None

    # -- egress (narrow-only) ---------------------------------------------------
    allowed_hosts: tuple[str, ...] = tuple(sorted(ALLOWED_HOSTS))
    connect_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    request_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    subprocess_timeout_seconds: float = Field(default=300.0, gt=0, le=1800)
    fetch_attempts: int = Field(default=3, ge=1, le=5)
    max_report_bytes: int = Field(default=1024 * 1024, ge=4096, le=16 * 1024 * 1024)

    # -- freshness and breaker --------------------------------------------------
    kev_max_age_hours: float = Field(default=24.0, gt=0, le=_MAX_AGE_CAP_HOURS)
    epss_max_age_hours: float = Field(default=48.0, gt=0, le=_MAX_AGE_CAP_HOURS)
    breaker_failures: int = Field(default=3, ge=1, le=20)
    breaker_cooldown_seconds: float = Field(default=3600.0, gt=0, le=86_400)

    # -- pass lease ----------------------------------------------------------------
    pass_lease_seconds: float = Field(default=60.0, gt=0, le=3600)
    pass_heartbeat_seconds: float = Field(default=15.0, gt=0, le=600)

    # -- caller -----------------------------------------------------------------
    #: Real uids permitted to run enrichment. Empty permits any local user
    #: outside production; required in production.
    allowed_uids: tuple[int, ...] = ()

    @field_validator("signing_key_hex", "kid", "templates_digest", "policy_path", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        """An empty variable (as in ``.env.example``) means "not configured"."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def _validate(self) -> EnrichmentSettings:
        extra = set(self.allowed_hosts) - ALLOWED_HOSTS
        if extra:
            raise EnrichmentConfigurationError(
                "allowed_hosts may only narrow the code-constant allowlist; "
                f"refusing: {', '.join(sorted(extra))}"
            )
        if self.pass_heartbeat_seconds * 2 > self.pass_lease_seconds:
            raise EnrichmentConfigurationError(
                "pass_lease_seconds must be at least twice pass_heartbeat_seconds"
            )
        if self.kid and self.signing_key_hex is None:
            raise EnrichmentConfigurationError("kid is set but signing_key_hex is not")
        if self.signing_key_hex is not None:
            signer = build_signing_key(self)
            if signer is not None and self.trusted_public_keys:
                configured = self.trusted_public_keys.get(signer.kid)
                # An empty value is a placeholder, not a key: it neither matches
                # nor contradicts the signer (production requires a real one).
                if configured and configured.strip().lower() != signer.public_key_raw_hex():
                    raise EnrichmentConfigurationError(
                        "trusted public key for the enrichment kid does not match its signing key"
                    )
        return self

    def max_age_seconds(self, source: str) -> float:
        hours = self.kev_max_age_hours if source == "KEV" else self.epss_max_age_hours
        return hours * 3600.0

    def assert_production_ready(self) -> None:
        """Refuse a production start without a recognized signing key and caller list."""
        if self.signing_key_hex is None or not self.kid:
            raise EnrichmentConfigurationError(
                "an enrichment signing key and kid are required in production"
            )
        if not (self.trusted_public_keys.get(self.kid) or "").strip():
            raise EnrichmentConfigurationError(
                "the enrichment kid must be present, with its public key, in the trusted key map"
            )
        if not self.allowed_uids:
            raise EnrichmentConfigurationError(
                "allowed_uids is required in production: enrichment callers are authenticated"
            )


def _private_key(hex_value: str) -> ed25519.Ed25519PrivateKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise EnrichmentConfigurationError("enrichment signing key is not valid hex") from exc
    if len(raw) != ED25519_PRIVATE_KEY_BYTES:
        raise EnrichmentConfigurationError(
            f"enrichment signing key must be {ED25519_PRIVATE_KEY_BYTES} bytes"
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def build_signing_key(settings: EnrichmentSettings) -> Ed25519SigningKey | None:
    """The dedicated enrichment signing key, or None when unconfigured."""
    if settings.signing_key_hex is None:
        return None
    private = _private_key(settings.signing_key_hex.get_secret_value())
    kid = settings.kid or "enrichment-" + private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()[:12]
    return Ed25519SigningKey(kid=kid, _private=private)


def build_trust_store(settings: EnrichmentSettings) -> TrustedKeyStore:
    """Trusted public keys for verifying enrichment artifacts.

    The configured signing key is always trusted for its own kid, so a fresh
    deployment can verify what it emits; rotated-out keys stay verifiable for as
    long as they remain in the configured map.
    """
    keys: dict[str, ed25519.Ed25519PublicKey] = {}
    for kid, pub_hex in settings.trusted_public_keys.items():
        if not pub_hex:
            continue
        try:
            raw = bytes.fromhex(pub_hex.strip())
        except ValueError as exc:
            raise EnrichmentConfigurationError(f"trusted key {kid!r} is not valid hex") from exc
        if len(raw) != ED25519_PUBLIC_KEY_BYTES:
            raise EnrichmentConfigurationError(f"trusted key {kid!r} has the wrong length")
        keys[kid] = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    signer = build_signing_key(settings)
    if signer is not None:
        keys.setdefault(signer.kid, signer.public_key())
    return TrustedKeyStore(keys)


@lru_cache(maxsize=1)
def get_enrichment_settings() -> EnrichmentSettings:
    return EnrichmentSettings()
