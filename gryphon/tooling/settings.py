"""Fail-closed configuration for the tool execution layer.

Security rules enforced here (mirroring the authorization core):

* In ``prod`` the capability-signing key and its ``kid`` are REQUIRED; no
  ephemeral key is ever generated.
* ``unenforced`` egress is PROHIBITED in ``prod`` and requires an explicit
  opt-in flag outside it — the default is OS-enforced containment.
* Capability signing is asymmetric; the configured key must be a valid 32-byte
  Ed25519 key, and its public half must appear in the trusted map under its
  ``kid`` so the issuer's own capabilities verify.

Distinctness of the capability key from the grant and audit keys is checked in
``bootstrap`` where all three are available (SEC: three distinct keys).
"""

from __future__ import annotations

import platform
from functools import lru_cache
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gryphon.constants import ED25519_PRIVATE_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES
from gryphon.tooling.constants import MAX_CAPABILITY_TTL_SECONDS, EgressMode
from gryphon.tooling.reasons import ToolingConfigurationError


def _public_raw_hex(key: ed25519.Ed25519PublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def _load_private(hex_value: str, label: str) -> ed25519.Ed25519PrivateKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise ToolingConfigurationError(f"{label} is not valid hex") from exc
    if len(raw) != ED25519_PRIVATE_KEY_BYTES:
        raise ToolingConfigurationError(f"{label} must be {ED25519_PRIVATE_KEY_BYTES} bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def _load_public(hex_value: str, label: str) -> ed25519.Ed25519PublicKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise ToolingConfigurationError(f"{label} is not valid hex") from exc
    if len(raw) != ED25519_PUBLIC_KEY_BYTES:
        raise ToolingConfigurationError(f"{label} must be {ED25519_PUBLIC_KEY_BYTES} bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


class ToolingSettings(BaseSettings):
    """Typed configuration for the tool execution layer."""

    model_config = SettingsConfigDict(
        env_prefix="GRYPHON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    environment: Literal["dev", "test", "prod"] = "dev"

    # ---- Capability signing (DISTINCT from grant & audit keys) --------------
    capability_signing_key_hex: SecretStr | None = None
    capability_kid: str | None = None
    capability_trusted_public_keys: dict[str, str] = Field(default_factory=dict)

    # ---- Capability temporal policy -----------------------------------------
    capability_ttl_seconds: int = Field(default=120, gt=0, le=MAX_CAPABILITY_TTL_SECONDS)
    capability_clock_skew_seconds: int = Field(default=30, ge=0, le=300)

    # ---- Egress enforcement posture -----------------------------------------
    egress_mode: EgressMode = EgressMode.ENFORCED
    #: Opt-in required to run ``unenforced`` egress outside prod; never in prod.
    allow_unenforced_egress: bool = False
    #: Optional privileged helper that performs the namespace + nftables setup,
    #: so the application process itself can run unprivileged. When unset, the
    #: process must hold CAP_NET_ADMIN to establish a context.
    egress_helper_path: str | None = None

    # ---- Aggregate budgets --------------------------------------------------
    max_host_concurrent_executions: int = Field(default=16, ge=1, le=1024)
    per_run_max_concurrent: int = Field(default=8, ge=1, le=512)
    per_run_rate_per_second: float = Field(default=5.0, gt=0, le=1000)
    per_run_burst: int = Field(default=10, ge=1, le=1000)
    breaker_failure_threshold: int = Field(default=5, ge=1, le=100)
    breaker_reset_seconds: float = Field(default=30.0, gt=0, le=600)

    # ---- Subprocess bounds --------------------------------------------------
    subprocess_default_timeout_seconds: float = Field(default=120.0, gt=0, le=1800)
    subprocess_max_stdout_bytes: int = Field(default=16 * 1024 * 1024, ge=4096)
    subprocess_memory_limit_mb: int = Field(default=1024, ge=64, le=16384)

    # ---- Resolution ---------------------------------------------------------
    resolve_timeout_seconds: float = Field(default=5.0, gt=0, le=60)

    # ---- Provisioning -------------------------------------------------------
    tool_bin_dir: str | None = None
    tool_manifest_path: str | None = None
    nuclei_templates_dir: str | None = None

    # ---- Retry / reconciliation --------------------------------------------
    db_max_retries: int = Field(default=2, ge=0, le=5)

    @property
    def is_production(self) -> bool:
        return self.environment == "prod"

    @model_validator(mode="after")
    def _validate(self) -> "ToolingSettings":
        prod = self.environment == "prod"

        # Linux is the only supported production runtime: OS egress containment,
        # the memory rlimit and process-group kill all require it. Other
        # platforms remain fully usable for tests, readiness and verification.
        if prod and platform.system() != "Linux":
            raise ToolingConfigurationError(
                f"production requires Linux; {platform.system()} cannot enforce OS egress "
                "containment, subprocess memory limits or process-group termination"
            )

        if prod and not (self.capability_signing_key_hex and self.capability_kid):
            raise ToolingConfigurationError(
                "production requires GRYPHON_CAPABILITY_SIGNING_KEY_HEX and GRYPHON_CAPABILITY_KID"
            )

        # Egress: unenforced is prohibited in prod and needs an explicit opt-in.
        if self.egress_mode is EgressMode.UNENFORCED:
            if prod:
                raise ToolingConfigurationError("unenforced egress is prohibited in production")
            if not self.allow_unenforced_egress:
                raise ToolingConfigurationError(
                    "unenforced egress requires GRYPHON_ALLOW_UNENFORCED_EGRESS=true"
                )

        if self.capability_ttl_seconds < self.capability_clock_skew_seconds:
            raise ToolingConfigurationError(
                "capability_ttl_seconds must be >= capability_clock_skew_seconds"
            )

        # Validate trusted capability public keys.
        for kid, pub_hex in self.capability_trusted_public_keys.items():
            if not pub_hex:
                if prod:
                    raise ToolingConfigurationError(
                        f"capability trusted key {kid!r} has empty public key in prod"
                    )
                continue
            _load_public(pub_hex, f"capability trusted public key {kid!r}")

        # Validate the signing key and that its public half is trusted.
        if self.capability_signing_key_hex:
            private = _load_private(
                self.capability_signing_key_hex.get_secret_value(), "capability signing key"
            )
            public_fpr = _public_raw_hex(private.public_key())
            if self.capability_kid:
                configured = self.capability_trusted_public_keys.get(self.capability_kid)
                if configured:
                    if configured.strip().lower() != public_fpr.lower():
                        raise ToolingConfigurationError(
                            f"capability trusted public key for kid {self.capability_kid!r} "
                            "does not match its signing key"
                        )
                elif prod:
                    raise ToolingConfigurationError(
                        f"capability signing kid {self.capability_kid!r} is not in its trusted map"
                    )
        return self

    def capability_public_fingerprint(self) -> str | None:
        if not self.capability_signing_key_hex:
            return None
        private = _load_private(
            self.capability_signing_key_hex.get_secret_value(), "capability signing key"
        )
        return _public_raw_hex(private.public_key())


@lru_cache(maxsize=1)
def get_tooling_settings() -> ToolingSettings:
    return ToolingSettings()  # type: ignore[call-arg]
