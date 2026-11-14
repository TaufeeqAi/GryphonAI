"""Fail-closed configuration for the verification layer.

Security-relevant values are code constants; a setting may only *narrow* them.
Budgets can be lowered but never raised past the ceilings below, a lease must
outlast two heartbeats, and production refuses to start without a signing key the
trust store recognizes, a caller allowlist, a registry whose signature is
required and checkable, an enforced egress posture and a gateway socket.

Three properties of this module are more than configuration hygiene:

* **An unknown security key is a startup refusal.** ``extra="ignore"`` is kept so
  one ``.env`` can serve several layers, but on its own it means that
  ``GRYPHON_VERIFICATION_ALLOWED_UIDSS`` is discarded in silence and the process
  starts with no caller allowlist at all. A typo in a security variable must not
  leave a permissive default quietly active, so the process environment is
  scanned for prefixed names that are not fields of this model and the load is
  refused, naming every one of them.
* **Two trust stores, and only one key.** ``trusted_public_keys`` belongs to the
  verification key this process holds; ``policy_signing_trusted_keys`` belongs to
  the registry's signer, which it must be unable to sign for. If one key served
  both, "the registry is signed" would be a statement about ourselves rather than
  about an operator's review.
* **No value is ever echoed in an error.** A refusal names the field and the
  rule, never the input, because the fields most likely to be malformed are the
  ones holding key material.

Every field is read from ``GRYPHON_VERIFICATION_*`` environment variables (or
``.env``). The verification process connects to the database with its *own*
role, so it can write only its own tables — never the evidence it adjudicates.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Final, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.constants import ED25519_PRIVATE_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES
from gryphon.verification.constants import (
    DATABASE_ROLE,
    MAX_CONTROLS_PER_FINDING,
    VERIFICATION_CODE_VERSION,
)
from gryphon.verification.reasons import VerificationConfigurationError
from gryphon.verification.registry import DEFAULT_REGISTRY_PATH

#: Every variable this layer reads begins with this. The strict scan below treats
#: the prefix as a namespace the deployment has claimed: a name inside it that is
#: not a field is a mistake, not somebody else's setting.
SECURITY_ENV_PREFIX: Final[str] = "GRYPHON_VERIFICATION_"

#: Budget ceilings. A deployment may lower any of these; raising one past its
#: ceiling is a startup refusal, because the bound belongs to the contract rather
#: than to the environment it runs in. They are expressed as field bounds so the
#: refusal happens while the settings are being built, before anything can run.
_MAX_FINDINGS_PER_PASS: Final[int] = 5_000
_MAX_OBSERVATIONS_PER_PASS: Final[int] = 15_000
#: Per-pass concurrency can never exceed the host ceiling the gateway enforces
#: for one destination; asking for more only moves the queue to the other side of
#: the socket, where a capacity refusal is charged to the pass.
_MAX_CONCURRENCY: Final[int] = 16
_MAX_PASS_DEADLINE_SECONDS: Final[float] = 6 * 3600.0
#: Controls are additional requests to somebody else's host. The ceiling caps how
#: much of that one host absorbs in a single pass; beyond it the control count is
#: reduced and the reduction is recorded on the verdict rather than hidden.
_MAX_CONTROLS_PER_HOST: Final[int] = 1_000

#: What ``resolver_set_digest`` reports when no resolver is pinned. A digest over
#: an empty set would claim a pin that does not exist, and relying on a
#: resolver's defaults is precisely what pinning exists to prevent.
RESOLVER_SET_UNPINNED: Final[str] = "unpinned"


class VerificationSettings(BaseSettings):
    """Typed, frozen configuration for the verification layer."""

    model_config = SettingsConfigDict(
        env_prefix=SECURITY_ENV_PREFIX,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    #: DSN for the dedicated ``gryphon_verification`` role. One process holds one
    #: database identity: the component that writes the gateway's ledger must not
    #: be the component whose claims that ledger settles.
    database_url: str = (
        f"postgresql+asyncpg://{DATABASE_ROLE}:verification_pw@localhost:5432/gryphon"
    )

    # -- attestation key (dedicated purpose: verification output only) ---------
    signing_key_hex: SecretStr | None = None
    kid: str | None = None
    #: Public keys trusted for *verification's own* artifacts — its reports and
    #: its signed events. Nothing else belongs here.
    trusted_public_keys: dict[str, str] = Field(default_factory=dict)

    # -- policy trust (a key this process must not hold) -----------------------
    #: Public keys of the policy signer: the registry, the pinned provider list
    #: and the resolver set are reviewed and signed in operator custody. A digest
    #: proves integrity; a signature from a key this process cannot produce is
    #: what makes the registry an authority rather than a file we wrote.
    policy_signing_trusted_keys: dict[str, str] = Field(default_factory=dict)

    # -- registry --------------------------------------------------------------
    #: Override of the packaged registry document. Any change is a new digest,
    #: and the digest is pinned per pass.
    registry_path: Path | None = None
    #: Whether a registry must carry a signature from the policy trust store.
    #: Production forces this on; elsewhere it stays available so a deployment can
    #: rehearse the production path before it is in production.
    require_signed_registry: bool = False

    # -- gateway (the only outward socket) -------------------------------------
    #: Unix socket of ``gryphon-gatewayd``. A Unix socket is the transport
    #: because the peer's uid is checkable on the kernel's word rather than on
    #: the peer's claim. Without it this layer cannot observe anything at all,
    #: and it must not be able to fall back to a socket of its own.
    gateway_socket_path: Path | None = None
    gateway_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)

    # -- budgets (narrow-only) -------------------------------------------------
    findings_per_pass: int = Field(default=2_000, ge=1, le=_MAX_FINDINGS_PER_PASS)
    observations_per_pass: int = Field(default=6_000, ge=1, le=_MAX_OBSERVATIONS_PER_PASS)
    concurrency: int = Field(default=4, ge=1, le=_MAX_CONCURRENCY)
    pass_deadline_seconds: float = Field(
        default=3_600.0, gt=0, le=_MAX_PASS_DEADLINE_SECONDS
    )
    controls_per_host: int = Field(default=100, ge=1, le=_MAX_CONTROLS_PER_HOST)

    # -- pass lease ------------------------------------------------------------
    pass_lease_seconds: float = Field(default=60.0, gt=0, le=3600)
    pass_heartbeat_seconds: float = Field(default=15.0, gt=0, le=600)

    # -- pinned destination facts ----------------------------------------------
    #: Digest of the estate attestation applied when the pass pins its inputs.
    #: Recorded per pass so a later address change is detectable rather than
    #: invisible. Until an attestation is configured: unset.
    estate_digest: str | None = None
    #: The resolvers a resolver-mediated observation may use, pinned explicitly.
    #: Defaults are never relied upon: a resolver that answers for a name the
    #: operator did not choose can turn a dangling-record check into a false
    #: negative.
    resolver_set: tuple[str, ...] = ()

    # -- egress posture --------------------------------------------------------
    #: The posture the deployment declares. Readiness derives the effective
    #: posture from observed facts instead of trusting this text, so the two
    #: disagreeing is itself a finding; production refuses ``unenforced`` here
    #: before that check can even be reached.
    egress_posture: Literal["enforced", "unenforced"] = "enforced"

    # -- enrichment context (optional, never required) -------------------------
    #: Whether a verified enrichment report may order the pass. With it off the
    #: pass records ``observed_severity`` as its ordering basis and the
    #: deliverable states that prioritisation did not use exploitation
    #: intelligence — which is the honest reading, not a degraded one.
    use_enrichment_context: bool = True
    #: Whether a *superseded* enrichment report may still order the pass. It is a
    #: valid, attested artifact, so the default is yes; either way a superseded
    #: report never abandons traffic-bearing work.
    use_superseded_enrichment: bool = True
    #: Public keys of the enrichment attestation signer. Read-only trust: this
    #: process verifies enrichment reports and can sign none of them.
    enrichment_trusted_public_keys: dict[str, str] = Field(default_factory=dict)

    # -- caller ----------------------------------------------------------------
    #: Real uids permitted to run verification. Empty permits any local user
    #: outside production; required in production.
    allowed_uids: tuple[int, ...] = ()

    @field_validator(
        "signing_key_hex",
        "kid",
        "estate_digest",
        "registry_path",
        "gateway_socket_path",
        mode="before",
    )
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        """An empty variable (as in ``.env.example``) means "not configured"."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("allowed_uids", "resolver_set", mode="before")
    @classmethod
    def _blank_is_empty_sequence(cls, value: object) -> object:
        """A declared-but-empty list variable is an empty list, not a parse error.

        Without this, ``GRYPHON_VERIFICATION_ALLOWED_UIDS=`` fails to parse, and
        the operator's most likely next move is to delete the line — which is the
        same configuration with no record that it was considered.
        """
        if isinstance(value, str) and not value.strip():
            return ()
        return value

    @field_validator(
        "trusted_public_keys",
        "policy_signing_trusted_keys",
        "enrichment_trusted_public_keys",
        mode="before",
    )
    @classmethod
    def _blank_is_empty_mapping(cls, value: object) -> object:
        """Same reasoning as the sequences: a blank key map is empty, not invalid."""
        if isinstance(value, str) and not value.strip():
            return {}
        return value

    @model_validator(mode="after")
    def _validate(self) -> VerificationSettings:
        if self.pass_heartbeat_seconds * 3 > self.pass_lease_seconds:
            raise VerificationConfigurationError(
                "pass_lease_seconds must be at least three times pass_heartbeat_seconds, so one "
                "renewal round trip fits inside the staleness bound"
            )
        if self.kid and self.signing_key_hex is None:
            raise VerificationConfigurationError("kid is set but signing_key_hex is not")
        if self.signing_key_hex is not None:
            signer = build_signing_key(self)
            if signer is not None:
                self._assert_signer_agrees(signer)
                self._assert_policy_custody(signer)
        return self

    def _assert_signer_agrees(self, signer: Ed25519SigningKey) -> None:
        """The configured public key for our own kid must be our own key."""
        configured = self.trusted_public_keys.get(signer.kid)
        # An empty value is a placeholder, not a key: it neither matches nor
        # contradicts the signer (production requires a real one).
        if configured and configured.strip().lower() != signer.public_key_raw_hex():
            raise VerificationConfigurationError(
                "trusted public key for the verification kid does not match its signing key"
            )

    def _assert_policy_custody(self, signer: Ed25519SigningKey) -> None:
        """Refuse a policy trust store this process can sign for.

        If the registry's signer were the verification key, every "the registry
        is signed" check would be satisfied by a document this process produced,
        and an operator's review would have been replaced by a loop.
        """
        own_public = signer.public_key_raw_hex()
        for label, store in (
            ("policy_signing_trusted_keys", self.policy_signing_trusted_keys),
            ("enrichment_trusted_public_keys", self.enrichment_trusted_public_keys),
        ):
            if signer.kid in store:
                raise VerificationConfigurationError(
                    f"the verification kid {signer.kid!r} also appears in {label}; "
                    "this process must not be able to sign what it verifies"
                )
            if any((value or "").strip().lower() == own_public for value in store.values()):
                raise VerificationConfigurationError(
                    f"the verification signing key also appears in {label}; "
                    "generate a dedicated key for each purpose"
                )

    @property
    def registry_file(self) -> Path:
        """The registry document to load: the override, or the packaged one."""
        return self.registry_path or DEFAULT_REGISTRY_PATH

    @property
    def max_observations_per_finding(self) -> int:
        """One primary plus the per-finding control cap. Fixed by the spec."""
        return 1 + MAX_CONTROLS_PER_FINDING

    @property
    def resolvers_pinned(self) -> bool:
        return bool(self.resolver_set)

    @property
    def resolver_set_digest(self) -> str:
        """Digest of the pinned resolver set, recorded on every DNS observation.

        A set, so it is digested sorted: two deployments that list the same
        resolvers in a different order are the same pin, and a report that cites
        this digest is comparable between them.
        """
        if not self.resolver_set:
            return RESOLVER_SET_UNPINNED
        return sha256_hex(canonical_json_bytes({"resolvers": sorted(self.resolver_set)}))

    def redacted_manifest(self) -> dict[str, object]:
        """The effective configuration, safe to print in a readiness report.

        Readiness publishes this so an operator can see what the process actually
        loaded rather than what the deployment template says. Key material is
        reported as presence and kid only: a manifest that printed a private key
        would turn the diagnostic into the incident.
        """
        return {
            "code_version": VERIFICATION_CODE_VERSION,
            "database_role": DATABASE_ROLE,
            "signing_key_present": self.signing_key_hex is not None,
            "kid": self.kid,
            "trusted_kids": sorted(self.trusted_public_keys),
            "policy_signer_kids": sorted(self.policy_signing_trusted_keys),
            "enrichment_signer_kids": sorted(self.enrichment_trusted_public_keys),
            "registry_path": str(self.registry_file),
            "require_signed_registry": self.require_signed_registry,
            "gateway_socket_path": (
                str(self.gateway_socket_path) if self.gateway_socket_path else None
            ),
            "egress_posture": self.egress_posture,
            "allowed_uids": list(self.allowed_uids),
            "budgets": {
                "findings_per_pass": self.findings_per_pass,
                "observations_per_pass": self.observations_per_pass,
                "observations_per_finding": self.max_observations_per_finding,
                "concurrency": self.concurrency,
                "controls_per_host": self.controls_per_host,
                "pass_deadline_seconds": self.pass_deadline_seconds,
            },
            "lease": {
                "pass_lease_seconds": self.pass_lease_seconds,
                "pass_heartbeat_seconds": self.pass_heartbeat_seconds,
            },
            "estate_digest": self.estate_digest,
            "resolver_set_digest": self.resolver_set_digest,
            "enrichment_context": {
                "use_enrichment_context": self.use_enrichment_context,
                "use_superseded_enrichment": self.use_superseded_enrichment,
            },
        }

    def assert_production_ready(self) -> None:
        """Refuse a production start that cannot enforce its own guarantees.

        Each clause below is a control that cannot be added later: an unsigned
        registry has already decided what gets observed, an absent allowlist has
        already let an unknown caller send traffic, and an unenforced egress
        posture has already allowed a socket this layer is not supposed to have.
        """
        if self.signing_key_hex is None or not self.kid:
            raise VerificationConfigurationError(
                "a verification signing key and kid are required in production"
            )
        if not (self.trusted_public_keys.get(self.kid) or "").strip():
            raise VerificationConfigurationError(
                "the verification kid must be present, with its public key, in the trusted key map"
            )
        if not self.allowed_uids:
            raise VerificationConfigurationError(
                "allowed_uids is required in production: verification callers are authenticated"
            )
        if not self.require_signed_registry:
            raise VerificationConfigurationError(
                "production requires a signed registry "
                "(GRYPHON_VERIFICATION_REQUIRE_SIGNED_REGISTRY=true)"
            )
        if not self.policy_signing_trusted_keys:
            raise VerificationConfigurationError(
                "policy_signing_trusted_keys is required in production: a registry signature "
                "cannot be checked against an empty trust store"
            )
        if self.egress_posture != "enforced":
            raise VerificationConfigurationError(
                "production refuses an unenforced egress posture"
            )
        if self.gateway_socket_path is None:
            raise VerificationConfigurationError(
                "gateway_socket_path is required: the gateway is the only path to an observation"
            )


def unknown_security_keys(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Prefixed environment names that are not fields of the settings model.

    pydantic-settings is configured to ignore extras, which keeps one ``.env``
    usable across layers but also means a misspelled security variable is
    discarded without a word. This returns those names so the loader can refuse
    instead, which is the difference between "the allowlist is empty because you
    typed ALLOWED_UIDSS" and a process that silently accepts every caller.
    """
    source = os.environ if environ is None else environ
    known = {
        f"{SECURITY_ENV_PREFIX}{name.upper()}" for name in VerificationSettings.model_fields
    }
    return tuple(
        sorted(
            name
            for name in source
            if name.upper().startswith(SECURITY_ENV_PREFIX) and name.upper() not in known
        )
    )


def assert_strict_security_settings(environ: Mapping[str, str] | None = None) -> None:
    """Refuse the load when the environment carries a name this model cannot use."""
    unknown = unknown_security_keys(environ)
    if unknown:
        raise VerificationConfigurationError(
            "unrecognized " + SECURITY_ENV_PREFIX + "* settings: "
            + ", ".join(unknown)
            + " — a security setting is strict: correct or remove the name"
        )


def _describe(error: ValidationError) -> str:
    """Field names and rules from a validation error, never the inputs.

    The fields most likely to be malformed hold key material, so the message
    carries the location and the rule that rejected it and nothing else.
    """
    parts = []
    for item in error.errors():
        location = ".".join(str(piece) for piece in item["loc"]) or "(root)"
        parts.append(f"{location}: {item['msg']}")
    return "; ".join(parts)


def load_verification_settings(
    environ: Mapping[str, str] | None = None,
) -> VerificationSettings:
    """Build the settings, refusing an unknown or out-of-bounds security key.

    Both refusals are the same kind: a value the deployment believes is in effect
    but is not. They are raised as a configuration error so the operator CLI can
    report them with its configuration exit code rather than a traceback.
    """
    assert_strict_security_settings(environ)
    try:
        return VerificationSettings()
    except ValidationError as exc:
        raise VerificationConfigurationError(
            f"{SECURITY_ENV_PREFIX}* configuration is not usable: {_describe(exc)}"
        ) from exc


def _private_key(hex_value: str) -> ed25519.Ed25519PrivateKey:
    try:
        raw = bytes.fromhex(hex_value.strip())
    except ValueError as exc:
        raise VerificationConfigurationError("verification signing key is not valid hex") from exc
    if len(raw) != ED25519_PRIVATE_KEY_BYTES:
        raise VerificationConfigurationError(
            f"verification signing key must be {ED25519_PRIVATE_KEY_BYTES} bytes"
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def build_signing_key(settings: VerificationSettings) -> Ed25519SigningKey | None:
    """The dedicated verification signing key, or None when unconfigured."""
    if settings.signing_key_hex is None:
        return None
    private = _private_key(settings.signing_key_hex.get_secret_value())
    kid = settings.kid or "verification-" + private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()[:12]
    return Ed25519SigningKey(kid=kid, _private=private)


def _public_keys(
    mapping: Mapping[str, str], *, label: str
) -> dict[str, ed25519.Ed25519PublicKey]:
    keys: dict[str, ed25519.Ed25519PublicKey] = {}
    for kid, pub_hex in mapping.items():
        if not pub_hex:
            continue
        try:
            raw = bytes.fromhex(pub_hex.strip())
        except ValueError as exc:
            raise VerificationConfigurationError(
                f"{label} entry {kid!r} is not valid hex"
            ) from exc
        if len(raw) != ED25519_PUBLIC_KEY_BYTES:
            raise VerificationConfigurationError(f"{label} entry {kid!r} has the wrong length")
        keys[kid] = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    return keys


def build_trust_store(settings: VerificationSettings) -> TrustedKeyStore:
    """Trusted public keys for verifying *this layer's own* artifacts.

    The configured signing key is always trusted for its own kid, so a fresh
    deployment can re-verify the report it just published — which it does before
    serving one. Rotated-out keys stay verifiable for as long as they remain in
    the configured map.
    """
    keys = _public_keys(settings.trusted_public_keys, label="trusted_public_keys")
    signer = build_signing_key(settings)
    if signer is not None:
        keys.setdefault(signer.kid, signer.public_key())
    return TrustedKeyStore(keys)


def build_policy_trust_store(settings: VerificationSettings) -> TrustedKeyStore:
    """Trusted public keys for the policy signer — the registry and its pins.

    Deliberately *not* seeded with our own signing key, unlike the store above.
    Policy is an authority this process consults; a store it could sign for would
    make the registry's signature a formality.
    """
    return TrustedKeyStore(
        _public_keys(settings.policy_signing_trusted_keys, label="policy_signing_trusted_keys")
    )


def build_enrichment_trust_store(settings: VerificationSettings) -> TrustedKeyStore:
    """Trusted public keys for the enrichment attestation signer.

    Also unseeded: enrichment context is an input, and an input this process
    could sign would be an input it could invent.
    """
    return TrustedKeyStore(
        _public_keys(
            settings.enrichment_trusted_public_keys, label="enrichment_trusted_public_keys"
        )
    )


@lru_cache(maxsize=1)
def get_verification_settings() -> VerificationSettings:
    return load_verification_settings()
