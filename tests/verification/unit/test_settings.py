"""Fail-closed configuration: strict security keys, narrow-only budgets, custody.

Each test here stands for a way a deployment can look correct and be permissive.
The typo tests matter most: every one of them produced a *working* process under
``extra="ignore"``, with the security value the operator thought they had set
silently at its default.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.verification.reasons import VerificationConfigurationError
from gryphon.verification.settings import (
    RESOLVER_SET_UNPINNED,
    SECURITY_ENV_PREFIX,
    VerificationSettings,
    assert_strict_security_settings,
    build_enrichment_trust_store,
    build_policy_trust_store,
    build_signing_key,
    build_trust_store,
    load_verification_settings,
    unknown_security_keys,
)

pytestmark = pytest.mark.unit


def _hexes() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    return (
        key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                          serialization.NoEncryption()).hex(),
        key.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw).hex(),
    )


def _settings(**overrides) -> VerificationSettings:
    return VerificationSettings(_env_file=None, **overrides)


def _production(**overrides) -> VerificationSettings:
    """A settings object that passes every production clause, before overrides."""
    private, public = _hexes()
    base = {
        "signing_key_hex": private,
        "kid": "ver-1",
        "trusted_public_keys": {"ver-1": public},
        "policy_signing_trusted_keys": {"policy-1": _hexes()[1]},
        "require_signed_registry": True,
        "allowed_uids": (1000,),
        "gateway_socket_path": "/run/gryphon/gatewayd.sock",
    }
    return _settings(**{**base, **overrides})


# -- defaults ----------------------------------------------------------------


def test_defaults_are_safe() -> None:
    settings = _settings()
    assert settings.findings_per_pass == 2_000
    assert settings.observations_per_pass == 6_000
    assert settings.concurrency == 4
    assert settings.max_observations_per_finding == 3
    assert settings.egress_posture == "enforced"
    assert settings.allowed_uids == ()
    assert settings.registry_file.name == "registry_v1.json"
    # Nothing is pinned until an operator pins it, and the manifest says so
    # rather than reporting a digest over an empty set.
    assert settings.resolver_set_digest == RESOLVER_SET_UNPINNED
    assert settings.resolvers_pinned is False


def test_resolver_digest_is_order_independent_and_pinned() -> None:
    one = _settings(resolver_set=("192.0.2.10", "192.0.2.11"))
    other = _settings(resolver_set=("192.0.2.11", "192.0.2.10"))
    assert one.resolver_set_digest == other.resolver_set_digest != RESOLVER_SET_UNPINNED
    assert one.resolvers_pinned is True


def test_redacted_manifest_carries_no_key_material() -> None:
    private, public = _hexes()
    manifest = _settings(
        signing_key_hex=private, kid="ver-1", trusted_public_keys={"ver-1": public}
    ).redacted_manifest()
    assert manifest["signing_key_present"] is True
    assert manifest["kid"] == "ver-1"
    rendered = repr(manifest)
    assert private not in rendered
    assert public not in rendered


# -- strict security settings (CHG-P5-036) -----------------------------------


def test_unknown_prefixed_name_is_reported() -> None:
    environ = {
        f"{SECURITY_ENV_PREFIX}ALLOWED_UIDS": "[1000]",
        f"{SECURITY_ENV_PREFIX}ALLOWED_UIDSS": "[1000]",
        f"{SECURITY_ENV_PREFIX}CONCURENCY": "2",
        "GRYPHON_ENRICHMENT_KID": "enr-1",
        "PATH": "/usr/bin",
    }
    assert unknown_security_keys(environ) == (
        f"{SECURITY_ENV_PREFIX}ALLOWED_UIDSS",
        f"{SECURITY_ENV_PREFIX}CONCURENCY",
    )


def test_unknown_prefixed_name_refuses_the_load() -> None:
    environ = {f"{SECURITY_ENV_PREFIX}SIGNNG_KEY_HEX": "00"}
    with pytest.raises(VerificationConfigurationError) as refusal:
        assert_strict_security_settings(environ)
    # The message must name the key, or the operator cannot find the typo.
    assert f"{SECURITY_ENV_PREFIX}SIGNNG_KEY_HEX" in str(refusal.value)


def test_every_field_name_is_accepted() -> None:
    environ = {
        f"{SECURITY_ENV_PREFIX}{name.upper()}": "" for name in VerificationSettings.model_fields
    }
    assert unknown_security_keys(environ) == ()
    assert_strict_security_settings(environ)


def test_other_layers_settings_are_not_this_layers_business() -> None:
    assert unknown_security_keys({"GRYPHON_ENRICHMENT_WHATEVER": "x", "GRYPHON_KID": "k"}) == ()


def test_out_of_bounds_value_refuses_the_load_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(f"{SECURITY_ENV_PREFIX}FINDINGS_PER_PASS", "999999")
    with pytest.raises(VerificationConfigurationError) as refusal:
        load_verification_settings()
    message = str(refusal.value)
    # The field and the rule, so the operator can fix it; not the input, because
    # the next field to be malformed holds key material.
    assert "findings_per_pass" in message
    assert "999999" not in message


def test_a_malformed_signing_key_refuses_the_load(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{SECURITY_ENV_PREFIX}SIGNING_KEY_HEX", "not-a-key")
    with pytest.raises(VerificationConfigurationError, match="not valid hex"):
        load_verification_settings()


# -- narrow-only budgets -----------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("findings_per_pass", 5_001),
        ("observations_per_pass", 15_001),
        ("concurrency", 17),
        ("pass_deadline_seconds", 6 * 3600 + 1),
        ("controls_per_host", 1_001),
    ],
)
def test_a_budget_may_not_be_raised_past_its_ceiling(field: str, value: float) -> None:
    with pytest.raises(ValueError):
        _settings(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("findings_per_pass", 25),
        ("observations_per_pass", 100),
        ("concurrency", 1),
        ("pass_deadline_seconds", 300.0),
        ("controls_per_host", 5),
    ],
)
def test_a_budget_may_always_be_lowered(field: str, value: float) -> None:
    assert getattr(_settings(**{field: value}), field) == value


def test_lease_must_leave_room_for_one_renewal_round_trip() -> None:
    """The settings bound matches the kernel's, so the two cannot drift apart."""
    with pytest.raises(VerificationConfigurationError, match="three times"):
        _settings(pass_lease_seconds=30, pass_heartbeat_seconds=15)
    _settings(pass_lease_seconds=45, pass_heartbeat_seconds=15)


# -- keys and custody --------------------------------------------------------


def test_kid_without_key_is_refused() -> None:
    with pytest.raises(VerificationConfigurationError):
        _settings(kid="ver-1")


def test_mismatched_trusted_key_is_refused() -> None:
    private, _ = _hexes()
    _, other_public = _hexes()
    with pytest.raises(VerificationConfigurationError, match="does not match"):
        _settings(signing_key_hex=private, kid="ver-1",
                  trusted_public_keys={"ver-1": other_public})


def test_signer_is_trusted_for_its_own_kid_but_never_for_policy() -> None:
    private, public = _hexes()
    _, policy_public = _hexes()
    settings = _settings(
        signing_key_hex=private,
        kid="ver-1",
        policy_signing_trusted_keys={"policy-1": policy_public},
        enrichment_trusted_public_keys={"enr-1": policy_public},
    )
    signer = build_signing_key(settings)
    assert signer is not None and signer.public_key_raw_hex() == public
    assert "ver-1" in build_trust_store(settings).trusted_kids
    # The registry and the enrichment report are inputs: a store this process
    # can sign for would make verifying them a loop.
    assert build_policy_trust_store(settings).trusted_kids == frozenset({"policy-1"})
    assert build_enrichment_trust_store(settings).trusted_kids == frozenset({"enr-1"})


@pytest.mark.parametrize(
    "field", ["policy_signing_trusted_keys", "enrichment_trusted_public_keys"]
)
def test_a_store_this_process_can_sign_for_is_refused(field: str) -> None:
    private, public = _hexes()
    with pytest.raises(VerificationConfigurationError, match=r"must not be able to sign|dedicated"):
        _settings(signing_key_hex=private, kid="ver-1", **{field: {"ver-1": public}})
    with pytest.raises(VerificationConfigurationError, match="dedicated key"):
        _settings(signing_key_hex=private, kid="ver-1", **{field: {"policy-1": public}})


def test_a_malformed_trusted_key_is_refused() -> None:
    with pytest.raises(VerificationConfigurationError, match="not valid hex"):
        build_policy_trust_store(_settings(policy_signing_trusted_keys={"policy-1": "zz"}))
    with pytest.raises(VerificationConfigurationError, match="wrong length"):
        build_policy_trust_store(_settings(policy_signing_trusted_keys={"policy-1": "00ff"}))


# -- production clauses ------------------------------------------------------


def test_production_requires_a_recognized_signing_key() -> None:
    private, _public = _hexes()
    with pytest.raises(VerificationConfigurationError, match="signing key"):
        _settings().assert_production_ready()
    with pytest.raises(VerificationConfigurationError, match="trusted key map"):
        _settings(signing_key_hex=private, kid="ver-1").assert_production_ready()
    with pytest.raises(VerificationConfigurationError, match="trusted key map"):
        _settings(
            signing_key_hex=private, kid="ver-1", trusted_public_keys={"ver-1": ""}
        ).assert_production_ready()


def test_production_requires_a_caller_allowlist() -> None:
    with pytest.raises(VerificationConfigurationError, match="allowed_uids"):
        _production(allowed_uids=()).assert_production_ready()


def test_production_requires_a_signed_and_checkable_registry() -> None:
    with pytest.raises(VerificationConfigurationError, match="signed registry"):
        _production(require_signed_registry=False).assert_production_ready()
    with pytest.raises(VerificationConfigurationError, match="policy_signing_trusted_keys"):
        _production(policy_signing_trusted_keys={}).assert_production_ready()


def test_production_refuses_an_unenforced_egress_posture() -> None:
    with pytest.raises(VerificationConfigurationError, match="egress"):
        _production(egress_posture="unenforced").assert_production_ready()


def test_production_requires_a_gateway_socket() -> None:
    with pytest.raises(VerificationConfigurationError, match="gateway_socket_path"):
        _production(gateway_socket_path=None).assert_production_ready()


def test_a_complete_production_configuration_is_accepted() -> None:
    _production().assert_production_ready()


# -- blank is unset ----------------------------------------------------------


def test_blank_scalar_variables_mean_not_configured() -> None:
    settings = _settings(
        signing_key_hex="", kid="  ", estate_digest="", registry_path="", gateway_socket_path=""
    )
    assert settings.signing_key_hex is None
    assert settings.kid is None
    assert settings.estate_digest is None
    assert settings.registry_path is None
    assert settings.gateway_socket_path is None
    assert build_signing_key(settings) is None
    # The packaged registry still resolves: an unset override is not a missing
    # registry.
    assert settings.registry_file.name == "registry_v1.json"


def test_blank_collection_variables_mean_empty() -> None:
    settings = _settings(
        allowed_uids="",
        resolver_set="",
        trusted_public_keys="",
        policy_signing_trusted_keys="",
        enrichment_trusted_public_keys="",
    )
    assert settings.allowed_uids == ()
    assert settings.resolver_set == ()
    assert settings.trusted_public_keys == {}
    assert settings.policy_signing_trusted_keys == {}
    assert settings.enrichment_trusted_public_keys == {}
