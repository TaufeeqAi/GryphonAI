"""Fail-closed settings, caller identity, scan ids and the lease keeper."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.enrichment.engine import LeaseKeeper, canonical_scan_id, template_snapshot_id
from gryphon.enrichment.identity import local_cli_identity
from gryphon.enrichment.reasons import (
    CallerRejected,
    EnrichmentConfigurationError,
    FencedOut,
    InvalidScanId,
)
from gryphon.enrichment.settings import EnrichmentSettings, build_signing_key, build_trust_store

pytestmark = pytest.mark.unit


def _hexes() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    return (
        key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                          serialization.NoEncryption()).hex(),
        key.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw).hex(),
    )


def _settings(**overrides) -> EnrichmentSettings:
    return EnrichmentSettings(_env_file=None, **overrides)


def test_defaults_are_safe() -> None:
    settings = _settings()
    assert set(settings.allowed_hosts) == {"www.cisa.gov", "epss.empiricalsecurity.com"}
    assert settings.max_age_seconds("KEV") == 24 * 3600
    assert settings.max_age_seconds("EPSS") == 48 * 3600


def test_hosts_may_only_narrow() -> None:
    assert _settings(allowed_hosts=("www.cisa.gov",)).allowed_hosts == ("www.cisa.gov",)
    with pytest.raises(EnrichmentConfigurationError, match="narrow"):
        _settings(allowed_hosts=("www.cisa.gov", "nvd.nist.gov"))


def test_max_age_is_capped_at_seven_days() -> None:
    with pytest.raises(ValueError):
        _settings(kev_max_age_hours=24 * 8)


def test_lease_must_cover_two_heartbeats() -> None:
    with pytest.raises(EnrichmentConfigurationError, match="twice"):
        _settings(pass_lease_seconds=20, pass_heartbeat_seconds=15)


def test_kid_without_key_is_refused() -> None:
    with pytest.raises(EnrichmentConfigurationError):
        _settings(kid="enrichment-1")


def test_mismatched_trusted_key_is_refused() -> None:
    private, _ = _hexes()
    _, other_public = _hexes()
    with pytest.raises(EnrichmentConfigurationError, match="does not match"):
        _settings(signing_key_hex=private, kid="enr-1",
                  trusted_public_keys={"enr-1": other_public})


def test_signer_is_always_trusted_for_its_own_kid() -> None:
    private, public = _hexes()
    settings = _settings(signing_key_hex=private, kid="enr-1")
    signer = build_signing_key(settings)
    assert signer is not None and signer.public_key_raw_hex() == public
    assert "enr-1" in build_trust_store(settings).trusted_kids


def test_production_requires_key_trust_and_callers() -> None:
    private, public = _hexes()
    with pytest.raises(EnrichmentConfigurationError, match="signing key"):
        _settings().assert_production_ready()
    with pytest.raises(EnrichmentConfigurationError, match="trusted"):
        _settings(signing_key_hex=private, kid="enr-1").assert_production_ready()
    with pytest.raises(EnrichmentConfigurationError, match="allowed_uids"):
        _settings(signing_key_hex=private, kid="enr-1",
                  trusted_public_keys={"enr-1": public}).assert_production_ready()
    _settings(signing_key_hex=private, kid="enr-1", trusted_public_keys={"enr-1": public},
              allowed_uids=(1000,)).assert_production_ready()


def test_caller_identity_is_the_real_uid(monkeypatch) -> None:
    monkeypatch.setattr("os.getuid", lambda: 1234, raising=False)
    assert local_cli_identity().label == "cli:uid:1234"
    assert local_cli_identity(allowed_uids=(1234,)).uid == 1234
    with pytest.raises(CallerRejected):
        local_cli_identity(allowed_uids=(1,))


def test_caller_label_matches_the_orchestration_layer(monkeypatch) -> None:
    from gryphon.orchestration.commands import local_cli_identity as upstream

    monkeypatch.setattr("os.getuid", lambda: 1234, raising=False)
    assert local_cli_identity().label == upstream().label


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("11111111-2222-4333-8444-555555555555", "11111111-2222-4333-8444-555555555555"),
        (" 11111111-2222-4333-8444-555555555555 ", "11111111-2222-4333-8444-555555555555"),
        ("11111111222243338444555555555555", "11111111-2222-4333-8444-555555555555"),
        ("11111111-2222-4333-8444-55555555555A", "11111111-2222-4333-8444-55555555555a"),
    ],
)
def test_scan_ids_are_canonicalized(raw: str, expected: str) -> None:
    assert canonical_scan_id(raw) == expected


@pytest.mark.parametrize("raw", ["", "not-a-uuid", "'; DROP TABLE x; --", "1" * 100])
def test_invalid_scan_ids_are_refused(raw: str) -> None:
    with pytest.raises(InvalidScanId):
        canonical_scan_id(raw)


def test_template_snapshot_id() -> None:
    assert template_snapshot_id(None) == "TEMPLATES:unpinned"
    assert template_snapshot_id("abc") == "TEMPLATES:abc"


def test_lease_keeper_reports_loss_by_local_bound() -> None:
    now = [100.0]
    keeper = LeaseKeeper(None, holder="h", epoch=1, lease_seconds=60, heartbeat_seconds=15,  # type: ignore[arg-type]
                         monotonic=lambda: now[0])
    keeper.ensure_held()
    now[0] += 44.9
    assert not keeper.lost
    now[0] += 0.2  # past lease - heartbeat without a renewal
    assert keeper.lost
    with pytest.raises(FencedOut):
        keeper.ensure_held()
