"""Shared fixtures.

All tests use synthetic domains/IPs and reserved documentation ranges and MUST
NOT touch third-party infrastructure (§30). Pure fixtures build keys, claims and
tokens in-process; database-backed fixtures are gated on
``GRYPHON_TEST_DATABASE_URL`` and skipped when it is absent.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.audit_signer import AuditSigner
from gryphon.auth.authorization_token import GrantSigner, GrantVerifier
from gryphon.auth.claims import GrantClaims
from gryphon.auth.key_provider import build_key_material
from gryphon.auth.scope import ScopeEntry
from gryphon.clock import FixedClock
from gryphon.constants import CLAIMS_SCHEMA_VERSION, SCOPE_POLICY_VERSION, ScanDepth, TargetType
from gryphon.settings import Settings

ISSUER = "gryphon-test-issuer"
AUDIENCE = "gryphon-test-audience"
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _raw_hex(key: ed25519.Ed25519PrivateKey) -> tuple[str, str]:
    priv = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    return priv, pub


@pytest.fixture(scope="session")
def key_hexes() -> dict[str, str]:
    grant_priv, grant_pub = _raw_hex(ed25519.Ed25519PrivateKey.generate())
    audit_priv, audit_pub = _raw_hex(ed25519.Ed25519PrivateKey.generate())
    return {
        "grant_kid": "grant-test",
        "grant_priv": grant_priv,
        "grant_pub": grant_pub,
        "audit_kid": "audit-test",
        "audit_priv": audit_priv,
        "audit_pub": audit_pub,
    }


@pytest.fixture
def settings(key_hexes: dict[str, str]) -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        issuer=ISSUER,
        audience=AUDIENCE,
        grant_signing_key_hex=key_hexes["grant_priv"],
        grant_kid=key_hexes["grant_kid"],
        grant_trusted_public_keys={key_hexes["grant_kid"]: key_hexes["grant_pub"]},
        audit_signing_key_hex=key_hexes["audit_priv"],
        audit_kid=key_hexes["audit_kid"],
        audit_trusted_public_keys={key_hexes["audit_kid"]: key_hexes["audit_pub"]},
        clock_skew_seconds=60,
        database_url=os.environ.get(
            "GRYPHON_TEST_DATABASE_URL",
            "postgresql+asyncpg://gryphon_runtime:runtime_pw@localhost:5432/gryphon_test",
        ),
    )


@pytest.fixture
def key_material(settings: Settings):
    return build_key_material(settings)


@pytest.fixture
def grant_signer(key_material) -> GrantSigner:
    return GrantSigner(key_material.grant_signer)


@pytest.fixture
def audit_signer(key_material) -> AuditSigner:
    return AuditSigner(key_material.audit_signer)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(instant=NOW)


@pytest.fixture
def verifier(key_material) -> GrantVerifier:
    return GrantVerifier(
        key_material.grant_trust,
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
        clock_skew=timedelta(seconds=60),
    )


@pytest.fixture
def make_claims() -> Callable[..., GrantClaims]:
    """Factory producing valid claims with overridable fields."""

    def _make(
        *,
        scope: tuple[ScopeEntry, ...] | None = None,
        iat: datetime = NOW,
        nbf: datetime | None = None,
        exp: datetime | None = None,
        max_scan_depth: ScanDepth = ScanDepth.STANDARD,
        grant_id: str = "grant-0001",
        jti: str = "jti-0001",
        iss: str = ISSUER,
        aud: str = AUDIENCE,
    ) -> GrantClaims:
        if scope is None:
            scope = (
                ScopeEntry(target_type=TargetType.DOMAIN, target="app.example.com"),
            )
        return GrantClaims(
            iss=iss,
            aud=aud,
            iat=iat,
            nbf=nbf or iat,
            exp=exp or (iat + timedelta(days=7)),
            jti=jti,
            grant_id=grant_id,
            granted_by="owner@example.com",
            granted_to="tester@contractor.example",
            organization="Example Org",
            scope=scope,
            max_scan_depth=max_scan_depth,
            written_authorization_ref="SOW-TEST-0001",
            schema_version=CLAIMS_SCHEMA_VERSION,
            scope_policy_version=SCOPE_POLICY_VERSION,
        )

    return _make


@pytest.fixture
def make_token(grant_signer: GrantSigner, make_claims) -> Callable[..., str]:
    def _make(**kwargs) -> str:
        return grant_signer.sign(make_claims(**kwargs))

    return _make
