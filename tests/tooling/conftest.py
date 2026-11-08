"""Shared fixtures for the tool execution layer tests.

All tests use synthetic/owned targets and reserved documentation ranges and MUST
NOT contact third-party infrastructure.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes
from gryphon.clock import FixedClock
from gryphon.constants import ScanDepth
from gryphon.tooling.capability.claims import build_claims
from gryphon.tooling.capability.verifier import CapabilityVerifier
from gryphon.tooling.constants import ToolId
from gryphon.tooling.destination.egress import EgressHandle

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def cap_private() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def signing_key(cap_private) -> Ed25519SigningKey:
    return Ed25519SigningKey(kid="cap-test", _private=cap_private)


@pytest.fixture
def trust(signing_key) -> TrustedKeyStore:
    return TrustedKeyStore({signing_key.kid: signing_key.public_key()})


@pytest.fixture
def verifier(trust) -> CapabilityVerifier:
    return CapabilityVerifier(trust, clock_skew=timedelta(seconds=30))


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(instant=NOW)


@pytest.fixture
def make_capability_wire(signing_key) -> Callable[..., bytes]:
    """Sign a capability directly (bypassing the DB-backed issuer) for verifier tests."""

    def _make(
        *,
        tool_id: ToolId = ToolId.NUCLEI,
        execution_id: str = "exec-" + "a1b2c3d4e5f6a7b8",
        scan_run_id: str = "run-1",
        grant_id: str = "grant-1",
        claims_digest: str = "claimsdigest",
        scope_digest: str = "scopedigest",
        depth: ScanDepth = ScanDepth.STANDARD,
        iat: int | None = None,
        exp: int | None = None,
        signer: Ed25519SigningKey | None = None,
        kid: str | None = None,
    ) -> bytes:
        key = signer or signing_key
        base_iat = iat if iat is not None else int(NOW.timestamp())
        base_exp = exp if exp is not None else base_iat + 120
        claims = build_claims(
            capability_id="cap-" + secrets.token_hex(4),
            nonce=secrets.token_hex(8),
            kid=kid or key.kid,
            scan_run_id=scan_run_id,
            grant_id=grant_id,
            claims_digest=claims_digest,
            scope_digest=scope_digest,
            tool_id=tool_id,
            effective_scan_depth=depth,
            execution_id=execution_id,
            iat=base_iat,
            exp=base_exp,
        )
        payload = canonical_json_bytes(claims.to_canonical_payload())
        binding = base64.standard_b64encode(key.sign(payload)).decode("ascii")
        wire = {**claims.to_canonical_payload(), "binding": binding}
        return json.dumps(wire).encode("utf-8")

    return _make


class FakeEgressEnforcer:
    """Establishes an identity egress context (test-only allow path)."""

    enforcing = True

    async def establish(self, allowlist: list[str], ports: list[int]) -> EgressHandle:
        return EgressHandle(
            context_id="fake",
            allowlist=tuple(allowlist),
            ports=tuple(ports),
            enforcing=True,
        )

    async def teardown(self, handle: EgressHandle) -> None:
        return None


@pytest.fixture
def fake_egress() -> FakeEgressEnforcer:
    return FakeEgressEnforcer()
