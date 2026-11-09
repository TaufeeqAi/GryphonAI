"""Shared fixtures for the orchestration layer tests.

All tests use synthetic targets and reserved documentation ranges and MUST NOT
contact third-party infrastructure. The pure fixtures here need no database, no
graph and no tool, which is the point: the properties that matter most in this
layer (identity stability, coverage arithmetic, state closure) are pure
functions over recorded facts, so they are cheap to exercise exhaustively.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import Ed25519SigningKey
from gryphon.clock import FixedClock
from gryphon.constants import ScanDepth, TargetType
from gryphon.auth.scope import ScopeEntry
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.settings import OrchestrationSettings

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
SCAN_RUN_ID = "11111111-2222-3333-4444-555555555555"
SEED_TARGET = "app.example.com"
#: RFC 5737 documentation range: safe to use as an "estate" in tests.
ESTATE_CIDR = "203.0.113.0/24"
OUTSIDE_ESTATE = "198.51.100.7"
#: A deterministic salt so identity tests assert exact, reproducible values.
TEST_SALT = "a1" * 32


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(instant=NOW)


@pytest.fixture
def orchestration_settings() -> OrchestrationSettings:
    return OrchestrationSettings(
        _env_file=None,
        environment="test",
        scan_lease_seconds=60.0,
        scan_heartbeat_seconds=15.0,
        sweeper_interval_seconds=30.0,
        reconciliation_window_seconds=900.0,
        attested_estate_cidrs=(ESTATE_CIDR,),
        discovered_target_cap=100,
        strict_address_attestation=True,
    )


@pytest.fixture
def audit_builder() -> OrchestrationAuditBuilder:
    key = Ed25519SigningKey(kid="audit-test", _private=ed25519.Ed25519PrivateKey.generate())
    return OrchestrationAuditBuilder(key)


@pytest.fixture
def scope_entries() -> tuple[ScopeEntry, ...]:
    """A wildcard grant, which is the normal shape for an external engagement."""
    return (
        ScopeEntry(target_type=TargetType.DOMAIN_WILDCARD, target="*.example.com"),
    )


@pytest.fixture
def grant_expiry() -> datetime:
    return NOW + timedelta(hours=6)


class StubResolver:
    """A resolver with a fixed answer table. No DNS, no network."""

    def __init__(self, table: dict[str, list[str]] | None = None) -> None:
        self.table = table or {}
        self.calls: list[str] = []

    async def resolve(self, host: str):
        import ipaddress

        self.calls.append(host)
        if host not in self.table:
            raise OSError(f"no answer for {host}")
        return [ipaddress.ip_address(a) for a in self.table[host]]


@pytest.fixture
def stub_resolver() -> StubResolver:
    return StubResolver()


def depth() -> ScanDepth:
    return ScanDepth.STANDARD
