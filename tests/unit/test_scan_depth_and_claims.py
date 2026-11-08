"""Scan-depth clamp + claim validation (§11.2, §11.6, SEC-005)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from gryphon.auth.scope import ScopeEntry
from gryphon.constants import TargetType, ScanDepth
from gryphon.errors import ValidationError

pytestmark = pytest.mark.unit

_UTC = timezone.utc
_NOW = datetime(2026, 6, 1, tzinfo=_UTC)


def test_scan_depth_ordering() -> None:
    assert ScanDepth.PASSIVE.rank < ScanDepth.STANDARD.rank < ScanDepth.AGGRESSIVE.rank


@pytest.mark.parametrize(
    "requested,grant_max,expected",
    [
        (ScanDepth.AGGRESSIVE, ScanDepth.STANDARD, ScanDepth.STANDARD),
        (ScanDepth.PASSIVE, ScanDepth.AGGRESSIVE, ScanDepth.PASSIVE),
        (ScanDepth.STANDARD, ScanDepth.STANDARD, ScanDepth.STANDARD),
    ],
)
def test_clamp_is_less_permissive(requested, grant_max, expected) -> None:
    assert ScanDepth.clamp(requested, grant_max) is expected


def test_claims_reject_lifetime_over_90_days(make_claims) -> None:
    with pytest.raises(ValidationError):
        make_claims(iat=_NOW, exp=_NOW + timedelta(days=91))


def test_claims_reject_non_positive_lifetime(make_claims) -> None:
    with pytest.raises(ValidationError):
        make_claims(iat=_NOW, exp=_NOW)


def test_claims_reject_naive_datetime(make_claims) -> None:
    with pytest.raises(ValidationError):
        make_claims(iat=datetime(2026, 6, 1), exp=datetime(2026, 6, 2))  # noqa: DTZ001


def test_claims_reject_empty_scope(make_claims) -> None:
    with pytest.raises(ValidationError):
        make_claims(scope=())


def test_scope_entry_canonicalizes_on_construction() -> None:
    entry = ScopeEntry(target_type=TargetType.DOMAIN, target="API.Example.COM")
    assert entry.target == "api.example.com"
