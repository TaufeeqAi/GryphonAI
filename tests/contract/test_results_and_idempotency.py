"""Result-type and idempotency contracts (§11.4, §17, SEC-015/INV-022)."""

from __future__ import annotations

import pytest

from gryphon.auth.idempotency import (
    hash_idempotency_key,
    scan_request_hash,
    validate_idempotency_key,
)
from gryphon.auth.results import AuthorizedPermit
from gryphon.constants import ScanDepth
from gryphon.errors import ReasonCode, ValidationError

pytestmark = pytest.mark.contract


def test_permit_cannot_be_constructed_directly() -> None:
    with pytest.raises(TypeError):
        AuthorizedPermit(
            scan_run_id="r",
            grant_id="g",
            canonical_target="app.example.com",
            effective_scan_depth=ScanDepth.STANDARD,
            claims_digest="d",
            scope_policy_version="1",
            admitted_at=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
            audit_event_id="a",
        )


def test_permit_cannot_be_built_from_caller_json() -> None:
    # Simulating deserialization from request JSON: the guard object is absent.
    payload = {
        "scan_run_id": "r",
        "grant_id": "g",
        "canonical_target": "app.example.com",
        "effective_scan_depth": ScanDepth.STANDARD,
        "claims_digest": "d",
        "scope_policy_version": "1",
        "admitted_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ),
        "audit_event_id": "a",
    }
    with pytest.raises(TypeError):
        AuthorizedPermit(**payload)


@pytest.mark.parametrize("key", ["", "x" * 8, "a" * 1000, "z" * 16])
def test_idempotency_key_bounds(key: str) -> None:
    if key == "z" * 16:
        with pytest.raises(ValidationError) as exc:
            validate_idempotency_key(key)  # single repeated char -> low entropy
        assert exc.value.reason_code is ReasonCode.IDEMPOTENCY_KEY_INVALID
    else:
        with pytest.raises(ValidationError):
            validate_idempotency_key(key)


def test_valid_idempotency_key_accepted() -> None:
    validate_idempotency_key("0123456789abcdef0123456789abcdef")  # 32 hex chars


def test_key_hash_is_not_the_raw_key() -> None:
    key = "0123456789abcdef0123456789abcdef"
    assert hash_idempotency_key(key) != key
    assert len(hash_idempotency_key(key)) == 64


def test_request_hash_is_deterministic_and_token_sensitive() -> None:
    h1 = scan_request_hash(token="tok-a", target="app.example.com", path=None, requested_depth="standard")
    h2 = scan_request_hash(token="tok-a", target="app.example.com", path=None, requested_depth="standard")
    h3 = scan_request_hash(token="tok-b", target="app.example.com", path=None, requested_depth="standard")
    assert h1 == h2
    assert h1 != h3
