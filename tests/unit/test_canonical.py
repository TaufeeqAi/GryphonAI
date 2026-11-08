"""Strict parsing + canonicalization (§9.2.4, §22.1)."""

from __future__ import annotations

import pytest

from gryphon.canonical import canonical_json_bytes, sha256_hex, strict_json_loads
from gryphon.errors import ReasonCode, ValidationError

pytestmark = pytest.mark.unit


def test_canonical_json_is_deterministic_and_key_sorted() -> None:
    a = canonical_json_bytes({"b": 1, "a": 2})
    b = canonical_json_bytes({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_sha256_hex_known_value() -> None:
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_strict_json_accepts_simple_object() -> None:
    assert strict_json_loads(b'{"x": 1, "y": "z"}') == {"x": 1, "y": "z"}


def test_strict_json_rejects_duplicate_members() -> None:
    with pytest.raises(ValidationError) as exc:
        strict_json_loads(b'{"a": 1, "a": 2}')
    assert exc.value.reason_code is ReasonCode.TOKEN_DUPLICATE_CLAIM


@pytest.mark.parametrize("payload", [b'{"x": NaN}', b'{"x": Infinity}', b'{"x": -Infinity}'])
def test_strict_json_rejects_non_finite_constants(payload: bytes) -> None:
    with pytest.raises(ValidationError) as exc:
        strict_json_loads(payload)
    assert exc.value.reason_code is ReasonCode.TOKEN_MALFORMED


def test_strict_json_rejects_non_finite_float_literal() -> None:
    with pytest.raises(ValidationError):
        strict_json_loads(b'{"x": 1e999}')


def test_strict_json_rejects_non_object_top_level() -> None:
    with pytest.raises(ValidationError):
        strict_json_loads(b"[1, 2, 3]")


def test_strict_json_rejects_invalid_utf8() -> None:
    with pytest.raises(ValidationError):
        strict_json_loads(b'{"x": "\xff\xfe"}')
