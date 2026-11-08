"""Canonical serialization, strict parsing and digests.

Two distinct, pinned mechanisms live here:

1. **RFC 8785 JSON Canonicalization Scheme (JCS)** via the ``rfc8785`` library —
   used for audit payloads and scope digests so a signature covers one, stable,
   byte-exact representation (§22.1).

2. **A strict JSON loader** for the *decoded JWS payload bytes*. Per §9.2.4 the
   token parser MUST reject duplicate JSON member names (no last-key-wins),
   non-finite numbers and unbounded nesting. The ``claims_digest`` is computed
   over the *exact decoded bytes* — never a re-serialization (§22.1).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import rfc8785

from gryphon.constants import MAX_JSON_DEPTH, MAX_JSON_MEMBERS
from gryphon.errors import ReasonCode, ValidationError

__all__ = [
    "canonical_json_bytes",
    "sha256_hex",
    "sha256_hex_text",
    "strict_json_loads",
]


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize ``obj`` to RFC 8785 canonical JSON (UTF-8 bytes).

    Used for signable audit payloads and scope digests. Deterministic across
    processes and library versions pinned in the lock.
    """
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_hex_text(text: str) -> str:
    """Return the lowercase hex SHA-256 digest of ``text`` encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that fails closed on duplicate member names."""
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValidationError(
                ReasonCode.TOKEN_DUPLICATE_CLAIM,
                "duplicate JSON member name in token payload",
            )
        seen[key] = value
    return seen


def _reject_non_finite_float(raw: str) -> float:
    """``parse_float`` hook that rejects values that are not finite numbers."""
    value = float(raw)
    # float("1e999") == inf without raising; forbid it explicitly.
    if value != value or value in (float("inf"), float("-inf")):  # NaN or +/-inf
        raise ValidationError(ReasonCode.TOKEN_MALFORMED, "non-finite number in token payload")
    return value


def _reject_constant(name: str) -> float:
    """``parse_constant`` hook; JSON ``Infinity``/``-Infinity``/``NaN`` are rejected."""
    raise ValidationError(ReasonCode.TOKEN_MALFORMED, f"non-finite constant {name!r} in token payload")


def _assert_bounds(obj: Any, *, depth: int = 0, members: list[int] | None = None) -> None:
    """Enforce maximum nesting depth and total member/element count."""
    if members is None:
        members = [0]
    if depth > MAX_JSON_DEPTH:
        raise ValidationError(ReasonCode.TOKEN_MALFORMED, "token payload nesting too deep")
    if isinstance(obj, dict):
        for key, value in obj.items():
            members[0] += 1
            if members[0] > MAX_JSON_MEMBERS:
                raise ValidationError(ReasonCode.TOKEN_MALFORMED, "token payload has too many members")
            _assert_bounds(value, depth=depth + 1, members=members)
    elif isinstance(obj, list):
        for value in obj:
            members[0] += 1
            if members[0] > MAX_JSON_MEMBERS:
                raise ValidationError(ReasonCode.TOKEN_MALFORMED, "token payload has too many members")
            _assert_bounds(value, depth=depth + 1, members=members)


def strict_json_loads(data: bytes) -> dict[str, Any]:
    """Parse decoded JWS payload bytes into a JSON object, strictly.

    Rejects: non-UTF-8 input, non-object top level, duplicate member names,
    JSON ``Infinity``/``-Infinity``/``NaN``, other non-finite numbers, and
    nesting / member counts beyond the published bounds (§21.1).
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(ReasonCode.TOKEN_MALFORMED, "token payload is not valid UTF-8") from exc

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_constant,
            parse_float=_reject_non_finite_float,
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValidationError(ReasonCode.TOKEN_MALFORMED, "token payload is not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise ValidationError(ReasonCode.TOKEN_MALFORMED, "token payload must be a JSON object")

    _assert_bounds(parsed)
    return parsed
