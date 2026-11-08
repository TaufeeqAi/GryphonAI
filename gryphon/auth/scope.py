"""Scope Policy v1 — deterministic canonicalization and evaluation (BND-03).

This module is the sole owner of scope grammar and canonicalization. The *same*
pinned functions run at grant issuance (to canonicalize the signed scope) and at
admission (to canonicalize the requested target/path), which is what makes
"issuance and verification use identical normalization" enforceable (§11.3,
INV-009).

Security properties:

* No implicit broadening. Exact domains match only the identical canonical FQDN;
  there is no parent/suffix expansion (SEC-006).
* ``domain_wildcard`` is exactly ``*.<suffix>`` and matches exactly one extra
  leftmost label — never the apex and never two or more labels.
* CIDR uses strict network semantics; a network literal with host bits set is
  rejected, never widened.
* Excluded paths override every positive match (SEC-007).
* Pure computation: no DNS, HTTP, socket or redirect resolution (§21.3). Phase 1
  string matching is explicitly **not** SSRF/DNS-rebinding protection.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

import idna
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.constants import (
    MAX_DOMAIN_OCTETS,
    MAX_EXCLUDED_PATHS_PER_ENTRY,
    MAX_PATH_BYTES,
    MAX_TARGET_BYTES,
    TargetType,
)
from gryphon.errors import ReasonCode, ScopeEvaluationError

# -----------------------------------------------------------------------------
# Low-level canonicalizers (pure). Each raises ScopeEvaluationError on ambiguity.
# -----------------------------------------------------------------------------
_FORBIDDEN_DOMAIN_CHARS = set("/@:?#%\\ \t\r\n")


def _reject_control_chars(value: str, reason: ReasonCode) -> None:
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ScopeEvaluationError(reason, "control character in input")


def canonicalize_domain(raw: str) -> str:
    """Canonicalize a DNS name to lowercase IDNA A-label form (§11.3).

    Rejects URL schemes, userinfo, ports, paths, query, fragment, percent
    encodings, whitespace and malformed IDNA. Removes at most one terminal dot.
    """
    if not isinstance(raw, str) or not raw:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "empty domain")
    if len(raw.encode("utf-8")) > MAX_TARGET_BYTES:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "domain too long")

    value = raw.strip()
    _reject_control_chars(value, ReasonCode.SCOPE_INVALID_INPUT)
    if any(ch in _FORBIDDEN_DOMAIN_CHARS for ch in value):
        raise ScopeEvaluationError(
            ReasonCode.SCOPE_INVALID_INPUT, "domain contains scheme/port/path/percent characters"
        )
    # Remove at most one terminal root dot.
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith("."):
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "empty label in domain")

    try:
        # One pinned IDNA 2008 / UTS-46 profile.
        ascii_domain = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "malformed IDNA domain") from exc

    if len(ascii_domain) > MAX_DOMAIN_OCTETS:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "domain exceeds DNS length limit")
    for label in ascii_domain.split("."):
        if not label or len(label) > 63:
            raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "invalid domain label length")
    return ascii_domain


def canonicalize_wildcard(raw: str) -> str:
    """Canonicalize a ``*.<suffix>`` wildcard entry; return canonical form (§11.3)."""
    if not isinstance(raw, str) or not raw.startswith("*."):
        raise ScopeEvaluationError(
            ReasonCode.SCOPE_INVALID_INPUT, "wildcard must begin with exactly '*.'"
        )
    suffix = raw[2:]
    if "*" in suffix:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "only one leading wildcard allowed")
    canonical_suffix = canonicalize_domain(suffix)
    return f"*.{canonical_suffix}"


def canonicalize_ip(raw: str) -> ipaddress._BaseAddress:
    """Parse a canonical IPv4/IPv6 address (§11.3). Zone identifiers are rejected."""
    if not isinstance(raw, str) or not raw:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "empty IP")
    value = raw.strip()
    if "%" in value:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "IPv6 zone identifiers are rejected")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "invalid IP address") from exc


def canonicalize_cidr(raw: str) -> ipaddress._BaseNetwork:
    """Parse a strict CIDR network (§11.3). Host bits set => reject (no widening)."""
    if not isinstance(raw, str) or not raw:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "empty CIDR")
    value = raw.strip()
    if "%" in value:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "IPv6 zone identifiers are rejected")
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ScopeEvaluationError(
            ReasonCode.SCOPE_INVALID_INPUT, "invalid or non-strict CIDR network"
        ) from exc


def _hex_value(ch: str) -> int | None:
    return int(ch, 16) if ch in "0123456789abcdefABCDEF" else None


def canonicalize_path(raw: str) -> str:
    """Canonicalize an origin-form URL path for exclusion matching (§11.3).

    Percent-decodes exactly once with strict UTF-8. Rejects encoded slash /
    backslash, raw backslash, NUL/control bytes, dot segments, repeated
    separators and query/fragment components. Case-sensitive.
    """
    if not isinstance(raw, str) or not raw:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "empty path")
    if len(raw.encode("utf-8")) > MAX_PATH_BYTES:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "path too long")
    if not raw.startswith("/"):
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "path must be origin-form ('/...')")
    if "?" in raw or "#" in raw:
        raise ScopeEvaluationError(
            ReasonCode.SCOPE_INVALID_INPUT, "query/fragment are not part of the path policy"
        )
    if "\\" in raw:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "backslash is not permitted in path")
    _reject_control_chars(raw, ReasonCode.SCOPE_INVALID_INPUT)

    # Single-pass, decode-exactly-once percent handling.
    decoded = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch == "%":
            if i + 2 >= n:
                raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "truncated percent-encoding")
            hi, lo = _hex_value(raw[i + 1]), _hex_value(raw[i + 2])
            if hi is None or lo is None:
                raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "invalid percent-encoding")
            byte = (hi << 4) | lo
            if byte in (0x2F, 0x5C):  # encoded '/' or '\'
                raise ScopeEvaluationError(
                    ReasonCode.SCOPE_INVALID_INPUT, "encoded slash/backslash is rejected"
                )
            if byte < 0x20 or byte == 0x7F:
                raise ScopeEvaluationError(
                    ReasonCode.SCOPE_INVALID_INPUT, "encoded control byte is rejected"
                )
            decoded.append(byte)
            i += 3
        else:
            decoded.extend(ch.encode("utf-8"))
            i += 1

    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "invalid UTF-8 in path") from exc

    segments = text.split("/")
    # text starts with '/', so segments[0] == ''.
    body = segments[1:]
    for seg in body:
        if seg == "":
            raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "repeated '/' separator in path")
        if seg in (".", ".."):
            raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "dot segment in path is rejected")
    return "/" + "/".join(body)


# -----------------------------------------------------------------------------
# Canonical request target
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class CanonicalTarget:
    """A fully-canonicalized admission target (exactly one domain or IP)."""

    kind: TargetType  # DOMAIN or IP only
    text: str
    ip: ipaddress._BaseAddress | None = None


def canonicalize_target(raw: str) -> CanonicalTarget:
    """Canonicalize a requested admission target into one domain or IP (§11.3).

    A hostname with an explicit port is NOT a domain-scope target and is rejected
    (port authorization is undefined in Phase 1).
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "empty target")
    value = raw.strip()
    if len(value.encode("utf-8")) > MAX_TARGET_BYTES:
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "target too long")

    # IP takes precedence (an address never canonicalizes as a domain).
    try:
        if "%" in value:
            raise ValueError("zone id")
        ip = ipaddress.ip_address(value)
        return CanonicalTarget(kind=TargetType.IP, text=str(ip), ip=ip)
    except ValueError:
        pass
    domain = canonicalize_domain(value)
    return CanonicalTarget(kind=TargetType.DOMAIN, text=domain)


# -----------------------------------------------------------------------------
# Scope entry (signed, canonical)
# -----------------------------------------------------------------------------
class ScopeEntry(BaseModel):
    """One authorized target plus its path exclusions, stored in canonical form.

    Canonicalization runs on construction, so a signed grant's scope snapshot is
    already canonical and admission re-runs the identical policy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    target_type: TargetType
    target: str
    excluded_paths: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _canonicalize(self) -> "ScopeEntry":
        tt = self.target_type
        if tt is TargetType.DOMAIN:
            canonical = canonicalize_domain(self.target)
        elif tt is TargetType.DOMAIN_WILDCARD:
            canonical = canonicalize_wildcard(self.target)
        elif tt is TargetType.IP:
            canonical = str(canonicalize_ip(self.target))
        elif tt is TargetType.CIDR:
            canonical = str(canonicalize_cidr(self.target))
        else:  # pragma: no cover - enum exhaustively covered
            raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "unknown target type")

        if len(self.excluded_paths) > MAX_EXCLUDED_PATHS_PER_ENTRY:
            raise ScopeEvaluationError(
                ReasonCode.SCOPE_INVALID_INPUT, "too many excluded paths for entry"
            )
        canonical_paths = tuple(canonicalize_path(p) for p in self.excluded_paths)

        # Rebind canonical values on this frozen model.
        object.__setattr__(self, "target", canonical)
        object.__setattr__(self, "excluded_paths", canonical_paths)
        return self

    @field_validator("excluded_paths", mode="before")
    @classmethod
    def _coerce_paths(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, (list, tuple)):
            return tuple(value)
        raise ScopeEvaluationError(ReasonCode.SCOPE_INVALID_INPUT, "excluded_paths must be a list")

    def canonical_dict(self) -> dict[str, Any]:
        """Stable dict for digest computation (excludes the random entry_id)."""
        return {
            "target_type": self.target_type.value,
            "target": self.target,
            "excluded_paths": list(self.excluded_paths),
        }


# -----------------------------------------------------------------------------
# Evaluation
# -----------------------------------------------------------------------------
class ScopeResult(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    EXCLUDED = "EXCLUDED"
    INVALID_INPUT = "INVALID_INPUT"


@dataclass(frozen=True)
class ScopeDecision:
    result: ScopeResult
    reason_code: ReasonCode
    matched_entry_id: str | None = None


def _domain_matches(entry: ScopeEntry, target: CanonicalTarget) -> bool:
    if target.kind is not TargetType.DOMAIN:
        return False
    if entry.target_type is TargetType.DOMAIN:
        return target.text == entry.target
    if entry.target_type is TargetType.DOMAIN_WILDCARD:
        suffix = entry.target[2:]  # strip '*.'
        dotted = "." + suffix
        if not target.text.endswith(dotted):
            return False
        prefix = target.text[: -len(dotted)]
        return bool(prefix) and "." not in prefix  # exactly one extra label; not apex
    return False


def _ip_matches(entry: ScopeEntry, target: CanonicalTarget) -> bool:
    if target.kind is not TargetType.IP or target.ip is None:
        return False
    if entry.target_type is TargetType.IP:
        # Compare address objects (family-aware); never string comparison.
        return target.ip == canonicalize_ip(entry.target)
    if entry.target_type is TargetType.CIDR:
        network = canonicalize_cidr(entry.target)
        if target.ip.version != network.version:
            return False
        return target.ip in network
    return False


def _path_excluded(excluded: str, request_path: str) -> bool:
    return request_path == excluded or request_path.startswith(excluded + "/")


def evaluate(
    scope: list[ScopeEntry] | tuple[ScopeEntry, ...],
    target: CanonicalTarget,
    path: str | None,
) -> ScopeDecision:
    """Decide whether a canonical target/path satisfies the signed scope (§11.3).

    Positive target match is insufficient if a path exclusion applies. An
    exclusion on any matching entry dominates every positive match (SEC-007).
    """
    matched_entries: list[ScopeEntry] = []
    for entry in scope:
        if _domain_matches(entry, target) or _ip_matches(entry, target):
            matched_entries.append(entry)

    if not matched_entries:
        return ScopeDecision(ScopeResult.NO_MATCH, ReasonCode.SCOPE_NO_MATCH)

    if path is not None:
        for entry in matched_entries:
            for excluded in entry.excluded_paths:
                if _path_excluded(excluded, path):
                    return ScopeDecision(
                        ScopeResult.EXCLUDED, ReasonCode.SCOPE_EXCLUDED, entry.entry_id
                    )

    return ScopeDecision(ScopeResult.MATCH, ReasonCode.ADMITTED, matched_entries[0].entry_id)


def scope_digest(scope: list[ScopeEntry] | tuple[ScopeEntry, ...]) -> str:
    """Return a stable SHA-256 digest over the canonical scope (receipt field)."""
    payload = [entry.canonical_dict() for entry in scope]
    return sha256_hex(canonical_json_bytes(payload))
