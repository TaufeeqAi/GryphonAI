"""Typed facts: the only thing that crosses out of the observer.

The observer reads bytes a target chose. Those bytes are measured, hashed and
destroyed inside an unprivileged process that holds no database handle, no
signing key and no credential. What leaves is this module's types and nothing
else — no body, no body window, no header value outside the allowlist, no raw
exception text.

That is the whole of the secret guarantee. It does not rest on recognizing every
secret format, because a finite recognizer cannot do that; it rests on no
target-controlled bytes being carried out in the first place. The class counts
below are evidence *about* a body that no longer exists anywhere.

Completeness travels with every observation because a measurement that stopped
early cannot prove absence. A truncated body missing a token says nothing about
whether the token was there.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from gryphon.verification.constants import (
    HEADER_NAME_ALLOWLIST,
    ObservationKind,
    SecretClass,
    TruncationReason,
    ValueClass,
)


class ObserverErrorCode:
    """Closed error vocabulary for the observer.

    A sandbox that returned exception text would be a covert channel for
    target-controlled strings: a server can put anything in a header that a
    parser then quotes back. Every failure is one of these codes plus bounded
    numeric detail.
    """

    SPAWN_FAILED: Final[str] = "spawn_failed"
    BINARY_MISSING: Final[str] = "binary_missing"
    DEADLINE: Final[str] = "deadline"
    OUTPUT_UNPARSEABLE: Final[str] = "output_unparseable"
    OUTPUT_EMPTY: Final[str] = "output_empty"
    TOOL_NONZERO: Final[str] = "tool_nonzero"
    CONNECT_FAILED: Final[str] = "connect_failed"
    TLS_FAILED: Final[str] = "tls_failed"
    DECODE_FAILED: Final[str] = "decode_failed"
    BOUND_EXCEEDED: Final[str] = "bound_exceeded"
    INTERNAL: Final[str] = "internal"

    ALL: Final[frozenset[str]] = frozenset(
        {
            "spawn_failed",
            "binary_missing",
            "deadline",
            "output_unparseable",
            "output_empty",
            "tool_nonzero",
            "connect_failed",
            "tls_failed",
            "decode_failed",
            "bound_exceeded",
            "internal",
        }
    )


@dataclass(frozen=True, slots=True)
class Completeness:
    """Whether a measurement is whole, and if not, which bound stopped it."""

    #: The transport finished cleanly (no reset, no deadline mid-stream).
    transport_complete: bool
    #: The entire body was read within every byte bound.
    body_complete: bool
    truncation_reason: TruncationReason = TruncationReason.NONE
    bytes_read: int = 0
    decoded_bytes: int = 0

    @property
    def is_whole(self) -> bool:
        """True only when a negative claim may rest on this measurement."""
        return (
            self.transport_complete
            and self.body_complete
            and self.truncation_reason is TruncationReason.NONE
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "transport_complete": self.transport_complete,
            "body_complete": self.body_complete,
            "truncation_reason": self.truncation_reason.value,
            "bytes_read": self.bytes_read,
            "decoded_bytes": self.decoded_bytes,
        }

    @classmethod
    def from_payload(cls, raw: dict[str, Any]) -> Completeness:
        return cls(
            transport_complete=bool(raw["transport_complete"]),
            body_complete=bool(raw["body_complete"]),
            truncation_reason=TruncationReason(raw.get("truncation_reason", "none")),
            bytes_read=int(raw.get("bytes_read", 0)),
            decoded_bytes=int(raw.get("decoded_bytes", 0)),
        )

    @classmethod
    def incomplete(cls, reason: TruncationReason) -> Completeness:
        return cls(transport_complete=False, body_complete=False, truncation_reason=reason)


@dataclass(frozen=True, slots=True)
class DotenvFacts:
    """Structure of a dotenv-like body — key names and value *classes* only.

    This is what lets a verifier confirm that an exposed configuration file
    contains AWS-key-shaped content while the key itself never leaves the
    sandbox. The predicate reasons over the grammar; the operator reads the key
    names; nobody reads the values, because they were never carried out.
    """

    total_lines: int
    non_empty_lines: int
    assignment_lines: int
    key_names: tuple[str, ...]
    value_classes: tuple[str, ...]

    @property
    def assignment_ratio(self) -> float:
        if self.non_empty_lines == 0:
            return 0.0
        return self.assignment_lines / self.non_empty_lines

    def as_payload(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "non_empty_lines": self.non_empty_lines,
            "assignment_lines": self.assignment_lines,
            "key_names": list(self.key_names),
            "value_classes": list(self.value_classes),
        }

    @classmethod
    def from_payload(cls, raw: dict[str, Any]) -> DotenvFacts:
        classes = [str(v) for v in raw.get("value_classes", [])]
        for value in classes:
            ValueClass(value)  # closed set; an unknown member is a boundary failure
        return cls(
            total_lines=int(raw["total_lines"]),
            non_empty_lines=int(raw["non_empty_lines"]),
            assignment_lines=int(raw["assignment_lines"]),
            key_names=tuple(str(k) for k in raw.get("key_names", [])),
            value_classes=tuple(classes),
        )


@dataclass(frozen=True, slots=True)
class HttpFacts:
    """What an HTTP observation reports. Never the body."""

    status_code: int
    status_class: int
    content_type: str | None
    content_length_header: int | None
    body_sha256: str
    #: Allowlisted header *names* that were present. No values.
    header_names: tuple[str, ...]
    #: ``none`` | ``same_host`` | ``other_host``. A redirect is recorded, never
    #: followed: following one is how a probe reaches a destination nobody
    #: attested.
    location_class: str
    secret_class_counts: dict[str, int] = field(default_factory=dict)
    tokens_present: tuple[str, ...] = ()
    dotenv: DotenvFacts | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "status_class": self.status_class,
            "content_type": self.content_type,
            "content_length_header": self.content_length_header,
            "body_sha256": self.body_sha256,
            "header_names": list(self.header_names),
            "location_class": self.location_class,
            "secret_class_counts": dict(self.secret_class_counts),
            "tokens_present": list(self.tokens_present),
            "dotenv": self.dotenv.as_payload() if self.dotenv else None,
        }

    @classmethod
    def from_payload(cls, raw: dict[str, Any]) -> HttpFacts:
        names = tuple(str(n).lower() for n in raw.get("header_names", []))
        for name in names:
            if name not in HEADER_NAME_ALLOWLIST:
                raise ValueError(f"header name {name!r} is outside the allowlist")
        counts = {str(k): int(v) for k, v in (raw.get("secret_class_counts") or {}).items()}
        for key in counts:
            SecretClass(key)  # closed set
        location = str(raw.get("location_class", "none"))
        if location not in {"none", "same_host", "other_host"}:
            raise ValueError(f"location_class {location!r} is not a recognized class")
        dotenv_raw = raw.get("dotenv")
        return cls(
            status_code=int(raw["status_code"]),
            status_class=int(raw["status_class"]),
            content_type=(str(raw["content_type"]) if raw.get("content_type") else None),
            content_length_header=(
                int(raw["content_length_header"])
                if raw.get("content_length_header") is not None
                else None
            ),
            body_sha256=str(raw["body_sha256"]),
            header_names=names,
            location_class=location,
            secret_class_counts=counts,
            tokens_present=tuple(str(t) for t in raw.get("tokens_present", [])),
            dotenv=DotenvFacts.from_payload(dotenv_raw) if dotenv_raw else None,
        )


@dataclass(frozen=True, slots=True)
class DnsFacts:
    """What a resolver-mediated observation reports.

    ``rcode`` carries the answer that matters most for a dangling record:
    ``NXDOMAIN`` is a fact about the world, not a refusal, and it is the
    positive case for takeover verification rather than an error.
    """

    rcode: str
    cname_chain: tuple[str, ...]
    a_records: tuple[str, ...]
    resolver_set_digest: str
    authoritative: bool = False

    def as_payload(self) -> dict[str, Any]:
        return {
            "rcode": self.rcode,
            "cname_chain": list(self.cname_chain),
            "a_records": list(self.a_records),
            "resolver_set_digest": self.resolver_set_digest,
            "authoritative": self.authoritative,
        }

    @classmethod
    def from_payload(cls, raw: dict[str, Any]) -> DnsFacts:
        return cls(
            rcode=str(raw["rcode"]).upper(),
            cname_chain=tuple(str(c).lower().rstrip(".") for c in raw.get("cname_chain", [])),
            a_records=tuple(str(a) for a in raw.get("a_records", [])),
            resolver_set_digest=str(raw.get("resolver_set_digest", "")),
            authoritative=bool(raw.get("authoritative", False)),
        )


@dataclass(frozen=True, slots=True)
class ObservationFacts:
    """One kind's facts plus the completeness that qualifies them."""

    kind: ObservationKind
    completeness: Completeness
    http: HttpFacts | None = None
    dns: DnsFacts | None = None

    def __post_init__(self) -> None:
        if self.kind is ObservationKind.HTTP_RESPONSE_SUMMARY and self.http is None:
            raise ValueError("an HTTP observation requires HTTP facts")
        if self.kind is ObservationKind.DNS_ANSWER and self.dns is None:
            raise ValueError("a DNS observation requires DNS facts")

    def as_payload(self) -> dict[str, Any]:
        return {
            "observation_schema_version": OBSERVATION_FACTS_VERSION,
            "kind": self.kind.value,
            "completeness": self.completeness.as_payload(),
            "http": self.http.as_payload() if self.http else None,
            "dns": self.dns.as_payload() if self.dns else None,
        }

    @classmethod
    def from_payload(cls, raw: dict[str, Any]) -> ObservationFacts:
        version = str(raw.get("observation_schema_version", ""))
        if version != OBSERVATION_FACTS_VERSION:
            raise ValueError(f"unsupported observation schema version {version!r}")
        kind = ObservationKind(raw["kind"])
        return cls(
            kind=kind,
            completeness=Completeness.from_payload(raw["completeness"]),
            http=HttpFacts.from_payload(raw["http"]) if raw.get("http") else None,
            dns=DnsFacts.from_payload(raw["dns"]) if raw.get("dns") else None,
        )


#: Facts wire-format version. Travels inside the document so a mismatch is a
#: refusal rather than a misread.
OBSERVATION_FACTS_VERSION: Final[str] = "1"
