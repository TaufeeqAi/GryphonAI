"""The canonical request envelope: one contact, described exactly once.

An envelope is the complete, canonical description of a single contact — every
field that can change what goes on the wire. Two things depend on that
completeness:

* **Identity.** ``execution_id`` is derived from the envelope digest, so one id
  can mean exactly one request. The gateway stores the digest and refuses a
  reused id presented with a different envelope, *before* traffic. Without a
  stored request representation there is nothing to compare, which is why the
  previous "impossible by construction" claim could not be enforced.
* **Reproducibility.** A verdict cites the envelope that produced its evidence.
  Scheme and port are explicit members because a probe answered over a different
  scheme is a different observation, however similar the response looks.

The envelope is *built by the caller and validated by the gateway*. Nothing in
it is taken on trust: the gateway re-derives scope, re-resolves the subject and
pins its own addresses. The envelope says what was asked for, not what was
permitted.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Final

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.verification.constants import METHODS_BY_KIND, ObservationKind

#: Envelope wire-format version. A change here changes every derived identity,
#: so it is a MAJOR concern and is covered by the digest.
ENVELOPE_FORMAT_VERSION: Final[str] = "1"

_SCHEME_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}
_DNS_PORT: Final[int] = 53


class EnvelopeError(ValueError):
    """An envelope could not be built or is not representable.

    Raised at construction and at registry-validation time — never at dispatch.
    A target the gateway's interface cannot express is a registry problem, and
    surfacing it as a scope denial would point an operator at a grant that is
    perfectly correct.
    """


@dataclass(frozen=True, slots=True)
class RequestEnvelope:
    """Everything that determines what one contact puts on the wire."""

    kind: ObservationKind
    method: str
    #: Canonical host (already IDNA/case normalized by the caller's canonicalizer).
    host: str
    port: int
    scheme: str
    #: Origin-form path for HTTP kinds; ``None`` for resolver-mediated kinds.
    path: str | None
    #: DNS record types, ordered and de-duplicated; empty for HTTP kinds.
    record_types: tuple[str, ...]
    #: Pinned descriptor of the binary that will run, from the tool manifest.
    descriptor_version: str
    #: Digest of the fixed extractor set the observer will evaluate.
    extractor_set_digest: str
    #: Resolver list digest for mediated kinds; empty string otherwise. Pinned so
    #: a resolver swap mid-pass invalidates the pin rather than silently changing
    #: what "NXDOMAIN" meant.
    resolver_set_digest: str = ""

    def __post_init__(self) -> None:
        allowed = METHODS_BY_KIND.get(self.kind)
        if allowed is None:
            raise EnvelopeError(f"{self.kind!r} is not an observation kind")
        if self.method not in allowed:
            raise EnvelopeError(
                f"{self.kind.value} permits {'/'.join(allowed)}; refusing {self.method!r}"
            )
        if not self.host or self.host != self.host.strip().lower():
            raise EnvelopeError("host must be a canonical, lowercase, stripped name")
        if not 1 <= self.port <= 65_535:
            raise EnvelopeError(f"port {self.port} is out of range")

        if self.kind is ObservationKind.HTTP_RESPONSE_SUMMARY:
            if self.scheme not in _SCHEME_PORTS:
                raise EnvelopeError(f"scheme {self.scheme!r} is not http or https")
            if self.path is None:
                raise EnvelopeError("an HTTP observation requires a path")
            if not self.path.startswith("/"):
                raise EnvelopeError("path must be origin-form")
            # The scope canonicalizer rejects a query outright, so an envelope
            # carrying one is unrepresentable rather than merely out of scope.
            if "?" in self.path or "#" in self.path:
                raise EnvelopeError(
                    "a query or fragment is not representable in the gateway's "
                    "request interface; this class is UNSUPPORTED in verifier set v1"
                )
            if self.record_types:
                raise EnvelopeError("record_types belong to resolver-mediated kinds")
        else:
            if self.scheme != "dns":
                raise EnvelopeError("a resolver-mediated observation uses the 'dns' scheme")
            if self.path is not None:
                raise EnvelopeError("a resolver-mediated observation has no path")
            if not self.record_types:
                raise EnvelopeError("a DNS observation requires at least one record type")
            if len(set(self.record_types)) != len(self.record_types):
                raise EnvelopeError("record_types must be de-duplicated")
            for rtype in self.record_types:
                if rtype != rtype.upper() or not rtype.isalnum():
                    raise EnvelopeError(f"record type {rtype!r} is not a canonical token")

    # -- canonical form -------------------------------------------------------
    def as_canonical(self) -> dict[str, Any]:
        """The exact mapping the digest is taken over.

        Member order is irrelevant (RFC 8785 sorts), but membership is not:
        adding a field here changes every identity derived from it.
        """
        return {
            "envelope_format_version": ENVELOPE_FORMAT_VERSION,
            "kind": self.kind.value,
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "record_types": list(self.record_types),
            "descriptor_version": self.descriptor_version,
            "extractor_set_digest": self.extractor_set_digest,
            "resolver_set_digest": self.resolver_set_digest,
        }

    @property
    def digest(self) -> str:
        """SHA-256 over the canonical JSON form."""
        return sha256_hex(canonical_json_bytes(self.as_canonical()))

    @property
    def url(self) -> str:
        """Display form. Never used for matching — the members are authoritative."""
        if self.kind is ObservationKind.DNS_ANSWER:
            return f"dns:{self.host}"
        default = _SCHEME_PORTS[self.scheme]
        authority = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{authority}{self.path}"

    def with_path(self, path: str) -> RequestEnvelope:
        """A sibling envelope at another path — how a control locator is built."""
        return replace(self, path=path)


def http_envelope(
    *,
    scheme: str,
    host: str,
    port: int | None,
    path: str,
    method: str,
    descriptor_version: str,
    extractor_set_digest: str,
) -> RequestEnvelope:
    """Build an HTTP envelope, defaulting the port from the scheme."""
    scheme = scheme.strip().lower()
    if scheme not in _SCHEME_PORTS:
        raise EnvelopeError(f"scheme {scheme!r} is not http or https")
    return RequestEnvelope(
        kind=ObservationKind.HTTP_RESPONSE_SUMMARY,
        method=method,
        host=host.strip().lower(),
        port=port if port is not None else _SCHEME_PORTS[scheme],
        scheme=scheme,
        path=path,
        record_types=(),
        descriptor_version=descriptor_version,
        extractor_set_digest=extractor_set_digest,
    )


def dns_envelope(
    *,
    host: str,
    record_types: tuple[str, ...],
    descriptor_version: str,
    extractor_set_digest: str,
    resolver_set_digest: str,
) -> RequestEnvelope:
    """Build a resolver-mediated envelope.

    The subject need not resolve: an unresolvable name is the positive case for
    a dangling-record verifier, not a reason to refuse the observation.
    """
    return RequestEnvelope(
        kind=ObservationKind.DNS_ANSWER,
        method="DNS",
        host=host.strip().lower().rstrip("."),
        port=_DNS_PORT,
        scheme="dns",
        path=None,
        record_types=tuple(record_types),
        descriptor_version=descriptor_version,
        extractor_set_digest=extractor_set_digest,
        resolver_set_digest=resolver_set_digest,
    )
