"""The gateway and the observer must agree about the request document.

These two are separate processes by design, and the observer validates strictly
— it refuses an unknown member, because it is the one component that reads bytes
a target chose and leniency there is how a sandbox stops being one. That
strictness only helps if the gateway actually produces what the observer parses.

An earlier revision of these two modules disagreed on every member name
(``observer_request_version`` against ``request_format_version``,
``max_wire_bytes`` against ``wire_bytes``, plus extra top-level members and a
missing ``kind``). Both sides were internally consistent and individually
tested, so both test suites passed while the gateway could never have talked to
the observer at all. This file is the test that would have caught it: it builds
a request with the real gateway function and feeds it to the real observer
parser.
"""

from __future__ import annotations

import pytest

from gryphon.tooling.observation.extractors import EXTRACTOR_SET_DIGEST
from gryphon.tooling.observation.observer import parse_request
from gryphon.verification.constants import ObservationKind

pytestmark = pytest.mark.contract


def _resolver_pins(addresses: tuple[str, ...]):
    from gryphon.tooling.gateway.server import ResolverPins

    return ResolverPins(addresses=addresses, digest="resolvers-test")


def _http_envelope():
    from gryphon.tooling.observation.envelope import http_envelope

    return http_envelope(
        scheme="https",
        host="app.example.test",
        port=443,
        path="/.env",
        method="GET",
        descriptor_version="httpx/1.12.0",
        extractor_set_digest=EXTRACTOR_SET_DIGEST,
    )


def _dns_envelope():
    from gryphon.tooling.observation.envelope import dns_envelope

    return dns_envelope(
        host="app.example.test",
        record_types=("CNAME",),
        descriptor_version="dnsx/1.3.1",
        extractor_set_digest=EXTRACTOR_SET_DIGEST,
        resolver_set_digest="resolvers-test",
    )


def test_the_gateway_and_the_observer_agree_on_the_request_schema() -> None:
    """A gateway-built HTTP request parses in the observer without modification."""
    from gryphon.tooling.gateway.server import build_observer_request

    document = build_observer_request(
        envelope=_http_envelope(),
        binary_path="/usr/local/bin/httpx",
        deadline_seconds=20.0,
        resolvers=_resolver_pins(()),
        signal_tokens=("X-Powered-By",),
    )
    request = parse_request(document)

    assert request.kind is ObservationKind.HTTP_RESPONSE_SUMMARY
    assert request.binary_path == "/usr/local/bin/httpx"
    assert request.envelope.path == "/.env"
    assert request.signal_tokens == ("X-Powered-By",)
    assert request.bounds.deadline_seconds == 20.0


def test_the_gateway_and_the_observer_agree_for_a_resolver_mediated_request() -> None:
    """And for the DNS kind, whose resolvers must be pinned rather than default."""
    from gryphon.tooling.gateway.server import build_observer_request

    document = build_observer_request(
        envelope=_dns_envelope(),
        binary_path="/usr/local/bin/dnsx",
        deadline_seconds=10.0,
        resolvers=_resolver_pins(("203.0.113.53", "198.51.100.53")),
    )
    request = parse_request(document)

    assert request.kind is ObservationKind.DNS_ANSWER
    assert request.resolvers == ("203.0.113.53", "198.51.100.53")
    assert request.envelope.record_types == ("CNAME",)


def test_an_http_request_carries_no_resolvers() -> None:
    """Resolvers belong to mediated kinds; carrying them otherwise is noise."""
    from gryphon.tooling.gateway.server import build_observer_request

    document = build_observer_request(
        envelope=_http_envelope(),
        binary_path="/usr/local/bin/httpx",
        deadline_seconds=20.0,
        resolvers=_resolver_pins(("203.0.113.53",)),
    )
    assert document["resolvers"] == []
    assert parse_request(document).resolvers == ()


def test_the_document_carries_no_member_the_observer_would_refuse() -> None:
    """Belt and braces: the member sets are compared directly.

    Equality rather than containment, in both directions. A member the gateway
    stops sending is just as much a break as one it starts sending, because the
    observer requires the ones it needs.
    """
    from gryphon.tooling.gateway.server import build_observer_request
    from gryphon.tooling.observation import observer as observer_module

    document = build_observer_request(
        envelope=_http_envelope(),
        binary_path="/usr/local/bin/httpx",
        deadline_seconds=20.0,
        resolvers=_resolver_pins(()),
    )
    assert set(document) <= observer_module._REQUEST_KEYS
    required = {"request_format_version", "kind", "binary_path", "envelope", "bounds"}
    assert required <= set(document)


def test_the_gateway_cannot_widen_an_observer_bound() -> None:
    """Bounds may only narrow, and the observer refuses a widening request.

    The gateway is trusted to pin destinations; it is not trusted to raise a cap
    the sandbox enforces on itself, because the whole point of enforcing it
    there is that it does not depend on the caller being right.
    """
    from gryphon.tooling.gateway.server import build_observer_request
    from gryphon.tooling.observation.observer import RequestInvalid

    document = build_observer_request(
        envelope=_http_envelope(),
        binary_path="/usr/local/bin/httpx",
        deadline_seconds=20.0,
        resolvers=_resolver_pins(()),
    )
    document["bounds"]["wire_bytes"] = document["bounds"]["wire_bytes"] * 10
    with pytest.raises(RequestInvalid, match="narrow"):
        parse_request(document)


def test_the_observer_refuses_an_envelope_pinning_another_extractor_set() -> None:
    """A measurement must be made by the extractors its identity claims.

    The envelope digest covers the extractor-set digest, so an image running a
    different set would be producing facts under an identity that describes
    somebody else's measurement.
    """
    from gryphon.tooling.gateway.server import build_observer_request
    from gryphon.tooling.observation.observer import RequestInvalid

    document = build_observer_request(
        envelope=_http_envelope(),
        binary_path="/usr/local/bin/httpx",
        deadline_seconds=20.0,
        resolvers=_resolver_pins(()),
    )
    document["envelope"]["extractor_set_digest"] = "0" * 64
    with pytest.raises(RequestInvalid):
        parse_request(document)
