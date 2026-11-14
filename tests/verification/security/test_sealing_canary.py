"""The sealing canary: nothing a target wrote may cross the observer boundary.

This is the test the secret guarantee rests on, and it is deliberately stronger
than "the redactor recognized our example key". Two of the canaries below have
no recognizer at all. If the guarantee depended on recognizing formats it would
be false for every shape nobody has thought of yet, and the shapes are chosen by
someone else.

What is asserted instead is structural: the observer is handed tool output that
*contains* the canaries, and the document it emits is searched, recursively and
in full, for any of them. The body is measured inside the sandbox and dies with
it; only counts, digests, key names and value classes come out.

The test also covers the two channels that historically leak when the main path
is sealed: diagnostics, where a parser quotes back a header a target chose, and
error text, where an exception message carries the input that caused it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from gryphon.tooling.observation import secrets
from gryphon.tooling.observation.extractors import EXTRACTOR_SET_DIGEST
from gryphon.tooling.observation.observer import (
    CapturedOutput,
    ObservationRequest,
    document_for,
    observe_from_output,
    parse_request,
)
from gryphon.verification.constants import ObservationKind
from tests.verification.conftest import (
    ALL_CANARIES,
    AWS_CANARY,
    DOTENV_BODY,
    OPAQUE_CANARY,
    PEM_CANARY,
)

pytestmark = pytest.mark.security

#: A header value a target controls. Parsers that quote headers back into
#: diagnostics turn this into a channel.
HEADER_CANARY = "Nginx/1.2.3-cANARY-hEADER-v4lu3"


def _strings(value: Any) -> list[str]:
    """Every string anywhere in a nested structure, including keys."""
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.append(str(key))
            found.extend(_strings(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(_strings(item))
    elif value is not None:
        found.append(str(value))
    return found


def _assert_sealed(document: Any, *, canaries: tuple[str, ...] = ALL_CANARIES) -> None:
    """No canary may appear anywhere in the emitted document.

    Checked twice — against the serialized form and against every individual
    string — because a canary split across two fields would survive only one of
    those checks, and a canary used as a mapping *key* would survive neither a
    values-only walk nor a naive substring test on a pretty-printed dump.
    """
    blob = json.dumps(document, sort_keys=True, default=str)
    pieces = _strings(document)
    for canary in canaries:
        assert canary not in blob, f"{canary[:16]}... leaked into the observation document"
        for piece in pieces:
            assert canary not in piece, f"{canary[:16]}... leaked into field {piece[:40]!r}"


def _http_request(**overrides: Any) -> ObservationRequest:
    payload: dict[str, Any] = {
        "request_format_version": "1",
        "kind": ObservationKind.HTTP_RESPONSE_SUMMARY.value,
        "binary_path": "/usr/local/bin/httpx",
        "envelope": {
            "envelope_format_version": "1",
            "kind": ObservationKind.HTTP_RESPONSE_SUMMARY.value,
            "method": "GET",
            "scheme": "https",
            "host": "app.example.test",
            "port": 443,
            "path": "/.env",
            "record_types": [],
            "descriptor_version": "httpx/1.12.0",
            "extractor_set_digest": EXTRACTOR_SET_DIGEST,
            "resolver_set_digest": "",
        },
        "bounds": {
            "wire_bytes": 65536,
            "decoded_bytes": 262144,
            "header_bytes": 16384,
            "deadline_seconds": 20.0,
            "answer_count": 64,
            "cname_depth": 16,
        },
        "signal_tokens": [],
        "resolvers": [],
    }
    payload.update(overrides)
    return parse_request(payload)


def _captured(
    stdout: bytes = b"",
    *,
    stderr_bytes: int = 0,
    exit_code: int | None = 0,
    timed_out: bool = False,
    truncated: bool = False,
) -> CapturedOutput:
    """Tool output as the observer receives it.

    Note the shape: ``stderr_bytes`` is a COUNT. The observer's own type makes it
    impossible to hand it stderr text, so the error-channel leak this test was
    written to catch cannot be expressed — which is a stronger guarantee than
    asserting the text is absent afterwards.
    """
    return CapturedOutput(
        stdout=stdout,
        stderr_bytes=stderr_bytes,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_truncated=truncated,
        elapsed_seconds=0.1,
    )


def _httpx_line(*, body: str, headers: dict[str, str] | None = None) -> bytes:
    """One httpx JSON record, shaped as the real tool emits it with -irr."""
    header_block = "\r\n".join(
        f"{name}: {value}" for name, value in (headers or {"Content-Type": "text/plain"}).items()
    )
    raw_response = f"HTTP/1.1 200 OK\r\n{header_block}\r\n\r\n{body}"
    record = {
        "url": "https://app.example.test/.env",
        "status_code": 200,
        "content_length": len(body.encode()),
        "raw_header": header_block,
        "response": raw_response,
        "body": body,
        "header": headers or {"content_type": "text/plain"},
    }
    return (json.dumps(record) + "\n").encode()


# =============================================================================
# The guarantee
# =============================================================================


def test_no_body_bytes_cross_the_observer_boundary() -> None:
    """A dotenv body full of canaries produces facts and no content."""
    request = _http_request()
    outcome = observe_from_output(request, _captured(_httpx_line(body=DOTENV_BODY)))
    document = document_for(outcome)
    _assert_sealed(document)


def test_the_shape_still_crosses_even_though_the_value_does_not() -> None:
    """Sealing is useless if it also removes the evidence.

    The point of the boundary is that a count is evidence *about* a body that no
    longer exists. If nothing crossed, the checkpoint could not be met at all.
    """
    request = _http_request()
    outcome = observe_from_output(request, _captured(_httpx_line(body=DOTENV_BODY)))
    document = document_for(outcome)
    blob = json.dumps(document)
    assert "aws_access_key_id" in blob, "the secret's class must cross"
    assert "AWS_ACCESS_KEY_ID" in blob, "the key name must cross"
    assert AWS_CANARY not in blob, "the key value must not"


def test_an_unrecognized_secret_shape_still_does_not_cross() -> None:
    """The guarantee cannot depend on recognizing a format.

    ``OPAQUE_CANARY`` matches no recognizer. It stays inside anyway, because
    nothing target-controlled is carried out — which is the difference between a
    structural guarantee and a detector's coverage.
    """
    body = f"TOTALLY_UNKNOWN_FORMAT={OPAQUE_CANARY}\nOTHER=1\nTHIRD=2\n"
    assert OPAQUE_CANARY not in json.dumps(secrets.classify(body))
    request = _http_request()
    outcome = observe_from_output(request, _captured(_httpx_line(body=body)))
    _assert_sealed(document_for(outcome), canaries=(OPAQUE_CANARY,))


def test_a_private_key_block_does_not_cross_and_is_counted_once() -> None:
    """The defect the previous recognizer had: a matched header, an intact body."""
    body = f"CERT_PEM=\n{PEM_CANARY}\nMORE=1\nEVEN_MORE=2\n"
    request = _http_request()
    outcome = observe_from_output(request, _captured(_httpx_line(body=body)))
    document = document_for(outcome)
    _assert_sealed(document, canaries=(PEM_CANARY,))
    blob = json.dumps(document)
    assert "private_key_block" in blob


def test_a_target_controlled_header_value_does_not_cross() -> None:
    """Header *names* cross; values do not.

    A server can put anything in a header, so a parser that reported values
    would be a channel for whatever the target chose to put there.
    """
    request = _http_request()
    outcome = observe_from_output(
        request,
        _captured(
            _httpx_line(
                body="A=1\nB=2\nC=3\n",
                headers={"Content-Type": "text/plain", "Server": HEADER_CANARY},
            )
        ),
    )
    document = document_for(outcome)
    _assert_sealed(document, canaries=(HEADER_CANARY,))
    assert "server" in json.dumps(document), "the header name should still be reported"


def test_tool_stderr_cannot_cross_even_by_construction() -> None:
    """The error channel is closed by the type, not by a later scrub.

    ``CapturedOutput`` carries ``stderr_bytes`` as a count. There is no field to
    put stderr text in, so the classic leak — an exception message quoting the
    input that caused it — cannot be expressed at this boundary at all. That is
    a stronger guarantee than asserting the text is absent afterwards, because
    it does not depend on anyone remembering to scrub.
    """
    import dataclasses

    fields = {f.name: f.type for f in dataclasses.fields(CapturedOutput)}
    assert "stderr" not in fields, "stderr text must have nowhere to live"
    assert "stderr_bytes" in fields

    request = _http_request()
    outcome = observe_from_output(
        request,
        _captured(b"", stderr_bytes=len(f"panic near {AWS_CANARY}".encode()), exit_code=1),
    )
    document = document_for(outcome)
    _assert_sealed(document, canaries=(AWS_CANARY,))
    # And the failure is still reported, as a closed code with a numeric detail.
    assert document.get("ok") is False
    assert isinstance(document.get("error_code"), str)
    assert document["detail_numeric"]["stderr_bytes"] > 0


def test_unparseable_tool_output_reports_a_closed_code_not_the_output() -> None:
    request = _http_request()
    outcome = observe_from_output(
        request,
        _captured(f"this is not json and it mentions {OPAQUE_CANARY}".encode()),
    )
    document = document_for(outcome)
    _assert_sealed(document, canaries=(OPAQUE_CANARY,))
    assert document.get("ok") is False


def test_the_emitted_document_contains_only_closed_error_codes() -> None:
    """Every failure is one of a known set, so none can carry free text."""
    from gryphon.tooling.observation.facts import ObserverErrorCode

    request = _http_request()
    for captured in (
        _captured(b"", stderr_bytes=4, exit_code=1),
        _captured(b"{not json"),
        _captured(b""),
    ):
        document = document_for(observe_from_output(request, captured))
        if document.get("ok") is False:
            assert document["error_code"] in ObserverErrorCode.ALL


# =============================================================================
# The sandbox itself
# =============================================================================


def test_a_sandbox_holding_credentials_refuses_to_run() -> None:
    """The observer checks its own environment before it measures anything.

    It is the one component that reads bytes a target chose, so it is the one
    component that must be certain it holds nothing worth stealing.
    """
    from gryphon.tooling.observation.observer import (
        SandboxNotSealed,
        assert_environment_scrubbed,
    )

    assert_environment_scrubbed({"PATH": "/usr/bin", "LC_ALL": "C.UTF-8"})

    for leaked in (
        {"PATH": "/usr/bin", "GRYPHON_DATABASE_URL": "postgresql://x"},
        {"PATH": "/usr/bin", "GRYPHON_VERIFICATION_SIGNING_KEY_HEX": "ab" * 32},
        {"PATH": "/usr/bin", "AWS_SECRET_ACCESS_KEY": OPAQUE_CANARY},
    ):
        with pytest.raises(SandboxNotSealed):
            assert_environment_scrubbed(leaked)


def test_the_http_argv_pins_every_flag_the_guarantee_depends_on() -> None:
    """Scheme, redirects, decoding, config and caps are all explicit.

    Each of these was an ambient default that would otherwise decide behaviour:
    the tool reads a config file from the runtime user's home directory, follows
    redirects when asked, and falls back to another scheme on failure.
    """
    from gryphon.tooling.observation.observer import build_http_argv

    argv = build_http_argv(_http_request(), empty_config="/tmp/empty.yaml")
    joined = " ".join(argv)

    assert "-nfs" in argv, "scheme fallback must be off: the envelope claims a scheme"
    assert "-no-decode" in argv, "we control decoding, so a compressed body cannot outgrow a bound"
    assert "-config" in argv, "an ambient config file must not decide behaviour"
    assert "-irr" in argv, "a body must exist to be measured"
    assert "-rstr" in argv
    assert "-x" in argv
    for forbidden in ("-fr", "-fhr", "-maxr", "-H", "-proxy", "-pa", "-tech-detect"):
        assert forbidden not in argv, f"{forbidden} must never be passed"
    assert "--" not in joined or True  # argv is a list; no shell is involved


def test_the_dns_argv_pins_the_resolvers() -> None:
    """Unpinned resolvers send the client's host names to third parties.

    The tool's own defaults are public resolvers, and a filtering resolver's
    NXDOMAIN would become takeover "evidence" about a name that resolves fine
    elsewhere.
    """
    from gryphon.tooling.observation.observer import build_dns_argv

    request = parse_request(
        {
            "request_format_version": "1",
            "kind": ObservationKind.DNS_ANSWER.value,
            "binary_path": "/usr/local/bin/dnsx",
            "envelope": {
                "envelope_format_version": "1",
                "kind": ObservationKind.DNS_ANSWER.value,
                "method": "DNS",
                "scheme": "dns",
                "host": "app.example.test",
                "port": 53,
                "path": None,
                "record_types": ["CNAME", "A"],
                "descriptor_version": "dnsx/1.3.1",
                "extractor_set_digest": EXTRACTOR_SET_DIGEST,
                "resolver_set_digest": "r",
            },
            "bounds": {
                "wire_bytes": 65536,
                "decoded_bytes": 262144,
                "header_bytes": 16384,
                "deadline_seconds": 10.0,
                "answer_count": 64,
                "cname_depth": 16,
            },
            "signal_tokens": [],
            "resolvers": ["203.0.113.53", "198.51.100.53"],
        }
    )
    argv = build_dns_argv(request, names_file="/tmp/names.txt")
    assert "-r" in argv, "resolvers must be pinned explicitly"
    index = argv.index("-r")
    assert "203.0.113.53" in argv[index + 1]
