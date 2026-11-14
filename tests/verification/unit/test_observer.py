"""The observer: bounds it applies itself, facts it will carry, bytes it will not.

Nothing here spawns a process. The measurement is driven through
``observe_from_output`` with recorded tool output, which is how the interesting
cases — a body cut at the bound, a redirect, a resolver answer that is not an
address — can be exercised at all: no live target produces them on demand.

The last test is the one that matters most. A canary value is fed through a
response body and the emitted document is searched for it byte by byte. The
guarantee is not that the recognizer saw it; the guarantee is that nothing the
target wrote crosses, recognized or not.
"""

from __future__ import annotations

import gzip
import json

import pytest

from gryphon.tooling.observation import __main__ as entry
from gryphon.tooling.observation.envelope import dns_envelope, http_envelope
from gryphon.tooling.observation.extractors import EXTRACTOR_SET_DIGEST
from gryphon.tooling.observation.facts import ObservationFacts, ObserverErrorCode
from gryphon.tooling.observation.observer import (
    CapturedOutput,
    ObserverFailure,
    RequestInvalid,
    SandboxNotSealed,
    assert_environment_scrubbed,
    build_dns_argv,
    build_http_argv,
    document_for,
    observe_from_output,
    parse_request,
)
from gryphon.verification.constants import (
    HTTP_MAX_WIRE_BYTES,
    ObservationKind,
    SecretClass,
    TruncationReason,
)

pytestmark = pytest.mark.unit

HTTPX_PATH = "/opt/gryphon/bin/httpx"
DNSX_PATH = "/opt/gryphon/bin/dnsx"
HOST = "app.example.test"
RESOLVER = "192.0.2.53"

#: AWS's documented example key id: shape-valid, access to nothing.
AWS_CANARY = "AKIAIOSFODNN7EXAMPLE"
#: No recognizer matches this one, which is the point — the guarantee cannot
#: depend on recognition.
OPAQUE_CANARY = "zqf7Xp3Lk9Vn2Rt8Ws5Yd1Hb4Mj6Qc0Ae"
PASSWORD_CANARY = "hunter2hunter2trombone"
CANARIES = (AWS_CANARY, OPAQUE_CANARY, PASSWORD_CANARY)

DOTENV_BODY = (
    "APP_ENV=production\n"
    f"AWS_ACCESS_KEY_ID={AWS_CANARY}\n"
    f"AWS_SECRET_ACCESS_KEY={OPAQUE_CANARY}\n"
    f"DB_PASSWORD={PASSWORD_CANARY}\n"
    "DEBUG=false\n"
)

BOUNDS = {
    "wire_bytes": 65_536,
    "decoded_bytes": 262_144,
    "header_bytes": 16_384,
    "deadline_seconds": 20.0,
    "answer_count": 64,
    "cname_depth": 16,
}
#: A resolver-mediated observation has its own, shorter deadline ceiling.
DNS_BOUNDS = {**BOUNDS, "deadline_seconds": 10.0}


def _http_payload(*, path: str = "/.env", method: str = "GET", **overrides: object) -> dict:
    envelope = http_envelope(
        scheme="https",
        host=HOST,
        port=None,
        path=path,
        method=method,
        descriptor_version="httpx@1.12.0",
        extractor_set_digest=EXTRACTOR_SET_DIGEST,
    )
    payload: dict = {
        "request_format_version": "1",
        "kind": "http.response.summary",
        "binary_path": HTTPX_PATH,
        "envelope": envelope.as_canonical(),
        "bounds": dict(BOUNDS),
        "signal_tokens": [],
    }
    payload.update(overrides)
    return payload


def _dns_payload(**overrides: object) -> dict:
    envelope = dns_envelope(
        host=HOST,
        record_types=("A", "CNAME"),
        descriptor_version="dnsx@1.3.1",
        extractor_set_digest=EXTRACTOR_SET_DIGEST,
        resolver_set_digest="resolvers-test",
    )
    payload: dict = {
        "request_format_version": "1",
        "kind": "dns.answer",
        "binary_path": DNSX_PATH,
        "envelope": envelope.as_canonical(),
        "bounds": dict(DNS_BOUNDS),
        "signal_tokens": [],
        "resolvers": [RESOLVER],
    }
    payload.update(overrides)
    return payload


def _httpx_line(
    *, status: int = 200, headers: dict[str, str] | None = None, body: str = "", **extra: object
) -> dict:
    block = f"HTTP/1.1 {status} OK\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in (headers or {}).items()
    )
    line: dict = {"status_code": status, "raw_header": block, "body": body}
    line.update(extra)
    return line


def _captured(*lines: object, exit_code: int = 0, **overrides: object) -> CapturedOutput:
    stdout = "".join(f"{json.dumps(line)}\n" for line in lines)
    values: dict = {
        # json.dumps escapes every non-ASCII character, surrogates included, so
        # the recorded stdout is byte-exact for a binary body as well.
        "stdout": stdout.encode("utf-8"),
        "stderr_bytes": 0,
        "exit_code": exit_code,
        "timed_out": False,
        "stdout_truncated": False,
        "elapsed_seconds": 0.25,
    }
    values.update(overrides)
    return CapturedOutput(**values)  # type: ignore[arg-type]


def _facts(outcome: ObservationFacts | ObserverFailure) -> ObservationFacts:
    assert isinstance(outcome, ObservationFacts), outcome
    return outcome


# =============================================================================
# HTTP facts
# =============================================================================


def test_a_well_formed_httpx_line_becomes_http_facts() -> None:
    request = parse_request(_http_payload(signal_tokens=["APP_ENV"]))
    line = _httpx_line(
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Length": str(len(DOTENV_BODY)),
            "Server": "nginx",
            "Set-Cookie": "session=abc",
        },
        body=DOTENV_BODY,
    )

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.kind is ObservationKind.HTTP_RESPONSE_SUMMARY
    assert facts.completeness.is_whole
    http = facts.http
    assert http is not None
    assert (http.status_code, http.status_class) == (200, 2)
    assert http.content_type == "text/plain"
    assert http.content_length_header == len(DOTENV_BODY)
    assert http.body_sha256 and len(http.body_sha256) == 64
    assert http.location_class == "none"
    assert http.tokens_present == ("APP_ENV",)
    assert http.secret_class_counts[SecretClass.AWS_ACCESS_KEY_ID.value] == 1
    assert http.dotenv is not None
    assert http.dotenv.key_names[:2] == ("APP_ENV", "AWS_ACCESS_KEY_ID")
    # Allowlisted names only: a cookie header was present and is not reported.
    assert http.header_names == ("content-length", "content-type", "server")


def test_a_body_at_the_wire_bound_is_recorded_as_truncated() -> None:
    """The tool's cap and ours are one number, so a body at the cap reads as cut."""
    request = parse_request(_http_payload(bounds={**BOUNDS, "wire_bytes": 512}))
    line = _httpx_line(headers={"Content-Type": "text/plain"}, body="A" * 512)

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.completeness.truncation_reason is TruncationReason.WIRE_BYTES
    assert facts.completeness.body_complete is False
    assert facts.completeness.transport_complete is False
    assert facts.completeness.is_whole is False
    assert facts.completeness.bytes_read == 512


def test_a_declared_length_longer_than_the_body_is_a_short_read() -> None:
    request = parse_request(_http_payload())
    line = _httpx_line(headers={"Content-Length": "9999"}, body="short")

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.completeness.truncation_reason is TruncationReason.WIRE_BYTES
    assert facts.completeness.body_complete is False


def test_a_head_response_declares_a_body_it_does_not_send() -> None:
    request = parse_request(_http_payload(method="HEAD"))
    line = _httpx_line(headers={"Content-Length": "9999"}, body="")

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.completeness.is_whole
    assert facts.completeness.bytes_read == 0


def test_an_oversized_header_block_stops_the_read() -> None:
    request = parse_request(_http_payload(bounds={**BOUNDS, "header_bytes": 64}))
    line = _httpx_line(headers={f"X-Pad-{i}": "padding" for i in range(32)}, body="body")

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.completeness.truncation_reason is TruncationReason.HEADER_BYTES
    assert facts.completeness.transport_complete is False


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        (f"https://{HOST}/login", "same_host"),
        ("/login", "same_host"),
        ("https://takeover.example.net/login", "other_host"),
        ("http://[not-a-host/", "other_host"),
    ],
)
def test_a_redirect_is_classified_and_never_followed(location: str, expected: str) -> None:
    request = parse_request(_http_payload())
    line = _httpx_line(status=302, headers={"Location": location}, body="")

    facts = _facts(observe_from_output(request, _captured(line)))

    http = facts.http
    assert http is not None
    assert http.location_class == expected
    assert http.status_class == 3
    assert "location" in http.header_names
    # Whatever the class, nothing in the facts is the redirect target itself.
    assert location not in json.dumps(document_for(facts))


def test_the_argv_pins_the_scheme_and_omits_every_redirect_flag() -> None:
    request = parse_request(_http_payload())
    argv = build_http_argv(request, empty_config="/sandbox/empty.yaml")

    assert argv[0] == HTTPX_PATH
    assert argv[argv.index("-u") + 1] == f"https://{HOST}/.env"
    assert argv[argv.index("-x") + 1] == "GET"
    for flag in ("-nfs", "-irr", "-no-decode", "-json", "-silent", "-no-color"):
        assert flag in argv
    assert argv[argv.index("-rstr") + 1] == str(HTTP_MAX_WIRE_BYTES)
    assert argv[argv.index("-config") + 1] == "/sandbox/empty.yaml"
    # One second inside our own wall clock, so an orderly tool timeout still
    # produces a document.
    assert argv[argv.index("-timeout") + 1] == "19"
    for forbidden in ("-fr", "-maxr", "-fhr", "-H", "-proxy", "-pa", "-tech-detect"):
        assert forbidden not in argv


def test_a_compressed_body_is_decoded_under_our_own_bound() -> None:
    request = parse_request(_http_payload())
    packed = gzip.compress(DOTENV_BODY.encode("utf-8"))
    line = _httpx_line(
        headers={"Content-Encoding": "gzip", "Content-Type": "text/plain"},
        body=packed.decode("utf-8", "surrogateescape"),
    )

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.completeness.is_whole
    assert facts.completeness.bytes_read == len(packed)
    assert facts.completeness.decoded_bytes == len(DOTENV_BODY)
    http = facts.http
    assert http is not None
    # The extractors ran over the decoded body, not the compressed bytes.
    assert http.dotenv is not None and http.dotenv.assignment_lines == 5


def test_an_encoding_we_cannot_bound_is_a_decode_failure_not_a_guess() -> None:
    request = parse_request(_http_payload())
    line = _httpx_line(headers={"Content-Encoding": "br"}, body="\x1b\x0a\x00binary")

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.completeness.truncation_reason is TruncationReason.DECODE_FAILED
    assert facts.completeness.body_complete is False
    # The bytes still arrived, so the transport is not what failed.
    assert facts.completeness.transport_complete is True


# =============================================================================
# The error vocabulary
# =============================================================================


def test_malformed_tool_output_is_output_unparseable() -> None:
    request = parse_request(_http_payload())
    captured = _captured(stdout=b"<html>panic: not json</html>\n")

    outcome = observe_from_output(request, captured)

    assert isinstance(outcome, ObserverFailure)
    assert outcome.error_code == ObserverErrorCode.OUTPUT_UNPARSEABLE
    assert outcome.detail_numeric == {"stdout_bytes": 29, "exit_code": 0}


def test_silence_is_reported_as_silence() -> None:
    """httpx prints nothing for a host it could not reach; we do not invent a cause."""
    request = parse_request(_http_payload())

    outcome = observe_from_output(request, _captured(stdout=b""))
    nonzero = observe_from_output(request, _captured(stdout=b"", exit_code=1))

    assert isinstance(outcome, ObserverFailure)
    assert outcome.error_code == ObserverErrorCode.OUTPUT_EMPTY
    assert isinstance(nonzero, ObserverFailure)
    assert nonzero.error_code == ObserverErrorCode.TOOL_NONZERO


def test_a_deadline_is_a_closed_code_with_numeric_detail() -> None:
    request = parse_request(_http_payload())
    captured = _captured(stdout=b"", exit_code=None, timed_out=True, elapsed_seconds=20.0004)

    outcome = observe_from_output(request, captured)

    assert isinstance(outcome, ObserverFailure)
    assert outcome.error_code == ObserverErrorCode.DEADLINE
    assert outcome.detail_numeric == {"elapsed_seconds": 20.0}


def test_a_transport_error_crosses_as_a_code_and_a_length() -> None:
    request = parse_request(_http_payload())
    secretish = f"x509: certificate signed by unknown authority for {OPAQUE_CANARY}"
    line = _httpx_line(failed=True, error=secretish)

    outcome = observe_from_output(request, _captured(line))

    assert isinstance(outcome, ObserverFailure)
    assert outcome.error_code == ObserverErrorCode.TLS_FAILED
    assert outcome.detail_numeric == {"error_chars": len(secretish)}
    assert OPAQUE_CANARY not in json.dumps(document_for(outcome))


def test_every_failure_detail_is_numeric() -> None:
    with pytest.raises(ValueError, match="numbers only"):
        ObserverFailure(ObserverErrorCode.INTERNAL, {"detail": "a string"})  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="not an observer error code"):
        ObserverFailure("improvised", {})


# =============================================================================
# DNS facts
# =============================================================================


def test_nxdomain_is_a_successful_complete_observation() -> None:
    """The positive case for a dangling record is an answer, not an error."""
    request = parse_request(_dns_payload())
    line = {
        "host": HOST,
        "status_code": "nxdomain",
        "cname": ["app.example.test.", "bucket.s3.amazonaws.com."],
        "a": [],
    }

    outcome = observe_from_output(request, _captured(line))
    facts = _facts(outcome)

    assert document_for(outcome)["ok"] is True
    assert facts.kind is ObservationKind.DNS_ANSWER
    dns = facts.dns
    assert dns is not None
    assert dns.rcode == "NXDOMAIN"
    assert dns.cname_chain == ("app.example.test", "bucket.s3.amazonaws.com")
    assert dns.a_records == ()
    assert dns.resolver_set_digest == "resolvers-test"
    assert facts.completeness.is_whole


def test_a_resolver_answer_that_is_not_an_address_does_not_cross() -> None:
    request = parse_request(_dns_payload())
    line = {"status_code": "NOERROR", "a": ["192.0.2.10", f"not-an-address-{OPAQUE_CANARY}"]}

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.dns is not None
    assert facts.dns.a_records == ("192.0.2.10",)
    assert OPAQUE_CANARY not in json.dumps(document_for(facts))


def test_an_unreadable_rcode_is_output_unparseable() -> None:
    request = parse_request(_dns_payload())

    outcome = observe_from_output(request, _captured({"host": HOST, "status_code": "¿qué?"}))

    assert isinstance(outcome, ObserverFailure)
    assert outcome.error_code == ObserverErrorCode.OUTPUT_UNPARSEABLE


def test_a_chain_filled_to_the_bound_is_recorded_as_truncated() -> None:
    request = parse_request(_dns_payload(bounds={**DNS_BOUNDS, "cname_depth": 2}))
    line = {"status_code": "NOERROR", "cname": [f"hop{i}.example.test" for i in range(6)]}

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.dns is not None
    assert len(facts.dns.cname_chain) == 2
    assert facts.completeness.truncation_reason is TruncationReason.CNAME_DEPTH
    assert facts.completeness.is_whole is False


def test_the_dns_argv_pins_the_resolvers_and_keeps_nxdomain() -> None:
    request = parse_request(_dns_payload())
    argv = build_dns_argv(request, names_file="/sandbox/name.txt")

    assert argv[0] == DNSX_PATH
    assert argv[argv.index("-r") + 1] == RESOLVER
    assert argv[argv.index("-l") + 1] == "/sandbox/name.txt"
    assert "nxdomain" in argv[argv.index("-rcode") + 1]
    assert argv[argv.index("-retry") + 1] == "1"


# =============================================================================
# The request it will accept
# =============================================================================


@pytest.mark.parametrize("missing", ["kind", "binary_path", "envelope", "bounds"])
def test_a_request_missing_a_field_is_refused(missing: str) -> None:
    payload = _http_payload()
    del payload[missing]

    with pytest.raises(RequestInvalid):
        parse_request(payload)


def test_a_missing_bound_is_named_rather_than_defaulted() -> None:
    payload = _http_payload(bounds={k: v for k, v in BOUNDS.items() if k != "decoded_bytes"})

    with pytest.raises(RequestInvalid, match="decoded_bytes"):
        parse_request(payload)


def test_bounds_may_only_narrow() -> None:
    narrowed = parse_request(_http_payload(bounds={**BOUNDS, "wire_bytes": 1_024}))
    assert narrowed.bounds.wire_bytes == 1_024

    with pytest.raises(RequestInvalid, match="narrow"):
        parse_request(_http_payload(bounds={**BOUNDS, "wire_bytes": HTTP_MAX_WIRE_BYTES + 1}))
    with pytest.raises(RequestInvalid, match="narrow"):
        parse_request(_http_payload(bounds={**BOUNDS, "deadline_seconds": 600.0}))


@pytest.mark.parametrize(
    "payload",
    [
        _http_payload(request_format_version="2"),
        _http_payload(binary_path="httpx"),
        _http_payload(kind="dns.answer"),
        _http_payload(resolvers=[RESOLVER]),
        _http_payload(signal_tokens=["x" * 400]),
        _http_payload(surprise="extra"),
        _dns_payload(resolvers=["resolver.example.test"]),
        _dns_payload(resolvers=[]),
    ],
)
def test_anything_unexpected_in_the_request_is_refused(payload: dict) -> None:
    with pytest.raises(RequestInvalid):
        parse_request(payload)


def test_an_envelope_pinning_another_extractor_set_is_refused() -> None:
    payload = _http_payload()
    payload["envelope"]["extractor_set_digest"] = "0" * 64

    with pytest.raises(RequestInvalid, match="extractor set"):
        parse_request(payload)


def test_an_unscrubbed_environment_refuses_to_start() -> None:
    assert_environment_scrubbed({"PATH": "/usr/bin", "HOME": "/sandbox"})

    with pytest.raises(SandboxNotSealed, match="GRYPHON_VERIFICATION_DATABASE_URL"):
        assert_environment_scrubbed({"GRYPHON_VERIFICATION_DATABASE_URL": "postgresql://x"})


# =============================================================================
# The entry point
# =============================================================================


def test_a_malformed_request_exits_two_with_no_document(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(entry, "assert_environment_scrubbed", lambda: None)
    path = tmp_path / "request.json"
    payload = _http_payload()
    del payload["bounds"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    status = entry.main([str(path)])

    assert status == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "refusing to observe" in captured.err


def test_a_refusal_is_a_document_and_exit_zero(tmp_path, monkeypatch, capsys) -> None:
    """A missing binary is a result: one document, status 0, nothing on stderr."""
    monkeypatch.setattr(entry, "assert_environment_scrubbed", lambda: None)
    path = tmp_path / "request.json"
    missing = tmp_path / "bin" / "httpx"
    path.write_text(json.dumps(_http_payload(binary_path=str(missing))), encoding="utf-8")

    status = entry.main([str(path)])

    assert status == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "ok": False,
        "error_code": ObserverErrorCode.BINARY_MISSING,
        "detail_numeric": {},
    }
    assert captured.err == ""


def test_the_usage_line_is_not_a_document(capsys) -> None:
    assert entry.main([]) == 2
    assert capsys.readouterr().out == ""


# =============================================================================
# The secret boundary
# =============================================================================


def test_no_byte_of_the_body_appears_in_the_emitted_document() -> None:
    """The sealing canary. Counts cross; the bytes they describe do not."""
    request = parse_request(_http_payload())
    line = _httpx_line(
        headers={"Content-Type": "text/plain", "Content-Length": str(len(DOTENV_BODY))},
        body=DOTENV_BODY,
    )

    outcome = observe_from_output(request, _captured(line))
    document = json.dumps(document_for(outcome), sort_keys=True)

    for canary in CANARIES:
        assert canary not in document
    # And the measurement still happened: a shape was counted and the key names
    # an operator needs are there, without any value behind them.
    facts = _facts(outcome)
    assert facts.http is not None
    assert facts.http.secret_class_counts[SecretClass.AWS_ACCESS_KEY_ID.value] >= 1
    assert "AWS_SECRET_ACCESS_KEY" in facts.http.dotenv.key_names  # type: ignore[union-attr]
    assert set(facts.http.dotenv.value_classes) <= {  # type: ignore[union-attr]
        "empty",
        "secret_shaped",
        "other",
    }


def test_a_body_that_serves_a_redaction_marker_produces_no_secret_class() -> None:
    """There is no in-band protocol to forge: shapes are counted, never marked up."""
    request = parse_request(_http_payload())
    marker = "«redacted-secret»"
    body = f"NOTE={marker}\nOTHER=«redacted-secret:aws_access_key_id»\n"
    line = _httpx_line(headers={"Content-Type": "text/plain"}, body=body)

    facts = _facts(observe_from_output(request, _captured(line)))

    assert facts.http is not None
    assert all(count == 0 for count in facts.http.secret_class_counts.values())
    assert marker not in json.dumps(document_for(facts))
