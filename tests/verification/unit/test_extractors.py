"""The fixed extractor set: bounded, pure, and carrying names rather than bytes."""

from __future__ import annotations

import hashlib
import json
import time

import pytest

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.tooling.observation.extractors import (
    EXTRACTOR_FUNCTIONS,
    EXTRACTOR_SET_DIGEST,
    EXTRACTOR_SET_VERSION,
    MAX_DNS_RECORDS,
    MAX_DOTENV_KEY_NAMES,
    MAX_DOTENV_LINES,
    MAX_HEADERS,
    MAX_SEARCH_CHARS,
    MAX_SIGNAL_TOKENS,
    MAX_TOKEN_CHARS,
    body_digest,
    cname_chain,
    dotenv_grammar,
    header_presence,
    size_facts,
    status_class,
    token_presence,
)
from gryphon.verification.constants import (
    DNS_MAX_CNAME_DEPTH,
    EXTRACTORS_BY_KIND,
    HEADER_NAME_ALLOWLIST,
    Extractor,
    ValueClass,
)

pytestmark = pytest.mark.unit

AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

LINE_SEPARATOR = chr(0x2028)
FORM_FEED = chr(0x0C)

DOTENV_BODY = (
    "# deployment configuration\n"
    "\n"
    f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n"
    f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n"
    "DEBUG=\n"
    "APP_NAME=gryphon\n"
    "lowercase_key=ignored\n"
    "   \n"
    "NOT AN ASSIGNMENT\n"
)


# -- dotenv_grammar ------------------------------------------------------------


def test_mixed_body_is_counted_line_by_line() -> None:
    facts = dotenv_grammar(DOTENV_BODY, max_lines=1_000)
    assert facts.total_lines == 9
    assert facts.non_empty_lines == 7
    assert facts.assignment_lines == 4
    assert facts.assignment_ratio == pytest.approx(4 / 7)


def test_key_names_and_value_classes_stay_parallel() -> None:
    facts = dotenv_grammar(DOTENV_BODY, max_lines=1_000)
    assert facts.key_names == (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DEBUG",
        "APP_NAME",
    )
    assert facts.value_classes == (
        ValueClass.SECRET_SHAPED.value,
        ValueClass.SECRET_SHAPED.value,
        ValueClass.EMPTY.value,
        ValueClass.OTHER.value,
    )


def test_no_value_reaches_the_payload() -> None:
    """The sealing property, at the one extractor that reads values."""
    facts = dotenv_grammar(DOTENV_BODY, max_lines=1_000)
    serialized = json.dumps(facts.as_payload())
    assert AWS_KEY_ID not in serialized
    assert AWS_SECRET not in serialized
    assert "gryphon" not in serialized
    assert "AWS_ACCESS_KEY_ID" in serialized


def test_lowercase_keys_and_prose_are_not_assignments() -> None:
    facts = dotenv_grammar("lowercase=1\nNOT AN ASSIGNMENT\nA=1\n", max_lines=100)
    # ``A=1`` fails the grammar too: it requires at least two key characters.
    assert facts.assignment_lines == 0
    assert facts.non_empty_lines == 3


def test_crlf_lines_are_normalized() -> None:
    facts = dotenv_grammar("AB=1\r\n\r\nCD=2\r\n", max_lines=100)
    assert facts.total_lines == 3
    assert facts.non_empty_lines == 2
    assert facts.key_names == ("AB", "CD")


def test_empty_body_measures_zero() -> None:
    facts = dotenv_grammar("", max_lines=100)
    assert (facts.total_lines, facts.non_empty_lines, facts.assignment_lines) == (0, 0, 0)
    assert facts.assignment_ratio == 0.0
    assert facts.key_names == ()


def test_max_lines_stops_the_read_visibly() -> None:
    body = "".join(f"KEY_{index:04d}=value\n" for index in range(50))
    facts = dotenv_grammar(body, max_lines=10)
    assert facts.total_lines == 10
    assert facts.assignment_lines == 10


def test_a_caller_cannot_raise_the_line_ceiling() -> None:
    body = "AA=1\n" * (MAX_DOTENV_LINES + 50)
    facts = dotenv_grammar(body, max_lines=10_000_000)
    assert facts.total_lines == MAX_DOTENV_LINES


def test_key_name_list_is_capped_while_counts_stay_exact() -> None:
    count = MAX_DOTENV_KEY_NAMES + 50
    body = "".join(f"KEY_{index:04d}=value\n" for index in range(count))
    facts = dotenv_grammar(body, max_lines=MAX_DOTENV_LINES)
    assert facts.assignment_lines == count
    assert len(facts.key_names) == MAX_DOTENV_KEY_NAMES
    assert len(facts.value_classes) == MAX_DOTENV_KEY_NAMES


def test_unicode_body_is_measured_without_raising() -> None:
    facts = dotenv_grammar("GREETING=café ☕\n# 日本語\n", max_lines=100)
    assert facts.assignment_lines == 1
    assert facts.key_names == ("GREETING",)


def test_binary_body_is_measured_without_raising() -> None:
    facts = dotenv_grammar(bytes(range(256)).decode("utf-8", "replace"), max_lines=100)
    assert facts.total_lines >= 1


def test_exotic_line_separators_do_not_inflate_the_line_count() -> None:
    # U+2028 and the form feed are newlines to ``str.splitlines`` but not to a
    # configuration loader; counting them would let a target move its own ratio.
    facts = dotenv_grammar(f"KEY_ONE=a{LINE_SEPARATOR}b{FORM_FEED}c\n", max_lines=100)
    assert facts.total_lines == 1
    assert facts.assignment_lines == 1


def test_a_very_long_single_line_completes_quickly() -> None:
    started = time.perf_counter()
    facts = dotenv_grammar("KEY_ONE=" + "A1" * 200_000, max_lines=100)
    assert facts.assignment_lines == 1
    assert time.perf_counter() - started < 2.0


# -- token_presence ------------------------------------------------------------

HEADERS = {
    "Server": "Apache/2.4.1",
    "X-Powered-By": "PHP/8.2",
    "Content-Type": "text/plain; charset=utf-8",
    "X-Custom-Thing": "1",
}


def test_tokens_are_matched_case_insensitively_in_body_and_headers() -> None:
    found = token_presence(
        "<html>WELCOME to Acme Widgets</html>",
        HEADERS,
        ("Acme Widgets", "php/8.2", "nowhere-at-all"),
    )
    assert found == ("Acme Widgets", "php/8.2")


def test_the_registry_spelling_is_what_comes_back() -> None:
    assert token_presence("welcome to acme", {}, ("ACME",)) == ("ACME",)


def test_no_tokens_and_no_match_return_empty() -> None:
    assert token_presence("anything", HEADERS, ()) == ()
    assert token_presence("anything", HEADERS, ("absent",)) == ()


def test_duplicate_blank_and_oversized_tokens_are_skipped() -> None:
    oversized = "x" * (MAX_TOKEN_CHARS + 1)
    found = token_presence(f"body with {oversized} inside", {}, ("", "   ", oversized))
    assert found == ()


def test_repeated_token_is_reported_once() -> None:
    assert token_presence("acme acme acme", {}, ("acme", "acme")) == ("acme",)


def test_token_list_is_capped() -> None:
    tokens = tuple(f"tok{index:03d}" for index in range(MAX_SIGNAL_TOKENS + 5))
    body = " ".join(tokens)
    assert len(token_presence(body, {}, tokens)) == MAX_SIGNAL_TOKENS


def test_only_the_leading_body_window_is_searched() -> None:
    assert token_presence("." * MAX_SEARCH_CHARS + " needle", {}, ("needle",)) == ()


def test_empty_body_with_header_only_match() -> None:
    assert token_presence("", {"Server": "nginx/1.25"}, ("nginx",)) == ("nginx",)


# -- header_presence -----------------------------------------------------------


def test_allowlisted_names_only_sorted_and_lowercased() -> None:
    headers = {
        "Content-Type": "text/plain",
        "SERVER": "nginx",
        "X-Custom": "1",
        "retry-after": "5",
    }
    assert header_presence(headers) == ("content-type", "retry-after", "server")


def test_every_reported_name_is_in_the_allowlist() -> None:
    headers = {name: "value" for name in ("Server", "X-Secret", "Location", "Set-Cookie")}
    assert set(header_presence(headers)) <= HEADER_NAME_ALLOWLIST


def test_no_headers_report_nothing() -> None:
    assert header_presence({}) == ()


def test_header_scan_is_capped() -> None:
    headers = {f"x-filler-{index}": "1" for index in range(MAX_HEADERS + 50)}
    headers["Server"] = "nginx"  # past the cap, so it is never reached
    assert header_presence(headers) == ()


# -- status_class --------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [(404, 4), (200, 2), (301, 3), (500, 5), (100, 1), (599, 5)],
)
def test_status_class_is_the_leading_digit(code: int, expected: int) -> None:
    assert status_class(code) == expected


@pytest.mark.parametrize("code", [0, -1, 99, 600, 999_999, -404])
def test_implausible_status_codes_have_no_class(code: int) -> None:
    assert status_class(code) == 0


# -- body_digest and size_facts ------------------------------------------------


@pytest.mark.parametrize("raw", [b"", b"gryphon", bytes(range(256)), "héllo".encode()])
def test_body_digest_is_sha256_of_the_wire_bytes(raw: bytes) -> None:
    assert body_digest(raw) == hashlib.sha256(raw).hexdigest()


def test_size_facts_reports_both_numbers() -> None:
    assert size_facts(b"12345", b"1234567890") == (5, 10)


def test_unencoded_body_reports_equal_sizes() -> None:
    assert size_facts(b"12345", None) == (5, 5)
    assert size_facts(b"", None) == (0, 0)


# -- cname_chain ---------------------------------------------------------------


def test_chain_is_normalized_and_deduplicated() -> None:
    records = ["App.Example.COM.", "cdn.provider.net", "cdn.provider.net", "  edge.provider.net. "]
    assert cname_chain(records, max_depth=10) == (
        "app.example.com",
        "cdn.provider.net",
        "edge.provider.net",
    )


def test_a_loop_cannot_extend_the_chain() -> None:
    records = ["a.example.com", "b.example.com", "a.example.com", "b.example.com"]
    assert cname_chain(records, max_depth=10) == ("a.example.com", "b.example.com")


def test_depth_is_bounded_by_the_caller_and_by_the_ceiling() -> None:
    records = [f"n{index}.example.com" for index in range(DNS_MAX_CNAME_DEPTH + 20)]
    assert len(cname_chain(records, max_depth=2)) == 2
    assert len(cname_chain(records, max_depth=10_000)) == DNS_MAX_CNAME_DEPTH
    assert cname_chain(records, max_depth=0) == ()


def test_names_outside_the_presentation_grammar_are_dropped() -> None:
    records = ["bad name with spaces", "ok.example.com", "x" * 300, "", "   ", "héllo.example"]
    assert cname_chain(records, max_depth=10) == ("ok.example.com",)


def test_wildcard_and_underscore_labels_survive() -> None:
    records = ["*.example.com", "_acme-challenge.example.com"]
    assert cname_chain(records, max_depth=10) == tuple(records)


def test_empty_records_produce_an_empty_chain() -> None:
    assert cname_chain([], max_depth=10) == ()


def test_record_scan_is_capped() -> None:
    records = ["bad name"] * MAX_DNS_RECORDS + ["ok.example.com"]
    assert cname_chain(records, max_depth=5) == ()


# -- the set and its digest ----------------------------------------------------


def test_every_catalog_extractor_is_implemented() -> None:
    assert frozenset(EXTRACTOR_FUNCTIONS) == frozenset(Extractor)
    for kind, extractors in EXTRACTORS_BY_KIND.items():
        assert extractors <= frozenset(EXTRACTOR_FUNCTIONS), kind


def test_digest_matches_an_independently_canonicalized_spec() -> None:
    """Pinned to a literal, so hash randomization or dict order cannot move it."""
    expected = sha256_hex(
        canonical_json_bytes(
            {
                "extractor_set_version": "1",
                "extractors": [
                    "body_digest",
                    "cname_chain",
                    "dotenv_grammar",
                    "header_presence",
                    "size_facts",
                    "status_class",
                    "token_presence",
                ],
            }
        )
    )
    assert EXTRACTOR_SET_DIGEST == expected


def test_digest_is_lowercase_sha256_hex() -> None:
    assert len(EXTRACTOR_SET_DIGEST) == 64
    assert EXTRACTOR_SET_DIGEST == EXTRACTOR_SET_DIGEST.lower()
    int(EXTRACTOR_SET_DIGEST, 16)


def test_version_bump_changes_the_digest() -> None:
    bumped = sha256_hex(
        canonical_json_bytes(
            {
                "extractor_set_version": "2",
                "extractors": sorted(member.value for member in Extractor),
            }
        )
    )
    assert bumped != EXTRACTOR_SET_DIGEST
    assert EXTRACTOR_SET_VERSION == "1"


def test_adding_an_extractor_would_change_the_digest() -> None:
    widened = sha256_hex(
        canonical_json_bytes(
            {
                "extractor_set_version": EXTRACTOR_SET_VERSION,
                "extractors": sorted([*(m.value for m in Extractor), "new_extractor"]),
            }
        )
    )
    assert widened != EXTRACTOR_SET_DIGEST
