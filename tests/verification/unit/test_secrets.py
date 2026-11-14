"""Secret-shape classification: counts are returned, values never are."""

from __future__ import annotations

import time

import pytest

from gryphon.tooling.observation.secrets import (
    MAX_MATCHES_PER_CLASS,
    MAX_SCAN_CHARS,
    classify,
    credential_key_names,
    value_class,
)
from gryphon.tooling.tools.sanitize import redact_text
from gryphon.verification.constants import SecretClass, ValueClass

pytestmark = pytest.mark.unit

AWS = SecretClass.AWS_ACCESS_KEY_ID.value
CREDENTIAL = SecretClass.CREDENTIAL_ASSIGNMENT.value
PRIVATE_KEY = SecretClass.PRIVATE_KEY_BLOCK.value
JWT = SecretClass.JWT.value
URL_CREDENTIAL = SecretClass.URL_CREDENTIAL.value

# A synthetic block. The "body" lines are base64-shaped filler, not key material.
PEM_BODY_FIRST = "MIIEowIBAAKCAQEA3Zx1vQ2bRnotarealkeyjustbase64shapedfillerAAAAAAA"
PEM_BODY_SECOND = "bGludGhlbWlkZGxlb2ZhYmxvY2tib2R5dGhhdG11c3Rub3RzdXJ2aXZlAAAAAAA"
PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
PEM_FOOTER = "-----END RSA PRIVATE KEY-----"
PEM_BLOCK = f"{PEM_HEADER}\n{PEM_BODY_FIRST}\n{PEM_BODY_SECOND}\n{PEM_FOOTER}\n"

JWT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# -- the closed set -----------------------------------------------------------


def test_every_class_is_reported_with_an_explicit_count() -> None:
    counts = classify("nothing interesting here")
    assert set(counts) == {member.value for member in SecretClass}
    assert set(counts.values()) == {0}


def test_empty_input_is_all_zeros() -> None:
    assert classify("") == {member.value: 0 for member in SecretClass}


# -- private key blocks: the defect this module closes -------------------------


def test_whole_pem_block_counts_once() -> None:
    assert classify(PEM_BLOCK)[PRIVATE_KEY] == 1


def test_block_body_is_inside_the_match_not_an_extra_occurrence() -> None:
    noisy = f"before\n{PEM_BLOCK}after\n"
    assert classify(noisy)[PRIVATE_KEY] == 1


def test_two_blocks_count_twice() -> None:
    assert classify(PEM_BLOCK + "\n" + PEM_BLOCK)[PRIVATE_KEY] == 2


def test_header_without_a_footer_still_counts() -> None:
    # A response truncated mid-key has exposed a key just the same.
    truncated = f"{PEM_HEADER}\n{PEM_BODY_FIRST}\n"
    assert classify(truncated)[PRIVATE_KEY] == 1


def test_a_block_followed_by_a_stray_header_counts_twice() -> None:
    assert classify(PEM_BLOCK + PEM_HEADER + "\n")[PRIVATE_KEY] == 2


@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ],
)
def test_key_type_variants_are_recognized(header: str) -> None:
    footer = header.replace("BEGIN", "END")
    assert classify(f"{header}\nAAAA\n{footer}\n")[PRIVATE_KEY] == 1


def test_a_public_key_block_is_not_a_private_key() -> None:
    public = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    assert classify(public)[PRIVATE_KEY] == 0


def test_the_sanitizer_defect_this_module_closes() -> None:
    """The execution layer's redaction removes only the header line.

    Pinned deliberately: it documents *why* the pattern here spans the whole
    block. When :mod:`gryphon.tooling.tools.sanitize` is brought in line, this
    assertion is the one to delete.
    """
    redacted = redact_text(PEM_BLOCK)
    assert PEM_HEADER not in redacted
    assert PEM_BODY_FIRST in redacted  # the key body survived the redaction
    assert classify(PEM_BLOCK)[PRIVATE_KEY] == 1


# -- AWS access key ids --------------------------------------------------------


def test_aws_example_key_is_recognized() -> None:
    assert classify(f"key = {AWS_KEY_ID}")[AWS] == 1


def test_temporary_credential_prefix_is_recognized() -> None:
    assert classify("ASIAIOSFODNN7EXAMPLE")[AWS] == 1


@pytest.mark.parametrize(
    "candidate",
    [
        "AKIA",
        "AKIAIOSFODNN7EXAMP",  # too short
        "akiaiosfodnn7example",  # lowercase
        "XAKIAIOSFODNN7EXAMPLE",  # no left boundary
        "AKIAIOSFODNN7EXAMPLEX",  # no right boundary
    ],
)
def test_near_misses_are_not_counted(candidate: str) -> None:
    assert classify(candidate)[AWS] == 0


def test_a_dotenv_line_counts_as_both_shapes() -> None:
    # Shapes are not a partition: the predicate asks whether a shape appeared.
    counts = classify(f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}")
    assert counts[AWS] == 1
    assert counts[CREDENTIAL] == 1


# -- credential assignments ----------------------------------------------------


def test_keyword_in_the_middle_of_a_key_name_is_recognized() -> None:
    body = f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}"
    assert classify(body)[CREDENTIAL] == 1
    assert credential_key_names(body) == ("AWS_SECRET_ACCESS_KEY",)


def test_quoted_and_colon_forms_are_recognized() -> None:
    assert classify('API_KEY="abcdef123456"')[CREDENTIAL] == 1
    assert classify('"apiKey": "abcdef123456"')[CREDENTIAL] == 1


def test_non_credential_key_names_are_not_counted() -> None:
    assert classify("DEBUG=verbose_mode\nAPP_NAME=gryphon_service")[CREDENTIAL] == 0


def test_key_names_are_reported_once_in_first_seen_order() -> None:
    body = "API_KEY=abcdef123456\nDB_PASSWORD=abcdef123456\nAPI_KEY=abcdef123456\n"
    assert credential_key_names(body) == ("API_KEY", "DB_PASSWORD")


def test_a_key_with_no_value_is_not_an_exposure() -> None:
    assert classify("PASSWORD=")[CREDENTIAL] == 0


# -- JWTs ----------------------------------------------------------------------


def test_jwt_is_recognized() -> None:
    assert classify(f"Authorization: Bearer {JWT_TOKEN}")[JWT] == 1


def test_two_segment_token_is_not_a_jwt() -> None:
    assert classify("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")[JWT] == 0


# -- URL credentials -----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "postgres://admin:s3cr3tpw@db.internal.example:5432/app",
        "https://user:pass@www.example.com/path",
        "amqp://svc:hunter22@broker.example",
    ],
)
def test_url_credentials_are_recognized(url: str) -> None:
    assert classify(url)[URL_CREDENTIAL] == 1


def test_a_url_without_credentials_is_not_counted() -> None:
    assert classify("https://www.example.com/path?x=1")[URL_CREDENTIAL] == 0


def test_an_innocuous_key_name_still_exposes_a_url_credential() -> None:
    counts = classify("DATABASE_URL=postgres://u:p@db.example")
    assert counts[URL_CREDENTIAL] == 1
    assert counts[CREDENTIAL] == 0


# -- value classes -------------------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", '""', "''", '"  "'])
def test_absent_values_are_empty(raw: str) -> None:
    assert value_class(raw) is ValueClass.EMPTY


@pytest.mark.parametrize(
    "raw",
    [AWS_KEY_ID, AWS_SECRET, JWT_TOKEN, f'"{AWS_KEY_ID}"', "a1b2c3d4e5f6a7b8c9d0e1f2"],
)
def test_secret_shaped_values(raw: str) -> None:
    assert value_class(raw) is ValueClass.SECRET_SHAPED


@pytest.mark.parametrize(
    "raw",
    [
        "true",
        "gryphon",
        "/var/log/app.log",
        "localhost",
        "supercalifragilistic",  # long, but no digits: not token-shaped
        "2026-11-14T00:00:00Z",
        "postgres",
    ],
)
def test_ordinary_values(raw: str) -> None:
    assert value_class(raw) is ValueClass.OTHER


# -- hostile input -------------------------------------------------------------


def test_unicode_body_is_handled_and_finds_nothing() -> None:
    body = "日本語のテキスト ☕ ünïcödé — no credentials here\n"
    assert classify(body) == {member.value: 0 for member in SecretClass}


def test_unicode_around_a_secret_does_not_hide_it() -> None:
    assert classify(f"鍵 → {AWS_KEY_ID} ☕")[AWS] == 1


def test_binary_bytes_decoded_with_replacement_do_not_raise() -> None:
    body = bytes(range(256)).decode("utf-8", "replace")
    counts = classify(body)
    assert set(counts) == {member.value for member in SecretClass}


def test_null_bytes_and_control_characters_are_tolerated() -> None:
    assert classify("\x00\x01\x02" * 1000 + AWS_KEY_ID)[AWS] == 1


# -- bounds --------------------------------------------------------------------


def test_counts_stop_at_the_per_class_ceiling() -> None:
    body = " ".join(f"AKIA{index:016d}" for index in range(MAX_MATCHES_PER_CLASS + 200))
    assert classify(body)[AWS] == MAX_MATCHES_PER_CLASS


def test_only_the_leading_window_is_scanned() -> None:
    assert classify("." * MAX_SCAN_CHARS + f" {AWS_KEY_ID}")[AWS] == 0
    assert classify(f"{AWS_KEY_ID} " + "." * MAX_SCAN_CHARS)[AWS] == 1


@pytest.mark.parametrize(
    "body",
    [
        "A" * 100_000,
        ("-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 2_000) * 40,
        ("x" * 70 + "=" + "y" * 70 + "\n") * 500,
        "eyJ" + "A" * 50_000,
        "http://" + "u" * 50_000,
        "password" * 20_000,
        ("https://user:" + "p" * 500) * 100,
        "=" * 100_000,
        ("-" * 5 + "BEGIN ") * 10_000,
    ],
)
def test_adversarial_input_completes_quickly(body: str) -> None:
    """Bounded quantifiers only: a long repetitive body must not blow up."""
    started = time.perf_counter()
    classify(body)
    assert time.perf_counter() - started < 2.0


def test_unterminated_headers_are_each_counted_once() -> None:
    body = ("-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 2_000) * 40
    assert classify(body)[PRIVATE_KEY] == 40


def test_value_classification_of_a_huge_value_completes_quickly() -> None:
    started = time.perf_counter()
    assert value_class("A1" * 100_000) is ValueClass.SECRET_SHAPED
    assert time.perf_counter() - started < 2.0
