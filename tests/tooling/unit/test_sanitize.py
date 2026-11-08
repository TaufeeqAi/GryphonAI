"""Output redaction, bounded parsing and drift detection."""

from __future__ import annotations

import json

import pytest

from gryphon.tooling.tools.sanitize import parse_jsonl, redact_text

pytestmark = pytest.mark.unit


def test_redacts_secrets() -> None:
    assert "AKIA" not in redact_text("leak AKIAIOSFODNN7EXAMPLE here")
    assert "redacted" in redact_text('api_key: "abcdef0123456789abcd"')
    jwt = "eyJhbGciOi.eyJzdWIiOi.sig123"
    assert jwt not in redact_text(jwt)


def test_parse_jsonl_happy() -> None:
    stdout = "\n".join(json.dumps({"host": f"h{i}.example"}) for i in range(5))
    parsed = parse_jsonl(stdout, max_records=100)
    assert len(parsed.records) == 5
    assert parsed.degraded is False
    assert parsed.failed_lines == 0


def test_parse_jsonl_drift_flagged() -> None:
    lines = [json.dumps({"ok": 1})] + ["not json"] * 9
    parsed = parse_jsonl("\n".join(lines), max_records=100)
    assert parsed.failed_lines == 9
    assert parsed.degraded is True  # 90% failure > threshold


def test_parse_jsonl_truncates() -> None:
    stdout = "\n".join(json.dumps({"n": i}) for i in range(50))
    parsed = parse_jsonl(stdout, max_records=10)
    assert len(parsed.records) == 10
    assert parsed.truncated is True


def test_parse_jsonl_redacts_records() -> None:
    stdout = json.dumps({"body": "token=abcdef0123456789abcd"})
    parsed = parse_jsonl(stdout, max_records=10)
    assert "abcdef0123456789abcd" not in json.dumps(parsed.records)
