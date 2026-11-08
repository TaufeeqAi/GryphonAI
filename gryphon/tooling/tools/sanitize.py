"""Output bounds, secret redaction and parse-drift detection.

Tool output is bounded and secret-redacted before records leave the execution
boundary. Parse drift (a non-trivial fraction of unparseable records) flips the
outcome to degraded/FAILED rather than being silently skipped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from gryphon.tooling.constants import PARSE_DRIFT_FAILURE_THRESHOLD

_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{12,}"),
    re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
)
_REDACTION = "«redacted-secret»"


def redact_text(value: str) -> str:
    out = value
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(_REDACTION, out)
    return out


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    return value


@dataclass(frozen=True)
class ParsedJsonl:
    records: list[dict[str, Any]]
    total_lines: int
    failed_lines: int
    truncated: bool

    @property
    def degraded(self) -> bool:
        if self.total_lines == 0:
            return False
        return (self.failed_lines / self.total_lines) > PARSE_DRIFT_FAILURE_THRESHOLD


def parse_jsonl(stdout: str, *, max_records: int) -> ParsedJsonl:
    """Parse newline-delimited JSON with drift accounting and a record cap."""
    records: list[dict[str, Any]] = []
    total = 0
    failed = 0
    truncated = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        total += 1
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            failed += 1
            continue
        if not isinstance(obj, dict):
            failed += 1
            continue
        if len(records) < max_records:
            records.append(redact_value(obj))
        else:
            truncated = True
    return ParsedJsonl(records=records, total_lines=total, failed_lines=failed, truncated=truncated)
