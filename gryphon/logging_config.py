"""Structured, redacted logging (§24).

Telemetry is diagnostic, not the audit of record (§24.3). It MUST NOT contain
bearer tokens, private keys, passwords, database URLs or full claim payloads
(SEC-016 / INV-024 / §21.2). This module configures ``structlog`` with a
redaction processor that drops known-sensitive keys and masks any value whose
*key name* indicates a secret.

The redaction is defense-in-depth: callers are still expected to log only the
safe correlation fields enumerated in §24.1.
"""

from __future__ import annotations

import logging
from typing import Any

import structlog

#: Event-dict keys whose values are always removed before emission.
_REDACT_KEYS: frozenset[str] = frozenset(
    {
        "token",
        "authorization_token",
        "jws",
        "bearer",
        "signature",
        "sig",
        "private_key",
        "signing_key",
        "grant_signing_key_hex",
        "audit_signing_key_hex",
        "password",
        "db_password",
        "database_url",
        "migration_database_url",
        "dsn",
        "idempotency_key",  # raw key; only its hash is safe to log
        "claims",           # full claim payload
        "written_authorization_ref",
    }
)

_MASK = "«redacted»"


def _redact_processor(
    _logger: Any, _method: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Remove or mask sensitive keys from every event."""
    for key in list(event_dict.keys()):
        if key.lower() in _REDACT_KEYS:
            event_dict[key] = _MASK
    return event_dict


def configure_logging(*, level: int = logging.INFO, json_output: bool = True) -> None:
    """Configure process-wide structured logging. Idempotent."""
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_processor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    processors.append(
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)
