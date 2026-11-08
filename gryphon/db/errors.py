"""Classification of persistence failures (§15, §16).

Translates SQLAlchemy/asyncpg exceptions into a stable decision about whether an
operation is retryable (deadlock/serialization — known rolled back), a unique
violation (idempotency conflict / concurrent duplicate), a connection failure
(DB unavailable) or an unknown outcome (NEVER treated as success).
"""

from __future__ import annotations

from sqlalchemy.exc import (
    DBAPIError,
    IntegrityError,
    InterfaceError,
    OperationalError,
)

from gryphon.errors import ReasonCode

# PostgreSQL SQLSTATE codes.
_SQLSTATE_UNIQUE_VIOLATION = "23505"
_SQLSTATE_DEADLOCK = "40P01"
_SQLSTATE_SERIALIZATION = "40001"


def _sqlstate(exc: BaseException) -> str | None:
    orig = getattr(exc, "orig", None)
    code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return str(code) if code is not None else None


def is_unique_violation(exc: BaseException) -> bool:
    """True for a unique-constraint violation (idempotency/concurrent duplicate)."""
    return isinstance(exc, IntegrityError) and _sqlstate(exc) == _SQLSTATE_UNIQUE_VIOLATION


def is_retryable(exc: BaseException) -> bool:
    """True only for deadlock/serialization failures known to have rolled back."""
    return isinstance(exc, (OperationalError, DBAPIError)) and _sqlstate(exc) in {
        _SQLSTATE_DEADLOCK,
        _SQLSTATE_SERIALIZATION,
    }


def is_connection_failure(exc: BaseException) -> bool:
    """True for failures establishing/holding a connection (DB unavailable)."""
    if isinstance(exc, InterfaceError):
        return True
    if isinstance(exc, OperationalError):
        # OperationalError with no SQLSTATE is typically a transport/connect error.
        return _sqlstate(exc) is None
    return False


def classify(exc: BaseException) -> tuple[ReasonCode, bool]:
    """Return ``(reason_code, retryable)`` for a persistence exception."""
    if is_unique_violation(exc):
        return ReasonCode.IDEMPOTENCY_CONFLICT, False
    if is_retryable(exc):
        return ReasonCode.DB_UNAVAILABLE, True
    if is_connection_failure(exc):
        return ReasonCode.DB_UNAVAILABLE, True
    return ReasonCode.INTERNAL_ERROR, False
