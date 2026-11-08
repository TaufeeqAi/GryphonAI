"""Stable reason codes and typed domain errors.

Reason codes are a *public, stable* contract surface (§15, §21.2, §24.1). They
are safe to persist in ``scan_runs.reason_code`` and audit rows and to return to
callers. Detailed exception strings are operational diagnostics only and MUST
NOT leak crypto/parser internals or secrets to the public result.
"""

from __future__ import annotations

from enum import Enum


class ReasonCode(str, Enum):
    """Stable denial / outcome codes.

    Values are frozen identifiers; never repurpose one. New conditions get new
    codes. Grouped by the stage that produces them.
    """

    # ---- Allow -------------------------------------------------------------
    ADMITTED = "ADMITTED"

    # ---- Request / input validation (§9.2.2, §21.1) ------------------------
    REQUEST_MALFORMED = "REQUEST_MALFORMED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    IDEMPOTENCY_KEY_INVALID = "IDEMPOTENCY_KEY_INVALID"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"

    # ---- Token / JWS envelope (§9.2.4-6, BND-02) ---------------------------
    TOKEN_MISSING = "TOKEN_MISSING"
    TOKEN_TOO_LARGE = "TOKEN_TOO_LARGE"
    TOKEN_MALFORMED = "TOKEN_MALFORMED"
    TOKEN_DUPLICATE_CLAIM = "TOKEN_DUPLICATE_CLAIM"
    TOKEN_HEADER_INVALID = "TOKEN_HEADER_INVALID"
    TOKEN_ALGORITHM_UNSUPPORTED = "TOKEN_ALGORITHM_UNSUPPORTED"
    TOKEN_KID_UNKNOWN = "TOKEN_KID_UNKNOWN"
    TOKEN_SIGNATURE_INVALID = "TOKEN_SIGNATURE_INVALID"

    # ---- Claim validation (§11.1-2) ----------------------------------------
    CLAIMS_INVALID = "CLAIMS_INVALID"
    CLAIMS_SCHEMA_UNSUPPORTED = "CLAIMS_SCHEMA_UNSUPPORTED"
    SCOPE_POLICY_UNSUPPORTED = "SCOPE_POLICY_UNSUPPORTED"
    ISSUER_UNTRUSTED = "ISSUER_UNTRUSTED"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"
    TOKEN_NOT_YET_VALID = "TOKEN_NOT_YET_VALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    GRANT_LIFETIME_INVALID = "GRANT_LIFETIME_INVALID"

    # ---- Issuance receipt (§11.2, BND-04) ----------------------------------
    RECEIPT_MISSING = "RECEIPT_MISSING"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"

    # ---- Scope evaluation (§11.3, BND-03) ----------------------------------
    SCOPE_NO_MATCH = "SCOPE_NO_MATCH"
    SCOPE_EXCLUDED = "SCOPE_EXCLUDED"
    SCOPE_INVALID_INPUT = "SCOPE_INVALID_INPUT"

    # ---- Scan depth (§11.6) -------------------------------------------------
    DEPTH_INVALID = "DEPTH_INVALID"

    # ---- Persistence / audit / unknown (§15) -------------------------------
    DB_UNAVAILABLE = "DB_UNAVAILABLE"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    SCHEMA_NOT_READY = "SCHEMA_NOT_READY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# -----------------------------------------------------------------------------
# Exception hierarchy
# -----------------------------------------------------------------------------
class GryphonError(Exception):
    """Base class for all GRYPHON domain errors."""


class ConfigurationError(GryphonError):
    """Invalid or missing security-critical configuration (SEC-004)."""


class KeyConfigurationError(ConfigurationError):
    """Signing/verification key material is missing, malformed, or non-distinct."""


class ReadinessError(GryphonError):
    """Service is not ready to admit requests (schema/key/privilege invalid)."""


class ValidationError(GryphonError):
    """A bounded input failed strict validation.

    Carries a stable :class:`ReasonCode`. The message is a diagnostic detail and
    is never the public contract; callers key off ``reason_code``.
    """

    def __init__(self, reason_code: ReasonCode, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail}" if detail else reason_code.value)


class TokenVerificationError(ValidationError):
    """Grant token failed authenticity or claim validation (BND-02)."""


class ScopeEvaluationError(ValidationError):
    """Target/path could not be canonicalized or evaluated (BND-03)."""


class PersistenceError(GryphonError):
    """A classified persistence failure (BND-07)."""

    def __init__(self, reason_code: ReasonCode, detail: str = "", *, retryable: bool = False) -> None:
        self.reason_code = reason_code
        self.detail = detail
        self.retryable = retryable
        super().__init__(f"{reason_code.value}: {detail}" if detail else reason_code.value)


class IdempotencyConflictError(PersistenceError):
    """Same idempotency key presented with a different request hash (§17)."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(ReasonCode.IDEMPOTENCY_CONFLICT, detail, retryable=False)


class CommitOutcomeUnknownError(PersistenceError):
    """Commit result could not be established; NEVER treated as success (§15)."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(ReasonCode.COMMIT_OUTCOME_UNKNOWN, detail, retryable=False)
