"""Stable reason codes and typed errors for the tool execution layer.

Reason codes are a public, stable contract surface: they are safe to persist in
audit rows and return to callers. Detailed exception strings are operational
diagnostics only and never leak crypto/parser internals or secrets.
"""

from __future__ import annotations

from enum import Enum


class ToolReasonCode(str, Enum):
    """Stable ALLOW / DENY / outcome codes. Never repurpose a value."""

    # ---- Allow -------------------------------------------------------------
    ADMITTED = "ADMITTED"

    # ---- Pre-authorization input (bounded, cheap) --------------------------
    REQUEST_MALFORMED = "REQUEST_MALFORMED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    EXECUTION_ID_INVALID = "EXECUTION_ID_INVALID"
    ARGS_INVALID = "ARGS_INVALID"
    TOOL_UNKNOWN = "TOOL_UNKNOWN"

    # ---- Capability (cross-process) ----------------------------------------
    CAPABILITY_MISSING = "CAPABILITY_MISSING"
    CAPABILITY_TOO_LARGE = "CAPABILITY_TOO_LARGE"
    CAPABILITY_MALFORMED = "CAPABILITY_MALFORMED"
    CAPABILITY_SCHEMA_UNSUPPORTED = "CAPABILITY_SCHEMA_UNSUPPORTED"
    CAPABILITY_ALGORITHM_UNSUPPORTED = "CAPABILITY_ALGORITHM_UNSUPPORTED"
    CAPABILITY_KID_UNKNOWN = "CAPABILITY_KID_UNKNOWN"
    CAPABILITY_SIGNATURE_INVALID = "CAPABILITY_SIGNATURE_INVALID"
    CAPABILITY_EXPIRED = "CAPABILITY_EXPIRED"
    CAPABILITY_NOT_YET_VALID = "CAPABILITY_NOT_YET_VALID"
    CAPABILITY_TOOL_MISMATCH = "CAPABILITY_TOOL_MISMATCH"
    CAPABILITY_REPLAYED = "CAPABILITY_REPLAYED"

    # ---- Scope provenance (grant-rooted) -----------------------------------
    RECEIPT_MISSING = "RECEIPT_MISSING"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"
    SCOPE_PROVENANCE_MISMATCH = "SCOPE_PROVENANCE_MISMATCH"

    # ---- Scope / depth / policy --------------------------------------------
    SCOPE_NO_MATCH = "SCOPE_NO_MATCH"
    SCOPE_EXCLUDED = "SCOPE_EXCLUDED"
    SCOPE_INVALID_INPUT = "SCOPE_INVALID_INPUT"
    DEPTH_EXCEEDED = "DEPTH_EXCEEDED"
    DEPTH_INVALID = "DEPTH_INVALID"
    TAG_PROHIBITED = "TAG_PROHIBITED"
    PROTOCOL_PROHIBITED = "PROTOCOL_PROHIBITED"
    DESCRIPTOR_MISSING = "DESCRIPTOR_MISSING"

    # ---- Budgets / breaker -------------------------------------------------
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    BREAKER_OPEN = "BREAKER_OPEN"

    # ---- Destination / egress ----------------------------------------------
    DESTINATION_DENIED = "DESTINATION_DENIED"
    DESTINATION_UNRESOLVABLE = "DESTINATION_UNRESOLVABLE"
    REDIRECT_ESCAPE = "REDIRECT_ESCAPE"
    EGRESS_UNAVAILABLE = "EGRESS_UNAVAILABLE"

    # ---- Persistence / execution lifecycle ---------------------------------
    INTENT_COMMIT_FAILED = "INTENT_COMMIT_FAILED"
    DB_UNAVAILABLE = "DB_UNAVAILABLE"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    READINESS_FAILED = "READINESS_FAILED"

    # ---- Execution outcomes (non-DENY) -------------------------------------
    COMPLETED = "COMPLETED"
    TOOL_TIMED_OUT = "TOOL_TIMED_OUT"
    TOOL_FAILED = "TOOL_FAILED"
    OUTPUT_DEGRADED = "OUTPUT_DEGRADED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# -----------------------------------------------------------------------------
# Exception hierarchy
# -----------------------------------------------------------------------------
class ToolingError(Exception):
    """Base class for tool-execution-layer errors."""


class ToolingConfigurationError(ToolingError):
    """Invalid or missing security-critical configuration (fails closed)."""


class CapabilityError(ToolingError):
    """A capability failed verification. Carries a stable reason code."""

    def __init__(self, reason_code: ToolReasonCode, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail}" if detail else reason_code.value)


class EnforcementDenied(ToolingError):
    """A tool call was denied by the enforcement gateway."""

    def __init__(self, reason_code: ToolReasonCode, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail}" if detail else reason_code.value)


class EgressUnavailableError(ToolingError):
    """An OS egress context could not be established; execution must not run."""

    def __init__(self, detail: str = "") -> None:
        self.reason_code = ToolReasonCode.EGRESS_UNAVAILABLE
        self.detail = detail
        super().__init__(f"EGRESS_UNAVAILABLE: {detail}" if detail else "EGRESS_UNAVAILABLE")


class DestinationDeniedError(ToolingError):
    """A destination resolved outside the authorized/safe set."""

    def __init__(self, reason_code: ToolReasonCode, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail}" if detail else reason_code.value)


class ProvisioningError(ToolingError):
    """A pinned binary / template / descriptor failed verification."""
