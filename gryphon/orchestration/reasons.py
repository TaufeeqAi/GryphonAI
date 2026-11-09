"""Stable reason codes and typed errors for the orchestration layer.

Reason codes are a published contract surface: they appear in the work ledger,
in signed audit events and in the report. New codes are additive; a value is
never repurposed.
"""

from __future__ import annotations

from enum import Enum


class OrchestrationReasonCode(str, Enum):
    """Stable, additive reason codes."""

    # -- success / progress ---------------------------------------------------
    OK = "OK"
    PLAN_COMMITTED = "PLAN_COMMITTED"

    # -- authorization (the gate and the per-call precondition) ---------------
    NO_ADMISSION = "NO_ADMISSION"
    ADMISSION_NOT_AUTHORIZED = "ADMISSION_NOT_AUTHORIZED"
    ADMISSION_EXPIRED = "ADMISSION_EXPIRED"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    KID_UNTRUSTED = "KID_UNTRUSTED"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"
    #: ``now + tool.hard_deadline`` would cross the grant's expiry.
    AUTHORIZATION_WINDOW_EXCEEDED = "AUTHORIZATION_WINDOW_EXCEEDED"

    # -- claim / concurrency --------------------------------------------------
    ALREADY_RUNNING = "ALREADY_RUNNING"
    ALREADY_TERMINAL = "ALREADY_TERMINAL"
    STALE_CLAIM_EPOCH = "STALE_CLAIM_EPOCH"

    # -- target admission -----------------------------------------------------
    TARGET_ADDRESS_UNATTESTED = "TARGET_ADDRESS_UNATTESTED"
    TARGET_UNRESOLVABLE = "TARGET_UNRESOLVABLE"
    TARGET_CAP_EXCEEDED = "TARGET_CAP_EXCEEDED"
    TARGET_INVALID = "TARGET_INVALID"

    # -- budgets / deadlines --------------------------------------------------
    SCAN_DEADLINE_EXCEEDED = "SCAN_DEADLINE_EXCEEDED"
    RETRY_BUDGET_EXHAUSTED = "RETRY_BUDGET_EXHAUSTED"
    DECISION_BUDGET_EXHAUSTED = "DECISION_BUDGET_EXHAUSTED"
    BREAKER_COOLDOWN = "BREAKER_COOLDOWN"
    STATE_BOUND_EXCEEDED = "STATE_BOUND_EXCEEDED"

    # -- uncertainty / reconciliation -----------------------------------------
    #: Something is still indeterminate: reconciliation has work to do.
    RECONCILE_REQUIRED = "RECONCILE_REQUIRED"
    UNRESOLVED_POSSIBLY_CONTACTED = "UNRESOLVED_POSSIBLY_CONTACTED"

    # -- coverage (settled gaps: there is nothing left to reconcile) ----------
    #: Every gap is already settled and coverage is under the failure floor.
    COVERAGE_BELOW_FLOOR = "COVERAGE_BELOW_FLOOR"
    #: Every gap is already settled and coverage is above the failure floor.
    COVERAGE_INCOMPLETE = "COVERAGE_INCOMPLETE"

    # -- integrity ------------------------------------------------------------
    #: A finding with no corroborating enforcement-layer execution record.
    FINDING_UNCORROBORATED = "FINDING_UNCORROBORATED"
    #: The enforcement layer denied an admitted target on scope grounds.
    SCOPE_DISAGREEMENT = "SCOPE_DISAGREEMENT"
    SCAN_INTEGRITY_FAILURE = "SCAN_INTEGRITY_FAILURE"

    # -- operational ----------------------------------------------------------
    DB_UNAVAILABLE = "DB_UNAVAILABLE"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    OPERATOR_ABORT = "OPERATOR_ABORT"
    CALLER_UNAUTHORIZED = "CALLER_UNAUTHORIZED"
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"


class OrchestrationError(Exception):
    """Base class for orchestration-layer failures."""


class OrchestrationConfigurationError(OrchestrationError):
    """Fail-closed configuration error raised at startup, never at scan time."""


class StateSchemaViolation(OrchestrationError):
    """The graph-state schema declares a field that could carry authority.

    Raised at import time so a non-conforming schema fails the build rather than
    a scan.
    """


class AuthorizationPreconditionFailed(OrchestrationError):
    """A protected call was refused before any enforcement-layer invocation."""

    def __init__(self, reason_code: OrchestrationReasonCode, detail: str = "") -> None:
        super().__init__(f"{reason_code.value}{f': {detail}' if detail else ''}")
        self.reason_code = reason_code
        self.detail = detail


class StaleClaimError(OrchestrationError):
    """A fenced write was attempted with a superseded claim epoch."""

    def __init__(self, scan_run_id: str, presented: int, current: int) -> None:
        super().__init__(
            f"stale claim epoch for {scan_run_id}: presented {presented}, current {current}"
        )
        self.scan_run_id = scan_run_id
        self.presented = presented
        self.current = current
