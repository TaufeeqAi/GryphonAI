"""Stable constants for the tool execution layer.

Every value here is a contract surface: the version strings are signed into
capabilities and audit events, and the limits are published request/execution
bounds. Changing any of these is a compatibility review item.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

# -----------------------------------------------------------------------------
# Compatibility versions (signed / recorded)
# -----------------------------------------------------------------------------
#: Operation-capability claim schema version (signed into the capability).
CAPABILITY_SCHEMA_VERSION: Final[str] = "1"
#: Tool-invocation audit event schema version (covered by the audit signature).
TOOL_AUDIT_EVENT_SCHEMA_VERSION: Final[str] = "1"
#: Tool-execution aggregate record schema version.
EXECUTION_SCHEMA_VERSION: Final[str] = "1"

SUPPORTED_CAPABILITY_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1"})

# -----------------------------------------------------------------------------
# Request / execution bounds (publish + test; reject, never truncate silently)
# -----------------------------------------------------------------------------
#: A capability travels as an untrusted tool argument; bound it before parsing.
MAX_CAPABILITY_BYTES: Final[int] = 8 * 1024
#: An execution id must carry at least 128 bits of entropy.
MIN_EXECUTION_ID_BYTES: Final[int] = 16
MAX_EXECUTION_ID_BYTES: Final[int] = 128
#: Prefer one target per execution; a batch is capped (per-target recorded).
MAX_TARGETS_PER_EXECUTION: Final[int] = 64
#: Captured subprocess stdout is bounded; overflow sets ``truncated=true``.
DEFAULT_MAX_STDOUT_BYTES: Final[int] = 16 * 1024 * 1024
#: Parse-failure fraction above which an outcome is flagged ``degraded``.
PARSE_DRIFT_FAILURE_THRESHOLD: Final[float] = 0.20
#: Maximum structured records retained from one tool execution (overflow caps).
MAX_RESULT_RECORDS: Final[int] = 5000
#: Hard ceiling on capability lifetime regardless of configuration.
MAX_CAPABILITY_TTL_SECONDS: Final[int] = 900

#: JOSE-style algorithm pin for capability signatures (asymmetric only).
CAPABILITY_ALGORITHM: Final[str] = "Ed25519"


class ToolId(str, Enum):
    """The closed, enumerable tool catalog. Adding a member is a MINOR change."""

    SUBFINDER = "subfinder"
    HTTPX = "httpx"
    NAABU = "naabu"
    KATANA = "katana"
    DNSX = "dnsx"
    TLSX = "tlsx"
    NUCLEI = "nuclei"


class ToolOutcome(str, Enum):
    """Per-execution outcome. Only COMPLETED yields authoritative records."""

    COMPLETED = "COMPLETED"
    TIMED_OUT = "TIMED_OUT"
    FAILED = "FAILED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"

    @property
    def is_success(self) -> bool:
        return self is ToolOutcome.COMPLETED


class ExecutionState(str, Enum):
    """Persisted Execution-aggregate state machine.

    ``ADMITTED`` means the intent record committed and traffic is permitted from
    that point; it is reached only after every pre-flight check passes.
    """

    ADMITTED = "ADMITTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    TIMED_OUT = "TIMED_OUT"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    DENIED = "DENIED"


class TargetContactState(str, Enum):
    """Per-target contact record for batch executions (faithful partial state)."""

    CONTACTED = "contacted"
    NOT_CONTACTED = "not_contacted"


class CredentialSource(str, Enum):
    """How authority entered the gateway (CHG-009 conditional capability)."""

    CAPABILITY = "capability"  # cross-process, verified operation capability
    PERMIT = "permit"          # in-process AuthorizedPermit, no serialized token


#: The OS egress enforcement posture.
class EgressMode(str, Enum):
    ENFORCED = "enforced"      # an OS egress context MUST be established or deny
    UNENFORCED = "unenforced"  # single-tenant/dev only; never permitted in prod
