"""Stable constants for the orchestration layer.

Every value here is a *contract surface*: the version strings are recorded in
the work ledger and signed into orchestration audit events, and the bounds are
published limits. Changing any of these is a compatibility review item.

The stage/step table is deliberately **data**, not control flow (§14.3): the
pipeline's shape is inspectable, testable and reorderable without touching a
node body.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from gryphon.tooling.constants import ToolId

# -----------------------------------------------------------------------------
# Compatibility versions (recorded / signed)
# -----------------------------------------------------------------------------
#: Graph topology version. Bumped when the node set or edges change. Because no
#: checkpoint is persisted, a bump never invalidates an in-flight scan: a
#: re-invocation simply re-enters the new graph and re-walks covered ledger steps.
GRAPH_VERSION: Final[str] = "1"
#: Closed graph-state schema version.
SCAN_STATE_SCHEMA_VERSION: Final[str] = "1"
#: Work-ledger record schema version (plan / plan_item / raw_finding).
LEDGER_SCHEMA_VERSION: Final[str] = "1"
#: Structured report artifact schema version. Encodes the assurance model.
REPORT_SCHEMA_VERSION: Final[str] = "1"
#: Orchestration audit event schema version (covered by the audit signature).
ORCHESTRATION_AUDIT_EVENT_SCHEMA_VERSION: Final[str] = "1"
#: Lifecycle read-view version (the supported interface for later layers).
READ_VIEW_VERSION: Final[str] = "1"

#: Domain separation label for the execution-identity KDF. Never change without
#: a MAJOR review: it is an input to every derived ``execution_id``.
EXECUTION_ID_KDF_INFO_LABEL: Final[str] = "gryphon/orchestration/execution-id/v1"

# -----------------------------------------------------------------------------
# Bounds (publish + test; reject, never silently truncate)
# -----------------------------------------------------------------------------
#: Execution-identity length in bytes (>= 16 satisfies the 128-bit floor the
#: enforcement layer requires of a caller-supplied id).
EXECUTION_ID_BYTES: Final[int] = 32
#: Per-scan execution salt length. Secret; lives only on the lifecycle row.
EXECUTION_SALT_BYTES: Final[int] = 32
#: Hard ceiling on items in one committed step plan.
MAX_PLAN_ITEMS_PER_STEP: Final[int] = 10_000
#: Hard ceiling on discovered targets admitted into the active stages. Above the
#: configured cap the scan halts for operator review rather than fanning out.
MAX_DISCOVERED_TARGETS: Final[int] = 50_000
#: Maximum raw findings recorded per scan (overflow is a declared coverage note).
MAX_FINDINGS_PER_SCAN: Final[int] = 100_000
#: Maximum serialized graph-state size. The state carries only references and
#: counters, so this is a guard against accidental growth, not a working limit.
MAX_GRAPH_STATE_BYTES: Final[int] = 64 * 1024
#: Monotonic claim epoch starts here; 0 means "never claimed".
FIRST_CLAIM_EPOCH: Final[int] = 1


class ScanStage(str, Enum):
    """Pipeline stages. Ordered; inter-stage progression is strictly sequential."""

    GATE = "gate"
    RECON = "recon"
    TARGET_ADMIT = "target_admit"
    ENUMERATE = "enumerate"
    FINGERPRINT = "fingerprint"
    SCAN = "scan"
    REPORT = "report"

    @property
    def order(self) -> int:
        return _STAGE_ORDER[self]


_STAGE_ORDER: Final[dict[ScanStage, int]] = {
    ScanStage.GATE: 0,
    ScanStage.RECON: 1,
    ScanStage.TARGET_ADMIT: 2,
    ScanStage.ENUMERATE: 3,
    ScanStage.FINGERPRINT: 4,
    ScanStage.SCAN: 5,
    ScanStage.REPORT: 6,
}

#: Stages that may contact a target. Nothing here is reachable before the
#: authorization gate passes and target admission has attested its addresses.
ACTIVE_STAGES: Final[frozenset[ScanStage]] = frozenset(
    {ScanStage.ENUMERATE, ScanStage.FINGERPRINT, ScanStage.SCAN}
)


class TargetSource(str, Enum):
    """Where a step's targets come from. Keeps target flow declarative."""

    #: The single admitted canonical target carried by the permit.
    ADMITTED_TARGET = "admitted_target"
    #: Hostnames discovered by a prior step in this scan.
    DISCOVERED_HOSTS = "discovered_hosts"
    #: Hostnames that passed target admission (attested addresses).
    ADMITTED_HOSTS = "admitted_hosts"
    #: Live HTTP endpoints recorded by the HTTP probe step.
    LIVE_HTTP = "live_http"


@dataclass(frozen=True, slots=True)
class StepSpec:
    """One unit of planned work: a stage, a tool and where its targets come from."""

    stage: ScanStage
    step: str
    tool_id: ToolId
    target_source: TargetSource
    #: Minimum fraction of this step's planned items that must be *covered*
    #: before the pipeline may advance past it. ``0.0`` means "advance on any
    #: outcome"; the declared value is the step's partial-result policy.
    min_coverage_to_proceed: float = 0.0
    #: Maximum targets per enforcement-layer execution. ``1`` keeps one
    #: execution per target, which is the cleanest idempotency unit. Batching is
    #: permitted only where the enforcement layer records per-target contact
    #: state, and is a measured decision per tool.
    max_targets_per_execution: int = 1


# -----------------------------------------------------------------------------
# The step plan (§14.3)
# -----------------------------------------------------------------------------
# Lifted from the master plan's stage/tool assignment, decomposed into dependent
# steps, with ONE deliberate correction:
#
#   The master plan places the HTTP probe (httpx) in ENUMERATE and the port scan
#   (naabu) in FINGERPRINT — i.e. the consumer of port data runs a whole stage
#   BEFORE its producer. This table puts the port scan first, inside ENUMERATE,
#   so the ordering is correct and future-proof.
#
#   Note the honest limit this does NOT fix: the enforcement layer pins the HTTP
#   probe's destination allowlist to its descriptor's required ports (80, 443),
#   so probing a discovered non-standard port additionally requires an optional
#   port argument in that layer. Until then the HTTP probe covers default ports
#   only, and the gap is DECLARED in the report's coverage block (see
#   ``report.py``) rather than left silent. Reordering costs nothing today and
#   removes the need to reorder later.
#
# Passive discovery runs before target admission; nothing active runs before it.
STEP_PLAN: Final[tuple[StepSpec, ...]] = (
    # -- RECON (passive discovery) --------------------------------------------
    StepSpec(
        stage=ScanStage.RECON,
        step="subdomain_discovery",
        tool_id=ToolId.SUBFINDER,
        target_source=TargetSource.ADMITTED_TARGET,
    ),
    StepSpec(
        stage=ScanStage.RECON,
        step="dns_resolution",
        tool_id=ToolId.DNSX,
        target_source=TargetSource.DISCOVERED_HOSTS,
    ),
    # -- ENUMERATE (ports first, then HTTP) -----------------------------------
    StepSpec(
        stage=ScanStage.ENUMERATE,
        step="port_discovery",
        tool_id=ToolId.NAABU,
        target_source=TargetSource.ADMITTED_HOSTS,
    ),
    StepSpec(
        stage=ScanStage.ENUMERATE,
        step="http_probe",
        tool_id=ToolId.HTTPX,
        target_source=TargetSource.ADMITTED_HOSTS,
    ),
    # -- FINGERPRINT ----------------------------------------------------------
    StepSpec(
        stage=ScanStage.FINGERPRINT,
        step="tls_inspection",
        tool_id=ToolId.TLSX,
        target_source=TargetSource.ADMITTED_HOSTS,
    ),
    StepSpec(
        stage=ScanStage.FINGERPRINT,
        step="endpoint_crawl",
        tool_id=ToolId.KATANA,
        target_source=TargetSource.LIVE_HTTP,
    ),
    # -- SCAN -----------------------------------------------------------------
    # "Exposure checks" named in the master plan are template tags of this one
    # tool, not a separate capability (resolved; see docs).
    StepSpec(
        stage=ScanStage.SCAN,
        step="vulnerability_scan",
        tool_id=ToolId.NUCLEI,
        target_source=TargetSource.LIVE_HTTP,
    ),
)

#: Every tool in the catalog is assigned to exactly one step. Asserted by test.
PLANNED_TOOLS: Final[frozenset[ToolId]] = frozenset(spec.tool_id for spec in STEP_PLAN)


class CoverageClass(str, Enum):
    """How one planned item's recorded outcome counts toward coverage (§15).

    A *negative result* is a result: a reachable-but-silent target is COVERED.
    Only an item we could not account for is a GAP.
    """

    #: Executed and accounted for (including a truthful empty result).
    COVERED = "covered"
    #: Planned, attempted, not accounted for. In the denominator only.
    GAP = "gap"
    #: Admission and the enforcement layer disagree. Raises a scan-level failure.
    INTEGRITY = "integrity"
    #: Excluded before planning. NOT in the denominator; reported separately.
    EXCLUDED = "excluded"
    #: Planned but not yet dispatched.
    PENDING = "pending"


class PlanItemState(str, Enum):
    """Persisted plan-item lifecycle. ``PLANNED`` rows are the work queue."""

    PLANNED = "PLANNED"
    DISPATCHED = "DISPATCHED"
    COMPLETED = "COMPLETED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"
    FAILED = "FAILED"
    #: Terminal classification for a permanently indeterminate outcome. Never
    #: retried, never re-contacted, always a declared coverage gap.
    UNRESOLVED_POSSIBLY_CONTACTED = "UNRESOLVED_POSSIBLY_CONTACTED"
    #: Excluded at target admission; carries its exclusion reason.
    EXCLUDED = "EXCLUDED"

    @property
    def is_terminal(self) -> bool:
        return self is not PlanItemState.PLANNED and self is not PlanItemState.DISPATCHED


class ScanLifecycleState(str, Enum):
    """Scan-level lifecycle. Terminal states are terminal (§14.1)."""

    RUNNING = "RUNNING"
    RECONCILING = "RECONCILING"
    #: Every planned item covered.
    COMPLETED = "COMPLETED"
    #: Finished, with enumerated coverage gaps. A truthful, non-clean completion.
    COMPLETED_WITH_GAPS = "COMPLETED_WITH_GAPS"
    #: The gate denied entry. Zero side effects.
    HALTED_UNAUTHORIZED = "HALTED_UNAUTHORIZED"
    #: Discovered-target cap exceeded; awaiting an operator decision.
    HALTED_FOR_REVIEW = "HALTED_FOR_REVIEW"
    FAILED = "FAILED"
    ABORTED_DEADLINE = "ABORTED_DEADLINE"
    ABORTED_AUTHORIZATION_EXPIRED = "ABORTED_AUTHORIZATION_EXPIRED"
    ABORTED_RETRY_BUDGET = "ABORTED_RETRY_BUDGET"
    ABORTED_STATE_BOUND = "ABORTED_STATE_BOUND"
    ABORTED_OPERATOR = "ABORTED_OPERATOR"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_LIFECYCLE_STATES


_TERMINAL_LIFECYCLE_STATES: Final[frozenset[ScanLifecycleState]] = frozenset(
    {
        ScanLifecycleState.COMPLETED,
        ScanLifecycleState.COMPLETED_WITH_GAPS,
        ScanLifecycleState.HALTED_UNAUTHORIZED,
        ScanLifecycleState.FAILED,
        ScanLifecycleState.ABORTED_DEADLINE,
        ScanLifecycleState.ABORTED_AUTHORIZATION_EXPIRED,
        ScanLifecycleState.ABORTED_RETRY_BUDGET,
        ScanLifecycleState.ABORTED_STATE_BOUND,
        ScanLifecycleState.ABORTED_OPERATOR,
    }
)

#: ``HALTED_FOR_REVIEW`` and ``RECONCILING`` are intentionally NOT terminal: an
#: operator decision or a reconciliation pass moves them onward. Both are
#: bounded — review by the operator command boundary, reconciliation by a
#: configured window — so neither is an absorbing state.
NON_TERMINAL_LIFECYCLE_STATES: Final[frozenset[ScanLifecycleState]] = frozenset(
    {
        ScanLifecycleState.RUNNING,
        ScanLifecycleState.RECONCILING,
        ScanLifecycleState.HALTED_FOR_REVIEW,
    }
)


class ClaimResult(str, Enum):
    """Outcome of a fenced execution-start claim."""

    CLAIMED = "CLAIMED"
    TAKEOVER = "TAKEOVER"
    ALREADY_RUNNING = "ALREADY_RUNNING"
    ALREADY_TERMINAL = "ALREADY_TERMINAL"


class ExclusionReason(str, Enum):
    """Why target admission refused a discovered target."""

    #: Resolved to an address outside the attested estate.
    ADDRESS_UNATTESTED = "TARGET_ADDRESS_UNATTESTED"
    #: Did not resolve at all.
    UNRESOLVABLE = "TARGET_UNRESOLVABLE"
    #: Beyond the configured discovered-target cap.
    CAP_EXCEEDED = "TARGET_CAP_EXCEEDED"
    #: Malformed or non-canonicalizable.
    INVALID = "TARGET_INVALID"


class AssuranceStatus(str, Enum):
    """What was and was not performed on a finding.

    This layer produces *evidence*. It never asserts meaning or truth: those are
    later layers, and they attach separate, attributed assertions rather than
    mutating evidence.
    """

    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_PERFORMED = "NOT_PERFORMED"


class OrchestrationEventType(str, Enum):
    """Signed orchestration audit event kinds."""

    GATE = "gate"
    SCAN_START = "scan_start"
    PLAN_COMMITTED = "plan_committed"
    TARGET_ADMISSION = "target_admission"
    LIFECYCLE_TRANSITION = "lifecycle_transition"
    RECONCILIATION = "reconciliation"
    REPORT_EMITTED = "report_emitted"
    OPERATOR_COMMAND = "operator_command"
