"""Scan orchestration — composing enforced tool calls into one authorized scan.

This layer answers a single question: *how do many individually-enforced tool
calls compose one scan, with lifecycle, ordering, resume, recovery and
coverage?* It decides nothing about authorization (the authorization core owns
that) and enforces nothing about tool execution (the tool-execution layer owns
that). It sequences, accounts, and tells the truth about what happened.

Five ideas carry the design:

1. **Gate always.** The graph is compiled without persistence, so every
   invocation — including a resume or a takeover — re-enters at the
   authorization gate, and the authority touchpoint re-checks liveness and the
   authorization window before every protected call.
2. **One authority.** A durable work ledger is the only source of truth this
   layer owns. The authorization core owns "is this authorized"; the
   enforcement layer owns "was this target contacted". No cache can diverge
   from any of them, because there is no cache.
3. **Hold, never store.** The permit is reached only through the touchpoint,
   lives in a local variable for the duration of one call, and cannot enter
   graph state: the state schema is closed to primitives and validated at
   import.
4. **Stored identity.** Each call's execution identity is derived once, with a
   keyed KDF over the full canonical request, and persisted. A re-executed step
   re-reads it, so crash-resume and replay return recorded outcomes instead of
   scanning again.
5. **Covered means done.** Coverage is computed and persisted, and the terminal
   state is a function of it. Reaching the end of the graph is not completion;
   accounting for the planned work is.

Public surface: build the services, then invoke by scan id.

    services = build_orchestration_services()
    outcome = await services.orchestrator.invoke(scan_run_id, initiated_by="cli")
"""

from __future__ import annotations

from gryphon.orchestration.bootstrap import (
    OrchestrationServices,
    build_orchestration_services,
)
from gryphon.orchestration.commands import (
    CallerIdentity,
    CallerRejected,
    Command,
    OperatorCommands,
    ScanStatus,
)
from gryphon.orchestration.constants import (
    GRAPH_VERSION,
    REPORT_SCHEMA_VERSION,
    STEP_PLAN,
    CoverageClass,
    PlanItemState,
    ScanLifecycleState,
    ScanStage,
)
from gryphon.orchestration.coverage import ScanCoverage, StepCoverage
from gryphon.orchestration.orchestrator import ScanOrchestrator, ScanOutcome
from gryphon.orchestration.readiness import (
    ReadinessReport,
    check_orchestration_readiness,
)
from gryphon.orchestration.reasons import (
    OrchestrationConfigurationError,
    OrchestrationError,
    OrchestrationReasonCode,
)
from gryphon.orchestration.settings import OrchestrationSettings
from gryphon.orchestration.sweeper import RecoverySweeper

__all__ = [
    # composition
    "build_orchestration_services",
    "OrchestrationServices",
    "OrchestrationSettings",
    # the scan
    "ScanOrchestrator",
    "ScanOutcome",
    "RecoverySweeper",
    # operator surface
    "OperatorCommands",
    "Command",
    "CallerIdentity",
    "CallerRejected",
    "ScanStatus",
    # contract surfaces
    "ScanStage",
    "ScanLifecycleState",
    "PlanItemState",
    "CoverageClass",
    "ScanCoverage",
    "StepCoverage",
    "STEP_PLAN",
    "GRAPH_VERSION",
    "REPORT_SCHEMA_VERSION",
    # errors
    "OrchestrationError",
    "OrchestrationConfigurationError",
    "OrchestrationReasonCode",
    # readiness
    "check_orchestration_readiness",
    "ReadinessReport",
]
