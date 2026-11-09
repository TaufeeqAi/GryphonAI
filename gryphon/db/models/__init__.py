"""ORM models (§22.1).

Importing this package registers every table on ``Base.metadata`` so Alembic and
readiness checks can see the full schema. ``exploit_chain`` is intentionally a
behaviour-free placeholder: it defines NO table (§22.1, §34).
"""

from __future__ import annotations

from gryphon.db.models.audit_log import AuthorizationAuditLog
from gryphon.db.models.authorization import AuthorizationGrant
from gryphon.db.models.capability_consumption import CapabilityConsumption
from gryphon.db.models.finding import Finding
from gryphon.db.models.raw_finding import RawFinding
from gryphon.db.models.scan_lifecycle import ScanLifecycle
from gryphon.db.models.scan_plan import AdmittedScanTarget, PlanItem, ScanPlan
from gryphon.db.models.scan_report import OrchestrationAudit, ScanReport
from gryphon.db.models.scan_run import ScanRun
from gryphon.db.models.tool_execution import ToolExecution
from gryphon.db.models.tool_invocation_audit import ToolInvocationAudit

__all__ = [
    "AuthorizationGrant",
    "ScanRun",
    "Finding",
    "AuthorizationAuditLog",
    # Tool execution layer (sibling tables; authorization schema untouched).
    "ToolExecution",
    "CapabilityConsumption",
    "ToolInvocationAudit",
    # Orchestration layer (sibling tables; upstream schemas untouched).
    "ScanLifecycle",
    "ScanPlan",
    "PlanItem",
    "AdmittedScanTarget",
    "RawFinding",
    "ScanReport",
    "OrchestrationAudit",
]
