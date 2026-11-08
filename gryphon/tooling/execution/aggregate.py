"""Public execution-result types (contract §11.4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gryphon.tooling.constants import TargetContactState, ToolId, ToolOutcome


@dataclass(frozen=True)
class TargetOutcome:
    target: str
    state: TargetContactState


@dataclass(frozen=True)
class ToolExecutionResult:
    """The result returned to a caller for one tool execution.

    Only ``outcome == COMPLETED`` yields authoritative ``records``. A
    DENIED/TIMED_OUT/FAILED/UNKNOWN result carries no records-as-success.
    """

    scan_run_id: str | None
    execution_id: str
    tool_id: ToolId
    outcome: ToolOutcome
    reason_code: str
    records: tuple[Any, ...] = ()
    per_target: tuple[TargetOutcome, ...] = ()
    truncated: bool = False
    degraded: bool = False
    audit_event_id: str | None = None
    replayed: bool = field(default=False)

    @property
    def is_success(self) -> bool:
        return self.outcome is ToolOutcome.COMPLETED

    def record_count(self) -> int:
        return len(self.records)
