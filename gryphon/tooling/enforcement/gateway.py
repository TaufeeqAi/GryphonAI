"""Enforcement gateway facade.

The per-call decision (verify → re-derive scope → scope/depth/descriptor policy →
budgets) and the execution saga are implemented together in
:class:`~gryphon.tooling.enforcement.service.ToolExecutionService` because they
share one transactional pipeline. This module re-exports it as the public,
transport-agnostic entry point; no transport type is imported here.
"""

from __future__ import annotations

from gryphon.tooling.enforcement.service import BinaryResolver, ToolExecutionService

__all__ = ["ToolExecutionService", "BinaryResolver"]
