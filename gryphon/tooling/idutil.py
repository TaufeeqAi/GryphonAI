"""Small shared id helpers for the tool execution layer."""

from __future__ import annotations

from gryphon.tooling.constants import MAX_EXECUTION_ID_BYTES, MIN_EXECUTION_ID_BYTES
from gryphon.tooling.reasons import EnforcementDenied, ToolReasonCode


def validate_execution_id(execution_id: str) -> None:
    """Enforce execution-id bounds (≥128 bits of carryable entropy).

    True entropy is the caller's responsibility; this enforces a length floor
    and ceiling and rejects a single repeated character.
    """
    if not isinstance(execution_id, str) or not execution_id:
        raise EnforcementDenied(ToolReasonCode.EXECUTION_ID_INVALID, "missing execution id")
    raw = execution_id.encode("utf-8")
    if len(raw) < MIN_EXECUTION_ID_BYTES:
        raise EnforcementDenied(ToolReasonCode.EXECUTION_ID_INVALID, "execution id too short")
    if len(raw) > MAX_EXECUTION_ID_BYTES:
        raise EnforcementDenied(ToolReasonCode.EXECUTION_ID_INVALID, "execution id too long")
    if len(set(execution_id)) <= 1:
        raise EnforcementDenied(ToolReasonCode.EXECUTION_ID_INVALID, "execution id lacks entropy")
