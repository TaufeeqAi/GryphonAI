"""Append-only tool-invocation audit repository."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.db.models.tool_invocation_audit import ToolInvocationAudit


class ToolInvocationAuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        event_schema_version: str,
        scan_run_id: str,
        execution_id: str,
        tool_id: str,
        payload: dict,
        payload_digest: str,
        signer_kid: str,
        signature: str,
        capability_id: str | None = None,
        decision: str | None = None,
        reason_code: str | None = None,
        outcome: str | None = None,
        canonical_target: str | None = None,
        pinned_destinations_summary: str | None = None,
        external_disclosure: bool = False,
        descriptor_version: str | None = None,
    ) -> ToolInvocationAudit:
        row = ToolInvocationAudit(
            event_id=event_id,
            event_type=event_type,
            event_schema_version=event_schema_version,
            scan_run_id=scan_run_id,
            execution_id=execution_id,
            tool_id=tool_id,
            capability_id=capability_id,
            decision=decision,
            reason_code=reason_code,
            outcome=outcome,
            canonical_target=canonical_target,
            pinned_destinations_summary=pinned_destinations_summary,
            external_disclosure=external_disclosure,
            descriptor_version=descriptor_version,
            payload=payload,
            payload_digest=payload_digest,
            signer_kid=signer_kid,
            signature=signature,
        )
        self._session.add(row)
        return row
