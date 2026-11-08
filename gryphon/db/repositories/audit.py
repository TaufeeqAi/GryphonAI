"""Append-only audit repository (BND-06).

Append + read only. UPDATE/DELETE/TRUNCATE are denied to the runtime role at the
database (privileges + trigger, §22.3); this repository never issues them.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.auth.audit_signer import SignedAuditEvent
from gryphon.constants import DecisionStatus
from gryphon.db.models.audit_log import AuthorizationAuditLog
from gryphon.errors import ReasonCode


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_scan_run_id(self, scan_run_id: str) -> AuthorizationAuditLog | None:
        stmt = select(AuthorizationAuditLog).where(
            AuthorizationAuditLog.scan_run_id == scan_run_id
        )
        return (await self._session.execute(stmt)).scalars().first()

    async def get_by_event_id(self, event_id: str) -> AuthorizationAuditLog | None:
        stmt = select(AuthorizationAuditLog).where(
            AuthorizationAuditLog.event_id == event_id
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    def append_admission(
        self,
        event: SignedAuditEvent,
        *,
        decision: DecisionStatus,
        reason_code: ReasonCode,
        authorization_valid: bool,
        scope_check_passed: bool,
        target_requested: str | None,
        canonical_target: str | None,
        path_requested: str | None,
        grant_id: str | None,
        requested_by: str | None,
        organization: str | None,
        scope_policy_version: str | None,
    ) -> AuthorizationAuditLog:
        """Stage a signed scan-admission audit event for insertion (no commit)."""
        row = AuthorizationAuditLog(
            event_id=event.event_id,
            event_type=event.event_type.value,
            event_schema_version=event.payload["event_schema_version"],
            scan_run_id=event.scan_run_id,
            grant_id=grant_id,
            target_requested=target_requested,
            canonical_target=canonical_target,
            path_requested=path_requested,
            authorization_valid=authorization_valid,
            scope_check_passed=scope_check_passed,
            decision=decision.value,
            reason_code=reason_code.value,
            requested_by=requested_by,
            organization=organization,
            scope_policy_version=scope_policy_version,
            payload=event.payload,
            payload_digest=event.payload_digest,
            signer_kid=event.signer_kid,
            signature=event.signature_b64,
        )
        self._session.add(row)
        return row

    def append_issuance(
        self,
        event: SignedAuditEvent,
        *,
        grant_id: str,
        organization: str,
        granted_by: str,
    ) -> AuthorizationAuditLog:
        """Stage a signed grant-issuance audit event for insertion (no commit)."""
        row = AuthorizationAuditLog(
            event_id=event.event_id,
            event_type=event.event_type.value,
            event_schema_version=event.payload["event_schema_version"],
            scan_run_id=None,
            grant_id=grant_id,
            target_requested=None,
            canonical_target=None,
            path_requested=None,
            authorization_valid=True,
            scope_check_passed=False,
            decision=None,
            reason_code=None,
            requested_by=granted_by,
            organization=organization,
            scope_policy_version=event.payload.get("scope_policy_version"),
            payload=event.payload,
            payload_digest=event.payload_digest,
            signer_kid=event.signer_kid,
            signature=event.signature_b64,
        )
        self._session.add(row)
        return row
