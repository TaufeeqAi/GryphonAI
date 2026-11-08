"""Immutable grant issuance repository (BND-04)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.db.models.authorization import AuthorizationGrant


class GrantRepository:
    """Persist and retrieve immutable issuance receipts."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_grant_id(self, grant_id: str) -> AuthorizationGrant | None:
        return await self._session.get(AuthorizationGrant, grant_id)

    async def get_by_issuance_hash(self, issuance_hash: str) -> AuthorizationGrant | None:
        stmt = select(AuthorizationGrant).where(
            AuthorizationGrant.issuance_idempotency_hash == issuance_hash
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    def add(
        self,
        *,
        grant_id: str,
        jti: str,
        issuer: str,
        issuer_kid: str,
        granted_by: str,
        granted_to: str,
        organization: str,
        scope: list[dict],
        scope_digest: str,
        claims_digest: str,
        scope_policy_version: str,
        schema_version: str,
        issued_at: datetime,
        not_before: datetime,
        expires_at: datetime,
        max_scan_depth: str,
        written_authorization_ref: str,
        issuance_idempotency_hash: str,
        request_hash: str,
    ) -> AuthorizationGrant:
        """Stage an immutable receipt for insertion (no commit)."""
        row = AuthorizationGrant(
            grant_id=grant_id,
            jti=jti,
            issuer=issuer,
            issuer_kid=issuer_kid,
            granted_by=granted_by,
            granted_to=granted_to,
            organization=organization,
            scope=scope,
            scope_digest=scope_digest,
            claims_digest=claims_digest,
            scope_policy_version=scope_policy_version,
            schema_version=schema_version,
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            max_scan_depth=max_scan_depth,
            written_authorization_ref=written_authorization_ref,
            issuance_idempotency_hash=issuance_idempotency_hash,
            request_hash=request_hash,
        )
        self._session.add(row)
        return row
