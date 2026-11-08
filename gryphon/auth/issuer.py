"""Local controlled grant issuance (BND-01).

Issuance is available only through a locally-controlled operator path; the
operator verifies written authority OUT OF BAND (§20.1). The signed token and
its immutable receipt + issuance audit event commit atomically before the token
is returned (§14.1). Response-loss recovery reissues the SAME deterministic JWS
from the stored receipt rather than creating a second grant (§17.2 / §23.2).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from gryphon.auth.audit_signer import AuditSigner
from gryphon.auth.authorization_token import GrantSigner
from gryphon.auth.claims import GrantClaims, IssuanceRequest
from gryphon.auth.idempotency import (
    hash_idempotency_key,
    issuance_request_hash,
    validate_idempotency_key,
)
from gryphon.auth.scope import ScopeEntry, scope_digest
from gryphon.clock import Clock
from gryphon.constants import CLAIMS_SCHEMA_VERSION, SCOPE_POLICY_VERSION, ScanDepth
from gryphon.db.errors import is_unique_violation
from gryphon.db.models.authorization import AuthorizationGrant
from gryphon.db.repositories.audit import AuditRepository
from gryphon.db.repositories.grants import GrantRepository
from gryphon.db.session import Database
from gryphon.errors import ConfigurationError, IdempotencyConflictError
from gryphon.logging_config import get_logger
from gryphon.settings import Settings

logger = get_logger(__name__)


@dataclass(frozen=True)
class IssuedGrant:
    """Result of a successful issuance."""

    grant_id: str
    jti: str
    token: str
    claims_digest: str
    issuer_kid: str
    expires_at: datetime


def _floor_seconds(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(microsecond=0)


class GrantIssuer:
    def __init__(
        self,
        *,
        signer: GrantSigner,
        audit_signer: AuditSigner,
        database: Database,
        settings: Settings,
        clock: Clock,
    ) -> None:
        self._signer = signer
        self._audit = audit_signer
        self._db = database
        self._settings = settings
        self._clock = clock

    async def issue_grant(self, request: IssuanceRequest, idempotency_key: str) -> IssuedGrant:
        """Issue (or deterministically reissue) a signed grant."""
        validate_idempotency_key(idempotency_key)
        key_hash = hash_idempotency_key(idempotency_key)
        req_hash = issuance_request_hash(self._request_identity(request))

        try:
            async with self._db.session() as session:
                async with session.begin():
                    grants = GrantRepository(session)
                    existing = await grants.get_by_issuance_hash(key_hash)
                    if existing is not None:
                        if existing.request_hash != req_hash:
                            raise IdempotencyConflictError(
                                "issuance key reused with different request"
                            )
                        return self._reissue(existing)

                    claims = self._build_claims(request)
                    token = self._signer.sign(claims)
                    claims_digest = self._signer.claims_digest(claims)
                    sdigest = scope_digest(claims.scope)

                    grants.add(
                        grant_id=claims.grant_id,
                        jti=claims.jti,
                        issuer=claims.iss,
                        issuer_kid=self._signer.kid,
                        granted_by=claims.granted_by,
                        granted_to=claims.granted_to,
                        organization=claims.organization,
                        scope=[e.canonical_dict() for e in claims.scope],
                        scope_digest=sdigest,
                        claims_digest=claims_digest,
                        scope_policy_version=claims.scope_policy_version,
                        schema_version=claims.schema_version,
                        issued_at=claims.iat,
                        not_before=claims.nbf,
                        expires_at=claims.exp,
                        max_scan_depth=claims.max_scan_depth.value,
                        written_authorization_ref=claims.written_authorization_ref,
                        issuance_idempotency_hash=key_hash,
                        request_hash=req_hash,
                    )
                    audit_event = self._audit.sign_grant_issuance(
                        grant_id=claims.grant_id,
                        jti=claims.jti,
                        issuer_kid=self._signer.kid,
                        organization=claims.organization,
                        granted_by=claims.granted_by,
                        granted_to=claims.granted_to,
                        claims_digest=claims_digest,
                        scope_digest=sdigest,
                        scope_policy_version=claims.scope_policy_version,
                        timestamp=self._clock.now(),
                    )
                    AuditRepository(session).append_issuance(
                        audit_event,
                        grant_id=claims.grant_id,
                        organization=claims.organization,
                        granted_by=claims.granted_by,
                    )
                    logger.info(
                        "grant_issued",
                        grant_id=claims.grant_id,
                        issuer_kid=self._signer.kid,
                        audit_event_id=audit_event.event_id,
                    )
                    return IssuedGrant(
                        grant_id=claims.grant_id,
                        jti=claims.jti,
                        token=token,
                        claims_digest=claims_digest,
                        issuer_kid=self._signer.kid,
                        expires_at=claims.exp,
                    )
        except IntegrityError as exc:
            if not is_unique_violation(exc):
                raise
            # Concurrent duplicate committed first; reconcile by issuance hash.
            async with self._db.session() as session:
                existing = await GrantRepository(session).get_by_issuance_hash(key_hash)
            if existing is not None and existing.request_hash == req_hash:
                return self._reissue(existing)
            raise IdempotencyConflictError("concurrent issuance with different request") from exc

    # -- internals -----------------------------------------------------------
    def _request_identity(self, request: IssuanceRequest) -> dict:
        """Canonical, semantic request identity (defines 'same request')."""
        nbf = request.not_before or request.issued_at
        return {
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "organization": request.organization,
            "granted_by": request.granted_by,
            "granted_to": request.granted_to,
            "scope": [e.canonical_dict() for e in request.scope],
            "issued_at": int(_floor_seconds(request.issued_at).timestamp()),
            "not_before": int(_floor_seconds(nbf).timestamp()),
            "expires_at": int(_floor_seconds(request.expires_at).timestamp()),
            "max_scan_depth": request.max_scan_depth.value,
            "written_authorization_ref": request.written_authorization_ref,
            "schema_version": CLAIMS_SCHEMA_VERSION,
            "scope_policy_version": SCOPE_POLICY_VERSION,
        }

    def _build_claims(self, request: IssuanceRequest) -> GrantClaims:
        nbf = request.not_before or request.issued_at
        return GrantClaims(
            iss=self._settings.issuer,
            aud=self._settings.audience,
            iat=_floor_seconds(request.issued_at),
            nbf=_floor_seconds(nbf),
            exp=_floor_seconds(request.expires_at),
            jti=uuid.uuid4().hex,
            grant_id=str(uuid.uuid4()),
            granted_by=request.granted_by,
            granted_to=request.granted_to,
            organization=request.organization,
            scope=request.scope,
            max_scan_depth=request.max_scan_depth,
            written_authorization_ref=request.written_authorization_ref,
            schema_version=CLAIMS_SCHEMA_VERSION,
            scope_policy_version=SCOPE_POLICY_VERSION,
        )

    def _reissue(self, receipt: AuthorizationGrant) -> IssuedGrant:
        """Deterministically reproduce the original token from a stored receipt."""
        if self._signer.kid != receipt.issuer_kid:
            # Original signing key unavailable — do NOT mint a different grant.
            raise ConfigurationError(
                "recovery required: original issuer key is unavailable for reissuance"
            )
        claims = GrantClaims(
            iss=receipt.issuer,
            aud=self._settings.audience,
            iat=receipt.issued_at,
            nbf=receipt.not_before,
            exp=receipt.expires_at,
            jti=receipt.jti,
            grant_id=receipt.grant_id,
            granted_by=receipt.granted_by,
            granted_to=receipt.granted_to,
            organization=receipt.organization,
            scope=tuple(ScopeEntry(**entry) for entry in receipt.scope),
            max_scan_depth=ScanDepth(receipt.max_scan_depth),
            written_authorization_ref=receipt.written_authorization_ref,
            schema_version=receipt.schema_version,
            scope_policy_version=receipt.scope_policy_version,
        )
        token = self._signer.sign(claims)
        return IssuedGrant(
            grant_id=receipt.grant_id,
            jti=receipt.jti,
            token=token,
            claims_digest=receipt.claims_digest,
            issuer_kid=receipt.issuer_kid,
            expires_at=receipt.expires_at,
        )
