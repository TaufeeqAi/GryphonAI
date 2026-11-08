"""Composition root — wire configuration into collaborating services.

Keeps construction in one place so the graph gate, readiness checks, operator
scripts and tests all build the object graph identically. Nothing here makes an
authorization decision; it only assembles the owners defined in ``auth`` and
``db`` (§29.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from gryphon.auth.audit_signer import AuditSigner
from gryphon.auth.authorization_token import GrantSigner, GrantVerifier
from gryphon.auth.issuer import GrantIssuer
from gryphon.auth.key_provider import KeyMaterial, build_key_material
from gryphon.auth.service import AuthorizationService
from gryphon.clock import Clock, SystemClock
from gryphon.db.session import Database
from gryphon.errors import ConfigurationError
from gryphon.settings import Settings, get_settings


@dataclass
class Services:
    """Fully-wired service object graph for one deployment."""

    settings: Settings
    clock: Clock
    database: Database
    key_material: KeyMaterial
    grant_signer: GrantSigner | None
    audit_signer: AuditSigner | None
    verifier: GrantVerifier
    authorization_service: AuthorizationService
    issuer: GrantIssuer | None

    async def dispose(self) -> None:
        await self.database.dispose()


def build_services(
    settings: Settings | None = None,
    *,
    clock: Clock | None = None,
    database: Database | None = None,
) -> Services:
    """Build the service graph. Audit signing is required to admit requests."""
    settings = settings or get_settings()
    clock = clock or SystemClock()
    key_material = build_key_material(settings)
    database = database or Database(settings)

    if key_material.audit_signer is None:
        raise ConfigurationError("audit signing key is required to admit scans")
    audit_signer = AuditSigner(key_material.audit_signer)

    verifier = GrantVerifier(
        key_material.grant_trust,
        expected_issuer=settings.issuer,
        expected_audience=settings.audience,
        clock_skew=timedelta(seconds=settings.clock_skew_seconds),
    )

    grant_signer = (
        GrantSigner(key_material.grant_signer) if key_material.grant_signer else None
    )

    authorization_service = AuthorizationService(
        verifier=verifier,
        audit_signer=audit_signer,
        database=database,
        settings=settings,
        clock=clock,
    )

    issuer = None
    if grant_signer is not None:
        issuer = GrantIssuer(
            signer=grant_signer,
            audit_signer=audit_signer,
            database=database,
            settings=settings,
            clock=clock,
        )

    return Services(
        settings=settings,
        clock=clock,
        database=database,
        key_material=key_material,
        grant_signer=grant_signer,
        audit_signer=audit_signer,
        verifier=verifier,
        authorization_service=authorization_service,
        issuer=issuer,
    )
