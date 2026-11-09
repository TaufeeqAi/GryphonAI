"""Startup / readiness validation (§22.4, SEC-004).

A partially-applied or incompatible schema makes the service UNREADY and
authorization unavailable; GRYPHON never attempts best-effort writes against a
mixed schema (§22.4). Readiness requires: audit key material, a non-empty grant
trust store, the expected Alembic revision and the append-only audit triggers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import text

from gryphon.bootstrap import Services
from gryphon.logging_config import get_logger

logger = get_logger(__name__)

#: Head revision this build expects (bump with each forward migration).
#: The migration that creates this layer's schema. A LATER head is fine:
#: subsequent layers only add tables.
MINIMUM_ALEMBIC_REVISION = "0001"

#: Append-only protection triggers required on audit + grant tables (§22.3).
REQUIRED_TRIGGERS = (
    "trg_authorization_audit_log_no_mutation",
    "trg_authorization_grants_no_mutation",
)


@dataclass
class ReadinessReport:
    ready: bool
    checks: dict[str, bool] = field(default_factory=dict)
    details: dict[str, str] = field(default_factory=dict)



def _revision_at_least(applied: str | None, minimum: str) -> bool:
    """Is the applied migration head at or beyond the one this layer needs?

    An exact-equality check answers the wrong question: a later layer's
    migration raises the head, and this layer's schema is still present. Pinning
    equality makes every readiness probe in the repository fail the moment the
    next layer lands, which trains an operator to ignore a NOT READY verdict.
    """
    if applied is None:
        return False
    try:
        return int(applied) >= int(minimum)
    except ValueError:
        # A non-numeric revision cannot be ordered; demand an exact match.
        return applied == minimum

async def check_readiness(services: Services) -> ReadinessReport:
    """Return a readiness report; ``ready`` is True only if every check passes."""
    checks: dict[str, bool] = {}
    details: dict[str, str] = {}

    checks["audit_key"] = services.audit_signer is not None
    checks["grant_trust"] = len(services.key_material.grant_trust.trusted_kids) > 0

    try:
        async with services.database.session() as session:
            revision = (
                await session.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one_or_none()
            checks["schema_revision"] = _revision_at_least(revision, MINIMUM_ALEMBIC_REVISION)
            details["schema_revision"] = f"found={revision!r} minimum={MINIMUM_ALEMBIC_REVISION!r}"

            trigger_names = set(
                (await session.execute(text("SELECT tgname FROM pg_trigger"))).scalars().all()
            )
            checks["audit_triggers"] = set(REQUIRED_TRIGGERS).issubset(trigger_names)
            details["audit_triggers"] = (
                "present" if checks["audit_triggers"] else "missing append-only triggers"
            )
        checks["database"] = True
    except Exception as exc:  # pragma: no cover - exercised by integration env
        checks["database"] = False
        details["database"] = type(exc).__name__
        logger.warning("readiness_db_check_failed", error_type=type(exc).__name__)

    ready = all(checks.values())
    if not ready:
        logger.warning("service_not_ready", checks=checks)
    return ReadinessReport(ready=ready, checks=checks, details=details)
