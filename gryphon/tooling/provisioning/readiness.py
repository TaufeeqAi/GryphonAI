"""Readiness checks for the tool execution layer.

A partially-provisioned or mixed-schema deployment is UNREADY and must not admit
executions. Checks: capability key material, egress posture, descriptors, schema
revision + append-only triggers, and (when configured) manifest binary integrity.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field

from sqlalchemy import text

from gryphon.db.session import Database
from gryphon.logging_config import get_logger
from gryphon.tooling.constants import EgressMode, ToolId
from gryphon.tooling.destination.egress import EgressEnforcer, build_egress_enforcer
from gryphon.tooling.provisioning.manifest import ToolManifest, verify_entry
from gryphon.tooling.settings import ToolingSettings
from gryphon.tooling.tools.descriptors import get_descriptor

logger = get_logger(__name__)

#: The migration that creates this layer's schema. A LATER head is fine:
#: subsequent layers only add tables.
MINIMUM_ALEMBIC_REVISION = "0002"
REQUIRED_TRIGGERS = (
    "trg_tool_invocation_audit_no_mutation",
    "trg_capability_consumption_no_mutation",
)


@dataclass
class ToolingReadinessReport:
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

async def check_tooling_readiness(
    *,
    settings: ToolingSettings,
    database: Database,
    has_capability_signer: bool,
    manifest: ToolManifest | None = None,
    egress_enforcer: EgressEnforcer | None = None,
) -> ToolingReadinessReport:
    checks: dict[str, bool] = {}
    details: dict[str, str] = {}

    # Capability key material (required in prod).
    checks["capability_key"] = has_capability_signer or not settings.is_production

    # Egress posture: enforced, or an explicitly permitted non-prod unenforced.
    checks["egress_posture"] = settings.egress_mode is EgressMode.ENFORCED or (
        not settings.is_production and settings.allow_unenforced_egress
    )

    # Linux is the only supported production runtime (OS egress containment,
    # memory rlimit, process-group kill).
    checks["platform"] = not settings.is_production or platform.system() == "Linux"
    details["platform"] = platform.system()

    # Can this host actually establish an egress context? Probing is free and
    # has no side effects. Outside production an incapable host is reported but
    # not fatal: passive tools still run and active ones fail closed.
    enforcer = egress_enforcer or build_egress_enforcer(settings)
    capable = bool(getattr(enforcer, "capable", True))
    checks["egress_capability"] = capable or not settings.is_production
    if not capable:
        details["egress_capability"] = (
            "cannot establish a per-execution egress allowlist: "
            + str(getattr(enforcer, "_incapable_reason", "unknown"))
            + " -- active tools will be DENIED"
        )

    # All seven descriptors resolvable.
    try:
        for tool_id in ToolId:
            get_descriptor(tool_id)
        checks["descriptors"] = True
    except Exception as exc:  # pragma: no cover
        checks["descriptors"] = False
        details["descriptors"] = str(exc)

    # Manifest binary integrity (if configured).
    if manifest is not None:
        try:
            for entry in manifest.entries:
                verify_entry(entry)
            checks["binaries"] = True
        except Exception as exc:
            checks["binaries"] = False
            details["binaries"] = str(exc)

    # Schema revision + append-only triggers.
    try:
        async with database.session() as session:
            revision = (
                await session.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one_or_none()
            checks["schema_revision"] = _revision_at_least(revision, MINIMUM_ALEMBIC_REVISION)
            details["schema_revision"] = f"found={revision!r} minimum={MINIMUM_ALEMBIC_REVISION!r}"
            triggers = set(
                (await session.execute(text("SELECT tgname FROM pg_trigger"))).scalars().all()
            )
            checks["append_only_triggers"] = set(REQUIRED_TRIGGERS).issubset(triggers)
        checks["database"] = True
    except Exception as exc:  # pragma: no cover - exercised with a live DB
        checks["database"] = False
        details["database"] = type(exc).__name__

    ready = all(checks.values())
    if not ready:
        logger.warning("tooling_not_ready", checks=checks)
    return ToolingReadinessReport(ready=ready, checks=checks, details=details)
