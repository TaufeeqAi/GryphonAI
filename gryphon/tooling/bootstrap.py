"""Composition root for the tool execution layer.

Wires the authorization core's services (grant trust, audit key, database) with
the tooling collaborators, and enforces that the capability-signing key is
distinct from the grant and audit keys (three distinct keys).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from gryphon.bootstrap import Services as AuthServices
from gryphon.bootstrap import build_services
from gryphon.clock import Clock
from gryphon.db.session import Database
from gryphon.settings import Settings
from gryphon.tooling.audit.builder import ToolAuditBuilder
from gryphon.tooling.capability.issuer import CapabilityIssuer
from gryphon.tooling.capability.keys import build_capability_key_material
from gryphon.tooling.capability.verifier import CapabilityVerifier
from gryphon.tooling.destination.egress import build_egress_enforcer
from gryphon.tooling.destination.guard import DestinationGuard
from gryphon.tooling.destination.resolver import SystemResolver
from gryphon.tooling.enforcement.budgets import BudgetManager
from gryphon.tooling.enforcement.service import BinaryResolver, ToolExecutionService
from gryphon.tooling.provisioning.manifest import (
    ManifestBinaryResolver,
    StaticBinaryResolver,
    ToolManifest,
)
from gryphon.tooling.reasons import ToolingConfigurationError
from gryphon.tooling.settings import ToolingSettings, get_tooling_settings
from gryphon.tooling.tools.runner import SafeSubprocessRunner


@dataclass
class ToolingServices:
    tooling_settings: ToolingSettings
    auth: AuthServices
    database: Database
    clock: Clock
    verifier: CapabilityVerifier
    service: ToolExecutionService
    issuer: CapabilityIssuer | None
    has_capability_signer: bool
    manifest: ToolManifest | None

    async def dispose(self) -> None:
        await self.database.dispose()


def _assert_distinct_keys(cap_fpr: str, auth: AuthServices) -> None:
    grant = auth.key_material.grant_signer
    audit = auth.key_material.audit_signer
    if grant is not None and cap_fpr == grant.public_key_raw_hex():
        raise ToolingConfigurationError("capability key must be distinct from the grant key")
    if audit is not None and cap_fpr == audit.public_key_raw_hex():
        raise ToolingConfigurationError("capability key must be distinct from the audit key")


def build_tooling_services(
    *,
    settings: Settings | None = None,
    tooling_settings: ToolingSettings | None = None,
    clock: Clock | None = None,
    database: Database | None = None,
    binary_resolver: BinaryResolver | None = None,
) -> ToolingServices:
    auth = build_services(settings, clock=clock, database=database)
    ts = tooling_settings or get_tooling_settings()
    cap_material = build_capability_key_material(ts)

    if auth.key_material.audit_signer is None:  # pragma: no cover - build_services enforces this
        raise ToolingConfigurationError("audit signing key is required to sign tool audit events")
    audit_builder = ToolAuditBuilder(auth.key_material.audit_signer)

    if cap_material.signer is not None:
        _assert_distinct_keys(cap_material.signer.public_key_raw_hex(), auth)

    verifier = CapabilityVerifier(
        cap_material.trust,
        clock_skew=timedelta(seconds=ts.capability_clock_skew_seconds),
    )
    budgets = BudgetManager(ts, auth.clock)
    guard = DestinationGuard(SystemResolver(timeout_seconds=ts.resolve_timeout_seconds))
    egress = build_egress_enforcer(ts)
    runner = SafeSubprocessRunner(
        max_stdout_bytes=ts.subprocess_max_stdout_bytes,
        memory_limit_mb=ts.subprocess_memory_limit_mb,
    )

    manifest: ToolManifest | None = None
    if binary_resolver is None:
        if ts.tool_manifest_path:
            manifest = ToolManifest.load(ts.tool_manifest_path)
            binary_resolver = ManifestBinaryResolver(manifest)
        else:
            binary_resolver = StaticBinaryResolver(paths={})

    service = ToolExecutionService(
        verifier=verifier,
        database=auth.database,
        clock=auth.clock,
        budgets=budgets,
        destination_guard=guard,
        egress_enforcer=egress,
        runner=runner,
        audit_builder=audit_builder,
        binary_resolver=binary_resolver,
        settings=ts,
    )

    issuer = None
    if cap_material.signer is not None:
        issuer = CapabilityIssuer(
            signing_key=cap_material.signer,
            grant_trust=auth.key_material.grant_trust,
            database=auth.database,
            clock=auth.clock,
            ttl_seconds=ts.capability_ttl_seconds,
        )

    return ToolingServices(
        tooling_settings=ts,
        auth=auth,
        database=auth.database,
        clock=auth.clock,
        verifier=verifier,
        service=service,
        issuer=issuer,
        has_capability_signer=cap_material.signer is not None,
        manifest=manifest,
    )
