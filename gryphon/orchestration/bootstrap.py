"""Composition root for the orchestration layer.

Wires the authorization core, the tool-execution layer and this layer's own
collaborators into a runtime, then builds the orchestrator, the sweeper and the
command boundary around it.

Two things happen here before anything else, and both are startup-time refusals
rather than scan-time surprises:

* **Telemetry is neutralized and then asserted off.** The orchestration runtime
  pulls in a tracing client transitively, and that client activates from
  environment variables alone — no code change needed. Its payloads would be
  node inputs and outputs, which here means client hostnames, discovered attack
  surface and findings, leaving the one process that holds the live
  authorization. An inherited variable from a shell, a CI job or a base image is
  enough, so startup refuses rather than hoping nobody set one.
* **Configuration is validated.** Lease and heartbeat relationships, the
  attested estate in production, the control socket and its allowlist. A
  misconfiguration that would weaken a control fails the process, not a scan.
"""

from __future__ import annotations

from dataclasses import dataclass

from gryphon.clock import Clock
from gryphon.db.session import Database
from gryphon.orchestration.admission import TargetAdmission
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.commands import OperatorCommands
from gryphon.orchestration.engine import StepEngine
from gryphon.orchestration.orchestrator import ScanOrchestrator
from gryphon.orchestration.reasons import OrchestrationConfigurationError
from gryphon.orchestration.reconcile import Reconciler
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.settings import (
    OrchestrationSettings,
    assert_telemetry_disabled,
    get_orchestration_settings,
    neutralize_telemetry,
)
from gryphon.orchestration.sweeper import RecoverySweeper
from gryphon.orchestration.touchpoint import AuthorityTouchpoint
from gryphon.settings import Settings
from gryphon.tooling.bootstrap import ToolingServices, build_tooling_services
from gryphon.tooling.constants import CredentialSource
from gryphon.tooling.destination.resolver import SystemResolver


@dataclass
class OrchestrationServices:
    """Everything a deployment needs to run scans."""

    settings: OrchestrationSettings
    tooling: ToolingServices
    runtime: ScanRuntime
    orchestrator: ScanOrchestrator
    sweeper: RecoverySweeper
    commands: OperatorCommands

    @property
    def database(self) -> Database:
        return self.tooling.database

    @property
    def clock(self) -> Clock:
        return self.tooling.clock

    async def dispose(self) -> None:
        await self.tooling.dispose()


def build_orchestration_services(
    *,
    settings: Settings | None = None,
    orchestration_settings: OrchestrationSettings | None = None,
    tooling: ToolingServices | None = None,
    clock: Clock | None = None,
    database: Database | None = None,
    owner_id: str | None = None,
) -> OrchestrationServices:
    """Build the orchestration layer, refusing to start if it cannot be safe."""
    # Disable the tracing client, then verify nothing in the environment turned
    # it back on. Order matters: neutralize first so a library default cannot
    # win, assert second so an explicit opt-in cannot pass silently.
    neutralize_telemetry()
    assert_telemetry_disabled()

    os_settings = orchestration_settings or get_orchestration_settings()
    services = tooling or build_tooling_services(
        settings=settings, clock=clock, database=database
    )

    if services.auth.key_material.audit_signer is None:  # pragma: no cover
        raise OrchestrationConfigurationError(
            "an audit signing key is required: orchestration decisions and the "
            "report attestation are signed with it"
        )
    audit = OrchestrationAuditBuilder(services.auth.key_material.audit_signer)

    touchpoint = AuthorityTouchpoint(
        database=services.database,
        clock=services.clock,
        grant_trust=services.auth.key_material.grant_trust,
        execution_service=services.service,
        # The in-process posture is the default for a single-host deployment:
        # it avoids a second process, capability lifetimes tuned against queue
        # delay, and a clock-sync precondition, for no benefit at this scale.
        # The touchpoint still runs the same liveness predicate either way, and
        # records which posture was in force on every call.
        credential_source=CredentialSource.PERMIT,
    )

    engine = StepEngine(
        database=services.database,
        clock=services.clock,
        touchpoint=touchpoint,
        audit=audit,
        settings=os_settings,
    )
    reconciler = Reconciler(
        database=services.database,
        clock=services.clock,
        touchpoint=touchpoint,
        audit=audit,
        settings=os_settings,
    )
    admission = TargetAdmission(
        resolver=SystemResolver(
            timeout_seconds=services.tooling_settings.resolve_timeout_seconds
        ),
        attested_estate_cidrs=os_settings.attested_estate_cidrs,
        discovered_target_cap=os_settings.discovered_target_cap,
        strict_address_attestation=os_settings.strict_address_attestation,
    )

    runtime = ScanRuntime(
        database=services.database,
        clock=services.clock,
        settings=os_settings,
        touchpoint=touchpoint,
        engine=engine,
        reconciler=reconciler,
        admission=admission,
        audit=audit,
    )
    orchestrator = ScanOrchestrator(runtime=runtime, audit=audit, owner_id=owner_id)
    sweeper = RecoverySweeper(runtime=runtime, orchestrator=orchestrator)
    commands = OperatorCommands(
        runtime=runtime, orchestrator=orchestrator, audit=audit
    )

    return OrchestrationServices(
        settings=os_settings,
        tooling=services,
        runtime=runtime,
        orchestrator=orchestrator,
        sweeper=sweeper,
        commands=commands,
    )
