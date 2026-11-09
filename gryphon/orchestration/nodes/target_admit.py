"""The target-admission node — the boundary between discovery and action.

Discovery output is not a work list. It is attacker-influenceable input: a
wildcard DNS record can return tens of thousands of names, and a dangling
subdomain under an authorized wildcard resolves to an address somebody else
owns. This node stands between "a name was discovered" and "we send traffic to
it", and it answers two questions the stages on either side cannot:

* *Is this many targets a workload or a symptom?* Above the configured cap the
  scan stops for an operator decision rather than fanning out silently and
  spending the authorization window on noise.
* *Does this name's address belong to the estate the client agreed to?* Scope is
  granted over names; containment is enforced over addresses. Only this layer
  sees both, so only this layer can notice when they disagree.

Placed before the active stages are planned, so ``planned implies admitted``
and exclusions never land in the coverage denominator. A refused target is
reported separately — it is not a gap in coverage, because we never undertook
to scan it.
"""

from __future__ import annotations

import hashlib
from typing import Callable

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.auth.scope import ScopeEntry
from gryphon.db.repositories.grants import GrantRepository
from gryphon.logging_config import get_logger
from gryphon.orchestration.constants import ScanLifecycleState, ScanStage
from gryphon.orchestration.ledger import (
    AdmittedTargetRepository,
    OrchestrationAuditRepository,
    RawFindingRepository,
    ScanLifecycleRepository,
)
from gryphon.orchestration.projection import ObservationType
from gryphon.orchestration.reasons import (
    AuthorizationPreconditionFailed,
    OrchestrationReasonCode,
)
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.state import ScanGraphState

logger = get_logger(__name__)


def build_target_admit_node(
    runtime: ScanRuntime,
) -> Callable[[ScanGraphState], object]:
    """Build the target-admission node closure."""

    async def target_admit(state: ScanGraphState) -> ScanGraphState:
        scan_run_id = state["scan_run_id"]
        claim_epoch = int(state["claim_epoch"])

        try:
            context = await runtime.touchpoint.context(scan_run_id)
            resolved = await runtime.touchpoint.resolve(scan_run_id)
        except AuthorizationPreconditionFailed as exc:
            return ScanGraphState(
                halted=True,
                stage=ScanStage.TARGET_ADMIT.value,
                reason_code=exc.reason_code.value,
            )

        scope_entries = await _scope_entries(runtime, resolved.permit.grant_id)
        discovered = await _discovered_hosts(runtime, scan_run_id)

        result = await runtime.admission.admit(
            discovered=discovered,
            seed_target=context.canonical_target,
            discovered_by="subdomain_discovery",
            scope_entries=scope_entries,
            now=runtime.clock.now(),
        )

        await _audit_admission(
            runtime, scan_run_id=scan_run_id, claim_epoch=claim_epoch, result=result
        )

        if result.halted_for_review:
            # Not a failure: a decision the operator must make. The scan stays
            # reclaimable and nothing has been scanned.
            await _halt_for_review(runtime, scan_run_id, claim_epoch)
            return ScanGraphState(
                halted=True,
                stage=ScanStage.TARGET_ADMIT.value,
                reason_code=OrchestrationReasonCode.TARGET_CAP_EXCEEDED.value,
            )

        rows = [
            {
                "admitted_target_id": hashlib.sha256(
                    f"{scan_run_id}|{target.canonical_target}".encode("utf-8")
                ).hexdigest()[:48],
                "scan_run_id": scan_run_id,
                "canonical_target": target.canonical_target,
                "addresses": list(target.addresses),
                "provenance": target.provenance,
            }
            for target in result.admitted
        ]
        try:
            async with runtime.database.session() as session:
                async with session.begin():
                    await AdmittedTargetRepository(session).record(rows)
        except (OperationalError, DBAPIError):
            logger.warning("admitted_target_record_failed", scan_run_id=scan_run_id)
            return ScanGraphState(
                halted=True,
                stage=ScanStage.TARGET_ADMIT.value,
                reason_code=OrchestrationReasonCode.DB_UNAVAILABLE.value,
            )

        logger.info(
            "targets_admitted",
            scan_run_id=scan_run_id,
            discovered=result.discovered_count,
            admitted=len(result.admitted),
            excluded=result.exclusion_histogram,
        )
        return ScanGraphState(stage=ScanStage.ENUMERATE.value)

    return target_admit


def route_after_admission(state: ScanGraphState) -> str:
    """Conditional edge: a halt ends the graph without entering active stages."""
    return "denied" if state.get("halted") else "admitted"


async def _scope_entries(runtime: ScanRuntime, grant_id: str) -> tuple[ScopeEntry, ...]:
    """Load the granted scope from the committed receipt.

    Read, never re-derived into a local policy: the authorization layer owns
    what the grant means, and a second interpretation here would be a second
    opinion about scope.
    """
    async with runtime.database.session() as session:
        receipt = await GrantRepository(session).get_by_grant_id(grant_id)
    if receipt is None:
        return ()
    try:
        return tuple(ScopeEntry(**entry) for entry in receipt.scope)
    except Exception:  # pragma: no cover - a tampered receipt fails closed
        logger.warning("scope_receipt_unparsable", grant_id=grant_id)
        return ()


async def _discovered_hosts(runtime: ScanRuntime, scan_run_id: str) -> list[str]:
    """Collect discovered hostnames from persisted evidence."""
    async with runtime.database.session() as session:
        evidence = await RawFindingRepository(session).for_scan(scan_run_id)
    return [
        row.canonical_target
        for row in evidence
        if row.observation_type
        in (ObservationType.SUBDOMAIN, ObservationType.DNS_RECORD)
    ]


async def _halt_for_review(
    runtime: ScanRuntime, scan_run_id: str, claim_epoch: int
) -> None:
    async with runtime.database.session() as session:
        async with session.begin():
            await ScanLifecycleRepository(session).transition(
                scan_run_id=scan_run_id,
                claim_epoch=claim_epoch,
                state=ScanLifecycleState.HALTED_FOR_REVIEW,
                reason_code=OrchestrationReasonCode.TARGET_CAP_EXCEEDED.value,
            )


async def _audit_admission(
    runtime: ScanRuntime, *, scan_run_id: str, claim_epoch: int, result
) -> None:
    event = runtime.audit.target_admission(
        scan_run_id=scan_run_id,
        admitted_count=len(result.admitted),
        excluded=result.exclusion_histogram,
        cap=runtime.settings.discovered_target_cap,
        halted_for_review=result.halted_for_review,
        attestation_configured=result.attestation_configured,
        claim_epoch=claim_epoch,
        timestamp=runtime.clock.now(),
    )
    try:
        async with runtime.database.session() as session:
            async with session.begin():
                OrchestrationAuditRepository(session).append(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    event_schema_version=event.payload["event_schema_version"],
                    scan_run_id=scan_run_id,
                    stage=ScanStage.TARGET_ADMIT.value,
                    decision="HALT" if result.halted_for_review else "ADMIT",
                    claim_epoch=claim_epoch,
                    payload=event.payload,
                    payload_digest=event.payload_digest,
                    signer_kid=event.signer_kid,
                    signature=event.signature_b64,
                )
    except (OperationalError, DBAPIError):
        logger.warning("target_admission_audit_unavailable", scan_run_id=scan_run_id)
