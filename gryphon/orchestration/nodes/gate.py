"""The authorization gate node — the entry fast-fail.

Because the graph is compiled **without** a checkpointer, every invocation —
first run, resume, takeover — re-enters here. That turns "gate first" into
"gate always" by construction, and closes the gap a position-based check
otherwise leaves: a resumed graph normally restarts at its saved position, which
is by definition *past* the entry, so the one path that most needs the check is
the one that skips it.

This node is a fast fail, not the only enforcement. It denies cheaply before any
planning work happens; the authority touchpoint independently re-checks
liveness and the authorization window before every protected call. Two checks,
one predicate: the gate makes denial cheap, the touchpoint makes it correct.

The gate does not *decide* authorization. It confirms a committed decision made
upstream and refuses to proceed if that decision is not currently live.
"""

from __future__ import annotations

from typing import Callable

from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.logging_config import get_logger
from gryphon.orchestration.constants import ScanStage
from gryphon.orchestration.ledger import OrchestrationAuditRepository
from gryphon.orchestration.reasons import (
    AuthorizationPreconditionFailed,
    OrchestrationReasonCode,
)
from gryphon.orchestration.runtime import ScanRuntime
from gryphon.orchestration.state import ScanGraphState

logger = get_logger(__name__)

#: Routing labels. Any denial routes to the same terminal edge.
ROUTE_ADMITTED = "admitted"
ROUTE_DENIED = "denied"


def build_gate_node(
    runtime: ScanRuntime, *, initiated_by: str
) -> Callable[[ScanGraphState], object]:
    """Build the gate node closure."""

    async def gate(state: ScanGraphState) -> ScanGraphState:
        scan_run_id = state["scan_run_id"]
        decision = "ALLOW"
        reason = OrchestrationReasonCode.OK
        detail = ""

        try:
            # Resolving the permit *is* the check: resolution fails closed on a
            # missing admission, an expired grant, or a signing key that is no
            # longer trusted. Revocation therefore reaches an in-flight scan.
            await runtime.touchpoint.resolve(scan_run_id)
        except AuthorizationPreconditionFailed as exc:
            decision = "DENY"
            reason = exc.reason_code
            detail = exc.detail

        await _audit_gate(
            runtime,
            scan_run_id=scan_run_id,
            decision=decision,
            reason=reason,
            initiated_by=initiated_by,
            detail=detail,
        )

        if decision == "DENY":
            logger.info(
                "gate_denied", scan_run_id=scan_run_id, reason_code=reason.value
            )
            return ScanGraphState(
                halted=True,
                stage=ScanStage.GATE.value,
                reason_code=reason.value,
            )

        logger.info("gate_admitted", scan_run_id=scan_run_id)
        return ScanGraphState(halted=False, stage=ScanStage.RECON.value)

    return gate


def route_after_gate(state: ScanGraphState) -> str:
    """Conditional edge: a denial ends the graph with zero side effects."""
    return ROUTE_DENIED if state.get("halted") else ROUTE_ADMITTED


async def _audit_gate(
    runtime: ScanRuntime,
    *,
    scan_run_id: str,
    decision: str,
    reason: OrchestrationReasonCode,
    initiated_by: str,
    detail: str,
) -> None:
    """Record the evaluation before anything downstream runs.

    Audited on pass *and* fail. A gate that only records its refusals cannot
    later show that it ran at all on the scans that proceeded.
    """
    event = runtime.audit.gate(
        scan_run_id=scan_run_id,
        decision=decision,
        reason_code=reason.value,
        initiated_by=initiated_by,
        timestamp=runtime.clock.now(),
        detail=detail or None,
    )
    try:
        async with runtime.database.session() as session:
            async with session.begin():
                OrchestrationAuditRepository(session).append(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    event_schema_version=event.payload["event_schema_version"],
                    scan_run_id=scan_run_id,
                    decision=decision,
                    reason_code=reason.value,
                    stage=ScanStage.GATE.value,
                    initiated_by=initiated_by,
                    payload=event.payload,
                    payload_digest=event.payload_digest,
                    signer_kid=event.signer_kid,
                    signature=event.signature_b64,
                )
    except (OperationalError, DBAPIError):
        # The gate's own accountability record could not be written. Log it;
        # the decision itself already stands, and a denial is still a denial.
        logger.warning("gate_audit_unavailable", scan_run_id=scan_run_id)
