"""Signed orchestration audit events.

The upstream layers audit two questions: *was this scan authorized* and *was
this call enforced and contained*. Neither records the question only this layer
can answer — **why was this host scanned, and what did we intend to do?** That
reasoning otherwise lives in logs, which this project treats as diagnostic and
losable, and in a mutable ledger. For a product whose deliverable is an
assertion about someone else's infrastructure, "we scanned X because passive
discovery found it under authorized wildcard W, and its address attested to the
agreed estate" is the defensible story, so it belongs in the accountability
record.

Events reuse the existing audit key and the existing verifier. Nothing here
invents a key or a trust path: a signature with no verifier is ritual, and a
fourth key would mean a fourth thing to rotate, distribute and compromise.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from gryphon.auth.key_provider import Ed25519SigningKey
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import ensure_utc
from gryphon.orchestration.constants import (
    ORCHESTRATION_AUDIT_EVENT_SCHEMA_VERSION,
    OrchestrationEventType,
)


@dataclass(frozen=True, slots=True)
class SignedOrchestrationEvent:
    """A canonical, signed orchestration decision event."""

    event_id: str
    event_type: str
    payload: dict[str, Any]
    payload_digest: str
    signer_kid: str
    signature_b64: str


class OrchestrationAuditBuilder:
    """Signs canonical orchestration payloads with the audit key."""

    def __init__(self, audit_key: Ed25519SigningKey) -> None:
        self._key = audit_key

    @property
    def kid(self) -> str:
        return self._key.kid

    def _sign(
        self, event_type: OrchestrationEventType, payload: dict[str, Any]
    ) -> SignedOrchestrationEvent:
        canonical = canonical_json_bytes(payload)
        signature = self._key.sign(canonical)
        return SignedOrchestrationEvent(
            event_id=payload["event_id"],
            event_type=event_type.value,
            payload=payload,
            payload_digest=sha256_hex(canonical),
            signer_kid=self._key.kid,
            signature_b64=base64.standard_b64encode(signature).decode("ascii"),
        )

    def _base(
        self,
        event_type: OrchestrationEventType,
        *,
        timestamp: datetime,
        scan_run_id: str | None,
    ) -> dict[str, Any]:
        return {
            "event_id": str(uuid4()),
            "event_type": event_type.value,
            "event_schema_version": ORCHESTRATION_AUDIT_EVENT_SCHEMA_VERSION,
            "scan_run_id": scan_run_id,
            "occurred_at": ensure_utc(timestamp).isoformat(),
        }

    # -- the gate -------------------------------------------------------------
    def gate(
        self,
        *,
        scan_run_id: str | None,
        decision: str,
        reason_code: str,
        initiated_by: str,
        timestamp: datetime,
        detail: str | None = None,
    ) -> SignedOrchestrationEvent:
        """Record a gate evaluation — pass or fail — before anything downstream.

        Audited on *every* entry, including a resume, because the graph is
        compiled without persistence and therefore re-enters here every time.
        """
        payload = self._base(
            OrchestrationEventType.GATE, timestamp=timestamp, scan_run_id=scan_run_id
        )
        payload.update(
            {"decision": decision, "reason_code": reason_code,
             "initiated_by": initiated_by, "detail": detail}
        )
        return self._sign(OrchestrationEventType.GATE, payload)

    def scan_start(
        self,
        *,
        scan_run_id: str,
        initiated_by: str,
        claim_epoch: int,
        claim_result: str,
        deadline_at: datetime,
        policy_version: str,
        graph_version: str,
        timestamp: datetime,
    ) -> SignedOrchestrationEvent:
        """Record who started (or took over) this scan, and under what deadline."""
        payload = self._base(
            OrchestrationEventType.SCAN_START, timestamp=timestamp, scan_run_id=scan_run_id
        )
        payload.update(
            {
                "initiated_by": initiated_by,
                "claim_epoch": claim_epoch,
                "claim_result": claim_result,
                "deadline_at": ensure_utc(deadline_at).isoformat(),
                "policy_version": policy_version,
                "graph_version": graph_version,
            }
        )
        return self._sign(OrchestrationEventType.SCAN_START, payload)

    # -- intent ---------------------------------------------------------------
    def plan_committed(
        self,
        *,
        scan_run_id: str,
        stage: str,
        step: str,
        tool_id: str,
        plan_generation: int,
        plan_digest: str,
        item_count: int,
        claim_epoch: int,
        timestamp: datetime,
    ) -> SignedOrchestrationEvent:
        """Record intended work before the step's first protected call.

        This is the event that makes target selection accountable: the plan
        digest plus the item count fix what the scan set out to do, so the
        audit alone can reconstruct intent without the ledger or the logs.
        """
        payload = self._base(
            OrchestrationEventType.PLAN_COMMITTED,
            timestamp=timestamp,
            scan_run_id=scan_run_id,
        )
        payload.update(
            {
                "stage": stage,
                "step": step,
                "tool_id": tool_id,
                "plan_generation": plan_generation,
                "plan_digest": plan_digest,
                "item_count": item_count,
                "claim_epoch": claim_epoch,
            }
        )
        return self._sign(OrchestrationEventType.PLAN_COMMITTED, payload)

    def target_admission(
        self,
        *,
        scan_run_id: str,
        admitted_count: int,
        excluded: dict[str, int],
        cap: int,
        halted_for_review: bool,
        attestation_configured: bool,
        claim_epoch: int,
        timestamp: datetime,
    ) -> SignedOrchestrationEvent:
        """Record which discovered targets were admitted to active scanning."""
        payload = self._base(
            OrchestrationEventType.TARGET_ADMISSION,
            timestamp=timestamp,
            scan_run_id=scan_run_id,
        )
        payload.update(
            {
                "admitted_count": admitted_count,
                "excluded": dict(sorted(excluded.items())),
                "cap": cap,
                "halted_for_review": halted_for_review,
                "attestation_configured": attestation_configured,
                "claim_epoch": claim_epoch,
            }
        )
        return self._sign(OrchestrationEventType.TARGET_ADMISSION, payload)

    # -- lifecycle ------------------------------------------------------------
    def lifecycle_transition(
        self,
        *,
        scan_run_id: str,
        from_state: str | None,
        to_state: str,
        reason_code: str | None,
        claim_epoch: int,
        coverage: dict[str, Any] | None,
        timestamp: datetime,
    ) -> SignedOrchestrationEvent:
        """Record a scan-level transition and the coverage that justified it."""
        payload = self._base(
            OrchestrationEventType.LIFECYCLE_TRANSITION,
            timestamp=timestamp,
            scan_run_id=scan_run_id,
        )
        payload.update(
            {
                "from_state": from_state,
                "to_state": to_state,
                "reason_code": reason_code,
                "claim_epoch": claim_epoch,
                "coverage": coverage,
            }
        )
        return self._sign(OrchestrationEventType.LIFECYCLE_TRANSITION, payload)

    def reconciliation(
        self,
        *,
        scan_run_id: str,
        examined: int,
        resolved: int,
        unresolved: int,
        claim_epoch: int,
        timestamp: datetime,
    ) -> SignedOrchestrationEvent:
        """Record a reconciliation pass and what it concluded."""
        payload = self._base(
            OrchestrationEventType.RECONCILIATION,
            timestamp=timestamp,
            scan_run_id=scan_run_id,
        )
        payload.update(
            {
                "examined": examined,
                "resolved": resolved,
                "unresolved_possibly_contacted": unresolved,
                "claim_epoch": claim_epoch,
            }
        )
        return self._sign(OrchestrationEventType.RECONCILIATION, payload)

    # -- the deliverable ------------------------------------------------------
    def report_emitted(
        self,
        *,
        scan_run_id: str,
        report_id: str,
        report_digest: str,
        report_schema_version: str,
        terminal_state: str,
        covered: int,
        denominator: int,
        finding_count: int,
        claim_epoch: int,
        timestamp: datetime,
    ) -> SignedOrchestrationEvent:
        """Attest the report by carrying its content digest under signature.

        The report row itself is unsigned; this event is its tamper evidence,
        verifiable with the audit key the deployment already trusts.
        """
        payload = self._base(
            OrchestrationEventType.REPORT_EMITTED,
            timestamp=timestamp,
            scan_run_id=scan_run_id,
        )
        payload.update(
            {
                "report_id": report_id,
                "report_digest": report_digest,
                "report_schema_version": report_schema_version,
                "terminal_state": terminal_state,
                "covered": covered,
                "denominator": denominator,
                "finding_count": finding_count,
                "claim_epoch": claim_epoch,
            }
        )
        return self._sign(OrchestrationEventType.REPORT_EMITTED, payload)

    def operator_command(
        self,
        *,
        scan_run_id: str | None,
        command: str,
        initiated_by: str,
        accepted: bool,
        reason_code: str | None,
        timestamp: datetime,
    ) -> SignedOrchestrationEvent:
        """Record an operator command and whether it was accepted."""
        payload = self._base(
            OrchestrationEventType.OPERATOR_COMMAND,
            timestamp=timestamp,
            scan_run_id=scan_run_id,
        )
        payload.update(
            {
                "command": command,
                "initiated_by": initiated_by,
                "accepted": accepted,
                "reason_code": reason_code,
            }
        )
        return self._sign(OrchestrationEventType.OPERATOR_COMMAND, payload)
