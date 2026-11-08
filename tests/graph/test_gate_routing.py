"""Compiled-graph routing conformance (§30.4, INV-001/002/026).

These tests drive the REAL compiled LangGraph with a stub decision owner so the
routing contract is validated without a database: only a committed
``AuthorizedPermit`` reaches the sentinel; every other outcome ends the graph
with the sentinel never reached.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gryphon.auth.results import AdmissionReplayReceipt, DeniedDecision, UnknownOutcome, mint_permit
from gryphon.auth.service import ScanAdmissionRequest
from gryphon.constants import ScanDepth
from gryphon.errors import ReasonCode
from gryphon.graph_contract.authorization_gate_test_graph import build_gate_graph, run_gate

pytestmark = pytest.mark.graph


class _StubService:
    def __init__(self, result) -> None:
        self._result = result
        self.calls = 0

    async def authorize_scan(self, request: ScanAdmissionRequest):
        self.calls += 1
        return self._result


def _request() -> ScanAdmissionRequest:
    return ScanAdmissionRequest(
        target="app.example.com",
        token="tok",
        requested_depth="standard",
        idempotency_key="0123456789abcdef0123456789abcdef",
    )


def _permit():
    return mint_permit(
        scan_run_id="run-allow",
        grant_id="g",
        canonical_target="app.example.com",
        effective_scan_depth=ScanDepth.STANDARD,
        claims_digest="d",
        scope_policy_version="1",
        admitted_at=datetime.now(timezone.utc),
        audit_event_id="a",
    )


@pytest.mark.asyncio
async def test_allow_reaches_sentinel_once() -> None:
    graph = build_gate_graph(_StubService(_permit()))
    result, sentinel = await run_gate(graph, _request())
    assert sentinel == 1
    assert result.scan_run_id == "run-allow"


@pytest.mark.asyncio
async def test_deny_never_reaches_sentinel() -> None:
    denied = DeniedDecision(scan_run_id="run-deny", reason_code=ReasonCode.SCOPE_NO_MATCH, audit_event_id="a")
    graph = build_gate_graph(_StubService(denied))
    result, sentinel = await run_gate(graph, _request())
    assert sentinel == 0
    assert isinstance(result, DeniedDecision)


@pytest.mark.asyncio
async def test_unknown_never_reaches_sentinel() -> None:
    unknown = UnknownOutcome(scan_run_id=None, reason_code=ReasonCode.DB_UNAVAILABLE, retry_after_reconciliation=True)
    graph = build_gate_graph(_StubService(unknown))
    _, sentinel = await run_gate(graph, _request())
    assert sentinel == 0


@pytest.mark.asyncio
async def test_replay_receipt_never_reaches_sentinel() -> None:
    replay = AdmissionReplayReceipt(scan_run_id="run-x", stored_status="AUTHORIZED_ADMITTED", audit_event_id="a")
    graph = build_gate_graph(_StubService(replay))
    _, sentinel = await run_gate(graph, _request())
    assert sentinel == 0
