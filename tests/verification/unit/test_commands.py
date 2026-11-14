"""The composition: the parts that are easy to get quietly wrong.

These cover the three translations the commands module owns, each of which has
a plausible wrong version that no other test in the suite would catch:

* the two ``VerdictRecord`` shapes, which share a name and almost nothing else;
* which stored observations may be reused on resume, where the plausible wrong
  version turns a CONFIRMED into an INCONCLUSIVE on a retry;
* which planned contact a gateway reply answers for, where the plausible wrong
  version attaches one contact's evidence to another contact's verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from gryphon.tooling.gateway.protocol import ObserveReply, ObserveRequest
from gryphon.tooling.observation.envelope import http_envelope
from gryphon.tooling.observation.extractors import EXTRACTOR_SET_DIGEST
from gryphon.verification.commands import (
    CLIENT_NAME,
    PassResult,
    _GatewayObservations,
    reconstructed_observation,
    row_verdict,
)
from gryphon.verification.constants import (
    AssertedBy,
    Justification,
    ObservationRole,
    OutcomeClass,
    PassState,
    VerdictStatus,
)
from gryphon.verification.evaluator import Verdict
from gryphon.verification.publish import VerdictRecord as ReportVerdict

pytestmark = pytest.mark.unit


# =============================================================================
# Fakes
# =============================================================================


@dataclass
class _Row:
    """The columns ``reconstructed_observation`` reads, and nothing else."""

    observation_id: str = "obs-1"
    execution_id: str = "exec-1"
    role: str = "primary"
    control_index: int = 0
    outcome_class: str = "FAILED"
    reason_code: str = "ok"
    facts_digest: str | None = None
    peer_address: str | None = "203.0.113.10"


class _FakeClient:
    """A gateway client that records what it was asked and answers from a map."""

    def __init__(self, reply: ObserveReply, *, welcome_digest: str = "pinned") -> None:
        self._reply = reply
        self._welcome_digest = welcome_digest
        self.requests: list[ObserveRequest] = []
        self.pins_asserted: list[str] = []

    def assert_pin(self, pinned_digest: str) -> None:
        self.pins_asserted.append(pinned_digest)
        if pinned_digest != self._welcome_digest:
            raise AssertionError(f"pin {pinned_digest} does not match {self._welcome_digest}")

    async def observe(self, request: ObserveRequest) -> ObserveReply:
        self.requests.append(request)
        return self._reply


def _envelope() -> Any:
    return http_envelope(
        scheme="https",
        host="app.example.test",
        port=443,
        path="/.env",
        method="GET",
        descriptor_version="httpx/1.12.0",
        extractor_set_digest=EXTRACTOR_SET_DIGEST,
    )


# =============================================================================
# The two VerdictRecord shapes
# =============================================================================


def test_the_engines_verdict_becomes_the_rows_verdict() -> None:
    """Every field the row needs comes from the verdict, not from a default."""
    verdict = Verdict(
        status=VerdictStatus.CONFIRMED,
        justification=None,
        verifier_id="exposed_config.dotenv@1",
        rule=3,
        matched_predicates=("body_contains_secret_shape",),
        projection={"aws_access_key_id": 1},
    )
    record = ReportVerdict(
        finding_id="f-1",
        subject_key="subject-1",
        verdict=verdict,
        observed_at=None,
        canonical_target="app.example.test",
        url="https://app.example.test/.env",
    )

    row = row_verdict(record, registry_digest="registry-digest")

    assert row.finding_id == "f-1"
    assert row.subject_key == "subject-1"
    assert row.status is VerdictStatus.CONFIRMED
    assert row.justification is None
    assert row.verifier_id == "exposed_config.dotenv@1"
    assert row.registry_digest == "registry-digest"
    assert row.rule == 3
    assert row.matched_predicates == ("body_contains_secret_shape",)
    assert row.projection == {"aws_access_key_id": 1}
    # Fixed, never inherited: every row this layer writes is a deterministic
    # verifier's claim, and a model's label must not be able to occupy it.
    assert row.asserted_by is AssertedBy.DETERMINISTIC_VERIFIER


def test_the_registry_digest_is_recorded_even_when_no_verifier_ran() -> None:
    """UNSUPPORTED is a statement about a particular registry."""
    verdict = Verdict(
        status=VerdictStatus.UNSUPPORTED,
        justification=Justification.NO_VERIFIER,
        verifier_id=None,
        rule=0,
    )
    record = ReportVerdict(
        finding_id="f-2",
        subject_key="subject-2",
        verdict=verdict,
        observed_at=None,
        canonical_target="app.example.test",
    )

    row = row_verdict(record, registry_digest="registry-digest")

    assert row.verifier_id is None
    assert row.registry_digest == "registry-digest"
    assert row.justification is Justification.NO_VERIFIER


# =============================================================================
# What may be reused on resume
# =============================================================================


def test_a_row_without_facts_is_reusable() -> None:
    """A refusal carried no evidence, so an absence is a faithful rebuild."""
    rebuilt = reconstructed_observation(
        _Row(outcome_class="REFUSED_POLICY", reason_code="destination_denied", facts_digest=None)
    )

    assert rebuilt is not None
    assert rebuilt.observation_id == "obs-1"
    assert rebuilt.execution_id == "exec-1"
    assert rebuilt.outcome is OutcomeClass.REFUSED_POLICY
    assert rebuilt.reason_code == "destination_denied"
    assert rebuilt.facts is None


def test_a_row_that_carried_evidence_is_never_rebuilt() -> None:
    """The decisive one.

    The row keeps a digest of the facts, not the facts. Rebuilding this with
    ``facts=None`` would hand the evaluator an absence where there was a
    measurement — and a resumed pass would downgrade its own CONFIRMED to
    INCONCLUSIVE with nothing in the system explaining the change. Declining to
    rebuild sends the pass back to the gateway, which answers the repeated
    execution from its own record, facts included, without contacting anyone.
    """
    assert reconstructed_observation(_Row(outcome_class="OBSERVED", facts_digest="a" * 64)) is None


def test_the_role_and_control_index_survive_the_rebuild() -> None:
    """A control rebuilt as a primary would be judged as the finding itself."""
    rebuilt = reconstructed_observation(
        _Row(role="control", control_index=2, outcome_class="FAILED", facts_digest=None)
    )

    assert rebuilt is not None
    assert rebuilt.role is ObservationRole.CONTROL
    assert rebuilt.control_index == 2


# =============================================================================
# Which contact a reply answers for
# =============================================================================


async def test_a_reply_is_attached_to_the_planned_contact_not_to_itself() -> None:
    """The observation id comes from the plan, never from the far side."""
    reply = ObserveReply(
        outcome=OutcomeClass.REFUSED_POLICY,
        reason_code="destination_denied",
        execution_id="exec-1",
        facts=None,
        peer_address="203.0.113.10",
    )
    client = _FakeClient(reply)
    port = _GatewayObservations(
        client, pinned_digest="pinned", observation_ids={"exec-1": "planned-observation-1"}
    )

    observation = await port.observe(
        execution_id="exec-1",
        envelope=_envelope(),
        pass_id="pass-1",
        claim_epoch=1,
        cancellation_epoch=0,
        deadline_seconds=20.0,
        scan_run_id="scan-1",
        finding_id="f-1",
        role=ObservationRole.PRIMARY,
        control_index=0,
    )

    assert observation.observation_id == "planned-observation-1"
    assert observation.execution_id == "exec-1"


async def test_every_request_carries_the_pass_the_epoch_and_the_purpose() -> None:
    """The gateway re-decides per request, so each one must stand alone."""
    reply = ObserveReply(
        outcome=OutcomeClass.REFUSED_CAPACITY,
        reason_code="budget_exhausted",
        execution_id="exec-1",
    )
    client = _FakeClient(reply)
    port = _GatewayObservations(
        client, pinned_digest="pinned", observation_ids={"exec-1": "obs-1"}
    )

    await port.observe(
        execution_id="exec-1",
        envelope=_envelope(),
        pass_id="pass-1",
        claim_epoch=4,
        cancellation_epoch=2,
        deadline_seconds=20.0,
        scan_run_id="scan-1",
        finding_id="f-1",
        role=ObservationRole.PRIMARY,
        control_index=0,
    )

    sent = client.requests[0]
    assert sent.purpose == "verification"
    assert sent.pass_id == "pass-1"
    assert sent.claim_epoch == 4
    assert sent.cancellation_epoch == 2
    assert sent.scan_run_id == "scan-1"


async def test_the_pin_is_reasserted_before_every_single_request() -> None:
    """Not once at connect: a gateway can be redeployed mid-pass."""
    reply = ObserveReply(
        outcome=OutcomeClass.REFUSED_CAPACITY,
        reason_code="budget_exhausted",
        execution_id="exec-1",
    )
    client = _FakeClient(reply)
    port = _GatewayObservations(
        client, pinned_digest="pinned", observation_ids={"exec-1": "obs-1"}
    )

    for _ in range(3):
        await port.observe(
            execution_id="exec-1",
            envelope=_envelope(),
            pass_id="pass-1",
            claim_epoch=1,
            cancellation_epoch=0,
            deadline_seconds=20.0,
            scan_run_id="scan-1",
            finding_id="f-1",
            role=ObservationRole.PRIMARY,
            control_index=0,
        )

    assert client.pins_asserted == ["pinned", "pinned", "pinned"]


async def test_a_gateway_that_changed_mid_pass_stops_the_contact() -> None:
    """The refusal happens before the request is written, not after."""
    reply = ObserveReply(
        outcome=OutcomeClass.REFUSED_CAPACITY,
        reason_code="budget_exhausted",
        execution_id="exec-1",
    )
    client = _FakeClient(reply, welcome_digest="a-different-gateway")
    port = _GatewayObservations(
        client, pinned_digest="pinned", observation_ids={"exec-1": "obs-1"}
    )

    with pytest.raises(AssertionError):
        await port.observe(
            execution_id="exec-1",
            envelope=_envelope(),
            pass_id="pass-1",
            claim_epoch=1,
            cancellation_epoch=0,
            deadline_seconds=20.0,
            scan_run_id="scan-1",
            finding_id="f-1",
            role=ObservationRole.PRIMARY,
            control_index=0,
        )

    assert client.requests == []


# =============================================================================
# The printed result
# =============================================================================


def test_a_returned_pass_says_so() -> None:
    """``returned`` is how an operator tells a re-run from a replayed answer."""
    result = PassResult(
        pass_id="pass-1",
        scan_run_id="scan-1",
        state=PassState.COMPLETE,
        resumed=True,
        returned=True,
    )
    payload = result.as_payload()

    assert payload["returned"] is True
    assert payload["state"] == "COMPLETE"


def test_the_client_name_is_what_the_gateway_binds_a_purpose_to() -> None:
    assert CLIENT_NAME == "gryphon-verification"
