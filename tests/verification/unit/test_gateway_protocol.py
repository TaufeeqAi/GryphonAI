"""The gateway wire protocol: framing that content cannot steer, and a handshake
that refuses rather than degrades."""

from __future__ import annotations

import asyncio

import pytest

from gryphon.tooling.gateway.protocol import (
    FRAME_HEADER_BYTES,
    MAX_FRAME_BYTES,
    OUTCOME_FOR_REASON,
    FeatureSet,
    GatewayReason,
    Hello,
    ObserveReply,
    ObserveRequest,
    Welcome,
    assert_compatible,
    encode_frame,
    read_frame,
    write_frame,
)
from gryphon.tooling.observation.envelope import dns_envelope, http_envelope
from gryphon.tooling.observation.facts import Completeness
from gryphon.verification.constants import (
    GATEWAY_PROTOCOL_VERSION,
    REQUIRED_GATEWAY_FEATURES,
    ObservationRole,
    OutcomeClass,
    TruncationReason,
)
from gryphon.verification.reasons import GatewayProtocolError

pytestmark = pytest.mark.unit

_DIGEST = "a" * 64


class FakeReader:
    """An in-memory read half. Records how far the reader actually consumed."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.position = 0

    async def readexactly(self, n: int) -> bytes:
        chunk = self._data[self.position : self.position + n]
        if len(chunk) < n:
            self.position = len(self._data)
            raise asyncio.IncompleteReadError(chunk, n)
        self.position += n
        return chunk


class FakeWriter:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _welcome(**overrides: object) -> Welcome:
    fields: dict[str, object] = {
        "protocol_version": GATEWAY_PROTOCOL_VERSION,
        "feature_set": frozenset(REQUIRED_GATEWAY_FEATURES),
        "descriptor_versions": {"http.response.summary": "httpx/1.12.0"},
        "extractor_set_digest": _DIGEST,
        "sanitizer_ruleset_digest": "b" * 64,
        "binary_digests": {"httpx": "c" * 64},
    }
    fields.update(overrides)
    return Welcome(**fields)  # type: ignore[arg-type]


def _request() -> ObserveRequest:
    envelope = http_envelope(
        scheme="https",
        host="app.example.com",
        port=None,
        path="/.env",
        method="GET",
        descriptor_version="httpx/1.12.0",
        extractor_set_digest=_DIGEST,
    )
    return ObserveRequest(
        purpose="verification",
        pass_id="pass-1",
        claim_epoch=4,
        cancellation_epoch=0,
        execution_id="e" * 32,
        envelope=envelope.as_canonical(),
        deadline_seconds=20.0,
        scan_run_id="scan-1",
        finding_id="finding-1",
        role=ObservationRole.PRIMARY,
    )


# -- framing ------------------------------------------------------------------
async def test_every_message_survives_a_framing_round_trip() -> None:
    messages = [
        Hello(protocol_version=GATEWAY_PROTOCOL_VERSION, client_name="gryphon-verification"),
        _welcome(),
        _request(),
        ObserveReply(
            outcome=OutcomeClass.OBSERVED,
            reason_code=GatewayReason.OBSERVED.value,
            execution_id="e" * 32,
            facts={"observation_schema_version": "1", "kind": "dns.answer"},
            completeness=Completeness(transport_complete=True, body_complete=True),
            peer_address="203.0.113.7",
        ),
    ]
    parsers = [Hello, Welcome, ObserveRequest, ObserveReply]

    writer = FakeWriter()
    for message in messages:
        await write_frame(writer, message.as_payload())
    reader = FakeReader(bytes(writer.buffer))

    for message, parser in zip(messages, parsers, strict=True):
        assert parser.from_payload(await read_frame(reader)) == message
    assert reader.position == len(writer.buffer)


async def test_a_newline_in_a_field_does_not_break_the_frame() -> None:
    """Framing must not depend on content: that is why it is length-prefixed."""
    reply = ObserveReply(
        outcome=OutcomeClass.FAILED,
        reason_code="probe_failed\nreason_code=observed",
        execution_id="e" * 32,
    )
    reader = FakeReader(encode_frame(reply.as_payload()))
    assert ObserveReply.from_payload(await read_frame(reader)) == reply


async def test_an_oversize_claim_is_refused_before_the_body_is_read() -> None:
    oversize = (MAX_FRAME_BYTES + 1).to_bytes(FRAME_HEADER_BYTES, "big")
    reader = FakeReader(oversize + b"{}")

    with pytest.raises(GatewayProtocolError, match="exceeds"):
        await read_frame(reader)
    # A peer cannot make this process allocate by asserting a size.
    assert reader.position == FRAME_HEADER_BYTES


async def test_an_empty_frame_is_refused() -> None:
    reader = FakeReader((0).to_bytes(FRAME_HEADER_BYTES, "big"))
    with pytest.raises(GatewayProtocolError, match="empty frame"):
        await read_frame(reader)


def test_an_oversize_payload_is_never_sent() -> None:
    with pytest.raises(GatewayProtocolError, match="refusing to send"):
        encode_frame({"message": "hello", "client_name": "x" * (MAX_FRAME_BYTES + 1)})


async def test_a_duplicate_member_is_refused_rather_than_last_key_wins() -> None:
    body = b'{"message":"hello","protocol_version":"1","client_name":"a","client_name":"b"}'
    reader = FakeReader(len(body).to_bytes(FRAME_HEADER_BYTES, "big") + body)
    with pytest.raises(GatewayProtocolError, match="well-formed"):
        await read_frame(reader)


async def test_a_truncated_frame_surfaces_as_a_transport_failure() -> None:
    """A half-written frame is a connection that went away, not a bad document."""
    frame = encode_frame(_welcome().as_payload())
    reader = FakeReader(frame[: len(frame) // 2])
    with pytest.raises(asyncio.IncompleteReadError):
        await read_frame(reader)


def test_a_frame_read_as_the_wrong_message_is_refused() -> None:
    with pytest.raises(GatewayProtocolError, match="expected a hello frame"):
        Hello.from_payload(_welcome().as_payload())


# -- messages -----------------------------------------------------------------
def test_the_envelope_digest_is_the_envelope_identity() -> None:
    envelope = dns_envelope(
        host="assets.example.com.",
        record_types=("CNAME", "A"),
        descriptor_version="dnsx/1.3.1",
        extractor_set_digest=_DIGEST,
        resolver_set_digest="d" * 64,
    )
    request = ObserveRequest(
        purpose="verification",
        pass_id="pass-1",
        claim_epoch=1,
        cancellation_epoch=0,
        execution_id="f" * 32,
        envelope=envelope.as_canonical(),
        deadline_seconds=10.0,
        scan_run_id="scan-1",
        finding_id="finding-2",
        role=ObservationRole.CONTROL,
        control_index=1,
    )
    assert request.envelope_digest == envelope.digest


def test_an_unknown_role_is_a_protocol_failure() -> None:
    payload = _request().as_payload()
    payload["role"] = "spectator"
    with pytest.raises(GatewayProtocolError, match="observation role"):
        ObserveRequest.from_payload(payload)


def test_a_wrong_purpose_parses_so_the_service_can_refuse_it() -> None:
    """Presenting the wrong purpose is a policy refusal, not a dropped frame."""
    payload = _request().as_payload()
    payload["purpose"] = "scan"
    assert ObserveRequest.from_payload(payload).purpose == "scan"


def test_an_unknown_outcome_class_is_refused() -> None:
    payload = ObserveReply(
        outcome=OutcomeClass.FAILED, reason_code="probe_failed", execution_id="e"
    ).as_payload()
    payload["outcome"] = "PROBABLY_FINE"
    with pytest.raises(GatewayProtocolError, match="outcome class"):
        ObserveReply.from_payload(payload)


def test_completeness_travels_with_the_bound_that_stopped_the_read() -> None:
    reply = ObserveReply(
        outcome=OutcomeClass.OBSERVED,
        reason_code="observed",
        execution_id="e" * 32,
        completeness=Completeness.incomplete(TruncationReason.WIRE_BYTES),
    )
    parsed = ObserveReply.from_payload(ObserveReply.from_payload(reply.as_payload()).as_payload())
    assert parsed.completeness is not None
    assert parsed.completeness.truncation_reason is TruncationReason.WIRE_BYTES
    assert not parsed.completeness.is_whole


# -- the handshake ------------------------------------------------------------
def test_a_complete_feature_set_is_compatible() -> None:
    welcome = _welcome()
    assert welcome.features.satisfied
    assert_compatible(welcome)


@pytest.mark.parametrize("absent", sorted(REQUIRED_GATEWAY_FEATURES))
def test_a_missing_security_critical_feature_refuses_dispatch(absent: str) -> None:
    welcome = _welcome(feature_set=frozenset(REQUIRED_GATEWAY_FEATURES - {absent}))

    assert welcome.features.missing == (absent,)
    with pytest.raises(GatewayProtocolError, match=absent):
        assert_compatible(welcome)


def test_an_extra_feature_is_not_a_mismatch() -> None:
    welcome = _welcome(feature_set=frozenset(REQUIRED_GATEWAY_FEATURES | {"future_thing"}))
    assert_compatible(welcome)


def test_a_protocol_mismatch_refuses_dispatch_and_names_both_versions() -> None:
    welcome = _welcome(protocol_version="99")
    with pytest.raises(GatewayProtocolError) as raised:
        assert_compatible(welcome)
    assert "99" in str(raised.value)
    assert GATEWAY_PROTOCOL_VERSION in str(raised.value)


def test_the_feature_set_names_everything_missing_at_once() -> None:
    features = FeatureSet(frozenset())
    assert set(features.missing) == set(REQUIRED_GATEWAY_FEATURES)
    assert not features.satisfied


def test_the_welcome_digest_changes_with_every_pinned_fact() -> None:
    baseline = _welcome().digest
    assert _welcome(extractor_set_digest="e" * 64).digest != baseline
    assert _welcome(binary_digests={"httpx": "0" * 64}).digest != baseline
    assert _welcome(sanitizer_ruleset_digest="0" * 64).digest != baseline
    assert _welcome(descriptor_versions={"dns.answer": "dnsx/1.3.1"}).digest != baseline
    # Pinning must not depend on how the advertised set happened to be ordered.
    assert _welcome(feature_set=frozenset(sorted(REQUIRED_GATEWAY_FEATURES))).digest == baseline


# -- the refusal classes ------------------------------------------------------
def test_every_reason_maps_to_exactly_one_outcome_class() -> None:
    assert set(OUTCOME_FOR_REASON) == set(GatewayReason)
    assert all(isinstance(outcome, OutcomeClass) for outcome in OUTCOME_FOR_REASON.values())


def test_a_world_fact_is_not_a_refusal() -> None:
    assert OUTCOME_FOR_REASON[GatewayReason.NXDOMAIN] is OutcomeClass.WORLD_FACT
    assert OUTCOME_FOR_REASON[GatewayReason.NO_ANSWER] is OutcomeClass.WORLD_FACT


def test_capacity_and_policy_refusals_stay_apart() -> None:
    assert OUTCOME_FOR_REASON[GatewayReason.SCOPE_EXCLUDED] is OutcomeClass.REFUSED_POLICY
    assert (
        OUTCOME_FOR_REASON[GatewayReason.DEPENDENCY_UNAVAILABLE] is OutcomeClass.REFUSED_CAPACITY
    )
