"""The client refuses an untrustworthy gateway and blocks on an absent one.

Both properties are about what does *not* happen, so they are asserted against
in-memory streams: the bytes the client wrote are the evidence that no request
was dispatched.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import pytest

from gryphon.tooling.gateway.client import GatewayClient, UnixSocketConnector
from gryphon.tooling.gateway.protocol import (
    FRAME_HEADER_BYTES,
    GatewayReason,
    Hello,
    MessageType,
    ObserveReply,
    ObserveRequest,
    Welcome,
    encode_frame,
)
from gryphon.tooling.observation.envelope import http_envelope
from gryphon.tooling.observation.facts import Completeness
from gryphon.verification.constants import (
    GATEWAY_PROTOCOL_VERSION,
    REQUIRED_GATEWAY_FEATURES,
    BlockedReason,
    ObservationRole,
    OutcomeClass,
)
from gryphon.verification.reasons import (
    GatewayProtocolError,
    GatewayUnavailable,
    VerificationConfigurationError,
)

pytestmark = pytest.mark.unit

_DIGEST = "a" * 64
_EXECUTION_ID = "e" * 32


class FakeReader:
    def __init__(self, data: bytes = b"") -> None:
        self._data = bytearray(data)
        self.position = 0

    async def readexactly(self, n: int) -> bytes:
        chunk = bytes(self._data[self.position : self.position + n])
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

    @property
    def sent(self) -> list[dict[str, Any]]:
        """The frames the client actually put on the wire."""
        return _decode_frames(bytes(self.buffer))


class FakeConnector:
    def __init__(self, reader: FakeReader, writer: FakeWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.attempts = 0

    async def connect(self) -> tuple[FakeReader, FakeWriter]:
        self.attempts += 1
        return self.reader, self.writer


class FailingConnector:
    def __init__(self, error: BaseException) -> None:
        self._error = error

    async def connect(self) -> tuple[FakeReader, FakeWriter]:
        raise self._error


def _decode_frames(buffer: bytes) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    offset = 0
    while offset < len(buffer):
        length = int.from_bytes(buffer[offset : offset + FRAME_HEADER_BYTES], "big")
        offset += FRAME_HEADER_BYTES
        frames.append(json.loads(buffer[offset : offset + length]))
        offset += length
    return frames


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


def _request(execution_id: str = _EXECUTION_ID) -> ObserveRequest:
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
        execution_id=execution_id,
        envelope=envelope.as_canonical(),
        deadline_seconds=20.0,
        scan_run_id="scan-1",
        finding_id="finding-1",
        role=ObservationRole.PRIMARY,
    )


def _client(*frames: bytes) -> tuple[GatewayClient, FakeConnector]:
    connector = FakeConnector(FakeReader(b"".join(frames)), FakeWriter())
    client = GatewayClient(connector, client_name="gryphon-verification")
    return client, connector


# -- the handshake refuses rather than degrades -------------------------------
async def test_a_protocol_mismatch_refuses_and_dispatches_nothing() -> None:
    client, connector = _client(encode_frame(_welcome(protocol_version="99").as_payload()))

    with pytest.raises(GatewayProtocolError, match="99"):
        await client.connect()

    # Exactly one frame left: the hello. No observe request was ever sent.
    assert [frame["message"] for frame in connector.writer.sent] == [MessageType.HELLO.value]
    assert connector.writer.closed


@pytest.mark.parametrize("absent", sorted(REQUIRED_GATEWAY_FEATURES))
async def test_a_missing_security_critical_feature_dispatches_nothing(absent: str) -> None:
    welcome = _welcome(feature_set=frozenset(REQUIRED_GATEWAY_FEATURES - {absent}))
    client, connector = _client(encode_frame(welcome.as_payload()))

    with pytest.raises(GatewayProtocolError, match=absent):
        await client.connect()

    assert len(connector.writer.sent) == 1
    assert connector.writer.closed
    with pytest.raises(GatewayProtocolError, match="has not completed"):
        _ = client.welcome


async def test_a_refused_handshake_leaves_observe_unusable() -> None:
    client, connector = _client(encode_frame(_welcome(protocol_version="99").as_payload()))
    with pytest.raises(GatewayProtocolError):
        await client.connect()

    with pytest.raises(GatewayProtocolError, match="before a completed handshake"):
        await client.observe(_request())
    assert len(connector.writer.sent) == 1


async def test_the_handshake_sends_hello_once_and_exposes_the_pin() -> None:
    welcome = _welcome()
    client, connector = _client(encode_frame(welcome.as_payload()))

    negotiated = await client.connect()

    assert negotiated == welcome
    assert client.welcome.digest == welcome.digest
    assert Hello.from_payload(connector.writer.sent[0]).client_name == "gryphon-verification"
    # Reconnecting does not re-handshake a live connection.
    assert await client.connect() == welcome
    assert connector.attempts == 1


async def test_a_feature_set_change_invalidates_the_pin() -> None:
    client, _ = _client(encode_frame(_welcome().as_payload()))
    welcome = await client.connect()
    client.assert_pin(welcome.digest)

    with pytest.raises(GatewayProtocolError, match="changed mid-pass"):
        client.assert_pin("0" * 64)


# -- an absent gateway blocks a pass; it never becomes a verdict --------------
async def test_a_connect_failure_blocks_the_pass() -> None:
    client = GatewayClient(
        FailingConnector(FileNotFoundError("no socket at /run/gryphon/gatewayd.sock")),
        client_name="gryphon-verification",
    )

    with pytest.raises(GatewayUnavailable) as raised:
        await client.connect()

    assert raised.value.reason is BlockedReason.GATEWAY_UNAVAILABLE
    assert "FileNotFoundError" in raised.value.detail


async def test_a_connect_timeout_blocks_the_pass() -> None:
    client = GatewayClient(
        FailingConnector(TimeoutError()), client_name="gryphon-verification"
    )
    with pytest.raises(GatewayUnavailable) as raised:
        await client.connect()
    assert raised.value.reason is BlockedReason.GATEWAY_UNAVAILABLE


async def test_a_gateway_that_closes_during_the_handshake_blocks_the_pass() -> None:
    client, connector = _client()  # nothing to read

    with pytest.raises(GatewayUnavailable) as raised:
        await client.connect()

    assert raised.value.reason is BlockedReason.GATEWAY_UNAVAILABLE
    assert connector.writer.closed


async def test_a_connection_lost_mid_request_blocks_the_pass() -> None:
    client, connector = _client(encode_frame(_welcome().as_payload()))
    await client.connect()

    with pytest.raises(GatewayUnavailable) as raised:
        await client.observe(_request())

    assert raised.value.reason is BlockedReason.GATEWAY_UNAVAILABLE
    # The request may already have been dispatched, so the client does not retry:
    # the gateway's durable record is what resolves it.
    assert [frame["message"] for frame in connector.writer.sent] == [
        MessageType.HELLO.value,
        MessageType.OBSERVE_REQUEST.value,
    ]
    assert connector.writer.closed


# -- dispatch ------------------------------------------------------------------
async def test_an_observation_round_trips_with_its_completeness() -> None:
    reply = ObserveReply(
        outcome=OutcomeClass.OBSERVED,
        reason_code=GatewayReason.OBSERVED.value,
        execution_id=_EXECUTION_ID,
        facts={
            "observation_schema_version": "1",
            "kind": "http.response.summary",
            "completeness": {"transport_complete": True, "body_complete": True},
            "http": {
                "status_code": 200,
                "status_class": 2,
                "content_type": "text/plain",
                "content_length_header": 120,
                "body_sha256": _DIGEST,
                "header_names": ["content-type"],
                "location_class": "none",
            },
        },
        completeness=Completeness(transport_complete=True, body_complete=True),
        peer_address="203.0.113.7",
    )
    client, connector = _client(
        encode_frame(_welcome().as_payload()), encode_frame(reply.as_payload())
    )
    await client.connect()

    received = await client.observe(_request())

    assert received == reply
    assert received.completeness is not None and received.completeness.is_whole
    typed = received.typed_facts()
    assert typed is not None and typed.http is not None
    assert typed.http.status_code == 200
    assert connector.writer.sent[1]["execution_id"] == _EXECUTION_ID


async def test_a_refusal_comes_back_as_a_value_not_an_exception() -> None:
    reply = ObserveReply(
        outcome=OutcomeClass.REFUSED_POLICY,
        reason_code=GatewayReason.DESTINATION_UNATTESTED.value,
        execution_id=_EXECUTION_ID,
    )
    client, _ = _client(encode_frame(_welcome().as_payload()), encode_frame(reply.as_payload()))
    await client.connect()

    received = await client.observe(_request())

    assert received.outcome is OutcomeClass.REFUSED_POLICY
    assert received.reason_code == "destination_unattested"
    assert received.facts is None


async def test_a_reply_about_another_execution_is_refused() -> None:
    reply = ObserveReply(
        outcome=OutcomeClass.OBSERVED,
        reason_code=GatewayReason.OBSERVED.value,
        execution_id="f" * 32,
    )
    client, _ = _client(encode_frame(_welcome().as_payload()), encode_frame(reply.as_payload()))
    await client.connect()

    with pytest.raises(GatewayProtocolError, match="was asked about"):
        await client.observe(_request())


async def test_close_releases_the_connection() -> None:
    client, connector = _client(encode_frame(_welcome().as_payload()))
    async with client:
        assert client.welcome.protocol_version == GATEWAY_PROTOCOL_VERSION
    assert connector.writer.closed


# -- transport configuration ---------------------------------------------------
async def test_a_host_without_af_unix_is_a_configuration_error_not_a_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(socket, "AF_UNIX", raising=False)
    client = GatewayClient.over_unix_socket(
        "/run/gryphon/gatewayd.sock", client_name="gryphon-verification"
    )

    # Not a GatewayUnavailable: a host that cannot check the peer uid is a
    # deployment to fix, not a dependency to wait for.
    with pytest.raises(VerificationConfigurationError, match="AF_UNIX"):
        await client.connect()


def test_the_connector_records_the_socket_it_was_configured_with() -> None:
    assert UnixSocketConnector("/run/gryphon/gatewayd.sock").socket_path == (
        "/run/gryphon/gatewayd.sock"
    )
