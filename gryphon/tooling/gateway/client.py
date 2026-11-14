"""The client half of the gateway boundary — what the verification layer holds.

The verification process holds one database role and one signing key. It holds
no permit, no resolver, no HTTP client and no socket to any target: its entire
ability to cause traffic is this object, and this object can only ask. Authority
is established on the other side of the socket, per contact, by the component
that actually dispatches (CHG-P5-002).

Two refusals here are deliberately *not* verdicts, and they are not the same
refusal:

* **The gateway cannot be reached.** That is our outage, not the client's
  ambiguity. A pass that published thousands of INCONCLUSIVE verdicts because
  its own dependency was down would be reporting an operational failure as a
  finding about someone else's estate. ``GatewayUnavailable`` is raised and the
  pass blocks (CHG-P5-031).
* **The gateway is reachable but under-featured or speaking another protocol.**
  Then dispatch is refused outright rather than attempted and interpreted.
  Mapping a missing enforcement feature to INCONCLUSIVE would keep the verdicts
  honest while still letting traffic leave through a gateway that is not
  applying the checks the invariants rest on (CHG-P5-034).

The handshake therefore happens on connect, before any request can be sent, and
the negotiated :class:`~gryphon.tooling.gateway.protocol.Welcome` is exposed so
a pass can pin its digest and detect a mid-pass change.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from types import TracebackType
from typing import Protocol

from gryphon.logging_config import get_logger
from gryphon.tooling.gateway.protocol import (
    HANDSHAKE_DEADLINE_SECONDS,
    ByteReader,
    ByteWriter,
    Hello,
    ObserveReply,
    ObserveRequest,
    Welcome,
    assert_compatible,
    read_frame,
    write_frame,
)
from gryphon.verification.constants import GATEWAY_PROTOCOL_VERSION, BlockedReason
from gryphon.verification.reasons import (
    GatewayProtocolError,
    GatewayUnavailable,
    VerificationConfigurationError,
)

logger = get_logger(__name__)

#: Grace added to a request's own deadline before the client stops waiting. The
#: gateway owns the real deadline; this only stops a wedged socket from holding
#: a pass open forever, so it is a margin rather than a competing timeout.
DEFAULT_RESPONSE_MARGIN_SECONDS: float = 15.0

#: Errors that mean the transport failed rather than that the peer misbehaved.
#: ``IncompleteReadError`` is an ``EOFError``: a half-written frame is a
#: connection that went away mid-sentence, not a malformed document.
_TRANSPORT_ERRORS = (OSError, EOFError, TimeoutError)


class StreamConnector(Protocol):
    """Opens one duplex connection to the gateway.

    Injected rather than hard-coded so the client can be exercised against
    in-memory streams: a handshake refusal must be provable without a socket,
    since the property being tested is that *nothing was sent*.
    """

    async def connect(self) -> tuple[ByteReader, ByteWriter]: ...


class UnixSocketConnector:
    """Connects to ``gryphon-gatewayd`` over its Unix socket.

    A Unix socket is the transport because the peer's uid is checkable on the
    kernel's word (``SO_PEERCRED``) rather than on the peer's own claim, and
    because there is no non-local bind to misconfigure.
    """

    def __init__(self, socket_path: str | Path, *, connect_timeout_seconds: float = 5.0) -> None:
        self._path = str(socket_path)
        self._timeout = connect_timeout_seconds

    @property
    def socket_path(self) -> str:
        return self._path

    async def connect(self) -> tuple[ByteReader, ByteWriter]:
        if not hasattr(socket, "AF_UNIX") or not hasattr(asyncio, "open_unix_connection"):
            # Refused loudly rather than degraded to a TCP or in-process path.
            # Both of those would mean the peer-uid check silently stops
            # existing, and a control that disappears on one host is not a
            # control.
            raise VerificationConfigurationError(
                "this host has no AF_UNIX support, so the gateway socket cannot be "
                "reached; run the verification layer on a host that can open "
                f"{self._path}"
            )
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(path=self._path), timeout=self._timeout
        )
        return reader, writer


class GatewayClient:
    """One connection to the gateway service, one request in flight at a time.

    Requests are not pipelined. Replies are correlated to requests by order, and
    a reply whose ``execution_id`` is not the one just asked about is treated as
    a protocol failure rather than matched up: silently accepting a mismatched
    reply would attach one contact's evidence to another contact's verdict.
    """

    def __init__(
        self,
        connector: StreamConnector,
        *,
        client_name: str,
        response_margin_seconds: float = DEFAULT_RESPONSE_MARGIN_SECONDS,
    ) -> None:
        self._connector = connector
        self._client_name = client_name
        self._margin = response_margin_seconds
        self._reader: ByteReader | None = None
        self._writer: ByteWriter | None = None
        self._welcome: Welcome | None = None
        self._lock = asyncio.Lock()

    @classmethod
    def over_unix_socket(
        cls,
        socket_path: str | Path,
        *,
        client_name: str,
        connect_timeout_seconds: float = 5.0,
        response_margin_seconds: float = DEFAULT_RESPONSE_MARGIN_SECONDS,
    ) -> GatewayClient:
        return cls(
            UnixSocketConnector(socket_path, connect_timeout_seconds=connect_timeout_seconds),
            client_name=client_name,
            response_margin_seconds=response_margin_seconds,
        )

    # -- handshake ------------------------------------------------------------
    async def connect(self) -> Welcome:
        """Open the connection and complete the handshake, or refuse.

        Returns the negotiated feature set so the caller can pin its digest for
        the life of the pass.
        """
        if self._welcome is not None:
            return self._welcome

        try:
            reader, writer = await self._connector.connect()
        except _TRANSPORT_ERRORS as exc:
            raise GatewayUnavailable(
                BlockedReason.GATEWAY_UNAVAILABLE,
                f"cannot connect to the gateway: {type(exc).__name__}",
            ) from exc

        try:
            welcome = await asyncio.wait_for(
                self._exchange_hello(reader, writer), timeout=HANDSHAKE_DEADLINE_SECONDS
            )
        except _TRANSPORT_ERRORS as exc:
            await _close(writer)
            raise GatewayUnavailable(
                BlockedReason.GATEWAY_UNAVAILABLE,
                f"the gateway closed during the handshake: {type(exc).__name__}",
            ) from exc
        except GatewayProtocolError:
            # Hold no socket open to a gateway we have just refused to use.
            await _close(writer)
            raise

        self._reader, self._writer, self._welcome = reader, writer, welcome
        logger.info(
            "gateway_handshake_complete",
            protocol_version=welcome.protocol_version,
            feature_count=len(welcome.feature_set),
            welcome_digest=welcome.digest,
        )
        return welcome

    async def _exchange_hello(self, reader: ByteReader, writer: ByteWriter) -> Welcome:
        await write_frame(
            writer,
            Hello(
                protocol_version=GATEWAY_PROTOCOL_VERSION, client_name=self._client_name
            ).as_payload(),
        )
        welcome = Welcome.from_payload(await read_frame(reader))
        assert_compatible(welcome)
        return welcome

    @property
    def welcome(self) -> Welcome:
        """The negotiated feature set. Available only after a successful connect."""
        if self._welcome is None:
            raise GatewayProtocolError("the gateway handshake has not completed")
        return self._welcome

    def assert_pin(self, pinned_digest: str) -> None:
        """Refuse if the gateway is no longer the one this pass pinned.

        A pass cites one gateway configuration in every verdict it writes. If the
        service is redeployed mid-pass with a different extractor set or a
        different binary, the evidence behind the remaining findings would not be
        comparable to the evidence behind the earlier ones, and the pin is what
        makes that visible instead of invisible.
        """
        if self.welcome.digest != pinned_digest:
            raise GatewayProtocolError(
                "the gateway's feature set changed mid-pass; the pinned digest "
                f"{pinned_digest} no longer matches {self.welcome.digest}"
            )

    # -- dispatch -------------------------------------------------------------
    async def observe(self, request: ObserveRequest) -> ObserveReply:
        """Ask the gateway to make one contact and return what it found.

        Outcomes — including every refusal class — come back as a value. The
        only exceptions are the two that must stop the caller rather than inform
        it: an unreachable gateway and an untrustworthy one.
        """
        if self._reader is None or self._writer is None:
            raise GatewayProtocolError("observe() before a completed handshake")
        reader, writer = self._reader, self._writer
        timeout = max(request.deadline_seconds, 0.0) + self._margin

        async with self._lock:
            try:
                await write_frame(writer, request.as_payload())
                payload = await asyncio.wait_for(read_frame(reader), timeout=timeout)
            except _TRANSPORT_ERRORS as exc:
                # The request may already have been dispatched, so this is not a
                # retry: the gateway's durable record is what resolves it.
                await self.close()
                raise GatewayUnavailable(
                    BlockedReason.GATEWAY_UNAVAILABLE,
                    f"the gateway connection failed mid-request: {type(exc).__name__}",
                ) from exc

        reply = ObserveReply.from_payload(payload)
        if reply.execution_id != request.execution_id:
            raise GatewayProtocolError(
                f"reply names execution {reply.execution_id!r}, "
                f"but {request.execution_id!r} was asked about"
            )
        return reply

    # -- lifecycle ------------------------------------------------------------
    async def close(self) -> None:
        writer, self._writer = self._writer, None
        self._reader = None
        self._welcome = None
        if writer is not None:
            await _close(writer)

    async def __aenter__(self) -> GatewayClient:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()


async def _close(writer: ByteWriter) -> None:
    """Close a writer without letting the teardown mask the original failure."""
    try:
        writer.close()
        await writer.wait_closed()
    except _TRANSPORT_ERRORS:  # pragma: no cover - teardown of an already-dead socket
        pass
