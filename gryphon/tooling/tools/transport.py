"""Transport posture for the tool host.

This layer authenticates **operations**, not presenters: a capability proves that
*this tool call* was authorized, not that the caller is who they claim. The
transport must therefore not be reachable by anyone the deployment does not
already trust. That is enforced here in code rather than left to a deployment
note:

* :func:`assert_transport_safe` refuses any configuration that would expose the
  host beyond the local machine. ``stdio`` is always safe — there is no listener
  at all, and the only possible caller is the parent process that spawned the
  host and owns its pipes. An HTTP transport is permitted only on a loopback
  address, and a non-loopback bind is refused outright.
* :class:`UnixSocketToolHost` serves MCP over a unix socket and checks the
  connecting process's credentials with ``SO_PEERCRED`` against an allowlist of
  uids, closing anything else before a single byte is read. The socket is created
  with mode ``0600``.

Ordered by strength: ``stdio`` > unix socket + peer uid > loopback HTTP. Prefer
the in-process permit path over any of them when the control plane and the tool
host live in one process — then no credential is serialized at all.
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
from collections.abc import Iterable
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from gryphon.logging_config import get_logger
from gryphon.tooling.reasons import ToolingConfigurationError

logger = get_logger(__name__)

#: Addresses that cannot be reached from another machine.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "localhost6", ""})
#: Transports this layer will serve. ``sse`` is legacy and not offered.
SAFE_TRANSPORTS = frozenset({"stdio", "unix", "http", "streamable-http"})
#: Default permissions for the socket file: owner only.
SOCKET_MODE = 0o600


def assert_transport_safe(transport: str, *, host: str | None = None) -> None:
    """Raise unless this transport/bind cannot be reached off-host.

    Called before the host starts serving. It fails closed: an unknown transport
    or a non-loopback bind is refused rather than warned about.
    """
    if transport not in SAFE_TRANSPORTS:
        raise ToolingConfigurationError(
            f"transport {transport!r} is not offered; use stdio, unix, or loopback http"
        )
    if transport in {"stdio", "unix"}:
        return
    normalized = (host or "").strip().lower()
    if normalized not in LOOPBACK_HOSTS:
        raise ToolingConfigurationError(
            f"refusing to bind the tool host to {host!r}: it authenticates operations, "
            "not callers, and must not be reachable off-host. Use stdio, a unix socket, "
            "or a loopback address."
        )


def peer_uid(sock: socket.socket | None) -> int | None:
    """The uid of the process at the other end of a unix socket, if knowable."""
    if sock is None or not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    except (OSError, AttributeError):
        return None
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


class UnixSocketToolHost:
    """Serve an MCP server over a unix socket, gated on peer credentials.

    ``mcp_server`` is a FastMCP instance. Each accepted connection is bridged to
    the MCP session as newline-delimited JSON-RPC, the same framing the stdio
    transport uses, so no protocol behaviour changes with the transport.
    """

    def __init__(
        self,
        mcp_server: Any,
        socket_path: str | os.PathLike[str],
        *,
        allowed_uids: Iterable[int] | None = None,
        socket_mode: int = SOCKET_MODE,
    ) -> None:
        if os.name != "posix":
            raise ToolingConfigurationError("unix socket transport requires a POSIX host")
        self._mcp = mcp_server
        self._path = Path(socket_path)
        self._allowed = frozenset(allowed_uids) if allowed_uids is not None else None
        self._mode = socket_mode
        self._server: asyncio.AbstractServer | None = None
        self._lifespan: AsyncExitStack | None = None
        self.rejected_connections = 0
        self.accepted_connections = 0

    async def start(self) -> asyncio.AbstractServer:
        assert_transport_safe("unix")
        if self._path.exists():
            # A stale socket from a crashed host must not block a restart, but
            # anything that is not a socket is left alone.
            if self._path.is_socket():
                self._path.unlink()
            else:
                raise ToolingConfigurationError(f"{self._path} exists and is not a socket")
        # A session cannot be served before the server's lifespan is active.
        # This mirrors FastMCP's own transport entry sequence; the wire framing is
        # the stdio framing (newline-delimited JSON-RPC), carried over a socket.
        self._lifespan = AsyncExitStack()
        await self._lifespan.__aenter__()
        try:
            from fastmcp.server.context import reset_transport, set_transport

            token = set_transport("stdio")
            self._lifespan.callback(reset_transport, token)
            await self._lifespan.enter_async_context(self._mcp._lifespan_manager())  # noqa: SLF001
        except Exception:
            await self._lifespan.aclose()
            self._lifespan = None
            raise

        self._server = await asyncio.start_unix_server(self._handle, path=str(self._path))
        os.chmod(self._path, self._mode)
        logger.info(
            "tool_host_listening",
            socket=str(self._path),
            mode=oct(self._mode),
            peer_uid_allowlist=sorted(self._allowed) if self._allowed is not None else "any",
        )
        return self._server

    async def serve_forever(self) -> None:
        server = self._server or await self.start()
        async with server:
            await server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._lifespan is not None:
            await self._lifespan.aclose()
            self._lifespan = None
        if self._path.exists() and self._path.is_socket():
            self._path.unlink()

    # -- connection handling -------------------------------------------------
    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        uid = peer_uid(writer.get_extra_info("socket"))
        if self._allowed is not None and (uid is None or uid not in self._allowed):
            self.rejected_connections += 1
            logger.warning("tool_host_peer_rejected", peer_uid=uid)
            writer.close()
            return
        self.accepted_connections += 1
        logger.info("tool_host_peer_accepted", peer_uid=uid)
        try:
            await self._bridge(reader, writer)
        except (ConnectionResetError, BrokenPipeError):  # pragma: no cover - client vanished
            return
        finally:
            writer.close()

    async def _bridge(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Pump newline-delimited JSON-RPC between the socket and the session."""
        import anyio
        import mcp_types as types
        from mcp.shared.message import SessionMessage

        read_send, read_recv = anyio.create_memory_object_stream(64)
        write_send, write_recv = anyio.create_memory_object_stream(64)

        async def inbound() -> None:
            # Framing and validation are the upstream stdio transport's, so the
            # protocol behaves identically over a socket.
            try:
                async with read_send:
                    while True:
                        line = await reader.readline()
                        if not line:
                            return
                        text = line.strip()
                        if not text:
                            continue
                        try:
                            message = types.jsonrpc_message_adapter.validate_json(
                                text, by_name=False
                            )
                        except Exception as exc:  # noqa: BLE001 - surfaced to the session
                            await read_send.send(exc)
                            continue
                        await read_send.send(SessionMessage(message))
            except anyio.ClosedResourceError:  # pragma: no cover - session ended first
                return

        async def outbound() -> None:
            try:
                async with write_recv:
                    async for session_message in write_recv:
                        payload = session_message.message.model_dump_json(
                            by_alias=True, exclude_unset=True
                        )
                        writer.write(payload.encode("utf-8") + b"\n")
                        await writer.drain()
            except anyio.ClosedResourceError:  # pragma: no cover - session ended first
                return

        server = self._mcp._mcp_server  # noqa: SLF001 - the documented lowlevel server
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(inbound)
            task_group.start_soon(outbound)
            try:
                await server.run(
                    read_recv, write_send, server.create_initialization_options()
                )
            finally:
                task_group.cancel_scope.cancel()
