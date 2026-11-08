"""The tool host must not be reachable by anyone the deployment does not trust.

The bind-gate tests run anywhere. The unix-socket tests require POSIX and are
skipped on Windows. Nothing here opens a network socket: the only listener is a
unix socket inside a temporary directory.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat

import pytest

from gryphon.tooling.reasons import ToolingConfigurationError
from gryphon.tooling.tools.transport import (
    SOCKET_MODE,
    UnixSocketToolHost,
    assert_transport_safe,
)

pytestmark = pytest.mark.security

requires_posix = pytest.mark.skipif(
    os.name != "posix", reason="unix domain sockets and SO_PEERCRED are POSIX-only"
)


# =============================================================================
# The bind gate — enforced in code, not left to a deployment note
# =============================================================================
def test_stdio_and_unix_are_always_safe() -> None:
    assert_transport_safe("stdio")
    assert_transport_safe("unix")


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_http_is_allowed_on_loopback(host: str) -> None:
    assert_transport_safe("http", host=host)
    assert_transport_safe("streamable-http", host=host)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "tools.internal.example", "::"])
def test_a_non_loopback_bind_is_refused(host: str) -> None:
    with pytest.raises(ToolingConfigurationError, match="refusing to bind"):
        assert_transport_safe("http", host=host)


def test_an_unoffered_transport_is_refused() -> None:
    # Legacy SSE and anything unrecognised fail closed rather than being served.
    for transport in ("sse", "websocket", "tcp", ""):
        with pytest.raises(ToolingConfigurationError):
            assert_transport_safe(transport, host="127.0.0.1")


@pytest.mark.skipif(os.name == "posix", reason="Windows-only behaviour")
def test_unix_host_refuses_to_construct_on_windows(tmp_path) -> None:
    with pytest.raises(ToolingConfigurationError, match="POSIX"):
        UnixSocketToolHost(object(), tmp_path / "s.sock")


# =============================================================================
# The unix socket host
# =============================================================================
def _service_stub():
    """A minimal object the FastMCP host can be built against."""
    from gryphon.tooling.tools.host import build_tool_host

    class _NeverCalled:
        async def execute_with_capability(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("no tool call is made in a transport test")

    return build_tool_host(_NeverCalled())


@requires_posix
async def test_socket_is_created_owner_only(tmp_path) -> None:
    host = UnixSocketToolHost(_service_stub(), tmp_path / "gryphon.sock")
    await host.start()
    try:
        mode = stat.S_IMODE(os.stat(tmp_path / "gryphon.sock").st_mode)
        assert mode == SOCKET_MODE, oct(mode)
    finally:
        await host.close()
    assert not (tmp_path / "gryphon.sock").exists()


@requires_posix
async def test_a_peer_outside_the_uid_allowlist_is_closed_unread(tmp_path) -> None:
    path = tmp_path / "gated.sock"
    # Allow a uid this process cannot have, so our own connection is refused.
    host = UnixSocketToolHost(_service_stub(), path, allowed_uids={os.getuid() + 4242})
    await host.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(path))
        writer.write(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
        await writer.drain()
        # The host closes before reading. Depending on whether unread bytes are
        # pending, the client observes a clean EOF or a reset -- both are a
        # refusal, and neither carries a response.
        try:
            answer = await asyncio.wait_for(reader.read(), timeout=5)
        except (ConnectionResetError, BrokenPipeError):
            answer = b""
        assert answer == b"", "the host must not answer an unauthorized peer"
        writer.close()
        assert host.rejected_connections == 1
        assert host.accepted_connections == 0
    finally:
        await host.close()


@requires_posix
async def test_an_allowed_peer_completes_an_mcp_session(tmp_path) -> None:
    """End-to-end over the socket: handshake, then the seven tools are listed."""
    from mcp_types import LATEST_PROTOCOL_VERSION

    path = tmp_path / "allowed.sock"
    host = UnixSocketToolHost(_service_stub(), path, allowed_uids={os.getuid()})
    await host.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(path))

        async def send(payload: dict) -> None:
            writer.write(json.dumps(payload).encode() + b"\n")
            await writer.drain()

        async def receive() -> dict:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            assert line, "the host closed the connection"
            return json.loads(line)

        await send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": LATEST_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "gryphon-transport-test", "version": "1"},
                },
            }
        )
        initialized = await receive()
        assert initialized["id"] == 1
        assert "result" in initialized, initialized

        await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        await send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        listed = await receive()
        names = sorted(tool["name"] for tool in listed["result"]["tools"])
        assert len(names) == 7, names
        assert "nuclei_scan" in names

        writer.close()
        assert host.accepted_connections == 1
        assert host.rejected_connections == 0
    finally:
        await host.close()


@requires_posix
async def test_a_stale_socket_file_does_not_block_a_restart(tmp_path) -> None:
    path = tmp_path / "stale.sock"
    first = UnixSocketToolHost(_service_stub(), path)
    await first.start()
    # Simulate a crash: the server is dropped without unlinking the socket.
    first._server.close()  # noqa: SLF001 - simulating an unclean exit
    await first._server.wait_closed()  # noqa: SLF001
    first._server = None  # noqa: SLF001
    assert path.exists()

    second = UnixSocketToolHost(_service_stub(), path)
    await second.start()
    try:
        assert path.is_socket()
    finally:
        await second.close()


@requires_posix
async def test_a_non_socket_file_is_never_unlinked(tmp_path) -> None:
    path = tmp_path / "important.txt"
    path.write_text("not a socket", encoding="utf-8")
    host = UnixSocketToolHost(_service_stub(), path)
    with pytest.raises(ToolingConfigurationError, match="not a socket"):
        await host.start()
    assert path.read_text(encoding="utf-8") == "not a socket"
