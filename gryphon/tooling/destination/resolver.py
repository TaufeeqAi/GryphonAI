"""Async DNS resolution for resolve-then-pin.

Uses the stdlib resolver via the event loop (no extra dependency). Returns the
full resolved address set at bind time; the guard pins it and the egress context
enforces it. A resolution failure denies — it never "tries anyway".
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Protocol, runtime_checkable


@runtime_checkable
class Resolver(Protocol):
    async def resolve(self, host: str) -> list[ipaddress._BaseAddress]: ...


class SystemResolver:
    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
        self._timeout = timeout_seconds

    async def resolve(self, host: str) -> list[ipaddress._BaseAddress]:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
                timeout=self._timeout,
            )
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            return []
        addresses: list[ipaddress._BaseAddress] = []
        seen: set[str] = set()
        for info in infos:
            sockaddr = info[4]
            ip_text = sockaddr[0]
            if ip_text in seen:
                continue
            seen.add(ip_text)
            try:
                addresses.append(ipaddress.ip_address(ip_text))
            except ValueError:
                continue
        return addresses
