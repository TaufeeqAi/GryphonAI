"""Destination Guard — resolve, pin, deny, and validate redirects.

Produces the pinned address set that becomes the OS egress allowlist. It is the
single accountable owner of the destination invariant at the application layer;
the egress context is the enforcing mechanism.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from gryphon.auth.scope import CanonicalTarget
from gryphon.constants import TargetType
from gryphon.logging_config import get_logger
from gryphon.tooling.destination.ranges import classify, is_denied
from gryphon.tooling.destination.resolver import Resolver
from gryphon.tooling.reasons import ToolReasonCode

logger = get_logger(__name__)


@dataclass(frozen=True)
class PinnedDestinations:
    target: str
    addresses: tuple[str, ...]
    ports: tuple[int, ...]


@dataclass(frozen=True)
class DestinationDenied:
    reason_code: ToolReasonCode
    detail: str = ""


class DestinationGuard:
    def __init__(self, resolver: Resolver) -> None:
        self._resolver = resolver

    async def bind(
        self, canonical_target: CanonicalTarget, ports: tuple[int, ...]
    ) -> PinnedDestinations | DestinationDenied:
        """Resolve + pin the target; deny any non-public resolved address."""
        if canonical_target.kind is TargetType.IP and canonical_target.ip is not None:
            candidates = [canonical_target.ip]
        else:
            candidates = await self._resolver.resolve(canonical_target.text)
            if not candidates:
                return DestinationDenied(
                    ToolReasonCode.DESTINATION_UNRESOLVABLE, "target did not resolve"
                )

        pinned: list[str] = []
        for addr in candidates:
            if is_denied(addr):
                return DestinationDenied(
                    ToolReasonCode.DESTINATION_DENIED,
                    f"resolved address is {classify(addr)}",
                )
            pinned.append(str(addr))

        if not pinned:
            return DestinationDenied(ToolReasonCode.DESTINATION_UNRESOLVABLE, "no usable address")

        return PinnedDestinations(
            target=canonical_target.text, addresses=tuple(sorted(set(pinned))), ports=ports
        )

    def validate_redirect(self, destination_ip: str, pinned: PinnedDestinations) -> bool:
        """A redirect/connection destination must be within the pinned set.

        Strict membership is intentional: a redirect to any address outside the
        pinned allowlist is treated as an escape and denied (fail closed).
        """
        try:
            addr = ipaddress.ip_address(destination_ip)
        except ValueError:
            return False
        if is_denied(addr):
            return False
        return str(addr) in pinned.addresses
