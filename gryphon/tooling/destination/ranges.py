"""Address-range classification for destination denial.

Default-deny is enforced by the OS egress allowlist; this module is the
application-layer pre-check that refuses to pin a private/loopback/link-local/
CGNAT/multicast/reserved/metadata address in the first place. It is pure.
"""

from __future__ import annotations

import ipaddress

# Explicit cloud-metadata addresses (also covered by link-local/ULA, listed for clarity).
_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
        ipaddress.ip_address("100.100.100.200"),  # Alibaba
    }
)

# IPv4 carrier-grade NAT (RFC 6598).
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def classify(addr: ipaddress._BaseAddress) -> str:
    """Return a stable category string for observability."""
    if addr in _METADATA_ADDRESSES:
        return "metadata"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.version == 4 and addr in _CGNAT_V4:
        return "cgnat"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"
    return "public"


def is_denied(addr: ipaddress._BaseAddress) -> bool:
    """True iff an address must never be a pinned destination."""
    return classify(addr) != "public"
