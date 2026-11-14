"""The gateway service boundary: the tool execution gateway as a principal.

The gateway used to be a library its callers constructed. That meant a caller
had to hold the gateway's database role and the platform audit key — so the
component that writes the ledger also wrote the rows that ledger adjudicates,
and the component that must verify an attestation could also produce one. The
defect was the composition, not the code, and this package closes it: the
gateway runs as a local service with its own uid, role and key, and a caller
holds only a socket.

* :mod:`gryphon.tooling.gateway.protocol` — framing, the four wire messages and
  the feature handshake that decides whether a dispatch may happen at all.
* :mod:`gryphon.tooling.gateway.client` — what the verification layer holds. It
  can ask, and that is all it can do.
* :mod:`gryphon.tooling.gateway.server` — the daemon, and the fixed order in
  which it mediates one contact.

In-process construction survives only as a test double. It is not re-exported
here, because an import that is easy to reach is an import that ends up in a
deployment.
"""

from __future__ import annotations

from gryphon.tooling.gateway.client import GatewayClient, StreamConnector, UnixSocketConnector
from gryphon.tooling.gateway.protocol import (
    MAX_FRAME_BYTES,
    OUTCOME_FOR_REASON,
    FeatureSet,
    GatewayReason,
    Hello,
    ObserveReply,
    ObserveRequest,
    Welcome,
    assert_compatible,
)

__all__ = [
    "MAX_FRAME_BYTES",
    "OUTCOME_FOR_REASON",
    "FeatureSet",
    "GatewayClient",
    "GatewayReason",
    "Hello",
    "ObserveReply",
    "ObserveRequest",
    "StreamConnector",
    "UnixSocketConnector",
    "Welcome",
    "assert_compatible",
]
