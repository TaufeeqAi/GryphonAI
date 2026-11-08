"""Grant-rooted operation capability: mint, verify, consume.

A capability is a single-operation, short-TTL, asymmetrically-signed **reference**
to an authorization admission — it carries digests, never a copy of authority.
The authorized scope is always re-derived from the grant receipt by the gateway
(see ``enforcement/scope_provenance``); a capability can never widen scope.
"""

from __future__ import annotations
