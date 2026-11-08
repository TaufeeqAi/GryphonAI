"""Destination containment: resolve-then-pin + OS default-deny egress.

A hostname's scope membership never implies its resolved address is permitted.
Every active execution resolves its target, pins the resolved addresses, denies
private/loopback/link-local/CGNAT/metadata ranges, and runs inside an OS egress
context whose allowlist is exactly the pinned addresses — so a re-resolving or
raw-packet tool cannot reach anything else. Fail closed if the context cannot be
established.
"""

from __future__ import annotations
