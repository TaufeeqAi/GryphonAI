"""Phase 1 graph conformance (§30.4).

A minimal, REAL compiled LangGraph whose only job is to prove the gate contract:
the authorization gate is the entry point, DENY/UNKNOWN/replay route to END with
the sentinel never reached, and only a committed ALLOW reaches a harmless
sentinel. It is not the production pipeline (that is Phase 3) and it performs no
network or tool activity.
"""

from __future__ import annotations
