"""GRYPHON — Phase 1: Authorization Gate + Core Database.

Phase 1 establishes GRYPHON's authorization root of trust: Ed25519-signed,
scope-bound, time-limited grants; a deterministic scope policy; durable
grant / scan-run / finding records; and an independently-signed, append-only
authorization audit trail.

Controlling principle (contract v1.1.0 §2):

    No protected scanning operation may execute unless a valid grant covers the
    canonical requested target, and the ALLOW decision plus its audit record
    have been durably committed.

This package owns authentication of *grants*, not authentication of *presenters*
(§20). It MUST NOT be exposed as a multi-user remote service.
"""

from __future__ import annotations

__version__ = "1.1.0"
__contract_version__ = "1.1.0"

__all__ = ["__version__", "__contract_version__"]
