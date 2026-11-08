"""GRYPHON authorization domain.

Dependency direction (contract §29.1): this package owns grant claims, scope
policy, token crypto adapter, key resolution, audit signing, issuance and the
single authorization/admission decision. It MUST NOT depend on FastAPI,
LangGraph, MCP tooling or scanner execution.
"""

from __future__ import annotations
