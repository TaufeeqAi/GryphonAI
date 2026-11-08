"""Persistence module (BND-07).

Owns SQLAlchemy models, async session/unit-of-work and domain repositories.
PostgreSQL is the only authoritative durable state; no cache is authoritative
(§13). This package MUST NOT make authorization policy decisions (§29.1).
"""

from __future__ import annotations
