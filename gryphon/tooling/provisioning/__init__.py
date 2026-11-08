"""Pinned-binary provisioning and readiness.

Binaries are obtained as publisher-signed release artifacts (or a reproducible
build) and verified against published checksums; ``@latest`` is never used in a
release. The manifest is the source of truth for what will run; binaries are
resolved from it, never from ambient ``PATH``.
"""

from __future__ import annotations
