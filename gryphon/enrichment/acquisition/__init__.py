"""Whole-snapshot acquisition — the only network code in the enrichment layer.

This package runs as a **separate, short-lived subprocess**, launched by the
enrichment process inside the tool-execution layer's OS egress enforcer. It is
given a list of sources, the pinned IPv4 addresses of their hosts, and the
metadata of the last accepted snapshot of each. It holds no database
credentials, no keys and no engagement data, so nothing it sends can depend on
what was scanned: every request fetches a whole published file.

Import discipline: modules here import only the standard library and
:mod:`gryphon.enrichment.constants`. They must never import settings, the
database, the key provider or anything from the enrichment process, so that the
code that parses untrusted provider bytes cannot reach a secret even by mistake.
"""

from __future__ import annotations
