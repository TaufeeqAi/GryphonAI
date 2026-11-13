"""Finding intelligence enrichment.

Turns the *verified* evidence of a finished scan into an explainable, reproducible
priority, using public intelligence acquired **whole** — the CISA KEV catalog and
the FIRST EPSS daily file — plus pinned, offline ATT&CK reference data.

The layer is built around four commitments:

* **Evidence is immutable, and verified before use.** Enrichment never writes the
  evidence or any upstream table. It recomputes the scan report's digest and
  checks the report's attestation signature before deriving anything.
* **The outside world is acquired whole, never queried.** Network access exists
  only in a short-lived subprocess, contained by the OS egress enforcer, which has
  no engagement data, no database and no keys. No outbound request depends on
  what was scanned.
* **A negative needs proof; a failure is staleness, not data.** "Not on KEV" is
  asserted only against an accepted, complete catalog. A failed download writes
  nothing, so knowledge goes stale rather than wrong.
* **Priority is derived, versioned and explained.** A pure function of attributed
  inputs, identified by the digest of its policy, that never lowers a finding below
  its observed severity.

This package deliberately imports nothing from the orchestration package: that
package pulls a graph runtime whose dependency closure includes an HTTP client, and
the enrichment process must contain no HTTP client code. Only
:mod:`gryphon.enrichment.acquisition`, which runs as a separate contained process,
may make a network connection.
"""

from __future__ import annotations
