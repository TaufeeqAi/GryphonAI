"""Errors raised by the enrichment layer.

Refusals and abandonments are *outcomes*, recorded and audited — not exceptions.
The exceptions here are for conditions that must stop the process: configuration
that would weaken a control, a fenced-out writer, or an integrity conflict.
"""

from __future__ import annotations


class EnrichmentError(Exception):
    """Base class for enrichment errors."""


class EnrichmentConfigurationError(EnrichmentError):
    """Configuration that would weaken a control. Refused at startup."""


class FencedOut(EnrichmentError):
    """A newer holder owns the pass; this process must stop writing."""


class SlotBusy(EnrichmentError):
    """Another live pass or refresh holds the system-wide enrichment slot."""

    def __init__(self, holder: str | None, lease_expires_at: object | None) -> None:
        self.holder = holder
        self.lease_expires_at = lease_expires_at
        super().__init__(
            f"the enrichment slot is held by {holder or 'another process'}"
            + (f" until {lease_expires_at}" if lease_expires_at else "")
        )


class InvalidScanId(EnrichmentError):
    """The scan identifier is not a well-formed scan run id."""


class IdentityConflictError(EnrichmentError):
    """A keyed row already exists with different content.

    Raised when an idempotent insert conflicts and the read-back shows a
    different payload. The pass cannot complete: two writers disagree about the
    same identity, which is an integrity failure, not a retry.
    """


class ArtifactIntegrityError(EnrichmentError):
    """A stored or received artifact does not match its recorded digest or format."""


class CallerRejected(EnrichmentError):
    """The invoking user is not permitted to run enrichment."""
