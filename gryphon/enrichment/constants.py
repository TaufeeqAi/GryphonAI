"""Enumerations and fixed bounds for the enrichment layer.

Values that carry security meaning — the egress host list, the size caps, the
acceptance ratios — are code constants. Settings may *narrow* them (fewer hosts,
shorter maximum ages); nothing a deployment configures can widen them.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Final


class Source(StrEnum):
    """Where an assertion's value came from."""

    KEV = "KEV"
    EPSS = "EPSS"
    CVSS_TEMPLATE = "CVSS_TEMPLATE"
    ATTACK_CTID = "ATTACK_CTID"


#: Sources acquired over the network, as whole published snapshots.
NETWORK_SOURCES: Final[tuple[Source, ...]] = (Source.KEV, Source.EPSS)
#: Every source a pass plans for each finding, in a fixed order.
ALL_SOURCES: Final[tuple[Source, ...]] = (
    Source.KEV,
    Source.EPSS,
    Source.CVSS_TEMPLATE,
    Source.ATTACK_CTID,
)


class AssertionStatus(StrEnum):
    """The only three answers a source can give. There is no "zero" answer."""

    ENRICHED = "ENRICHED"
    #: Proven absent: valid only against an accepted, complete snapshot or a
    #: pinned dataset, which the reason names.
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"


class UnavailableReason(StrEnum):
    NO_ACCEPTED_SNAPSHOT = "no_accepted_snapshot"
    INTEGRITY_HOLD = "integrity_hold"
    DATASET_UNAVAILABLE = "dataset_unavailable"
    SNAPSHOT_REVOKED = "snapshot_revoked"
    SCHEMA_UNSUPPORTED = "schema_unsupported"


class RemediationClass(StrEnum):
    """What an operator should do about a failure — the first discriminator."""

    TRANSIENT = "TRANSIENT"
    CAPACITY = "CAPACITY"
    INTEGRITY = "INTEGRITY"
    INCOMPATIBLE = "INCOMPATIBLE"
    MISCONFIGURED = "MISCONFIGURED"
    STALE = "STALE"


#: Reasons for which an assertion may carry no snapshot id (database CHECK).
SNAPSHOTLESS_REASONS: Final[frozenset[str]] = frozenset(
    {UnavailableReason.NO_ACCEPTED_SNAPSHOT.value, UnavailableReason.DATASET_UNAVAILABLE.value}
)


class AssertedBy(StrEnum):
    """Who asserted a value. Template intelligence is never provider truth."""

    PROVIDER_SNAPSHOT = "provider_snapshot"
    TEMPLATE = "template"
    REFERENCE_DATASET = "reference_dataset"


class PassState(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    REFUSED = "REFUSED"
    ABANDONED = "ABANDONED"


TERMINAL_PASS_STATES: Final[frozenset[PassState]] = frozenset(
    {PassState.COMPLETE, PassState.REFUSED, PassState.ABANDONED}
)


class PassOutcome(StrEnum):
    """Outcome of a COMPLETE pass."""

    ENRICHED = "ENRICHED"
    #: Every source usable, but at least one past its maximum age.
    ENRICHED_STALE = "ENRICHED_STALE"
    #: At least one (finding, source) pair is UNAVAILABLE.
    ENRICHMENT_DEGRADED = "ENRICHMENT_DEGRADED"
    NOTHING_TO_ENRICH = "NOTHING_TO_ENRICH"


class RefusalReason(StrEnum):
    REPORT_UNVERIFIED = "report_unverified"
    REPORT_SCHEMA_UNSUPPORTED = "report_schema_unsupported"
    SCAN_NOT_TERMINAL = "scan_not_terminal"
    SCAN_INTEGRITY_FAILED = "scan_integrity_failed"
    GRANT_SIGNER_UNTRUSTED = "grant_signer_untrusted"
    CALLER_REJECTED = "caller_rejected"


class AbandonReason(StrEnum):
    PINS_UNAVAILABLE = "pins_unavailable"
    OPERATOR_ABORT = "operator_abort"


class EnrichmentEventType(StrEnum):
    PASS_REFUSED = "pass_refused"  # noqa: S105 - an event name, not a secret
    PASS_ABANDONED = "pass_abandoned"  # noqa: S105 - an event name, not a secret
    SNAPSHOT_ACCEPTED = "snapshot_accepted"
    SNAPSHOT_REVOKED = "snapshot_revoked"
    ENRICHMENT_REPORT_EMITTED = "enrichment_report_emitted"


class AttemptResult(StrEnum):
    """Outcome of one acquisition attempt for one source."""

    ACCEPTED = "ACCEPTED"
    #: The download matched the newest accepted snapshot byte for byte; the
    #: snapshot's freshness is re-confirmed and nothing new is written.
    UNCHANGED = "UNCHANGED"
    REJECTED = "REJECTED"


class Severity(IntEnum):
    """Ordinal priority scale. An unrecognized label orders as LOW."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str | None) -> tuple[Severity, bool]:
        """Return (severity, recognized). Never raises."""
        if raw is None:
            return cls.LOW, False
        try:
            return cls[str(raw).strip().upper()], True
        except KeyError:
            return cls.LOW, False


# -- egress (code constants; settings may only narrow) -----------------------
KEV_HOST: Final[str] = "www.cisa.gov"
KEV_PATH: Final[str] = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_HOST: Final[str] = "epss.empiricalsecurity.com"
#: The dated daily file. Requesting it by date means no redirect is ever needed.
EPSS_PATH_TEMPLATE: Final[str] = "/epss_scores-{date}.csv.gz"
ALLOWED_HOSTS: Final[frozenset[str]] = frozenset({KEV_HOST, EPSS_HOST})
HOST_FOR_SOURCE: Final[dict[Source, str]] = {Source.KEV: KEV_HOST, Source.EPSS: EPSS_HOST}
HTTPS_PORT: Final[int] = 443

# -- acceptance bounds --------------------------------------------------------
KEV_MAX_BYTES: Final[int] = 64 * 1024 * 1024
#: A new catalog may shrink by at most 2% against the last accepted one.
KEV_MIN_COUNT_RATIO: Final[float] = 0.98
#: Absolute floor: the catalog has listed well over a thousand CVEs for years.
KEV_MIN_COUNT: Final[int] = 1_000
#: Size growth bound against the last accepted catalog.
KEV_MAX_GROWTH_FACTOR: Final[int] = 4
#: A CVE removed from the catalog is held as an integrity question for this long.
KEV_REMOVAL_HOLD_DAYS: Final[int] = 7

EPSS_MAX_COMPRESSED_BYTES: Final[int] = 32 * 1024 * 1024
EPSS_MAX_DECOMPRESSED_BYTES: Final[int] = 256 * 1024 * 1024
EPSS_MIN_ROW_RATIO: Final[float] = 0.95
#: A sanity floor, chosen well below the size of the published file.
EPSS_MIN_ROWS: Final[int] = 100_000
EPSS_COLUMNS: Final[tuple[str, ...]] = ("cve", "epss", "percentile")

#: CISA's published schema for a catalog entry's ``cveID``.
KEV_CVE_PATTERN: Final[str] = r"^CVE-[0-9]{4}-[0-9]{4,19}$"

# -- extraction ---------------------------------------------------------------
#: CVE subjects extracted from evidence: canonical form, bounded sequence length.
EXTRACTED_CVE_PATTERN: Final[str] = r"^CVE-(1999|20[0-9]{2})-[0-9]{4,7}$"
MAX_CVES_PER_FINDING: Final[int] = 32
MAX_CVES_PER_PASS: Final[int] = 5_000
EXTRACTION_RULES_VERSION: Final[str] = "1"

# -- versions -----------------------------------------------------------------
ENRICHMENT_REPORT_SCHEMA_VERSION: Final[str] = "1"
ENRICHMENT_AUDIT_EVENT_SCHEMA_VERSION: Final[str] = "1"
VALUE_SCHEMA_VERSION: Final[str] = "1"
NORMALIZED_FORMAT_VERSION: Final[str] = "1"
ENRICHMENT_CODE_VERSION: Final[str] = "1.1.0"

# -- the upstream report this layer consumes (read-only) ----------------------
#: Orchestration audit event that attests a scan report's digest.
BASE_REPORT_EVENT_TYPE: Final[str] = "report_emitted"
SUPPORTED_BASE_REPORT_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1"})
#: A scan that failed on integrity is never enriched. The report's
#: ``integrity.failed`` flag is authoritative; these reason codes are checked too.
INTEGRITY_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {"SCAN_INTEGRITY_FAILURE", "SCOPE_DISAGREEMENT"}
)
#: Upstream lifecycle states an operator decision or reconciliation moves onward.
NON_TERMINAL_SCAN_STATES: Final[frozenset[str]] = frozenset(
    {"RUNNING", "RECONCILING", "HALTED_FOR_REVIEW"}
)

# -- identity -----------------------------------------------------------------
ENRICHMENT_SLOT_ID: Final[str] = "global"
DATABASE_ROLE: Final[str] = "gryphon_enrichment"
