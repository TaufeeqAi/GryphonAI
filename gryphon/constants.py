"""Stable Phase 1 constants: versions, enums and resource bounds.

Every value here is a *contract surface*. The version strings are signed into
grant claims and audit events (§25); the limits are the published Phase 1
request bounds (§21.1). Changing any of these is a compatibility review item,
not an incidental edit.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

# -----------------------------------------------------------------------------
# Compatibility versions (signed / recorded; §25)
# -----------------------------------------------------------------------------
#: Grant claim schema version (claim ``schema_version``).
CLAIMS_SCHEMA_VERSION: Final[str] = "1"
#: Scope canonicalization semantics version (claim ``scope_policy_version``).
SCOPE_POLICY_VERSION: Final[str] = "1"
#: Audit event schema version (covered by the audit signature).
AUDIT_EVENT_SCHEMA_VERSION: Final[str] = "1"
#: Scan-admission request identity schema version (hashed into request_hash).
REQUEST_SCHEMA_VERSION: Final[str] = "1"

#: Supported versions accepted by this build. Unsupported => DENY (§9.2.7).
SUPPORTED_CLAIMS_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1"})
SUPPORTED_SCOPE_POLICY_VERSIONS: Final[frozenset[str]] = frozenset({"1"})

#: Fixed deployment namespace mixed into the idempotency request hash (§17.1).
#: Single-operator / single-database in Phase 1 (§20.3).
DEPLOYMENT_NAMESPACE: Final[str] = "gryphon.phase1.default"

# -----------------------------------------------------------------------------
# JOSE policy (§11.1)
# -----------------------------------------------------------------------------
#: The one and only accepted JWS algorithm. The verifier pins this; a token
#: header can never negotiate a different algorithm (SEC-002 / INV-003).
JWS_ALGORITHM: Final[str] = "EdDSA"
#: Required JOSE ``typ`` header value.
JWS_TYP: Final[str] = "JWT"

# -----------------------------------------------------------------------------
# Temporal policy (§11.2)
# -----------------------------------------------------------------------------
#: Maximum grant lifetime (exp - iat). Forces periodic re-authorization.
MAX_GRANT_LIFETIME_DAYS: Final[int] = 90
MAX_GRANT_LIFETIME_SECONDS: Final[int] = MAX_GRANT_LIFETIME_DAYS * 24 * 60 * 60

# -----------------------------------------------------------------------------
# Phase 1 request bounds (§21.1) — reject, never truncate/repair.
# -----------------------------------------------------------------------------
MAX_JWS_BYTES: Final[int] = 64 * 1024
MAX_SCOPE_ENTRIES: Final[int] = 64
MAX_EXCLUDED_PATHS_PER_ENTRY: Final[int] = 32
MAX_DOMAIN_OCTETS: Final[int] = 253
MAX_HTTP_BODY_BYTES: Final[int] = 96 * 1024
MAX_TARGET_BYTES: Final[int] = 2 * 1024
MAX_PATH_BYTES: Final[int] = 4 * 1024
MAX_WRITTEN_AUTH_REF_BYTES: Final[int] = 1 * 1024
MAX_IDEMPOTENCY_KEY_BYTES: Final[int] = 128
MIN_IDEMPOTENCY_KEY_ENTROPY_BITS: Final[int] = 128
#: Minimum raw idempotency-key length (bytes) that can carry 128 bits of entropy.
MIN_IDEMPOTENCY_KEY_BYTES: Final[int] = 16

#: Strict JSON parser bounds for the decoded token payload.
MAX_JSON_DEPTH: Final[int] = 32
MAX_JSON_MEMBERS: Final[int] = 256

#: Ed25519 raw key sizes (bytes).
ED25519_PRIVATE_KEY_BYTES: Final[int] = 32
ED25519_PUBLIC_KEY_BYTES: Final[int] = 32


class ScanDepth(str, Enum):
    """Permitted scan depth, ordered ``passive < standard < aggressive`` (§11.2).

    Effective depth at admission is ``min(requested, grant.max_scan_depth)`` by
    this explicit ordering. Any value outside this enum fails closed.
    """

    PASSIVE = "passive"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"

    @property
    def rank(self) -> int:
        return _SCAN_DEPTH_RANK[self]

    @classmethod
    def clamp(cls, requested: "ScanDepth", grant_maximum: "ScanDepth") -> "ScanDepth":
        """Return the less-permissive of two depths by explicit ordering."""
        return requested if requested.rank <= grant_maximum.rank else grant_maximum


_SCAN_DEPTH_RANK: Final[dict[ScanDepth, int]] = {
    ScanDepth.PASSIVE: 0,
    ScanDepth.STANDARD: 1,
    ScanDepth.AGGRESSIVE: 2,
}

#: Default requested depth, applied ONLY at the trusted API/CLI adapter when the
#: caller omits it — never via a truthy fallback inside the core service (§11.6).
DEFAULT_REQUESTED_SCAN_DEPTH: Final[ScanDepth] = ScanDepth.STANDARD


class TargetType(str, Enum):
    """Scope-entry target kinds (§11.3). No other kinds are accepted."""

    DOMAIN = "domain"
    DOMAIN_WILDCARD = "domain_wildcard"
    IP = "ip"
    CIDR = "cidr"


class DecisionStatus(str, Enum):
    """Terminal + non-terminal admission outcomes (§11.4)."""

    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


class ScanRunStatus(str, Enum):
    """Persisted scan-run admission status (§14.2 / §22.1).

    Phase 1 persists only terminal admission outcomes. UNKNOWN is never stored
    as success; execution-lifecycle states belong to Phase 3.
    """

    AUTHORIZED_ADMITTED = "AUTHORIZED_ADMITTED"
    DENIED_AUDITED = "DENIED_AUDITED"


# -----------------------------------------------------------------------------
# Finding enumerations (master-plan schema; §22.1). Validated at the domain
# boundary; Phase 1 does not produce findings, only persists the schema.
# -----------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"


class RemediationStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class AuditEventType(str, Enum):
    """Audit event kinds (§22.1)."""

    SCAN_ADMISSION = "scan_admission"
    GRANT_ISSUANCE = "grant_issuance"
