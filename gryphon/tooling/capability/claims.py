"""Operation-capability claim model and domain types.

The capability is a flat signed object. Its ``binding`` is an Ed25519 signature
over the RFC 8785 (JCS) canonical serialization of every other field; any field
mutation invalidates it. The claims carry only *references* — ``scan_run_id``,
``grant_id``, ``claims_digest``, ``scope_digest`` — never a scope list used as
authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from gryphon.constants import ScanDepth
from gryphon.tooling.constants import (
    CAPABILITY_ALGORITHM,
    CAPABILITY_SCHEMA_VERSION,
    ToolId,
)

_VERIFIED_GUARD = object()


class CapabilityClaims(BaseModel):
    """The signed claim set (everything except the binding). Immutable, strict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability_schema_version: str = Field(min_length=1)
    algorithm: str = Field(min_length=1)
    capability_id: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    kid: str = Field(min_length=1)

    scan_run_id: str = Field(min_length=1)
    grant_id: str = Field(min_length=1)
    claims_digest: str = Field(min_length=1)
    scope_digest: str = Field(min_length=1)

    tool_id: ToolId
    effective_scan_depth: ScanDepth
    execution_id: str = Field(min_length=1)

    iat: int = Field(ge=0)
    exp: int = Field(gt=0)

    def to_canonical_payload(self) -> dict[str, Any]:
        """Plain dict for JCS canonicalization (deterministic, enums as values)."""
        return {
            "capability_schema_version": self.capability_schema_version,
            "algorithm": self.algorithm,
            "capability_id": self.capability_id,
            "nonce": self.nonce,
            "kid": self.kid,
            "scan_run_id": self.scan_run_id,
            "grant_id": self.grant_id,
            "claims_digest": self.claims_digest,
            "scope_digest": self.scope_digest,
            "tool_id": self.tool_id.value,
            "effective_scan_depth": self.effective_scan_depth.value,
            "execution_id": self.execution_id,
            "iat": self.iat,
            "exp": self.exp,
        }


@dataclass(frozen=True)
class OperationCapability:
    """A minted, signed capability held in-process by issuer and caller."""

    claims: CapabilityClaims
    binding: str  # base64 Ed25519 signature over JCS(claims)

    def to_wire(self) -> dict[str, Any]:
        """Serialize to the flat wire object (claims fields + ``binding``)."""
        return {**self.claims.to_canonical_payload(), "binding": self.binding}

    @property
    def capability_id(self) -> str:
        return self.claims.capability_id

    @property
    def nonce(self) -> str:
        return self.claims.nonce


@dataclass(frozen=True)
class VerifiedCapability:
    """Authenticated capability. Mintable only by :class:`CapabilityVerifier`."""

    claims: CapabilityClaims
    _guard: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._guard is not _VERIFIED_GUARD:
            raise TypeError("VerifiedCapability cannot be constructed directly")


def build_claims(
    *,
    capability_id: str,
    nonce: str,
    kid: str,
    scan_run_id: str,
    grant_id: str,
    claims_digest: str,
    scope_digest: str,
    tool_id: ToolId,
    effective_scan_depth: ScanDepth,
    execution_id: str,
    iat: int,
    exp: int,
) -> CapabilityClaims:
    """Construct canonical claims with the pinned schema/algorithm."""
    return CapabilityClaims(
        capability_schema_version=CAPABILITY_SCHEMA_VERSION,
        algorithm=CAPABILITY_ALGORITHM,
        capability_id=capability_id,
        nonce=nonce,
        kid=kid,
        scan_run_id=scan_run_id,
        grant_id=grant_id,
        claims_digest=claims_digest,
        scope_digest=scope_digest,
        tool_id=tool_id,
        effective_scan_depth=effective_scan_depth,
        execution_id=execution_id,
        iat=iat,
        exp=exp,
    )


def make_verified(claims: CapabilityClaims) -> VerifiedCapability:
    """Internal factory used only by the verifier."""
    return VerifiedCapability(claims=claims, _guard=_VERIFIED_GUARD)
