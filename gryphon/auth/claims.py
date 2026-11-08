"""Grant claim domain model and issuance request (§11.1-2).

These are the *domain* types for grant claims — distinct from the JWS wire form
and from the ORM row. Cross-field invariants (``exp > iat``, ``nbf <= exp``,
positive duration, 90-day maximum, timezone-aware instants) are enforced here
with Pydantic model validation (SEC-005 / INV-005/006).

The JWS payload carries temporal claims as integer NumericDate seconds and scope
as canonical dicts without the local ``entry_id`` — so issuance is deterministic
and reproducible for response-loss recovery (§17.2 / §23.2).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gryphon.auth.scope import ScopeEntry
from gryphon.clock import ensure_utc
from gryphon.constants import (
    MAX_GRANT_LIFETIME_SECONDS,
    MAX_SCOPE_ENTRIES,
    MAX_WRITTEN_AUTH_REF_BYTES,
    ScanDepth,
)
from gryphon.errors import ReasonCode, ValidationError


def _require_aware(value: datetime, field_name: str) -> datetime:
    try:
        return ensure_utc(value)
    except ValueError as exc:
        raise ValidationError(
            ReasonCode.CLAIMS_INVALID, f"{field_name} must be timezone-aware UTC"
        ) from exc


class GrantClaims(BaseModel):
    """The signed claim set (§11.1). Immutable once constructed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iss: str = Field(min_length=1)
    aud: str = Field(min_length=1)
    iat: datetime
    nbf: datetime
    exp: datetime
    jti: str = Field(min_length=1)
    grant_id: str = Field(min_length=1)
    granted_by: str = Field(min_length=1)
    granted_to: str = Field(min_length=1)
    organization: str = Field(min_length=1)
    scope: tuple[ScopeEntry, ...]
    max_scan_depth: ScanDepth
    written_authorization_ref: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    scope_policy_version: str = Field(min_length=1)

    @field_validator("iat", "nbf", "exp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return _require_aware(value, "temporal claim")

    @field_validator("scope", mode="before")
    @classmethod
    def _coerce_scope(cls, value: Any) -> tuple[Any, ...]:
        if isinstance(value, (list, tuple)):
            return tuple(value)
        raise ValidationError(ReasonCode.CLAIMS_INVALID, "scope must be a list")

    @model_validator(mode="after")
    def _validate(self) -> "GrantClaims":
        if not self.scope:
            raise ValidationError(ReasonCode.CLAIMS_INVALID, "scope must contain at least one entry")
        if len(self.scope) > MAX_SCOPE_ENTRIES:
            raise ValidationError(ReasonCode.CLAIMS_INVALID, "too many scope entries")
        if len(self.written_authorization_ref.encode("utf-8")) > MAX_WRITTEN_AUTH_REF_BYTES:
            raise ValidationError(ReasonCode.CLAIMS_INVALID, "written_authorization_ref too long")

        duration = (self.exp - self.iat).total_seconds()
        if duration <= 0:
            raise ValidationError(
                ReasonCode.GRANT_LIFETIME_INVALID, "exp must be strictly greater than iat"
            )
        if duration > MAX_GRANT_LIFETIME_SECONDS:
            raise ValidationError(
                ReasonCode.GRANT_LIFETIME_INVALID, "grant lifetime exceeds 90 days"
            )
        if self.nbf > self.exp:
            raise ValidationError(ReasonCode.GRANT_LIFETIME_INVALID, "nbf must not exceed exp")
        return self

    def to_jws_payload(self) -> dict[str, Any]:
        """Serialize to the canonical JWS payload dict (NumericDate seconds)."""
        return {
            "iss": self.iss,
            "aud": self.aud,
            "iat": int(self.iat.timestamp()),
            "nbf": int(self.nbf.timestamp()),
            "exp": int(self.exp.timestamp()),
            "jti": self.jti,
            "grant_id": self.grant_id,
            "granted_by": self.granted_by,
            "granted_to": self.granted_to,
            "organization": self.organization,
            "scope": [entry.canonical_dict() for entry in self.scope],
            "max_scan_depth": self.max_scan_depth.value,
            "written_authorization_ref": self.written_authorization_ref,
            "schema_version": self.schema_version,
            "scope_policy_version": self.scope_policy_version,
        }

    @classmethod
    def from_jws_payload(cls, payload: dict[str, Any]) -> "GrantClaims":
        """Parse a decoded JWS payload dict into validated claims.

        Raises :class:`ValidationError` with a stable reason code on any
        structural or cross-field failure.
        """
        try:
            return cls.model_validate(payload)
        except ValidationError:
            raise
        except Exception as exc:  # pydantic.ValidationError and friends
            raise ValidationError(ReasonCode.CLAIMS_INVALID, "claim validation failed") from exc


class IssuanceRequest(BaseModel):
    """A locally-submitted request to issue a grant (BND-01).

    ``written_authorization_ref`` points to authority that the operator has
    verified OUT OF BAND; Phase 1 signs the reference, it does not validate the
    document (§20.1).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    organization: str = Field(min_length=1)
    granted_by: str = Field(min_length=1)
    granted_to: str = Field(min_length=1)
    scope: tuple[ScopeEntry, ...]
    issued_at: datetime
    not_before: datetime | None = None
    expires_at: datetime
    max_scan_depth: ScanDepth = ScanDepth.STANDARD
    written_authorization_ref: str = Field(min_length=1)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _aware_required(cls, value: datetime) -> datetime:
        return _require_aware(value, "issuance instant")

    @field_validator("not_before")
    @classmethod
    def _aware_optional(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _require_aware(value, "not_before")

    @field_validator("scope", mode="before")
    @classmethod
    def _coerce_scope(cls, value: Any) -> tuple[Any, ...]:
        if isinstance(value, (list, tuple)):
            return tuple(value)
        raise ValidationError(ReasonCode.CLAIMS_INVALID, "scope must be a list")

    @model_validator(mode="after")
    def _validate(self) -> "IssuanceRequest":
        if not self.scope:
            raise ValidationError(ReasonCode.CLAIMS_INVALID, "scope must contain at least one entry")
        if len(self.scope) > MAX_SCOPE_ENTRIES:
            raise ValidationError(ReasonCode.CLAIMS_INVALID, "too many scope entries")
        duration = (self.expires_at - self.issued_at).total_seconds()
        if duration <= 0:
            raise ValidationError(
                ReasonCode.GRANT_LIFETIME_INVALID, "expires_at must be strictly after issued_at"
            )
        if duration > MAX_GRANT_LIFETIME_SECONDS:
            raise ValidationError(
                ReasonCode.GRANT_LIFETIME_INVALID, "grant lifetime exceeds 90 days"
            )
        return self
