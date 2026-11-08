"""``authorization_grants`` — immutable issuance receipt (§22.1, BND-04).

Insert-only for the runtime role. Claim fields and digests MUST NOT be updated
in place; a trigger + role privileges enforce this at the database (§22.3). No
``status=ACTIVE/REVOKED`` column exists in Phase 1 — a grant is admissible until
its exclusive expiry while its signer ``kid`` remains trusted (§20.4).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gryphon.db.base import Base


class AuthorizationGrant(Base):
    __tablename__ = "authorization_grants"

    grant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer_kid: Mapped[str] = mapped_column(String(128), nullable=False)

    granted_by: Mapped[str] = mapped_column(String(320), nullable=False)
    granted_to: Mapped[str] = mapped_column(String(320), nullable=False)
    organization: Mapped[str] = mapped_column(String(320), nullable=False)

    # Canonical, validated scope snapshot (list of entry dicts).
    scope: Mapped[list] = mapped_column(JSONB, nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    # SHA-256 of the exact decoded JWS payload bytes (no re-serialization).
    claims_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    scope_policy_version: Mapped[str] = mapped_column(String(16), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)

    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    max_scan_depth: Mapped[str] = mapped_column(String(16), nullable=False)
    written_authorization_ref: Mapped[str] = mapped_column(Text, nullable=False)

    # Idempotency metadata: hashes only; never the raw key.
    issuance_idempotency_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
