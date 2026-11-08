"""Capability issuance with live-trust re-validation.

Minting is co-located with the authorization decision owner. It re-checks, at
mint time and against *current* state, that the grant is unexpired, its signer
``kid`` is still trusted, and the receipt is consistent with the permit — so a
removed ``kid`` or an expired grant halts further execution even for an
in-memory permit. The capability carries only digests re-derived by the gateway.
"""

from __future__ import annotations

import base64
import secrets
import uuid

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.auth.results import AuthorizedPermit
from gryphon.canonical import canonical_json_bytes
from gryphon.clock import Clock
from gryphon.db.repositories.grants import GrantRepository
from gryphon.db.session import Database
from gryphon.tooling.capability.claims import OperationCapability, build_claims
from gryphon.tooling.constants import ToolId
from gryphon.tooling.idutil import validate_execution_id
from gryphon.tooling.reasons import EnforcementDenied, ToolReasonCode, ToolingConfigurationError
from gryphon.logging_config import get_logger

logger = get_logger(__name__)


class CapabilityIssuer:
    def __init__(
        self,
        *,
        signing_key: Ed25519SigningKey,
        grant_trust: TrustedKeyStore,
        database: Database,
        clock: Clock,
        ttl_seconds: int,
    ) -> None:
        self._key = signing_key
        self._grant_trust = grant_trust
        self._db = database
        self._clock = clock
        self._ttl = ttl_seconds

    async def mint(
        self, permit: AuthorizedPermit, tool_id: ToolId, execution_id: str
    ) -> OperationCapability:
        """Mint a grant-rooted capability for one tool execution."""
        validate_execution_id(execution_id)
        now = self._clock.now()

        # Live-trust re-validation against current state.
        async with self._db.session() as session:
            receipt = await GrantRepository(session).get_by_grant_id(permit.grant_id)

        if receipt is None:
            raise EnforcementDenied(ToolReasonCode.RECEIPT_MISSING, "grant receipt not found")
        if receipt.claims_digest != permit.claims_digest:
            raise EnforcementDenied(ToolReasonCode.RECEIPT_MISMATCH, "permit/receipt digest mismatch")
        if now >= receipt.expires_at:
            raise EnforcementDenied(ToolReasonCode.CAPABILITY_EXPIRED, "grant expired at mint time")
        if receipt.issuer_kid not in self._grant_trust.trusted_kids:
            raise EnforcementDenied(
                ToolReasonCode.RECEIPT_MISMATCH, "grant signer key no longer trusted"
            )

        iat = int(now.timestamp())
        claims = build_claims(
            capability_id=str(uuid.uuid4()),
            nonce=secrets.token_hex(16),
            kid=self._key.kid,
            scan_run_id=permit.scan_run_id,
            grant_id=permit.grant_id,
            claims_digest=receipt.claims_digest,
            scope_digest=receipt.scope_digest,
            tool_id=tool_id,
            effective_scan_depth=permit.effective_scan_depth,
            execution_id=execution_id,
            iat=iat,
            exp=iat + self._ttl,
        )
        signing_input = canonical_json_bytes(claims.to_canonical_payload())
        binding = base64.standard_b64encode(self._key.sign(signing_input)).decode("ascii")

        logger.info(
            "capability_minted",
            capability_id=claims.capability_id,
            scan_run_id=claims.scan_run_id,
            tool_id=tool_id.value,
            execution_id=execution_id,
        )
        return OperationCapability(claims=claims, binding=binding)


def require_signer(signer: Ed25519SigningKey | None) -> Ed25519SigningKey:
    if signer is None:
        raise ToolingConfigurationError("capability signing key is required to mint capabilities")
    return signer
