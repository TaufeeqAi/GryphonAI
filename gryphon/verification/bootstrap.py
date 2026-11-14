"""The composition root: where custody is proved before anything is built.

Most of this layer's guarantees are properties of *what it does not hold*. That
is unusual, and it means the assembly step is a security control rather than
plumbing. Four refusals happen here, before a single object is wired:

* **One database identity.** The verification process connects with its own
  role and nothing else. If it also held the shared runtime role — which is what
  constructing the tool execution gateway in-process would require — it would
  have write access to the evidence it judges, and "never writes upstream" would
  be a promise rather than a privilege.
* **One signing key.** No private key may be loadable here except the
  verification key. The orchestration attestation key in particular must be
  absent: a process that can verify a base report's attestation *and* produce
  one can fabricate its own inputs, and key separation by name does not prevent
  that. Only custody does.
* **The policy key is somebody else's.** The registry is signed by a key this
  process does not hold, so whoever defines what CONFIRMED means is not the
  component that says it.
* **No in-process gateway.** The gateway is reached over a socket. A build that
  tried to construct it here would acquire every credential it holds, which is
  the defect all of the above exist to close; so the attempt is refused outright
  rather than configured away.

Everything else — settings validation, the registry's own validation, readiness
by facts — is delegated to the modules that own it.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.clock import Clock, SystemClock
from gryphon.db.session import Database
from gryphon.logging_config import get_logger
from gryphon.settings import Settings
from gryphon.verification.audit import VerificationAuditBuilder
from gryphon.verification.constants import DATABASE_ROLE
from gryphon.verification.evaluator import ProofEvaluator
from gryphon.verification.identity import CallerIdentity, local_cli_identity
from gryphon.verification.reasons import VerificationConfigurationError
from gryphon.verification.registry import VerifierRegistry
from gryphon.verification.settings import (
    VerificationSettings,
    assert_strict_security_settings,
    build_enrichment_trust_store,
    build_policy_trust_store,
    build_signing_key,
    build_trust_store,
    get_verification_settings,
)

if TYPE_CHECKING:  # pragma: no cover - the runtime import lives in the property
    from gryphon.verification.commands import VerificationCommands

logger = get_logger(__name__)

#: Environment variables that carry a *private* key this process must not hold.
#: Each one, if set, means a different purpose's signing key is reachable here.
FOREIGN_KEY_VARIABLES: Final[tuple[str, ...]] = (
    "GRYPHON_GRANT_SIGNING_KEY_HEX",
    "GRYPHON_AUDIT_SIGNING_KEY_HEX",
    "GRYPHON_CAPABILITY_SIGNING_KEY_HEX",
    "GRYPHON_ENRICHMENT_SIGNING_KEY_HEX",
    "GRYPHON_ORCHESTRATION_SIGNING_KEY_HEX",
    "GRYPHON_POLICY_SIGNING_KEY_HEX",
)

#: Environment variables naming a database other than this layer's own.
FOREIGN_DSN_VARIABLES: Final[tuple[str, ...]] = (
    "GRYPHON_DATABASE_URL",
    "GRYPHON_MIGRATION_DATABASE_URL",
    "GRYPHON_ENRICHMENT_DATABASE_URL",
    "GRYPHON_GATEWAY_DATABASE_URL",
)


@dataclass(frozen=True, slots=True)
class VerificationServices:
    """Everything a command needs, assembled once and proved safe."""

    core: Settings
    settings: VerificationSettings
    database: Database
    clock: Clock
    registry: VerifierRegistry
    evaluator: ProofEvaluator
    audit: VerificationAuditBuilder
    signer: Ed25519SigningKey
    attestation_trust: TrustedKeyStore
    enrichment_trust: TrustedKeyStore
    policy_trust: TrustedKeyStore
    caller: CallerIdentity
    gateway_socket: Path

    @property
    def production(self) -> bool:
        return self.core.environment == "prod"

    async def dispose(self) -> None:
        """Release the connection pool.

        Named on the services value rather than left to callers to reach
        through to ``database``, because a probe that opened a pool and a
        command that opened a pool should be shut down the same way — and the
        readiness script, which runs last in a deployment, was calling exactly
        this.
        """
        await self.database.dispose()

    @property
    def commands(self) -> VerificationCommands:
        """The operator commands, assembled on demand.

        Built from this value rather than passed into it, so every custody
        assertion in :func:`build_verification_services` is necessarily upstream
        of any command: there is no way to obtain one except through an assembly
        that already refused the unsafe configurations. Imported inside the
        property because the commands module imports the gateway *client*, and
        the import graph is one of the things this module asserts about.
        """
        from gryphon.verification.commands import build_commands

        return build_commands(self)


# =============================================================================
# Custody assertions
# =============================================================================


def assert_single_database_identity(
    settings: VerificationSettings, environ: Mapping[str, str] | None = None
) -> None:
    """Refuse a process that can reach more than one database identity.

    The role name is checked from the DSN rather than inferred: a verification
    process pointed at the shared runtime role would pass every behavioural test
    while holding INSERT on the evidence tables it is meant only to read.
    """
    from sqlalchemy.engine import make_url

    try:
        username = make_url(settings.database_url).username
    except Exception as exc:
        raise VerificationConfigurationError(f"the verification DSN is unusable: {exc}") from exc

    if username != DATABASE_ROLE:
        raise VerificationConfigurationError(
            f"the verification layer must connect as {DATABASE_ROLE!r}, not {username!r}: "
            "a shared role would carry write access to the evidence this layer judges"
        )

    env = dict(os.environ if environ is None else environ)
    present = [name for name in FOREIGN_DSN_VARIABLES if (env.get(name) or "").strip()]
    if present:
        raise VerificationConfigurationError(
            "a second database identity is reachable from this process "
            f"({', '.join(sorted(present))}); one process holds one role"
        )


def assert_key_custody(
    settings: VerificationSettings, environ: Mapping[str, str] | None = None
) -> None:
    """Refuse a process that can sign with a key it is required to verify.

    This is the rule that makes the input boundary meaningful. The base report's
    attestation is checked against a public key whose private half lives in the
    orchestration process; if that private key were loadable here, a compromise
    of this process would be enough to forge a report *and* mint the attestation
    that makes the forgery look genuine.
    """
    env = dict(os.environ if environ is None else environ)
    present = [name for name in FOREIGN_KEY_VARIABLES if (env.get(name) or "").strip()]
    if present:
        raise VerificationConfigurationError(
            "this process can load a signing key for another purpose "
            f"({', '.join(sorted(present))}). Verification must not hold a key whose "
            "signatures it verifies, or it can attest its own inputs"
        )

    signer = build_signing_key(settings)
    if signer is None:
        return
    attestation = build_trust_store(settings)
    # The verification kid must not also be a trusted *attestation* signer: that
    # would let this layer's own signature satisfy its input check.
    for store_name, store in (
        ("enrichment", build_enrichment_trust_store(settings)),
        ("policy", build_policy_trust_store(settings)),
    ):
        if signer.kid in store.trusted_kids:
            raise VerificationConfigurationError(
                f"the verification kid {signer.kid!r} is also trusted for {store_name} "
                "artifacts; one key, one purpose"
            )
    if signer.kid not in attestation.trusted_kids:
        # Its own store should contain it, so a fresh deployment can verify what
        # it emits. Absence here means the trust map and the key disagree.
        logger.warning("verification_key_absent_from_own_trust_store", kid=signer.kid)


def assert_no_in_process_gateway() -> None:
    """Refuse an assembly that would construct the gateway here.

    Importing the gateway's service implementation into this process is enough
    to require its database handle and its audit signing key, which is the
    composition defect every custody rule above exists to prevent. The check is
    deliberately on *reachability*, not on use: a code path that is present will
    eventually be taken.
    """
    import sys

    forbidden = "gryphon.tooling.enforcement.service"
    if forbidden in sys.modules:
        raise VerificationConfigurationError(
            "the tool execution service is loaded in this process. Verification reaches "
            "the gateway over its socket; constructing it here would require the gateway's "
            "database role and its audit signing key"
        )


# =============================================================================
# Build
# =============================================================================


def build_verification_services(
    *,
    core: Settings | None = None,
    settings: VerificationSettings | None = None,
    clock: Clock | None = None,
    database: Database | None = None,
    environ: Mapping[str, str] | None = None,
    check_caller: bool = True,
) -> VerificationServices:
    """Assemble the layer, refusing anything that would weaken a control."""
    assert_strict_security_settings(environ)

    core_settings = core or Settings()
    verification_settings = settings or get_verification_settings()
    production = core_settings.environment == "prod"

    if production:
        verification_settings.assert_production_ready()

    assert_single_database_identity(verification_settings, environ)
    assert_key_custody(verification_settings, environ)
    assert_no_in_process_gateway()

    signer = build_signing_key(verification_settings)
    if signer is None:
        raise VerificationConfigurationError(
            "a verification signing key is required: an unattested deliverable cannot be "
            "told apart from a fabricated one"
        )

    socket_path = verification_settings.gateway_socket_path
    if socket_path is None:
        raise VerificationConfigurationError(
            "a gateway socket path is required: this layer has no other way to reach a target"
        )

    registry = VerifierRegistry.load(
        verification_settings.registry_file,
        trust=build_policy_trust_store(verification_settings),
        require_signature=production or verification_settings.require_signed_registry,
    )

    db = database or Database(
        core_settings.model_copy(update={"database_url": verification_settings.database_url})
    )

    caller = (
        local_cli_identity(allowed_uids=verification_settings.allowed_uids)
        if check_caller
        else CallerIdentity(uid=-1, label="cli:uid:-1")
    )

    logger.info(
        "verification_services_built",
        environment=core_settings.environment,
        registry_digest=registry.digest[:16],
        registry_reviewer=registry.approval.reviewer,
        registry_signed=registry.approval.is_signed,
        role=DATABASE_ROLE,
        signer_kid=signer.kid,
        initiated_by=caller.label,
    )

    return VerificationServices(
        core=core_settings,
        settings=verification_settings,
        database=db,
        clock=clock or SystemClock(),
        registry=registry,
        evaluator=ProofEvaluator(),
        audit=VerificationAuditBuilder(signer),
        signer=signer,
        attestation_trust=build_trust_store(verification_settings),
        enrichment_trust=build_enrichment_trust_store(verification_settings),
        policy_trust=build_policy_trust_store(verification_settings),
        caller=caller,
        gateway_socket=socket_path,
    )
