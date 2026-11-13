"""Composition root for the enrichment layer.

Startup-time refusals, before any pass can run:

* **A dedicated signing key is mandatory** — enrichment attestations are never
  signed with the grant, audit or capability keys, and the enrichment key must be
  distinct from all of them (by kid *and* by public key).
* **A dedicated database role** — in production the DSN must authenticate as
  ``gryphon_enrichment``, whose privileges allow writing enrichment tables only.
* **Production readiness** — caller allowlist, trusted kid, and an *enforcing*
  egress posture (the tool-execution settings already refuse ``unenforced`` in
  production; this layer re-checks the built enforcer rather than trusting it).

Import discipline: this module — like every module of the parent process — must
not import the orchestration package or the tooling bootstrap. Both pull HTTP
client libraries into the process that holds keys and engagement data; the only
code in this layer allowed an HTTP client is the acquisition subprocess.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.engine import make_url

from gryphon.auth.key_provider import KeyMaterial, TrustedKeyStore, build_key_material
from gryphon.clock import Clock, SystemClock
from gryphon.db.session import Database
from gryphon.enrichment.artifacts import ArtifactStore
from gryphon.enrichment.audit import EnrichmentAuditBuilder
from gryphon.enrichment.constants import DATABASE_ROLE
from gryphon.enrichment.engine import EnrichmentEngine
from gryphon.enrichment.policy import Policy, load_policy
from gryphon.enrichment.reader import ReportReader
from gryphon.enrichment.reasons import EnrichmentConfigurationError
from gryphon.enrichment.reference import DatasetUnavailable, ReferenceData, load_reference
from gryphon.enrichment.settings import (
    EnrichmentSettings,
    build_signing_key,
    build_trust_store,
    get_enrichment_settings,
)
from gryphon.enrichment.snapshots import (
    AcquisitionLauncher,
    Enforcer,
    Resolver,
    SnapshotService,
    SubprocessAcquisitionLauncher,
)
from gryphon.logging_config import get_logger
from gryphon.settings import Settings, get_settings
from gryphon.tooling.destination.egress import build_egress_enforcer
from gryphon.tooling.destination.resolver import SystemResolver
from gryphon.tooling.settings import ToolingSettings, get_tooling_settings

logger = get_logger(__name__)


@dataclass
class EnrichmentServices:
    """Everything the enrichment commands need, built once per process."""

    core: Settings
    settings: EnrichmentSettings
    database: Database
    clock: Clock
    keys: KeyMaterial
    trust: TrustedKeyStore
    audit: EnrichmentAuditBuilder
    artifacts: ArtifactStore
    policy: Policy
    enforcer: Enforcer
    snapshots: SnapshotService
    reader: ReportReader
    engine: EnrichmentEngine

    @property
    def posture(self) -> str:
        return self.snapshots.posture

    async def dispose(self) -> None:
        await self.database.dispose()


def _raw_public_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def assert_key_separation(
    *, enrichment_kid: str, enrichment_public_hex: str, core: Settings,
    keys: KeyMaterial, tooling: ToolingSettings,
) -> None:
    """The enrichment key must share neither a kid nor a key with any other purpose."""
    other_kids: set[str] = set()
    other_publics: set[str] = set()
    for store in (keys.grant_trust, keys.audit_trust):
        for kid in store.trusted_kids:
            other_kids.add(kid)
            key = store.get(kid)
            if key is not None:
                other_publics.add(_raw_public_hex(key))
    for kid, pub_hex in tooling.capability_trusted_public_keys.items():
        other_kids.add(kid)
        if pub_hex:
            other_publics.add(pub_hex.strip().lower())
    for signer in (keys.grant_signer, keys.audit_signer):
        if signer is not None:
            other_kids.add(signer.kid)
            other_publics.add(signer.public_key_raw_hex())
    if tooling.capability_kid:
        other_kids.add(tooling.capability_kid)
    for value in (core.grant_kid, core.audit_kid):
        if value:
            other_kids.add(value)

    if enrichment_kid in other_kids:
        raise EnrichmentConfigurationError(
            f"the enrichment kid {enrichment_kid!r} is also used for another purpose"
        )
    if enrichment_public_hex.lower() in other_publics:
        raise EnrichmentConfigurationError(
            "the enrichment signing key is also used for another purpose; generate a dedicated key"
        )


def assert_dedicated_role(settings: EnrichmentSettings, *, production: bool) -> None:
    username = make_url(settings.database_url).username
    if username == DATABASE_ROLE:
        return
    message = (
        f"the enrichment DSN authenticates as {username!r}; it must use the dedicated "
        f"{DATABASE_ROLE!r} role"
    )
    if production:
        raise EnrichmentConfigurationError(message)
    logger.warning("enrichment_role_not_dedicated", role=username)


def build_enrichment_services(
    *,
    settings: Settings | None = None,
    enrichment_settings: EnrichmentSettings | None = None,
    tooling_settings: ToolingSettings | None = None,
    clock: Clock | None = None,
    database: Database | None = None,
    enforcer: Enforcer | None = None,
    launcher: AcquisitionLauncher | None = None,
    resolver: Resolver | None = None,
    reference_loader: Callable[[], ReferenceData | DatasetUnavailable] | None = None,
) -> EnrichmentServices:
    """Build the enrichment layer, refusing to start if it cannot be safe."""
    core = settings or get_settings()
    es = enrichment_settings or get_enrichment_settings()
    ts = tooling_settings or get_tooling_settings()
    production = core.environment == "prod"

    if production:
        es.assert_production_ready()
    signer = build_signing_key(es)
    if signer is None:
        raise EnrichmentConfigurationError(
            "an enrichment signing key is required (GRYPHON_ENRICHMENT_SIGNING_KEY_HEX): "
            "every report and snapshot acceptance is attested with it"
        )
    keys = build_key_material(core)
    assert_key_separation(
        enrichment_kid=signer.kid,
        enrichment_public_hex=signer.public_key_raw_hex(),
        core=core,
        keys=keys,
        tooling=ts,
    )
    assert_dedicated_role(es, production=production)

    active_clock = clock or SystemClock()
    db = database or Database(core.model_copy(update={"database_url": es.database_url}))
    active_enforcer = enforcer or build_egress_enforcer(ts)
    if production and not active_enforcer.enforcing:
        raise EnrichmentConfigurationError("production acquisition requires enforced egress")
    posture = "ENFORCED" if active_enforcer.enforcing else "UNENFORCED"

    artifacts = ArtifactStore(es.artifact_dir)
    policy = load_policy(es.policy_path)
    audit = EnrichmentAuditBuilder(signer)
    trust = build_trust_store(es)
    snapshots = SnapshotService(
        database=db,
        artifacts=artifacts,
        launcher=launcher
        or SubprocessAcquisitionLauncher(
            enforcer=active_enforcer,
            timeout_seconds=es.subprocess_timeout_seconds,
            max_report_bytes=es.max_report_bytes,
        ),
        resolver=resolver or SystemResolver(timeout_seconds=ts.resolve_timeout_seconds),
        audit=audit,
        settings=es,
        clock=active_clock,
        posture=posture,
    )
    reader = ReportReader(audit_trust=keys.audit_trust, grant_trust=keys.grant_trust)
    reference_dir = es.reference_dir
    engine = EnrichmentEngine(
        database=db,
        reader=reader,
        snapshots=snapshots,
        artifacts=artifacts,
        audit=audit,
        trust=trust,
        policy=policy,
        settings=es,
        clock=active_clock,
        reference_loader=reference_loader or (lambda: load_reference(reference_dir)),
    )
    logger.info(
        "enrichment_services_built",
        environment=core.environment,
        egress_posture=posture,
        policy=policy.short_digest,
        signer_kid=signer.kid,
    )
    return EnrichmentServices(
        core=core,
        settings=es,
        database=db,
        clock=active_clock,
        keys=keys,
        trust=trust,
        audit=audit,
        artifacts=artifacts,
        policy=policy,
        enforcer=active_enforcer,
        snapshots=snapshots,
        reader=reader,
        engine=engine,
    )
