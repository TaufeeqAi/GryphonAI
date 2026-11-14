"""Readiness for the verification layer — by facts, never by a revision number.

A migration revision proves only that a script once ran, and a configuration
value proves only what somebody typed. These checks inspect what is true *now*:
the objects and partitions that exist, that every append-only trigger is present
**and enabled**, that the trigger functions' bodies are the ones this code
expects, the dedicated role's exact privilege matrix including what it must
*not* hold, the custody properties that make this layer's claims worth
something, the import graph of the package as shipped, the registry's signature
and named reviewer, the gateway's advertised feature set, and the egress posture
*observed* rather than declared.

Four of these deserve their reason stated, because they are the ones that fail
silently in a system that otherwise looks healthy:

* **Absence checks.** A role that happens to hold what it needs is not
  least-privileged. The matrix therefore asserts every privilege that must be
  missing — no write on upstream evidence, no write on the gateway's ledger, no
  UPDATE on a pin — because those are the grants a well-meaning operator adds
  while debugging and never removes.
* **Custody.** One database identity, one key, non-owner, non-superuser, no role
  membership that grants more, a restricted ``search_path``, no callable
  ``SECURITY DEFINER`` path. A verifier that can write the evidence it judges, or
  sign the attestation it checks, is marking its own homework; none of that shows
  up in behavioural tests.
* **The gateway's feature set.** A missing enforcement feature is a FAIL and
  never a warning. Dispatching through a gateway that does not apply a check an
  invariant rests on is exactly the outcome this check exists to prevent, and a
  warning is something an operator can scroll past.
* **The posture.** The effective egress posture is derived from what the gateway
  advertises and pins, not from the deployment's own ``egress_posture`` text. The
  two disagreeing is itself a finding.

Checks are advisory outside production and fatal inside it where a developer
could reasonably run without the dependency; the controls above are fatal
everywhere, because a control that is optional on a laptop is a control whose
absence nobody notices in production either.
"""

from __future__ import annotations

import ast
import os
import sys
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from sqlalchemy import text

from gryphon.db.session import Database
from gryphon.tooling.gateway.client import GatewayClient
from gryphon.tooling.gateway.protocol import FeatureSet, Welcome
from gryphon.verification.constants import DATABASE_ROLE, REQUIRED_GATEWAY_FEATURES
from gryphon.verification.reasons import (
    GatewayProtocolError,
    GatewayUnavailable,
    RegistryError,
)
from gryphon.verification.registry import VerifierRegistry
from gryphon.verification.schema import (
    BARRIER_TABLE,
    EXPECTED_ALEMBIC_REVISION,
    EXPECTED_FUNCTION_FINGERPRINTS,
    EXPECTED_UNIQUE_COLUMNS,
    OPEN_PASS_INDEX,
    PARTITION_KEY_BY_TABLE,
    PARTITION_UNIQUE_COLUMNS,
    PARTITION_WARN_MONTHS,
    PARTITIONED_TABLES,
    VERIFICATION_TABLES,
    VIEW_NAME,
    default_partition,
    expected_column_updates,
    expected_table_privileges,
    expected_triggers,
    function_fingerprint,
    month_sequence,
    partition_name,
    partition_truncate_trigger,
    required_partitions,
)
from gryphon.verification.settings import unknown_security_keys

if TYPE_CHECKING:  # pragma: no cover - typing only
    from gryphon.verification.bootstrap import VerificationServices

#: The package whose import graph is walked. This layer's whole claim to having
#: no network client is a claim about what this directory imports.
VERIFICATION_PACKAGE_ROOT: Final[Path] = Path(__file__).resolve().parent

#: Dotted prefixes no module under the verification package may import. The
#: gateway socket and the database are the only permitted sockets, so the client
#: that holds the socket lives in ``gryphon.tooling.gateway`` and the typed fact
#: schemas in ``gryphon.tooling.observation`` — both permitted. A resolver, an
#: HTTP client, a subprocess, the in-process gateway service and the
#: orchestration package are not.
FORBIDDEN_IMPORT_PREFIXES: Final[tuple[str, ...]] = (
    "aiodns",
    "aiohttp",
    "dns",
    "dnspython",
    "ftplib",
    "http",
    "httpcore",
    "httpx",
    "multiprocessing",
    "paramiko",
    "requests",
    "smtplib",
    "socket",
    "socketserver",
    "ssl",
    "subprocess",
    "telnetlib",
    "urllib.error",
    "urllib.request",
    "urllib3",
    "websockets",
    # Telemetry to a third party, and tracing enabled from the environment.
    "ddtrace",
    "opentelemetry",
    "sentry_sdk",
    # Other layers this one must not reach into.
    "fastmcp",
    "gryphon.orchestration",
    "gryphon.tooling.destination",
    "gryphon.tooling.enforcement",
    "gryphon.tooling.runner",
    "langgraph",
)

#: Modules that must not be *loaded* in this process. Narrower than the static
#: list on purpose: ``socket`` and ``ssl`` arrive with the database driver and
#: the gateway client, which are the two sockets this layer is allowed.
FORBIDDEN_LOADED_MODULES: Final[tuple[str, ...]] = (
    "aiohttp",
    "dns",
    "fastmcp",
    "gryphon.orchestration",
    "gryphon.tooling.destination",
    "gryphon.tooling.enforcement",
    "http.client",
    "httpcore",
    "httpx",
    "langgraph",
    "requests",
    "urllib3",
)

#: Predefined roles whose membership would hand this role more than its matrix.
PRIVILEGED_ROLE_MEMBERSHIPS: Final[tuple[str, ...]] = (
    "pg_read_all_data",
    "pg_write_all_data",
    "pg_read_all_settings",
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_execute_server_program",
    "pg_maintain",
    "pg_monitor",
    "pg_signal_backend",
    "pg_checkpoint",
)

#: Schemas a restricted ``search_path`` may name. ``"$user"`` is absent on
#: purpose: a per-user schema is a place where a table or function can be
#: shadowed without changing one line of this layer's SQL.
SAFE_SEARCH_PATH_ENTRIES: Final[frozenset[str]] = frozenset({"public", "pg_catalog"})

#: Default location of the environment file the settings loader also reads.
DEFAULT_ENV_FILE: Final[Path] = Path(".env")

HandshakeProbe = Callable[[], Awaitable[Welcome]]


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    passed: bool
    detail: str = ""
    fatal: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "fatal": self.fatal,
            "detail": self.detail,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    checks: tuple[Check, ...]
    environment: str

    @property
    def ready(self) -> bool:
        return all(c.passed or not c.fatal for c in self.checks)

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.passed)

    def as_payload(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "environment": self.environment,
            "checks": [c.as_payload() for c in self.checks],
        }


# =============================================================================
# The import graph (static)
# =============================================================================


@dataclass(frozen=True, slots=True)
class ForbiddenImport:
    """One import statement that must not exist, named precisely.

    Naming the file and line matters: "the import graph is dirty" is a support
    ticket, and the operator's next action is to open one line of one file.
    """

    module: str
    imported: str
    lineno: int

    def describe(self) -> str:
        return f"{self.module}:{self.lineno} imports {self.imported}"


def forbidden_prefix(name: str) -> str | None:
    """The forbidden prefix ``name`` falls under, if any.

    Matching is on dotted segments, so ``http`` does not catch ``httpx`` by
    accident and ``urllib.request`` does not condemn ``urllib.parse`` — which is
    pure string handling and is used to canonicalize a target.
    """
    for prefix in FORBIDDEN_IMPORT_PREFIXES:
        if name == prefix or name.startswith(prefix + "."):
            return prefix
    return None


def scan_import_graph(root: Path) -> tuple[ForbiddenImport, ...]:
    """Walk every module under ``root`` and report forbidden imports.

    Static rather than runtime: a code path that is present will eventually be
    taken, and an import inside a function body or under ``TYPE_CHECKING`` is
    still a line somebody can call. Relative imports are skipped — they can only
    reach inside this package.
    """
    found: list[ForbiddenImport] = []
    for path in sorted(root.rglob("*.py")):
        label = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            found.append(ForbiddenImport(label, f"<unreadable: {type(exc).__name__}>", 0))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if forbidden_prefix(alias.name):
                        found.append(ForbiddenImport(label, alias.name, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                base = node.module or ""
                if forbidden_prefix(base):
                    found.append(ForbiddenImport(label, base, node.lineno))
                    continue
                for alias in node.names:
                    candidate = f"{base}.{alias.name}" if base else alias.name
                    if forbidden_prefix(candidate):
                        found.append(ForbiddenImport(label, candidate, node.lineno))
    return tuple(found)


def import_graph_check(root: Path | None = None) -> Check:
    violations = scan_import_graph(root or VERIFICATION_PACKAGE_ROOT)
    return Check(
        "package_import_graph_clean",
        not violations,
        "no module of this layer imports a network client, a resolver, a subprocess "
        "or the orchestration package"
        if not violations
        else "; ".join(v.describe() for v in violations[:8]),
        details={"violations": [v.describe() for v in violations]},
    )


def loaded_module_check(modules: Collection[str] | None = None) -> Check:
    loaded = sys.modules.keys() if modules is None else modules
    names = set(loaded)
    present = sorted(
        name
        for name in FORBIDDEN_LOADED_MODULES
        if name in names or any(m.startswith(name + ".") for m in names)
    )
    return Check(
        "process_import_graph_clean",
        not present,
        "no HTTP client, resolver, gateway service or orchestration module is loaded "
        "in this process"
        if not present
        else f"forbidden modules loaded: {', '.join(present)}",
        details={"forbidden": list(FORBIDDEN_LOADED_MODULES)},
    )


# =============================================================================
# Custody of keys (no database needed)
# =============================================================================


def dotenv_assigned_names(path: Path) -> tuple[str, ...]:
    """Names assigned a non-empty value in an environment file.

    The settings loader reads ``.env``, so a key present only there is still
    loadable in this process and must still be caught. Only the *name* is
    returned and nothing on the value side is retained — the question is whether
    an assignment exists, never what it says.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    names: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.removeprefix("export ").strip()
        if name and value.strip().strip("\"'"):
            names.append(name)
    return tuple(names)


def foreign_signing_keys(
    environ: Mapping[str, str], *, dotenv_names: Collection[str] = ()
) -> tuple[str, ...]:
    """Which other purposes' private keys this process could load.

    The composition root refuses to start when one of these is set. Readiness
    re-establishes it as an observed fact, because the refusal only covers the
    environment as it was at build time and an operator may have exported a key
    into a long-running service's environment file since.
    """
    from gryphon.verification.bootstrap import FOREIGN_KEY_VARIABLES

    assigned = {name for name, value in environ.items() if (value or "").strip()}
    assigned |= set(dotenv_names)
    return tuple(name for name in FOREIGN_KEY_VARIABLES if name in assigned)


def key_custody_check(
    environ: Mapping[str, str] | None = None, *, env_file: Path | None = None
) -> Check:
    path = DEFAULT_ENV_FILE if env_file is None else env_file
    present = foreign_signing_keys(
        os.environ if environ is None else environ, dotenv_names=dotenv_assigned_names(path)
    )
    return Check(
        "single_key_custody",
        not present,
        "no private key other than the verification key is loadable here"
        if not present
        else "this process can load a signing key for another purpose: "
        f"{', '.join(present)}",
        details={"reachable": list(present)},
    )


# =============================================================================
# The gateway and the posture
# =============================================================================


def missing_gateway_features(advertised: Collection[str]) -> tuple[str, ...]:
    """Required enforcement features the gateway does not offer."""
    return FeatureSet(frozenset(advertised)).missing


def effective_posture(welcome: Welcome | None) -> str:
    """The posture derived from observed facts.

    ``ENFORCED`` requires a completed handshake whose feature set is satisfied
    *and* a gateway that can name the extractor set and sanitizer rules it ran:
    a service that cannot say which code measured the bytes has not demonstrably
    sealed the observer, whatever its configuration file says.
    """
    if welcome is None:
        return "UNENFORCED"
    if not welcome.features.satisfied:
        return "UNENFORCED"
    if not (welcome.extractor_set_digest.strip() and welcome.sanitizer_ruleset_digest.strip()):
        return "UNENFORCED"
    return "ENFORCED"


async def _default_handshake(socket_path: Path, *, timeout_seconds: float) -> Welcome:
    client = GatewayClient.over_unix_socket(
        socket_path,
        client_name="verification-readiness",
        connect_timeout_seconds=timeout_seconds,
    )
    try:
        return await client.connect()
    finally:
        await client.close()


async def gateway_checks(
    services: VerificationServices, *, prod: bool, handshake: HandshakeProbe | None = None
) -> list[Check]:
    """Socket, handshake, feature set and the observed posture."""
    socket_path = services.gateway_socket
    exists = socket_path.exists()
    checks: list[Check] = [
        Check(
            "gateway_socket_present",
            exists,
            f"the gateway socket is at {socket_path}"
            if exists
            else f"no socket at {socket_path}: this layer has no other path to an observation",
            fatal=prod,
            details={"socket_path": str(socket_path)},
        )
    ]

    welcome: Welcome | None = None
    failure = ""
    if exists:
        probe = handshake or (
            lambda: _default_handshake(
                socket_path, timeout_seconds=services.settings.gateway_connect_timeout_seconds
            )
        )
        try:
            welcome = await probe()
        except GatewayUnavailable as exc:
            failure = f"the gateway did not answer: {exc}"
        except GatewayProtocolError as exc:
            failure = str(exc)
        except OSError as exc:
            failure = f"{type(exc).__name__}: {exc}"
    else:
        failure = "the socket is absent, so no feature set could be established"

    missing = missing_gateway_features(welcome.feature_set) if welcome else ()
    checks.append(
        Check(
            "gateway_feature_set_complete",
            welcome is not None and not missing,
            f"the gateway enforces every required feature (protocol {welcome.protocol_version}, "
            f"pin {welcome.digest[:16]})"
            if welcome is not None and not missing
            else (
                f"the gateway does not enforce {', '.join(missing)}"
                if missing
                else failure or "no handshake"
            ),
            # Never advisory. Dispatching through a gateway that is missing an
            # enforcement feature is the thing this check exists to prevent, and
            # the correct number of requests to send is zero.
            details={
                "required": sorted(REQUIRED_GATEWAY_FEATURES),
                "advertised": sorted(welcome.feature_set) if welcome else [],
                "missing": list(missing),
            },
        )
    )

    observed = effective_posture(welcome)
    declared = services.settings.egress_posture.upper()
    agrees = observed == declared
    checks.append(
        Check(
            "egress_posture_observed",
            observed == "ENFORCED",
            "observation runs inside the gateway's enforced containment"
            if observed == "ENFORCED"
            else (
                f"the deployment declares {declared} but the observed posture is {observed}"
                if not agrees
                else "the observed egress posture is unenforced: nothing contains a contact"
            ),
            fatal=prod,
            details={"observed": observed, "declared": declared},
        )
    )
    return checks


# =============================================================================
# Configuration
# =============================================================================


def configuration_checks(services: VerificationServices, *, prod: bool) -> list[Check]:
    """Checks that need neither a database nor the gateway."""
    checks: list[Check] = [
        import_graph_check(),
        loaded_module_check(),
        key_custody_check(),
    ]
    vs = services.settings

    signer_kid = services.audit.kid
    trusted = signer_kid in services.attestation_trust.trusted_kids
    configured = bool((vs.trusted_public_keys.get(signer_kid) or "").strip())
    checks.append(
        Check(
            "signing_key_dedicated",
            trusted and (configured or not prod),
            f"verification attestations are signed with {signer_kid!r}"
            if trusted and (configured or not prod)
            else "the verification kid is not in the configured trusted key map",
            details={"kid": signer_kid, "configured_in_trust_map": configured},
        )
    )

    checks.append(
        Check(
            "caller_allowlist_configured",
            bool(vs.allowed_uids),
            "verification callers are restricted to an allowlist of uids"
            if vs.allowed_uids
            else "no caller allowlist: any local user may run verification",
            fatal=prod,
            details={"allowed_uids": list(vs.allowed_uids)},
        )
    )

    unknown = unknown_security_keys()
    checks.append(
        Check(
            "security_settings_recognized",
            not unknown,
            "every GRYPHON_VERIFICATION_* variable in the environment is a known setting"
            if not unknown
            else f"ignored security variables (typo?): {', '.join(unknown)}",
            fatal=prod,
            details={"unknown": list(unknown)},
        )
    )

    checks.extend(_registry_checks(services, prod=prod))
    return checks


def _registry_checks(services: VerificationServices, *, prod: bool) -> list[Check]:
    """The registry is the product, so it is checked as a governed artifact.

    Two separate facts: the document on disk still validates and still has the
    digest this process is using (an edited file after startup is caught), and
    it carries a signature from a key this process does not hold plus a named
    reviewer. A digest is integrity, not authority.
    """
    registry = services.registry
    approval = registry.approval
    checks: list[Check] = []

    path = services.settings.registry_file
    try:
        on_disk = VerifierRegistry.load(path)
        matches = on_disk.digest == registry.digest
        detail = (
            f"{len(registry.verifier_ids)} verifiers, digest {registry.digest[:16]}"
            if matches
            else f"the document at {path} now digests to {on_disk.digest[:16]}, "
            f"not the loaded {registry.digest[:16]}"
        )
    except RegistryError as exc:
        matches = False
        detail = f"{path}: {exc}"
    checks.append(
        Check(
            "registry_valid_and_unchanged",
            matches,
            detail,
            details={"path": str(path), "verifiers": list(registry.verifier_ids)},
        )
    )

    signed = approval.is_signed and bool(approval.reviewer)
    checks.append(
        Check(
            "registry_signed_by_named_reviewer",
            signed,
            f"reviewed by {approval.reviewer!r}, signed by {approval.signer_kid!r}"
            if signed
            else (
                f"reviewed by {approval.reviewer!r} but unsigned: without a signature, "
                "anything that can write the file redefines what CONFIRMED means"
            ),
            fatal=prod or services.settings.require_signed_registry,
            details={
                "reviewer": approval.reviewer,
                "signer_kid": approval.signer_kid,
                "approved_at": approval.approved_at,
            },
        )
    )
    return checks


# =============================================================================
# Database facts
# =============================================================================


@dataclass(frozen=True, slots=True)
class DatabaseFacts:
    """What the database actually says, gathered once and judged separately.

    Separating the gathering from the judging is what lets the whole matrix be
    exercised without a server: the checks below are a pure function of this
    value.
    """

    current_user: str
    session_user: str
    today: date
    revision: str | None
    role_exists: bool
    relations: dict[str, str]
    owners: dict[str, str]
    columns: dict[str, frozenset[str]]
    partitions: dict[str, frozenset[str]]
    triggers: dict[tuple[str, str], str]
    functions: dict[str, str]
    unique_indexes: dict[str, tuple[frozenset[str], ...]]
    partial_unique_index_names: frozenset[str]
    privileges: dict[tuple[str, str], bool]
    column_updates: dict[tuple[str, str], bool]
    can_create_schema: bool
    role_flags: dict[str, bool]
    memberships: tuple[str, ...]
    privileged_roles: tuple[str, ...]
    search_path: str
    security_definers: tuple[str, ...]


_IDENTITY_SQL = text(
    "SELECT current_user AS current_user_name, session_user AS session_user_name, "
    "current_setting('search_path') AS search_path, CURRENT_DATE AS today"
)
#: Guarded so a missing table or a missing grant returns NULL instead of
#: aborting the transaction the rest of the facts are gathered in.
_REVISION_SQL = text(
    "SELECT CASE WHEN to_regclass('alembic_version') IS NOT NULL "
    "AND has_table_privilege('alembic_version', 'SELECT') "
    "THEN (SELECT version_num FROM alembic_version LIMIT 1) END AS revision"
)
#: ``relkind`` and ``tgenabled`` are PostgreSQL's single-byte ``"char"`` type,
#: which asyncpg hands back as *bytes* (``b'p'``, ``b'O'``) rather than ``str``.
#: Both are cast to text in the statement rather than decoded afterwards,
#: because the comparison that matters is silent when it is wrong: ``b'D' ==
#: "D"`` is simply False, so a *disabled* append-only trigger would read as
#: enabled and this probe would certify a database whose guarantees were off.
_RELATION_SQL = text(
    "SELECT c.relname, c.relkind::text, pg_get_userbyid(c.relowner) AS owner "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'v', 'p')"
)
_TRIGGER_SQL = text(
    "SELECT t.tgname, c.relname, t.tgenabled::text FROM pg_trigger t "
    "JOIN pg_class c ON c.oid = t.tgrelid "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE NOT t.tgisinternal AND n.nspname = current_schema()"
)
_FUNCTION_SQL = text("SELECT p.proname, p.prosrc FROM pg_proc p WHERE p.proname = ANY(:names)")
_COLUMN_SQL = text(
    "SELECT c.relname, a.attname FROM pg_attribute a "
    "JOIN pg_class c ON c.oid = a.attrelid "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = current_schema() AND a.attnum > 0 AND NOT a.attisdropped "
    "AND c.relname = ANY(:tables)"
)
_PARTITION_SQL = text(
    "SELECT p.relname AS parent, ch.relname AS partition FROM pg_inherits h "
    "JOIN pg_class p ON p.oid = h.inhparent "
    "JOIN pg_class ch ON ch.oid = h.inhrelid "
    "JOIN pg_namespace n ON n.oid = p.relnamespace "
    "WHERE n.nspname = current_schema() AND p.relname = ANY(:tables)"
)
_INDEX_SQL = text(
    "SELECT c.relname AS table_name, i.relname AS index_name, ix.indisunique AS is_unique, "
    "ix.indpred IS NOT NULL AS is_partial, "
    "(SELECT array_agg(a.attname ORDER BY a.attname) FROM pg_attribute a "
    " WHERE a.attrelid = c.oid AND a.attnum = ANY(ix.indkey)) AS column_names "
    "FROM pg_index ix JOIN pg_class i ON i.oid = ix.indexrelid "
    "JOIN pg_class c ON c.oid = ix.indrelid "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = current_schema() AND c.relname = ANY(:tables)"
)
_ROLE_SQL = text(
    "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication "
    "FROM pg_roles WHERE rolname = :role"
)
_MEMBERSHIP_SQL = text(
    "SELECT g.rolname FROM pg_auth_members m "
    "JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member "
    "WHERE u.rolname = current_user"
)
_PRIVILEGED_ROLE_SQL = text(
    "SELECT rolname FROM pg_roles WHERE rolname = ANY(:roles) "
    "AND pg_has_role(current_user, oid, 'USAGE')"
)
_SECURITY_DEFINER_SQL = text(
    "SELECT n.nspname || '.' || p.proname AS qualified FROM pg_proc p "
    "JOIN pg_namespace n ON n.oid = p.pronamespace "
    "WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND has_function_privilege(current_user, p.oid, 'EXECUTE')"
)
#: Batched: the matrix asks about a few hundred (table, privilege) pairs, and a
#: readiness probe that costs a round trip each would be a reason not to run it.
_TABLE_PRIVILEGE_SQL = text(
    "SELECT u.t AS table_name, u.p AS privilege, has_table_privilege(:role, u.t, u.p) AS granted "
    "FROM unnest(CAST(:tables AS text[]), CAST(:privileges AS text[])) AS u(t, p)"
)
_COLUMN_PRIVILEGE_SQL = text(
    "SELECT u.t AS table_name, u.c AS column_name, "
    "has_column_privilege(:role, u.t, u.c, 'UPDATE') AS granted "
    "FROM unnest(CAST(:tables AS text[]), CAST(:columns AS text[])) AS u(t, c)"
)
_SCHEMA_CREATE_SQL = text(
    "SELECT has_schema_privilege(:role, current_schema(), 'CREATE') AS can_create"
)


async def gather_database_facts(session: Any) -> DatabaseFacts:
    """Read every fact the checks need in one session."""
    identity = (await session.execute(_IDENTITY_SQL)).one()
    revision = (await session.execute(_REVISION_SQL)).scalar_one()
    role_exists = (
        await session.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": DATABASE_ROLE}
        )
    ).first() is not None

    relations: dict[str, str] = {}
    owners: dict[str, str] = {}
    for name, relkind, owner in (await session.execute(_RELATION_SQL)).all():
        relations[name] = relkind
        owners[name] = owner

    triggers = {
        (name, table): enabled
        for name, table, enabled in (await session.execute(_TRIGGER_SQL)).all()
    }
    functions = {
        name: function_fingerprint(source)
        for name, source in (
            await session.execute(_FUNCTION_SQL, {"names": list(EXPECTED_FUNCTION_FINGERPRINTS)})
        ).all()
    }

    partitions: dict[str, frozenset[str]] = {}
    for parent, partition in (
        await session.execute(_PARTITION_SQL, {"tables": list(PARTITIONED_TABLES)})
    ).all():
        partitions[parent] = partitions.get(parent, frozenset()) | {partition}

    known_tables = sorted(
        {*VERIFICATION_TABLES, *PARTITIONED_TABLES, *_partition_names(partitions)}
    )
    columns: dict[str, frozenset[str]] = {}
    for table, column in (
        await session.execute(_COLUMN_SQL, {"tables": known_tables})
    ).all():
        columns[table] = columns.get(table, frozenset()) | {column}

    unique_indexes: dict[str, tuple[frozenset[str], ...]] = {}
    partial_unique: set[str] = set()
    for table, index, is_unique, is_partial, column_names in (
        await session.execute(_INDEX_SQL, {"tables": known_tables})
    ).all():
        if not is_unique:
            continue
        unique_indexes[table] = (
            *unique_indexes.get(table, ()),
            frozenset(column_names or ()),
        )
        if is_partial:
            partial_unique.add(index)

    privileges, column_updates, can_create = await _privilege_facts(
        session, relations=relations, columns=columns, role_exists=role_exists
    )

    role_row = (await session.execute(_ROLE_SQL, {"role": identity.current_user_name})).first()
    role_flags = (
        {
            "rolsuper": bool(role_row[0]),
            "rolcreaterole": bool(role_row[1]),
            "rolcreatedb": bool(role_row[2]),
            "rolbypassrls": bool(role_row[3]),
            "rolreplication": bool(role_row[4]),
        }
        if role_row is not None
        else {}
    )
    memberships = tuple(sorted((await session.execute(_MEMBERSHIP_SQL)).scalars()))
    privileged = tuple(
        sorted(
            (
                await session.execute(
                    _PRIVILEGED_ROLE_SQL, {"roles": list(PRIVILEGED_ROLE_MEMBERSHIPS)}
                )
            ).scalars()
        )
    )
    definers = tuple(sorted((await session.execute(_SECURITY_DEFINER_SQL)).scalars()))

    return DatabaseFacts(
        current_user=str(identity.current_user_name),
        session_user=str(identity.session_user_name),
        today=identity.today,
        revision=None if revision is None else str(revision),
        role_exists=role_exists,
        relations=relations,
        owners=owners,
        columns=columns,
        partitions=partitions,
        triggers=triggers,
        functions=functions,
        unique_indexes=unique_indexes,
        partial_unique_index_names=frozenset(partial_unique),
        privileges=privileges,
        column_updates=column_updates,
        can_create_schema=can_create,
        role_flags=role_flags,
        memberships=memberships,
        privileged_roles=privileged,
        search_path=str(identity.search_path),
        security_definers=definers,
    )


def _partition_names(partitions: Mapping[str, frozenset[str]]) -> frozenset[str]:
    found: set[str] = set()
    for names in partitions.values():
        found |= set(names)
    return frozenset(found)


async def _privilege_facts(
    session: Any,
    *,
    relations: Mapping[str, str],
    columns: Mapping[str, frozenset[str]],
    role_exists: bool,
) -> tuple[dict[tuple[str, str], bool], dict[tuple[str, str], bool], bool]:
    """has_table_privilege / has_column_privilege for the whole matrix.

    Pairs naming a relation or a column that does not exist are skipped here and
    reported by the schema checks instead: "the privilege could not be read" and
    "the column is missing" are different problems with different fixes.
    """
    if not role_exists:
        return {}, {}, False

    table_pairs = [
        (table, privilege)
        for (table, privilege) in expected_table_privileges()
        if table in relations
    ]
    privileges: dict[tuple[str, str], bool] = {}
    if table_pairs:
        rows = (
            await session.execute(
                _TABLE_PRIVILEGE_SQL,
                {
                    "role": DATABASE_ROLE,
                    "tables": [t for t, _ in table_pairs],
                    "privileges": [p for _, p in table_pairs],
                },
            )
        ).all()
        privileges = {(str(t), str(p)): bool(granted) for t, p, granted in rows}

    column_pairs = [
        (table, column)
        for (table, column) in expected_column_updates()
        if table in relations and column in columns.get(table, frozenset())
    ]
    column_updates: dict[tuple[str, str], bool] = {}
    if column_pairs:
        rows = (
            await session.execute(
                _COLUMN_PRIVILEGE_SQL,
                {
                    "role": DATABASE_ROLE,
                    "tables": [t for t, _ in column_pairs],
                    "columns": [c for _, c in column_pairs],
                },
            )
        ).all()
        column_updates = {(str(t), str(c)): bool(granted) for t, c, granted in rows}

    can_create = bool(
        (await session.execute(_SCHEMA_CREATE_SQL, {"role": DATABASE_ROLE})).scalar_one()
    )
    return privileges, column_updates, can_create


# =============================================================================
# Judging the facts
# =============================================================================


def schema_barrier_checks(facts: DatabaseFacts) -> list[Check]:
    """The barrier: exact revision, every object, every enabled trigger."""
    checks: list[Check] = [
        Check(
            "schema_revision_exact",
            facts.revision == EXPECTED_ALEMBIC_REVISION,
            f"schema is at revision {EXPECTED_ALEMBIC_REVISION}"
            if facts.revision == EXPECTED_ALEMBIC_REVISION
            else (
                f"schema is at {facts.revision!r}, not {EXPECTED_ALEMBIC_REVISION!r} "
                "(a barrier, not a preference: the facts below describe one revision)"
                if facts.revision is not None
                else "the migration revision could not be read "
                f"(grant SELECT ON {BARRIER_TABLE} to this role)"
            ),
            details={"expected": EXPECTED_ALEMBIC_REVISION, "deployed": facts.revision},
        )
    ]

    missing = [t for t in (*VERIFICATION_TABLES, VIEW_NAME) if t not in facts.relations]
    wrong_kind = [
        f"{table} is {facts.relations[table]!r}, expected a partitioned table"
        for table in PARTITIONED_TABLES
        if facts.relations.get(table) not in (None, "p")
    ]
    checks.append(
        Check(
            "schema_present",
            not missing and not wrong_kind,
            "every verification table, the partitioned parents and the read view exist"
            if not missing and not wrong_kind
            else "; ".join([*(f"missing: {m}" for m in missing), *wrong_kind][:8]),
            details={"missing": missing, "wrong_kind": wrong_kind},
        )
    )

    absent_columns = [
        f"{table}.{column}"
        for (table, column) in expected_column_updates()
        if table in facts.relations and column not in facts.columns.get(table, frozenset())
    ]
    checks.append(
        Check(
            "expected_columns_present",
            not absent_columns,
            "every column the privilege matrix names exists"
            if not absent_columns
            else f"missing columns: {', '.join(absent_columns[:10])}",
            details={"missing": absent_columns},
        )
    )

    unmatched: list[str] = []
    for table, required in EXPECTED_UNIQUE_COLUMNS.items():
        if table not in facts.relations:
            continue
        have = facts.unique_indexes.get(table, ())
        for want in required:
            if not any(want <= columns for columns in have):
                unmatched.append(f"{table}({', '.join(sorted(want))})")
    checks.append(
        Check(
            "unique_keys_present",
            not unmatched,
            "every identity this layer keys on is unique in the database"
            if not unmatched
            else f"no unique index covers: {'; '.join(unmatched[:8])}",
            details={"unmatched": unmatched},
        )
    )

    partial_present = OPEN_PASS_INDEX in facts.partial_unique_index_names
    checks.append(
        Check(
            "open_pass_index_partial_unique",
            partial_present,
            f"{OPEN_PASS_INDEX} allows one open pass per scan"
            if partial_present
            else f"{OPEN_PASS_INDEX} is missing or is not a partial unique index: "
            "two processes would both see no open pass and both insert one",
            details={"index": OPEN_PASS_INDEX},
        )
    )

    checks.extend(_partition_checks(facts))
    checks.extend(_trigger_checks(facts))
    return checks


def _partition_checks(facts: DatabaseFacts) -> list[Check]:
    """A write path now, real months ahead, and a guard on every partition.

    The three are separate because their failures differ. With no partition for
    today and no default, an insert is refused outright. With only the default,
    writes succeed but retention cannot tier a catch-all, which is a problem
    with weeks of warning rather than minutes. A partition missing its own
    guards is a hole somebody opened by hand.
    """
    found = _partition_names(facts.partitions)
    unwritable = [
        table
        for table in PARTITIONED_TABLES
        if default_partition(table) not in found
        and partition_name(table, facts.today.year, facts.today.month) not in found
    ]
    checks = [
        Check(
            "partition_write_path_present",
            not unwritable,
            "every partitioned table can accept a row written now"
            if not unwritable
            else f"no partition covers {facts.today.isoformat()} on "
            f"{', '.join(unwritable)}: an insert would be refused",
            details={"as_of": facts.today.isoformat(), "tables": unwritable},
        )
    ]

    short = [
        name
        for table in PARTITIONED_TABLES
        for year, month in month_sequence(facts.today, PARTITION_WARN_MONTHS)
        if (name := partition_name(table, year, month)) not in found
    ]
    checks.append(
        Check(
            "partition_horizon",
            not short,
            f"at least {PARTITION_WARN_MONTHS} months of partitions remain"
            if not short
            else f"the partition horizon is short: {', '.join(short)} do not exist yet, "
            "so rows will land in the default partition that retention cannot tier",
            fatal=False,
            details={
                "warn_months": PARTITION_WARN_MONTHS,
                "missing": short,
                "expected_now": list(required_partitions(facts.today)),
            },
        )
    )

    missing_keys: list[str] = []
    for parent, children in sorted(facts.partitions.items()):
        want = frozenset(PARTITION_UNIQUE_COLUMNS.get(parent, ()))
        if not want:
            continue
        for child in sorted(children):
            have = facts.unique_indexes.get(child, ())
            if not any(want <= columns for columns in have):
                missing_keys.append(f"{child}({', '.join(sorted(want))})")
    checks.append(
        Check(
            "partition_narrow_keys_present",
            not missing_keys,
            "every partition carries the narrow unique key its parent cannot hold"
            if not missing_keys
            else f"no unique index covers: {'; '.join(missing_keys[:8])}",
            details={"missing": missing_keys, "expected": sorted(PARTITION_UNIQUE_COLUMNS)},
        )
    )
    return checks


def _trigger_checks(facts: DatabaseFacts) -> list[Check]:
    """Every append-only guard, on every table *and every partition*.

    A row-level trigger on a partitioned parent is cloned onto its partitions,
    including ones attached later, so the clones are checked rather than assumed.
    The statement-level truncate guard is not cloned and is created per
    partition, which makes "a partition added by hand" a visible failure instead
    of a silent gap.
    """
    problems: list[str] = []
    expected: dict[str, str] = dict(expected_triggers())
    for parent, children in facts.partitions.items():
        if parent not in PARTITION_KEY_BY_TABLE:
            continue
        for child in sorted(children):
            expected[f"trg_{parent}_no_mutation@{child}"] = child
            expected[partition_truncate_trigger(child)] = child

    for name, table in expected.items():
        trigger = name.split("@", 1)[0]
        state = facts.triggers.get((trigger, table))
        if state is None:
            problems.append(f"{trigger} on {table} missing")
        elif state == "D":
            problems.append(f"{trigger} on {table} disabled")

    checks = [
        Check(
            "append_only_triggers_enabled",
            not problems,
            "every append-only and no-truncate trigger exists and is enabled, "
            "on the tables and on their partitions"
            if not problems
            else "; ".join(problems[:8]),
            details={"expected": len(expected), "problems": problems},
        )
    ]

    drift = [
        name
        for name, expected_digest in EXPECTED_FUNCTION_FINGERPRINTS.items()
        if facts.functions.get(name) != expected_digest
    ]
    checks.append(
        Check(
            "trigger_functions_unaltered",
            not drift,
            "trigger function bodies match this code"
            if not drift
            else f"function body differs or is missing: {', '.join(drift)}",
            details={"drifted": drift},
        )
    )
    return checks


def privilege_matrix_checks(facts: DatabaseFacts) -> list[Check]:
    if not facts.role_exists:
        return [
            Check("role_privileges_exact", False, f"role {DATABASE_ROLE} does not exist"),
        ]

    wrong = [
        f"{table}.{privilege}={'granted' if facts.privileges[(table, privilege)] else 'missing'}"
        for (table, privilege), want in expected_table_privileges().items()
        if (table, privilege) in facts.privileges
        and facts.privileges[(table, privilege)] != want
    ]
    wrong += [
        f"{table}({column}).UPDATE="
        f"{'granted' if facts.column_updates[(table, column)] else 'missing'}"
        for (table, column), want in expected_column_updates().items()
        if (table, column) in facts.column_updates
        and facts.column_updates[(table, column)] != want
    ]
    if facts.can_create_schema:
        wrong.append("schema.CREATE=granted")

    checked = len(facts.privileges) + len(facts.column_updates)
    return [
        Check(
            "role_privileges_exact",
            not wrong,
            f"{DATABASE_ROLE} holds exactly its write set, with no upstream write, no "
            "gateway write, no DELETE, no TRUNCATE and no DDL"
            if not wrong
            else "; ".join(wrong[:10]),
            details={"checked": checked, "wrong": wrong},
        )
    ]


def custody_checks(facts: DatabaseFacts, *, prod: bool) -> list[Check]:
    """One role, not the owner, not a superuser, nothing shadowable.

    These are the checks that make the layer's claims mean something. A process
    that can reach a second identity, own the tables it writes, or call a
    ``SECURITY DEFINER`` function owned by someone powerful is a process whose
    privilege matrix describes an intention rather than a limit.
    """
    one_role = facts.current_user == facts.session_user
    extra = [*facts.memberships, *facts.privileged_roles]
    checks: list[Check] = [
        Check(
            "custody_single_role",
            one_role and not extra,
            f"the session holds exactly one role ({facts.current_user})"
            if one_role and not extra
            else (
                f"the session switched role: connected as {facts.session_user!r}, "
                f"acting as {facts.current_user!r}"
                if not one_role
                else f"role membership grants more than the matrix: {', '.join(sorted(set(extra)))}"
            ),
            details={
                "current_user": facts.current_user,
                "session_user": facts.session_user,
                "memberships": list(facts.memberships),
                "privileged_roles": list(facts.privileged_roles),
            },
        ),
        Check(
            "dedicated_role",
            facts.current_user == DATABASE_ROLE,
            f"the verification process authenticates as {DATABASE_ROLE}"
            if facts.current_user == DATABASE_ROLE
            else f"connected as {facts.current_user!r}, not the dedicated {DATABASE_ROLE!r} role",
            fatal=prod,
        ),
    ]

    attributes = sorted(name for name, held in facts.role_flags.items() if held)
    owned = sorted(
        table
        for table in (*VERIFICATION_TABLES, VIEW_NAME)
        if facts.owners.get(table) == facts.current_user
    )
    checks.append(
        Check(
            "custody_not_owner_not_superuser",
            not attributes and not owned,
            "the role is neither a superuser nor the owner of the tables it writes"
            if not attributes and not owned
            else "; ".join(
                [
                    *(f"role attribute {a} is set" for a in attributes),
                    *(f"owns {t}" for t in owned),
                ][:8]
            ),
            details={"attributes": attributes, "owned": owned},
        )
    )

    entries = [part.strip().strip('"') for part in facts.search_path.split(",") if part.strip()]
    unsafe = [entry for entry in entries if entry not in SAFE_SEARCH_PATH_ENTRIES]
    checks.append(
        Check(
            "custody_search_path_restricted",
            not unsafe,
            f"search_path is restricted to {', '.join(entries)}"
            if not unsafe
            else f"search_path names {', '.join(unsafe)}: a table or function there can "
            "shadow the one this layer meant to use",
            details={"search_path": facts.search_path},
        )
    )

    checks.append(
        Check(
            "custody_no_security_definer",
            not facts.security_definers,
            "no SECURITY DEFINER function is callable by this role"
            if not facts.security_definers
            else "callable SECURITY DEFINER functions: "
            f"{', '.join(facts.security_definers[:8])}",
            details={"functions": list(facts.security_definers)},
        )
    )
    return checks


def retirement_checks(facts: DatabaseFacts) -> list[Check]:
    """The competing schema is retired, so a finding lives in one place.

    Advisory rather than fatal: nothing this layer writes or decides depends on
    the placeholder tables, and refusing to start over a cleanup nobody has run
    yet would make readiness the obstacle instead of the diagnosis. The role
    holds no privilege on either table in any case (CHG-P5-038).
    """
    remaining = [t for t in ("findings", "exploit_chain") if t in facts.relations]
    return [
        Check(
            "legacy_evidence_retired",
            not remaining,
            "the placeholder finding table is retired and the chain placeholder is gone"
            if not remaining
            else f"still present: {', '.join(remaining)} — rename to legacy_findings and "
            "drop the chain placeholder",
            fatal=False,
            details={"remaining": remaining},
        )
    ]


def facts_checks(facts: DatabaseFacts, *, prod: bool) -> list[Check]:
    """Every database check, as a pure function of the gathered facts."""
    return [
        *custody_checks(facts, prod=prod),
        *schema_barrier_checks(facts),
        *privilege_matrix_checks(facts),
        *retirement_checks(facts),
    ]


async def database_checks(database: Database, *, prod: bool) -> list[Check]:
    try:
        async with database.session() as session:
            facts = await gather_database_facts(session)
    except Exception as exc:
        # Any failure here is "not ready": an unreachable database, a refused
        # catalog read, a driver error. None of them is a reason to report a
        # partial matrix as if it had been checked.
        return [Check("database_reachable", False, f"{type(exc).__name__}: {exc}")]
    return [
        Check("database_reachable", True, f"connected as {facts.current_user}"),
        *facts_checks(facts, prod=prod),
    ]


async def check_verification_readiness(
    services: VerificationServices, *, handshake: HandshakeProbe | None = None
) -> ReadinessReport:
    """Every readiness check, in one report with a JSON payload.

    ``handshake`` exists so the gateway probe can be driven against an in-memory
    stream: the property worth testing is that a missing feature refuses, and
    proving that must not require a running service.
    """
    prod = services.core.environment == "prod"
    checks = configuration_checks(services, prod=prod)
    checks.extend(await gateway_checks(services, prod=prod, handshake=handshake))
    checks.extend(await database_checks(services.database, prod=prod))
    return ReadinessReport(checks=tuple(checks), environment=services.core.environment)
