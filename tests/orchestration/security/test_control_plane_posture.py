"""Control-plane posture: telemetry, authority confinement, no write path.

The orchestration process is the most privileged component in the system — it
holds the live authorization and can drive every tool — so these tests cover
the ways it could leak that position rather than the ways a tool could misbehave.
"""

from __future__ import annotations

import ast
import pkgutil
from pathlib import Path

import pytest

import gryphon.orchestration as orchestration_pkg
from gryphon.orchestration.reasons import OrchestrationConfigurationError
from gryphon.orchestration.settings import (
    TELEMETRY_ENV_VARS,
    OrchestrationSettings,
    assert_telemetry_disabled,
    neutralize_telemetry,
)

pytestmark = pytest.mark.security

ORCHESTRATION_ROOT = Path(orchestration_pkg.__file__).parent


def _orchestration_sources() -> list[Path]:
    return sorted(ORCHESTRATION_ROOT.rglob("*.py"))


def _code_symbols(path: Path) -> set[str]:
    """Return the dotted names a module actually *uses*, ignoring prose.

    Parsed from the AST rather than grepped from the text, because this package
    discusses subprocesses and network clients at length in its docstrings — it
    exists to delegate both — and a text match on "a second subprocess." in a
    sentence is not evidence of a call. Scanning code means the test fails only
    when an import or an attribute access really appears.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                symbols.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            symbols.add(module)
            for alias in node.names:
                symbols.add(f"{module}.{alias.name}")
                symbols.add(alias.name)
        elif isinstance(node, ast.Attribute):
            symbols.add(_dotted(node))
        elif isinstance(node, ast.Name):
            symbols.add(node.id)
        elif isinstance(node, ast.keyword) and node.arg:
            symbols.add(f"keyword:{node.arg}")
    return symbols


def _dotted(node: ast.Attribute) -> str:
    """Flatten ``a.b.c`` into a dotted string where possible."""
    parts: list[str] = [node.attr]
    current: ast.expr = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


# -- third-party telemetry ----------------------------------------------------
@pytest.mark.parametrize("var", ["LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2"])
def test_startup_refuses_when_tracing_is_enabled(var: str) -> None:
    """One inherited environment variable must not be able to export scan data.

    The tracing client is a mandatory transitive dependency and activates from
    the environment alone — no code change required. Its payloads would be node
    inputs and outputs: client hostnames, discovered attack surface, findings.
    """
    with pytest.raises(OrchestrationConfigurationError, match="tracing must be disabled"):
        assert_telemetry_disabled({var: "true"})


@pytest.mark.parametrize("var", ["LANGSMITH_API_KEY", "LANGCHAIN_API_KEY"])
def test_startup_refuses_a_tracing_api_key(var: str) -> None:
    """A key is only meaningful for exporting, so its presence is refused."""
    with pytest.raises(OrchestrationConfigurationError):
        assert_telemetry_disabled({var: "ls-secret"})


def test_endpoint_override_is_refused() -> None:
    with pytest.raises(OrchestrationConfigurationError):
        assert_telemetry_disabled({"LANGSMITH_ENDPOINT": "https://example.invalid"})


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "FALSE"])
def test_explicitly_disabled_tracing_is_tolerated(value: str) -> None:
    assert_telemetry_disabled({"LANGSMITH_TRACING": value})


def test_neutralize_sets_the_flags_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGSMITH_TRACING", raising=False)
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    neutralize_telemetry()
    import os

    assert os.environ["LANGSMITH_TRACING"] == "false"
    assert os.environ["LANGCHAIN_TRACING_V2"] == "false"
    # And the result must satisfy our own assertion.
    assert_telemetry_disabled()


def test_every_watched_variable_is_a_tracing_variable() -> None:
    assert all(
        v.startswith(("LANGSMITH_", "LANGCHAIN_")) for v in TELEMETRY_ENV_VARS
    )


# -- no write path to admissions ---------------------------------------------
def test_orchestration_never_imports_the_admission_writer() -> None:
    """Nothing here may create an admission.

    Continuous scanning needs *standing* authority while the authorization model
    is *per-engagement*. If anything at or above this layer could mint an
    admission, a future scheduler would become a second authorization authority
    — inverting the product's central claim that nothing is scanned without a
    signed human authorization. The database grants enforce this when the layer
    runs under its own role; this test enforces it in code unconditionally.
    """
    forbidden = {"ScanRunRepository", "AuthorizationService", "ScanAdmissionRequest"}
    offenders: list[str] = []
    for path in _orchestration_sources():
        for symbol in sorted(_code_symbols(path) & forbidden):
            offenders.append(f"{path.name}: {symbol}")
    assert not offenders, f"orchestration must not write admissions: {offenders}"


def test_orchestration_does_not_mint_permits_itself() -> None:
    """Minting is the authorization layer's privilege, exercised by its resolver."""
    offenders = [
        path.name
        for path in _orchestration_sources()
        if "mint_permit" in _code_symbols(path)
    ]
    assert not offenders, f"permit minting must stay in the auth layer: {offenders}"


# -- no bypass of the enforcement boundary -----------------------------------
def test_orchestration_never_spawns_a_process_or_builds_a_shell_command() -> None:
    """All tool execution goes through the enforcement layer, without exception."""
    forbidden = {
        "subprocess",
        "os.system",
        "os.execv",
        "os.popen",
        "os.spawnv",
        "pty",
        "keyword:shell",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
    }
    offenders: list[str] = []
    for path in _orchestration_sources():
        for symbol in sorted(_code_symbols(path) & forbidden):
            offenders.append(f"{path.name}: {symbol}")
    assert not offenders, f"no direct execution is permitted here: {offenders}"


def test_orchestration_opens_no_network_client() -> None:
    """The control plane talks to the database and the enforcement layer only.

    ``socket`` appears in the command boundary solely to read a Unix peer
    credential, which is a local authentication primitive rather than an
    outbound client.
    """
    forbidden = {
        "httpx",
        "requests",
        "aiohttp",
        "urllib",
        "urllib.request",
        "websockets",
        "http.client",
        "ftplib",
        "smtplib",
        "langsmith",
    }
    offenders: list[str] = []
    for path in _orchestration_sources():
        for symbol in sorted(_code_symbols(path) & forbidden):
            offenders.append(f"{path.name}: {symbol}")
    assert not offenders, f"no outbound client is permitted here: {offenders}"


# -- authority confinement ----------------------------------------------------
def test_only_the_touchpoint_resolves_authority() -> None:
    """One place reaches the permit, so one place enforces the precondition."""
    importers = [
        path.name
        for path in _orchestration_sources()
        if path.name != "touchpoint.py"
        and "resolve_admitted_permit" in _code_symbols(path)
    ]
    assert not importers, f"authority must be reached via the touchpoint: {importers}"


def test_runtime_bundle_exposes_no_authority_field() -> None:
    """A node must not be able to read standing authority off the runtime."""
    from gryphon.orchestration.runtime import ScanRuntime

    banned = ("permit", "token", "capability", "secret", "salt", "key")
    for field in ScanRuntime.__dataclass_fields__:
        assert not any(b in field.lower() for b in banned), field


def test_every_module_in_the_package_is_importable() -> None:
    """A package that cannot be imported cannot be reviewed or tested."""
    failures: list[str] = []
    for module in pkgutil.walk_packages(
        orchestration_pkg.__path__, prefix="gryphon.orchestration."
    ):
        try:
            __import__(module.name)
        except Exception as exc:  # pragma: no cover - surfaces real breakage
            failures.append(f"{module.name}: {exc}")
    assert not failures, failures


# -- configuration fails closed ----------------------------------------------
def test_heartbeat_must_be_shorter_than_the_lease() -> None:
    """A lease shorter than its heartbeat would let a live owner lose its claim."""
    with pytest.raises(OrchestrationConfigurationError, match="heartbeat"):
        OrchestrationSettings(
            _env_file=None, scan_lease_seconds=10.0, scan_heartbeat_seconds=10.0
        )


def test_lease_must_tolerate_a_missed_heartbeat() -> None:
    """One missed beat must not hand the scan to a second owner."""
    with pytest.raises(OrchestrationConfigurationError, match="twice"):
        OrchestrationSettings(
            _env_file=None, scan_lease_seconds=15.0, scan_heartbeat_seconds=10.0
        )


def test_sweeper_cannot_run_slower_than_the_lease() -> None:
    with pytest.raises(OrchestrationConfigurationError, match="sweeper_interval"):
        OrchestrationSettings(
            _env_file=None,
            scan_lease_seconds=60.0,
            scan_heartbeat_seconds=15.0,
            sweeper_interval_seconds=120.0,
        )


def test_production_requires_an_authenticated_caller() -> None:
    with pytest.raises(OrchestrationConfigurationError, match="control_socket_path"):
        OrchestrationSettings(
            _env_file=None,
            environment="prod",
            attested_estate_cidrs=("203.0.113.0/24",),
        )


def test_production_requires_an_attested_estate() -> None:
    with pytest.raises(OrchestrationConfigurationError, match="attested_estate"):
        OrchestrationSettings(
            _env_file=None,
            environment="prod",
            control_socket_path="/run/gryphon.sock",
            control_allowed_uids=(1000,),
        )


def test_production_cannot_disable_address_attestation() -> None:
    with pytest.raises(OrchestrationConfigurationError, match="strict_address"):
        OrchestrationSettings(
            _env_file=None,
            environment="prod",
            control_socket_path="/run/gryphon.sock",
            control_allowed_uids=(1000,),
            attested_estate_cidrs=("203.0.113.0/24",),
            strict_address_attestation=False,
        )


def test_a_control_socket_without_an_allowlist_is_refused() -> None:
    """An authenticated surface with an empty allowlist authenticates nothing."""
    with pytest.raises(OrchestrationConfigurationError, match="control_allowed_uids"):
        OrchestrationSettings(
            _env_file=None, control_socket_path="/run/gryphon.sock"
        )
