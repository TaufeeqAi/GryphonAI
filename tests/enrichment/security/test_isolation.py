"""Process isolation and key separation — the boundaries the design rests on.

* The key-holding parent process must contain no HTTP client and no
  orchestration code (probed in a fresh interpreter).
* The acquisition child must contain no database driver, settings or key code,
  and runs with a scrubbed environment.
* The enrichment signing key may share neither kid nor key with another purpose.
* In production the enrichment DSN must use the dedicated role.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import build_key_material
from gryphon.enrichment.bootstrap import assert_dedicated_role, assert_key_separation
from gryphon.enrichment.readiness import FORBIDDEN_PARENT_MODULES, import_graph_check
from gryphon.enrichment.reasons import EnrichmentConfigurationError
from gryphon.enrichment.settings import EnrichmentSettings
from gryphon.enrichment.snapshots import child_environment
from gryphon.settings import Settings
from gryphon.tooling.settings import ToolingSettings

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[3]


def _probe(code: str) -> list[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GRYPHON_")}
    env["PYTHONPATH"] = str(REPO)
    out = subprocess.run(  # noqa: S603 - fixed interpreter, fixed code
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, cwd=str(REPO),
        timeout=120, check=True,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def _loaded(forbidden: tuple[str, ...]) -> str:
    return (
        f"forbidden = {forbidden!r}\n"
        "loaded = [m for m in forbidden if m in sys.modules "
        "or any(k.startswith(m + '.') for k in sys.modules)]\n"
        "print(json.dumps(loaded))\n"
    )


def test_parent_process_imports_no_http_client_or_orchestration() -> None:
    code = (
        "import json, sys\n"
        "import gryphon.enrichment.bootstrap, gryphon.enrichment.engine\n"
        "import gryphon.enrichment.readiness, gryphon.enrichment.publish\n"
        + _loaded(FORBIDDEN_PARENT_MODULES)
    )
    assert _probe(code) == []


def test_acquisition_child_imports_no_database_settings_or_keys() -> None:
    code = (
        "import importlib, json, sys\n"
        "importlib.import_module('gryphon.enrichment.acquisition.__main__')\n"
        + _loaded(("sqlalchemy", "asyncpg", "pydantic", "pydantic_settings", "cryptography",
                   "gryphon.settings", "gryphon.db", "gryphon.auth", "gryphon.enrichment.settings",
                   "gryphon.enrichment.repository"))
    )
    assert _probe(code) == []


def test_import_graph_check_detects_forbidden_modules() -> None:
    assert not import_graph_check({"httpx": object()}).passed
    assert not import_graph_check({"gryphon.orchestration.engine": object()}).passed
    assert import_graph_check({"json": object()}).passed


def test_child_environment_carries_no_secrets_or_proxies(monkeypatch) -> None:
    monkeypatch.setenv("GRYPHON_ENRICHMENT_SIGNING_KEY_HEX", "00" * 32)
    monkeypatch.setenv("GRYPHON_DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
    monkeypatch.setenv("SSL_CERT_FILE", "evil-ca-bundle.pem")
    env = child_environment()
    assert not any(k.startswith("GRYPHON_") for k in env)
    assert "HTTPS_PROXY" not in env and "SSL_CERT_FILE" not in env
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"


# -- key separation ----------------------------------------------------------------
def _pair() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    return (
        key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                          serialization.NoEncryption()).hex(),
        key.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw).hex(),
    )


@pytest.fixture
def core() -> tuple[Settings, dict[str, str]]:
    grant_priv, grant_pub = _pair()
    audit_priv, audit_pub = _pair()
    settings = Settings(
        _env_file=None, environment="test", issuer="gryphon-test-issuer",
        audience="gryphon-test-audience",
        grant_signing_key_hex=grant_priv, grant_kid="grant-test",
        grant_trusted_public_keys={"grant-test": grant_pub},
        audit_signing_key_hex=audit_priv, audit_kid="audit-test",
        audit_trusted_public_keys={"audit-test": audit_pub},
    )
    return settings, {"grant_pub": grant_pub, "audit_pub": audit_pub, "audit_priv": audit_priv}


def test_dedicated_key_passes(core) -> None:
    settings, _ = core
    _, public = _pair()
    assert_key_separation(enrichment_kid="enrichment-1", enrichment_public_hex=public,
                          core=settings, keys=build_key_material(settings),
                          tooling=ToolingSettings(_env_file=None, environment="test"))


def test_reused_audit_key_is_refused(core) -> None:
    settings, hexes = core
    with pytest.raises(EnrichmentConfigurationError, match="another purpose"):
        assert_key_separation(enrichment_kid="enrichment-1",
                              enrichment_public_hex=hexes["audit_pub"], core=settings,
                              keys=build_key_material(settings),
                              tooling=ToolingSettings(_env_file=None, environment="test"))


def test_reused_kid_is_refused(core) -> None:
    settings, _ = core
    _, public = _pair()
    with pytest.raises(EnrichmentConfigurationError, match="kid"):
        assert_key_separation(enrichment_kid="grant-test", enrichment_public_hex=public,
                              core=settings, keys=build_key_material(settings),
                              tooling=ToolingSettings(_env_file=None, environment="test"))


def test_reused_capability_key_is_refused(core) -> None:
    settings, _ = core
    cap_priv, cap_pub = _pair()
    tooling = ToolingSettings(_env_file=None, environment="test",
                              capability_signing_key_hex=cap_priv, capability_kid="cap-1",
                              capability_trusted_public_keys={"cap-1": cap_pub})
    with pytest.raises(EnrichmentConfigurationError):
        assert_key_separation(enrichment_kid="enrichment-1", enrichment_public_hex=cap_pub,
                              core=settings, keys=build_key_material(settings), tooling=tooling)


def test_production_requires_the_dedicated_role() -> None:
    shared = EnrichmentSettings(
        _env_file=None,
        database_url="postgresql+asyncpg://gryphon_runtime:pw@localhost:5432/gryphon",
    )
    with pytest.raises(EnrichmentConfigurationError, match="dedicated"):
        assert_dedicated_role(shared, production=True)
    assert_dedicated_role(shared, production=False)  # warns only
    assert_dedicated_role(EnrichmentSettings(_env_file=None), production=True)
