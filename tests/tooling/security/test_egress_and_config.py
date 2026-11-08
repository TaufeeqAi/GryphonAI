"""Egress fail-closed behaviour and fail-closed configuration."""

from __future__ import annotations

import platform

import pytest

from gryphon.tooling.constants import EgressMode
from gryphon.tooling.destination.egress import (
    LinuxNamespaceEgressEnforcer,
    NullEgressEnforcer,
    build_egress_enforcer,
)
from gryphon.tooling.reasons import EgressUnavailableError, ToolingConfigurationError
from gryphon.tooling.settings import ToolingSettings

pytestmark = pytest.mark.security


def test_enforced_mode_selects_namespace_enforcer() -> None:
    settings = ToolingSettings(_env_file=None, environment="test", egress_mode=EgressMode.ENFORCED)
    enforcer = build_egress_enforcer(settings)
    assert isinstance(enforcer, LinuxNamespaceEgressEnforcer)
    assert enforcer.enforcing is True


@pytest.mark.asyncio
async def test_namespace_enforcer_fails_closed_without_capability() -> None:
    # On a host that cannot create a namespace (e.g. non-Linux / unprivileged),
    # establishing an egress context MUST raise (fail closed), never degrade.
    enforcer = LinuxNamespaceEgressEnforcer()
    if enforcer._capable and platform.system() == "Linux":  # pragma: no cover
        pytest.skip("host is capable; fail-closed path not exercised here")
    with pytest.raises(EgressUnavailableError):
        await enforcer.establish(["203.0.113.10"], [443])


@pytest.mark.asyncio
async def test_null_enforcer_establishes_non_enforcing() -> None:
    enforcer = NullEgressEnforcer()
    handle = await enforcer.establish(["203.0.113.10"], [443])
    assert handle.enforcing is False
    assert handle.wrap_argv(["bin", "-x"]) == ["bin", "-x"]


def test_unenforced_egress_requires_optin_outside_prod() -> None:
    with pytest.raises(ToolingConfigurationError):
        ToolingSettings(_env_file=None, environment="test", egress_mode=EgressMode.UNENFORCED)


def test_unenforced_egress_allowed_with_optin() -> None:
    settings = ToolingSettings(
        _env_file=None, environment="dev", egress_mode=EgressMode.UNENFORCED,
        allow_unenforced_egress=True,
    )
    assert settings.egress_mode is EgressMode.UNENFORCED


def test_production_requires_capability_key() -> None:
    with pytest.raises(ToolingConfigurationError):
        ToolingSettings(_env_file=None, environment="prod")


def test_production_forbids_unenforced_egress() -> None:
    with pytest.raises(ToolingConfigurationError):
        ToolingSettings(
            _env_file=None, environment="prod", egress_mode=EgressMode.UNENFORCED,
            allow_unenforced_egress=True,
        )
