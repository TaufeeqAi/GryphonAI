"""Tool Capability Descriptors (BND-09).

Each tool declares its security-relevant behaviour: whether it re-resolves,
follows redirects, emits out-of-band callbacks, uses raw packets, which ports it
needs, which external sources a passive tool contacts, which tag classes are
always excluded, which template protocols are permitted, and its result-schema
version. The gateway's policy and the egress-context builder read these; nothing
tool-specific is hardcoded in the gateway.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from gryphon.tooling.constants import ToolId
from gryphon.tooling.reasons import ProvisioningError, ToolReasonCode, ToolingError


class ToolDescriptor(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: ToolId
    descriptor_version: str = Field(min_length=1)
    binary_name: str = Field(min_length=1)

    touches_target: bool
    re_resolves: bool
    follows_redirects: bool
    emits_oob: bool
    raw_packets: bool

    required_ports: tuple[int, ...] = ()
    external_sources: tuple[str, ...] = ()
    destructive_tag_classes: tuple[str, ...] = ()
    permitted_template_protocols: tuple[str, ...] = ()
    prohibited_template_protocols: tuple[str, ...] = ()

    result_schema_version: str = Field(min_length=1)
    timeout_seconds: float = Field(gt=0, le=1800)
    rate_limit_floor: int = Field(ge=1, le=10000)

    @property
    def is_passive(self) -> bool:
        return not self.touches_target


# -----------------------------------------------------------------------------
# The seven pinned descriptors. Versions track the pinned binary versions.
# -----------------------------------------------------------------------------
_ALWAYS_EXCLUDED = ("dos", "fuzz")

_DESCRIPTORS: dict[ToolId, ToolDescriptor] = {
    ToolId.SUBFINDER: ToolDescriptor(
        tool_id=ToolId.SUBFINDER,
        descriptor_version="subfinder/2.17.0",
        binary_name="subfinder",
        touches_target=False,
        re_resolves=False,
        follows_redirects=False,
        emits_oob=False,
        raw_packets=False,
        external_sources=("certificate-transparency", "passive-dns-aggregators"),
        result_schema_version="1",
        timeout_seconds=90.0,
        rate_limit_floor=10,
    ),
    ToolId.HTTPX: ToolDescriptor(
        tool_id=ToolId.HTTPX,
        descriptor_version="httpx/1.12.0",
        binary_name="httpx",
        touches_target=True,
        re_resolves=True,
        follows_redirects=True,
        emits_oob=False,
        raw_packets=False,
        required_ports=(80, 443),
        result_schema_version="1",
        timeout_seconds=120.0,
        rate_limit_floor=50,
    ),
    ToolId.NAABU: ToolDescriptor(
        tool_id=ToolId.NAABU,
        descriptor_version="naabu/2.7.0",
        binary_name="naabu",
        touches_target=True,
        re_resolves=True,
        follows_redirects=False,
        emits_oob=False,
        raw_packets=True,  # SYN scanning — an HTTP proxy cannot contain this
        result_schema_version="1",
        timeout_seconds=180.0,
        rate_limit_floor=100,
    ),
    ToolId.KATANA: ToolDescriptor(
        tool_id=ToolId.KATANA,
        descriptor_version="katana/1.8.0",
        binary_name="katana",
        touches_target=True,
        re_resolves=True,
        follows_redirects=True,
        emits_oob=False,
        raw_packets=False,
        required_ports=(80, 443),
        result_schema_version="1",
        timeout_seconds=180.0,
        rate_limit_floor=50,
    ),
    ToolId.DNSX: ToolDescriptor(
        tool_id=ToolId.DNSX,
        descriptor_version="dnsx/1.3.1",
        binary_name="dnsx",
        touches_target=True,
        re_resolves=True,
        follows_redirects=False,
        emits_oob=False,
        raw_packets=False,
        required_ports=(53,),
        result_schema_version="1",
        timeout_seconds=90.0,
        rate_limit_floor=100,
    ),
    ToolId.TLSX: ToolDescriptor(
        tool_id=ToolId.TLSX,
        descriptor_version="tlsx/1.4.0",
        binary_name="tlsx",
        touches_target=True,
        re_resolves=True,
        follows_redirects=False,
        emits_oob=False,
        raw_packets=False,
        required_ports=(443,),
        result_schema_version="1",
        timeout_seconds=120.0,
        rate_limit_floor=50,
    ),
    ToolId.NUCLEI: ToolDescriptor(
        tool_id=ToolId.NUCLEI,
        descriptor_version="nuclei/3.11.1",
        binary_name="nuclei",
        touches_target=True,
        re_resolves=True,
        follows_redirects=True,
        emits_oob=True,  # interactsh/OAST must be pinned/disabled
        raw_packets=False,
        required_ports=(80, 443),
        destructive_tag_classes=_ALWAYS_EXCLUDED,
        permitted_template_protocols=("http", "dns", "ssl", "tcp"),
        prohibited_template_protocols=("code",),  # host code execution — never
        result_schema_version="1",
        timeout_seconds=300.0,
        rate_limit_floor=50,
    ),
}


def get_descriptor(tool_id: ToolId) -> ToolDescriptor:
    descriptor = _DESCRIPTORS.get(tool_id)
    if descriptor is None:
        raise ToolingError(f"no descriptor for tool {tool_id.value}")
    return descriptor


def all_descriptors() -> tuple[ToolDescriptor, ...]:
    return tuple(_DESCRIPTORS.values())


def require_descriptor_reason(tool_id: ToolId) -> ToolReasonCode | None:
    """Return a DENY reason if the tool has no descriptor, else ``None``."""
    return None if tool_id in _DESCRIPTORS else ToolReasonCode.DESCRIPTOR_MISSING


def assert_template_protocols(tool_id: ToolId, protocols: list[str]) -> None:
    """Raise if any requested template protocol is prohibited (e.g. ``code``)."""
    descriptor = get_descriptor(tool_id)
    prohibited = set(descriptor.prohibited_template_protocols)
    for proto in protocols:
        if proto in prohibited:
            raise ProvisioningError(f"prohibited template protocol: {proto}")
