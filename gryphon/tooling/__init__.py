"""GRYPHON capability-gated tool execution layer.

This package makes every ProjectDiscovery reconnaissance/scan tool
architecturally unreachable unless a decision **rooted in a committed
authorization grant receipt** authorizes this exact tool, against a destination
the operating system is forced to contain, within the granted scan depth — and
a durable *intent* record has committed before any traffic leaves the host.

The tool wrappers are replaceable mechanism. The load-bearing semantics are the
enforcement gateway, the grant-rooted capability, the OS egress containment and
the execution saga. Nothing in this layer re-decides authorization: the grant
decision is owned upstream and consumed read-only.

Controlling principle:

    No protected tool process may be created unless a decision rooted in the
    authorization grant receipt authorizes this tool against an OS-enforced,
    in-scope destination within the granted scan depth — and a durable intent
    record for that ``execution_id`` has committed.

Module map (implementation projection of the contract's module structure):

    capability/    grant-rooted, single-use, asymmetric operation capability
    enforcement/   the sole decision point + the execution saga orchestrator
    destination/   resolve-then-pin + OS default-deny egress containment
    execution/     the Execution aggregate (execution_id) and outcome taxonomy
    tools/         descriptors, safe runner, result models, arg builders, host
    provisioning/  pinned-binary manifest + readiness
    audit/         signed tool-invocation audit event builder
"""

from __future__ import annotations

__all__: list[str] = []
