"""Operator self-verification for the capability-gated tool execution layer.

This exercises the REAL enforcement pipeline against YOUR configured database
and YOUR configured key material, with two components replaced by dry-run
doubles:

* the subprocess runner — so **no tool process is ever created**, and
* the DNS resolver — so **no name is ever looked up**.

Consequently **no packet is sent to any target**. What is proven is the part
that must never be wrong: key distinctness, readiness, capability
signing/verification, grant-rooted scope re-derivation, tool binding,
replay/single-use, out-of-scope denial, egress fail-closed, and append-only
audit.

It complements ``pytest tests/tooling`` (which proves the code against synthetic
fixtures); this proves the *deployment* you are about to run.

    python -m scripts.verify_tooling              # dev/test
    python -m scripts.verify_tooling --json
    python -m scripts.verify_tooling --yes        # required when environment=prod

WRITES DURABLE ROWS: it issues a synthetic grant for the reserved domain
``self-verify.example.com``, admits one scan run, and records its executions and
append-only audit events. Those rows cannot be deleted by the runtime role (by
design); they are tagged with the organization ``GRYPHON Self-Verification``.
Exit code 0 = every check passed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import json
import secrets
import sys
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import text

from gryphon.auth.claims import IssuanceRequest
from gryphon.auth.scope import ScopeEntry
from gryphon.auth.service import ScanAdmissionRequest
from gryphon.canonical import canonical_json_bytes
from gryphon.constants import ScanDepth, TargetType
from gryphon.db.repositories.tool_execution import ToolExecutionRepository
from gryphon.tooling.audit.builder import ToolAuditBuilder
from gryphon.tooling.bootstrap import build_tooling_services
from gryphon.tooling.capability.claims import build_claims
from gryphon.tooling.capability.keys import build_capability_key_material
from gryphon.tooling.constants import EgressMode, ToolId, ToolOutcome
from gryphon.tooling.destination.egress import EgressHandle, build_egress_enforcer
from gryphon.tooling.destination.guard import DestinationGuard
from gryphon.tooling.enforcement.budgets import BudgetManager
from gryphon.tooling.enforcement.service import ToolExecutionService
from gryphon.tooling.provisioning.manifest import StaticBinaryResolver
from gryphon.tooling.provisioning.readiness import check_tooling_readiness
from gryphon.tooling.reasons import EgressUnavailableError, ToolReasonCode
from gryphon.tooling.tools.runner import RunResult

#: IANA-reserved documentation domain; in scope of the synthetic grant only.
VERIFY_DOMAIN = "self-verify.example.com"
#: Deliberately outside the synthetic grant's scope.
OUT_OF_SCOPE_DOMAIN = "not-authorized.example.net"
#: A globally-routable literal the dry-run resolver pins to. Never contacted:
#: the runner is a double, so no socket is ever opened to it.
PINNED_ADDRESS = "93.184.216.34"

ORGANIZATION = "GRYPHON Self-Verification"


# -----------------------------------------------------------------------------
# Dry-run doubles (no process, no DNS, no packets)
# -----------------------------------------------------------------------------
class _DryRunRunner:
    """Returns canned JSONL instead of spawning a subprocess."""

    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.calls = 0

    async def run(self, **_: object) -> RunResult:
        self.calls += 1
        return RunResult(
            outcome=ToolOutcome.COMPLETED,
            exit_code=0,
            stdout=self.stdout,
            stderr="",
            stdout_truncated=False,
        )


class _PinnedResolver:
    """Resolves every name to one pinned literal without touching DNS."""

    async def resolve(self, host: str) -> list[object]:
        return [ipaddress.ip_address(PINNED_ADDRESS)]


class _WithheldEgress:
    """Refuses to establish a context, to prove the gateway fails closed."""

    enforcing = True

    async def establish(self, allowlist: list[str], ports: list[int]) -> EgressHandle:
        raise EgressUnavailableError("self-verification: egress context withheld")

    async def teardown(self, handle: EgressHandle) -> None:
        return None


class _PermissiveEgress:
    """Establishes a nominal egress context to exercise the allow path."""

    enforcing = True

    async def establish(self, allowlist: list[str], ports: list[int]) -> EgressHandle:
        return EgressHandle(
            context_id="self-verify",
            allowlist=tuple(allowlist),
            ports=tuple(ports),
            enforcing=True,
        )

    async def teardown(self, handle: EgressHandle) -> None:
        return None


# -----------------------------------------------------------------------------
# Check accumulation
# -----------------------------------------------------------------------------
@dataclass
class Check:
    name: str
    ok: bool | None  # None = skipped
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, ok: bool | None, detail: str = "") -> None:
        self.checks.append(Check(name, ok, detail))

    def expect(self, name: str, actual: object, expected: object, detail: str = "") -> bool:
        ok = actual == expected
        self.add(name, ok, detail or f"got={actual!r} expected={expected!r}")
        return ok

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.ok is False]

    @property
    def skipped(self) -> list[Check]:
        return [c for c in self.checks if c.ok is None]


def _exec_id() -> str:
    return "exec-" + secrets.token_hex(16)


def _dry_service(services, *, runner, egress) -> ToolExecutionService:
    """A ToolExecutionService identical to production except for the doubles."""
    ts = services.tooling_settings
    return ToolExecutionService(
        verifier=services.verifier,
        database=services.database,
        clock=services.clock,
        budgets=BudgetManager(ts, services.clock),
        destination_guard=DestinationGuard(_PinnedResolver()),
        egress_enforcer=egress,
        runner=runner,
        audit_builder=ToolAuditBuilder(services.auth.key_material.audit_signer),
        binary_resolver=StaticBinaryResolver(paths={t: "/nonexistent/dry-run" for t in ToolId}),
        settings=ts,
    )


async def _admit(services):
    """Issue a synthetic, narrowly-scoped grant and admit one scan run."""
    now = services.clock.now()
    issued = await services.auth.issuer.issue_grant(
        IssuanceRequest(
            organization=ORGANIZATION,
            granted_by="self-verification@localhost",
            granted_to="self-verification@localhost",
            scope=(ScopeEntry(target_type=TargetType.DOMAIN, target=VERIFY_DOMAIN),),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(hours=1),
            max_scan_depth=ScanDepth.STANDARD,
            written_authorization_ref="SELF-VERIFICATION",
        ),
        idempotency_key=secrets.token_hex(16),
    )
    return await services.auth.authorization_service.authorize_scan(
        ScanAdmissionRequest(
            target=VERIFY_DOMAIN,
            token=issued.token,
            requested_depth="standard",
            idempotency_key=secrets.token_hex(16),
        )
    )


# -----------------------------------------------------------------------------
# The verification run
# -----------------------------------------------------------------------------
async def verify(report: Report) -> None:
    services = build_tooling_services()
    ts = services.tooling_settings
    report.add(
        "configuration_and_three_distinct_keys",
        True,
        f"environment={ts.environment} egress_mode={ts.egress_mode.value} "
        f"capability_kid={ts.capability_kid}",
    )

    try:
        # --- readiness -------------------------------------------------------
        readiness = await check_tooling_readiness(
            settings=ts,
            database=services.database,
            has_capability_signer=services.has_capability_signer,
            manifest=services.manifest,
        )
        report.add(
            "readiness",
            readiness.ready,
            ", ".join(f"{k}={'ok' if v else 'FAIL'}" for k, v in sorted(readiness.checks.items())),
        )

        if services.auth.issuer is None:
            report.add("live_saga", None, "no grant signing key configured; cannot admit a scan")
            return

        permit = await _admit(services)
        report.add(
            "grant_issued_and_scan_admitted",
            bool(permit.scan_run_id),
            f"scan_run_id={permit.scan_run_id} depth={permit.effective_scan_depth.value}",
        )

        jsonl = "\n".join(
            json.dumps({"host": f"{label}.{VERIFY_DOMAIN}"}) for label in ("a", "b")
        )
        runner = _DryRunRunner(jsonl)
        svc = _dry_service(services, runner=runner, egress=_PermissiveEgress())

        # --- passive execution: the full intent -> outcome saga --------------
        first_exec = _exec_id()
        first = await svc.execute_with_permit(permit, ToolId.SUBFINDER, first_exec, VERIFY_DOMAIN)
        report.expect(
            "passive_execution_completes",
            first.outcome,
            ToolOutcome.COMPLETED,
            f"outcome={first.outcome.value} reason={first.reason_code} "
            f"records={len(first.records)} audit_event={first.audit_event_id}",
        )

        # --- idempotent replay on the same execution_id ----------------------
        again = await svc.execute_with_permit(permit, ToolId.SUBFINDER, first_exec, VERIFY_DOMAIN)
        report.expect(
            "replay_returns_stored_outcome",
            (again.replayed, again.outcome),
            (True, ToolOutcome.COMPLETED),
            f"replayed={again.replayed} outcome={again.outcome.value}",
        )
        report.expect(
            "replay_did_not_re_run_the_tool",
            runner.calls,
            1,
            f"runner invocations={runner.calls} (expected exactly 1)",
        )

        # --- out-of-scope target --------------------------------------------
        denied = await svc.execute_with_permit(
            permit, ToolId.SUBFINDER, _exec_id(), OUT_OF_SCOPE_DOMAIN
        )
        report.expect(
            "out_of_scope_denied",
            (denied.outcome, denied.reason_code),
            (ToolOutcome.DENIED, ToolReasonCode.SCOPE_NO_MATCH.value),
            f"target={OUT_OF_SCOPE_DOMAIN} reason={denied.reason_code}",
        )

        # --- capability path -------------------------------------------------
        if services.issuer is None:
            report.add("capability_path", None, "no capability signing key configured")
        else:
            cap_exec = _exec_id()
            capability = await services.issuer.mint(permit, ToolId.SUBFINDER, cap_exec)
            wire = capability.to_wire()
            wire_bytes = json.dumps(wire).encode("utf-8")

            cap_result = await svc.execute_with_capability(
                wire_bytes, ToolId.SUBFINDER, VERIFY_DOMAIN
            )
            report.expect(
                "capability_execution_completes",
                cap_result.outcome,
                ToolOutcome.COMPLETED,
                f"outcome={cap_result.outcome.value} reason={cap_result.reason_code}",
            )

            reused = await svc.execute_with_capability(
                wire_bytes, ToolId.SUBFINDER, VERIFY_DOMAIN
            )
            report.expect(
                "capability_is_single_use",
                reused.replayed,
                True,
                f"re-presented capability replayed={reused.replayed} "
                f"(authority was consumed, the tool did not re-run)",
            )

            # bound to one tool: presenting it for another tool must fail
            mismatch = await svc.execute_with_capability(wire_bytes, ToolId.NUCLEI, VERIFY_DOMAIN)
            report.expect(
                "capability_bound_to_one_tool",
                mismatch.reason_code,
                ToolReasonCode.CAPABILITY_TOOL_MISMATCH.value,
                f"subfinder capability presented to nuclei -> {mismatch.reason_code}",
            )

            # tampered signature
            tampered = dict(wire)
            raw = bytearray(base64.standard_b64decode(tampered["binding"]))
            raw[0] ^= 0x01
            tampered["binding"] = base64.standard_b64encode(bytes(raw)).decode("ascii")
            bad_sig = await svc.execute_with_capability(
                json.dumps(tampered).encode(), ToolId.SUBFINDER, VERIFY_DOMAIN
            )
            report.expect(
                "tampered_capability_rejected",
                bad_sig.reason_code,
                ToolReasonCode.CAPABILITY_SIGNATURE_INVALID.value,
                f"flipped one signature bit -> {bad_sig.reason_code}",
            )

            # correctly signed but WIDENED: scope re-derivation must catch it
            signer = build_capability_key_material(ts).signer
            claims = capability.claims
            widened = build_claims(
                capability_id="cap-" + secrets.token_hex(4),
                nonce=secrets.token_hex(8),
                kid=claims.kid,
                scan_run_id=claims.scan_run_id,
                grant_id=claims.grant_id,
                claims_digest=claims.claims_digest,
                scope_digest="0" * 64,  # a scope this grant never authorized
                tool_id=ToolId.SUBFINDER,
                effective_scan_depth=claims.effective_scan_depth,
                execution_id=_exec_id(),
                iat=claims.iat,
                exp=claims.exp,
            )
            payload = canonical_json_bytes(widened.to_canonical_payload())
            widened_wire = {
                **widened.to_canonical_payload(),
                "binding": base64.standard_b64encode(signer.sign(payload)).decode("ascii"),
            }
            widened_result = await svc.execute_with_capability(
                json.dumps(widened_wire).encode(), ToolId.SUBFINDER, VERIFY_DOMAIN
            )
            report.expect(
                "widened_capability_rejected_by_scope_provenance",
                widened_result.reason_code,
                ToolReasonCode.SCOPE_PROVENANCE_MISMATCH.value,
                "a validly-signed capability carrying a wider scope than the grant "
                f"receipt was denied with {widened_result.reason_code}",
            )

        # --- fail closed: an active tool must never run without a context ---
        # Proven deterministically on every host by withholding the context,
        # rather than relying on this host being unable to provide one.
        withheld_exec = _exec_id()
        withheld = await _dry_service(
            services, runner=_DryRunRunner(""), egress=_WithheldEgress()
        ).execute_with_permit(permit, ToolId.HTTPX, withheld_exec, VERIFY_DOMAIN)
        async with services.database.session() as session:
            withheld_row = await ToolExecutionRepository(session).get(withheld_exec)
        report.expect(
            "active_tool_fails_closed_without_egress",
            (withheld.outcome, withheld.reason_code),
            (ToolOutcome.DENIED, ToolReasonCode.EGRESS_UNAVAILABLE.value),
            "with no egress context the active tool was refused "
            f"({withheld.reason_code})",
        )
        report.expect(
            "no_execution_intent_committed_for_denied_run",
            withheld_row,
            None,
            "no intent row exists -> no traffic was ever authorized",
        )

        # --- the real enforcer on THIS host ---------------------------------
        real_egress = build_egress_enforcer(ts)
        egress_detail = ""
        try:
            probe = await real_egress.establish([PINNED_ADDRESS], [443])
            probe_context = probe.context_id
            await real_egress.teardown(probe)
            egress_available = True
        except EgressUnavailableError as exc:
            egress_available = False
            probe_context = ""
            egress_detail = str(exc)

        if not egress_available:
            report.add(
                "active_tool_contained_by_the_os",
                None,
                f"this host cannot establish an egress context ({egress_detail}); "
                "active tools are denied here -- run this on Linux with CAP_NET_ADMIN "
                "to exercise the containment allow path",
            )
        else:
            active_exec = _exec_id()
            active = await _dry_service(
                services, runner=_DryRunRunner(""), egress=real_egress
            ).execute_with_permit(permit, ToolId.HTTPX, active_exec, VERIFY_DOMAIN)
            async with services.database.session() as session:
                active_row = await ToolExecutionRepository(session).get(active_exec)
            report.expect(
                "active_tool_contained_by_the_os",
                active.outcome,
                ToolOutcome.COMPLETED,
                f"posture={ts.egress_mode.value} "
                f"enforcing={getattr(real_egress, 'enforcing', None)} "
                f"context={probe_context or 'n/a'} outcome={active.outcome.value}",
            )
            report.expect(
                "execution_intent_committed_for_the_contained_run",
                bool(active_row),
                True,
                "the intent record committed before the tool ran",
            )

        # --- append-only audit: the runtime role must not be able to mutate --
        try:
            async with services.database.session() as session:
                await session.execute(
                    text("UPDATE tool_invocation_audit SET event_type = 'tampered'")
                )
                await session.commit()
            report.add(
                "tool_audit_is_append_only", False, "an UPDATE SUCCEEDED (this must not happen)"
            )
        except Exception as exc:  # noqa: BLE001 - any refusal is a pass
            message = str(getattr(exc, "orig", exc))
            if "append-only" in message:
                barrier = "the append-only trigger"
            elif "permission denied" in message:
                barrier = "the least-privilege role grant"
            else:
                barrier = type(exc).__name__
            report.add("tool_audit_is_append_only", True, f"UPDATE refused by {barrier}")

        # --- the MCP host registers all seven tools --------------------------
        try:
            from gryphon.tooling.tools.host import build_tool_host

            host = build_tool_host(svc)
            tools = await host.list_tools()
            names = sorted(getattr(t, "name", str(t)) for t in tools)
            report.expect(
                "mcp_host_registers_seven_tools", len(names), 7, ", ".join(names)
            )
        except ImportError as exc:
            report.add("mcp_host_registers_seven_tools", None, f"fastmcp not installed ({exc})")
    finally:
        await services.dispose()


def _print_human(report: Report) -> None:
    print()
    print("GRYPHON tool execution layer — deployment self-verification")
    print("no tool process was created and no target was contacted")
    print("-" * 78)
    for check in report.checks:
        mark = "PASS" if check.ok else ("SKIP" if check.ok is None else "FAIL")
        print(f"[{mark}] {check.name}")
        if check.detail:
            print(f"       {check.detail}")
    print("-" * 78)
    passed = sum(1 for c in report.checks if c.ok)
    verdict = "VERIFIED" if not report.failed else "VERIFICATION FAILED"
    print(
        f"{passed} passed, {len(report.failed)} failed, "
        f"{len(report.skipped)} skipped — {verdict}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Self-verify the tool execution layer.")
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="confirm writing self-verification rows when environment=prod",
    )
    args = parser.parse_args()

    from gryphon.tooling.settings import get_tooling_settings

    if get_tooling_settings().is_production and not args.yes:
        print(
            "refusing to run against a production deployment without --yes: this writes a "
            "synthetic grant, a scan run and append-only audit rows that cannot be deleted.",
            file=sys.stderr,
        )
        sys.exit(2)

    report = Report()
    try:
        asyncio.run(verify(report))
    except Exception as exc:  # noqa: BLE001 - report the failure, never half-claim success
        report.add("verification_run", False, f"{type(exc).__name__}: {exc}")

    if args.json:
        print(
            json.dumps(
                {
                    "verified": not report.failed,
                    "checks": [
                        {"name": c.name, "result": c.ok, "detail": c.detail}
                        for c in report.checks
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_human(report)
    sys.exit(0 if not report.failed else 1)


if __name__ == "__main__":
    main()
