"""Operator CLI to issue a local authorization grant (§20.1).

LOCAL, CONTROLLED USE ONLY. You are asserting that you have verified written
authorization to test the given scope OUT OF BAND; GRYPHON signs your reference,
it does not validate the document. Unauthorized use is prohibited.

    python -m scripts.issue_grant \
        --organization "Acme Corp" \
        --granted-by alice@acme.example \
        --granted-to pentest-team@contractor.example \
        --domain staging.acme.example \
        --wildcard '*.dev.acme.example' \
        --cidr 203.0.113.0/24 \
        --exclude-path /admin \
        --days 30 --max-depth standard \
        --written-auth-ref SOW-2026-0042

Prints the compact JWS token on success.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
from datetime import timedelta

from gryphon.auth.claims import IssuanceRequest
from gryphon.auth.scope import ScopeEntry
from gryphon.bootstrap import build_services
from gryphon.clock import SystemClock
from gryphon.constants import ScanDepth, TargetType


def _build_scope(args: argparse.Namespace) -> list[ScopeEntry]:
    excluded = tuple(args.exclude_path or ())
    entries: list[ScopeEntry] = []
    for domain in args.domain or ():
        entries.append(ScopeEntry(target_type=TargetType.DOMAIN, target=domain, excluded_paths=excluded))
    for wildcard in args.wildcard or ():
        entries.append(
            ScopeEntry(target_type=TargetType.DOMAIN_WILDCARD, target=wildcard, excluded_paths=excluded)
        )
    for ip in args.ip or ():
        entries.append(ScopeEntry(target_type=TargetType.IP, target=ip, excluded_paths=excluded))
    for cidr in args.cidr or ():
        entries.append(ScopeEntry(target_type=TargetType.CIDR, target=cidr, excluded_paths=excluded))
    if not entries:
        raise SystemExit("error: at least one of --domain/--wildcard/--ip/--cidr is required")
    return entries


async def _run(args: argparse.Namespace) -> int:
    services = build_services(clock=SystemClock())
    if services.issuer is None:
        raise SystemExit("error: no grant signing key configured (GRYPHON_GRANT_SIGNING_KEY_HEX)")

    now = services.clock.now()
    request = IssuanceRequest(
        organization=args.organization,
        granted_by=args.granted_by,
        granted_to=args.granted_to,
        scope=tuple(_build_scope(args)),
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(days=args.days),
        max_scan_depth=ScanDepth(args.max_depth),
        written_authorization_ref=args.written_auth_ref,
    )
    try:
        issued = await services.issuer.issue_grant(request, idempotency_key=secrets.token_hex(16))
        print(issued.token)
        print(f"# grant_id={issued.grant_id} expires_at={issued.expires_at.isoformat()}", flush=True)
        return 0
    finally:
        await services.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a GRYPHON authorization grant (local operator).")
    parser.add_argument("--organization", required=True)
    parser.add_argument("--granted-by", required=True)
    parser.add_argument("--granted-to", required=True)
    parser.add_argument("--domain", action="append", help="exact domain (repeatable)")
    parser.add_argument("--wildcard", action="append", help="'*.suffix' wildcard (repeatable)")
    parser.add_argument("--ip", action="append", help="exact IP (repeatable)")
    parser.add_argument("--cidr", action="append", help="strict CIDR network (repeatable)")
    parser.add_argument("--exclude-path", action="append", help="origin-form path exclusion (repeatable)")
    parser.add_argument("--days", type=int, default=30, help="validity window in days (<=90)")
    parser.add_argument(
        "--max-depth", choices=[d.value for d in ScanDepth], default=ScanDepth.STANDARD.value
    )
    parser.add_argument("--written-auth-ref", required=True, help="reference to written authority (SOW id)")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
