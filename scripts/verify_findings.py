"""Operator CLI for the verification layer.

Every command identifies its caller by the process's real uid (enforced against
``GRYPHON_VERIFICATION_ALLOWED_UIDS``) and records it as ``initiated_by`` on
every pass, observation and signed event.

    python -m scripts.verify_findings start <scan_run_id> --request-key KEY
                                       [--only inconclusive|unknown|<ids>]
    python -m scripts.verify_findings reverify <scan_run_id> --request-key KEY
                                       --supersedes <pass_id> --reason TEXT
    python -m scripts.verify_findings status [<scan_run_id>]
    python -m scripts.verify_findings report <scan_run_id> [--out report.json]
    python -m scripts.verify_findings stop <scan_run_id> [--detail TEXT]
    python -m scripts.verify_findings abort <scan_run_id> [--detail TEXT]

``--request-key`` is what makes a lost command response harmless: the same key
returns the same pass and the same report, with no new traffic to the client's
estate. A *changed* request under a reused key is refused rather than guessed at.
``reverify`` is a distinct operation for that reason — re-running with a new key
is a new pass, and saying so requires a supersession reason.

``stop`` advances the pass's cancellation epoch, which the gateway checks before
every dispatch, so new traffic ceases within one probe. It does not require the
lease, because for a component that sends requests to someone else's systems
"stop now" is a safety control and not an ownership question. ``abort`` keeps its
narrower meaning: finish off a pass whose process is gone and whose lease lapsed.

stdout carries exactly one JSON document per command; diagnostics go to stderr.
The pass salt, the caller's request key in clear and evidence projections are
never printed — the key appears as a digest and a projection as counts, so a
terminal, a shell history file and a CI log cannot become the place where this
layer's own secrets or a client's evidence leaked.

Exit codes: 0 ok · 1 unexpected error · 2 usage, invalid id or a reused request
key presented with a different request · 3 configuration refused · 4 another
open pass owns the scan · 5 pass refused · 6 pass abandoned or blocked on a
dependency · 7 no report or report failed verification · 8 caller rejected.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from gryphon.logging_config import configure_logging
from gryphon.verification.bootstrap import build_verification_services
from gryphon.verification.constants import PassState
from gryphon.verification.identity import canonical_scan_id, request_key_digest
from gryphon.verification.reasons import (
    CallerRejected,
    InvalidScanId,
    PassBusy,
    RequestKeyConflict,
    VerificationConfigurationError,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_BUSY = 4
EXIT_REFUSED = 5
EXIT_ABANDONED = 6
EXIT_NO_REPORT = 7
EXIT_CALLER = 8

#: Selectors ``--only`` accepts in place of an explicit finding-id list. The
#: engine resolves them against the scan's recorded verdicts; anything else is
#: taken as ids, so a typo scopes the pass to nothing rather than to everything.
ONLY_SELECTORS = ("inconclusive", "unknown")

#: Names whose value is dropped from any printed document. The pass salt is what
#: makes observation identities and control locators unpredictable to a target:
#: it is stored on the pass row, excluded from every view, and has no reading
#: that belongs on an operator's screen.
_NEVER_PRINTED = frozenset({"salt", "pass_salt", "signing_key", "signing_key_hex", "private_key"})

#: Names printed as a digest instead of in clear. An operator's request key can
#: be anything they chose, including something they consider sensitive.
_AS_DIGEST = frozenset({"request_key"})

#: Names printed as counts instead of content. A projection is minimized
#: evidence, not public text, and the CLI is not the boundary that decides what
#: is safe to show.
_AS_COUNTS = frozenset({"projection", "projections", "facts", "evidence", "body"})


def _counts(value: object) -> dict[str, int]:
    """Describe a value's size without reproducing any of it."""
    if isinstance(value, Mapping):
        return {"keys": len(value)}
    if isinstance(value, list | tuple):
        return {"items": len(value)}
    if isinstance(value, str):
        return {"chars": len(value)}
    return {"keys": 0}


def _redact(value: Any) -> Any:
    """Apply the printing rules to a whole document, at every depth.

    The rules live here rather than only in the engine's payload builders
    because this is the last place before stdout: a field added upstream should
    arrive on screen already covered, not covered the next time someone
    remembers.
    """
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key).lower()
            if name in _NEVER_PRINTED:
                continue
            if name in _AS_DIGEST:
                safe[f"{key}_digest"] = request_key_digest(str(item))
            elif name in _AS_COUNTS:
                safe[f"{key}_counts"] = _counts(item)
            else:
                safe[key] = _redact(item)
        return safe
    if isinstance(value, list | tuple):
        return [_redact(item) for item in value]
    return value


def _document(value: object) -> dict[str, Any]:
    """The printable mapping for a command's typed result.

    Results expose ``as_payload()``; a command that returns a plain mapping is
    printed as it stands. Both are accepted because the JSON fields are
    additive-only, so the CLI prints what a result offers rather than a list of
    fields it would have to be taught again on every addition.
    """
    as_payload = getattr(value, "as_payload", None)
    if callable(as_payload):
        payload = as_payload()
        if isinstance(payload, Mapping):
            return dict(payload)
    if isinstance(value, Mapping):
        return dict(value)
    return {"result": str(value)}


def _emit(payload: Mapping[str, Any], *, redact: bool = True) -> None:
    body = _redact(dict(payload)) if redact else dict(payload)
    print(json.dumps(body, indent=2, sort_keys=True, default=str))


def _exit_for(state: object) -> int:
    """Map a pass's terminal or waiting state onto its stable exit code."""
    value = getattr(state, "value", state)
    if value == PassState.REFUSED.value:
        return EXIT_REFUSED
    if value in (PassState.ABANDONED.value, PassState.BLOCKED.value):
        return EXIT_ABANDONED
    return EXIT_OK


def _only_value(raw: str) -> str | tuple[str, ...]:
    """Normalize ``--only`` into a selector or an explicit finding-id tuple.

    Parsed by argparse so a malformed scope exits with the usage code before
    anything is built: a scope that silently fell back to "everything" would
    turn a three-finding re-observation into a full pass of traffic.
    """
    text = raw.strip()
    if text.lower() in ONLY_SELECTORS:
        return text.lower()
    ids = tuple(dict.fromkeys(part.strip() for part in text.split(",") if part.strip()))
    if not ids:
        raise argparse.ArgumentTypeError("--only needs a selector or at least one finding id")
    return ids


def _nonblank(raw: str) -> str:
    """Reject an empty argument where blank would mean something else entirely.

    An empty request key would make every command share one identity, which is
    the opposite of what the key is for.
    """
    text = raw.strip()
    if not text:
        raise argparse.ArgumentTypeError("the value must not be empty")
    return text


def _scan_id(args: argparse.Namespace) -> str:
    """Canonical scan run id for a command that requires one."""
    return canonical_scan_id(args.scan_run_id)


async def _dispatch(args: argparse.Namespace) -> int:
    # The composition root identifies the caller while it builds, so an
    # unlisted uid is refused before a database handle or a signing key exists.
    try:
        services = build_verification_services()
    except VerificationConfigurationError as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except CallerRejected as exc:
        print(f"caller rejected: {exc}", file=sys.stderr)
        return EXIT_CALLER
    try:
        caller = services.caller
        commands = services.commands

        if args.command == "start":
            result = await commands.start(
                _scan_id(args),
                request_key=args.request_key,
                caller=caller,
                only=args.only,
            )
            _emit(_document(result) | {"request_key_digest": request_key_digest(args.request_key)})
            return _exit_for(getattr(result, "state", None))

        if args.command == "reverify":
            result = await commands.reverify(
                _scan_id(args),
                request_key=args.request_key,
                supersedes_pass_id=args.supersedes,
                reason=args.reason,
                caller=caller,
            )
            _emit(_document(result) | {"request_key_digest": request_key_digest(args.request_key)})
            return _exit_for(getattr(result, "state", None))

        if args.command == "status":
            scope = canonical_scan_id(args.scan_run_id) if args.scan_run_id else None
            _emit(_document(await commands.status(scope)))
            return EXIT_OK

        if args.command == "report":
            served = await commands.report(_scan_id(args))
            if served is None:
                print("no completed verification pass for that scan", file=sys.stderr)
                return EXIT_NO_REPORT
            if not served.verification.verified:
                print(
                    f"report {served.report_id} FAILED verification: "
                    f"{served.verification.reason}; refusing to serve it",
                    file=sys.stderr,
                )
                return EXIT_NO_REPORT
            # The report body is the one document printed in full: it is the
            # attested deliverable, its digest and signature were re-checked
            # just now, and its projections are the declared, minimized ones.
            body = json.dumps(served.body, indent=2, sort_keys=True, default=str)
            if args.out:
                await asyncio.to_thread(Path(args.out).write_text, body + "\n", encoding="utf-8")
                _emit(
                    {"report_id": served.report_id, "verified": True, "written": args.out},
                    redact=False,
                )
            else:
                print(body)
            return EXIT_OK

        if args.command == "stop":
            stopped = await commands.stop(_scan_id(args), caller=caller, detail=args.detail)
            if stopped is None:
                print("no open pass for that scan; nothing to cancel", file=sys.stderr)
                return EXIT_ERROR
            _emit(_document(stopped))
            return EXIT_OK

        if args.command == "abort":
            aborted = await commands.abort(_scan_id(args), caller=caller, detail=args.detail)
            if aborted is None:
                print("no unfinished pass for that scan", file=sys.stderr)
                return EXIT_ERROR
            _emit(_document(aborted))
            return EXIT_OK

        print(f"unknown command: {args.command}", file=sys.stderr)
        return EXIT_USAGE
    except InvalidScanId as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    except RequestKeyConflict as exc:
        # Not a retry: the caller may believe either request ran. A new key is
        # the only way to express a new intent.
        print(f"{exc}; use a new request key", file=sys.stderr)
        return EXIT_USAGE
    except PassBusy as exc:
        print(f"busy: {exc}", file=sys.stderr)
        return EXIT_BUSY
    finally:
        await services.dispose()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GRYPHON verification layer operator commands",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="run, resume or re-return the pass for a scan")
    start.add_argument("scan_run_id")
    start.add_argument(
        "--request-key",
        required=True,
        type=_nonblank,
        help="caller-chosen identity for this command; the same key returns the same pass",
    )
    start.add_argument(
        "--only",
        type=_only_value,
        help="scope the pass: 'inconclusive', 'unknown', or a comma-separated finding-id list",
    )

    reverify = sub.add_parser("reverify", help="verify again, superseding an earlier pass")
    reverify.add_argument("scan_run_id")
    reverify.add_argument("--request-key", required=True, type=_nonblank)
    reverify.add_argument(
        "--supersedes", required=True, type=_nonblank, help="the pass_id being superseded"
    )
    reverify.add_argument(
        "--reason", required=True, type=_nonblank, help="why this scan is being verified again"
    )

    status = sub.add_parser("status", help="open passes, budgets and a scan's pass history")
    status.add_argument("scan_run_id", nargs="?")

    report = sub.add_parser("report", help="print the re-verified verification report")
    report.add_argument("scan_run_id")
    report.add_argument("--out", help="write to a file instead of stdout")

    stop = sub.add_parser("stop", help="cease new traffic now; no lease required")
    stop.add_argument("scan_run_id")
    stop.add_argument("--detail")

    abort = sub.add_parser("abort", help="abandon an unfinished pass whose process is gone")
    abort.add_argument("scan_run_id")
    abort.add_argument("--detail")
    return parser


def main(argv: list[str] | None = None) -> int:
    # Diagnostics go to stderr so stdout carries only the command's result.
    configure_logging(json_output=False, stream=sys.stderr)
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(_dispatch(args))
    except KeyboardInterrupt:
        print(
            "interrupted; already-dispatched observations are reconciled on the next start. "
            "Use `stop` to cease new traffic, then `start` with the same request key",
            file=sys.stderr,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
