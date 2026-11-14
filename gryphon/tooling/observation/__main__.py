"""Observer sandbox entry point.

    python -m gryphon.tooling.observation <request.json>

The gateway establishes the egress namespace, scrubs the environment, writes the
request document and starts this module. It reads bytes a target chose, measures
them against its own bounds, and prints exactly one JSON document on stdout:

    {"ok": true,  "facts": {...}}
    {"ok": false, "error_code": "<closed enum>", "detail_numeric": {...}}

Exit status is about whether a document exists, not about what it says. ``0``
means a document was produced — a refusal is a result, and an unreachable host
or an exhausted bound is an answer the verifier needs. A non-zero status means
this process would not start: a request it cannot execute exactly, or an
environment it will not parse hostile bytes inside.

Nothing else is written to stdout. The parent reads that stream as the document,
so a stray log line would both corrupt it and be a way for target-controlled
text to cross a boundary that exists to stop exactly that.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from gryphon.tooling.observation.facts import ObserverErrorCode
from gryphon.tooling.observation.observer import (
    ObservationOutcome,
    ObserverFailure,
    RequestInvalid,
    SandboxNotSealed,
    assert_environment_scrubbed,
    document_for,
    load_request,
    observe,
)

_USAGE = "usage: python -m gryphon.tooling.observation <request.json>"
#: Exit status for "this process refused to run at all".
_REFUSED_TO_START = 2


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(_USAGE, file=sys.stderr)
        return _REFUSED_TO_START
    try:
        assert_environment_scrubbed()
        request = load_request(Path(args[0]))
    except (OSError, ValueError, RequestInvalid, SandboxNotSealed) as exc:
        # This message describes a document the gateway wrote and an environment
        # the gateway built. No target has been contacted yet, so there is
        # nothing of theirs in it.
        print(f"refusing to observe: {exc}", file=sys.stderr)
        return _REFUSED_TO_START

    outcome: ObservationOutcome
    try:
        outcome = asyncio.run(observe(request))
    except Exception:
        # The exception is dropped rather than reported: by this point the
        # process has handled target bytes, and its own failure text is as
        # untrusted as they are. The gateway sees a closed code.
        outcome = ObserverFailure(ObserverErrorCode.INTERNAL, {})
    print(json.dumps(document_for(outcome), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
