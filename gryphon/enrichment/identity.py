"""Caller identity for the enrichment command boundary.

The caller is the process's *real* uid — not a value it supplies — recorded as
``initiated_by`` on every pass and every signed event, using the same
``cli:uid:<n>`` form as the orchestration layer's commands (pinned by test).
Re-implemented here because importing the orchestration package would load a
graph runtime whose dependency closure contains an HTTP client.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass

from gryphon.enrichment.reasons import CallerRejected


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    uid: int
    label: str


def local_cli_identity(*, allowed_uids: Sequence[int] = ()) -> CallerIdentity:
    """Identify a direct CLI caller by its own uid; enforce the allowlist."""
    uid = os.getuid() if hasattr(os, "getuid") else -1
    if allowed_uids and uid not in allowed_uids:
        raise CallerRejected(f"uid {uid} is not permitted to run enrichment")
    return CallerIdentity(uid=uid, label=f"cli:uid:{uid}")
