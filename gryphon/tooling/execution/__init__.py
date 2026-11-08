"""The Execution aggregate: a durable, idempotent, accountable tool run.

Keyed by ``execution_id``. A durable intent record commits before any subprocess
spawns; an outcome record commits after. Duplicate ids return the recorded
outcome, never a second subprocess. ``UNKNOWN`` is never success.
"""

from __future__ import annotations
