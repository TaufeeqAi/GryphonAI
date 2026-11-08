"""The sole per-execution decision point and the execution saga.

The gateway re-derives authority from the grant receipt (never a credential's
copy), applies scope/depth/descriptor policy and aggregate budgets, and the
execution service runs the intent → execute → outcome saga with OS egress
containment. Enforcement is a transport-independent domain service.
"""

from __future__ import annotations
