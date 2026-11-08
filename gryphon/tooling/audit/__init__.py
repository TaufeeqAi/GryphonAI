"""Signed tool-invocation audit events (intent + outcome).

Reuses the authorization core's audit signing key and canonicalization so the
accountability record is produced identically. Events are persisted into a
dedicated append-only sibling table; the authorization audit table is untouched.
"""

from __future__ import annotations
