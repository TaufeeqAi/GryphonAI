"""ORM models (§22.1).

Importing this package registers every table on ``Base.metadata`` so Alembic and
readiness checks can see the full schema. ``exploit_chain`` is intentionally a
behaviour-free placeholder: it defines NO table (§22.1, §34).
"""

from __future__ import annotations

from gryphon.db.models.audit_log import AuthorizationAuditLog
from gryphon.db.models.authorization import AuthorizationGrant
from gryphon.db.models.finding import Finding
from gryphon.db.models.scan_run import ScanRun

__all__ = [
    "AuthorizationGrant",
    "ScanRun",
    "Finding",
    "AuthorizationAuditLog",
]
