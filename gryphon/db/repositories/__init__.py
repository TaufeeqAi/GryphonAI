"""Domain repositories (BND-04/05/06/07).

Repositories map domain operations to SQLAlchemy. They do NOT decide scope or
policy (§29.1) and they do NOT commit — the caller owns the transaction so that
``scan_runs`` and the audit event commit atomically (§22.2).
"""

from __future__ import annotations

from gryphon.db.repositories.audit import AuditRepository
from gryphon.db.repositories.findings import FindingRepository
from gryphon.db.repositories.grants import GrantRepository
from gryphon.db.repositories.scan_runs import ScanRunRepository

__all__ = [
    "GrantRepository",
    "ScanRunRepository",
    "AuditRepository",
    "FindingRepository",
]
