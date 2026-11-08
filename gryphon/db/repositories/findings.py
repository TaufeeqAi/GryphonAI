"""Finding repository (schema only in Phase 1; §22.1).

Phase 1 does NOT produce findings from scans. This repository exists so the
master-plan schema is persistable and integration-testable (§30.3) by later
producers; domain-enum validation happens at the boundary before insertion.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from gryphon.constants import RemediationStatus, Severity, VerificationStatus
from gryphon.db.models.finding import Finding


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, finding_id: uuid.UUID) -> Finding | None:
        return await self._session.get(Finding, finding_id)

    def add(
        self,
        *,
        scan_run_id: str,
        target: str,
        finding_type: str,
        title: str,
        severity: Severity,
        verification_status: VerificationStatus = VerificationStatus.UNVERIFIED,
        remediation_status: RemediationStatus = RemediationStatus.OPEN,
        description: str | None = None,
        cve_id: str | None = None,
        cvss_score: float | None = None,
        tool_source: str | None = None,
    ) -> Finding:
        """Stage a finding for insertion (no commit). Enums validated by type."""
        row = Finding(
            scan_run_id=scan_run_id,
            target=target,
            finding_type=finding_type,
            title=title,
            severity=severity.value,
            verification_status=verification_status.value,
            remediation_status=remediation_status.value,
            description=description,
            cve_id=cve_id,
            cvss_score=cvss_score,
            tool_source=tool_source,
            compliance_frameworks=[],
        )
        self._session.add(row)
        return row
