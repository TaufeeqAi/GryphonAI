"""The collaborator bundle every node needs.

Nodes are closures over this object rather than over module-level singletons, so
a test can substitute any collaborator (a stub touchpoint, a fixed clock, a
different settings object) without monkeypatching imports.

It deliberately holds **no authority**: the permit is reached only through the
touchpoint, which resolves it per call and drops it when the call returns. There
is no field here that a node could read to obtain standing authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from gryphon.clock import Clock
from gryphon.db.session import Database
from gryphon.orchestration.admission import TargetAdmission
from gryphon.orchestration.audit import OrchestrationAuditBuilder
from gryphon.orchestration.engine import StepEngine
from gryphon.orchestration.reconcile import Reconciler
from gryphon.orchestration.settings import OrchestrationSettings
from gryphon.orchestration.touchpoint import AuthorityTouchpoint


@dataclass(frozen=True, slots=True)
class ScanRuntime:
    """Everything a node may use. No authority material lives here."""

    database: Database
    clock: Clock
    settings: OrchestrationSettings
    touchpoint: AuthorityTouchpoint
    engine: StepEngine
    reconciler: Reconciler
    admission: TargetAdmission
    audit: OrchestrationAuditBuilder

    def effective_deadline(self, *, grant_expires_at: datetime) -> datetime:
        """The scan deadline, which the grant always wins.

        A configured deadline is an operator preference; the grant is the
        authorization. Taking the minimum is what stops a generous local setting
        from licensing work past the authorized window.
        """
        configured = self.clock.now() + timedelta(
            seconds=self.settings.scan_deadline_seconds
        )
        return min(configured, grant_expires_at)
