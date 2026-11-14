"""``gryphon-gatewayd`` — the only component permitted to contact a subject.

Until now the tool execution service was constructed in-process by whoever
wanted to use it, which meant every such caller had to hold the gateway's
database role and the platform audit key: the component that writes the ledger
was also the component whose claims that ledger adjudicates, and the process
that verifies an attestation could also sign one. Making the gateway a service
closes that by construction (CHG-P5-003). It runs under its own uid, with the
``gryphon_gateway`` role and the tool-audit key, and its callers hold none of
those — only a socket.

**The order of the steps in :meth:`GatewayServer.observe` is the contract, not
an implementation detail.** Each step exists to produce a refusal *before* the
step that would make a refusal too late:

1.  **Peer credentials.** The uid comes from the kernel (``SO_PEERCRED``), never
    from the peer, because every later check is authorization for a principal
    and a principal that can be asserted is not one.
2.  **Purpose.** A ``verification`` purpose permits only the closed observation
    kinds and never a scan tool. The request names no tool at all: the kind
    selects the binary, so there is nothing to name.
3.  **Fencing.** The pass's current epochs are read under this service's own
    role. A stale claim or an advanced cancellation is refused here, with zero
    traffic — database fencing stops a superseded owner from *writing*, and only
    this stops it from *sending* (CHG-P5-012).
4.  **Envelope conflict.** One ``execution_id`` means exactly one request. A
    reused id with a different envelope is terminal and refused before traffic;
    the same envelope returns the stored facts and makes no contact at all.
5.  **Authority at contact.** Liveness is re-resolved here, on the database
    clock, immediately before dispatch — admission is not standing authority,
    and a revoked signer or an expired grant must stop work already in flight.
    The deadline rule uses the **descriptor's** timeout: a caller that supplies
    a smaller number must not thereby fit inside a window the real timeout would
    overrun (CHG-P5-002).
6.  **Destination.** Resolved once. Estate policy is applied to the addresses
    actually pinned, and only attested ones are pinned, so there is no gap
    between the answer that was judged and the answer that is used
    (CHG-P5-004). A resolver-mediated kind pins the resolvers instead and does
    not require the subject to resolve — an unresolvable name is the positive
    case for a dangling-record verifier, not a failure.
7.  **Scope and path exclusions**, re-derived from the grant receipt with the
    same canonicalizer the grant was signed under.
8.  **Budgets**, keyed by destination and resolver rather than by scan, because
    two scans of one estate are two scans of one estate (CHG-P5-014).
9.  **Intent, egress, observer.** Intent commits durably *before* any contact,
    so a crash leaves a record that traffic may have happened. The measurement
    itself runs in an unprivileged observer with a scrubbed environment and an
    egress allowlist that is exactly the pinned set.
10. **Validate and persist.** The observer's document is validated strictly —
    it is untrusted output from the one process that reads bytes a target
    chose — and the observation is persisted before the reply is sent. An
    execution whose facts did not persist is ``OBSERVATION_LOST``, never
    success.

Several of these steps need upstream support that does not exist yet: a durable
observation table owned by this service, the pass fencing tokens, the signed
estate artifact and the global budget state. They appear here as ports. The
concrete adapters are supplied by the composition root, which is also the only
place that knows this service's database role — defining their schemas inside
another layer's package is exactly the coupling this module exists to remove.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final, Protocol

from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, OperationalError

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.auth.permit_resolver import (
    PermitUnavailable,
    ResolvedPermit,
    resolve_admitted_permit,
)
from gryphon.auth.results import AuthorizedPermit
from gryphon.auth.scope import (
    CanonicalTarget,
    ScopeResult,
    canonicalize_path,
    canonicalize_target,
    evaluate,
)
from gryphon.clock import ensure_utc
from gryphon.db.session import Database
from gryphon.errors import ScopeEvaluationError
from gryphon.logging_config import get_logger
from gryphon.tooling.constants import ToolId
from gryphon.tooling.destination.egress import EgressEnforcer
from gryphon.tooling.destination.guard import DestinationDenied, DestinationGuard
from gryphon.tooling.enforcement.gateway import BinaryResolver
from gryphon.tooling.enforcement.scope_provenance import ProvenanceFailure, rederive_scope
from gryphon.tooling.gateway.protocol import (
    HANDSHAKE_DEADLINE_SECONDS,
    OUTCOME_FOR_REASON,
    ByteReader,
    ByteWriter,
    GatewayReason,
    Hello,
    ObserveReply,
    ObserveRequest,
    Welcome,
    read_frame,
    write_frame,
)
from gryphon.tooling.observation.envelope import EnvelopeError, RequestEnvelope
from gryphon.tooling.observation.facts import (
    Completeness,
    ObservationFacts,
    ObserverErrorCode,
)
from gryphon.tooling.reasons import (
    EgressUnavailableError,
    ToolingConfigurationError,
    ToolReasonCode,
)
from gryphon.tooling.tools.descriptors import ToolDescriptor, get_descriptor
from gryphon.verification.constants import (
    DNS_DEADLINE_SECONDS,
    DNS_MAX_ANSWERS,
    DNS_MAX_CNAME_DEPTH,
    EXECUTION_PURPOSE,
    GATEWAY_PROTOCOL_VERSION,
    HTTP_DEADLINE_SECONDS,
    HTTP_MAX_DECODED_BYTES,
    HTTP_MAX_HEADER_BYTES,
    HTTP_MAX_WIRE_BYTES,
    MEDIATED_KINDS,
    POSSIBLY_APPLIED_OUTCOMES,
    REQUIRED_GATEWAY_FEATURES,
    ObservationKind,
    OutcomeClass,
    TruncationReason,
)
from gryphon.verification.reasons import GatewayProtocolError

logger = get_logger(__name__)

#: The enforcement features this implementation actually performs. Advertised
#: verbatim in the handshake: a feature named here that is not performed is a
#: lie a client cannot detect, so this tuple and the steps below move together.
IMPLEMENTED_FEATURES: Final[frozenset[str]] = frozenset(REQUIRED_GATEWAY_FEATURES)

#: Request document the observer reads. Versioned so a gateway and an observer
#: from different builds refuse each other rather than misread each other.
OBSERVER_REQUEST_VERSION: Final[str] = "1"

#: The binary each observation kind runs. The kind catalog is closed, so this
#: mapping is the whole of what a verification purpose can reach.
TOOL_FOR_KIND: Final[dict[ObservationKind, ToolId]] = {
    ObservationKind.HTTP_RESPONSE_SUMMARY: ToolId.HTTPX,
    ObservationKind.DNS_ANSWER: ToolId.DNSX,
}

#: Wall-clock ceiling per kind. The effective deadline is the smallest of this,
#: the descriptor's timeout and the caller's request — never the largest.
DEADLINE_FOR_KIND: Final[dict[ObservationKind, float]] = {
    ObservationKind.HTTP_RESPONSE_SUMMARY: HTTP_DEADLINE_SECONDS,
    ObservationKind.DNS_ANSWER: DNS_DEADLINE_SECONDS,
}

#: What a closed observer error code means for the outcome. Anything outside
#: this map is a failed probe: an unrecognized code is not a partial success.
REASON_FOR_OBSERVER_ERROR: Final[dict[str, GatewayReason]] = {
    ObserverErrorCode.DEADLINE: GatewayReason.TIMEOUT,
    ObserverErrorCode.CONNECT_FAILED: GatewayReason.UNREACHABLE,
    ObserverErrorCode.TLS_FAILED: GatewayReason.UNREACHABLE,
}

#: Environment handed to the observer. Nothing else is inherited: no database
#: URL, no key material, no proxy variables, no ambient tool configuration. The
#: config path is pointed at a known-empty file because several of the pinned
#: binaries read one from ``$HOME`` by default (CHG-P5-022).
_OBSERVER_ENV_KEYS: Final[tuple[str, ...]] = ("PATH", "LANG")
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]

_SO_PEERCRED: Final[int] = 17  # SO_PEERCRED on Linux; struct ucred is 3 ints.
_PEERCRED_STRUCT: Final[str] = "3i"


# =============================================================================
# Ports — the upstream support this service composes over
# =============================================================================


@dataclass(frozen=True, slots=True)
class DependencyUnavailable:
    """A dependency this service needs is down. Transient, never a policy fact."""

    detail: str


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """Who is on the other end of the socket, according to the kernel."""

    pid: int
    uid: int
    gid: int


class PeerCredentials(Protocol):
    """Reads the connected peer's credentials from the socket itself."""

    def identify(self, writer: ByteWriter) -> PeerIdentity | None: ...


@dataclass(frozen=True, slots=True)
class PassFencing:
    """The fencing tokens a pass currently holds."""

    claim_epoch: int
    cancellation_epoch: int


class FencingPort(Protocol):
    """Reads a pass's current epochs under *this service's* database role.

    The concrete adapter is supplied by the composition root. It must read, not
    cache: the whole point is that the value can have moved since the caller
    last saw it.
    """

    async def fencing(self, pass_id: str) -> PassFencing | DependencyUnavailable | None: ...


@dataclass(frozen=True, slots=True)
class StoredObservation:
    """One durable observation record, owned by the gateway."""

    execution_id: str
    envelope_digest: str
    outcome: OutcomeClass
    reason_code: str
    facts: dict[str, Any] | None = None
    completeness: Completeness | None = None
    peer_address: str | None = None
    possibly_applied: bool = False


class ObservationStore(Protocol):
    """Durable storage for executions and their observations.

    The concrete adapter is supplied by the composition root, against the
    gateway's own tables. It is a port rather than a schema here because this
    package must not define tables another layer's migrations own.

    ``record_intent`` must commit before any contact, and must fail rather than
    overwrite: an ``execution_id`` that already exists with a different envelope
    digest is an identity conflict, not an update.
    """

    async def get(self, execution_id: str) -> StoredObservation | DependencyUnavailable | None: ...

    async def record_intent(
        self,
        *,
        execution_id: str,
        envelope_digest: str,
        pass_id: str,
        scan_run_id: str,
        finding_id: str,
        pinned_addresses: tuple[str, ...],
    ) -> DependencyUnavailable | None: ...

    async def record_outcome(
        self, observation: StoredObservation
    ) -> DependencyUnavailable | None: ...


@dataclass(frozen=True, slots=True)
class Authority:
    """A live permit plus the facts the deadline rule needs, read on one clock."""

    permit: AuthorizedPermit
    grant_expires_at: datetime
    issuer_kid: str
    #: The database clock reading the liveness decision was made against. Used
    #: for the deadline rule so that a skewed gateway host cannot widen a window.
    now: datetime


class AuthorityPort(Protocol):
    """Re-resolves authority at contact, on the database clock.

    The adapter wraps :func:`gryphon.auth.permit_resolver.resolve_admitted_permit`
    — authority is minted in the authorization layer and read here, never
    re-decided here.
    """

    async def resolve(
        self, scan_run_id: str
    ) -> Authority | PermitUnavailable | DependencyUnavailable: ...


@dataclass(frozen=True, slots=True)
class ScopeAdmitted:
    scope_policy_version: str


@dataclass(frozen=True, slots=True)
class ScopeRefused:
    reason: GatewayReason


class ScopePort(Protocol):
    """Re-derives the authorized scope from the grant receipt and evaluates it.

    The adapter wraps
    :func:`gryphon.tooling.enforcement.scope_provenance.rederive_scope` and
    :func:`gryphon.auth.scope.evaluate`. The request's own claims about scope are
    never consulted.
    """

    async def admit(
        self, *, permit: AuthorizedPermit, target: CanonicalTarget, path: str | None
    ) -> ScopeAdmitted | ScopeRefused | DependencyUnavailable: ...


class EstatePolicy(Protocol):
    """Which addresses the client attested as theirs.

    Applied to resolved addresses at pin time, never to a name. The concrete
    adapter is supplied by the composition root from the signed estate artifact
    referenced by the grant; ``digest`` is recorded on every verdict so a verdict
    can say which estate it was judged against.
    """

    @property
    def digest(self) -> str: ...

    def attests(self, address: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class ResolverPins:
    """The pinned resolver set for mediated kinds.

    Pinned explicitly, never defaulted: if "NXDOMAIN" came from whichever
    resolver the host happened to use, it is not evidence about the world.
    """

    addresses: tuple[str, ...]
    digest: str
    port: int = 53


@dataclass(frozen=True, slots=True)
class BudgetKey:
    """What a budget is counted against.

    Keyed by destination, resolver set and estate — never by scan. A per-scan
    key gives two scans of one estate two independent budgets, which is not what
    the client agreed to.
    """

    destination: str
    resolver_set: str
    estate: str


class BudgetPort(Protocol):
    """Global, persisted budgets. Returns the refusal reason, or ``None`` to allow."""

    async def acquire(self, key: BudgetKey) -> GatewayReason | None: ...

    async def release(self, key: BudgetKey) -> None: ...


@dataclass(frozen=True, slots=True)
class ObserverReport:
    """What came back from the unprivileged observer.

    Either a facts document or one closed error code — never both, and never
    free text. The observer's stderr is discarded rather than reported: a server
    can put anything in a header that a parser then quotes back, and a diagnostic
    string is a covert channel for exactly those bytes.
    """

    facts: dict[str, Any] | None = None
    error_code: str | None = None
    peer_address: str | None = None


class ObserverLauncher(Protocol):
    """Runs one measurement inside an egress context limited to ``addresses``."""

    async def run(
        self,
        request: dict[str, Any],
        *,
        addresses: tuple[str, ...],
        ports: tuple[int, ...],
        deadline_seconds: float,
    ) -> ObserverReport: ...


# =============================================================================
# The service
# =============================================================================


def build_welcome(
    *,
    binary_digests: dict[str, str],
    extractor_set_digest: str,
    sanitizer_ruleset_digest: str,
    descriptor_versions: dict[str, str] | None = None,
) -> Welcome:
    """Assemble the handshake this build may honestly advertise."""
    versions = descriptor_versions
    if versions is None:
        versions = {
            kind.value: get_descriptor(tool).descriptor_version
            for kind, tool in TOOL_FOR_KIND.items()
        }
    return Welcome(
        protocol_version=GATEWAY_PROTOCOL_VERSION,
        feature_set=IMPLEMENTED_FEATURES,
        descriptor_versions=versions,
        extractor_set_digest=extractor_set_digest,
        sanitizer_ruleset_digest=sanitizer_ruleset_digest,
        binary_digests=binary_digests,
    )


class GatewayServer:
    """The daemon. One connection per client, one request at a time per connection."""

    def __init__(
        self,
        *,
        socket_path: str | Path,
        uid_allowlist: frozenset[int],
        welcome: Welcome,
        peer_credentials: PeerCredentials,
        fencing: FencingPort,
        observations: ObservationStore,
        authority: AuthorityPort,
        scope: ScopePort,
        estate: EstatePolicy,
        destination_guard: DestinationGuard,
        budgets: BudgetPort,
        launcher: ObserverLauncher,
        binaries: BinaryResolver,
        resolvers: ResolverPins,
    ) -> None:
        if not uid_allowlist:
            # An empty allowlist that admitted everyone would be the failure
            # this check exists to prevent, so it is refused at construction.
            raise ToolingConfigurationError("the gateway requires a non-empty uid allowlist")
        self._socket_path = str(socket_path)
        self._uids = uid_allowlist
        self._welcome = welcome
        self._peers = peer_credentials
        self._fencing = fencing
        self._observations = observations
        self._authority = authority
        self._scope = scope
        self._estate = estate
        self._guard = destination_guard
        self._budgets = budgets
        self._launcher = launcher
        self._binaries = binaries
        self._resolvers = resolvers

    # -- transport ------------------------------------------------------------
    async def serve(self) -> asyncio.AbstractServer:
        """Bind the Unix socket and start accepting. Never binds a network port."""
        if not hasattr(socket, "AF_UNIX") or not hasattr(asyncio, "start_unix_server"):
            raise ToolingConfigurationError(
                "the gateway serves only on a Unix socket, which this host does not support"
            )
        await asyncio.to_thread(self._clear_stale_socket)
        server = await asyncio.start_unix_server(self._handle, path=self._socket_path)
        await asyncio.to_thread(self._restrict_socket_mode)
        logger.info("gateway_listening", socket_path=self._socket_path, uids=sorted(self._uids))
        return server

    def _clear_stale_socket(self) -> None:
        """Remove a socket file left by a crash, so a restart is not a bind error."""
        path = Path(self._socket_path)
        if path.exists():
            path.unlink()

    def _restrict_socket_mode(self) -> None:
        """Owner-only. The uid allowlist is the control; this narrows the blast
        radius of a misconfigured allowlist rather than replacing it."""
        os.chmod(self._socket_path, 0o600)

    async def _handle(self, reader: ByteReader, writer: ByteWriter) -> None:
        peer = self._peers.identify(writer)
        try:
            if peer is None or peer.uid not in self._uids:
                logger.warning("gateway_peer_refused", uid=None if peer is None else peer.uid)
                return
            await asyncio.wait_for(
                self._handshake(reader, writer), timeout=HANDSHAKE_DEADLINE_SECONDS
            )
            while True:
                request = ObserveRequest.from_payload(await read_frame(reader))
                reply = await self.observe(request, peer)
                await write_frame(writer, reply.as_payload())
        except (EOFError, ConnectionError, TimeoutError):
            pass  # The client went away; its durable records are unaffected.
        except GatewayProtocolError as exc:
            logger.warning("gateway_protocol_violation", detail=str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, EOFError):  # pragma: no cover - already-dead socket
                pass

    async def _handshake(self, reader: ByteReader, writer: ByteWriter) -> None:
        hello = Hello.from_payload(await read_frame(reader))
        if hello.protocol_version != GATEWAY_PROTOCOL_VERSION:
            # Answer with the version anyway: the client must be able to say
            # *which* skew it refused, not merely that the socket closed.
            await write_frame(writer, self._welcome.as_payload())
            raise GatewayProtocolError(
                f"client {hello.client_name!r} speaks protocol {hello.protocol_version!r}"
            )
        await write_frame(writer, self._welcome.as_payload())

    # -- the ten steps --------------------------------------------------------
    async def observe(self, request: ObserveRequest, peer: PeerIdentity) -> ObserveReply:
        """Mediate one contact. The step order is the contract (see the module docstring)."""
        # 1. Peer credentials, re-asserted per request so the order is uniform.
        if peer.uid not in self._uids:
            return self._refuse(request, GatewayReason.PEER_REFUSED)

        # 2. Purpose. A verification purpose reaches the observation kinds and
        #    nothing else; the request cannot name a tool, so it cannot name one
        #    outside this set.
        if request.purpose != EXECUTION_PURPOSE:
            return self._refuse(request, GatewayReason.PURPOSE_FORBIDDEN)
        parsed = _parse_envelope(request.envelope)
        if isinstance(parsed, GatewayReason):
            return self._refuse(request, parsed)
        envelope = parsed
        descriptor = get_descriptor(TOOL_FOR_KIND[envelope.kind])
        if envelope.descriptor_version != descriptor.descriptor_version:
            # The envelope pinned a descriptor that has since moved. Running the
            # new one would mean the evidence does not match the identity.
            return self._refuse(request, GatewayReason.DESCRIPTOR_MISMATCH)

        # 3. Fencing. Zero traffic for a stale owner or a cancelled pass.
        fencing = await self._fencing.fencing(request.pass_id)
        if isinstance(fencing, DependencyUnavailable):
            return self._refuse(request, GatewayReason.DEPENDENCY_UNAVAILABLE)
        if fencing is None:
            return self._refuse(request, GatewayReason.EPOCH_STALE)
        if request.claim_epoch != fencing.claim_epoch:
            return self._refuse(request, GatewayReason.EPOCH_STALE)
        if request.cancellation_epoch != fencing.cancellation_epoch:
            return self._refuse(request, GatewayReason.CANCELLED)

        # 4. Envelope conflict. One execution_id, one request, forever.
        existing = await self._observations.get(request.execution_id)
        if isinstance(existing, DependencyUnavailable):
            return self._refuse(request, GatewayReason.DEPENDENCY_UNAVAILABLE)
        if existing is not None:
            if existing.envelope_digest != request.envelope_digest:
                return self._refuse(request, GatewayReason.ENVELOPE_CONFLICT)
            return ObserveReply(
                outcome=existing.outcome,
                reason_code=existing.reason_code,
                execution_id=request.execution_id,
                facts=existing.facts,
                completeness=existing.completeness,
                peer_address=existing.peer_address,
                possibly_applied=existing.possibly_applied,
            )

        # 5. Authority at contact, on the database clock.
        authority = await self._authority.resolve(request.scan_run_id)
        if isinstance(authority, DependencyUnavailable):
            return self._refuse(request, GatewayReason.DEPENDENCY_UNAVAILABLE)
        if isinstance(authority, PermitUnavailable):
            logger.info(
                "gateway_authority_unavailable",
                scan_run_id=request.scan_run_id,
                reason_code=authority.reason_code.value,
            )
            return self._refuse(request, GatewayReason.AUTHORIZATION_UNAVAILABLE)
        window_seconds = _window_seconds(envelope.kind, descriptor)
        if authority.grant_expires_at < authority.now + timedelta(seconds=window_seconds):
            # The descriptor's timeout, not the caller's number: a caller that
            # asks for two seconds does not thereby fit a twenty-second tool
            # inside the last five seconds of a grant.
            return self._refuse(request, GatewayReason.DEADLINE_EXCEEDS_GRANT)
        deadline_seconds = min(window_seconds, _requested_deadline(request, window_seconds))

        # 6. Destination: resolve once, attest the resolved addresses, pin only
        #    those. The resolve is a DNS lookup, not target contact.
        destination = await self._bind_destination(envelope)
        if isinstance(destination, GatewayReason):
            return self._refuse(request, destination)
        pinned, ports = destination

        # 7. Scope and path exclusions, re-derived from the grant receipt.
        try:
            target = canonicalize_target(envelope.host)
            path = canonicalize_path(envelope.path) if envelope.path is not None else None
        except ScopeEvaluationError:
            return self._refuse(request, GatewayReason.DESTINATION_MISMATCH)
        admitted = await self._scope.admit(permit=authority.permit, target=target, path=path)
        if isinstance(admitted, DependencyUnavailable):
            return self._refuse(request, GatewayReason.DEPENDENCY_UNAVAILABLE)
        if isinstance(admitted, ScopeRefused):
            return self._refuse(request, admitted.reason)

        # 8. Budgets, keyed by destination and resolver.
        budget_key = BudgetKey(
            destination=target.text,
            resolver_set=envelope.resolver_set_digest or "-",
            estate=self._estate.digest,
        )
        refusal = await self._budgets.acquire(budget_key)
        if refusal is not None:
            return self._refuse(request, refusal)

        try:
            # 9. Intent, egress, observer.
            return await self._dispatch(
                request,
                envelope=envelope,
                pinned=pinned,
                ports=ports,
                deadline_seconds=deadline_seconds,
            )
        finally:
            await self._budgets.release(budget_key)

    # -- step 6 ---------------------------------------------------------------
    async def _bind_destination(
        self, envelope: RequestEnvelope
    ) -> tuple[tuple[str, ...], tuple[int, ...]] | GatewayReason:
        """Resolve once and pin only what the estate attests.

        For a resolver-mediated kind the destination is the resolver set, not the
        subject: the subject need not resolve, and the resolver pin is what makes
        a negative answer mean anything.
        """
        if envelope.kind in MEDIATED_KINDS:
            if envelope.resolver_set_digest != self._resolvers.digest:
                return GatewayReason.DESTINATION_MISMATCH
            if not self._resolvers.addresses:
                return GatewayReason.DEPENDENCY_UNAVAILABLE
            return self._resolvers.addresses, (self._resolvers.port,)

        try:
            target = canonicalize_target(envelope.host)
        except ScopeEvaluationError:
            return GatewayReason.DESTINATION_MISMATCH
        bound = await self._guard.bind(target, (envelope.port,))
        if isinstance(bound, DestinationDenied):
            return _reason_for_denied(bound)
        attested = tuple(a for a in bound.addresses if self._estate.attests(a))
        if not attested:
            # Resolved, but to addresses nobody attested. Refused as policy: the
            # estate decision and the pin are now one decision over one answer.
            logger.info(
                "gateway_destination_unattested",
                host=envelope.host,
                resolved=len(bound.addresses),
                estate_digest=self._estate.digest,
            )
            return GatewayReason.DESTINATION_UNATTESTED
        return attested, bound.ports

    # -- steps 9 and 10 -------------------------------------------------------
    async def _dispatch(
        self,
        request: ObserveRequest,
        *,
        envelope: RequestEnvelope,
        pinned: tuple[str, ...],
        ports: tuple[int, ...],
        deadline_seconds: float,
    ) -> ObserveReply:
        binary_path = self._binaries.resolve(TOOL_FOR_KIND[envelope.kind])
        if binary_path is None:
            return self._refuse(request, GatewayReason.DEPENDENCY_UNAVAILABLE)

        # Intent first. After this commit the record says contact may have
        # happened, which is what makes a crash recoverable rather than silent.
        failure = await self._observations.record_intent(
            execution_id=request.execution_id,
            envelope_digest=request.envelope_digest,
            pass_id=request.pass_id,
            scan_run_id=request.scan_run_id,
            finding_id=request.finding_id,
            pinned_addresses=pinned,
        )
        if failure is not None:
            return self._refuse(request, GatewayReason.DEPENDENCY_UNAVAILABLE)

        observer_request = build_observer_request(
            envelope=envelope,
            binary_path=binary_path,
            deadline_seconds=deadline_seconds,
            resolvers=self._resolvers,
            signal_tokens=request.signal_tokens,
        )
        try:
            report = await self._launcher.run(
                observer_request,
                addresses=pinned,
                ports=ports,
                deadline_seconds=deadline_seconds,
            )
        except EgressUnavailableError:
            # The context could not be established, so nothing ran and nothing
            # was contacted. Transient by nature: this is our host, not theirs.
            return await self._settle(
                request, GatewayReason.DEPENDENCY_UNAVAILABLE, intent_committed=True
            )
        except (OSError, ValueError) as exc:
            logger.error("gateway_observer_spawn_failed", error=type(exc).__name__)
            return await self._settle(
                request, GatewayReason.PROBE_FAILED, intent_committed=True
            )

        return await self._settle_report(request, envelope, report, pinned)

    async def _settle_report(
        self,
        request: ObserveRequest,
        envelope: RequestEnvelope,
        report: ObserverReport,
        pinned: tuple[str, ...],
    ) -> ObserveReply:
        """Validate the observer's document strictly, then persist and answer."""
        if report.error_code is not None or report.facts is None:
            code = report.error_code or ObserverErrorCode.OUTPUT_EMPTY
            if code not in ObserverErrorCode.ALL:
                code = ObserverErrorCode.INTERNAL
            reason = REASON_FOR_OBSERVER_ERROR.get(code, GatewayReason.PROBE_FAILED)
            return await self._settle(request, reason, intent_committed=True)

        try:
            facts = ObservationFacts.from_payload(report.facts)
        except (KeyError, TypeError, ValueError) as exc:
            # Untrusted output from the one process that reads target bytes. A
            # document that does not validate is a boundary failure, never a
            # partially-trusted result.
            logger.error("gateway_observation_rejected", error=type(exc).__name__)
            return await self._settle(request, GatewayReason.PROBE_FAILED, intent_committed=True)
        if facts.kind is not envelope.kind:
            return await self._settle(request, GatewayReason.PROBE_FAILED, intent_committed=True)
        if report.peer_address is not None and report.peer_address not in pinned:
            # The egress allowlist is the pinned set, so this should be
            # impossible; if it happens the measurement came from somewhere
            # nobody attested and its facts are discarded rather than recorded.
            logger.error("gateway_peer_outside_pin", execution_id=request.execution_id)
            return await self._settle(request, GatewayReason.PROBE_FAILED, intent_committed=True)

        reason = _classify(facts)
        observation = StoredObservation(
            execution_id=request.execution_id,
            envelope_digest=request.envelope_digest,
            outcome=OUTCOME_FOR_REASON[reason],
            reason_code=reason.value,
            facts=report.facts,
            completeness=facts.completeness,
            peer_address=report.peer_address,
            possibly_applied=False,
        )
        if await self._observations.record_outcome(observation) is not None:
            # The contact happened and its facts are gone. Never success: the
            # subject carries a possibly-applied fact and the pass must decide.
            logger.error("gateway_observation_lost", execution_id=request.execution_id)
            return self._reply(request, GatewayReason.OBSERVATION_LOST, possibly_applied=True)
        return ObserveReply(
            outcome=observation.outcome,
            reason_code=observation.reason_code,
            execution_id=request.execution_id,
            facts=observation.facts,
            completeness=observation.completeness,
            peer_address=observation.peer_address,
        )

    async def _settle(
        self, request: ObserveRequest, reason: GatewayReason, *, intent_committed: bool
    ) -> ObserveReply:
        """Record a factless outcome for an execution whose intent is committed."""
        outcome = OUTCOME_FOR_REASON[reason]
        possibly_applied = intent_committed and outcome in POSSIBLY_APPLIED_OUTCOMES
        completeness = Completeness.incomplete(
            TruncationReason.DEADLINE
            if outcome is OutcomeClass.TIMED_OUT
            else TruncationReason.NONE
        )
        failure = await self._observations.record_outcome(
            StoredObservation(
                execution_id=request.execution_id,
                envelope_digest=request.envelope_digest,
                outcome=outcome,
                reason_code=reason.value,
                completeness=completeness,
                possibly_applied=possibly_applied,
            )
        )
        if failure is not None:
            return self._reply(request, GatewayReason.OBSERVATION_LOST, possibly_applied=True)
        return self._reply(
            request, reason, possibly_applied=possibly_applied, completeness=completeness
        )

    # -- replies --------------------------------------------------------------
    def _refuse(self, request: ObserveRequest, reason: GatewayReason) -> ObserveReply:
        """A refusal that precedes intent: zero traffic, nothing persisted."""
        logger.info(
            "gateway_refused",
            execution_id=request.execution_id,
            outcome=OUTCOME_FOR_REASON[reason].value,
            reason_code=reason.value,
        )
        return self._reply(request, reason)

    def _reply(
        self,
        request: ObserveRequest,
        reason: GatewayReason,
        *,
        possibly_applied: bool = False,
        completeness: Completeness | None = None,
    ) -> ObserveReply:
        return ObserveReply(
            outcome=OUTCOME_FOR_REASON[reason],
            reason_code=reason.value,
            execution_id=request.execution_id,
            completeness=completeness,
            possibly_applied=possibly_applied,
        )


# =============================================================================
# The observer request
# =============================================================================


def build_observer_request(
    *,
    envelope: RequestEnvelope,
    binary_path: str,
    deadline_seconds: float,
    resolvers: ResolverPins,
    signal_tokens: tuple[str, ...] = (),
) -> dict[str, Any]:
    """The document the observer reads on stdin-equivalent input.

    Every bound travels explicitly rather than being inherited from the tool's
    flags. A flag typo or a version that renames an option must not silently
    remove a cap, so the observer enforces these itself and the gateway enforces
    them again around it (CHG-P5-028).
    """
    # The member names and the bound names below are the observer's, exactly.
    # It validates this document strictly and refuses an unknown member, which
    # is the right behaviour for the one process that reads bytes a target
    # chose — so the gateway conforms to the stricter side rather than teaching
    # the sandbox to be lenient. The two schemas are pinned together by
    # ``test_the_gateway_and_the_observer_agree_on_the_request_schema``.
    bounds: dict[str, Any] = {
        "wire_bytes": HTTP_MAX_WIRE_BYTES,
        "decoded_bytes": HTTP_MAX_DECODED_BYTES,
        "header_bytes": HTTP_MAX_HEADER_BYTES,
        "deadline_seconds": deadline_seconds,
        "answer_count": DNS_MAX_ANSWERS,
        "cname_depth": DNS_MAX_CNAME_DEPTH,
    }
    return {
        "request_format_version": OBSERVER_REQUEST_VERSION,
        "kind": envelope.kind.value,
        "binary_path": binary_path,
        "envelope": envelope.as_canonical(),
        "bounds": bounds,
        "signal_tokens": list(signal_tokens),
        "resolvers": list(resolvers.addresses) if envelope.kind in MEDIATED_KINDS else [],
    }


def observer_environment(*, empty_config: Path) -> dict[str, str]:
    """The observer's entire environment.

    Nothing is inherited beyond the two variables an exec needs. No database
    URL, no key material, no proxy variables, and every ambient tool
    configuration path aimed at a file known to be empty — a scanner that reads
    ``$HOME/.config`` would otherwise be configured by whatever the gateway host
    happens to have.
    """
    env = {key: os.environ[key] for key in _OBSERVER_ENV_KEYS if key in os.environ}
    env.update(
        {
            "HOME": str(empty_config.parent),
            "XDG_CONFIG_HOME": str(empty_config.parent),
            "PYTHONPATH": str(_REPO_ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "LC_ALL": "C.UTF-8",
        }
    )
    return env


class SubprocessObserverLauncher:
    """Runs ``python -m gryphon.tooling.observation`` inside the egress context.

    The observer is unprivileged by construction: it is handed a request file, a
    pinned binary path and nothing else. It holds no database handle, no key and
    no credential, and its egress is exactly the addresses pinned for this one
    measurement — which is why it is the right place, and the only place, for
    bytes a target chose to be parsed.
    """

    def __init__(
        self,
        *,
        enforcer: EgressEnforcer,
        staging_dir: Path,
        max_report_bytes: int = 1_048_576,
        python: str | None = None,
    ) -> None:
        self._enforcer = enforcer
        self._staging = staging_dir
        self._max_report = max_report_bytes
        self._python = python or sys.executable

    @property
    def posture(self) -> str:
        return "ENFORCED" if self._enforcer.enforcing else "UNENFORCED"

    async def run(
        self,
        request: dict[str, Any],
        *,
        addresses: tuple[str, ...],
        ports: tuple[int, ...],
        deadline_seconds: float,
    ) -> ObserverReport:
        staging = self._staging / str(request["execution_id"])
        staging.mkdir(parents=True, exist_ok=True)
        request_path = staging / "request.json"
        request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
        empty_config = staging / "empty.yaml"
        empty_config.write_text("", encoding="utf-8")

        handle = await self._enforcer.establish(list(addresses), list(ports))
        try:
            argv = handle.wrap_argv(
                [
                    self._python,
                    "-I",
                    "-B",
                    "-m",
                    "gryphon.tooling.observation",
                    str(request_path),
                ]
            )
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    cwd=str(staging),
                    env=observer_environment(empty_config=empty_config),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except (OSError, ValueError):
                return ObserverReport(error_code=ObserverErrorCode.SPAWN_FAILED)
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=deadline_seconds
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return ObserverReport(error_code=ObserverErrorCode.DEADLINE)
        finally:
            await self._enforcer.teardown(handle)

        # stderr is measured, never carried: it may contain target bytes.
        if stderr:
            logger.info("observer_stderr_discarded", bytes_discarded=len(stderr))
        if proc.returncode != 0:
            return ObserverReport(error_code=ObserverErrorCode.TOOL_NONZERO)
        if not stdout:
            return ObserverReport(error_code=ObserverErrorCode.OUTPUT_EMPTY)
        if len(stdout) > self._max_report:
            return ObserverReport(error_code=ObserverErrorCode.BOUND_EXCEEDED)
        try:
            document = json.loads(stdout)
        except ValueError:
            return ObserverReport(error_code=ObserverErrorCode.OUTPUT_UNPARSEABLE)
        if not isinstance(document, dict):
            return ObserverReport(error_code=ObserverErrorCode.OUTPUT_UNPARSEABLE)

        error_code = document.get("error_code")
        facts = document.get("facts")
        peer = document.get("peer_address")
        return ObserverReport(
            facts=facts if isinstance(facts, dict) else None,
            error_code=str(error_code) if error_code else None,
            peer_address=str(peer) if isinstance(peer, str) else None,
        )


# =============================================================================
# Peer credentials
# =============================================================================


class SoPeercredCredentials:
    """Reads ``SO_PEERCRED`` from the connected socket.

    The uid comes from the kernel's record of who opened the other end. A
    credential the peer can state is not a credential, and every check after
    this one is authorization for whoever this says it is.
    """

    def identify(self, writer: ByteWriter) -> PeerIdentity | None:
        extra_info = getattr(writer, "get_extra_info", None)
        if extra_info is None or not hasattr(socket, "AF_UNIX"):
            return None
        sock = extra_info("socket")
        if sock is None:
            return None
        try:
            raw = sock.getsockopt(
                socket.SOL_SOCKET, _SO_PEERCRED, struct.calcsize(_PEERCRED_STRUCT)
            )
        except (OSError, AttributeError):
            # Fail closed: an unidentifiable peer is refused, not admitted.
            return None
        pid, uid, gid = struct.unpack(_PEERCRED_STRUCT, raw)
        return PeerIdentity(pid=pid, uid=uid, gid=gid)


# =============================================================================
# Helpers
# =============================================================================


def _parse_envelope(payload: dict[str, Any]) -> RequestEnvelope | GatewayReason:
    """Rebuild the envelope and prove it is the canonical form that was sent.

    Nothing in the envelope is taken on trust, and the comparison matters as
    much as the parse: if the mapping the caller digested is not the mapping
    these members produce, then the identity the gateway stores is not the
    identity the caller derived.
    """
    try:
        kind = ObservationKind(str(payload.get("kind", "")))
    except ValueError:
        return GatewayReason.KIND_FORBIDDEN
    record_types = payload.get("record_types") or []
    if not isinstance(record_types, list):
        return GatewayReason.ENVELOPE_MALFORMED
    path = payload.get("path")
    if path is not None and not isinstance(path, str):
        return GatewayReason.ENVELOPE_MALFORMED
    port = payload.get("port")
    if not isinstance(port, int) or isinstance(port, bool):
        return GatewayReason.ENVELOPE_MALFORMED
    try:
        envelope = RequestEnvelope(
            kind=kind,
            method=str(payload.get("method", "")),
            host=str(payload.get("host", "")),
            port=port,
            scheme=str(payload.get("scheme", "")),
            path=path,
            record_types=tuple(str(r) for r in record_types),
            descriptor_version=str(payload.get("descriptor_version", "")),
            extractor_set_digest=str(payload.get("extractor_set_digest", "")),
            resolver_set_digest=str(payload.get("resolver_set_digest", "")),
        )
    except EnvelopeError:
        return GatewayReason.ENVELOPE_MALFORMED
    if envelope.as_canonical() != dict(payload):
        return GatewayReason.ENVELOPE_MALFORMED
    return envelope


def _window_seconds(kind: ObservationKind, descriptor: ToolDescriptor) -> float:
    """The window the deadline rule checks: the descriptor's timeout, capped.

    Deliberately independent of the caller's number. The caller may shorten what
    it waits for; it may not shorten what the grant must cover.
    """
    return min(DEADLINE_FOR_KIND[kind], descriptor.timeout_seconds)


def _requested_deadline(request: ObserveRequest, window_seconds: float) -> float:
    if request.deadline_seconds <= 0:
        return window_seconds
    return request.deadline_seconds


def _reason_for_denied(denied: DestinationDenied) -> GatewayReason:
    """Map the destination guard's codes onto the three refusal classes.

    An unresolvable name is a fact about the world, not a denial: for a dangling
    record it is the answer being looked for.
    """
    if denied.reason_code is ToolReasonCode.DESTINATION_UNRESOLVABLE:
        return GatewayReason.DESTINATION_UNRESOLVABLE
    return GatewayReason.DESTINATION_UNATTESTED


def _classify(facts: ObservationFacts) -> GatewayReason:
    """Separate a world fact from an observation.

    NXDOMAIN and NOERROR-with-no-answer are evidence routed to the verifier, not
    refusals: reporting them as denials is how the positive case for takeover
    verification becomes invisible.
    """
    if facts.dns is not None:
        if facts.dns.rcode == "NXDOMAIN":
            return GatewayReason.NXDOMAIN
        if (
            facts.dns.rcode == "NOERROR"
            and not facts.dns.a_records
            and not facts.dns.cname_chain
        ):
            return GatewayReason.NO_ANSWER
    return GatewayReason.OBSERVED


def resolved_permit_to_authority(resolved: ResolvedPermit, *, now: datetime) -> Authority:
    """Adapt the authorization layer's resolution to this service's port.

    ``now`` is the database clock reading the resolution was made against, kept
    with the result so the deadline rule and the liveness check cannot end up on
    two different clocks.
    """
    return Authority(
        permit=resolved.permit,
        grant_expires_at=resolved.grant_expires_at,
        issuer_kid=resolved.issuer_kid,
        now=now,
    )


# =============================================================================
# Database-backed adapters for the authorization ports
# =============================================================================


class DatabaseAuthority:
    """Re-resolves authority at contact, on the database clock.

    The clock reading and the liveness check happen in one session, so the
    instant the window is measured against is the instant the database holds —
    not this host's idea of now. A gateway whose clock has drifted forward would
    otherwise widen every grant window by the drift.

    Minting is not re-decided here: ``resolve_admitted_permit`` lives in the
    authorization layer because "is this authorization still live?" must have
    exactly one answer, and this is a read of that answer.
    """

    def __init__(self, *, database: Database, trust: TrustedKeyStore) -> None:
        self._db = database
        self._trust = trust

    async def resolve(
        self, scan_run_id: str
    ) -> Authority | PermitUnavailable | DependencyUnavailable:
        try:
            async with self._db.session() as session:
                now = ensure_utc((await session.execute(select(func.now()))).scalar_one())
                resolved = await resolve_admitted_permit(
                    session, scan_run_id=scan_run_id, trust=self._trust, now=now
                )
        except (OperationalError, DBAPIError) as exc:
            # Transient and ours. A database blip is not a statement about the
            # client's authorization, so it must not read as one.
            return DependencyUnavailable(f"database unavailable: {type(exc).__name__}")
        if isinstance(resolved, PermitUnavailable):
            return resolved
        return resolved_permit_to_authority(resolved, now=now)


class DatabaseScope:
    """Re-derives the authorized scope from the grant receipt and evaluates it.

    The request's host and path are canonicalized with the same policy the grant
    was signed under, and the scope is rebuilt from the committed receipt rather
    than read from anything the caller sent: a credential's own account of its
    scope is exactly what must not be trusted.
    """

    def __init__(self, *, database: Database) -> None:
        self._db = database

    async def admit(
        self, *, permit: AuthorizedPermit, target: CanonicalTarget, path: str | None
    ) -> ScopeAdmitted | ScopeRefused | DependencyUnavailable:
        try:
            async with self._db.session() as session:
                provenance = await rederive_scope(
                    session,
                    grant_id=permit.grant_id,
                    expected_claims_digest=permit.claims_digest,
                )
        except (OperationalError, DBAPIError) as exc:
            return DependencyUnavailable(f"database unavailable: {type(exc).__name__}")
        if isinstance(provenance, ProvenanceFailure):
            # A missing or tampered receipt is not a scope decision: there is no
            # authorization to evaluate, so it is reported as its absence.
            logger.warning(
                "gateway_scope_provenance_failed", reason_code=provenance.reason_code.value
            )
            return ScopeRefused(GatewayReason.AUTHORIZATION_UNAVAILABLE)

        decision = evaluate(provenance.scope_entries, target, path)
        if decision.result is ScopeResult.EXCLUDED:
            return ScopeRefused(GatewayReason.SCOPE_EXCLUDED)
        if decision.result is not ScopeResult.MATCH:
            # NO_MATCH and INVALID_INPUT both fail closed. A target the signed
            # policy cannot evaluate is not a target it authorized.
            return ScopeRefused(GatewayReason.SCOPE_NO_MATCH)
        return ScopeAdmitted(scope_policy_version=provenance.scope_policy_version)
