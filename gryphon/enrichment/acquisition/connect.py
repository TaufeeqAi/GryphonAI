"""Pinned-address HTTPS GET with connection-level egress rules.

Rules enforced here, by construction rather than by configuration:

* **Exact hosts.** A request names a host from the code-constant allowlist and a
  set of *pinned IPv4 addresses* resolved by the parent. The child connects to a
  pinned address — it performs no DNS of its own — with SNI and certificate
  verification against the hostname, using the system trust store.
* **No redirects.** :mod:`http.client` never follows one; any 3xx is a rejection.
* **No proxies.** :mod:`http.client` never consults proxy environment variables
  (only :mod:`urllib` does), and the subprocess environment carries none.
* **Size caps** on the declared length and on the bytes actually read, and a
  total deadline per request.

Retries are bounded and typed: transport failures, 5xx and 429 are retried
(honouring ``Retry-After`` up to a ceiling); everything else is final.
"""

from __future__ import annotations

import http.client
import ipaddress
import random
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from gryphon.enrichment.constants import ALLOWED_HOSTS, HTTPS_PORT

USER_AGENT = "gryphon-enrichment/1.1 (whole-snapshot acquisition)"
_READ_CHUNK = 64 * 1024
_RETRY_AFTER_CEILING_SECONDS = 60.0
_BACKOFF_SECONDS = (2.0, 4.0, 8.0)


class FetchFailure(Exception):
    """A typed, final-or-retryable failure of one HTTP request."""

    def __init__(
        self,
        remediation_class: str,
        reason: str,
        *,
        retryable: bool,
        status: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(reason)
        self.remediation_class = remediation_class
        self.reason = reason
        self.retryable = retryable
        self.status = status
        self.retry_after = retry_after


@dataclass
class RequestRecord:
    """One HTTP request, reported to the parent for the egress ledger."""

    host: str
    path: str
    address: str
    started_at: str
    finished_at: str = ""
    status: int | None = None
    bytes_received: int = 0
    outcome_class: str = "PENDING"
    detail: str | None = None

    def as_payload(self) -> dict[str, object]:
        return {
            "host": self.host,
            "path": self.path,
            "address": self.address,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "bytes_received": self.bytes_received,
            "outcome_class": self.outcome_class,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class FetchRequest:
    host: str
    path: str
    addresses: tuple[str, ...]
    max_bytes: int
    connect_timeout: float
    request_timeout: float

    def __post_init__(self) -> None:
        if self.host not in ALLOWED_HOSTS:
            raise ValueError(f"host {self.host!r} is not an allowed intelligence host")
        if not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            raise ValueError("path must be an absolute path with no query or fragment")
        if not self.addresses:
            raise ValueError("at least one pinned address is required")
        for address in self.addresses:
            if not isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address):
                raise ValueError(f"pinned address {address!r} is not IPv4")


@dataclass
class FetchOutcome:
    body: bytes | None
    failure: FetchFailure | None
    records: list[RequestRecord] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()  # CERT_REQUIRED + check_hostname
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pinned address while presenting and verifying the hostname."""

    def __init__(self, host: str, address: str, *, context: ssl.SSLContext, timeout: float):
        super().__init__(host, HTTPS_PORT, timeout=timeout, context=context)
        self._pinned_address = address
        self._tls = context

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_address, self.port), self.timeout)
        try:
            self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def fetch_once(request: FetchRequest, address: str) -> tuple[int, bytes]:
    """Perform one GET against one pinned address. Raises :class:`FetchFailure`."""
    deadline = time.monotonic() + request.request_timeout
    connection = _PinnedHTTPSConnection(
        request.host, address, context=_tls_context(), timeout=request.connect_timeout
    )
    try:
        connection.request(
            "GET",
            request.path,
            headers={
                "User-Agent": USER_AGENT,
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        status = response.status
        if 300 <= status < 400:
            raise FetchFailure(
                "MISCONFIGURED", f"redirect {status} refused", retryable=False, status=status
            )
        if status == 429 or status >= 500:
            raise FetchFailure(
                "TRANSIENT",
                f"http {status}",
                retryable=True,
                status=status,
                retry_after=_parse_retry_after(response.getheader("Retry-After")),
            )
        if status != 200:
            raise FetchFailure("MISCONFIGURED", f"http {status}", retryable=False, status=status)
        declared = response.getheader("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > request.max_bytes:
            raise FetchFailure(
                "INTEGRITY", "declared size exceeds cap", retryable=False, status=status
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise FetchFailure("TRANSIENT", "request deadline exceeded", retryable=True)
            chunk = response.read(_READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > request.max_bytes:
                raise FetchFailure("INTEGRITY", "body exceeds size cap", retryable=False)
            chunks.append(chunk)
        return status, b"".join(chunks)
    except FetchFailure:
        raise
    except (ssl.SSLError, ssl.CertificateError) as exc:
        # SSLError subclasses OSError, so it is caught first: a TLS failure is a
        # configuration problem (wrong host, intercepting proxy), never retried.
        raise FetchFailure("MISCONFIGURED", f"tls: {type(exc).__name__}", retryable=False) from exc
    except TimeoutError as exc:  # socket.timeout is an alias of TimeoutError
        raise FetchFailure("TRANSIENT", "timeout", retryable=True) from exc
    except (OSError, http.client.HTTPException) as exc:
        raise FetchFailure(
            "TRANSIENT", f"connection: {type(exc).__name__}", retryable=True
        ) from exc
    finally:
        connection.close()


def fetch_with_retry(
    request: FetchRequest,
    *,
    attempts: int = 3,
    fetch: Callable[[FetchRequest, str], tuple[int, bytes]] = fetch_once,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[], float] = random.random,
) -> FetchOutcome:
    """Fetch with bounded, typed retries. Never raises; the outcome says why."""
    outcome = FetchOutcome(body=None, failure=None)
    addresses = request.addresses
    for attempt in range(max(1, attempts)):
        address = addresses[attempt % len(addresses)]
        record = RequestRecord(
            host=request.host, path=request.path, address=address, started_at=_now_iso()
        )
        outcome.records.append(record)
        try:
            status, body = fetch(request, address)
        except FetchFailure as failure:
            record.finished_at = _now_iso()
            record.status = failure.status
            record.outcome_class = failure.remediation_class
            record.detail = failure.reason
            outcome.failure = failure
            if not failure.retryable or attempt == attempts - 1:
                return outcome
            backoff = _BACKOFF_SECONDS[min(attempt, len(_BACKOFF_SECONDS) - 1)]
            delay = backoff * (0.5 + jitter())
            if failure.retry_after is not None:
                delay = max(delay, min(failure.retry_after, _RETRY_AFTER_CEILING_SECONDS))
            sleep(delay)
            continue
        record.finished_at = _now_iso()
        record.status = status
        record.bytes_received = len(body)
        record.outcome_class = "OK"
        outcome.body = body
        outcome.failure = None
        return outcome
    return outcome
