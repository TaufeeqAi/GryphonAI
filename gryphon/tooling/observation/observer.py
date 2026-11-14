"""The unprivileged observer — the one component that reads bytes a target chose.

The gateway spawns this module inside an already-established egress namespace
with a scrubbed environment. It holds no database handle, no signing key and no
credential, and it is the only place in the system where a response body exists
at all. What leaves it is a single JSON document: typed facts, or a closed error
code with bounded numeric detail.

Three rules shape everything below.

**The bounds are ours.** Every cap a security property rests on is applied to
what *this process* reads, never to what the probe binary was asked to do. A
flag typo, a renamed option or a tool build that quietly raises its own ceiling
changes the argument vector; it does not change how many bytes this module will
hash, decode or scan. That is also why the tool's read cap and the observer's
wire bound are the same number, and why a body that arrives exactly at the bound
is recorded as truncated: when the two agree, the only honest reading of a body
that stops at the cap is that something was cut off.

**Nothing target-controlled is carried out.** No body, no body window, no header
value except a content type that fits the media-type grammar, no resolver answer
that is not an address, no exception text, no stderr. The secret guarantee does
not rest on recognizing every secret format — a finite recognizer cannot do that
— it rests on the bytes being destroyed with the process. The counts that cross
are evidence *about* a body that no longer exists. Nothing is marked up in band
either: the classifier counts shapes and never rewrites text, so a target that
serves a redaction marker produces no secret class.

**A refusal is a result.** Every failure this module can describe is one member
of :class:`~gryphon.tooling.observation.facts.ObserverErrorCode` plus numbers.
The process exits 0 whenever it produced a document; it exits non-zero only when
it would not start at all.

The measurement itself lives in :mod:`gryphon.tooling.observation.extractors`
and :mod:`gryphon.tooling.observation.secrets`. This module owns what surrounds
them: the request it will accept, the argument vector it will run, the bounds it
applies to what it reads, and the one document it emits.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final
from urllib.parse import urlsplit

try:  # POSIX only; absent on Windows, where these limits cannot be applied.
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

from gryphon.tooling.observation.envelope import (
    ENVELOPE_FORMAT_VERSION,
    EnvelopeError,
    RequestEnvelope,
)
from gryphon.tooling.observation.extractors import (
    EXTRACTOR_SET_DIGEST,
    MAX_DOTENV_LINES,
    MAX_SIGNAL_TOKENS,
    MAX_TOKEN_CHARS,
    body_digest,
    cname_chain,
    dotenv_grammar,
    header_presence,
    size_facts,
    status_class,
    token_presence,
)
from gryphon.tooling.observation.facts import (
    Completeness,
    DnsFacts,
    HttpFacts,
    ObservationFacts,
    ObserverErrorCode,
)
from gryphon.tooling.observation.secrets import classify
from gryphon.verification.constants import (
    DNS_DEADLINE_SECONDS,
    DNS_MAX_ANSWERS,
    DNS_MAX_CNAME_DEPTH,
    HTTP_DEADLINE_SECONDS,
    HTTP_MAX_DECODED_BYTES,
    HTTP_MAX_HEADER_BYTES,
    HTTP_MAX_WIRE_BYTES,
    ObservationKind,
    TruncationReason,
)

#: Request wire-format version. The gateway writes the document; a version this
#: image does not know is refused rather than interpreted, because a request it
#: cannot read in full is one whose bounds it cannot promise to apply.
REQUEST_FORMAT_VERSION: Final[str] = "1"

_IS_POSIX: Final[bool] = os.name == "posix"

# -- limits this module applies to itself -------------------------------------
_MAX_REQUEST_BYTES: Final[int] = 64 * 1024
_MAX_RESOLVERS: Final[int] = 8
_MAX_OUTPUT_LINES: Final[int] = 64
_MAX_STDOUT_BYTES: Final[int] = 8 * 1024 * 1024
#: stderr is read only so that a full pipe cannot deadlock the child, and only
#: its size is ever reported: its text is written by a tool that was parsing a
#: target's bytes.
_STDERR_CAP_BYTES: Final[int] = 8 * 1024
_MEMORY_LIMIT_BYTES: Final[int] = 512 * 1024 * 1024
_CPU_SECONDS_SLACK: Final[int] = 2
_KILL_GRACE_SECONDS: Final[float] = 5.0
#: The tool's own timeout is set this far inside our wall clock, so an orderly
#: tool-side timeout still yields a parsable document and the hard kill stays
#: ours.
_TOOL_DEADLINE_MARGIN_SECONDS: Final[float] = 1.0

#: Record types this image can answer for. An envelope asking for more would
#: promise facts the fixed fact vocabulary cannot carry.
_SUPPORTED_RECORD_TYPES: Final[frozenset[str]] = frozenset({"A", "CNAME"})

#: dnsx filters its output by response code. The accepted set is stated rather
#: than inherited: a default that kept only NOERROR would silently delete the
#: positive case for a dangling record.
_ACCEPTED_RCODES: Final[tuple[str, ...]] = ("noerror", "nxdomain", "servfail", "refused")

_RCODE_RE: Final[re.Pattern[str]] = re.compile(r"[A-Z]{3,16}")
_CONTENT_TYPE_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+*-]{0,63}"
)

#: Environment variable name fragments that must never be visible to the process
#: that parses hostile bytes. A scrubbing mistake in the parent becomes a refusal
#: here rather than a credential sitting inside the sandbox.
_FORBIDDEN_ENV_FRAGMENTS: Final[tuple[str, ...]] = (
    "GRYPHON_",
    "DATABASE_URL",
    "DSN",
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "SIGNING_KEY",
    "AWS_",
)


class RequestInvalid(Exception):
    """The request document is not one this image can execute exactly.

    Raised, not returned: a request whose bounds, envelope or extractor set this
    observer cannot honour must stop the process before any traffic, because the
    alternative is a measurement whose caps nobody can state afterwards.
    """


class SandboxNotSealed(Exception):
    """The process was started with an environment it will not parse bytes in."""


# =============================================================================
# The request document
# =============================================================================


@dataclass(frozen=True, slots=True)
class Bounds:
    """The caps this process applies, whatever the probe binary was told."""

    wire_bytes: int
    decoded_bytes: int
    header_bytes: int
    deadline_seconds: float
    answer_count: int
    cname_depth: int

    @classmethod
    def from_payload(cls, raw: object, kind: ObservationKind) -> Bounds:
        """Validate a bounds mapping, which may only *narrow* the code ceilings.

        A request asking for a wider bound than the layer's own constant is a
        malformed request, not a negotiation: widening is exactly the change a
        mistake or an attacker would want, and a silent clamp would hide the
        attempt from the operator who has to explain the measurement later.
        """
        if not isinstance(raw, dict):
            raise RequestInvalid("bounds must be an object")
        ceilings = _BOUND_CEILINGS[kind]
        unknown = sorted(set(raw) - set(ceilings))
        if unknown:
            raise RequestInvalid(f"bounds carries unknown members: {', '.join(unknown)}")
        missing = sorted(set(ceilings) - set(raw))
        if missing:
            raise RequestInvalid(f"bounds is missing: {', '.join(missing)}")
        values: dict[str, float] = {}
        for name, ceiling in ceilings.items():
            value = raw[name]
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise RequestInvalid(f"bound {name} must be a number")
            if value <= 0:
                raise RequestInvalid(f"bound {name} must be positive")
            if value > ceiling:
                raise RequestInvalid(f"bound {name} may only narrow the observer's own ceiling")
            values[name] = float(value)
        return cls(
            wire_bytes=int(values["wire_bytes"]),
            decoded_bytes=int(values["decoded_bytes"]),
            header_bytes=int(values["header_bytes"]),
            deadline_seconds=values["deadline_seconds"],
            answer_count=int(values["answer_count"]),
            cname_depth=int(values["cname_depth"]),
        )


_BOUND_CEILINGS: Final[dict[ObservationKind, dict[str, float]]] = {
    ObservationKind.HTTP_RESPONSE_SUMMARY: {
        "wire_bytes": HTTP_MAX_WIRE_BYTES,
        "decoded_bytes": HTTP_MAX_DECODED_BYTES,
        "header_bytes": HTTP_MAX_HEADER_BYTES,
        "deadline_seconds": HTTP_DEADLINE_SECONDS,
        "answer_count": DNS_MAX_ANSWERS,
        "cname_depth": DNS_MAX_CNAME_DEPTH,
    },
    ObservationKind.DNS_ANSWER: {
        "wire_bytes": HTTP_MAX_WIRE_BYTES,
        "decoded_bytes": HTTP_MAX_DECODED_BYTES,
        "header_bytes": HTTP_MAX_HEADER_BYTES,
        "deadline_seconds": DNS_DEADLINE_SECONDS,
        "answer_count": DNS_MAX_ANSWERS,
        "cname_depth": DNS_MAX_CNAME_DEPTH,
    },
}

_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "request_format_version",
        "kind",
        "binary_path",
        "envelope",
        "bounds",
        "signal_tokens",
        "resolvers",
    }
)
_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "envelope_format_version",
        "kind",
        "method",
        "scheme",
        "host",
        "port",
        "path",
        "record_types",
        "descriptor_version",
        "extractor_set_digest",
        "resolver_set_digest",
    }
)


@dataclass(frozen=True, slots=True)
class ObservationRequest:
    """One measurement, described exactly once by the gateway."""

    kind: ObservationKind
    binary_path: str
    envelope: RequestEnvelope
    bounds: Bounds
    #: Signals a verifier pinned. Their spelling is operator-controlled, so
    #: reporting which ones appeared carries nothing the target wrote.
    signal_tokens: tuple[str, ...]
    #: Pinned resolver addresses for mediated kinds; empty otherwise.
    resolvers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ObserverFailure:
    """A refusal, carried as a result: a closed code plus numbers."""

    error_code: str
    detail_numeric: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.error_code not in ObserverErrorCode.ALL:
            raise ValueError(f"{self.error_code!r} is not an observer error code")
        for key, value in self.detail_numeric.items():
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError(f"detail {key!r} is not numeric; detail is numbers only")


#: What one measurement can produce. There is no third answer.
ObservationOutcome = ObservationFacts | ObserverFailure


@dataclass(frozen=True, slots=True)
class CapturedOutput:
    """What the probe binary produced, already bounded by the readers.

    ``stderr_bytes`` is a count on purpose: the text was written by a tool that
    was talking to the target, so it is exactly the kind of string that must not
    cross.
    """

    stdout: bytes
    stderr_bytes: int
    exit_code: int | None
    timed_out: bool
    stdout_truncated: bool
    elapsed_seconds: float


def _envelope_from_canonical(raw: object) -> RequestEnvelope:
    """Rebuild the envelope from its canonical mapping and re-validate it here.

    The gateway's copy is not taken on trust: the envelope decides the method,
    the scheme and the URL that go on the wire, so this process reconstructs it
    through the same constructor the caller used and refuses anything that
    constructor will not build.
    """
    if not isinstance(raw, dict):
        raise RequestInvalid("envelope must be an object")
    if raw.get("envelope_format_version") != ENVELOPE_FORMAT_VERSION:
        raise RequestInvalid("envelope format version is not the one this image reads")
    unknown = sorted(set(raw) - _ENVELOPE_KEYS)
    if unknown:
        raise RequestInvalid(f"envelope carries unknown members: {', '.join(unknown)}")
    try:
        envelope = RequestEnvelope(
            kind=ObservationKind(str(raw["kind"])),
            method=str(raw["method"]),
            host=str(raw["host"]),
            port=int(raw["port"]),
            scheme=str(raw["scheme"]),
            path=None if raw.get("path") is None else str(raw["path"]),
            record_types=tuple(str(item) for item in raw.get("record_types") or ()),
            descriptor_version=str(raw["descriptor_version"]),
            extractor_set_digest=str(raw["extractor_set_digest"]),
            resolver_set_digest=str(raw.get("resolver_set_digest") or ""),
        )
    except (EnvelopeError, KeyError, TypeError, ValueError) as exc:
        raise RequestInvalid(f"envelope is not representable: {exc}") from exc
    if envelope.extractor_set_digest != EXTRACTOR_SET_DIGEST:
        raise RequestInvalid("envelope pins an extractor set this observer image does not run")
    return envelope


def _signal_tokens_from(raw: object) -> tuple[str, ...]:
    """Validate the pinned signal list against the extractor's own ceilings.

    The refusal and the extractor share one set of bounds, so a token the
    extractor would silently skip is rejected here instead: a pass must never
    believe it searched for a signal that was never looked for.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_SIGNAL_TOKENS:
        raise RequestInvalid(f"signal_tokens must be a list of at most {MAX_SIGNAL_TOKENS}")
    tokens: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or len(item) > MAX_TOKEN_CHARS:
            raise RequestInvalid("each signal token must be a bounded, non-empty string")
        tokens.append(item)
    return tuple(tokens)


def _resolvers_from(raw: object, kind: ObservationKind) -> tuple[str, ...]:
    """Validate the pinned resolver list.

    Every entry must be a literal address. A resolver named by hostname would
    have to be resolved by *something* — the ambient system resolver, which is
    the surface this layer exists to remove — and the answer would no longer be
    the one the pass pinned and recorded a digest for.
    """
    values = () if raw is None else raw
    if not isinstance(values, list | tuple):
        raise RequestInvalid("resolvers must be a list")
    if kind is not ObservationKind.DNS_ANSWER:
        if values:
            raise RequestInvalid("resolvers belong to resolver-mediated kinds only")
        return ()
    if not values or len(values) > _MAX_RESOLVERS:
        raise RequestInvalid(f"a DNS observation needs 1 to {_MAX_RESOLVERS} pinned resolvers")
    resolvers: list[str] = []
    for item in values:
        try:
            resolvers.append(str(ipaddress.ip_address(str(item))))
        except ValueError as exc:
            raise RequestInvalid("each resolver must be a literal IP address") from exc
    return tuple(resolvers)


def _is_absolute_path(path: str) -> bool:
    """Whether the manifest named a fully qualified path, in either flavour.

    A relative path would be resolved against ``PATH`` or the working directory,
    which is the ambient surface a pinned manifest path exists to replace. Both
    flavours are accepted because the deployment that wrote the request decides
    the flavour, and ``os.path.isabs`` has answered differently for ``/usr/bin``
    across interpreter versions on Windows — a validator must not depend on
    which interpreter happens to be reading the document.
    """
    if not path:
        return False
    return PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute()


def parse_request(raw: object) -> ObservationRequest:
    """Validate a request document strictly. Anything unexpected is refused."""
    if not isinstance(raw, dict):
        raise RequestInvalid("request must be a JSON object")
    if raw.get("request_format_version") != REQUEST_FORMAT_VERSION:
        raise RequestInvalid("request format version is not the one this image reads")
    unknown = sorted(set(raw) - _REQUEST_KEYS)
    if unknown:
        raise RequestInvalid(f"request carries unknown members: {', '.join(unknown)}")
    try:
        kind = ObservationKind(str(raw["kind"]))
    except (KeyError, ValueError) as exc:
        raise RequestInvalid("kind is not an observation kind") from exc

    envelope = _envelope_from_canonical(raw.get("envelope"))
    if envelope.kind is not kind:
        raise RequestInvalid("kind and envelope.kind disagree about what is being observed")
    if kind is ObservationKind.DNS_ANSWER and not _SUPPORTED_RECORD_TYPES.issuperset(
        envelope.record_types
    ):
        raise RequestInvalid("this image answers for A and CNAME record types only")

    binary_path = str(raw.get("binary_path") or "")
    if not _is_absolute_path(binary_path):
        raise RequestInvalid("binary_path must be an absolute path")

    return ObservationRequest(
        kind=kind,
        binary_path=binary_path,
        envelope=envelope,
        bounds=Bounds.from_payload(raw.get("bounds"), kind),
        signal_tokens=_signal_tokens_from(raw.get("signal_tokens")),
        resolvers=_resolvers_from(raw.get("resolvers"), kind),
    )


def load_request(path: Path) -> ObservationRequest:
    """Read and validate the request document the gateway wrote."""
    raw = path.read_bytes()
    if len(raw) > _MAX_REQUEST_BYTES:
        raise RequestInvalid("request document is larger than this image will read")
    try:
        return parse_request(json.loads(raw))
    except json.JSONDecodeError as exc:
        raise RequestInvalid("request document is not valid JSON") from exc


def assert_environment_scrubbed(environ: Mapping[str, str] | None = None) -> None:
    """Refuse to start if a credential-shaped variable survived into this process.

    The sandbox's guarantee is that the code parsing a target's bytes cannot
    reach a secret even by mistake. That guarantee is established by the parent,
    so it is checked here: a scrubbing bug should be a loud refusal with no
    traffic, not a quiet weakening of the one boundary this layer rests on.
    """
    values = os.environ if environ is None else environ
    offenders = sorted(
        name
        for name in values
        if any(fragment in name.upper() for fragment in _FORBIDDEN_ENV_FRAGMENTS)
    )
    if offenders:
        raise SandboxNotSealed("the observer environment was not scrubbed: " + ", ".join(offenders))


# =============================================================================
# Argument vectors
# =============================================================================


def _tool_deadline_seconds(bounds: Bounds) -> int:
    return max(1, int(bounds.deadline_seconds - _TOOL_DEADLINE_MARGIN_SECONDS))


def build_http_argv(request: ObservationRequest, *, empty_config: str) -> list[str]:
    """Build httpx's argument vector explicitly. Every flag is here for a reason.

    * ``-u`` / ``-x`` — one URL and one method, both taken from the envelope, so
      the request that runs is the request the verdict will cite.
    * ``-json -silent -no-color`` — one machine-readable document on stdout and
      nothing else; banner text would make that document unparseable.
    * ``-nfs`` — no scheme fallback. An ``https`` probe answered over ``http`` is
      a different observation: the envelope, and therefore the identity and the
      verdict, claim ``https``.
    * ``-irr`` — include the response, so there is a body to measure at all.
    * ``-rstr`` — the tool-side read cap. We apply the same bound ourselves; the
      flag only saves the tool from reading bytes we would discard.
    * ``-no-decode`` — we control decoding, so a compressed body cannot expand
      past our bound before anyone looks at it.
    * ``-timeout`` — an orderly tool-side timeout inside our wall clock.
    * ``-config`` — httpx otherwise reads ``$HOME/.config/httpx/config.yaml``,
      which would let ambient configuration turn redirects back on. It is
      pointed at a known-empty file; the scrubbed environment closes the same
      surface a second way.

    Deliberately absent: ``-fr``, ``-maxr`` and ``-fhr`` (a redirect is recorded
    as a class and never followed, because following one reaches a destination
    nobody attested), ``-H`` (no headers of ours on the wire), ``-proxy`` and
    ``-pa`` (the egress namespace is the only path out), and ``-tech-detect``
    (inference about the target is not an observation).
    """
    bounds = request.bounds
    return [
        request.binary_path,
        "-u",
        request.envelope.url,
        "-x",
        request.envelope.method,
        "-json",
        "-silent",
        "-no-color",
        "-nfs",
        "-irr",
        "-rstr",
        str(bounds.wire_bytes),
        "-no-decode",
        "-timeout",
        str(_tool_deadline_seconds(bounds)),
        "-config",
        empty_config,
    ]


def _record_type_flags(record_types: tuple[str, ...]) -> list[str]:
    """The query flags for exactly the record types the envelope pinned.

    Deterministic order, de-duplicated. ``_SUPPORTED_RECORD_TYPES`` already
    guarantees the set is {A, CNAME}, and ``parse_request`` refuses anything
    else, so an unrecognized type cannot reach here.
    """
    flags: list[str] = []
    for rtype in sorted(set(record_types)):
        flag = "-a" if rtype == "A" else "-cname"
        if flag not in flags:
            flags.append(flag)
    return flags


def build_dns_argv(request: ObservationRequest, *, names_file: str) -> list[str]:
    """Build dnsx's argument vector explicitly.

    * ``-l`` — the one name to query, in a file. The name does not go on stdin
      because the child's stdin stays closed, and not in ``-d``, which means a
      bruteforce base rather than a single query.
    * ``-r`` — the pass's pinned resolvers. The tool's defaults (Google,
      Cloudflare, Quad9) are never relied upon: unpinned resolvers send the
      client's engagement host names to three third parties, and a filtering
      resolver's NXDOMAIN would become takeover "evidence".
    * ``-cname -a -resp`` — the two record types this image answers for, with
      the records included in the output.
    * ``-rcode`` — the accepted response codes, stated rather than inherited, so
      NXDOMAIN (the positive case for a dangling record) is never filtered away
      as though it were a failure.
    * ``-retry 1`` — one retry: enough for a dropped UDP datagram, not enough to
      turn one observation into traffic the budget did not plan for.
    """
    return [
        request.binary_path,
        "-l",
        names_file,
        "-json",
        "-silent",
        "-no-color",
        "-r",
        ",".join(request.resolvers),
        # Record types come from the envelope, not from a fixed pair. The
        # envelope's whole claim is that its digest describes the contact
        # exactly, so putting an A query on the wire for an envelope that pinned
        # only CNAME would mean the recorded identity does not describe what
        # was asked. Order is fixed for determinism.
        *_record_type_flags(request.envelope.record_types),
        "-resp",
        "-rcode",
        ",".join(_ACCEPTED_RCODES),
        "-retry",
        "1",
    ]


def stdout_cap_for(bounds: Bounds) -> int:
    """How many bytes of stdout the reader will keep.

    This is not the byte bound. JSON escaping can turn one byte into six
    characters, so capping the pipe at the wire bound would make a merely large
    response unparseable and lose the facts we did measure. The bounds that
    carry meaning are applied to the measured body, below.
    """
    return min(_MAX_STDOUT_BYTES, 65_536 + bounds.header_bytes + bounds.wire_bytes * 6)


def probe_environment(sandbox: Path) -> dict[str, str]:
    """The child's whole environment. Nothing of ours is inherited.

    ``HOME`` and ``TMPDIR`` point into a directory created for this one
    measurement and deleted after it, so a tool that looks for user
    configuration finds an empty directory rather than the runtime user's.
    """
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    env.update({"HOME": str(sandbox), "TMPDIR": str(sandbox), "LC_ALL": "C.UTF-8"})
    return env


# =============================================================================
# Subprocess discipline
# =============================================================================


async def _read_capped(stream: asyncio.StreamReader | None, cap: int) -> tuple[bytes, bool]:
    """Drain a pipe, keeping at most ``cap`` bytes.

    Draining continues past the cap on purpose: a reader that stopped would
    leave the child blocked on a full pipe, which is a deadlock dressed up as a
    timeout.
    """
    if stream is None:
        return b"", False
    buf = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            break
        if len(buf) < cap:
            buf.extend(chunk[: cap - len(buf)])
            if len(buf) >= cap:
                truncated = True
        else:
            truncated = True
    return bytes(buf), truncated


def _preexec(memory_limit_bytes: int, cpu_seconds: int) -> None:  # pragma: no cover - POSIX child
    """Child-side hardening, applied between fork and exec.

    * New session and process group, so the deadline kills the whole tree rather
      than the tool alone and leaves its helpers running.
    * Address-space and CPU ceilings, so neither a decompression bomb nor a
      spinning parser can outgrow or outlive the measurement even if our own
      wall clock were somehow not reached.
    * No core dumps: a core of a probe may contain the body this layer exists to
      destroy.
    """
    os.setsid()
    if resource is None:
        return
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
    except (ValueError, OSError):
        # A limit we cannot set must not silently become "no limit": a failed
        # exec surfaces as a spawn failure, which is a recorded refusal.
        os._exit(126)


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    try:
        if _IS_POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover - Windows path
            proc.kill()
    except (OSError, ProcessLookupError, PermissionError):
        pass


async def run_probe(
    *,
    argv: list[str],
    deadline_seconds: float,
    stdout_cap: int,
    environ: dict[str, str],
    cwd: str,
) -> CapturedOutput | ObserverFailure:
    """Run the pinned binary under our own wall clock. Never a shell."""
    popen_kwargs: dict[str, Any] = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
        "stdin": asyncio.subprocess.DEVNULL,
        "env": environ,
        "cwd": cwd,
    }
    if _IS_POSIX:
        cpu_seconds = int(deadline_seconds) + _CPU_SECONDS_SLACK
        popen_kwargs["preexec_fn"] = partial(_preexec, _MEMORY_LIMIT_BYTES, cpu_seconds)
    else:  # pragma: no cover - Windows path
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(*argv, **popen_kwargs)
    except (OSError, ValueError):
        return ObserverFailure(ObserverErrorCode.SPAWN_FAILED, {})

    stdout_task = asyncio.ensure_future(_read_capped(proc.stdout, stdout_cap))
    stderr_task = asyncio.ensure_future(_read_capped(proc.stderr, _STDERR_CAP_BYTES))
    try:
        await asyncio.wait_for(proc.wait(), timeout=deadline_seconds)
    except TimeoutError:
        _kill_group(proc)
        try:
            await asyncio.wait_for(proc.wait(), timeout=_KILL_GRACE_SECONDS)
        except TimeoutError:  # pragma: no cover - the group is already signalled
            pass
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        return CapturedOutput(
            stdout=b"",
            stderr_bytes=0,
            exit_code=None,
            timed_out=True,
            stdout_truncated=False,
            elapsed_seconds=time.monotonic() - started,
        )

    stdout, truncated = await stdout_task
    stderr, _ = await stderr_task
    return CapturedOutput(
        stdout=stdout,
        stderr_bytes=len(stderr),
        exit_code=proc.returncode,
        timed_out=False,
        stdout_truncated=truncated,
        elapsed_seconds=time.monotonic() - started,
    )


# =============================================================================
# HTTP observation
# =============================================================================


def classify_location(location: str | None, envelope: RequestEnvelope) -> str:
    """Classify a ``Location`` header against the envelope host.

    The class is recorded and the redirect is never followed. A relative target
    stays on this host; anything that does not parse is treated as another host,
    because the safe reading of a destination we cannot parse is that we do not
    know where it points.
    """
    if not location:
        return "none"
    try:
        parts = urlsplit(location.strip())
        if not parts.netloc:
            return "same_host"
        host = (parts.hostname or "").strip().lower()
    except ValueError:
        return "other_host"
    return "same_host" if host == envelope.host else "other_host"


def _parse_raw_headers(block: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in block.replace("\r\n", "\n").split("\n"):
        if not line or line.startswith("HTTP/"):
            continue
        name, separator, value = line.partition(":")
        if not separator:
            continue
        # First occurrence wins: a second Location is a difference of opinion the
        # observer records as the first answer rather than resolving.
        headers.setdefault(name.strip().lower(), value.strip())
    return headers


def _headers_from(line: dict[str, Any]) -> tuple[dict[str, str], int]:
    """Headers as names and values, plus the size of the block they came in.

    The raw block is preferred because it is what the header bound is about: a
    parsed map has already lost the duplicates and the whitespace that made an
    oversized block oversized.
    """
    raw = line.get("raw_header")
    if isinstance(raw, str) and raw:
        return _parse_raw_headers(raw), len(raw.encode("utf-8", "surrogateescape"))
    mapping = line.get("header")
    if isinstance(mapping, dict):
        headers = {
            str(key).replace("_", "-").strip().lower(): str(value)
            for key, value in mapping.items()
            if isinstance(value, str | int)
        }
        # Four bytes per header for ": " and the line break, so the block bound
        # is still measured when only the parsed map is available.
        size = sum(len(name) + len(value) + 4 for name, value in headers.items())
        return headers, size
    return {}, 0


def _normalized_content_type(raw: str | None) -> str | None:
    """The media type without parameters, or nothing.

    A content type is the one header *value* that crosses, so only a value that
    fits the media-type grammar is carried: a header the target filled with prose
    becomes ``None`` rather than a string of its bytes.
    """
    if not raw:
        return None
    value = raw.split(";", 1)[0].strip().lower()
    return value if _CONTENT_TYPE_RE.fullmatch(value) else None


def _declared_length(headers: dict[str, str]) -> int | None:
    value = headers.get("content-length", "").strip()
    return int(value) if value.isdigit() else None


def _decode_body(wire: bytes, encoding: str, cap: int) -> tuple[bytes | None, TruncationReason]:
    """Decode a body under our own ceiling.

    Decoding happens here, not in the tool, so a compressed body cannot expand
    past the decoded bound before anyone looks at it. ``None`` means no encoding
    was applied and the wire bytes are the body. An encoding this image cannot
    bound is a decode failure — an incomplete observation, never a guess at what
    the bytes meant.
    """
    name = encoding.strip().lower()
    if name in ("", "identity"):
        return None, TruncationReason.NONE
    if name == "gzip":
        wbits = 16 + zlib.MAX_WBITS
    elif name == "deflate":
        wbits = zlib.MAX_WBITS
    else:
        return b"", TruncationReason.DECODE_FAILED
    # A raw deflate stream (no zlib header) is common enough in the wild that
    # refusing it would report a decode failure for a body we can in fact bound.
    for candidate in (wbits, -zlib.MAX_WBITS):
        try:
            decompressor = zlib.decompressobj(candidate)
            decoded = decompressor.decompress(wire, cap)
        except zlib.error:
            continue
        # Completeness is decided on the decompressor's own state, not on
        # whether input happens to be left over. When the output reaches the cap
        # and the decompressor has consumed all remaining input,
        # ``unconsumed_tail`` is empty while the stream is NOT finished — so
        # trusting the tail alone reports a body we cut at the bound as whole,
        # and a whole body is exactly what may then prove absence. ``eof`` is
        # the only answer to "did the stream end".
        if decompressor.unconsumed_tail or not decompressor.eof:
            return decoded, TruncationReason.DECODED_BYTES
        if len(decoded) >= cap:
            # Reaching the cap exactly is indistinguishable from being cut at
            # it, so it is reported as cut. Over-reporting truncation costs a
            # verdict of INCONCLUSIVE; under-reporting it buys a false negative.
            return decoded, TruncationReason.DECODED_BYTES
        return decoded, TruncationReason.NONE
    return b"", TruncationReason.DECODE_FAILED


def _transport_failure(line: dict[str, Any]) -> ObserverFailure | None:
    """Map a tool-reported transport error to a closed code.

    The error string is read to choose the code and then dropped: it is written
    by a tool that was talking to the target, so its length is the only part of
    it that may cross.
    """
    error = line.get("error")
    text = error.strip() if isinstance(error, str) else ""
    if not text and line.get("failed") is not True:
        return None
    lowered = text.lower()
    tls = any(mark in lowered for mark in ("tls", "x509", "certificate", "handshake"))
    code = ObserverErrorCode.TLS_FAILED if tls else ObserverErrorCode.CONNECT_FAILED
    return ObserverFailure(code, {"error_chars": len(text)})


def _http_observation(line: dict[str, Any], request: ObservationRequest) -> ObservationOutcome:
    bounds = request.bounds
    failure = _transport_failure(line)
    if failure is not None:
        return failure

    status = line.get("status_code")
    if isinstance(status, bool) or not isinstance(status, int) or status_class(status) == 0:
        return ObserverFailure(ObserverErrorCode.OUTPUT_UNPARSEABLE, {"status_fields": 0})

    headers, header_bytes = _headers_from(line)
    header_truncated = header_bytes > bounds.header_bytes

    body = line.get("body")
    wire = body.encode("utf-8", "surrogateescape") if isinstance(body, str) else b""
    # The tool's read cap and ours are the same number, so a body that arrives
    # exactly at the bound is treated as cut: a flag change cannot make a
    # truncated body read as whole.
    wire_truncated = len(wire) >= bounds.wire_bytes
    wire = wire[: bounds.wire_bytes]

    declared = _declared_length(headers)
    # A HEAD response declares the length of a body it does not send, so the
    # short-read check does not apply to it.
    short_read = request.envelope.method != "HEAD" and declared is not None and declared > len(wire)

    decoded, decode_reason = _decode_body(
        wire, headers.get("content-encoding", ""), bounds.decoded_bytes
    )
    text = (wire if decoded is None else decoded).decode("utf-8", errors="replace")

    if header_truncated:
        reason = TruncationReason.HEADER_BYTES
    elif wire_truncated or short_read:
        reason = TruncationReason.WIRE_BYTES
    else:
        reason = decode_reason
    read_to_the_end = not (header_truncated or wire_truncated or short_read)
    bytes_read, decoded_bytes = size_facts(wire, decoded)

    completeness = Completeness(
        # The stream was read to its end: no transport bound stopped it.
        transport_complete=read_to_the_end,
        # And the body could be measured as the server meant it. A decode failure
        # leaves the transport complete and the body not.
        body_complete=read_to_the_end and decode_reason is TruncationReason.NONE,
        truncation_reason=reason,
        bytes_read=bytes_read,
        decoded_bytes=decoded_bytes,
    )
    facts = HttpFacts(
        status_code=status,
        status_class=status_class(status),
        content_type=_normalized_content_type(
            headers.get("content-type") or _string_field(line, "content_type")
        ),
        content_length_header=declared,
        body_sha256=body_digest(wire),
        header_names=header_presence(headers),
        location_class=classify_location(headers.get("location"), request.envelope),
        secret_class_counts=classify(text),
        tokens_present=token_presence(text, headers, request.signal_tokens),
        # The byte bound already limits the body, so the extractor's own line
        # ceiling is the only one there is to apply.
        dotenv=dotenv_grammar(text, max_lines=MAX_DOTENV_LINES),
    )
    return ObservationFacts(
        kind=ObservationKind.HTTP_RESPONSE_SUMMARY, completeness=completeness, http=facts
    )


def _string_field(line: dict[str, Any], name: str) -> str | None:
    value = line.get(name)
    return value if isinstance(value, str) else None


# =============================================================================
# DNS observation
# =============================================================================


def _addresses_from(raw: object, cap: int) -> tuple[tuple[str, ...], bool]:
    """Keep only answers that parse as addresses, up to the answer bound.

    A resolver answer is target-influenced: the zone is served by whoever
    controls it. Re-rendering each record through :mod:`ipaddress` means an
    answer cannot carry an arbitrary string out of the sandbox in place of an
    address.
    """
    if not isinstance(raw, list):
        return (), False
    addresses: list[str] = []
    for item in raw:
        try:
            addresses.append(str(ipaddress.ip_address(str(item))))
        except ValueError:
            continue
    return tuple(addresses[:cap]), len(addresses) > cap


def _dns_observation(line: dict[str, Any], request: ObservationRequest) -> ObservationOutcome:
    bounds = request.bounds
    rcode = str(line.get("status_code") or line.get("rcode") or "").strip().upper()
    if not _RCODE_RE.fullmatch(rcode):
        return ObserverFailure(ObserverErrorCode.OUTPUT_UNPARSEABLE, {"rcode_chars": len(rcode)})

    raw_chain = line.get("cname")
    records = raw_chain if isinstance(raw_chain, list) else []
    chain = cname_chain(
        [item for item in records if isinstance(item, str)], max_depth=bounds.cname_depth
    )
    addresses, answers_truncated = _addresses_from(line.get("a"), bounds.answer_count)
    if len(chain) >= bounds.cname_depth:
        # A chain filled to the bound may continue past what was recorded.
        reason = TruncationReason.CNAME_DEPTH
    elif answers_truncated:
        reason = TruncationReason.ANSWER_COUNT
    else:
        reason = TruncationReason.NONE

    # NXDOMAIN is a complete observation: the resolver answered, and the answer
    # is that the name does not exist. Byte counts stay zero because they
    # describe a body, and a resolver answer has none.
    completeness = Completeness(
        transport_complete=reason is TruncationReason.NONE,
        body_complete=reason is TruncationReason.NONE,
        truncation_reason=reason,
        bytes_read=0,
        decoded_bytes=0,
    )
    facts = DnsFacts(
        rcode=rcode,
        cname_chain=chain,
        a_records=addresses,
        resolver_set_digest=request.envelope.resolver_set_digest,
        authoritative=bool(line.get("authoritative") or line.get("aa")),
    )
    return ObservationFacts(kind=ObservationKind.DNS_ANSWER, completeness=completeness, dns=facts)


# =============================================================================
# The measurement
# =============================================================================


def _first_json_object(stdout: bytes) -> dict[str, Any] | None:
    text = stdout.decode("utf-8", "surrogateescape")
    for index, raw in enumerate(text.splitlines()):
        if index >= _MAX_OUTPUT_LINES:
            break
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def observe_from_output(
    request: ObservationRequest, captured: CapturedOutput
) -> ObservationOutcome:
    """Produce facts from already-captured tool output. Spawns nothing.

    The whole measurement lives here so the bounds, the extractors and the error
    vocabulary can be exercised against recorded tool output — including output
    no live target would reliably produce — without a binary.
    """
    if captured.timed_out:
        return ObserverFailure(
            ObserverErrorCode.DEADLINE, {"elapsed_seconds": round(captured.elapsed_seconds, 3)}
        )

    detail: dict[str, float] = {"stdout_bytes": len(captured.stdout)}
    if captured.exit_code is not None:
        detail["exit_code"] = captured.exit_code
    if captured.stderr_bytes:
        detail["stderr_bytes"] = captured.stderr_bytes

    line = _first_json_object(captured.stdout)
    if line is None:
        if captured.stdout.strip():
            return ObserverFailure(ObserverErrorCode.OUTPUT_UNPARSEABLE, detail)
        if captured.exit_code not in (0, None):
            return ObserverFailure(ObserverErrorCode.TOOL_NONZERO, detail)
        # httpx prints nothing for a host it could not reach. The observer
        # reports the silence it actually saw rather than inventing a connect
        # failure it cannot distinguish from an empty answer.
        return ObserverFailure(ObserverErrorCode.OUTPUT_EMPTY, detail)

    if request.kind is ObservationKind.HTTP_RESPONSE_SUMMARY:
        return _http_observation(line, request)
    return _dns_observation(line, request)


def _prepare(request: ObservationRequest) -> tuple[Path | None, list[str]]:
    """Check the pinned binary and lay out the sandbox directory.

    Returns ``(None, [])`` when the binary is not there, which is a recorded
    refusal rather than a crash: a manifest that points at a missing file is an
    operator's problem, and the pass needs to be told which one it was.
    """
    if not Path(request.binary_path).is_file():
        return None, []
    sandbox = Path(tempfile.mkdtemp(prefix="gryphon-observer-"))
    if request.kind is ObservationKind.HTTP_RESPONSE_SUMMARY:
        config = sandbox / "httpx-empty.yaml"
        config.write_bytes(b"")
        return sandbox, build_http_argv(request, empty_config=str(config))
    names = sandbox / "name.txt"
    names.write_text(f"{request.envelope.host}\n", encoding="utf-8")
    return sandbox, build_dns_argv(request, names_file=str(names))


async def observe(request: ObservationRequest) -> ObservationOutcome:
    """Run one measurement and return its facts or its refusal.

    The filesystem work happens off the loop thread, which is the same thread
    that will be draining the child's pipes a moment later: a stall there is how
    a full pipe becomes a deadlock instead of a deadline.
    """
    try:
        sandbox, argv = await asyncio.to_thread(_prepare, request)
    except OSError:
        return ObserverFailure(ObserverErrorCode.SPAWN_FAILED, {})
    if sandbox is None:
        return ObserverFailure(ObserverErrorCode.BINARY_MISSING, {})
    try:
        captured = await run_probe(
            argv=argv,
            deadline_seconds=request.bounds.deadline_seconds,
            stdout_cap=stdout_cap_for(request.bounds),
            environ=probe_environment(sandbox),
            cwd=str(sandbox),
        )
    finally:
        await asyncio.to_thread(shutil.rmtree, sandbox, ignore_errors=True)
    if isinstance(captured, ObserverFailure):
        return captured
    return observe_from_output(request, captured)


def document_for(outcome: ObservationOutcome) -> dict[str, Any]:
    """The one document this process emits. There is no third shape."""
    if isinstance(outcome, ObserverFailure):
        return {
            "ok": False,
            "error_code": outcome.error_code,
            "detail_numeric": dict(outcome.detail_numeric),
        }
    return {"ok": True, "facts": outcome.as_payload()}
