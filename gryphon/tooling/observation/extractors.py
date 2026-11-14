"""The fixed extractor set: named functions, versioned with the observer image.

These are the only measurements taken over raw target bytes, and they run
inside the unprivileged observer. Each one turns bytes into a typed fact and
nothing else: a count, a class, a digest, a list of names the operator chose.

**Why there is no extractor language.** The obvious generalization — a grammar,
an interpreter, a version policy and a review process for operator-supplied
extraction programs — would buy generality that nothing has asked for. The
verifiers this set serves are all of one shape: *is this response structurally
the artifact we think it is, and does the same structure appear on a control?*
Eight predicates of one shape do not need a language; they need eight reviewed
functions. The language would also put a parser and an evaluator for
operator-supplied programs inside the one process whose entire job is to have no
hostile-input surface beyond the bytes it is already holding, and it would make
"what ran" a property of a document someone can edit rather than of the image
that was deployed. Adding an extractor here is a catalog change with a code
review — which is the governance the language would have had to reinvent.

The registry at the bottom deliberately holds functions with *different*
signatures. A uniform ``(bytes) -> facts`` signature would be the first step
toward an interpreter; keeping the signatures honest keeps the caller a piece of
reviewed code that knows which extractor it is calling and why.

Every function is bounded. No loop here runs over attacker-controlled input
without a ceiling, and each ceiling is a module constant so a caller can see
from the result that it was reached: ``total_lines == max_lines`` means lines
were left unread, a chain of exactly ``max_depth`` means the chain may continue.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from itertools import islice
from types import MappingProxyType
from typing import Final

from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.tooling.observation.facts import DotenvFacts
from gryphon.tooling.observation.secrets import value_class
from gryphon.verification.constants import (
    DNS_MAX_ANSWERS,
    DNS_MAX_CNAME_DEPTH,
    HEADER_NAME_ALLOWLIST,
    HTTP_MAX_DECODED_BYTES,
    HTTP_MAX_HEADER_BYTES,
    Extractor,
)
from gryphon.verification.reasons import VerificationConfigurationError

# =============================================================================
# Bounds
# =============================================================================

#: Hard ceiling on lines examined by :func:`dotenv_grammar`. ``max_lines`` may
#: narrow it and may not widen it, the same rule settings obey everywhere else.
MAX_DOTENV_LINES: Final[int] = 20_000

#: Key names (and their parallel value classes) carried out of one body. A
#: configuration file with more keys than this is still measured in full — the
#: counts are exact — but the operator-readable list stops here.
MAX_DOTENV_KEY_NAMES: Final[int] = 200

#: Characters of a value handed to the value classifier.
MAX_DOTENV_VALUE_CHARS: Final[int] = 512

#: Characters of a body searched for pinned signal tokens.
MAX_SEARCH_CHARS: Final[int] = HTTP_MAX_DECODED_BYTES

#: Header entries examined, and characters of the header block searched.
MAX_HEADERS: Final[int] = 256
MAX_HEADER_ENTRY_CHARS: Final[int] = 2_048
MAX_HEADER_SEARCH_CHARS: Final[int] = HTTP_MAX_HEADER_BYTES

#: Pinned signal tokens honoured per call, and the longest one considered. The
#: tokens come from the signed registry, not from the target, but a bound that
#: depends on a document is still a bound worth stating.
MAX_SIGNAL_TOKENS: Final[int] = 32
MAX_TOKEN_CHARS: Final[int] = 128

#: Answer records read while building a CNAME chain.
MAX_DNS_RECORDS: Final[int] = DNS_MAX_ANSWERS
MAX_DNS_NAME_CHARS: Final[int] = 253

#: The lowest and highest integers treated as an HTTP status code.
MIN_HTTP_STATUS: Final[int] = 100
MAX_HTTP_STATUS: Final[int] = 599

#: The contract's dotenv assignment grammar, matched anchored at line start.
#: Written here as a literal rather than derived from a template's own regex:
#: the whole point of the predicate is to be independent of the template that
#: produced the finding.
_DOTENV_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{1,63}=")

#: Presentation-form DNS name. Anchored with ``fullmatch`` against one bounded
#: candidate, so it costs a constant per record.
_DNS_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9*_\-.]{1,253}")


# =============================================================================
# Extractors
# =============================================================================


def _iter_lines(body: str, limit: int) -> Iterator[str]:
    """Yield at most ``limit`` lines, splitting on LF and tolerating CRLF.

    Only LF ends a line, because that is what a dotenv reader does. Python's
    ``str.splitlines`` also breaks on form feed, U+2028 and friends, which would
    let a target inflate its own line count — and therefore its assignment ratio
    — with characters no configuration loader treats as a newline.
    """
    start = 0
    emitted = 0
    length = len(body)
    while start < length and emitted < limit:
        end = body.find("\n", start)
        if end == -1:
            yield body[start:]
            return
        yield body[start:end].rstrip("\r")
        start = end + 1
        emitted += 1


def dotenv_grammar(body: str, *, max_lines: int) -> DotenvFacts:
    """Measure a body against the dotenv assignment grammar.

    The structural counts are what a verifier reasons over, so that confirming
    an exposed configuration file does not depend on the detection template's
    own regex being right. Key names are carried out because an operator needs
    to know *which* keys were exposed; values are classified and dropped inside
    this function and never appear in the result.

    ``total_lines == max_lines`` means the cap stopped the read, and the ratios
    describe only the lines that were examined.
    """
    limit = max(1, min(max_lines, MAX_DOTENV_LINES))
    total = 0
    non_empty = 0
    assignments = 0
    key_names: list[str] = []
    value_classes: list[str] = []

    for line in _iter_lines(body, limit):
        total += 1
        if not line.strip():
            continue
        non_empty += 1
        match = _DOTENV_ASSIGNMENT_RE.match(line)
        if match is None:
            continue
        assignments += 1
        if len(key_names) < MAX_DOTENV_KEY_NAMES:
            cut = match.end()
            key_names.append(line[: cut - 1])
            value_classes.append(value_class(line[cut : cut + MAX_DOTENV_VALUE_CHARS]).value)

    return DotenvFacts(
        total_lines=total,
        non_empty_lines=non_empty,
        assignment_lines=assignments,
        key_names=tuple(key_names),
        value_classes=tuple(value_classes),
    )


def token_presence(
    body: str,
    headers: Mapping[str, str],
    tokens: Sequence[str],
) -> tuple[str, ...]:
    """Report which pinned signal tokens appear, in the spelling they were given.

    Only the token names come back — never the text around them. That is what
    makes this extractor usable for refutation: "the signal the template matched
    also appears on a control" is a complete answer, and the bytes that carried
    it are not needed to state it.

    Matching is case-insensitive via ``str.lower`` on both sides. Tokens are
    taken from the signed registry, so their spelling is operator-controlled and
    safe to echo; the body and the header values are not, and never are.
    """
    haystack = body[:MAX_SEARCH_CHARS].lower()
    header_blob = _header_blob(headers)
    found: list[str] = []
    for token in islice(tokens, MAX_SIGNAL_TOKENS):
        needle = token.strip().lower()
        if not needle or len(needle) > MAX_TOKEN_CHARS or token in found:
            continue
        if needle in haystack or needle in header_blob:
            found.append(token)
    return tuple(found)


def _header_blob(headers: Mapping[str, str]) -> str:
    """A bounded, lowercased ``name: value`` blob to search for signal tokens.

    Built and discarded inside this module. Header values are searched but never
    reported: :func:`header_presence` is the only thing that crosses out, and it
    carries names alone.
    """
    parts: list[str] = []
    budget = MAX_HEADER_SEARCH_CHARS
    for name, value in islice(headers.items(), MAX_HEADERS):
        if budget <= 0:
            break
        entry = f"{name}: {value}"[:MAX_HEADER_ENTRY_CHARS]
        parts.append(entry[:budget].lower())
        budget -= len(entry)
    return "\n".join(parts)


def header_presence(headers: Mapping[str, str]) -> tuple[str, ...]:
    """Allowlisted header *names* that were present, sorted and de-duplicated.

    An allowlist rather than a denylist, because a header a target invents is
    still a string a target chose. Sorted so two observations of the same
    response produce the same fact and therefore the same projection digest.
    """
    present: set[str] = set()
    for name in islice(headers, MAX_HEADERS):
        normalized = name.strip().lower()
        if normalized in HEADER_NAME_ALLOWLIST:
            present.add(normalized)
    return tuple(sorted(present))


def status_class(status_code: int) -> int:
    """The leading digit of an HTTP status: 404 becomes 4.

    Returns 0 for anything outside 100..599 rather than raising. The number
    arrives from a parsed response line, so a target can make it absurd; an
    absurd status is a fact the evaluator should see as "no class", not an
    exception thrown inside the sandbox.
    """
    if not MIN_HTTP_STATUS <= status_code <= MAX_HTTP_STATUS:
        return 0
    return status_code // 100


def body_digest(raw: bytes) -> str:
    """SHA-256 of the body as it arrived on the wire.

    Computed in the observer, over the raw bytes, before anything decodes or
    normalizes them — a digest taken after a transform identifies the transform,
    not the artifact a verdict claims to have seen.
    """
    return sha256_hex(raw)


def size_facts(raw: bytes, decoded: bytes | None) -> tuple[int, int]:
    """Return (wire bytes, decoded bytes).

    ``decoded`` is ``None`` when no content encoding was applied, and the two
    numbers are then equal. Reporting zero decoded bytes for an unencoded body
    would read as an empty response, which is exactly the fact a predicate about
    an exposed file turns on.
    """
    return len(raw), len(raw) if decoded is None else len(decoded)


def cname_chain(records: Sequence[str], *, max_depth: int) -> tuple[str, ...]:
    """Normalize a CNAME chain: lowercased, root dot removed, de-duplicated.

    De-duplication is not cosmetic. A chain that revisits a name is a loop, and
    a loop plus a depth bound is the difference between a terminated extraction
    and a sandbox that spins until its deadline. A name outside the
    presentation-form grammar is dropped rather than reported, because this
    tuple crosses the observer boundary and must carry names and nothing else.

    A result of exactly ``max_depth`` names means the chain may continue past
    what was recorded; the caller pairs that with ``TruncationReason.CNAME_DEPTH``.
    """
    depth = max(0, min(max_depth, DNS_MAX_CNAME_DEPTH))
    chain: list[str] = []
    seen: set[str] = set()
    for record in islice(records, MAX_DNS_RECORDS):
        if len(chain) >= depth:
            break
        name = record.strip().lower().rstrip(".")
        if not name or len(name) > MAX_DNS_NAME_CHARS:
            continue
        if _DNS_NAME_RE.fullmatch(name) is None or name in seen:
            continue
        seen.add(name)
        chain.append(name)
    return tuple(chain)


# =============================================================================
# The set, and its digest
# =============================================================================

#: Bump this when any function above changes what it reports, not only when a
#: name is added. The digest below covers the names and this version, so the
#: version string is the only place a behavioural change can be recorded — and
#: a verdict cites the digest to say exactly which extractors produced its
#: evidence.
EXTRACTOR_SET_VERSION: Final[str] = "1"

#: Name to implementation. The signatures differ on purpose — see the module
#: docstring — so the value type says only "something callable that returns a
#: fact". The caller is reviewed code that knows which one it is invoking.
EXTRACTOR_FUNCTIONS: Final[Mapping[Extractor, Callable[..., object]]] = MappingProxyType(
    {
        Extractor.DOTENV_GRAMMAR: dotenv_grammar,
        Extractor.TOKEN_PRESENCE: token_presence,
        Extractor.HEADER_PRESENCE: header_presence,
        Extractor.CNAME_CHAIN: cname_chain,
        Extractor.STATUS_CLASS: status_class,
        Extractor.BODY_DIGEST: body_digest,
        Extractor.SIZE_FACTS: size_facts,
    }
)

if frozenset(EXTRACTOR_FUNCTIONS) != frozenset(Extractor):
    _missing = sorted(member.value for member in Extractor if member not in EXTRACTOR_FUNCTIONS)
    raise VerificationConfigurationError(
        f"the catalog declares extractors this image does not implement: {_missing}"
    )

#: The canonical description the digest is taken over. A literal mapping with a
#: sorted list, so the bytes do not depend on dict iteration order, set hashing
#: or the interpreter's hash seed: the same image produces the same digest in
#: every process, which is the only reason an envelope can pin it.
_EXTRACTOR_SET_SPEC: Final[dict[str, object]] = {
    "extractor_set_version": EXTRACTOR_SET_VERSION,
    "extractors": sorted(member.value for member in EXTRACTOR_FUNCTIONS),
}

#: SHA-256 over the canonical JSON of that description.
EXTRACTOR_SET_DIGEST: Final[str] = sha256_hex(canonical_json_bytes(_EXTRACTOR_SET_SPEC))
