"""Secret-shape classification: a class and a count leave, a value never does.

The observer reads bytes the target chose and has to answer one question about
them — *is something credential-shaped in here?* — without carrying any part of
the evidence out. Every function in this module returns a class name and a
number. No match, no span, no window and no value is returned, logged or
retained; the body is destroyed inside the sandbox immediately afterwards.

Recognition is therefore not the boundary. A finite recognizer cannot see every
secret format and this module does not pretend to: the guarantee is that no
target-controlled byte crosses out, which holds whether or not a shape was
recognized. The counts are evidence *about* bytes that no longer exist anywhere.

**The defect this module closes.** The execution layer's sanitizer
(:mod:`gryphon.tooling.tools.sanitize`) recognizes a private key by its
``-----BEGIN ... PRIVATE KEY-----`` header *line* alone. Redaction therefore
replaces the header and leaves the base64 body exactly where it was: the key
material survives the step that was supposed to remove it, and a reader who
knows the format has lost one line of a key they can still reassemble. The
pattern here matches the whole block, header through footer, under an explicit
character bound, so one key is one occurrence and its body is *inside* the
match. A header with no footer is still counted once, because a response
truncated mid-key has exposed a key just the same.

Counts may overlap on purpose: ``AWS_SECRET_ACCESS_KEY=AKIA...`` is both an
AWS-shaped identifier and a credential assignment. The classes are shapes, not
a partition, because the predicate that consumes them asks "did this shape
appear", never "how many distinct secrets are there".

Every pattern is bounded. Each quantifier has a literal ceiling and no
repetition is nested inside another, so a hostile body cannot turn a scan into
an exponential one; the comment above each pattern says why it stays linear-ish.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

from gryphon.verification.constants import (
    HTTP_MAX_DECODED_BYTES,
    SecretClass,
    ValueClass,
)
from gryphon.verification.reasons import VerificationConfigurationError

# =============================================================================
# Bounds
# =============================================================================

#: Characters scanned per call. This is the decoded-bytes bound the observer
#: already enforces on the wire, applied a second time here so a caller that
#: hands this module a larger string cannot spend unbounded CPU inside the
#: sandbox. The truncation itself is reported where it belongs — in
#: ``Completeness.truncation_reason`` — not invented by the classifier.
MAX_SCAN_CHARS: Final[int] = HTTP_MAX_DECODED_BYTES

#: Per-class ceiling on counted occurrences. A count equal to this means "at
#: least this many": the scan stopped, and a predicate that needs ">= 1" is
#: already satisfied long before it.
MAX_MATCHES_PER_CLASS: Final[int] = 1_000

#: Credential-shaped key *names* reported per body. Names are operator-readable
#: and cross the boundary; the values they were assigned never do.
MAX_CREDENTIAL_KEY_NAMES: Final[int] = 64

#: Characters of a single value examined by :func:`value_class`. A value longer
#: than this is classified on its leading window, which is sufficient: the
#: question is what the value looks like, not what it is.
MAX_VALUE_CHARS: Final[int] = 512

#: Characters a PEM block may span between header and footer. Larger than any
#: real key; small enough that an unterminated header costs one bounded scan.
MAX_PRIVATE_KEY_BLOCK_CHARS: Final[int] = 65_536

#: Longest key name considered for a credential assignment.
MAX_KEY_NAME_CHARS: Final[int] = 64

# =============================================================================
# Patterns
# =============================================================================

# A fixed-width literal alternation followed by a fixed repetition, fenced by
# single-character lookarounds. There is no second way to match the same text,
# so the engine has nothing to backtrack into: linear in the input length.
_AWS_ACCESS_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)"
    r"[0-9A-Z]{16}(?![A-Z0-9])"
)

# The key is anchored at a token boundary by a one-character lookbehind, so each
# key name has exactly one start position. The separator characters are outside
# both the key class and the value class, so the two quantifiers can never trade
# characters with each other; a failed key costs at most MAX_KEY_NAME_CHARS
# backtracking steps before the engine moves to the next token.
_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9_\-])(?P<key>[A-Za-z_][A-Za-z0-9_\-]{0,63})"
    r"[\"']?[ \t]{0,8}[:=][ \t]{0,8}[\"']?"
    r"(?P<value>[^\s\"'\r\n]{6,512})"
)

# Searched only against a key name of at most MAX_KEY_NAME_CHARS, so its cost is
# bounded by a constant however large the body is. The key name is matched
# *separately* from the assignment: a predicate reasons over names, which are
# safe to report, while the value is only ever counted.
_CREDENTIAL_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:api[_\-]?key|access[_\-]?key|private[_\-]?key|signing[_\-]?key|"
    r"session[_\-]?key|client[_\-]?secret|secret|token|passwd|password|"
    r"credential|bearer)"
)

_PRIVATE_KEY_HEADER_SOURCE: Final[str] = r"-----BEGIN (?:[A-Z][A-Z0-9 ]{0,32} )?PRIVATE KEY-----"
_PRIVATE_KEY_FOOTER_SOURCE: Final[str] = r"-----END (?:[A-Z][A-Z0-9 ]{0,32} )?PRIVATE KEY-----"

# Lazy and explicitly bounded: the engine advances one character at a time
# looking for the footer and gives up at MAX_PRIVATE_KEY_BLOCK_CHARS, so a
# header with no footer costs one bounded scan rather than a quadratic one. The
# optional key-type group is uppercase-only and capped at 33 characters, so the
# only ambiguity in the pattern backtracks a constant number of times.
_PRIVATE_KEY_BLOCK_RE: Final[re.Pattern[str]] = re.compile(
    _PRIVATE_KEY_HEADER_SOURCE
    + rf"[\s\S]{{0,{MAX_PRIVATE_KEY_BLOCK_CHARS}}}?"
    + _PRIVATE_KEY_FOOTER_SOURCE
)

#: The header on its own — used only to find blocks whose footer never arrived.
_PRIVATE_KEY_HEADER_RE: Final[re.Pattern[str]] = re.compile(_PRIVATE_KEY_HEADER_SOURCE)

# Each segment's character class excludes the '.' that separates segments, so a
# segment has exactly one possible extent at any start position: the engine
# cannot redistribute characters between segments, and the match either runs to
# the end or fails there.
_JWT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9._\-])eyJ[A-Za-z0-9_\-]{8,4096}"
    r"\.[A-Za-z0-9_\-]{8,8192}"
    r"\.[A-Za-z0-9_\-]{0,8192}(?![A-Za-z0-9_\-])"
)

# The user class excludes ':' and the password class excludes '@', so the
# authority splits exactly one way. No two quantifiers compete for the same
# characters, and the scheme is capped at 16 characters.
_URL_CREDENTIAL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{1,15}://"
    r"[^\s/:@]{1,128}:[^\s/@]{1,256}@[A-Za-z0-9.\-]{1,253}"
)

# A value made only of token characters, long enough that nobody typed it by
# hand. Anchored with ``fullmatch`` against a single bounded value, never
# searched across a body.
_OPAQUE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/_\-]{20,512}={0,2}")


# =============================================================================
# Counters
# =============================================================================


def _count_matches(pattern: re.Pattern[str], text: str) -> int:
    """Count non-overlapping matches, stopping at the per-class ceiling."""
    count = 0
    for _ in pattern.finditer(text):
        count += 1
        if count >= MAX_MATCHES_PER_CLASS:
            break
    return count


def _count_aws_access_key_ids(text: str) -> int:
    return _count_matches(_AWS_ACCESS_KEY_ID_RE, text)


def _count_jwts(text: str) -> int:
    return _count_matches(_JWT_RE, text)


def _count_url_credentials(text: str) -> int:
    return _count_matches(_URL_CREDENTIAL_RE, text)


def _scan_credential_assignments(text: str) -> tuple[int, tuple[str, ...]]:
    """Return (occurrences, key names) for credential-shaped assignments.

    The key name is read from its own capture group and tested on its own, so
    the pattern does not have to encode "a credential-ish word somewhere inside
    a longer name" — which is how the execution layer's sanitizer misses
    ``AWS_SECRET_ACCESS_KEY=...``, whose keyword is in the middle.
    """
    count = 0
    names: list[str] = []
    for match in _ASSIGNMENT_RE.finditer(text):
        key = match.group("key")
        if len(key) > MAX_KEY_NAME_CHARS or _CREDENTIAL_NAME_RE.search(key) is None:
            continue
        count += 1
        if len(names) < MAX_CREDENTIAL_KEY_NAMES and key not in names:
            names.append(key)
        if count >= MAX_MATCHES_PER_CLASS:
            break
    return count, tuple(names)


def _count_credential_assignments(text: str) -> int:
    return _scan_credential_assignments(text)[0]


def _count_private_key_blocks(text: str) -> int:
    """Count whole blocks, plus any header whose footer never arrived.

    Both iterators yield in increasing position, so the overlap check walks the
    recorded spans with a single cursor instead of rescanning them.
    """
    spans: list[tuple[int, int]] = []
    count = 0
    for match in _PRIVATE_KEY_BLOCK_RE.finditer(text):
        spans.append(match.span())
        count += 1
        if count >= MAX_MATCHES_PER_CLASS:
            return count

    cursor = 0
    for header in _PRIVATE_KEY_HEADER_RE.finditer(text):
        start = header.start()
        while cursor < len(spans) and spans[cursor][1] <= start:
            cursor += 1
        if cursor < len(spans) and spans[cursor][0] <= start < spans[cursor][1]:
            continue
        count += 1
        if count >= MAX_MATCHES_PER_CLASS:
            break
    return count


#: One counter per class. The mapping exists so the closed set can be checked
#: against the enum at import: a class nobody counts would silently report zero
#: forever, which reads as "we looked and found nothing".
_COUNTERS: Final[Mapping[SecretClass, Callable[[str], int]]] = MappingProxyType(
    {
        SecretClass.AWS_ACCESS_KEY_ID: _count_aws_access_key_ids,
        SecretClass.CREDENTIAL_ASSIGNMENT: _count_credential_assignments,
        SecretClass.PRIVATE_KEY_BLOCK: _count_private_key_blocks,
        SecretClass.JWT: _count_jwts,
        SecretClass.URL_CREDENTIAL: _count_url_credentials,
    }
)

if frozenset(_COUNTERS) != frozenset(SecretClass):
    missing = sorted(member.value for member in SecretClass if member not in _COUNTERS)
    raise VerificationConfigurationError(
        f"secret classes with no recognizer would always report zero: {missing}"
    )


# =============================================================================
# Public surface
# =============================================================================


def classify(text: str) -> dict[str, int]:
    """Count secret shapes in ``text``. Pure, deterministic, no I/O.

    Every class is present with an explicit count, including zero. A missing key
    and a zero would otherwise be indistinguishable, and they mean very
    different things: zero is a measurement, absence is an observer that never
    looked. What a zero is *worth* depends on completeness — a truncated body
    that shows no AWS key says nothing about the bytes that were not read — and
    that qualifier travels with the facts, not with this number.
    """
    window = text[:MAX_SCAN_CHARS]
    return {member.value: _COUNTERS[member](window) for member in SecretClass}


def credential_key_names(text: str) -> tuple[str, ...]:
    """Credential-shaped key *names* found in ``text``, first-seen order.

    Names are reported because an operator needs to know that a key called
    ``STRIPE_SECRET_KEY`` was exposed. The value it was assigned is counted and
    then forgotten; it is never a return value here or anywhere else.
    """
    return _scan_credential_assignments(text[:MAX_SCAN_CHARS])[1]


def value_class(raw: str) -> ValueClass:
    """Classify one dotenv-style value without reporting it.

    Three answers, because three are all a predicate can act on: the key was
    present but unset, the value looks like a credential, or it looks like
    ordinary configuration. The opaque-token test errs toward
    ``SECRET_SHAPED``: calling a long random-looking identifier secret-shaped
    costs an operator a second glance, while the opposite error tells them an
    exposed key was boring. Neither error can leak anything, because the value
    is already gone by the time this answer is read.
    """
    value = _strip_quotes(raw.strip())
    if not value:
        return ValueClass.EMPTY
    window = value[:MAX_VALUE_CHARS]
    if any(counter(window) > 0 for counter in _COUNTERS.values()):
        return ValueClass.SECRET_SHAPED
    if _is_opaque_token(window):
        return ValueClass.SECRET_SHAPED
    return ValueClass.OTHER


def _strip_quotes(value: str) -> str:
    """Remove one layer of matched surrounding quotes, then re-strip."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


def _is_opaque_token(value: str) -> bool:
    """True for a long token-character run mixing letters and digits.

    The mixing requirement is what keeps a long English word or a path out of
    this class; ``fullmatch`` against one bounded value keeps it constant-cost.
    """
    if _OPAQUE_TOKEN_RE.fullmatch(value) is None:
        return False
    return any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value)
