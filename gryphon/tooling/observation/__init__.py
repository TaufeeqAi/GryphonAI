"""Observation: the envelope, the typed facts, and the observer that produces them.

This package spans a trust boundary. :mod:`envelope` and :mod:`facts` are shared
vocabulary — the privileged side builds requests with one and validates results
with the other. :mod:`observer` and its ``__main__`` run on the far side, in an
unprivileged process with no database handle, no key and no credential, where a
target's bytes are read, measured and destroyed.

Import discipline follows that split: nothing here imports the database, the key
provider or any settings, so the code that parses hostile input cannot reach a
secret even by mistake. :mod:`observer` is deliberately *not* re-exported here —
it is the far side of the boundary, started as a subprocess, and a privileged
process has no reason to hold it.

What is re-exported is the vocabulary and the measurements:
:mod:`extractors` (the fixed, named set and the ``EXTRACTOR_SET_DIGEST`` an
envelope pins) and :mod:`secrets` (shape classification that returns a class and
a count, never a value).
"""

from __future__ import annotations

from gryphon.tooling.observation.envelope import (
    ENVELOPE_FORMAT_VERSION,
    EnvelopeError,
    RequestEnvelope,
    dns_envelope,
    http_envelope,
)
from gryphon.tooling.observation.extractors import (
    EXTRACTOR_FUNCTIONS,
    EXTRACTOR_SET_DIGEST,
    EXTRACTOR_SET_VERSION,
    MAX_DOTENV_KEY_NAMES,
    MAX_DOTENV_LINES,
    MAX_SIGNAL_TOKENS,
    body_digest,
    cname_chain,
    dotenv_grammar,
    header_presence,
    size_facts,
    status_class,
    token_presence,
)
from gryphon.tooling.observation.facts import (
    OBSERVATION_FACTS_VERSION,
    Completeness,
    DnsFacts,
    DotenvFacts,
    HttpFacts,
    ObservationFacts,
    ObserverErrorCode,
)
from gryphon.tooling.observation.secrets import (
    MAX_MATCHES_PER_CLASS,
    MAX_SCAN_CHARS,
    classify,
    credential_key_names,
    value_class,
)

__all__ = [
    "ENVELOPE_FORMAT_VERSION",
    "EXTRACTOR_FUNCTIONS",
    "EXTRACTOR_SET_DIGEST",
    "EXTRACTOR_SET_VERSION",
    "MAX_DOTENV_KEY_NAMES",
    "MAX_DOTENV_LINES",
    "MAX_MATCHES_PER_CLASS",
    "MAX_SCAN_CHARS",
    "MAX_SIGNAL_TOKENS",
    "OBSERVATION_FACTS_VERSION",
    "Completeness",
    "DnsFacts",
    "DotenvFacts",
    "EnvelopeError",
    "HttpFacts",
    "ObservationFacts",
    "ObserverErrorCode",
    "RequestEnvelope",
    "body_digest",
    "classify",
    "cname_chain",
    "credential_key_names",
    "dns_envelope",
    "dotenv_grammar",
    "header_presence",
    "http_envelope",
    "size_facts",
    "status_class",
    "token_presence",
    "value_class",
]
