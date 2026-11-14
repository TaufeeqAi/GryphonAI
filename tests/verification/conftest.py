"""Shared fixtures for the verification layer tests.

Everything here is synthetic and offline: no DNS, no network, no real targets.
Database-backed tests live under ``integration/`` and are gated on
``GRYPHON_TEST_DATABASE_URL``; the rest run anywhere, including the Windows
development host, because the layer's most consequential rules are pure
functions and were designed to be testable without a stack.

The canary below is the one value every secret-boundary test looks for. It is
AWS's own documented *example* key, so it is recognizable by shape, carries no
access to anything, and is safe to commit — while still exercising exactly the
recognizer path a real credential would take.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from gryphon.auth.key_provider import Ed25519SigningKey, TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.clock import FixedClock
from gryphon.tooling.observation.facts import (
    Completeness,
    DnsFacts,
    DotenvFacts,
    HttpFacts,
    ObservationFacts,
)
from gryphon.verification.audit import VerificationAuditBuilder
from gryphon.verification.constants import (
    ObservationKind,
    ObservationRole,
    OutcomeClass,
    TruncationReason,
)
from gryphon.verification.inputs import AttestedEvent, BaseReportMaterial
from gryphon.verification.observation import Observation
from gryphon.verification.registry import DEFAULT_REGISTRY_PATH, VerifierRegistry

NOW = datetime(2026, 11, 14, 9, 0, 0, tzinfo=UTC)
SCAN_RUN_ID = "11111111-2222-4333-8444-555555555555"

#: AWS's documented example access key id. Shape-valid, access to nothing.
AWS_CANARY = "AKIAIOSFODNN7EXAMPLE"
#: A second canary with no recognizer at all, used to prove the guarantee does
#: not depend on recognizing a format: nothing a target wrote may cross.
OPAQUE_CANARY = "zqf7Xp3Lk9Vn2Rt8Ws5Yd1Hb4Mj6Qc0Ae"
#: A full PEM block. The previous sanitizer matched only its header line, so the
#: base64 body would have crossed intact; tests assert the whole block is seen.
PEM_CANARY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n"
    "-----END RSA PRIVATE KEY-----"
)

DOTENV_BODY = (
    "APP_ENV=production\n"
    f"AWS_ACCESS_KEY_ID={AWS_CANARY}\n"
    f"AWS_SECRET_ACCESS_KEY={OPAQUE_CANARY}\n"
    "DB_PASSWORD=hunter2hunter2\n"
    "DEBUG=false\n"
    "MAIL_DRIVER=smtp\n"
)

ALL_CANARIES: tuple[str, ...] = (AWS_CANARY, OPAQUE_CANARY, "hunter2hunter2", PEM_CANARY)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(instant=NOW)


@pytest.fixture(scope="session")
def registry() -> VerifierRegistry:
    return VerifierRegistry.load(DEFAULT_REGISTRY_PATH)


@pytest.fixture
def verification_key() -> tuple[Ed25519SigningKey, TrustedKeyStore]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(kid="verification-test", _private=private)
    return signer, TrustedKeyStore({"verification-test": private.public_key()})


@pytest.fixture
def verification_audit(verification_key) -> VerificationAuditBuilder:
    return VerificationAuditBuilder(verification_key[0])


@pytest.fixture
def attestation_key() -> tuple[Ed25519SigningKey, TrustedKeyStore]:
    """Stands in for the *orchestration attestation* key.

    Deliberately a different key from ``verification_key``. The custody rule is
    that this layer can verify a base report's attestation but cannot produce
    one; a test that used the same key would pass while proving the opposite.
    """
    private = ed25519.Ed25519PrivateKey.generate()
    signer = Ed25519SigningKey(kid="attestation-test", _private=private)
    return signer, TrustedKeyStore({"attestation-test": private.public_key()})


# =============================================================================
# Facts builders
# =============================================================================


def http_facts(
    *,
    status: int = 200,
    content_type: str | None = "text/plain",
    body: str = DOTENV_BODY,
    secret_counts: dict[str, int] | None = None,
    tokens: Sequence[str] = (),
    header_names: Sequence[str] = (),
    complete: bool = True,
    truncation: TruncationReason = TruncationReason.NONE,
    digest_salt: str = "",
    with_dotenv: bool = True,
) -> ObservationFacts:
    """Facts as the observer would have emitted them.

    Note what is *absent*: there is no body field. The body was measured in the
    sandbox and destroyed there, so a test cannot accidentally assert on content
    that production would never have.
    """
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assignments = [ln for ln in lines if "=" in ln and ln.split("=", 1)[0].isupper()]
    dotenv = (
        DotenvFacts(
            total_lines=len(body.splitlines()),
            non_empty_lines=len(lines),
            assignment_lines=len(assignments),
            key_names=tuple(ln.split("=", 1)[0] for ln in assignments),
            value_classes=tuple("secret_shaped" for _ in assignments),
        )
        if with_dotenv
        else None
    )
    return ObservationFacts(
        kind=ObservationKind.HTTP_RESPONSE_SUMMARY,
        completeness=Completeness(
            transport_complete=complete,
            body_complete=complete,
            truncation_reason=truncation,
            bytes_read=len(body.encode()),
            decoded_bytes=len(body.encode()),
        ),
        http=HttpFacts(
            status_code=status,
            status_class=status // 100,
            content_type=content_type,
            content_length_header=len(body.encode()),
            body_sha256=sha256_hex((digest_salt + body).encode()),
            header_names=tuple(header_names),
            location_class="none",
            secret_class_counts=dict(secret_counts or {}),
            tokens_present=tuple(tokens),
            dotenv=dotenv,
        ),
    )


def dns_facts(
    *,
    rcode: str = "NXDOMAIN",
    chain: Sequence[str] = ("app.example.test", "bucket.s3.amazonaws.com"),
    a_records: Sequence[str] = (),
    complete: bool = True,
) -> ObservationFacts:
    return ObservationFacts(
        kind=ObservationKind.DNS_ANSWER,
        completeness=Completeness(transport_complete=complete, body_complete=complete),
        dns=DnsFacts(
            rcode=rcode,
            cname_chain=tuple(chain),
            a_records=tuple(a_records),
            resolver_set_digest="resolvers-test",
            authoritative=True,
        ),
    )


def observation(
    observation_id: str,
    *,
    facts: ObservationFacts | None = None,
    role: ObservationRole = ObservationRole.PRIMARY,
    control_index: int = 0,
    outcome: OutcomeClass = OutcomeClass.OBSERVED,
    reason_code: str = "ADMITTED",
) -> Observation:
    return Observation(
        observation_id=observation_id,
        execution_id=f"exec-{observation_id}",
        role=role,
        control_index=control_index,
        outcome=outcome,
        reason_code=reason_code,
        facts=facts,
    )


# =============================================================================
# Base report material
# =============================================================================


def base_report_material(
    *,
    signer: Ed25519SigningKey,
    findings: Sequence[dict[str, Any]],
    scan_run_id: str = SCAN_RUN_ID,
    terminal_state: str = "COMPLETED",
    integrity_failed: bool = False,
    tamper: bool = False,
) -> BaseReportMaterial:
    """A base report plus a genuine attestation over its digest."""
    body: dict[str, Any] = {
        "report_schema_version": "1",
        "scan_run_id": scan_run_id,
        "terminal_state": terminal_state,
        "reason_code": "SCAN_COMPLETE",
        "integrity": {"failed": integrity_failed},
        "findings": list(findings),
    }
    digest = sha256_hex(canonical_json_bytes(body))
    payload = {
        "event_schema_version": "1",
        "event_type": "report_emitted",
        "scan_run_id": scan_run_id,
        "report_digest": digest,
        "signer_kid": signer.kid,
    }
    canonical = canonical_json_bytes(payload)
    import base64

    event = AttestedEvent(
        payload=payload,
        payload_digest=sha256_hex(canonical),
        signer_kid=signer.kid,
        signature_b64=base64.standard_b64encode(signer.sign(canonical)).decode("ascii"),
    )
    if tamper:
        # Alter the body *after* the attestation was produced. The digest no
        # longer matches, which is exactly what the input verifier must catch.
        body["findings"] = [*body["findings"], {"finding_id": "injected", "canonical_target": "x"}]
    return BaseReportMaterial(
        scan_run_id=scan_run_id,
        report_id="rep-1",
        report_digest=digest,
        report_schema_version="1",
        body=body,
        events=[event],
    )


def report_finding(
    finding_id: str,
    *,
    observation_type: str = "exposed_config",
    template_id: str | None = "laravel-env",
    target: str = "app.example.test",
    url: str | None = "https://app.example.test/.env",
    severity: str = "high",
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "observation_type": observation_type,
        "canonical_target": target,
        "url": url,
        "severity": severity,
        "observation": {"template_id": template_id} if template_id else {},
    }
