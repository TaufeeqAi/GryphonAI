"""The acceptance checkpoints, restated as executable tests.

These are the criteria a reviewer should run first. Each one corresponds to a
checkpoint in the layer's contract, and each exists because the opposite
behaviour is a plausible, tempting shortcut:

* **CK-1** — a secret can be *proven* without being *moved*. The tempting
  shortcut is to carry a redacted excerpt "just for the report".
* **CK-2** — a signal that is everywhere is evidence of nothing. The shortcut is
  to trust the original matcher because it fired once.
* **CK-3** — unknown is never success and never refutation. The shortcut is to
  treat an unreachable host as a false positive and quietly shrink the report.
* **CK-4** — the verifier cannot write its own inputs or sign its own
  attestations. The shortcut is one convenient database role.
* **CK-5** — a repeated command is not a second pass, and a resumed pass does not
  re-contact. The shortcut is to start fresh, which is invisible in the output
  and visible in the client's logs.
* **CK-6** — the two verifier shapes that must actually work, including the one
  that the previous destination model made impossible.
"""

from __future__ import annotations

import json

import pytest

from gryphon.tooling.observation import extractors, secrets
from gryphon.verification.constants import (
    Justification,
    ObservationRole,
    OutcomeClass,
    TruncationReason,
    VerdictStatus,
)
from gryphon.verification.evaluator import ProofEvaluator
from gryphon.verification.identity import execution_id, new_pass_salt, subject_key
from gryphon.verification.inputs import (
    Refusal,
    findings_from,
    verify_base_report,
)
from gryphon.verification.planner import ObservationPlanner
from gryphon.verification.publish import VerdictRecord, build_report_body, declared_limitations
from gryphon.verification.registry import Finding, Unsupported
from tests.verification.conftest import (
    ALL_CANARIES,
    AWS_CANARY,
    DOTENV_BODY,
    OPAQUE_CANARY,
    PEM_CANARY,
    base_report_material,
    dns_facts,
    http_facts,
    observation,
    report_finding,
)

pytestmark = pytest.mark.contract


# =============================================================================
# CK-1 — an exposed configuration file, proven without moving the secret
# =============================================================================


def test_ck1_confirms_exposed_config_by_its_own_grammar(registry) -> None:
    """The predicate is independent of the detection template's regex.

    Re-running the original matcher would reproduce the original false positive,
    so the verifier reasons over the file's grammar instead: enough non-empty
    lines, enough of them assignments, and a content type that is not HTML.
    """
    finding = Finding(
        finding_id="f1",
        observation_type="exposed_config",
        canonical_target="app.example.test",
        template_id="laravel-env",
        url="https://app.example.test/.env",
    )
    spec = registry.resolve(finding)
    assert not isinstance(spec, Unsupported)

    real = http_facts(secret_counts={"aws_access_key_id": 1}, digest_salt="real")
    absent = http_facts(
        status=404, content_type="text/html", body="<html>not found</html>", with_dotenv=False
    )

    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=real),
        [
            observation("c1", facts=absent, role=ObservationRole.CONTROL, control_index=1),
            observation("c2", facts=absent, role=ObservationRole.CONTROL, control_index=2),
        ],
    )

    assert verdict.status is VerdictStatus.CONFIRMED
    assert verdict.justification is None
    assert verdict.projection["secret_class_counts"]["aws_access_key_id"] >= 1


def test_ck1_the_secret_value_is_nowhere_in_the_published_artifacts(registry) -> None:
    """The canary must not appear in the verdict, the projection or the report.

    This is the checkpoint the whole secret boundary exists for. Note that one
    canary has no recognizer at all: the guarantee cannot rest on recognizing a
    format, because a finite recognizer cannot be right about every shape it has
    never seen. It rests on no target-controlled bytes being carried out.
    """
    finding = Finding(
        finding_id="f1",
        observation_type="exposed_config",
        canonical_target="app.example.test",
        template_id="laravel-env",
        url="https://app.example.test/.env",
    )
    spec = registry.resolve(finding)
    real = http_facts(secret_counts=secrets.classify(DOTENV_BODY), digest_salt="real")
    absent = http_facts(status=404, content_type="text/html", body="x", with_dotenv=False)

    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=real),
        [
            observation("c1", facts=absent, role=ObservationRole.CONTROL, control_index=1),
            observation("c2", facts=absent, role=ObservationRole.CONTROL, control_index=2),
        ],
    )
    record = VerdictRecord(
        finding_id="f1",
        subject_key=subject_key(
            kind="http.response.summary",
            canonical_target="app.example.test",
            locator="/.env",
            finding_class="laravel-env",
        ),
        verdict=verdict,
        observed_at=None,
        canonical_target="app.example.test",
        url="https://app.example.test/.env",
    )

    serialized = json.dumps(
        {
            "verdict": verdict.as_payload(),
            "projection": verdict.projection,
            "entry": record.as_report_entry(),
        },
        default=str,
    )
    for canary in ALL_CANARIES:
        assert canary not in serialized, f"{canary[:12]}... leaked into a published artifact"

    # The *shape* still crossed, which is the whole point: a count is evidence
    # about a body that no longer exists anywhere.
    assert verdict.projection["secret_class_counts"]["aws_access_key_id"] >= 1


def test_ck1_the_whole_private_key_block_is_recognized() -> None:
    """A PEM block counts once, body included.

    The previous recognizer matched only the ``-----BEGIN ... PRIVATE KEY-----``
    header line, so the base64 body would have passed through as ordinary text.
    """
    counts = secrets.classify(f"preamble\n{PEM_CANARY}\ntrailer")
    assert counts.get("private_key_block", 0) == 1


def test_ck1_dotenv_extractor_reports_keys_and_classes_never_values() -> None:
    facts = extractors.dotenv_grammar(DOTENV_BODY, max_lines=500)
    assert "AWS_ACCESS_KEY_ID" in facts.key_names
    assert facts.assignment_ratio >= 0.5
    payload = json.dumps(facts.as_payload())
    for canary in (AWS_CANARY, OPAQUE_CANARY):
        assert canary not in payload


# =============================================================================
# CK-2 — a signal that appears everywhere refutes the finding
# =============================================================================


def test_ck2_site_wide_signal_is_refuted(registry) -> None:
    """A header the host adds to every response says nothing about this path."""
    spec = registry.spec("signal-specificity@1.0.0")
    assert spec is not None and spec.can_refute and not spec.can_confirm

    everywhere = http_facts(
        tokens=("X-Powered-By",), header_names=("x-powered-by",), with_dotenv=False
    )
    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=everywhere),
        [
            observation(
                "c1", facts=everywhere, role=ObservationRole.CONTROL, control_index=1
            ),
            observation(
                "c2", facts=everywhere, role=ObservationRole.CONTROL, control_index=2
            ),
        ],
    )
    assert verdict.status is VerdictStatus.REFUTED
    assert verdict.justification is Justification.SIGNAL_UBIQUITOUS


def test_ck2_a_refuted_finding_is_listed_not_deleted(registry) -> None:
    """A consumer must be able to tell "verified away" from "never produced"."""
    spec = registry.spec("signal-specificity@1.0.0")
    everywhere = http_facts(tokens=("X-Powered-By",), with_dotenv=False)
    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=everywhere),
        [
            observation("c1", facts=everywhere, role=ObservationRole.CONTROL, control_index=1),
            observation("c2", facts=everywhere, role=ObservationRole.CONTROL, control_index=2),
        ],
    )
    from gryphon.verification.constants import EnrichmentContext, OrderingBasis, PassOutcome
    from gryphon.verification.inputs import ReportRef

    body = build_report_body(
        scan_run_id="s",
        pass_id="p",
        records=[
            VerdictRecord(
                finding_id="f1",
                subject_key="subj",
                verdict=verdict,
                observed_at=None,
                canonical_target="app.example.test",
            )
        ],
        base=ReportRef(report_id="r", report_digest="d", schema_version="1"),
        enrichment=None,
        enrichment_context=EnrichmentContext.ABSENT,
        ordering_basis=OrderingBasis.OBSERVED_SEVERITY,
        manifest={},
        outcome=PassOutcome.VERIFIED,
        scope=None,
        generated_at=__import__("datetime").datetime(
            2026, 11, 14, tzinfo=__import__("datetime").UTC
        ),
        limitations=(),
    )
    filtered = body["sections"]["filtered_false_positives"]
    assert len(filtered) == 1
    assert filtered[0]["justification"] == "signal_ubiquitous"
    assert body["counts"]["REFUTED"] == 1


# =============================================================================
# CK-3 — honesty controls
# =============================================================================


def test_ck3_catch_all_host_is_refuted_not_confirmed(registry) -> None:
    """A server that answers identically for everything proves nothing."""
    spec = registry.spec("exposed-config@1.0.0")
    same = http_facts(secret_counts={"aws_access_key_id": 1}, digest_salt="identical")
    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=same),
        [
            observation("c1", facts=same, role=ObservationRole.CONTROL, control_index=1),
            observation("c2", facts=same, role=ObservationRole.CONTROL, control_index=2),
        ],
    )
    assert verdict.status is VerdictStatus.REFUTED
    assert verdict.justification is Justification.CONTROL_MATCHED


@pytest.mark.parametrize(
    ("outcome", "reason", "expected"),
    [
        (OutcomeClass.TIMED_OUT, "TOOL_TIMED_OUT", Justification.TIMEOUT),
        (OutcomeClass.FAILED, "TOOL_FAILED", Justification.PROBE_FAILED),
        (OutcomeClass.OBSERVATION_LOST, "OBSERVATION_LOST", Justification.EVIDENCE_UNAVAILABLE),
        (OutcomeClass.REFUSED_POLICY, "SCOPE_EXCLUDED", Justification.SCOPE_EXCLUDED),
        (
            OutcomeClass.REFUSED_POLICY,
            "DESTINATION_UNATTESTED",
            Justification.DESTINATION_UNATTESTED,
        ),
        (OutcomeClass.REFUSED_CAPACITY, "BREAKER_OPEN", Justification.DEPENDENCY_UNAVAILABLE),
    ],
)
def test_ck3_unreachable_is_never_refuted(registry, outcome, reason, expected) -> None:
    """Every failure to observe is INCONCLUSIVE with its own reason.

    Mapping any of these to REFUTED would turn "we could not look" into "there
    was nothing there", which is how a verification layer becomes a way of
    quietly deleting findings.
    """
    spec = registry.spec("exposed-config@1.0.0")
    verdict = ProofEvaluator().evaluate(
        spec, observation("p", facts=None, outcome=outcome, reason_code=reason), []
    )
    assert verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.justification is expected


def test_ck3_an_incomplete_observation_can_never_prove_absence(registry) -> None:
    """A truncated body missing a token says nothing about whether it was there."""
    spec = registry.spec("exposed-config@1.0.0")
    truncated = http_facts(complete=False, truncation=TruncationReason.WIRE_BYTES)
    absent = http_facts(status=404, content_type="text/html", body="x", with_dotenv=False)
    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=truncated),
        [
            observation("c1", facts=absent, role=ObservationRole.CONTROL, control_index=1),
            observation("c2", facts=absent, role=ObservationRole.CONTROL, control_index=2),
        ],
    )
    assert verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.justification is Justification.INCOMPLETE_OBSERVATION


def test_ck3_disagreeing_controls_refuse_to_judge(registry) -> None:
    """If the host's behaviour for missing things is unstable, comparison is void."""
    spec = registry.spec("exposed-config@1.0.0")
    real = http_facts(digest_salt="real")
    a = http_facts(status=404, content_type="text/html", body="a", with_dotenv=False)
    b = http_facts(status=200, content_type="text/html", body="b", with_dotenv=False)
    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=real),
        [
            observation("c1", facts=a, role=ObservationRole.CONTROL, control_index=1),
            observation("c2", facts=b, role=ObservationRole.CONTROL, control_index=2),
        ],
    )
    assert verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.justification is Justification.CONTROLS_DISAGREE


def test_ck3_tampered_base_report_refuses_the_pass(attestation_key) -> None:
    """A body altered after its attestation is refused, never verified."""
    signer, trust = attestation_key
    material = base_report_material(
        signer=signer, findings=[report_finding("f1")], tamper=True
    )
    result = verify_base_report(material, trust)
    assert isinstance(result, Refusal)
    assert "digest" in result.detail


def test_ck3_untrusted_attestation_signer_refuses_the_pass(
    attestation_key, verification_key
) -> None:
    """A report signed by a key we hold is still refused.

    This is the custody rule made executable: the attestation must come from the
    orchestration signer, whose private half this layer does not have. If the
    verification key could attest a base report, a compromise here would be
    enough to fabricate an input and make it look genuine.
    """
    _, attestation_trust = attestation_key
    verification_signer, _ = verification_key
    material = base_report_material(
        signer=verification_signer, findings=[report_finding("f1")]
    )
    result = verify_base_report(material, attestation_trust)
    assert isinstance(result, Refusal)


def test_ck3_integrity_failed_scan_is_never_verified(attestation_key) -> None:
    signer, trust = attestation_key
    material = base_report_material(
        signer=signer, findings=[report_finding("f1")], integrity_failed=True
    )
    result = verify_base_report(material, trust)
    assert isinstance(result, Refusal)


def test_ck3_non_terminal_scan_is_never_verified(attestation_key) -> None:
    signer, trust = attestation_key
    material = base_report_material(
        signer=signer, findings=[report_finding("f1")], terminal_state="RUNNING"
    )
    result = verify_base_report(material, trust)
    assert isinstance(result, Refusal)


def test_ck3_report_states_what_it_could_not_do() -> None:
    """A silent gap reads as a clean bill of health, so gaps are declared."""
    from gryphon.verification.constants import EnrichmentContext, OrderingBasis

    limitations = declared_limitations(
        enrichment_context=EnrichmentContext.UNVERIFIED,
        ordering_basis=OrderingBasis.OBSERVED_SEVERITY,
        degraded_hosts=("app.example.test",),
        blocked_seconds=42.0,
        unsupported_classes=("no_verifier",),
    )
    joined = " ".join(limitations)
    assert "ordered by the severity observed" in joined
    assert "could not be verified" in joined
    assert "responding protectively" in joined
    assert "waited" in joined
    assert "unsupported" in joined


# =============================================================================
# CK-5 — identity and recovery
# =============================================================================


def test_ck5_execution_identity_changes_with_every_envelope_field(registry) -> None:
    """One identity means one request, or a conflict is undetectable.

    Scheme and port are included deliberately: a probe answered over a different
    scheme is a different observation, however similar the response looks.
    """
    from gryphon.tooling.observation.envelope import http_envelope

    salt = new_pass_salt()
    base = http_envelope(
        scheme="https",
        host="app.example.test",
        port=443,
        path="/.env",
        method="GET",
        descriptor_version="httpx/1.12.0",
        extractor_set_digest="x",
    )
    original = execution_id(
        pass_salt=salt,
        envelope=base,
        finding_id="f1",
        role=ObservationRole.PRIMARY,
        control_index=0,
    )

    variants = {
        "scheme": http_envelope(
            scheme="http",
            host="app.example.test",
            port=443,
            path="/.env",
            method="GET",
            descriptor_version="httpx/1.12.0",
            extractor_set_digest="x",
        ),
        "port": http_envelope(
            scheme="https",
            host="app.example.test",
            port=8443,
            path="/.env",
            method="GET",
            descriptor_version="httpx/1.12.0",
            extractor_set_digest="x",
        ),
        "path": base.with_path("/.env.bak"),
        "method": http_envelope(
            scheme="https",
            host="app.example.test",
            port=443,
            path="/.env",
            method="HEAD",
            descriptor_version="httpx/1.12.0",
            extractor_set_digest="x",
        ),
        "descriptor": http_envelope(
            scheme="https",
            host="app.example.test",
            port=443,
            path="/.env",
            method="GET",
            descriptor_version="httpx/1.13.0",
            extractor_set_digest="x",
        ),
        "extractors": http_envelope(
            scheme="https",
            host="app.example.test",
            port=443,
            path="/.env",
            method="GET",
            descriptor_version="httpx/1.12.0",
            extractor_set_digest="y",
        ),
    }
    for name, envelope in variants.items():
        changed = execution_id(
            pass_salt=salt,
            envelope=envelope,
            finding_id="f1",
            role=ObservationRole.PRIMARY,
            control_index=0,
        )
        assert changed != original, f"changing {name} did not change the execution identity"
        assert envelope.digest != base.digest, f"changing {name} did not change the envelope digest"


def test_ck5_identity_is_stable_for_the_same_envelope_and_salt() -> None:
    """Stability across resume is what lets a replay avoid re-contacting."""
    from gryphon.tooling.observation.envelope import http_envelope

    salt = new_pass_salt()
    envelope = http_envelope(
        scheme="https",
        host="app.example.test",
        port=443,
        path="/.env",
        method="GET",
        descriptor_version="httpx/1.12.0",
        extractor_set_digest="x",
    )
    first = execution_id(
        pass_salt=salt,
        envelope=envelope,
        finding_id="f1",
        role=ObservationRole.PRIMARY,
        control_index=0,
    )
    second = execution_id(
        pass_salt=salt,
        envelope=envelope,
        finding_id="f1",
        role=ObservationRole.PRIMARY,
        control_index=0,
    )
    assert first == second


def test_ck5_a_different_pass_cannot_predict_the_previous_identities() -> None:
    """Identities are keyed, so a target cannot anticipate the next control."""
    from gryphon.tooling.observation.envelope import http_envelope

    envelope = http_envelope(
        scheme="https",
        host="app.example.test",
        port=443,
        path="/.env",
        method="GET",
        descriptor_version="httpx/1.12.0",
        extractor_set_digest="x",
    )
    args = {
        "envelope": envelope,
        "finding_id": "f1",
        "role": ObservationRole.PRIMARY,
        "control_index": 0,
    }
    assert execution_id(pass_salt=new_pass_salt(), **args) != execution_id(
        pass_salt=new_pass_salt(), **args
    )


def test_ck5_subject_key_is_stable_across_scans() -> None:
    """The identity that outlives a scan is what makes re-verification possible."""
    first = subject_key(
        kind="http.response.summary",
        canonical_target="app.example.test",
        locator="/.env",
        finding_class="laravel-env",
    )
    second = subject_key(
        kind="http.response.summary",
        canonical_target="APP.EXAMPLE.TEST",
        locator="/.env",
        finding_class="laravel-env",
    )
    assert first == second
    other = subject_key(
        kind="http.response.summary",
        canonical_target="app.example.test",
        locator="/.env.bak",
        finding_class="laravel-env",
    )
    assert other != first


def test_ck5_possibly_applied_blocks_automatic_replay(registry) -> None:
    """Transport failure is not a rollback, and a new identity must not hide that."""
    from dataclasses import replace

    spec = registry.spec("exposed-config@1.0.0")
    assert spec is not None
    not_repeat_safe = replace(spec, repeat_safe=False)
    verdict = ProofEvaluator().evaluate(
        not_repeat_safe,
        observation("p", facts=http_facts()),
        [],
        subject_possibly_applied=True,
    )
    assert verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.justification is Justification.REPLAY_REQUIRES_DECISION
    assert verdict.possibly_applied is True


# =============================================================================
# CK-6 — the verifier shapes that must work
# =============================================================================


def test_ck6_dangling_record_confirms_from_an_authoritative_negative(registry) -> None:
    """The case the previous destination model made impossible.

    A dangling CNAME is, by definition, a name that does not resolve. A gateway
    that required the subject to resolve before running the resolver query
    denied exactly this observation — so the only takeover verifier could never
    confirm anything.
    """
    spec = registry.spec("dangling-dns@1.0.0")
    assert spec is not None
    assert spec.controls.count == 0, "an authoritative negative answer is its own control"

    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=dns_facts(rcode="NXDOMAIN")),
        [],
    )
    assert verdict.status is VerdictStatus.CONFIRMED
    assert verdict.projection["dns"]["rcode"] == "NXDOMAIN"


def test_ck6_a_resolving_name_is_not_a_dangling_record(registry) -> None:
    spec = registry.spec("dangling-dns@1.0.0")
    verdict = ProofEvaluator().evaluate(
        spec,
        observation("p", facts=dns_facts(rcode="NOERROR", a_records=("203.0.113.10",))),
        [],
    )
    assert verdict.status is VerdictStatus.NOT_REPRODUCED


def test_ck6_a_chain_ending_outside_the_pinned_provider_list_is_not_confirmed(
    registry,
) -> None:
    """Provider fingerprints are signals whose statuses change.

    The list is pinned and entered only by review, so a chain terminating
    somewhere unreviewed is not a confirmation.
    """
    spec = registry.spec("dangling-dns@1.0.0")
    verdict = ProofEvaluator().evaluate(
        spec,
        observation(
            "p", facts=dns_facts(rcode="NXDOMAIN", chain=("a.example.test", "unknown.example"))
        ),
        [],
    )
    assert verdict.status is not VerdictStatus.CONFIRMED


def test_ck6_a_query_bearing_finding_is_unsupported_at_resolve_time(registry) -> None:
    """It fails at the registry, not at dispatch.

    The gateway's path canonicalizer rejects a query outright. Surfacing that as
    a scope denial would point an operator at a grant that is perfectly correct;
    the honest answer is that the class is not representable in this verifier
    set.
    """
    finding = Finding(
        finding_id="f1",
        observation_type="exposed_config",
        canonical_target="app.example.test",
        template_id="laravel-env",
        url="https://app.example.test/dump?file=.env",
    )
    resolved = registry.resolve(finding)
    assert isinstance(resolved, Unsupported)
    assert resolved.justification is Justification.UNREPRESENTABLE_TARGET

    verdict = ProofEvaluator().evaluate(None, None, unsupported=resolved.justification)
    assert verdict.status is VerdictStatus.UNSUPPORTED
    assert verdict.rule == 0


def test_ck6_unmapped_class_is_unsupported_not_silently_skipped(registry) -> None:
    finding = Finding(
        finding_id="f1",
        observation_type="something_nobody_reviewed",
        canonical_target="app.example.test",
    )
    resolved = registry.resolve(finding)
    assert isinstance(resolved, Unsupported)
    assert resolved.justification is Justification.NO_VERIFIER


# =============================================================================
# Planner: controls are unpredictable, structurally different, and bounded
# =============================================================================


def test_controls_are_unpredictable_and_structurally_different(registry) -> None:
    """Two shapes, keyed, so an unstable host shows up as disagreement.

    A predictable locator is one a host that wanted to look clean could
    special-case. Deriving it from the pass salt — rather than from a timestamp,
    as some well-known calibration implementations do — removes that option.
    """
    planner = ObservationPlanner(
        registry=registry,
        descriptor_versions={
            "http.response.summary": "httpx/1.12.0",
            "dns.answer": "dnsx/1.3.1",
        },
        extractor_set_digest="x",
        resolver_set_digest="r",
    )
    findings = findings_from([report_finding("f1")])
    salt_a, salt_b = new_pass_salt(), new_pass_salt()

    plan_a = planner.plan(findings, pass_salt=salt_a, pass_id="pa")
    plan_b = planner.plan(findings, pass_salt=salt_b, pass_id="pb")

    paths_a = [c.envelope.path for c in plan_a.findings[0].controls]
    paths_b = [c.envelope.path for c in plan_b.findings[0].controls]

    assert len(paths_a) == 2
    assert paths_a != paths_b, "control locators must not be predictable across passes"
    assert paths_a[0] != paths_a[1]
    # One sibling file, one sibling directory: different in structure, not only
    # in name, so a host that behaves differently per depth is detected.
    assert paths_a[0].count("/") == 1
    assert paths_a[1].count("/") == 2


def test_planner_is_deterministic_for_the_same_salt(registry) -> None:
    """Determinism is what makes a resumed pass avoid duplicate traffic."""
    planner = ObservationPlanner(
        registry=registry,
        descriptor_versions={
            "http.response.summary": "httpx/1.12.0",
            "dns.answer": "dnsx/1.3.1",
        },
        extractor_set_digest="x",
        resolver_set_digest="r",
    )
    findings = findings_from([report_finding("f1"), report_finding("f2")])
    salt = new_pass_salt()
    first = planner.plan(findings, pass_salt=salt, pass_id="p")
    second = planner.plan(findings, pass_salt=salt, pass_id="p")
    assert [o.execution_id for f in first.findings for o in f.observations] == [
        o.execution_id for f in second.findings for o in f.observations
    ]
