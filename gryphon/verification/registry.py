"""The verifier registry: what may be verified, and how.

The registry is the product. Everything else in this layer is machinery for
executing it honestly, and the layer's value grows only as reviewed verifiers do.
That is why it is treated as a governed artifact rather than a configuration
file:

* **Signed, with a named reviewer.** A digest gives integrity and identity, not
  authority. Without a signature, any process that can write a file and restart
  a service can redefine what CONFIRMED means, and the report will faithfully
  print the new digest. The policy signing key is deliberately *not* the
  verification key: whoever writes the policy is not the verifier.
* **Validated at load, never at dispatch.** A spec that could derive a target
  the gateway cannot express, that omits a control strategy for a claim that
  needs one, or that names an unreviewed endpoint class is rejected when the
  registry loads. Surfacing those as refusals mid-pass would point an operator
  at a grant or a host that is perfectly fine.
* **Keyed on explicit identifiers.** Classes map by observation type and
  template id — never by template tags, whose vocabulary belongs to an upstream
  project and changes without notice.
* **Lifecycle-aware.** A verifier version can be withdrawn, and withdrawal does
  not edit the verdicts it produced; it retracts them. For a layer that sells
  proof, "what happens to the proofs we already issued when the prover turns out
  to be wrong?" cannot be undefined.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from gryphon.auth.key_provider import TrustedKeyStore
from gryphon.canonical import canonical_json_bytes, sha256_hex
from gryphon.verification.constants import (
    MAX_CONTROLS_PER_FINDING,
    ClaimScope,
    ControlStrategy,
    Justification,
    ObservationKind,
    SafeReadClass,
    VerifierLifecycle,
)
from gryphon.verification.reasons import RegistryError
from gryphon.verification.spec import (
    ControlPlan,
    Predicate,
    ProjectionSpec,
    SpecError,
    VerifierSpec,
)

REGISTRY_FORMAT_VERSION: Final[str] = "1"
#: Where the packaged registry lives when a deployment does not override it.
DEFAULT_REGISTRY_PATH: Final[Path] = Path(__file__).with_name("registry_v1.json")


@dataclass(frozen=True, slots=True)
class Finding:
    """The subset of a verified finding this layer reasons about."""

    finding_id: str
    observation_type: str
    canonical_target: str
    template_id: str | None = None
    url: str | None = None
    port: int | None = None
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class Unsupported:
    """The registry declined, with a reason the deliverable can print."""

    justification: Justification
    registry_digest: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class RegistryApproval:
    """Who signed off on this registry, and who reviewed it."""

    reviewer: str
    approved_at: str
    signer_kid: str | None = None
    signature_b64: str | None = None

    @property
    def is_signed(self) -> bool:
        return bool(self.signer_kid and self.signature_b64)


class VerifierRegistry:
    """A loaded, validated, digest-identified registry."""

    def __init__(
        self,
        *,
        verifiers: Mapping[str, VerifierSpec],
        class_map: Mapping[str, str],
        template_map: Mapping[str, str],
        approval: RegistryApproval,
        digest: str,
        provider_list_digest: str,
    ) -> None:
        self._verifiers = dict(verifiers)
        self._class_map = dict(class_map)
        self._template_map = dict(template_map)
        self._approval = approval
        self._digest = digest
        self._provider_list_digest = provider_list_digest

    # -- identity -------------------------------------------------------------
    @property
    def digest(self) -> str:
        return self._digest

    @property
    def approval(self) -> RegistryApproval:
        return self._approval

    @property
    def provider_list_digest(self) -> str:
        return self._provider_list_digest

    @property
    def verifier_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._verifiers))

    def spec(self, verifier_id: str) -> VerifierSpec | None:
        return self._verifiers.get(verifier_id)

    def signal_tokens(self, verifier_id: str) -> tuple[str, ...]:
        spec = self._verifiers.get(verifier_id)
        return spec.signal_tokens if spec else ()

    # -- resolution -----------------------------------------------------------
    def resolve(self, finding: Finding) -> VerifierSpec | Unsupported:
        """Pick the verifier for a finding, or say why there is none.

        Template id wins over observation type: it is the more specific claim,
        and a registry that mapped broadly by type would quietly verify classes
        nobody reviewed.
        """
        verifier_id: str | None = None
        if finding.template_id:
            verifier_id = self._template_map.get(finding.template_id)
        if verifier_id is None:
            verifier_id = self._class_map.get(finding.observation_type)
        if verifier_id is None:
            return Unsupported(
                justification=Justification.NO_VERIFIER,
                registry_digest=self._digest,
                detail=finding.template_id or finding.observation_type,
            )

        spec = self._verifiers.get(verifier_id)
        if spec is None:
            # A mapping that names a verifier the document does not define is a
            # malformed registry, which load() rejects; reaching here means the
            # object was built by hand.
            raise RegistryError(f"mapping points at unknown verifier {verifier_id!r}")

        if spec.safe_read_class is not SafeReadClass.REVIEWED_SAFE_READ:
            return Unsupported(
                justification=Justification.UNREVIEWED_CLASS,
                registry_digest=self._digest,
                detail=verifier_id,
            )
        if spec.lifecycle is VerifierLifecycle.WITHDRAWN:
            return Unsupported(
                justification=Justification.NO_VERIFIER,
                registry_digest=self._digest,
                detail=f"{verifier_id} is withdrawn",
            )
        if spec.kind is ObservationKind.HTTP_RESPONSE_SUMMARY and _carries_query(finding.url):
            # Phase-1 scope policy has no canonical query, and the gateway's
            # canonicalizer rejects one outright. The honest answer is that this
            # class is not representable in verifier set v1 — not that the
            # operator's grant excluded it.
            return Unsupported(
                justification=Justification.UNREPRESENTABLE_TARGET,
                registry_digest=self._digest,
                detail="the observed URL carries a query string",
            )
        return spec

    # -- construction ---------------------------------------------------------
    @classmethod
    def load(
        cls,
        path: Path,
        *,
        trust: TrustedKeyStore | None = None,
        require_signature: bool = False,
    ) -> VerifierRegistry:
        """Load, verify and validate a registry document.

        ``require_signature`` is true in production. A deployment that starts
        with an unsigned registry has no authority behind its definition of
        proof, however correct the document happens to be.
        """
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise RegistryError(f"registry {path} could not be read: {exc}") from exc
        try:
            document = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RegistryError(f"registry {path} is not valid JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise RegistryError("a registry document must be a JSON object")
        return cls.from_document(document, trust=trust, require_signature=require_signature)

    @classmethod
    def from_document(
        cls,
        document: Mapping[str, Any],
        *,
        trust: TrustedKeyStore | None = None,
        require_signature: bool = False,
    ) -> VerifierRegistry:
        version = str(document.get("registry_format_version", ""))
        if version != REGISTRY_FORMAT_VERSION:
            raise RegistryError(f"unsupported registry format version {version!r}")

        body = document.get("body")
        if not isinstance(body, dict):
            raise RegistryError("a registry document needs a body object")

        digest = sha256_hex(canonical_json_bytes(body))
        approval = _approval_from(document)

        if require_signature:
            if not approval.is_signed:
                raise RegistryError(
                    "production requires a signed registry: a digest proves integrity, "
                    "not authority"
                )
            if trust is None:
                raise RegistryError("a trust store is required to verify a signed registry")
            _verify_signature(digest, approval, trust)

        providers = tuple(sorted(str(p).lower().rstrip(".") for p in body.get("providers", [])))
        provider_list_digest = sha256_hex(canonical_json_bytes(list(providers)))

        verifiers: dict[str, VerifierSpec] = {}
        raw_verifiers = body.get("verifiers")
        if not isinstance(raw_verifiers, list) or not raw_verifiers:
            raise RegistryError("a registry needs at least one verifier")
        for raw in raw_verifiers:
            spec = _spec_from(raw, providers=providers)
            if spec.verifier_id in verifiers:
                raise RegistryError(f"duplicate verifier {spec.verifier_id!r}")
            verifiers[spec.verifier_id] = spec

        class_map = _mapping_from(body.get("class_map", {}), verifiers, "class_map")
        template_map = _mapping_from(body.get("template_map", {}), verifiers, "template_map")
        if not class_map and not template_map:
            raise RegistryError("a registry with no mappings can never verify anything")

        return cls(
            verifiers=verifiers,
            class_map=class_map,
            template_map=template_map,
            approval=approval,
            digest=digest,
            provider_list_digest=provider_list_digest,
        )


# =============================================================================
# Parsing helpers
# =============================================================================


def _carries_query(url: str | None) -> bool:
    return bool(url) and ("?" in str(url) or "#" in str(url))


def _approval_from(document: Mapping[str, Any]) -> RegistryApproval:
    raw = document.get("approval")
    if not isinstance(raw, dict):
        raise RegistryError("a registry document needs an approval block with a named reviewer")
    reviewer = str(raw.get("reviewer", "")).strip()
    if not reviewer:
        raise RegistryError("the approval block must name a reviewer")
    return RegistryApproval(
        reviewer=reviewer,
        approved_at=str(raw.get("approved_at", "")),
        signer_kid=(str(raw["signer_kid"]) if raw.get("signer_kid") else None),
        signature_b64=(str(raw["signature_b64"]) if raw.get("signature_b64") else None),
    )


def _verify_signature(digest: str, approval: RegistryApproval, trust: TrustedKeyStore) -> None:
    import base64

    from cryptography.exceptions import InvalidSignature

    assert approval.signer_kid is not None  # noqa: S101 - checked by the caller
    assert approval.signature_b64 is not None  # noqa: S101 - checked by the caller
    public_key = trust.get(approval.signer_kid)
    if public_key is None:
        raise RegistryError(f"registry signer {approval.signer_kid!r} is not trusted")
    try:
        signature = base64.standard_b64decode(approval.signature_b64)
    except (ValueError, TypeError) as exc:
        raise RegistryError("registry signature is not valid base64") from exc
    try:
        public_key.verify(signature, digest.encode("ascii"))
    except InvalidSignature as exc:
        raise RegistryError("registry signature does not verify against its digest") from exc


def _mapping_from(
    raw: Any, verifiers: Mapping[str, VerifierSpec], label: str
) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise RegistryError(f"{label} must be an object")
    out: dict[str, str] = {}
    for key, value in raw.items():
        verifier_id = str(value)
        if verifier_id not in verifiers:
            raise RegistryError(f"{label}[{key!r}] names unknown verifier {verifier_id!r}")
        out[str(key)] = verifier_id
    return out


def _spec_from(raw: Any, *, providers: Sequence[str]) -> VerifierSpec:
    if not isinstance(raw, dict):
        raise RegistryError("each verifier must be an object")
    try:
        kind = ObservationKind(raw["kind"])
        controls = _controls_from(raw.get("controls", {}))
        predicate = _predicate_from(raw.get("predicate"), providers=providers)
        refutation = _predicate_from(raw.get("refutation"), providers=providers)
        projection = _projection_from(raw.get("projection", {}))
        return VerifierSpec(
            verifier_id=str(raw["verifier_id"]),
            lifecycle=VerifierLifecycle(raw.get("lifecycle", "active")),
            kind=kind,
            claim_scope=ClaimScope(raw["claim_scope"]),
            can_confirm=bool(raw["can_confirm"]),
            can_refute=bool(raw["can_refute"]),
            safe_read_class=SafeReadClass(raw["safe_read_class"]),
            repeat_safe=bool(raw["repeat_safe"]),
            method=str(raw["method"]),
            predicate=predicate,
            refutation=refutation,
            controls=controls,
            projection=projection,
            signal_tokens=tuple(str(t) for t in raw.get("signal_tokens", [])),
            record_types=tuple(str(r).upper() for r in raw.get("record_types", [])),
            description=str(raw.get("description", "")),
        )
    except KeyError as exc:
        raise RegistryError(f"verifier is missing required field {exc}") from exc
    except (SpecError, ValueError) as exc:
        raise RegistryError(f"verifier is not admissible: {exc}") from exc


def _controls_from(raw: Any) -> ControlPlan:
    if not isinstance(raw, dict):
        raise RegistryError("controls must be an object")
    strategy = ControlStrategy(raw.get("strategy", "none"))
    count = int(raw.get("count", 0))
    if count > MAX_CONTROLS_PER_FINDING:
        raise RegistryError(
            f"a verifier may request at most {MAX_CONTROLS_PER_FINDING} controls; "
            "controls are requests too, and their cost lands on the client's host"
        )
    return ControlPlan(
        strategy=strategy,
        count=count,
        reason=(str(raw["reason"]) if raw.get("reason") else None),
    )


def _predicate_from(raw: Any, *, providers: Sequence[str]) -> Predicate | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise RegistryError("a predicate must be a list of clauses")
    clauses: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RegistryError("each predicate clause must be an object")
        clause = dict(item)
        # The provider list lives once in the document; a clause that needs it
        # refers to it rather than repeating it, so one review covers one list.
        if clause.get("clause") == "cname_terminates_in_provider" and "providers" not in clause:
            clause["providers"] = list(providers)
        clauses.append(clause)
    return Predicate.from_payload(clauses)


def _projection_from(raw: Any) -> ProjectionSpec:
    if not isinstance(raw, dict):
        raise RegistryError("projection must be an object")
    return ProjectionSpec(
        include_dotenv_keys=bool(raw.get("include_dotenv_keys", False)),
        include_secret_counts=bool(raw.get("include_secret_counts", True)),
        include_tokens=bool(raw.get("include_tokens", False)),
        include_header_names=bool(raw.get("include_header_names", True)),
        include_dns_chain=bool(raw.get("include_dns_chain", False)),
        max_keys=int(raw.get("max_keys", 200)),
    )
