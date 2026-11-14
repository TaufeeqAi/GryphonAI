"""Generate a distinct grant-signing and audit-signing Ed25519 key set.

Run ONCE per deployment and store the private keys securely (§19.4). The grant
and audit keys are generated independently so they are distinct (SEC-014). The
public keys are printed as ``kid -> hex`` trusted-key maps for the verifier.

Five purposes, five independent keys: grant, audit, capability, enrichment and
verification. The enrichment and verification layers each refuse to start if
their key shares a kid or a public key with any of the others — a layer that
signs with the key it also verifies against can attest to its own conclusions.

    python -m scripts.generate_keys

Copy the emitted lines into your ``.env`` (never commit real keys).
"""

from __future__ import annotations

from datetime import date

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def _new_keypair() -> tuple[str, str]:
    private = ed25519.Ed25519PrivateKey.generate()
    priv_hex = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    pub_hex = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv_hex, pub_hex


def main() -> None:
    stamp = date.today().strftime("%Y-%m")
    grant_kid = f"grant-key-{stamp}"
    audit_kid = f"audit-key-{stamp}"
    capability_kid = f"capability-key-{stamp}"
    enrichment_kid = f"enrichment-key-{stamp}"
    verification_kid = f"verification-key-{stamp}"

    grant_priv, grant_pub = _new_keypair()
    audit_priv, audit_pub = _new_keypair()
    capability_priv, capability_pub = _new_keypair()
    enrichment_priv, enrichment_pub = _new_keypair()
    verification_priv, verification_pub = _new_keypair()

    print("# ---- GRYPHON key material (store securely; never commit) ----")
    print(f'GRYPHON_GRANT_KID={grant_kid}')
    print(f"GRYPHON_GRANT_SIGNING_KEY_HEX={grant_priv}")
    print(f'GRYPHON_GRANT_TRUSTED_PUBLIC_KEYS={{"{grant_kid}": "{grant_pub}"}}')
    print()
    print(f'GRYPHON_AUDIT_KID={audit_kid}')
    print(f"GRYPHON_AUDIT_SIGNING_KEY_HEX={audit_priv}")
    print(f'GRYPHON_AUDIT_TRUSTED_PUBLIC_KEYS={{"{audit_kid}": "{audit_pub}"}}')
    print()
    # Capability signing key — MUST be distinct from the grant and audit keys.
    print(f'GRYPHON_CAPABILITY_KID={capability_kid}')
    print(f"GRYPHON_CAPABILITY_SIGNING_KEY_HEX={capability_priv}")
    print(f'GRYPHON_CAPABILITY_TRUSTED_PUBLIC_KEYS={{"{capability_kid}": "{capability_pub}"}}')
    print()
    # Enrichment attestation key — dedicated; signs enrichment reports and
    # snapshot acceptances only. MUST be distinct from all keys above.
    print(f"GRYPHON_ENRICHMENT_KID={enrichment_kid}")
    print(f"GRYPHON_ENRICHMENT_SIGNING_KEY_HEX={enrichment_priv}")
    print(
        f'GRYPHON_ENRICHMENT_TRUSTED_PUBLIC_KEYS={{"{enrichment_kid}": "{enrichment_pub}"}}'
    )
    print()
    # Verification attestation key — dedicated; signs verification verdicts only.
    # MUST be distinct from all keys above: the layer refuses to start if its kid
    # appears in any trust store it checks against, because a signer that is also
    # a trusted verifier of its own output can attest to whatever it concludes.
    print(f"GRYPHON_VERIFICATION_KID={verification_kid}")
    print(f"GRYPHON_VERIFICATION_SIGNING_KEY_HEX={verification_priv}")
    print(
        f'GRYPHON_VERIFICATION_TRUSTED_PUBLIC_KEYS={{"{verification_kid}": "{verification_pub}"}}'
    )
    print()
    # The verification layer must also be given the ENRICHMENT public key, so it
    # can check enrichment context it consumes without being able to mint it:
    enrichment_map = f'{{"{enrichment_kid}": "{enrichment_pub}"}}'
    print(f"GRYPHON_VERIFICATION_ENRICHMENT_TRUSTED_PUBLIC_KEYS={enrichment_map}")


if __name__ == "__main__":
    main()
