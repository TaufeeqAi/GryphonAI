"""Generate a distinct grant-signing and audit-signing Ed25519 key set.

Run ONCE per deployment and store the private keys securely (§19.4). The grant
and audit keys are generated independently so they are distinct (SEC-014). The
public keys are printed as ``kid -> hex`` trusted-key maps for the verifier.

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

    grant_priv, grant_pub = _new_keypair()
    audit_priv, audit_pub = _new_keypair()

    print("# ---- GRYPHON key material (store securely; never commit) ----")
    print(f'GRYPHON_GRANT_KID={grant_kid}')
    print(f"GRYPHON_GRANT_SIGNING_KEY_HEX={grant_priv}")
    print(f'GRYPHON_GRANT_TRUSTED_PUBLIC_KEYS={{"{grant_kid}": "{grant_pub}"}}')
    print()
    print(f'GRYPHON_AUDIT_KID={audit_kid}')
    print(f"GRYPHON_AUDIT_SIGNING_KEY_HEX={audit_priv}")
    print(f'GRYPHON_AUDIT_TRUSTED_PUBLIC_KEYS={{"{audit_kid}": "{audit_pub}"}}')


if __name__ == "__main__":
    main()
