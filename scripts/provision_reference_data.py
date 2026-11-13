"""Provision the pinned, offline ATT&CK reference data.

Two source files are pinned by SHA-256 and byte size to immutable commit URLs
(see ``gryphon/enrichment/reference.py``): the MITRE ATT&CK Enterprise STIX
bundle and the CTID KEV→ATT&CK mapping file. This script verifies each against
its pin, builds compact indexes and writes a manifest. The enrichment process
itself never fetches reference data.

    # from files you downloaded and reviewed yourself
    python -m scripts.provision_reference_data \
        --attack-bundle enterprise-attack-20.1.json \
        --ctid-map kev-07.28.2025_attack-16.1-enterprise.json

    # or let the script download the pinned URLs (verified before use)
    python -m scripts.provision_reference_data --download

This runs as a separate, key-less provisioning step: it is the only reference
code path with an HTTP client, and nothing it downloads is used unless the
digest and size match the pin exactly.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from gryphon.enrichment.reasons import ArtifactIntegrityError
from gryphon.enrichment.reference import (
    PINNED_ATTACK_BUNDLE,
    PINNED_CTID_KEV_MAP,
    PinnedDataset,
    load_reference,
    provision,
)
from gryphon.enrichment.settings import get_enrichment_settings

_CHUNK = 1 << 20
_TIMEOUT_SECONDS = 120


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Commit-pinned URLs never redirect; a redirect is refused, not followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            req.full_url, code, f"refused redirect to {newurl}", headers, fp
        )


def download_pinned(pin: PinnedDataset, dest_dir: Path) -> Path:
    """Stream a pinned file to disk, enforcing its size and digest."""
    if not pin.url.startswith("https://"):
        raise ArtifactIntegrityError(f"{pin.name}: pinned URL is not HTTPS")
    opener = urllib.request.build_opener(_NoRedirect)
    # The scheme is checked above: only https:// pins are ever opened.
    request = urllib.request.Request(  # noqa: S310
        pin.url, headers={"User-Agent": "gryphon-reference-provisioner/1"}
    )
    target = dest_dir / Path(pin.url).name
    digest = hashlib.sha256()
    received = 0
    with opener.open(request, timeout=_TIMEOUT_SECONDS) as response, target.open("wb") as out:
        while True:
            chunk = response.read(_CHUNK)
            if not chunk:
                break
            received += len(chunk)
            if received > pin.size:
                raise ArtifactIntegrityError(f"{pin.name}: larger than the pinned {pin.size} bytes")
            digest.update(chunk)
            out.write(chunk)
    if received != pin.size:
        raise ArtifactIntegrityError(f"{pin.name}: {received} bytes, pinned {pin.size}")
    if digest.hexdigest() != pin.sha256:
        raise ArtifactIntegrityError(f"{pin.name}: digest does not match the pin")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--attack-bundle", type=Path, help="local ATT&CK Enterprise STIX bundle")
    parser.add_argument("--ctid-map", type=Path, help="local CTID KEV mapping JSON")
    parser.add_argument("--download", action="store_true", help="download the pinned URLs")
    parser.add_argument(
        "--out", type=Path, help="output directory (default: settings.reference_dir)"
    )
    args = parser.parse_args(argv)

    out_dir = args.out or get_enrichment_settings().reference_dir
    workdir: Path | None = None
    try:
        if args.download:
            workdir = Path(tempfile.mkdtemp(prefix="gryphon-reference-"))
            print(f"downloading {PINNED_ATTACK_BUNDLE.name} ({PINNED_ATTACK_BUNDLE.size:,} bytes)")
            attack = download_pinned(PINNED_ATTACK_BUNDLE, workdir)
            print(f"downloading {PINNED_CTID_KEV_MAP.name} ({PINNED_CTID_KEV_MAP.size:,} bytes)")
            ctid = download_pinned(PINNED_CTID_KEV_MAP, workdir)
        elif args.attack_bundle and args.ctid_map:
            attack, ctid = args.attack_bundle, args.ctid_map
        else:
            parser.error("pass --download, or both --attack-bundle and --ctid-map")
            return 2
        manifest = provision(attack_bundle_path=attack, ctid_map_path=ctid, out_dir=out_dir)
    except (ArtifactIntegrityError, OSError, ValueError) as exc:
        print(f"provisioning refused: {exc}", file=sys.stderr)
        return 1
    finally:
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)

    loaded = load_reference(out_dir)
    print(f"wrote {out_dir}")
    for name, entry in sorted(manifest["datasets"].items()):
        print(f"  {name:<14} {entry['version']:<40} sha256 {entry['source_sha256'][:16]}…")
    print(f"verified load: {getattr(loaded, 'snapshot_id', None) or loaded}")
    return 0 if hasattr(loaded, "snapshot_id") else 1


if __name__ == "__main__":
    sys.exit(main())
