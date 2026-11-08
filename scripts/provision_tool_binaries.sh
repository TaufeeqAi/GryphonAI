#!/bin/bash
# =============================================================================
# Provision the pinned ProjectDiscovery binaries (Linux x86-64).
# =============================================================================
# Downloads each pinned release archive, verifies it against the publisher's own
# checksums file, extracts the binary to an absolute path, and writes the tool
# manifest with the installed binary's real SHA-256.
#
#   sudo scripts/provision_tool_binaries.sh                 # all seven
#   sudo scripts/provision_tool_binaries.sh naabu katana    # just these
#
# Environment:
#   GRYPHON_TOOL_BIN_DIR        default /opt/gryphon/bin
#   GRYPHON_TOOL_MANIFEST_PATH  default /opt/gryphon/tool-manifest.json
#
# This contacts GitHub release downloads only; it never contacts a scan target.
# `@latest` is never used: every version below is pinned, and a checksum
# mismatch aborts that tool rather than installing it.
#
# Note: the checksums filename differs per project, so several conventions are
# tried. Verify the result with:  python -m scripts.verify_tool_binaries
# =============================================================================
set -uo pipefail

BIN="${GRYPHON_TOOL_BIN_DIR:-/opt/gryphon/bin}"
MANIFEST="${GRYPHON_TOOL_MANIFEST_PATH:-/opt/gryphon/tool-manifest.json}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN}" "$(dirname "${MANIFEST}")"

# Versions confirmed live from the publisher's releases on 2026-11-08.
# Bumping one is a compatibility review item: re-run verify_tool_binaries.
ALL_TOOLS=(
  "subfinder:2.17.0"
  "httpx:1.12.0"
  "naabu:2.7.0"
  "katana:1.8.0"
  "dnsx:1.3.1"
  "tlsx:1.4.0"
  "nuclei:3.11.1"
)

WANTED=("$@")
selected() {
  [ ${#WANTED[@]} -eq 0 ] && return 0
  local tool="$1"
  for want in "${WANTED[@]}"; do [ "${want}" = "${tool}" ] && return 0; done
  return 1
}

for cmd in curl unzip sha256sum; do
  command -v "${cmd}" >/dev/null || { echo "missing required command: ${cmd}" >&2; exit 2; }
done

declare -A INSTALLED=()
# Preserve entries for tools we are not re-provisioning in this run.
if [ -f "${MANIFEST}" ] && [ ${#WANTED[@]} -gt 0 ]; then
  while IFS=$'\t' read -r t v p s; do
    [ -n "${t}" ] && INSTALLED["${t}"]="${v}"$'\t'"${p}"$'\t'"${s}"
  done < <(python3 - "${MANIFEST}" <<'PY'
import json, sys
for e in json.load(open(sys.argv[1]))["entries"]:
    print(e["tool_id"], e["version"], e["path"], e["sha256"], sep="\t")
PY
)
fi

failures=0
for pair in "${ALL_TOOLS[@]}"; do
  tool="${pair%%:*}"
  version="${pair##*:}"
  selected "${tool}" || continue

  zip="${tool}_${version}_linux_amd64.zip"
  base="https://github.com/projectdiscovery/${tool}/releases/download/v${version}"
  echo "== ${tool} v${version} =="

  # The checksums filename is not consistent across these projects.
  expected=""
  for sums in "${tool}_${version}_checksums.txt" "${tool}-checksums.txt" \
              "${tool}-${version}-checksums.txt" "checksums.txt"; do
    if curl -fsSL --retry 2 -o "${WORK}/sums.txt" "${base}/${sums}" 2>/dev/null; then
      expected="$(grep -E "[ *]${zip}\$" "${WORK}/sums.txt" | awk '{print $1}' | head -1)"
      [ -n "${expected}" ] && { echo "   checksums: ${sums}"; break; }
    fi
  done
  if [ -z "${expected}" ]; then
    echo "   FAILED: no published checksum found for ${zip}"
    failures=$((failures + 1))
    continue
  fi

  if ! curl -fsSL --retry 2 -o "${WORK}/${zip}" "${base}/${zip}"; then
    echo "   FAILED: download of ${zip}"
    failures=$((failures + 1))
    continue
  fi
  actual="$(sha256sum "${WORK}/${zip}" | awk '{print $1}')"
  if [ "${actual}" != "${expected}" ]; then
    echo "   FAILED: checksum mismatch (expected ${expected}, got ${actual})"
    failures=$((failures + 1))
    continue
  fi
  echo "   archive verified against the publisher's checksum"

  rm -f "${BIN}/${tool}"
  unzip -o -q -j "${WORK}/${zip}" "${tool}" -d "${BIN}" 2>/dev/null \
    || unzip -o -q -j "${WORK}/${zip}" -d "${BIN}"
  chmod 0755 "${BIN}/${tool}"
  binsum="$(sha256sum "${BIN}/${tool}" | awk '{print $1}')"
  echo "   installed ${BIN}/${tool}"
  INSTALLED["${tool}"]="${version}"$'\t'"${BIN}/${tool}"$'\t'"${binsum}"
done

# Emit the manifest.
{
  echo '{'
  echo '  "entries": ['
  first=1
  for tool in "${!INSTALLED[@]}"; do
    IFS=$'\t' read -r version path sum <<<"${INSTALLED[$tool]}"
    [ ${first} -eq 0 ] && echo ','
    printf '    {"tool_id": "%s", "version": "%s", "path": "%s", "sha256": "%s"}' \
      "${tool}" "${version}" "${path}" "${sum}"
    first=0
  done
  echo
  echo '  ]'
  echo '}'
} > "${MANIFEST}"

echo
echo "manifest: ${MANIFEST} (${#INSTALLED[@]} entries, ${failures} failures)"
echo "next: python -m scripts.verify_tool_binaries --manifest ${MANIFEST}"
[ ${failures} -eq 0 ]
