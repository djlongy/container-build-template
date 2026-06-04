#!/usr/bin/env bash
# ─── DO NOT EDIT — template scan job ───────────────────────────────
# Behaviour comes from image.env (SBOM_SCAN_REF / SBOM_TARGET /
# SYFT_VERSION / SYFT_INSTALLER_URL). Edit those, not this file.
# ───────────────────────────────────────────────────────────────────
#
# scripts/scan/syft-sbom.sh — Anchore Syft CycloneDX SBOM emitter
#
# Single responsibility: run `syft <target> -o cyclonedx-json=...`
# and produce the canonical sbom.cdx.json. Hands off to
# scripts/ingest/sbom-post.sh for vendor-neutral sink shipping (Splunk,
# Dependency-Track, Artifactory, webhook).
#
# Output filename is the SAME as scripts/scan/xray-sbom.sh — both
# write sbom.cdx.json by default. That's the artifact contract:
# downstream stages (Grype, sbom-post) consume sbom.cdx.json without
# caring which generator produced it. Swap one for the other by
# changing the script name in the CI YAML; nothing else needs to move.
#
# Usage:
#   bash scripts/scan/syft-sbom.sh                 # SBOM of the BUILT image
#                                                  # (IMAGE_DIGEST from
#                                                  #  build.env, fallback
#                                                  #  chain below)
#   bash scripts/scan/syft-sbom.sh <image-ref>     # SBOM of arbitrary ref
#   bash scripts/scan/syft-sbom.sh dir:./          # SBOM of source tree
#                                                  # (override SBOM_TARGET)
#
# Scan target resolution (highest precedence first):
#   1. positional arg $1
#   2. SBOM_SCAN_REF env var (explicit override)
#   3. SBOM_TARGET=source → dir:${PROJECT_ROOT}
#   4. IMAGE_DIGEST   (from build.env — the rebuilt image's digest)
#   5. IMAGE_REF      (from build.env — the rebuilt image's tag)
#   6. UPSTREAM_REF   (from image.env — the upstream we rebuilt from)
#   7. UPSTREAM_REGISTRY/UPSTREAM_IMAGE:UPSTREAM_TAG (assembled if all set)
#
# Default targets the BUILT image (consumers pull THAT, not upstream).
#
# Required env: none (the script auto-installs syft if missing).
#
# Optional env:
#   SBOM_SCAN_REF             override the resolved target (parallels XRAY_SCAN_REF)
#   SBOM_TARGET               "image" (default) | "source" — switches to dir:${PROJECT_ROOT}
#   SBOM_FILE                 output path (default sbom.cdx.json — the canonical name)
#   SYFT_INSTALLER_URL        installer URL (default: GitHub raw)
#   SYFT_VERSION              default v1.14.0
#
# Exit codes: 0 on success (incl. graceful fallbacks); 1 on missing
# scan target or unrecoverable syft failure.

set -euo pipefail

TEMPLATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
export TEMPLATE_ROOT PROJECT_ROOT
cd "${PROJECT_ROOT}"

# shellcheck source=../lib/scan-common.sh
. "${TEMPLATE_ROOT}/scripts/lib/scan-common.sh"
scan_bootstrap

# ── Resolve scan target ─────────────────────────────────────────────
# SBOM_TARGET=source scans the working tree (dir:) when no explicit ref
# is given; otherwise resolve via the shared chain ($1 > SBOM_SCAN_REF >
# IMAGE_DIGEST > IMAGE_REF > UPSTREAM_REF > assembled-upstream).
SBOM_TARGET="$(printf '%s' "${SBOM_TARGET:-image}" | tr '[:upper:]' '[:lower:]')"
if [ "${SBOM_TARGET}" = "source" ] && [ -z "${1:-}" ] && [ -z "${SBOM_SCAN_REF:-}" ]; then
  SCAN_REF="dir:${PROJECT_ROOT}"
else
  SCAN_REF="$(resolve_scan_ref "${1:-}" SBOM_SCAN_REF)" || exit 1
fi
echo "→ Scan target: ${SCAN_REF}"

# ── Auto-install syft ───────────────────────────────────────────────
if ! command -v syft >/dev/null 2>&1; then
  _url="${SYFT_INSTALLER_URL:-https://raw.githubusercontent.com/anchore/syft/main/install.sh}"
  _ver="${SYFT_VERSION:-v1.14.0}"
  echo "→ syft not on PATH — installing ${_ver} from ${_url}"
  mkdir -p "${HOME}/.local/bin"
  if curl -fsSL --max-time 120 "${_url}" \
       | sh -s -- -b "${HOME}/.local/bin" "${_ver}" >/dev/null 2>&1 \
     && [ -x "${HOME}/.local/bin/syft" ]; then
    export PATH="${HOME}/.local/bin:${PATH}"
    echo "  ✓ syft installed ($(syft version 2>&1 | head -1))"
  else
    echo "ERROR: syft install failed — set SYFT_INSTALLER_URL to a reachable mirror" >&2
    exit 1
  fi
fi

# ── docker login when scanning an image (Syft pulls by digest) ──────
# Same multi-registry pattern as xray-vuln.sh — login to whichever
# backend the build pushed to, so syft can `docker pull` the digest.
if [ "${SCAN_REF#dir:}" = "${SCAN_REF}" ] && command -v docker >/dev/null 2>&1; then
  # shellcheck source=../lib/docker-login.sh
  . "${TEMPLATE_ROOT}/scripts/lib/docker-login.sh"
  docker_login_all_registries || true
fi

# ── Generate the SBOM ───────────────────────────────────────────────
# SBOM_FILE comes from scripts/lib/artifact-names.sh (default
# sbom.cdx.json) or build.env (when sourced beforehand). Treat bare
# filenames as PROJECT_ROOT-relative.
case "${SBOM_FILE}" in
  /*) SBOM_FILE_OUT="${SBOM_FILE}" ;;
  *)  SBOM_FILE_OUT="${PROJECT_ROOT}/${SBOM_FILE}" ;;
esac
echo "→ syft ${SCAN_REF} → ${SBOM_FILE_OUT}"

if ! syft "${SCAN_REF}" -o "cyclonedx-json=${SBOM_FILE_OUT}"; then
  echo "ERROR: syft failed — no SBOM produced" >&2
  exit 1
fi

if [ ! -s "${SBOM_FILE_OUT}" ]; then
  echo "ERROR: syft produced an empty file at ${SBOM_FILE_OUT}" >&2
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  COMPONENT_COUNT="$(jq '.components | length' "${SBOM_FILE_OUT}" 2>/dev/null || echo '?')"
  echo "  ✓ Syft SBOM: ${SBOM_FILE_OUT} ($(wc -c < "${SBOM_FILE_OUT}") bytes, ${COMPONENT_COUNT} components)"
else
  echo "  ✓ Syft SBOM: ${SBOM_FILE_OUT} ($(wc -c < "${SBOM_FILE_OUT}") bytes)"
fi

# ── Optional inline hand-off to sbom-post.sh (off by default) ──────
# Set SBOM_INLINE_POST=true to ship sinks here in the scan job.
# Default OFF — the sbom-ingest stage runs sbom-post.sh canonically.
# Inline is for callers that want scan-time delivery without waiting
# for the ingest stage (mirrors Xray's native scan+post pattern).
case "$(printf '%s' "${SBOM_INLINE_POST:-false}" | tr '[:upper:]' '[:lower:]')" in
  true|1|yes|on)
    if [ -f "${TEMPLATE_ROOT}/scripts/ingest/sbom-post.sh" ]; then
      echo ""
      echo "→ SBOM_INLINE_POST=true → handing off to scripts/ingest/sbom-post.sh"
      bash "${TEMPLATE_ROOT}/scripts/ingest/sbom-post.sh" "${SBOM_FILE_OUT}" || {
        echo "  WARN: sbom-post.sh exited non-zero — SBOM artifact still written" >&2
      }
    fi
    ;;
esac
