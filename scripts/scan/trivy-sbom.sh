#!/usr/bin/env bash
# ─── DO NOT EDIT — except to enable the kill-switch below ──────────
# Behaviour comes from image.env (SBOM_FILE, TRIVY_VERSION,
# TRIVY_INSTALLER_URL, TRIVY_BINARY_URL). Edit those, not the body.
# ───────────────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════
# KILL-SWITCH — Trivy is BANNED for business use
# ═══════════════════════════════════════════════════════════════════
# This script EXITS 1 by default. To actually run Trivy, BOTH gates
# must be flipped — single flag is not enough, to prevent accidental
# runs from a stray env var or uncommented CI job:
#
#   1. EDIT this file: change ALLOW_TRIVY=0 to ALLOW_TRIVY=1 below
#   2. AND export: ALLOW_TRIVY_RUN=yes-i-understand-trivy-is-banned
#
# Even after both gates are flipped, the script still refuses
# v0.69.4–v0.69.6 (the compromised range). See trivy-vuln.sh for the
# full security note.
#
# Status: BOTH GATES LOCKED. End-to-end testing of the trivy path
# completed 2026-05-28 (prometheus / redis / cert-builder pipelines
# successfully ran trivy + ingested results to Splunk + Artifactory).
# Reverted to the original "banned by default" state — re-enabling
# now needs the same deliberate two-step the killswitch enforces.
ALLOW_TRIVY=0

if [ "${ALLOW_TRIVY}" -ne 1 ] || [ "${ALLOW_TRIVY_RUN:-}" != "yes-i-understand-trivy-is-banned" ]; then
  echo "REFUSED: trivy-sbom.sh is disabled (Trivy is banned for business use)." >&2
  echo "  To run anyway, BOTH gates must be flipped — see kill-switch header." >&2
  echo "    1. Edit this file: ALLOW_TRIVY=1" >&2
  echo "    2. export ALLOW_TRIVY_RUN=yes-i-understand-trivy-is-banned" >&2
  exit 1
fi
# ═══════════════════════════════════════════════════════════════════

# scripts/scan/trivy-sbom.sh — Aqua Trivy CycloneDX SBOM generator
#
# Single responsibility: run `trivy image --format cyclonedx` and
# produce the canonical sbom.cdx.json. Three SBOM producers now share
# the contract: scan/syft-sbom.sh, scan/xray-sbom.sh, scan/trivy-sbom.sh.
# Swap any of them by changing the script name in CI YAML.
#
# ── DISABLED BY DEFAULT — Trivy is banned for business use here ─────
# Same security caveat as scripts/scan/trivy-vuln.sh: this is a
# scaffold for re-enablement. PINNED to v0.69.3 (the last safe
# pre-compromise binary release). Bump only after vetting the
# upstream advisory list — see the version note in trivy-vuln.sh.
#
# Usage:
#   bash scripts/scan/trivy-sbom.sh                # SBOM of IMAGE_DIGEST/IMAGE_REF
#   bash scripts/scan/trivy-sbom.sh <image-ref>    # SBOM of arbitrary ref
#
# Optional env:
#   SBOM_FILE                 output path (default sbom.cdx.json — the
#                             canonical name from artifact-names.sh)
#   TRIVY_VERSION             default 0.69.3 (last safe pre-compromise)
#   TRIVY_INSTALLER_URL       installer URL (default: aquasec install.sh)
#   TRIVY_BINARY_URL          direct binary tarball (air-gap mirror)
#
# Exit codes: 0 (success), 1 (install failure / no scan target).

set -euo pipefail

TEMPLATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
export TEMPLATE_ROOT PROJECT_ROOT
cd "${PROJECT_ROOT}"

# shellcheck source=../lib/load-image-env.sh
. "${TEMPLATE_ROOT}/scripts/lib/load-image-env.sh"
# shellcheck source=../lib/artifact-names.sh
. "${TEMPLATE_ROOT}/scripts/lib/artifact-names.sh"
import_bamboo_vars
load_image_env

# ── Resolve scan target ─────────────────────────────────────────────
SCAN_REF="${1:-${TRIVY_SCAN_REF:-${SBOM_SCAN_REF:-${XRAY_SCAN_REF:-}}}}"
if [ -z "${SCAN_REF}" ]; then
  if   [ -n "${IMAGE_DIGEST:-}" ];                                          then SCAN_REF="${IMAGE_DIGEST}"
  elif [ -n "${IMAGE_REF:-}" ];                                             then SCAN_REF="${IMAGE_REF}"
  elif [ -n "${UPSTREAM_REF:-}" ];                                          then SCAN_REF="${UPSTREAM_REF}"
  elif [ -n "${UPSTREAM_REGISTRY:-}" ] && [ -n "${UPSTREAM_IMAGE:-}" ] && [ -n "${UPSTREAM_TAG:-}" ]; then
    SCAN_REF="${UPSTREAM_REGISTRY}/${UPSTREAM_IMAGE}:${UPSTREAM_TAG}"
  fi
fi
if [ -z "${SCAN_REF}" ]; then
  echo "ERROR: no scan target available." >&2
  exit 1
fi
echo "→ Scan target: ${SCAN_REF}"

# ── Resolve output path ─────────────────────────────────────────────
case "${SBOM_FILE}" in
  /*) SBOM_OUT="${SBOM_FILE}" ;;
  *)  SBOM_OUT="${PROJECT_ROOT}/${SBOM_FILE}" ;;
esac

# ── Auto-install trivy at the PINNED safe version ──────────────────
TRIVY_VERSION="${TRIVY_VERSION:-0.69.3}"
if ! command -v trivy >/dev/null 2>&1; then
  if [ -n "${TRIVY_BINARY_URL:-}" ]; then
    echo "→ trivy not on PATH — installing from TRIVY_BINARY_URL"
    mkdir -p "${PROJECT_ROOT}/.bin"
    if curl -fsSL --max-time 120 "${TRIVY_BINARY_URL}" -o /tmp/trivy.tgz \
       && tar xz -C "${PROJECT_ROOT}/.bin" -f /tmp/trivy.tgz trivy 2>/dev/null \
       && [ -x "${PROJECT_ROOT}/.bin/trivy" ]; then
      export PATH="${PROJECT_ROOT}/.bin:${PATH}"
      echo "  ✓ trivy installed ($(trivy --version 2>&1 | head -1))"
    else
      echo "ERROR: trivy install from TRIVY_BINARY_URL failed" >&2
      exit 1
    fi
  else
    _url="${TRIVY_INSTALLER_URL:-https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh}"
    echo "→ trivy not on PATH — installing v${TRIVY_VERSION} from ${_url}"
    mkdir -p "${PROJECT_ROOT}/.bin"
    if curl -fsSL --max-time 120 "${_url}" \
         | sh -s -- -b "${PROJECT_ROOT}/.bin" "v${TRIVY_VERSION}" >/dev/null 2>&1 \
       && [ -x "${PROJECT_ROOT}/.bin/trivy" ]; then
      export PATH="${PROJECT_ROOT}/.bin:${PATH}"
      echo "  ✓ trivy installed ($(trivy --version 2>&1 | head -1))"
    else
      echo "ERROR: trivy install failed — set TRIVY_BINARY_URL to a reachable mirror" >&2
      exit 1
    fi
  fi
fi

# Refuse compromised versions (defence in depth — same check as
# trivy-vuln.sh).
_installed="$(trivy --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo unknown)"
case "${_installed}" in
  0.69.4|0.69.5|0.69.6)
    echo "ERROR: trivy ${_installed} is in the compromised range (v0.69.4–v0.69.6)." >&2
    echo "       Pin TRIVY_VERSION to 0.69.3 or upgrade past the next vetted release." >&2
    exit 1
    ;;
esac

# ── Multi-registry docker login ────────────────────────────────────
if command -v docker >/dev/null 2>&1; then
  # shellcheck source=../lib/docker-login.sh
  . "${TEMPLATE_ROOT}/scripts/lib/docker-login.sh"
  docker_login_for_xray_scan || true
fi

# ── Generate the SBOM ──────────────────────────────────────────────
echo "→ trivy image --format cyclonedx ${SCAN_REF} → ${SBOM_OUT}"
trivy image --format cyclonedx --output "${SBOM_OUT}" "${SCAN_REF}" || {
  echo "ERROR: trivy SBOM generation failed" >&2
  exit 1
}

if [ ! -s "${SBOM_OUT}" ]; then
  echo "ERROR: trivy produced no SBOM output" >&2
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  COMPONENT_COUNT="$(jq '.components | length' "${SBOM_OUT}" 2>/dev/null || echo '?')"
  echo "  ✓ Trivy SBOM: ${SBOM_OUT} ($(wc -c < "${SBOM_OUT}") bytes, ${COMPONENT_COUNT} components)"
else
  echo "  ✓ Trivy SBOM: ${SBOM_OUT} ($(wc -c < "${SBOM_OUT}") bytes)"
fi

# ── Optional inline hand-off to sbom-post.sh (off by default) ──────
# Same SBOM_INLINE_POST=true gate as syft-sbom.sh. Default OFF — the
# sbom-ingest stage runs sbom-post.sh canonically. Generic — handles
# all sinks (webhook / DT / Artifactory / Splunk).
case "$(printf '%s' "${SBOM_INLINE_POST:-false}" | tr '[:upper:]' '[:lower:]')" in
  true|1|yes|on)
    if [ -f "${TEMPLATE_ROOT}/scripts/ingest/sbom-post.sh" ]; then
      echo ""
      echo "→ SBOM_INLINE_POST=true → handing off to scripts/ingest/sbom-post.sh"
      bash "${TEMPLATE_ROOT}/scripts/ingest/sbom-post.sh" "${SBOM_OUT}" || {
        echo "  WARN: sbom-post.sh exited non-zero — SBOM artifact still written" >&2
      }
    fi
    ;;
esac
