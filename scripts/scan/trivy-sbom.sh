#!/usr/bin/env bash
# ─── DO NOT EDIT — template scan job ───────────────────────────────
# Behaviour comes from image.env (SBOM_FILE, TRIVY_VERSION,
# TRIVY_INSTALLER_URL, TRIVY_BINARY_URL). Edit those, not the body.
# ───────────────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════
# KILL-SWITCH + VERSION SAFETY
# ═══════════════════════════════════════════════════════════════════
# Trivy is OPT-IN behind a single toggle, ALLOW_TRIVY (default 0 = off).
# Flip it WITHOUT editing this file — set ALLOW_TRIVY=1 as an env var, a
# CI/CD variable, or an image.env line. Gate enforced after config load.
# A hard VERSION-SAFETY pin always applies once enabled: TRIVY_VERSION
# defaults to 0.69.3 and the guard further down HARD-FAILS the
# compromised range v0.69.4–v0.69.6. See trivy-vuln.sh for the full note.
# ═══════════════════════════════════════════════════════════════════

# scripts/scan/trivy-sbom.sh — Aqua Trivy CycloneDX SBOM generator
#
# Single responsibility: run `trivy image --format cyclonedx` and
# produce the canonical sbom.cdx.json. Three SBOM producers now share
# the contract: scan/syft-sbom.sh, scan/xray-sbom.sh, scan/trivy-sbom.sh.
# Swap any of them by changing the script name in CI YAML.
#
# Same version safety as scripts/scan/trivy-vuln.sh: PINNED to v0.69.3
# (the last safe pre-compromise binary release) with a hard guard
# against the compromised v0.69.4–v0.69.6 range. Bump only after vetting
# the upstream advisory list — see the version note in trivy-vuln.sh.
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

# shellcheck source=../lib/scan-common.sh
. "${TEMPLATE_ROOT}/scripts/lib/scan-common.sh"
scan_bootstrap

# ── KILL-SWITCH: Trivy is opt-in. Toggle with ALLOW_TRIVY=1 (env / CI
# variable / image.env). Default 0 = disabled. No file edit needed. ──
if [ "${ALLOW_TRIVY:-0}" != "1" ]; then
  echo "→ trivy-sbom.sh disabled (ALLOW_TRIVY=${ALLOW_TRIVY:-0}). Set ALLOW_TRIVY=1 to enable." >&2
  exit 1
fi

# ── Resolve scan target ($1 > TRIVY_SCAN_REF > SBOM_SCAN_REF > XRAY_SCAN_REF > … chain).
SCAN_REF="$(resolve_scan_ref "${1:-}" TRIVY_SCAN_REF SBOM_SCAN_REF XRAY_SCAN_REF)" || exit 1
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
    mkdir -p "${HOME}/.local/bin"
    if curl -fsSL --max-time 120 "${TRIVY_BINARY_URL}" -o /tmp/trivy.tgz \
       && tar xz -C "${HOME}/.local/bin" -f /tmp/trivy.tgz trivy 2>/dev/null \
       && [ -x "${HOME}/.local/bin/trivy" ]; then
      export PATH="${HOME}/.local/bin:${PATH}"
      echo "  ✓ trivy installed ($(trivy --version 2>&1 | head -1))"
    else
      echo "ERROR: trivy install from TRIVY_BINARY_URL failed" >&2
      exit 1
    fi
  else
    _url="${TRIVY_INSTALLER_URL:-https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh}"
    echo "→ trivy not on PATH — installing v${TRIVY_VERSION} from ${_url}"
    mkdir -p "${HOME}/.local/bin"
    if curl -fsSL --max-time 120 "${_url}" \
         | sh -s -- -b "${HOME}/.local/bin" "v${TRIVY_VERSION}" >/dev/null 2>&1 \
       && [ -x "${HOME}/.local/bin/trivy" ]; then
      export PATH="${HOME}/.local/bin:${PATH}"
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
  docker_login_all_registries || true
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
