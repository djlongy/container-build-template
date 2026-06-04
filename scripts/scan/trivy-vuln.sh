#!/usr/bin/env bash
# ─── DO NOT EDIT — template scan job ───────────────────────────────
# Behaviour comes from image.env (TRIVY_FAIL_ON_SEVERITY,
# TRIVY_VERSION, TRIVY_INSTALLER_URL, TRIVY_BINARY_URL). Edit those,
# not the body of this file.
# ───────────────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════
# KILL-SWITCH + VERSION SAFETY
# ═══════════════════════════════════════════════════════════════════
# Trivy is OPT-IN behind a single toggle, ALLOW_TRIVY (default 0 = off).
# Flip it WITHOUT editing this file — set ALLOW_TRIVY=1 as an env var, a
# CI/CD variable, or an image.env line — so it's easy to turn on and off
# per pipeline. The gate is enforced just after config load (below).
#
# Independently, a hard VERSION-SAFETY pin always applies once enabled:
# TRIVY_VERSION defaults to 0.69.3 (the last safe pre-compromise binary)
# and the guard further down HARD-FAILS the compromised range
# v0.69.4–v0.69.6 even if a stale mirror serves one. Bump TRIVY_VERSION
# only after vetting the upstream advisory list — see the note below.
# ═══════════════════════════════════════════════════════════════════

# scripts/scan/trivy-vuln.sh — Aqua Trivy image vulnerability scan
#
# Single responsibility: run `trivy image --format json` against the
# built image and produce the canonical vuln-scan.json. Optional
# severity gate (TRIVY_FAIL_ON_SEVERITY) parallels xray-vuln.sh and
# grype-vuln.sh so swapping scanners doesn't change the contract.
#
# Output filename matches xray-vuln.sh and grype-vuln.sh — all three
# write vuln-scan.json by default. Downstream stages (audit shippers,
# SecOps) consume vuln-scan.json without caring which scanner ran.
#
# Enable by adding (or swapping in) a CI stage that calls this script —
# consumers pick Trivy / Xray / Grype per scanner-of-record. The PINNED
# VERSION below (TRIVY_VERSION default 0.69.3) predates the published-
# image compromise that affected v0.69.4 / v0.69.5 / v0.69.6 binaries +
# Docker Hub images. See the security note at the bottom of this file
# before you bump the version.
#
# Usage:
#   bash scripts/scan/trivy-vuln.sh                # scan IMAGE_DIGEST/IMAGE_REF
#   bash scripts/scan/trivy-vuln.sh <image-ref>    # scan an arbitrary ref
#
# Required env: none (auto-installs trivy at the pinned version).
#
# Optional env:
#   VULN_SCAN_FILE            output path (default: vuln-scan.json)
#   TRIVY_VERSION             default 0.69.3 (last safe pre-compromise)
#   TRIVY_INSTALLER_URL       installer URL (default: aquasec install.sh)
#   TRIVY_BINARY_URL          direct binary tarball (air-gap mirror)
#   TRIVY_FAIL_ON_SEVERITY    comma-separated severities → exit 2 on match
#                             (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
#                             Empty/unset = report-only mode.
#
# Security note (date-of-record 2026-04): the compromised range was
# trivy v0.69.4–v0.69.6 (binary + Docker Hub images), trivy-action
# v0.0.1–v0.34.2, setup-trivy v0.2.0–v0.2.5. Safe defaults:
# trivy ≤ v0.69.3, trivy-action ≥ v0.35.0, setup-trivy v0.2.6.
#
# Exit codes:
#   0  scan completed
#   1  hard error (install failure, no scan target)
#   2  policy gate failed (matching severities present)

set -euo pipefail

TEMPLATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
export TEMPLATE_ROOT PROJECT_ROOT
cd "${PROJECT_ROOT}"

# shellcheck source=../lib/scan-common.sh
. "${TEMPLATE_ROOT}/scripts/lib/scan-common.sh"
scan_bootstrap

# ── KILL-SWITCH: Trivy is opt-in. Toggle with ALLOW_TRIVY=1 (env / CI
# variable / image.env). Default 0 = disabled → exit non-zero so a
# wired-but-disabled job is visibly skipped. No file edit needed. ──
if [ "${ALLOW_TRIVY:-0}" != "1" ]; then
  echo "→ trivy-vuln.sh disabled (ALLOW_TRIVY=${ALLOW_TRIVY:-0}). Set ALLOW_TRIVY=1 to enable." >&2
  exit 1
fi

# ── Resolve scan target ($1 > TRIVY_SCAN_REF > XRAY_SCAN_REF > … chain).
SCAN_REF="$(resolve_scan_ref "${1:-}" TRIVY_SCAN_REF XRAY_SCAN_REF)" || exit 1
echo "→ Scan target: ${SCAN_REF}"

# ── Resolve output path ─────────────────────────────────────────────
case "${VULN_SCAN_FILE}" in
  /*) SCAN_OUT="${VULN_SCAN_FILE}" ;;
  *)  SCAN_OUT="${PROJECT_ROOT}/${VULN_SCAN_FILE}" ;;
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

# Verify the installed version is in the safe range. Hard-fail if the
# user (or a stale mirror) provided a compromised version.
_installed="$(trivy --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo unknown)"
case "${_installed}" in
  0.69.4|0.69.5|0.69.6)
    echo "ERROR: trivy ${_installed} is in the compromised range (v0.69.4–v0.69.6)." >&2
    echo "       Pin TRIVY_VERSION to 0.69.3 or upgrade past the next vetted release." >&2
    exit 1
    ;;
esac

# ── Multi-registry docker login (private digest pulls need auth) ────
if command -v docker >/dev/null 2>&1; then
  # shellcheck source=../lib/docker-login.sh
  . "${TEMPLATE_ROOT}/scripts/lib/docker-login.sh"
  docker_login_all_registries || true
fi

# ── Run the scan ────────────────────────────────────────────────────
echo "→ trivy image --format json ${SCAN_REF} → ${SCAN_OUT}"
trivy image \
  --format json \
  --output "${SCAN_OUT}" \
  --severity "${TRIVY_SEVERITY_FILTER:-CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN}" \
  --exit-code 0 \
  "${SCAN_REF}" || {
    echo "ERROR: trivy scan failed" >&2
    exit 1
  }

# Human-readable table for the pipeline log
trivy image --severity "${TRIVY_SEVERITY_FILTER:-CRITICAL,HIGH}" "${SCAN_REF}" || true

if [ ! -s "${SCAN_OUT}" ]; then
  echo "ERROR: trivy produced no output" >&2
  exit 1
fi

# ── Severity summary for the pipeline log ──────────────────────────
if command -v jq >/dev/null 2>&1; then
  echo ""
  echo "→ Vulnerability summary:"
  for sev in CRITICAL HIGH MEDIUM LOW UNKNOWN; do
    count=$(jq "[.Results[]?.Vulnerabilities[]? | select(.Severity==\"${sev}\")] | length" "${SCAN_OUT}")
    printf '    %-9s %s\n' "${sev}:" "${count}"
  done
fi

# ── Optional inline hand-off to vuln-post.sh (off by default) ──────
# Same VULN_INLINE_POST=true gate as grype-vuln.sh. Generic — calls
# vuln-post.sh which handles all sinks (no Splunk hardcoding here).
case "$(printf '%s' "${VULN_INLINE_POST:-false}" | tr '[:upper:]' '[:lower:]')" in
  true|1|yes|on)
    if [ -f "${TEMPLATE_ROOT}/scripts/ingest/vuln-post.sh" ]; then
      echo ""
      echo "→ VULN_INLINE_POST=true → handing off to scripts/ingest/vuln-post.sh"
      bash "${TEMPLATE_ROOT}/scripts/ingest/vuln-post.sh" "${SCAN_OUT}" || {
        echo "  WARN: vuln-post.sh exited non-zero — scan artifact still written" >&2
      }
    fi
    ;;
esac

# ── Policy gate (opt-in) ───────────────────────────────────────────
if [ -n "${TRIVY_FAIL_ON_SEVERITY:-}" ]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo "WARN: TRIVY_FAIL_ON_SEVERITY set but jq not on PATH — gate skipped" >&2
  else
    _gate=$(printf '%s' "${TRIVY_FAIL_ON_SEVERITY}" | tr '[:lower:]' '[:upper:]')
    _violations=0
    echo ""
    echo "→ Policy gate: fail-on=${_gate}"
    for sev in $(printf '%s\n' "${_gate}" | tr ',' '\n' | sed '/^$/d'); do
      _count=$(jq --arg s "${sev}" '[.Results[]?.Vulnerabilities[]? | select(.Severity == $s)] | length' "${SCAN_OUT}")
      printf '    %-9s %s\n' "${sev}:" "${_count}"
      _violations=$((_violations + _count))
    done
    if [ "${_violations}" -gt 0 ]; then
      echo "  ✗ FAIL: ${_violations} vulnerabilit(ies) match policy gate (TRIVY_FAIL_ON_SEVERITY=${TRIVY_FAIL_ON_SEVERITY})" >&2
      exit 2
    fi
    echo "  ✓ PASS: no matching vulnerabilities at the configured severity threshold"
  fi
fi
