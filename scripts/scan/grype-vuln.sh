#!/usr/bin/env bash
# ─── DO NOT EDIT — template scan job ───────────────────────────────
# Behaviour comes from image.env (GRYPE_FAIL_ON_SEVERITY,
# GRYPE_VERSION, GRYPE_INSTALLER_URL, ARTIFACTORY_GRYPE_DB_REPO).
# Edit those, not this file.
# ───────────────────────────────────────────────────────────────────
#
# scripts/scan/grype-vuln.sh — Anchore Grype SBOM-based vulnerability scan
#
# Single responsibility: run `grype sbom:<SBOM_FILE> -o json` and
# produce the canonical vuln-scan.json. Optional severity gate
# (GRYPE_FAIL_ON_SEVERITY) parallels xray-vuln.sh's gate so swapping
# scanners doesn't break downstream policy.
#
# Output filename is the SAME as scripts/scan/xray-vuln.sh — both
# write vuln-scan.json by default. That's the artifact contract:
# downstream stages (audit shippers, SecOps) consume vuln-scan.json
# without caring which scanner produced it. Swap one for the other
# by changing the script name in CI YAML; nothing else moves.
#
# Usage:
#   bash scripts/scan/grype-vuln.sh                # uses ${SBOM_FILE} from
#                                                  # build.env / artifact-names.sh
#   bash scripts/scan/grype-vuln.sh <sbom-path>    # scan an arbitrary SBOM
#
# Required upstream input: a CycloneDX SBOM at ${SBOM_FILE} (default
# sbom.cdx.json). Produced by scripts/scan/syft-sbom.sh OR
# scripts/scan/xray-sbom.sh — Grype reads either.
#
# Optional env:
#   SBOM_FILE                 input CycloneDX SBOM (default: sbom.cdx.json)
#   VULN_SCAN_FILE            output path (default: vuln-scan.json)
#   GRYPE_INSTALLER_URL       installer URL (default: GitHub raw)
#   GRYPE_VERSION             default v0.82.0
#   GRYPE_DB_UPDATE_URL       override CVE DB source (air-gap mirror)
#   GRYPE_FAIL_ON_SEVERITY    comma-separated severities that trigger
#                             exit 2 (case-insensitive — Critical,
#                             High, Medium, Low, Negligible, Unknown)
#                             Empty/unset = report-only mode.
# Sink shipping primarily happens in scripts/ingest/vuln-post.sh as
# its own CI stage (mirrors sbom-post.sh — clean producer/consumer
# split). Optional INLINE Splunk shipping is available via
# VULN_INLINE_POST=true for callers that need scan-time delivery
# without waiting for the ingest stage. Off by default.
#   VULN_INLINE_POST="false"                  default — ingest stage only
#   VULN_INLINE_POST="true"                   ALSO ship inline here
#
# Exit codes:
#   0  scan completed (incl. report-only mode with findings)
#   1  hard error (missing SBOM, install failure)
#   2  policy gate failed (matching severity vulns present)

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

# ── Resolve input SBOM ─────────────────────────────────────────────
SBOM_IN="${1:-${SBOM_FILE}}"
case "${SBOM_IN}" in
  /*) ;;
  *)  SBOM_IN="${PROJECT_ROOT}/${SBOM_IN}" ;;
esac
if [ ! -s "${SBOM_IN}" ]; then
  echo "ERROR: SBOM not found at ${SBOM_IN}" >&2
  echo "  Run scripts/scan/syft-sbom.sh (or xray-sbom.sh) first," >&2
  echo "  or pass an explicit SBOM path: bash scripts/scan/grype-vuln.sh <path>" >&2
  exit 1
fi

# ── Resolve output path ────────────────────────────────────────────
case "${VULN_SCAN_FILE}" in
  /*) SCAN_OUT="${VULN_SCAN_FILE}" ;;
  *)  SCAN_OUT="${PROJECT_ROOT}/${VULN_SCAN_FILE}" ;;
esac

# ── Auto-install grype ─────────────────────────────────────────────
if ! command -v grype >/dev/null 2>&1; then
  _url="${GRYPE_INSTALLER_URL:-https://raw.githubusercontent.com/anchore/grype/main/install.sh}"
  _ver="${GRYPE_VERSION:-v0.82.0}"
  echo "→ grype not on PATH — installing ${_ver} from ${_url}"
  mkdir -p "${PROJECT_ROOT}/.bin"
  if curl -fsSL --max-time 120 "${_url}" \
       | sh -s -- -b "${PROJECT_ROOT}/.bin" "${_ver}" >/dev/null 2>&1 \
     && [ -x "${PROJECT_ROOT}/.bin/grype" ]; then
    export PATH="${PROJECT_ROOT}/.bin:${PATH}"
    echo "  ✓ grype installed ($(grype version 2>&1 | head -1))"
  else
    echo "ERROR: grype install failed — set GRYPE_INSTALLER_URL to a reachable mirror" >&2
    exit 1
  fi
fi

# ── Air-gap CVE DB redirect (Artifactory mirror) ───────────────────
# Same logic as the inline GitLab block we replaced — picks up an
# Artifactory-hosted Grype DB when ARTIFACTORY_GRYPE_DB_REPO is set.
if [ -n "${ARTIFACTORY_GRYPE_DB_REPO:-}" ] && [ -n "${ARTIFACTORY_URL:-}" ] \
   && [ -z "${GRYPE_DB_UPDATE_URL:-}" ]; then
  _art_host="${ARTIFACTORY_URL#https://}"
  _art_host="${_art_host#http://}"
  _art_host="${_art_host%%/*}"
  _art_secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD:-}}"
  _subpath="${GRYPE_DB_MIRROR_SUBPATH:-grype-db/v6}"
  if [ -n "${ARTIFACTORY_USER:-}" ] && [ -n "${_art_secret}" ]; then
    export GRYPE_DB_UPDATE_URL="https://${ARTIFACTORY_USER}:${_art_secret}@${_art_host}/artifactory/${ARTIFACTORY_GRYPE_DB_REPO}/${_subpath}/latest.json"
    export GRYPE_DB_AUTO_UPDATE=true
    echo "→ Grype DB source: ${ARTIFACTORY_URL}/artifactory/${ARTIFACTORY_GRYPE_DB_REPO}/${_subpath}/latest.json"
  fi
fi

# ── Run the scan ───────────────────────────────────────────────────
echo "→ grype sbom:${SBOM_IN} → ${SCAN_OUT}"
grype "sbom:${SBOM_IN}" --output json --file "${SCAN_OUT}" --fail-on "" || true
grype "sbom:${SBOM_IN}" --output table || true

if [ ! -s "${SCAN_OUT}" ]; then
  echo "ERROR: grype produced no output (rc=$?)" >&2
  exit 1
fi

# ── Severity summary for the pipeline log ──────────────────────────
if command -v jq >/dev/null 2>&1; then
  echo ""
  echo "→ Vulnerability summary:"
  for sev in Critical High Medium Low Negligible Unknown; do
    count=$(jq "[.matches[] | select(.vulnerability.severity==\"${sev}\")] | length" "${SCAN_OUT}")
    printf '    %-11s %s\n' "${sev}:" "${count}"
  done
fi

# ── Optional inline hand-off to vuln-post.sh (off by default) ──────
# Set VULN_INLINE_POST=true to ship sinks here in the scan job.
# Default OFF — the vuln-ingest stage runs vuln-post.sh canonically.
# Inline is for callers that want scan-time delivery without waiting
# for the ingest stage (mirrors Xray's native scan+post pattern).
# vuln-post.sh handles ALL sinks (webhook / Artifactory archive /
# Splunk HEC) — no scanner-side hardcoding to a specific sink.
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
if [ -n "${GRYPE_FAIL_ON_SEVERITY:-}" ]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo "WARN: GRYPE_FAIL_ON_SEVERITY set but jq not on PATH — gate skipped" >&2
  else
    _gate=$(printf '%s' "${GRYPE_FAIL_ON_SEVERITY}" | tr '[:upper:]' '[:lower:]')
    _violations=0
    echo ""
    echo "→ Policy gate: fail-on=${_gate}"
    for sev in $(printf '%s\n' "${_gate}" | tr ',' '\n' | sed '/^$/d'); do
      _count=$(jq --arg s "${sev}" '[.matches[]? | select((.vulnerability.severity // "" | ascii_downcase) == $s)] | length' "${SCAN_OUT}")
      printf '    %-11s %s\n' "${sev}:" "${_count}"
      _violations=$((_violations + _count))
    done
    if [ "${_violations}" -gt 0 ]; then
      echo "  ✗ FAIL: ${_violations} vulnerabilit(ies) match policy gate (GRYPE_FAIL_ON_SEVERITY=${GRYPE_FAIL_ON_SEVERITY})" >&2
      exit 2
    fi
    echo "  ✓ PASS: no matching vulnerabilities at the configured severity threshold"
  fi
fi
