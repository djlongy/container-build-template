#!/usr/bin/env bash
# ─── DO NOT EDIT — template ingest job ─────────────────────────────
# Sink config (VULN_WEBHOOK_URL, ARTIFACTORY_VULN_ARCHIVE_REPO,
# SPLUNK_HEC_*) comes from image.env + masked CI vars. Edit those,
# not this file. All sinks are opt-in and no-op when unset.
# ───────────────────────────────────────────────────────────────────
#
# Post a vulnerability scan (vuln-scan.json) to one or more ingestion
# endpoints. Scanner-agnostic — auto-detects whether the report came
# from grype / trivy / xray (by report shape) and picks a sensible
# Splunk sourcetype accordingly.
#
# Mirrors scripts/ingest/sbom-post.sh — same producer-vs-consumer
# split as SBOM. Scanners (grype-vuln, trivy-vuln, xray-vuln) write
# vuln-scan.json as their CI artifact; this script consumes it.
#
# ── Where do the sink env vars come from? ────────────────────────────
# Shell / CI env or image.env (committed). Precedence: shell beats
# file. This script self-loads image.env via lib/load-image-env.sh.
#
# ── Supported sinks (set one or more) ────────────────────────────────
#
#   Generic webhook (raw vuln-scan.json body):
#     VULN_WEBHOOK_URL          full URL accepting a POST
#     VULN_WEBHOOK_AUTH_HEADER  optional, e.g. "Authorization: Bearer xxx"
#
#   JFrog Artifactory generic archive (long-term browsable copy —
#   no Xray indexing required, just a PUT to a generic repo):
#     ARTIFACTORY_URL           https://artifactory.example.com
#     ARTIFACTORY_USER          user with Deploy on the generic repo
#     ARTIFACTORY_TOKEN         access token (preferred), OR
#     ARTIFACTORY_PASSWORD      basic-auth password
#     ARTIFACTORY_VULN_ARCHIVE_REPO  generic repo name
#
#   Splunk HEC (audit-trail ingestion; vuln report goes inside HEC
#   `event` field):
#     SPLUNK_HEC_URL            HEC base URL (we append /services/collector)
#     SPLUNK_HEC_TOKEN          HEC token
#     SPLUNK_HEC_INDEX          target index. Default: main
#     VULN_SPLUNK_SOURCETYPE    sourcetype tag. Default: auto-detected
#                               from report shape (anchore:grype:vuln /
#                               aqua:trivy:vuln / jfrog:xray:scan).
#     SPLUNK_HEC_INSECURE       "true" → curl -k. Default: false
#
# Usage:
#   bash scripts/ingest/vuln-post.sh                 # reads ${VULN_SCAN_FILE}
#   bash scripts/ingest/vuln-post.sh <path-to-json>  # explicit override
#
# Exit codes:
#   0  success (including "no sinks configured — nothing to do")
#   1  one or more configured sinks returned an error

set -euo pipefail

TEMPLATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
export TEMPLATE_ROOT PROJECT_ROOT

# shellcheck source=../lib/artifact-names.sh
. "${TEMPLATE_ROOT}/scripts/lib/artifact-names.sh"

# Capture $1 BEFORE sourcing build.env / image.env — both can carry
# their own VULN_SCAN_FILE (set by build.sh from artifact-names.sh
# defaults) and would clobber a caller-passed override otherwise.
# Pattern: pin the explicit path here, restore it after env loading.
_ARG_VULN_FILE="${1:-}"

cd "${PROJECT_ROOT}"

# Auto-import bamboo_* + source image.env.
# shellcheck source=../lib/load-image-env.sh
. "${TEMPLATE_ROOT}/scripts/lib/load-image-env.sh"
import_bamboo_vars
load_image_env

# Pull build.env so sinks get IMAGE_REF / IMAGE_DIGEST / IMAGE_TAG /
# IMAGE_NAME / GIT_SHA for richer metadata.
[ -f build.env ] && { set -a; . ./build.env; set +a; }

# Restore caller's explicit path (overrides build.env's default).
if [ -n "${_ARG_VULN_FILE}" ]; then
  VULN_SCAN_FILE="${_ARG_VULN_FILE}"
fi
case "${VULN_SCAN_FILE}" in
  /*) ;;
  *)  VULN_SCAN_FILE="$(pwd)/${VULN_SCAN_FILE}" ;;
esac
[ -f "${VULN_SCAN_FILE}" ] || { echo "ERROR: vuln scan not found: ${VULN_SCAN_FILE}" >&2; exit 1; }

_TMP=$(mktemp -d)
trap 'rm -rf "${_TMP}"' EXIT

echo "→ vuln scan: ${VULN_SCAN_FILE} ($(wc -c < "${VULN_SCAN_FILE}") bytes)"

# ── Detect scanner from report shape ────────────────────────────────
# Different scanners produce different top-level JSON keys. Use that
# to pick a default Splunk sourcetype and a nested-event key (so the
# Splunk record clearly shows which tool produced it).
SCANNER="unknown"
SCANNER_KEY="vuln"
DEFAULT_SOURCETYPE="scan:vuln:json"
if command -v jq >/dev/null 2>&1; then
  if   jq -e 'has("matches")'         "${VULN_SCAN_FILE}" >/dev/null 2>&1; then
    SCANNER="grype"; SCANNER_KEY="grype"; DEFAULT_SOURCETYPE="anchore:grype:vuln"
  elif jq -e 'has("Results")'         "${VULN_SCAN_FILE}" >/dev/null 2>&1; then
    SCANNER="trivy"; SCANNER_KEY="trivy"; DEFAULT_SOURCETYPE="aqua:trivy:vuln"
  elif jq -e 'has("vulnerabilities")' "${VULN_SCAN_FILE}" >/dev/null 2>&1; then
    SCANNER="xray";  SCANNER_KEY="xray";  DEFAULT_SOURCETYPE="jfrog:xray:scan"
  fi
fi
echo "→ scanner detected: ${SCANNER} (default sourcetype: ${DEFAULT_SOURCETYPE})"
echo ""

posted=0
failed=0

# ════════════════════════════════════════════════════════════════════
# SINK 1: Generic webhook
# ════════════════════════════════════════════════════════════════════
if [ -z "${VULN_WEBHOOK_URL:-}" ]; then
  echo "→ webhook              skip (VULN_WEBHOOK_URL empty)"
else
  echo "→ webhook              POST ${VULN_WEBHOOK_URL}"
  rc=0
  (
    headers=(-H "Content-Type: application/json"
             -H "X-Vuln-Scanner: ${SCANNER}")
    [ -n "${VULN_WEBHOOK_AUTH_HEADER:-}" ] && headers+=(-H "${VULN_WEBHOOK_AUTH_HEADER}")
    [ -n "${IMAGE_DIGEST:-}" ]             && headers+=(-H "X-Image-Digest: ${IMAGE_DIGEST}")
    [ -n "${UPSTREAM_TAG:-}" ]             && headers+=(-H "X-Image-Version: ${UPSTREAM_TAG}")
    curl -fsSL -X POST "${headers[@]}" --data-binary "@${VULN_SCAN_FILE}" \
      "${VULN_WEBHOOK_URL}" -o "${_TMP}/webhook.out"
    echo "  ✓ posted ($(wc -c < "${_TMP}/webhook.out") bytes response)"
  ) || rc=$?
  if [ "${rc}" -eq 0 ]; then
    posted=$((posted + 1))
  else
    echo "  ✗ webhook POST failed" >&2
    failed=$((failed + 1))
  fi
fi

# ════════════════════════════════════════════════════════════════════
# SINK 2: Artifactory generic archive (long-term browsable copy)
# ════════════════════════════════════════════════════════════════════
# PUT to <repo>/<image>/<tag>/vuln-scan.json. No Xray indexing
# expectation — just a stable URL for downstream consumers / auditors
# / SecOps to fetch the report later.
if [ -z "${ARTIFACTORY_URL:-}" ] || [ -z "${ARTIFACTORY_USER:-}" ] || [ -z "${ARTIFACTORY_VULN_ARCHIVE_REPO:-}" ]; then
  echo "→ artifactory-archive  skip (ARTIFACTORY_VULN_ARCHIVE_REPO / URL / USER missing)"
else
  arc_secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD:-}}"
  arc_image="${IMAGE_NAME:-${UPSTREAM_IMAGE##*/}}"
  arc_version="${IMAGE_TAG:-${UPSTREAM_TAG:-unknown}}"
  arc_path="${ARTIFACTORY_VULN_ARCHIVE_REPO}/${arc_image}/${arc_version}/vuln-scan.json"
  arc_url="${ARTIFACTORY_URL%/}/artifactory/${arc_path}"
  echo "→ artifactory-archive  PUT ${arc_url}"
  rc=0
  (
    # Portable SHA wrappers (Mac vs Linux).
    _sha1=$(shasum -a 1   "${VULN_SCAN_FILE}" 2>/dev/null | awk '{print $1}' || sha1sum   "${VULN_SCAN_FILE}" | awk '{print $1}')
    _sha256=$(shasum -a 256 "${VULN_SCAN_FILE}" 2>/dev/null | awk '{print $1}' || sha256sum "${VULN_SCAN_FILE}" | awk '{print $1}')
    code=$(curl -sS -o "${_TMP}/art.out" -w "%{http_code}" \
      -u "${ARTIFACTORY_USER}:${arc_secret}" \
      -H "X-Checksum-Sha1: ${_sha1}" \
      -H "X-Checksum-Sha256: ${_sha256}" \
      -H "Content-Type: application/json" \
      -T "${VULN_SCAN_FILE}" "${arc_url}")
    case "${code}" in
      2*) echo "  ✓ uploaded (HTTP ${code})";;
      *)  echo "  ✗ HTTP ${code}" >&2; sed 's/^/    /' "${_TMP}/art.out" >&2; exit 1;;
    esac
  ) || rc=$?
  if [ "${rc}" -eq 0 ]; then
    posted=$((posted + 1))
  else
    failed=$((failed + 1))
  fi
fi

# ════════════════════════════════════════════════════════════════════
# SINK 3: Splunk HEC (audit-trail ingestion)
# ════════════════════════════════════════════════════════════════════
if [ -z "${SPLUNK_HEC_URL:-}" ] || [ -z "${SPLUNK_HEC_TOKEN:-}" ]; then
  echo "→ splunk-hec           skip (SPLUNK_HEC_URL / SPLUNK_HEC_TOKEN missing)"
elif ! command -v jq >/dev/null 2>&1; then
  echo "  ✗ splunk-hec needs jq for HEC envelope — skipping" >&2
  failed=$((failed + 1))
else
  sourcetype="${VULN_SPLUNK_SOURCETYPE:-${DEFAULT_SOURCETYPE}}"
  echo "→ splunk-hec           POST ${SPLUNK_HEC_URL} (sourcetype=${sourcetype})"
  rc=0
  (
    _scanref="${IMAGE_DIGEST:-${IMAGE_REF:-${UPSTREAM_REF:-unknown}}}"
    _gitsha="${GIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
    # Nest the report under the detected scanner's key so Splunk
    # records clearly show provenance (event.grype vs event.trivy
    # vs event.xray vs event.vuln for unknown).
    jq -nc \
      --arg image     "${_scanref}" \
      --arg gitsha    "${_gitsha}" \
      --arg scanner   "${SCANNER}" \
      --arg key       "${SCANNER_KEY}" \
      --slurpfile rep "${VULN_SCAN_FILE}" \
      '{ scanned_image: $image, git_commit: $gitsha, scanner: $scanner }
       + { ($key): $rep[0] }' \
      > "${_TMP}/hec.json"

    # shellcheck source=../lib/splunk-hec.sh
    . "${TEMPLATE_ROOT}/scripts/lib/splunk-hec.sh"
    splunk_hec_post "${_TMP}/hec.json" "${sourcetype}"
  ) || rc=$?
  if [ "${rc}" -eq 0 ]; then
    posted=$((posted + 1))
  else
    failed=$((failed + 1))
  fi
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "→ vuln-ingest summary: ${posted} posted, ${failed} failed"

if [ "${posted}" -eq 0 ] && [ "${failed}" -eq 0 ]; then
  echo ""
  echo "  No sinks configured. Set one or more to enable ingestion:"
  echo "    - VULN_WEBHOOK_URL (+ optional VULN_WEBHOOK_AUTH_HEADER)"
  echo "    - ARTIFACTORY_URL + ARTIFACTORY_USER + ARTIFACTORY_TOKEN/PASSWORD"
  echo "      + ARTIFACTORY_VULN_ARCHIVE_REPO"
  echo "    - SPLUNK_HEC_URL + SPLUNK_HEC_TOKEN"
fi

[ "${failed}" -gt 0 ] && exit 1
exit 0
