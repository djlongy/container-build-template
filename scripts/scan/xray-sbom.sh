#!/usr/bin/env bash
# ─── DO NOT EDIT — template scan job ───────────────────────────────
# Behaviour comes from image.env (XRAY_SCAN_REF, XRAY_GENERATE_SBOM,
# XRAY_ARTIFACTORY_* overrides). Edit those, not this file.
# ───────────────────────────────────────────────────────────────────
#
# scripts/scan/xray-sbom.sh — JFrog Xray CycloneDX SBOM emitter
#
# Single responsibility: run `jf docker scan --format=cyclonedx --sbom`
# against the upstream image and produce the canonical sbom.cdx.json.
# Hands off to scripts/ingest/sbom-post.sh for vendor-neutral sink shipping
# (Splunk, Dependency-Track, Artifactory, webhook).
#
# Output filename is the SAME as scripts/scan/syft-sbom.sh — both
# write sbom.cdx.json by default. The artifact contract is
# scanner-agnostic so swapping producers (Xray ↔ Syft) keeps
# downstream consumers (Grype, sbom-post) working unchanged.
#
# Pairs with scripts/scan/xray-vuln.sh which produces the simple-json
# vuln scan via a separate jf invocation.
#
# Why a separate scan call rather than reusing xray-vuln's output: jf
# docker scan emits ONE format per invocation (no caching across
# format flags). The CycloneDX output is structurally different from
# simple-json (formal BOM standard, components list, dependencies
# graph) and serves a different audience (audit / compliance / SCA
# tools rather than vuln triage).
#
# Default ON because in environments where Trivy is banned and Syft
# awaits security approval, this is the only working CycloneDX SBOM
# source. Skip via XRAY_GENERATE_SBOM=false in image.env when Syft is
# producing the SBOM and an Xray duplicate isn't needed.
#
# Usage:
#   bash scripts/scan/xray-sbom.sh                 # SBOM of the BUILT image
#                                                  # (IMAGE_DIGEST from
#                                                  #  build.env, fallback
#                                                  #  chain below)
#   bash scripts/scan/xray-sbom.sh <image-ref>     # SBOM of arbitrary ref
#
# Scan target resolution (highest precedence first):
#   1. positional arg $1
#   2. XRAY_SCAN_REF env var (Xray-specific override)
#   3. SBOM_SCAN_REF env var (generic SBOM-producer override — shared
#      with syft-sbom.sh / trivy-sbom.sh)
#   4. IMAGE_DIGEST   (from build.env — the rebuilt image's digest)
#   5. IMAGE_REF      (from build.env — the rebuilt image's tag)
#   6. UPSTREAM_REF   (from image.env — the upstream we rebuilt from)
#   7. UPSTREAM_REGISTRY/UPSTREAM_IMAGE:UPSTREAM_TAG (assembled if all set)
#
# Default targets the BUILT image — same reasoning as xray-vuln.sh.
# Pair with that script as the postscan stage of your pipeline.
#
# Required env (Phase 1 preconditions — no-op when unset):
#   ARTIFACTORY_URL + ARTIFACTORY_USER + ARTIFACTORY_TOKEN/PASSWORD
#     OR explicit XRAY_ARTIFACTORY_URL/USER/TOKEN/PASSWORD overrides.
#
# Optional env:
#   XRAY_GENERATE_SBOM    "true" (default) | "false" → no-op
#   XRAY_SCAN_REF         override the resolved target
#   SBOM_FILE             output path (default sbom.cdx.json — the
#                         canonical name from scripts/lib/artifact-names.sh,
#                         shared with scan/syft-sbom.sh so swapping
#                         producers doesn't break downstream consumers)
#   ARTIFACTORY_PROJECT   pass-through to --project=
#
# Exit codes: 0 (including graceful no-ops), 1 (missing scan target).

set -euo pipefail

TEMPLATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
export TEMPLATE_ROOT PROJECT_ROOT
cd "${PROJECT_ROOT}"

# shellcheck source=../lib/scan-common.sh
. "${TEMPLATE_ROOT}/scripts/lib/scan-common.sh"
scan_bootstrap

# Opt-out gate
if [ "${XRAY_GENERATE_SBOM:-true}" = "false" ]; then
  echo "→ XRAY_GENERATE_SBOM=false — skipping Xray SBOM generation"
  exit 0
fi

# ── Resolve scan target ($1 > XRAY_SCAN_REF > SBOM_SCAN_REF > … chain).
# XRAY_SCAN_REF is the Xray-specific override; SBOM_SCAN_REF is the
# generic SBOM-producer override (syft/trivy honour it too), so swapping
# SBOM producers needs only one var.
SCAN_REF="$(resolve_scan_ref "${1:-}" XRAY_SCAN_REF SBOM_SCAN_REF)" || exit 1
echo "→ Scan target: ${SCAN_REF}"

# ── Phase 1 preconditions: scan-side Artifactory creds ────────────
# PREFER the normal ARTIFACTORY_* creds (Xray usually shares the push
# Artifactory). XRAY_ARTIFACTORY_* is an OPTIONAL fallback for a separate
# Xray-side instance — set those only when scan-side ≠ push-side.
SCAN_ART_URL="${ARTIFACTORY_URL:-${XRAY_ARTIFACTORY_URL:-}}"
SCAN_ART_USER="${ARTIFACTORY_USER:-${XRAY_ARTIFACTORY_USER:-}}"
SCAN_ART_TOKEN="${ARTIFACTORY_TOKEN:-${XRAY_ARTIFACTORY_TOKEN:-}}"
SCAN_ART_PASSWORD="${ARTIFACTORY_PASSWORD:-${XRAY_ARTIFACTORY_PASSWORD:-}}"
ART_SECRET="${SCAN_ART_TOKEN:-${SCAN_ART_PASSWORD}}"
if [ -z "${SCAN_ART_URL}" ] || [ -z "${SCAN_ART_USER}" ] || [ -z "${ART_SECRET}" ]; then
  echo "→ xray-sbom: Xray-side Artifactory creds unset — no-op"
  exit 0
fi

# ── jf install ────────────────────────────────────────────────────
if ! command -v jf >/dev/null 2>&1; then
  # shellcheck source=../lib/install-jf.sh
  . "${TEMPLATE_ROOT}/scripts/lib/install-jf.sh"
  install_jf || {
    echo "WARN: jf install failed — skipping Xray SBOM" >&2
    exit 0
  }
fi

# ── Configure jf (separate server-id from xray-vuln to avoid clash) ─
_url="${SCAN_ART_URL%/}"
if [[ "${_url}" == */artifactory ]]; then
  _art_url="${_url}"
  _platform_url="${_url%/artifactory}"
else
  _art_url="${_url}/artifactory"
  _platform_url="${_url}"
fi
if [ -n "${SCAN_ART_TOKEN}" ]; then
  _auth_flag="--access-token=${SCAN_ART_TOKEN}"
else
  _auth_flag="--password=${SCAN_ART_PASSWORD}"
fi
echo "→ jf config add xray-sbom-server (url=${_platform_url}, user=${SCAN_ART_USER})"
# shellcheck disable=SC2086
jf config add xray-sbom-server \
  --url="${_platform_url}" \
  --artifactory-url="${_art_url}" \
  --user="${SCAN_ART_USER}" \
  ${_auth_flag} \
  --interactive=false \
  --overwrite=true >/dev/null
jf config use xray-sbom-server >/dev/null

# ── Multi-registry docker login (mirrors xray-vuln.sh's flow) ─────
# shellcheck source=../lib/docker-login.sh
. "${TEMPLATE_ROOT}/scripts/lib/docker-login.sh"
docker_login_all_registries

# ── Pre-pull image ────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI not on PATH — jf docker scan needs local docker" >&2
  exit 1
fi
echo "→ docker pull ${SCAN_REF}"
if ! docker pull "${SCAN_REF}" >/dev/null 2>/tmp/xray-sbom-pull.err; then
  echo "ERROR: docker pull failed — cannot scan a missing local image" >&2
  echo "── pull error ──" >&2
  sed 's/^/  /' /tmp/xray-sbom-pull.err >&2 || true
  echo "  Check: registry credentials in env, network reachability, image ref correctness." >&2
  exit 1
fi

# ── Digest refs → re-tag before scanning ───────────────────────────
# `jf docker scan` indexes by running `docker save <ref>` and feeding
# the tarball to Xray's indexer. A digest-only ref (repo@sha256:…)
# saves with RepoTags:null, and the indexer then UNDER-reports — a
# tiny SBOM instead of the full component graph. Re-tag the pulled
# image to a local alias so the saved tarball carries a RepoTag; the
# image id is identical, so this only fixes the naming context. Tag
# refs pass through unchanged. Prefer IMAGE_REF for a meaningful name.
SCAN_IMG="${SCAN_REF}"
XRAY_SCAN_ALIAS=""
case "${SCAN_REF}" in
  *@sha256:*)
    alias_ref="${IMAGE_REF:-}"
    if [ -z "${alias_ref}" ] || [ "${alias_ref}" = "${SCAN_REF}" ]; then
      alias_ref="${SCAN_REF%@*}:xray-scan"
    fi
    if docker tag "${SCAN_REF}" "${alias_ref}" 2>/dev/null; then
      echo "→ digest ref → scanning via local tag alias ${alias_ref}"
      echo "  (digest 'docker save' has RepoTags:null → Xray under-indexes; alias restores it)"
      SCAN_IMG="${alias_ref}"
      XRAY_SCAN_ALIAS="${alias_ref}"
    fi
    ;;
esac

# ── Generate SBOM ─────────────────────────────────────────────────
# SBOM_FILE is the canonical CycloneDX filename (default sbom.cdx.json
# from scripts/lib/artifact-names.sh; build.env override wins). Treat
# bare names as PROJECT_ROOT-relative.
case "${SBOM_FILE}" in
  /*) SBOM_FILE_OUT="${SBOM_FILE}" ;;
  *)  SBOM_FILE_OUT="${PROJECT_ROOT}/${SBOM_FILE}" ;;
esac
PROJECT_FLAG=""
[ -n "${ARTIFACTORY_PROJECT:-}" ] && PROJECT_FLAG="--project=${ARTIFACTORY_PROJECT}"

echo "→ jf docker scan --format=cyclonedx --sbom ${PROJECT_FLAG} ${SCAN_IMG}"
set +e
# shellcheck disable=SC2086
jf docker scan ${PROJECT_FLAG} \
  --format=cyclonedx \
  --sbom \
  --fail=false \
  "${SCAN_IMG}" \
  > "${SBOM_FILE_OUT}" 2>/tmp/xray-sbom.err
SBOM_RC=$?
set -e

if [ ! -s "${SBOM_FILE_OUT}" ]; then
  echo "ERROR: jf docker scan (cyclonedx) produced no output (rc=${SBOM_RC})" >&2
  echo "── stderr ──" >&2
  sed 's/^/  /' /tmp/xray-sbom.err >&2 || true
  echo "  Common causes: image not pulled into local daemon, Xray service" >&2
  echo "  unreachable, or credentials wrong. The job will fail visibly so" >&2
  echo "  the gap is noticed (allow_failure: true at the CI level still" >&2
  echo "  prevents this from blocking downstream jobs)." >&2
  exit 1
fi

# Validate JSON shape (jf occasionally emits a warning above the JSON).
if command -v jq >/dev/null 2>&1; then
  if ! jq empty "${SBOM_FILE_OUT}" >/dev/null 2>&1; then
    echo "ERROR: ${SBOM_FILE_OUT} is not valid JSON — keeping as artifact for debug" >&2
    exit 1
  fi
  COMPONENT_COUNT="$(jq '.components | length' "${SBOM_FILE_OUT}" 2>/dev/null || echo '?')"
  VULN_COUNT="$(jq '.vulnerabilities | length' "${SBOM_FILE_OUT}" 2>/dev/null || echo '?')"
  echo "  ✓ Xray SBOM: ${SBOM_FILE_OUT} ($(wc -c < "${SBOM_FILE_OUT}") bytes, ${COMPONENT_COUNT} components, ${VULN_COUNT} vulns inline, rc=${SBOM_RC})"
else
  echo "  ✓ Xray SBOM: ${SBOM_FILE_OUT} ($(wc -c < "${SBOM_FILE_OUT}") bytes, rc=${SBOM_RC})"
fi

# ── Free disk (mirrors xray-vuln.sh's cleanup) ─────────────────────
rm -rf /tmp/jfrog.cli.temp.* 2>/dev/null || true
if command -v docker >/dev/null 2>&1; then
  docker rmi -f "${SCAN_REF}" >/dev/null 2>&1 || true
  [ -n "${XRAY_SCAN_ALIAS}" ] && docker rmi -f "${XRAY_SCAN_ALIAS}" >/dev/null 2>&1 || true
fi

# ── Optional inline hand-off to sbom-post.sh (defaults TRUE for Xray) ─
# Xray natively scans + posts in one operation, so SBOM_INLINE_POST
# defaults to TRUE here. Syft + Trivy default FALSE. Generic —
# sbom-post.sh handles ALL sinks (webhook / DT / Artifactory / Splunk).
case "$(printf '%s' "${SBOM_INLINE_POST:-true}" | tr '[:upper:]' '[:lower:]')" in
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
