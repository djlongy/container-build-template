#!/usr/bin/env bash
# ─── DO NOT EDIT — template push backend (Artifactory JCR Free tier) ─
# Selected via REGISTRY_KIND="artifactory_jcr" in image.env. Uses
# only Free-tier commands (plain `docker push`, manual layer property
# tagging, build-info reconstruction via scripts/lib/build-info-merge.py)
# so the same code works on the JFrog Container Registry Free edition
# AND on self-hosted Artifactory Free without any Pro licence.
#
# All ARTIFACTORY_* knobs (URL, USER, TOKEN, TEAM, layout templates,
# …) come from image.env + masked CI vars. Edit those, not this file.
#
# If you have a Pro / Cloud Artifactory licence, switch to the lighter
# artifactory_pro.sh backend by setting REGISTRY_KIND="artifactory_pro"
# in image.env. The Pro backend doesn't need python3 and avoids ~830
# lines of compensating-for-Free-tier code (manifest fetching, layer
# property iteration, build-info merger).
# ───────────────────────────────────────────────────────────────────
#
# What this backend does on Free that Pro does natively:
#
# | Step                | JCR Free (this file)                            | PRO equivalent (artifactory_pro.sh)        |
# |---------------------|-------------------------------------------------|--------------------------------------------|
# | Docker push         | plain `docker push`                             | `jf docker push --build-name --build-number` |
# | Build info collect  | `jf rt bp --collect-env --collect-git`          | `jf build-collect-env` + `jf build-add-git` |
# | Build info publish  | side-build modules via build-info-merge.py + PUT | `jf build-publish --project`               |
# | Module linkage      | reconstruct artifacts[] + dependencies[] from manifests | automatic via `jf docker push`     |
# | Property tagging    | manual per-layer `jf rt set-props` loop          | automatic during `jf docker push`          |
# | Xray scans          | not available (Xray needs Pro)                   | optional `jf docker scan` / `jf build-scan` |
#
# Required CLI deps: jf, docker, python3 (for the build-info merger).
#
# ── Variables this backend reads ────────────────────────────────────
#
# Required:
#   ARTIFACTORY_URL, ARTIFACTORY_USER,
#   ARTIFACTORY_TOKEN | ARTIFACTORY_PASSWORD,
#   ARTIFACTORY_TEAM
#
# Optional:
#   ARTIFACTORY_ENVIRONMENT, ARTIFACTORY_PUSH_HOST,
#   ARTIFACTORY_IMAGE_REF, ARTIFACTORY_MANIFEST_PATH,
#   ARTIFACTORY_BUILD_NAME, ARTIFACTORY_BUILD_NUMBER,
#   ARTIFACTORY_PROPERTIES
#
# Auto-install (air-gap):
#   JF_BINARY_URL, JF_DEB_URL, JF_RPM_URL, JF_INSTALL_DIR
#
# See image.env.example for what each variable does and its default.

set -uo pipefail

# Pull in the common (shared) helpers. The file lives in the same
# directory as this one.
# shellcheck source=./artifactory_common.sh
. "$(dirname "${BASH_SOURCE[0]}")/artifactory_common.sh"

# ════════════════════════════════════════════════════════════════════
# JCR Free-specific helpers
# ════════════════════════════════════════════════════════════════════

# FREE-tier build info publish WITH module linkage.
#
# Two-step publish so we get jf's sensitive-value env filter AND our
# module data on a tier without jf docker push:
#   1. `jf rt bp --collect-env --collect-git-info` publishes a skeletal
#      build record with env + git, using jf's own secret redaction
#      (more comprehensive than a regex).
#   2. We GET that record back, side-load the final + upstream manifests
#      via the curl helpers, and hand everything to build-info-merge.py
#      which writes a modules-enriched JSON PUT to /api/build.
#
# Caveat: Packages → Produced By in the Artifactory UI is Pro-gated
# (calls /api/search/buildArtifacts, which returns HTTP 400 on Free).
# The build record itself — Artifacts, Dependencies, Env, Properties
# tabs — renders correctly.
_artifactory_jcr_build_publish_with_modules() {
  local build_name="$1" build_number="$2" manifest_path="$3" target="$4"
  local secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD}}"
  local _url="${ARTIFACTORY_URL%/}"
  _url="${_url%/artifactory}"
  local art_base="${_url}/artifactory"

  # Capture epoch-ms at the start so the Python merger can compute
  # durationMillis for the build-info UI "Duration" field.
  local started_ms
  started_ms=$(python3 -c 'import time; print(int(time.time()*1000))')

  # Step 1: jf rt bp publishes build info with env + git, using jf's
  # own sensitive-value filtering (more comprehensive than regex).
  echo ""
  echo "── JCR: publishing baseline build info via jf rt bp ──"
  jf rt bp "${build_name}" "${build_number}" \
    --collect-env --collect-git-info 2>/dev/null || true

  # Step 2: GET the published record back so we can merge modules
  # into it (preserving jf's filtered env vars + git context).
  echo "── JCR: fetching published build info for merge ──"
  # Write directly to file instead of capturing in a shell variable —
  # the JSON can contain special characters in env var values that
  # break shell variable assignment.
  local _bi_tmpfile
  _bi_tmpfile=$(mktemp)
  local _bi_http_code
  _bi_http_code=$(curl -sSL -o "${_bi_tmpfile}" -w "%{http_code}" \
    -u "${ARTIFACTORY_USER}:${secret}" \
    "${art_base}/api/build/${build_name}/${build_number}" 2>/dev/null)
  if [ "${_bi_http_code}" = "200" ] && [ -s "${_bi_tmpfile}" ]; then
    echo "  ✓ fetched (HTTP ${_bi_http_code}, $(wc -c < "${_bi_tmpfile}" | tr -d ' ') bytes)"
  else
    echo "  WARN: fetch returned HTTP ${_bi_http_code} — env vars won't be merged" >&2
    rm -f "${_bi_tmpfile}"
    _bi_tmpfile=""
  fi

  echo "── JCR: building module linkage from storage API ──"

  # Get the tag directory path (strip manifest.json from the end)
  local tag_dir="${manifest_path%/manifest.json}"
  local repo_name="${tag_dir%%/*}"
  local tag_subpath="${tag_dir#*/}"

  # List all files in the tag directory and build the module JSON
  # using Python for reliable JSON construction (sed-based assembly
  # was producing malformed JSON with special characters in paths).
  local listing
  listing=$(curl -fsSL -u "${ARTIFACTORY_USER}:${secret}" \
    "${art_base}/api/storage/${tag_dir}" 2>/dev/null) || {
    echo "  WARN: could not list ${tag_dir} — skipping module linkage" >&2
    return 0
  }

  # Extract filenames from the listing (proper JSON parse, not sed/grep)
  local files_list
  files_list=$(printf '%s' "${listing}" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for child in d.get('children', []):
        uri = child.get('uri', '').lstrip('/')
        if uri:
            print(uri)
except json.JSONDecodeError:
    pass
")

  if [ -z "${files_list}" ]; then
    echo "  WARN: no files found in ${tag_dir} — skipping module linkage" >&2
    return 0
  fi

  # Fetch checksums for each file and build the JSON via Python.
  # Write one JSON line per file to a temp file, then assemble.
  local tmpdir
  tmpdir=$(mktemp -d)
  local file_count=0

  while IFS= read -r fname; do
    [ -z "${fname}" ] && continue
    curl -fsSL -u "${ARTIFACTORY_USER}:${secret}" \
      "${art_base}/api/storage/${tag_dir}/${fname}" \
      > "${tmpdir}/file_${file_count}.json" 2>/dev/null && \
      echo "${fname}" > "${tmpdir}/name_${file_count}.txt"
    file_count=$((file_count + 1))
  done <<< "${files_list}"

  # Get git info
  local git_rev="" git_url=""
  if git rev-parse HEAD >/dev/null 2>&1; then
    git_rev=$(git rev-parse HEAD)
    git_url=$(git config --get remote.origin.url 2>/dev/null || echo "")
  fi

  local started
  started=$(date -u +"%Y-%m-%dT%H:%M:%S.000+0000")

  # Side-load final + upstream manifests for accurate per-blob
  # dependency classification. Two small registry calls (~2 KB each)
  # replace the old "first N blobs" heuristic, which was wrong whenever
  # the storage listing order didn't match the layer order or when the
  # upstream wasn't locally tagged under the expected ref.
  _artifactory_jcr_fetch_manifests_for_merge "${target}" "${tmpdir}"

  # Copy the fetched build info into the tmpdir for Python to read
  if [ -n "${_bi_tmpfile}" ] && [ -f "${_bi_tmpfile}" ]; then
    mv "${_bi_tmpfile}" "${tmpdir}/published-bi.json"
  fi

  # Assemble the build info JSON with Python — merges modules into
  # the jf-published record (preserving env vars + git + VCS from jf).
  local _backend_dir
  _backend_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # docker.image.id = config blob digest of the local tagged image.
  # Pro's jf docker push populates this automatically; on Free we read
  # it from the Docker daemon while the image is still present.
  local docker_image_id
  docker_image_id=$(docker inspect --format '{{.Id}}' "${target}" 2>/dev/null || echo "")

  python3 "${_backend_dir}/../lib/build-info-merge.py" \
    "${tmpdir}" "${file_count}" "${tag_subpath}" \
    "${build_name}" "${build_number}" "${target}" \
    "${IMAGE_NAME}" "${IMAGE_TAG}" "${git_rev}" "${git_url}" \
    "${started}" \
    "${repo_name}" "${started_ms}" "${docker_image_id}"

  # PUT to /api/build
  echo "── JCR: publishing enriched build info ──"
  local http_code
  http_code=$(curl -fsSL -o /dev/null -w "%{http_code}" \
    -X PUT -u "${ARTIFACTORY_USER}:${secret}" \
    -H "Content-Type: application/json" \
    --data-binary "@${tmpdir}/build-info.json" \
    "${art_base}/api/build" 2>/dev/null) || true

  if [ "${http_code}" = "204" ]; then
    echo "  ✓ build info published with module linkage"
  else
    echo "  WARN: enriched build info publish returned HTTP ${http_code}" >&2
    echo "        (modules may not appear in the Packages UI)" >&2
  fi

  rm -rf "${tmpdir}"
}

# Set build.name + build.number props on ALL files in a tag directory.
# On Pro, jf docker push does this automatically. On Free, we iterate.
_artifactory_jcr_set_props_all_layers() {
  local manifest_path="$1" build_name="$2" build_number="$3"
  local tag_dir="${manifest_path%/manifest.json}"
  local props="build.name=${build_name};build.number=${build_number}"
  local secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD}}"
  local _url="${ARTIFACTORY_URL%/}"
  _url="${_url%/artifactory}"
  local art_base="${_url}/artifactory"

  local listing
  listing=$(curl -fsSL -u "${ARTIFACTORY_USER}:${secret}" \
    "${art_base}/api/storage/${tag_dir}" 2>/dev/null) || return 0

  local count=0
  local files_list
  files_list=$(printf '%s' "${listing}" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for child in d.get('children', []):
        uri = child.get('uri', '').lstrip('/')
        if uri:
            print(uri)
except json.JSONDecodeError:
    pass
")
  while IFS= read -r fname; do
    [ -z "${fname}" ] && continue
    # Swallow jf's per-call `{"status":"success",...}` stdout blob —
    # on the Free path we iterate over every blob in the tag dir and
    # the repetition is just noise. The trailing "set on N files" line
    # below is the one user-facing summary.
    jf rt set-props "${tag_dir}/${fname}" "${props}" >/dev/null 2>&1 && count=$((count + 1))
  done <<< "${files_list}"

  echo "  ✓ build.name/build.number set on ${count} files"
}

# Fetch a v2 distribution manifest via curl. ARTIFACTORY creds are used
# (push target and upstream proxy both live on the same Artifactory in
# our topology; public upstreams ignore the auth header). Empty stdout
# on failure.
_artifactory_jcr_curl_manifest() {
  local ref="$1"
  local secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD:-}}"
  local host repo_ref repo reference
  host="${ref%%/*}"
  repo_ref="${ref#*/}"
  if [[ "${repo_ref}" == *"@"* ]]; then
    repo="${repo_ref%@*}"
    reference="${repo_ref#*@}"
  else
    repo="${repo_ref%:*}"
    reference="${repo_ref##*:}"
  fi
  local accept="application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json"
  local auth=()
  [ -n "${secret}" ] && auth=(-u "${ARTIFACTORY_USER:-}:${secret}")
  curl -fsSL "${auth[@]}" -H "Accept: ${accept}" \
    "https://${host}/v2/${repo}/manifests/${reference}" 2>/dev/null
}

# Fetch a blob by digest. Used to pull the upstream image config so we
# can read rootfs.diff_ids (stable across docker re-compression).
_artifactory_jcr_curl_blob() {
  local ref="$1" digest="$2"
  local secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD:-}}"
  local host repo_ref repo
  host="${ref%%/*}"
  repo_ref="${ref#*/}"
  repo="${repo_ref%@*}"
  repo="${repo%:*}"
  local auth=()
  [ -n "${secret}" ] && auth=(-u "${ARTIFACTORY_USER:-}:${secret}")
  curl -fsSL "${auth[@]}" \
    "https://${host}/v2/${repo}/blobs/${digest}" 2>/dev/null
}

# Side-load the data build-info-merge.py needs to classify blobs
# accurately on the Free path without any post-push round trip through
# the merger. Two files end up in <tmpdir>:
#
#   final-manifest.json   distribution v2 manifest of what we pushed
#                         (config.digest + layers[].digest in order)
#   upstream-diffids.json upstream's rootfs.diff_ids, used only for its
#                         length (= upstream layer count)
#
# Python then marks the first N entries of final-manifest.layers[] as
# dependencies, where N = len(upstream-diffids). This matches what Pro's
# `jf docker push` records on the Pro path — same semantics, same data
# shape — just derived from REST rather than the internal Go pipeline.
# Handles multi-arch upstream by resolving the manifest list to the
# PLATFORM-matching child (default linux/amd64). Silent on any failure
# — Python falls back to "all non-config blobs are dependencies".
_artifactory_jcr_fetch_manifests_for_merge() {
  local target="$1" tmpdir="$2"

  # FINAL manifest = our pushed image, in our Artifactory. Basic auth
  # via the existing curl helper works because we already have
  # ARTIFACTORY_USER + ARTIFACTORY_TOKEN/PASSWORD in env.
  local final_body
  final_body=$(_artifactory_jcr_curl_manifest "${target}")
  [ -n "${final_body}" ] && printf '%s' "${final_body}" > "${tmpdir}/final-manifest.json"

  [ -z "${UPSTREAM_REF:-}" ] && return 0

  # UPSTREAM config = whatever public registry the user pulls from
  # (docker.io / gcr / ghcr / mcr / quay / private mirror). The earlier
  # curl path failed silently for docker.io because:
  #
  #   1. docker.io is not the registry — registry-1.docker.io is
  #      (docker.io/v2/... returns HTTP 302 redirect to the website)
  #   2. registry-1.docker.io requires a bearer token from
  #      auth.docker.io, not basic auth with Artifactory creds
  #
  # When the upstream fetch failed, the merger fell into "fallback"
  # mode — counting ALL non-config sha256 blobs as dependencies, which
  # over-counts by the number of layers we added on top of upstream.
  #
  # Using `crane config <upstream-ref>` skips both problems: it
  # handles each registry's auth transparently (bearer for docker hub,
  # static for gcr/ghcr/mcr/quay public, basic from
  # ~/.docker/config.json for private), AND auto-resolves multi-arch
  # indices to the local-platform manifest in one call. It returns the
  # config JSON directly — we extract rootfs.diff_ids from it. Crane
  # is already on PATH (build.sh installs it for the BASE_DIGEST OCI
  # label resolution), so no new dependency.
  #
  # Falls through to the legacy curl-then-walk path if crane is
  # somehow missing — that path still works for upstreams hosted in
  # the same Artifactory as the push target (proxy / remote repo).
  if command -v crane >/dev/null 2>&1; then
    if crane config "${UPSTREAM_REF}" 2>/dev/null \
         | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
json.dump(cfg.get('rootfs', {}).get('diff_ids', []), sys.stdout)" \
         > "${tmpdir}/upstream-diffids.json" 2>/dev/null \
       && [ -s "${tmpdir}/upstream-diffids.json" ]; then
      return 0
    fi
    rm -f "${tmpdir}/upstream-diffids.json"
  fi

  # ── Fallback: legacy curl path ────────────────────────────────────
  # Works when upstream is on the same Artifactory as the push (proxy
  # repos with our auth). Doesn't work for direct public docker.io
  # without bearer-auth handling — that's covered by the crane branch.
  local upstream_body
  upstream_body=$(_artifactory_jcr_curl_manifest "${UPSTREAM_REF}")
  [ -z "${upstream_body}" ] && return 0

  local upstream_effective_ref="${UPSTREAM_REF}"
  if printf '%s' "${upstream_body}" | grep -q '"manifests"'; then
    local plat="${PLATFORM:-linux/amd64}"
    local plat_digest
    plat_digest=$(printf '%s' "${upstream_body}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
os_, arch = '${plat}'.split('/', 1)
for m in d.get('manifests', []):
    p = m.get('platform', {})
    if p.get('os') == os_ and p.get('architecture') == arch:
        print(m.get('digest', '')); break
" 2>/dev/null)
    [ -z "${plat_digest}" ] && {
      echo "  WARN: upstream manifest list has no ${plat} variant" >&2
      return 0
    }
    local upstream_base="${UPSTREAM_REF%:*}"
    upstream_effective_ref="${upstream_base}@${plat_digest}"
    upstream_body=$(_artifactory_jcr_curl_manifest "${upstream_effective_ref}")
    [ -z "${upstream_body}" ] && return 0
  fi

  local upstream_config_digest
  upstream_config_digest=$(printf '%s' "${upstream_body}" | python3 -c "
import json, sys
print(json.load(sys.stdin).get('config', {}).get('digest', ''))" 2>/dev/null)
  [ -z "${upstream_config_digest}" ] && return 0

  _artifactory_jcr_curl_blob "${upstream_effective_ref}" "${upstream_config_digest}" \
    | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
json.dump(cfg.get('rootfs', {}).get('diff_ids', []), sys.stdout)" \
    > "${tmpdir}/upstream-diffids.json" 2>/dev/null || \
    rm -f "${tmpdir}/upstream-diffids.json"
}

# ── Flow orchestrator ──────────────────────────────────────────────
_artifactory_jcr_flow() {
  local built_local_ref="$1"
  docker tag "${built_local_ref}" "${_ART_TARGET}"

  local push_output
  push_output=$(docker push "${_ART_TARGET}" 2>&1) || {
    echo "${push_output}" >&2
    echo "ERROR: docker push to Artifactory failed" >&2
    return 1
  }
  echo "${push_output}"

  local push_digest
  push_digest=$(_artifactory_resolve_push_digest "${_ART_TARGET}" "${push_output}")
  _artifactory_write_build_env "${_ART_TARGET}" "${push_digest}"

  # Build info WITH module linkage — constructs artifacts[] and
  # dependencies[] from storage-API checksums + side-loaded manifests.
  # Same data shape jf docker push writes on Pro. The Packages →
  # Produced By UI hyperlink is Pro-gated; the linkage data is still
  # correctly stored and surfaces in the Build's own tabs.
  _artifactory_jcr_build_publish_with_modules \
    "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}" "${_ART_MANIFEST_PATH}" "${_ART_TARGET}"

  # Set build.name + build.number on every blob for "Used by Build"
  # UI backlinks. Pro's jf docker push does this automatically — on
  # Free we iterate manually.
  _artifactory_jcr_set_props_all_layers "${_ART_MANIFEST_PATH}" \
    "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}"

  # Custom metadata props on the manifest.
  _artifactory_set_props "${_ART_MANIFEST_PATH}" \
    "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}" "${ARTIFACTORY_ENVIRONMENT}"
}

# ── Entry point ─────────────────────────────────────────────────────

push_to_backend() {
  local built_local_ref="$1"

  _artifactory_jcr_require_env   || return 1
  _artifactory_jcr_require_tools || return 1

  # JCR is the Free path — explicitly clear ARTIFACTORY_PRO in case
  # it's set, so the banner shows the right tier and the common
  # helpers don't accidentally trigger Pro behaviour.
  export ARTIFACTORY_PRO="false"
  _artifactory_normalise_bools
  _artifactory_decompose_ref "${built_local_ref}"
  _artifactory_resolve_templates

  _artifactory_jf_config || return 1
  _artifactory_docker_login "${ARTIFACTORY_PUSH_HOST}" || return 1

  _artifactory_print_banner "${built_local_ref}"

  _artifactory_jcr_flow "${built_local_ref}" || return 1

  echo "Pushed: ${_ART_TARGET}"
}

# ── Internals ────────────────────────────────────────────────────────

_artifactory_jcr_require_env() {
  local missing=0 var
  for var in ARTIFACTORY_URL ARTIFACTORY_USER ARTIFACTORY_TEAM; do
    if [ -z "${!var:-}" ]; then
      echo "ERROR: ${var} is required when REGISTRY_KIND=artifactory_jcr" >&2
      missing=1
    fi
  done
  if [ -z "${ARTIFACTORY_TOKEN:-}" ] && [ -z "${ARTIFACTORY_PASSWORD:-}" ]; then
    echo "ERROR: set either ARTIFACTORY_TOKEN (preferred) or ARTIFACTORY_PASSWORD" >&2
    missing=1
  fi
  return "${missing}"
}
# Public alias — build.sh's _build_validate_backend looks up
# `${kind}_require_env`.
artifactory_jcr_require_env() { _artifactory_jcr_require_env "$@"; }

# JCR require_tools: base (jf + docker) PLUS python3, which the
# build-info merger + JSON parsers depend on.
_artifactory_jcr_require_tools() {
  local missing=0
  _artifactory_require_tools_base || missing=1
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: 'python3' required for the JCR build-info merge flow" >&2
    echo "       (scripts/lib/build-info-merge.py + JSON parsers in artifactory_jcr.sh)" >&2
    echo "       Install python3 (alpine: apk add python3) OR switch to" >&2
    echo "       REGISTRY_KIND=artifactory_pro if you have a Pro licence" >&2
    echo "       (Pro uses jf's native build-info publishing, no python3 needed)." >&2
    missing=1
  fi
  return "${missing}"
}
