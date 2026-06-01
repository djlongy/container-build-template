#!/usr/bin/env bash
# ─── DO NOT EDIT — shared between artifactory_jcr.sh + artifactory_pro.sh ───
# Functions used by BOTH JFrog Container Registry (Free) and Pro
# backends. Sourced via `. "$(dirname "${BASH_SOURCE[0]}")/artifactory_common.sh"`
# at the top of each tier's backend file.
#
# Deliberately kept in scripts/push-backends/ (NOT scripts/lib/) so a
# reader opening this folder sees all the artifactory backend code in
# one place — no jumping to lib/ to follow the call chain.
# ───────────────────────────────────────────────────────────────────
#
# What's here:
#   _artifactory_normalise_bools         lowercase boolean env vars
#   _artifactory_decompose_ref           extract IMAGE_NAME / IMAGE_TAG / push host
#   _artifactory_expand_template         ${VAR} substitution in layout templates
#   _artifactory_resolve_templates       produce _ART_TARGET / _ART_MANIFEST_PATH / build name+number
#   _artifactory_print_banner            "=== Artifactory push ===" with tier line
#   _artifactory_resolve_push_digest     crane → docker inspect → push-output fallback
#   _artifactory_write_build_env         emit build.env for downstream CI stages
#   _artifactory_require_tools_base      jf + docker check (callers add tier-specific deps)
#   _artifactory_install_jf              sudoless install via scripts/lib/install-jf.sh
#   _artifactory_jf_config               jf config add + use
#   _artifactory_docker_login            docker login to the push host
#   _artifactory_resolve_manifest_filename  multi-arch (list.manifest.json) vs single (manifest.json)
#   _artifactory_set_props               custom property tagging on the pushed manifest

# shellcheck disable=SC2148
# (sourced, not executed — no shebang interpretation needed)

# Normalise the three Xray-related booleans plus ARTIFACTORY_PRO.
# Safe to call from both tiers; Free callers just see the Pro vars
# stay at their defaults.
_artifactory_normalise_bools() {
  ARTIFACTORY_PRO="$(printf '%s' "${ARTIFACTORY_PRO:-false}"                                 | tr '[:upper:]' '[:lower:]')"
  ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS="$(printf '%s' "${ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS:-false}" | tr '[:upper:]' '[:lower:]')"
  ARTIFACTORY_BUILD_XRAY_PRESCAN="$(printf '%s' "${ARTIFACTORY_BUILD_XRAY_PRESCAN:-false}"      | tr '[:upper:]' '[:lower:]')"
  ARTIFACTORY_BUILD_XRAY_POSTSCAN="$(printf '%s' "${ARTIFACTORY_BUILD_XRAY_POSTSCAN:-false}"     | tr '[:upper:]' '[:lower:]')"
}

# Split the locally-built ref (e.g. reg/proj/nginx:1.25-abc) into the
# short IMAGE_NAME + IMAGE_TAG the layout templates expect, derive
# ARTIFACTORY_PUSH_HOST + ARTIFACTORY_REPO_SUFFIX, and export the lot.
_artifactory_decompose_ref() {
  local built_local_ref="$1"
  local image_repo_tag="${built_local_ref##*/}"

  export IMAGE_NAME="${image_repo_tag%:*}"
  export IMAGE_TAG="${image_repo_tag##*:}"
  export ARTIFACTORY_TEAM

  : "${ARTIFACTORY_ENVIRONMENT:=dev}"
  case "${ARTIFACTORY_ENVIRONMENT}" in
    prod|production) export ARTIFACTORY_REPO_SUFFIX="prod"  ;;
    *)               export ARTIFACTORY_REPO_SUFFIX="local" ;;
  esac
  export ARTIFACTORY_ENVIRONMENT

  if [ -z "${ARTIFACTORY_PUSH_HOST:-}" ]; then
    local _host="${ARTIFACTORY_URL#https://}"
    _host="${_host#http://}"
    _host="${_host%%/*}"
    ARTIFACTORY_PUSH_HOST="${_host}"
  fi
  export ARTIFACTORY_PUSH_HOST
}

# Expand ${VAR} references in a template string using bash parameter
# expansion. Only the whitelisted variables below are substituted —
# anything else is left untouched. Safer than `eval` because it can't
# execute arbitrary code if a variable value contains backticks, $(...),
# or semicolons.
_artifactory_expand_template() {
  local tpl="$1"
  local v
  for v in ARTIFACTORY_PUSH_HOST ARTIFACTORY_TEAM ARTIFACTORY_ENVIRONMENT \
           ARTIFACTORY_REPO_SUFFIX IMAGE_NAME IMAGE_TAG; do
    tpl="${tpl//\$\{${v}\}/${!v:-}}"
  done
  printf '%s' "${tpl}"
}

# Resolve layout templates to concrete `_ART_TARGET` + `_ART_MANIFEST_PATH`.
# Plus computes the build name / number for build-info publishing.
# _ART_PROJECT_KEY and _ART_PROJECT_FLAG are computed here even on the
# Free path (just stay empty / unused there) so the banner function can
# read them unconditionally.
_artifactory_resolve_templates() {
  local image_ref_tpl manifest_path_tpl
  if [ -n "${ARTIFACTORY_IMAGE_REF:-}" ]; then
    image_ref_tpl="${ARTIFACTORY_IMAGE_REF}"
  else
    image_ref_tpl='${ARTIFACTORY_PUSH_HOST}/${ARTIFACTORY_TEAM}/${IMAGE_NAME}:${IMAGE_TAG}'
  fi
  if [ -n "${ARTIFACTORY_MANIFEST_PATH:-}" ]; then
    manifest_path_tpl="${ARTIFACTORY_MANIFEST_PATH}"
  else
    manifest_path_tpl='${ARTIFACTORY_TEAM}-docker-${ARTIFACTORY_REPO_SUFFIX}/${IMAGE_NAME}/${IMAGE_TAG}/manifest.json'
  fi

  _ART_TARGET=$(_artifactory_expand_template "${image_ref_tpl}")
  _ART_MANIFEST_PATH=$(_artifactory_expand_template "${manifest_path_tpl}")
  _ART_BUILD_NAME="${ARTIFACTORY_BUILD_NAME:-${IMAGE_NAME}-build}"
  # Build-number resolution chain (highest precedence first):
  #   ARTIFACTORY_BUILD_NUMBER  explicit override (image.env / CI var)
  #   CI_JOB_ID                 GitLab job id
  #   CI_PIPELINE_ID            GitLab pipeline id
  #   BUILD_NUMBER              Jenkins (and generic CI convention)
  #   bamboo_buildNumber        Bamboo agent env (always exported)
  #   GITHUB_RUN_ID             GitHub Actions
  #   <UTC timestamp>           last-resort so local builds always work
  _ART_BUILD_NUMBER="${ARTIFACTORY_BUILD_NUMBER:-${CI_JOB_ID:-${CI_PIPELINE_ID:-${BUILD_NUMBER:-${bamboo_buildNumber:-${GITHUB_RUN_ID:-$(date -u +"%Y-%m-%dT%H-%M-%SZ")}}}}}}"
  _ART_IS_PRO="${ARTIFACTORY_PRO}"
  _ART_PROJECT_KEY="${ARTIFACTORY_PROJECT:-${ARTIFACTORY_TEAM:-}}"
  _ART_PROJECT_FLAG=""
  if [ "${_ART_IS_PRO}" = "true" ] && [ -n "${_ART_PROJECT_KEY}" ]; then
    _ART_PROJECT_FLAG="--project=${_ART_PROJECT_KEY}"
  fi
}

# Single banner that works for both tiers. The Pro file may set
# _ART_SKIP_BUILD_POSTSCAN=1 in its preflight when a project is missing
# — banner reads that to surface the downgrade.
_artifactory_print_banner() {
  local built_local_ref="$1"
  echo ""
  echo "=== Artifactory push ==="
  echo "  Source (local):  ${built_local_ref}"
  echo "  Target:          ${_ART_TARGET}"
  echo "  Push host:       ${ARTIFACTORY_PUSH_HOST}"
  echo "  Manifest path:   ${_ART_MANIFEST_PATH}"
  echo "  Build name:      ${_ART_BUILD_NAME}"
  echo "  Build number:    ${_ART_BUILD_NUMBER}"
  if [ "${_ART_IS_PRO}" = "true" ]; then
    if [ "${_ART_SKIP_BUILD_POSTSCAN:-0}" = "1" ]; then
      echo "  Tier:            PRO (downgraded — project '${_ART_PROJECT_KEY}' missing; build-info goes to global namespace, scans skipped)"
    else
      echo "  Tier:            PRO (project=${_ART_PROJECT_KEY})"
    fi
  else
    echo "  Tier:            JCR Free (baseline — no Pro features)"
  fi
}

# Single source of truth for digest resolution after a push. Prefers
# crane (manifest-only, fast) then falls back to docker inspect. Takes
# an optional push_output parameter to mine for "digest: sha256:…"
# lines left by `docker push` on the Free path. Echoes the digest or
# empty string to stdout.
_artifactory_resolve_push_digest() {
  local target="$1" push_output="${2:-}"
  local digest=""
  if command -v crane >/dev/null 2>&1; then
    digest=$(crane digest "${target}" 2>/dev/null || echo "")
  fi
  if [ -z "${digest}" ]; then
    digest=$(docker inspect --format='{{index .RepoDigests 0}}' "${target}" 2>/dev/null | grep -oE 'sha256:[0-9a-f]{64}' || echo "")
  fi
  if [ -z "${digest}" ] && [ -n "${push_output}" ]; then
    digest=$(printf '%s' "${push_output}" | awk '/digest: sha256:/{print $3}' | head -1)
  fi
  printf '%s' "${digest}"
}

# Export IMAGE_REF + IMAGE_DIGEST to the parent shell (build.sh reads
# them for SBOM generation), then write build.env for downstream CI.
_artifactory_write_build_env() {
  local target="$1" push_digest="$2"
  local image_ref_bare="${target%:*}"
  local digest_ref=""
  [ -n "${push_digest}" ] && digest_ref="${image_ref_bare}@${push_digest}"

  export IMAGE_REF="${target}"
  export IMAGE_DIGEST="${digest_ref}"

  # SBOM_FILE / VULN_SCAN_FILE come from scripts/lib/artifact-names.sh
  # (sourced by build.sh before this backend ran).
  #
  # Plain KEY=VALUE — NO `export ` prefix. GitLab's dotenv parser
  # (artifacts.reports.dotenv) rejects lines that start with `export `
  # because it treats "export KEY" as the key name and fails on the
  # space ("Key can contain only letters, digits and '_'").
  # For bash subshell propagation (local + Bamboo), every consumer
  # wraps `. ./build.env` with `set -a; ...; set +a`.
  cat > build.env <<EOF
IMAGE_REF=${target}
IMAGE_TAG=${IMAGE_TAG}
IMAGE_DIGEST=${digest_ref}
IMAGE_NAME=${IMAGE_NAME}
UPSTREAM_TAG=${UPSTREAM_TAG:-unknown}
UPSTREAM_REF=${UPSTREAM_REF:-unknown}
BASE_DIGEST=${BASE_DIGEST:-}
GIT_SHA=${GIT_SHA:-unknown}
CREATED=${CREATED:-}
SBOM_FILE=${SBOM_FILE}
VULN_SCAN_FILE=${VULN_SCAN_FILE}
EOF
}

# Base require_tools — jf + docker. Each tier wraps this to add
# tier-specific dependency checks (e.g. JCR adds a python3 check
# for the build-info merger).
_artifactory_require_tools_base() {
  local missing=0
  if ! command -v jf >/dev/null 2>&1; then
    _artifactory_install_jf || { missing=1; }
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: 'docker' CLI not found on PATH" >&2
    missing=1
  fi
  return "${missing}"
}

# Auto-install the JFrog CLI if not present. Delegates to the shared
# helper at scripts/lib/install-jf.sh so Bamboo, GitLab CI, and the
# backend all install the same way (no sudo, JF_BINARY_URL takes
# precedence). See that file for JF_BINARY_URL / JF_DEB_URL / JF_RPM_URL
# / JF_INSTALL_DIR documentation.
_artifactory_install_jf() {
  # shellcheck source=../lib/install-jf.sh
  . "$(dirname "${BASH_SOURCE[0]}")/../lib/install-jf.sh"
  install_jf
}

_artifactory_jf_config() {
  local secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD}}"
  local auth_flag

  # Sanitize ARTIFACTORY_URL: strip trailing slashes, validate scheme,
  # avoid doubling /artifactory suffix.
  local _url="${ARTIFACTORY_URL%/}"
  if [[ ! "${_url}" =~ ^https?:// ]]; then
    echo "ERROR: ARTIFACTORY_URL must start with http:// or https://" >&2
    echo "       Got: ${_url}" >&2
    echo "       Example: https://artifactory.example.com" >&2
    return 1
  fi
  local _art_url
  if [[ "${_url}" == */artifactory ]]; then
    _art_url="${_url}"
    _url="${_url%/artifactory}"
  else
    _art_url="${_url}/artifactory"
  fi

  if [ -n "${ARTIFACTORY_TOKEN:-}" ]; then
    auth_flag="--access-token=${secret}"
  else
    auth_flag="--password=${secret}"
  fi
  # shellcheck disable=SC2086
  jf config add container-build-template-artifactory \
    --url="${_url}" \
    --artifactory-url="${_art_url}" \
    --user="${ARTIFACTORY_USER}" \
    ${auth_flag} \
    --interactive=false \
    --overwrite=true >/dev/null || {
      echo "ERROR: 'jf config add' failed" >&2
      return 1
    }
  jf config use container-build-template-artifactory >/dev/null
}

_artifactory_docker_login() {
  local host="$1"
  printf '%s' "${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD}}" \
    | docker login "${host}" -u "${ARTIFACTORY_USER}" --password-stdin >/dev/null || {
      echo "ERROR: 'docker login ${host}' failed" >&2
      return 1
    }
}

# Multi-arch builds (any buildx output that produces an OCI image index)
# store the manifest at <tag>/list.manifest.json, NOT <tag>/manifest.json.
# Single-arch builds use manifest.json. The ARTIFACTORY_MANIFEST_PATH
# template can't predict which the user's build produces, so probe the
# tag directory and return whichever exists. Echoes the resolved path
# (or the input path on probe failure — caller's set-props will then
# emit its existing WARN).
_artifactory_resolve_manifest_filename() {
  local manifest_path="$1"
  local tag_dir="${manifest_path%/manifest.json}"
  local secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD:-}}"
  local _url="${ARTIFACTORY_URL%/}"
  _url="${_url%/artifactory}"

  local listing
  listing=$(curl -fsSL -u "${ARTIFACTORY_USER}:${secret}" \
    "${_url}/artifactory/api/storage/${tag_dir}" 2>/dev/null) || {
    printf '%s' "${manifest_path}"
    return 0
  }

  # Walk children, prefer list.manifest.json (multi-arch index) since
  # that's what consumers pull by tag. Fall back to manifest.json.
  # Uses python3 only when available — falls back to printf the input
  # path so the caller still has SOMETHING to act on.
  if ! command -v python3 >/dev/null 2>&1; then
    printf '%s' "${manifest_path}"
    return 0
  fi

  local resolved
  resolved=$(printf '%s' "${listing}" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    files = [c.get('uri','').lstrip('/') for c in d.get('children', [])]
    for candidate in ('list.manifest.json', 'manifest.json'):
        if candidate in files:
            print(candidate); break
except json.JSONDecodeError:
    pass
" 2>/dev/null)

  if [ -n "${resolved}" ]; then
    printf '%s/%s' "${tag_dir}" "${resolved}"
  else
    printf '%s' "${manifest_path}"
  fi
}

# Custom property tagging on the pushed manifest. Both tiers use this
# (Pro stamps custom props on top of jf's own; JCR is the only way to
# get custom props on Free).
_artifactory_set_props() {
  local manifest_path="$1" build_name="$2" build_number="$3" env="$4"
  # Resolve manifest.json → list.manifest.json for multi-arch images.
  manifest_path=$(_artifactory_resolve_manifest_filename "${manifest_path}")

  local props="environment=${env};build.name=${build_name};build.number=${build_number}"
  [ -n "${ARTIFACTORY_TEAM:-}" ] && props="${props};team=${ARTIFACTORY_TEAM}"
  [ -n "${GIT_SHA:-}" ]          && props="${props};git.commit=${GIT_SHA}"
  [ -n "${UPSTREAM_TAG:-}" ]     && props="${props};upstream.tag=${UPSTREAM_TAG}"
  # NOTE: sbom.path is NOT set here — it's set by sbom-post.sh AFTER
  # the SBOM upload succeeds, so the property always points to a real
  # artifact rather than a speculative path.
  [ -n "${ARTIFACTORY_PROPERTIES:-}" ] && props="${props};${ARTIFACTORY_PROPERTIES}"

  if ! jf rt set-props "${manifest_path}" "${props}" >/dev/null 2>&1; then
    echo "  WARN: 'jf rt set-props' failed for ${manifest_path}" >&2
    echo "        (check manifest path matches the repo storage layout)" >&2
  fi
}
