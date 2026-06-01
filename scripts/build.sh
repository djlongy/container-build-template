#!/usr/bin/env bash
# ─── DO NOT EDIT — template orchestrator ──────────────────────────
# Behaviour is driven by image.env. To change anything for your fork
# (registry, tag, backend, severity gates, …), edit image.env — not
# this file. Edit here only when changing the template's own logic.
# ──────────────────────────────────────────────────────────────────
#
# Single-image build + push driver.
#
# - Computes pushed tag as <UPSTREAM_TAG>-<gitShort>.
# - Pulls upstream base digest for supply-chain labels.
# - `docker build` with the full OCI label set.
# - Optionally pushes via the selected REGISTRY_KIND backend.
# - ALWAYS emits build.env for downstream CI stages, regardless of
#   --push. No-push path sets IMAGE_REF=UPSTREAM_REF (pullable from
#   any runner) so postscan jobs in fresh containers can resolve
#   something; LOCAL_IMAGE preserves the bare docker tag for same-
#   daemon scans. --push overwrites build.env with the registry URL +
#   remote manifest digest.
#
# Usage:
#   ./scripts/build.sh            # build only, load into local daemon
#   ./scripts/build.sh --push     # build + push via REGISTRY_KIND backend
#   ./scripts/build.sh --dry-run  # resolve config + digest, no build
#   ./scripts/build.sh --help     # full flag list
#
# Required env when --push:
#   REGISTRY_KIND       "harbor" (default) | "artifactory_jcr" | "artifactory_pro"
#   then per-backend (validated pre-build by _build_validate_backend):
#     harbor            → HARBOR_REGISTRY, HARBOR_PROJECT, HARBOR_USER, HARBOR_PASSWORD
#     artifactory_jcr   → ARTIFACTORY_URL, ARTIFACTORY_USER,
#                          ARTIFACTORY_TOKEN | ARTIFACTORY_PASSWORD,
#                          ARTIFACTORY_TEAM
#     artifactory_pro   → same as jcr, plus optional ARTIFACTORY_PROJECT
#
# Optional env: see image.env.example. Highlights:
#   IMAGE_NAME          default: leaf of UPSTREAM_IMAGE
#   ORIGINAL_USER       auto-detected via `crane config`
#   CA_CERT             PEM → certs/ci-injected.crt (cert sidecar)
#   CRANE_URL           override for air-gap
#   APPEND_GIT_SHORT    default true; false to skip the SHA suffix
#
# Structure: small named phases, orchestrator at the bottom. Phases
# never silently skip downstream work — they return non-zero and the
# orchestrator handles the rollup.

set -euo pipefail

# ════════════════════════════════════════════════════════════════════
# Root-path decoupling — TEMPLATE_ROOT vs PROJECT_ROOT
# ════════════════════════════════════════════════════════════════════
# This template is designed to be cloned-and-invoked by per-image repos:
#
#     git clone --depth 1 ${TEMPLATE_REPO} .template
#     cd <per-image-repo>        # has image.env + Dockerfile + certs/
#     bash .template/scripts/build.sh
#
# Two distinct roots are needed:
#
#   TEMPLATE_ROOT  where THIS script (and its sibling libs / push backends
#                  / scan scripts) lives. Computed from BASH_SOURCE.
#                  Read-only; never the place artifacts land.
#
#   PROJECT_ROOT   where image.env, Dockerfile, certs/ live, and where
#                  build.env / sbom.cdx.json / vuln-scan.json land.
#                  Defaults to the operator's CWD at invocation. Override
#                  via --project-root <path> or the PROJECT_ROOT env var
#                  for callers that can't cd first.
#
# When the per-image repo IS the template repo (e.g. running the
# template's own self-tests), the two coincide and the contract still
# works — no special handling needed.
TEMPLATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# PROJECT_ROOT defaults to CWD; _build_parse_args may override via flag.
# Re-export so child scripts (scan/scan-*.sh, ingest/sbom-post.sh)
# inherit the same project context.
export PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
export TEMPLATE_ROOT

# ════════════════════════════════════════════════════════════════════
# Shared lib: image.env loader + bamboo_* importer + _dbg
# ════════════════════════════════════════════════════════════════════
# scripts/lib/load-image-env.sh provides:
#   _dbg <msg>            — debug echo (BUILD_DEBUG=true to enable)
#   import_bamboo_vars    — translate bamboo_* env vars to bare names
#   load_image_env [path] — source <path> (default ./image.env in CWD),
#                           apply shell-set overrides on top
#
# Sourced once here. Other scripts (scan/xray-vuln.sh, scan/xray-sbom.sh,
# sbom-post.sh) source the same lib so all config loading goes through
# the same code path — same precedence, same debug logs, same fail-fast
# message on missing image.env.
# shellcheck source=lib/load-image-env.sh
. "${TEMPLATE_ROOT}/scripts/lib/load-image-env.sh"
# shellcheck source=lib/artifact-names.sh
. "${TEMPLATE_ROOT}/scripts/lib/artifact-names.sh"

# ════════════════════════════════════════════════════════════════════
# PHASE 0 — Argument parsing
# ════════════════════════════════════════════════════════════════════
# Runs first, before any work. Sets WANT_PUSH and WANT_DRY_RUN for
# later phases. Unknown flags fail loud with a usage hint instead of
# being silently ignored (which let e.g. `--list` trigger a full build
# when the user was just probing for options).

_build_print_usage() {
  cat <<EOF
Usage: ./scripts/build.sh [flags]

  --push                   Build, then push to HARBOR_REGISTRY/HARBOR_PROJECT
                           (or via the Artifactory backend when
                           REGISTRY_KIND=artifactory_jcr or artifactory_pro).
  --dry-run                Resolve config + base digest, print the report
                           block, stop before docker build. No image
                           produced. Useful for "what would this build
                           with my current env?"
  --project-root <path>    Per-image repo root containing image.env,
                           Dockerfile, certs/. Default: \$PWD. Use this
                           when invoking from outside the per-image repo,
                           e.g. \`bash .template/scripts/build.sh
                           --project-root /builds/my-image\`.
  --env-file <path>        Path to image.env. Default:
                           \$PROJECT_ROOT/image.env. Use to point at an
                           alternate config (e.g. dev/prod variants).
  --dockerfile <path>      Path to the Dockerfile. Default: ./Dockerfile.
                           Set when invoking from a repo whose Dockerfile
                           lives under a different name (e.g. the template
                           repo's self-build uses Dockerfile.example).
  --help, -h               This message.

  Flags can appear in any order. Without --push or --dry-run, build
  runs locally and loads into the docker daemon without pushing.

Per-fork customisation: edit the Dockerfile directly, in the
"FORK EDITS GO HERE" region between the cert-injection stage and
the final USER flip. Use that region for RUN \`apk upgrade\`/\`apt-get
upgrade\` (CVE remediation), package installs, COPY of static configs,
ENV/HEALTHCHECK lines, etc.

All behavioural toggles are env-driven. See image.env.example for the
full list. Commonly-used flags:

  REGISTRY_KIND=artifactory_jcr   use scripts/push-backends/artifactory_jcr.sh
                                  (Free tier — needs python3 for build-info merger)
  REGISTRY_KIND=artifactory_pro   use scripts/push-backends/artifactory_pro.sh
                                  (Pro tier — slimmer, no python3 dep)
                                  Default: REGISTRY_KIND=harbor → push-backends/harbor.sh
  CA_CERT='<pem>'             inject a corp CA — sidecar materialises it
                              into certs/ and the Dockerfile picks it up
  ARTIFACTORY_BUILD_XRAY_PRESCAN=true
                              jf docker scan inside the build job
                              BEFORE push (admin gate; default false)
  ARTIFACTORY_BUILD_XRAY_POSTSCAN=true
                              jf build-scan inside the build job
                              AFTER push (default false)
  ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS=true
                              fail build on Xray policy violation

Note: BUILD_ in the var name marks these as INLINE scans that run
INSIDE the push backend (build job). The standalone scan scripts
(scripts/scan/xray-{vuln,sbom}.sh) are separate CI stages — same
Xray engine, different pipeline placement. Both default OFF — opt
in only when an Xray licence is provisioned.
EOF
}

_build_parse_args() {
  WANT_PUSH=0
  WANT_DRY_RUN=0
  IMAGE_ENV_FILE=""
  DOCKERFILE="Dockerfile"

  # Loop until args exhausted. Each --flag may take a value (then we
  # shift twice). Unknown flag = fail loud with usage so e.g. `--lst`
  # doesn't silently get treated as a positional.
  while [ $# -gt 0 ]; do
    case "$1" in
      --push)         WANT_PUSH=1; shift ;;
      --dry-run)      WANT_DRY_RUN=1; shift ;;
      --project-root)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
          echo "ERROR: --project-root requires a path argument" >&2
          _build_print_usage >&2
          return 1
        fi
        # Resolve to absolute path so subsequent cd / sourcing is stable.
        PROJECT_ROOT="$(cd "$2" 2>/dev/null && pwd)" || {
          echo "ERROR: --project-root path does not exist: $2" >&2
          return 1
        }
        export PROJECT_ROOT
        shift 2
        ;;
      --env-file)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
          echo "ERROR: --env-file requires a path argument" >&2
          _build_print_usage >&2
          return 1
        fi
        IMAGE_ENV_FILE="$2"
        shift 2
        ;;
      --dockerfile)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
          echo "ERROR: --dockerfile requires a path argument" >&2
          _build_print_usage >&2
          return 1
        fi
        DOCKERFILE="$2"
        shift 2
        ;;
      --help|-h)      _build_print_usage; exit 0 ;;
      *)
        echo "ERROR: unknown flag '$1'" >&2
        echo "" >&2
        _build_print_usage >&2
        return 1
        ;;
    esac
  done

  # cd into project root so every subsequent phase reads image.env,
  # writes build.env, sees certs/, etc. relative to the per-image repo
  # rather than the template clone.
  cd "${PROJECT_ROOT}"

  # Tell load_image_env exactly which file to source. Default keeps
  # backwards compat with callers that just `cd <project>` first.
  if [ -n "${IMAGE_ENV_FILE}" ]; then
    export IMAGE_ENV_FILE
  fi

  echo "→ context: TEMPLATE_ROOT=${TEMPLATE_ROOT}"
  echo "           PROJECT_ROOT=${PROJECT_ROOT}"
  if [ -n "${IMAGE_ENV_FILE:-}" ]; then
    echo "           IMAGE_ENV_FILE=${IMAGE_ENV_FILE}"
  fi
}

# ════════════════════════════════════════════════════════════════════
# PHASE 1 — Config loading (delegated to scripts/lib/load-image-env.sh)
# ════════════════════════════════════════════════════════════════════
# image.env is the SINGLE source of truth. It MUST exist or the build
# fails — image.env.example is a TEMPLATE you copy from on first
# checkout, never sourced as real config.
#
# Two-layer precedence:
#   1. image.env          — committed canonical config (REQUIRED)
#   2. Shell / CI env     — always wins, for pipeline-level overrides
#
# Bamboo bonus: any env var named `bamboo_FOO` is auto-imported as
# `FOO` before the snapshot via import_bamboo_vars (also in the lib).
#
# Implementation lives in scripts/lib/load-image-env.sh and is shared
# by all scripts that read image.env (xray-vuln.sh, xray-sbom.sh,
# sbom-post.sh, etc.). See that file for the snapshot/restore details.

# Decompose a full image reference (UPSTREAM_REF) into its parts:
#   _REF_HOST    registry host    docker.io | ghcr.io | registry:5000 | art.example.com
#   _REF_PATH    repo path        library/nginx | prom/prometheus | mirror/library/nginx
#   _REF_TAG     tag              1.25.3-alpine   ("" if the ref carried none)
#   _REF_DIGEST  @sha256:...      informational only — base digest is
#                                 re-resolved fresh via crane in PHASE 6.
#
# Follows Docker's reference grammar so air-gapped mirrors, ported
# registries, and Docker Hub shorthand all split correctly:
#   - the segment before the first "/" is the registry host ONLY if it
#     contains "." or ":" or equals "localhost"; otherwise the ref is on
#     Docker Hub and that segment is part of the path
#   - a single-segment Docker Hub path is namespaced under "library/"
#     ("nginx" → "library/nginx")
#   - a ":" introduces a tag ONLY after the last "/" — a ":" before it
#     is a registry port (registry:5000/app), never a tag
_build_decompose_upstream_ref() {
  local ref="$1" rest first last_segment host path tag="" digest=""

  # 1. peel optional @sha256:... digest
  case "${ref}" in
    *@*) digest="${ref##*@}"; rest="${ref%@*}" ;;
    *)   rest="${ref}" ;;
  esac

  # 2. peel tag — only a ':' in the LAST path segment is a tag separator
  last_segment="${rest##*/}"
  case "${last_segment}" in
    *:*) tag="${last_segment##*:}"; rest="${rest%:*}" ;;
  esac

  # 3. split host from path using Docker's host-detection rule
  case "${rest}" in
    */*)
      first="${rest%%/*}"
      case "${first}" in
        *.*|*:*|localhost) host="${first}";   path="${rest#*/}" ;;
        *)                 host="docker.io";  path="${rest}"     ;;
      esac
      ;;
    *) host="docker.io"; path="${rest}" ;;
  esac

  # 4. Docker Hub single-segment repos live under library/
  case "${host}" in
    docker.io|index.docker.io)
      case "${path}" in
        */*) : ;;
        *)   path="library/${path}" ;;
      esac
      ;;
  esac

  _REF_HOST="${host}"; _REF_PATH="${path}"; _REF_TAG="${tag}"; _REF_DIGEST="${digest}"
}

# Validate required fields + apply defaults. Fails fast on missing
# required fields.
_build_apply_defaults_and_normalise() {
  # Canonical input is a single full image URL in UPSTREAM_REF, e.g.
  #   UPSTREAM_REF="docker.io/library/nginx:1.25.3-alpine"
  # Decompose it into the registry/image/tag parts that the rest of the
  # build (and the Dockerfile build-args) consume. Explicit per-segment
  # vars still win as overrides, and the legacy three-var form (no
  # UPSTREAM_REF at all) keeps working unchanged.
  if [ -n "${UPSTREAM_REF:-}" ]; then
    _build_decompose_upstream_ref "${UPSTREAM_REF}"
    UPSTREAM_REGISTRY="${UPSTREAM_REGISTRY:-${_REF_HOST}}"
    UPSTREAM_IMAGE="${UPSTREAM_IMAGE:-${_REF_PATH}}"
    UPSTREAM_TAG="${UPSTREAM_TAG:-${_REF_TAG}}"
    [ -n "${_REF_DIGEST}" ] && _dbg "UPSTREAM_REF carried ${_REF_DIGEST} — informational; base digest is re-resolved via crane"
    _dbg "decomposed UPSTREAM_REF=${UPSTREAM_REF} → REGISTRY=${UPSTREAM_REGISTRY} IMAGE=${UPSTREAM_IMAGE} TAG=${UPSTREAM_TAG}"
  fi

  : "${UPSTREAM_REGISTRY:?set UPSTREAM_REF (full image URL) or UPSTREAM_REGISTRY in image.env}"
  : "${UPSTREAM_IMAGE:?set UPSTREAM_REF (full image URL) or UPSTREAM_IMAGE in image.env}"
  : "${UPSTREAM_TAG:?set UPSTREAM_REF (full image URL incl. :tag) or UPSTREAM_TAG in image.env}"

  # Defaults are SAFE-BY-DEFAULT: every optional behaviour is OFF
  # unless explicitly turned on. The bare-minimum build path is
  # "pull → retag → push" with no cert injection, no Xray, no SBOM.
  # Anything bespoke (package upgrades, extra installs, file drops)
  # goes directly in the Dockerfile's editable region — never sneaks
  # into the upstream template path via env-var toggles.
  # IMAGE_NAME defaults to UPSTREAM_IMAGE's LEAF segment (after the
  # last "/") so:
  #   nginx              → nginx
  #   library/nginx      → nginx
  #   prom/prometheus    → prometheus
  # Consumers can override with IMAGE_NAME= in image.env if they want
  # a different short name (e.g. "nginx-hardened").
  [ -z "${IMAGE_NAME:-}" ] && _dbg "default applied: IMAGE_NAME=${UPSTREAM_IMAGE##*/} (leaf of UPSTREAM_IMAGE=${UPSTREAM_IMAGE})"
  [ -z "${VENDOR:-}"     ] && _dbg "default applied: VENDOR=example.com (was unset)"

  IMAGE_NAME="${IMAGE_NAME:-${UPSTREAM_IMAGE##*/}}"
  VENDOR="${VENDOR:-example.com}"
  # ORIGINAL_USER is auto-detected from upstream in PHASE 6.5 — only
  # apply the safety-net default if both auto-detection AND user
  # override fail downstream.
}

# ════════════════════════════════════════════════════════════════════
# PHASE 2 — Tag computation + source URL
# ════════════════════════════════════════════════════════════════════
# Tag format:
#   <UPSTREAM_TAG>-<gitShort>
# The upstream tag IS the semver; the git SHA differentiates builds
# of the same upstream version. No internal version axis.

_build_compute_tag() {
  if ! git rev-parse HEAD >/dev/null 2>&1; then
    GIT_SHA="unknown"
    GIT_SHORT="unknown"
  else
    GIT_SHA=$(git rev-parse HEAD)
    GIT_SHORT=$(git rev-parse --short=7 HEAD)
  fi
  CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  # APPEND_GIT_SHORT controls whether the pushed tag carries the
  # git short SHA. Default true (build differentiation matters when
  # rebuilding the same upstream tag). Set to false/0/no to keep the
  # raw upstream tag — useful when UPSTREAM_TAG is a moving alias
  # like "latest" or "stable" and you want the local image tag to
  # mirror that exactly. Falsy values: false/False/FALSE/0/no/No/NO.
  local _append="${APPEND_GIT_SHORT:-true}"
  case "$(printf '%s' "${_append}" | tr '[:upper:]' '[:lower:]')" in
    false|0|no|off)
      FULL_TAG="${UPSTREAM_TAG}"
      _dbg "APPEND_GIT_SHORT=${_append} → tag=${FULL_TAG} (no SHA suffix)"
      ;;
    *)
      FULL_TAG="${UPSTREAM_TAG}-${GIT_SHORT}"
      _dbg "APPEND_GIT_SHORT=${_append} → tag=${FULL_TAG}"
      ;;
  esac
}

# CI-supplied source URL (GitLab / Bamboo) or git remote fallback.
_build_resolve_source_url() {
  SOURCE_URL="${CI_PROJECT_URL:-${bamboo_planRepository_1_repositoryUrl:-}}"
  if [ -z "${SOURCE_URL}" ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_URL=$(git config --get remote.origin.url 2>/dev/null || echo "")
  fi
}

# ════════════════════════════════════════════════════════════════════
# PHASE 3 — Cert materialisation
# ════════════════════════════════════════════════════════════════════
# If CA_CERT is set (CI secret), write it to certs/ so the cert
# sidecar stage in the Dockerfile picks it up. Overwrites are
# intentional — CI runs should be reproducible. Typical CI source:
# curl from an Artifactory generic repo into the CA_CERT variable
# (or set the variable's value to the PEM directly).
#
# When certs/ stays empty, the sidecar stage runs but is effectively
# a no-op (rebuild produces the same trust store) — no env toggle
# needed. The Dockerfile's FROM final re-bases FROM base so the
# sidecar's USER root never propagates into the final image.

_build_materialise_certs() {
  mkdir -p certs
  : > certs/.gitkeep

  if [ -n "${CA_CERT:-}" ]; then
    echo "${CA_CERT}" > certs/ci-injected.crt
    echo "→ Wrote CA_CERT to certs/ci-injected.crt ($(wc -c < certs/ci-injected.crt) bytes)"
    return 0
  fi

  _dbg "no CA_CERT in env — using certs/ on disk as-is (empty dir = sidecar no-op)"
}

# ════════════════════════════════════════════════════════════════════
# PHASE 4 — Push target derivation (backend-agnostic)
# ════════════════════════════════════════════════════════════════════
# build.sh stays out of every backend's namespace. Each push-backend
# (scripts/push-backends/<kind>.sh) is wholly responsible for:
#   - reading its OWN required env (HARBOR_* for harbor.sh,
#     ARTIFACTORY_* for artifactory_jcr.sh / artifactory_pro.sh, etc.)
#   - validating those vars when --push is requested
#   - retagging the local image to its push URL before docker push
#
# That means HARBOR_* and ARTIFACTORY_* are fully independent — you
# only need to set the namespace that matches your REGISTRY_KIND, and
# neither cross-derives from the other. Symmetric, no surprises.
#
# Build.sh just composes a SIMPLE local tag for docker build to use:
#   <IMAGE_NAME>:<FULL_TAG>          e.g. nginx:1.25.3-alpine-a1b2c3d
# Backends retag from this to their target URL during push_to_backend.

_build_resolve_push_target() {
  REGISTRY_KIND_LC="$(echo "${REGISTRY_KIND:-harbor}" | tr '[:upper:]' '[:lower:]')"
  _dbg "REGISTRY_KIND=${REGISTRY_KIND:-<unset>} → backend=${REGISTRY_KIND_LC}"

  FULL_IMAGE="${IMAGE_NAME}:${FULL_TAG}"
  UPSTREAM_REF="${UPSTREAM_REGISTRY}/${UPSTREAM_IMAGE}:${UPSTREAM_TAG}"
}

# Pre-flight: source the selected push backend and run its require_env
# so a missing config (HARBOR_REGISTRY / ARTIFACTORY_URL / etc.) fails
# fast BEFORE we waste time on docker build + crane probes. Only runs
# when --push was requested. Fail-fast for an unknown REGISTRY_KIND
# happens here too — same error as the dispatch in PHASE 8 but earlier.
#
# Convention: each push-backends/<kind>.sh exposes a `${kind}_require_env`
# function (no leading underscore — it's part of the public contract).
# build.sh sources the backend AND `_${kind}_require_env` (legacy name)
# also works for backward compat.
_build_validate_backend() {
  [ "${WANT_PUSH}" -eq 1 ] || return 0

  local kind="${REGISTRY_KIND_LC:-harbor}"
  local backend="${TEMPLATE_ROOT}/scripts/push-backends/${kind}.sh"
  if [ ! -f "${backend}" ]; then
    echo "ERROR: REGISTRY_KIND='${kind}' but ${backend} not found" >&2
    echo "       Available backends:" >&2
    ls "${TEMPLATE_ROOT}/scripts/push-backends/" 2>/dev/null | sed 's/\.sh$//' | sed 's/^/         /' >&2
    return 1
  fi

  # shellcheck disable=SC1090
  . "${backend}"

  # Try public name first (kind_require_env), then legacy private
  # name (_kind_require_env), then no-op if neither exists.
  local fn
  for fn in "${kind}_require_env" "_${kind}_require_env"; do
    if declare -f "${fn}" >/dev/null 2>&1; then
      _dbg "early backend validation: calling ${fn}"
      "${fn}" || return 1
      return 0
    fi
  done
  _dbg "backend ${kind} has no require_env hook — skipping pre-flight"
}

# ════════════════════════════════════════════════════════════════════
# PHASE 5 — Report resolved config
# ════════════════════════════════════════════════════════════════════
# Printed BEFORE the upstream digest is resolved — the user sees
# progress immediately. Digest resolution runs next and can take a few
# seconds against slow/air-gapped registries.

_build_print_config_report() {
  echo ""
  echo "=========================================="
  echo "  container-build-template build"
  echo "=========================================="
  echo "  Image:              ${FULL_IMAGE}"
  echo "  Upstream:           ${UPSTREAM_REF}"
  echo "  Upstream digest:    <resolving...>"
  echo "  Upstream USER:      <auto-detecting...>"
  echo "  Git commit:         ${GIT_SHORT} (${GIT_SHA})"
  echo "  Created (UTC):      ${CREATED}"
  echo "  Vendor:             ${VENDOR}"
  echo "  Source URL:         ${SOURCE_URL:-<none>}"
  echo "=========================================="
  echo ""
}

# ════════════════════════════════════════════════════════════════════
# PHASE 6 — Upstream base digest resolution
# ════════════════════════════════════════════════════════════════════
# Used for the org.opencontainers.image.base.digest OCI label. Strategy:
#   1. crane digest                       — fast, manifest-only
#   2. auto-install crane from CRANE_URL  — if not on PATH
#   3. docker buildx imagetools inspect   — fallback
# Empty BASE_DIGEST is non-fatal — the build still succeeds.

# If no CRANE_URL is set, derive one matching host OS/arch.
_build_derive_crane_url() {
  [ -n "${CRANE_URL:-}" ] && return 0

  local _os="" _arch=""
  case "$(uname -s)" in
    Linux)  _os="Linux" ;;
    Darwin) _os="Darwin" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)   _arch="x86_64" ;;
    aarch64|arm64)  _arch="arm64" ;;
  esac
  if [ -n "${_os}" ] && [ -n "${_arch}" ]; then
    CRANE_URL="https://github.com/google/go-containerregistry/releases/download/v0.20.2/go-containerregistry_${_os}_${_arch}.tar.gz"
  fi
}

# Try to install crane into ${PROJECT_ROOT}/.bin from CRANE_URL. Never
# fatal — returns 0 on success, 1 on failure (caller falls back).
_build_install_crane() {
  if command -v crane >/dev/null 2>&1; then
    _dbg "crane already on PATH: $(command -v crane)"
    return 0
  fi
  _build_derive_crane_url

  if [ -z "${CRANE_URL:-}" ]; then
    echo "  NOTE: crane not on PATH and CRANE_URL not set — skipping install" >&2
    echo "        (will fall back to docker buildx imagetools inspect)" >&2
    _dbg "uname=$(uname -s)/$(uname -m) didn't match a known crane release URL"
    return 1
  fi

  echo "→ crane not on PATH — installing from ${CRANE_URL}"
  mkdir -p "${PROJECT_ROOT}/.bin"
  if curl -fSL --progress-bar --max-time 120 "${CRANE_URL}" \
       | tar xz -C "${PROJECT_ROOT}/.bin" crane 2>/dev/null \
     && [ -x "${PROJECT_ROOT}/.bin/crane" ]; then
    export PATH="${PROJECT_ROOT}/.bin:${PATH}"
    echo "  ✓ crane installed to ${PROJECT_ROOT}/.bin/crane ($(${PROJECT_ROOT}/.bin/crane version 2>&1 | head -1))"
    return 0
  fi

  echo "  WARN: crane install failed — URL unreachable or tarball invalid" >&2
  echo "        (will fall back to docker buildx imagetools inspect)" >&2
  return 1
}

_build_resolve_with_crane() {
  command -v crane >/dev/null 2>&1 || return 1

  echo "→ Resolving upstream digest: crane digest ${UPSTREAM_REF}"
  local _out _rc
  _out=$(crane digest "${UPSTREAM_REF}" 2>&1) && _rc=0 || _rc=$?
  if [ "${_rc}" -eq 0 ]; then
    BASE_DIGEST="${_out}"
    echo "  ✓ ${BASE_DIGEST}"
    return 0
  fi
  echo "  WARN: crane digest failed (rc=${_rc}) for ${UPSTREAM_REF}" >&2
  printf '%s\n' "${_out}" | head -2 | sed 's/^/        /' >&2
  return 1
}

_build_resolve_with_buildx() {
  command -v docker >/dev/null 2>&1 || return 1

  echo "→ Resolving upstream digest: docker buildx imagetools inspect ${UPSTREAM_REF}"
  BASE_DIGEST=$(docker buildx imagetools inspect "${UPSTREAM_REF}" --format '{{.Digest}}' 2>/dev/null || echo "")
  if [ -n "${BASE_DIGEST}" ]; then
    echo "  ✓ ${BASE_DIGEST}"
    return 0
  fi
  echo "  WARN: docker buildx imagetools inspect also failed" >&2
  echo "        (base.digest label will be empty — image build unaffected)" >&2
  return 1
}

_build_resolve_base_digest() {
  BASE_DIGEST=""
  _build_install_crane || true
  _build_resolve_with_crane && return 0
  _build_resolve_with_buildx || true
  return 0
}

# ════════════════════════════════════════════════════════════════════
# PHASE 6.5 — Upstream USER auto-detection
# ════════════════════════════════════════════════════════════════════
# The Dockerfile's final stage flips to USER root for the editable
# region (so apk/apt work without auth dance), then restores the
# upstream USER at the end via `USER ${ORIGINAL_USER}`. Without auto-
# detection, a fork would have to manually look up the upstream's
# USER and set ORIGINAL_USER in image.env — easy to forget, ends up
# silently with a root-running image.
#
# Auto-detect from `crane config <upstream>` (the same crane we
# already installed in PHASE 6 for base.digest). Resolution chain:
#   1. ORIGINAL_USER explicitly set in image.env / shell env  → wins
#   2. crane config .config.User                              → use it
#   3. fallback                                               → "root"
#
# Distroless / scratch / busybox images often have no USER set in
# their config — they default to root, so the fallback is correct.

_build_resolve_upstream_user() {
  if [ -n "${ORIGINAL_USER:-}" ]; then
    echo "→ ORIGINAL_USER explicitly set: ${ORIGINAL_USER} (skipping auto-detect)"
    export ORIGINAL_USER
    return 0
  fi
  if ! command -v crane >/dev/null 2>&1; then
    ORIGINAL_USER="root"
    echo "  NOTE: crane not on PATH → ORIGINAL_USER defaults to root" >&2
    export ORIGINAL_USER
    return 0
  fi

  echo "→ Detecting upstream USER: crane config ${UPSTREAM_REF}"
  local _config _user
  _config=$(crane config "${UPSTREAM_REF}" 2>/dev/null) || _config=""
  if [ -z "${_config}" ]; then
    ORIGINAL_USER="root"
    echo "  WARN: crane config failed → ORIGINAL_USER defaults to root" >&2
    export ORIGINAL_USER
    return 0
  fi

  if command -v jq >/dev/null 2>&1; then
    _user=$(printf '%s' "${_config}" | jq -r '.config.User // ""' 2>/dev/null)
  else
    # Fallback parser: grep .config.User from the JSON. Brittle but
    # works for the common single-line / pretty-printed case.
    _user=$(printf '%s' "${_config}" | grep -oE '"User"[[:space:]]*:[[:space:]]*"[^"]*"' \
                                     | head -1 \
                                     | sed -E 's/.*"User"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')
  fi

  if [ -n "${_user}" ]; then
    ORIGINAL_USER="${_user}"
    echo "  ✓ ORIGINAL_USER auto-detected: ${ORIGINAL_USER}"
  else
    ORIGINAL_USER="root"
    echo "  ✓ upstream has no USER set → ORIGINAL_USER defaults to root"
  fi
  export ORIGINAL_USER
}

# ════════════════════════════════════════════════════════════════════
# PHASE 7 — docker build
# ════════════════════════════════════════════════════════════════════
# Dynamic OCI labels passed via --label. Label policy: preserve
# upstream, append ours. See Dockerfile for the reasoning — we
# explicitly own only the dynamic provenance labels and team
# identity; everything else flows through untouched.

_build_docker_build() {
  local build_args=(
    --build-arg "UPSTREAM_REGISTRY=${UPSTREAM_REGISTRY}"
    --build-arg "UPSTREAM_IMAGE=${UPSTREAM_IMAGE}"
    --build-arg "UPSTREAM_TAG=${UPSTREAM_TAG}"
    --build-arg "ORIGINAL_USER=${ORIGINAL_USER}"
  )
  # CERT_BUILDER_IMAGE — only pass when set (Dockerfile has a default).
  # Override via image.env / shell env for air-gap to point at your
  # internal Artifactory / Nexus mirror.
  if [ -n "${CERT_BUILDER_IMAGE:-}" ]; then
    build_args+=(--build-arg "CERT_BUILDER_IMAGE=${CERT_BUILDER_IMAGE}")
  fi
  local label_args=(
    --label "org.opencontainers.image.vendor=${VENDOR}"
    --label "org.opencontainers.image.authors=${AUTHORS:-Platform Engineering}"
    --label "org.opencontainers.image.created=${CREATED}"
    --label "org.opencontainers.image.revision=${GIT_SHA}"
    --label "org.opencontainers.image.version=${FULL_TAG}"
    --label "org.opencontainers.image.ref.name=${FULL_TAG}"
    --label "org.opencontainers.image.base.name=${UPSTREAM_REF}"
    --label "promoted.from=${UPSTREAM_REF}"
    --label "promoted.tag=${FULL_TAG}"
  )
  if [ -n "${BASE_DIGEST}" ]; then
    label_args+=(--label "org.opencontainers.image.base.digest=${BASE_DIGEST}")
  fi
  if [ -n "${SOURCE_URL}" ]; then
    label_args+=(--label "org.opencontainers.image.source=${SOURCE_URL}")
    label_args+=(--label "org.opencontainers.image.url=${SOURCE_URL}")
  fi

  # Detect buildx and toggle the attestation flags accordingly.
  #
  # When buildx is present (Docker Desktop, Colima vz-rosetta, modern
  # Docker Engine with the buildx plugin) we pass `--provenance=false
  # --sbom=false` to force a FLAT single-arch v2 distribution manifest
  # (config + layers in the tag dir) instead of an OCI image index
  # wrapping the manifest + an attestation manifest. The index lands
  # in JFrog as <tag>/list.manifest.json with the layer blobs at
  # <repo>/<image>/sha256:<digest>/ rather than in the tag dir, which
  # makes our Free-tier build-info merger (lib/build-info-merge.py)
  # report "1 artifact, 0 dependencies (fallback)" instead of the
  # proper "manifest + config + N layers" count.
  #
  # When buildx is NOT installed (some hosted CI runners ship plain
  # Docker Engine), `docker build` rejects those flags as unknown,
  # so we fall back to a vanilla `docker build` — non-buildx Docker
  # never produces OCI indices anyway, so the flags wouldn't have
  # served any purpose there.
  #
  # We don't consume buildx's provenance/SBOM attestations — Xray
  # covers provenance separately and Syft/Trivy/Xray + sbom-post.sh
  # cover SBOMs as their own stages — so disabling them is lossless.
  local _build_cmd=(docker build)
  if docker buildx version >/dev/null 2>&1; then
    _build_cmd=(docker buildx build --provenance=false --sbom=false --load)
    echo "→ docker buildx build (provenance/sbom disabled)"
  else
    echo "→ docker build (buildx not detected — flat manifest by default)"
  fi
  "${_build_cmd[@]}" \
    "${build_args[@]}" "${label_args[@]}" -t "${FULL_IMAGE}" \
    -f "${DOCKERFILE}" .
  echo "→ build complete: ${FULL_IMAGE}"

  # Export derived values so the sourced backend script can pull them
  # in via parameter expansion when building build.env.
  export UPSTREAM_TAG UPSTREAM_REF BASE_DIGEST GIT_SHA CREATED
}

# ════════════════════════════════════════════════════════════════════
# PHASE 8a — Local build.env (always)
# ════════════════════════════════════════════════════════════════════
# Emit build.env immediately after docker build, BEFORE the optional
# push step. This guarantees downstream CI stages always find the
# canonical artifact — feature-branch pipelines that only build (no
# --push) still produce something for prescan/postscan/test jobs to
# consume. MR-to-main gates require a full green pipeline including
# the postscan stages, so this no-push build.env has to be SCANNABLE
# from a fresh container in a downstream job.
#
# IMAGE_REF policy (no-push path):
#   IMAGE_REF=${UPSTREAM_REF}    — fully-qualified, pullable from any
#                                   runner. The local docker tag
#                                   ${FULL_IMAGE} is bare image:tag
#                                   and won't resolve in a downstream
#                                   job's fresh dind/runner. The
#                                   built image's content is identical
#                                   to upstream + cert-sidecar tweak,
#                                   so scanning upstream is a valid
#                                   pipeline-validation proxy.
#   LOCAL_IMAGE=${FULL_IMAGE}    — preserved separately so a same-
#                                   daemon scan (local dev / a runner
#                                   that shares dind across jobs) can
#                                   prefer the actually-built artifact.
#   IMAGE_DIGEST=                — empty (no remote manifest exists).
#
# When --push runs in PHASE 8b, the push backend overwrites this file
# with the registry URL + remote @sha256 digest, so IMAGE_REF then
# points at the real artifact.

_build_emit_local_build_env() {
  cat > build.env <<EOF
IMAGE_REF=${UPSTREAM_REF}
LOCAL_IMAGE=${FULL_IMAGE}
IMAGE_TAG=${FULL_TAG}
IMAGE_DIGEST=
IMAGE_NAME=${IMAGE_NAME}
UPSTREAM_TAG=${UPSTREAM_TAG:-unknown}
UPSTREAM_REF=${UPSTREAM_REF:-unknown}
BASE_DIGEST=${BASE_DIGEST:-}
GIT_SHA=${GIT_SHA:-unknown}
CREATED=${CREATED:-}
SBOM_FILE=${SBOM_FILE}
VULN_SCAN_FILE=${VULN_SCAN_FILE}
EOF
  echo "→ wrote build.env (no-push — IMAGE_REF=UPSTREAM_REF for downstream pull;"
  echo "  LOCAL_IMAGE=${FULL_IMAGE} kept for same-daemon scans)"
  sed 's/^/    /' build.env
}

# ════════════════════════════════════════════════════════════════════
# PHASE 8b — Push + build.env override (delegated to push backend)
# ════════════════════════════════════════════════════════════════════
# Every push backend lives at scripts/push-backends/<kind>.sh and
# exports a single function: push_to_backend "<built-local-ref>".
# That function is responsible for:
#   1. docker login to its target host
#   2. docker push (or jf docker push, etc.)
#   3. OVERWRITING build.env with the canonical fields IMAGE_REF,
#      IMAGE_TAG, IMAGE_DIGEST, IMAGE_NAME, UPSTREAM_TAG, UPSTREAM_REF,
#      BASE_DIGEST, GIT_SHA, CREATED (the local stub from PHASE 8a is
#      replaced with the registry URL + remote manifest digest).
#
# Adding a new backend = drop a new file in push-backends/ that
# exposes push_to_backend. No edits to build.sh required. Swap by
# changing REGISTRY_KIND in image.env.
#
# REGISTRY_KIND defaults to "harbor" (plain docker push). Other
# shipped backends: "artifactory".

_build_push_and_emit_env() {
  if [ "${WANT_PUSH}" -ne 1 ]; then
    _dbg "WANT_PUSH=0 (no --push flag) — skipping push; PHASE 8a's local build.env stands"
    return 0
  fi

  local kind="${REGISTRY_KIND_LC:-harbor}"
  local backend="${TEMPLATE_ROOT}/scripts/push-backends/${kind}.sh"
  if [ ! -f "${backend}" ]; then
    echo "ERROR: REGISTRY_KIND='${kind}' but ${backend} not found" >&2
    echo "       Available backends:" >&2
    ls "${TEMPLATE_ROOT}/scripts/push-backends/" 2>/dev/null | sed 's/\.sh$//' | sed 's/^/         /' >&2
    return 1
  fi

  _dbg "dispatching push: backend=${kind} target=${FULL_IMAGE}"
  # shellcheck disable=SC1090
  . "${backend}"
  push_to_backend "${FULL_IMAGE}" || return 1

  echo "→ overwrote build.env (push backend: ${kind})"
  sed 's/^/    /' build.env
}

# ════════════════════════════════════════════════════════════════════
# Orchestrator
# ════════════════════════════════════════════════════════════════════
# One phase per line. Phase helpers never skip downstream work — any
# failure returns non-zero here and the orchestrator exits.

_build_parse_args "$@"

import_bamboo_vars   # from scripts/lib/load-image-env.sh
load_image_env       # from scripts/lib/load-image-env.sh
_build_apply_defaults_and_normalise

_build_compute_tag
_build_resolve_source_url
_build_materialise_certs
_build_resolve_push_target
_build_validate_backend          # fail-fast on missing HARBOR_*/ARTIFACTORY_*

_build_print_config_report
_build_resolve_base_digest
_build_resolve_upstream_user

# --dry-run stops here: config resolved, digest fetched, USER probed.
if [ "${WANT_DRY_RUN}" -eq 1 ]; then
  echo "→ --dry-run: stopping before docker build"
  exit 0
fi

# Docker logins for ALL registries we might pull from (UPSTREAM_REGISTRY
# host, HARBOR_REGISTRY, ARTIFACTORY_PUSH_HOST). Push backend does its
# own login for the push target later — this covers the PULL side so
# the upcoming docker build can fetch the base image through an
# auth-protected internal mirror.
# shellcheck source=lib/docker-login.sh
. "${TEMPLATE_ROOT}/scripts/lib/docker-login.sh"
docker_login_for_xray_scan || true

_build_docker_build
_build_emit_local_build_env      # always — feature branches need this too
_build_push_and_emit_env         # overwrites build.env when --push

# SBOM generation lives in scripts/scan/syft-sbom.sh as its own stage —
# call it after build (or as a CI postscan job) when you want a BOM.
