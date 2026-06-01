#!/usr/bin/env bash
# ─── DO NOT EDIT — template push backend (Artifactory Pro tier) ────
# Selected via REGISTRY_KIND="artifactory_pro" in image.env. Uses
# JFrog Pro features (jf docker push with build-info module linkage,
# jf build-publish, optional jf docker scan / jf build-scan).
#
# All ARTIFACTORY_* knobs (URL, USER, TOKEN, TEAM, PROJECT, layout
# templates, …) come from image.env + masked CI vars. Edit those,
# not this file.
#
# DELETION SAFETY: this file deliberately does NOT depend on
# artifactory_jcr.sh or scripts/lib/build-info-merge.py — they can
# both be removed from a Pro-only deployment with no impact here.
# Only artifactory_common.sh is required.
# ───────────────────────────────────────────────────────────────────
#
# What Pro gives you over JCR Free (build.sh selects the backend via
# REGISTRY_KIND so you opt in by switching the string in image.env):
#
# | Step                | JCR Free                              | PRO (this file)                                     |
# |---------------------|---------------------------------------|-----------------------------------------------------|
# | Docker push         | plain `docker push`                   | `jf docker push --build-name --build-number --project` |
# | Build info collect  | `jf rt bp --collect-env --collect-git`| `jf build-collect-env` + `jf build-add-git` (richer) |
# | Build info publish  | published to `artifactory-build-info` | `jf build-publish --project` → `<project>-build-info` |
# | Module linkage      | side-built by lib/build-info-merge.py | automatic (jf captures layers + manifests)           |
# | Xray build scan     | not available (no Xray on Free)       | `jf build-scan --project` (returns CVE table)        |
# | Project scoping     | not available                          | `--project` on all jf commands                       |
# | Property tagging    | manual per-layer loop                  | automatic via `jf docker push` + custom manifest props |
#
# ── Variables this backend reads ────────────────────────────────────
#
# Required:
#   ARTIFACTORY_URL, ARTIFACTORY_USER,
#   ARTIFACTORY_TOKEN | ARTIFACTORY_PASSWORD,
#   ARTIFACTORY_TEAM
#
# Optional (improve build-info richness + property tagging):
#   ARTIFACTORY_ENVIRONMENT, ARTIFACTORY_PUSH_HOST,
#   ARTIFACTORY_IMAGE_REF, ARTIFACTORY_MANIFEST_PATH,
#   ARTIFACTORY_BUILD_NAME, ARTIFACTORY_BUILD_NUMBER,
#   ARTIFACTORY_PROPERTIES
#
# Pro-specific:
#   ARTIFACTORY_PROJECT                 — defaults to ARTIFACTORY_TEAM
#   ARTIFACTORY_BUILD_XRAY_PRESCAN      — "true" → jf docker scan BEFORE push
#   ARTIFACTORY_BUILD_XRAY_POSTSCAN     — "true" → jf build-scan AFTER push
#   ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS — "true" → strict (exit 1 on policy hits)
#
# Auto-install (air-gap):
#   JF_BINARY_URL, JF_DEB_URL, JF_RPM_URL, JF_INSTALL_DIR
#
# See image.env.example for what each variable does and its default.

set -uo pipefail

# Pull in the common (shared) helpers. The file lives in the same
# directory as this one — relative path keeps the relationship
# obvious and survives clone-anywhere usage.
# shellcheck source=./artifactory_common.sh
. "$(dirname "${BASH_SOURCE[0]}")/artifactory_common.sh"

# ════════════════════════════════════════════════════════════════════
# Pro-specific phase helpers
# ════════════════════════════════════════════════════════════════════
# Each Pro helper has one job. Helpers that may surface a policy
# failure return non-zero; the flow orchestrator translates the code
# into whatever action the user's fail-mode policy dictates.

# Pro preflight: confirm the Artifactory Project exists. If it doesn't,
# graceful-downgrade the run instead of failing — the user's typical
# observation when this is missing is "first build for a new team
# pushes the image fine but BP and scan both fail mid-flow." Cleaner
# behaviour:
#
#   - image push still proceeds → docker/<team>/<image>:<tag> lands
#   - build-info still publishes, but to GLOBAL artifactory-build-info
#     (no --project flag) so it doesn't 404
#   - jf docker scan / jf build-scan are SKIPPED — running them without
#     the project flag would evaluate the wrong watch set and produce
#     misleading "all clear" results, worse than no scan
#   - the postscan stage's xray-vuln.sh / xray-sbom.sh still cover
#     vuln visibility (they scan IMAGE_DIGEST, not the build-info)
#
# When the admin eventually creates the project (curl snippet printed
# in the warning), the next run flips back to full Pro flow with no
# code or env-var change.
#
# Sets globals when project is missing:
#   _ART_PROJECT_FLAG=""         drops --project from all subsequent jf calls
#   _ART_SKIP_BUILD_POSTSCAN=1   read by _artifactory_pro_xray_postscan
#   _ART_SKIP_BUILD_PRESCAN=1    read by _artifactory_pro_xray_prescan
_artifactory_pro_preflight_project() {
  _ART_SKIP_BUILD_POSTSCAN=0
  _ART_SKIP_BUILD_PRESCAN=0

  # Only relevant when there's a project key to check.
  [ -n "${_ART_PROJECT_KEY}" ] || return 0

  # /access/api/v1/* requires Bearer auth (Basic returns 401 even with
  # the same access token that works against /artifactory/api/*). Fall
  # back to Basic only when ARTIFACTORY_TOKEN is unset and we're using
  # ARTIFACTORY_PASSWORD instead — that's basic-auth-only by definition.
  local url="${ARTIFACTORY_URL%/}/access/api/v1/projects/${_ART_PROJECT_KEY}"
  local code
  if [ -n "${ARTIFACTORY_TOKEN:-}" ]; then
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer ${ARTIFACTORY_TOKEN}" \
      "${url}" 2>/dev/null) || code=000
  else
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -u "${ARTIFACTORY_USER}:${ARTIFACTORY_PASSWORD:-}" \
      "${url}" 2>/dev/null) || code=000
  fi

  case "${code}" in
    200)
      _dbg "project preflight: '${_ART_PROJECT_KEY}' exists (HTTP 200) — full Pro flow"
      return 0
      ;;
    404)
      cat >&2 <<EOF

──────────────────────────────────────────────────────────────────────
  WARN: Artifactory project '${_ART_PROJECT_KEY}' does not exist.
  Continuing with a GRACEFUL DOWNGRADE for this run:
    ✓ image push proceeds to docker/${ARTIFACTORY_TEAM}/${IMAGE_NAME}
    ✓ build-info publishes to GLOBAL artifactory-build-info
    ✗ jf docker scan / jf build-scan are SKIPPED (project-scoped
      watches don't exist; running scans without scope would
      evaluate the wrong watch set)

  To enable full Pro flow on the next build, have an admin create
  the project once via REST:

    curl -H "Authorization: Bearer \$ADMIN_TOKEN" -X POST \\
      "${ARTIFACTORY_URL%/}/access/api/v1/projects" \\
      -H "Content-Type: application/json" \\
      -d '{
            "project_key":"${_ART_PROJECT_KEY}",
            "display_name":"${_ART_PROJECT_KEY}",
            "admin_privileges":{"manage_members":true,"manage_resources":true,"index_resources":true},
            "storage_quota_bytes":-1
          }'

  Or via UI: Administration → Platform Configuration → Projects → New.

  Naming note (JFrog Cloud SaaS, may differ on self-hosted Pro): the
  project_key must be lowercase letters / digits / dashes only. If
  '${_ART_PROJECT_KEY}' contains uppercase letters, the create call
  above returns 400 — pick an all-lowercase key and update
  ARTIFACTORY_PROJECT in image.env (or your CI vars) to match.

  Auth note: /access/api/v1/* endpoints require Bearer auth; Basic auth
  with the same token returns 401 even for admins.
──────────────────────────────────────────────────────────────────────
EOF
      _ART_PROJECT_FLAG=""
      _ART_SKIP_BUILD_POSTSCAN=1
      _ART_SKIP_BUILD_PRESCAN=1
      return 0
      ;;
    401|403)
      echo "WARN: project preflight HTTP ${code} for '${_ART_PROJECT_KEY}' — token may lack project read scope." >&2
      echo "      Continuing with --project=${_ART_PROJECT_KEY}; if BP fails downstream, check admin rights." >&2
      return 0
      ;;
    000)
      echo "WARN: project preflight failed (Artifactory unreachable / curl error) for '${_ART_PROJECT_KEY}'." >&2
      echo "      Continuing with --project=${_ART_PROJECT_KEY}." >&2
      return 0
      ;;
    *)
      echo "WARN: project preflight returned HTTP ${code} for '${_ART_PROJECT_KEY}' — unexpected response." >&2
      echo "      Continuing with --project=${_ART_PROJECT_KEY}." >&2
      return 0
      ;;
  esac
}

_artifactory_pro_enrich_build_info() {
  echo ""
  echo "── Pro: enriching build info before push ──"
  # shellcheck disable=SC2086
  jf rt build-collect-env "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}" ${_ART_PROJECT_FLAG} 2>&1
  # shellcheck disable=SC2086
  jf rt build-add-git "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}" ${_ART_PROJECT_FLAG} 2>&1
}

# Optional pre-push Xray gate. When ARTIFACTORY_BUILD_XRAY_PRESCAN=true,
# runs `jf docker scan` against the locally-tagged image BEFORE pushing.
# Returns:
#   0  scan clean / scanner unavailable / disabled entirely
#   0  violations in warn mode (prints WARN, caller proceeds)
#   1  violations in strict mode (caller must abort before push)
#
# Benefits over post-push scanning:
#   1. Violations in strict mode keep the image OUT of Artifactory
#      entirely — no cleanup, no bad digest in prod-local.
#   2. Only talks to internal Artifactory/Xray — no outbound to
#      anchore.io or other public sources. Good for air-gapped runs.
#
# Caveat: Xray needs a scope (`--watches` / `--project` / `--repo-path`)
# to return exit 3 on violations. Without one the scan is informational
# only. We pass the project flag we've already computed.
_artifactory_pro_xray_prescan() {
  if [ "${_ART_SKIP_BUILD_PRESCAN:-0}" = "1" ]; then
    echo ""
    echo "── Pro: Xray pre-push scan SKIPPED (project '${_ART_PROJECT_KEY}' missing — preflight downgrade) ──"
    return 0
  fi

  [ "${ARTIFACTORY_BUILD_XRAY_PRESCAN}" = "true" ] || return 0

  if [ -z "${_ART_PROJECT_FLAG}" ]; then
    echo "" >&2
    echo "  WARN: ARTIFACTORY_BUILD_XRAY_PRESCAN=true but project_flag is empty" >&2
    echo "        (no ARTIFACTORY_PROJECT or ARTIFACTORY_TEAM set). Scan will" >&2
    echo "        be informational only — set a project to enforce violations." >&2
  fi
  echo ""
  echo "── Pro: Xray pre-push scan (jf docker scan ${_ART_TARGET}) ──"
  # shellcheck disable=SC2086
  jf docker scan "${_ART_TARGET}" ${_ART_PROJECT_FLAG} --fail=true 2>&1
  local rc=$?

  case "${rc}" in
    0)
      echo "  ✓ Xray pre-push clean"
      return 0
      ;;
    3)
      case "${ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS}" in
        true|strict)
          echo "" >&2
          echo "  ERROR: Xray pre-push scan reported policy violations" >&2
          echo "         — refusing to push (ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS=${ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS})" >&2
          echo "         The image is NOT in Artifactory. Review the scanner" >&2
          echo "         output above, remediate, rebuild, and retry." >&2
          return 1
          ;;
        *)
          echo "  WARN: Xray pre-push scan found violations — pushing anyway (warn mode)" >&2
          echo "        Set ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS=true to block push on violations." >&2
          return 0
          ;;
      esac
      ;;
    *)
      echo "  WARN: Xray pre-push scan exit ${rc} (unlicensed, unreachable, or indexing) — continuing with push" >&2
      return 0
      ;;
  esac
}

# Pro docker push with full build-info module linkage.
_artifactory_pro_push() {
  # shellcheck disable=SC2086
  jf docker push "${_ART_TARGET}" \
    --build-name="${_ART_BUILD_NAME}" \
    --build-number="${_ART_BUILD_NUMBER}" \
    ${_ART_PROJECT_FLAG} || {
      echo "ERROR: jf docker push failed" >&2
      return 1
    }
}

_artifactory_pro_publish_build_info() {
  echo ""
  echo "── Pro: publishing build info ──"
  # shellcheck disable=SC2086
  jf rt build-publish "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}" ${_ART_PROJECT_FLAG} 2>&1 | tail -5
}

# Optional post-push Xray build scan. Toggled by
# ARTIFACTORY_BUILD_XRAY_POSTSCAN (default false — opt in only when
# a Pro/Xray licence is provisioned). Same return-code contract as
# the pre-scan above:
#   0  clean / disabled / scanner unavailable / warn-mode violations
#   1  strict-mode violations (caller propagates; image is already in
#      Artifactory at this point — the failure gates promote/deploy)
#
# Non-3 exits (licensing / unreachable / indexing) always stay
# warnings regardless of fail-mode — those are scanner availability
# blips, not policy decisions.
_artifactory_pro_xray_postscan() {
  if [ "${_ART_SKIP_BUILD_POSTSCAN:-0}" = "1" ]; then
    echo ""
    echo "── Pro: Xray build scan SKIPPED (project '${_ART_PROJECT_KEY}' missing — preflight downgrade) ──"
    return 0
  fi
  if [ "${ARTIFACTORY_BUILD_XRAY_POSTSCAN}" != "true" ]; then
    echo ""
    echo "── Pro: Xray build scan skipped (ARTIFACTORY_BUILD_XRAY_POSTSCAN=${ARTIFACTORY_BUILD_XRAY_POSTSCAN}) ──"
    return 0
  fi

  echo ""
  echo "── Pro: Xray build scan ──"
  # shellcheck disable=SC2086
  jf build-scan "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}" ${_ART_PROJECT_FLAG} 2>&1
  local rc=$?

  case "${rc}" in
    0)
      echo "  ✓ Xray clean (no policy violations)"
      return 0
      ;;
    3)
      case "${ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS}" in
        true|strict)
          echo "" >&2
          echo "  ERROR: Xray policy violations detected — failing build" >&2
          echo "         (ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS=${ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS})" >&2
          echo "         The image has been pushed, but this run is being" >&2
          echo "         rejected so downstream promote/deploy stages don't" >&2
          echo "         advance. Review findings in Artifactory →" >&2
          echo "         Builds → ${_ART_BUILD_NAME}/${_ART_BUILD_NUMBER} → Xray Data." >&2
          return 1
          ;;
        *)
          echo "  WARN: Xray reported policy violations — continuing (warn mode)" >&2
          echo "        Set ARTIFACTORY_XRAY_FAIL_ON_VIOLATIONS=true to hard-fail the build." >&2
          return 0
          ;;
      esac
      ;;
    *)
      echo "  WARN: Xray scan exit ${rc} (unlicensed, unreachable, or still indexing)" >&2
      return 0
      ;;
  esac
}

# ── Flow orchestrator ──────────────────────────────────────────────
# Reads top-to-bottom. A helper returning non-zero means "stop the
# flow and propagate" — orchestrator chains with `|| return 1`.
_artifactory_pro_flow() {
  local built_local_ref="$1"
  # Preflight is run by push_to_backend before this, so _ART_PROJECT_FLAG
  # and the skip flags already reflect the project's presence/absence.
  _artifactory_pro_enrich_build_info

  docker tag "${built_local_ref}" "${_ART_TARGET}"
  _artifactory_pro_xray_prescan || return 1

  _artifactory_pro_push || return 1
  _artifactory_pro_publish_build_info
  _artifactory_pro_xray_postscan || return 1

  # After this point the image is in Artifactory and has passed both
  # scan gates (or scans were disabled/warned). Resolve digest, write
  # build.env, tag custom properties on the manifest.
  local push_digest
  push_digest=$(_artifactory_resolve_push_digest "${_ART_TARGET}")
  _artifactory_write_build_env "${_ART_TARGET}" "${push_digest}"

  # Custom properties on the manifest. jf docker push already set
  # build.name + build.number on all layers — we only add our custom
  # metadata on the manifest file itself.
  _artifactory_set_props "${_ART_MANIFEST_PATH}" \
    "${_ART_BUILD_NAME}" "${_ART_BUILD_NUMBER}" "${ARTIFACTORY_ENVIRONMENT}"
}

# ── Entry point ─────────────────────────────────────────────────────

push_to_backend() {
  local built_local_ref="$1"

  _artifactory_pro_require_env   || return 1
  _artifactory_pro_require_tools || return 1

  # Pro behaviour requires the tier flag — set it on this caller's
  # behalf so they don't have to also export ARTIFACTORY_PRO=true.
  export ARTIFACTORY_PRO="true"
  _artifactory_normalise_bools
  _artifactory_decompose_ref "${built_local_ref}"
  _artifactory_resolve_templates

  _artifactory_jf_config || return 1
  _artifactory_docker_login "${ARTIFACTORY_PUSH_HOST}" || return 1

  # Preflight needs creds (curl /access/api/v1/projects). Runs BEFORE
  # the banner so the "Tier:" line correctly reflects whether this run
  # is full-Pro or downgraded.
  _artifactory_pro_preflight_project

  _artifactory_print_banner "${built_local_ref}"

  _artifactory_pro_flow "${built_local_ref}" || return 1

  echo "Pushed: ${_ART_TARGET}"
}

# ── Internals ────────────────────────────────────────────────────────

_artifactory_pro_require_env() {
  local missing=0 var
  for var in ARTIFACTORY_URL ARTIFACTORY_USER ARTIFACTORY_TEAM; do
    if [ -z "${!var:-}" ]; then
      echo "ERROR: ${var} is required when REGISTRY_KIND=artifactory_pro" >&2
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
# `${kind}_require_env` so each backend exports a predictable name.
artifactory_pro_require_env() { _artifactory_pro_require_env "$@"; }

# Pro require_tools: just the base (jf + docker). No python3 needed —
# Pro uses jf's native build-info publishing, not the side-channel
# JSON merger that the JCR tier needs.
_artifactory_pro_require_tools() {
  _artifactory_require_tools_base
}
