#!/usr/bin/env bash
# ─── DO NOT EDIT — template lib ────────────────────────────────────
# Sourced by build.sh + every scan/ingest script. To change config,
# edit image.env in your per-fork repo, not this file.
# ───────────────────────────────────────────────────────────────────
#
# scripts/lib/load-image-env.sh — single source of truth for image.env loading
#
# Sourced by every script that needs to read behavioural config —
# build.sh, every scan/* script, sbom-post.sh, etc. Add a new
# script that needs config? Just `. scripts/lib/load-image-env.sh
# && load_image_env` at the top.
#
# Provides:
#
#   _dbg <msg>            — print '[debug] msg' to stderr when
#                           BUILD_DEBUG=true; otherwise no-op. Safe under
#                           `set -e` (returns 0 either way).
#
#   import_bamboo_vars    — translate every `bamboo_FOO` env var to a
#                           bare `FOO` export. Skips vars already set in
#                           the shell (explicit export wins). No-op when
#                           not running under Bamboo.
#
#   load_image_env        — source ./image.env from the caller's CWD.
#                           Fails fast (return 1) if the file is missing.
#                           image.env.example is intentionally NOT a
#                           fallback — it's a template only. Snapshot/
#                           restore semantics: shell-set non-empty vars
#                           override image.env values; empty-set shell
#                           vars don't (so a stray `VAR=` in the agent
#                           env can't clobber the file value).
#                           Snapshot list is AUTO-DERIVED from image.env
#                           (greps `^[# ]*VAR=` patterns) — adding a var
#                           to image.env is a one-place edit, no hardcoded
#                           list to maintain. Shell/CI-only vars (build.env
#                           outputs, secrets) need no entry: image.env
#                           can't clobber what it doesn't set.
#
# Centralising means each script self-loads its config — same precedence
# everywhere, same debug logs everywhere, same "fail with clear hint"
# message when image.env is missing.

# shellcheck disable=SC2148
# (sourced, not executed — no shebang interpretation needed)

# ════════════════════════════════════════════════════════════════════
# _dbg — opt-in debug echo
# ════════════════════════════════════════════════════════════════════
# Set BUILD_DEBUG=true (env or image.env) to surface verbose decision
# logs from scripts that source this lib. Off by default to keep CI
# logs clean. The `return 0` keeps the call site `set -e` safe.
_dbg() {
  [ "${BUILD_DEBUG:-false}" = "true" ] && echo "  [debug] $*" >&2
  return 0
}

# ════════════════════════════════════════════════════════════════════
# _redact_value — censor secret values in load-time logging
# ════════════════════════════════════════════════════════════════════
# Vars whose name matches secret-ish patterns (TOKEN/PASSWORD/SECRET/
# AUTH/KEY/CA_CERT) print as "[redacted, N chars]" so the log shows
# WHETHER a secret was loaded without leaking its contents. Everything
# else prints in full so the operator can verify URLs, hostnames,
# tags, project paths, etc. landed correctly.
_redact_value() {
  local __name="$1" __value="$2"
  case "${__name}" in
    *TOKEN*|*PASSWORD*|*SECRET*|*AUTH*|*_KEY|*_KEY_*|CA_CERT|COSIGN_KEY)
      if [ -z "${__value}" ]; then
        printf '<empty>'
      else
        printf '[redacted, %d chars]' "${#__value}"
      fi
      ;;
    *) printf '%s' "${__value}" ;;
  esac
}

# ════════════════════════════════════════════════════════════════════
# import_bamboo_vars — sourced from scripts/lib/bamboo-import.sh
# ════════════════════════════════════════════════════════════════════
# The actual Bamboo auto-import logic lives in a SEPARATE file
# (scripts/lib/bamboo-import.sh) so the codebase remains modular —
# Bamboo support can be removed by deleting that one file plus
# bamboo-specs/bamboo.yml. The stub below provides a safe no-op
# function when bamboo-import.sh isn't present, so callers that do
# `import_bamboo_vars` keep working unchanged.
_bamboo_lib="$(dirname "${BASH_SOURCE[0]}")/bamboo-import.sh"
if [ -f "${_bamboo_lib}" ]; then
  # shellcheck source=./bamboo-import.sh
  . "${_bamboo_lib}"
else
  # Bamboo support removed. Stub keeps the API stable for callers.
  import_bamboo_vars() { :; }
fi
unset _bamboo_lib

# ════════════════════════════════════════════════════════════════════
# load_image_env [path] — source image.env with snapshot/restore semantics
# ════════════════════════════════════════════════════════════════════
# Path resolution (first non-empty wins):
#   1. explicit $1 argument
#   2. ${IMAGE_ENV_FILE} env var (set by build.sh --env-file)
#   3. ${PROJECT_ROOT}/image.env (per-image repo when invoked via clone)
#   4. ./image.env relative to CWD (callers run from the repo root)
# Fails fast with a hint when nothing exists.
#
# Three-step:
#   1. Snapshot all known config vars that are SET AND NON-EMPTY in
#      the caller's shell. (Empty-set is intentionally excluded —
#      a stray `VAR=` exported by the runner shouldn't override
#      the file's VAR=<real-value>.)
#   2. Source image.env from the resolved path. Fail if missing.
#   3. Re-export the snapshot so shell values win over file values.
#
# Pre-fail behaviour: the caller's shell may have run import_bamboo_vars
# already, which means `bamboo_VENDOR=foo` becomes a bare `VENDOR=foo`
# BEFORE this function snapshots. So plan-var values survive the
# snapshot/restore round-trip and override the file.
load_image_env() {
  local __env_file=""
  if [ -n "${1:-}" ]; then
    __env_file="$1"
  elif [ -n "${IMAGE_ENV_FILE:-}" ]; then
    __env_file="${IMAGE_ENV_FILE}"
  elif [ -n "${PROJECT_ROOT:-}" ] && [ -f "${PROJECT_ROOT}/image.env" ]; then
    __env_file="${PROJECT_ROOT}/image.env"
  else
    __env_file="image.env"
  fi

  if [ ! -f "${__env_file}" ]; then
    echo "ERROR: image.env not found at ${__env_file}" >&2
    echo "       (resolved from arg='${1:-}', IMAGE_ENV_FILE='${IMAGE_ENV_FILE:-}'," >&2
    echo "        PROJECT_ROOT='${PROJECT_ROOT:-}', CWD='$(pwd)')" >&2
    echo "" >&2
    echo "  image.env is the single source of truth for this build." >&2
    echo "  image.env.example is a TEMPLATE — it is NOT sourced as a" >&2
    echo "  fallback, because that would mask config drift between" >&2
    echo "  local edits and CI's untouched template." >&2
    echo "" >&2
    echo "  To fix:" >&2
    echo "    cp image.env.example image.env" >&2
    echo "    \$EDITOR image.env       # adjust UPSTREAM_TAG, REGISTRY_KIND, etc." >&2
    echo "    git add image.env && git commit -m 'add image.env'" >&2
    echo "" >&2
    echo "  image.env lives in the per-image repo (PROJECT_ROOT)." >&2
    echo "  Keep secrets OUT of image.env; pass tokens via CI plan vars." >&2
    return 1
  fi

  # ── Build the snapshot list ─────────────────────────────────────
  # Auto-derive PURELY from image.env by grepping every line that
  # mentions a `VAR=` (active or commented — only the NAME is taken;
  # commented lines are never sourced for their value). That way
  # ADDING A NEW VAR TO image.env IS A ONE-PLACE EDIT — no hardcoded
  # list to maintain here. (image.env.example is a template and is
  # intentionally NOT scanned.)
  #
  # No supplementary list is needed: this snapshot exists only to make
  # a shell/CI value WIN over an image.env value for the SAME var.
  # Vars that live only in the shell/CI and never in image.env
  # (build.env outputs like IMAGE_REF/IMAGE_DIGEST, secrets like
  # CA_CERT, scan-time overrides, ALLOW_TRIVY) need no entry here:
  # image.env can't clobber what it doesn't set, so their shell value
  # already survives sourcing untouched. They simply won't appear in
  # the "→ Loaded config" listing below — each script logs its own
  # resolved target/inputs anyway.
  local __v __line __SHELL_OVERRIDES=""
  local __known
  __known=$(
    grep -oE '^[# ]*[A-Z][A-Z0-9_]+=' "${__env_file}" 2>/dev/null \
      | sed -E 's/^[# ]*//; s/=$//' \
      | sort -u
  )
  for __v in ${__known}; do
    if [ -n "${!__v-}" ]; then
      __SHELL_OVERRIDES="${__SHELL_OVERRIDES}${__v}=$(printf '%q' "${!__v}")"$'\n'
      _dbg "shell-set override captured: ${__v}"
    fi
  done

  echo "→ Sourcing ${__env_file}"
  _dbg "image.env present at ${__env_file}"
  # shellcheck disable=SC1091
  . "${__env_file}"

  # Track which keys were overridden from the shell vs. taken straight
  # from image.env so the per-var log can annotate the source. The set
  # is built from __SHELL_OVERRIDES (one line per override).
  local __overridden=""
  if [ -n "${__SHELL_OVERRIDES}" ]; then
    _dbg "re-applying shell-set overrides on top of image.env"
    while IFS= read -r __line; do
      [ -z "${__line}" ] && continue
      eval "export ${__line}"
      __overridden="${__overridden} ${__line%%=*}"
    done <<< "${__SHELL_OVERRIDES}"
  fi

  # ── Visibility: enumerate every loaded var ──────────────────────
  # Printed by default (LOAD_ENV_LOG unset or "true") so operators
  # can verify config landed correctly without re-running the job
  # under BUILD_DEBUG=true. Secrets are redacted by _redact_value so
  # logs are safe to share.
  #
  # Three modes (set LOAD_ENV_LOG in env, image.env, or CI variable):
  #   true (default)  per-var listing with [source] annotation
  #   summary         one-line count (loaded X / overridden Y)
  #   false           silent — for very chatty CI runs where the listing
  #                   would dominate the log
  case "${LOAD_ENV_LOG:-true}" in
    false|False|FALSE|0|off|Off|OFF|no|No|NO)
      ;;
    summary|Summary|SUMMARY|count|Count|COUNT)
      local __loaded_count=0 __override_count=0
      for __v in ${__known}; do
        [ -n "${!__v-}" ] && __loaded_count=$((__loaded_count+1))
      done
      for __o in ${__overridden}; do
        __override_count=$((__override_count+1))
      done
      echo "→ Loaded ${__loaded_count} config vars (${__override_count} shell-overridden). Set LOAD_ENV_LOG=true for per-var listing."
      ;;
    *)
      echo "→ Loaded config (image.env + shell-overrides):"
      for __v in ${__known}; do
        if [ -n "${!__v-}" ]; then
          local __source="image.env"
          case " ${__overridden} " in *" ${__v} "*) __source="shell-override" ;; esac
          echo "    ${__v}=$(_redact_value "${__v}" "${!__v}")  [${__source}]"
        fi
      done
      ;;
  esac
}
