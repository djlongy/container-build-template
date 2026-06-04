#!/usr/bin/env bash
# ─── DO NOT EDIT — template lib ────────────────────────────────────
# Sourced by scan scripts. Credentials come from image.env / CI vars.
# ───────────────────────────────────────────────────────────────────
#
# scripts/lib/docker-login.sh — multi-registry docker login for scan jobs
#
# Sourced by scripts/scan/xray-vuln.sh and scripts/scan/xray-sbom.sh
# (and any future scan script that needs to `docker pull` private
# images). Logs the daemon into every registry whose credentials it
# finds in env, so the subsequent `docker pull` of either the upstream
# OR the rebuilt image just works.
#
# Provides one function:
#
#   docker_login_for_xray_scan
#     Attempts a non-fatal docker login against the hosts it has creds
#     for:
#     - HARBOR_REGISTRY                (default Harbor backend)
#     - ARTIFACTORY_PUSH_HOST          (REGISTRY_KIND=artifactory_jcr|artifactory_pro)
#     - the UPSTREAM host              (pull side) — see resolution below
#
#     Upstream pull-auth resolution (decoupled from the push side):
#       1. explicit UPSTREAM_REGISTRY_USER + UPSTREAM_REGISTRY_PASSWORD
#          (token ok) → used for ANY host (private mirror, Docker Hub /
#          ghcr / quay account, …);
#       2. else ARTIFACTORY_USER + ARTIFACTORY_TOKEN/PASSWORD, but ONLY
#          when the upstream host shares ARTIFACTORY_URL's domain (the
#          "upstream is our own Artifactory mirror" case — existing forks
#          that set only ARTIFACTORY_* keep working, no migration);
#       3. else none → anonymous pull. Artifactory creds are NEVER sent
#          to a public registry (docker.io / ghcr / quay / …).
#
#     Each login is independent: failure of one doesn't block the
#     others. Hosts without configured creds are silently skipped.
#     A failed individual login logs WARN but continues — public
#     images (e.g. docker.io/library/* for prescan) are still
#     pullable without auth.
#
#     NOTE: the function name is historical (it predates syft-sbom +
#     non-Xray scanners); it is the shared multi-registry login used by
#     every scan/build job, not Xray-specific.
#
# Why a separate lib instead of doing this inline:
#   - build.sh has its own narrower _build_docker_login that targets
#     ONE host (the push target). This lib targets MULTIPLE hosts
#     because a postscan job may need to pull from HARBOR_REGISTRY
#     (built image) AND the upstream registry (cached locally maybe,
#     or if you're scanning multiple images in one job).
#   - Reused across xray-vuln + xray-sbom. Keeps the per-script logic
#     focused on its single responsibility (scan + ship).
#
# shellcheck disable=SC2148
# (sourced, not executed)

docker_login_for_xray_scan() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "  WARN: docker CLI not on PATH — skipping login (subsequent pull will likely fail)" >&2
    return 0
  fi

  local _attempts=0 _failures=0

  # ── HARBOR_REGISTRY (Harbor / default backend) ───────────────────
  if [ -n "${HARBOR_REGISTRY:-}" ] && [ -n "${HARBOR_USER:-}" ] && [ -n "${HARBOR_PASSWORD:-}" ]; then
    _attempts=$((_attempts + 1))
    echo "→ docker login ${HARBOR_REGISTRY} (HARBOR_REGISTRY)"
    if printf '%s' "${HARBOR_PASSWORD}" \
         | docker login "${HARBOR_REGISTRY}" -u "${HARBOR_USER}" --password-stdin >/dev/null 2>/tmp/docker-login.err; then
      echo "  ✓ logged in"
    else
      echo "  WARN: login failed — ${HARBOR_REGISTRY} pulls will be unauthenticated" >&2
      sed 's/^/    /' /tmp/docker-login.err >&2 || true
      _failures=$((_failures + 1))
    fi
  fi

  # ── ARTIFACTORY_PUSH_HOST (when REGISTRY_KIND=artifactory_jcr|artifactory_pro) ─────
  if [ -n "${ARTIFACTORY_PUSH_HOST:-}" ] && [ -n "${ARTIFACTORY_USER:-}" ]; then
    local _secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD:-}}"
    if [ -n "${_secret}" ]; then
      _attempts=$((_attempts + 1))
      echo "→ docker login ${ARTIFACTORY_PUSH_HOST} (ARTIFACTORY_PUSH_HOST)"
      if printf '%s' "${_secret}" \
           | docker login "${ARTIFACTORY_PUSH_HOST}" -u "${ARTIFACTORY_USER}" --password-stdin >/dev/null 2>/tmp/docker-login.err; then
        echo "  ✓ logged in"
      else
        echo "  WARN: login failed — ${ARTIFACTORY_PUSH_HOST} pulls will be unauthenticated" >&2
        sed 's/^/    /' /tmp/docker-login.err >&2 || true
        _failures=$((_failures + 1))
      fi
    fi
  fi

  # ── Upstream registry pull auth (explicit-wins, safe fallback) ───
  # Logging in to pull the BASE image is decoupled from the push side.
  # Credential resolution for the upstream host:
  #   1. explicit UPSTREAM_REGISTRY_USER + UPSTREAM_REGISTRY_PASSWORD
  #      (PASSWORD accepts a token) — used for ANY host. This is the
  #      flexible knob: private mirror, Docker Hub / ghcr / quay account.
  #   2. else ARTIFACTORY_USER + ARTIFACTORY_TOKEN/PASSWORD — but ONLY
  #      when the upstream host is in the SAME domain as ARTIFACTORY_URL
  #      (the common "upstream is our own Artifactory mirror" case, so
  #      existing forks that only set ARTIFACTORY_* keep working with no
  #      migration). NEVER sent to a public registry.
  #   3. else none → anonymous pull (public / anonymous-pull registries).
  # Host comes from UPSTREAM_REGISTRY (legacy) or the single-URL
  # UPSTREAM_REF. Skipped when already logged in above (push host / Harbor).
  local _ups_ref="${UPSTREAM_REGISTRY:-${UPSTREAM_REF:-}}"
  local _ups_host="${_ups_ref%%/*}"
  local _ups_user="" _ups_pass="" _ups_src=""
  if [ -n "${UPSTREAM_REGISTRY_USER:-}" ] && [ -n "${UPSTREAM_REGISTRY_PASSWORD:-}" ]; then
    _ups_user="${UPSTREAM_REGISTRY_USER}"; _ups_pass="${UPSTREAM_REGISTRY_PASSWORD}"; _ups_src="UPSTREAM_REGISTRY_USER"
  elif [ -n "${ARTIFACTORY_USER:-}" ] && [ -n "${_ups_host}" ]; then
    local _art_secret="${ARTIFACTORY_TOKEN:-${ARTIFACTORY_PASSWORD:-}}"
    local _art_host="${ARTIFACTORY_URL#*://}"; _art_host="${_art_host%%/*}"
    local _art_apex=""
    [ -n "${_art_host}" ] && _art_apex="$(printf '%s' "${_art_host}" | rev | cut -d. -f1,2 | rev)"
    if [ -n "${_art_secret}" ] && [ -n "${_art_host}" ]; then
      case "${_ups_host}" in
        "${_art_host}"|"${_art_apex}"|*".${_art_apex}")
          _ups_user="${ARTIFACTORY_USER}"; _ups_pass="${_art_secret}"; _ups_src="ARTIFACTORY_USER (same domain)" ;;
      esac
    fi
  fi
  if [ -n "${_ups_host}" ] && [ -n "${_ups_user}" ] && [ -n "${_ups_pass}" ] \
     && [ "${_ups_host}" != "${HARBOR_REGISTRY:-}" ] \
     && [ "${_ups_host}" != "${ARTIFACTORY_PUSH_HOST:-}" ]; then
    _attempts=$((_attempts + 1))
    echo "→ docker login ${_ups_host} (upstream — ${_ups_src})"
    if printf '%s' "${_ups_pass}" \
         | docker login "${_ups_host}" -u "${_ups_user}" --password-stdin >/dev/null 2>/tmp/docker-login.err; then
      echo "  ✓ logged in"
    else
      echo "  WARN: login failed — ${_ups_host} pulls will be unauthenticated" >&2
      sed 's/^/    /' /tmp/docker-login.err >&2 || true
      _failures=$((_failures + 1))
    fi
  elif [ -n "${_ups_host}" ]; then
    [ "${BUILD_DEBUG:-false}" = "true" ] && \
      echo "  [debug] no upstream creds for ${_ups_host} (not in Artifactory domain, no UPSTREAM_REGISTRY_USER) — anonymous pull" >&2
  fi

  # NOTE: we deliberately DO NOT attempt docker login against
  # XRAY_ARTIFACTORY_URL. That URL is the JFrog Platform API endpoint
  # for `jf config add` (scan API), not a registry host we pull from.
  # On JFrog Cloud especially, docker login uses a different identity
  # (the access-token's encoded subject, not the API user/email) and
  # an attempted login with the API creds fails with "Wrong username
  # was used" — noisy and confusing. The actual built image lives at
  # HARBOR_REGISTRY or ARTIFACTORY_PUSH_HOST, both handled above.

  if [ "${_attempts}" -eq 0 ]; then
    echo "  NOTE: no registry credentials in env — relying on existing daemon auth + public pulls" >&2
  fi
  # Always return 0 — failed logins shouldn't block the script;
  # pull-failure is a separate concern handled by the caller.
  return 0
}
