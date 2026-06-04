#!/usr/bin/env bash
# ─── DO NOT EDIT — template lib (shared by scripts/scan/*.sh) ───────
# Generic scan bootstrap + scan-target resolution. Contains NO tool-
# specific logic — every scan producer calls these the same way, so
# deleting any one scan script never touches this file and never affects
# the others. Override-var names are passed in as ARGUMENTS, so the
# resolution order is the caller's to decide.
# ───────────────────────────────────────────────────────────────────
# shellcheck disable=SC2148

# scan_bootstrap — the preamble every scan script shares.
# Sources load-image-env + artifact-names, imports Bamboo plan vars,
# loads image.env, then self-sources build.env (latest IMAGE_DIGEST)
# so build.sh → scan needs no manual `. build.env`. Requires
# TEMPLATE_ROOT + PROJECT_ROOT already exported by the caller.
scan_bootstrap() {
  # Capture operator-set output filenames BEFORE artifact-names.sh defaults
  # them, so an explicit shell/CI override survives the build.env self-source
  # below (build.env carries the canonical names and would otherwise clobber
  # them — defeating distinct per-producer outputs in a multi-scanner run).
  local __sbom_override="${SBOM_FILE:-}" __vuln_override="${VULN_SCAN_FILE:-}"
  # shellcheck source=./load-image-env.sh
  . "${TEMPLATE_ROOT}/scripts/lib/load-image-env.sh"
  # shellcheck source=./artifact-names.sh
  . "${TEMPLATE_ROOT}/scripts/lib/artifact-names.sh"
  import_bamboo_vars
  load_image_env
  if [ -f build.env ]; then set -a; . ./build.env; set +a; fi
  # build.env supplies build OUTPUTS (IMAGE_DIGEST/IMAGE_REF/…); but an
  # explicitly-overridden output FILENAME wins over its canonical default.
  [ -n "${__sbom_override}" ] && export SBOM_FILE="${__sbom_override}"
  [ -n "${__vuln_override}" ] && export VULN_SCAN_FILE="${__vuln_override}"
  return 0   # never let a falsy build.env test trip the caller's `set -e`
}

# resolve_scan_ref <positional-$1> [override-var-name ...]
# Echoes the resolved scan target on stdout, or prints the standard
# error block to stderr and returns 1. Precedence:
#   $1 > each named override var (in the order given)
#      > IMAGE_DIGEST > IMAGE_REF > UPSTREAM_REF
#      > UPSTREAM_REGISTRY/UPSTREAM_IMAGE:UPSTREAM_TAG (assembled)
resolve_scan_ref() {
  local ref="$1"; shift
  local v chain='$1'
  for v in "$@"; do
    chain="${chain} > ${v}"
    [ -z "${ref}" ] && [ -n "${!v:-}" ] && ref="${!v}"
  done
  if [ -z "${ref}" ]; then
    if   [ -n "${IMAGE_DIGEST:-}" ]; then ref="${IMAGE_DIGEST}"
    elif [ -n "${IMAGE_REF:-}" ];    then ref="${IMAGE_REF}"
    elif [ -n "${UPSTREAM_REF:-}" ]; then ref="${UPSTREAM_REF}"
    elif [ -n "${UPSTREAM_REGISTRY:-}" ] && [ -n "${UPSTREAM_IMAGE:-}" ] && [ -n "${UPSTREAM_TAG:-}" ]; then
      ref="${UPSTREAM_REGISTRY}/${UPSTREAM_IMAGE}:${UPSTREAM_TAG}"
    fi
  fi
  if [ -z "${ref}" ]; then
    echo "ERROR: no scan target available." >&2
    echo "  Resolution chain: ${chain} > IMAGE_DIGEST > IMAGE_REF > UPSTREAM_REF > UPSTREAM_REGISTRY/IMAGE:TAG" >&2
    echo "  All empty. To scan after build, ensure build.env (with IMAGE_DIGEST) is on disk." >&2
    echo "  To scan upstream as a prescan, set UPSTREAM_REF in image.env, or pass a ref explicitly." >&2
    return 1
  fi
  printf '%s' "${ref}"
}
