#!/usr/bin/env sh
# ─── VENDORED — copy verbatim into per-image repos ─────────────────
# Lives next to the Dockerfile in every per-image repo so the build
# context can COPY it. Do not edit unless updating the template.
# ───────────────────────────────────────────────────────────────────
#
# install-ca-certificates.sh — best-effort install of the ca-certificates
# package + its rebuild tool, IF neither tool is already present.
#
# Runs INSIDE the Dockerfile's cert-builder stage (USER root). Idempotent.
#
# Lives at the repo root alongside Dockerfile because the Dockerfile
# does `COPY install-ca-certificates.sh /tmp/install-ca-certificates.sh
# && RUN /tmp/...`. Extracted from the Dockerfile (rather than inlined
# as a multi-line RUN) so SonarQube and shellcheck can scan the bash.
#
# Per-image repos vendor a verbatim copy at THEIR repo root.
#
# Strategy:
#   - If update-ca-certificates or update-ca-trust already exists, skip
#     the install entirely — that's the airgap-safe path and avoids
#     a network attempt the build doesn't actually need.
#   - Otherwise try every common package manager in order. Each install
#     is best-effort (2>/dev/null + || true) because some bases have
#     stale repo metadata and the cat-append in inject-certs.sh is
#     what actually delivers TLS trust at runtime anyway.

set -eu

if command -v update-ca-certificates >/dev/null 2>&1 \
   || command -v update-ca-trust >/dev/null 2>&1; then
  echo "→ ca-certificates rebuild tool already present — skipping install"
  exit 0
fi

if command -v apk >/dev/null 2>&1; then
  apk add --no-cache ca-certificates 2>/dev/null || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y ca-certificates 2>/dev/null || true
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq 2>/dev/null \
    && apt-get install -y ca-certificates 2>/dev/null \
    || true
elif command -v microdnf >/dev/null 2>&1; then
  microdnf install -y ca-certificates 2>/dev/null \
    && microdnf clean all 2>/dev/null \
    || true
else
  echo "→ no known package manager — skipping (cat-append in inject-certs.sh"
  echo "  is the runtime trust mechanism; rebuild tool is nice-to-have only)"
fi
