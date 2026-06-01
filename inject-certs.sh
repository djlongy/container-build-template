#!/usr/bin/env sh
# ─── VENDORED — copy verbatim into per-image repos ─────────────────
# Lives next to the Dockerfile in every per-image repo so the build
# context can COPY it. Do not edit unless updating the template.
# ───────────────────────────────────────────────────────────────────
#
# inject-certs.sh — drop corp CA certs from /tmp/certs/ into the
# system trust store of a cert-builder stage.
#
# Runs INSIDE the Dockerfile's cert-builder stage (USER root). Idempotent.
#
# Lives at the repo root alongside Dockerfile because the Dockerfile
# does `COPY inject-certs.sh /tmp/inject-certs.sh && RUN /tmp/...`.
# Extracted from the Dockerfile (rather than inlined as a multi-line
# RUN) so SonarQube and shellcheck can scan the bash — both ignore
# code buried inside Dockerfile RUN blocks.
#
# Per-image repos vendor a verbatim copy of this file at THEIR repo
# root. `docker build .` works without any wrapper because the file
# is right there next to the Dockerfile.
#
# Strategy (chicken-and-egg-aware):
#   1. Append the cert PEM directly to the bundle file at
#      /etc/ssl/certs/ca-certificates.crt AND /etc/ssl/cert.pem.
#      That's what most openssl/curl/wget/etc. consult at TLS-handshake
#      time. Trust becomes instant — no rebuild tool required.
#   2. Copy the cert into the drop-in dir (debian/alpine:
#      /usr/local/share/ca-certificates; rhel: /etc/pki/ca-trust/source/
#      anchors) for tools that c_rehash-walk that directory.
#   3. Optionally run update-ca-certificates / update-ca-trust to
#      regenerate the hashed symlink farm in /etc/ssl/certs/<hash>.0
#      for the small set of tools that look those up. Cosmetic — the
#      cat-append in step 1 is the trust-delivery mechanism.
#
# The cat-append-first order is deliberate. Running update-ca-certificates
# (or apk add ca-certificates) FIRST against a TLS-protected internal
# Artifactory mirror deadlocks — the install itself needs the corp CA
# already trusted at handshake time. See sibling cert-builder repo
# (github.com/djlongy/cert-builder) for the same pattern applied to
# pre-baked corp-CA-trusting base images.

set -eu

if [ -d /usr/local/share/ca-certificates ]; then
  DROP_DIR=/usr/local/share/ca-certificates
  REBUILD=update-ca-certificates
elif [ -d /etc/pki/ca-trust/source/anchors ]; then
  DROP_DIR=/etc/pki/ca-trust/source/anchors
  REBUILD=update-ca-trust
else
  DROP_DIR=/usr/local/share/ca-certificates
  mkdir -p "${DROP_DIR}"
  REBUILD=""
fi

found=0
for f in /tmp/certs/*.crt /tmp/certs/*.pem; do
  [ -f "$f" ] || continue
  name="$(basename "$f")"
  case "${name}" in
    *.crt|*.pem) name="${name%.*}" ;;
  esac
  # alpine's /etc/ssl/cert.pem symlinks to ca-certificates.crt — append
  # to both for portability across distros without checking symlink-ness.
  cat "$f" >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
  cat "$f" >> /etc/ssl/cert.pem 2>/dev/null || true
  cp "$f" "${DROP_DIR}/${name}.crt"
  found=$((found + 1))
done
echo "Injected ${found} CA cert(s) (drop_dir=${DROP_DIR})"

# Staged certs are consumed; clean up so they don't leak into the
# final image via COPY --from later.
rm -rf /tmp/certs

if [ -n "${REBUILD}" ] && command -v "${REBUILD}" >/dev/null 2>&1; then
  "${REBUILD}" 2>/dev/null || true
fi

# Ensure both drop-in dirs EXIST so the final stage's COPY --from
# never fails on a missing source path (the final stage COPYs both
# /usr/local/share/ca-certificates/ and /etc/pki/ca-trust/source/anchors/
# unconditionally so the same Dockerfile works for any base distro).
mkdir -p /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors
