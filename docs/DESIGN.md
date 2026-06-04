# Design notes

Rationale for the non-obvious decisions in `scripts/build.sh` and the
scan/ingest flow. The scripts carry one-line pointers here instead of
inline essays, so the code stays readable.

## Two roots: TEMPLATE_ROOT vs PROJECT_ROOT

The template is cloned and invoked by per-image repos:

```
git clone --depth 1 ${TEMPLATE_REPO} .template
cd <per-image-repo>            # has image.env + Dockerfile + certs/
bash .template/scripts/build.sh
```

- **TEMPLATE_ROOT** — where `build.sh` and its sibling libs / push
  backends / scan scripts live. Computed from `BASH_SOURCE`. Read-only;
  artifacts never land here.
- **PROJECT_ROOT** — where `image.env`, `Dockerfile`, `certs/` live and
  where `build.env` / `sbom.cdx.json` / `vuln-scan.json` are written.
  Defaults to the operator's CWD; override with `--project-root <path>`
  or the `PROJECT_ROOT` env var for callers that can't `cd` first.

When the per-image repo *is* the template repo (e.g. the template's own
tests), the two coincide and the contract still holds — no special case.

## Reproducible build digest (SOURCE_DATE_EPOCH)

Two consecutive `--push` of the **same commit** must produce the **same**
image digest. The only thing that used to differ between runs was
`CREATED=$(date now)`, which fed `org.opencontainers.image.created` and
(via BuildKit) the image config's own timestamps — so each build got a
fresh manifest digest, the re-push **orphaned** the previous digest in
the registry, and any scan still holding that digest failed immediately
(`manifest not found`).

Fix: anchor the build clock to the git **commit** time. BuildKit honours
`SOURCE_DATE_EPOCH` (clamps layer + config timestamps), so identical
source → identical digest, and a re-push is a no-op overwrite to the same
digest (nothing orphaned). Precedence:

1. `SOURCE_DATE_EPOCH` already in env → respected (CI override)
2. git committer date of HEAD → reproducible per commit
3. wall clock (no git) → last resort, non-reproducible

It is **not** exported globally — `build.sh` passes it inline on the
buildx command so it can't leak into the caller's shell and silently pin
a later same-shell run's timestamp.

## buildx attestation flags / flat manifest

When buildx is present we pass `--provenance=false --sbom=false` to force
a **flat single-arch v2** distribution manifest (config + layers in the
tag dir) instead of an OCI image index wrapping the manifest + an
attestation manifest. The index lands in JFrog as
`<tag>/list.manifest.json` with layer blobs outside the tag dir, which
makes the Free-tier build-info merger (`lib/build-info-merge.py`) report
"1 artifact, 0 dependencies (fallback)" instead of the proper
"manifest + config + N layers" count.

When buildx is **not** installed (some hosted CI runners ship plain
Docker Engine), `docker build` rejects those flags, so we fall back to a
vanilla `docker build` — non-buildx Docker never produces OCI indices
anyway, so the flags wouldn't have served a purpose there.

We don't consume buildx's provenance/SBOM attestations — Xray covers
provenance, and Syft/Trivy/Xray + `sbom-post.sh` cover SBOMs as their own
stages — so disabling them is lossless.

## build.env policy on the no-push path

`build.sh` emits `build.env` immediately after `docker build`, **before**
the optional push, so feature-branch pipelines that only build (no
`--push`) still produce a scannable artifact for prescan/postscan/test
jobs. On the no-push path:

- `IMAGE_REF=${UPSTREAM_REF}` — fully-qualified, pullable from any
  runner. The local `docker tag` (`${FULL_IMAGE}`) is bare `image:tag`
  and won't resolve in a fresh downstream dind. The built content is
  upstream + the cert-sidecar tweak, so scanning upstream is a valid
  pipeline-validation proxy.
- `LOCAL_IMAGE=${FULL_IMAGE}` — preserved so a same-daemon scan (local
  dev, or a runner sharing dind across jobs) can prefer the built image.
- `IMAGE_DIGEST=` — empty (no remote manifest exists yet).

When `--push` runs, the push backend overwrites `build.env` with the
registry URL + remote `@sha256` digest, so `IMAGE_REF` then points at
the real artifact.

## Scan-target resolution & tool deletability

See `scripts/lib/scan-common.sh`. Every scan producer bootstraps the same
way (`scan_bootstrap`) and resolves its target through one shared
`resolve_scan_ref` whose override-var precedence is passed in as
arguments — so the lib has zero tool-specific logic. Deleting any one
scan script (e.g. all `trivy-*.sh` if Trivy is banned) never touches the
lib and never affects the other scanners.
