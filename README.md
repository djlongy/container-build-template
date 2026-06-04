# container-build-template

Build one container image from an upstream base through a DevSecOps
pipeline. Ships with a working nginx example. Modular by design —
swap any push backend or scan tool by changing one script name.

**Features**
- **Pluggable push backends**: `harbor.sh` (default plain v2 registry),
  `artifactory_jcr.sh` (Free tier — JCR / self-hosted Free), or
  `artifactory_pro.sh` (Pro tier — Pro / JFrog Cloud, slimmer, no python3
  dep). Pick via `REGISTRY_KIND="harbor"|"artifactory_jcr"|"artifactory_pro"`.
- **Pluggable scan tools** (each its own CI job): Syft / Xray / Trivy
  for SBOM; Grype / Xray / Trivy for vuln. All write canonical
  `sbom.cdx.json` / `vuln-scan.json` so downstream stages work
  regardless of which producer ran.
- **Cert injection**: drop `*.crt` in `certs/` or set `CA_CERT` (PEM
  string) at build time — distro-agnostic stage.
- **Per-image customisation in the Dockerfile**: edit the marked
  FORK EDITS region directly. No env-toggle abstractions.
- **Upstream-version tagging**: `<image>:<UPSTREAM_TAG>-<gitShort>`
  (e.g. `nginx:1.25.3-alpine-a1b2c3d`). The upstream is one full image
  URL (`UPSTREAM_REF`) in `image.env`; Renovate reads the repo + tag
  straight from it and auto-bumps — no `# renovate:` hint to maintain.
- **5 SBOM sinks** (`scripts/ingest/sbom-post.sh`): generic webhook,
  OWASP Dependency-Track, Artifactory Xray-indexed, Artifactory plain
  archive, Splunk HEC. All opt-in, all no-op when unset.
- **Cosign scaffold** (dormant — uncomment to restore).
- **GitLab + Bamboo at 1:1 parity**, both inline (no template
  indirection).

## Consuming the template (per-image repo)

Each image (prometheus, redis, …) lives in its own repo and consumes
this template at CI time. Vendor these files from the template:

```bash
cp Dockerfile.example                  Dockerfile
cp image.env.example                   image.env  &&  $EDITOR image.env
cp inject-certs.sh install-ca-certificates.sh  .
cp .gitignore .dockerignore            .
cp .gitlab-ci.yml                      .       # or bamboo-specs/bamboo.yml
mkdir -p certs/                                # populate at build time
```

The CI YAML clones the template at job time and runs its scripts
against your `image.env` + `Dockerfile`. See `software/prometheus`
or `software/redis` in the homelab for working examples.

## Quick start (self-build)

```bash
# 1. Clone
git clone <this-repo-url> my-app && cd my-app

# 2. Copy template, edit
cp image.env.example image.env
$EDITOR image.env
#   UPSTREAM_REF   docker.io/library/nginx:1.25.3-alpine  (one full URL;
#                  build.sh splits it, Renovate auto-bumps the tag)
#   REGISTRY_KIND  harbor (default) | artifactory_jcr | artifactory_pro
#   HARBOR_*  OR  ARTIFACTORY_*  per the chosen backend

# 3. (Optional) bespoke work in the Dockerfile's FORK EDITS region

# 4. Sanity check
./scripts/build.sh --dry-run

# 5. Build + push
./scripts/build.sh --push
```

Every knob is documented inline in `image.env.example`.

## Required CI variables — secrets only

`image.env` is the single source of truth for everything except
**secrets**. Hostnames, project paths, layout templates, sourcetypes
all live in `image.env` (committed). Only the items below need to be
masked CI variables.

Pick the row matching your `REGISTRY_KIND` — `HARBOR_*` and
`ARTIFACTORY_*` are mutually exclusive (the unselected backend
ignores its namespace entirely).

| Variable | When required |
|---|---|
| `HARBOR_PASSWORD` | `REGISTRY_KIND=harbor` |
| `ARTIFACTORY_TOKEN` *or* `ARTIFACTORY_PASSWORD` | `REGISTRY_KIND=artifactory_jcr` or `artifactory_pro` |
| `XRAY_ARTIFACTORY_TOKEN` | scan-side Artifactory differs from push-side |
| `UPSTREAM_REGISTRY_PASSWORD` (+ `UPSTREAM_REGISTRY_USER`) | base-image pull needs auth for a NON-Artifactory upstream (Docker Hub / ghcr / quay account, or a foreign private mirror). Accepts a token. **Not needed when the upstream is your own Artifactory mirror** — `ARTIFACTORY_*` creds are reused automatically for same-domain hosts. Unset = anonymous pull |
| `SPLUNK_HEC_TOKEN` | shipping events to Splunk |
| `DEPENDENCY_TRACK_API_KEY` | shipping SBOMs to Dependency-Track |
| `SBOM_WEBHOOK_AUTH_HEADER` | generic SBOM webhook needs auth |
| `COSIGN_KEY` (file-type) | restoring the dormant cosign-sign job |

Plus 3 CI-runtime images that YAML reads at pipeline-load time
(can't come from `image.env`): `ALPINE_IMAGE`, `DOCKER_CLI_IMAGE`,
`DOCKER_DIND_IMAGE`. Defaults work in a public-internet runner.

**Bare-minimum to push via Artifactory**: export `ARTIFACTORY_USER`
and `ARTIFACTORY_TOKEN`, set everything else in `image.env`, then
`./scripts/build.sh --push`. The backend handles its own docker login
to the push target. Pulling the *base* image is separate: when the
upstream is your own Artifactory mirror (same domain as
`ARTIFACTORY_URL`), the `ARTIFACTORY_*` creds are reused automatically —
nothing extra to set. For a non-Artifactory upstream that needs auth
(Docker Hub / ghcr / quay account, foreign mirror) set
`UPSTREAM_REGISTRY_USER` + `UPSTREAM_REGISTRY_PASSWORD`; those win for
any host. Public / anonymous upstreams need neither. Artifactory creds
are never sent to a public registry.

## Running the scripts manually (handover-friendly)

Every script is self-contained — run them **one after another, no manual
`source` step**:

```bash
bash scripts/build.sh --push          # writes build.env
bash scripts/scan/syft-sbom.sh        # self-sources build.env → scans the image just built
bash scripts/scan/grype-vuln.sh
bash scripts/ingest/sbom-post.sh      # self-sources build.env → ships with the right scanned_image
```

The scan + ingest scripts **self-source `./build.env`**, so they always
target the **latest** build (a second `--push` is scanned at its new
digest — no stale-digest failures). You do **not** need
`set -a; . ./build.env; set +a`.

**Overriding the scan target** — the only manual step. `IMAGE_REF` /
`IMAGE_DIGEST` are *build outputs* owned by `build.env`; exporting them is
ignored (build.env wins). To point a scan elsewhere, use the override
knobs, which outrank build.env:

```bash
bash scripts/scan/xray-vuln.sh registry/img:tag    # positional arg — always wins
export XRAY_SCAN_REF=registry/img:tag              # (or SBOM_SCAN_REF / TRIVY_SCAN_REF)
```

Resolution order: `arg > <tool>_SCAN_REF > IMAGE_DIGEST > IMAGE_REF > UPSTREAM_REF`.

**Reproducibility / no-git:** the image digest is reproducible **per git
commit** (`SOURCE_DATE_EPOCH` = commit time), so re-pushing the same commit
is an idempotent overwrite. Without git (e.g. files copied to a bare dir)
the build still works but uses a wall-clock timestamp — not reproducible —
and a moving tag (`APPEND_GIT_SHORT=false`) across commits can still
re-push to a new digest; the self-sourcing scan stays correct either way
because it reads the current `build.env`.

## Pipeline flow

```
prescan        →   build    →   postscan                →   ingest
─────────────      ─────        ──────────────────────      ──────────
xray-vuln-…        build →      syft-sbom-postscan ─┐
xray-sbom-…        build.env    xray-sbom-postscan  │
syft-sbom-…                     xray-vuln-postscan  │
                                grype-vuln          │
                                grype-db-sync       ↓
(prescan = scan UPSTREAM_REF)   (postscan = scan      sbom-ingest →
                                 IMAGE_DIGEST)         configured sinks
```

Every scan job is single-purpose and parallel within its stage.
Swap script names to swap producers — downstream stages keep working
because they consume canonical `${SBOM_FILE}` / `${VULN_SCAN_FILE}`
from `build.env`.

**Branch behaviour:** feature/MR branches build (no push) and scan
(postscan falls back to `UPSTREAM_REF` since nothing was pushed), so the
pipeline completes green for the merge gate — but the **`ingest` stage
runs only on the default branch + tags**. Only `main` pushes a real
artifact, so only `main` ships results to the sinks; feature branches
don't post duplicate upstream events to Splunk/Artifactory.

`cosign-sign` is dormant (commented blocks in both CI files). Restore
by uncommenting the job AND the `- sign` stage entry, then setting
`COSIGN_KEY` (file-type CI variable, ideally Vault transit / KMS).

`trivy-{vuln,sbom}-{pre,post}scan` are dormant scaffolds for when
Trivy is re-permitted. Pinned to v0.69.3 (last safe pre-compromise
binary; refuses v0.69.4–v0.69.6 even if the mirror serves them).

### Branch behaviour

Only the default branch (`main`/`master`) and tag builds **push** to
the registry. Feature-branch / MR pipelines build + scan as validation
but skip the push — short-lived branches don't pollute the registry.

### Promoting to production

Promotion is **not** in the CI pipeline by design. After dev
validation, a human promotes via Artifactory's native copy:

```bash
# Option A — UI: Browse → <repo>/<image>/<dev-tag> → Copy.
# Option B — CLI (scriptable, same digest):
crane auth login <prod-registry> -u <user> -p <password>
crane copy \
  <dev-registry>/<project>/<image>@sha256:<digest-from-build.env> \
  <prod-registry>/<project>/<image>:<tag>
```

The dev pipeline keeps `build.env` as a 1-month artifact —
`IMAGE_DIGEST` is what to copy. Cosign attestations transfer to the
prod tag because the digest is preserved.

## Editing the Dockerfile

There is **no extension surface**, **no DISTRO selector**, **no
remediate stage**. Bespoke per-image work goes between the cert
stage and the final `USER ${ORIGINAL_USER}` flip:

```dockerfile
# ═══════════════════════════════════════════════════════════════════
# ▼▼▼  FORK EDITS GO HERE  ▼▼▼
# ═══════════════════════════════════════════════════════════════════
RUN apk update && apk upgrade --no-cache
# RUN apt-get update && apt-get -y --only-upgrade upgrade && rm -rf /var/lib/apt/lists/*
# RUN microdnf -y update && microdnf clean all

RUN apk add --no-cache curl jq
COPY config/nginx.conf /etc/nginx/nginx.conf
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost/ || exit 1
# ═══════════════════════════════════════════════════════════════════
# ▲▲▲  END FORK EDITS  ▲▲▲
# ═══════════════════════════════════════════════════════════════════
```

The region inherits `USER root` from the certs stage; the
`ORIGINAL_USER` flip happens AFTER your edits. For distroless /
scratch / busybox bases where OS upgrades don't apply, leave it empty.

## Tagging convention

```
<registry>/<project>/<image>:<UPSTREAM_TAG>-<gitShort>
# e.g. harbor.example.com/apps/platform/nginx:1.25.3-alpine-a1b2c3d
```

- `UPSTREAM_TAG` — the upstream release this started from (the `:tag`
  in `UPSTREAM_REF`). Bumped by Renovate, which reads it from the
  `UPSTREAM_REF` URL in `image.env`.
- `gitShort` — 7-char commit SHA. Every commit gets its own tag, so
  cert rotation, label tweaks etc. each produce a traceable artifact
  even when the upstream tag is unchanged.

The OCI `org.opencontainers.image.version` label is also set to
`<UPSTREAM_TAG>-<gitShort>` so tools can tell at a glance that this
is a rebuild, not the upstream.

**Reproducible digests.** The build clock is anchored to the git
commit time via `SOURCE_DATE_EPOCH` (BuildKit clamps layer + config
timestamps), so rebuilding the *same commit* produces the *same*
image digest. A re-push of the same tag is therefore an idempotent
overwrite to the identical digest — it never orphans the previous
digest, so a postscan job that scans `IMAGE_DIGEST` from `build.env`
keeps resolving. Set `SOURCE_DATE_EPOCH` explicitly to override.

## OCI labels

`build.sh` adds dynamic labels via `docker buildx build --label`.
Upstream labels (e.g. `maintainer`) flow through untouched.

| Label | Source |
|---|---|
| `org.opencontainers.image.version` / `.ref.name` | `${UPSTREAM_TAG}-${gitShort}` |
| `org.opencontainers.image.revision` | `git rev-parse HEAD` |
| `org.opencontainers.image.created` | git commit time of `HEAD` via `SOURCE_DATE_EPOCH` (reproducible; override with `SOURCE_DATE_EPOCH`, falls back to wall-clock only without git) |
| `org.opencontainers.image.base.name` | `UPSTREAM_REF` (the full upstream URL) |
| `org.opencontainers.image.base.digest` | `crane digest` of the upstream ref |
| `org.opencontainers.image.source` / `.url` | `CI_PROJECT_URL` / git remote |
| `org.opencontainers.image.vendor` | `VENDOR` |
| `org.opencontainers.image.authors` | `AUTHORS` (default `Platform Engineering`) |
| `promoted.from` / `promoted.tag` | base.name / version |

## Closed-network / air-gap

Every runtime download is variable-driven. Override these to point
at internal Artifactory / Nexus mirrors:

| Variable | Default |
|---|---|
| `DOCKER_CLI_IMAGE` / `DOCKER_DIND_IMAGE` / `ALPINE_IMAGE` | Docker Hub library |
| `UPSTREAM_REF` (point the host at your mirror) | `docker.io/library/nginx:<tag>` |
| `CRANE_URL` | github.com/google/go-containerregistry release |
| `SYFT_INSTALLER_URL` / `SYFT_VERSION` | raw.githubusercontent.com/anchore/syft |
| `GRYPE_INSTALLER_URL` / `GRYPE_VERSION` | raw.githubusercontent.com/anchore/grype |
| `TRIVY_INSTALLER_URL` / `TRIVY_BINARY_URL` / `TRIVY_VERSION` | aquasec install.sh / pinned to v0.69.3 |
| `JF_BINARY_URL` / `JF_DEB_URL` / `JF_RPM_URL` | none — set ONE of these |
| `CERT_BUILDER_IMAGE` | `docker.io/library/alpine:3.20` |

For Grype's CVE database, mirror it once via
`./scripts/sync/mirror-grype-db.sh` (set `ARTIFACTORY_GRYPE_DB_REPO`
first) and the `grype-vuln` job will pull from your mirror automatically.

## Repository structure

```
container-build-template/
├── image.env                  # ★ Per-fork live config (REQUIRED, committed). EDIT
├── image.env.example          # Template reference — copy to image.env. NEVER sourced
├── Dockerfile.example         # Template — copy to Dockerfile. Edit only FORK EDITS region
├── inject-certs.sh            # Vendored verbatim into per-image repos
├── install-ca-certificates.sh # Vendored verbatim into per-image repos
├── renovate.json              # Tracks UPSTREAM_REF via custom manager
├── certs/                     # Gitignored *.crt; populated at build time
├── scripts/                   # Template logic — DO NOT EDIT per-fork
│   ├── build.sh               # Orchestrator: tags + OCI labels + buildx, dispatches push backend
│   ├── lib/
│   │   ├── load-image-env.sh  # image.env loader + bamboo_* importer + _dbg
│   │   ├── artifact-names.sh  # Canonical SBOM_FILE / VULN_SCAN_FILE contract
│   │   ├── install-jf.sh      # Sudoless jf installer (binary | .deb | .rpm)
│   │   ├── docker-login.sh    # Multi-registry login for scan jobs
│   │   ├── splunk-hec.sh      # Generic Splunk HEC envelope poster
│   │   ├── bamboo-import.sh   # Bamboo plan-var auto-importer (deletable)
│   │   └── build-info-merge.py  # Free-tier build-info merger (Pro skips it)
│   ├── push-backends/         # ★ Pick one via REGISTRY_KIND
│   │   ├── harbor.sh                  # REGISTRY_KIND="harbor"
│   │   ├── artifactory_common.sh      # shared by both artifactory tiers
│   │   ├── artifactory_jcr.sh         # REGISTRY_KIND="artifactory_jcr" — Free
│   │   └── artifactory_pro.sh         # REGISTRY_KIND="artifactory_pro" — Pro
│   ├── scan/                  # ★ Pick the producer per stage
│   │   ├── syft-sbom.sh   │   xray-sbom.sh   │   trivy-sbom.sh   (dormant)
│   │   └── grype-vuln.sh  │   xray-vuln.sh   │   trivy-vuln.sh   (dormant)
│   ├── ingest/sbom-post.sh    # 5 SBOM sinks
│   └── sync/mirror-grype-db.sh # Mirror Anchore Grype DB to Artifactory
├── .gitlab-ci.yml             # GitLab pipeline — prescan → build → postscan → ingest
├── bamboo-specs/bamboo.yml   # Bamboo plan spec (1:1 parity with GitLab)
├── .gitignore  └  LICENSE  └  README.md
```

## Local build

```bash
# 1. First time
cp image.env.example image.env  &&  $EDITOR image.env

# 2. Dry-run (no docker pull, no build)
./scripts/build.sh --dry-run

# 3. Build locally
./scripts/build.sh

# 4. Build + push (creds via env or pre-existing daemon login)
#    Harbor backend:
export HARBOR_PASSWORD='...'
./scripts/build.sh --push
#    Artifactory backend (image.env: REGISTRY_KIND="artifactory_jcr" or "artifactory_pro"):
export ARTIFACTORY_USER='svc-deploy' ARTIFACTORY_TOKEN='...'
./scripts/build.sh --push

# Verbose:
BUILD_DEBUG=true ./scripts/build.sh --dry-run
```

## License

MIT — see `LICENSE`.
