# CI/CD and Release Process

## GitHub Actions workflows

Three workflows live in `.github/workflows/`: `ci.yml`, `release.yml` and `pages.yml`.

### `ci.yml` — build, lint, test, fuzz-target build, cross-repo E2E

Triggers: push and pull request to `main` (and the legacy `initial_commit` branch),
a nightly `schedule` (`cron: "0 4 * * *"`, 04:00 UTC), and manual `workflow_dispatch`.

| Job | What it runs | When |
|-----|--------------|------|
| **Check** | `cargo check --workspace`, then `cargo check --workspace --all-features --all-targets` (every cargo feature of every crate must compile) | every push/PR |
| **Format** | `cargo fmt --all -- --check` | every push/PR |
| **Clippy** | `cargo clippy --workspace`, plus `-p nextgcore-easdfd --features dns-udp --all-targets` | every push/PR (errors gate; warnings are shown) |
| **Test** | `cargo test --workspace`, plus `cargo test -p nextgcore-easdfd --features dns-udp`. No retry: a red run is a real failure. The job adds swap and disables test debuginfo because the generated RRC codec crates need a lot of rustc memory | every push/PR |
| **Fuzz targets build** | `src/fuzz` is its own workspace: `cargo fmt -- --check` and `cargo clippy --locked --bins -- -D warnings` there | every push/PR |
| **Release image list** | `docker/check-release-images.sh`: every daemon, Dockerfile and deployed image is in the Docker Hub publish list, `docker/release-images.json` (#420) | every push/PR |
| **Docker Build** | checks out the sibling `nextgsim`, records the (nextgcore, nextgsim) commit pair, builds `Dockerfile.builder` → binaries → `Dockerfile.core` + per-NF `Dockerfile.nf` images, and fails if any expected image is missing | nightly + dispatch |
| **Docker E2E** | brings up the 5GC (mongodb, nrf, ausf/udm/udr/pcf/nssf/bsf, amf/smf/upf), registers a real nextgsim UE over N2, asserts the Namf event notifications, drives a CM-IDLE → Service Request cycle and a gNB-initiated UE Context Release, then runs the **0.2.0 UE-flow gate** (`docker/rust/ue-flow-check.sh`): downlink paging of an idle UE, uplink from CM-IDLE, a page after a Service Request, UE-initiated de-registration + re-registration, and UDM `REREGISTRATION_REQUIRED` re-registration, each ending in a 0%-loss ping. A second stage brings up the OAuth2 overlay and asserts authenticated token exchange | nightly + dispatch |
| **Docker E2E (EPC)** | brings up `docker-compose-epc.yml` (hss, pcrf, sgwc, sgwu, pgwc, pgwu, mme), waits for the Sxa and Sxb PFCP associations, then attaches a real LTE UE through nextgsim's eNB (`docker/rust/epc-attach-check.sh`) and pings through the default bearer with 0% loss. Dedicated bearers, handover, idle mode/paging and IPv6 PDN are not asserted | nightly + dispatch |
| **Record the validated commit pair** | runs only if Docker Build and both E2E jobs passed; uploads `validated-pair.json` naming the nextgcore and nextgsim commits that passed together | nightly + dispatch |

`Test`/`Clippy` depend on `Check`; the Docker E2E jobs depend on `Docker Build`.

Tests that touch process-global NF state (a `<nf>_context_init` or `std::env::set_var`) must
serialize on the lock declared beside that global, or they race under the default parallelism.

The local one-command matched-sim E2E, `docker/rust/e2e.sh`, is documented in
[`docker/rust/CI.md`](../docker/rust/CI.md).

### `release.yml` — paired release

nextgcore and nextgsim are one system under test, so a release is the **promotion of a commit
pair that passed the nightly E2E together**, not "tag main". `release.yml` is
`workflow_dispatch` only, with inputs:

| Input | Meaning |
|-------|---------|
| `version` | the version to release this repo as (e.g. `0.2.0`) |
| `validated_run_id` | the CI run whose `validated-pair.json` authorises the release (a green nightly) |
| `paired_version` | the nextgsim version released alongside |
| `dry_run` | default `true`: validate and print the notes without writing anything |

The workflow validates the manifest, refuses to re-release an existing tag, generates release
notes from `git log <previous-tag>..<validated sha>`, bumps `[workspace.package] version` in
`src/Cargo.toml`, commits, tags the bump commit, and creates the GitHub release. nextgsim has a
sibling workflow that tags itself from the same manifest.

After a non-dry-run release, and on any pushed version tag, the `publish-*` jobs push the
release's images to Docker Hub; see [Docker Hub images](#docker-hub-images).

### Docker Hub images

`release.yml` publishes every image in `docker/release-images.json` to Docker Hub (#420).

**Trigger: a version tag only.** Publishing runs for:
- a pushed tag `X.Y.Z` or `X.Y.Z-<pre>`;
- the tag a dispatched `release.yml` run with `dry_run=false` has just created. That tag is
  pushed with `GITHUB_TOKEN`, which starts no workflow, so the same run publishes it.

Nothing is pushed from a PR, a branch, the nightly or a dry run. The tagged commit must also be on
`main` (`publish-gate` checks its ancestry and fails otherwise), so only reviewed code is
published. Recommended: a tag ruleset (Settings, Rules, Rulesets) that restricts who may create
or move `[0-9]*` tags, since any writer can otherwise push one.

**Setup.** Repository settings, Secrets and variables, Actions:

| Name | Kind | Value |
|------|------|-------|
| `DOCKERHUB_USERNAME` | secret | the Docker Hub account that pushes |
| `DOCKERHUB_TOKEN` | secret | a Docker Hub access token with Read & Write scope, not the password |
| `DOCKERHUB_NAMESPACE` | variable (optional) | the Docker Hub organisation. Without it, images go under `DOCKERHUB_USERNAME` |

Credentials live only in these secrets, never in a file. If either secret is missing, the
`publish-gate` job prints a "Docker Hub publish skipped" notice and the publish jobs are
skipped. The release itself still succeeds. To publish a release made before the secrets
existed, add them and re-run that run's `Docker Hub publish gate` job. GitHub re-runs its
dependent jobs with it.

**What is pushed.** Each image is `<namespace>/<image>:<version>`, built from the tagged commit.
After every versioned push has succeeded, `<namespace>/<image>:latest` is moved to it. A
pre-release (`X.Y.Z-<pre>`) never moves `latest`. The image names replace the local-only
`nextgcore-rust/<nf>` names that compose and Helm use:

| Image | Built from |
|-------|------------|
| `nextgcore-core` | `docker/rust/Dockerfile.core`, the base every NF image is built FROM |
| `nextgcore-<nf>`, one per daemon under `src/bins/` (`amf`, `ausf`, `bsf`, `dccf`, `easdf`, `ees`, `hss`, `lmf`, `mbsmf`, `mme`, `nef`, `nrf`, `nsacf`, `nssf`, `nwdaf`, `pcf`, `pcrf`, `pin`, `scp`, `sepp`, `sgwc`, `sgwu`, `smf`, `tsctsf`, `ucmf`, `udm`, `udr`, `upf`) | `docker/rust/Dockerfile.nf` with `NF_NAME=nextgcore-<nf>d` (`nextgcore-tsctsf` for TSCTSF). Binaries come from `Dockerfile.builder`, as in `ci.yml`'s Docker Build |
| `nextgcore-webui` | `docker/webui/Dockerfile` (the Node.js WebUI) |

**First publish.** A pushed image name is public and cannot be cleanly withdrawn, so prove the
setup first. Point `DOCKERHUB_NAMESPACE` at a private namespace and push a pre-release tag such
as `0.2.0-rc.1`. Check the images, then set the variable to the public organisation.

No published image carries a credential:
- The NF images hold only their binary, plus the runtime directories from `Dockerfile.core`.
  Configs, the home-network keys under `docker/rust/configs/` and TLS material are mounted at
  run time.
- The WebUI image refuses to start without a `JWT_SECRET_KEY` of at least 32 characters, and has
  no default account (`create-admin.js`).

The base images (`debian:bookworm-slim`, `rust:1.95.0-bookworm`, `node:19`) and every action in
`release.yml` are pinned by digest or commit SHA, with the tag in a comment. To bump a base
image, run `docker buildx imagetools inspect <tag>` and replace the digest.

nextgsim publishes `nextgsim-nr-gnb`, `nextgsim-nr-ue`, `nextgsim-lte-enb` and
`nextgsim-lte-ue` from its own `release.yml`, with the same secrets in that repository.

**The list cannot silently go stale.** `ci.yml`'s `Release image list` job runs
`docker/check-release-images.sh` on every push and PR. It fails when any of these is in neither
the manifest's `images` nor its `excluded` list (which gives a reason for each entry):
- a crate under `src/bins/`;
- a tracked `Dockerfile*`;
- a `nextgcore-rust/<nf>` image referenced in `docker/`, `deploy/` or `k8s/`.

A new NF therefore needs a manifest line in the PR that adds it.

### `pages.yml` — documentation site

Deploys `docs/` to GitHub Pages (runs `docs/scripts/update-api-docs.sh`, uploads `docs/`).
Triggers: `release: [published]` and `workflow_dispatch`. It does not redeploy on every
`docs/**` push. A release created by `release.yml` with the default `GITHUB_TOKEN` does not
start other workflows (a GitHub Actions rule), so after a release run `pages.yml` by hand
from the Actions tab.

The mdBook sources live in `docs-book/`; `mdbook build docs-book` writes the book into
`docs/book/`, which is committed and served under `/book/`.

## Local pre-push gate (mirror of CI)

Run from `src/` before pushing:

```bash
cargo fmt --all -- --check                                  # Format
cargo check --workspace --all-features --all-targets        # Check
cargo clippy --workspace                                    # Clippy
cargo test --workspace                                      # Test
(cd fuzz && cargo clippy --locked --bins -- -D warnings)    # Fuzz targets build
```

Optionally the data-plane E2E: `cd docker/rust && ./e2e.sh`.

## Cutting a release

1. Pick a green nightly `ci.yml` run on `main`; note its run id. Its `validated-pair.json`
   artifact names the nextgcore and nextgsim commits it validated.
2. Move the `## [Unreleased]` section of `CHANGELOG.md` under a dated `## [X.Y.Z]` heading and
   merge that to `main` (the release notes the workflow publishes come from `git log`, not from
   the CHANGELOG).
3. Run `release.yml` with `version`, `validated_run_id`, `paired_version` and `dry_run=true`;
   read the notes in the job summary. Re-run with `dry_run=false` to tag and publish.
   With the Docker Hub secrets set, the same run then pushes the images
   ([Docker Hub images](#docker-hub-images)).
4. Do the same in nextgsim with the same run id.
5. Run `pages.yml` by hand to publish the docs site for the release.

> **Honesty in release notes:** keep the validation caveat: spec text, golden vectors, strict
> peers and the matched-sim E2E, **not** TTCN-certified or third-party-interop tested. 6G/Rel-20
> items are research prototypes (no frozen stage-3 spec).
