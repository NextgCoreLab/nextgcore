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
4. Do the same in nextgsim with the same run id.
5. Run `pages.yml` by hand to publish the docs site for the release.

> **Honesty in release notes:** keep the validation caveat: spec text, golden vectors, strict
> peers and the matched-sim E2E, **not** TTCN-certified or third-party-interop tested. 6G/Rel-20
> items are research prototypes (no frozen stage-3 spec).
