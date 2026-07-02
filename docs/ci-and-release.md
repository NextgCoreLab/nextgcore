# CI/CD and Release Process

## GitHub Actions workflows

Two workflows live in `.github/workflows/`.

### `ci.yml` — build, lint, test, container E2E

| Job | Command | Gates on |
|-----|---------|----------|
| **Check** | `cd src && cargo check --workspace` | compile errors |
| **Format** | `cd src && cargo fmt --all -- --check` | rustfmt drift (fails on any diff) |
| **Clippy** | `cd src && cargo clippy --workspace` | **errors only** — style warnings are shown but do not fail CI (see the note in the job) |
| **Test** | `cd src && cargo test --workspace` | any failing test |
| **Docker Build** | builds `Dockerfile.builder` → extracts binaries → builds `Dockerfile.core` + per-NF `Dockerfile.nf` | image build failures (needs the sibling `nextgsim` checkout) |
| **Docker E2E** | brings up the 5GC stack (mongodb, nrf, ausf/udm/udr/pcf/nssf/bsf, amf/smf/upf) and health-checks NRF/AMF | startup / health failures |
| **Docker E2E (EPC)** | brings up the 4G EPC stack from `docker-compose-epc.yml` and inspects hss/pcrf/sgwc/sgwu/mme | startup / health failures |

`Test`/`Clippy` depend on `Check`; the two Docker E2E jobs depend on `Docker Build`.

**The `Test` job runs `cargo test --workspace` at the runner's default parallelism.** Tests
that touch process-global NF state (a `<nf>_context_init` or `std::env::set_var`) must serialize
on their crate's `test_support::CONTEXT_GUARD`, or they race and flake here — see
`docker/rust/CI.md` and the per-crate test guards.

The richer matched-sim data-plane E2E (registration + PDU session + GTP-U ping) is **not** run by
`ci.yml`; it is the one-command `docker/rust/e2e.sh` (documented in `docker/rust/CI.md`).

### `pages.yml` — documentation site

Deploys `docs/` to GitHub Pages (runs `docs/scripts/update-api-docs.sh`, uploads `docs/`).
Triggered **only when a GitHub release is published** (`on: release: [published]`) so the site
tracks the last release, plus `workflow_dispatch` for a manual re-deploy — it does **not** redeploy
on every `docs/**` push.

## Branch triggers

Both workflows run on the default release branch **`main`** and on the development branch
**`initial_commit`**:

```yaml
on:
  push:    { branches: [initial_commit, main] }
  pull_request: { branches: [initial_commit, main] }
```

(`ci.yml` on push + PR to either branch. `pages.yml` is **not** branch-triggered — it deploys the
docs site when a release is published; see below.)

## Local pre-push gate (mirror of CI)

Run from `src/` in both repos before pushing:

```bash
cargo fmt --all -- --check      # Format
cargo check --workspace         # Check
cargo clippy --workspace        # Clippy (errors only)
cargo test --workspace          # Test
```

Optionally the full data-plane E2E: `cd docker/rust && ./e2e.sh`.

## Cutting a release

1. Ensure `main` (or the release branch) is green in CI and the matched-sim E2E passes (`docker/rust/e2e.sh` → 84/84).
2. Bump the workspace version in `src/Cargo.toml` (`[workspace.package] version`) if used, and per-crate versions as needed. Current: `0.1.0`.
3. Move the `## [Unreleased]` section of `CHANGELOG.md` under a dated `## [X.Y.Z]` heading; add a fresh empty `Unreleased`.
4. Commit (`Signed-off-by: Murat Parlakisik <parlakisik@gmail.com>`), tag `vX.Y.Z`, push the tag.
5. Create the GitHub release from the tag, pasting the CHANGELOG section as the release notes:
   `gh release create vX.Y.Z --repo NextgCoreLab/nextgcore --title "NextGCore vX.Y.Z" --notes-file <(...)`.
   Publishing the release fires `pages.yml`, which deploys the docs site for this version.

> **Honesty in release notes:** keep the validation caveat — spec-text + golden-vector + strict-peer
> + matched-sim E2E, **not** TTCN-certified or third-party-interop tested. 6G/Rel-20 items are
> research prototypes (no frozen stage-3 spec).
