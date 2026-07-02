# CI-ability: running the matched-sim Docker E2E as a CI gate

Wave-6 H10 deliverable. This documents the *shape* of a CI job for the
matched-sim E2E (our nextgsim gNB/UE against our nextgcore 5GC — **no
Open5GS anywhere**). It is wire-ready; actually wiring a CI system is out of
scope here (no repo CI-infrastructure decision is made by this file).

## The one command

```bash
./docker/rust/e2e.sh                      # preflight -> build -> E2E, exit 0/1/2
./docker/rust/e2e.sh --quick              # reuse prebuilt binaries (fast re-run)
./docker/rust/e2e.sh --overlay oauth2     # OAuth2 enforcement overlay run
./docker/rust/e2e.sh --overlay kernel-sctp# native kernel-SCTP N2 run
./docker/rust/e2e.sh --overlay features   # baseline + Rel-17/18 feature harness
```

Exit codes (CI gates on them directly):

| code | meaning |
|------|---------|
| 0 | every assertion passed (score is N/N — stale patterns were purged 2026-07-01) |
| 1 | >= 1 test assertion failed |
| 2 | infrastructure failure: preflight refusal (low disk), build, startup timeout |

## Minimum runner shape

- **Disk: >= 60 GB free** on the filesystem holding the Docker data.
  A cold build needs ~20 GB of build cache + ~10 GB images/volumes; the
  preflight *refuses to build* below 25 GB free (hazard #269: Docker
  Desktop wiped its whole image store when a build ran under disk
  pressure, 2026-06-12). 60 GB gives headroom for two cached generations.
- **Docker Engine >= 24.0** with BuildKit / Compose v2.20+ (`docker compose`,
  not `docker-compose`). Kernel-SCTP overlay additionally needs a Linux
  kernel with SCTP (`CONFIG_IP_SCTP`) available inside the Docker VM
  (Docker Desktop's VM and stock Linux runners have it).
- Linux or macOS host. On macOS note the APFS df gotcha: local snapshots
  pin space `df` reports as used; the preflight error text explains the
  `tmutil` remedy.
- ~8 GB RAM for the 13-container baseline stack.
- No network egress needed beyond pulling base images
  (`rust`, `debian:trixie-slim`, `mongo`, `alpine:3`).

## What the job does

1. `preflight.sh` — refuses (exit 2) if host **or** in-VM free disk < 25 GB;
   runs `docker builder prune --force --keep-storage=20GB`; prints
   `docker system df`. Skippable with `--no-preflight` (don't, in CI).
2. `build.sh` — compiles both workspaces inside a Rust builder container,
   assembles per-NF images.
3. `e2e-test.sh --no-build --keep [--overlay X]` — starts the stack, waits
   for health, asserts the full registration + PDU-session + data-plane
   chain from container logs, pings through the GTP-U tunnel.
4. On failure `e2e.sh` captures artifacts **before** teardown.

## Artifact capture (on failure)

`e2e.sh` writes to `docker/rust/artifacts/e2e-<timestamp>/`:

- `docker logs` of every `nextgcore-*` / `nextgsim-*` container (one file per NF)
- `docker-ps.txt`, `docker-system-df.txt`

Upload that directory as the CI failure artifact. Optional pcap: the slim NF
images carry no tcpdump; attach a capture sidecar to a running stack when
debugging wire issues, e.g.

```bash
docker run --rm --net container:nextgcore-amf nicolaka/netshoot \
    tcpdump -w /tmp/n2.pcap sctp or port 7777
```

(pcap capture is intentionally not part of the default CI run — it needs an
extra image and produces large artifacts.)

## Assertion hygiene rules (keep the signal crisp)

- **Source-anchored patterns**: every `assert_log_contains` pattern must match
  a log line verifiable in the current source of the NF that owns the
  container. The 2026-07-01 refresh purged the 19 stale patterns (identity-
  procedure asserts that can never fire under SUCI registration, and drifted
  W5.1 MmOrchestrator strings) — do not re-introduce asserts you have not
  traced to an emitting `log::info!`/`info!` call on the success path.
- **Capture-then-grep, never `docker logs | grep -q`**: with `pipefail`,
  `grep -q` closing the pipe SIGPIPE-kills `docker logs` and turns a real
  match into a false negative. Both e2e-test.sh and feature-e2e-test.sh
  capture to a temp file and grep the file.
- A red run must mean a real regression; a green run must mean N/N.
