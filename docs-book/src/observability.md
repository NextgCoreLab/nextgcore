# Observability & Troubleshooting

NextGCore ships a Docker-based observability stack (Prometheus, Grafana, Jaeger) alongside its 24 network-function daemons, plus an in-tree metrics/tracing library (`src/libs/nextgcore-metrics/`). This chapter documents what actually works today — which endpoints exist, which are scaffolding, how logging is really configured per NF — and gives a code-grounded troubleshooting table and the one-command E2E recipe.

> **Honesty note:** NextGCore behavior is validated by this project's own unit tests and matched-simulator docker E2E (84/84 green as of 2026-07-02), not by third-party conformance certification. The observability stack described here is exactly what ships in this repo — it is **not** a certified telco OAM system. In particular, the Prometheus `/metrics` HTTP endpoint and the OpenTelemetry OTLP exporters in `nextgcore-metrics` are **structural stubs**: the compose stack starts Prometheus, Grafana, and Jaeger, but no NF currently serves scrapeable metrics or exports spans to them. Each such gap is called out explicitly below.

## Metrics

### What the library provides — and what it does not

`src/libs/nextgcore-metrics/src/server.rs` defines a `MetricsServer` documented to serve two HTTP endpoints — `/` (health check, returns "OK") and `/metrics` (Prometheus text exposition) — and `src/libs/nextgcore-metrics/src/lib.rs` defines `DEFAULT_PROMETHEUS_HTTP_PORT: u16 = 9090`. However, `MetricsServer::start()` does **not** bind a socket: it logs `metrics_server() [http://<addr>]:<port>`, flips its state to `Running`, and returns (the code comment reads "In a real implementation, this would start an HTTP server using hyper"). A repo-wide grep confirms no NF binary registers a `"/metrics"` HTTP route anywhere.

Consequently, **none of the 24 NF daemons serves Prometheus metrics over HTTP today**:

| NF daemon | Prometheus metrics served | Notes |
|---|---|---|
| `nextgcore-amfd` | none | Defines full metric families in `src/bins/nextgcore-amfd/src/metrics.rs` — which the file's own header attributes as a "Port of src/amf/metrics.c", the Open5GS AMF metrics module — with a `export_prometheus()` exposition method (see below), but no HTTP endpoint serves it, and no runtime code path increments the counters (call sites exist only in unit tests). The **only** NF binary that does *not* call `init_otel` at startup. |
| `nextgcore-ausfd` | none | Links `nextgcore-metrics`; calls `otel::init_otel` at startup (`src/app.rs`). |
| `nextgcore-bsfd` | none | Same; `init_otel` in `src/lib.rs`. |
| `nextgcore-dccfd` | none | Same; `init_otel` in `src/main.rs`. |
| `nextgcore-eesd` | none | Same. |
| `nextgcore-hssd` | none | Same. |
| `nextgcore-lmfd` | none | Same. |
| `nextgcore-mbsmfd` | none | Same. |
| `nextgcore-mmed` | none | Same. |
| `nextgcore-nrfd` | none | Same. |
| `nextgcore-nsacfd` | none | Same. |
| `nextgcore-nssfd` | none | Same. |
| `nextgcore-nwdafd` | none | Same. |
| `nextgcore-pcfd` | none | Same; `init_otel` in `src/app.rs`. |
| `nextgcore-pcrfd` | none | Same. |
| `nextgcore-pind` | none | Same. |
| `nextgcore-scpd` | none | Same. |
| `nextgcore-seppd` | none | Same. |
| `nextgcore-sgwcd` | none | Same. |
| `nextgcore-sgwud` | none | Same. |
| `nextgcore-smfd` | none | Same. |
| `nextgcore-udmd` | none | Same; `init_otel` in `src/app.rs`. |
| `nextgcore-udrd` | none | Same. |
| `nextgcore-upfd` | none | Same. |

All 24 NF binary crates depend on `nextgcore-metrics` in their `Cargo.toml`, but 23 of them use it solely for the `init_otel` call (see Tracing); the AMF is the one NF with real metric-family definitions.

### AMF metric families (`src/bins/nextgcore-amfd/src/metrics.rs`)

These are the metric names the AMF defines, mirroring Open5GS's `src/amf/metrics.c` (the only attribution the file itself gives — TS 28.552 is not cited anywhere in this repo). They are held in an in-process `AmfMetrics` registry with a Prometheus-format `export_prometheus()` method — ready to be wired to an HTTP endpoint, but not yet served or incremented at runtime:

| Metric | Type | Counts |
|---|---|---|
| `ran_ue` | gauge | RAN UEs |
| `amf_session` | gauge | AMF sessions |
| `gnb` | gauge | gNodeBs |
| `fivegs_amffunction_rm_reginitreq` / `_reginitsucc` | counter | Initial registration requests / successes |
| `fivegs_amffunction_rm_regmobreq` / `_regmobsucc` | counter | Mobility registration update requests / successes |
| `fivegs_amffunction_rm_regperiodreq` / `_regperiodsucc` | counter | Periodic registration update requests / successes |
| `fivegs_amffunction_rm_regemergreq` / `_regemergsucc` | counter | Emergency registration requests / successes |
| `fivegs_amffunction_mm_paging5greq` / `_paging5gsucc` | counter | 5G paging procedures initiated / succeeded |
| `fivegs_amffunction_amf_authreq` / `_authreject` | counter | Authentication requests sent / rejections sent |
| `fivegs_amffunction_mm_confupdate` / `_confupdatesucc` | counter | UE Configuration Update commands / completes |
| `fivegs_amffunction_rm_registeredsubnbr{plmn_id,snssai}` | gauge | Registered subscribers per slice |
| `fivegs_amffunction_rm_reginitfail` / `_regmobfail` / `_regperiodfail` / `_regemergfail` / `_amf_authfail` `{cause}` | counter | Failed registrations / authentication failures, labeled by cause |

The library's `NfMetrics` helper (`src/libs/nextgcore-metrics/src/otel.rs`) additionally defines a generic per-NF exposition (`nextgcore_<nf>_sbi_request_total`, `_sbi_error_total`, `_active_sessions`, `_uptime_seconds`, `_nrf_registered`) — also not served by any NF.

### The `metrics.server` YAML blocks are deploy-time decoration

Four docker config files — `docker/rust/configs/5gc/amf.yaml`, `pcf.yaml`, `smf.yaml`, `upf.yaml` — contain a `metrics.server` block with `port: 9090`. **None of these four NFs parses it:**

- **AMF**: `AmfSection` in `src/bins/nextgcore-amfd/src/lib.rs` deserializes only `amf_name`, `network_name`, `guami`, `tai`, `plmn_support`, `security`, `sbi`, `nas` — no `metrics` field (serde silently ignores unknown keys).
- **SMF**: `SmfYaml`/`SmfSection` in `src/bins/nextgcore-smfd/src/main.rs` deserializes only `smf.sbi`.
- **PCF**: `PcfSection` in `src/bins/nextgcore-pcfd/src/app.rs` deserializes only `pcf.sbi`.
- **UPF**: `src/bins/nextgcore-upfd/src/main.rs` reads the config file only to log its byte count ("Configuration file loaded (N bytes)") — no YAML deserialization at all; every UPF runtime knob is a CLI flag.

### The shipped scrape stack

`docker compose up -d` in `docker/rust/` starts the full observability trio unconditionally (no compose profile gating):

- **Prometheus** (`prom/prometheus:v2.51.0`, container `nextgcore-prometheus`, `172.23.0.200`, host port `9090`) — config `docker/rust/configs/observability/prometheus.yml`: 15s scrape interval, static targets for 10 NFs (NRF, AUSF, UDM, UDR, PCF, NSSF, BSF, AMF, SMF, UPF) at their fixed `172.23.0.x:9090` addresses, each labeled with `nf_type` and `instance_name`, plus self-scrape. Because no NF listens on 9090, **all 10 NF jobs read `up == 0`** in the current build.
- **Grafana** (`grafana/grafana:10.4.0`, `172.23.0.201`, host port `3000`, login `admin`/`nextgcore`) — provisioned datasources (`grafana-datasources.yml`: Prometheus at `http://172.23.0.200:9090`, Jaeger at `http://172.23.0.202:16686`) and dashboards from `configs/observability/dashboards/` with `overview.json` as the home dashboard.
- **Alert rules** (`configs/observability/alert-rules.yml`) — `NfInstanceDown` (`up == 0` for 1m) and `NfSlowResponse` are generic and will actually evaluate; the NF-specific rules reference metric names (`amf_registration_failure_total`, `amf_connected_ue_count`, `smf_pfcp_association_up`, `upf_packets_dropped_total`, `nrf_registered_nf_count`, `mongodb_up`, …) that **no code in this repo emits** — they are aspirational, written for a future exporter wiring.

## Tracing (OpenTelemetry)

**What exists.** `src/libs/nextgcore-metrics/src/otel.rs` provides `OtelConfig` (service name, OTLP endpoint — default `http://localhost:4317` — 10s export interval, traces/metrics/logs toggles), `OtelProvider`, W3C `traceparent` parse/generate helpers (`OtelSpanContext::from_traceparent`/`to_traceparent`), an `SbiSpan` wrapper with `nf.type`/`sbi.service`/`http.*` attributes, and a `JaegerConfig` (default endpoint `http://localhost:14268/api/traces`, sampling 1.0).

**Startup wiring.** 23 of the 24 NF daemons call `init_otel(OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(...))` at startup, taking the endpoint from the **`OTEL_EXPORTER_OTLP_ENDPOINT`** environment variable and defaulting to **`http://jaeger:4317`** when unset (which resolves to the compose `jaeger` service). The AMF is the exception — it never calls `init_otel`. The shared helper `nf_common_init` in `src/libs/nextgcore-app/src/init.rs` bundles the same logic (same env var, same default) but is currently not called by any NF binary.

**No-op behavior — the honest part.** `OtelProvider::init()` is structural: it prints `Initializing OpenTelemetry for service '<name>' (endpoint: <url>)` and per-signal init lines to stderr, but creates **no** actual OTLP exporters (the code comments read "In a real implementation, this would use the opentelemetry crate"). Initialization failure is deliberately non-fatal (`let _ = init_otel(...)` / `.ok()`). Net effect: whether or not a collector is reachable, **no spans, metrics, or logs are ever exported**. The Jaeger all-in-one container in the compose stack (UI on `16686`, OTLP gRPC `4317`, OTLP HTTP `4318`) will show no NextGCore traces.

**What IS real: wire-level trace propagation.** The SBI client (`src/libs/nextgcore-sbi/src/client.rs`, `prepare_request`) stamps every outbound SBI request with a W3C `traceparent` header — respecting a caller-supplied one, otherwise generating a new sampled root span with CSPRNG-random trace/span IDs — and echoes the inbound correlation ID as `x-request-id`. So cross-NF request correlation works today by grepping IDs across `docker logs`, even without a trace backend.

## Logging

All NFs log to **stdout/stderr** via `env_logger`. 22 of the 24 NF binaries enable millisecond timestamps (`format_timestamp_millis`); the two exceptions are **smfd** (`src/bins/nextgcore-smfd/src/main.rs:299`, plain `Builder::from_env(...).init()`) and **sgwud** (`src/bins/nextgcore-sgwud/src/main.rs:18`, `env_logger::init()`), which fall back to env_logger's default seconds-resolution timestamp format. In the docker deployment, logs are consumed with `docker logs <container>` / `docker compose logs -f amf gnb ue`. The compose file's `x-common` anchor (`docker/rust/docker-compose.yml`, line 15) sets `RUST_LOG: info` as the baseline, but four services override it with more verbose crate-level filters: `amf` (line 218: `info,nextgcore_amfd=debug`), `upf` (line 300), `gnb` (line 331), and `ue` (line 355). `RUST_BACKTRACE: 1` is uniform across all services (merged via `<<: *common-env`).

**CLI flags vary per NF** — check `--help` for the daemon you are running. Two verified patterns:

| Pattern | Flags | Verified in |
|---|---|---|
| Open5GS-style | `-e, --log-level` (default `info`), `-l, --log-file`, `-m, --no-color`; **nrfd additionally has `-k, --kill`** | `nextgcore-nrfd` (`src/bins/nextgcore-nrfd/src/main.rs:369-370` for `-k/--kill`), `nextgcore-nsacfd` (`src/bins/nextgcore-nsacfd/src/main.rs:136-152` — only `-c` config, `-l` log-file, `-e` log-level, `-m` no-color plus long-only flags; **no kill flag**) |
| AMF-style | `-l, --log-level` (default `info`), `--no-color`, `-d, --daemon` — **no** log-file flag | `nextgcore-amfd` (`src/bins/nextgcore-amfd/src/lib.rs`) |

`nextgcore-smfd` is a third case: it has no clap parser at all — it scans `std::env::args()` only for `-c <config>` and takes its log level purely from `RUST_LOG` (default `info`).

**`RUST_LOG` precedence is inconsistent by design stage.** Nine NFs honor `RUST_LOG`: the eight that build their logger with `env_logger::Builder::from_env` (with the CLI flag or `"info"` as fallback) — **smfd, nsacfd, eesd, dccfd, lmfd, mbsmfd, nwdafd, pind** (verified by grep across `src/bins/*/src/*.rs`) — plus **sgwud**, whose plain `env_logger::init()` (`src/bins/nextgcore-sgwud/src/main.rs:18`) also reads `RUST_LOG` via env_logger's default `Env`. The rest — including amfd (`lib.rs:780`, `Builder::new().filter_level(...)`), nrfd, udrd, udmd, upfd — set the filter solely from their `--log-level` flag and **ignore `RUST_LOG`**. So the compose-wide `RUST_LOG: info` is only effective for the first group.

**`--log-file` is accepted but not wired.** Most NFs — 19 binary crates in total (nrfd, upfd, udrd, udmd, nsacfd, ausfd, bsfd, dccfd, eesd, hssd, lmfd, mbsmfd, nssfd, pcfd, pcrfd, pind, scpd, seppd — verified by grepping `log_file` across `src/bins/*/src/*.rs`) — declare a `log_file` CLI arg, but in none of them is the parsed value ever consumed by the logging setup — e.g. nrfd's `init_logging()` never references `args.log_file`. Logs always go to stdout/stderr; rely on `docker logs` or shell redirection.

## Troubleshooting

Every row below is grounded in a specific file in this repo.

| Symptom | Likely cause | What to check / fix |
|---|---|---|
| Prometheus shows every NF target `DOWN` (`up == 0`), `NfInstanceDown` alerts fire for all 10 NF jobs | **Expected in the current build**: no NF binary serves `/metrics`; `MetricsServer::start()` is a stub that never binds port 9090 | `src/libs/nextgcore-metrics/src/server.rs`; scrape targets in `docker/rust/configs/observability/prometheus.yml` |
| Grafana/Jaeger show no NF traces despite "Initializing OpenTelemetry" in NF stderr | `OtelProvider::init()` creates no real OTLP exporter (structural stub); export never happens | `src/libs/nextgcore-metrics/src/otel.rs` (`init_traces`/`init_metrics`/`init_logs` bodies) |
| NF-specific alert rules never fire | Rules reference metric names (`amf_registration_failure_total`, `smf_pfcp_association_up`, …) that no code emits | `docker/rust/configs/observability/alert-rules.yml`; grep the names in `src/` — zero hits |
| NF starts with built-in defaults although you passed a config file | Lenient config loading: an unreadable or unparsable YAML logs a **warning** and continues with defaults instead of aborting | e.g. amfd `load_config` (`src/bins/nextgcore-amfd/src/lib.rs`): look for `Could not read config file '...'` / `Failed to parse YAML config '...'. Using defaults.` in startup logs |
| Editing `metrics.server` (or other unknown keys) in `amf.yaml`/`smf.yaml`/`pcf.yaml`/`upf.yaml` changes nothing | Those NFs deserialize only a small typed subset (UPF parses nothing at all — it only logs the file's byte count); serde ignores unknown keys silently | `AmfSection` in `src/bins/nextgcore-amfd/src/lib.rs`; `SmfYaml` in `src/bins/nextgcore-smfd/src/main.rs`; `PcfSection` in `src/bins/nextgcore-pcfd/src/app.rs`; `src/bins/nextgcore-upfd/src/main.rs` (~line 196) |
| Every NSAC admission fails (per-UE `SLICE_NOT_FOUND` failures / 403), breaking registration or PDU establishment | `nsacf.slice_quotas` missing from `nsacf.yaml` → NSACF starts with an **empty quota table** and no S-NSSAI is provisioned | `src/bins/nextgcore-nsacfd/src/main.rs` (quota provisioning ~line 250, failure-reason mapping ~lines 623–702); add `slice_quotas` entries as in `docker/rust/configs/5gc/nsacf.yaml` |
| SBI calls suddenly return **401** (or **503**) after enabling OAuth2 | Producer now requires an NRF-issued Bearer token (bad/absent token → 401; NRF JWKS unreachable → 503) but a consumer isn't attaching one | `docker/rust/docker-compose.oauth2.yml` (per-NF enablement map); `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` env / `--oauth2-require` flags; enforcement semantics in `src/libs/nextgcore-sbi/src/server.rs` |
| NF log shows `NRF registration failed (will operate without NRF)` | NRF was unreachable at startup; registration (`PUT /nnrf-nfm/v1/nf-instances/{id}`) is attempted **once**, with no retry loop | `src/bins/nextgcore-amfd/src/lib.rs` (~line 831) + `src/bins/nextgcore-amfd/src/sbi_path.rs` `amf_nrf_register`; ensure NRF is healthy first (compose `depends_on` does this), else restart the NF |
| Repeated `Heartbeat failed for <id>` / `Heartbeat got unexpected status ...` warnings | The heartbeat worker PATCHes `/nnrf-nfm/v1/nf-instances/{id}` (JSON-Patch `/load` gauge, every 5s for AMF/SMF) and only logs failures — it does not re-register a lost profile | `src/libs/nextgcore-sbi/src/heartbeat.rs` `spawn_heartbeat_worker_with_load`; restart the NF to re-register if the NRF lost its record |
| UDR cannot reach MongoDB (E2E assert `MongoDB connected` fails) | Wrong DB URI. Resolution order: `db_uri:` line in the config file → `DB_URI` env var → default `mongodb://172.23.0.2/nextgcore` (the compose MongoDB) | `src/bins/nextgcore-udrd/src/main.rs` (~lines 2250–2268); `docker compose ps mongodb` health (mongosh ping healthcheck); hssd takes `--db-uri` |
| A real/external gNB cannot establish an N2 (NGAP) association with the AMF | AMF's default SCTP backend is `userspace` (sctp-proto over UDP, matched to the nextgsim gNB) — a standard RAN needs native kernel SCTP | `--sctp-backend kernel` (needs the `kernel-sctp` build feature + libsctp), see `Args` in `src/bins/nextgcore-amfd/src/lib.rs` and `docker/rust/docker-compose.kernel-sctp.yml`; verify with `docker exec nextgcore-amf cat /proc/net/sctp/assocs` |
| Setting `RUST_LOG=debug` has no effect on a given NF | That NF ignores `RUST_LOG` (only smfd, nsacfd, eesd, dccfd, lmfd, mbsmfd, nwdafd, pind, sgwud honor it); use its `--log-level`/`-e` flag instead | amfd `src/bins/nextgcore-amfd/src/lib.rs:780` (`filter_level`, env ignored) vs smfd `src/bins/nextgcore-smfd/src/main.rs:299` (`from_env`) and sgwud `src/bins/nextgcore-sgwud/src/main.rs:18` (`env_logger::init()`) |
| `TLS_ENABLED=true SBI_SCHEME=https docker compose up` doesn't turn on TLS | No Rust code reads `TLS_ENABLED`/`SBI_SCHEME` — they are compose-level env decoration; real TLS knobs are per-NF CLI flags | grep in `src/` returns zero `.rs` hits; use `--tls --tls-cert --tls-key` (nrfd also `--mtls`, `--tls-ca-cert`), certs from `docker/rust/certs/generate-dev-certs.sh` |
| Docker build fails or (worse) Docker Desktop wipes its image store mid-build | Building under disk pressure — a full rebuild needs ~20 GB; this destroyed the image store once (hazard #269) | `docker/rust/preflight.sh` refuses to build below the free-space minimum (default 25 GB, checked on host **and** inside the Docker VM) and trims BuildKit cache to 20 GB; don't use `--no-preflight` casually |
| Manual log-grep "fails" even though the line is present | `docker logs \| grep -q` under `pipefail` dies via SIGPIPE on first match, turning a match into a false negative | header note in `docker/rust/e2e-test.sh`: always capture `docker logs` to a file, then grep the file (as `assert_log_contains` does) |

## Running the E2E suite

The single entrypoint is `docker/rust/e2e.sh` (Wave-6 H10):

```bash
cd nextgcore/docker/rust
./e2e.sh                         # preflight + full build + baseline E2E
./e2e.sh --quick                 # reuse existing binaries (build.sh --skip-rust)
./e2e.sh --overlay oauth2        # baseline suite with OAuth2 enforcement overlay
./e2e.sh --overlay kernel-sctp   # baseline suite over native kernel SCTP N2
./e2e.sh --overlay features      # baseline E2E + Rel-17/18 feature harness
./e2e.sh --keep                  # leave the stack running afterwards
```

Exit codes: `0` all passed, `1` test assertion failure, `2` infrastructure failure (preflight refusal, build, startup). Overlay names map to `docker-compose.<name>.yml`; `w6` is accepted as an alias for `features`.

**Prerequisites.** A Docker daemon with compose, and disk headroom: `preflight.sh` runs first and exits `2` if free space is below the minimum (default 25 GB) on the host filesystem holding Docker data **or** inside the Docker VM; it also trims the BuildKit cache with `docker builder prune --keep-storage=20GB`. Everything else (Rust compilation, images) is built by `build.sh` inside the builder image.

**What it runs.** `e2e.sh` chains preflight → `build.sh` → `e2e-test.sh --no-build --no-preflight --keep` (it owns teardown itself so artifacts can be captured first). `e2e-test.sh` then:

1. `docker compose up -d` the full stack (MongoDB + 5GC NFs + nextgsim gNB + UE) and waits up to **120 s** for 13 services (`mongodb nrf udr udm ausf pcf nssf bsf smf amf upf gnb ue`) to report healthy (NF healthcheck is `kill -0 1`; MongoDB uses a mongosh ping), printing the unhealthy ones on timeout.
2. Runs log-anchored assertions: per-NF process + `NextGCore <NF> ready` startup lines, `MongoDB connected` (UDR), AMF NGAP setup (`NGAP server listening`, `NG Setup successful`), and the full source-anchored registration flow (`Initial UE Message`, `Registration Request: type=`, `Calling AUSF authenticate`, `result=AUTHENTICATION_SUCCESS`, `keys derived; selected NIA`, …) through `UE PDU session 1 ACTIVE with IPv4 address`.
3. Verifies the data plane by pinging **through the UE's GTP-U tunnel** from the `nextgsim-ue` container: `10.45.0.1` (UPF gateway), `172.23.0.1` (Docker gateway), `172.23.0.7` (UPF host), then prints a Total/Passed/Failed summary. The full baseline suite was 84/84 green on 2026-07-02.

**When it fails, look here:**

- The `FAIL:` line names the container and the exact log pattern that was not found.
- On any failure, `e2e.sh` saves `docker logs` of **every** `nextgcore-*`/`nextgsim-*` container — before teardown — under `docker/rust/artifacts/e2e-YYYYMMDD-HHMMSS/` (one `<container>.log` per container, plus `docker-ps.txt` and `docker-system-df.txt`). Override the location with `--artifacts DIR`.
- To debug interactively, rerun with `--keep` and inspect the live stack (`docker compose logs -f amf gnb ue`, `docker exec nextgsim-ue ping 10.45.0.1`).
- Some historical assertions were removed as stale (e.g. Identity Request/Response — the UE sends its SUCI in the initial Registration Request, so the identity procedure never runs); the comments in `e2e-test.sh` explain each pattern's source anchor, which is the right place to start when an assertion and the logs disagree.
