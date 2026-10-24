# Observability & Troubleshooting

NextGCore ships a Docker-based observability stack (Prometheus, Grafana, Jaeger) alongside its 28 network-function daemons, plus an in-tree metrics/tracing library (`src/libs/nextgcore-metrics/`). This chapter documents what actually works today — which endpoints exist, which are scaffolding, how logging is really configured per NF — and gives a code-grounded troubleshooting table and the one-command E2E recipe.

> **Honesty note:** NextGCore behavior is validated by this project's own unit tests and matched-simulator docker E2E (run nightly by `.github/workflows/ci.yml`), not by third-party conformance certification. The observability stack described here is exactly what ships in this repo — it is **not** a certified telco OAM system. In particular, the library `MetricsServer` and the OpenTelemetry OTLP exporters in `nextgcore-metrics` are **structural stubs**. Three NFs (smfd, upfd, sgwud) now serve a small set of runtime gauges over HTTP through a separate helper; every other NF serves no scrapeable metrics, and no NF exports spans. Each gap is called out explicitly below.

## Metrics

### What the library provides — and what it does not

`src/libs/nextgcore-metrics/src/server.rs` defines a `MetricsServer` documented to serve two HTTP endpoints — `/` (health check, returns "OK") and `/metrics` (Prometheus text exposition) — and `src/libs/nextgcore-metrics/src/lib.rs` defines `DEFAULT_PROMETHEUS_HTTP_PORT: u16 = 9090`. However, `MetricsServer::start()` does **not** bind a socket: it logs `metrics_server() [http://<addr>]:<port>`, flips its state to `Running`, and returns (the code comment reads "In a real implementation, this would start an HTTP server using hyper"). What does serve HTTP is a different, minimal helper: `nextgcore_metrics::nes_energy::serve_metrics(addr, render)` (`src/libs/nextgcore-metrics/src/nes_energy.rs`) binds a TCP listener, logs `metrics endpoint listening on http://<addr>/metrics`, and answers with whatever text the NF's `render` closure returns. Three daemons call it unconditionally, and two more behind off-by-default cargo features:

| NF daemon | Metrics served on `/metrics` | Port |
|---|---|---|
| `nextgcore-smfd` | `smf_n4_associations`, `smf_n4_peers`, `smf_sessions`, `smf_up` (and the PGW-C S5/S8 binding) | 9090, or `SMF_METRICS_PORT` |
| `nextgcore-upfd` | `upf_pfcp_associations`, `upf_pfcp_sessions`, `upf_pfcp_unauthorized_messages_total`, `upf_up`, `upf_dataplane_{ul,dl}_{packets,bytes}_total` and dropped/oversize/spoofed packet counters | 9090, or `UPF_METRICS_PORT` |
| `nextgcore-sgwud` | `sgwu_pfcp_sessions`, `sgwu_pfcp_associations`, `sgwu_pfcp_unauthorized_messages_total`, `sgwu_up` | 9090, or `SGWU_METRICS_PORT` |
| `nextgcore-udmd` | NES energy gauges, only with `--features nes` | NES `metrics_port` (default 9090) |
| `nextgcore-nsacfd` | slice-SLA observe gauges, only with `--features sla-observe` | its `metrics_port` when > 0 |

Every one of these listeners is unauthenticated, so it binds `127.0.0.1` by default (#837): set `NEXTGCORE_METRICS_BIND` (an IP address, e.g. `0.0.0.0`) to widen it. The compose files, the Kind manifests, the Helm chart and the EKS overlays set it to `0.0.0.0` inside the private container or pod network, where Prometheus scrapes by container/pod address; none of them publishes a metrics port on the host. The `k8s/monitoring/*` and `k8s/manifests/nrf.yaml` NodePort Services are for kind only, where the node is the Docker bridge and `kind-config.yaml` maps the ports to 127.0.0.1; on a real cluster a NodePort is open on every node IP, so do not apply them there. The compose host-port publishes (MongoDB, NRF, PFCP, Prometheus, Grafana, Jaeger, OTLP) are bound to `127.0.0.1`; the RAN-facing NGAP/S1AP and GTP-U publishes use `${NEXTGCORE_RAN_PUBLISH_ADDR:-127.0.0.1}`, so an external gNB/eNB needs that set to the host address it reaches.

`docker-compose-epc.yml` uses these endpoints as healthchecks (`curl -fsS http://localhost:9090/metrics | grep -q '^smf_up 1$'`, likewise `upf_up`, `sgwu_up`).

The other NF daemons serve **no** Prometheus metrics over HTTP:

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
| `nextgcore-nsacfd` | none by default | Same. SLA-observe gauges with `--features sla-observe` (above). |
| `nextgcore-nssfd` | none | Same. |
| `nextgcore-nwdafd` | none | Same. |
| `nextgcore-pcfd` | none | Same; `init_otel` in `src/app.rs`. |
| `nextgcore-pcrfd` | none | Same. |
| `nextgcore-pind` | none | Same. |
| `nextgcore-scpd` | none | Same. |
| `nextgcore-seppd` | none | Same. |
| `nextgcore-sgwcd` | none | Same. |
| `nextgcore-udmd` | none by default | Same; `init_otel` in `src/app.rs`. NES gauges with `--features nes` (above). |
| `nextgcore-udrd` | none | Same. |
| `nextgcore-easdfd`, `nextgcore-nefd`, `nextgcore-tsctsf`, `nextgcore-ucmfd` | none | Same. |

Apart from the five `serve_metrics` callers above, the NF crates use `nextgcore-metrics` only for the `init_otel` call (see Tracing); the AMF is the one NF with full metric-family definitions, and it serves none of them.

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

Four docker config files — `docker/rust/configs/5gc/amf.yaml`, `pcf.yaml`, `smf.yaml`, `upf.yaml` — contain a `metrics.server` block with `port: 9090`. **None of these four NFs parses it** (smfd and upfd do listen on 9090, but the port comes from their default or `SMF_METRICS_PORT`/`UPF_METRICS_PORT`, not from this block):

- **AMF**: `AmfSection` in `src/bins/nextgcore-amfd/src/lib.rs` deserializes only `amf_name`, `network_name`, `guami`, `tai`, `plmn_support`, `security`, `sbi`, `nas`, `time`, `emergency` — no `metrics` field (serde silently ignores unknown keys).
- **SMF**: `SmfYaml`/`SmfSection` in `src/bins/nextgcore-smfd/src/main.rs` deserializes only `smf.sbi`, `smf.gtpc`, `smf.dns`, `smf.mtu`.
- **PCF**: `PcfSection` in `src/bins/nextgcore-pcfd/src/app.rs` deserializes only `pcf.sbi`.
- **UPF**: `src/bins/nextgcore-upfd/src/main.rs` reads the config file only to log its byte count ("Configuration file loaded (N bytes)") — no YAML deserialization at all; every UPF runtime knob is a CLI flag.

### The shipped scrape stack

`docker compose up -d` in `docker/rust/` starts the full observability trio unconditionally (no compose profile gating):

- **Prometheus** (`prom/prometheus:v2.51.0`, container `nextgcore-prometheus`, `172.23.0.200`, host port `9090`) — config `docker/rust/configs/observability/prometheus.yml`: 15s scrape interval, static targets for 10 NFs (NRF, AUSF, UDM, UDR, PCF, NSSF, BSF, AMF, SMF, UPF) at their fixed `172.23.0.x:9090` addresses, each labeled with `nf_type` and `instance_name`, plus self-scrape. Only the SMF and UPF listen on 9090, so those two jobs read `up == 1` and the other **8 NF jobs read `up == 0`** in the current build.
- **Grafana** (`grafana/grafana:10.4.0`, `172.23.0.201`, host port `3000`, login `admin`/`nextgcore`) — provisioned datasources (`grafana-datasources.yml`: Prometheus at `http://172.23.0.200:9090`, Jaeger at `http://172.23.0.202:16686`) and dashboards from `configs/observability/dashboards/` with `overview.json` as the home dashboard.
- **Alert rules** (`configs/observability/alert-rules.yml`) — `NfInstanceDown` (`up == 0` for 1m) and `NfSlowResponse` are generic and will actually evaluate; the NF-specific rules reference metric names (`amf_registration_failure_total`, `amf_connected_ue_count`, `smf_pfcp_association_up`, `upf_packets_dropped_total`, `nrf_registered_nf_count`, `mongodb_up`, …) that **no code in this repo emits** — they are aspirational, written for a future exporter wiring. (The SMF's real association gauge is `smf_n4_associations`, which no rule uses yet.)

## Tracing (OpenTelemetry)

**What exists.** `src/libs/nextgcore-metrics/src/otel.rs` provides `OtelConfig` (service name, OTLP endpoint — default `http://localhost:4317` — 10s export interval, traces/metrics/logs toggles), `OtelProvider`, W3C `traceparent` parse/generate helpers (`OtelSpanContext::from_traceparent`/`to_traceparent`), an `SbiSpan` wrapper with `nf.type`/`sbi.service`/`http.*` attributes, and a `JaegerConfig` (default endpoint `http://localhost:14268/api/traces`, sampling 1.0).

**Startup wiring.** 27 of the 28 NF daemons call `init_otel(OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(...))` at startup, taking the endpoint from the **`OTEL_EXPORTER_OTLP_ENDPOINT`** environment variable and defaulting to **`http://jaeger:4317`** when unset (which resolves to the compose `jaeger` service). The AMF is the exception — it never calls `init_otel`. The shared helper `nf_common_init` in `src/libs/nextgcore-app/src/init.rs` bundles the same logic (same env var, same default) but is currently not called by any NF binary.

**No-op behavior — the honest part.** `OtelProvider::init()` is structural: it prints `Initializing OpenTelemetry for service '<name>' (endpoint: <url>)` and per-signal init lines to stderr, but creates **no** actual OTLP exporters (the code comments read "In a real implementation, this would use the opentelemetry crate"). Initialization failure is deliberately non-fatal (`let _ = init_otel(...)` / `.ok()`). Net effect: whether or not a collector is reachable, **no spans, metrics, or logs are ever exported**. The Jaeger all-in-one container in the compose stack (UI on `16686`, OTLP gRPC `4317`, OTLP HTTP `4318`) will show no NextGCore traces.

**What IS real: wire-level trace propagation.** The SBI client (`src/libs/nextgcore-sbi/src/client.rs`, `prepare_request`) stamps every outbound SBI request with a W3C `traceparent` header — respecting a caller-supplied one, otherwise generating a new sampled root span with CSPRNG-random trace/span IDs — and echoes the inbound correlation ID as `x-request-id`. So cross-NF request correlation works today by grepping IDs across `docker logs`, even without a trace backend.

## Logging

All NFs log to **stdout/stderr** via `env_logger`. Every NF binary uses millisecond timestamps. In the docker deployment, logs are consumed with `docker logs <container>` / `docker compose logs -f amf gnb ue`. The compose file's `x-common` anchor (`docker/rust/docker-compose.yml`) sets `RUST_LOG: info` as the baseline, but four services override it with more verbose crate-level filters: `amf` (`info,nextgcore_amfd=debug`), `upf` (`info,nextgcore_upfd=debug`), `gnb` and `ue`. `RUST_BACKTRACE: 1` is uniform across all services (merged via `<<: *common-env`).

**CLI flags vary per NF** — check `--help` for the daemon you are running. Two verified patterns:

| Pattern | Flags | Verified in |
|---|---|---|
| Open5GS-style | `-e, --log-level` (default `info`), `-l, --log-file`, `-m, --no-color`; some also have `-k, --kill` (ausfd, bsfd, hssd, nrfd, nssfd, pcfd, pcrfd, scpd, seppd, udmd, udrd, upfd) | most SBI and Diameter NFs, e.g. `nextgcore-nrfd` and `nextgcore-nsacfd` (no kill flag) |
| AMF-style | `-l, --log-level` (default `info`), `--no-color`, `-d, --daemon` — **no** log-file flag | `nextgcore-amfd`, `nextgcore-mmed`, `nextgcore-sgwcd` |
| ucmfd | `-e, --log-level` only; no log-file or no-color flag | `nextgcore-ucmfd` |

`nextgcore-smfd` and `nextgcore-sgwud` have no clap parser. smfd scans `std::env::args()` for `-c/--config`, `-e/--log-level` (and `--state-file`); sgwud scans for `-c` and `-l/--log-level`.

**The level is chosen the same way in every NF.** Every NF builds its logger with `nextgcore_core::log::nf_log_builder` (#691): `RUST_LOG`, when set, is the filter; otherwise the level is `--log-level` when given, else the config file's `logger.level`, else `info` (`nextgcore_core::log::nf_log_level`; an unknown value means `info`). `RUST_LOG_STYLE` sets the colour style; `--no-color` overrides it.

Precedence, in full: a set, non-blank `RUST_LOG` **replaces** the resolved level (`--log-level` / `logger.level` / `info`); they are not merged. So `RUST_LOG=nextgcore_amfd=debug` alone logs only amfd's own targets (at debug) and silences every other target. Include a default level, as the compose files do (`info,nextgcore_amfd=debug`), to keep the rest at `info`. A blank `RUST_LOG=` counts as unset. `src/libs/nextgcore-core/tests/nf_logging_init.rs` fails if a daemon builds its own logger, skips `nf_log_level`, or gives its `log_level` flag a clap default (which would hide `logger.level`).

**`--log-file` is accepted but not wired.** 22 binary crates (ausfd, bsfd, dccfd, easdfd, eesd, hssd, lmfd, mbsmfd, nefd, nrfd, nsacfd, nssfd, nwdafd, pcfd, pcrfd, pind, scpd, seppd, tsctsf, udmd, udrd, upfd — `grep -rl log_file src/bins/*/src/*.rs`) declare a `log_file` CLI arg, but in none of them is the parsed value ever consumed by the logging setup — e.g. nrfd's `init_logging()` never references `args.log_file`. Logs always go to stdout/stderr; rely on `docker logs` or shell redirection.

## Troubleshooting

Every row below is grounded in a specific file in this repo.

| Symptom | Likely cause | What to check / fix |
|---|---|---|
| Prometheus shows NF targets `DOWN` (`up == 0`), `NfInstanceDown` alerts fire for 8 of the 10 NF jobs | **Expected in the current build**: only smfd and upfd serve `/metrics` on 9090; `MetricsServer::start()` is a stub that never binds | `src/libs/nextgcore-metrics/src/server.rs`, `nes_energy.rs` `serve_metrics`; scrape targets in `docker/rust/configs/observability/prometheus.yml` |
| Grafana/Jaeger show no NF traces despite "Initializing OpenTelemetry" in NF stderr | `OtelProvider::init()` creates no real OTLP exporter (structural stub); export never happens | `src/libs/nextgcore-metrics/src/otel.rs` (`init_traces`/`init_metrics`/`init_logs` bodies) |
| NF-specific alert rules never fire | Rules reference metric names (`amf_registration_failure_total`, `smf_pfcp_association_up`, …) that no code emits | `docker/rust/configs/observability/alert-rules.yml`; grep the names in `src/` — zero hits |
| NF starts with built-in defaults although you passed a config file | Lenient config loading: an unreadable or unparsable YAML logs a **warning** and continues with defaults instead of aborting | e.g. amfd `load_config` (`src/bins/nextgcore-amfd/src/lib.rs`): look for `Could not read config file '...'` / `Failed to parse YAML config '...'. Using defaults.` in startup logs |
| Editing `metrics.server` (or other unknown keys) in `amf.yaml`/`smf.yaml`/`pcf.yaml`/`upf.yaml` changes nothing | Those NFs deserialize only a small typed subset (UPF parses nothing at all — it only logs the file's byte count); serde ignores unknown keys silently. Move the SMF/UPF metrics port with `SMF_METRICS_PORT`/`UPF_METRICS_PORT` | `AmfSection` in `src/bins/nextgcore-amfd/src/lib.rs`; `SmfYaml` in `src/bins/nextgcore-smfd/src/main.rs`; `PcfSection` in `src/bins/nextgcore-pcfd/src/app.rs`; `src/bins/nextgcore-upfd/src/main.rs` (`Configuration file loaded`) |
| Every NSAC admission fails (per-UE `SLICE_NOT_FOUND` failures / 403), breaking registration or PDU establishment | `nsacf.slice_quotas` missing from `nsacf.yaml` → NSACF starts with an **empty quota table** and no S-NSSAI is provisioned | `src/bins/nextgcore-nsacfd/src/main.rs` (quota provisioning and failure-reason mapping); add `slice_quotas` entries as in `docker/rust/configs/5gc/nsacf.yaml` |
| SBI calls suddenly return **401** (or **503**) after enabling OAuth2 | Producer now requires an NRF-issued Bearer token (bad/absent token → 401; NRF JWKS unreachable → 503) but a consumer isn't attaching one | `docker/rust/docker-compose.oauth2.yml` (per-NF enablement map); `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` env / `--oauth2-require` flags; enforcement semantics in `src/libs/nextgcore-sbi/src/server.rs` |
| NF log shows `NRF registration failed (will operate without NRF)` | NRF was unreachable at startup; the startup registration (`PUT /nnrf-nfm/v1/nf-instances/{id}`) is attempted **once**, with no retry loop, and no heartbeat worker is started | `src/bins/nextgcore-amfd/src/lib.rs` (`amf_nrf_register` call in the startup path) + `src/bins/nextgcore-amfd/src/sbi_path.rs`; ensure NRF is healthy first (compose `depends_on` does this), else restart the NF |
| Repeated `Heartbeat failed for <id>` / `Heartbeat got unexpected status ...` warnings | The heartbeat worker PATCHes `/nnrf-nfm/v1/nf-instances/{id}` (JSON-Patch `/load` gauge, every 5s for AMF/SMF) and logs failures. A **404** (the NRF lost the profile, e.g. it restarted) makes the worker re-PUT the profile the NF registered (#434); other failures are only logged. NFs also deregister from the NRF on shutdown (#235) | `src/libs/nextgcore-sbi/src/heartbeat.rs` `spawn_heartbeat_worker_with_load` |
| UDR cannot reach MongoDB (E2E assert `MongoDB connected` fails) | Wrong DB URI. Resolution order: `db_uri:` line in the config file → `DB_URI` env var → default `mongodb://172.23.0.2/nextgcore` (the compose MongoDB) | `src/bins/nextgcore-udrd/src/main.rs` (`DB_URI` fallback); `docker compose ps mongodb` health (mongosh ping healthcheck); hssd takes `--db-uri` |
| A real/external gNB cannot establish an N2 (NGAP) association with the AMF | AMF's default SCTP backend is `userspace` (sctp-proto over UDP, matched to the nextgsim gNB) — a standard RAN needs native kernel SCTP | `--sctp-backend kernel` (needs the `kernel-sctp` build feature + libsctp), see `Args` in `src/bins/nextgcore-amfd/src/lib.rs` and `docker/rust/docker-compose.kernel-sctp.yml`; verify with `docker exec nextgcore-amf cat /proc/net/sctp/assocs` |
| Setting `RUST_LOG=debug` has no visible effect on an NF | `RUST_LOG` is not reaching the process (check `docker inspect` / the compose `environment:`), or the filter names the wrong target (crate names use underscores: `nextgcore_amfd=debug`) | `nextgcore_core::log::nf_log_builder` in `src/libs/nextgcore-core/src/log.rs` |
| `TLS_ENABLED=true SBI_SCHEME=https docker compose up` doesn't turn on TLS | No Rust code reads `TLS_ENABLED`/`SBI_SCHEME` — they are compose-level env decoration; real TLS knobs are per-NF CLI flags | grep in `src/` returns zero `.rs` hits; use `--tls --tls-cert --tls-key` (nrfd also `--mtls`, `--tls-ca-cert`), certs from `docker/rust/certs/generate-dev-certs.sh` |
| Docker build fails or (worse) Docker Desktop wipes its image store mid-build | Building under disk pressure — a full rebuild needs ~20 GB; this destroyed the image store once (hazard #269) | `docker/rust/preflight.sh` refuses to build below the free-space minimum (default 25 GB, checked on host **and** inside the Docker VM) and trims BuildKit cache to 20 GB; don't use `--no-preflight` casually |
| Manual log-grep "fails" even though the line is present | `docker logs \| grep -q` under `pipefail` dies via SIGPIPE on first match, turning a match into a false negative | header note in `docker/rust/e2e-test.sh`: always capture `docker logs` to a file, then grep the file (as `assert_log_contains` does) |

## Running the E2E suite

The single local entrypoint is `docker/rust/e2e.sh`:

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
3. Verifies the data plane by pinging **through the UE's GTP-U tunnel** from the `nextgsim-ue` container: `10.45.0.1` (UPF gateway), `172.23.0.1` (Docker gateway), `172.23.0.7` (UPF host), then prints a Total/Passed/Failed summary.

`e2e.sh` stops there. The nightly CI (`docker-e2e` in `.github/workflows/ci.yml`) also runs `docker/rust/ue-flow-check.sh` — downlink paging of a CM-IDLE UE, uplink from CM-IDLE, a page after a Service Request, UE-initiated de-registration and re-registration, UDM `REREGISTRATION_REQUIRED` re-registration, each ending in a ping — and the EPC LTE attach (`docker/rust/epc-attach-check.sh`). Run `./ue-flow-check.sh all` against a stack kept up with `--keep` to reproduce the former locally.

**When it fails, look here:**

- The `FAIL:` line names the container and the exact log pattern that was not found.
- On any failure, `e2e.sh` saves `docker logs` of **every** `nextgcore-*`/`nextgsim-*` container — before teardown — under `docker/rust/artifacts/e2e-YYYYMMDD-HHMMSS/` (one `<container>.log` per container, plus `docker-ps.txt` and `docker-system-df.txt`). Override the location with `--artifacts DIR`.
- To debug interactively, rerun with `--keep` and inspect the live stack (`docker compose logs -f amf gnb ue`, `docker exec nextgsim-ue ping 10.45.0.1`).
- Some historical assertions were removed as stale (e.g. Identity Request/Response — the UE sends its SUCI in the initial Registration Request, so the identity procedure never runs); the comments in `e2e-test.sh` explain each pattern's source anchor, which is the right place to start when an assertion and the logs disagree.
