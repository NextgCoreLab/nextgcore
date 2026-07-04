# SCP Configuration

The SCP (Service Communication Proxy, `nextgcore-scpd`) is the 5GC indirect-communication proxy: an HTTP/2 forwarding engine implementing TS 29.500 §6.10 (as cited in the daemon's source comments) with both **Model C** (consumer supplies `3gpp-Sbi-Target-apiRoot`) and **Model D** (delegated discovery driven by `3gpp-Sbi-Discovery-*` headers, resolved against the NRF's `nnrf-disc` service per TS 29.500 §6.10.3 / TS 29.510 §5.3.2 per code comments). It exposes no NF-specific API routes of its own — a single catch-all handler (`ScpProxy::handle` in `src/bins/nextgcore-scpd/src/proxy.rs`) proxies every inbound SBI request, adding binding stickiness (TS 29.500 §6.12), Via/Server loop detection (§6.10.10), and delegated OAuth2 token acquisition (TS 33.501 §13, per code comments).

Configuration is **CLI flags and environment variables only**. There is a YAML file path (default `/etc/nextgcore/scp.yaml`, overridable with `-c/--config`), but the daemon does not parse it — see the honesty note below. The NRF URI, the SCP's NF Instance ID, and its FQDN each have an environment-variable fallback (`NRF_URI`, `NF_INSTANCE_ID`, `SCP_FQDN`) used when the corresponding flag is absent; the flag always wins over the env var.

> **Honesty note:** SCP behavior is validated by this project's own unit tests (including an in-process mock NRF in `proxy.rs`) and the matched-simulator Docker E2E, not by third-party conformance certification. Three things an operator should know up front: (1) the daemon **reads the YAML config file only to log its byte count** — `main.rs` contains a placeholder (`// In C: scp_context_parse_config()`) and no `#[derive(Deserialize)]` config structs exist anywhere in the crate, so every field in the shipped `scp.yaml` is decorative; (2) the `-k/--kill` flag is a stub that logs "would send SIGTERM" and exits without killing anything; (3) `-l/--log-file` is accepted by clap but never used by `init_logging` — logs always go to the `env_logger` default sink.

## Example configuration

From `nextgcore/docker/rust/configs/scp.yaml`:

```yaml
# NextGCore SCP (Service Communication Proxy) Configuration
# For Docker deployment with Rust implementation

logger:
  file:
    path: /var/log/nextgcore/scp.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

scp:
  sbi:
    server:
      - address: 172.22.0.50
        port: 7777
    client:
      nrf:
        - uri: http://172.22.0.10:7777
    # TLS configuration (G36: SBI TLS)
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/scp.crt
      key: /etc/nextgcore/certs/scp.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
```

Note that the shipped `docker-compose.yml` service (`scp:`, lines 491–503) does not even mount this file into the container — it runs the daemon purely on CLI flags: `command: ["--sbi-addr", "172.23.0.37", "--sbi-port", "7777"]`. The YAML's addresses (`172.22.0.x`) do not match the compose network (`172.23.0.x`), which is further evidence the file is not load-bearing.

## YAML parameters

**None.** Unlike the other NF daemons, `nextgcore-scpd` deserializes no YAML fields at all. `main.rs` checks whether the `--config` path exists, reads the file to a string, and logs `"Configuration file loaded (N bytes)"` — nothing more. There are no serde `Deserialize` structs in `src/bins/nextgcore-scpd/`. All runtime knobs are CLI flags (below) with three env-var fallbacks, plumbed into `ScpProxyConfig` (`proxy.rs`) and `SbiServerConfig` (`sbi_path.rs`).

### Parsed-but-inert / decorative YAML fields

Every field in the shipped example file is inert. Where the real knob lives:

- **`logger.file.path` and `logger.level` are inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`); `init_logging` builds `env_logger` with an explicit filter level, so even `RUST_LOG` (set to `info` by the compose file's common environment) is not consulted. There is no working log-file output (`-l/--log-file` is accepted but unused).
- **`global.max.ue` / `global.max.peer` are inert.** The only pool sizing the daemon applies is `--max-assoc` (default `8192`), passed to `scp_context_init`.
- **`scp.sbi.server[]` (address/port) is inert.** The SBI bind address and port come from `--sbi-addr`/`--sbi-port`.
- **`scp.sbi.client.nrf[].uri` is inert.** The NRF URI for Model D delegated discovery comes from `--nrf-uri`, falling back to the `NRF_URI` environment variable; when neither is set, delegated discovery is disabled.
- **`scp.sbi.tls.*` (enabled/cert/key/ca/min_version) is inert.** TLS is controlled by the `--tls`, `--tls-cert`, and `--tls-key` flags; there is no CA-bundle or minimum-version knob in the code.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-scpd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/scp.yaml` | Configuration file path (read but **not parsed** — see honesty note). |
| `-l, --log-file` | path | unset | Log file path — **accepted but unused** by `init_logging`. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM to running instance" and exits. |
| `--sbi-addr` | string | `127.0.0.1` | SBI server bind address (docker deployments pass the container IP). |
| `--sbi-port` | u16 | `7777` | SBI server port. |
| `--tls` | flag | off | Enable TLS on the SBI server. Startup fails unless **both** `--tls-cert` and `--tls-key` are given. |
| `--tls-cert` | path | unset | TLS certificate file. |
| `--tls-key` | path | unset | TLS private key file. |
| `--max-assoc` | usize | `8192` | Maximum number of associations in the SCP context pool. |
| `--nrf-uri` | string | unset (falls back to `NRF_URI` env) | NRF base URI for Model D delegated discovery. When neither flag nor env is set, Model D is disabled and a warning is logged at startup. |
| `--nf-instance-id` | string | unset (falls back to `NF_INSTANCE_ID` env, then `nextgcore-scp`) | The SCP's own NF Instance ID, sent as `nfInstanceId` in delegated OAuth2 token requests to the NRF (TS 29.510 §6.3 per code comment). |
| `--scp-fqdn` | string | unset (falls back to `SCP_FQDN` env, then `scp.5gc.local`) | The SCP's identity for `Via`/`Server` headers and `SCP-<FQDN>` loop detection (TS 29.500 §6.10.8/§6.10.10 per code comment). |
| `--next-hop-scp` | flag | off | Treat the next hop as another SCP: convey the selected producer apiRoot in `3gpp-Sbi-Target-apiRoot` instead of stripping it (TS 29.500 §6.10.2.5 per code comment). Default off = next hop is the producer. |

## Behavior notes

- **Routing precedence** (`ScpProxy::route`, TS 29.500 §6.10.2 per code comment): a valid `3gpp-Sbi-Target-apiRoot` wins (Model C); otherwise a `3gpp-Sbi-Routing-Binding` matching a cached `3gpp-Sbi-Binding` learnt from an earlier producer response (§6.12 stickiness, with NF-set-level reselection per §5.2.3.2.6); otherwise any `3gpp-Sbi-Discovery-*` header triggers Model D. A request with none of these — or an unparsable Target-apiRoot — is rejected **400** ProblemDetails, cause `MANDATORY_IE_MISSING`.
- **Loop/hop guard** (before any forwarding, §6.10.10 per code comments): a received `Via` already containing this SCP's `SCP-<FQDN>` token → **400** `MSG_LOOP_DETECTED`; an scp-typed `3gpp-Sbi-Max-Forward-Hops: 0` → **502** `MAX_SCP_HOPS_REACHED`. On forwarding, the hop header is decremented only when present (never added), and `Via: 2.0 SCP-<fqdn>` is appended. A plain single-hop request is never blocked.
- **Model D admission/rejection**: `3gpp-Sbi-Discovery-target-nf-type` and `-requester-nf-type` are mandatory (**400** `MANDATORY_IE_MISSING` if absent); all other Discovery-* headers are forwarded as `nnrf-disc` query parameters (TS 29.500 §6.10.3.2 ↔ TS 29.510 §6.2.3.2.3 per code comment). No NRF configured or invalid NRF URI → **503** `NRF_NOT_AVAILABLE`; NRF non-200 or no usable NF instance → **502** `NF_DISCOVERY_FAILURE`. SearchResults are cached per (target-nf-type, service-names, discovery-factor discriminator) with the SearchResult's `validityPeriod` as TTL, **defaulting to 3600 s when absent**.
- **Delegated OAuth2**: when an NRF URI is known, the SCP acts as an OAuth2 client of NF type `SCP` and attaches producer-scoped access tokens on the Model D path; a token the NRF refuses yields **403** `ACCESS_TOKEN_DENIED`, and a producer `401` with a Bearer `WWW-Authenticate` challenge triggers one token-retry (TS 29.500 §6.10.11.2.3 per code comment). Model C requests are forwarded with the consumer's own `Authorization` untouched.
- **No NRF registration**: the SCP never registers or heartbeats itself with the NRF — its only NRF traffic is `GET /nnrf-disc/v1/nf-instances` and token requests. Note the shipped `docker-compose.yml` sets no `NRF_URI` for the `scp` service, so Model D is disabled in that deployment (discovery requests get 503). Error identity: SCP-originated errors carry `Server: SCP-<fqdn>` (§6.10.8.2 per code comment); relayed producer 4xx/5xx keep their body/status verbatim but gain this SCP's `Via` (§6.10.8.3).
- **Environment variables** (all read in `main.rs`; flags take precedence): `NRF_URI`, `NF_INSTANCE_ID`, `SCP_FQDN` (fallbacks as in the flags table) and `OTEL_EXPORTER_OTLP_ENDPOINT` (OpenTelemetry OTLP trace exporter endpoint, default `http://jaeger:4317`). Upstream timeouts are compile-time constants — 2 s connect, 10 s request (`proxy.rs`, bounded per TS 29.500 §6.11 guidance per code comment) — with no CLI or YAML override.
