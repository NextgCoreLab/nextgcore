# SCP Configuration

The SCP (Service Communication Proxy, `nextgcore-scpd`) is the 5GC indirect-communication proxy: an HTTP/2 forwarding engine implementing TS 29.500 §6.10 (as cited in the daemon's source comments) with both **Model C** (consumer supplies `3gpp-Sbi-Target-apiRoot`) and **Model D** (delegated discovery driven by `3gpp-Sbi-Discovery-*` headers, resolved against the NRF's `nnrf-disc` service per TS 29.500 §6.10.3 / TS 29.510 §5.3.2 per code comments). It exposes no NF-specific API routes of its own — a single catch-all handler (`ScpProxy::handle` in `src/bins/nextgcore-scpd/src/proxy.rs`) proxies every inbound SBI request, adding binding stickiness (TS 29.500 §6.12), Via/Server loop detection (§6.10.10), and delegated OAuth2 token acquisition (TS 33.501 §13, per code comments).

Configuration comes from **CLI flags, environment variables and the YAML file**, in that precedence order (CLI > env > file > built-in default). The file path defaults to `/etc/nextgcore/scp.yaml` and is overridable with `-c/--config`. The NRF URI, the SCP's NF Instance ID, and its FQDN each have an environment-variable fallback (`NRF_URI`, `NF_INSTANCE_ID`, `SCP_FQDN`) used when the corresponding flag is absent; the flag always wins over the env var, and the file is consulted after both.

> **Honesty note:** SCP behavior is validated by this project's own unit tests (including an in-process mock NRF in `proxy.rs`) and the matched-simulator Docker E2E, not by third-party conformance certification. Two things an operator should know up front: (1) the `-k/--kill` flag is a stub that logs "would send SIGTERM" and exits without killing anything; (2) `-l/--log-file` is accepted by clap but never used by `init_logging` — logs always go to the `env_logger` default sink.
>
> This note previously stated that the daemon read the YAML file only to log its byte count and that every field in it was decorative. **That is no longer true** and is corrected below: `config.rs` carries `#[derive(Deserialize)]` structs and `main.rs` reads the `scp` section for the SBI address/port, the NRF URI, `fqdn`, `nf_instance_id`, both timeouts, the cache bounds, `max_producer_attempts`, and `sbi.tls.enabled`/`cert`/`key`.

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

The commented-out optional `scp`-level keys are omitted from the excerpt above; see the live-fields table below.

Note that the shipped `docker-compose.yml` service (`scp:`, lines 491–503) does not mount this file into the container — it runs the daemon purely on CLI flags: `command: ["--sbi-addr", "172.23.0.37", "--sbi-port", "7777"]`. The YAML's addresses (`172.22.0.x`) do not match the compose network (`172.23.0.x`) either. So the file **is** parsed when present, but in *that* deployment it is never mounted and the flags supply everything.

## YAML parameters

`nextgcore-scpd` deserializes its `scp` section in `src/bins/nextgcore-scpd/src/config.rs` (serde `Deserialize` structs) and `main.rs` resolves each value as CLI flag > env var > file > built-in default via `config::resolve`. The resolved values are plumbed into `ScpProxyConfig` (`proxy.rs`) and `SbiServerConfig` (`sbi_path.rs`).

### Which YAML fields are live, and which are inert

**Live** — read by `config.rs` / `main.rs`, and used when no CLI flag or environment variable supplies the value:

| key | effect |
|---|---|
| `scp.sbi.server[0].address` / `.port` | SBI bind address / port (after `--sbi-addr` / `--sbi-port`) |
| `scp.sbi.client.nrf[0].uri` | NRF URI for Model D (after `--nrf-uri`, then `NRF_URI`) |
| `scp.sbi.tls.enabled` / `.cert` / `.key` | TLS on the SBI server; `--tls` forces it on regardless |
| `scp.fqdn` | SCP identity for `Via` / `Server` / loop detection (after `--scp-fqdn`, then `SCP_FQDN`) |
| `scp.nf_instance_id` | own `nfInstanceId` for delegated tokens (after `--nf-instance-id`, then `NF_INSTANCE_ID`) |
| `scp.connect_timeout` / `scp.request_timeout` | upstream timeouts, whole seconds |
| `scp.max_cache_entries` / `scp.cache_ttl` | proxy cache bounds |
| `scp.max_producer_attempts` | Model D alternate-producer reselection bound |

All of the `scp`-level keys are shipped **commented out**, so the built-in defaults apply unless an operator uncomments them.

**Inert** — present in the shipped file and not read anywhere:

- **`logger.file.path` and `logger.level`.** The log level comes from the CLI flag `-e/--log-level` (default `info`); `init_logging` builds `env_logger` with an explicit filter level, so even `RUST_LOG` (set to `info` by the compose file's common environment) is not consulted. There is no working log-file output (`-l/--log-file` is accepted but unused).
- **`global.max.ue` / `global.max.peer`.** The only pool sizing the daemon applies is `--max-assoc` (default `8192`), passed to `scp_context_init`.
- **`scp.sbi.tls.ca` and `scp.sbi.tls.min_version`.** There is no CA-bundle or minimum-version knob in the code; the rest of the `tls` block *is* read.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-scpd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/scp.yaml` | Configuration file path. Parsed; see the live-fields table above. |
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
- **Model D admission/rejection**: `3gpp-Sbi-Discovery-target-nf-type` and `-requester-nf-type` are mandatory (**400** `MANDATORY_IE_MISSING` if absent); all other Discovery-* headers are forwarded as `nnrf-disc` query parameters (TS 29.500 §6.10.3.2 ↔ TS 29.510 §6.2.3.2.3 per code comment). SearchResults are cached per (target-nf-type, service-names, discovery-factor discriminator) with the SearchResult's `validityPeriod` as TTL, **defaulting to 3600 s when absent**.
- **Model D producer selection** (TS 29.510 §6.2.6.2 per code comment): the endpoint is selected by matching the requested **service name** and the **API major version in the URI**, and scheme / `apiPrefix` / port come from the *matching* `NFService` — so a producer registering several services on different ports is addressed on the right one. The request URI is authoritative for the service name; `3gpp-Sbi-Discovery-service-names` is used only when the URI names no service, and only when the header names exactly one. A service declaring no `versions` serves **any** version, and a profile registering no `nfServices` at all keeps its profile-level endpoint — both because those fields are optional in TS 29.510 and reading silence as "supports nothing" would reject conformant producers. The existing health / priority / capacity ordering then applies *within* the matching set.
- **Model D failure conditions are reported distinctly** (TS 29.500 §6.10.8.2 per code comment) — five outcomes, each with its own status **and** cause, so an operator can tell an NRF outage from a typo in the consumer's Discovery headers without reading SCP logs:

  | condition | status | cause |
  |---|---|---|
  | no NRF configured, or an invalid NRF URI | **503** | `NRF_NOT_AVAILABLE` |
  | NRF unreachable (connection refused) or timing out | **504** | `NRF_NOT_REACHABLE` |
  | NRF answered, non-200 | **502** | `NF_DISCOVERY_FAILURE` |
  | empty `SearchResult`, or no instance offering the requested service | **404** | `NF_DISCOVERY_FAILURE` |
  | requested API major version served by no discovered producer | **400** | `INVALID_API` |
  | every discovered producer unreachable (candidate set exhausted) | **504** | `TARGET_NF_NOT_REACHABLE` |

  `TARGET_NF_NOT_REACHABLE` is reserved for **producer**-side unreachability and is never used for an NRF failure.
- **Model D alternate-producer reselection** (TS 29.500 §6.10.8.2 per code comment): the whole ranked candidate set is kept, and a forward that **provably never reached** the selected producer is retried against the next-best one. Bounded by `scp.max_producer_attempts` (default **3** — the selected producer plus two alternates; `1` disables reselection), and the bound is logged at `warn` when it leaves discovered candidates untried. Three rules govern when it fires:
  - **Only pre-send failures.** A connection refused or a TLS handshake failure proves the request bytes were never written, so replaying them cannot duplicate work even for a `POST`. A **timeout** does *not* qualify — the same error covers "never connected" and "sent, producer still working" — and neither does any post-send transport error, so a possibly-delivered request is never replayed.
  - **An open circuit breaker reselects rather than shedding.** Previously the breaker protected a dead producer but still failed the request; now the request goes to a sibling while the dead producer stays protected. If *every* candidate is shed by its own breaker, the answer is **503** `TARGET_NF_NOT_REACHABLE` (load shedding, retry shortly) rather than 504.
  - **A producer that answered is never reselected.** Any status the producer returns — including 4xx and 5xx — is relayed verbatim; a sibling has no business overriding it.

  A reselected producer reports **its own** `3gpp-Sbi-Producer-Id`, not the originally selected one's. Model C and binding-stickiness forwarding have no alternates, so a single pinned target keeps its previous mapping (**502** refused / **504** timeout).
- **Delegated OAuth2**: when an NRF URI is known, the SCP acts as an OAuth2 client of NF type `SCP` and attaches producer-scoped access tokens on the Model D path; a token the NRF refuses yields **403** `ACCESS_TOKEN_DENIED`, and a producer `401` with a Bearer `WWW-Authenticate` challenge triggers one token-retry (TS 29.500 §6.10.11.2.3 per code comment). Model C requests are forwarded with the consumer's own `Authorization` untouched.
- **Response relay** (TS 29.500 §6.10.3.4 / §6.10.4 per code comments): on a **2xx**, the SCP surfaces the producer it selected in `3gpp-Sbi-Producer-Id` (`nfinst=<uuid>[; nfset=<set-id>]`) and its NF group in `3gpp-Sbi-Target-Nf-Group-Id`. Three properties worth knowing:
  - **The metadata does not depend on cache state.** `nfSetId`/`nfGroupId` are parsed onto the cached candidate, so a discovery-cache *hit* reports the same `Producer-Id` as the miss that populated it. (Previously they were read from the raw `SearchResult`, which the cache does not store, so `nfset=` vanished on every cache hit and the loss looked intermittent.)
  - **A `Producer-Id` the producer or a downstream SCP already supplied is preserved**, never overwritten. A producer naming itself is first-hand and a downstream SCP's is derived from the instance *it* selected; the SCP's own value is second-hand and is only used where there is none.
  - **After retargeting, a relative `Location` gains `3gpp-Sbi-Target-apiRoot`.** When the SCP chose the producer (Model D, or a sticky binding resolved from its own cache) the consumer cannot resolve a relative `Location` — it names a resource without naming the holder. §6.10.4 permits either absolutising the `Location` or adding the header; **this SCP adds the header** because that is additive (the producer's `Location` stays intact), because it keeps the consumer's follow-up flowing *through* the SCP rather than inviting it to address the producer directly and lose stickiness and token delegation, and because the follow-up then takes the existing Model C path with no new handling. An **absolute** `Location` is already addressable and is left alone; Model C gets no fix-up, since the consumer named the target itself.
- **No NRF registration**: the SCP never registers or heartbeats itself with the NRF — its only NRF traffic is `GET /nnrf-disc/v1/nf-instances` and token requests. Note the shipped `docker-compose.yml` sets no `NRF_URI` for the `scp` service, so Model D is disabled in that deployment (discovery requests get 503). Error identity: SCP-originated errors carry `Server: SCP-<fqdn>` (§6.10.8.2 per code comment); relayed producer 4xx/5xx keep their body/status verbatim but gain this SCP's `Via` (§6.10.8.3).
- **Environment variables** (all read in `main.rs`; flags take precedence): `NRF_URI`, `NF_INSTANCE_ID`, `SCP_FQDN` (fallbacks as in the flags table) and `OTEL_EXPORTER_OTLP_ENDPOINT` (OpenTelemetry OTLP trace exporter endpoint, default `http://jaeger:4317`). Upstream timeouts are compile-time constants — 2 s connect, 10 s request (`proxy.rs`, bounded per TS 29.500 §6.11 guidance per code comment) — with no CLI or YAML override.
