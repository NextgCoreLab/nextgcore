# SEPP Configuration

The SEPP (Security Edge Protection Proxy, `nextgcore-seppd`) secures inter-PLMN (roaming) signaling per TS 29.573 and TS 33.501 (as cited in the daemon's source comments). It runs two HTTP servers: a consumer-facing SBI server where home-PLMN NFs send outbound roaming requests (forwarded to the peer SEPP over N32-f), and an N32 listener serving the TS 29.573 endpoints `POST /n32c-handshake/v1/exchange-capability` (§6.1.5.2 per code comment), `POST /n32c-handshake/v1/exchange-params` (§6.1.5.3), `POST /n32c-handshake/v1/n32f-error` (§6.1.5.4), and `POST /n32f-forward/v1/n32f-process` (§6.2). Both TLS and PRINS N32-f security schemes are implemented; PRINS applies JWE/JWS protection per TS 29.573 §6.3 with the key hierarchy derived from the N32-c TLS RFC 5705 exporter per TS 33.501 §13.2.4.4.1 (all citations from the daemon source, `n32_server.rs`/`n32c_handler.rs`/`sbi_path.rs`).

Configuration is unusual for this project: the daemon accepts a YAML file path (default `/etc/nextgcore/sepp.yaml`, overridable with `-c/--config`), but **it never deserializes the file** — `main.rs` only checks the path exists, reads it, and logs its size in bytes. Every functional setting (bind addresses, ports, TLS, peers, PLMNs, security schemes) comes from command-line flags. One environment variable is read (`OTEL_EXPORTER_OTLP_ENDPOINT`); notably, `RUST_LOG` is **not** consulted (logging is built with `env_logger::Builder::new()` + `filter_level` from `--log-level`, not `from_default_env`).

> **Honesty note:** SEPP behavior is validated by this project's own unit tests and matched-simulator Docker E2E only, not by third-party conformance certification or interop against another vendor's SEPP. The N32-c/N32-f handshake and PRINS JWE/JWS protection are exercised SEPP-to-SEPP within this codebase. Bespoke/non-normative aspects: the shipped YAML config files are entirely decorative (see below), the `-k/--kill` flag is a stub that logs and exits without signaling anything, `--log-file` is parsed but never used, the daemon performs **no NRF registration** (its state machine contains `nnrf-nfm` handlers but nothing initiates a registration and there is no NRF URI flag), and a zero-trust policy module (`zero_trust.rs`, TS 33.501 §13 per its header comment) is compiled in but not invoked on any runtime path.

## Example configuration

From `nextgcore/docker/rust/configs/sepp1.yaml` (the home-PLMN SEPP):

```yaml
# NextGCore SEPP1 (Security Edge Protection Proxy) Configuration
# Home PLMN SEPP for Docker deployment with Rust implementation

logger:
  file:
    path: /var/log/nextgcore/sepp1.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

sepp:
  default:
    tls:
      server:
        private_key: /etc/nextgcore/tls/sepp1.key
        cert: /etc/nextgcore/tls/sepp1.crt
      client:
        cacert: /etc/nextgcore/tls/ca.crt
  sbi:
    server:
      - address: 172.22.0.51
        port: 7777
    client:
      scp:
        - uri: http://172.22.0.50:7777
      nrf:
        - uri: http://172.22.0.10:7777
  n32:
    server:
      - sender: sepp1.localdomain
        scheme: https
        address: 172.22.0.51
        port: 7778
        n32f:
          scheme: https
          address: 172.22.0.51
          port: 7779
    client:
      sepp:
        - receiver: sepp2.localdomain
          uri: https://sepp2.localdomain:7778
          resolve: 172.22.0.52
          n32f:
            uri: https://sepp2.localdomain:7779
            resolve: 172.22.0.52
```

The variant `sepp2.yaml` (visited-PLMN SEPP) is the mirror image: log path `sepp2.log`, TLS key/cert `sepp2.key`/`sepp2.crt`, SBI/N32 address `172.22.0.52`, sender `sepp2.localdomain`, and the peer entry pointing back at `sepp1.localdomain` (`172.22.0.51`).

Neither file is mounted by any compose file. The shipped `docker-compose.yml` runs the single `sepp` service with `command: ["--sbi-addr", "172.23.0.38", "--sbi-port", "7777"]` and no config volume — note the YAML files even reference a different subnet (`172.22.0.x`) than the live deployment (`172.23.0.x`).

## YAML parameters

**None.** This binary defines no `#[derive(Deserialize)]` configuration structs. In `src/bins/nextgcore-seppd/src/main.rs`, if the `--config` path exists the file is read with `std::fs::read_to_string` and the daemon logs `Configuration file loaded (N bytes)` — the content is never parsed. (The `serde::Deserialize` derives elsewhere in the crate — `n32c_build.rs`, `n32c_handler.rs`, `prins.rs`, `jose.rs`, `n32_server.rs` — are N32-c/N32-f wire-message types, not configuration.) All configuration is via CLI flags below.

### Parsed-but-inert / decorative YAML fields

Everything in the shipped example YAML is inert. The functional equivalents, where they exist, are CLI flags:

- **`logger.level` / `logger.file.path`** — inert. Log level comes only from `-e/--log-level` (default `info`); there is no working log-file output (`--log-file` is declared in the `Args` struct but never referenced again).
- **`sepp.sbi.server[]` (address/port)** — inert. The consumer SBI bind comes from `--sbi-addr`/`--sbi-port`.
- **`sepp.n32.server[]` (sender/scheme/address/port/n32f)** — inert. Use `--n32-addr`/`--n32-port` (single listener; the separate n32f port in the YAML has no equivalent — N32-c and N32-f share one listener) and `--sender` for the FQDN.
- **`sepp.n32.client.sepp[]` (receiver/uri/resolve)** — inert. Peers come from repeatable `--peer-sepp fqdn=apiroot` flags; there is no `resolve` (DNS-override) equivalent.
- **`sepp.default.tls.*`** — inert. Use `--tls`, `--tls-cert`, `--tls-key`, `--n32-mtls-cacert`, `--n32-client-cert`, `--n32-client-key`, `--n32-ca-cert`.
- **`sepp.sbi.client.nrf[].uri` / `sepp.sbi.client.scp[].uri`** — inert with **no CLI equivalent at all**: the daemon never contacts an NRF or SCP.
- **`global.max.ue` / `global.max.peer`** — inert. The real pool limits are `--max-node` and `--max-assoc`.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-seppd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/sepp.yaml` | Configuration file path (read but not parsed — see above). |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `-l, --log-file` | path | unset | Declared but **never used** — no file logging is wired up. |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM" and exits; does not signal anything. |
| `--sbi-addr` | string | `127.0.0.1` | Consumer-facing SBI server bind address (docker passes `172.23.0.38`). |
| `--sbi-port` | u16 | `7777` | Consumer-facing SBI server port. |
| `--n32-addr` | string | unset | N32 listener address. The N32 listener starts **only** if both `--n32-addr` and `--n32-port` are given. |
| `--n32-port` | u16 | unset | N32 listener port. |
| `--tls` | flag | off | Enable TLS on both the SBI server and the N32 listener/client. |
| `--tls-cert` | path | unset | TLS server certificate (PEM). |
| `--tls-key` | path | unset | TLS server private key (PEM). |
| `--sender` | string | unset | This SEPP's FQDN; when set it is sent as `3gpp-sbi-sender-sepp` on N32-f, otherwise the header is omitted. |
| `--max-node` | usize | `16` | Maximum peer SEPP nodes in the context pool. |
| `--max-assoc` | usize | `8192` | Maximum associations in the context pool. |
| `--serving-plmn` | string, repeatable | empty | Serving PLMN as `mcc:mnc` (e.g. `999:70`); malformed values are warned about and ignored. Used to decide whether a target FQDN is in a *visited* PLMN. |
| `--prins` | flag | off | Advertise the PRINS security capability in addition to TLS. |
| `--peer-sepp` | string, repeatable | empty | Peer SEPP as `fqdn=apiroot` (e.g. `sepp.visited.com=http://10.0.0.2:7778`); one N32-c handshake is initiated per entry at startup. |
| `--n32-mtls-cacert` | path | unset | CA bundle for verifying peer-SEPP *client* certificates on the N32 listener (mTLS). Falls back to `--n32-ca-cert` if unset. |
| `--n32-client-cert` | path | unset | Client certificate presented on outgoing N32 connections (mTLS). |
| `--n32-client-key` | path | unset | Client private key for outgoing N32 connections. |
| `--n32-ca-cert` | path | unset | CA bundle for verifying peer-SEPP *server* certificates. |
| `--n32-allow-insecure-no-mtls` | flag | off | LAB USE ONLY: disable mandatory mTLS on the N32-c listener. Per the code comment, N32-c is mutually-authenticated TLS per TS 33.501, so mTLS is on by default whenever `--tls` is set and a client CA is available. |
| `--allow-insecure-no-tls` | flag | off | LAB/TEST ONLY: permit deriving the N32-f key hierarchy from a deterministic no-TLS fallback when the RFC 5705 exporter secret is unavailable. Strict by default: without it, `exchange-params` fails when no TLS exporter exists (TS 33.501 §13.2.4.4.1 per code comment). |

## Behavior notes

- **Forwarding admission** (consumer SBI handler in `n32_server.rs`): a request without a `3gpp-sbi-target-apiroot` header is rejected **400** `MANDATORY_IE_INCORRECT`; a target FQDN that is not in a visited PLMN or has no matching peer SEPP gets **404** `TARGET_NF_NOT_REACHABLE`; a matched peer whose N32-c handshake is not `Established` gets **503**; an N32-f relay failure returns **502 Bad Gateway**. Peer selection parses the MCC/MNC out of `*.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org` FQDNs, so non-`3gppnetwork.org` targets and FQDNs naming a `--serving-plmn` are never forwarded.
- **N32-c mTLS is mandatory by default.** With `--tls` set but no client CA (`--n32-mtls-cacert` or `--n32-ca-cert`) and no `--n32-allow-insecure-no-mtls`, the N32 listener refuses to start with an explicit error. With the escape hatch it starts but warns loudly that peers will not be client-authenticated.
- **Handshake at startup, no automatic retry from `main`.** One N32-c handshake (exchange-capability, plus exchange-params when PRINS is negotiated) is attempted per `--peer-sepp` entry at startup; a failure is logged (`Peer SEPP [...] handshake failed`) and the peer stays unestablished, so forwarding toward it keeps returning 503. A capability mismatch is a negotiation failure per TS 29.573 (code comment). Reconnect timer plumbing exists (`TimerConfig` defaults: 3000 ms, 10000 ms in exception state) but registration/heartbeat toward an NRF is never initiated — this NF does not register with the NRF, unlike the other NextGCore NFs (`docker-compose.yml`'s `depends_on: nrf` is ordering only).
- **PRINS key material** is derived exclusively from the N32-c TLS RFC 5705 exporter (label `EXPORTER_3GPP_N32_MASTER`, 64 octets, TS 33.501 §13.2.4.4.1 per code comments); JWE suites offered are A256GCM (preferred) and A128GCM with ES256 JWS for modifications (TS 33.501 §13.2.4.9 / §13.2.4.6 per code comments). On plaintext lab transports, key derivation only works with `--allow-insecure-no-tls`, which logs a prominent warning.
- **Received `n32f-error` reports** (TS 29.573 §6.1.5.4 per code comment) are logged, counted, and kept in an in-memory queue drainable by operators/tests; there is no state file — all peer/handshake state is in-memory and lost on restart.
- **Environment variables:** the only one read is `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP trace exporter endpoint, default `http://jaeger:4317`). `RUST_LOG` — although set by the docker compose environment — is **ignored** by this binary; the log level is controlled solely by `-e/--log-level`.
