# PIN Configuration

The PIN server (Personal IoT Network, `nextgcore-pind`) manages Personal IoT Networks: PIN creation and lifecycle, PIN Element (PINE) registration/discovery, PEGC gateway relay paths, and per-element liveness heartbeats, per TS 23.542 (as cited in the daemon's source comments, which model the PIN-6 §6.4.7, PIN-7 §6.4.8, and PIN-8 §6.4.9 reference points). Per those same code comments, the PIN server is an *application-enablement-layer* entity, **not** a 5GC SBI Network Function — there is no `PIN` NfType in TS 29.510 and no `Npin_PINManagement` service in 3GPP — so the daemon deliberately does **not** register with the NRF. It serves a NextGCore-internal REST binding under the `/pinapp/v1` prefix: `POST/GET /pinapp/v1/pins`, `GET/DELETE /pinapp/v1/pins/{pinId}`, `POST/GET /pinapp/v1/pins/{pinId}/elements` (register/discover), `GET/DELETE /pinapp/v1/pins/{pinId}/elements/{elementId}`, `PUT .../elements/{elementId}/heartbeat`, and `PUT /pinapp/v1/elements/{elementId}/relay`.

Configuration is CLI-flags-only. The clap `Args` struct accepts `-c/--config` with default path `/etc/nextgcore/pin.yaml`, but the daemon **never opens or parses that file** — there are no `#[derive(Deserialize)]` config structs anywhere in the crate, and `args.config` is referenced only by a unit test asserting its default value. Every runtime knob (bind address/port, TLS, pool sizes, lifecycle defaults, trust policy) is a CLI flag; two environment variables (`RUST_LOG`, `OTEL_EXPORTER_OTLP_ENDPOINT`) are also read (see Behavior notes).

> **Honesty note:** PIN behavior is validated by this project's own unit tests and matched-simulator docker E2E only, not by third-party conformance certification. The `/pinapp/v1` REST binding is a bespoke NextGCore-internal API modelling TS 23.542 procedures — 3GPP defines no Stage-3 wire protocol for a PIN SBI service, so nothing here is normative on the wire. The `x-caller-supi` header is a bespoke, unverified NextGCore extension (per the PIND-10 code comments), trusted only when explicitly enabled.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/pin.yaml`:

```yaml
# PIN (Personal IoT Network) Manager Configuration
logger:
  level: info

pin:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.35
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
```

The docker deployment mounts this file at `/etc/nextgcore/pin.yaml` (read-only) but configures the daemon entirely via its `command:` line: `--sbi-addr 172.23.0.35 --sbi-port 7815 --nrf-uri http://172.23.0.10:7777` (`docker/rust/docker-compose.yml`).

## YAML parameters

**None.** Unlike the other NF daemons, `nextgcore-pind` deserializes no YAML at all: there is no config-file `#[derive(Deserialize)]` struct in `src/bins/nextgcore-pind/src/main.rs` or `context.rs` (`serde_json` is used only for HTTP request/response bodies), and the `--config` path is parsed by clap but never read from disk. All configuration comes from the command-line flags below.

### Parsed-but-inert / decorative YAML fields

Because the daemon never reads the file, **every field in the shipped example YAML is decorative**:

- **`logger.level` is inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`) or the `RUST_LOG` environment variable.
- **`pin.sbi.server[]` (address/advertise/port) is inert.** The SBI bind address and port come from `--sbi-addr`/`--sbi-port`. Note the example file says port `7777` while the docker deployment actually launches the daemon with `--sbi-port 7815` — the YAML value is not consulted.
- **`pin.nrf.uri` is inert.** The NRF location comes from `--nrf-uri`, and is used only to locate the NRF JWKS endpoint when OAuth2 enforcement is on (the daemon does not register with the NRF at all).

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-pind/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/pin.yaml` | Configuration file path. **Accepted but never read** — the daemon performs no YAML parsing. |
| `-l, --log-file` | path | unset | Declared but not applied — the field is never read after parsing; logging goes to env_logger's default output. |
| `-e, --log-level` | string | `info` | Log level, used as the env_logger default filter. `RUST_LOG`, when set, takes precedence. |
| `-m, --no-color` | flag | off | Declared but not applied — the field is never read after parsing. |
| `--sbi-addr` | string | `0.0.0.0` | Server bind address (docker passes `172.23.0.35`). |
| `--sbi-port` | u16 | `7815` | Server port. The docker deployment also uses `7815` (not `7777` like most NFs). |
| `--tls` | flag | off | Enable TLS on the server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-pins` | usize | `1024` | Maximum concurrent PINs in the context pool. At the cap, PIN create fails with HTTP **507** `MAX_PINS_REACHED`. |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | Used **only** to derive the NRF JWKS URI when `--require-oauth2` is set (PIND-10 per code comment). No NF registration or heartbeat is performed. |
| `--require-oauth2` | flag | off | Enforce OAuth2 bearer-token verification on every request (signature + expiry against the NRF JWKS; TS 33.501 §13.4 per code comment). No audience check is set, since PIN is not a TS 29.510 NfType. Also enables trusting the verified token `sub` claim as the caller identity. |
| `--trust-caller-supi-header` | flag | off | Trust the bespoke `x-caller-supi` and `3gpp-Sbi-Consumer-Info` (TS 29.500 §5.2.3 per code comment) headers as caller identity. Off by default because they are unverified and forgeable; enable only on a mutually-authenticated intra-core transport. |
| `--default-pin-lifetime-secs` | u64 | `86400` | Default PIN lifetime assigned as the Expiration time at PIN create (TS 23.542 Table 8.5.2.3.3-1 per code comment). |
| `--default-heartbeat-secs` | u64 | `30` | Default per-PIN Heartbeat Timer assigned at PIN create. |
| `--require-pegc-at-create` | flag | off | When set, PIN creation fails with HTTP **409** `NO_PEGC_AVAILABLE` (TS 23.542 §8.5.2.2 per code comment) unless the owner already has a gateway-capable element (or a PEMC acting as PEGC) registered. Off by default so a fresh owner can bootstrap their first PIN. |
| `--reaper-interval-secs` | u64 | `30` | Background liveness-reaper interval. `0` disables the reaper entirely. |

## Behavior notes

- **No NRF registration.** Per the PIND-01 code comment, the former `register_with_nrf` helper (which advertised an invented `nfType: "PIN"`) was removed; the daemon never registers, heartbeats, or deregisters with the NRF. Service discovery for the PIN application is out of band of the 5GC SBA. `--nrf-uri` exists solely for JWKS fetch under `--require-oauth2`.
- **Caller-identity ladder (PIND-10).** Identity is resolved in priority order: (1) the verified JWT `sub` claim — honored only when `--require-oauth2` is on, since the server layer has already cryptographically verified the token; (2) `x-caller-supi`; (3) `3gpp-Sbi-Consumer-Info` — both honored only under `--trust-caller-supi-header`. With neither trust source enabled, every caller is anonymous and all **management** operations are denied (per the code's own doc comment, "every management/state-changing operation"): PIN create fails with **403** `AUTHENTICATION_REQUIRED`, and PIN delete and element deregister fail with **403** because the owner-or-PEMC authorization check never matches an empty caller. Anonymous callers can still change state through the non-management endpoints: element registration succeeds (**201**) with any requested PEMC/PEGC role downgraded to Regular (see the next-but-one bullet), and `PUT .../heartbeat` and `PUT .../relay` perform no caller-identity check at all — heartbeat updates the element's liveness state for anyone, and relay sets the relay path on any element that is a PEGC.
- **Admission/rejection semantics.** PIN create requires an authenticated caller (else **403** `AUTHENTICATION_REQUIRED`) whose identity matches the asserted `ueId` (else **403** `UE_ID_MISMATCH`); missing mandatory IEs (`ueId`/`securityCredentials` on create, `ueIdentifier`/`securityCredentials`/`pineAddress`/`port` on element register — TS 23.542 Tables 8.5.2.3.2-1 and 8.4.2.3.2-1 per code comments) return **400** `MANDATORY_IE_MISSING`. A successful create returns **201** carrying `pinId`, `expirationTime`, and `heartbeatTimer`. Role-authorization failures (non-owner delete/deregister, relay on a non-PEGC) return **403** `application/problem+json` with NextGCore-specific `urn:nextgcore:pin:*` type URIs.
- **Role gating, not rejection, on element register.** A non-owner requesting a `MANAGEMENT` (PEMC) element is still registered (**201**) but silently downgraded to a regular element; `roleOfPemc`/`roleOfPegc` are echoed `true` only when the role was actually granted (PIND-06).
- **Liveness reaper (PIND-09).** Every `--reaper-interval-secs`, elements whose last heartbeat is older than their heartbeat timer are deregistered (a timer of `0` exempts an element) and PINs past their expiration time are deleted with cascade removal of members. Losing a primary PEMC or default PEGC triggers the PIND-07 role take-over (TS 23.542 §8.5.10 per code comment), promoting the lowest-id secondary/backup. `PUT .../elements/{id}/heartbeat` (TS 23.542 §8.8 per code comment) resets the deadline.
- **No persistence; environment variables.** All PIN/element state lives in in-memory maps — there is no state file, so a restart loses everything. The binary reads two environment variables: `RUST_LOG` (overrides `-e/--log-level` via env_logger) and `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP trace exporter endpoint, default `http://jaeger:4317` when unset).
