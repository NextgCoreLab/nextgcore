# NRF Configuration

The NRF (Network Repository Function, `nextgcore-nrfd`) handles NF registration, discovery, status notifications, and acts as the OAuth2 Authorization Server for the SBI (per code comments citing 3GPP TS 29.510 and TS 33.501). It reads a YAML file whose path defaults to `/etc/nextgcore/nrf.yaml` (override with `-c/--config`).

**Important:** the NRF's typed config (`NrfYaml` in `src/bins/nextgcore-nrfd/src/main.rs`) only parses the `nrf:` section. The `logger:`, `global:`, `nrf.serving:`, and `nrf.sbi.server:` blocks in the shipped example are accepted but **not consumed by nrfd** — listen address/port and TLS come from CLI flags instead (`--sbi-addr`, `--sbi-port`, `--tls`, `--tls-cert`, `--tls-key`, `--mtls`, `--tls-ca-cert`). If the file is absent or fails to parse, conservative built-in defaults apply and startup continues.

## Example (`docker/rust/configs/5gc/nrf.yaml`)

```yaml
logger:
  file:
    path: /var/log/nextgcore/nrf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

nrf:
  serving:
    - plmn_id:
        mcc: 999
        mnc: 70
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.10
        port: 7777
        tls:
          enabled: false
          cert: /etc/nextgcore/certs/nrf.crt
          key: /etc/nextgcore/certs/nrf.key
          ca: /etc/nextgcore/certs/ca.crt
          # Minimum TLS version per 3GPP TS 33.501 §13.2
          min_version: "1.2"
```

## Parsed parameters (`nrf:` section)

Defaults below are the real values from `NrfPolicy::default()` and its constants in `main.rs`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `nrf.heartBeatTimer` | u32 (seconds) | `10` | NRF-preconfigured heartbeat default, used when an NF proposes no `heartBeatTimer` or an out-of-range one (code cites TS 29.510 Table 6.1.6.2.2-1). |
| `nrf.heartBeatTimerMin` | u32 (seconds) | `1` | Lower bound of accepted heartbeat proposals; proposals below are overridden to the default. |
| `nrf.heartBeatTimerMax` | u32 (seconds) | `3600` | Upper bound of accepted heartbeat proposals. The no-heartbeat supervision timer fires at 2x the negotiated interval. |
| `nrf.discovery.validity_period` | u32 (seconds) | `3600` | `validityPeriod` stamped into discovery SearchResults. |
| `nrf.discovery.default_page_size` | usize | `100` | Discovery page size when the consumer specifies none (values ≤ 0 ignored). |
| `nrf.discovery.max_page_size` | usize | `1000` | Cap on consumer-requested discovery page size. |
| `nrf.sbi.oauth2.require` | bool | `false` | Client-side: the NRF attaches NRF-issued Bearer tokens to its own outbound calls (status notifications). |
| `nrf.sbi.oauth2.require_server` | bool | `false` | Server-side OAuth2 enforcement on the NRF's own `nnrf-nfm`/`nnrf-disc` producer endpoints. The `/nnrf-oauth2/v1/access-token` and `/jwks` endpoints always stay exempt (the NRF is the Authorization Server). |
| `nrf.sbi.oauth2.require_client_auth` | bool | `false` | Token endpoint requires client authentication: a Client-Credentials-Assertion (CCA) bound to the body `nfInstanceId`, or an mTLS client identity. |
| `nrf.sbi.oauth2.require_client_cert_binding` | bool | `false` | Mandates a transport-authenticated (mTLS) client identity — conveyed via `x-forwarded-client-cert` — whose URI SAN matches the request `nfInstanceId` (code cites TS 33.501 §13.3.1/§13.4.1, TS 33.310). Mismatch checks always run when an identity is present, even with this off. |
| `nrf.sbi.oauth2.cca_verify_signature` | bool | `false` | Cryptographically verify the CCA's ES256 JWS signature against `cca_trusted_keys` (code cites TS 33.501 §13.3.8.3). Fail-closed for issuers with no trusted key. |
| `nrf.sbi.oauth2.cca_trusted_keys` | list | empty | Entries of `nfInstanceId` + RFC 7517 EC/P-256 `jwk`. Malformed keys are logged and dropped (the issuer then fails closed when verification is on). |

## Parsed-but-inert / non-YAML settings

- `logger`, `global.max.{ue,peer}`, `nrf.serving[].plmn_id`, and `nrf.sbi.server[]` (address, advertise, port, tls block) are present in the example YAML but ignored by nrfd's config structs. Equivalent runtime behavior comes from CLI flags: `--sbi-addr` (default `0.0.0.0`), `--sbi-port` (default `7777`), `--max-ue` (default `1024`), `--log-level` (default `info`), `--log-file`, and the TLS/mTLS flags.
- `--nf-instance-id` sets the NRF's NF Instance ID (OAuth2 `iss` per TS 29.510 §6.3.5.2.4, per code comments); auto-generated UUID otherwise.
- `--state-file` (or `NEXTGCORE_NRF_STATE_FILE`) enables JSON-snapshot persistence of the NF registry; without it the registry is in-memory and lost on restart.
- Env overrides `NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH` and `NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING` (`1`/`true`) force those knobs **on** only; they never turn a YAML-enabled knob off.
- `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry export target (default `http://jaeger:4317`).

## Honesty notes

- All security knobs default **off** so the matched in-house simulator keeps working; enabling them is a deliberate operator step.
- Behavior is validated against the project's matched simulator and unit/E2E tests, not third-party certified. Statements above describe what the code does; TS references are those cited in code comments, not conformance claims.
