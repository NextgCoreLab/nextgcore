# SMF Configuration

The SMF (Session Management Function, `nextgcore-smfd`) handles PDU session management over N4 (PFCP to UPF), N7 (PCF), N10 (UDM), N11 (AMF), and S5/S8 GTP-C in EPC mode.

The config file path is resolved in this order: the `-c`/`--config` CLI argument, then the `SMF_CONFIG` environment variable, then `/etc/nextgcore/smf.yaml`. If the file is missing or fails to parse, the SMF logs a warning and starts with built-in defaults rather than exiting.

## Example (`docker/rust/configs/5gc/smf.yaml`)

```yaml
logger:
  file:
    path: /var/log/nextgcore/smf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

smf:
  sbi:
    server:
      - address: 172.23.0.4
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
  pfcp:
    server:
      - address: 172.23.0.4
        port: 8805
    client:
      upf:
        - address: 172.23.0.7
  gtpc:
    server:
      - address: 172.23.0.4
  gtpu:
    server:
      - address: 172.23.0.4
  metrics:
    server:
      - address: 172.23.0.4
        port: 9090
  session:
    - subnet: 10.45.0.0/16
      gateway: 10.45.0.1
    - subnet: 2001:db8:cafe::/48
      gateway: 2001:db8:cafe::1
  dns:
    - 8.8.8.8
    - 8.8.4.4
    - 2001:4860:4860::8888
    - 2001:4860:4860::8844
  mtu: 1400
  tls:
    enabled: false
    cert: /etc/nextgcore/certs/smf.crt
    key: /etc/nextgcore/certs/smf.key
    ca: /etc/nextgcore/certs/ca.crt
    min_version: "1.2"
```

## Parsed parameters

The typed loader (`SmfYaml`/`SmfConfig` in `src/bins/nextgcore-smfd/src/main.rs`) deserializes only the `smf.sbi` subtree. Only the **first** entry of each list is used.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `smf.sbi.server[0].address` | string | `0.0.0.0` | Bind address for the SBI HTTP/2 server. |
| `smf.sbi.server[0].port` | u16 | `7777` | SBI server port. Address+port also derive the advertised callback base URI (with `0.0.0.0` replaced by `127.0.0.1` unless `SMF_SBI_ADVERTISE_URI` is set). |
| `smf.sbi.client.nrf[0].uri` | string | none | NRF base URI; seeded into the SBI context for NF registration. Without it the SMF operates NRF-less. |
| `smf.sbi.oauth2.require` | bool | `false` | Opt-in SBI OAuth2 enforcement (TS 33.501 §13.4.1, TS 29.510 §5.4.2, per code comments). Read by a separate generic YAML scan: true if *any* top-level section sets it, or if `NEXTGCORE_SBI_OAUTH2_REQUIRE=1/true/yes`. With no NRF URI configured the producer side fails closed (503). |

### Internal defaults not settable via YAML

`SmfConfig` also carries context-sizing limits, but the parsed struct has no YAML fields for them — they are always the hard-coded defaults:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_ue` | usize | `1024` | UE context pool size (also used as capacity basis for the NRF load gauge, TS 29.510 §5.2.2.3.2 per code comment). |
| `max_sess` | usize | `4096` | PDU session context pool size. |
| `max_bearer` | usize | `8192` | Bearer/QoS-flow context pool size. |

## Environment variables

The N4/PFCP endpoints are configured by environment variables, **not** by the `smf.pfcp` YAML section:

| Variable | Default | Description |
|---|---|---|
| `SMF_CONFIG` | `/etc/nextgcore/smf.yaml` | Config file path (overridden by `-c`/`--config`). |
| `SMF_PFCP_ADDR` / `SMF_PFCP_PORT` | `0.0.0.0` / `8805` | N4 PFCP bind address (single socket; sequence-number matching per TS 29.244 §7.2.1, per code comment). `SMF_PFCP_ADDR` also supplies the PFCP Node ID (falls back to `127.0.0.1` if not a dotted IPv4). |
| `UPF_PFCP_ADDR` / `UPF_PFCP_PORT` | `127.0.0.1` / `8805` | UPF N4 peer address. |
| `SMF_SBI_ADVERTISE_URI` | derived from SBI server address/port | Externally reachable base URI used in PCF callback (`notificationUri`) URIs. |
| `NEXTGCORE_SBI_OAUTH2_REQUIRE` | unset | `1`/`true`/`yes` forces OAuth2 enforcement, taking precedence over the YAML knob. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OpenTelemetry OTLP trace exporter endpoint. |

## Parsed-but-inert YAML sections

The example file follows an Open5GS-style layout, but the typed deserializer ignores everything outside `smf.sbi` (unknown keys are silently dropped). The following sections in the shipped example currently have **no effect** on `nextgcore-smfd`:

- `logger` — logging is controlled by `env_logger` (`RUST_LOG`, default `info`), not this section.
- `global.max.ue` / `global.max.peer` — not read; context limits use the hard-coded defaults above.
- `smf.pfcp` — PFCP addressing comes from the `SMF_PFCP_*` / `UPF_PFCP_*` environment variables.
- `smf.gtpc`, `smf.gtpu`, `smf.metrics` — not deserialized by the config structs.
- `smf.session` (UE IP subnets/gateways), `smf.dns`, `smf.mtu` — not deserialized by the config structs.
- `smf.tls` — not read by the SMF loader; the file comment ties TLS to `TLS_ENABLED`/`SBI_SCHEME` deployment variables.

## Honesty notes

- Behavior above is grounded in `nextgcore/src/bins/nextgcore-smfd/src/main.rs` and the docker example config; 3GPP TS references are quoted from code comments, not a conformance claim.
- The SMF is validated in matched-simulator and docker E2E runs against nextgsim peers; it has not been certified against third-party equipment or an external conformance suite.
- There is no `nextgcore/configs/smf.yaml`; example configs live at `docker/rust/configs/5gc/smf.yaml` (plus `k8s/manifests/smf.yaml` and the Helm template).
