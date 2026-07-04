# UPF Configuration

The UPF (User Plane Function, `nextgcore-upfd`) terminates the N4/PFCP interface toward the SMF and the N3/GTP-U interface toward the gNB, and forwards user traffic through a TUN device.

> **Important — how the UPF is actually configured:** unlike most other NextGCore NFs, `nextgcore-upfd` currently takes its runtime settings from **command-line flags**, not from the YAML file. The `-c/--config` flag points at a YAML file, and if that file exists the daemon reads it — but it only logs the file size (`main.rs`, "Configuration file loaded (N bytes)") and **does not deserialize or apply any of its contents**. There is no `#[derive(Deserialize)]` config struct in the UPF binary. The entire YAML file is therefore parsed-but-inert today; it is shipped for deployment-layout consistency with the other NFs (Docker/k8s/Helm mount it), and CLI flags are the source of truth.

## Example YAML (`docker/rust/configs/5gc/upf.yaml`)

This is the file mounted in the Docker E2E deployment. Every key below is currently ignored by the daemon (see note above):

```yaml
# UPF (User Plane Function) Configuration
# Docker container configuration for 5G Core deployment

logger:
  file:
    path: /var/log/nextgcore/upf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

upf:
  pfcp:
    server:
      - address: 172.23.0.7
        port: 8805
  gtpu:
    server:
      - address: 172.23.0.7
        port: 2152
  session:
    - subnet: 10.45.0.0/16
      gateway: 10.45.0.1
      dev: ogstun
    - subnet: 2001:db8:cafe::/48
      gateway: 2001:db8:cafe::1
      dev: ogstun
  metrics:
    server:
      - address: 172.23.0.7
        port: 9090
  # TLS configuration (G36: SBI TLS)
  # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
  tls:
    enabled: false
    cert: /etc/nextgcore/certs/upf.crt
    key: /etc/nextgcore/certs/upf.key
    ca: /etc/nextgcore/certs/ca.crt
    min_version: "1.2"
```

In Docker deployments the container is instead launched with matching CLI flags; the YAML values above mirror those flags but do not drive them.

## Effective parameters (CLI flags, `Args` struct in `bins/nextgcore-upfd/src/main.rs`)

Defaults below are the real clap `default_value`s from the source.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-c, --config` | string | `/etc/nextgcore/upf.yaml` | Configuration file path. Read if present, but contents are not applied (see note above). |
| `-l, --log-file` | string | *(none)* | Log file path. |
| `-e, --log-level` | string | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error`. |
| `-m, --no-color` | bool | `false` | Disable colored log output. |
| `-k, --kill` | bool | `false` | Kill a running instance (currently logs intent and exits). |
| `--pfcp-addr` | string | `127.0.0.4` | N4 PFCP server bind address. |
| `--pfcp-port` | u16 | `8805` | N4 PFCP server port. |
| `--gtpu-addr` | string | `127.0.0.4` | N3 GTP-U bind address. |
| `--gtpu-port` | u16 | `2152` | N3 GTP-U port. |
| `--tun-ifname` | string | `ogstun` | TUN interface name for the user-plane subnet. |
| `--tun-ip` | IPv4 | `10.45.0.1` | TUN interface IP address (UE subnet gateway). |
| `--tun-prefix` | u8 | `16` | TUN interface prefix length. |
| `--max-sessions` | usize | `1024` | Maximum number of PFCP sessions (sizes the UPF context). |
| `--no-dataplane` | bool | `false` | Disable the TUN data plane; control-plane-only mode (no user traffic forwarding). |
| `--nrf-uri` | string | `""` (empty = disabled) | Opt-in NRF base URI (e.g. `http://127.0.0.10:7777`). When set, the UPF registers a UPF NFProfile and PATCHes a real PFCP-session `/load` gauge on each heartbeat (code comment cites TS 29.510 §5.2.2.3.2). Empty disables the SBI/NRF plane entirely; NRF failures are log-only and never affect packet forwarding. |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OTLP endpoint for OpenTelemetry tracing (initialization is best-effort; failure is ignored). |

## Behavior notes

- **PFCP heartbeats:** the UPF also initiates PFCP heartbeats toward the associated CP function every 10 seconds (code comment cites TS 29.244 §6.2.2: either node may initiate).
- **Reports:** the data plane emits Downlink Data Reports (on first buffered downlink packet) and Error Indication Reports over N4.
- **Validation status:** UPF behavior has been exercised in the project's matched-simulator Docker E2E suite (UE→UPF GTP-U traffic). This is internal test validation, not third-party conformance certification.

## Parsed-but-inert summary

| YAML section | Status |
|--------------|--------|
| `logger.*` | Ignored — use `-l` / `-e` flags. |
| `global.max.*` | Ignored — use `--max-sessions`. |
| `upf.pfcp.server` | Ignored — use `--pfcp-addr` / `--pfcp-port`. |
| `upf.gtpu.server` | Ignored — use `--gtpu-addr` / `--gtpu-port`. |
| `upf.session` | Ignored — use `--tun-ifname` / `--tun-ip` / `--tun-prefix` (single IPv4 subnet only via CLI; the YAML's IPv6 entry has no CLI equivalent). |
| `upf.metrics.server` | Ignored by the UPF binary. |
| `upf.tls.*` | Ignored by the UPF binary; the deployment's TLS switch is the `TLS_ENABLED` / `SBI_SCHEME` compose environment, per the file's own comment. |
