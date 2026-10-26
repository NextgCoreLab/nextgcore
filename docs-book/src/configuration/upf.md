# UPF Configuration

The UPF (User Plane Function, `nextgcore-upfd`) terminates the N4/PFCP interface toward the SMF and the N3/GTP-U interface toward the gNB, and forwards user traffic through a TUN device.

> **Important — how the UPF is actually configured:** unlike most other NextGCore NFs, `nextgcore-upfd` currently takes its runtime settings from **command-line flags**, not from the YAML file. The `-c/--config` flag points at a YAML file, and if that file exists the daemon reads it — but it only logs the file size at `debug` level (`main.rs`, "Configuration file loaded (N bytes)") and **does not deserialize or apply any of its contents**. There is no `#[derive(Deserialize)]` config struct in the UPF binary. The entire YAML file is therefore parsed-but-inert today; it is shipped for deployment-layout consistency with the other NFs (Docker/k8s/Helm mount it), and CLI flags are the source of truth.

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
| `-e, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `-m, --no-color` | bool | `false` | Disable colored log output. |
| `-k, --kill` | bool | `false` | Not supported: logs an error and exits non-zero without signalling anything; stop the NF through its supervisor. |
| `--pfcp-addr` | string | `127.0.0.4` | N4 PFCP server bind address. |
| `--pfcp-port` | u16 | `8805` | N4 PFCP server port. |
| `--pfcp-allowed-peers` | list | empty | SMF/PGW-C hosts allowed to set up the PFCP association: IPs, CIDR prefixes or host names (re-resolved every 10 s, and at once -- at most once a second -- when a Setup comes from an unresolved address; a failed lookup keeps the last good addresses), comma-separated; `UPF_PFCP_ALLOWED_PEERS` when the flag is not given. Only the source IP is compared. A listed host may move a live association only as the same CP function (one of its hosts, or the same Node ID); a different CP function is refused until the association is released or times out. The Node ID is sender-written, so a broad entry (a pod CIDR, `0.0.0.0/0`) lets any host in range that knows the SMF's Node ID take the association over: prefer the SMF's own address or headless Service name. **Fail closed:** empty refuses every Association Setup (logged as an error at startup); `0.0.0.0/0` / `::/0` admit any host (labs only). The shipped compose, Helm, k8s and EKS deployments set it. Every PFCP message other than Heartbeat and Association Setup is accepted only from the associated SMF's hosts (its Setup source, its IPv4/IPv6 Node ID, or the addresses its FQDN Node ID resolves to); refusals count in `upf_pfcp_unauthorized_messages_total`. |
| `--gtpu-addr` | string | `127.0.0.4` | N3 GTP-U bind address. |
| `--gtpu-port` | u16 | `2152` | N3 GTP-U port. |
| `--gtpu-addr6` | IPv6 | unset | IPv6 N3 GTP-U address. When set, a second GTP-U socket is bound on it (same port), and N3 runs over IPv6 in both directions. Downlink to an IPv6 gNB uses it. A local F-TEID the SMF asks for with CH+V6 carries this address. An Error Indication for a G-PDU that arrived over IPv6 names it as the GTP-U Peer Address. Outer DSCP is marked through IPV6_TCLASS. The address is advertised, so it must be a unicast address of this host: `::` and multicast addresses are refused at startup. Unset: downlink to an IPv6 gNB is dropped and counted, and a PDR asking for CH+V6 alone is refused with Rule creation/modification failure (CH+V4+V6 gets the IPv4 address). |
| `--tun-ifname` | string | `ogstun` | TUN interface name for the user-plane subnet. |
| `--tun-ip` | IPv4 | `10.45.0.1` | TUN interface IP address (UE subnet gateway). |
| `--tun-prefix` | u8 | `16` | TUN interface prefix length. |
| `--max-sessions` | usize | `1024` | Maximum number of PFCP sessions (sizes the UPF context). |
| `--no-dataplane` | bool | `false` | Disable the TUN data plane; control-plane-only mode (no user traffic forwarding). |
| `--nrf-uri` | string | `""` (empty = disabled) | Opt-in NRF base URI (e.g. `http://127.0.0.10:7777`). When set, the UPF registers a UPF NFProfile and PATCHes a real PFCP-session `/load` gauge on each heartbeat (code comment cites TS 29.510 §5.2.2.3.2). Empty disables the SBI/NRF plane entirely; NRF failures are log-only and never affect packet forwarding. |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UPF_METRICS_PORT` | `9090` | Prometheus `/metrics` port, including the TUN-path data-plane counters (#581). |
| `NEXTGCORE_METRICS_BIND` | `127.0.0.1` | Host the unauthenticated `/metrics` listener binds to (#837). The compose files and manifests set `0.0.0.0` inside the private container/pod network. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OTLP endpoint for OpenTelemetry tracing (initialization is best-effort; failure is ignored). |

> **Clock:** this NF refuses to start when the local clock reads before 2020-01-01, because its PFCP Recovery Time Stamp would be wrong. See [A set clock is required](overview.md#a-set-clock-is-required-pfcp-nfs) for the remedy on RTC-less hosts.

## Behavior notes

- **PFCP heartbeats:** the UPF also initiates PFCP heartbeats toward the associated CP function every 10 seconds (code comment cites TS 29.244 §6.2.2: either node may initiate).
- **Reports:** the data plane emits Downlink Data Reports (on first buffered downlink packet) and Error Indication Reports over N4. URRs provisioned by the SMF are measured and enforced (Volume/Time Quota, #80), Usage Reports are sent, and an explicit Query URR IE is honoured (#428).
- **EPC role:** the EPC compose runs a dedicated upfd as PGW-U (`docker/rust/configs/epc/pgwu.yaml`, which it does not parse either; the flags in `docker-compose-epc.yml` drive it).
- **Validation status:** UPF behavior has been exercised in the project's matched-simulator Docker E2E suite (UE→UPF GTP-U traffic). This is internal test validation, not third-party conformance certification.

## Parsed-but-inert summary

| YAML section | Status |
|--------------|--------|
| `logger.*` | Ignored — use `-l` / `-e` flags. |
| `global.max.*` | Ignored — use `--max-sessions`. |
| `upf.pfcp.server` | Ignored — use `--pfcp-addr` / `--pfcp-port`. |
| `upf.gtpu.server` | Ignored — use `--gtpu-addr` / `--gtpu-port`. |
| `upf.session` | Ignored — use `--tun-ifname` / `--tun-ip` / `--tun-prefix` (single IPv4 subnet only via CLI; the YAML's IPv6 entry has no CLI equivalent). |
| `upf.metrics.server` | Not read, and removed from the shipped config (#1312): use `UPF_METRICS_PORT`. |
| `upf.tls.*` | Ignored. The file's comment names `TLS_ENABLED` / `SBI_SCHEME`, but no code reads them; the UPF serves no SBI listener (it is only an NRF client when `--nrf-uri` is set). |
