# NEF Configuration

The NEF (Network Exposure Function, `nextgcore-nefd`, TS 23.501 §6.2.5) exposes 5GC events to external Application Functions (AFs) and translates their northbound requests into internal service calls. It serves:

- **Monitoring Event** (TS 29.122 §5.3): `POST /3gpp-monitoring-event/v1/{scsAsId}/subscriptions` and `DELETE .../subscriptions/{subscriptionId}`. A create becomes a southbound subscription toward the AMF (`Namf_EventExposure`, TS 29.518) or the UDM (`Nudm_EE`, TS 29.503).
- **Device Triggering** (TS 29.122 §5.10): `POST /3gpp-device-triggering/v1/{scsAsId}/transactions`.
- **`Nnef_EventExposure`** (TS 29.591): `POST /nnef-eventexposure/v1/subscriptions`, `DELETE .../subscriptions/{subId}`, and the producer notification sink `POST /nnef-eventexposure/v1/notify/{subId}`, which forwards AMF/UDM notifications to the AF's `notificationDestination` as a TS 29.122 MonitoringNotification.

It registers with the NRF as `nfType: NEF` advertising `nnef-eventexposure`. PFD management, traffic influence and parameter provision are out of scope (`src/bins/nextgcore-nefd/src/main.rs` module docs).

No compose file, k8s manifest or Helm chart in this repo runs `nefd`, and no `nef.yaml` is shipped.

> **Honesty note:** NEF behavior is validated by this project's own unit tests, not by an end-to-end deployment or third-party certification. The northbound security rules (SUPI never sent to an AF, one UE per monitoring request, opt-in caller authentication) are described in [Configuration Overview → NEF northbound exposure](./overview.md#nef-northbound-exposure-issue-110).

## YAML parameters

The daemon reads one knob from the file, through an untyped `serde_yaml::Value` probe (`oauth2_required()`):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `<section>.sbi.oauth2.require` | bool | `false` | Require an OAuth2 token with audience `NEF` on every northbound route. Root-key agnostic: true if any top-level section sets it. `NEXTGCORE_SBI_OAUTH2_REQUIRE` overrides it. |

Everything else is configured by flags.

## Command-line flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/nef.yaml` | Configuration file path. |
| `-e, --log-level` | string | `info` | Log level; `RUST_LOG` overrides it. |
| `-l, --log-file` | path | unset | Log file path. |
| `-m, --no-color` | flag | off | Disable colored output. |
| `--sbi-addr` / `--sbi-port` | string / u16 | `0.0.0.0` / `7817` | SBI bind address and port. |
| `--tls`, `--tls-cert`, `--tls-key` | flag, path, path | off | TLS on the SBI listener. |
| `--verify-client` | flag | off | Require and verify a client certificate (needs `--tls`; without it startup fails). The certificate's URI SAN becomes the caller identity that subscription ownership is keyed to. |
| `--verify-client-cacert` | path | SBI layer default | CA bundle for `--verify-client`. |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI. |
| `--nf-instance-id` | string | generated | NF Instance ID (otherwise `NEXTGCORE_NF_INSTANCE_ID` / `NEXTGCORE_NEF_INSTANCE_ID`, then a UUID). |
| `--amf-uri` | string | unset | AMF base URI for southbound `Namf_EventExposure`. Unset: AMF-routed monitoring types are stored northbound-only and the southbound leg is deferred. |
| `--udm-uri` | string | unset | UDM base URI for southbound `Nudm_EE`. Same deferral when unset. |
| `--udm-sdm-uri` | string | `--udm-uri` | UDM used to resolve an AF-supplied GPSI (`msisdn`/`externalId`) to a SUPI via `id-translation-result`. With neither set, GPSI-targeted requests are refused. |
| `--notify-base` | string | `http://{sbi-addr}:{sbi-port}` | Externally routable base of the notification callback handed to AMF/UDM. Set it when `--sbi-addr` is a wildcard. |
| `--max-subscriptions` | usize | `4096` | Maximum stored northbound monitoring subscriptions. |
| `--max-transactions` | usize | `4096` | Maximum stored device-triggering transactions. |
| `--state-file` | path | unset | JSON snapshot of monitoring subscriptions and device-triggering transactions. Falls back to `NEXTGCORE_NEF_STATE_FILE`; an empty value is unset. An unreadable snapshot fails startup. |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `NEXTGCORE_NEF_STATE_FILE` | unset | Snapshot file when `--state-file` is absent. |
| `NEXTGCORE_SBI_OAUTH2_REQUIRE` | unset | Overrides the YAML OAuth2 knob. |
| `NEF_RECONCILE_INTERVAL_SECS` | `30` | How often deferred southbound legs are retried. |
| `NEF_PENDING_LEG_DEADLINE_SECS` | `300` | How long a deferred southbound leg is retried before it expires and is removed (#111). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OpenTelemetry OTLP exporter. |

## Behavior notes

- **Southbound is best-effort.** With no producer URI, or an unreachable producer, the northbound subscription is still created and the southbound leg is retried by the reconciler until `NEF_PENDING_LEG_DEADLINE_SECS`.
- **GPSI resolution needs the UDM.** nextgcore's own `udmd` serves `id-translation-result`, which resolves a GPSI through the UDR's `identity-data`.
