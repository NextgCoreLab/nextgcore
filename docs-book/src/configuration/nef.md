# NEF Configuration

The NEF (Network Exposure Function, `nextgcore-nefd`, TS 23.501 §6.2.5) exposes 5GC events to external Application Functions (AFs) and translates their northbound requests into internal service calls. It serves:

- **Monitoring Event** (TS 29.122 §5.3): `POST /3gpp-monitoring-event/v1/{scsAsId}/subscriptions` and `DELETE .../subscriptions/{subscriptionId}`. A create becomes a southbound subscription toward the AMF (`Namf_EventExposure`, TS 29.518) or the UDM (`Nudm_EE`, TS 29.503).
- **Device Triggering** (TS 29.122 §5.10): `POST /3gpp-device-triggering/v1/{scsAsId}/transactions`.
- **`Nnef_EventExposure`** (TS 29.591): `POST /nnef-eventexposure/v1/subscriptions`, `DELETE .../subscriptions/{subId}`, and the producer notification sink `POST /nnef-eventexposure/v1/notify/{subId}`, which forwards AMF/UDM notifications to the subscriber's notification URI in the shape of the API it subscribed on (#2154): a TS 29.122 MonitoringNotification for a T8 subscription, a TS 29.591 `NefEventExposureNotif` (`notifId`, and one `eventNotifs` entry per report with the subscribed `event` and its `timeStamp`) for a Nnef_EventExposure one. **Ceiling:** TS 29.591 defines no member for a location, reachability or loss-of-connectivity report, so a Nnef_EventExposure notification says which event occurred and when, and no more; the T8 API carries the report itself.

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
| `-e, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `-l, --log-file` | path | unset | Log file path. |
| `-m, --no-color` | flag | off | Disable colored output. |
| `--sbi-addr` / `--sbi-port` | string / u16 | `127.0.0.1` (loopback, #1308) / `7817` | SBI bind address and port. |
| `--sbi-advertise` | string | unset | The host in the NRF NFProfile and the default `--notify-base` (#1322). Then `NEXTGCORE_SBI_ADVERTISE`, then `--sbi-addr` when it is not a wildcard. A wildcard is never advertised. |
| `--tls`, `--tls-cert`, `--tls-key` | flag, path, path | off | TLS on the SBI listener. |
| `--verify-client` | flag | off | Require and verify a client certificate (needs `--tls`; without it startup fails). The certificate's URI SAN becomes the caller identity that subscription ownership is keyed to. |
| `--verify-client-cacert` | path | SBI layer default | CA bundle for `--verify-client`. |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI. |
| `--nf-instance-id` | string | generated | NF Instance ID (otherwise `NEXTGCORE_NF_INSTANCE_ID` / `NEXTGCORE_NEF_INSTANCE_ID`, then a UUID). |
| `--amf-uri` | string | unset | AMF base URI for southbound `Namf_EventExposure`. Unset: AMF-routed monitoring types are stored northbound-only and the southbound leg is deferred. |
| `--udm-uri` | string | unset | UDM base URI for southbound `Nudm_EE`. Same deferral when unset. |
| `--udm-sdm-uri` | string | `--udm-uri` | UDM used to resolve an AF-supplied GPSI (`msisdn`/`externalId`) to a SUPI via `id-translation-result`. With neither set, GPSI-targeted requests are refused. |
| `--notify-base` | string | `http://{advertised host}:{sbi-port}` | Externally routable base of the notification callback handed to AMF/UDM. One naming no host or a wildcard host is refused. With a wildcard `--sbi-addr`, nothing to advertise and no `--notify-base`, nefd refuses to start (#1322). |
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
| `NEF_SOUTHBOUND_LIFETIME_SECS` | `3600` | Expiry asked for on every southbound subscription, and granted again by each refresh (minimum 60, and at least four `NEF_RECONCILE_INTERVAL_SECS` ticks) (#2102). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OpenTelemetry OTLP exporter. |

## Behavior notes

- **Southbound is best-effort.** With no producer URI, or an unreachable producer, the northbound subscription is still created and the southbound leg is retried by the reconciler until `NEF_PENDING_LEG_DEADLINE_SECS`.
- **Cancellation-safe create and delete (#1877).** A monitoring-subscription create runs on its own task, so an AF that goes away while the producer's subscribe is out cannot leave a producer subscription recorded nowhere. A 201 the AF never read is removed together with its producer leg. A delete removes the record first, then sends the producer DELETE on its own task.
- **Producer unsubscribes are retried (#1877).** A southbound DELETE that fails (no answer, a non-2xx other than 404) is parked and retried every 30 s at the producer the subscription was made at (the URI configured at the time, for a subscription recorded before #1877), until the producer answers 2xx or 404. Within a pass, a producer that fails once is not tried again, and a tried unsubscribe goes to the back of the queue, so a blackholed producer cannot starve the others. Across passes, a failing producer backs off: 30 s after its first failure, doubled after each further one up to 10 min, and cleared by a delivery. A producer with nothing left parked is forgotten, so one that never comes back does not stay tracked (#1994). So a dead producer costs one request timeout per backoff period rather than one per pass. One parked for 24 h is given up and counted `expired`. At most 4096 are kept, and the oldest by park time, wherever rotation has put it, is evicted and counted `abandoned`. With a state file (#2086), the unsubscribes still owed are written to the same snapshot as the subscriptions. One is recorded before the removal of its subscription is persisted and before its DELETE is sent, and it leaves the snapshot once delivered. So a restart retries every unsubscribe the NEF owes, and its 24 h counts from the restart. Without a state file, nothing is kept across a restart. Metrics `nef_southbound_unsubscribes_pending`, `nef_southbound_unsubscribes_parked_total{producer}` and `nef_southbound_unsubscribes_reconciled_total{result}` are served on `/metrics` in a demo build, and are otherwise read in-process.
- **Southbound subscriptions expire unless refreshed (#2102).** Every AMF Namf_EventExposure or UDM Nudm_EE subscribe asks for an expiry `NEF_SOUTHBOUND_LIFETIME_SECS` ahead: `subscription.options.expiry`, or `reportingOptions.expiry` for the UDM. The NEF records the expiry the producer confirms. On every reconcile tick, on a task of its own, it refreshes a leg once half its lifetime or less is left. Legs are refreshed per producer, up to 8 producers at once. A producer that fails a refresh is not tried again that pass, so a dead producer costs one request timeout per tick and other producers' legs are still refreshed (#2128). The modifications are `replace /options/expiry` at the AMF, and `add /reportingOptions/expiry` at the UDM: the member, so the UDM's other `reportingOptions` members are kept (RFC 6902 `add` on `/reportingOptions` replaces the object). A leg made before #2102 has no `reportingOptions` and gets the whole object (#2133). If a refresh is answered 404, or the expiry passes before a refresh gets through, the subscription is removed. In the second case its DELETE is also sent. **The AF is told (#2133):** whenever the NEF removes a subscription on its own initiative (here, or a deferred leg past `NEF_PENDING_LEG_DEADLINE_SECS`), it sends the AF a MonitoringNotification naming the subscription with `cancelInd: true` and no reports (TS 29.122). Best effort, like every AF notification. A DELETE the AF asked for is not notified. TS 29.591 defines no such indication for a Nnef_EventExposure consumer, so one is sent nothing (#2154). **Upgrade order (#2154): upgrade udmd before nefd.** A udmd from before #2133 accepts only top-level patch paths and answers `add /reportingOptions/expiry` 400. nefd then retries that refresh once with the whole `reportingOptions` object, so legs are still refreshed during a rolling upgrade, but that form replaces the UDM's other `reportingOptions` members. So a subscription the NEF holds no record of, because its create timed out after the producer took it, is never refreshed and lapses at the producer. nextgcore's `udmd` enforces the EE expiry and grants a refresh (#2125).
- **GPSI resolution needs the UDM.** nextgcore's own `udmd` serves `id-translation-result`, which resolves a GPSI through the UDR's `identity-data`.
