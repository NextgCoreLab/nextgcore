# TSCTSF Configuration

The TSCTSF (Time Sensitive Communication and Time Synchronization Function,
`nextgcore-tsctsf`) is the 5GC entity that exposes time-synchronisation and
time-sensitive-communication services to an AF or NEF, per TS 23.501 §5.27–§5.28
and TS 23.502 §5.2.27 (as cited in the daemon's source comments). It registers with
the NRF as `nfType: TSCTSF` and serves all three services TS 23.501
Table 7.2.26-1 mandates.

> **Honesty note — read this before deploying it.** The TSCTSF's **control plane**
> is complete; its **actuation** is not. A stored configuration has no policy or
> user-plane effect: there is no PCF client, no PMIC/UMIC/TSCAI derivation, and the
> UPF's `tsn_bridge` scaffolding is never driven. So (g)PTP domains are not
> distributed, DS-TT/NW-TT ports are not managed, and no QoS/TSC assistance reaches
> the SMF or UPF. That work is tracked as **#284**, split out of #113 at the issue
> author's own suggestion because it is cross-NF and cannot be verified end-to-end in
> this tree. An AF that gets a `201` here has had its request *recorded*, not
> *actuated*.
>
> Separately: `TS29565_Ntsctsf_*.yaml` is **not** vendored in this repo, so the
> resource paths and JSON member names below are derived from the Stage-2 parameter
> names in TS 23.502 §5.2.27, **not** verified against the Stage-3 schema. Treat the
> spellings as this project's own until the yaml lands.

## Service surface

### `Ntsctsf_TimeSynchronization` (TS 23.502 §5.2.27.2)

| Operation | Route |
|---|---|
| ConfigCreate | `POST /ntsctsf-time-synchronization/v1/configuration` → 201 + `Location` + `configId` |
| (read) | `GET /ntsctsf-time-synchronization/v1/configuration/{configId}` → 200/404 |
| ConfigUpdate (merge) | `PATCH /…/configuration/{configId}` → 200/404 |
| ConfigUpdate (replace) | `PUT /…/configuration/{configId}` → 200/404 |
| ConfigDelete | `DELETE /…/configuration/{configId}` → 204/404 |
| CapsSubscribe | `POST /ntsctsf-time-synchronization/v1/subscriptions` → 201 + the minted Subscription Correlation ID |
| (read) | `GET /…/subscriptions/{subscriptionId}` → 200/404 |
| CapsUnsubscribe | `DELETE /…/subscriptions/{subscriptionId}` → 204/404 |
| ConfigUpdateNotify | outbound POST to the configuration's `notificationTargetAddr` on a change |
| CapsNotify | outbound POST to every capability subscriber on a capability change |

**PATCH merges, PUT replaces, and the difference is deliberate.** §5.2.27.2.3's only
required input is the PTP instance reference and every parameter is optional, which
is merge semantics — a body carrying only `gmEnable` means "change the grandmaster
flag", not "clear everything else". PUT is offered for a consumer that wants to state
the whole configuration. A merge that would leave the configuration invalid (e.g.
blanking `notificationTargetAddr`) is refused, because that configuration could never
notify again.

**SUPI add/remove lists apply in that order**, so a SUPI in both is removed: a
consumer asking for both cannot have meant "keep".

### `Ntsctsf_ASTI` (TS 23.502 §5.2.27.4)

`POST` / `GET` / `PATCH` / `PUT` / `DELETE` on
`/ntsctsf-asti/v1/configurations[/{configId}]`, with an outbound UpdateNotify when a
notification target was registered. An AF identifier **and** a target (one of `supi`,
`gpsi`, `externalGroupId`, `internalGroupId`) are both required: a configuration with
no target would activate time distribution for nobody.

### `Ntsctsf_QoSandTSCAssistance` (TS 23.502 §5.2.27.3)

`POST` / `GET` / `PATCH` / `PUT` / `DELETE` on
`/ntsctsf-qos-tsctsf/v1/tsc-qos-requests[/{transactionRefId}]`, plus
Subscribe/Unsubscribe on `/ntsctsf-qos-tsctsf/v1/subscriptions`, with an outbound
Notify to every subscriber scoped to the transaction on an Update. An **unscoped**
subscription (no `transactionRefId`) is notified for every transaction, because a
subscriber that named none asked for everything.

### Administrative route (not a 3GPP service operation)

`POST /ntsctsf-time-synchronization/v1/admin/capability-change` fans a capability
change out to every `CapsSubscribe` subscriber and answers `200 {"notified": N}`.

It exists because the 5GS capability change that would trigger `CapsNotify` has **no
in-tree source** — reporting one needs the capability leg tracked in #284 — and
without a trigger the notify path would be unreachable in principle. It answers a
count rather than 204 so an operator can tell "notified nobody because nobody
subscribed" from "notified nobody because the fan-out is broken". Expect it to be
removed or relabelled when #284 lands.

## Request validation

Bodies are deserialised into typed IEs, so a malformed configuration is refused at
ingress rather than stored verbatim. The TS 29.500 §5.2.7.2 causes are kept distinct,
because the distinction tells a consumer whether its JSON is malformed or merely
incomplete — two different fixes on its side:

| Cause | When | Detail |
|---|---|---|
| `MANDATORY_IE_MISSING` | a required member is absent **or present-but-empty** | names the member |
| `MANDATORY_IE_INCORRECT` | a member is out of range (e.g. `timeDomain > 255`) | names the member |
| `INVALID_MSG_FORMAT` | the body is not JSON, not an object, or a member has the wrong **type** | the serde error |

Present-but-empty is refused alongside absent because serde accepts `""` for a
`String`, and an empty `notificationTargetAddr` is exactly the un-notifiable state the
validation exists to prevent.

`INVALID_MSG_FORMAT` replaced a previous bespoke `INVALID_JSON` cause, which was this
NF's own invention rather than a name a conformant consumer knows.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-tsctsf/src/main.rs`:

| Flag | Default | Description |
|---|---|---|
| `-c, --config` | `/etc/nextgcore/tsctsf.yaml` | Config file path. |
| `-l, --log-file` | unset | Log file path. |
| `-e, --log-level` | `info` | Log level. |
| `-m, --no-color` | off | Disable colour output. |
| `--sbi-addr` | `0.0.0.0` | SBI bind address. |
| `--sbi-port` | `7819` | SBI port. |
| `--tls`, `--tls-cert`, `--tls-key` | off / unset | TLS for the SBI server. |
| `--nrf-uri` | `http://127.0.0.1:7777` | NRF location for registration and the OAuth2 JWKS. |
| `--nf-instance-id` | generated UUID | NF Instance ID. |
| `--max-configs` | `4096` | Capacity cap, applied **per collection** (configurations, capability subscriptions, ASTI configurations, QoS/TSC sessions and their subscriptions). Exhaustion answers `507`. |

## Behavior notes

- **All three services are advertised to the NRF.** The NFProfile lists
  `ntsctsf-time-synchronization`, `ntsctsf-asti` and `ntsctsf-qos-tsctsf`, so the
  profile and the router change together — advertising one while serving three makes
  the other two undiscoverable, and advertising services that are not served would be
  worse.
- **All state is in-memory** (`RwLock<HashMap<..>>`), matching the other small NFs.
  There is no state file, so every configuration and subscription is lost on restart.
- **Resource ids are minted by the server, never taken from the request.** A
  consumer-supplied `subscriptionId` would let one AF address another's subscription
  resource.
- **Unmodelled optional members survive a round trip.** A configuration is stored
  both as typed IEs and as the body it arrived in, and a GET or an update response
  overlays the typed members on the original — so a parameter this build does not
  model is returned rather than silently dropped.
- **Notifications are best-effort.** A failed notification is logged and never
  propagated to the consumer whose request triggered it: letting an unreachable AF
  fail the operation that changed the configuration would be a worse outcome than a
  missed notification. A notification target with no usable host is refused rather
  than guessed at, because notifying the wrong node is worse than not notifying.
- **OAuth2** producer enforcement mirrors dccfd: enable with
  `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` or `tsctsf.sbi.oauth2.require: true`; tokens are
  verified against the NRF JWKS with audience `TSCTSF`.
- **Environment variables:** `NEXTGCORE_SBI_OAUTH2_REQUIRE` and
  `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://jaeger:4317`).
