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
| `UDM_SBI_ADDR` / `UDM_SBI_PORT` | unset / `7777` | UDM address for `Nudm_SDM_Get(smf-select-data)`, used only to resolve the **subscribed default DNN** (#204). Tried **after** NRF discovery, so it is the fallback for a deployment with no NRF. With neither available, a `SmContextCreateData` carrying no `dnn` is refused with `SUBSCRIPTION_DATA_NOT_AVAILABLE`. |
| `NEXTGCORE_SBI_OAUTH2_REQUIRE` | unset | `1`/`true`/`yes` forces OAuth2 enforcement, taking precedence over the YAML knob. |
| `NEXTGCORE_SMF_STATE_FILE` | unset | JSON snapshot file for PFCP sessions, policy bindings and IPv4-pool allocations (#191). Read only when `--state-file` is absent — the flag wins; an empty value is treated as unset. With neither set the SMF is memory-only, which is the shipped default. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OpenTelemetry OTLP trace exporter endpoint. |

## Command-line flags

`smfd` has no `clap` argument parser; it scans `argv` for the two flags it
understands and ignores everything else.

| Flag | Default | Description |
|---|---|---|
| `-c` / `--config` | `/etc/nextgcore/smf.yaml` | Config file path. Falls back to `SMF_CONFIG`. |
| `--state-file` | unset | JSON snapshot file for durable state (#191). Falls back to `NEXTGCORE_SMF_STATE_FILE`; an empty value is treated as unset. |

## Durable state (#191)

Off by default. With `--state-file` (or `NEXTGCORE_SMF_STATE_FILE`) the SMF
snapshots three things on every mutation and reloads them at boot:

| Snapshotted | Why it matters on restart |
|---|---|
| PFCP sessions (`sm_context_ref` → UPF SEID) | Without it the UPF holds N4 sessions the SMF can no longer delete or modify. |
| Policy bindings (PCF association, authorized QoS, GSM FSM state, EASDF DNS context) | Without it a restarted SMF cannot terminate or update policy for a live session. |
| IPv4-pool allocations | **The one with a correctness consequence beyond lost state.** The pool is a bitmap; rebuilt empty, the next allocation returns an address a live UE still holds, and nothing logs the collision. |

Uses the shared `nextgcore-core::state_store::StateStore`: atomic +
fsynced + `0600` writes, and a snapshot that cannot be read is **never
overwritten**. An unreadable snapshot, or one written by a newer build,
**fails startup** rather than coming up with an empty pool.

**The restored PFCP session map is checked, not trusted.** The snapshot also
carries the last Recovery Time Stamp each UPF reported. That value is seeded
back into each `PfcpClient` before the association loop starts, so the first
Association Setup after a reload compares the UPF's reported stamp against it:
a changed stamp means the UPF restarted while the SMF was down, and the restored
sessions are flushed (TS 29.244 §5.22, TS 23.527 §4.2) instead of being believed
in. An unchanged stamp means they are genuinely still valid.

**Limits worth knowing:**

- The flush is process-wide, not per-peer — `clear_pfcp_sessions` empties the
  whole map, so with several UPFs configured one peer's restart discards the
  session bookkeeping for all of them. The map has no peer column to do better.
- Reconciling *which* sessions survived a restart, and signalling peers about
  the ones that did not, is TS 23.527 restoration work tracked as #193. This
  interlock is the minimum that makes restoring the map safe, not that work.
- Not enabled in the shipped Docker compose (unlike `udrd`), so the default E2E
  path is unchanged.

## Parsed-but-inert YAML sections

The example file follows an Open5GS-style layout, but the typed deserializer ignores everything outside `smf.sbi` (unknown keys are silently dropped). The following sections in the shipped example currently have **no effect** on `nextgcore-smfd`:

- `logger` — logging is controlled by `env_logger` (`RUST_LOG`, default `info`), not this section.
- `global.max.ue` / `global.max.peer` — not read; context limits use the hard-coded defaults above.
- `smf.pfcp` — PFCP addressing comes from the `SMF_PFCP_*` / `UPF_PFCP_*` environment variables.
- `smf.gtpc`, `smf.gtpu`, `smf.metrics` — not deserialized by the config structs.
- `smf.session` (UE IP subnets/gateways), `smf.dns`, `smf.mtu` — not deserialized by the config structs.
- `smf.tls` — not read by the SMF loader; the file comment ties TLS to `TLS_ENABLED`/`SBI_SCHEME` deployment variables.

## Subscribed default DNN (#204)

`dnn` is **optional** in `SmContextCreateData` (TS 29.502 §6.1.6.2.2). When the UE omits the DNN IE the AMF omits the member — it used to substitute the literal `"internet"`, so any deployment whose subscribers do not all default to a DNN of that name attached DNN-less sessions to the **wrong data network**, silently, because the session established fine against it. The SMF now selects the subscribed default itself, which is correct per TS 23.501 §6.2.2: the SMF is the NF that retrieves SM subscription data.

Resolution, in order:

1. `Nudm_SDM_Get` on **`smf-select-data`** (`SmfSelectionSubscriptionData`), because the default-DNN flag is `DnnInfo.defaultDnnIndicator` and lives there. `sm-data`'s `dnnConfigurations` has **no** default flag (TS 29.503 Table 5.5.2.4-1), so it cannot answer this question.
2. The `dnnInfos` entry flagged `defaultDnnIndicator: true` wins.
3. If exactly **one** DNN is subscribed for the S-NSSAI and none is flagged, that one is used — unambiguous.
4. Otherwise the session is **refused** with `400 MANDATORY_IE_MISSING`, listing the candidate DNNs. Choosing among several unflagged DNNs would invent an answer the subscription does not give.

Failure causes are distinct so an operator can tell a provisioning gap from an unreachable UDM: `MANDATORY_IE_MISSING` for "the subscription supplies no usable default", `SUBSCRIPTION_DATA_NOT_AVAILABLE` for "no UDM endpoint" or "the Nudm_SDM_Get failed".

**Limit worth knowing:** nothing in this tree emits `defaultDnnIndicator` — the subscription DB has no such field and `udrd`'s `build_smf_selection_data` writes only the DNN name. So against this tree's own UDM/UDR, rule 3 is what makes it work, and a subscriber with **two or more DNNs on one S-NSSAI cannot establish a DNN-less PDU session** (it is refused, with the candidates named). Tracked as issue #264 (`decision`).

No `single-nssai` query parameter is sent, even though TS 29.503 §5.2.2.2.1 allows scoping: the value is JSON and must be percent-encoded, but the shared SBI server stores query values verbatim without decoding them (issue #65), so a scoped query cannot round-trip to the in-tree UDM. The S-NSSAI's entry is selected locally by key instead.

## SM context lifecycle (#78)

`POST /sm-contexts` now **registers** the session in the SMF context list and takes
the `smContextRef` from the session itself. Before #78 it minted a reference from a
counter and registered nothing, so every `Retrieve` answered
`404 CONTEXT_NOT_FOUND` for a session that had just been created successfully. The
reference is read back out of the session rather than computed alongside it because
`sess_add_by_psi` mints it from the *same* counter — computing both would consume the
counter twice and leave the handler's reference one behind the session's.

A create that fails after registration **rolls the registration back**. An abandoned
registration would be an SM context the AMF never learned about and will never
release.

| Operation | Before #78 | Now |
|---|---|---|
| Retrieve, known ref | `404 CONTEXT_NOT_FOUND` (nothing was registered) | `200` with `SmContextRetrievedData` including the required `ueEpsPdnConnection` |
| Retrieve, unknown ref | `404`, body `{"status","cause"}` at `application/json` | `404` ProblemDetails at `application/problem+json` |
| Update, unknown ref | `200` | `404` + ProblemDetails (TS 29.502 §5.2.2.3.2) |
| Release, unknown ref | `204` | `404` + ProblemDetails (TS 29.502 §5.2.2.4) |
| Release body | not parsed at all — the handler took no body argument | `SmContextReleaseData` (`cause`, `n2SmInfo`, `vsmfReleaseOnly`) |
| `HANDOVER_REQUIRED` / `_REQ_ACK` / `_COMPLETE` / `_CANCEL` | `400 N2_SM_ERROR` via the catch-all | processed, `hoState` driven per TS 29.502 §5.2.2.3.4 |
| PFCP Downlink Data Report | logged only | drives `Namf_Communication_N1N2MessageTransfer` toward the serving AMF |

**The handover states deliberately do not touch the user plane until completion.**
`PREPARING` and `PREPARED` leave the DL tunnel on the source gNB, because until the
UE has actually moved the source is still serving it and re-pointing the UPF would
black-hole downlink traffic for the whole handover-execution window.
`HANDOVER_COMPLETE` switches it, through the same `pfcp_session_modify` call a path
switch uses, and **says so in the log when the request carried no decodable target
F-TEID** — a bare 200 would leave an operator unable to tell a switched tunnel from
an unswitched one. `HANDOVER_CANCEL` has nothing to undo, which is exactly why the
earlier states do nothing.

**Paging carries the N2 form, not the N1 form.** TS 23.502 §4.2.3.3 has the SMF send
N2 SM information so the AMF can re-establish the user plane; there is no NAS message
to deliver to a sleeping UE. So the DLDR path posts an `n2InfoContainer` (with the
QFI the UPF reported, so the gNB knows which flow to restore) rather than reusing the
`n1MessageContainer` sender the 5GSM timer path uses. A DLDR for a session whose user
plane is **not** `DEACTIVATED` does not page: TS 29.244 §7.5.8.2 scopes the report to
a deactivated connection, and paging a connected UE is a spurious service request.

**Limits worth knowing:**

- `ueEpsPdnConnection` is the minimal PDN-connection descriptor derivable from the
  5GS session (APN, PDN type, UE address, default-bearer QCI). It is **not** a mapped
  EPS bearer-context list, because this tree has no EBI assignment and no Mapped EPS
  bearer context IE at all — that is #117. A fabricated bearer list would be worse
  than a minimal descriptor: the AMF would forward it to an MME that would then try
  to use bearers this SMF never established.
- `vsmfReleaseOnly` is parsed and **logged, not honoured**: this SMF has no
  V-SMF/H-SMF split on the `sm-contexts` path, so acting on the flag would mean
  pretending to a split that does not exist.
- The create handler's *success* path is unreachable in this tree's test harness (it
  needs a PFCP-responding UPF, and no test establishes an N4 session), so what tests
  cover is the registration function's invariant plus the rollback contract.

## Honesty notes

- Behavior above is grounded in `nextgcore/src/bins/nextgcore-smfd/src/main.rs` and the docker example config; 3GPP TS references are quoted from code comments, not a conformance claim.
- The SMF is validated in matched-simulator and docker E2E runs against nextgsim peers; it has not been certified against third-party equipment or an external conformance suite.
- There is no `nextgcore/configs/smf.yaml`; example configs live at `docker/rust/configs/5gc/smf.yaml` (plus `k8s/manifests/smf.yaml` and the Helm template).
