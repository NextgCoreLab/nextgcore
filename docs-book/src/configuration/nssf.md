# NSSF Configuration

The NSSF (Network Slice Selection Function, `nextgcore-nssfd`) selects the network slice instances to serve a UE, determines the allowed NSSAI and its mapping to subscribed S-NSSAIs, and determines the AMF Set for a UE, per TS 29.531 (as cited in the daemon's source comments). It serves the `Nnssf_NSSelection` v2 API (`GET /nnssf-nsselection/v2/network-slice-information`, with dedicated handlers for the registration, PDU-session, and UE-Configuration-Update scenarios) and the `Nnssf_NSSAIAvailability` v1 API (`/nnssf-nssaiavailability/v1/nssai-availability/{nfId}` PUT/PATCH/DELETE, store-level OPTIONS, and `.../subscriptions` POST/PATCH/DELETE with availability-change notifications).

Configuration is split between a YAML file (default path `/etc/nextgcore/nssf.yaml`, overridable with `-c/--config`) and command-line flags, plus two environment variables (`NEXTGCORE_NSSF_STATE_FILE`, `OTEL_EXPORTER_OTLP_ENDPOINT`). Unusually for this codebase, the YAML `nssf.sbi.server` address/port **overrides** the CLI `--sbi-addr`/`--sbi-port` flags — per the code comment, so the NRF NFProfile advertises a routable endpoint instead of `0.0.0.0`.

> **Honesty note:** NSSF behavior is validated by this project's own unit tests and matched-simulator docker E2E only, not by third-party conformance certification. Two stances are explicitly non-strict by design (documented in code comments as matched-sim back-compat): availability updates are **default-allow** — any non-empty NF Id is treated as authorized without an NRF lookup, and with no `supported_snssai_list` configured every reported S-NSSAI is accepted. The NSSF advertises `supportedFeatures: "1"` and does not advertise the REROUTE capability (TS 29.531 §6.1.6.3 per code comment). The `-k/--kill` flag is a stub (logs and exits), and the TLS flags are not wired into the actual HTTP/2 listener (see below).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/nssf.yaml`:

```yaml
# NSSF (Network Slice Selection Function) Configuration
# Docker container configuration for 5G Core deployment

logger:
  file:
    path: /var/log/nextgcore/nssf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

nssf:
  sbi:
    server:
      - address: 172.23.0.14
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
      nsi:
        - uri: http://172.23.0.10:7777
          s_nssai:
            sst: 1
    # TLS configuration (G36: SBI TLS)
    # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/nssf.crt
      key: /etc/nextgcore/certs/nssf.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
```

An OAuth2-enforcing variant (`nssf-oauth2.yaml`, used via `docker-compose.oauth2.yml`) is identical except it adds:

```yaml
nssf:
  sbi:
    oauth2:
      require: true
```

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `NssfYaml`/`NssfSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml`/`SbiOauth2Yaml`/`SnssaiYaml` in `src/bins/nextgcore-nssfd/src/main.rs`).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `nssf.sbi.server[].address` | string | absent → CLI `--sbi-addr` (`0.0.0.0`) | SBI bind/advertised address. Only the **first** list entry is read; when present it **overrides** the CLI flag so the NRF NFProfile advertises a reachable endpoint (per code comment). |
| `nssf.sbi.server[].port` | u16 | absent → CLI `--sbi-port` (`7777`) | SBI port; same first-entry-only, overrides-CLI semantics. |
| `nssf.sbi.client.nrf[].uri` | string | absent → **no NRF registration** | NRF base URI (only the first list entry is used). Absent means the daemon skips NRF registration/heartbeat/discovery entirely and runs standalone — there is **no** CLI fallback for the NRF URI in this binary. `uri` is mandatory inside an entry (non-`Option` field). |
| `nssf.sbi.oauth2.require` | bool | **`true`** (#94) | SBI OAuth2 bearer-token enforcement. When enabled, incoming requests must carry an NRF-issued token whose audience includes `NSSF`, verified against the NRF JWKS (TS 33.501 §13.4.1); with no NRF URI configured the server fails closed (503). Outbound SBI calls (including availability notifications to AMFs) attach tokens. No CLI override exists. **It now DEFAULTS TO ENABLED, and an absent `oauth2` section means enforce.** This knob also governs whether NSSAI-availability writes must be bound to an attested caller (below), because binding is only meaningful against an authenticated identity. Every dev artefact (docker `nssf.yaml`, the k8s and Helm ConfigMaps) was given an explicit `require: false` in the same change as the flip, so nothing silently broke; those deployments log a startup WARNING naming the exposure. |
| `nssf.snssai_restrictions[]` (home_plmn, restricted) | list | absent → no restrictions | Per-home-PLMN S-NSSAI restrictions emitted as `restrictedSnssaiList` (TS 29.531 §6.2.6.2.5). **This is a new config surface** (#94): `set_plmn_snssai_restrictions` previously had no caller outside `#[cfg(test)]`, so an operator could not configure a restriction at all — which is why the serialization bug below was latent. An entry with an incomplete `home_plmn` is skipped with a warning. |
| `nssf.amf_set_id` | string | absent | Target AMF Set for AMF re-selection, emitted as `targetAmfSet` (TS 29.531 §5.2.2.2.2 step 2a per code comment). CLI `--target-amf-set` overrides the YAML value. When neither is set, `targetAmfSet` is **omitted** (#93): it previously derived `<mcc>-<mnc>-01-001` from the UE's serving-PLMN TAI, which is syntactically valid and an AMF set nobody deployed, so the AMF re-selected against a set that does not exist. It is also suppressed when a `candidateAmfList` is present, since TS 29.531 §6.1.6.2.2 makes those two alternative ways to steer re-selection and the candidate list is the more specific one. |
| `nssf.nssai_mapping[]` (serving, home) | list | absent → `pdn-connection` answers 403 | VPLMN→HPLMN S-NSSAI mapping served as `mappingOfNssai` on `slice-info-request-for-pdn-connection` (TS 29.531 §5.2.2.2.5, feature RSIPCE). Operator-provisioned because nothing in this core derives it — the registration path only echoes a mapping the consumer supplied. With no entries the scenario answers the spec's own 403 `SNSSAI_NOT_SUPPORTED` (§5.2.2.2.5 step 2b) rather than a fabricated mapping. |
| `nssf.supported_snssai_list` | list | absent → **no restriction (allow-all)** | Optional explicit set of S-NSSAIs supported in this PLMN (TS 29.531 §6.2.3.2.3.1 per code comment). When present, an NSSAIAvailability PUT/PATCH reporting an S-NSSAI outside the set is rejected with 403 `SNSSAI_NOT_SUPPORTED`. Absent means allow-all (matched-sim back-compat), **not** an empty set. |
| `nssf.supported_snssai_list[].sst` | u8 | **required** | Slice/Service Type of the S-NSSAI. |
| `nssf.supported_snssai_list[].sd` | string | absent (no SD) | Slice Differentiator as a hex string. The reserved value `FFFFFF` (and any non-hex string) is treated as "no SD". |

### Parsed-but-inert / decorative YAML fields

Unknown YAML keys are silently ignored by serde. In the shipped example file:

- **`logger.file.path` and `logger.level` are inert.** The log level comes solely from the CLI flag `-e/--log-level`; `init_logging` builds `env_logger::Builder::new()` with an explicit filter, so even `RUST_LOG` is not consulted, and no file logging is wired (see `--log-file` below).
- **`global.max.ue` / `global.max.peer` are inert** — no `global` section exists in the deserialize structs; the only pool cap is CLI `--max-nf`.
- **`nssf.sbi.client.nsi[]` (uri, s_nssai, optional nsi_id) is LOADED** (#93). Each entry installs one Network Slice Instance into the context, which is what `slice-info-request-for-pdu-session` and `slice-info-request-for-other-purpose` resolve against. Until #93 `SbiClientYaml` declared only `nrf`, so this block — present in every shipped config — deserialised into nothing, `nsi_add` had no production caller, and **every** PDU-session selection was answered `403`. An entry with no `s_nssai` is skipped with a warning rather than installed under a guessed SST. With no entries at all the daemon logs an ERROR at startup naming the consequence (it still serves the registration and NSSAI-availability scenarios, which do not consult the NSI table, so it does not refuse to boot).
- **`nssf.sbi.tls.*` (enabled/cert/key/ca/min_version) is inert.** TLS is CLI-flag-only, and even those flags only populate a legacy config (next section).

Note this differs from some sibling NFs: `nssf.sbi.server[]` **is** read here (and wins over the CLI flags), and there is no `--nrf-uri` CLI fallback.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-nssfd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/nssf.yaml` | Configuration file path. |
| `-l, --log-file` | path | unset | **Parsed but never used** — no file-logging sink is wired; logs go to the `env_logger` default (stderr). |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; unknown values fall back to `info`). |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM to running instance" and exits without signalling anything. |
| `--sbi-addr` | string | `0.0.0.0` | SBI bind address — **overridden** by `nssf.sbi.server[0].address` when the YAML sets it. |
| `--sbi-port` | u16 | `7777` | SBI port — overridden by `nssf.sbi.server[0].port`. |
| `--tls` | flag | off | Recorded in the legacy `SbiServerConfig` (`sbi_path.rs`) only; the actual HTTP/2 listener in `main.rs` is built without TLS, so the SBI server always speaks cleartext HTTP/2. |
| `--tls-cert` | path | unset | Same caveat as `--tls`. |
| `--tls-key` | path | unset | Same caveat as `--tls`. |
| `--max-nf` | usize | `512` | Maximum NSI entries and home contexts in the context pools; also the denominator of the NRF `/load` gauge. |
| `--target-amf-set` | string | unset | Target AMF Set (format `<MCC>-<MNC>-<RegionId>-<SetId>`, TS 29.531 `targetAmfSet` per code comment). Overrides YAML `nssf.amf_set_id`. |
| `--state-file` | path | unset | JSON snapshot file for NSSAI-availability subscriptions and availability data. Precedence: `--state-file`, then `NEXTGCORE_NSSF_STATE_FILE`; with neither set (or an empty value) state is purely in-memory and lost on restart. |

## Behavior notes

- **NRF registration is one-shot, heartbeat carries a real load gauge.** At startup the NSSF PUTs an NFProfile (`heartBeatTimer: 10`, services `nnssf-nsselection` v2 and `nnssf-nssaiavailability` v1, `allowedNfTypes` AMF/SCP/NSSF) to `/nnrf-nfm/v1/nf-instances/{uuid}`. On failure it logs a warning and **operates without NRF** — there is no registration retry loop. On success a heartbeat worker runs every 5 seconds and PATCHes a `/load` gauge computed as NSI count × 100 / `--max-nf`, clamped to 0–100 (TS 29.510 §5.2.2.3.2 per code comment). H-NSSF instances are also discovered from the NRF once at startup; a failure there is "will retry on demand".
- **NSSAI-availability writes are bound to the owning AMF** (#94). `PUT`/`PATCH`/`DELETE` on `nssai-availability/{nfId}` are authorized only when the caller identity **this process attested** — a verified OAuth2 token `sub`, or a verified client-certificate URI SAN, preferred in that order — equals `{nfId}` (TS 29.531 Table 6.2.3.2.3.1-2, TS 33.501 §13.4.1). Previously the check was `!nf_id.trim().is_empty()`: it verified only that the path segment was non-empty, so any reachable NF could overwrite any AMF's slice picture. When the policy cannot be **evaluated** (a poisoned context lock) the write is **denied**; it used to fall back to default-allow, so one panicking sibling request disabled the check. With `oauth2.require = false` there is no identity to bind to, so writes are permitted and a WARNING is logged on every one.
- **Subscription expiry is assigned and enforced** (#94). The NSSF assigns an `expiry` bounded by `SUBSCRIPTION_VALIDITY` (24 h), honouring a consumer-requested value only when it is EARLIER — a consumer cannot extend its own subscription. An expired subscription stops matching notifications immediately and is removed by a sweep on the run-loop tick (every 60 s). Previously the consumer's value was echoed verbatim, none was assigned when absent, and nothing ever swept or filtered, so subscriptions accumulated and kept firing forever.
- **Subscription create follows the schema** (#94). Only `nfNssaiAvailabilityUri` and `event` are mandatory (TS 29.531 Table 6.2.6.2.8-1); `taiList` is optional and absent/empty means **all TAIs**, which is already how matching treats an empty list. It used to be rejected as missing, so a consumer subscribing to all TAIs got a 400. `additionalEvents` is parsed, and `acceptedEvents` is returned listing only events this NSSF can actually report — `SNSSAI_STATUS_CHANGE_REPORT` is the only one with a producer, so an unreportable additional event is simply absent from `acceptedEvents` rather than rejected, and a subscription with no reportable event at all is refused because it could never fire.
- **`restrictedSnssaiList` uses the conformant key** (#94). The array is serialized under `sNssaiList`, which `RestrictedSnssai` requires; it was `sNssais`, which any strict consumer would reject. Authorized availability entries also now carry `taiList`, `taiRangeList` and `nsagInfos` through, instead of dropping them so an entry scoped by a TAI range came back scoped by nothing.
- **All five request scenarios are routed** (#93). `slice-info-request-for-pdn-connection` (TS 29.531 §5.2.2.2.5, RSIPCE) returns `mappingOfNssai` from `nssf.nssai_mapping[]`, and `slice-info-request-for-other-purpose` (§5.2.2.2.6, SIOP) returns `snssaiInfoRspData` — the NSI ID(s) for the requested S-NSSAIs — from the configured NSI table. Both answer 403 `SNSSAI_NOT_SUPPORTED` when nothing resolves, which is what each clause's step 2b prescribes. Previously both fell through to 400 `MANDATORY_QUERY_PARAM_MISSING`, telling a conformant consumer it had omitted a query parameter it had in fact supplied. Responses to these two scenarios advertise `supportedFeatures: "d"` (bit 1 plus RSIPCE and SIOP); the registration / PDU-session / UE-CU responses keep their existing `"1"`.
- **`roamingIndication` uses the normative token** (#93). `HOME_ROUTED_ROAMING` (TS 29.531 §6.1.6.3.3) is accepted inbound and is what the outbound H-NSSF query emits. The non-normative `HOME_ROUTED` this NSSF used to emit is still accepted inbound as a documented shim — a peer NSSF running an older build may echo it — but is never sent. Any other value is refused with 400 `INVALID_IE_VALUE` naming the three legal tokens.
- **`accessType` reflects the request** (#93). The registration response's `allowedNssaiList[].accessType` comes from the request's `allowedNssaiCurrentAccess.accessType`, defaulting to `3GPP_ACCESS` only when the consumer did not state one; `allowedNssaiOtherAccess` describes the *other* access and is deliberately not read as the current one. `SliceInfoForPDUSession` carries no `accessType` at all, so on that path `3GPP_ACCESS` remains the only available answer and is documented as a default rather than a derived value.
- **Availability-update admission is default-allow.** 403 `NOT_AUTHORIZED` is returned only for a missing/empty NF Id (deliberately no NRF authorization lookup, per code comment); 403 `SNSSAI_NOT_SUPPORTED` only when `supported_snssai_list` is configured *and* a reported S-NSSAI falls outside it. Success returns 200 with `authorizedNssaiAvailabilityData` — or **204 No Content when no supported S-NSSAIs remain** after the update (TS 29.531 §6.2.3.2.3.1 per code comment). Availability PATCH requires `Content-Type: application/json-patch+json` (else 415, RFC 6902 / TS 29.531 §6.2 per code comment) and is applied to a clone, committed only if the patched document re-validates.
- **Notifications are fire-and-forget.** Availability changes spawn one Tokio task per matching subscription, POSTing `NssfEventNotification` with bounded timeouts (2 s connect, 3 s request); delivery failures are logged, never retried, and the AMF whose own update caused the change is excluded (it gets the data in its direct response).
- **State persistence is per-mutation, not shutdown-only.** With a state file configured, subscriptions and availability documents are atomically rewritten on every add/update/delete and reloaded at startup; a corrupt or missing file is logged and skipped, starting empty.
- **Config parse errors are silent.** The YAML is parsed with `if let Ok(...)`: a type mismatch anywhere (e.g. a non-numeric `sst`) silently discards the *entire* `nssf` section and the daemon proceeds on CLI defaults — check the startup log for the expected "NRF URI configured" / "Target AMF Set configured" lines.
- **Environment variables:** `NEXTGCORE_NSSF_STATE_FILE` (state-file path; lower precedence than `--state-file`) and `OTEL_EXPORTER_OTLP_ENDPOINT` (OpenTelemetry OTLP exporter endpoint, default `http://jaeger:4317`). `RUST_LOG` is **not** honored by this binary.
