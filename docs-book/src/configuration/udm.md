# UDM Configuration

The UDM (Unified Data Management, `nextgcore-udmd`) is the subscriber-data front-end of the core: it manages UE context registrations, serves subscription data, and generates 5G authentication vectors, backed by the UDR over `Nudr_DataRepository`. Its SBI router (`udm_sbi_request_handler` in `src/bins/nextgcore-udmd/src/app.rs`) routes all ten Nudm services (#85). It implements `Nudm_UECM` (`/nudm-uecm/v1` — AMF 3GPP/non-3GPP-access and SMF registrations, `dereg-amf`, TS 29.503 §5.3.3 per code comments), `Nudm_SDM` (`/nudm-sdm/v2` — am-data, sm-data, smf-select-data, nssai, ue-context-in-amf-data, `id-translation-result`, sdm-subscriptions with SDM notifications, and SoR/UPU acknowledgements; the other per-SUPI data sets are read-throughs that relay the UDR's answer), `Nudm_UEAU` (`/nudm-ueau/v1` — `generate-auth-data` with 5G-AKA/EAP-AKA' per TS 33.501 §6.1.2 as cited in the daemon source, plus `auth-events`; every Nudm_UEAU operation is refused `403` before the handler when the caller's verified client certificate names an NF type other than AUSF or a relaying SCP, #1866), `Nudm_EE` (`/nudm-ee/v1` — event-exposure subscriptions with create/modify/delete and notifications, TS 29.503 §5.5 per code comments), `Nudm_PP` and `Nudm_MT` (partly: see below). `nudm-niddau`, `nudm-rsds`, `nudm-ssau` and `nudm-ueid` are recognised and answered `501`. SUCI deconcealment (SIDF role) is implemented in `context.rs` per TS 33.501 §6.12 as cited in the source, and Steering-of-Roaming / UE-Parameters-Update injection into am-data goes through the AUSF's protection services (TS 33.501 §6.14.2.1 / §6.15.2.1 per code comments).

Configuration is split between a YAML file (default path `/etc/nextgcore/udm.yaml`, overridable with `-c/--config`) and command-line flags, with a small set of environment variables on top. For the SBI, the CLI `--sbi-addr`/`--sbi-port` beat the YAML `udm.sbi.server[0]` address/port, which beat `127.0.0.1`/`7777` (#1312; the YAML used to override the flags). What is registered with the NRF is set apart from the bind: `--sbi-advertise`, `NEXTGCORE_SBI_ADVERTISE`, the YAML `advertise`, then the bind address, never a wildcard. If the config file is missing the daemon logs at debug level and runs on pure CLI defaults; a YAML file that fails to deserialize fails startup (#1313).

> **Honesty note:** UDM behavior is validated by this project's own unit tests and matched-simulator docker E2E runs , not by third-party conformance certification. Routes that answer **501 NOT_IMPLEMENTED**: `sdm-subscriptions` PATCH; UECM sub-resources other than `dereg-amf` (`pei-update`, `roaming-info-update`, ...); `Nudm_PP` 5G VN group and MBS group management; `Nudm_MT` `provide-loc-info`; QueryUeInfo fields outside the supported set; and the whole of `nudm-niddau`/`nudm-rsds`/`nudm-ssau`/`nudm-ueid` (Deconceal stays 501 so the UDM is not an unauthenticated SUPI oracle). The `--tls*` flags are placeholders (see below); TLS on the listener comes from the SBI security profile.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/udm.yaml`:

```yaml
# UDM (Unified Data Management) Configuration
# Docker container configuration for 5G Core deployment

logger:
  file:
    path: /var/log/nextgcore/udm.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

udm:
  hnet:
    - id: 1
      scheme: 1
      key: /etc/nextgcore/hnet/curve25519-1.key
    - id: 2
      scheme: 2
      key: /etc/nextgcore/hnet/secp256r1-2.key
  sbi:
    server:
      - address: 172.23.0.12
        port: 7777
    client:
      nrf:
        - uri: https://172.23.0.10:7777
    # TLS configuration (G36: SBI TLS)
    # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/udm.crt
      key: /etc/nextgcore/certs/udm.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
```

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `UdmYaml`/`UdmSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml`/`HnetYaml`/`SorYaml`/`UpuYaml` in `src/bins/nextgcore-udmd/src/app.rs`), plus one knob (`sbi.oauth2.require`) read by a separate untyped `serde_yaml::Value` scan in `oauth2_required()`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `udm.sbi.server[].address` | string | absent → `127.0.0.1` (#1308) | Only the **first** list entry is read. The SBI bind address, after `--sbi-addr` (#1312). |
| `udm.sbi.server[0].advertise` | string | absent → the bind address, unless it is a wildcard | The host registered in the NRF NFProfile and put in callback URIs (#1312). After `--sbi-advertise` and `NEXTGCORE_SBI_ADVERTISE`. A wildcard is never advertised: with a wildcard bind and nothing set here, the NF does not register with the NRF and logs why. |
| `udm.sbi.server[].port` | u16 | absent → `7777` | First entry only; the SBI port, after `--sbi-port` (#1312). |
| `udm.sbi.client.nrf[].uri` | string | absent → **no NRF registration** | First entry only; seeds the NRF URI in the shared SBI context. If absent, NRF registration is skipped entirely (debug log) and the UDM operates without NRF. |
| `udm.sbi.oauth2.require` | bool | `false` | SBI OAuth2 enforcement (Wave-6 H8; TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comments). Read via a raw YAML scan that is root-key agnostic (true iff *any* top-level section sets `sbi.oauth2.require: true`). The env var `NEXTGCORE_SBI_OAUTH2_REQUIRE` takes precedence over the YAML. When on, incoming requests must carry an NRF-issued Bearer token with audience `UDM` (verified against the NRF JWKS; fails closed with 503 when no NRF URI is configured, per code comment) and outbound SBI calls attach tokens. |
| `udm.hnet[].id` | u8 | **required** per entry | Home-network key identifier for SUCI deconcealment (TS 33.501 §6.12 per code comment); matched against the SUCI's key id. |
| `udm.hnet[].scheme` | u8 | **required** per entry | Protection scheme: `1` = Profile A (ECIES X25519), `2` = Profile B (ECIES P-256), per the `deconceal_suci` doc comment in `context.rs`. A key whose scheme mismatches the SUCI's scheme is rejected. |
| `udm.hnet[].key` | string | **required** per entry | Either a 64-hex-char private key inline, or a **path to a file containing 64 hex chars** (not PEM, despite the `.key` extension in the example). A key that fails to load logs a warning and every SUCI using that key id is rejected. |
| `udm.allow_null_scheme` | bool | `true` (context default `AtomicBool::new(true)`; YAML applied only when present) | udmd-11: gate for null-scheme SUCIs. When `false`, null-scheme SUCIs are rejected at deconcealment; `imsi-` passthrough is always allowed. |
| `udm.sor.steering` | array of JSON objects | absent/empty → **no SoR injection**, am-data passthrough is byte-identical | Wave-6 F-04: TS 29.509 `SteeringContainer` as a `SteeringInfo[]` array (`{plmnId: {mcc, mnc}, accessTechList: [..]}`; quote `mcc`/`mnc` as strings, per the struct doc comment). The AUSF performs the TS 24.501 §9.11.3.51 wire encoding per code comment. |
| `udm.sor.ack_ind` | bool | `true` (`unwrap_or(true)`) | Request UE acknowledgement (`SorInfo.ackInd`). |
| `udm.upu.data` | array of JSON objects | absent/empty → **no UPU injection**, am-data passthrough is byte-identical | Wave-6 F-05: TS 29.509 `UpuData[]` entries (`{routingId}`, `{defaultConfNssai: [..]}`, `{secPacket}`, …, per the struct doc comment). The AUSF performs the TS 24.501 §9.11.3.53A wire encoding and MAC per code comment. |
| `udm.upu.ack_ind` | bool | `true` (`unwrap_or(true)`) | Request UE acknowledgement (`UpuInfo.upuAckInd`). |

### Parsed-but-inert / decorative YAML fields

Unknown YAML keys are silently ignored by serde. In the shipped `udm.yaml`:

- **`logger.level` is read; `logger.file.path` is inert.** The log level is `-e/--log-level` when given, else this file's `logger.level`, else `info`; `RUST_LOG`, when set, overrides all three (#691). No log file is ever opened (see the CLI table: even `-l/--log-file` is inert).
- **`global.max.ue` and `global.max.peer` are inert.** Context capacities come from the CLI flags `--max-ue` (default `1024`) and `--max-sess` (default `4096`); the example's `ue: 1024` merely coincides with the CLI default.
- **`udm.sbi.tls.*` (`enabled`/`cert`/`key`/`ca`/`min_version`) is entirely inert.** `SbiYaml` has no `tls` field, and even the CLI TLS flags only populate a legacy placeholder config (see behavior notes).

Everything else in the shipped example (`udm.hnet[]`, `udm.sbi.server[]`, `udm.sbi.client.nrf[]`) is genuinely read.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-udmd/src/app.rs` (the binary's `main.rs` is a thin wrapper around `nextgcore_udmd::run`):

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/udm.yaml` | Configuration file path. |
| `-l, --log-file` | path | unset | **Parsed but unused** — `init_logging()` never references it; logging goes to stderr via `env_logger`. |
| `-e, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Not supported: logs an error and exits non-zero without signalling anything; stop the NF through its supervisor. |
| `--sbi-addr` | string | `udm.sbi.server[0].address`, else `127.0.0.1` (#1308) | SBI bind address; beats the YAML (#1312). |
| `--sbi-advertise` | string | unset | The SBI host advertised to the NRF and in callback URIs (#1312); then `NEXTGCORE_SBI_ADVERTISE`, then `udm.sbi.server[0].advertise`, then the bind address when it is not a wildcard. |
| `--sbi-port` | u16 | `udm.sbi.server[0].port`, else `7777` | SBI port; beats the YAML (#1312). |
| `--tls` | flag | off | Stored only in the legacy `SbiServerConfig` placeholder (affects its reported URI scheme). The HTTP/2 listener's TLS comes from `NEXTGCORE_SBI_PROFILE`: under `production` (the default) it serves mutually-authenticated TLS; under `dev` (what every shipped deployment sets) it is plaintext. |
| `--tls-cert` | path | unset | Same placeholder-only caveat as `--tls`. |
| `--tls-key` | path | unset | Same placeholder-only caveat as `--tls`. |
| `--max-ue` | usize | `1024` | UE context pool capacity (also the denominator of the NRF load gauge). |
| `--max-sess` | usize | `4096` | Session context pool capacity. |
| `--state-file` | path | `NEXTGCORE_UDM_STATE_FILE`, else unset | The durable state file (#1836): SDM subscriptions, the UDR am-data subscriptions and the am-data changes waiting for an AMF. Unset (or empty) is memory-only, and udmd logs `no UDM state file`. A file that cannot be read fails the start rather than be overwritten. See "Durable state" below. |

## Behavior notes

- **NRF registration and load-reporting heartbeat.** When an NRF URI is configured, the UDM PUTs an NFProfile advertising one entry per served service — `nudm-sdm` (v2), `nudm-uecm`, `nudm-ueau`, `nudm-ee`, `nudm-pp`, `nudm-mt` (#394), `allowedNfTypes` `[AMF, SMF, AUSF, PCF, SCP, UDR]` (UDR since #2123: the UDR discovers the UDM to verify a UDM caller's NF type, and the NRF hides a profile from a requester this list leaves out), a per-service `allowedNfTypes: [AUSF]` on `nudm-ueau` (TS 29.503 §5.4.2.2.2, so the NRF grants an `nudm-ueau` token to the AUSF only, #1866), and `heartBeatTimer: 10`. On success it spawns a heartbeat worker every 5 s that PATCHes a real `/load` gauge — registered UEs as a percentage of `--max-ue`, clamped 0–100 (TS 29.510 §5.2.2.3.2 per code comment). Registration failure is non-fatal: the UDM logs a warning and operates without NRF.
- **am-data changes reach the AMF (#1775, TS 23.502 §4.5.1).** While an SDM subscription of a SUPI monitors its `am-data`, the UDM holds one subscription for that SUPI at the UDR (`POST /nudr-dr/v2/subscription-data/subs-to-notify`). It monitors `/subscription-data/{supi}/provisioned-data/am-data` only, with no `ueId`, and its callback is `/nudm-callback/v1/{supi}/udr-data-change/{token}`. The token is minted per subscription, and it is what admits the UDR's notification, which carries no access token (TS 33.501 §13.4.1). The UDR's `ChangeItem`s are passed on unchanged in a `ModificationNotification` naming `/nudm-sdm/v2/{supi}/am-data` and the subscription id, to every am-data SDM subscription of the SUPI. The UDR is answered 204 as soon as its notification is validated and queued, before any consumer is tried, so a slow AMF cannot make the UDR's 3 s wait run out and the change be sent twice. Each SUPI's notifications are delivered by one worker, one at a time and in the order the UDR sent them; the consumers of one notification are tried concurrently. At most 32 notifications of a SUPI wait; one more is answered 503, and the UDR resends it at its next pass. When a consumer answers 404, that SDM subscription is removed. Any other refusal (a 400, say) or an unanswered notification is logged and not resent. A UDR subscription that could not be made (the UDR down at the AMF's registration) is retried with backoff, 1 s doubling to 60 s, eight times. The UDR subscription is deleted with the SUPI's last am-data SDM subscription. Subscriptions are held in memory, so after a UDM restart the UDR's notifications on an old token are answered 404, and the UDR then removes them.
- **Hard UDR dependency with env-var fallback.** All subscription data, authentication material, and UECM persistence go to the UDR via `Nudr_DataRepository`. UDR selection uses NRF discovery-cache instances first, then falls back to `UDR_SBI_ADDR`/`UDR_SBI_PORT` (port default `7777`); with neither available, SDM/UEAU requests answer **503**. The AUSF client for SoR/UPU protection follows the same pattern: the AUSF that authenticated the UE first, then any cached AUSF, then `AUSF_SBI_ADDR`/`AUSF_SBI_PORT` (port default `7777`), failing closed (withholding `sorInfo`/`upuInfo`) on any AUSF failure since TS 33.501 defines no unprotected delivery path, per code comments.
- **Auth-vector admission is strict.** `generate-auth-data` rejects: missing `servingNetworkName`/`ausfInstanceId` (400 `MANDATORY_IE_MISSING`), malformed serving-network names (403 `SERVING_NETWORK_NOT_AUTHORIZED`, anti-bidding-down per TS 33.501 §6.1.2 code comment), SUCI deconcealment failure (403 `AUTHENTICATION_REJECTED`), unknown subscribers (404 `USER_NOT_FOUND`), auth methods other than `5G_AKA`/`EAP_AKA_PRIME` (501), and subscriptions whose AMF separation bit is unset (403, TS 33.102 Annex H per code comment).
- **SQN replay protection gates AV issuance.** After Milenage AV generation the SQN is advanced per TS 33.102 Annex C.3.2 (per code comment) and PATCHed to the UDR. A UDR 5xx or transport failure makes the UDM **refuse to issue the AV** (503) to prevent SQN replay; other non-success statuses (e.g. 404 in the matched sim) degrade with a warning and the AV is issued anyway.
- **A UECM registration the UDR does not take is not answered 2xx** (#2100, TS 29.503 §6.2.7). The UDM writes an AMF, SMF, SMSF or IP-SM-GW registration (PUT, or an AMF PATCH) to the UDR before it caches anything or sends any notification. If that write fails, nothing local changes and the consumer gets an error: a UDR `404` is `404 USER_NOT_FOUND`; another refusal (for example `403` on the UDM's scope) is `500 SYSTEM_FAILURE`; a UDR `5xx` or no answer is `503`. A non-5xx refusal and a transport failure used to be answered 201, as if registered.
- **A UECM deregistration the UDR does not take is not answered 204** (#2109). The AMF deregistration (DELETE, `purgeFlag` PATCH or `dereg-amf`), and the SMF, SMSF and IP-SM-GW deregistrations, DELETE the UDR record before anything local changes. A DELETE the UDR does not take maps the same way as a registration write: `404 USER_NOT_FOUND`, `500 SYSTEM_FAILURE` or `503`. The record stays, the AMF stays cached as serving, nobody is notified, and the consumer's retry deletes it. These used to be answered 204 with the record still stored.
- **SoR/UPU acks are MAC-verified, single-use.** When an am-data response carried a protected SoR/UPU payload, the expected XMAC-I_UE is pinned; the UE's ack MAC is compared constant-time and a match yields 204 *and clears the pin* (a replayed ack is rejected). Mismatch or missing MAC → 400 (`SOR_MAC_FAILURE`/`UPU_MAC_FAILURE`/`MANDATORY_IE_MISSING`); a MAC with nothing outstanding → 400 `UNEXPECTED_MESSAGE`. A plain ack with nothing outstanding stays 204 (backward-compatible with the matched sim, which never sends acks, per code comment). `ueNotReachable: true` is recorded without a MAC check.
- **Environment variables** read by this binary: `NEXTGCORE_SBI_OAUTH2_REQUIRE` (`1`/`true`/`TRUE`/`yes` = on; checked *before* and overriding the YAML `sbi.oauth2.require`), `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP tracing endpoint, default `http://jaeger:4317`), `NEXTGCORE_SBI_PROFILE` (see [Configuration Overview](./overview.md)), and the peer fallbacks `UDR_SBI_ADDR`/`UDR_SBI_PORT`, `AUSF_SBI_ADDR`/`AUSF_SBI_PORT` and `AMF_SBI_ADDR`/`AMF_SBI_PORT` (the AMF that receives UECM deregistration notifications and Namf calls when none is cached) used only when NRF discovery yields no instance.

## Durable state (#1836, #1885)

With `--state-file` or `NEXTGCORE_UDM_STATE_FILE`, udmd writes its SDM
subscriptions, its am-data subscriptions at the UDR and the queued am-data
changes to that file before it answers, and restores them before its listener
opens. The file is one udmd instance's: give each instance its own file, and
never two processes one file.

Every shipped deployment except compose leaves it off:

| Deployment | How to turn it on | Volume |
|---|---|---|
| Docker compose | on by default | named volume `udm_state` at `/var/lib/nextgcore` |
| Helm chart | `udm.durableState.enabled=true` | `type: pvc` (default; a ReadWriteOnce claim) or `type: emptyDir`. The render fails for `udm.replicas > 1` or a ReadWriteMany claim. |
| k8s/ (kustomize) | component `k8s/components/udm-durable-state` (claim) or `k8s/components/udm-durable-state-emptydir` | at `/var/lib/nextgcore`, file `udm-state.json` |
| EKS (`deploy-eks.sh`) | `UDM_DURABLE_STATE=pvc` (gp3) or `emptydir`. `auto` (the default) keeps the live mode. | as k8s/ |

An emptyDir survives a container restart, not a pod delete or reschedule: a new
pod starts with no state. A claim survives both. The claim modes run one replica
with strategy `Recreate`, so a rollout stops the old pod before the new one
mounts the claim. A pod delete or node drain can still overlap the two on one
node for the termination grace period, and `ReadWriteOncePod` closes that where
the CSI driver supports it. Details: `deploy/eks/README.md` ("UDM durable
state") and `deploy/helm/nextgcore/README.md`.

## Metrics endpoint (#1334)

`UDM_METRICS_PORT` (default `9090`) and `NEXTGCORE_METRICS_BIND` (default `127.0.0.1`, #837) place the unauthenticated Prometheus `/metrics` endpoint. The compose file and manifests set `0.0.0.0` inside the private container/pod network and publish no host port; the Kubernetes Service port is ClusterIP. The series are listed in the [Observability](../observability.md) chapter.
