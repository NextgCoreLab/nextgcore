# EES Configuration

The EES (Edge Enabler Server, `nextgcore-eesd`) is an Edge Enabler Layer entity per TS 23.558 / TS 24.558 / TS 29.558 — **not** an NRF-discoverable 5GC NF (there is no `nfType "EES"` in TS 29.510, per the daemon's module doc comment). It self-registers toward the Edge Configuration Server (ECS) over EDGE-6 instead of the NRF, and serves twelve `eees-*` service APIs with the `{apiRoot}/<apiName>/<apiVersion>` layout (router in `src/bins/nextgcore-eesd/src/main.rs`, TS section numbers as cited in its route comments): `eees-easregistration` (TS 29.558 §5.2, EAS registration CRUD with PUT full-replace and RFC 7396 PATCH), `eees-easdiscovery` (TS 24.558 §5.3, `request-discovery` plus discovery-change subscriptions), `eees-eecregistration` (TS 24.558 §5.2), `eees-appctxtreloc` (TS 24.558 §5.5, Determine/Initiate/Declare), `eees-eel-acr` (TS 29.558 §5.11), `eees-acrstatus-update` (TS 29.558 §5.12), `eees-cea` (TS 29.558 Common EAS Announcement, single `POST /declare` custom operation), `eees-appclientinformation` (TS 29.558 §8.4), `eees-acrmgntevent` (TS 29.558 §5.8), `eees-eeccontextreloc` (TS 29.558 §8.7.2, push/pull on `/eec-contexts` only), `eees-acr-param` (TS 29.558 ACR Parameter Information, `POST /send-acrparamsinfo`), and `eees-acrevents` (TS 24.558 §6.4, subscribe/notify). Anything else — including the legacy bespoke `nees-*` paths — falls through to 404.

Configuration is unusual for this project: the binary accepts a `-c/--config` flag (default path `/etc/nextgcore/ees.yaml`), but **the daemon never opens or parses that file** — `args.config` appears only in a unit-test assertion, and the only file `main.rs` ever reads is the OAuth2 JWKS (`--oauth2-jwks-file`). Every runtime knob is a CLI flag, plus two environment variables (`RUST_LOG` and `OTEL_EXPORTER_OTLP_ENDPOINT`). The shared `nextgcore-app` config layer is a declared dependency but is not called from any `nextgcore-eesd` source file.

> **Honesty note:** EES behavior is validated by this project's own unit tests and matched-simulator Docker E2E only, not by third-party conformance certification. Several pieces are explicitly stubbed or deferred in the source: there is no live ECS peer in this stack (without `--ecs-uri` the EDGE-6 registration request is built, logged, and skipped), full CAPIF onboarding (AEF credential exchange) is deferred — token verification uses an out-of-band JWKS file instead — and UE location/identifier exposure (eesd-09/10, NEF path) plus SessionWithQoS/TIE are deferred per the module doc comments. The `EESProfile`/`EESRegistration` structures sent to the ECS are documented in code as TS 29.558 §8 *subsets*.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/ees.yaml` (mounted read-only to `/etc/nextgcore/ees.yaml` by `docker-compose.yml`):

```yaml
# EES (Edge Enabler Server) Configuration
logger:
  level: info

ees:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.31
        port: 7777
  nrf:
    uri: https://172.23.0.10:7777
```

The docker deployment does its real configuration on the command line: `command: ["--sbi-addr", "172.23.0.31", "--sbi-port", "7777"]`. It passes no `--nrf-uri`, so that EES has no NRF and sends no access token to 5GC NFs (see `--nrf-uri` below, #1529).

## YAML parameters

**None.** The daemon defines no `#[derive(Deserialize)]` configuration struct and never reads the file named by `-c/--config`. All `Deserialize` structs in this crate are SBI message bodies (`types.rs`, `services.rs`, `acr.rs`, `acrevents.rs`, `eec.rs`, `ecs_registration.rs`), not configuration. If you need to change the bind address, port, capacity, ECS URI, or OAuth2 keys, use the command-line flags below — editing `ees.yaml` has no effect on `nextgcore-eesd`.

### Parsed-but-inert / decorative YAML fields

Since the YAML file is never parsed, **every** field in the shipped example is decorative:

- **`logger.level` is read.** The log level is `-e/--log-level` when given, else this file's `logger.level`, else `info`; `RUST_LOG`, when set, overrides all three (#691).
- **`ees.sbi.server[0]` is read (#1312).** The SBI bind is `--sbi-addr`/`--sbi-port`, else `address`/`port` here, else `127.0.0.1` and the default port. The advertised host is `--sbi-advertise`, else `NEXTGCORE_SBI_ADVERTISE`, else `advertise` here, else the bind address when it is not a wildcard; it is used in the `EESRegistration` endpoint sent to the ECS (the EES has no NRF registration); with a wildcard bind and nothing to advertise, the ECS registration is skipped and the reason logged. A wildcard is never advertised: with a wildcard bind and nothing set to advertise, the NF does not register and logs why. A config that does not parse fails startup (#1313).
- **`ees.nrf.uri` is inert.** The NRF is `--nrf-uri`, a CLI flag only (#1529); the ECS apiRoot is `--ecs-uri`, likewise.

The file exists for visual consistency with the other NF configs and to satisfy the compose volume mount.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-eesd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/ees.yaml` | Configuration file path. **Accepted but never read** by the daemon. |
| `-l, --log-file` | path | unset | Log file path. **Parsed but never consumed** — logging goes through `env_logger` regardless. |
| `-e, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `-m, --no-color` | flag | off | Disable color output. **Parsed but never consumed.** |
| `--sbi-addr` | string | `ees.sbi.server[0].address`, else `127.0.0.1` (#1308) | SBI server bind address; beats the YAML (#1312). |
| `--sbi-advertise` | string | unset | The advertised SBI host (#1312); then `NEXTGCORE_SBI_ADVERTISE`, then `ees.sbi.server[0].advertise`, then the bind address when it is not a wildcard. |
| `--sbi-port` | u16 | `7814` | SBI server port (docker deployments pass `7777`). |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-eas` | usize | `512` | Capacity cap, applied **per resource family** (see behavior notes). |
| `--ecs-uri` | string | unset | ECS apiRoot for EES self-registration over EDGE-6 (TS 29.558 §9.1 per code comment). When unset, the registration request is built and logged but skipped. |
| `--nrf-uri` | string | unset | NRF apiRoot (#1529). When set, the EES registers at the NRF as an **AF** NF instance (TS 23.558 §6.2: the EES acts as an AF toward the 5GC; TS 29.510 has no `EES` NF type), heartbeats and deregisters it, and presents an NRF-issued OAuth2 access token (TS 33.501 §13.4.1, client credentials grant with the shared CCA: `NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE`, public half under `NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR`) on its requests to 5GC NFs and on the EEC context relocation pull (scope `eees-eeccontextreloc`, see EEC context relocation below, #1664): today demo d443a's `Nsmf_EventExposure` Subscribe, check and DELETE (scope `nsmf-event-exposure`). A token the NRF does not issue fails the request (`reason="no-token"`) rather than sending it bare. When unset, no NRF registration and no token: an SMF enforcing OAuth2 refuses the Subscribe (`reason="refused"`). |
| `--ees-id` | string | fresh `ees-<UUIDv4>` per start | EES identifier advertised to the ECS (`eesId`), and the `ees-id` this EES presents when it pulls an EEC context from a source EES (see EEC context relocation below). |
| `--oauth2-jwks-file` | path | unset | JSON JWKS used to verify OAuth2 access tokens (CAPIF/NRF issuer). When unset, **every protected operation fails closed with 401** (authorization is mandatory, TS 29.558 §6 per code comment). |
| `--callback-max-attempts` | u32 | `3` | Max delivery attempts per notification callback, including the first (clamped to ≥ 1); exhausting the budget drops the notification. |
| `--callback-backoff-ms` | u64 | `1000` | Base backoff between callback retries; a `Retry-After` response header takes precedence (RFC 9110 §10.2.3 per code comment). |
| `--callback-timeout-secs` | u64 | `5` | Per-attempt callback request timeout. |

## Behavior notes

- **Resources are bound to their creator (#1865, #1937).** EAS/EEC registrations and every EES subscription record the verified identity of the consumer that created them (its token `sub`, else its client certificate; `nextgcore_sbi::owner_binding`). Only that consumer may read, update or delete them. A collection `GET` lists only the caller's own records, the same callers each item's `GET` admits. With the ECS role on, an EES registration (`eecs-eesregistration`) is refreshed, read and removed only by the EES that registered it. **Gap, stated:** the ECS routes run no per-route token gate, unlike every `eees-*` route, and eesd's production listener verifies no client certificate. So under the `production` profile an ECS caller has no verified identity, and an EES registration is refused. Authenticating the ECS routes needs the EES-side ECS client to present a token, which it does not yet do.

- **OAuth2 is fail-closed and per-operation** (eesd-08, `auth.rs`): every `eees-*` route runs `require_oauth2` *before* method dispatch. No JWKS configured, or a missing/invalid/expired bearer → 401; a valid token whose space-delimited `scope` lacks the per-API scope (the scope string equals the apiName, e.g. `eees-easregistration`) → 403 `INSUFFICIENT_SCOPE`. The shipped docker-compose command passes no `--oauth2-jwks-file`, so in that deployment every protected EES operation answers 401; `main.rs` logs a startup warning to that effect.
- **ECS, not NRF**: with `--ecs-uri` set, the EES POSTs an `EESRegistration` to `{ecsApiRoot}/eecs-eesregistration/v1/registrations` and, on 200/201, spawns a refresh task that PUTs the resource every 60 s; without `--ecs-uri` the daemon runs standalone. As of #107 the initial POST is **retried with capped exponential backoff** (5 attempts, 500 ms doubling to a 30 s cap) instead of being abandoned after one failure, the refresh **re-POSTs** on any non-2xx instead of looping on a resource the ECS no longer has, and the body carries live `easIds` and an `expTime` instead of `null` — see *Restoring a lost registration* below.

## Restoring a lost registration, and the ECS role (#107)

**Every ECS route needs a verified caller (#2050).** The `eecs-eesregistration`, `eecs-serviceprovisioning` and `eecs-targeteesdiscovery` routes accept either a verified client certificate (mTLS) or an access token for that API's scope (`eecs-eesregistration`, …), checked by the same per-operation gate as the `eees-*` routes. Anything else gets 401, or 403 for a token without the scope. Under the `production` profile the EES listener verifies a client certificate whenever one is presented, against the policy CA, without demanding one: EECs and EASes hold none. The EES-side ECS client presents its own certificate through the shared profile-following client. Under `dev` nothing presents a credential, so the ECS role answers 401 unless a caller sends a token.

Three things were silently brittle before #107, and one thing was missing entirely.

**The EDGE-6 client.**

| was | now |
|---|---|
| one POST, then `warn!("will operate without ECS")` forever — a transient blip during startup dropped the EES from the registry permanently | retried up to `MAX_REGISTRATION_ATTEMPTS` (5) with backoff `500 ms → 1 s → 2 s → 4 s`, capped at 30 s. The body is **rebuilt each attempt**, so an EAS that registered while the ECS was unreachable appears in the registration that finally lands |
| the refresh only ever PUT; a 404 — what an ECS returns for a resource lost across a restart — was logged and the loop kept PUTting forever | any **non-2xx** re-POSTs and adopts the new `registrationId`. Not only 404: a 410 or a schema-version 400 leave the EES in the identical state, and re-creating is idempotent from this side, so the narrower check would buy nothing and loop forever on those |
| `easIds: null` and `expTime: null`, so the ECS's view of this EES was wrong even on the happy path and target-EES selection could never match it | both derived from live state on every POST **and** every refresh. `expTime` is 10 minutes out and the refresh runs every 60 s, so a live EES is never expired while one that stopped refreshing is |

`easIds` is absent rather than `[]` when the EES serves no EAS: the member is optional, and an empty array asserts "serves no EAS" where absent says "not stated". Either way the ECS's discovery does not match it, which is the point — an EES advertising no EAS cannot be selected as a target.

**The ECS role.** All eight ECS-side APIs were unimplemented anywhere in the workspace, so an EEC had no EDGE-4 bootstrap and an EES could not be brought into a deployment through an ECS. `ECS_ROLE=1` now makes this process serve three of them:

| API | Path | What it does |
|---|---|---|
| `Eecs_EESRegistration` | `POST/PUT/GET/DELETE /eecs-eesregistration/v1/registrations[/{registrationId}]` | EDGE-6. Mints the `registrationId` server-side and returns it in `Location`. **404 for an id it does not hold**, which is what makes the client's re-POST recovery reachable. |
| `Eecs_ServiceProvisioning` | `POST /eecs-serviceprovisioning/v1/provisioning-requests` | EDGE-4. Returns the registered EES endpoints an EEC needs. `eecId` is mandatory. An ECS with no EES answers **200 with an empty list**, not 404 — "none available yet" and "not served here" are different states. |
| `Eecs_TargetEESDiscovery` | `POST /eecs-targeteesdiscovery/v1/target-ees-discovery` | Matches `easId` (directly, or via an AC profile's `easIds`) against the registered `eesProf.easIds`. An unfiltered query returns every EES: "which EESs exist" is a legitimate discovery. |

| Variable | Default | Effect |
|---|---|---|
| `ECS_ROLE` | unset (off) | `1`/`true`/`yes`/`on` serves the three `eecs-*` APIs from this process. A **runtime** switch rather than a cargo feature, per this project's convention that a feature-gated path is left uncompiled by CI and rots. |

**Limits worth knowing:**

- **Five of the eight ECS APIs are not implemented** — `Eecs_ECSDiscovery`, `Eecs_EASInfoManagement`, `Eecs_ACREvents`, `Eecs_ECSServiceProvisioning` and `Ecas_SelectedEES`. They answer 404, deliberately: a route returning a fabricated 2xx is worse than one that is honest about not existing. #107's own suggested approach scoped the initial surface to three.
- **The role is a role, not a separate `ecsd`.** An ECS has no `nfType` in TS 29.510 — the same fact that made EDGE-6 registration replace this daemon's old NRF self-registration — so a separate binary would gain none of the NF machinery that justifies one, and the registry an ECS matches against is the EAS pool this process already keeps. With `ECS_ROLE` unset the `eecs-*` paths answer 404 exactly as before.
- **The ECS registry is in memory**, like every other piece of EES state, so it is lost on restart — which is precisely the case the hardened client's re-POST recovery handles.
- **The `eecs-*` routes are not OAuth2-gated.** They are a different reference point (EDGE-4/EDGE-6) with different consumers, and requiring an `eees-*` scope would make an EEC's bootstrap need an EAS's token. A test pins the contrast.
- **`ECS_ROLE` is not set by any compose service**, so the default E2E path is unchanged.
- **Capacity and rejection**: the single `--max-eas` value caps each resource family independently in `context.rs` — EAS registrations, EEC registrations, discovery subscriptions, AC-information subscriptions, ACR-management-event subscriptions, ACR-events subscriptions, and stored EEC contexts. On exhaustion, create handlers return **507** with cause `INSUFFICIENT_RESOURCES`. Mandatory-IE violations return 400 `MANDATORY_IE_MISSING`; malformed JSON returns 400 `INVALID_MSG_FORMAT`; changing an immutable `easId`/`eecId` on update returns 403 `MODIFICATION_NOT_ALLOWED`.
- **Registration lifecycle** (eesd-12): a sweep every 30 s (`LIFECYCLE_SWEEP_INTERVAL_SECS`) drops expired EAS/EEC registrations; an EEC registration created without `expTime` is minted one 3600 s out (`DEFAULT_EEC_REG_LIFETIME_SECS` in `eec.rs`). All state is in-memory only — there is no state file, and the context is cleared on shutdown.
- **Notification callbacks** (D6, `notifier.rs`): every subscription callback is POSTed to its `notificationDestination` through a bounded queue (default capacity 1024; a full queue drops the newest with a warning) with bounded retry per the `--callback-*` flags; `suppFeat` negotiation echoes the hex-AND of the consumer's mask with `EES_SUPPORTED_FEATURES = 0x1` (`types.rs`).
- **EEC registration and AC profiles** (#105, TS 24.558 §5.2.2.2): when an EEC registration carries `acProfs`, the EES matches each profile against its registered EASes — but **only for profiles that include `eass`**, because the clause conditions the matching rule on that member. For each such profile the named `easId` must be registered *and* satisfy the profile's `minimumReqSvcKPIs` (`respTime`, `avail`, `reqRate` are compared; `connBand` is not, because it is a `BitRate` string on both sides and this tree has no parser for it). Outcomes:
  - **no profile matched** → the registration is refused with **404** `RESOURCE_NOT_FOUND`, before any resource is created and before any context pull is attempted;
  - **some profiles matched** → **201**, with the failures reported in the response body as `unfulfilledAcProfs` (exactly one failure) or `unfulfillAcProfs` (two or more), per NOTE 2 of the clause. Reason is `EAS_NOT_AVAILABLE` when no EAS answers to the `easId`, `REQ_UNFULFILLED` when one does but misses the KPIs. There is **no 422** — the OpenAPI declares none for `CreateEECReg`, and both members belong to `EECRegistration`, which is the 201 body;
  - `easSelReqInd: true` additionally returns the EASes the EES selected in `discoveredEas`. Omitted or `false` means the EES does not select, and the member is left as the EEC sent it.
  `ueMobilityReq` and `ueType` are stored but drive nothing: the EdgeApp_2 behaviour behind them (subscribing to UE location via NEF/NWDAF) has no path in this binary. `easBundleInfos` is not modelled at all.
- **EEC context relocation** (#105, TS 29.558 §5.10): a registration presenting **both** `eecCntxId` and `srcEesId` makes the EES `GET {srcEesId}/eees-eeccontextreloc/v1/eec-contexts?ees-id={--ees-id}&eec-cntx-id={eecCntxId}` and store a retrieved context under its own `cntxId`, so a later pull from this EES serves it. Operational limits:
  - `srcEesId` must be an **absolute `http(s)` URI** — it is used as the source EES `apiRoot`. A bare identifier logs `not addressable` and the registration proceeds without the relocated context; there is no EES-level NRF discovery in this tree to resolve one, and the OpenAPI has no companion member carrying the source EES endpoint.
  - **Security (#1664)**:
    - With `--nrf-uri`, the pull presents an NRF-issued token of scope `eees-eeccontextreloc`, target type AF. Without one, a source EES's gate refuses the pull with 401. The NRF issues that scope because every EES registers it as an `nfServices` entry of its AF profile, offered to AF consumers only.
    - The source EES checks the token against its `--oauth2-jwks-file`, so that file must hold the NRF's public keys. It also checks the token's audience: it must be `AF` or this EES's own AF `nfInstanceId`. A token for any other audience is refused 401, even with the right scope (TS 33.501 §13.4.1.1.2). That includes `EES`: this EES has one trust source and cannot tell a CAPIF-issued token from an NRF-issued one, so CAPIF tokens on this route are out of scope until a separate CAPIF trust source exists.
    - **Known limit:** EESs register at the NRF as plain AFs, so under option 1 any AF-type consumer in the PLMN can obtain an `eees-eeccontextreloc` token and pull an EEC context it can name, not only an EES. The operator accepted this when choosing option 1, which is not CAPIF-conformant; CAPIF authorization (TS 29.558 §10.2) or an EES identity check would close it.
    - Under the `production` SBI profile the pull is https with this EES's client certificate, whatever scheme `srcEesId` names. Under `dev` it uses `srcEesId`'s scheme.
  - The pull is bounded at **3 s** and never fails the registration. An unreachable, 404-ing, or malformed-responding source EES produces a `warn` and a registration that succeeded *without* continuity data — that log line is the only signal, so watch for it.
  - Only one of the two identifiers present is treated as **no** relocation (a context id with no source EES names a context nobody can be asked for, and vice versa).
  - The EES does **not** mint a new `eecCntxId` on registration, which §5.2.2.2 permits but does not require; the context keeps the id its owner gave it.
- **Environment variables**: `RUST_LOG` overrides `-e/--log-level` (the `env_logger` builder uses the flag only as the default filter), and `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry OTLP exporter endpoint, defaulting to `http://jaeger:4317` when unset. These are the only env vars read by this binary's sources.
