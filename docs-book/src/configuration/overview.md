# Configuration Overview

NextGCore network functions (NFs) are configured with per-NF YAML files, modelled on the Open5GS configuration layout. This page describes where the config files live, how they are loaded, and the parameters shared across NFs.

> **Honesty note.** Everything below is grounded in the current source tree. Configuration behaviour is exercised by unit tests and the project's own matched-simulator Docker E2E runs; it is **not** third-party certified. Any 6G/Rel-20 knobs are non-normative research prototypes.

## Where the config files live

| Location | Purpose |
|---|---|
| `configs/` (repo root) | Minimal sample; currently only `amf.yaml` (PLMN 999-70, TAC 1, SST 1) |
| `docker/rust/configs/5gc/` | The full working set used by the Docker E2E deployment: `amf.yaml`, `smf.yaml`, `upf.yaml`, `nrf.yaml`, `ausf.yaml`, `udm.yaml`, `udr.yaml`, `pcf.yaml`, `nssf.yaml`, `bsf.yaml`, `nsacf.yaml`, `nwdaf.yaml`, `lmf.yaml`, `ees.yaml`, `mbsmf.yaml`, `dccf.yaml`, `pin.yaml`, `ucmf.yaml` plus `*-oauth2.yaml` variants (NRF/UDR/BSF/NSSF/NSACF) for OAuth2-enabled runs |
| `docker/rust/configs/` | `scp.yaml`, `sepp1.yaml`, `sepp2.yaml`; `epc/` holds the 4G/EPS set (`mme.yaml`, `hss.yaml`, `sgwc.yaml`, `sgwu.yaml`, `pcrf.yaml`, and `pgwc.yaml`/`pgwu.yaml` for `smfd`/`upfd` in their PGW roles) |
| `k8s/manifests/`, `deploy/helm/`, `deploy/eks/` | Kubernetes, Helm and EKS packaging of the same configs |

Each file has the same shape: optional `logger:` and `global:` sections, plus one NF-specific root section named after the NF (`amf:`, `smf:`, `upf:`, ...).

## How an NF loads its YAML

There are two cooperating layers.

**1. Per-NF binary (clap).** Each NF binary (e.g. `nextgcore-amfd`) parses CLI args and loads its YAML with `serde_yaml`. From `src/bins/nextgcore-amfd/src/lib.rs`:

- `-c / --config <path>` — config file, default `/etc/nextgcore/amf.yaml`
- `--log-level <level>` — `trace|debug|info|warn|error`. Without it, the config file's `logger.level`, else `info`. The short form is `-l` in amfd, mmed, sgwcd and sgwud; most other NFs, smfd included, follow Open5GS and use `-e` for the level and `-l` for `--log-file`. Run `<binary> --help` for the rest of an NF's flags
- `--ngap-addr` (AMF only) — NGAP bind address, default `127.0.0.1:38412` (loopback, #1308)
- `--sctp-backend` (AMF only) — `userspace` (default, sctp-proto over UDP) or `kernel` (Linux kernel SCTP, needs the `kernel-sctp` build feature)

Loading is lenient: if the file is missing or fails to parse, the NF logs a warning and **continues with built-in defaults** rather than aborting.

**2. Shared app library (`src/libs/nextgcore-app/src/init.rs`, `config.rs`).** `nextgcore_app_initialize()` mirrors Open5GS's `ogs_app_initialize()`: it parses `-c` (config file), `-l` (log file), `-e` (log level), `-m` (domain mask), `-k` (config section id), then reads the YAML and parses the `db_uri`, `logger`, and `global` root sections. It also provides hot-reload plumbing (`ConfigWatcher` polls the file mtime every second and re-parses on change) and a snapshot/rollback `ConfigHistoryManager`.

## Common configuration blocks

### `logger`

```yaml
logger:
  file:
    path: /var/log/nextgcore/amf.log
  level: info
```

Every NF picks its level the same way (#691): `RUST_LOG`, when set and not blank, is the filter; otherwise `--log-level` when given, else the config file's `logger.level`, else `info` (`nextgcore_core::log::nf_log_level`). An unknown value means `info`; the C configs' `fatal` and `none` mean `error` and `off`. The logger is built with `nextgcore_core::log::nf_log_builder`.

### `global`

```yaml
global:
  max:
    ue: 1024      # code default: 1024 (MAX_NUM_OF_UE)
    peer: 64      # code default: 64 (MAX_NUM_OF_PEER)
```

Also accepted under `global`: `parameter` (NF-disable and network flags such as `no_ipv4`, `no_ipv6`, `prefer_ipv4`; setting both `no_ipv4` and `no_ipv6` fails validation), `sockopt` (`no_delay`, `linger`), and `pool` (packet-buffer pool sizes, e.g. `128: 65536` ... `big: 8`).

### NF section (`amf:`, `smf:`, `upf:`, ...)

Common sub-blocks seen in the Docker configs:

- `sbi.server` — list of `{address, port}` (port 7777 everywhere)
- `sbi.client.nrf` — list of `{uri}` pointing at the NRF
- No `metrics.server`: no daemon reads one, so the shipped configs carry none (#1312). A metrics listener, where a daemon has one, is set by its environment (`MME_METRICS_ADDR`, `NEXTGCORE_METRICS_BIND`, `SMF_METRICS_PORT`, `UPF_METRICS_PORT`, `SGWC_METRICS_PORT`, `SGWU_METRICS_PORT`, `UCMF_METRICS_ADDR`) and binds loopback by default (#1308)
- `tls` — `enabled` (false by default), `cert`/`key`/`ca` paths, `min_version: "1.2"`. The config comments say `TLS_ENABLED=true SBI_SCHEME=https` turns it on, but no Rust code reads those variables. An NF's SBI listener uses TLS when started with `--tls --tls-cert <pem> --tls-key <pem>` (the SBI NFs other than amfd/smfd) or under the `production` SBI profile (amf/smf/ausf/udm, below)
- Protocol servers per NF: AMF `ngap` (38412), SMF/UPF `pfcp` (8805), UPF `gtpu` (2152), SMF `gtpc`/`gtpu`
- SMF/UPF `session` subnets (`10.45.0.0/16` gw `10.45.0.1`, `2001:db8:cafe::/48`), SMF `dns` and `mtu: 1400`
- AMF-specific: `guami`, `tai`, `plmn_support` (PLMN 999/70 in samples), `security.integrity_order`/`ciphering_order` (NIA/NEA lists), `network_name`, `time.t3512` (540 s in the Docker config), and `nas.use_nextgcore_security` (default `false` — canary for the strict TS 24.501 §4.4 NAS-security path)

## Environment overrides

| Variable | Effect | Source |
|---|---|---|
| `RUST_LOG` | Overrides `--log-level` and `logger.level` in every NF (env_logger filter syntax) | `nextgcore_core::log::nf_log_builder` |
| `DB_URI` | Overrides the YAML `db_uri` (MongoDB) | `init.rs` stage 4 |
| `<NF>_SBI_ADDR` / `<NF>_SBI_PORT` | SBI bind address/port (e.g. `AMF_SBI_ADDR`, `UDM_SBI_PORT`); defaults `127.0.0.1:7777` | each NF `lib.rs` |
| `NRF_URI`, `PCF_URI`, `NSACF_URI` | Peer NF discovery URIs | NF binaries |
| `SMF_PFCP_ADDR/PORT`, `UPF_PFCP_ADDR/PORT` | PFCP endpoints | SMF/UPF |
| `AMF_NAS_SECURITY=nextgcore` | Forces the strict NAS-security path, overriding `nas.use_nextgcore_security` in YAML | amfd `lib.rs` |
| `NEXTGCORE_SBI_OAUTH2_REQUIRE` | Forces OAuth2 enforcement on the SBI server regardless of YAML | amfd `lib.rs` |
| `NEXTGCORE_SBI_PROFILE` | SBI security profile for every SBI NF (#1795). **Defaults to `production`** (mutually-authenticated TLS + a required OAuth2 access token). `dev`/`development`/`insecure`/`local`/`test` opt out to cleartext h2c; **any other value, including a typo, stays `production`** so a mistake cannot silently downgrade security | `nextgcore-sbi` `security.rs` |
| `NEXTGCORE_SBI_TLS_CERT` / `_KEY` / `_CA` | Override the production profile's **server** certificate paths (defaults under `/etc/nextgcore/tls/`), so the certs can be mounted wherever the deployment puts them | `nextgcore-sbi` `security.rs` |
| `NEXTGCORE_SBI_TLS_CLIENT_CERT` / `_CLIENT_KEY` | Override the certificate this NF **presents when it dials a peer**. Under mTLS an NF is both server and client, and a deployment may mount the two roles' material separately | `nextgcore-sbi` `security.rs` |
| NRF URI `https://…` | How every NF reaches **its NRF** (#1617): NFRegister / NFUpdate / NFDeregister, heartbeats, discovery, subscriptions, the access-token and JWKS requests. An `https://` NRF URI (or the `production` profile) dials TLS with the NRF client TLS below, whatever the profile says about other peers; an `http://` NRF URI under `dev` stays h2c. The NRF binds registration to the presented certificate's `urn:uuid:` URI SAN and RFC 9310 NFTypes | `nextgcore-sbi` `nrf_tls.rs` |
| `NEXTGCORE_NRF_TLS_CA` | Trust anchor for the NRF's server certificate. Falls back to `NEXTGCORE_SBI_TLS_CA`, then `/etc/nextgcore/tls/ca.crt`; never to public roots | `nextgcore-sbi` `nrf_tls.rs` |
| `NEXTGCORE_NRF_TLS_CLIENT_CERT` / `_CLIENT_KEY` | The certificate this NF presents to the NRF. Falls back to `NEXTGCORE_SBI_TLS_CLIENT_CERT` / `_KEY`, then `/etc/nextgcore/tls/client.{crt,key}` when both exist; with none, no certificate (no verified identity). Half a pair fails every NRF connection, logged at startup | `nextgcore-sbi` `nrf_tls.rs` |
| `NEXTGCORE_NRF_TLS_SERVER_NAME` | Name the NRF's certificate is verified against when the NRF URI's host is not in it, e.g. `nrf` for `https://127.0.0.1:7777` (the dev PKI names no loopback address) | `nextgcore-sbi` `nrf_tls.rs` |
| `NEXTGCORE_NRF_SERVER_TLS`, `_CERT`, `_KEY`, `_CA`, `_CLIENT_AUTH` | **nrfd only**: TLS on the NRF's one SBI listener (#1617), between its flags and `nrf.sbi.server[0].tls`. The listener requests a client certificate (`optional`, default) or requires one (`required`); a presented certificate must chain to `_CA`. See [NRF](nrf.md) | `nextgcore-nrfd` `main.rs` |
| `TLS_ENABLED`, `SBI_SCHEME` | Set in `docker-compose.yml`, but **not read** by any NF; use `--tls`/`--tls-cert`/`--tls-key` or the SBI profile | compose file |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector (default `http://jaeger:4317`; no-op if absent) | `init.rs` |

Precedence, where both exist: **environment variable > YAML > compiled-in default.**

### Durable state snapshots

Ten NFs can persist their long-lived runtime state as a full-store JSON snapshot,
rewritten on every mutation and reloaded at boot: **nrfd** (NF registry),
**nssfd** (NSSAI-availability subscriptions and data), **nsacfd** (admission
counters), **udrd** (the non-subscriber resource trees), **nefd** (TS 29.122
monitoring subscriptions and device-triggering transactions) and **nwdafd**
(TS 29.520 analytics and ML-provision subscriptions — see
[NWDAF](./nwdaf.md)) and **pcfd** (AM/SM policy associations, PDU sessions and AF
application sessions — see [PCF](./pcf.md)). Since 0.1.0 three more do the
same: **smfd** (PFCP sessions, policy bindings and the IPv4 pool, #191),
**pcrfd** (Gx sessions) and **ucmfd** (the RACS capability store). Each is enabled by its
own `--state-file` flag or `NEXTGCORE_<NF>_STATE_FILE` variable (nsacfd and ucmfd
have the flag or their config's `state_file` only); with neither set
the NF is purely in-memory — the shipped Docker/E2E default for all but udrd, which
is on by default (see [UDR](./udr.md)).

`nefd`, `nwdafd` and `pcfd` differ from the older four in one respect worth
knowing: an unreadable snapshot **fails their startup** rather than only refusing to persist.
They adopt the `StateStore` type directly, so the caller sees the load error and
declines to serve; the other four predate that type and keep their own flag,
refusing the write but coming up empty.

`nwdafd` and `pcfd` go one step further and version their snapshot document,
refusing one written by a *newer* build. Restoring only the members an older build recognises and
then rewriting the file would discard the rest — the same data loss the table below
guards against, reached by downgrade instead of by corruption.

They share one implementation (`nextgcore-core`'s `state_store`), which
distinguishes three cases:

| snapshot file | meaning | behaviour |
|---|---|---|
| absent | first boot, or persistence disabled | start empty, persisting enabled |
| present, valid | normal restart | state restored, persisting enabled |
| present, **invalid** | a human must look at it | start empty, **persisting REFUSED** |

The third row is the one to know about. Previously an unreadable or malformed
snapshot was logged as a warning and treated as "no state" — and the next mutation
rewrote the file from the resulting empty snapshot, making the loss permanent and
destroying the only recoverable copy. Now the NF logs an error, starts empty, and
**refuses to write**, so the file survives for inspection. Move it aside to start
fresh deliberately.

Snapshots are written atomically (temporary file, fsync, rename, parent-directory
fsync) and created `0600` — the UDR's contains IMSI-keyed subscriber
registrations.

### Resources are bound to the NF that created them (#1809, #1865, #1937)

Every NF that lets a consumer create a resource and then manage it binds the resource to the creator's **verified** identity. This covers subscriptions, policy associations, app sessions, bindings, configurations, registrations and contexts. A later read, update or delete from anyone else is refused before anything is read or changed. Knowing a resource's id proves nothing. Most NFs share one rule, `nextgcore_sbi::owner_binding`, described below. nrf and ausf follow their own rules, given after it.

* **Identity.** The NF Instance ID of the verified client certificate, unless the certificate's RFC 9310 NFTypes name a relay (SCP or SEPP). Otherwise the `sub` of the verified access token, which survives an SCP hop. When both are present they must agree, or the caller is refused (`403`) at create (nothing is stored) and at every later operation.
* **Production.** Under the `production` SBI profile, an anonymous create is refused. A resource restored ownerless from state written before its NF's binding is frozen: nobody can manage it. Such a resource lapses where it has a lifetime (NRF and UCMF subscriptions are capped at 24 h). Under `dev`, unauthenticated stacks keep working, unbound.
* **Limit: no NF-set awareness.** A binding names one NF instance. A member of the same NF set or AMF set (TS 29.500 §6.5, TS 23.501 §5.21, TS 23.527) that takes over a failed member's resources gets `403` until the resource is re-created.
* **Limit: issue relay certificates with NFTypes.** A relay is recognised only by the NFTypes extension of its certificate. An SCP certificate without one counts as the consumer. With an access token as well, the certificate and the token disagree and the request is refused. With no token, the certificate alone is taken as the identity, so the SCP itself would own everything relayed through it and any consumer behind it could manage all of it. #2065 closes this: under `production` a certificate without NFTypes and with no token is refused, because it cannot be told apart from a relay. Under `dev` it is still taken as the owner. Until #2065 lands, the no-token case is fail-open under both profiles.

**nrf** binds NF status subscriptions (#1831) by its own registrant identity rule, not `owner_binding`. It has no SCP/SEPP relay exemption, a mismatch is a `400 invalid_client` rather than a `403`, and an identity is required when client-certificate verification or `trust_forwarded_client_cert` is on, not by the SBI profile.

**ausf** binds authentication contexts by its own equivalent (token `sub` first; #1905, #1919, #1946). It exempts an SCP certificate only, not a SEPP one, and it does not freeze an ownerless context: one restored without an owner can be managed by anyone. #2065 brings ausf in line: the same no-token refusal under `production`, and ownerless contexts frozen.

Coverage by NF, with the PR that bound each (all through `owner_binding` except nrf and ausf):

| NF | Bound resources |
|---|---|
| nrf | NF status subscriptions, by nrf's own rule (#1831) |
| amf, udm, smf, pcf, bsf, nwdaf, tsctsf, lmf, mbsmf, nsacf, eesd, dccf | event, status and exposure subscriptions and their kin (#1936) |
| udr | subscriptions (#1903, moved onto `owner_binding` by #1936) |
| smf | SM contexts, bound to the serving AMF (#1899) |
| mbsmf | TMGIs and MBS sessions, bound to the consumer that allocated or created them (#1943) |
| nssf | availability subscriptions (#1936); `nssai-availability/{nfId}`: the document belongs to the NF it names (#1955) |
| bsf | PDU, UE and MBS PCF bindings (#1959) |
| tsctsf | time-sync configurations, ASTI configurations and QoS/TSC sessions (#1969). The admin trigger is on a loopback listener only (#1980) |
| ucmf | subscriptions and provisionings (#1910, #1938); ownerless restored subscriptions lapse within 24 h (#1975) |
| pcf | AM, UE and SM policy associations, app sessions and their events subscription (#1988) |
| ees | EAS and EEC registrations and subscriptions (#1936); collection GETs list only the caller's own records, and ECS EES registrations are bound to their EES (#2049) |
| easdf | DNS contexts and baseline DNS patterns (#1936) |
| nwdaf | MLModelMonitor subscriptions (#2047) |
| ausf | authentication contexts, by ausf's own rule (#1905, #1919, #1946) |

nsacf's `slice-quotas` are operator resources, served only on the loopback admin listener (#1912). They have no NF owner to bind to.

### SBI security profile (issue #63)

Every NF that serves SBI resolves `NEXTGCORE_SBI_PROFILE` at startup (#1795;
before it, only `amf`, `smf`, `ausf`, `udm` and `easdf`). Under `production`:

* its **listener** serves SBI over mutually-authenticated TLS and requires an
  OAuth2 access token whose audience is its own NF type, whatever its own
  `--tls` flag or config `tls` block says (the profile's certificate wins).
  Under `dev` the NF's own `--tls` still applies. The exceptions, each by
  what its callers can present:
  * `scp` and `sepp` verify the client certificate but require no token of
    their own: a proxied or roaming request carries the token for the
    producer, which checks it (TS 33.501 §13.4.1.2). The SEPP's N32 listener
    refuses to start without `--tls` (N32-c is TLS, TS 33.501 §13.2.1);
  * `ees` and `pin` serve TLS without demanding a client certificate or a
    token at the listener: their callers are UEs and application servers
    (TS 23.558, TS 23.542). The EES's per-operation gate checks tokens;
  * `nrf` serves its own TLS (`nrf.sbi.server[0].tls`) with a client
    certificate optional (#1617), and refuses to start without TLS;
* their **outbound peer calls** use `https`, presenting this NF's client
  certificate and verifying the peer against the configured CA;
* they **refuse to start** when any certificate named above is missing —
  including the client material, since an NF that cannot dial its peers is not
  usable — rather than falling back to cleartext.

The outbound half also covers the shared peer-client cache in
`nextgcore-sbi`'s global context, so **peripheral NFs that resolve peers through
it follow the profile too**.

**Every NF presents tokens under `production`** (#1665). `bsf`, `dccf`, `lmf`,
`mbsmf`, `nsacf`, `nssf`, `nwdaf`, `pcf`, `tsctsf`, `ucmf` and `udr` install their
outbound OAuth2 client under this profile even with their `sbi.oauth2.require` knob
off. A consumer presents an NRF-issued token on each service request (TS 33.501
§13.4.1.1.2), and the four NFs above require one under this profile. The knob
still decides whether those NFs' own listeners require a token.

Every artefact this repo ships — `docker/rust/docker-compose.yml`,
`k8s/manifests/`, and the Helm chart via `global.sbiProfile` — sets the explicit
`dev` opt-out, because none of them mount SBI certificates. Local development and
the matched-simulator E2E are therefore unchanged.

**Mixed deployments are not supported:** the scheme comes from the profile, not
from a peer's advertised URI, so run either a uniformly `production` or a
uniformly `dev` core. (Before this, the scheme was hardcoded `http` regardless of
what a peer advertised, so mixed was already broken.)

The NFProfile each NF registers advertises, in `nfServices[].scheme`, the scheme
its own SBI listener serves (#1791): `https` once the listener is TLS, `http`
otherwise. Only `amf`, `ausf`, `smf` and `udm` take their listener's TLS from this
profile. The other NFs still take it from their own `--tls` flag or TLS config,
or serve cleartext only (`nssf`, `udr`), whatever the profile says (#1795). Their
advertised scheme follows the listener in either case.

### NEF northbound exposure (issue #110)

`nefd` is the only NF whose consumers are **outside** the operator — third-party
Application Functions over the TS 29.122 T8 APIs — so its northbound surface has
rules the internal SBI ones do not.

**Always on, not configurable:**

* **The SUPI is never sent to an AF** (TS 33.501 §5.9.2.3). Monitoring
  notifications echo the external identity the AF itself supplied (`msisdn` or
  `externalId`), in the same member it used. An AF that targeted a UE by the
  NextGCore-internal `supi` extension gets **no** UE identity in its
  notifications rather than the SUPI.
* **A monitoring request must resolve to exactly one UE.** A GPSI is translated
  to a SUPI via UDM (TS 29.503 `id-translation-result`), and a target that
  cannot be resolved is refused with `404 UE_NOT_FOUND`. It is never promoted to
  a network-wide `anyUE` subscription — which is what previously happened to any
  request naming its UE by `msisdn` or `externalId`.
* `externalGroupId` (group-scoped monitoring) is refused rather than ignored, for
  the same reason: an ignored group identifier used to fall through to
  network-wide scope.

**Caller authentication is opt-in and off by default**, so the matched-simulator
E2E path is unchanged:

| knob | effect |
|---|---|
| `nef.sbi.oauth2.require: true` / `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` | require an OAuth2 token with audience `NEF` on every northbound route |
| `--verify-client` (needs `--tls`) | require and verify a client certificate; its URI SAN becomes the caller's identity |
| `--verify-client-cacert` | CA bundle for the above |
| `--udm-sdm-uri` | UDM used for GPSI→SUPI resolution; defaults to `--udm-uri` |

With authentication enabled, **subscription ownership is keyed to the
authenticated identity** rather than to the `{scsAsId}` path segment, so one
client can no longer delete another's subscriptions by naming their ID. With it
disabled the NF logs a startup warning and ownership falls back to that path
segment, which is a routing check and not a security one — do not expose such a
listener to an untrusted or partner-facing network.

Two limits worth knowing. `--verify-client` without `--tls` **fails startup**
rather than running a plaintext listener that reports itself as mutually
authenticated. GPSI resolution needs the UDM's `id-translation-result`, which
this repo's `udmd` serves from the UDR's identity data (it answered `501` before
#85 was fixed); a GPSI the UDR has no mapping for is still refused with `404`.

### A listener that cannot be bound (#2056)

Under the production SBI profile, an NF that cannot bind a listener it is configured with exits at start-up with status `78` (`EX_CONFIG`), logging the NF, the listener and the address. This covers its `/metrics` endpoint, the udmd NES and nsacfd SLA-observe metrics listeners, and the pcrfd Gx/Rx and hssd S6a Diameter listeners (#2088). Every TCP, SCTP and Diameter listener in the NFs either fails start-up through its error or goes through this rule; a source test checks each call site. It does so before serving anything, so the orchestrator reports a crash loop rather than an NF that runs on silently without metrics. Under `dev` the NF logs a warning and runs on without the listener, which was the behaviour of every profile before #2056.

**The N26 exception (#2073).** amfd's N26 GTP-C listener (`AMF_N26_ADDR`, `AMF_N26_INTERWORKING`) and mmed's (`mme.n26.server`, `MME_N26_INTERWORKING`) stay non-fatal under every profile, production included. They are the one deliberate exception to the rule above. Interworking without N26 is a specified mode (TS 23.501 §5.17.2.3), so an N26 socket that does not come up degrades the NF to a conformant one rather than a broken one:
- the AMF forces its N26 posture off, so every UE is told IWK N26 = 1, "interworking without N26 supported";
- the MME rejects an inter-system TAU from 5GS with EMM cause #9, as TS 24.301 requires of an MME without N26.

Taking either daemon down instead would turn an interworking misconfiguration into a total 5G or LTE outage. The failure is logged at error level.

### Request paths every SBI server refuses (#1934, #1939)

Before routing, before the callback exemption and before any OAuth2 or resource-scope check, every nextgcore-sbi server answers `400 INVALID_MSG_FORMAT` to a request path that has:
- an empty segment (`//` anywhere, a leading `//`, a trailing `/`), or
- a dot segment (`.` or `..`, also percent-encoded as `%2e`).

This is so a router and a per-path check can never disagree on which resource a path names (#1934: `//` once skipped a resource scope).

A percent-encoded `/` (`%2F`) or `\` (`%5C`) inside a segment is accepted. A resource URI variable that is a free-form string (TS 29.519 `{appId}`, TS 29.122 `{scsAsId}`, `{afId}`) may carry one. No router or per-path check in this tree decodes a path before splitting it, so an encoded separator is one segment to all of them. A router that decodes must do so per segment, after splitting. The HTTP/3 prototype transport applies the same check.

## Common parameters and code defaults

| Parameter | Default (from code) | Where defined |
|---|---|---|
| Config file path | `/etc/nextgcore/<nf>.yaml` | clap `Args` in each NF |
| Log level | `info` | clap `Args` / `nf_common_init` |
| SBI bind | `127.0.0.1:7777` | env fallback in NF `run()` |
| `global.max.ue` | `1024` | `config.rs` `MAX_NUM_OF_UE` |
| `global.max.peer` | `64` | `config.rs` `MAX_NUM_OF_PEER` |
| Metrics port | `9090` (all shipped configs) | Docker YAMLs |
| NF-instance validity | `30` s (must be non-zero) | `NextgcoreLocalConf::prepare()` |
| Subscription validity | `86400` s | `NextgcoreLocalConf::prepare()` |
| Message wait duration | `10` s (derives SBI/PFCP/GTP retry timers) | `NextgcoreLocalConf::prepare()` |
| Handover wait | `300` ms | `NextgcoreLocalConf::prepare()` |
| `tls.enabled` | `false` | Docker YAMLs |
| `nas.use_nextgcore_security` (AMF) | `false` | amf.yaml / amfd |
| Max PLMNs / slices / sessions / bearers | 6 / 8 / 4 / 4 | `config.rs` constants |

## A set clock is required (PFCP NFs)

`nextgcore-smfd`, `nextgcore-sgwcd`, `nextgcore-upfd`, `nextgcore-sgwud` and `nextgcore-mbsmfd` **refuse to start when the local clock reads before 2020-01-01**. They exit with an error naming the clock.

Each of these NFs puts its start time in every PFCP Association Setup and Heartbeat, as the Recovery Time Stamp (TS 29.244 §8.2.65, NTP-era seconds since 1900; #995). A host without a real-time clock that boots at 1970 would advertise a 1970 start time. Peers then misjudge restarts: one is missed, or a false one releases every session. So the NFs refuse to start rather than send a wrong stamp.

On a host or node that may boot without a set clock (an RTC-less board, a VM restored from a snapshot), start these NFs only after the clock is synchronised:

- **systemd:** order the unit `After=time-sync.target` and `Wants=time-sync.target`, and enable a time-sync waiter such as `systemd-time-wait-sync.service` (or chrony's `chronyd-wait`).
- **Kubernetes:** add an init container that waits for NTP sync, for example `chronyc waitsync` or polling `timedatectl show -p NTPSynchronized`. Alternatively, rely on the pod's restart policy: the NF exits, and the kubelet restarts it with back-off until the node clock is set.
- **Docker / Compose:** `restart: unless-stopped` (or `on-failure`) retries the same way. The containers use the host clock, so synchronise the host.

## Dynamic reconfiguration

`nextgcore-app` includes a `ConfigReloadManager` that watches the config file and re-parses the `global` and NF-local sections on change, plus a versioned snapshot store with rollback and JSON export/import. These are library facilities (unit-tested); how much each NF wires them in varies — check the individual NF pages before relying on hot reload in a deployment.
