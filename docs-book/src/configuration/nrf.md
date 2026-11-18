# NRF Configuration

The NRF (Network Repository Function, `nextgcore-nrfd`) handles NF registration, discovery, status notifications, and acts as the OAuth2 Authorization Server for the SBI (per code comments citing 3GPP TS 29.510 and TS 33.501). It reads a YAML file whose path defaults to `/etc/nextgcore/nrf.yaml` (override with `-c/--config`).

**Important:** the NRF's typed config (`NrfYaml` in `src/bins/nextgcore-nrfd/src/main.rs`) only parses the `nrf:` section. The `logger:`, `global:` and `nrf.serving:` blocks in the shipped example are accepted but **not consumed by nrfd**. Of `nrf.sbi.server[0]`, nrfd reads `address`, `port` and `advertise` (#1311) and the `tls` block (#1617, below); the CLI flags (`--sbi-addr`, `--sbi-port`, `--tls`, `--tls-cert`, `--tls-key`, `--mtls`, `--tls-ca-cert`) win over them. An absent file means the built-in defaults; a file that cannot be read or parsed fails startup.

## Example (`docker/rust/configs/5gc/nrf.yaml`)

```yaml
logger:
  file:
    path: /var/log/nextgcore/nrf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

nrf:
  serving:
    - plmn_id:
        mcc: 999
        mnc: 70
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.10
        port: 7777
        tls:
          enabled: false
          cert: /etc/nextgcore/certs/nrf.crt
          key: /etc/nextgcore/certs/nrf.key
          ca: /etc/nextgcore/certs/ca.crt
          # Minimum TLS version per 3GPP TS 33.501 §13.2
          min_version: "1.2"
```

## Parsed parameters (`nrf:` section)

Defaults below are the real values from `NrfPolicy::default()` and its constants in `main.rs`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `nrf.heartBeatTimer` | u32 (seconds) | `10` | NRF-preconfigured heartbeat default, used when an NF proposes no `heartBeatTimer` or an out-of-range one (code cites TS 29.510 Table 6.1.6.2.2-1). |
| `nrf.heartBeatTimerMin` | u32 (seconds) | `1` | Lower bound of accepted heartbeat proposals; proposals below are overridden to the default. |
| `nrf.heartBeatTimerMax` | u32 (seconds) | `3600` | Upper bound of accepted heartbeat proposals. The no-heartbeat supervision timer fires at 2x the negotiated interval. |
| `nrf.discovery.validity_period` | u32 (seconds) | `3600` | `validityPeriod` stamped into discovery SearchResults. |
| `nrf.discovery.default_page_size` | usize | `100` | Discovery page size when the consumer specifies none (values ≤ 0 ignored). |
| `nrf.discovery.max_page_size` | usize | `1000` | Cap on consumer-requested discovery page size. |
| `nrf.nf_set_allowlist` | list | absent | Entries of `nf_set_id` plus optional `nf_types` and `nf_instance_ids` (#1719). Absent: a registrant's `nfSetIdList` is accepted as sent, with a startup WARN. Present, even empty: NFRegister is refused `403` when it claims an NF Set that no entry admits for its `nfType` and instance. NFUpdate is refused `403` when a patch adds such a set, or changes `nfType` while the profile holds one. Nothing is stored on a refusal. NF Set IDs compare case-insensitively (TS 23.003 §28.12). An entry with no `nf_types` admits any type, and an entry with no `nf_instance_ids` admits any instance. The set ID names its PLMN, so an entry per set is per PLMN. At startup, a profile restored from the state file is held to the allowlist too: each set it may not claim is removed from its stored profile (WARN, and NF_PROFILE_CHANGED to subscribers). The NF stays registered for its services, and re-adding the set is refused. `nfServices[].nfServiceSetIdList` is not allowlisted; no consumer authorises on it today. An instance ID is only as trustworthy as the registrant identity behind it: pair this with mTLS (#1611). |
| `nrf.sbi.oauth2.require` | bool | `false` | Client-side: the NRF attaches NRF-issued Bearer tokens to its own outbound calls (status notifications). |
| `nrf.sbi.oauth2.require_server` | bool | `false` | Server-side OAuth2 enforcement on the NRF's own `nnrf-nfm`/`nnrf-disc` producer endpoints. The `/nnrf-oauth2/v1/access-token` and `/jwks` endpoints always stay exempt (the NRF is the Authorization Server). A token must be signed by this NRF, list the invoked service (`nnrf-nfm` / `nnrf-disc`) in `scope` (else `403`, `insufficient_scope`), and name this NRF (`NRF` or its instance ID) in `aud` (else `403 ACCESS_TOKEN_CLAIM_MISMATCH`), per TS 29.500 §6.7.3 (issue #1634). It must also be **issued by this NRF instance** (`iss` = its NF Instance ID): pin that ID (`NEXTGCORE_NRF_INSTANCE_ID` or `NEXTGCORE_NF_INSTANCE_ID`). An unpinned ID changes on every restart, and the tokens issued before it are then refused `403 ACCESS_TOKEN_CLAIM_MISMATCH`. Replicas that share `--signing-key-file` act as one NRF instance and must be pinned to the **same** ID; replicas with different IDs refuse each other's tokens. With this on, the NRF registers itself (with its nnrf-nfm / nnrf-disc / nnrf-oauth2 services) so its token endpoint can issue those scopes. |
| `nrf.sbi.oauth2.require_client_auth` | bool | **`true`** | Token endpoint requires client authentication: a **signature-verified** Client-Credentials-Assertion (CCA) bound to the body `nfInstanceId`, or an mTLS client identity. Setting this to `false` is the documented escape hatch — it makes the endpoint mint a token for any registered `nfInstanceId` a caller names, and is announced with a startup `warn!`. |
| `nrf.sbi.oauth2.require_client_cert_binding` | bool | `false` | Mandates a transport-authenticated (mTLS) client identity whose certificate URI SAN matches the request `nfInstanceId` (code cites TS 33.501 §13.3.1/§13.4.1, TS 33.310). Mismatch checks always run when an identity is present, even with this off. A CCA does **not** satisfy it. |
| `nrf.sbi.oauth2.trust_forwarded_client_cert` | bool | `false` | Whether an `x-forwarded-client-cert` header is trusted as proof of mTLS identity. With this off the header confers no identity at all. Turn it on **only** when every path to the NRF passes through a TLS terminator that sets the header and strips any client-supplied copy — it is an ordinary request header, so without such a terminator any client could assert any identity by setting it. |
| `nrf.sbi.oauth2.cca_verify_signature` | bool | **`true`** | Cryptographically verify the CCA's ES256 JWS signature against `cca_trusted_keys` (code cites TS 33.501 §13.3.8.3). Fail-closed for issuers with no trusted key. With this off a CCA is still claim-checked but authenticates nothing, so it cannot satisfy `require_client_auth`. |
| `nrf.sbi.oauth2.cca_trusted_keys` | list | empty | Entries of `nfInstanceId` + RFC 7517 EC/P-256 `jwk`. Malformed keys are logged and dropped (the issuer then fails closed when verification is on). **With the default policy and an empty store, no CCA can verify** — provision the consumers' public keys here, or use `trust_forwarded_client_cert` behind a terminator. |
| `nrf.sbi.oauth2.cca_trusted_keys_dir` | path | none | Directory of `<nfInstanceId>.jwk` public keys, loaded at startup in addition to `cca_trusted_keys` (#187). Each consumer NF publishes its own key there when `NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR` names the directory (its private key lives in `NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE`, generated on first use). An absent or unreadable directory is not fatal; a CCA from an NF with no key is rejected. Pin each NF's identity with `NEXTGCORE_NF_INSTANCE_ID` or `NEXTGCORE_<TYPE>_INSTANCE_ID` so the key name is stable across restarts. |
| `nrf.sbi.oauth2.cca_trust_anchors` | path | none | PEM file of CA certificates a CCA's `x5c` chain is validated against (TS 33.501 §13.3.8.2/§13.3.8.3, #393). Set: an `x5c` certificate is authoritative, must bind the NF Instance ID, and the key store is not consulted. Unset: a CCA carrying `x5c` is `invalid_client`; a CCA without `x5c` uses the trust store above. Consumers emit `x5c` when `NEXTGCORE_SBI_CCA_CERT_FILE` is set. |

## SBI listener TLS (`nrf.sbi.server[0].tls`, #1617)

nrfd has **one** SBI listener. With TLS on, it serves TLS and **requests** a client certificate but, by default, does not require one: a client that presents a certificate must chain to the configured CA or its handshake fails; a client without one (a discovery consumer, a probe) still connects. NFRegister / NFUpdate / NFDeregister are bound to the presented certificate's `urn:uuid:` URI SAN and RFC 9310 NFTypes (TS 33.310 §6.1.3c.3, TS 33.501 §13.1.0). A management request from a caller with no verified certificate identity (a cleartext connection, a TLS client without a certificate, a certificate without a `urn:uuid:` URI SAN) is refused `400 INVALID_CLIENT` (TS 29.510 Table 6.1.7.3-1) before anything is read or stored, and counted in `nrf_nf_management_unverified_total` (#1617 step f). There is no setting that turns this off: an NRF with TLS off serves discovery and the token endpoint but registers no NF, and says so in a startup WARN. A caller naming another NF's `nfInstanceId`, the NRF's own included, is refused the same way, since only that NF's certificate names it. With persistence on, an NRF that no longer registers itself (neither OAuth2 client nor server enforcement on) drops its own entry restored from the state file at startup.

Each setting comes from the command line, else the environment, else the YAML, else the default:

| YAML (`nrf.sbi.server[0].tls.`) | Environment | Flag | Default | Meaning |
|---|---|---|---|---|
| `enabled` | `NEXTGCORE_NRF_SERVER_TLS` (`true`/`false`) | `--tls` (on only) | off (h2c) | TLS on the listener. A non-boolean value fails startup. |
| `cert` | `NEXTGCORE_NRF_SERVER_TLS_CERT` | `--tls-cert` | `/etc/nextgcore/tls/server.crt` | The NRF's certificate. |
| `key` | `NEXTGCORE_NRF_SERVER_TLS_KEY` | `--tls-key` | `/etc/nextgcore/tls/server.key` | Its private key. |
| `ca` | `NEXTGCORE_NRF_SERVER_TLS_CA` | `--tls-ca-cert` | `/etc/nextgcore/tls/ca.crt` | The CA a client certificate must chain to. |
| `client_auth` | `NEXTGCORE_NRF_SERVER_TLS_CLIENT_AUTH` | `--mtls` (= `required`) | `optional` | `optional` or `required`. `--mtls` wins; any other value fails startup. |
| `min_version` | none | none | `"1.2"` | Only `"1.2"` (TLS 1.2 or 1.3 are negotiated); any other value fails startup rather than being ignored. |

The three files must exist at startup, or nrfd exits naming the missing one. `--mtls` without TLS is an error. With TLS off and the SBI profile `production`, nrfd logs a WARN: NFs on that profile dial their NRF over https.

**The NRF's own token client** (`nrf.sbi.oauth2.require: true`) dials the NRF's own listener. Under TLS it uses the NRF client TLS (`NEXTGCORE_NRF_TLS_*`, see the overview), and fills what those settings leave unset from the listener: the CA above as the trust anchor, the first DNS-ID of the NRF's own certificate as the server name (the self URI's address need not be in the certificate), and the NRF's own certificate as its client certificate, but only when that certificate's `urn:uuid:` names the NRF's nfInstanceId (else a WARN, and no client certificate).

## Parsed-but-inert / non-YAML settings

- `logger`, `global.max.{ue,peer}` and `nrf.serving[].plmn_id` are present in the example YAML but ignored by nrfd's config structs. Equivalent runtime behavior comes from CLI flags: `--max-ue` (default `1024`), `--log-level` (default `info`) and `--log-file`. The listen address (`--sbi-addr`, else `nrf.sbi.server[0].address`, else `127.0.0.1`, loopback since #1308), port (`--sbi-port`, else the YAML, else `7777`) and TLS (above) are read.
- The token endpoint compares NF Instance IDs as the registry keys them (#1633): a UUID case-insensitively (TS 29.510 §5.2.2.2.2), any other ID exactly. This covers the CCA `sub`/`iss`, the `x5c` certificate binding, the mTLS certificate binding and the `cca_trusted_keys`/`cca_trusted_keys_dir` lookup; the token `sub` is the lower-case UUID, with or without a proven identity. Two trust-store entries (inline, or files in `cca_trusted_keys_dir`) that spell one UUID in different case and hold different keys mean that NF has no trusted key at all: neither entry, nor a key for it from the other source, nor one in a file published later (for the NRF's life), so its CCA is refused until the stale entry is removed and the NRF restarted. The conflict is logged once as an ERROR and counted by `nrf_cca_trusted_key_conflicts_total`. A key published after start is looked up across every file whose name is that NF's ID in any case, and two different keys among them are refused the same way. The same key twice is kept.
- `--signing-key-file <path>` holds the ES256 access-token signing key: generated on first start if absent, then reused. Mount the same file into every NRF replica, or restarts and scale-out invalidate outstanding tokens (#64). `--token-expires-in` sets the access-token lifetime in seconds (default `3600`).
- `-k/--kill` is not supported and exits with an error; stop the NRF through its supervisor. `-m/--no-color` disables colored logs.
- `--nf-instance-id` sets the NRF's NF Instance ID (OAuth2 `iss` per TS 29.510 §6.3.5.2.4, per code comments); auto-generated UUID otherwise.
- `--state-file` (or `NEXTGCORE_NRF_STATE_FILE`) enables JSON-snapshot persistence of the NF registry; without it the registry is in-memory and lost on restart.
- Env overrides `NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH`, `NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING` and `NRF_SBI_OAUTH2_TRUST_FORWARDED_CLIENT_CERT` (`1`/`true`) force those knobs **on** only; they never turn a YAML-enabled knob off.
- `NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED` (`1`/`true`) is the one **loosening** override: it turns client authentication off for non-TLS dev and the matched simulator. It is applied last, so it wins over `NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH`.
- Consumer side: an NF signs its CCA with the ES256 key at `NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE` (resolved process-wide in `nextgcore-sbi`, generated `0600` on first use if absent, and an error — never a silent replacement — if malformed). Its public half must be registered here under `cca_trusted_keys`, keyed by that NF's `nfInstanceId`.
- **Status notifications follow `NEXTGCORE_SBI_PROFILE`** (#1869, TS 33.501 §13.1.0). Under **production** NFStatusSubscribe refuses an `nfStatusNotificationUri` that is not `https` with **400** `MANDATORY_IE_INCORRECT` and `invalidParams` `[{"param": "/nfStatusNotificationUri"}]`, storing nothing. A stored `http` subscription (e.g. restored from an older build) is not dialled either, so no access token is put on a cleartext request. An `https` subscriber is dialled with the profile CA and the NRF's client certificate (`NEXTGCORE_SBI_TLS_CA`, `NEXTGCORE_SBI_TLS_CLIENT_CERT` / `_KEY`). Under **dev** any URI is accepted and dialled on its own scheme, as before. The shipped k8s and helm NRF set the profile to match their NFs (`dev`, or helm's `global.sbiProfile`).
- **The NRF is not exempt from its own policy.** With `nrf.sbi.oauth2.require = true` the NRF requests tokens from itself for its outbound status notifications, and that request is authenticated like any other: give the NRF a CCA signing key and register its own public key under `cca_trusted_keys`. It deliberately does **not** self-exempt by `nfInstanceId` — a token request arriving over the network claiming to be the NRF is indistinguishable from a spoofed one, so exempting that identity would reopen the bypass this closes.
- `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry export target (default `http://jaeger:4317`).
- `NRF_METRICS_PORT` (default `9090`) and `NEXTGCORE_METRICS_BIND` (default `127.0.0.1`, #837) place the Prometheus `/metrics` endpoint (#1334; families in the Observability chapter). The Kind manifests reach it through the `nrf-metrics` ClusterIP Service; the `nrf` SBI Service is ClusterIP too (#1365), so no node port is opened for either.

## Honesty notes

- Token-endpoint client authentication (`require_client_auth`) and CCA signature verification (`cca_verify_signature`) default **on** (issue #64 gaps 1+2, TS 33.501 §13.3.1/§13.4.1.1). They are one decision: an enforced requirement that accepts an unverified assertion is no requirement at all. The matched simulator and non-TLS dev reach the previous behaviour through the explicit, `warn!`-announced escape hatch, not through a silent default.
- The remaining knobs (`require_server`, `require_client_cert_binding`, `trust_forwarded_client_cert`) default **off**: the first would gate the NRF's own producer endpoints, and the other two describe a deployment posture (mTLS-only, or a trusted TLS terminator) that the NRF cannot verify for itself.
- **Direct mTLS now yields an identity** (issue #186): the rustls-verified peer certificate's URI SubjectAltName (TS 33.310, conventionally `urn:uuid:<nfInstanceId>`) is surfaced onto `SbiRequest` and **preferred over** `x-forwarded-client-cert`. It needs no trust declaration — this process verified the chain itself, so there is no terminator to trust. `require_client_cert_binding` is therefore satisfiable on a direct connection, which it previously was not. Caveat: only rcgen-generated certificates have been tested; a vendor certificate that encodes the NF Instance ID somewhere other than a URI SAN will not be recognised.
- **NF-instance management is bound to the caller** (issue #1611, TS 33.501 §5.9.2.2 NOTE, TS 33.310 §6.1.3c.3): NFRegister, NFUpdate and NFDeregister (`PUT`/`PATCH`/`DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceID}`) are refused `400 INVALID_CLIENT` (TS 29.510 Table 6.1.7.3-1) when `{nfInstanceID}` differs from a verified identity of the caller (a UUID compared case-insensitively, TS 29.510 §5.2.2.2.2, any other ID exactly, as the registry keys them; #1633): the client-certificate NF Instance ID (the `urn:uuid:` URI SAN, preferred over other URI SANs), a trusted forwarded certificate identity, or the `sub` of a token verified under `require_server`. The profile's `nfType`, including after a PATCH, must also be one the verified certificate's RFC 9310 NFTypes extension names, when it has one. This needs no setting and changes nothing without such an identity (plaintext, TLS without client authentication, a certificate without a URI SAN or NFTypes): TS 33.501 §13.3.1.1 allows implicit NF-NRF authentication there. A registration relayed through an SCP over mTLS is checked against the SCP's own certificate, and so refused (fail-closed); nextgcore NFs register with the NRF directly. The dev PKI (`docker/rust/certs/generate-dev-certs.sh`, issue #1617) issues each NF of the compose stacks a certificate with that URN and NFTypes, from `docker/rust/certs/nf-identities.txt`; the stacks pin each NF's nfInstanceId to match.
- Behavior is validated against the project's matched simulator and unit/E2E tests, not third-party certified. Statements above describe what the code does; TS references are those cited in code comments, not conformance claims.
