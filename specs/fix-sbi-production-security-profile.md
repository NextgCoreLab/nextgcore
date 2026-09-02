# nextgcore #63 (part 2 of 3): a production SBI security profile for the four core NFs

Verified against `main` @ `1cb487c`.

Ships `Refs #63`. **#63 stays OPEN**, and the open count deliberately does not
move. Read "what is deliberately not here" before treating that as a convention
violation — the remaining half is named, planned and file:line-verified below.

## The defect

The four core control-plane NFs — AMF, SMF, AUSF, UDM — served SBI over cleartext
h2c and verified no access tokens. TS 33.501 §13.1.0 requires mutually
authenticated TLS inside a PLMN and §13.4.1.1 requires producers to verify a
signed access token. The `with_tls` builder already existed and thirteen
peripheral NFs used it; these four never called it, so the NFs carrying
subscriber identifiers, authentication vectors and session context were the ones
running in the clear.

`SbiSecurityPolicy::production()` — TLS + mTLS + OAuth2 — was defined and had
**no non-test caller**, so the intended posture was dead code.

## What this ships

### One resolved posture per process (`libs/nextgcore-sbi/src/security.rs`)

`SbiProfile` is `Production` or `Dev`, resolved from `NEXTGCORE_SBI_PROFILE`.
**`Production` is the default**, and — the load-bearing detail — so is every
*unrecognised* value: `NEXTGCORE_SBI_PROFILE=devel` must not read as "insecure is
fine". Only `dev`/`development`/`insecure`/`local`/`test` opt out, and doing so
logs a `warn!` naming what is exposed.

`apply_sbi_security_profile` is the single place that turns the policy into
listener settings: TLS from the policy's certificate paths, `verify_client` for
mTLS, `require_oauth2` with the NRF's JWKS as the key source, and the NF's own
type as the expected audience. Under `Dev` it returns the config **untouched**,
so the existing h2c path is byte-identical.

Centralised on purpose: four NFs each build their listener at a different site,
and a posture expressed as four copies of twenty lines is a posture that will
disagree with itself — the `--kill` flag was duplicated across twelve daemons and
was therefore wrong in twelve places at once.

### Fail closed at startup, never fall back

A production profile whose certificate, key or CA file is missing is a **startup
error naming the path**, not a silent downgrade. A posture that degrades when a
file is absent is not a posture. It surfaces at boot rather than as a handshake
failure on the first peer connection, which would present as a peer problem.

`TlsPaths` gained `NEXTGCORE_SBI_TLS_{CERT,KEY,CA}` overrides. The compiled-in
`/etc/nextgcore/tls` cannot be right for Kubernetes Secret mounts, Docker bind
mounts and packaging all at once, and a production profile that is unusable
wherever it does not match is a production profile operators will switch off.

### amfd advertises what it actually serves

`advertised_sbi_scheme()` follows the listener, and the NFProfile service entry
and callback base URL both use it. Hardcoded `http` there would publish an
unusable URL for a TLS listener, and that failure appears on the *peer's* side as
a connection error with nothing pointing back at the AMF's registration.

### Dev opt-out in every shipped artefact, in the same commit

Flipping the default before the dev artefacts opt out would break everything and
look like a code bug — the same sequencing trap as the SCTP node-prerequisite
work. So both land together:

- `docker/rust/docker-compose.yml` — one line on the `&common-env` anchor, which
  every service already merges (`NEXTGCORE_SBI_PROFILE: ${NEXTGCORE_SBI_PROFILE:-dev}`).
  The `.features`, `.kernel-sctp` and `.oauth2` overlays inherit it.
- `k8s/manifests/{amf,smf,ausf,udm}.yaml` — verified with `kubectl kustomize
  deploy/eks`, which renders four `NEXTGCORE_SBI_PROFILE` entries; the EKS overlay
  kustomizes these same manifests, so one edit covers both.
- `deploy/helm/nextgcore/templates/{amf,smf,ausf,udm}.yaml` plus
  `global.sbiProfile: dev` in `values.yaml`.
- `docker-compose-epc.yml` needs nothing: it runs the 4G stack, none of these four.

## Verification

`mtls_oauth2_e2e` is criterion 6: a real TLS handshake with client-certificate
verification, a real token minted by a stub NRF and fetched over the wire, and a
real signature check against a JWKS. Five cases — the transaction succeeds; it
fails `AuthenticationFailed` when the token endpoint is down (guarding PR 181's
fix from outside); a tokenless request is 401; a TLS client with **no client
certificate** is refused; a cleartext client cannot reach the TLS listener.

That fourth case exists because without it the whole module would pass against
`verify_client = false` — a TLS-only listener serves a client that brings no
certificate, so "mTLS" would have been untested. **Revert-verified:** disabling
`verify_client` fails all five.

Two source guards cover what the library E2E cannot: the E2E proves the library
path works, not that each daemon reaches it. `every_core_nf_applies_the_sbi_profile`
reads the four daemons' sources, and `amfd_does_not_hardcode_its_advertised_scheme`
pins both scheme sites.

## What is deliberately NOT here

**The outbound half of criterion 1.** This wires the INBOUND listener. The four
NFs still build peer clients with `SbiClient::with_host_port`, which defaults to
cleartext http with no client certificate, so a call between two
production-profile NFs fails at the TLS layer. Found while verifying, after the
posture decision was taken. The production profile now logs a `warn!` saying so
at startup, because the alternative is debugging a connection error on the callee
with nothing pointing at the caller's scheme.

Nothing shipped is affected — every artefact above is dev-profile — but it does
mean the production default is not yet an end-to-end working configuration, and
that is why #63 stays open.

### Verified plan for the outbound half (checked against `main` @ `1cb487c`)

43 `SbiClient::with_host_port` / `SbiClient::new` sites across seven files, test
modules included:

| NF | sites | files |
|---|---|---|
| amfd | 19 | `sbi_path.rs`, `lib.rs`, `namf_server.rs` |
| ausfd | 11 | `app.rs` |
| smfd | 8 | `main.rs`, `policy.rs` |
| udmd | 5 | `app.rs` |

Add `sbi_client_config_for_profile(host, port) -> SbiClientConfig` beside
`apply_sbi_security_profile`: under `Production` set `with_https()` plus
`ca_cert`/`client_cert`/`client_key` from `TlsPaths::from_env()`; under `Dev`
return today's config unchanged. Then give each NF one local
`fn peer_client(host, port) -> SbiClient` and route its **non-test** sites
through it.

**The trap to avoid:** do NOT make `SbiClientConfig::new` / `with_host_port`
profile-aware in the library. `cargo test` sets no `NEXTGCORE_SBI_PROFILE`, so
they would resolve to `Production` and every existing client test — which starts a
plain-http server on loopback — would try to speak TLS to it. `cfg!(test)` does
not save you either: it is false when nextgcore-sbi is compiled as a dependency
of the bins, so the bins' own tests would still break. An explicit helper at the
call sites is why this is 25-ish deliberate edits rather than one clever one.

Once that lands, extend `mtls_oauth2_e2e` so the consumer side is built by the
same helper the NFs use, and #63 can close.

## Definition of done (this PR)

- [x] `grep -R with_tls src/bins/nextgcore-{amfd,smfd,ausfd,udmd}` — reached via
      `apply_sbi_security_profile`, pinned by a source guard (criterion 1, inbound).
- [x] amfd advertises `https` and an `https://` base URL under the profile;
      cleartext cannot reach a TLS listener (criterion 2).
- [x] The profile sets `require_oauth2`; a tokenless request is 401 and an
      unconfigured JWKS is 503 (criterion 3).
- [x] `SbiSecurityPolicy::production()` has a non-test runtime caller via
      `for_profile` (criterion 4).
- [x] mTLS + OAuth2 transaction end to end, plus the token-endpoint-down negative
      case (criterion 6, library-level — scope limit stated in-test).
- [x] Dev/E2E flows preserved through an explicit opt-out in every shipped
      artefact (criterion 7).
- [ ] Outbound peer clients follow the profile — planned above, not shipped.
