# nextgcore #63 (part 3 of 3): outbound peer calls follow the SBI security profile

Verified against `main` @ `1cb487c`, on top of commit `56c84f7` (PR #188).

Completes #63. **Closes it.**

## The defect

Commit `56c84f7` made the production SBI profile the default for amfd, smfd,
ausfd and udmd — but only on the **inbound** listener. Those four still built
their outbound peer clients with `SbiClient::with_host_port`, which is cleartext
`http` with no client certificate. So under the production profile:

* NF A's listener required mutually-authenticated TLS and a valid access token;
* NF A's own call to NF B went out as cleartext `http`;
* NF B's listener refused it at the TLS layer.

**Every inter-NF call failed.** The production default was a configuration that
could not work, rescued only by every shipped artefact carrying the dev opt-out.

An NF is both a server and a client on the SBI; configuring one direction is
half a posture. That is recorded as a learning, because nothing written for
`56c84f7` could have caught it: every acceptance criterion in #63 is phrased
about the *producer*, the E2E built its client by hand, and the source guard only
proved the four daemons called the *server* helper.

## The fix

### `sbi_client_config_for_profile(host, port, profile)`

Under `Production`: `https`, this NF's client certificate and key, and the CA to
verify the peer against — all from `TlsPaths::from_env()`. Under `Dev`: exactly
`SbiClientConfig::new`, so the cleartext path is byte-identical.

`SbiClient::for_peer(host, port)` wraps it with the profile resolved from the
environment. **`SbiClient::with_host_port` deliberately stays profile-blind** —
plain `http` always — because that is what a test spinning up a loopback
plaintext server needs.

### Why not make the general constructor profile-aware

Because `cargo test` sets no `NEXTGCORE_SBI_PROFILE`, so it would resolve to
`Production` and every existing client test — each of which starts a plaintext
server on loopback — would try to speak TLS to it. `cfg!(test)` does not help:
it is false when `nextgcore-sbi` is compiled as a dependency of the binaries, so
the binaries' own tests would still break. Hence an explicit helper at 22
deliberate call sites rather than one clever change.

### The shared peer-client cache

`GlobalContext::get_client(host, port)` built a cleartext config. It hands out
clients for dialling **peer NFs**, so leaving it cleartext would have silently
undone the fix for every NF that resolves peers through it. One line there covers
more than the four core NFs — pcfd and others use it too, which is why their
tests surfaced during verification.

### Client material is now required at startup

`apply_sbi_security_profile`'s production check gained the client certificate and
key. An NF whose listener comes up but which cannot dial any peer is not usable,
and "the listener started fine" is a bad way to discover that. This immediately
caught that the tests written for `56c84f7` supplied incomplete production
material — which is what the check is for.

### `NEXTGCORE_SBI_TLS_CLIENT_CERT` / `_CLIENT_KEY`

Separate from the server pair, because under mTLS an NF fills both roles and a
deployment may mount their material separately.

## Scheme comes from the profile, not from a discovered URI

In a uniformly production deployment every peer is `https`; in a uniformly dev
one every peer is `http`. A deployment mixing the two per-NF is **not
supported** — and was already broken before this, since the scheme was hardcoded
`http` regardless of what a peer advertised. Stated in the docs rather than left
implicit.

## Call sites

22 production sites; test-module sites keep `with_host_port` on purpose.

| NF | file | production sites |
|---|---|---|
| amfd | `sbi_path.rs` | 14 |
| amfd | `namf_server.rs` | 1 (`notify_client`) |
| smfd | `policy.rs` | 4 |
| smfd | `main.rs` | 1 (`SmContextStatusNotification`) |
| ausfd | `app.rs` | 1 (peer-client helper) |
| udmd | `app.rs` | 1 (peer-client helper) |
| — | `nextgcore-sbi` `context.rs` | 1 (shared cache, covers all consumers) |

## Verification

`peer_client_built_by_the_profile_helper_completes_the_transaction` extends the
mTLS + OAuth2 E2E with a consumer built **by the helper the NFs call**, not by
hand — with the certificate paths supplied through the same env vars a deployment
uses. If the helper stopped setting `https`, or dropped the client certificate,
this fails where the hand-built case would not. **Revert-verified:** restoring
the cleartext peer config fails exactly this test and no other, which is the
point — it is the only case that could catch it.

`dev_profile_peer_client_stays_cleartext` pins that dev is unchanged.

`core_nf_peer_call_paths_do_not_build_cleartext_clients` reads
`amfd/sbi_path.rs` and `smfd/policy.rs` — the two all-production peer-call files —
and fails if either reaches for `with_host_port` again. That constructor has to
keep existing for tests, which makes it exactly the thing a future edit could
grab in production code without noticing.

### Tests that now declare their profile

19 tests across amfd, ausfd, udmd, smfd, lmfd and pcfd drive **production**
peer-call code against loopback **plaintext** peers — they describe a dev-profile
deployment. Each now says so with `set_sbi_profile_override(SbiProfile::Dev)`
rather than inheriting whatever the environment holds. That is a clarification,
not a concession: in a real dev deployment (which is what every shipped artefact
configures) those paths *are* http, so the tests assert the deployment they were
always describing.

`set_sbi_profile_override` is a relaxed atomic store; parallel tests all storing
`Dev` is benign, so no serialisation is needed.

## Definition of done

- [x] All four core NFs dial peers through the profile-aware helper.
- [x] The shared peer-client cache honours the profile.
- [x] Client certificate/key are required at startup under production.
- [x] E2E proves a transaction with the consumer built by the NFs' own helper.
- [x] Dev profile byte-identical; guard prevents regression to `with_host_port`.
- [x] Workspace green; docs state the mixed-deployment limitation.
