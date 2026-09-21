# Make the OAuth2 overlay demonstrate the SECURE posture: a pinnable nfInstanceId, one registration, generated CCA keys

**Issue:** nextgcore #187 (split out of #64; PR #185 introduced the escape hatch this removes)
**Verified against:** nextgcore `main` @ `6ba388d`
**Spec basis:** TS 33.501 §13.3.1, §13.3.8.2, §13.3.8.3; TS 29.510 §6.7.5.
Spec text read at `6g_docs/specs/33501-k20.txt` (§13.3.8.2 at `:14355`, §13.3.8.3 at `:14382`)
and `6g_docs/specs/TS29510_Nnrf_AccessToken.yaml`.

## Claim-vs-site-vs-still-true

The issue and the prior `needs-human` comment each make claims. Every one re-located
at `6ba388d`.

| claim | where checked | still true? |
|---|---|---|
| `nrf-oauth2.yaml` sets `require_client_auth: false` | `docker/rust/configs/5gc/nrf-oauth2.yaml:62` | **real** |
| NRF defaults `require_client_auth` ON | `nrfd/src/main.rs:218` (`NrfPolicy::default`) | **real** |
| the opt-out is announced by a startup `warn!` | `nrfd/src/main.rs:738-745` | **real** |
| `cca_trusted_keys` is keyed by `nfInstanceId` | `nrfd/src/main.rs:200`, `:2907` | **real** |
| verification is fail-closed for an unknown issuer | `nrfd/src/main.rs:2907-2915` | **real** |
| **Blocker 1**: no NF reads an instance ID from an env var | `grep -rn 'nf_instance_id' --include='*.rs' src/bins/` ∩ `env::var` → **empty** | **real** |
| **Blocker 1**: only 5 of 19 daemons have a clap `--nf-instance-id` | `#[arg(long)] nf_instance_id` at `nrfd/src/main.rs:537`, `nefd/src/main.rs:160`, `nwdafd/src/main.rs:102`, `easdfd/src/main.rs:98`, `tsctsf/src/main.rs:115`, `scpd/src/main.rs:115` → **6, not 5** (the comment missed `scpd`) | **real, count corrected** |
| **Blocker 1**: the other daemons mint `Uuid::new_v4()` at startup | 30 mint sites; enumerated below | **real** |
| **Blocker 2**: several NFs mint an instance ID at 2–3 distinct sites | per-crate counts below | **real** |
| `docker-compose.yml` pins no instance IDs | `grep -n 'nf.instance.id' docker/rust/docker-compose.yml` → empty | **real** |
| the overlay provisions no CCA key | `grep -n CCA docker/rust/docker-compose.oauth2.yml` → only prose | **real** |
| CI skips the Docker jobs on a PR | `.github/workflows/ci.yml:121` `if: schedule \|\| workflow_dispatch` | **real** |
| `OAuth2Client::new` seeds the CCA key process-wide | `oauth.rs:995-1009` (`cca_signing_key: cca_signing_key_default()`) | **real** |
| `load_or_create_es256_key` is already idempotent, `0600`, and errors on malformed | `oauth.rs:168-215` | **real** — criterion 4's generator requirement is **already met in code**; only the overlay wiring is missing |
| `init_cca_signing_key_from_env` exists for fail-fast startup resolution | `oauth.rs:381` | **real**, and **has zero callers** — "correct but unreachable" |
| #235 (stable ID also wanted for deregistration) | `gh issue view 235` → **CLOSED** | **void** — do not cite it as a co-beneficiary |
| #186 (mTLS peer cert would remove the need) | `gh issue view 186` → **CLOSED** | **void as a future alternative**; the CCA path is the one to wire |
| #64 (parent) | `gh issue view 64` → **CLOSED** | real, closed by #185 |

### Blocker 1, enumerated

30 mint sites across 20 crates. The 14 daemons the issue's comment names as
unpinnable are unpinnable: `amfd`, `smfd`, `udmd`, `udrd`, `ausfd`, `pcfd`,
`nssfd`, `bsfd`, `upfd`, `nsacfd`, `dccfd`, `lmfd`, `mbsmfd`, `pind`.

### Blocker 2, enumerated (distinct mint sites per crate)

| crate | sites | cites |
|---|---|---|
| `amfd` | 3 | `lib.rs:281`, `sbi_path.rs:288`, `sbi_path.rs:364` |
| `udmd` | 3 | `app.rs:282`, `app.rs:3588`, `sbi_path.rs:112` |
| `smfd` | 3 | `main.rs:200`, `main.rs:1248`, `udm.rs:80` |
| `ausfd`, `bsfd`, `dccfd`, `lmfd`, `mbsmfd`, `nssfd`, `udrd` | 2 each | see `git grep` in the commit |

Each is production-reachable, not test-only. Verified for the two worst:
`amfd`'s `amf_sbi_open` is called from `lib.rs:367` and `amf_nrf_register`
from `lib.rs:959`; `udmd`'s `udm_sbi_open` from `app.rs:498` and
`register_with_nrf` from `app.rs:532`. So an AMF really does build its OAuth2
client under one UUID (`lib.rs:281`), its self NF instance under a second
(`sbi_path.rs:288`), and its NRF registration under a third
(`sbi_path.rs:364`). The CCA subject is `OAuth2Client`'s ID; the registered
profile carries a different one. Since the token endpoint **also** requires the
requester to be registered (`nrfd/src/main.rs:3217`), the authenticated path
cannot work at all today even with a pinned ID and a trusted key: the ID the
CCA asserts is not the ID that is registered.

That last point is new and is the reason blocker 2 cannot be deferred. It is
not merely "which ID is ambiguous" — it is that CCA identity and registered
identity are *structurally different values*, so `invalid_client` is guaranteed.

## Decision 1: one shared resolver in `nextgcore-sbi`, memoized process-wide

`nextgcore_sbi::context::nf_instance_id(NfType)` — a process-wide `OnceLock`
resolved on first call, with documented precedence:

1. `NEXTGCORE_NF_INSTANCE_ID` (explicit operator pin, any NF)
2. `NEXTGCORE_<TYPE>_INSTANCE_ID` (e.g. `NEXTGCORE_AMF_INSTANCE_ID`) — lets one
   compose file pin every NF without a per-service `command:` override
3. a generated `uuid::Uuid::new_v4()`, as today

Why memoized rather than "pass the ID down from `main`": it dissolves blocker 2
**structurally** instead of by 10 separate per-daemon audits. Every existing
mint site becomes a call to the same resolver, so all 30 sites in a process
return the *same* value by construction. A future 31st site cannot reintroduce
the divergence, which a per-daemon refactor could. This is the honest fix for
blocker 2's *consequence* (one identity per process) and it is a strictly
smaller, more reviewable change than threading a value through 20 `main`s.

**What it deliberately does NOT do.** It does not remove the *second
registration* itself. `amfd` still PUTs two NFProfiles to the NRF — they now
carry the same `nfInstanceId`, so the second is an idempotent overwrite of the
first rather than a duplicate registry entry, which is what unblocks this
issue. Whether the second registration should exist at all (PR #237's `pcfd`
treatment: one conformant profile, not two) is a separate per-NF conformance
question with its own blast radius. It is **split to its own issue** (see
"Split", below) rather than absorbed here.

Generated form: bare `Uuid::new_v4()`, dropping the `format!("amf-{uuid}")`
prefixes. TS 29.571 `NfInstanceId` is a UUID; `"amf-<uuid>"` is not one, and
`pcfd/src/sbi_path.rs:2893` already asserts a UUID for `pcfId`. Checked that
nothing parses the `<nf>-` prefix: the three `split_once('-')` sites in the
tree (`nsacfd/src/context.rs:51`, `nrfd/src/nnrf_handler.rs:1807`,
`pcfd/src/npcf_handler.rs:950`) are S-NSSAI path segments, SUPI/GPSI digits and
`PCF_LOCAL_PLMN` respectively — none touches an `nfInstanceId`.

Rejected: a per-daemon clap `--nf-instance-id` on all 19. It is the mechanism 6
daemons already have, and it is the one the prior comment proposed, but a flag
must be plumbed to every construction site by hand — which is exactly the
defect. The 6 existing flags are **kept** and feed the resolver as a
higher-precedence seed, so no CLI surface is removed.

## Decision 2: `cca_trusted_keys` from a directory of public JWKs

Take the issue's own floated alternative: `nrf.sbi.oauth2.cca_trusted_keys_dir`,
a directory of `<nfInstanceId>.jwk` files, merged over the inline
`cca_trusted_keys` list. Inline YAML is kept and unchanged, so no existing
config breaks.

Why: it removes the chicken-and-egg the issue names. With inline YAML the NRF's
config must quote public keys that do not exist until the NFs have started and
generated them, which cannot be expressed in a committed file. With a directory,
each NF writes its own public JWK next to its private key at startup and the NRF
reads whatever is present. Nothing has to be committed, and nothing has to
template YAML at container start.

The private key stays where it already is
(`NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE`, hex P-256 scalar, `0600`, generated on
first use). What is added is that the same code path also writes the **public**
half as an RFC 7517 JWK beside it — `<key>.jwk` — because the NRF needs it and
only the owning NF can produce it.

Rejected: an entrypoint shell script that shells out to `openssl` and templates
YAML. The in-tree key format is a raw hex scalar deliberately, not PEM
(`oauth.rs:152-157`), so a shell generator would have to re-implement scalar
extraction from OpenSSL's DER — a second, divergent implementation of the
project's key format, in bash, with no test.

## Criterion table

| # | criterion | disposition |
|---|---|---|
| 1 | `require_client_auth: false` gone; startup shows client auth required | **implemented** |
| 2 | full overlay run, every consumer presenting a signature-verified CCA | **implemented**; observation ceiling stated below |
| 3 | negative case: absent key → `invalid_client`, visible in that NF's log | **implemented** (NRF-side positive+negative test; consumer-side log line added) |
| 4 | no committed private keys; generator idempotent | **implemented** (already true in `load_or_create_es256_key`; now reached) |
| 5 | the NRF authenticates to itself | **implemented** |
| 6 | overlay E2E in CI on `oauth.rs` / `nrfd` changes, or exclusion documented | **implemented** as the two-gate split of `specs/cross-repo-e2e-gating.md` |

## What changed

`nextgcore-sbi`:

- **new** `nf_instance_id.rs` — the shared resolver (`seed` / `nf_instance_id` /
  `type_env_var`), memoized in a `OnceLock`.
- `oauth.rs` — `es256_public_jwk` (the inverse of the existing
  `parse_es256_jwk`), `publish_cca_public_jwk`, `CCA_PUBLIC_JWK_DIR_ENV`,
  `init_cca_client_credentials`, and publishing wired into `OAuth2Client::new`
  beside the key seeding that was already there. `build_cca` made `pub` so a
  deployment can assert what its NFs will actually present.
- `security.rs` — the `no_daemon_mints_its_own_nf_instance_id` source guard,
  modelled on the adjacent `OAuth2Client::new` guard.

`nextgcore-nrfd`:

- `cca_trusted_keys_dir` config key; `load_cca_trusted_keys_dir` at startup and
  `lookup_cca_trusted_key_on_disk` on a miss (the NRF boots before the NFs that
  publish into the directory).
- `nrf_instance_id()` now resolves through the shared resolver;
  `--nf-instance-id` seeds it and warns if it lost a race rather than being
  silently dropped.
- `register_self_with_own_registry` + `nrf_self_profile` — criterion 5. The NRF
  requests tokens from itself and the endpoint refuses an unregistered requester,
  so without this it was locked out of itself.

**38 self-identity mint sites across 20 daemon crates** converted to the
resolver (`git diff -U0 -- src/bins` removes 38 `Uuid::new_v4()` lines and adds 38
resolver calls). No daemon mints its own instance ID any more.

The count grew from the 28 the first sweep found, and the guard is why. Its first
version matched only the line the `Uuid::new_v4()` appeared on, which silently
passed the multi-line shape

```rust
let nf_instance_id = args.nf_instance_id.clone()
    .unwrap_or_else(|| format!("nef-{}", uuid::Uuid::new_v4()));
```

— the `Uuid` line names no identity at all. Nine further real sites were hiding
there: `nefd`, `easdfd`, `eesd`, `nwdafd`, `tsctsf` (the CLI-flag fallbacks, which
the prior comment on #187 had counted as "already pinnable" — the flag worked, the
fallback did not), `bsfd`/`pcfd` self NF instances, and `ausfd`'s throwaway id in
an outbound body. The guard now decides by the assignment the UUID flows into, and
rejects that shape; revert-verified against exactly it.

It also excludes one verified FALSE positive rather than being left noisy:
`udmd/context.rs`'s subscription constructors take `nf_instance_id` as a
*parameter* while minting the subscription's own `id`. A guard that cries wolf
gets muted, so the assignment target itself must name an identity.

For the five daemons with a `--nf-instance-id` (or `--ees-id`) flag, the flag now
**seeds** the resolver: it keeps working, keeps highest precedence, and those NFs
additionally become pinnable from the environment like every other.

Docker:

- `configs/5gc/nrf-oauth2.yaml` — `require_client_auth: false` **deleted** (the
  file now inherits the secure default rather than restating it) and
  `cca_trusted_keys_dir` added.
- `docker-compose.oauth2.yml` — a pinned `nfInstanceId`, a private-key path and a
  public-JWK directory per NF, on two named volumes (`cca_keys` private per the
  `udr_state` precedent, `cca_public` shared and public-only).
- `.github/workflows/ci.yml` — the overlay stage in `Docker E2E`, asserting the
  NRF logged client authentication REQUIRED, that public JWKs were published and
  no private key leaked into the shared directory, and that no consumer was
  refused `invalid_client`.

## Verification

Per-PR gate (runs on every PR):

- `nextgcore-sbi`: the resolver's precedence, memoization (two calls, one
  value), and that a value set in the environment **actually reaches** a
  constructed `OAuth2Client`'s CCA subject — a POSITIVE assertion, because four
  declared-and-never-read config keys were found in this tree this month.
- `nextgcore-sbi`: the public JWK written beside the private key round-trips
  through `parse_es256_jwk` back to the signing key's verifying key.
- `nrfd`: **positive** — a CCA signed by a key loaded from
  `cca_trusted_keys_dir` yields a 200 and a token whose `sub` is the pinned ID.
  **Negative** — an untrusted key yields 400 `invalid_client`. Both against an
  explicit `NrfPolicy` via `handle_access_token_request_with_policy`, the
  existing seam for exactly this.
- a source guard, in the shape of the existing
  `every_nf_builds_its_oauth2_client_through_the_shared_constructor`
  (`security.rs:1954`): no crate under `bins/` may mint an instance ID with a
  bare `Uuid::new_v4()`, so a 20th daemon cannot quietly reintroduce blocker 1.

Scheduled gate: `Docker E2E` gains an OAuth2 overlay run asserting the NRF
logged client authentication REQUIRED and that a consumer obtained a token.

Every behavioural claim revert-verified: the change is undone, the NAMED test is
watched to fail, and the change restored. Recorded per test in a doc comment.
Verified reverts, each failing the named test with the named message:

| change undone | test that failed |
|---|---|
| swap `x`/`y` in `es256_public_jwk` | `a_published_cca_jwk_is_the_public_half_of_the_signing_key` |
| rotate the key on every publish | `publishing_a_cca_public_key_twice_republishes_the_same_key` |
| drop `load_cca_trusted_keys_dir` from `from_yaml` | `a_cca_signed_by_a_directory_published_key_is_accepted_and_an_unpublished_one_is_not` |
| drop `lookup_cca_trusted_key_on_disk` | `a_key_published_after_the_nrf_started_is_still_trusted` |
| drop `register_self_with_own_registry` | `the_nrf_can_obtain_a_token_from_its_own_endpoint_under_its_own_policy` |
| reintroduce one bare `Uuid::new_v4()` in `lmfd` | `no_daemon_mints_its_own_nf_instance_id` (named `nextgcore-lmfd/main.rs:195`) |
| drop BOTH publish calls | `the_environment_alone_provisions_a_key_and_a_trust_store_entry` |

One overclaim was caught and corrected this way: the provisioning test's doc
comment first said removing the publish from `OAuth2Client::new` alone would fail
it. It does not — `init_cca_client_credentials` publishes too — so the comment now
says which revert actually fails it and names the test that covers the
constructor site on its own.

### A real isolation defect in this change's own tests, found only by looping

The two integration tests were originally one binary. Under
`cargo test -p nextgcore-sbi -p nextgcore-nrfd` looped 20×, that failed **twice**
— about 1 run in 10 — and every single run passed on its own. Cause: both tests
write process-global CCA key state (`CCA_KEY_FROM_ENV`, `CCA_KEY_OVERRIDE`) and
both published a JWK under the same `PINNED` filename, each racing the other's
`remove_dir_all`. `cargo test` runs a binary's tests in parallel with no ordering,
so the memoized resolver this change introduces cannot be exercised twice in one
process by construction.

Fixed by splitting into two test binaries — two processes — and giving each a
distinct `PINNED` literal so a future merge back into one file could not silently
recreate the collision. Re-looped **30×** with zero anomalies (load average noted
at 2.14 start / 7.80 end, so the runs were not idle-machine flattery).

Recorded because it is the second instance this month of process-global test state
producing a low-rate flake that a single green run hides.

## What the first dispatched run found, which no unit test could

Run
[35655379256](https://github.com/NextgCoreLab/nextgcore/actions/runs/35655379256):
`Format`, `Check`, `Clippy`, `Test`, `Docker Build` and `EPC bring-up` all **green**;
**`Docker E2E` failed** — and it failed on a real defect in this change that 6745
green unit tests could not have caught.

What it proved works:

- The NRF logged `nrfd-05: token-endpoint client authentication required`. The
  escape hatch is gone and the secure posture is live. **Criterion 1, observed.**
- Every NF registered under its **pinned** UUID
  (`6b1d7e3c-0000-4000-8000-0000000005f0` (SMF), `...000af0` (AMF), `...a05f`
  (AUSF), …). Blocker 1 is closed in a real container, not just in a test.

What it caught: **`0 trusted CCA key(s) configured`**, and every consumer logging

> `CCA signing key /var/lib/nextgcore/cca/<nf>-cca.key is unusable: failed to
> write ...: Permission denied (os error 13)`

Cause: a Docker named volume mounted onto a path the image does not create is
initialised **root-owned**, and these processes run as the non-root `nextgcore`
user. `Dockerfile.core` already knew this — its comment on `/var/lib/nextgcore`
states exactly that rule, for exactly this reason, from issue #66 — and the new
`cca_keys` / `cca_public` volumes did not follow it. Fixed by creating
`/etc/nextgcore/cca-public` and `/var/lib/nextgcore/cca` in the image and chowning
them (a volume at a subpath does not inherit a parent's ownership).

Worth recording for two reasons. First, the failure was **loud and diagnosable**
because the error message names the consequence — "requests will be sent WITHOUT
client authentication, and an NRF running its default policy will reject them with
`invalid_client`" — which is what made a 20-minute container run readable in one
grep. Second, it is precisely the defect class the issue is about: the code was
correct, every in-process test passed, and the *deployment artefact* was wrong.
Only the dispatched run could see it, and the PR gate would have reported green.

## The second dispatched run went green — and the green was PARTLY VACUOUS

Run
[35660647077](https://github.com/NextgCoreLab/nextgcore/actions/runs/35660647077):
**all seven jobs green**, `Docker E2E` included. The Dockerfile fix worked —
**9 public JWKs published**, 11 containers healthy, and the NRF again logged client
authentication REQUIRED.

Then the log was read rather than trusted, and one of the three overlay assertions
turned out to prove nothing:

```
grep -c 'OAuth2 Access Token Request'  ->  0
```

The step said *"if any `invalid_client` appears, fail"*, found none, and passed —
because during a bring-up-only run **no NF ever requested a token**. The assertion
was satisfied by the path never being taken. This is precisely the "a negative
assertion is satisfied by every path that never arrives" trap, and it survived a
*green* heavy CI run. Had the log not been read, criterion 2 would have been
reported as observed on the strength of a check that could not fail.

Replaced with a **positive** assertion: `cca_token_probe`
(`src/libs/nextgcore-sbi/examples/cca_token_probe.rs`), run inside the AMF and NRF
containers — the only places that can reach both the private key (on a volume
deliberately not shared with the host) and the NRF on the core network. It mints a
CCA with the same `mint_cca` the NFs use, requires a **200 with a JWS-shaped
token**, and then presents a CCA signed by an **untrusted** key and requires
`invalid_client` — so a pass cannot come from an NRF that authenticates nobody.

### Validated against a real NRF locally, before trusting it in CI

Rather than discover a flaw in the probe during a 30-minute container run, it was
driven against a real `nextgcore-nrfd` on a socket:

```
PASS positive: the NRF issued a token to 6b1d7e3c-...-000000000af0
               against a signature-verified CCA (scope "nudm-sdm")
PASS negative: an untrusted CCA key is refused invalid_client
PROBE EXIT=0
```

and corroborated from the NRF's own side:

```
nrfd-187: picked up the CCA trusted key for nfInstanceId 6b1d7e3c-...-000000000af0
          from .../6b1d7e3c-...-000000000af0.jwk (published after this NRF started)
OAuth2 Access Token Request
Issued access token for 6b1d7e3c-...-000000000af0 (AMF) -> UDM scope=nudm-sdm
```

That is criteria 2, 3 and the late-publish directory lookup all confirmed over a
real socket, independently of Docker.

The local run also **corrected the probe's own error message**: a first attempt
failed with "is not registered with this NRF" while the probe blamed the trust
store, which would have sent a reader to the wrong place. It now branches on the
NRF's wording and names the actual cause — registry vs trust store vs stale key.

## Observation ceiling (criterion 2)

`Docker Build`, `Docker E2E` and `EPC bring-up` are gated
`if: schedule || workflow_dispatch` (`ci.yml:121`), so they **skip on a PR** and
a green PR proves nothing about the overlay. This spec's claims about the
overlay are therefore backed by a **dispatched** run, whose URL and result are
recorded in the PR body. Where the dispatched run could not observe something,
the PR says so rather than reasoning about it — the prior comment on #187
recorded criterion 2 as "not verifiable without a cold image build", and that
is the failure mode this issue is about.

## Split

**One follow-up issue, not absorbed here:** the *second registration* in
`amfd`, `udmd`, `smfd`, `ausfd`, `bsfd`, `dccfd`, `lmfd`, `mbsmfd`, `nssfd`,
`udrd` — PR #237's `pcfd` treatment applied per NF (one conformant NFProfile,
not two that each omit what the other has). This issue makes those
registrations agree on identity, which is what criteria 1/2/3/5 need; it does
not make them one registration, which is a conformance question per NF with its
own review surface. No criterion of #187 is deferred to it.

## Workspace state

`cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets`
reports **0 errors** (the remaining warnings — `clone_on_copy` in
`nextgcore-nas/src/interworking.rs`, `struct update has no effect` at
`security.rs:854`, `zero_prefixed_literal` in `tests/integration/common/` — are
pre-existing in files this change does not touch).

`cargo test --workspace`: **6745 passed, 0 failed**, from a **6734/0** baseline at
`6ba388d` — +11, all new tests here. Affected crates
(`nextgcore-sbi`, `nrfd`, `nefd`, `eesd`, `pcfd`, `bsfd`) looped **12×** with zero
anomalies at 1035 tests each; the two env-driven integration binaries looped
**30×** after the isolation split. Load average recorded at each loop (0.65–7.80),
so no run is idle-machine flattery.

## Ceilings

Stated rather than implied:

1. **The scheduled overlay stage covers 10 of the 14 configured NFs.** It reuses
   the images `Docker E2E` already builds, so `dccf`, `lmf`, `mbsmf`, `nsacf` and
   `nwdaf` are configured by the overlay but not exercised by it. Recorded in the
   workflow comment as well as here.
2. **`require_client_cert_binding` and `trust_forwarded_client_cert` stay off.**
   This change provisions the CCA path (TS 33.501 §13.3.8), which is the
   alternative §13.3.8 offers precisely for deployments that cannot surface an
   mTLS peer identity. The overlay runs plaintext, so mTLS binding is not
   assertable here at all.
3. **No `x5u`/`x5c` in the CCA.** TS 33.501 §13.3.8.2 says the signed CCA "shall
   include one of" `x5u` or `x5c`, and §13.3.8.3's last bullet has the receiver
   check the NF instance ID against the certificate used for signing. This
   implementation carries neither and binds the key to the `nfInstanceId` through
   the NRF's configured trust store instead. That is a **pre-existing** deviation
   in `mint_cca` (unchanged by this PR) and is the reason a trust store is needed
   at all; it is out of scope here but worth its own issue, because it is the
   remaining gap between this and a §13.3.8-conformant CCA.
