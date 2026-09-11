# nextgcore #308: one ambient process-state test lock per crate, covering readers as well as writers

Filed as an smfd issue. It is a **workspace** issue: fixing smfd exposed the same defect in `lmfd`
and `nextgcore-sbi`, both of which criterion 1 requires closing. Named for what it is rather than
for where it was first seen.

Verified against `main` @ `8c3321b`.

#308's *symptom* is real and reproducible. **Its stated mechanism is stale**, and the two tests it
names are not the whole set — a third test fails the same way, and the dominant race is not the one
the issue describes. Everything below was measured on this machine (48 cores), not inferred.

## Verified against current main

| claim in the issue | site on `8c3321b` | still true? |
|---|---|---|
| `cargo test --workspace` fails ~1 run in 5 in smfd | 1 of 5 whole-workspace runs; 3 of 10 crate runs under load | **yes** |
| `udm::tests::the_smf_registers_with_the_udm_and_fetches_sm_data` fails at `udm.rs:853` | reproduced, `left: "DELETE" right: "PUT"` | yes |
| `tests::the_create_subscribes_to_sm_data_…` fails at `main.rs:7101` | reproduced, `left: None right: Some("sub-293")` | yes |
| a third test also fails | `a_successful_create_registers_an_activated_session_and_its_binding`, `main.rs:8040` | **the issue does not name it** |
| the mechanism is that `UDM_SBI_*` writers are unserialised | **NO** — every writer in smfd already held `UDM_ENV_TEST_LOCK` | **false** |
| `N4_TEST_LOCK` is the existing lock to check against | it exists and is correct; it is not the one at fault | yes, but not the fix |
| `ausfd`/`udmd`/`amfd` carry the same two-writer pattern | ausfd 7 writers **all locked**; udmd 3 writers **no lock at all**; amfd 1 writer | partly |
| the `ci.yml` retry hides it at ~96% | arithmetic confirmed; the `TODO` is a CONSTITUTION violation | yes |
| smfd is the only crate the workspace gate flakes in | **NO** — with smfd fixed, `lmfd` failed 2 of 20 runs and `nextgcore-sbi` 1 of 20 | **false, twice** |

## What actually races

Not one hazard but three, all the same family: **a locked writer and an unlocked reader disagreeing
about a global that neither test names.**

1. **The UDM leg's switch.** `handle_sm_context_create` consults `udm::enabled()`. A sibling with
   the switch ON and `UDM_SBI_*` pointed at its own recording UDM makes an unrelated create fetch
   *that sibling's* subscribed session-AMBR (40/80 Mbps), and the subscription outranks the config
   default — so `a_successful_create_…` asserts `(100 Mbps, 100 Mbps)` and gets the sibling's values.
2. **The `UDM_SBI_*` environment.** `main.rs:8415` uses the **same SUPI** as the `udm.rs` test.
   Its release sends `DELETE /nudm-uecm/v1/imsi-001010000000079/registrations/smf-registrations/…`
   to whatever the env names — landing on the `udm.rs` test's recording server, whose
   `find(|uri| uri.contains("smf-registrations") && uri.contains(supi))` then matches the DELETE
   before its own PUT. Hence `left: "DELETE"`.
3. **The SMF context itself.** `smf_context_init` clears every pool for the whole process, and
   **17 test sites called it with no lock of any kind**. One of them between a create and its
   assertion is why `lookup_policy_binding(…).sdm_subscription_id` reads `None`.

And the reason writer-locking was not enough is sharper than "readers were unguarded": there were
**four** locks over one ambient state (`udm::SWITCH_LOCK`, `easdf::SWITCH_LOCK`,
`eps_iwk::SWITCH_LOCK`, `main::UDM_ENV_TEST_LOCK`). Four locks are four disjoint agreements. A test
holding the easdf lock ran concurrently with a test holding the udm locks, and the easdf test's
create then fetched from the udm test's server *while both were correctly locked*.

## Decision 1: one lock per crate, declared beside the largest global it guards

`context::PROCESS_STATE_TEST_LOCK` replaces all four, and additionally covers the context wipe and
the 25 ambient **readers** the audit found. It is declared beside `GLOBAL_SMF_CONTEXT` rather than
inside any `mod tests`, so every module reaches the same static — the trap `#276` hit as a *hang*.

`pfcp_path::N4_TEST_LOCK` is deliberately kept as a second, **inner** lock. It guards a different
set (`PFCP_CLIENT`/`PFCP_POOL` `OnceLock`s and the installed client's association state), it is
already correct, and `stand_in::associated_upf` takes it on the caller's behalf and holds it for the
life of the returned value. Collapsing it in would mean either a reentrant acquisition (tokio
mutexes are not reentrant → deadlock) or reworking the stand-in's ownership, which no part of #308
asks for. The documented order — ambient first, N4 second — is unchanged and now stated in both
places.

Sync `#[test]` functions take the lock with `blocking_lock()`, which is sound precisely because they
have no runtime to block.

## Decision 2: udmd gets the same lock; ausfd's is relocated; amfd is named, not changed

- **udmd** had 3 `UDR_SBI_*` writers and **no lock at all**, with 13 tests touching that env or a
  UDR-backed path. `sbi_path::UDR_ENV_TEST_LOCK` is declared beside the fallback that reads it
  (`udm_sbi_discover_and_send_nudr_dr`) and taken by all 13. It did not flake in 6 runs before the
  change, which is not evidence of no race — a crate with no guard is not a crate with nothing to
  guard.
- **ausfd** was already correct: all 7 writers and its 3 readers took `TEST_MUTEX`, and the two
  tests that matched an audit grep without it touch neither `env::` nor the fallback. But the lock
  lived **inside `mod tests`**, which is the latent form of exactly this defect, so it moved to
  module scope beside the fallback. Relocation only; no test changed.
- **amfd** writes `SMF_SBI_*` from **one** test, and that same test is the only one in
  `ngap_path.rs` that reaches either reader (`smf_sbi_target`, `handle_ue_context_release`). One
  writer with no concurrent reader is not this defect. Named rather than fixed. Residual, stated
  because it is not zero: those readers `unwrap_or_else(|_| "127.0.0.1")` and default the port, so
  an unset env is not an error — if a future test reaches the release path it will silently dial
  whatever the writer installed rather than fail. 0 failures in 8 runs under load.

## Decision 3: lmfd is in scope, because criterion 1 is the deliverable

#308's body is smfd-only. Its **criterion 1** is not: "`cargo test --workspace` is green over at
least 20 consecutive runs". With smfd fixed, 20 runs produced 2 failures — both
`lmfd::tests::test_capabilities_handler_serves_the_derived_body` at `main.rs:3816`, which is the
second flake the #217 measurement recorded ("smfd's UDM_SBI_* env fallback **and lmfd's context
TOCTOU**") and which the issue text drops. Removing the retry makes it a red gate rather than an
annotation, so leaving it would ship a criterion this PR claims to meet and a CI that fails on it.

lmfd is the same defect with **zero** locks. `lmf_context_init` clears the cell-coordinate registry
process-wide (32 tests call it), `seed_scene_and_build_multi_rtt_lpp` writes coordinates into the
global context and never removes them, and `capabilities_body` derives `nrppaSupported` /
`nlsInterfaceSupported` from exactly that registry. The test reads the served body from the handler
and then recomputes the expected body from the context — so a wipe in that gap makes them disagree.
Its own doc comment claimed the comparison "holds whatever state a sibling test has left behind",
which is true of state left behind and false of state changed in the gap.

`context::PROCESS_STATE_TEST_LOCK`, declared beside `GLOBAL_LMF_CONTEXT`, taken by all 58 tests that
touch the context. All 58 rather than just the 33 mutators-plus-reader, because the cheap version is
the writer-only asymmetry this PR exists to remove, and lmfd's suite pays 1.0 s → 3.05 s for it.

## Decision 4: nextgcore-sbi's path-mode guard moves out of `mod tests`, and gains two readers

The third flake, and the clearest instance of the whole pattern. `OAUTH2_PATH_MODE` selects the
bespoke or the TS 29.510 OAuth2 resource paths process-wide. Its writers were **already correctly
serialised** — ten `oauth.rs` tests take `lock_path_mode()` — but the guard was declared inside
`oauth.rs`'s `mod tests`, so no sibling module could reach it, and the selector has readers in two:

- `security.rs`'s `production_profile_configures_tls_mtls_and_oauth2` asserts the derived JWKS URI
  is `/nnrf-oauth2/v1/jwks`. `apply_sbi_security_policy` derives it through `JwksCache::for_nrf`,
  which consults the selector. Concurrent with `test_flag_flips_default_to_standard`, it gets
  `/oauth2/retrieve-key`. **1 of 20 whole-workspace runs.**
- `client.rs`'s `test_oauth2_token_attached_when_enabled` stubs a token endpoint at the bespoke path
  only, so a flipped selector makes its client dial `/oauth2/token` and receive nothing.

The guard moves beside `OAUTH2_PATH_MODE` as `pub(crate)`, and both readers take it. It also becomes
a `tokio::sync::Mutex` with a sync (`blocking_lock`) and an async entry point, because two of the
guarded tests — and now `client.rs`'s reader, a third — await while holding it, and a `std` guard
held across an await blocks the executor thread. That is this repo's own recorded reason for
preferring a tokio mutex for a test switch (it was written in `easdf.rs`'s switch-lock comment).

It is **not** a clippy fix, and the first draft of this spec claimed it was on the strength of a
cached `-p` run. Measured properly: `clippy::await_holding_lock` fires 21 times workspace-wide on
both main and this branch, in `nssfd` (13), `udmd/sbi_path.rs` (3), `tsctsf` (3) and `hssd` (2) —
none in `nextgcore-sbi` on either side, so the conversion changes no count. It is justified by what
the guard does, not by the lint.

`client.rs`'s reader was found by **widening the writer's window during the revert pass**, not by a
failing run. It is the same defect one window narrower, and it is the argument for covering readers
structurally rather than only the ones a sample happens to catch.

## Decision 5: the ci.yml retry is removed, not narrowed

The retry existed for two named races. This closes the first. The second — `free_port` handing out a
port and unbinding it before the caller binds, with a per-**binary** issued-port set so two crates
can be given the same port — genuinely remains, and is now filed as **#313** (its own doc claimed it
was "tracked separately" while no such issue existed).

Removing rather than narrowing, because a retry that passes ~96% of the time against a 20% flake is
not a mitigation but a detector for the failures nobody looks at — it hid this for months behind a
warning annotation. The port half did not occur once in ~60 whole-crate runs under synthetic 40-way
load or 5 whole-workspace runs, so a rare red is the honest signal.

The CONSTITUTION's no-TODO rule is satisfied by the issue existing, not by the comment moving.

## Verification

Reproduction harness: the smfd test binary under 40 synthetic busy loops, which is the only thing
the whole-workspace run adds (`cargo test -p nextgcore-smfd` alone is green, as the issue says).
12 s per run against ~75 s for a whole-workspace run, so the rate is measurable rather than argued.

| claim | how it was made to fail | result |
|---|---|---|
| the flake is real and this harness sees it | run the harness on `8c3321b` | **3 / 10 failed**, in 3 distinct tests |
| the flake is real on the whole-workspace run too | 5 whole-workspace runs on `8c3321b` | **1 / 5 failed** (`main.rs:8040`) |
| the locking scheme is load-bearing | delete every first-line lock acquisition (38 lines: the collapse **and** the additions) | **10 / 10 failed** — 3 named tests, with the sibling's 40/80 Mbps values in the diff |
| the 25 reader locks are load-bearing **on their own** | delete exactly those 25, keep the collapse | **0 / 30 failed — the revert did NOT bite** |
| the fixed branch is green under the same load | run the harness on the branch | **0 / 20 failed** |
| smfd's fix holds on the whole-workspace gate | 20 consecutive runs, smfd fixed, lmfd not yet | **0 smfd failures**; 2 lmfd |
| lmfd's flake is real (this is the lmfd revert baseline) | the same 20 runs, lmfd unlocked | **2 / 20 failed**, same test both times |
| nextgcore-sbi's flake is real | the same 20 runs, guard still inside `mod tests` | **1 / 20 failed** |
| the sbi reader locks are load-bearing | revert the `security.rs` lock, widen the writer's window to 800 ms | **fails**, `left: ".../oauth2/retrieve-key"` — the production message exactly, plus a SECOND reader in `client.rs` this exposed |
| …and the locks close it | keep the widened window, restore both reader locks | **green** |
| all three fixes hold together | 20 consecutive `cargo test --workspace` runs | **0 / 20 failed** |
| the added clippy warnings are none | `cargo clippy --workspace --all-targets`, branch vs stashed main | 21 `MutexGuard`-across-await on **both**, same four files; CI's `cargo clippy --workspace` is **0** on both |

**The fourth row is the honest result and it is not the one I expected.** What carries the weight is
the *collapse* of four locks into one, not the reader additions. Two further experiments were run to
try to make the reader locks fail on their own, and both were negative for a reason worth recording:
widening a writer's switch-ON window to 2–3 s and unlocking one reader still produced green runs,
because `N4_TEST_LOCK` **incidentally** serialises most reader/writer pairs — both tests take a UPF
stand-in, so they could never have overlapped. The one racing writer that takes no stand-in
(`a_sdm_notification_…`) does not overlap the reader either, because the reader waits on the heavily
contended N4 lock and by then the switch is off again.

So the reader locks are kept on a **structural** argument, not a measured one, and this spec says so
rather than implying a revert proved them: 25 tests read ambient state that a sibling writes, one of
the three failures reproduced on main (`main.rs:8040`) *was* an unlocked reader with no lock at all,
and the protection those tests currently have is a side effect of a lock that guards something else.
A side effect is not an agreement. If a future change gives `associated_upf` a cheaper lock, the
incidental serialisation disappears and the hazard is live again.

## Ceilings

- **The 0/20 whole-workspace result bounds the rate, it does not prove zero.** At the measured
  pre-fix rate (~20%), 20 clean runs put the residual state-flake rate under roughly 15% with 95%
  confidence — enough to say the 1-in-5 failure is gone, not enough to certify the suite
  deterministic. The reader-lock hazard specifically is below this floor by construction.
- **The reader locks are unfalsified, not verified.** See above. This is the one claim in the PR
  that rests on reading the code rather than on a revert.
- **lmfd's fix is verified statistically, not deterministically.** Its revert baseline is the 2/20
  whole-workspace measurement, not a forced failure: `-p nextgcore-lmfd` under 40-way load is 0/12
  with the locks reverted, and widening the reader's own TOCTOU gap to 500 ms with the locks reverted
  is still green. Both negatives have one explanation — the failure needs a specific ORDER (a sibling
  seeds coordinates, the handler reads them, another sibling wipes), and a crate-alone run does not
  produce it. So the lmfd claim is: the flake was measured at 2/20, the mechanism is read from the
  code, and 20 runs after the fix are clean.
- **`free_port`'s cross-process window is untouched** (#313), and removing the retry makes it
  visible rather than fixing it. This PR deliberately trades a hidden 20% for an exposed rare one.
- **The audit was per-crate, not workspace-wide.** `rg 'set_var\("[A-Z]+_SBI_' src/bins/` covers the
  `*_SBI_*` fallbacks #308 names — smfd, ausfd, udmd, amfd, plus nrfd's OAuth2 switches. The nrfd
  ones are a different shape (each test sets its own boolean and the tests are in one module) and
  were not audited; other process-globals in other crates were not audited at all.
- **The 15+ crate-local `fn free_port` duplicates have no in-process guard either**, which is worse
  than the shared helper and is scoped into #313 rather than fixed here.
- **No E2E.** Everything here is one process's test binary; the Docker jobs are
  `workflow_dispatch`-only and untouched.
