# nextgcore #107: give the deployment an ECS, and make the EES's EDGE-6 client survive one

Verified against `main` @ `8f38870`.

Every claim in #107's "Current implementation" section, all of which it recorded
against `76ea248`, still held. That is unusual for this backlog and worth saying:
this issue's cites did not go stale.

## Verified against current main

| claim in the issue | site on `8f38870` | still true? |
|---|---|---|
| the only `eecs-*` surface in the workspace is a *client* | `eesd/ecs_registration.rs`; `rg 'eecs-'` finds nothing server-side | yes |
| no `ecsd` binary exists | no workspace member references it | yes |
| self-registration is skipped when `--ecs-uri` is unset | `ecs_registration.rs:119-126` | yes |
| on POST failure it logs a warning and permanently gives up | `:136-139`, one attempt, no retry | yes |
| `spawn_refresh` only PUTs; a non-2xx is only logged and it never re-POSTs | `:187-205`, `log::warn!("… refresh returned status {}")` at `:200` | yes |
| the body is static: `eas_ids: None`, `exp_time: None` | `:81`, `:83` | yes |
| eesd routes only `eees-*`; no `eecs-*` server routing | router in `main.rs`, ~30 arms, all `eees-*` | yes |
| all 8 ECS-side APIs are unimplemented server-side | confirmed | yes |

## Decision 1: a role inside eesd, not a new `ecsd` binary

#107 offers either. Three reasons for the role:

- **An ECS is not a 5GC NF.** It has no `nfType` in TS 29.510 — the same fact that
  made `ecs_registration` replace eesd's old (incorrect) NRF self-registration. So a
  separate binary gains none of the NF machinery (NRF profile, heartbeat, discovery)
  that justifies one for nefd/easdfd/tsctsf, the precedents #107 cites.
- **The registry an ECS matches against is the registry this process already
  keeps.** `Eecs_TargetEESDiscovery` matches on registered `easIds`, and the EAS pool
  those come from lives here. Crossing a process boundary to read it would mean
  inventing a protocol TS 29.558 does not define.
- **It costs one runtime switch** instead of a Dockerfile, a compose service, a
  config file and a health probe, none of which #107 asks for.

`ECS_ROLE=1`, off by default, and a **runtime** switch rather than the cargo feature
#107 suggests — this project has a recorded convention for that, because a
feature-gated path is left uncompiled by CI and rots. With the switch off,
`ecs_role::route` returns `None` and the router's own 404 answers, so the paths
behave exactly as before rather than merely being quiet.

## Decision 2: three of the eight APIs, and the other five stay 404

#107's own suggested approach scopes the initial surface to
`Eecs_ServiceProvisioning`, `Eecs_EESRegistration` and `Eecs_TargetEESDiscovery`,
"to stay implementable". The remaining five — `Eecs_ECSDiscovery`,
`Eecs_EASInfoManagement`, `Eecs_ACREvents`, `Eecs_ECSServiceProvisioning`,
`Ecas_SelectedEES` — answer 404 rather than a stub. A route returning a fabricated
2xx is worse than one that is honest about not existing: this crate already made
that call for three `eees-*` APIs in #106, which answer 501 for the same reason.

Two response-code choices inside the three are deliberate and each has a test:

- **A refresh for an id the ECS does not hold is 404**, not 200 and not a silent
  re-create. That 404 is precisely what the hardened client's recovery keys on, so
  an ECS that answered 200 would make criterion 4's recovery *unreachable* — the
  server and the client have to agree, and a revert of this arm fails the client's
  test as well as the server's.
- **Provisioning with no registered EES is 200 with an empty list**, not 404. "No
  EES is available yet" and "this ECS does not serve provisioning" are different
  states and a consumer must be able to tell them apart.

## Decision 3: the refresh re-POSTs on ANY non-2xx, not only on 404

#107's criterion 4 names 404. The implementation is wider, and the reason is that
the narrower check buys nothing:

a 410 Gone, or a 400 from an ECS that has forgotten the schema version an id was
created under, leave the EES in *exactly* the same state as a 404 — PUTting a
resource that will never accept it again. Re-creating is idempotent from this side
(the ECS mints a fresh id), so the only effect of checking `== 404` would be to loop
forever on those statuses. Stated in the function's own doc so a later reader does
not "tighten" it back.

The interlock is tested from the other side too: an **accepted** refresh must not
re-POST. Without that, "re-create on failure" could be satisfied by a version that
re-creates every tick, minting a new id every 60 seconds and leaving the ECS holding
a growing pile of dead registrations.

## Decision 4: `easIds` is derived at send time, not maintained by hooks

Criterion 5 asks that `easIds` be "updated on EAS register/deregister". Two ways to
do that:

1. Hook every mutation of the EAS pool and push a fresh registration.
2. Derive the list from the live pool each time a body is built.

(2), because the registration is already sent on a 60-second timer and (1) would
add a second, event-driven sender racing it — two writers of one remote resource,
where the loser silently overwrites the winner. Deriving at send time makes the
next refresh carry the change and cannot disagree with itself. The cost is up to
one refresh interval of staleness at the ECS, which is stated as a ceiling.

`easIds` is `None` rather than `Some([])` for an empty pool: the member is optional,
and an empty array asserts "serves no EAS" where absent says "not stated". The
ECS's own discovery does not match either, so the choice is about honesty rather
than behaviour.

`expTime` is 10 minutes out against a 60-second refresh, so a live EES is never
expired by an ECS that honours it while one that has stopped refreshing is. Its
timestamp formatter is hand-rolled (this binary has no date dependency) and
therefore gets its own test against three fixed points including a leap day, rather
than being trusted because it compiled.

## Decision 5: the crate's two test locks are collapsed into one

`auth::GLOBAL_STATE_TEST_LOCK` guarded the global EES context and the JWKS from
inside `auth`. Adding a process-global to `ecs_role` made a natural reach for a lock
in `context` — and **that is exactly the mistake, and it was made in this PR**: a
`context::PROCESS_STATE_TEST_LOCK` was added, a test took it, and a `main.rs` test
holding the *other* lock failed on the very next run. Two disjoint agreements over
one ambient state is #308's defect, and #276 showed that shape hangs the suite
rather than merely flaking it.

Collapsed: the static now lives in `context` beside the context it guards, and
`auth::GLOBAL_STATE_TEST_LOCK` is a `pub(crate) use` alias so the 55 existing call
sites do not churn. `relocation::PULL_HOOK_LOCK` stays as a second, inner lock over
a genuinely different thing, with the order documented.

Recorded because the failure took one run to appear and the diagnosis took longer
than the fix.

## Verification

| claim | how it was made to fail | result |
|---|---|---|
| `easIds` comes from the live pool | back to `eas_ids: None` | **fails** the pool/expiry test |
| `expTime` is set | back to `exp_time: None` | **fails** the same test |
| the initial POST is retried | one attempt only | **fails** `the_initial_post_retries_with_increasing_delay` |
| the retry backs OFF | retry with no delay | **fails** the same test (it asserts on arrival times at the stub, so it measures the delay the peer experienced) |
| a failed refresh re-POSTs | log and return `Failed` | **fails** `a_404_refresh_re_registers_and_adopts_the_new_id` |
| the ECS 404s an id it does not hold | answer 200 | **fails** both the server's test and the client's |
| discovery matches on `easIds` | treat absent `easIds` as a match | **fails** `an_ees_advertising_no_eas_ids_is_not_a_discovery_candidate` |
| the ECS routes are wired into the router | drop the arm | **fails** both router tests |

The router tests go through `ees_sbi_request_handler` rather than through
`ecs_role`'s functions, deliberately: the arm is added at the end of a ~30-arm
match, where a typo leaves it shadowed or unreached and every unit test still
passes.

Gates: `cargo test -p nextgcore-eesd` **194 passed / 0 failed** (was 174), stable
over 6 consecutive runs plus the revert pass; workspace **6416 passed / 0 failed**;
clippy `--workspace` and `--all-targets` 0 errors; fmt clean.

## Ceilings

- **Five of the eight ECS APIs are unimplemented** and answer 404. See Decision 2.
- **The ECS registry is in memory.** Lost on restart — which is exactly the case the
  hardened client's re-POST recovery handles, so the two halves of this PR cover
  each other rather than one of them being unexercised. Persisting it would be
  #191/#192's shape in a new place and no criterion asks for it.
- **`easIds` at the ECS can be up to one refresh interval (60 s) stale.** See
  Decision 4; the alternative was two racing writers of one remote resource.
- **Registration is still gated on `--ecs-uri`.** With it unset the request is built
  and logged and nothing is sent, as before. An EES running the ECS role in the same
  process does **not** register with itself: nothing points `--ecs-uri` at the local
  address automatically, and doing so silently would make a single-process
  deployment look like a two-node one.
- **No `expTime` enforcement on the ECS side.** The role stores the `expTime` an EES
  sends and returns it, but nothing sweeps expired registrations — so a dead EES
  stays discoverable until an operator deletes it. eesd has a lapsed-registration
  sweeper for EAS/EEC (`spawn_*`, eesd-12); the ECS registry does not use it.
- **`Eecs_TargetEESDiscovery` matches on `easIds` only.** Not on service area, not
  on AC service KPIs, both of which TS 29.558 permits as query members and both of
  which the EES's own `eas_discover_filter` already implements for EAS discovery.
  A query carrying them is accepted and they are ignored, which is the kind of
  half-truth worth naming: the response is a candidate list, not a ranked one.
- **The `eecs-*` routes are not OAuth2-gated.** A different reference point with
  different consumers; requiring an `eees-*` scope would make an EEC's bootstrap
  need an EAS's token. A test pins the contrast against an `eees-*` route that does
  fail closed, so this is a stated position rather than an omission.
- **No E2E.** Every assertion is in-process: the ECS role is exercised through the
  real router, and the client through a loopback stub ECS. No compose service sets
  `ECS_ROLE`, so the default Docker path is unchanged — which is also what makes the
  default safe.
