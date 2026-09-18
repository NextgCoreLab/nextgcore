# fix(amfd): one `AmfContext` in the process, not two

Closes NextgCoreLab/nextgcore#363. Sequenced **before** #341, as that issue asks.

## The decision: option 1 — the global `std::sync::RwLock` wins

#363 costed three options. **Option 1** is implemented: `NgapServer` reads
`context::amf_self()` instead of holding an injected
`Arc<tokio::sync::RwLock<AmfContext>>`, the config loader writes only the global, and
the 8 `.read().await` sites in `ngap_path.rs` become scoped sync locks.

Rationale, unchanged from the issue's own and confirmed while implementing:

- **Option 2 (the injected `tokio` instance wins) is unavailable, not merely costly.**
  `namf_server.rs` has 55 sync `fn` handlers; they cannot `.await`, and
  `blocking_read()` panics when called from a runtime thread — and they are reached
  from the SBI server's async tasks. It is an async-ification of the whole Namf
  surface, not a lock swap.
- **Option 3 (keep both, make the duplication total) institutionalises two objects
  that can disagree about UE state the moment #341 lands**, and a source guard can
  only see the config loader's writes, not runtime ones. It fixes the symptom and
  leaves the cause.
- Option 1 is also where the code had already voted: `ngap_path.rs` reached the global
  **23** times against **8** uses of its injected one.

## What was actually broken

`lib.rs` documented the split and worked around it for the timers only:

> These are applied to BOTH contexts on purpose. […] `build_registration_accept` reads
> the global, so writing only `ctx` here would leave the YAML inert for the one message
> that actually carries T3512.

Everything else the loader set — `integrity_order`, `ciphering_order`, `served_guami`,
`served_tai`, `plmn_support` and the counters beside them — was written to the injected
instance **only**, and was therefore inert for every reader that went through
`amf_self()`. The security-algorithm pair is the one that mattered: a reader added in
the wrong place would have got `AmfContext::new()`'s defaults with no error.

## The `!Send` guard constraint, and why it cost almost nothing

A `std::sync::RwLockReadGuard` is `!Send` and cannot be held across an `.await`. Each of
the 8 sites was checked before conversion:

- **7 of 8 were already scoped** as `let x = { let ctx = …; <no await> };`, so they
  convert with no restructuring.
- **The 8th** (`handle_ng_setup_request`, `ngap_path.rs:1233`) holds the guard inside a
  block that ends with the comment `// All locks released here`; every send happens
  after it closes. No `await` inside either.
- `lib.rs`'s `load_config` holds a *write* guard from the middle of the function to its
  end. Its only `.await` (the NRF-URI seed) completes **before** the guard is taken.

Verification that this is not merely believed: `cargo clippy -p nextgcore-amfd
--all-targets` reports `await_holding_lock` for exactly one site — a pre-existing
`congestion_test_guard()` in a test at `ngap_path.rs:12424` — and **none** of the 9
converted sites.

### Poison semantics: read and write THROUGH the poison

The replaced `tokio::sync::RwLock` **cannot poison**, so `let Ok(g) = …else { bail }` at
these sites would be a *new* failure mode rather than a preserved one. Every converted
site uses `unwrap_or_else(|e| e.into_inner())`, matching the recorded pcfd decision
(*one poison semantics for the whole context: read and write through the poison*).

This matters most in `load_config`: bailing there would produce the worst available
outcome — an AMF running with default `integrity_order`/`ciphering_order` and no
operator signal that the YAML was ignored.

## A deadlock the deletion turns from latent into impossible

The old dual-write did `context::amf_self().write()` *inside* `load_config`. Now that
`ctx` **is** the global write guard, that second acquisition would not merely be
redundant — it would **deadlock**, because `std::sync::RwLock` is not reentrant. The
comment where it used to stand says so, so a future author restoring "belt and braces"
double-writing is warned in the right place.

## The test, and the revert round

`the_config_loader_writes_the_context_the_ngap_readers_read` drives the real
`load_config` against a fixture YAML and reads every field back through
`context::amf_self()`.

Two things about the fixture are deliberate:

- **`t3512` is 777, not 540.** 540 is both `AmfContext::new()`'s default *and* what every
  shipped config declares — the coincidence that let the original T3512 bug go
  unnoticed. A test using 540 would pass whether or not the YAML was read at all.
- **The algorithm orders are `NIA3,NIA1` / `NEA3,NEA1`** — non-empty (the default is
  empty) and in a non-preference order, so the assertion cannot be satisfied by the
  fallback mask.

The integrity mask is asserted through `ngap_path::algorithm_order_to_mask` — the
registration path's own reader, made `pub(crate)` for this — rather than by
recomputing the mask in the test, which would only prove two copies of the arithmetic
agree.

**Revert round.** Restoring the split (`load_config` writes a freshly constructed
instance, as before) makes the named test fail and leaves all 485 others green:

```
assertion `left == right` failed: integrity_order must reach the global context IN ORDER
  left: []
 right: [3, 1]
test result: FAILED. 485 passed; 1 failed
```

`left: []` is precisely the inert-for-a-global-reader symptom #363 describes. This is
also the revert-verification the issue asks for — *"the T3512 workaround in `lib.rs`
becomes deletable, and deleting it is the revert-verification."*

The test snapshots and restores the fields it perturbs (truncating the vectors back to
their saved lengths, since the loader *pushes*), because the context is now
process-global and leaving residue would be the #368 defect class in a new place.

## One instance, verified mechanically

Every `AmfContext::new()` in the crate was classified. Exactly **one** is production:
`context.rs:3354`, inside `amf_self()`'s `get_or_init`. All others are unit tests
constructing a local context to exercise a pure function, which is not a second
*process* context.

## Test-site fallout, and the one that mattered

Three test sites passed an injected context and simply drop the argument. The fourth,
`ngap_path.rs`'s undecodable-NG-Setup test, is load-bearing: its own comment records that
against an empty context *every* NG Setup is rejected on "no matching TAI", so the test
"would stay green even if the fabricated-request path came back — it would be passing
for the wrong reason." It now seeds the served TAI into the **global**, which is the only
reason it still proves what it claims.

That seed is written to be **idempotent** (push only if absent, then
`num_of_served_tai = served_tai.len()`). An unconditional push on a process-global would
make the counter disagree with the vector's length across runs — the
accumulate-on-a-global hazard a per-instance context used to hide. It is also the only
writer of `served_tai` in the process outside the config loader; every other write is on
a locally-constructed context in `ngap_handler`'s own tests.

## What this does NOT do

- **It does not answer #341.** The UE store is still `NgapServer::ue_auth_state` with the
  context's UE lists written by tests only. #363 explicitly says it blocks nothing today,
  and re-verification confirms it: 107 production `ue_auth_state` references and 268
  production `.amf_ue` accesses in `ngap_path.rs`, exactly as banked on #341.
- **It does not fix the global's writer-starvation hazard**, documented at
  `amf_context_init`: the std queued `RwLock` gives writers priority, so a stream of
  writers can starve readers. Option 1 inherits that, as the issue says it would. Nothing
  here adds a new writer on a hot path — the loader writes once at startup, and all 8
  converted NGAP sites are *readers*.
- **`load_config` pushes rather than replaces**, so a second call in one process would
  double the lists. It has exactly one caller (`init`), called once, and no test calls
  it. Noted so a future second caller is a deliberate choice rather than a silent bug.

## Verification

- `cargo test -p nextgcore-amfd`: 486 passed (was 485; +1).
- `cargo test --workspace --no-fail-fast`: **6612 passed, 0 failed**.
- `cargo fmt --all -- --check` clean; `cargo clippy --workspace` no errors. The amfd
  warnings are pre-existing (2 in `nextgcore-nas`, 1 `await_holding_lock` in a
  congestion test), none from the converted sites.
- Revert round run and restored, as above.
