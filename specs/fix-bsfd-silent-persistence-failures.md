# bsfd: three binding-persistence failures logged below the level operators run at

Verified against `main` @ (post-#195).

Found while resolving a pre-check I wrote into #192 — "`bsfd` already has a
`persist_binding_async`; read it first, it may be a notification hook rather than
durable storage."

## What the pre-check turned up

It is durable storage, MongoDB-backed, and **fully wired**:

| | |
|---|---|
| load at boot | `lib.rs:200` → `load_persisted_bindings_async` |
| persist on create | `lib.rs:924`, `lib.rs:1364` |
| unpersist on delete | `lib.rs:1086`, `lib.rs:2197` |

So **#192 is wrong about BSF** — it lists BSF bindings as memory-only. That is the
same error #66 made about UDR ("the one NF with a durable store", when four had
one), and for the same reason: a survey written once and not re-verified. #192 needs
correcting; BSF drops out of it, leaving PCF, NWDAF and NEF.

## The defect

All three DB-failure arms logged at **`debug!`**, while every shipped deployment
runs `RUST_LOG=info` (`docker/rust/docker-compose.yml`). So each failure was
invisible in practice — and each has a consequence worth knowing about:

* **persist fails** — the create was answered *successfully*, but the binding is
  memory-only and dies at restart. The BSF keeps answering discovery correctly from
  memory, so nothing looks wrong until it is too late.
* **unpersist fails** — worse than a lost write. The row survives, so
  `load_persisted_bindings_async` **reinstalls the deleted binding** at the next
  boot. The BSF then reports a PCF binding for a session that was deliberately
  deleted, and a consumer routes policy to a PCF that is not serving it. Not loss —
  *resurrection*.
* **load fails at boot** — the BSF starts with zero bindings and answers "no
  binding", authoritatively with a 404, for sessions that have one. A consumer
  cannot distinguish that from a session that was never bound. Same shape as the UDR
  failure #194 addressed.

## The fix

All three raised to `error!`, each message naming the consequence rather than the
mechanism — "will be RESURRECTED on the next restart and reported as live" is
actionable; "DB persistence unavailable" is not.

This makes the failures **visible**; it does not make them correct. Reconciling a
resurrected binding is restoration work and belongs to #193, which already exists
for exactly that. Filed rather than bodged here: retrying the delete, or
tombstoning, is a design choice about durable-store semantics and should not be
smuggled into a logging change.

## Verification

`persistence_failures_are_not_logged_below_warn` is a source guard: it extracts each
of the three function bodies and asserts none logs at `debug` and each logs at
`warn` or `error`. The property is about the log *level*, which has no runtime
signal to assert against, so a source guard is the honest instrument. Keyed to
function bodies rather than message text, so rewording a message does not break it.

**Revert-verified:** regressing the unpersist arm to `debug!` fails it, naming the
function.

It also caught something on first run that is worth recording: the guard greps for
the macro token, so it matched the token inside a **comment I had written to explain
the fix**. The comments now say "debug level" in prose. Stripping comments first was
the alternative and is worse — a naive stripper cuts at the `//` in a URL, which
this repo has already been bitten by.

Workspace **5671 passed / 0 failed** (baseline 5670), `cargo test` exit 0. fmt
clean; `cargo clippy --workspace --all-targets` 0 errors.

**Not verified:** no MongoDB failure was induced against a running bsfd. The change
is to which level a message is emitted at, which the guard pins at the source; that
the surrounding error paths are reached under a real DB outage is untested here.

## Definition of done

- [x] All three persistence-failure paths log at `error` with the consequence named.
- [x] Guarded against regression, revert-verified.
- [x] The resurrection semantics referred to #193 rather than bodged.
- [ ] #192 corrected to drop BSF — follow-up comment on that issue.
