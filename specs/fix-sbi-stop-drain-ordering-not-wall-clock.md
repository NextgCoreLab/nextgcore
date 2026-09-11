# fix(sbi): assert the drain ORDERING, not a wall-clock lower bound

Closes #326.

## Claim-vs-site-vs-still-true

Re-located against `1606deb`, because a stale cite is the usual reason an issue looks
bigger or smaller than it is:

| # | #326's claim | site now | still true? |
|---|---|---|---|
| 1 | the assertion is a wall-clock lower bound on how long `stop()` blocked | `server.rs:2496` `assert!(stop_started.elapsed() >= Duration::from_millis(150))` | **yes** |
| 2 | the setup that makes it hold is an unsynchronised 80 ms sleep | `server.rs:2490` `sleep(Duration::from_millis(80))` | **yes** |
| 3 | the handler sleeps 300 ms | `server.rs:2479` | **yes** |
| 4 | siblings with the same sleep-then-measure shape exist in this crate | `rg 'elapsed\(\)' libs/nextgcore-sbi/src` → 6 hits, **all production**: `heartbeat.rs:63,70,243`, `oauth.rs:518,1486`. `rg 'sleep\(Duration::from_millis'` → **1 hit, this test**. | **no — none** |

So criterion 4 is answered by enumeration rather than by work: `stop_drains_an_in_flight_request`
was the only sleep-then-measure test in `nextgcore-sbi`. Every other `Instant::now()` in the
crate is either production code or a test that **injects** `now` as a parameter
(`overload.rs:606,635,668` all pass `now` into `record`/`decide`/`live_count`), which is the
shape that has no wall-clock dependency to begin with.

## Why the old test flaked, precisely

The failing inequality needed the 80 ms sleep to be an *upper* bound on how long the request
takes to reach the handler:

```text
elapsed(stop) ≈ 300 ms − (time already spent in the handler when stop() was called)
             ≈ 300 ms − (80 ms sleep + scheduling overshoot + connect/send time)
```

so the assertion `elapsed(stop) >= 150 ms` holds only while overshoot + connect stays under
**70 ms**. On a loaded whole-workspace runner it does not, and the drain is blamed for it.
That is a 70 ms margin on an accumulated overshoot — which is why it reproduced at roughly
1 run in 5 under load and 0 in 25 in isolation.

## What it does now

Two changes, and the second is the one that makes the first safe:

1. **The handler signals ENTRY and then parks on a signal the test owns.** No sleep has to
   stand in for "the request has reached the handler" — `entered.notified().await` *is* that
   fact. `tokio::sync::Notify` rather than a `oneshot` because `SbiRequestHandler` is
   implemented for `Fn` (not `FnOnce`), and because a `notify_one` that lands before the
   waiter stores its permit instead of being dropped.

2. **`stop()` runs in its own task and the test asserts that task is STILL PENDING** while
   the handler is parked. This is the ordering the doc comment already claimed to be about
   ("in-flight completes, connection then closes"), asserted as an ordering:

   ```rust
   let stop_task = tokio::spawn(async move { server.stop().await });
   tokio::time::sleep(Duration::from_millis(50)).await;
   assert!(!stop_task.is_finished(), "stop() returned while a stream was still in flight, …");
   release.notify_one();
   ```

The margin is now infinite in the direction that used to fail. `stop()` waits on
`drain.recv()`, which returns only when every cloned drain token has dropped; the connection
task holds one until it returns, and it cannot return until the handler does. So **no amount
of scheduling delay can make a correct `stop()` look finished** — waiting longer only makes
the pending assertion more obviously true.

## Decisions

**The 50 ms sleep is a revert-DETECTOR, not a correctness dependency, and the comment says
so.** A `stop()` that skips the drain still needs *some* slice of time to run to completion
before `is_finished()` can observe it. Deleting the sleep would make the test unable to
notice a broken drain (`is_finished()` would be `false` merely because the task had not been
polled yet); lengthening it never invalidates the assertion. Load pushes this test toward a
*slower* verdict, never a wrong one — which is the opposite of the property it had before.

**Assert on `is_finished()` rather than on a completion flag the handler sets.** An
`AtomicBool` set on the handler's way out, read after `stop()` returns, states the same
ordering — but it degrades to a *vacuous pass* if the handler happens to finish before
`stop()` is called, so a broken drain could go unreported under load. Asserting the stop task
is pending while the handler is *provably* still parked has no such window: the test controls
when the handler returns.

**The existing 200/`"drained"` assertions are kept verbatim.** They are the half that already
proved the request was not *dropped*, which is a different property from ordering, and #326
explicitly asks for them to stay.

## Revert-verify

Required by the convention that a behavioural claim is verified by making it fail, not by
writing it down. `stop()`'s drain wait was replaced with an early `return Ok(())`:

```text
test server::tests::stop_drains_an_in_flight_request ... FAILED
panicked at libs/nextgcore-sbi/src/server.rs:2542:9:
stop() returned while a stream was still in flight, so it did not drain
```

Restored, and green again. The **named** assertion is the one that fires — not a transport
error, not a join failure — so the test fails for the reason it claims to test.

Worth recording because it nearly did not bite: the first revert attempt reported green and
proved nothing. The command was `cd src && cp … && python3 …`, run from a shell whose working
directory was *already* `src`; `cd` failed, the `&&` chain short-circuited, the edit never
applied, and `cargo test` re-ran the unmodified tree. A revert-verify that passes is
indistinguishable from a revert that never happened unless the edit is confirmed
independently — here by `grep`-ing for the injected line before running the test.

## Criterion 3: 25 consecutive whole-workspace runs

`cargo test --workspace`, 25 runs, **6520 tests each, 0 failures**. Run under the same
condition that produced the original flake (a full workspace run with every test binary
competing), which is what makes the count meaningful rather than decorative.

## Files

- `src/libs/nextgcore-sbi/src/server.rs` — `stop_drains_an_in_flight_request` reworked; doc
  comment records the mechanism, the ordering property, and why the residual sleep is safe.
