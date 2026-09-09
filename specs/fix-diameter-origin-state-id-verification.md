# nextgcore #280 (nextgcore-diameter): finish the Origin-State-Id verification §8.16 asks for

Verified against `main` @ `3024f20`.

**The issue is stale, and this is the headline.** #280 was filed on 2026-09-09 out of #57's
text, which cited `peer.rs:588-594` returning `SystemTime::now().as_secs()` per call. That
defect was already fixed on 2026-08-13 by `4eb7c49` (PR #148, slice 1 of #55), which latched
the value in a `OnceLock`. #57's citation was carried forward without re-checking the code, so
#280 describes a defect that had not existed for four weeks by the time it was written. This
is the "a stated claim is a hypothesis, whoever stated it" rule applying to an issue *we*
filed.

What #280 asks for is nonetheless not all present. Its four acceptance criteria split cleanly:
one was met by #148, three were not, and the three are the interesting ones.

## Verified against current main

| claim in the issue | site on `3024f20` | still true? |
|---|---|---|
| `origin_state_id()` computes seconds-since-epoch on every call | `libs/nextgcore-diameter/src/peer.rs:758` — `*ORIGIN_STATE_ID.get_or_init(...)` | **no — fixed by `4eb7c49`** |
| the value is emitted in four places | `peer.rs:324` (CER), `:404` (CEA), `:484` (DWA), `:513` (DWR) | yes |
| a test asserts stability across a sleep | `origin_state_id_is_stable_across_a_second_boundary` (added by `4eb7c49`) | yes — criterion 1 already met |
| the ordering property is tested | nothing tested it | true, gap |
| the four message paths are asserted to agree | nothing tested it | true, gap |
| whether any in-tree peer consumes a received Origin-State-Id | never enumerated | true, gap |

## Criterion-by-criterion, and what this PR adds

1. **Stable for the process lifetime.** Already met by `4eb7c49`. Untouched.
2. **The ordering property, not only the stability.** `origin_state_id()` is a latch, and one
   process observes exactly one value — so *no* test inside one process can assert that a later
   start yields a greater value. The derivation is therefore split into
   `derive_origin_state_id(SystemTime)` and the property asserted against two synthetic start
   instants. This is a refactor #280 does not ask for; it is here because without it the
   criterion is not expressible at all rather than merely untested.
3. **Every message-building path carries the latched value.** Four call sites each call
   `origin_state_id()` independently, so the latch's own tests say nothing about them: a fifth
   path added later could read the clock per call without disturbing either existing test.
   `every_message_path_carries_the_latched_origin_state_id` drives all four over loopback — this
   node is the raw transport twice, once facing a real responder (capturing its CEA and DWA)
   and once facing a real initiator (capturing its CER and DWR) — and asserts all four AVPs
   equal each other and equal `origin_state_id()`.
4. **The receive-side enumeration.** Answered in full below and recorded at the latch in
   `peer.rs`, so the next reader does not have to redo the grep.

## Decision: the 1.1s sleeps are load-bearing, and the false-guard check proves it

`every_message_path_carries_the_latched_origin_state_id` sleeps past a wall-clock second
between the handshake and the watchdog in *both* directions. That is not padding. The defect
being guarded against returned `now().as_secs()`, which yields the **same** value for every
message sent inside one second — so an exchange run back to back agrees with itself even with
the bug present.

This was checked rather than assumed. With the defect restored and the two sleeps cut to 1ms,
the test **passes** (see Verification). A version of this test without the sleeps would have
been exactly the green-proves-nothing shape this repo keeps finding.

## Criterion 4: what consumes a RECEIVED Origin-State-Id in this tree — nothing

Enumerated across the whole workspace (`rg 'origin_state_id|OriginStateId|ORIGIN_STATE_ID'`):

| site | direction | reads a received value? |
|---|---|---|
| `common.rs:37` | the AVP code constant `278` | n/a |
| `peer.rs:324` `send_cer` | send | no |
| `peer.rs:404` `handle_cer` → CEA | send | no |
| `peer.rs:484` `handle_dwr` → DWA | send | no |
| `peer.rs:513` `send_watchdog` → DWR | send | no |
| `handle_cea` (`peer.rs:435`) | receive | **no** — reads Result-Code, Origin-Host, Origin-Realm only |
| `hssd`, `pcrfd`, `mmed` | either | **no reference to the AVP at all** |

So the behaviour change on the receive side that #280 asked to have "stated rather than
discovered" is: **there is none**, because no in-tree peer acts on the value it receives.

That is a clean answer to the criterion and a real gap underneath it. Diameter peer-restart
detection (TS 23.007 restoration) exists in neither direction here: we now advertise a
conformant value that no in-tree peer would notice changing. Closing that needs a per-NF
decision about what to discard when a restart *is* detected — the same question #57 hit and
answered with persistence instead. Filed separately rather than folded in: #280 asks for the
enumeration, and adding unrequested outbound-behaviour change to a verification PR is how a
reviewer stops being able to tell what was asked for.

## Acceptance criteria

- [x] `origin_state_id()` returns the same value for the process lifetime, with a test that
      sleeps across a second boundary — met by `4eb7c49`, left as found.
- [x] The value is derived once and a later start derives a greater one —
      `a_later_process_start_derives_a_greater_origin_state_id`, covering an ordinary restart,
      a same-second restart (equality, which §8.16's "non-decreasing" permits), and a pre-epoch
      clock (floors at `0` rather than wrapping to `u32::MAX`).
- [x] Every message-building path uses the stored value, asserted by comparing the AVP across
      messages — `every_message_path_carries_the_latched_origin_state_id`, all four paths.
- [x] Whether any in-tree peer consumes a received Origin-State-Id is enumerated — table above,
      and recorded at `ORIGIN_STATE_ID` in `peer.rs`.

## Verification

Workspace `6209 passed / 0 failed` (baseline `6207` on `3024f20`; +2 tests). `cargo clippy
--workspace --all-targets` and `cargo fmt --all -- --check` clean, and `nextgcore-diameter`
itself carries zero clippy warnings.

| revert | expected to break | result |
|---|---|---|
| `origin_state_id()` recomputes per call (the original defect) | `every_message_path_carries_the_latched_origin_state_id`, `origin_state_id_is_stable_across_a_second_boundary` | **2 failed** — CEA `1788993454` vs DWA `1788993455` |
| `derive_origin_state_id` returns a constant | `a_later_process_start_derives_a_greater_origin_state_id` | **1 failed** |
| **false-guard check**: defect restored *and* the two 1.1s sleeps cut to 1ms | nothing — the point is that it passes | **passed**, confirming the sleeps are the guard |

## Ceilings

* The ordering property is asserted on `derive_origin_state_id`, not on two real processes. A
  genuine cross-restart assertion needs two process lifetimes, which no harness here provides;
  what is verified is that the derivation is monotonic in its input and that the latch feeds it
  the process-start instant.
* `every_message_path_carries_the_latched_origin_state_id` proves the four paths agree *within
  one process*. It cannot prove a fifth future path calls the latch — only that the four that
  exist today do. A lint would be the general fix; four call sites did not justify one.
* The receive side remains unimplemented and is now documented as such rather than left to be
  rediscovered. See the enumeration above.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep:
  `origin_state_id` has four callers, all in `peer.rs`; `derive_origin_state_id` has one
  production caller (the latch) and one test caller.

