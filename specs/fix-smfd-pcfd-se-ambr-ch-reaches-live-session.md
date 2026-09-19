# nextgcore #310 (smfd + pcfd): a subscribed session-AMBR change reaches a PCF-authorised live session

Verified against `main` @ `680a9f7`.

#310 is a `decision` issue asking who propagates a subscribed-session-AMBR change to a
PCF-authorised live session. It recommends **option A** (the SMF reports `SE_AMBR_CH`), and option A
is what this PR implements. TS 23.503 §6.1.3.2, TS 29.512 §4.2.4 / §5.6.2.3 / §5.6.2.5 / §5.6.3.6,
TS 29.503 §5.2.2.6, TS 29.519 §5.6.2.

## Verified against current main

| claim in the issue | site on `680a9f7` | still true? |
|---|---|---|
| `handle_sdm_notification` returns 204 and does nothing when a PCF authorised the session | `smfd/src/main.rs:5817` — the `binding.sm_policy_id.is_some()` arm | **yes** |
| its log line claims the PCF "learns of subscription changes from the UDR" | `main.rs:5824-5830`, and the doc comment at `main.rs:5776-5780` repeats the deferral | **yes**, and there are **two** sites, not one |
| `smfd` has the sender `policy::sm_policy_update(pcf, id, triggers, ue_init_res_req)` | `smfd/src/policy.rs:735` | **yes** |
| `handle_sdm_notification` does not call `sm_policy_update` | correct — but the function is **not** dead: `main.rs:4060`, the `PDU_RES_MOD_REQ` arm, calls it with `RES_MO_RE`. See finding 3 | **the narrow claim yes; "the sender is unused" NO** |
| `pcfd` has the `SE_AMBR_CH` receiver arm in `handle_sm_policy_update_notify` | `pcfd/src/app.rs:2632` | **yes** |
| that arm calls `pcf_get_session_data("", None, …)` with an **empty SUPI** | `app.rs:2639` | **yes** |
| `PcfSess.subscribed_sess_ambr` has one writer and zero readers | writer `pcfd/src/npcf_handler.rs:776`; declared `context.rs:485` | **yes, and worse — see below** |
| `SmPolicyDnnData` (UDR policy data) carries no session-AMBR | `pcfd/src/app.rs:2055-2058` comment, unchanged | **yes** |
| `SmPolicyContextData.subsSessAmbr` is the PCF's input for this datum, supplied by the SMF | TS 29.512 §5.6.2.3 | **yes** |
| the SMF supplies `subsSessAmbr` on create today | `grep subsSessAmbr bins/nextgcore-smfd/` → **nothing**. `sm_policy_create`'s body (`policy.rs:684-694`) carries `supi`/`pduSessionId`/`pduSessionType`/`dnn`/`notificationUri`/`ipv4Address`/`sliceInfo`/`servingNetwork`/`suppFeat` and **no `subsSessAmbr`** | **NO — the issue assumes this and it is false** |

### Three findings the issue does not state

**1. The SMF never sends `subsSessAmbr` at all — not on create, and so not anywhere.** #310 says
"`SmPolicyContextData.subsSessAmbr`, which the **SMF** supplies on create". It does not. `grep` for
`subsSessAmbr` across `bins/nextgcore-smfd/` returns nothing, and `sm_policy_create` builds its body
literally. So the PCF's *only* input for the subscribed AMBR is absent on every leg. Option A as
written ("report the new `subsSessAmbr` on update") would have made the update leg carry a datum the
create leg does not, leaving the PCF unable to bound the create. Both legs are fixed here.

**2. `PcfSess.subscribed_sess_ambr`'s writer is itself dead.** The issue says the field has one
writer and zero readers. The writer is `pcf_npcf_smpolicycontrol_handle_create`
(`npcf_handler.rs:667`), and `grep` shows that function has **no caller** outside its own file — the
live create path is `app::handle_sm_policy_create` (`app.rs:1886`), routed at `app.rs:659`, which
never touches the field. So the field was unwritten as well as unread on the live path: a
"written once" description that is itself optimistic. This PR gives it a **real reader and a real
writer on the live path**, which is the branch of the criterion this PR takes.

`pcf_npcf_smpolicycontrol_handle_create` and its three siblings in `npcf_handler.rs` are a dead C
port; they are left alone here (deleting them is its own change with its own blast radius), but the
field is now written by the path that actually serves the create.

**3. `sm_policy_update` is NOT an unused sender.** #310 calls it "the unused sender". It is used:
`main.rs:4060`, the `PDU_RES_MOD_REQ` arm of the SM-context update, drives it with `RES_MO_RE` for a
UE-initiated resource modification. This matters twice. First, adding a parameter to it touches a
live path, so that call site is updated deliberately (it passes `None` — a UE resource modification
reports no subscription change, and restating an unchanged subscribed value would have the PCF
re-evaluate a bound that did not move). Second, it means the `/update` leg is already exercised
end-to-end in production, so option A's "both halves already exist" is *more* true than the issue
claims, not less: what was missing was one trigger and one member, not a transport.

## The chain as it stands, and as it stands after

Before: operator edits `sessionAmbr` → UDM notifies SMF → SMF logs and returns 204 → **nothing**. The
PCF's `SE_AMBR_CH` arm exists but no one drives it, and if driven it would re-read the DB with an
empty SUPI and answer with the same value it answered before.

After: operator edits `sessionAmbr` → UDM notifies SMF → SMF **re-reads** `sm-data` scoped to the
session's own slice, compares against what the session enforces, and on a difference POSTs
`/sm-policies/{id}/update` with `repPolicyCtrlReqTriggers: ["SE_AMBR_CH"]` and the new
`subsSessAmbr` → the PCF stores it and authorises **from the reported value, bounded by it** → the
SMF applies the returned `authSessAmbr` to the N4 QER, the binding and the session through the SAME
code the PCF-notify path uses.

## Decision 1: option A, and the reported value BOUNDS the authorisation rather than replacing it

TS 23.503 §6.1.3.2 makes the PCF the authority on session-AMBR, and the subscribed value is one of
its *inputs*: the authorised AMBR **shall not exceed** the subscribed one. So the PCF's `SE_AMBR_CH`
arm does not simply echo `subsSessAmbr`:

1. it re-reads the PCF's own policy input for the session (`pcf_get_session_data(supi, …)` — with the
   **real** SUPI, resolved from the session's `PcfUeSm`, which is the defect half of this issue);
2. it takes the **minimum** of that and the reported subscribed value, per direction independently.

So a subscription lowered below the PCF's own policy lowers the authorisation; a subscription raised
above it does not raise it past what the PCF's policy permits. A direction the SMF did not report
falls through to the PCF's own value unchanged, because "the SMF did not tell us the uplink" is not
evidence that the uplink is unlimited.

This is also why the empty-SUPI call had to go regardless of which option #310 chose: with `""` the
DB lookup cannot resolve a subscriber (`nextgcore_id_get_value("")` returns `None`, so
`nextgcore_dbi_session_data` errors `InvalidSupi` and the `Err` arm hands back the hard-coded
100/100 Mbps fallback). Every `SE_AMBR_CH` re-authorisation answered 100/100 Mbps regardless of the
subscriber, the slice or the DB — the "wired mechanism with no effect" shape again.

## Decision 2: the SMF re-reads and compares before reporting, rather than reporting every notification

The notification says *when*, not *what* (#293's Decision, unchanged and still right). So the
PCF-present arm now does the same re-read and the same change-detection the no-PCF arm does, and
reports only a genuine difference. Two reasons:

- an `SE_AMBR_CH` report the PCF answers with an unchanged decision is a round trip plus an N4
  Session Modification for nothing, and a UDM that notifies liberally would cost one per
  notification;
- the comparison is against **what this session enforces** (`binding.ambr_ul_bps` / `ambr_dl_bps`),
  which after a PCF decision is the *authorised* value, not the subscribed one. A subscription raised
  from 100 to 200 Mbps against a PCF that authorises 100 is therefore reported (the subscribed input
  changed, and the PCF may now authorise more), and the PCF's answer may legitimately be unchanged.
  That is the PCF's call to make, which is the point of option A.

The re-read uses `udm::fetch_sm_data` — the same function the establishment path and the no-PCF arm
use — scoped to the binding's `(dnn, sst, sd)`, for the reason #293 records: `sm-data` is one entry
per S-NSSAI and `parse_sm_data` falls back to the first entry, so an unscoped re-read would report
another slice's AMBR and look like a success.

## Decision 3: a failed report leaves the session enforcing what the PCF last authorised

If the PCF is unreachable or rejects the update, the SMF logs it and answers the UDM **204**, keeping
the previously authorised QoS. Not a 504:

- the notification *was* received and understood; a 5xx tells the UDM to retry a notification whose
  failure is on a third leg the UDM cannot see;
- there is nothing to roll back — the SMF applied nothing — and the previously authorised AMBR is
  still a value the PCF authorised, which is the safe state. The alternative (falling back to the
  subscribed value) is exactly the "SMF enforces what the PCF never authorised" conformance defect
  #293's Decision 3 refused, and refusing it is still right.

## Decision 4: `subsSessAmbr` on create too, and `PcfSess.subscribed_sess_ambr` gets the reader

`sm_policy_create` now carries `subsSessAmbr` when the UDM supplied one (TS 29.512 §5.6.2.3, where it
is an optional `Ambr`), and `handle_sm_policy_create` parses and stores it on the session. The
`SE_AMBR_CH` arm reads it as the fallback when an update does not restate it, which is what gives the
field a reader. Absent (no UDM leg, or a subscription that states no AMBR) stays `None` and the PCF
bounds by nothing, i.e. exactly today's behaviour.

`Ambr` is stored as the TS 29.571 `BitRate` strings received, not parsed to bps, because that is what
the wire and the existing `context::Ambr` both hold; parsing happens where the comparison does. pcfd
gained `parse_bitrate` for that (it had only `format_bitrate`, the opposite direction).

## Decision 5: no cargo feature, and the report is ON by default

The SMF's UDM leg is already gated on the runtime switch `SMF_UDM=1` (off by default, for the reason
`udm.rs:35-41` records), and `handle_sdm_notification` is only ever reached through a subscription
that leg creates. So the new report inherits that gate and needs no second one: with `SMF_UDM` unset
nothing subscribes, nothing notifies, and this path is unreachable. Adding a cargo feature would
leave it uncompiled by CI, which this project has a recorded decision against.

## Acceptance criteria

#310's own four checkboxes, each marked:

- [x] **real** — `PcfSess.subscribed_sess_ambr` gains a reader. Written by the live create path
      (`handle_sm_policy_create`) from `SmPolicyContextData.subsSessAmbr`, read by the `SE_AMBR_CH`
      arm as the bound when an update does not restate it. Guarded by
      `a_create_stores_the_reported_subscribed_ambr_and_a_later_update_bounds_by_it`.
- [x] **real** — pcfd's `SE_AMBR_CH` arm stops calling `pcf_get_session_data("")`. It resolves the
      session's real SUPI through `ue_sm_find_by_id` and bounds the result by the reported/stored
      subscribed value. Guarded by `the_se_ambr_ch_arm_reads_the_sessions_real_supi`.
- [x] **real** — #293's log line no longer claims the PCF learns this from the UDR. **Both** sites
      amended (the log line at `main.rs:5824` and the doc comment at `main.rs:5776`), because the
      issue names only the first and leaving the second would keep the false claim in the tree.
- [x] **real** — a test drives the whole chain, with the seam stated:
      `a_sdm_notification_reports_se_ambr_ch_to_the_pcf_and_applies_the_answer` drives the real smfd
      router against a stub UDM and a stub PCF in one process, asserting the POST path, the reported
      trigger, the reported `subsSessAmbr`, and that the PCF's `authSessAmbr` reached the binding and
      the session. **Seam**: the two daemons are not run in one process, so the PCF half is a stub on
      the SMF side and is separately asserted against the real pcfd handler on the pcfd side.

No criterion is void or already-met. The issue's *approach* needed one correction (finding 1: the
create leg never carried `subsSessAmbr` either), which widened the change rather than shrinking it.

## Verification

`cargo test --workspace`: **6639 passed / 0 failed** (baseline 6631 on `680a9f7`; smfd 496 → 504,
pcfd 206 → 209). `cargo clippy --workspace` introduces no new warning in either crate — pcfd is at
zero and smfd's one remaining (`await_holding_lock` at `main.rs:556`) is pre-existing startup code
this change does not touch, and is a false positive there: the guard is explicitly dropped at
`main.rs:568`, before the `.await`. `cargo clippy -p nextgcore-easdfd --features dns-udp
--all-targets` clean; `cargo fmt --all -- --check` clean; `cargo test -p nextgcore-easdfd --features
dns-udp` green (51 passed).

| revert | expected to break | result |
|---|---|---|
| the PCF arm of `handle_sdm_notification` returns 204 without reporting | `a_sdm_notification_reports_se_ambr_ch_to_the_pcf_and_applies_the_answer` | **1 failed** |
| the report omits `subsSessAmbr` from the update body | same test (it asserts the reported value on the wire) | **1 failed** |
| the re-read/compare is dropped so every notification reports | `an_sdm_notification_that_changes_nothing_reports_nothing_to_the_pcf` | **1 failed** |
| `sm_policy_create` stops carrying `subsSessAmbr` | `the_sm_policy_create_body_carries_the_subscribed_session_ambr` | **1 failed** |
| the `SE_AMBR_CH` arm goes back to `pcf_get_session_data("")` | `the_se_ambr_ch_arm_reads_the_sessions_real_supi` | **1 failed** |
| the bound is dropped (the arm echoes the reported value) | `the_authorised_ambr_is_bounded_by_the_reported_subscribed_ambr` | **1 failed** |
| the create stops storing `subsSessAmbr` on the session | `a_create_stores_the_reported_subscribed_ambr_and_a_later_update_bounds_by_it` | **1 failed** |
| a failed PCF report becomes a 504 | `a_pcf_that_rejects_the_se_ambr_ch_report_leaves_the_session_as_authorised` | **1 failed** |

Eight reverts, eight bites, and in every case the assertion that fired was the one about the
sabotaged behaviour rather than an incidental downstream break. Every assertion is positive: a
recorded POST body, an authorised AMBR read back off the binding and the session, an answered
`authSessAmbr` string — not "the value did not change", which a parse error or an early return
satisfies too.

Two of the reverts are worth reading precisely:

- **The two `subsSessAmbr` blocks have separate guards.** Neutralising the one in `sm_policy_update`
  fails only the chain test; neutralising the one in `sm_policy_create` fails only the create test.
  The blocks look identical, so it was worth proving one test is not covering both.
- **The SUPI revert is guarded by a `None`, not by a value.** `the_se_ambr_ch_arm_reads_the_sessions_real_supi`
  orphans the session from its UE-SM and asserts the arm authorises NO session rule. Under the revert
  (`pcf_get_session_data("")` plus the emptiness guard neutralised) it answered
  `Some(("100 Mbps", "100 Mbps"))` — the subscriber-less DB default, which is exactly the pre-#310
  behaviour, for every session. A `""` SUPI resolves identically whether the UE-SM is present or not,
  which is what makes the orphaned case able to distinguish them.

## Ceilings

- **Only the session-AMBR is reported.** A changed default 5QI or ARP is a `DEF_QOS_CH` trigger
  (TS 29.512 Table 5.6.2.6-1) and the PCF has no arm for it; the SMF's re-read notices the change and
  still reports `SE_AMBR_CH` only, so a 5QI-only edit against a PCF-authorised session is still
  invisible. Named rather than half-built: `DEF_QOS_CH` needs its own PCF arm deriving an
  `authDefQos`, which is a separate decision about how the PCF bounds a subscribed 5QI.
- **The bound is `min` per direction, on the PCF's own policy input.** A deployment whose PCF policy
  is the DB's `SessionData` therefore cannot authorise above the DB even when the subscription is
  higher. That is the DB being the PCF's policy source, not a property of this change.
- **`pcf_npcf_smpolicycontrol_handle_create` (and its three dead siblings) still exist** in
  `npcf_handler.rs` with no callers. The field it writes is now written by the live path instead; the
  dead C port is left for a deletion change of its own.
- **No E2E.** The Docker jobs are `workflow_dispatch`-only, and `SMF_UDM` is off in the compose
  files, so the whole chain is exercised by in-process stubs on both sides.
