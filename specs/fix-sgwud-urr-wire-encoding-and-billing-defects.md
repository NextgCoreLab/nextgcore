# nextgcore #267 (sgwud): URR wire-encoding and billing defects from #215

Verified against `main` @ `71418a5`. Every defect was found by a review pass **immediately after #215
merged**, and every claim was checked against `nextgcore-upfd`'s existing implementation of the same
IEs rather than against the spec text alone — upfd is a working second opinion in-tree, and it is where
three of these had already been done correctly.

## What was wrong, and how it was confirmed

| defect | confirmed by |
|---|---|
| **VOLQU on the DROTH bit** — `flags[0] \|= 0x40` | `upfd/n4_build.rs:604-612`: `dropped_dl_traffic_threshold` → `flags[0] 0x40`, `volume_quota` → `flags[1] 0x01` |
| **`trigger_set` truncated `u16`→`u8`** | the cast is in the source; every octet-6/7 trigger was unreachable |
| **UNIX-epoch timestamps** on all four time IEs | §8.2.34-37 specify RFC 5905; `NTP_UNIX_OFFSET` already exists at `lmfd/main.rs:652` |
| **buffer-full packets billed** | `context.rs:989` returns `Some(len)` **without pushing** when full; `apply_far` billed unconditionally |
| **DURAT-only URR emitted a Volume Measurement IE** | `usage_report_from` set the three packet counters to `Some(0)`; flags `0x38` ≠ 0 |
| **Volume Quota unreachable** whenever a threshold fired | `take_report` zeroed the counters the quota was compared against |
| **check-then-take race** | `urr_record` dropped the lock before `urr_take_report` re-acquired it |

One review claim was checked and **rejected**: TEBUR at `flags[2] |= 0x02` is correct — `upfd:637` uses
the same bit for `termination_by_up_function_report`.

## Decision 1: the two trigger defects had to land together

VOLQU was declared as an octet-5 constant (`0x40`) *and* matched through a `u8` cast. **Each hid the
other**: moving VOLQU to its real bit without widening the mask would have made Volume Quota stop
working entirely, and widening the mask without moving the constant would have left it on DROTH. The
`reporting_trigger` module is now `u16` throughout.

## Decision 2: counters are cumulative, reports carry the delta

A **threshold** is per measurement period; a **quota** is the session's allowance. #215 compared both
against one counter that was zeroed on every report, so with VOLTH=250 and VOLQU=1000 the total never
climbed past 250 and quota exhaustion was unreachable.

`SgwuUrr` now keeps cumulative `*_bytes` / `*_packets` plus a `reported_*` watermark. `take_report`
advances the watermark instead of zeroing the totals, so `measured_volume()` returns the period's delta
while the cumulative total remains available for the quota check. This is the shape `upfd`'s
`UrrAccounting` already had.

**A test caught a second-order bug in this change before it shipped**: `urr_install`'s carry-over
preserved the totals but not the watermark, so re-provisioning a URR would have made the next report's
delta the whole session again — re-billing every byte an earlier report already covered. The re-Create
and Update tests caught it *because* they assert the delta and not only the total.

## Decision 3: every satisfied trigger is reported

`reportable` accumulated into one `UsageReportTrigger` instead of returning at the first match. The IE
is a bitmask (§8.2.42) and `take_report` resets the period, so returning only the first **consumed the
others' conditions without ever reporting them** — a packet crossing a volume threshold as a time
threshold expired reported VOLTH and silently swallowed TIMTH.

## Decision 4: the check and the take are one locked operation

`urr_record` now counts the packet, evaluates reportability, and takes the report under **one** write
guard, returning `Some((snapshot, ur_seqn))` only when that packet made the URR reportable. Before,
two threads both got a trigger and the second took a **zero-volume** report with the next UR-SEQN — a
spurious report plus a gap in the meaningful sequence. `urr_take_report` survives for the deletion
path, where there is no packet and so no race.

## Decision 5: only accepted buffered packets are billed

`far_buffer_packet` returns a `BufferOutcome` rather than `Option<usize>`, because the old return could
not distinguish *accepted* from *discarded-because-full*. `apply_far` measures only on `Accepted`, and
the first-packet DLDR trigger is likewise gated on it.

Not fixed, and now stated in the docs rather than implied away: a buffered packet is still billed on
paths where it is provably never delivered (teardown discards the queue, a failed flush logs and
continues, an SGW-C switching the FAR to DROP discards it). Counting at flush-success would need the
flush path to know the PDR. The claim in the code is now "accepted", which is what the code does.

## Decision 6: association gaps closed

`UpdatePdrRequest` gains `urr_ids: Option<Vec<u32>>` — TS 29.244 Table 7.5.4.2-1 lists URR ID as an
Update PDR IE, and without it an SGW-C moving a bearer from URR 3 to URR 4 got `Ok` and the SGW-U kept
billing URR 3. `Some` **replaces** rather than merges, because an Update states the PDR's current shape.

`process_remove_urr` now detaches the id from every PDR naming it. A dangling id measured **nothing**
silently (`urr_record` returned `None` and the loop's `continue` swallowed it), and a later re-Create of
the same id silently re-attached the old PDR to a rule the SGW-C may have re-scoped.

## Decision 7: the docs overclaim is corrected, in both directions

`docs-book/src/configuration/sgwu.md` said the SGW-U "parses Create / Update / Remove URR". There is no
PFCP IE decoder in sgwud at all. #215's spec carefully declared the **egress** ceiling (nothing is
transmitted, #217) and left the **ingress** ceiling undeclared while the docs asserted the opposite —
the same failure `CONVENTIONS.md` names for "emitted" vs "transmitted", applied to "parses". The page now
leads with both ceilings and says the URR work is modelling and encoding, not a live interface.

## Not done in this PR

**Lifting the Usage Report type and encoder into `nextgcore-pfcp`.** #267's criterion asks for a
*decision*, and the honest one is that it should move: three of these seven defects are places where the
new copy diverged from an existing one that had it right, and `upfd` plus `nextgcore-pfcp` already carry
`UsageReport`, `UsageReportTrigger`, `add_usage_report`, `add_volume_measurement`, `CreateUrr`,
`MeasurementMethod` and `ReportingTriggers`. Doing it here would mean changing `upfd`'s encoder in the
same PR that fixes sgwud's, which is how a shared-library change turns into two daemons' regressions at
once. **Recommendation recorded, work deliberately separate**, and left as an open item on #267.

The per-packet `Vec<u32>` clone in `pdr_find_by_teid` is likewise unaddressed: fixing it means changing
how sgwud stores every rule, which #215's ceiling already flagged and no issue has asked for.

## Verification

Workspace **6002 passed / 0 failed / 6 ignored** (baseline `5995` on `71418a5`; +7 tests, sgwud 111 →
118). `cargo clippy -p nextgcore-sgwud --all-targets` clean (zero warnings), `cargo clippy --workspace`
0 errors, `cargo fmt --all -- --check` clean, and **5 consecutive full sgwud runs green** (the crate has
a recorded history of env-global flakes).

Seven reverts:

| revert | expected to break | result |
|---|---|---|
| VOLQU back on `flags[0] 0x40` | `every_usage_report_trigger_has_its_own_bit` | **1 failed** |
| `trigger_set` masks the low byte only | `a_trigger_in_the_high_octet_is_reachable`, `a_volume_quota_fires_...` | **2 failed** |
| `ntp_seconds` returns UNIX seconds | `usage_report_timestamps_are_ntp_epoch_not_unix` | **1 failed** |
| bill buffered packets unconditionally | `a_packet_dropped_because_the_buffer_is_full_is_not_billed` | **1 failed** |
| packet counts `Some(..)` unconditionally | `a_duration_only_urr_emits_no_volume_ie_through_usage_report_from` | **1 failed** |
| `reportable` returns at the first match | `reportable_carries_every_satisfied_trigger` | **1 failed** — *see below* |
| Update PDR ignores `urr_ids` | `update_pdr_repoints_the_urr_and_remove_urr_detaches_it` | **1 failed** |

**The multi-trigger revert broke nothing on the first attempt.** The quota test loops packets and the
quota happened to fire on a packet where the threshold delta had already reset, so co-occurrence was
never forced. Fixed by adding `reportable_carries_every_satisfied_trigger`, which constructs the exact
state where all four conditions hold at once; re-running the revert against it fails on `VOLQU`. That is
the **fourth** time today a guard turned out to cover a neighbouring claim rather than the named one —
the recorded convention (revert each claim separately, require a *named* test) is what caught it again.

Five tests from #215 asserted the old behaviour and were **inverted with the flip recorded at each
assertion**: the VOLQU bit, the counter-reset model (three sites), and the per-period volume figure.
Those are tests that pinned the defects.

## Ceilings

* **Everything here is still in-process.** #217 remains: no PFCP transport out, no IE decoder in. These
  fixes make the encoding correct for when there is a wire; they do not create one.
* **A buffered packet is still billed on paths where it is never delivered** (teardown, failed flush,
  FAR switched to DROP) — see Decision 5.
* **The duplication with `upfd` / `nextgcore-pfcp` is unresolved** and is the root cause of three of
  these defects. Recommendation recorded above; the work is deliberately not in this PR.
* **No `EVENT` measurement, no periodic timer, no Query URR** — all unchanged from #215's ceilings.
* **`Measurement Information` (MNOP) is still not parsed**, so the packet-count fields are emitted
  whenever volume is measured rather than only when the CP function asked for them. §8.2.32 ties them to
  MNOP; this PR only stopped emitting them for a URR that measures no volume at all.
* **The per-packet `Vec<u32>` clone and the per-packet write lock** are both unaddressed.
* GitNexus impact analysis unrunnable (no MCP server connected — 46th consecutive PR).
