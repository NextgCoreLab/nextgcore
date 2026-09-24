# Let the AMF learn a UE's location from every NGAP message that reports one (#406)

`parse_uplink_nas_transport_asn1` discards the `UserLocationInformation` the NGAP
parser decodes as a **mandatory** IE, so the SERVICE REQUEST — the one moment a UE
that moved while in CM-IDLE tells the network where it now is — cannot refresh the
stored location. #402's `LOCATION_REPORT` fires from that site and therefore reports
the TAI learned at *registration*, and #407 declined to fire presence events there
for exactly this reason.

This change makes the Service Request a genuine location-learning moment, and fixes
the same defect shape at the two other sites where it repeats.

## Claim / site / still-true

| # | Issue criterion or claim | Site (re-located) | Verdict |
|---|---|---|---|
| C1 | *"`UplinkNasTransportData` carries the `UserLocationInformation` the parser already decodes, and `parse_uplink_nas_transport_asn1` populates it. Nothing new is decoded off the wire."* | `ngap_asn1.rs:735-742` has exactly three fields; `:769-773` constructs from three members. The lib parser decodes the IE and refuses the message without it (`libs/nextgcore-ngap/src/parser.rs:660-663`), and `types.rs:87-96` carries it. | **real — implemented.** Cites drifted ~4 lines from the issue's (`:731-738` → `:735-742`); the code is as described. |
| C2 | *"`handle_uplink_nas_transport` writes `amf_ue.nr_tai` AND `amf_ue.nr_cgi` from it."* | `handle_uplink_nas_transport` is at `ngap_path.rs:1708` post-change (the issue said `:1638`); its SERVICE REQUEST dispatch is at `:1976` (issue said `:1860`). Before the change neither `nr_tai` nor `nr_cgi` was written anywhere in the function. | **real — implemented** (the write is at `:1762-1771`). |
| C3 | *"#400 established that `handle_handover_notify` is `nr_cgi`'s ONLY production writer; the registration path parses `nr_cell_identity`, logs it, and drops it."* | Confirmed by grep: the only non-test `nr_cgi` writes are `ngap_path.rs:7742-7743` (`handle_handover_notify`) and `gmm_handler.rs:154`/`:302`, and both `gmm_handler` functions are test-only-reachable (#397). `ngap_asn1.rs:357-368` decodes `nr_cell_identity` for the InitialUEMessage; `ngap_path.rs:1602-1607` logs it; `:1633-1636` stores only the TAI. | **real.** |
| C4 | *"The write goes through `ue_auth_state.with_mut` (or a `get` + `update` pair), because `UeStore::get` returns a clone."* | `ue_store.rs:113-115`: `get` is `.cloned()`. `with_mut` at `:128`. | **real — `with_mut` used at every site.** |
| C5 | *"A test drives a real `UplinkNASTransport` PDU carrying a TAI **different** from the registration's, through the production handler, and asserts the stored TAI changed."* | No such test existed. The one existing live-dispatch UL NAS test (`a_configuration_update_complete_stops_t3555_and_commits_the_guti`, `ngap_path.rs:15010-15025`) builds a real PDU with `tai_tac: [0,0,1]` but asserts nothing about location. | **real — implemented** as a contrast pair. |
| C6 | *"Once landed, reconsider `handle_service_request_nas` as a fire point for `PRESENCE_IN_AOI_REPORT` / `UES_IN_AREA_REPORT` and remove the stated ceiling."* | Ceiling at `ngap_path.rs:7789-7807` and `namf_server.rs:786-792`. | **real — implemented.** The premise the ceiling rested on is what this change removes; §5.3.1's change rule makes firing safe. |
| C7 | *"Consider whether `handle_initial_ue_message` should also store `nr_cgi` (it has the value and drops it)."* | `ngap_path.rs:1633-1636` stores `nr_tai` only, from `initial_ue.plmn_id`/`.tac`. `initial_ue.nr_cell_identity` is parsed (`ngap_asn1.rs:364-367`) and used only in a log line. | **real — implemented.** Third instance of the class. |
| M3 | #407's report: *"the AMF learns location at exactly TWO live moments, not three"* — the InitialUEMessage and `handle_handover_notify`. | Confirmed against `specs/implement-amfd-presence-area-model-for-aoi-events.md:48`. | **real, and this change makes it FOUR** (adds the Uplink NAS Transport and the PathSwitchRequest). |
| — | The issue's own framing: *"Fixing this makes the Service Request a **third** genuine location-learning moment."* | See the class survey below. | **INCOMPLETE.** The issue names one parser; the class has **three** instances, and fixing them takes the count from two to four. |

## Spec basis — every clause read, every IE id pinned to a quoted line

### The IE is mandatory on UPLINK NAS TRANSPORT, and its id is 121

TS 38.413 §9.2.5.3 UPLINK NAS TRANSPORT, `38413-j30.txt:14672-14673`:

```
  User Location    M                  9.3.1.16                  YES           ignore
  Information
```

`M`, not `O`. The presence column is what makes the lib parser's
`MissingMandatoryIe` refusal correct, and what makes discarding the decoded value a
defect rather than an unimplemented option.

The IE id is **121**, pinned to the assignment and not inferred from an adjacent
row — `38413-j30.txt:59673`:

```
id-UserLocationInformation ProtocolIE-ID ::= 121
```

which matches `libs/nextgcore-ngap/src/ie.rs:237`
(`IE_ID_USER_LOCATION_INFORMATION: u16 = 121`). No change needed there; verified
because three of four IE ids inferred from adjacent table rows elsewhere in this
session were wrong.

### It is equally mandatory on PATH SWITCH REQUEST

TS 38.413 §9.2.3.8 PATH SWITCH REQUEST, `38413-j30.txt:13741-13742`:

```
| User Location | M        |                         | 9.3.1.16      |             | YES         | ignore      |
| Information   |          |                         |               |             |             |             |
```

TS 23.502 §4.9.1.2.2 step 1b names the same value on the same message and says what
it means (`23502-k20.txt:17848-17858`): *"N2 Path Switch Request (... UE Location
Information ...). The Target NG-RAN sends an N2 Path Switch Request message to an AMF
to inform that **the UE has moved to a new Target cell**"*. An Xn handover completes
without the AMF seeing a `HandoverNotify` at all — the AMF's only notification of the
move is this message — so an AMF that ignores its ULI has no idea the UE relocated.

### What the AMF is expected to store, and when

TS 23.502 §4.2.3.2 step 2 (UE Triggered Service Request),
`23502-k20.txt:6149-6155`:

```
When NG-RAN is used, the N2 parameters include the 5G-S-TMSI, Selected
PLMN ID (or PLMN ID and NID, see clause 5.30 of TS 23.501 [2]), Location
information and Establishment cause, UE Context Request.
...
procedure. NG-RAN selects the AMF according to 5G-S-TMSI. The Location
Information relates to the cell in which the UE is camping.
```

*"the cell in which the UE is camping"* — present tense, the current cell, not the
one the UE registered from. That is the sentence this whole change implements.

### What a `LOCATION_REPORT` must carry

TS 29.518 §5.3.1.2, `29518-k00.txt:4833-4835`:

```
any of these UEs when AMF becomes aware of a location change of any of
these UEs with the granularity as requested.
```

The AMF *is being told* on every Uplink NAS Transport and *is not listening* — which
is the whole defect. The report's payload is `NrLocation`, whose two mandatory members
are both affected. TS 29.571 §5.4.4.9 Table 5.4.4.9-1, `29571-k00.txt:4674` and
`:4689`:

```
| tai                      | Tai             | M | 1           | Tracking Area Identity                 |
| ncgi                     | Ncgi            | M | 1           | NR Cell Identity                       |
```

Both `M`. So a truthful `LOCATION_REPORT` needs a fresh TAI **and** a fresh NCGI —
which is why this change writes both at every site, and why C7 (`nr_cgi` at
registration) is in scope rather than deferred: without it the `ncgi` half of a
mandatory pair is a default for every UE that never handed over.

### Why firing presence events from the Service Request is now safe

TS 29.518 §5.3.1.3, `29518-k00.txt:4893-4895`:

```
In subsequent notifications, the AMF shall only report the UE(s) whose
presence status has changed compared to the previous notification sent
by the AMF.
```

A `shall`. #407 read this correctly: re-evaluating a *stale* TAI at the Service
Request would report an unchanged verdict as news, breaching the clause. With the TAI
genuinely refreshed the clause is satisfied by the emitter's existing gate
(`event_subscription_record_presence`, `namf_server.rs:2205-2211`), which suppresses
an unchanged verdict — so the site now reports only real transitions.

## The defect class: three instances, all fixed in this pass

The recorded convention is that an issue naming one arm of a repeated shape has
usually found a class. It had. The class is *"an NGAP message whose
`UserLocationInformation` this tree decodes and then does not store"*. Enumerated by
walking every `user_location_info` field in `libs/nextgcore-ngap/src/types.rs` — there
are exactly four (`:62` `InitialUeMessage`, `:95` `UplinkNasTransport`, `:674`
`HandoverNotify`, `:707` `PathSwitchRequest`) — and checking each consumer:

| NGAP message | Decoded? | Stored before | Verdict |
|---|---|---|---|
| `HandoverNotify` | yes | **both** `nr_tai` and `nr_cgi` (`ngap_path.rs:7742-7745`) | already correct; the one working site, and the reference implementation for the others |
| `UplinkNasTransport` | yes, as **mandatory** | **nothing** — the wrapper struct had no field | **instance 1**, the filed issue |
| `PathSwitchRequest` | yes, as **mandatory** | **nothing** — `handle_path_switch_request` (`ngap_path.rs:8080`) bound `req` and never read `req.user_location_info` | **instance 2, not in the issue.** Found by the class grep. |
| `InitialUeMessage` | yes | `nr_tai` only; `nr_cell_identity` parsed, logged, dropped | **instance 3** — the half-instance #407 recorded as a ceiling (C7) |

`LocationReportingFailureIndication` was checked and is **not** an instance: the tree
has no such message type at all (`grep -rn 'LocationReportingFailure'
libs/nextgcore-ngap/src/` → zero hits), so the issue prompt's suggestion to grep it
names an artefact that does not exist here. Nothing to fix and nothing to enumerate.

### Instance 2 is the one that matters most after the filed one

`handle_path_switch_request` is the AMF's only view of an **Xn**-based handover. An
N2 handover ends in `HandoverNotify`, which does store the location; an Xn handover
ends here, which did not. So before this change a UE that moved by Xn handover — the
common case, since Xn is preferred whenever the interface exists — left the AMF's
stored location untouched, and `nr_cgi`'s "one production writer" was reachable only
via the *less* common handover type.

## Design decisions

### Where the write goes, and why the ordering is load-bearing

`ue_auth_state` **is** the store the emitter reads. Verified rather than assumed,
because this tree has bitten agents twice with clones and once with two stores:
`ngap_path.rs:697` initialises `ue_auth_state` from
`crate::context::amf_self()...ue_store()`, and `context.rs:1618-1620`'s `ue_store()`
hands back an `Arc` clone of the same `UeStore` — one store, two names.
`find_ue_by_context_id` (`namf_server.rs:374-388`) resolves through
`amf_ue_find_by_supi`, which reads that store (`context.rs:1663-1667`). So a
`with_mut` on `ue_auth_state` is visible to `LOCATION_REPORT` with no publish step.
Every write in this change uses `with_mut`, so there is no clone to forget to write
back (C4).

In `handle_uplink_nas_transport` the write is placed **before** the EPD/security
branching, not beside the SERVICE REQUEST arm. Three reasons:

1. **The Service Request arm is not the only path that needs it.** The legacy raw-5GSM
   branch (`epd == 0x2E`) returns early, and the MAC-failure branch returns from
   `handle_integrity_check_failure`. Both are still an Uplink NAS Transport carrying a
   mandatory, already-validated location.
2. **`handle_service_request_nas` must observe the new value.** It reads the UE out of
   the store to build the Service Accept and again to fire its five events. A write after
   dispatch would leave `fire_location_report` reading the old TAI — the defect,
   relocated. Verified by revert, not by argument: moving the call to after the
   `match msg_type` block makes
   `a_service_request_reports_the_location_it_arrived_with_not_the_registration_s` fail
   while its sibling still passes.
3. The IE's validity does not depend on the NAS payload. It was decoded and accepted by
   the time `parse_uplink_nas_transport_asn1` returned.

Placing it before the security-decode block is safe despite that block's
`remove`/`insert` round-trip: the same record object is taken out, mutated and put
back, so an earlier field write survives it.

### One helper rather than four copies of the destructure

`UserLocationInformation::Nr` has to be unpacked into a `Tai5gs` and an `NrCgi` at
each site, with a 3-byte-big-endian TAC assembly that is easy to get subtly wrong.
`handle_handover_notify` had it inline. Extracted to `apply_user_location`
(`ngap_path.rs`), which the Uplink NAS Transport, PathSwitchRequest and HandoverNotify
sites all call. Four copies of a byte-order expression is how one of them ends up
different from the others.

`handle_initial_ue_message` does **not** use it: `parse_initial_ue_message_asn1`
already flattens the ULI into `InitialUeMessageData`'s `plmn_id` / `nr_cell_identity`
/ `tac` fields, so there is no `UserLocationInformation` left at that site to pass.
Reshaping that struct to carry the enum instead would be a wider change for no
behavioural gain.

### Why `ue_ncgi_is_known`'s guard STAYS, though its prose changes

C7 gives `nr_cgi` a writer at registration, so the #407 ceiling — *"an `ncgiList`
area can only resolve after a handover"* — stops being true. It is tempting to delete
the `ue_ncgi_is_known` guard along with it. That would be wrong: a default
`cell_id == 0` still means *"never learned"* for a UE published by something other
than the NGAP registration path (a test fixture, an inter-AMF context transfer via
`amf_ue_publish`), and reporting `OUT_OF_AREA` off an unwritten field is the
fabrication #400 exists to prevent. The guard is unchanged; the doc comments and the
test name that asserted *"only after a handover"* are corrected to state the real
invariant, which is about the value being default rather than about which procedure
ran.

### Rejected: adding a `LocationReport` NGAP message type

TS 38.413 has a LOCATION REPORT / LOCATION REPORTING CONTROL pair, and an AMF that
wanted an *unsolicited* location refresh would use it. Out of scope: this change is
about not discarding locations the tree already receives and decodes. Implementing a
new NGAP procedure that no nextgsim gNB sends would be a correct implementation in an
unreachable place — the tree's commonest defect, and the reason `AmfContext::gnb_list`
and the dead MBS manager are on record.

## Behavioural change

| Site | Before | After |
|---|---|---|
| `handle_uplink_nas_transport` (every UL NAS message, incl. SERVICE REQUEST) | no location write | `nr_tai` + `nr_cgi` refreshed from the message's ULI, before NAS dispatch |
| `handle_service_request_nas`'s `LOCATION_REPORT` | reports the **registration's** TAI | reports the TAI the gNB just sent |
| `handle_service_request_nas` presence events | did not fire (ceiling) | `PRESENCE_IN_AOI_REPORT` + `UES_IN_AREA_REPORT` fire, gated by §5.3.1's change rule |
| `handle_path_switch_request` (Xn handover) | no location write | `nr_tai` + `nr_cgi` moved to the target cell |
| `handle_initial_ue_message` | `nr_tai` only | `nr_tai` + `nr_cgi` |
| `nr_cgi` production writers | 1 (`handle_handover_notify`) | 4 |

## Tests

Contrast pairs throughout, with **positive** assertions: each asserts the stored value
EQUALS what the message carried, against a fixture whose registration value is
genuinely DIFFERENT. #407 caught one of its own tests passing with the guard deleted
because its fixture UE had no location at all, so every fixture here is seeded with a
real, distinct prior location.

Every row below was actually run: the change was reverted, the NAMED test was watched
to fail with the recorded values, and the revert was restored. The observed `left:`
values are quoted because "it failed" is weaker than "it failed by reading back
precisely the stale value the defect would have produced".

| Test | Asserts | Revert-verification (observed) |
|---|---|---|
| `an_uplink_nas_transport_refreshes_the_stored_tai_and_cell` (`ngap_path.rs`) | a real APER-encoded `UplinkNASTransport` carrying TAC `0x0A0B0C` / cell `0x9_9999` through `handle_uplink_nas_transport` leaves the store holding exactly those, where registration had seeded TAC `0x000401` / cell `0x1_1111` | deleted the `apply_user_location` call from `handle_uplink_nas_transport` → **FAILED**, `left: 1025` — decimal `0x000401`, the registration's TAC, against `right: 658188` (`0x0A0B0C`) |
| `a_service_request_reports_the_location_it_arrived_with_not_the_registration_s` (`ngap_path.rs`) | the same handler driving a genuine SERVICE REQUEST: the store's TAI is the one the PDU carried and differs from the seeded registration TAI | **two** reverts. (a) deleting the call → **FAILED**, `left: 1026` (`0x000402`). (b) MOVING the call to after the `match msg_type` dispatch → **FAILED** with the same `left: 1026` **while the sibling test still PASSED** — which is what makes the ordering argument falsifiable rather than merely asserted |
| `a_path_switch_request_moves_the_stored_location_to_the_target_cell` (`ngap_path.rs`) | Xn handover: `nr_tai`/`nr_cgi` after `handle_path_switch_request` are the target's, not the source's | deleted the `apply_user_location` call from the handler's `with_mut` → **FAILED**, `left: 1027` (`0x000403`, the source TAC) against `right: 921360` (`0x0E0F10`) |
| `the_initial_ue_message_stores_the_cell_identity_it_parsed` (`ngap_path.rs`) | registration leaves `nr_cgi.cell_id` equal to the InitialUEMessage's `nr_cell_identity`, not `0` | removed the `nr_cgi` write at the registration site → **FAILED**, `left: 0` against `right: 419430` — the default that made `ue_ncgi_is_known` answer `UNKNOWN` |
| `an_ncgi_area_reports_unknown_for_a_ue_whose_cell_was_never_learned` (`namf_server.rs`, renamed from `..._until_the_cell_identity_is_learned`) | unchanged behaviour, corrected name and prose: a DEFAULT `nr_cgi` reports `UNKNOWN`, a learned one resolves | made `ue_ncgi_is_known` return `true` unconditionally → **FAILED**, `left: Some("OUT_OF_AREA")` against `right: Some("UNKNOWN")`. Re-confirmed AFTER the rename, so the inversion did not quietly stop testing anything |

Distinct literal keys per test, each with a comment saying why, because two amfd
tests once shared `78_001` and failed ~1 run in 3. Tests that touch the
process-global AMF context take `crate::test_support::CONTEXT_GUARD`; no new lock is
declared.

## Verification

* `cargo fmt --all -- --check`: clean.
* `cargo clippy --workspace` (CI's exact invocation, which gates on errors): **0 errors**.
  The warnings it prints are all pre-existing and in other crates — `nextgcore-nas`
  (two `clone_on_copy` on `PlmnId`), `nextgcore-eesd`, `nextgcore-smfd`. None in the
  three files this change touches.
* `cargo test --workspace`: **6898 → 6902 passed, 0 failed.** +4 net: four new tests, one
  renamed (rename is net-zero).
* The amfd suite looped **10×**, 609 passing every run, `/proc/loadavg` 1.44–2.07
  throughout. No flake, which matters because this change adds four tests that touch the
  process-global AMF context.

### The Docker E2E: affected, but its assertion still holds — and for a better reason

`Docker E2E` is gated `schedule || workflow_dispatch` and skips on a PR. Its phase-2 step
(#403) drives a real nextgsim UE to `RRC_INACTIVE` via `ue-suspend` and asserts that the
Service Request's `LOCATION_REPORT` carries `mcc 999 / mnc 70 / tac 0001`
(`.github/workflows/ci.yml:508`).

That assertion **passes before and after**, and the reason it changes is the point of this
issue. The deployment has a single cell: `nextgsim/config/gnb.yaml` carries
`plmn: {mcc: 999, mnc: 70}` and `tac: 1`, matching `configs/5gc/amf.yaml`. So the TAI the
UE registered with and the TAI its Service Request arrives with are the SAME value, and
the probe cannot distinguish a fresh read from a stale one. Before this change it was
passing off the registration's stored TAI; after, off the TAI the Uplink NAS Transport
carried. Same bytes, different provenance.

Not dispatched, deliberately: the run would exercise the same single-cell topology and
could only reconfirm a value it already confirms. The provenance — which is the whole
defect — is not observable at that probe and **is** observable in
`a_service_request_reports_the_location_it_arrived_with_not_the_registration_s`, which
uses two genuinely different TACs and fails by reading back `0x000402` when the write is
removed or misordered. The unit test is the stronger instrument here, and a green E2E
could not have caught the defect in the first place.

What a future E2E *could* add: a two-cell gNB config, so `ue-suspend` followed by a move
makes the stale and fresh values differ on the wire. That needs a nextgsim topology
change and is out of scope.

## Residual ceilings

* **`ageOfLocationInformation` and `ueLocationTimestamp` are still omitted** from
  `NrLocation`. Both are `O` (`29571-k00.txt:4700`, `:4720`), and the tree holds no
  per-location timestamp to populate them from. Unchanged by this issue; naming them
  here so a reader does not mistake the omission for this change's doing.
* **Non-NR access.** `UserLocationInformation` in this tree is a one-variant enum
  (`types.rs:460-472`, `Nr` only); TS 38.413 also defines EUTRA, N3IWF, TNGF, TWIF and
  W-AGF variants. Out of scope and unchanged: nothing decodes them, so there is no
  discarded value to rescue.
* **`ignoreNcgi`** (`29571-k00.txt:4692`) is not sent. The AMF has no reason to tell a
  consumer to ignore a cell identity it now genuinely learns.
* **At registration only, the TAI's PLMN is taken from the NR-CGI's.** `InitialUeMessageData`
  keeps one `plmn_id`, decoded from `nr_cgi_plmn`, and discards `tai_plmn`
  (`ngap_asn1.rs:357-368`). The pre-existing `nr_tai` write already used it and the new
  `nr_cgi` write uses it correctly, so this change neither introduces nor worsens the
  inexactness — but it is now the ONE site that does not read the two PLMNs separately,
  since `apply_user_location` does. It only matters in a shared-RAN deployment where a
  cell's PLMN differs from its tracking area's; nothing in this tree distinguishes them.
  Widening `InitialUeMessageData` to carry the `UserLocationInformation` (or both PLMNs)
  would close it, and is deliberately left as a separate change rather than smuggled in
  here. Recorded so a reader does not have to rediscover it.
