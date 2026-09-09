# nextgcore #56: the HSS-initiated half of S6a

Verified against `main` @ `675ab95`.

Closes #56 — all six acceptance criteria, plus the reliability criterion the issue
lists separately.

## The defect

`nextgcore-hssd` implemented the reactive half of S6a (ULR/AIR/PUR answers) and
none of the HSS-initiated procedures that keep MME subscriber state coherent. Five
distinct gaps, all re-verified against `main` before starting:

1. **No previous-MME CLR on ULR.** `handle_ulr` called
   `nextgcore_dbi_update_mme`, a blind Mongo `$set`, which never reads the stored
   MME identity — so the identity was unrecoverable by the time anything could act
   on it, and the Cancel Location TS 29.272 §5.2.1.1.3 requires could never be sent.
2. **No change-driven propagation.** `hss_s6a_send_clr` / `hss_s6a_send_idr`
   existed with **no production caller**: their only invocations were the `lib.rs`
   re-export and unit tests.
3. **Missing procedures.** The `cmd` table had 316/317/318/319/321 only. NOR (323)
   fell to the dispatch catch-all and was answered `3001 DIAMETER_COMMAND_UNSUPPORTED`
   with the E-bit; DSR (320) and RSR (322) did not exist.
4. **No reliability.** `send_to_mme` returned `Ok` as soon as the message hit a
   channel and failed immediately when the MME was not connected.
   `handle_s6a_answer` incremented counters and nothing else — no Session-Id
   correlation, no retransmission, no requeue.
5. **Charging-Characteristics** was a raw 2-byte OctetString (TS 29.061 specifies a
   4-hex-char UTF8String) **and** hardcoded `None`, so it was never sent at all.

## Two absent preconditions in the suggested approach

Both found by grepping what the approach names, as this project's convention
requires.

**"Wire IDR/CLR/DSR into the existing DB change-poll loop" — there is no such
loop.** `run_event_loop` was a 100 ms `sleep` with three comments describing what a
full implementation would do (`// Poll database for changes (if configured)`) and no
database access of any kind. The detection had to be **built**, which is
`subscriber_watch.rs`.

**"Populated from the subscriber record" — the record has no such field.**
`NextgcoreSubscriptionData` had no `charging_characteristics`, at subscriber or APN
level, so criterion 6's second half needed the DB model and its BSON parse extended
first.

## The change

### Charging-Characteristics (criterion 6)

New `s6a::ChargingCharacteristics`, so the wire form is a property of the type
rather than of each call site. Encodes as the 4-hex-char UTF8String; **parses both**
encodings, discriminated by length (4 bytes of ASCII hex vs 2 raw octets) — which
is why the hex branch checks hex-ness rather than merely "is it a string": a decoded
AVP arrives as `Raw`, and two arbitrary octets are often valid UTF-8.

`NextgcoreSubscriptionData` and `NextgcoreSession` gain
`charging_characteristics: Option<String>` (the provisioned value verbatim — the DB
layer does not know the S6a wire format) and the session gains `pgw_id`.
`subscription_data_from_db` sources per-APN first, then subscriber-level, per
Table 7.3.1/2's own wording. A provisioned value that is not 4 hex characters is
**omitted with a warning naming the subscriber**, because a wrong charging class is
a billing error and sending it mangled is worse than sending nothing.

**Verification limit, stated because it cannot be closed here:** TS 29.061 is not
vendored in this tree. `29272-j50.txt` Table 7.3.1/2 defines the AVP only by
reference to it. So the 4-hex-char form rests on that deferral plus #56's citation,
not on a quotable local source — which is exactly why the parser accepts both and
the encode change is the only leap.

### Previous-MME Cancel Location (criterion 1)

`handle_ulr` reads the stored identity via the existing `lookup_serving_mme`
**before** the `$set`, then sends CLR(`MME_UPDATE_PROCEDURE`) if it differs. The
decision is `previous_mme_needing_cancel`, kept pure so its four cases are testable
without Mongo.

Two judgement calls in it:

* **ASCII-case-insensitive comparison.** A Diameter identity is a FQDN
  (RFC 6733 §4.3.1), so `MME1.example.org` and `mme1.example.org` are one node.
  Treating them as two sends a spurious Cancel Location that detaches a UE
  mid-attach — worse than the stale context this fixes.
* **The Cancel Location is non-fatal to the ULR.** The new MME's location update has
  already succeeded; failing it because the *old* MME is unreachable would deny
  service to a UE that attached correctly. It is queued instead (below).

### Reliability (the separate criterion)

`send_tracked` replaces `send_to_mme` on every HSS-initiated path. Requests are
held in a Session-Id-keyed table; `handle_s6a_answer` correlates and clears.
`decide_pending_action` is pure — attempts, elapsed, peer-connected,
awaiting-peer, period, max — so every branch is testable with no socket, timer or
peer. `sweep_pending_requests` runs every 5 s from the event loop;
`requeue_for_peer` runs from `register_mme_peer`.

The load-bearing detail: a request whose peer is **disconnected** neither
retransmits nor spends its retry budget. Spending it against a peer that is not
there would abandon the request before the peer came back, which is the same
data-loss the fire-and-forget send had, just slower.

Locks are taken one at a time and decisions are made under a read lock before
acting, because `send_to_mme` takes the peer-registry lock and holding the pending
table across it is the AB-BA shape this crate documents elsewhere.

### NOR / NOA (criterion 3a)

`parse_nor` reads `MIP6-Agent-Info` (RFC 5447, **no vendor id**),
`Service-Selection` (RFC 5778, no vendor id), `Context-Identifier`, `NOR-Flags` and
`Alert-Reason`. `PdnGwIdentity::to_stored_string` prefers the FQDN per §7.3.45
(*"FQDN shall be used if known"*) and renders an RFC 3588 Address otherwise, falling
back to hex for an unrecognised family rather than dropping the identity.

Three decisions:

* **An unscoped identity is refused.** §5.2.5.1.1 scopes the notification to a
  PDN-GW *"for an APN"*; with neither Service-Selection nor Context-Identifier
  nothing names which APN, and filing it somewhere arbitrary is worse than saying so.
* **A NOR carrying only unmodelled IEs is answered NOA 2001.** §7.2.17 makes every
  informational IE optional and most are things this HSS does not model. The
  pre-#56 3001+E-bit tells a conformant MME the whole command is unsupported, so it
  stops using the procedure — including the PDN-GW notification that *is* handled.
* **A missing subscriber or APN answers `ERROR_USER_UNKNOWN`**, not
  `UNABLE_TO_COMPLY`: the MME asked about something this HSS does not have.

### DSR and RSR (criterion 3b, 4)

Builders plus the answer-side handling. Two spec details that a looser
implementation would get wrong, and which have tests:

* **Context-Identifiers only travel with the PDN-subscription-contexts withdrawal
  bit** (§7.3.25 Note 1). Sending them without it names contexts the MME was not
  told to delete.
* **RSR carries no `User-Name`.** §7.2.15's message format has none: Reset applies
  to a *set* of subscribers named by `User-Id` prefixes (§7.3.50). A per-subscriber
  Reset is a message the spec does not define.

Restart restoration uses a running-marker file, and **arms** rather than sends: the
HSS is the S6a responder, so at startup no MME is connected and an immediate send
reaches nobody — the shape of a procedure that looks implemented and never fires.
Every MME registering within 300 s gets the Reset. Bounded because an MME
reconnecting an hour later has already re-run Update Location as part of
reconnecting. A marker that cannot be written disables crash detection **and says
so**, because declaring every start unclean makes every MME re-run Update Location
for its whole subscriber base.

### Change-driven IDR / CLR (criterion 2), and why it is OFF by default

`subscriber_watch.rs`. The **decision** is `diff_subscribers`, pure over two maps;
the **wiring** is `poll_once`'s Mongo read.

Rules, each with a reason:

| Transition | Action | Why |
|---|---|---|
| present → present, fingerprint changed, has MME | IDR | the §5.2.2.1.1 administrative-change case |
| present → absent, had MME | CLR(SUBSCRIPTION_WITHDRAWAL) | §5.2.1.2.1 |
| absent → present | nothing | its data came in the ULA it attached with |
| serving MME changed | nothing | that Cancel Location is `handle_ulr`'s; acting here cancels the same UE twice |
| fingerprint changed, no MME | nothing | nobody to tell |
| present → absent, no MME | nothing | nobody to cancel |

The fingerprint covers **only the fields that reach Subscription-Data**. Hashing the
whole document would fire an IDR on every SQN increment — which happens on *every
authentication* — turning the watcher into a per-attach IDR generator.

A failed read returns the **previous** view unchanged, because the alternative reads
as "every subscriber was deleted" and fires a Cancel Location storm. That is the one
failure mode of a polling differ that is worse than not polling.

**Off by default** (`HSS_SUBSCRIBER_WATCH=1`), which is unusual for this project —
most runtime switches here default on. The reason is specific: this is the one part
of #56 whose MongoDB read no test in this tree can verify, and a misfiring watcher
does not merely fail to notify, it sends unsolicited Cancel Locations that **detach
live UEs**. Something that can detach a subscriber gets switched on deliberately.
The disabled path logs what it is not doing, so the gap is visible.

## Verification

**21 guards revert-verified**: fix broken, **named** test watched to fail, file
restored (`md5sum`-checked). Grouped:

| Area | Reverts that bit |
|---|---|
| previous-MME CLR | decision blind to a different MME; equality check removed; empty-host guard removed |
| reliability | disconnected peer abandoned instead of parked; retry bound removed; retransmit period removed |
| Charging-Characteristics | back to raw octets; hex validation removed; legacy octet parse removed |
| PDN-GW identity | FQDN preference removed |
| NOR | unscoped identity stored anyway; Service-Selection ignored; MIP6-Agent-Info ignored |
| DSR / RSR | Context-Ids sent without their bit; RSR given a User-Name |
| restart | marker sense inverted; marker not released; no Reset on registration |
| watcher | cancels on inter-MME move; IDRs unconditionally; never IDRs; never cancels a deletion; IDRs a new attach; output unordered; IDRs with no MME |

### An existing test was inverted, and it was pinning the defect

`test_send_clr_requires_connected_peer` **required** `hss_s6a_send_clr` to fail when
no peer is connected, asserting on the "no connected S6a peer" message. That is
precisely the fire-and-forget behaviour criterion 5 exists to remove
(*"requeued when the MME reconnects rather than dropped when no peer is
connected"*). Renamed to `test_send_clr_queues_when_no_peer_is_connected` with the
inversion and its reason recorded at the site.

### Three sibling tests broke, and the cause was my own new global state

`arm_restart_reset` installs process-global state that stays armed for 300 s, so a
test that armed it made **every later test registering an MME peer** receive an
unexpected Reset-Request first — `test_send_clr_transmits_to_registered_peer` and
the S6a end-to-end test read command 322 where they expected 317. Fixed with one
`PEER_TEST_LOCK` taken by every test that touches the peer registry, the pending
table or the arming flag, plus a `#[cfg(test)] disarm_restart_reset` the arming test
calls before releasing. One agreement about those variables rather than several
disjoint ones. Three consecutive full-crate runs green after.

Workspace: **6171 passed / 0 failed**, `cargo clippy --workspace` and
`cargo fmt --all --check` clean.

## Ceilings

* **The watcher's MongoDB read is verified by inspection only.** No test harness in
  this tree runs a MongoDB, so `read_current_view` and `poll_once`'s query are
  unexercised. This repo has a recorded hazard that "the helper is tested and the
  wiring is not — and the better the helper's test, the more convincing the
  illusion", so: the decision function has 7 tests and the read has none, and the
  switch defaults off partly for that reason.
* **`hssd` never connects to MongoDB at all** (pre-existing, already documented):
  no code path calls `nextgcore_dbi_init`, so in the released binary every DB-touching
  path answers 5012. Every criterion here whose effect is a DB write — the PDN-GW
  identity store, the Charging-Characteristics read, the watcher — is therefore
  logic verified against the model, not against a running database.
* **`MIP6-Agent-Info`, `MIP-Home-Agent-Address` and `MIP-Home-Agent-Host` codes
  (486, 334, 348) come from RFC 5447 and RFC 4004**, which are not vendored here;
  TS 29.272 §7.3.42-45 defines them only by reference. The 3GPP-specific codes
  (DSR-Flags 1421, NOR-Flags 1443, User-Id 1444, Reset-ID 1670, Alert-Reason 1434)
  were all read out of the vendored §7.3 AVP table.
* **`Charging-Rule-Base-Name`-style group resolution has no analogue here**, but the
  same shape appears in NOR: a `Context-Identifier`-scoped PDN-GW identity is stored
  at subscriber level with the context id alongside, rather than resolved to an array
  element, because the ordinal is assigned by enumeration order in
  `subscription_data_from_db` and a read-modify-write to resolve it would race
  provisioning.
* **No wire interop.** Every message round-trips through the real encoder and
  decoder, but against this tree's own codec and a channel-backed fake MME, not a
  third-party MME.
* **GitNexus impact analysis unrunnable** (54th consecutive PR): the MCP server is
  not connected. Blast radius by grep — the only breaking signature change is
  `SubscriptionData::charging_characteristics` / `ApnConfiguration::charging_characteristics`
  changing type, whose consumers are `mmed`'s `s6a_handler` and `fd_path` (both
  updated) and the s6a codec itself.
