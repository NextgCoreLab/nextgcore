# nextgcore #301 (mbsmfd): release shared delivery per RAN node, not per session

Verified against `main` @ `a724778`.

#301 was filed from #295's own first ceiling. Every claim in it still holds. TS 23.247 §7.2.1.4 /
§7.2.2.4, TS 38.413 §9.3.5.7 / §9.3.5.10 / §9.3.1.5, TS 29.571 `GlobalRanNodeId`.

## Verified against current main

| claim in the issue | site on `a724778` | still true? |
|---|---|---|
| the `MbsDisRelReq` arm calls the unconditional `session_context_terminate` | `main.rs:1646` | yes |
| …then `release_n4mb_transport`, so one RAN node tears down shared delivery for all | `main.rs:1658-1663` | yes |
| #295's set is keyed on `nfcInstanceId`, which on this leg is the AMF's | `context.rs:190`, registered only on the SMF leg (`main.rs:1277`) | yes |
| nothing in the tree tracks a RAN node | `grep ran_node_id` → one `Option<serde_json::Value>` field, read only for the `is_amf` decision | yes |
| `session_context_terminate`'s own doc names this gap and points at the spec's ceiling | `context.rs:1009-1012` | yes |
| `test_router_context_update_amf_release_golden_204` exists and must keep passing | `main.rs:3049` | yes |

The issue's diagnosis of **why #295 could not fix it** is also correct as written: deregistering
the AMF's `nfcInstanceId` finds it absent (SMF STARTs populate that set), so a legitimate N2-driven
release would stop releasing anything and that golden test would fail; and registering it would let
an AMF's silence pin the transport open, which #295's Decision 2 explicitly declines to create.

## Decision 1: the key is a canonical string, not the decoded structure

`ranNodeId` arrives as an untyped `serde_json::Value` and `GlobalRanNodeId` (TS 29.571) is a choice
of `gNbId` / `ngeNbId` / `n3IwfId` / `wagfId` / `tngfId` / `eNbId` / `nid`. `canonical_ran_node_key`
renders one string per node: `<mcc>-<mnc>/<member>:<normalised value>`, with `gNbId` normalised as
`bitLength:GNBVALUE` and every textual id upper-cased.

Why not the structure: two JSON objects that mean the same node can differ in member order and in
hex case, and **a key that does not agree with what was stored silently fails to match** — the
symptom being a release that answers 204 and releases nothing. That is exactly what `MbsSession.ssm`
records for the SSM, and #295's note asks for it to be considered here.

Three specifics the guard pins:

- The **PLMN scopes the node id**. A gNB id is only unique within its PLMN (TS 38.413 §9.3.1.5), so
  the same `gNBValue` in two PLMNs is two holders.
- **`bitLength` is part of the identity**, not decoration: a 22-bit and a 24-bit gNB id with the
  same value are different nodes, not one truncated.
- An **unrecognised shape still keys consistently with itself** (via a sorted-member rendering)
  rather than being dropped. It only has to match its own release. `Value::to_string()` is not used
  for this — it is not guaranteed to order members independently of how they were parsed, and it
  preserves hex case.

Not stored: the received `ranNodeId` value. Nothing echoes it back to a peer (unlike the SSM, which
a ContextUpdate response carries), so a `HashSet<String>` is the whole requirement. If a future
issue needs to echo it, the set becomes a map from key to received value.

## Decision 2: either set being non-empty keeps the transport up — stated, and guarded both ways

The issue asks for this explicitly ("the safe reading is that either set being non-empty keeps the
transport up, but that is a decision, not an obvious truth — say which and why"). **Adopted**, and
applied on both legs.

The reason: the two sets count different things at different layers — SMF consumers of the MBS
session, and RAN nodes receiving the shared NG-U tunnel — and there is exactly **one** MB-UPF
session underneath serving both. Releasing it while either side still needs it stops that side's
data, which is the defect #295 and #301 each fix in their own dimension. Consulting only one set
would leave the other's version of the bug open, and the tests prove it: reverting either half of
the cross-check fails `either_a_consumer_or_a_ran_node_keeps_the_shared_transport_up`.

So `session_context_terminate_for` (the #295 SMF leg) now also refuses while a RAN node holds the
transport, and `session_ran_node_release` refuses while a consumer does. Both share one
`transport_holders` helper that returns the union, prefixed `consumer:` / `ran-node:` so the warn
line and the assertions can tell them apart.

**This changes #295's behaviour**, deliberately: an SMF's last TERMINATE used to release
unconditionally once its own set emptied. It no longer does when a RAN node is still receiving. The
`ConsumerTerminate::ConsumerRemains` variant's doc was widened from "other consumers" to "other
holders" rather than adding a second near-identical enum.

## Decision 3: untracked means pre-#301 behaviour, not a silent non-match

A setup or release whose `ranNodeId` is absent (the schema makes it optional; a release can arrive
identified only by its N2 container) or is not an object cannot be keyed. Such a leg is **not**
inserted into the set, and the first release therefore still tears the transport down — the same
"cannot be tracked, so behave as it did before" rule #295 states for an empty `nfcInstanceId`,
warned about at both ends and guarded by its own test.

The alternative — keying an untracked node on the empty string — would make **every** untracked RAN
node the same holder, so two of them would share one entry and the first release would strand the
second. Refusing to key is the honest option.

## Decision 4: register on the establish side, before the transport exists

`session_ran_node_register` runs at the top of `amf_shared_delivery_setup`, before
`session_context_start` brings the N4mb transport up — mirroring where #295 registers a consumer,
and for the same reason it gives: registering afterwards leaves a window in which a second RAN
node's release sees an empty set and tears down a transport this setup had just asked for.

Both entries into `amf_shared_delivery_setup` register: the `MBS_DIS_SETUP_REQ` arm and the legacy
JSON-only AMF request (`ranNodeId` with no container), which is also a shared-delivery setup.

## Acceptance criteria

- [x] Two RAN nodes are set up for one TMGI; the first `MBS_DIS_REL_REQ` answers `204` and the
      transport stays up (`n4mb_session` still present) —
      `two_ran_nodes_share_delivery_and_only_the_last_release_tears_it_down`.
- [x] The second releases it, and the context is cleared (same test).
- [x] A repeated release for the same `ranNodeId` does not double-decrement (same test: a second
      release from gNB 000001 leaves gNB 000002's delivery up).
- [x] A setup from a `ranNodeId` already in the set does not double-count —
      `a_repeated_setup_from_one_ran_node_does_not_double_count`.
- [x] The interaction with #295's consumer set is stated (Decision 2) and guarded by a test in both
      directions — `either_a_consumer_or_a_ran_node_keeps_the_shared_transport_up`.
- [x] `test_router_context_update_amf_release_golden_204` still passes: a session with exactly one
      RAN node behaves as it does today. So does
      `mbs_context_update_strict_peer_release_204`, the golden-bytes version of the same flow.

## Verification

`cargo test --workspace`: **6300 passed / 0 failed** (baseline 6295 on `a724778`; mbsmfd 97 → 102).
`cargo clippy --workspace --all-targets` introduces no new warning; `cargo fmt --all -- --check`
clean.

| revert | expected to break | result |
|---|---|---|
| the release arm calls the unconditional `session_context_terminate` again | `two_ran_nodes_...`, `either_a_consumer_...` | **2 failed** |
| the setup leg no longer registers the RAN node | both of those plus `a_repeated_setup_...` | **3 failed** |
| the SMF terminate ignores the RAN-node set (#295 alone) | `either_a_consumer_...` | **1 failed** |
| the RAN-node release ignores the consumer set | `either_a_consumer_...` | **1 failed** |
| the key is `value.to_string()` with no canonicalisation | `the_ran_node_key_is_stable_...` | **1 failed** |

Five reverts, five bites. The two middle ones are what make Decision 2 a verified claim rather than
a stated preference: each direction of the cross-check has a test that only it can fail.

## Ceilings

- **Nothing unpins a transport whose RAN node never releases.** #295's never-departing-consumer
  decision is followed unchanged: the pin is logged at `warn` naming every remaining holder rather
  than timed out, because tearing down a transport that is still carrying data because a RAN node
  went quiet is worse than the pin. No NGAP-level liveness signal reaches this daemon to do better.
- **The RAN-node set is not driven by anything except ContextUpdate.** An AMF that loses its NG
  connection to a gNB does not tell the MB-SMF, so the entry persists. Same shape as the point
  above and out of this issue's scope.
- **`MbsDistributionReleaseRequestTransfer`'s own contents are not consulted** beyond the TMGI
  match that already existed. The container names the session, not the node; the node comes from
  the JSON `ranNodeId`, which is the only place TS 29.532 carries it.
- **No test drives two AMFs**, only two RAN nodes through one AMF's `nfcInstanceId`. The set is
  keyed on the RAN node precisely so that does not matter, but it is asserted at the router rather
  than across two peers.
- **The MB-UPF is not asked to prune per RAN node.** TS 23.247 §7.2.2.4 releases shared delivery
  toward one node; this makes the MB-UPF *session* survive, but the N4mb Create FAR's gNB endpoint
  list (`N4mbSession.gnb_teids`) is not trimmed when one node leaves. Nothing populates that list
  per RAN node today either, so trimming it would be inventing state; worth its own issue if
  per-node NG-U pruning is wanted.
