# nextgcore #299 (pcfd): a policy-data change reaches a live SM policy association

Verified against `main` @ `f5bf6ab`.

#299 was split out of #293 by that issue's own instruction. Its **scope and criteria hold**; the
example in its motivation does not, and that is the finding this spec leads with. TS 23.502
§4.16.11, TS 23.503 §6.1.3.2, TS 29.519 §5.2 / §5.6.2, TS 29.512 §4.2.3.2.

## Verified against current main

| claim in the issue | site on `f5bf6ab` | still true? |
|---|---|---|
| pcfd has no UDR policy-data subscription and no notification sink | `grep -rn 'subs-to-notify' bins/nextgcore-pcfd/` → **nothing** | yes |
| nothing re-drives `Npcf_SMPolicyControl_UpdateNotify` for a subscription change | `pcf_sbi_send_smpolicycontrol_update_notify` has callers, none of them a data change | yes |
| the SMF side needs nothing new (`handle_sm_policy_notify` already serves) | smfd, unchanged here | yes |
| "Check whether udrd can even notify" | **it can, fully** — see below | the pre-check passes |
| an operator's edit reaches a live PCF-authorised session through no path | yes for policy data; **and still yes for session-AMBR after this PR** | see Decision 1 |

**The pre-check the issue asks for comes back favourable.** udrd already implements the whole UDR
half: `POST /nudr-dr/v2/policy-data/subs-to-notify` (`handle_policy_subs_to_notify`, validating
`notificationUri` and a non-empty `monitoredResourceUris`, answering 201 + `Location`), and
`notify_policy_data_change` emits a `PolicyDataChangeNotification` carrying `ueId`, `reportId` and
`policyDataSubset` to every subscriber whose monitored URIs cover the changed path. Its own comment
says why both notification trees are emitted: *"a `/policy-data/subs-to-notify` subscriber (the PCF)
gets the `PolicyDataChangeNotification`. Emitting only the first is why a PCF could subscribe and
never hear anything."* So this PR is the first in-tree producer of that subscription, and no udrd
work was needed.

## Decision 1: the issue's session-AMBR example is served by a different mechanism, and is filed separately

#299's motivation leads with *"an operator editing a subscriber's session-AMBR reaches a live
session through no path at all"*. Implementing the issue does **not** fix that, and it cannot:

`SmPolicyDnnData` (TS 29.519 §5.6.2) carries `online`, `offline`, `gbrUl`/`gbrDl`,
`allowedServices`, `subscCats` and charging/usage-monitoring references — and **no session-AMBR, no
default 5QI, no ARP**. This tree already said so, in a comment older than both issues, at the create
path that reads the resource:

> "The QoS/ARP/AMBR/PCC decision is not re-derived from this resource (**SmPolicyDnnData does not
> carry them**); only the spec-defined online/offline charging flags are."

The subscribed session-AMBR lives in the **UDM's** session-management subscription data, and the
PCF's input for it is `SmPolicyContextData.subsSessAmbr`, which the **SMF** supplies. So #293's
deferral ("the PCF learns of subscription changes from the UDR") points at a path that structurally
cannot carry that datum. The TS-conformant route is the SMF reporting `SE_AMBR_CH` on the
`/sm-policies/{id}/update` leg — both halves of which exist in-tree and neither of which is wired.

That contradicts a decision #293 recorded deliberately, so it is **not** silently overturned here:
filed as its own `decision` issue with the three options and a recommendation.

**What this PR therefore delivers** is the mechanism for what the UDR's policy data *does* carry:
the charging flags this PCF maps, reaching a live association instead of only a new one.

## Decision 2: selection by SUPI, evaluation per session scoped to its own S-NSSAI and DNN

The notification names only `ueId` and the changed resource. A UE can hold PDU sessions on several
slices, so re-authorising every session of that SUPI from an unscoped read would apply one slice's
policy data to another slice's session — which is exactly what #293's Decision 2 records for the
SMF's own re-read ("an unscoped lookup silently applies another slice's values").

So: `ueId` selects the candidate sessions, and each candidate is evaluated against a read scoped to
**its own** `(sst, sd, dnn)`. The guard asserts both halves: only the changed slice's session is
notified, and the UDR saw one query per slice carrying that slice's S-NSSAI.

## Decision 3: a session whose mapped data did not change is not notified

An `SmPolicyUpdateNotify` carrying an unchanged decision is a re-authorisation the SMF processes for
nothing, and at scale one UDR write would notify every session of every UE. So the re-read is
compared against what the session holds, and only a difference produces a notify.

This is what forced the create path to **store** the resource (below): without a stored baseline the
first notification for any session is always a "change".

## Decision 4: a failed read is not "nothing provisioned"

`pcf_udr_sm_policy_dnn_data` returns `Option`, collapsing a 404 with an unreachable UDR. The first
draft of the handler used it, and its own criterion-5 test caught the consequence: a transient UDR
failure erased the session's stored policy data and sent a re-authorisation carrying the local
default — a network blip silently reverting a subscriber's charging mode.

So #299 adds `pcf_udr_sm_policy_dnn_data_from(ep, …) -> Result<Option<_>, String>`, which
distinguishes them, and:

- **no UDR discoverable** → nothing is read, nothing is stored, nothing is notified (criterion 5);
- **discoverable but the read fails** → that session keeps the policy it was authorised with;
- **404** → genuinely nothing provisioned for that slice, which is a change only if something was.

It also takes an already-discovered endpoint, so a UE with several PDU sessions costs one NRF round
trip rather than one per session.

## The defect that made the mechanism observable

`build_sm_policy_notification` rebuilt `chgDecs` from `pcf_get_session_data` and applied **none** of
the UDR's charging flags, while the create path applied them inline and then **discarded** the
resource. Two consequences, both pre-existing and both fixed here because #299 is unimplementable
without it:

1. Every `Npcf_SMPolicyControl_UpdateNotify` — from an AF, from a re-authorisation, from anything —
   sent the SMF a decision with the charging mode reverted to the local default. A create said
   "online charging on", any later notify said "off", and nothing logged it.
2. A re-authorisation on a policy-data change would have been sent and changed nothing: the wired
   mechanism with no effect this backlog keeps finding.

The overlay now lives in one shared `apply_policy_dnn_charging`, used by both the create path and
the notify builder, and the resource is stored on the session (`PcfSess.policy_dnn_data`, held as
received JSON with `#[serde(default)]` for snapshot compatibility, like `access_type`).

## Acceptance criteria

- [x] pcfd serves a `Nudr_DM_Notification` sink for policy-data changes, and the subscribe is not
      sent before the sink exists — the sink is a router arm on `POLICY_DATA_NOTIFY_PATH`, the
      subscribe runs in `main` **after** `sbi_server.start()`, and
      `the_advertised_policy_data_callback_is_a_path_this_pcf_serves` feeds the advertised URI's own
      path back through the real router and refuses a 404/405. One constant serves both sides, so
      they cannot drift.
- [x] A policy-data change for a subscriber with a live SM policy association produces an
      `Npcf_SMPolicyControl_UpdateNotify` to the SMF, asserted over the wire from the notification
      handler — `a_policy_data_change_reauthorises_the_live_association_with_the_new_decision` drives
      the real router and captures the POST on a stub SMF, asserting the path
      (`{notificationUri}/update`), the `resourceUri`, and that the **changed** flag is in `chgDecs`.
- [x] The SMF applies it through the existing `handle_sm_policy_notify` path — unchanged on that
      side. **Seam stated**: the two daemons are not driven in one test process, so the assertion
      stops at the wire (the body the SMF receives). What is NOT claimed is a changed **AMBR**: see
      Decision 1.
- [x] The affected-association lookup is scoped deliberately, and a change for one slice does not
      re-authorise another slice's session —
      `a_change_for_one_slice_does_not_reauthorise_another_slices_session`, one SUPI with two PDU
      sessions on two slices.
- [x] With no UDR configured/discoverable, pcfd behaves exactly as it does today —
      `with_no_udr_a_policy_data_notification_changes_nothing`, which also asserts the stored data is
      not erased.

## Verification

`cargo test --workspace`: **6306 passed / 0 failed** over three consecutive runs (baseline 6300 on
`f5bf6ab`; pcfd 178 → 184). `cargo clippy --workspace --all-targets` introduces no new warning;
`cargo fmt --all -- --check` clean.

| revert | expected to break | result |
|---|---|---|
| the notify builder drops the UDR charging overlay | `a_policy_data_change_reauthorises_...` | **1 failed** |
| the create path no longer stores the UDR policy data | `the_create_stores_the_udrs_policy_data_...` | **1 failed** |
| the no-UDR case is not short-circuited | `a_change_for_one_slice_...` | **1 failed** |
| a failed read is treated as "nothing provisioned" | `a_failed_udr_read_leaves_the_association_...` | **1 failed** |
| the re-read is not scoped to the session's slice | `a_change_for_one_slice_...` | **1 failed** |
| unchanged data still re-authorises | `a_policy_data_change_...`, `the_create_stores_...` | **2 failed** |

Six reverts, six bites. One is worth reading precisely: the **no-UDR short-circuit** revert failed
the *slice* test rather than the no-UDR test, because with the short-circuit gone the reads fail and
Decision 4's error handling still protects the session. So the no-UDR *behaviour* is guarded by the
combination of that check and the error handling, not by either alone — stated rather than left to
look like one guard covering both.

### Two of my own tests were wrong before they were right

- The mock UDR asserted scoping by reading `req.header.uri`, and saw no query at all: the shared SBI
  server decodes query values into `http.params` and leaves the path in `header.uri`. A correctly
  scoped re-read looked unscoped, i.e. the harness lied in the shape of a product defect.
- `seed_sm_policy_session` called `ue_sm_add` per session, and that function **always inserts** a
  fresh UE-SM and overwrites `supi_sm_hash` — so the two-slice test orphaned the first session and
  `ue_sm_find_by_supi` saw only the second. It passed in the per-crate run and failed in the
  whole-workspace run, which is the shape a real flake takes. The helper now reuses an existing
  UE-SM, which is also what "one UE, two PDU sessions" means.

## Ceilings

- **Only `online`/`offline` are mapped from `SmPolicyDnnData`**, because they are the only members
  this PCF derives a decision from — unchanged by this issue, and the create path's comment already
  said so. `gbrUl`/`gbrDl`, `subscCats`, `allowedServices` and the usage-monitoring references are
  stored (the whole resource is held) but not mapped. A future issue that maps one gets the
  notification path for free.
- **The subscribed session-AMBR is not propagated** (Decision 1) — filed as a `decision` issue. This
  PR does not touch `PcfSess.subscribed_sess_ambr`, which remains written-and-never-read.
- **`monitoredResourceUris` is the whole per-UE collection**, not one entry per subscriber: the PCF
  cannot enumerate the UEs it will serve. So a UDR write for a UE this PCF holds no session for
  still costs a notification, answered 204 after one hash lookup.
- **The subscription is not renewed or repaired.** It is created once at startup and deleted at
  shutdown; a UDR that restarts and forgets it leaves this PCF subscribed to nothing until the PCF
  restarts. Detecting that needs either a validity time (TS 29.519 has none for this resource) or an
  NF-status subscription this daemon does not hold.
- **One subscription per PCF process**, so two PCFs behind the same NRF each get their own — correct,
  but the UDR then fans out to both and each re-reads. Not a defect; worth knowing before reading a
  UDR's notification counters.
- **No E2E.** The Docker jobs are `workflow_dispatch`-only, so every assertion here is a loopback
  stub NRF/UDR and stub SMF in one process; the notification path against real udrd is unexercised
  in CI, though udrd's half is unit-tested on its own side.
