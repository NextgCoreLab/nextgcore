# nextgcore #113: the TSCTSF's three-service control plane

Verified against `main` @ `2918eb7`.

**Closes #113**, with acceptance criterion 6 (the cross-NF actuation) split out as
**#284** at the issue author's own suggestion. Which criterion went where is
enumerated below so the close is auditable.

## The defect

Verified against `main` before starting, all five parts still held:

* The router matched exactly three routes: `POST /…/configuration`, and
  `GET`/`DELETE /…/configuration/{configId}`. ConfigUpdate, ConfigUpdateNotify and
  every capability operation were absent.
* `Ntsctsf_QoSandTSCAssistance` and `Ntsctsf_ASTI` had **no routes and no handlers**
  — TS 23.501 Table 7.2.26-1 mandates all three services.
* `TimeSyncConfig` held `{ id: String, raw: String }`: the configuration JSON
  verbatim, with no typed IEs and no validation beyond "is it an object" and an
  ad-hoc `timeDomain` range check.
* No PCF interaction, no PMIC/UMIC/TSCAI derivation, `upfd`'s `tsn_bridge` still
  `None` and never referenced.
* The NFProfile advertised one service.

## How #113 was scoped, and why

#113's own suggested approach opens: *"This is deliberately broad (five missing
operations plus two whole services plus PCF/UPF actuation) and is **best tracked as
an umbrella issue split into per-service child issues rather than delivered in one
change**"*, and separates the actuation explicitly: *"Actuation (PCF client, UPF
`tsn_bridge` driving, SMF port management) is cross-NF and behaviour-changing."*

So this PR delivers criteria **1, 2, 3, 4, 5, 7 and 8** — the whole control plane —
and criterion **6** (actuation) is **#284**. Three reasons, in order of weight:

1. **It cannot be verified end-to-end anywhere in this tree.** tsctsf, smfd and upfd
   are separate binaries; there is no PFCP TSC container codec; and criterion 6's own
   wording ("drives the UPF `tsn_bridge` from `None` to a populated bridge") describes
   a cross-process effect no in-process test can observe.
2. **Landing it off-by-default, as the issue suggests, would ship code no test
   exercises.** That is this repo's recorded "a correct implementation can be
   unreachable" hazard, and the switch being off is exactly what would hide it.
3. **The author asked for the split.**

Criterion 7 ("with the actuation feature disabled, UPF/SMF behaviour is unchanged")
is satisfied trivially and completely: no UPF or SMF code is touched at all.

**Count arithmetic, stated because it goes the wrong way:** closing #113 while filing
#284 leaves the open count unchanged. That is the same understatement this project's
issues-closed-vs-parts-closed learning warns about, so both numbers are quoted rather
than just the close.

## The change

### Typed IEs (criterion 5)

`context.rs` gains `TimeSyncExposureConfig`, `CapsSubscription`, `AstiConfig`,
`QosTscSession` and `QosTscSubscription`, each with a `validate()` returning a
per-member error.

Required scalars are bare `String` with `serde(default)` rather than
`Option<String>`, and presence is enforced in `validate()`. This is the pattern
recorded in this project's learnings: a bare non-`Option` makes an **absent** member a
serde parse error, which a handler can only report as `INVALID_MSG_FORMAT` — losing
the TS 29.500 §5.2.7.2 distinction between "your JSON is malformed" and "your JSON is
incomplete", which is two different fixes on the consumer's side.

Present-but-**empty** is refused alongside absent, because serde accepts `""` for a
`String` and an empty `notificationTargetAddr` is exactly the un-notifiable state the
validation exists to prevent — accepting it reproduces the defect through a different
door.

`timeDomain` is modelled `u16` even though IEEE 802.1AS `domainNumber` is one octet,
so a value of 256 arrives as a **range** error naming the member rather than as a
serde type error that names nothing.

The either/or required inputs are checked **as alternatives**, not conjunctions:
§5.2.27.2.6's scope is *"(DNN, S-NSSAI) or an AF-Service-Identifier"*, and
§5.2.27.3.2's are *"flow description(s) or External Application Identifier"* and
*"QoS Reference or individual QoS parameters"*. Requiring both halves would refuse
conformant requests, which is the mirror of accepting one that names nothing — the
tests cover both directions.

Also changed: a malformed JSON body's cause moved from the bespoke `INVALID_JSON` to
`INVALID_MSG_FORMAT`. The old value was this NF's own invention rather than a name a
conformant consumer knows. The pre-existing test that pinned it is updated with the
reason at the site.

### ConfigUpdate, and why two verbs (criteria 1, 2)

`PATCH` merges; `PUT` replaces. §5.2.27.2.3's only required input is the PTP instance
reference and every parameter is optional, which **is** merge semantics — a body
carrying only `gmEnable` means "change the grandmaster flag", not "clear everything
else". `PUT` exists for a consumer that wants to state the whole configuration. If the
two behaved the same, offering both would be a lie, so a test asserts they differ.

A merge that would leave the configuration invalid is refused: an update blanking the
notification target would produce a configuration that can never notify again.

SUPI `supisToAdd` and `supisToRemove` apply **in that order**, so a SUPI in both is
removed — a consumer asking for both cannot have meant "keep". Adding one already
present does not duplicate it.

`ConfigUpdateNotify` fires on a change and **not on a create**: a create is not a
change, and the notification target has just been told the configuration exists by the
`201`.

Unmodelled optional members survive a round trip: the record keeps both the typed IEs
and the body as received, and a response overlays the typed members on the original. A
parameter this build does not model is returned rather than silently dropped.

### Capability subscriptions (criterion 3)

`CapsSubscribe` / `CapsUnsubscribe`, with the Subscription Correlation ID **minted by
the server**. A consumer-supplied id would let one AF address another's subscription
resource; a test asserts an attacker-chosen id is not honoured.

`CapsNotify` fans out to every subscriber. Its trigger is the honest problem: a 5GS
capability change has **no in-tree source**, so the notify path would be unreachable
in principle — this repo's "grep the SINK before implementing an emit-side feature"
hazard, in reverse. So there is an administrative route,
`POST /…/v1/admin/capability-change`, explicitly labelled as **not** a 3GPP service
operation, which is the producer. It answers `200 {"notified": N}` rather than 204 so
an operator can tell "notified nobody because nobody subscribed" from "notified nobody
because the fan-out is broken" — two states a 204 conflates. #284 owns replacing it.

### The two missing services (criterion 4)

`Ntsctsf_ASTI` and `Ntsctsf_QoSandTSCAssistance`, each with create/read/update/delete
and their notification, plus Subscribe/Unsubscribe for the latter. An unscoped
QoS/TSC subscription (no `transactionRefId`) is notified for every transaction,
because a subscriber that named none asked for everything — refusing would make an
unfiltered subscription the one shape that never fires.

The NFProfile now advertises all three service names. The profile and the router are
changed together: advertising one while serving three makes the other two
undiscoverable, and advertising services that are not served would be worse.

### Notification delivery

Best-effort, and never propagated to the consumer whose request triggered it: letting
an unreachable AF fail the operation that changed the configuration is a worse outcome
than a missed notification. A target with no usable host is **refused rather than
guessed at**, because notifying the wrong node is worse than not notifying — `http://`
defaults to port 80 and `https://` to 443, and a bare authority is accepted with the
root path.

## Verification

**20 guards revert-verified**: fix broken, **named** test watched to fail, file
restored.

| Area | Reverts that bit |
|---|---|
| ConfigUpdate | route removed (→405); update replaces instead of merging; PUT merges instead of replacing |
| validation | create skips `validate`; required-IE checks blinded; range check blinded; either/or turned into a conjunction |
| notifications | ConfigUpdateNotify not fired; CapsNotify does not fan out; QoS/TSC Notify not fired; unusable target guessed at |
| subscriptions | unsubscribe does not remove; subscription id taken from the request |
| new services | ASTI routes removed (→404); QoS/TSC routes removed (→404); ASTI target check blinded |
| profile | advertises fewer than three services |
| SUPI lists | add/remove order swapped; duplicate add allowed |

Two of those reverts needed a second attempt because my first mutation did not
actually change behaviour (it left the original block in place alongside the mutant),
which is the harness being wrong rather than the guard being weak — recorded because a
"DID NOT BITE" that turns out to be a bad mutation is easy to mistake for a real gap.

### Pre-existing tests that had to change

* **`config_create_get_delete_flow` and `config_create_at_capacity_returns_507`**
  posted bodies with no required IEs, because before #113 there were none. Their
  `create_request` helper now merges the required members in unless the caller states
  one, so they keep testing what they were written to test (the flow, the cap) rather
  than becoming validation tests.
* **`config_create_validation_400s`** pinned the bespoke `INVALID_JSON` cause; updated
  to `INVALID_MSG_FORMAT` with the reason at the site.
* **`block_on`** used a bare current-thread runtime with the comment "the handlers
  under test do no real I/O". That stopped being true: ConfigUpdate fires a
  notification whose client sets a request timeout, and a runtime without timers
  panics on it. Now `enable_all`, with the reason recorded — a test registering an
  unreachable target still exercises the send.

Workspace: **6207 passed / 0 failed**, `cargo clippy --workspace` and
`cargo fmt --all --check` clean.

## Ceilings

* **A stored configuration still actuates nothing.** No PCF client, no PMIC/UMIC/TSCAI
  derivation, `tsn_bridge` untouched. This is #284, and it is stated at the top of the
  new docs page as well as in the module docs, because an operator discovering
  `nfType: TSCTSF` will otherwise assume a working time-synchronisation function.
* **`TS29565_Ntsctsf_*.yaml` is not vendored in this tree.** Every resource path and
  JSON member name is derived from the Stage-2 parameter names in TS 23.502 §5.2.27,
  **not** verified against the Stage-3 schema. That is called out in the module docs,
  the type docs and the docs page rather than left to be assumed checked. #113's own
  gap list called the previous surface "bespoke" for this reason; this one is
  spec-shaped but still not schema-verified.
* **`CapsNotify` has no in-tree producer of a real trigger** — the administrative route
  is the producer, and it is labelled as such.
* **All state is in-memory.** No state file, so every configuration and subscription is
  lost on restart. Not in #113's scope; worth knowing next to #191/#192's durable
  stores for other NFs.
* **No wire interop.** Notifications are asserted against a fake AF spawned by this
  crate's own SBI server. The `set_sbi_profile_override(Dev)` those tests need is
  declared with its reason, because the default profile is Production and would refuse
  a loopback plaintext peer.
* **GitNexus impact analysis unrunnable** (56th consecutive PR): the MCP server is not
  connected. Blast radius by grep — `TimeSyncConfig::new` changed signature and its
  only callers are the create handler and this crate's tests; nothing outside
  `nextgcore-tsctsf` references any of these types.
