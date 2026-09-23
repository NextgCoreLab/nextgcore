# Serve the PWS non-UE N2 information subscription and notify a CBCF what each NG-RAN actually answered

**Issue:** nextgcore #399 (author-marked split out of #396 by PR #401, merged)
**Verified against:** nextgcore `main` @ `0dc01e4`
**Spec basis:** TS 29.518 §5.2.2.4.2 (NonUeN2InfoSubscribe) + §5.2.2.4.2.2 (for N2
PWS Information), §5.2.2.4.3 (NonUeN2InfoUnSubscribe), §5.2.2.4.4 +
§5.2.2.4.4.1/.3 (NonUeN2InfoNotify and its use for PWS related events),
§5.2.2.4.1.3 (the Warning Request Transfer Procedure, for the `n2PwsSubMissInd`
and `unknownTaiList` halves), §6.1.3.9 / §6.1.3.10 (the two resources),
§6.1.6.2.10 / §6.1.6.2.11 (the create/created bodies), §6.1.6.2.46
(`PWSResponseData`), §6.1.6.4.3.3 (which NGAP message each PWS N2 information
class carries). TS 38.413 §9.2.8.2 / §9.2.8.4 / §9.2.8.5 / §9.2.8.6 (the four
RAN-originated PWS messages and their IEs).
Spec text read at `6g_docs/specs/29518-k00.txt`, `6g_docs/specs/38413-j30.txt`,
`6g_docs/specs/TS29518_Namf_Communication.yaml` and
`6g_docs/specs/TS29571_CommonData.yaml`. Every clause quoted below was read
there, with file:line.
**Precedent:** `handle_uplink_non_ue_associated_nrppa_transport`
(`ngap_path.rs:6093`) is the in-tree shape for "a gNB-initiated non-UE N2
procedure resolves its consumer from a subscription registry and relays the PDU
verbatim as an N2InfoNotify"; `send_n2_info_notify` /
`build_n2_info_notify_request` (`namf_server.rs:1840`, `:1879`) are the
fire-and-forget callback producers it uses. `handle_n1n2_subscription_create`
(`namf_server.rs:2468`) is the fail-closed half-pair validation this reuses.

## Read this first: the resource in criterion 1 does not exist, and criterion 5's mechanism cannot work

#399's factual claims about the tree all hold. Two of its six criteria name a
mechanism that the spec or the code contradicts, and both are load-bearing —
implementing either literally would ship a resource no conformant CBCF would
ever call, and a field that can only ever be empty.

### Criterion-by-criterion, re-located at `0dc01e4`

| # | criterion | cite in the issue | site at `0dc01e4` | verdict |
|---|---|---|---|---|
| 1 | `POST`/`DELETE /namf-comm/v1/non-ue-n2-info-subscriptions[/{subscriptionId}]` routed, stored keyed by `n2InformationClass`, fail-closed | "`grep -rn "non-ue-n2-info-subscriptions" src/` returns **zero**" | grep confirmed: the only three hits are prose in `namf_server.rs` comments (`:4378`, `:4585`, `:8744`). **But the URI is wrong** — see below | **real — implemented at the spec's URI, `non-ue-n2-messages/subscriptions`** |
| 2 | NGAP receive path dispatches 51/32 successful outcomes and 33/34 initiating messages; they currently hit the `_` fallthrough and earn an Error Indication | `ngap_path.rs`'s `process_ngap_message` has no arms | confirmed. `process_ngap_message` (`:889-1205`) has arms for 21/15/46/14/29/26/28/41/20/22/23/9/12/13/25/10/11/50/47/35/49/27/30/68/71/72/73/74/19/44/48/52 and **none** for 51/32/33/34; the `_` arm at `:1183` answers `ErrorIndication(AbstractSyntaxErrorReject)` | **real — implemented** |
| 3 | a matched PWS subscription receives an `n2InfoNotify` carrying the decoded area list; no subscription → no notification | — | no producer existed | **real — implemented, forwarding the RAN's own bytes rather than a re-encode** |
| 4 | `n2PwsSubMissInd` returned `true` **only** when `sendRanResponse: true` and no subscription exists | `namf_server.rs:4606-4608` sets it on `sendRanResponse` alone | confirmed unconditional-on-`sendRanResponse` | **real — implemented, now conditional on both** |
| 5 | `unknownTaiList` populated from the `taiList` entries that matched no served NG-RAN node; "`pws_target_associations` already computes the match; it discards the misses" | `ngap_path.rs::pws_target_associations` | the premise about the resolver is **true** (`:5820-5869` filters and discards). But the *destination* makes it unreachable, and the spec scopes the IE narrower than the issue does | **void as stated — the honest, synchronously-knowable form is implemented instead** |
| 6 | a test asserts the notification body against a gNB-produced response PDU, via `build_write_replace_warning_response` | — | `build_write_replace_warning_response` exists (`builder.rs:1599`) | **real — implemented** |

### Wrong premise 1: there is no `non-ue-n2-info-subscriptions` resource

`grep -n "non-ue-n2" TS29518_Namf_Communication.yaml` returns exactly three
paths: `/non-ue-n2-messages/transfer` (`:1718`),
`/non-ue-n2-messages/subscriptions` (`:1921`) and
`/non-ue-n2-messages/subscriptions/{n2NotifySubscriptionId}` (`:2123`). The
normative prose agrees twice over:

> Resource URI:
> `{apiRoot}/namf-comm/<apiVersion>/non-ue-n2-messages/subscriptions`

— §6.1.3.9.2, `29518-k00.txt:9962-9963`, and the Document form at §6.1.3.10.2
(`:10111-10112`). The 201's `Location` header description spells the same
structure out a third time (`yaml:1945`).

`non-ue-n2-info-subscriptions` appears **nowhere** in the vendored spec text or
the OpenAPI — it is an invention of the issue body (and of #401's ceiling
comments, which named the same non-existent path). Serving it would have created
an endpoint no conformant CBCF ever POSTs to, i.e. the "correct but unreachable"
defect from the far side: reachable by nothing.

The subscriptions collection is a **sibling of the transfer resource under
`non-ue-n2-messages`**, not a top-level collection. That also means it cannot
reuse the existing router arm, which pins `parts.len() == 4 && parts[3] ==
"transfer"` (`namf_server.rs:148-155`); it needs its own arm, and the arm order
matters because both start `namf-comm`/`non-ue-n2-messages`.

### Wrong premise 2: `unknownTaiList` cannot be fed by the resolver's discarded misses

Three independent reasons, each sufficient:

**(a) It is not in the notification at all.** `unknownTaiList` is a member of
`PWSResponseData` (`yaml:3786-3791`), and `PWSResponseData` has exactly one
referent in the whole OpenAPI: `N2InformationTransferRspData.pwsRspData`
(`yaml:3348-3349`) — the **synchronous 200 body** of the transfer. It is absent
from `N2InformationNotification` (`yaml:2637-2679`), whose members are
`n2NotifySubscriptionId`, `n2InfoContainer`, `toReleaseSessionList`,
`lcsCorrelationId`, `notifyReason`, `smfChangeInfoList`, `ranNodeId`,
`initialAmfName`, `anN2IPv4Addr`, `anN2IPv6Addr`, `guami`, `notifySourceNgRan`,
`notifCorrelationId` and `toReleaseSessionInfo`. So this criterion is not part of
the asynchronous surface the rest of #399 is about — it belongs to the response
#401 already ships.

**(b) The 200 is written before the misses are known.** The resolver the issue
points at runs in the NGAP task's pump (`process_pws_n2_transfers`, `:5754`,
which is the sole non-test caller of `pws_target_associations`). The SBI handler
`handle_non_ue_n2_message_transfer` enqueues and returns; the 200 is on the wire
long before the pump iterates. Feeding the pump's per-node misses back into that
response would mean blocking the HTTP response on SCTP progress — which is
exactly what #401 established is wrong rather than merely hard, and what
§5.2.2.4.1.3 step 2a's echo semantics exist to avoid.

**(c) The spec scopes the IE to the PWS Cancel direction only.** §5.2.2.4.1.3
step 2a (`29518-k00.txt:4169-4173`):

> the POST response body shall contain the mandatory elements from the
> Write-Replace-Warning Confirm response (see clause 9.2.17 in TS 23.041 [20])
> **or** the mandatory elements **and optionally the unknown TAI List IE from the
> Stop-Warning Confirm response** (see clause 9.2.19 in TS 23.041 [20]).

The unknown-TAI option hangs off the *Stop-Warning* Confirm branch — the PWS
Cancel (procedure 32) direction — and not off the Write-Replace-Warning Confirm
branch. The issue treats it as unconditional. Corroborating this from the other
side: `grep -n -i "unknown Tracking Area\|unknownTAI" 38413-j30.txt` returns
**zero**. There is no Unknown TAI List IE anywhere in TS 38.413, so no NG-RAN
node ever sends one; it is a CBC-facing concept from TS 23.041, which is why the
AMF — not the RAN — is the thing that has to know it.

**What is implemented instead.** The intent behind the criterion is honestly
serviceable, synchronously, and without inventing anything: the AMF genuinely
does know at handler time which `taiList` entries name tracking areas **it does
not serve at all**, from the config-loaded `served_tai` via
`AmfContext::find_served_tai` (`context.rs:2196`). Unlike `gnb_list`, that
collection has a real production writer — `lib.rs:520` populates it from the
`amf.tai` config section at startup. A TAI the AMF does not serve can never match
a served node, so it is an unknown TAI under any reading, and it is knowable
before the response is written. That is what `unknownTaiList` now carries, only
on the PWS Cancel branch, with the reason recorded at the site.

The per-node misses the pump discards are not lost either: `process_pws_n2_transfers`
already WARNs when a relay matched no connected node (`:5771-5780`), which is the
operator-visible surface for "targeted, but nothing was there".

## The two findings from PR #401, verified and honoured

**1. The AMF is a relay, not a composer — applied in the notification direction.**
Re-verified: `N2InfoContent` is *"Represents a transparent N2 information content
to be relayed by AMF"* (`yaml:3250-3251`), and §5.2.2.4.1.3 says "forward" three
times (`29518-k00.txt:4152`, `:4155`, `:4158`).

§6.1.6.4.3.3 permits the AMF to aggregate and re-encode on the way back
(`29518-k00.txt:19069-19077`: the AMF *"may* aggregate the Broadcast Completed
Area Lists ... and transfer the ASN.1 (re-)encoded Message Type, Message
Identifier, Serial Number and the (aggregated) Broadcast Completed Area List
IE"). **Permission, not obligation** — and taking it would require exactly the
decode/re-encode round trip through a partial model that #401 refused in the
forward direction, dropping any IE the gNB sent that this build does not model
(including whatever the `...` extension markers admit). So the notification
carries the **gNB's own PDU bytes, verbatim**, as the
`pwsInfo.pwsContainer.ngapData` multipart part. The AMF decodes only to validate,
to lift `messageIdentifier`/`serialNumber` into `pwsInfo`, and to decide whether
an area list was present at all. §5.2.2.4.4.1 (`:4416`) and §5.2.2.4.4.3
(`:4478`) both provide for "one (or more) NonUEN2InfoNotify request(s)", so one
notify per responding RAN node is conformant; the no-aggregation choice is stated
at the site rather than left implicit.

The one field the AMF must compose is `bcEmptyAreaList`, and it is composed
because the spec orders it in the imperative, not the permissive
(§5.2.2.4.4.3, `:4468-4471`): *"If the NG-RAN node(s) have responded without the
Broadcast Completed Area List IE then the AMF **shall** include the NG-RAN node
ID(s) in "bcEmptyAreaList" attribute in the request body."* Both inputs are
honestly held: whether the list was present comes from the decode, and which node
answered comes from the SCTP association.

**2. `gnb_list` has zero production writers — so nothing here touches it.**
Re-verified independently at `0dc01e4`: `grep -rn "gnb_add\|gnb_publish"
bins/nextgcore-amfd/src/ | grep -v context.rs` returns **nothing**, and inside
`context.rs` every `gnb_add` call site (`:4117`, `:4133`, `:4146`, `:4163`,
`:4181`, `:4200`, `:4221`, `:4586`, `:4686`) is inside `mod tests` (which opens
at `:4100`-ish, well before all of them). The only production readers left are
`gnb_count`-shaped and even those are association-derived
(`ngap_path.rs:8601`).

Every per-RAN fact this change needs is therefore taken from the NGAP task's live
`sessions` map — `self.sessions` keyed by `association_id`, the same map
`pws_target_associations` resolves against — or from the received PDU itself.
Concretely:

- WRITE-REPLACE WARNING RESPONSE and PWS CANCEL RESPONSE do **not** carry a
  Global RAN Node ID: their IE tables (`38413-j30.txt:15916-15939` and
  `:15968-15993`) are Message Type / Message Identifier / Serial Number /
  the area list / Criticality Diagnostics, full stop. So the responding node's
  identity can *only* come from the association. It is read from
  `session.gnb`.
- PWS RESTART INDICATION and PWS FAILURE INDICATION **do** carry Global RAN Node
  ID as a mandatory IE (`:16031-16034` and the §9.2.8.6 table at `:16064`). For
  those the PDU's own value wins over the association-derived one: it is what the
  node said about itself.

### One dependency this exposed: `AmfGnb` dropped the gNB ID bit length

`GNbId` requires **both** `bitLength` and `gNBValue` (`TS29571_CommonData.yaml:2911-2913`),
so rendering a conformant `ranNodeId` for a response needs the bit length.
`parse_ng_setup_request_asn1` decodes it (`ngap_asn1.rs:257-261` →
`NgSetupRequest.gnb_id_len`, `ngap_handler.rs:120`), but
`ngap_handler::handle_ng_setup_request` copied only `gnb_id`, `gnb_id_presence`
and `plmn_id` (`:349-351`) — the length was parsed and thrown away, so `AmfGnb`
had no field for it.

`AmfGnb.gnb_id_len` is added and populated from the NG SETUP REQUEST. This is not
scope creep: the alternative is fabricating a bit length (22 or 32) for every
notification, which would misidentify a node whose real ID is neither. The
default is 32 only for a node that never completed NG Setup, which cannot be a
notification source anyway.

## Which N2 information class carries which message

§6.1.6.4.3.3 assigns the four RAN-originated messages to two classes, and
§5.2.2.4.2.2 (`29518-k00.txt:4334-4336`) names the three a PWS consumer may
subscribe to: *"to subscribe for notifications of N2 PWS information classes
("PWS", "PWS-BCAL" or "PWS-RF")"*. All three are in `N2InformationClass`'s enum
(`yaml:4487-4499`).

| received NGAP message | proc code | class per §6.1.6.4.3.3 | table / line |
|---|---|---|---|
| WRITE-REPLACE WARNING RESPONSE | 51 | `PWS-BCAL` | Table 6.1.6.4.3.3-2, `29518-k00.txt:19055-19062` |
| PWS CANCEL RESPONSE | 32 | `PWS-BCAL` | Table 6.1.6.4.3.3-2, `:19055-19062` |
| PWS RESTART INDICATION | 34 | `PWS-RF` | Table 6.1.6.4.3.3-3, `:19108-19118` |
| PWS FAILURE INDICATION | 33 | `PWS-RF` | Table 6.1.6.4.3.3-3, `:19108-19118` |

The lookup therefore tries the **specific** class first and falls back to the
umbrella `PWS`. The fallback is not a loosening: §5.2.2.4.1.3's own
`n2PwsSubMissInd` condition is phrased against *"the corresponding N2 information
subscription for PWS information"* (`:4176-4177`) without narrowing to a
sub-class, and §5.2.2.4.2.2 offers all three as alternatives for the same
purpose. A CBCF that subscribed `PWS` asked for PWS events and gets them. What is
*not* done is treating a `PWS-RF` subscription as covering a response, or
vice versa — those are disjoint (`PWS-RF` ⊅ `PWS-BCAL`), and crossing them would
notify a consumer about a message class it did not ask for.

Exact-class, fail-closed, most-recent-wins, in the shape
`n1n2_subscription_find_n2` already uses (`context.rs:2088`).

## `sendRanResponse` gates a response notification; an indication is unconditional

§5.2.2.4.4.3 splits its two events on exactly this (`29518-k00.txt:4455-4489`):

> 1) The AMF has received a Write-Replace-Warning-Response or a
> PWS-Cancel-Response from the NG-RAN over N2. ... **If the Send-Write-Replace-Warning
> Indication IE was present** in the Write-Replace-Warning Request message, then
> the AMF **may** forward the Broadcast Completed Area List IE(s) to the NF
> Service Consumer.
>
> 2) The AMF has received a Restart Indication or a Failure Indication from a
> NG-RAN Node. The AMF **shall** forward the Restart Indication or Failure
> Indication to the NF Service Consumer.

So a **response** notification is conditioned on the originating request having
asked for it, which on the SBI side is `pwsInfo.sendRanResponse: true`
(`yaml:3290-3292`; the IE's table row at `:14712` reads *"This IE shall be
present to request the AMF to send the N2 response information it has received
from the RAN nodes to the NF Service Consumer"*). An **indication** is
unconditional — gated only on a subscription existing, because there is otherwise
nowhere to send it.

That requires remembering, per warning, that a response was asked for. A small
process-global map keyed by `(messageIdentifier, serialNumber)` — the pair
§6.1.6.4.3.3 itself names as the identity of a warning (*"for a message
identified by its Serial Number and Message Identifier"*, `:19073`) — records the
request and the requesting `nfId`. Fail-closed: no record means no notification,
so the AMF never invents a consumer for a warning nobody asked to be told about.
The record also carries `pwsInfo.nfId`, which §6.1.6.2.10's `nfId` row
(`:11876-11886`) and §5.2.2.4.2.2 item 1 both describe as the way the AMF
*"identif[ies] whether the same CBCF/PWS-IWF instance has subscribed"* — so when
the transfer named an `nfId`, only that instance's subscription matches.

This is also what makes criterion 4 implementable: `n2PwsSubMissInd` now requires
`sendRanResponse: true` **and** no matching subscription, which is precisely
§5.2.2.4.1.3's condition (`:4175-4181`).

## Procedure codes and IEs, pinned

Procedure codes re-verified against `6g_docs/specs/38413-j30.txt` (all four
already in `nextgcore-asn1c`, and #401's test pins them):

| name | value | line |
|---|---|---|
| `id-PWSCancel ProcedureCode ::= 32` | 32 | `:59077` |
| `id-PWSFailureIndication ProcedureCode ::= 33` | 33 | `:59079` |
| `id-PWSRestartIndication ProcedureCode ::= 34` | 34 | `:59081` |
| `id-WriteReplaceWarning ProcedureCode ::= 51` | 51 | `:59115` |

The ordering trap #401 documented is live here in a new way: the dispatch arms
are keyed on `data[0]` as well as the code, and the two pairs differ.
51 and 32 arrive as **SuccessfulOutcome** (`data[0] == 0x20`) because
WriteReplaceWarning and PWSCancel are AMF-initiated class-1 procedures; 33 and 34
arrive as **InitiatingMessage** (`data[0] == 0x00`) because the indications are
NG-RAN-initiated class-2. Getting that backwards would make each pair fall
through to the `_` arm and keep earning the Error Indication this change exists to
stop. A test asserts byte 0 and byte 1 on all four fixtures.

IE presence, from the four IE tables (used to decide what may be absent):

- WRITE-REPLACE WARNING RESPONSE (§9.2.8.2, `:15916`): Message Identifier **M**,
  Serial Number **M**, Broadcast Completed Area List **O**, Criticality
  Diagnostics **O**. No Global RAN Node ID.
- PWS CANCEL RESPONSE (§9.2.8.4, `:15968`): Message Identifier **M**, Serial
  Number **M**, Broadcast Cancelled Area List **O**, Criticality Diagnostics
  **O**. No Global RAN Node ID.
- PWS RESTART INDICATION (§9.2.8.5, `:15995`): CHOICE Cell List for Restart
  **M**, Global RAN Node ID **M**, TAI List for Restart (`1..maxnoofTAIforRestart`),
  Emergency Area ID List for Restart (`0..maxnoofEAIforRestart`).
- PWS FAILURE INDICATION (§9.2.8.6, `:16064`): CHOICE PWS Failed Cell List **M**,
  Global RAN Node ID **M**.

The two area lists being **optional** is the whole reason `bcEmptyAreaList`
exists, and is the branch the tests exercise in both directions.

## What is built

**`context.rs`**

- `NonUeN2InfoSubscription`: `subscription_id`, `n2_information_class`,
  `n2_notify_callback_uri`, `nf_id`, `notif_correlation_id`,
  `global_ran_node_gnb_ids`, `an_type_list`, `supported_features` — the members of
  `NonUeN2InfoSubscriptionCreateData` (`yaml:2570-2596`).
- `non_ue_n2_subscriptions: RwLock<HashMap<String, NonUeN2InfoSubscription>>`,
  keyed by the AMF-minted subscription id (the Document resource's
  `{n2NotifySubscriptionId}`), with `non_ue_n2_subscription_add` / `_remove` /
  `_find` / `_find_by_class` / `_count`. `_find_by_class` takes the specific class
  and an optional `nf_id`, tries the specific class then `PWS`, and is
  fail-closed.
- `pws_response_requests: RwLock<HashMap<(u16, u16), PwsResponseRequest>>` — the
  `sendRanResponse` record described above, with `pws_response_request_set` /
  `_get`. Bounded by replacement on the same (mid, sn) pair, which is what
  "replace" means for a warning.
- `AmfGnb.gnb_id_len`.

**`ngap_handler.rs`** — `handle_ng_setup_request` stores `gnb_id_len`.

**`namf_server.rs`**

- Router arms for `POST /namf-comm/v1/non-ue-n2-messages/subscriptions` and
  `DELETE .../subscriptions/{n2NotifySubscriptionId}`, placed **before** the
  existing `transfer` arm's sibling so neither shadows the other (both are
  `parts[2] == "non-ue-n2-messages"`; they are disjoint on `parts[3]`, and the
  ordering is asserted by a test that the transfer arm still answers 200).
- `handle_non_ue_n2_info_subscribe`: validates `n2InformationClass` and
  `n2NotifyCallbackUri` (both **M**, `yaml:2594-2596`), rejects a non-HTTP
  callback URI, restricts the served classes to the three PWS ones and says so
  in the 403 body rather than accepting a class nothing can notify, removes a
  duplicate subscription from the same `nfId` for the same class as
  §5.2.2.4.2.2 item 2 permits (`:4351-4356`), and returns 201 +
  `Location: /namf-comm/v1/non-ue-n2-messages/subscriptions/{id}` +
  `NonUeN2InfoSubscriptionCreatedData`.
- `handle_non_ue_n2_info_unsubscribe`: 204, or 404 `SUBSCRIPTION_NOT_FOUND` —
  the cause §6.1.3.10.3.1's table names for a missing subscription
  (`:10170-10175`).
- `n2PwsSubMissInd` made conditional; the `sendRanResponse` record written;
  `unknownTaiList` computed for the PWS Cancel branch.
- `build_non_ue_n2_info_notify_request` + `send_non_ue_n2_info_notify`: the
  `N2InformationNotification` with `n2InfoContainer.n2InformationClass`,
  `pwsInfo` (`messageIdentifier`, `serialNumber`, `pwsContainer` referencing the
  binary part, `bcEmptyAreaList` when the area list was absent, `nfId` when
  known), `ranNodeId`, and `notifCorrelationId` when the subscription carried
  one. Separate from `build_n2_info_notify_request` rather than generalising it:
  that one hardcodes the NRPPa container shape, and widening it would put an
  `Option` on every NRPPa call site for no gain.

**`ngap_path.rs`**

- Dispatch arms: `Some(51) | Some(32)` on `data[0] == 0x20` →
  `handle_pws_response`; `Some(34) | Some(33)` on `data[0] == 0x00` →
  `handle_pws_indication`. The wrong-direction case of each logs rather than
  answering, matching how the neighbouring arms treat an unexpected outcome.
- `handle_pws_response`: decodes, looks up the `sendRanResponse` record by
  (mid, sn), looks up a `PWS-BCAL`-or-`PWS` subscription for that `nfId`, renders
  the responding node's `ranNodeId` from `session.gnb`, and sends the notify with
  the received bytes verbatim. Every drop reason is a distinct WARN/DEBUG, because
  "nothing happened" is the failure mode that hides here.
- `handle_pws_indication`: decodes, looks up a `PWS-RF`-or-`PWS` subscription
  (no `nfId` filter and no `sendRanResponse` gate — §5.2.2.4.4.3 item 2 is a
  "shall" with no request to correlate to), and renders `ranNodeId` from the
  PDU's own mandatory Global RAN Node ID.

## Ceilings, stated at their sites

1. **No cross-node aggregation.** One `n2InfoNotify` per responding NG-RAN node,
   not one aggregate per warning. §6.1.6.4.3.3's aggregation is a "may" and
   §5.2.2.4.4.1/§5.2.2.4.4.3 both provide for "one (or more)" notifications;
   aggregating would force the decode/re-encode #401 established is lossy.
   Recorded in `handle_pws_response`.
2. **`unknownTaiList` is "TAIs this AMF does not serve", not "TAIs no connected
   node served".** The narrower fact is not knowable when the 200 is written; the
   wider one is, and is genuinely an unknown TAI. Recorded at the computation
   site with the three reasons above in short form.
3. **No `omcId` trace records.** `PwsInformation.omcId` (`yaml:3294`) asks the AMF
   to write the RAN's N2 information into trace records on an OMC
   (`:14735-14742`). This deployment has no OMC and no trace-record writer;
   `grep -rn "omcId\|OmcIdentifier" src/` finds no consumer. Accepting the IE and
   silently not tracing would be the quieter lie, so the handler logs at WARN
   that the IE was received and not honoured, and nothing pretends otherwise.
4. **The delivered notification is asserted in-process, not over a socket.**
   `send_non_ue_n2_info_notify` is fire-and-forget on a spawned task like every
   other notify producer in this file, so the tests drive
   `build_non_ue_n2_info_notify_request` — the real body builder the producer
   calls — and separately prove the NGAP arms reach the producer. Wire-level
   delivery to a real CBCF is the matched-sim E2E's job and there is no CBCF in
   this deployment to be that peer (`grep -rn "CBCF\|cbcf\|PWS-IWF" src/` is
   still zero outside comments, as #401 found).

## Reachability, proved not assumed

The defect this tree produces most is a correct-but-unreachable path. Each new
producer is tied to a live receive path:

- The subscription store's **reader** is `handle_pws_response` /
  `handle_pws_indication`, reached from `process_ngap_message`, which is the real
  SCTP dispatch — not a test-only entry point. A test drives
  `process_ngap_message` itself with gNB-built PDUs and asserts the arm was taken.
- The subscription store's **writer** is the new router arm, reached from
  `namf_request_handler`. A test POSTs through the router.
- The `sendRanResponse` record's writer is `handle_non_ue_n2_message_transfer`
  (the live SBI arm #401 landed) and its reader is `handle_pws_response`.
- `AmfGnb.gnb_id_len`'s writer is `handle_ng_setup_request`, called from
  `ngap_path.rs:1325` on the real NG Setup path.

## Tests

In `nextgcore-amfd`, all taking `crate::test_support::CONTEXT_GUARD`, with
distinct literal `(messageIdentifier, serialNumber)` pairs per test because the
subscription store and the `sendRanResponse` map are process-global. Tests that
touch the PWS queue also take the existing module-level `pws_queue_test_lock()`
(`namf_server.rs:4697`) — no new lock is declared inside any `mod tests`.

**16 tests, 6833 → 6849.** Six in `namf_server` (the SBI surface), six in
`ngap_path` (the receive path), plus the four body/rendering ones.

The two `ngap_path` notification tests stand up a real `SbiServer` sink on the
subscription's `n2NotifyCallbackUri`, so the assertions are on the notification as
**delivered over HTTP** rather than on the builder's return value — the producer
is fire-and-forget on a spawned task, and a test that only called the builder
could not tell a wired-up dispatch from a dead one.

*`namf_server`:*

1. `non_ue_n2_info_subscribe_is_routed_at_the_spec_uri_and_returns_a_location` —
   201, `n2NotifySubscriptionId`, `Location` matching the
   `non-ue-n2-messages/subscriptions/{id}` structure, the record findable both by
   id and by the notify path's own class lookup, and a DELETE round-trip at the
   advertised Location. Plus: the issue's `non-ue-n2-info-subscriptions` URI is
   **404**, positively asserted, so the invented path can never quietly start
   working.
2. `non_ue_n2_info_subscribe_rejects_half_pairs_and_unservable_classes` — each
   mandatory member, a non-HTTP callback, and four non-PWS classes refused
   (asserted per-class rather than by count, because the store is process-global);
   all three PWS classes accepted and findable.
3. `non_ue_n2_info_unsubscribe_removes_it_and_is_404_the_second_time` — 204 then
   404 `SUBSCRIPTION_NOT_FOUND`, and the notify lookup stops matching.
4. `the_two_specific_pws_classes_do_not_answer_for_each_other` — `PWS-RF` does
   not answer for a response nor `PWS-BCAL` for an indication; the umbrella `PWS`
   answers for both.
5. `n2_pws_sub_miss_ind_is_suppressed_once_a_pws_subscription_exists` — criterion
   4, the inversion of #401's test which asserted the unconditional form. Also
   asserts the `sendRanResponse` record the async path reads was written by the
   live SBI arm.
6. `a_transfer_without_send_ran_response_records_nothing_to_notify` — the
   fail-closed gate, asserted on the record's absence.
7. `unknown_tai_list_reports_tais_this_amf_does_not_serve_on_the_cancel_branch` —
   criterion 5 in the form the spec permits: the unserved TAI reported and the
   served one not, nothing at all on the Write-Replace branch, and the IE omitted
   rather than sent empty when every TAI is served.
8. `the_n2_info_notify_body_carries_the_rans_own_response_verbatim` and
   `a_response_without_an_area_list_reports_bc_empty_area_list` — the body
   builder, member by member, against a `build_write_replace_warning_response`
   PDU, with byte 0 (`0x20`) and byte 1 (`51`) pinned and the binary part asserted
   byte-identical.
9. `global_ran_node_id_renders_the_gnb_id_at_its_real_bit_length` — 6 nibbles at
   or below 24 bits, 8 above.

*`ngap_path`:*

10. `a_write_replace_warning_response_notifies_the_subscribed_consumer` —
    criteria 2+3+6 end to end. A gNB-built response with a real
    `BroadcastCompletedAreaList::CellIdNr` through the **real**
    `process_ngap_message`, and the delivered body asserted: class `PWS-BCAL`, the
    RAN's own identifiers, `ranNodeId.gNbId.gNBValue` equal to *that* gNB's id at
    *that* bit length, no `bcEmptyAreaList`, the right `notifCorrelationId`.
11. `a_response_without_an_area_list_reports_bc_empty_area_list_over_the_wire` —
    a PWS CANCEL RESPONSE (procedure 32, exercising the other half of the shared
    arm) with the list absent; `bcEmptyAreaList` **names** the node, rendered at a
    22-bit length as 6 nibbles.
12. `a_pws_response_is_not_notified_without_send_ran_response_or_a_subscription`
    — both negative halves, separately, so one guard cannot pass for the other's
    reason.
13. `pws_restart_and_failure_indications_notify_on_pws_rf_with_the_pdus_own_node_id`
    — procedures 34 and 33, class `PWS-RF`, `ranNodeId` from the PDU whose gNB id
    is deliberately **different** from the session's so a session-derived value
    fails, identifiers 0/0, no `bcEmptyAreaList`.
14. `an_indication_without_a_subscription_is_dropped_not_error_indicated`.
15. `the_four_pws_procedures_no_longer_reach_the_error_indication_fallthrough` —
    byte 0 and byte 1 pinned for all four fixtures, each asserted to dispatch and
    to be extracted at the code the assertions pinned.

## How I revert-verified

Nine breaks, each applied, the NAMED test watched to fail, then restored:

| break | failing test(s) |
|---|---|
| response arm keyed on `0x00` instead of `0x20` (the byte-0 trap) | both response-notify tests time out waiting for the delivery |
| procedure 33 dropped from the indication arm | `an_indication_without_a_subscription_is_dropped_not_error_indicated` fails with *"SCTP send error"* — the `_` fallthrough trying to send the Error Indication, i.e. the exact pre-#399 defect |
| indication looks up `PWS-BCAL` instead of `PWS-RF` | `pws_restart_and_failure_indications_...` |
| indication sets `bcEmptyAreaList: true` | `pws_restart_and_failure_indications_...` |
| `n2PwsSubMissInd` made unconditional on `sendRanResponse` (the pre-#399 form) | `n2_pws_sub_miss_ind_is_suppressed_once_a_pws_subscription_exists` |
| `unknownTaiList` emitted on both branches | `unknown_tai_list_reports_tais_...` |
| subscription routed at the issue's `non-ue-n2-info-subscriptions` | 4 subscription tests |
| `gNBValue` padded to 8 nibbles regardless of bit length | `global_ran_node_id_renders_...` + the `bcEmptyAreaList` test |
| relayed container truncated by one byte | `the_n2_info_notify_body_carries_the_rans_own_response_verbatim` |

## Checks

- Tests **6833 → 6849** (+16), 0 failed.
- `cargo fmt --all -- --check` clean. `cargo clippy --workspace` adds **zero**
  warnings: the four that remain (2 in `nextgcore-nas`, 1 in `eesd`, 1 in `smfd`)
  are byte-identical to the set at `0dc01e4`, verified by stashing and re-running.
- **amfd suite looped 10x**: 584 passed / 0 failed every run, at
  `/proc/loadavg` 4.98–7.61.
- No new test lock: the PWS-queue tests take the existing module-level
  `pws_queue_test_lock()` (`namf_server.rs:4697`) and every test takes
  `crate::test_support::CONTEXT_GUARD`. Distinct literal
  `(messageIdentifier, serialNumber)` pairs per test, and distinct literal
  subscription ids and association ids, because the subscription store, the
  `sendRanResponse` map and the PWS queue are all process-global.
