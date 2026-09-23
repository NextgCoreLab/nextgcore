# Give NGAP the PWS elementary procedures and serve `/non-ue-n2-messages/transfer` for the PWS N2 information class

**Issue:** nextgcore #396 (split out of #74 by PR #398, labelled `architecture`)
**Verified against:** nextgcore `main` @ `04266af`
**Spec basis:** TS 38.413 §8.12 / §9.2.8.1-§9.2.8.6 (the PWS elementary procedures,
their procedure codes and IEs); TS 29.518 §5.2.2.4.1 + §5.2.2.4.1.1/.3
(NonUeN2MessageTransfer and the Warning Request Transfer Procedure), Table
6.1.3.8.4.2.2-2 (the response bodies); TS 36.413 §9.1.13 (the S1AP counterpart, for
comparison with the in-tree `nextgcore-s1ap` implementation); TS 23.041 §9.2.17 /
§9.2.19 (Write-Replace-Warning Confirm / Stop-Warning Confirm, which define what the
AMF answers the CBCF).
Spec text read at `6g_docs/specs/38413-j30.txt`, `6g_docs/specs/29518-k00.txt` and the
OpenAPI at `6g_docs/specs/TS29518_Namf_Communication.yaml`. Every clause quoted below
was read there, with file:line.
**Precedent:** `nextgcore-s1ap` already implements Write-Replace Warning end to end for
the 4G side (`libs/nextgcore-s1ap/src/builder.rs:1179`, `parser.rs:233`,
`types.rs:855`). PR #379 (#75) is the cautionary precedent for how NOT to encode an
NGAP PDU, and `handle_mbs_n2_message_transfer` (`namf_server.rs:3873`) is the in-tree
precedent for an `n2-messages/transfer` router arm.

## Read this first: the issue's premise is true, but its two design implications are both wrong

#396's central factual claim holds. Its two *architectural* claims — that the AMF must
build a WRITE-REPLACE WARNING REQUEST from decomposed IEs, and that the SBI arm's
response can be "built from what the RAN answered" — are both contradicted by the
clauses the issue itself cites. Both are load-bearing: following the issue literally
would produce a *less* conformant AMF than following the spec.

### Criterion-by-criterion, re-located at `04266af`

| # | criterion | cite in the issue | site at `04266af` | verdict |
|---|---|---|---|---|
| 1 | `nextgcore-ngap` gains `WriteReplaceWarningRequest`/`Response` types, builder, parser, `NgapMessage` variants, round-trip tests over every IE | "`grep -rn WRITE_REPLACE_WARNING src/` returns exactly one hit"; `parser.rs:18-74` has no variant | **confirmed.** `grep -rn "WriteReplaceWarning\|WRITE_REPLACE" libs/nextgcore-ngap/src/` returns **zero**. The only NGAP hit tree-wide is the bare constant `libs/nextgcore-asn1c/src/ngap/types.rs:101` | **real — implemented** |
| 2 | `amfd` routes `POST /namf-comm/v1/non-ue-n2-messages/transfer`, relays to the served gNBs, returns a `PWSResponseData` "built from what the RAN answered — not a fabricated one" | `namf_server.rs:1718-1723` of the YAML; arm absent | arm absent (`grep -rn "non-ue-n2" src/` returns zero). **But** the "from what the RAN answered" requirement is contradicted by §5.2.2.4.1.3, which makes the 200 response an *echo*, not a collection — see "Wrong implication 2" | **real — implemented, with the response semantics corrected to the spec's** |
| 3 | a test asserts the encoded NGAP PDU the gNB would receive, not merely that the SBI arm returned 200 | — | — | **real — implemented** (byte 0 / byte 1 asserted positively) |
| 4 | the `architecture` question answered in the PR: does this deployment carry PWS, and what is on the other side of the CBC interface? | — | `grep -rn "CBCF\|PWS-IWF" src/` returns **zero**: this tree has no CBC, CBCF or SBc-AP/N50 peer | **answered below, and it bounds the increment** |

### Wrong implication 1: the AMF does not build the WRITE-REPLACE WARNING REQUEST from IEs — it relays an opaque PDU

The issue reasons from the S1AP/`mmed` shape, where the MME *does* decompose SBc-AP IEs
and rebuild them (`bins/nextgcore-mmed/src/s1ap_build.rs:616`). On the 5G side the
service operation is defined the other way round. `PwsInformation`
(`TS29518_Namf_Communication.yaml:3275-3299`) carries the warning as

```
pwsContainer:
  $ref: '#/components/schemas/N2InfoContent'
```

and `N2InfoContent` (`:3250-3262`) is described verbatim as *"Represents a transparent
N2 information content to be relayed by AMF"*, holding `ngapMessageType`, `ngapIeType`
and `ngapData` (a `RefToBinaryData`, i.e. a multipart binary reference). §5.2.2.4.1.3
says it three times (`29518-k00.txt:4152`, `:4155`, `:4158`): *"The AMF shall **forward
the N2 Message Container** to ng-eNBs or to gNBs indicated in the globalRanNodeList
IE"*. Not "construct", not "encode" — forward.

This matters in the direction that makes the work *smaller and more correct*: an AMF
that decomposed `messageIdentifier`/`serialNumber`/`warningAreaList` out of JSON and
re-encoded a fresh PDU would corrupt every IE the CBCF sent that the AMF's own type
does not model (`warningAreaCoordinates`, the unknown extension IEs the `...` in
`WriteReplaceWarningRequestIEs` at `38413-j30.txt:40940` explicitly admits). The
relay is not a shortcut; it is the conformant behaviour.

The builders in criterion 1 are therefore **still required**, but for a different and
honest reason: the AMF must be able to *decode* what it relays (to validate it is
really procedure 51, and to echo the identifiers the response demands), and this tree
has no gNB-side implementation, so a round-trip test needs a producer. That is exactly
the framing `build_uplink_ran_status_transfer` already uses in this crate
(`libs/nextgcore-ngap/src/builder.rs:1181-1183`: *"gNB -> AMF in production; provided
so a test (or a simulated source gNB) can produce a conformant PDU for the AMF's relay
path to consume"*).

### Wrong implication 2: the 200 response is an echo of the request, not a collection of gNB answers

The issue requires a `PWSResponseData` "built from what the RAN answered — not a
fabricated one", and criterion 2 says the AMF "collect[s] a `PWSResponseData`". Read
§5.2.2.4.1.3 step 2a (`29518-k00.txt:4169-4173`):

> 2a. Same as step 2a of Figure 5.2.2.4.1.1-1, and the POST response body shall contain
> the mandatory elements from the **Write-Replace-Warning Confirm** response (see
> clause 9.2.17 in TS 23.041) or the mandatory elements and optionally the unknown TAI
> List IE from the **Stop-Warning Confirm** response (see clause 9.2.19 in TS 23.041).

The mandatory elements of `PWSResponseData`
(`TS29518_Namf_Communication.yaml:3777-3796`) are `ngapMessageType`, `serialNumber` and
`messageIdentifier` — all three of which are **the request's own values**. The
genuinely RAN-derived fields are the two OPTIONAL ones: `unknownTaiList` and
`n2PwsSubMissInd`. So the HTTP 200 is emitted *when the AMF has initiated the transfer*,
echoing the identifiers, and is not gated on WRITE-REPLACE WARNING RESPONSEs arriving
from gNBs. That is forced by the transport: NGAP responses arrive asynchronously on
SCTP in the NGAP task, long after the HTTP response must be written, and TS 29.518
routes the asynchronous per-RAN outcome through the *separate*
`non-ue-n2-info-subscriptions` + `n2InfoNotify` callback surface — which is what
`n2PwsSubMissInd` exists to signal the absence of (`:4176-4181`).

Building the response by blocking on gNB answers would therefore be *wrong*, not merely
hard. The spec-faithful thing is an echo plus a truthful `result`, and that is what is
implemented.

## The architecture question (criterion 4), answered

**Does this deployment carry PWS?** It carries the N2 *relay*, and not a warning
origin. `grep -rn "CBCF\|cbcf\|PWS-IWF\|pws_iwf" src/` returns **zero**: there is no
CBC, no CBCF, and no SBc-AP/N50 termination anywhere in this tree. The 4G side is not
a counter-example — `mmed`'s `sbc_handler.rs` is the *SBc-AP peer-facing* half, and
`SBC_PROCEDURE_WRITE_REPLACE_WARNING` (`sbc_message.rs:93`) is an SBc-AP procedure
code, not a warning generator either.

That bounds the increment honestly, in the direction this repo prefers (#75's
`N2_NOT_SENT`, #185's deliberate Error Indications):

* The AMF is implemented as a **conformant relay**: it accepts a PWS N2 container from
  any NF service consumer that speaks TS 29.518 (a real CBCF, or a test), validates it,
  targets the right RAN nodes, and hands the bytes to the NGAP task for egress.
* It does **not** grow a CBC, an SBc-AP/N50 interface, or a warning-message composer.
  Those are the CBCF's, and filing them here would be inventing a peer.
* The asynchronous per-RAN-node PWS outcome reporting (the
  `non-ue-n2-info-subscriptions` resource and the `n2InfoNotify` callback) is **split
  out** — see below — because it is a second SBI resource with its own CRUD, and
  because `n2PwsSubMissInd` gives the spec's own answer for its absence in the interim.

## The split, and why this PR still CLOSES #396

All four criteria of #396 are addressed here. One capability that #396 *touches but
does not list as a criterion* is filed separately, following the #141→#190 and
#74→#396/#397 pattern.

**Filed as #399: the PWS N2 information subscription + `n2InfoNotify` callback
surface.** §5.2.2.4.1.3 (`29518-k00.txt:4176-4181`) has the AMF set
`n2PwsSubMissInd` to `true` when `sendRanResponse` was requested *but no PWS N2
information subscription from that consumer exists*, so the consumer re-creates it.
This PR implements that signalling exactly (it is a criterion-2 mandatory element), and
answers `n2PwsSubMissInd: true` truthfully, because `grep -rn
"non-ue-n2-info-subscriptions" src/` returns zero — the resource does not exist, so the
subscription genuinely never exists. Building the subscription CRUD plus the
asynchronous notify is a separate resource with its own lifecycle and does not fit here;
until it lands, every `sendRanResponse: true` request gets the spec's prescribed
"re-create your subscription" answer rather than a fabricated per-RAN report.

## Procedure codes and IE identifiers, pinned to the vendored text

Every value below is quoted from `6g_docs/specs/38413-j30.txt` at the line given. Two
prior incidents in this tree (#45's NRPPa codes, #75's MBS codes) came from *adjacent*
readings of the code table, so these are quoted, not inferred.

| name | value | line in `38413-j30.txt` | exact text |
|---|---|---|---|
| `id-WriteReplaceWarning` | **51** | `:59115` | `id-WriteReplaceWarning ProcedureCode ::= 51` |
| `id-PWSCancel` | 32 | `:59077` | `id-PWSCancel ProcedureCode ::= 32` |
| `id-PWSFailureIndication` | 33 | `:59079` | `id-PWSFailureIndication ProcedureCode ::= 33` |
| `id-PWSRestartIndication` | 34 | `:59081` | `id-PWSRestartIndication ProcedureCode ::= 34` |

All four already exist in `libs/nextgcore-asn1c/src/ngap/types.rs` (`:101`, `:82`,
`:83`, `:84`) and all four match. **Note the ordering trap**: in the alphabetical
ASN.1 table, Failure is 33 and Restart is 34, i.e. *Failure precedes Restart* — the
opposite of the §9.2.8.5/§9.2.8.6 clause order (Restart is §9.2.8.5, Failure is
§9.2.8.6). A reading that followed clause order would swap them. A test asserts all
four constants.

Protocol IE identifiers, from the `NGAP-PDU-Descriptions` IE-ID table:

| IE | id | line | IE | id | line |
|---|---|---|---|---|---|
| `id-MessageIdentifier` | 35 | `:59503` | `id-SerialNumber` | 95 | `:59623` |
| `id-WarningAreaList` | 122 | `:59675` | `id-RepetitionPeriod` | 87 | `:59607` |
| `id-NumberOfBroadcastsRequested` | 47 | `:59527` | `id-WarningType` | 125 | `:59681` |
| `id-WarningSecurityInfo` | 124 | `:59679` | `id-DataCodingScheme` | 20 | `:59473` |
| `id-WarningMessageContents` | 123 | `:59677` | `id-ConcurrentWarningMessageInd` | 17 | `:59467` |
| `id-WarningAreaCoordinates` | 141 | `:59713` | `id-BroadcastCompletedAreaList` | 13 | `:59459` |
| `id-CancelAllWarningMessages` | 14 | `:59461` | `id-BroadcastCancelledAreaList` | 12 | `:59457` |
| `id-CriticalityDiagnostics` | 19 | `:59471` | | | |

## How much of the S1AP precedent transferred, and the four places TS 38.413 diverges

`nextgcore-s1ap` is a genuine reference for the *shape*: `types.rs:855`/`:880`,
`builder.rs:1179`/`:1215`, `parser.rs:233`/`:291` and the ETWS round-trip at
`tests/roundtrip.rs:1558`. The IE *set* of §9.2.8.1 is, modulo one addition, TS 36.413
§9.1.13.1's. What did **not** transfer, and would have been a silent wire bug if it
had:

1. **`RepetitionPeriod` is `INTEGER (0..131071)` in NGAP** (`:55881`) versus
   `(0..4095)` in S1AP (`libs/nextgcore-s1ap/src/types.rs:865` documents `0..4095`).
   The range crosses the 64K boundary, so PER encodes it with the *length-of-length*
   form (X.691 §13.2.6, `libs/nextgcore-asn1c/src/per.rs:168-180`) rather than S1AP's
   two aligned octets. Copying the S1AP encoder would have produced an undecodable IE
   for every repetition period. A test round-trips 131071.
2. **`WarningAreaList` has four root alternatives in NGAP, not three.** `:58760-58772`:
   `eUTRA-CGIListForWarning`, `nR-CGIListForWarning`, `tAIListForWarning`,
   `emergencyAreaIDList`, plus `choice-Extensions`. S1AP's has three
   (`nextgcore-s1ap/src/types.rs:923-930`). The NR list is new, and the E-UTRA/NR split
   runs through `BroadcastCompletedAreaList` too, which has **six** root alternatives
   (`:45687-45704`) against S1AP's three. Reusing the S1AP CHOICE indices would have
   mislabelled every area type.
3. **`WarningAreaCoordinates`** (`id` 141, `OCTET STRING (SIZE(1..1024))`, `:58758`) is
   an NGAP-only IE with no S1AP counterpart.
4. **`NRCellIdentity` is `BIT STRING (SIZE(36))`** (`:52455`) where
   `EUTRACellIdentity` is `(SIZE(28))` (`:47860`). Both appear in the same
   `BroadcastCompletedAreaList` CHOICE, so one shared cell-identity width would be
   wrong for one of the two arms.

The `WarningSecurityInfo` IE is carried but never *interpreted*: §9.2.8.1's own table
says *"This IE is not used in the specification. If received, the IE is ignored."*
(`38413-j30.txt:15896-15899`). It is encoded and decoded so a relayed container
survives byte-exact, and that clause is cited at the site.

## Where this goes, and why the NGAP builders are not the SBI arm's encoder

The tree has two NGAP codec surfaces. The AMF's outbound non-UE-associated path uses
the **hand-written `nextgcore-ngap` builders over the real APER encoder** — verified by
following `send_overload_start` (`ngap_path.rs:6603-6616`) to
`ngap_asn1::build_overload_start_asn1` (`ngap_asn1.rs:964-968`) to
`nextgcore_ngap::builder::build_overload_start`, which ends in `encode_pdu` →
`AperEncoder` (`builder.rs:17-22`). So `nextgcore-ngap` is the right home, and the
generated `tools/`-vendored codec (used by nextgsim) is not involved.

**Byte 0 and byte 1.** `#75`/PR #379 found the old MBS byte-writer builders opened with
`write_u16(procedure_code)`, so a gNB decoded procedure 0 from the high byte of 71. The
`NgapPdu` CHOICE puts the PDU-type index in byte 0 (`0x00` InitiatingMessage, `0x20`
SuccessfulOutcome, `0x40` UnsuccessfulOutcome — the convention `ngap_path.rs:922-987`
already dispatches on) and the procedure code in byte 1. Every builder added here goes
through `NgapPdu` + `encode_pdu` rather than writing bytes, and the tests assert
`bytes[0]` and `bytes[1]` **positively** for each of the six messages.

### The relay's egress path, and the discarded-clone / unreachable-code hazards

The SBI task cannot send on SCTP: the associations live in `NgapServer.sessions`, which
is private to the NGAP task. Two findings shaped the mechanism:

* **`AmfContext::gnb_list` has zero production writers.** `grep -rn "gnb_add\|gnb_remove\|gnb_list\|gnb_find" src/bins/nextgcore-amfd/src/ | grep -v context.rs` returns
  **nothing**: `gnb_add` (`context.rs:906`) is called only from that file's own tests.
  The NGAP path maintains gNB identity on `session.gnb` inside `sessions`
  (`ngap_path.rs:1493-1494`) and never publishes it to the context. So an SBI handler
  that enumerated `gnb_list` to resolve `globalRanNodeList`/`taiList` would target an
  always-empty map — precisely the "production reader, test-only writer" defect
  `ngap_path.rs:592-601` records for `ue_store`, and the #398 `amf_ue_add` vs
  `amf_ue_publish` bug. **Targeting is therefore resolved in the NGAP task**, against
  the live `sessions` map that really holds the gNBs.
* **The queue + pump is the established bridge**, not a new invention: `positioning_dl_queue`
  (`context.rs:601`) and `network_dereg_queue` (`:633`) are both written by Namf SBI
  handlers and drained by the NGAP task's per-iteration pump (`ngap_path.rs:760-766`).
  `pws_n2_queue` follows them exactly, and `process_pws_n2_transfers` is called from
  the same pump, so the arm reaches the encoder on a live path.

`PendingPwsN2Transfer` carries the already-encoded container plus the targeting
selectors; the pump resolves them against `sessions` and sends. Because the container
is relayed verbatim, the pump does not rebuild it — it only decodes far enough to log
the procedure it is relaying.

## Test plan

Each assertion is positive. Revert-verification is recorded in the PR body.

* `nextgcore-ngap`: round-trip every one of the six PWS messages through
  builder → `decode_ngap_pdu` → typed message, over **every** IE including the
  optional ones, and assert `bytes[0]`/`bytes[1]`.
* `RepetitionPeriod` at the 131071 bound (the divergence that would have silently
  broken if S1AP's encoder had been copied).
* All four PWS CHOICE arms of `WarningAreaList` and all six of
  `BroadcastCompletedAreaList` / `BroadcastCancelledAreaList`.
* The four procedure-code constants, asserted against the pinned values.
* `amfd`: the router arm reaches the handler; a PWS container is validated, enqueued,
  and the 200 body echoes `messageIdentifier`/`serialNumber`/`ngapMessageType`;
  `sendRanResponse: true` yields `n2PwsSubMissInd: true`; a non-PWS/absent container is
  rejected with the spec's error rather than enqueued.
* The pump drains the queue and produces a PDU whose byte 0/byte 1 are 51's — the
  "asserts the encoded NGAP PDU the gNB would receive" of criterion 3.
* `amfd` tests that touch the process-global context use
  `crate::test_support::CONTEXT_GUARD` and distinct literal keys; the PWS queue is
  process-global and destructively drained, so its tests serialize on a single
  module-level lock declared beside the queue's tests, not inside a `mod tests`.

## Result

* Workspace tests: **6800 -> 6826** (+26; 13 in `nextgcore-ngap`, 13 in `nextgcore-amfd`).
* `cargo fmt --all -- --check`, `cargo clippy --workspace` (CI's invocation) and
  `cargo test --workspace` all clean. The amfd suite was looped 10x at load ~5.0,
  561 passed / 0 failed every run.
* Follow-up filed as #399 (asynchronous per-RAN PWS outcome reporting).
