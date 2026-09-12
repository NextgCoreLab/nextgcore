# fix(ngap): correct all four Paging IE ids

Refs #69. Extracted from it deliberately — see "Why this ships alone".

## The defect

`nextgcore-ngap`'s four Paging IE ids were **all wrong**, read against
`6g_docs/specs/38413-j30.txt:59485-59661`:

| constant | said | TS 38.413 §9.3.1 | what the wrong value is |
|---|---|---|---|
| `IE_ID_UE_PAGING_IDENTITY` | 112 | **115** | 112 is `id-UEContextRequest` |
| `IE_ID_PAGING_DRX` | 70 | **50** | 70 is `id-MaskedIMEISV` |
| `IE_ID_TAI_LIST_FOR_PAGING` | 106 | **103** | 106 is `id-TargetID` |
| `IE_ID_PAGING_PRIORITY` | 69 | **52** | 69 is `id-LocationReportingRequestType` |

The UE paging identity is the load-bearing one: a gNB reading the AMF's 5G-S-TMSI as a
`UEContextRequest` cannot page anybody, so **every** PAGING PDU this stack would emit was
addressed to nobody.

## Why it was invisible

`build_paging_asn1` and `NgapServer::send_paging` have **no callers**. `rg send_paging`
across the tree returns the definition and nothing else, so no PAGING PDU has ever been
built by this AMF, and four wrong constants sat behind that with nothing to expose them.

This is the same class as `smfd`'s `S_NSSAI = 250` (#321) and `mmed`/`sgwcd`'s F-TEID
interface types 4/22/23 (#48): a hand-maintained wire table is wrong, and the error is
inert exactly as long as the code path that would emit it has no caller.

The diagnostic pattern is worth naming, because it repeated a fourth time here. The
**live** IE ids in the same file are all correct — `IE_ID_ALLOWED_NSSAI` 0,
`IE_ID_RRC_ESTABLISHMENT_CAUSE` 90, `IE_ID_UE_CONTEXT_REQUEST` 112, every one exercised
by every registration. It is only the ids nothing exercises that rot. So "is this
constant on a reachable path?" is the question that predicts whether it is right.

## The guard

`paging_ie_ids_match_ts38413_clause_9_3_1` asserts all four as literals against the
clause, plus the three live ones as a control, plus **pairwise distinctness**. The
distinctness check earns its place: the pre-fix `IE_ID_UE_PAGING_IDENTITY` *collided* with
`IE_ID_UE_CONTEXT_REQUEST`, and a set of literal assertions written from the same wrong
source would have agreed with itself.

## Revert-verify

Setting `IE_ID_UE_PAGING_IDENTITY` back to 112 fails the named assertion with
`left: 112, right: 115` and the message about a gNB reading the identity as a UE context
request. Restored, green again.

## Why this ships alone, labelled `Refs #69`

The whole-issue convention says an umbrella gets one PR covering all its parts, so that
umbrellas actually close. Its stated exception is a safety-critical defect that should not
wait, shipped alone and labelled `Refs #N`, with the PR saying why the count deliberately
does not move.

This qualifies, and #69 itself cannot close yet: six of its nine criteria are blocked by
an architecture question about which AMF UE store is authoritative, filed separately. The
IE ids are independent of that question — they are wrong regardless of which store wins,
they are correct and verifiable on their own, and leaving them in the tree would mean the
next person to wire the paging pump ships a PAGING PDU no gNB can act on.

**The open-issue count deliberately does not move.** #69 stays open with a
criterion-by-criterion re-verification and the blocker named.

## Verification

Workspace **6523 → 6524** tests, 0 failures. `cargo clippy --workspace` 0 errors;
`nextgcore-ngap` at 0 warnings. `cargo fmt` clean.
