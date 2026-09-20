# The AMF's MBS N2 activation leg

**Issues:** nextgcore #75 (the leg), #221 (the scope decision it presumes)
**Verified against:** nextgcore `main` @ `a60b60c`
**Spec basis:** TS 23.247 §7.2.5.2, §7.3.1; TS 38.413 §9.2.9, §9.3.5; TS 29.518

## The decision #221 asks for

> whether the AMF is intended to be the NGAP anchor for MBS in this project

**Yes.** Not as a product preference but because the tree already committed to
it, in three places that only make sense together:

1. `src/libs/nextgcore-ngap/src/mbs_transfer.rs` is 1,602 lines of **real APER**
   MBS SM-container codecs (`MbsSessionId`,
   `MbsDistributionSetupRequestTransfer` and the response / unsuccessful /
   release transfers), each citing its `38413-j30.txt` line.
2. `nextgcore-mbsmfd` already **imports and uses** them (`main.rs:13-15`,
   `1538`, `1610`, `3227`), so the MB-SMF half of
   Nmbsmf_MBSSession_ContextUpdate genuinely works.
3. `nextgsim-gnb/src/mbs_ngap.rs` exists as an MBS session state machine — but
   see the correction below: it is **not** a wire peer.

So both ends of the N2 relay exist and only the relay is missing. Deleting
`ngap_mcast` — #221's other branch — would strand a working producer and a
working RAN peer on either side of a gap, which is the worse outcome.

TS 23.247 §7.2.5.2 puts the AMF in this position normatively: the MB-SMF
triggers activation *via the AMF*, which relays it to the RAN over N2.

## Three premises in the issues are false

### 1. "MBS is not exposed by nextgcore-ngap yet"

Asserted by `ngap_mcast.rs`'s own doc comment (line 35) and repeated in both
issues. It was true when that comment was written and is not true now: the
codec landed in the shared library and `mbsmfd` is its proven consumer. So
criterion 3's "port the builders onto `nextgcore-ngap`" is not "write a codec",
it is "use the one already there".

### 2. The byte-writer builders are not merely "simplified" — they are undecodable

Both issues describe `McastMessageBuilder` as an ad-hoc-but-working
simplification. It cannot have worked. `build_mcast_session_activation_request`
(line 478) opens with `write_u16(procedure_code)`, but an NGAP PDU's byte 0 is
the outer CHOICE index (`0x00` InitiatingMessage / `0x20` Successful /
`0x40` Unsuccessful) and byte 1 is the procedure code — which is exactly what
this AMF's own `extract_procedure_code` (`ngap_path.rs:1193-1203`) reads.

So the framing is wrong at byte zero: a gNB would decode procedure code `0`
(`id-AMFConfigurationUpdate`) from the high byte of 71. The PDUs were never
"simplified APER", they were not NGAP at all. That raises the priority of the
port from tidiness to correctness, and it is why none of it can be kept.

### 3. "The RAN side is ready but the AMF cannot drive it" — the RAN side is not ready either

#75's production-impact section states:

> Because a real MBS-capable gNB peer already exists in nextgsim
> (`nextgsim-gnb/src/mbs_ngap.rs`), the RAN side is ready but the nextgcore AMF
> cannot drive it

Verified in nextgsim `main` @ `395f66f`: `mbs_ngap.rs` is 233 lines and contains
**zero** occurrences of `encode`, `decode`, `Aper` or `ngap::`. It is a session
state machine — `GnbMbsSession`, `NgapMbsManager`, `activate_cell`, `ue_join` —
with no NGAP codec and no socket path. Outside the file itself the only
references are `lib.rs:103` (`pub mod`) and `lib.rs:165` (a re-export), exactly
the dead-code shape #221 describes on the AMF side.

So MBS is unreachable at BOTH ends, and this is the mirror image of
`ngap_mcast.rs`. The consequence is specific and it bounds this PR: an
end-to-end MBS activation cannot be driven against nextgsim today, no matter
what the AMF sends, because nothing there would decode procedure 71 off an SCTP
association.

That is why criterion 6's scheduled half is **struck rather than claimed**, per
the project convention that a criterion blocked by a missing precondition in
another component is struck visibly with the blocker named, and that no
unexercised code ships for it. The per-PR half (a strict in-process fake peer)
is unaffected and is delivered, because it does not depend on nextgsim at all.

Filed as a nextgsim issue so the other half is tracked where the work belongs.

### 4. The procedure codes were already corrected, and are right

Re-verified against the vendored spec rather than the issue text
(`6g_docs/specs/38413-j30.txt:59145-59163`):

| Procedure | Code |
|---|---|
| `id-BroadcastSessionModification` | 66 |
| `id-BroadcastSessionRelease` | 67 |
| `id-BroadcastSessionSetup` | **68** |
| `id-DistributionSetup` | 69 |
| `id-DistributionRelease` | 70 |
| `id-MulticastSessionActivation` | **71** |
| `id-MulticastSessionDeactivation` | 72 |
| `id-MulticastSessionUpdate` | 73 |
| `id-MulticastGroupPaging` | 74 |
| `id-BroadcastSessionReleaseRequired` | 75 |

`mbs_procedure_code`'s 71/72/73/74 are correct, and #75's claim that the module
still has "68/71 swapped" is **stale** — that was fixed by the #71 PR. The
`ProcedureCode` constants in `nextgcore-asn1c` stop at 52, so 66-75 are added
there as literals against those spec lines, per the project's rule that every
new on-wire constant is pinned to its clause with a pairwise-distinctness
assertion beside it.

## Wire structure, read from the spec

`MulticastSessionActivationRequest` (`38413-j30.txt:42777`) carries exactly two
mandatory IEs and nothing else:

- `id-MBS-SessionID` = **299**, criticality reject, `TYPE MBS-SessionID`
- `id-MulticastSessionActivationRequestTransfer` = **304**, criticality reject,
  `TYPE OCTET STRING (CONTAINING MulticastSessionActivationRequestTransfer)`

Deactivation is the same shape with IE **305**. Group paging carries
`id-MulticastGroupPagingAreaList` = **307** (criticality ignore).

`MulticastSessionActivationRequestTransfer` (`:51642`) is
`SEQUENCE { mBS-SessionID, iE-Extensions OPTIONAL, ... }` — so the transfer
restates the session id, which is why the outer IE and the inner transfer both
carry it rather than one being redundant.

Note what the real message does **not** contain, all of which the byte-writer
invented: no S-NSSAI, no TEID, no transport address, no TAC list. Multicast
transport is established by the Distribution Setup procedures (69/70) against
the MB-UPF, not smuggled into the activation request. Dropping those invented
fields is part of the port, not a regression.

## What is built

**AMF NGAP (`ngap_mcast.rs`, `ngap_path.rs`)**
- `McastMessageBuilder` deleted. Builders re-expressed as real
  `NgapPdu::InitiatingMessage` values carrying a `ProtocolIeContainer`, encoded
  through `encode_pdu`, using `MbsSessionId::encode` from the shared library.
  `InitiatingMessageValue::Other` carries them, so the generated enum needs no
  new variant and the decode fallback already routes them.
- Dispatch arms for 71-74 and 68, replacing the `_` fallthrough
  (`ngap_path.rs:1156`) that answered every MBS procedure with an
  ErrorIndication.
- `NgapMcastContext` reachable from the NGAP server's state.

**AMF SBI (`namf_server.rs`)**
- `namf-mbs-comm` (N2 message transfer) and `namf-mbs-bc` (mbs-contexts)
  resources ahead of the `send_not_found` fall-through, decoding the consumer's
  MBS SM container and handing it to the NGAP layer.

**MB-SMF (`mbsmfd`)**
- AMF discovery by MBS service area (TS 23.247 §7.3.1 step 2, currently
  skipped), then the Namf_MBS invocation; RAN outcome surfaced back as
  ContextStatusNotify / Nmbsmf ContextUpdate.

## Feature gating

`mbs` cargo feature, per the issue, so the default non-MBS build and existing
NGAP/SBI behaviour are unchanged. Per the project rule, the feature ships with
a CI job exercising the **enabled** arm — an un-CI'd feature arm is dead code.

## Acceptance criteria

Criterion 6 is split per #349's answer (now merged), which settled that a
cross-repo criterion must name which of two gates it means:

- [ ] Per-PR: in-process test against a strict fake gNB peer asserts the
      activation completes and every MBS PDU round-trips APER.
- [ ] Scheduled: the nightly cross-repo E2E drives `nextgsim-gnb`'s real MBS
      peer.

The per-PR test's module docs must state what it does not prove and name the
scheduled job that does.

## Revert-verification

Executed, not tabled. Each guard was made to fail, the named test was watched
failing, and the change restored.

| Guard | Named test | Made to fail by | Bit? |
|---|---|---|---|
| A 3-digit MNC packs without the `0xF` filler | `a_three_digit_mnc_is_bcd_packed_without_the_filler_nibble` | Emitting the 3-digit packing unconditionally | **yes** |
| ContextCreate is idempotent on the TMGI | `mbs_context_create_is_idempotent_on_the_tmgi` | Forcing the existing-session lookup to `None` | **yes** |
| The `namf-mbs-comm` resource exists | `mbs_n2_message_transfer_is_served_rather_than_404` | Renaming the router arm | **yes** — fell back to exactly the 404 it replaced |
| MBS PDUs decode as real APER at the right procedure code | `an_activation_pdu_decodes_as_procedure_71_...`, `..._72_...`, `..._74_...` | (see below) | n/a — proven by construction |

### One candidate guard turned out to be a false one, and was rewritten

`a_session_with_no_service_area_builds_no_group_paging` **passed with the guard
removed.** The early `return None` for an empty `area_tacs` is redundant: the
APER encoder already refuses length 0 against `SEQUENCE (SIZE(1..16))` with a
`ConstraintViolation`, whose error path also yields `None`. So the test was
satisfied by a path that never reached the area list — the exact false-guard
shape this project keeps finding.

Two changes rather than deleting it:

1. The test now asserts a **contrast pair** — empty yields no PDU, and an
   otherwise identical session with one TAC yields a decodable procedure-74 PDU
   carrying IE 307. The populated half is what proves the builder works; the
   empty half alone proved nothing.
2. The `is_empty` check is kept but its comment now says what it is for — a
   legible log line, since `ConstraintViolation { value: 0, min: 1 }` does not
   tell an operator the session simply has no service area — and explicitly
   records that it is **not** a revert-verified guard.

A note on the three decode tests: they are not revert-verifiable in the
make-it-fail sense, because the thing they pin is the whole PDU structure rather
than one branch. What makes them meaningful instead is that they decode through
the real `NgapPdu` codec and assert the exact IE-id list from the spec — the
tests they REPLACED read `(msg[0] << 8) | msg[1]` as a u16 procedure code and so
agreed with a format no gNB could parse, comparing a built PDU against the same
constant it was built from.

### A defect the tests caught in this work

`mbs_n2_message_transfer_is_served_rather_than_404` failed on first run with a
404: the router arm required `parts.len() == 5`, but `namf_request_handler`
strips the leading `/` before splitting, so
`/namf-mbs-comm/v1/n2-messages/transfer` is **4** segments. Found by the test
rather than by review.

## Consequences

- #221 closes on its decision plus the wiring; #75 closes on the leg.
- The invented activation fields (S-NSSAI, TEID, transport address, TAC list)
  disappear from the wire. Nothing consumed them — the builders had no callers
  — so no behaviour regresses, but the diff looks subtractive and that is why.
- `McastTransportInfo` survives only as internal state until Distribution Setup
  (69/70) is implemented; that is named as the next increment rather than
  half-built here.
