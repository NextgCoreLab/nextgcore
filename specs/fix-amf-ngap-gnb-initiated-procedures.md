# nextgcore #71 (AMF NGAP): gNB-initiated procedures, multi-session relay, dead code

Verified against `main` @ `cb7bb6a`. The issue's cites are from `76ea248` and most had moved or been
partly addressed since; every one was re-checked before being touched, and two criteria turned out to
be **already satisfied**.

`Closes #71`, with one part split to a follow-up issue — see "Split".

## Already done on main (re-verified, not re-implemented)

* **Criterion 3 — NG SETUP FAILURE.** `parse_ng_setup_request_fallback` no longer exists; a decode
  failure answers `build_ng_setup_failure_asn1(PROTOCOL, SemanticError, 1s)` and returns
  (`ngap_path.rs` `handle_ng_setup_request`). A test was still owed under criterion 7, and writing it
  exposed a defect in my own test — see "Verification".
* **Criterion 6 — no blanket ErrorIndication.** Arms already existed for 19/27/30/44/48/49/52 and for
  35, so none of them reach the `_` fallthrough. What was missing is what those arms *do*.

## Gap: acknowledging a RAN Configuration Update without storing it (criterion 1)

`handle_ran_configuration_update` logged the Supported TA List and replied ACK. The subtler half of
the bug: NG-C looked synchronised while the AMF went on serving the TAC/slice set captured at NG
Setup, so a TAI the gNB had just stopped broadcasting still resolved and one it had just added did
not.

The list is now applied to the stored `AmfGnb`. Two decisions:

* **An absent Supported TA List means UNCHANGED, not none.** The IE is optional here (unlike in NG
  Setup); clearing the stored list on an update that did not mention it would strand every UE on that
  gNB. An *empty* list is treated the same way. That second case is unreachable through a conformant
  encoder — the ASN.1 constraint is `minItems 1`, so `build_ran_configuration_update` refuses to
  encode one — so the decision was extracted into `ta_list_replacement` where it can actually be
  asserted, rather than left as an untestable branch.
* The wire shapes are converted, not assumed: TAC is 3 octets big-endian, PLMN is 3 BCD octets, and an
  SD of `0xffffff` becomes **absent** rather than the literal (TS 23.003), because the literal never
  compares equal to a profile that simply omits the SD.

## Gap: UPLINK RAN STATUS TRANSFER accepted and dropped (criterion 2)

This is the one with user-visible cost: the container carries the per-DRB PDCP SN/HFN status the
target needs to resume without loss, so "accepted and dropped" meant **every N2 handover lost the
in-flight data the procedure exists to preserve**. (Before the accept-arm existed it was worse — an
ErrorIndication.)

Neither direction had a codec, so `nextgcore-ngap` gained one. Design notes:

* **One `RanStatusTransfer` type for both directions.** `UplinkRANStatusTransferIEs` and
  `DownlinkRANStatusTransferIEs` are the same three mandatory IEs. A single type makes the relay
  impossible to get wrong by re-encoding.
* **The transparent container is kept as raw IE-value bytes and re-emitted verbatim.** Unlike the
  handover transparent containers it is an ASN.1 `SEQUENCE`, not an `OCTET STRING`. A decode/re-encode
  round trip through a partial model would silently drop any extension the peer sent, and would give
  the AMF a way to corrupt state it has no stake in. `encode_verbatim_ie` exists for exactly this.
* **A new `handover_target_assoc` map**, because `ue_auth_state` cannot answer "where is this UE
  going" — it still names the *source* until the UE arrives. Recorded when the target admits the UE
  (HandoverRequestAcknowledge) and only on the success path, so a HandoverCommand that never reached
  the source cannot leave a target entry that misroutes the next handover's status transfer.
* **Cleanup happens before the PDU that used to sit in front of it.** On Notify / Cancel / Failure the
  entry is dropped *first*, so a failed acknowledgement cannot leave a stale relay target. This also
  changed `handle_handover_failure` to drop unconditionally rather than only when the source was found.
* **A failed relay send is logged, not propagated.** A dead target association is not a reason to
  abort processing of the source's association: the handover falls back to lossy resumption (the
  pre-existing behaviour) instead of tearing down a working NG interface. The handler returns the
  association it selected, which is what makes the routing testable at all — the relay itself goes out
  over SCTP and a test with no live association cannot observe the bytes.
* **Never relayed back to its own sender**, and a UE with no handover in flight is dropped with a
  warning rather than answered with an ErrorIndication — the AMF must not invent NGAP errors for a
  procedure that needs no response, the same rule the uplink NRPPa relay follows.

## Gap: only the last PDU session was relayed (criterion 4)

The loop over `setup_list` collapsed into a single `gnb_endpoint` variable that each iteration
overwrote. A UE with concurrent eMBB and IMS/VoNR — the ordinary multi-session case — had exactly one
session's downlink TEID installed at the SMF and the rest left half-open: the gNB believed they were
up, the UPF had no downlink FAR for them.

Now every entry is relayed, each against its **own** stored `sm_context_ref`. The failed-to-setup list
was never inspected at all; its per-session Unsuccessful Transfer carries the gNB's cause and the SMF
needs it to release a session it thinks it just established, so it is relayed too.

A session with no stored ref is **refused, not relayed under a synthesised one** — `format!("{psi}")`
lands on a stale N4 session, which is the black-hole this repo already fixed once and must not
reintroduce.

## Gap: Modify and Release responses logged and dropped (criterion 5)

`"Modification confirmed by gNB - no further action needed"` and `"session cleanup already done"` were
both wrong: the N2 SM response transfer is what completes the procedure at the SMF. Without it the SMF
kept the pre-modification QoS while the gNB had already applied the new one.

Both now relay, and so do **PDU Session Resource Notify (30)** and **Modify Indication (27)** — those
two are in the issue's suggested approach rather than its acceptance criteria, but their codecs already
existed and the same relay helper serves them, so leaving them log-only would have been an arbitrary
line. An empty Release Response Transfer is legitimately optional per session and relays nothing.

**Still deliberately log-only: 19, 44, 48, 52.** NAS Non Delivery Indication and UE Radio Capability
Info Indication terminate at the AMF; Uplink RAN Configuration Transfer is an inter-gNB transfer with
no target resolution defined for this deployment; Secondary RAT Data Usage Report needs a charging
consumer that does not exist here and has no codec in-tree. Each would otherwise be a sender into a
path with no receiver — the exact failure mode of adding a caller to a stub.

## Gap: dead code (criterion 8)

**`ngap_handler.rs` — 570 lines deleted.** Audited every public function for callers rather than
trusting the issue's line range: the only live cross-module entries are `handle_ng_setup_request`,
`handle_ng_reset` and `handle_uav_tracking_report` (plus the types and cause-group constants).
Everything from `handle_initial_ue_message` through `handle_error_indication` had **zero** references
outside its own tests, because `ngap_path.rs` reimplements each one on its `ProcessNgap` impl and the
dispatch has only ever called those. Deleted with their seven tests — tests that passed and proved
nothing about the code that runs.

Not deleted, and deliberately outside the criterion's range: `is_tai_served`, `is_s_nssai_supported`
and `parse_cause`. They are also test-only today, but they are small pure helpers that do not read as
working NGAP integration, and removing them is scope beyond what the issue asked.

**`ngap_mcast` — procedure codes corrected, module kept.** The codes were 68/69/70/71 against the spec's
71/72/73/74, which is not a harmless off-by-three: **68 is `id-BroadcastSessionSetup`**, so every
builder labelled its PDU as a different elementary procedure than the one it carried. The module is
*not* deleted, unlike the `ngap_handler` duplicates: those had live reimplementations, whereas this is
the only MBS N2 code in the AMF and `nextgcore-mbsmfd` exists as its peer. Whether the AMF should carry
MBS N2 at all is a product decision, not a cleanup.

Note how the existing `ngap_mcast` tests could never have caught this: they assert that a built PDU's
procedure code equals the same constant it was built from. The new test pins the **literal** spec
values instead.

## Split

Criterion 8's "or correctly wired" for `ngap_mcast` is **not** met: nothing dispatches procedures
71-74, and adding that dispatch is implementing MBS N2 end to end, which is a feature and not this
issue. Filed as its own issue and named in the PR, per the convention that an author-marked or
genuinely separable part becomes a follow-up so the parent can close. What this change delivers is that
the latent builders no longer carry wrong procedure codes, which is a trap removed for whoever wires
them.

Also out of scope, and not in the acceptance criteria (they appear only in Gap 5 / Gap 6): Location
Reporting §8.12, and populating `CriticalityDiagnostics` on ErrorIndication.

## Verification

**11 new tests in amfd, 2 in `nextgcore-ngap`.** amfd lib 419 → 423 (11 added, 7 deleted with the dead
code). Workspace `cargo test --workspace` green; `cargo clippy --workspace` (the CI gate) clean with
zero warnings; `cargo fmt --all --check` clean.

**Revert-verified: 22 reverts, 22 bit** — after two rounds. The first round found **two of my own tests
green for reasons that had nothing to do with what they claimed to pin**, which is the whole reason for
doing this:

1. `undecodable_ng_setup_request_is_answered_with_ng_setup_failure` passed even with a fabricated
   request restored, because `test_ngap_server`'s AMF context serves no TAI, so *every* NG Setup is
   rejected on "no matching TAI". Fixed by seeding the served TAI the deleted fallback used to
   fabricate (PLMN 999/70, TAC 1), so a fabricated request would now be accepted and the assertion
   bites.
2. `test_ran_status_transfer_rejects_a_missing_mandatory_ie` passed with the parser's missing-container
   check removed, because the mislabelled fixture is refused earlier by unknown-IE handling. That is
   defence in depth rather than a hole — but the test did not pin what it said it pinned. The builder's
   empty-container guard was split into its own assertion (which does bite), and the comment now states
   plainly that the parser's `MissingMandatoryIe` arm is **not independently pinned**, because every
   container constructible through the public builders either carries the transparent container or
   carries foreign IEs that trip unknown-IE rejection first.

A third false failure cost real time and is worth recording: the fake SMF recorded nothing because
`fake_smf()` returned only the port and **dropped the `SbiServer`**, closing the listener. Every relay
then failed with connection-refused, which looks exactly like the bug under test — a green-looking
harness bug masquerading as a red result. The helper now hands the server back, and waits for the port
to accept before returning, since `start()` spawns its accept loop.

**Not verified:** no live gNB. The RAN status relay is asserted at its routing decision, not on
captured wire bytes, because the send goes out over SCTP to an association a unit test cannot create;
the codec round trip is pinned separately in `nextgcore-ngap`. The cross-repo coupling recorded on the
issue (nextgsim#41/#42) still holds: the relay is not observable end to end until the gNB side
originates a RAN Configuration Update and consumes a Downlink RAN Status Transfer. Docker E2E is
skipped by CI. GitNexus impact analysis, which CLAUDE.md mandates, was **not run** — no MCP server is
connected, so that mandate remains unsatisfiable, and this is the ninth consecutive PR to say so.
