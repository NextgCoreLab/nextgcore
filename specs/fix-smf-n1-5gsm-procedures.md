# nextgcore #77 (SMF): UE-initiated N1 5GSM procedures, ePCO/DNS, T3591/T3592, SSC, DNN labels

Verified against `main` @ `15e4c4d`. The issue's cites are from `76ea248`; line numbers moved but every
described defect was still present exactly as written, which is unusual for this repo and worth saying.

`Closes #77`, with criterion 2 split to #223 — see "Split".

## Gap: a UE-originated 5GSM message on `/modify` was never decoded (criteria 1, 3)

The critical one. `handle_sm_context_update` matched **only** on `n2SmInfoType`. A `/modify` request
carrying only an N1 container fell into the `""` arm, which reads `upCnxState` and nothing else — so a
UE that released or modified a PDU session got `{"upCnxState":"ACTIVATED"}` back and the network ran no
procedure at all. The SMF context, the PFCP session and the gNB's N2 resources stayed allocated
indefinitely: a real leak under churn, not just a conformance gap.

The N1 container is now decoded and dispatched. Shape of the fix:

* **`classify_n1_sm_message` maps bytes to an `N1SmIntent`, and the caller carries the intent out.**
  Split that way so the classification is testable without an SBI request, a PCF or a UPF — and so a
  5GSM type this SMF does not act on here is *distinguishable* from a malformed container: the first is
  a 400 naming the type, the second a 400 naming the container. The previous behaviour silently ignored
  both.
* **The N1 path runs only when there is no N2 payload.** A request carrying both is an N2 procedure
  that happens to relay a NAS message, and those arms already existed; taking the N1 branch first
  unconditionally would have hijacked them.
* **RELEASE REQUEST** releases the user plane (PFCP Session Deletion + PCF policy delete), answers with
  a RELEASE COMMAND **and** an N2 `PDUSessionResourceReleaseCommandTransfer` so the AMF releases the
  gNB's resources too, and arms T3592. The context itself survives until RELEASE COMPLETE, because
  T3592 needs something to key on.
* **RELEASE COMPLETE** stops T3592, drops the context and notifies the AMF `RELEASED` — the same
  ending the SMF-initiated `/release` path reaches.
* **MODIFICATION REQUEST / COMPLETE** answer with a MODIFICATION COMMAND under T3591, and stop it.

## Gap: no T3591/T3592, and no transport to retransmit over (criterion 4)

Adding the timer IDs is the easy half. The hard half was that a 5GSM retransmission has to reach the
UE, which means Namf_Communication N1N2MessageTransfer toward the AMF — and smfd had **no** client for
it. Arming a timer whose expiry had nowhere to send would have been a sender into a path with no
receiver, the failure mode this repo has now recorded three times (#217, #221, #223).

So `send_n1_n2_message_transfer` was added, reusing the client construction
`send_sm_context_status_notification` already uses. The AMF's authority comes from the
`smContextStatusUri` it supplied at SM context create — the SMF has no other address for it, so an AMF
that supplied none is logged and skipped rather than guessed at.

Three decisions in the timer machinery:

* **Retransmission resends the stored command bytes verbatim.** Rebuilding it could pick up state that
  changed in the meantime and send the UE a *different* message under the same procedure.
* **`expire_gsm_timers` is pure over the timer map and returns what is due**, so retransmission and
  exhaustion are assertable by advancing a clock rather than sleeping 16 s five times. The caller does
  the sending.
* **One armed timer per SM context.** TS 24.501 runs at most one network-requested 5GSM procedure per
  session, so a second arm for the same context means the SMF started a procedure it should have
  queued — logged as such rather than silently overwritten. Cancelling with the *wrong* timer id is
  refused, so a MODIFICATION COMPLETE cannot stop a release timer.

## Gap: the accept carried no ePCO, so UEs got no DNS (criterion 5)

Three things were true at once: `docker/rust/configs/5gc/smf.yaml` has declared `smf.dns` (8.8.8.8,
8.8.4.4, two v6) and `smf.mtu: 1400` all along; nothing parsed them (`SmfYaml` had no such fields);
and `SmfContext.dns` was declared and **never read** (`grep '\.dns\['` returned nothing). A working
ePCO encoder existed too — reachable only from the `SmfSess`-based builder that nothing on the live
path calls.

Now `smf.dns`/`smf.mtu` are parsed and the live accept emits the ePCO IE. IPv6 entries in the list are
skipped with a debug line rather than failing the parse, because the container this SMF emits is the
IPv4 DNS one and losing the whole config file over a v6 address would be a worse trade.

With nothing configured, no ePCO IE is emitted — the previous behaviour — so a deployment that
configures no DNS is byte-identical. A test pins that.

## Gap: the requested SSC mode was echoed (criterion 6)

`selected_ssc = if requested_ssc == 0 { 1 } else { requested_ssc }` granted whatever the UE asked for.
`ALLOWED_SSC_MODE_BITMAP` is now `0b001`, and **that is a capability statement, not a policy choice**:
SSC modes 2 and 3 require PSA relocation (tear down and re-anchor, or run two anchors) and this SMF has
no such machinery. Echoing them told the UE it had been granted a session continuity the network cannot
deliver. A refused mode now gets 5GSM cause #68 plus the Allowed SSC mode IE, so the UE learns what to
ask for instead.

If SSC 2/3 are ever implemented, this constant is the single place to widen.

## Gap: multi-label DNNs were malformed on the wire (criterion 7)

The accept emitted one label whose length octet was the length of the **whole** string, dots included.
A single-label DNN (`internet`) encodes identically either way, which is exactly why it survived: only
the multi-label operator and roaming names (`internet.mnc001.mcc001.gprs`) are corrupted, and a UE
reading the first length octet walks past the end of the intended first label.

`encode_dnn_labels` is deliberately the same construction as `n4_build::add_apn_dnn`, which already did
this correctly for the N4 IE — and a test asserts the two agree **byte for byte by calling the N4
builder**, not by re-implementing it. Both DNN sites in `gsm_build.rs` were fixed too, per the
criterion, even though they sit on the test-only path.

An empty label (leading, trailing or doubled dot) is skipped rather than encoded as a zero length
octet, which would terminate the name early.

## Split: criterion 2 → #223

Criterion 2 asks that `handle_pdu_session_release_request` and
`handle_pdu_session_modification_request` gain a non-test caller. **`build_release_command` now has
one** — the release path above. The two `gsm_handler` functions do not, and the reason is not laziness:

`SmfSess`, the struct they take, is **never constructed outside tests**. `grep -rn "SmfSess {"` returns
the definition, two `impl`s and two `#[cfg(test)]` helpers; every other occurrence is in a
`gtp_handler.rs` test. The live 5GC path uses `context::PolicyBinding`. There are two parallel session
models in this binary and one has no producer.

Calling those handlers would mean synthesising an `SmfSess` from a `PolicyBinding`, letting the handler
set `sess.ngap_state` — its entire effect — and dropping it. That satisfies the criterion's literal
grep while changing nothing, and leaves the next person to fix a bug in those handlers believing they
fixed something. Filed as #223 and labelled `architecture`, because the real question is which session
model the SMF owns, and the answer also decides the fate of `gtp_handler.rs` and the `SmfSess`-based
builders in `gsm_build.rs`.

This is the third finding of this shape in three PRs (#217, #221, #223), which is itself worth noting:
issues in this repo that read as "the callee exists, only the caller is missing" have a habit of
resting on a model or transport that does not.

## Verification

**12 new tests.** smfd 380 → 392 passed. Workspace `cargo test --workspace` green; `cargo clippy
--workspace` (the CI gate) clean with zero warnings; `cargo fmt --all --check` clean. One clippy
warning of my own fixed before commit.

**Revert-verified: 18 reverts, 18 bit.** Each fix undone individually, the named test watched to fail,
then restored — including the two halves of the DNN fix (label splitting *and* empty-label skipping)
separately, the timer's exhaustion cap and its verbatim-resend separately, and the timer-id mismatch
guard.

Two harness traps cost time and are worth recording, because both produce a *false* signal rather than
an obvious error:

* The new tests initially landed inside `mod oauth2_h8_tests` rather than `mod tests`, because that is
  the module the file's last `}` closes. They compiled and ran, so nothing looked wrong — but every
  revert reported `NOT_RUN`, since the test path I was filtering on did not exist. This is the second
  time in this session (amfd's `ntn_retx_tests` was the first); appending before a file's final brace
  is not the same as appending to its `mod tests`.
* An earlier `re.sub` over `build_establishment_accept(` call sites matched greedily across the whole
  file and rewrote one span instead of five. Caught by `git diff --stat`, reverted, redone with
  paren-depth matching.

**Not verified:** no live UE, AMF or UPF. The release path's PFCP delete and PCF delete are exercised
only in the sense that the handler calls them; with no UPF they log and continue, so the test asserts
the *response* and the armed timer, not the N4 exchange. `send_n1_n2_message_transfer` has **no test**
— it needs an AMF listening on a `smContextStatusUri`-derived authority, and the seeded binding
deliberately carries none, so retransmission is pinned at the decision (`GsmTimerExpiry::Retransmit`
with the right bytes) and not on the wire. That is the weakest part of this change and the first place
to look if retransmission misbehaves. Docker E2E is skipped by CI. GitNexus impact analysis, which
CLAUDE.md mandates, was **not run** — no MCP server is connected; tenth consecutive PR to record it.
