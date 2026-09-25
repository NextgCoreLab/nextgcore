# Prove the SERVICE REQUEST Namf fire point against nextgsim's real gNB and UE

**Issue:** nextgcore #403 (the ceiling stated by PR #402 / #397)
**Verified against:** nextgcore `main` @ `b5b4792`, nextgsim `main` @ `bef2a96`
(read-only checkout). Originally written against nextgcore `0dc01e4`; re-dispatched
after nextgsim PR #198 landed, then after PR #200, then after PR #202. The sections
below are corrected to the fourth run,
[36089664496](https://github.com/NextgCoreLab/nextgcore/actions/runs/36089664496).
**Spec basis:** TS 24.501 §5.6.1 (the Service Request procedure), §5.6.1.2 /
§9.11.3.44 (the Uplink data status IE), §5.6.1.5 (Service Reject cause #9),
§5.3.7 (the N1 release and the mobile reachable timer); TS 29.518 §6.2
(`REACHABILITY_REPORT` / `LOCATION_REPORT` triggers), §6.2.6.2.4
(`AmfEventNotification`), §6.2.6.2.5 (`AmfEventReport`); TS 38.331 §5.3.8.3
(`RRCRelease` with a `suspendConfig` moves the UE to RRC_INACTIVE), §5.3.13.2
(the MO trigger for a resume), §5.3.13.3 / §5.3.13.4 (`RRCResumeRequest1`,
`RRCResume`, and the NAS that rides the `RRCResumeComplete`); TS 38.413 §8.3.2
(`UEContextReleaseRequest`), §9.3.1.2 (Cause); TS 33.501 §6.8.2.1.1 (the initial
NCC).
**Predecessor:** `specs/fix-amfd-namf-event-exposure-live-fire-points.md` (#397 /
PR #402), which records the owner's rationale and states this exact ceiling. This
spec closes it.

## OUTCOME FIRST: the fire point is still UNPROVEN, and the blocker has MOVED THREE TIMES

All three blockers this spec previously named are **resolved**. The coverage is **still not
live**, because a *fourth* defect sat behind them. Every fact below is measured, not
reasoned.

The shape of this issue is now its most useful lesson: **four defects in series, each
masking the next.** Discovery (#197), then an unwritten CLI registry (#199), then an
unreachable resume (#201), and now a resume that is *sent* but never *completes* (#203).
Each was invisible until the one in front of it was fixed, and each time the previous pass
predicted "the step should go green with no further nextgcore change". That prediction has
now been wrong **four** times, for four different reasons. The next reader should treat any
such estimate here as unverified until a run says otherwise — including this one's.

What genuinely changed this pass: **link 9 is now verified LIVE.** The UE emits a
conformant `RRCResumeRequest1` with a real `resumeMAC-I`, which had never happened in any
previous run. So nextgsim #201/#202 works. The chain now breaks at link 10–11 — the resume
is transmitted and never completed.

**And one honest correction to this repo's own work.** Run 36089664496 could not say *why*
the resume failed, and that was a defect in **this** spec's CI step rather than a finding
about nextgsim: the drive step captured the gNB log *before* sending the trigger and never
re-read it, so the gNB's entire reaction to the resume was missing from the evidence. That
is fixed in this pass (see "The gNB-side diagnostic gap" below). The lesson generalises:
a diagnostic that cannot observe the component it is about to blame will misattribute.

### Blocker 1 (discovery): FIXED, and confirmed here

Run
([35882746859](https://github.com/NextgCoreLab/nextgcore/actions/runs/35882746859))
failed with:

```
ERROR: No node found with name 'gnb'. Use --dump to list available nodes.
```

Filed as **nextgsim #197** and fixed by **nextgsim PR #198** (merged, `6ec9d47`),
which deleted the gNB's duplicate `CliServer` and converged it onto
`nextgsim-common`'s registering one. `nextgsim-gnb/src/app/cli_server.rs` no longer
exists; `nextgsim-gnb/src/app/task.rs:83` now calls `register_nodes`.

PR #198 also found something the #197 diagnosis had missed, and it is why the obvious
fix would have failed silently: the two `CliServer` copies framed at **different wire
versions** (the gNB's hard-coded `3.2.7`; common and `nr-cli` `1.0.0`), and both
decoders hard-reject a mismatch. Merely adding `register_nodes` to the gNB's own
server would have published a discoverable port that then dropped every `nr-cli`
datagram. Both now read `1.0.0` (`nextgsim-common/src/cli_server.rs:27-31`,
`nextgsim-cli/src/proc_table.rs:24-25`).

Confirmed in run
**[35957375665](https://github.com/NextgCoreLab/nextgcore/actions/runs/35957375665)**
against nextgsim `main` @ `6ec9d47`: **no discovery error at all.** The command
reached the gNB and the gNB answered.

### Blocker 2 (an empty UE registry): FIXED, and confirmed here

Run 35957375665 got, in the same step that had just logged
`PDU Session 1 is now ACTIVE (IPv4: Some([10, 45, 0, 2]))`:

```
$ nr-cli gnb --exec 'ue-list'
ues: []
```

That was `handle_ue_list` speaking — the gNB's own code, not a discovery failure — so
discovery, framing, dispatch and the response path all agreed, and the answer was simply
**wrong**. `AppTask.ue_contexts`, which `ue-list` and `ue-suspend` both read, had **no
production writer**: every caller of `AppTask::update_ue_context` was a unit test,
because `AppMessage` carried no UE-lifecycle variant.

Filed as **nextgsim #199** and **FIXED by nextgsim PR #200** (merged, `685e50b`), which
added `AppMessage::UeContextUpdate` / `UeContextRemove` and sends them from the NGAP
task's own context lifecycle — `sync_ue_context_to_app` at seven production sites
(`nextgsim-gnb/src/ngap/task.rs:442`, `:855`, `:1088`, `:1298`, `:1937`, `:3808`,
`:4493`), with removal from the single `delete_ue_context` convergence point (`:539`).
Verified by counting those call sites in the read-only checkout, not taken on trust.

Confirmed live in run **36045644289** against nextgsim `main` @ `685e50b`:

```
$ nr-cli gnb --exec 'ue-list'
ues:
  - ue_id: 0
    ran_ngap_id: 1
    amf_ngap_id: 2
suspending gNB UE context 0 to RRC_INACTIVE
```

Note the `ue_id` is `0`, not `1`. The step **reads** it from `ue-list` rather than
assuming — which is exactly why that decision was made, and it is now load-bearing
rather than hypothetical: a hardcoded `1` would have failed here.

### Blocker 3 (the UE could not resume): FIXED by nextgsim #202, and confirmed here

The suspension works on **both** ends, and the UE's NAS correctly goes CM-IDLE:

```
nextgsim-gnb | UE[0] suspended to RRC_INACTIVE: I-RNTI=0x1, t380=None min, RNA of 1 cell(s), NCC=0
nextgsim-ue  | Suspended to RRC_INACTIVE: I-RNTI=0x1, t380=None min, RNA of 1 cell(s), NCC=0
nextgsim-ue  | RRC connection released
nextgsim-ue  | Sending Service Request (Data), T3517 started
```

The UE used to stop there, taking `initiate_resume`'s `falling back to RRC_IDLE` arm on
every attempt because `self.as_security` was never populated under
`as_security_enabled: false`. **That is fixed.** nextgsim #201 was resolved by PR #202
(merged, `bef2a96`), which found **four** gates rather than the two the issue named:

1. the UE's NAS plane handed RRC its `KgNB` only when the wire gate was on — now ungated
   (`nextgsim-ue/src/nas/mm/orchestrator.rs:2513`), and safe because `KgNB` never crosses
   the air in either direction;
2. the UE recorded an AS context only from an SMC it *accepted*, and an unprotected SMC is
   correctly refused (TS 38.331 §5.3.4.2) — now a second field, `inactive_as_security`,
   records the resume keys *without* activating SRB1 protection
   (`store_inactive_as_context`, `nextgsim-ue/src/rrc/task.rs:899`);
3. **not in the issue, and invisible from the UE side:** the gNB's UL-CCCH byte-range
   dispatch ladder reached `handle_rrc_resume_request` only for a leading `0x28`, while a
   conformant `RRCResumeRequest1` is UL-CCCH1 c1 index 0 and leads with `0x00` — landing in
   the ladder's own `0x00..=0x1F` **RRCSetupRequest** arm. Resumes were answered with an
   `RRCSetup` built on a fabricated context: the I-RNTI never looked up, the `resumeMAC-I`
   never verified, and **nothing errored**. Now decoded by type before the ladder
   (`nextgsim-gnb/src/rrc/task.rs:521`);
4. the UE's fallback was silent, leaking one gNB-side I-RNTI context per failed attempt;
   a fresh `RRCSetupRequest` now discards the abandoned context (TS 38.300 §9.2.2.2).

**Confirmed live in run 36089664496**, and this line had never appeared in *any* previous
run — 35882746859, 35957375665 and 36045644289 all lacked it:

```
nextgsim-ue | INFO nextgsim_ue::rrc::task: Sending RRCResumeRequest1: cause=mo-data, I-RNTI=0x1, resumeMAC-I=0xc698
```

So link 9 is live: the UE genuinely computes a `resumeMAC-I` and transmits a conformant
resume on UL-CCCH1.

### Blocker 4 (the resume never completes): the current one, filed as nextgsim #203

Stated as "the resume never completes" and **not** as "the gNB rejects it", because which
end is at fault is not yet established — and asserting it anyway is how the previous three
passes went wrong.

What is measured: there is no `RRC resume complete`, no `Service Accept received`, and
~2s later the UE establishes a **new** RRC connection, so nextgcore sees a second
`InitialUEMessage` with a fresh `ran_ue_ngap_id`:

```
nextgcore-amf | Parsed Initial UE Message: ran_ue_ngap_id=1, nas_pdu_len=23, ...   <- the registration
nextgcore-amf | Parsed Initial UE Message: ran_ue_ngap_id=2, nas_pdu_len=24, ...   <- after the failed resume
nextgcore-amf | WARN Unhandled NAS message type 0x8b in Initial UE Message
```

`0x8b` is not a 5GMM message type — it is a **ciphered** byte: the UE NAS-protected the
Service Request (`protect_if_active`, `nextgsim-ue/src/nas/mm/orchestrator.rs`), correct per
TS 24.501 §4.4.2, but it rode an `InitialUEMessage` where the AMF has no security context to
unwrap it with. So the path did not even reach the cause-#9 arm this spec documents; it fell
one step short, at the NAS type match.

**Note the trap:** the AMF-side symptom is *unchanged* from the previous run (a second
`InitialUEMessage` carrying an unwrappable ciphered byte) even though its cause has moved a
link along. A reader comparing only the AMF log would conclude #201/#202 had not worked. It
did — the difference is on the UE side, one layer down.

### The gNB-side diagnostic gap, which was OURS

Run 36089664496 could not name the cause, and that was a defect in **this spec's CI step**
rather than a finding about nextgsim. The drive step captured `docker compose logs gnb` into
`/tmp/gnb.log` *before* sending the trigger, and its failure branch then re-read only the UE
and AMF logs. So the last gNB line in the evidence is the suspension itself, and the gNB's
entire reaction to the resume — whether it arrived, decoded, resolved the I-RNTI, or failed
its MAC — was simply absent.

Fixed in this pass. The failure branch now re-captures the gNB log and greps for the arms
that have **different owners**:

| grep | what it would mean |
|---|---|
| `Uplink RRC: ...UlCcch1` | the PDU reached the gNB's RLS at all (DEBUG, and the gNB runs at `nextgsim_gnb=debug` here, so absence is meaningful) |
| `RRC Resume Request from` | it decoded as a resume — #202's gate-3 fix working |
| `resumeMAC-I verified` | the I-RNTI resolved **and** the MAC matched |
| `Rejecting RRC Resume` | the MAC did **not** match (or the cell is barred) — for a MAC mismatch the line carries both the presented and the recomputed value, so the two ends' disagreement is readable off it |
| `Discarding an undecodable` | it arrived but no decoder accepted it |
| `RRC Resume for UE[..] refused` | `UnknownIRnti` / `MacIMismatch` / not buildable |

The generalisable lesson, recorded because it cost a run: **a diagnostic that cannot observe
the component it is about to blame will misattribute.** The step named nextgsim #201 in its
error text while holding no evidence about the gNB at all.

### What was ruled out, so the next reader does not repeat it

Checked in the read-only nextgsim checkout at `bef2a96`. Every `VarResumeMAC-Input` term
except the key agrees between the two ends:

| term | UE source | gNB source | agree? |
|---|---|---|---|
| C-RNTI | `AS_SECURITY_C_RNTI = 0x4601` (`ue/src/rrc/task.rs:139`) | `SIMULATED_C_RNTI = 0x4601` (`nextgsim-rrc/.../rrc_reestablishment.rs:405`) | **yes** |
| source PCI | `phys_cell_id_from_nci(serving_cell_identity())` (`ue/src/rrc/task.rs:3260`) | `security.phys_cell_id` = `phys_cell_id_from_nci(config.nci)` | **yes** — same function, same NCI (`0x10`) |
| target cell identity | `serving_cell_identity()` = SIB1 `nci` | `cell_identity()` = `config.nci & 0xF_FFFF_FFFF` | **yes** — one cell, no reselection in this scenario |
| I-RNTI | full form, `0x1` | `find_suspended` indexes full **and** short | **yes** |

So the remaining suspect is the **key**, and the two ends obtain `KgNB` from different
places: the gNB from the AMF's Initial Context Setup `SecurityKey` IE, the UE by deriving
`KDF(KAMF, uplink NAS COUNT, 0x01)` itself at `SecurityModeComplete`. nextgcore derives its
copy at `ngap_path.rs:4363` on the Registration Accept path. nextgsim's own comment at
`orchestrator.rs:2505-2508` flags exactly this as unverified — *"the exact uplink NAS COUNT
the AMF uses for the KgNB derivation is a cross-stack detail verified in the docker E2E
sign-off"*. That sign-off is what just ran, and this is the first time anything has depended
on the answer: before #202 the UE discarded these keys, so nothing ever compared them.

Offered as a **hypothesis, not a finding** — it predicts a `does not match the` line, which
the improved capture will either produce or refute.

### A nextgcore-side hazard these runs exposed

Runs 35957375665, 36045644289 **and** 36089664496 all reported job conclusion **`success`**
while the drive step and the probe-verdict step genuinely exited 1 — and `gh run view --job`
printed a **green tick beside every step** in all three. That is `continue-on-error` doing
exactly what it says, and it means **a green tick on `Docker E2E` does not mean this fire
point is proven**. The summary views derive from the tolerated status, not the exit code, so
the only evidence is the step's own `PASS:` / `FAIL:` line in `--log` output. The block
comment in `ci.yml` says so explicitly, because the next reader's most likely error is
trusting the tick. This is the same family as the vacuous-green failure #187 recorded.

**So the honest status of the SERVICE REQUEST fire point is: still unproven by
automated test.** What this change delivers is (a) the complete machinery, which
self-activates the moment the resume completes, with no further nextgcore change; (b) a
probe assertion **measured** to fail when the emitters are reverted; (c) the precise,
evidenced identification of the remaining missing link — which is what #403 actually asked
for when it said "if CM-IDLE genuinely cannot be reached from outside without new nextgsim
code, that is a legitimate finding: state it precisely"; and (d) **a diagnostic that can
now see the component it blames**, which the previous three passes could not. Note that
CM-IDLE **is** reached and the resume **is** now sent, both live, so #403's premise is
answered twice over: the gap is no longer getting *to* CM-IDLE, nor even *originating* the
return, but *completing* it.

Note the shape of the correction, now four times over. #403 claimed the blocker was a
missing **`nr-ue` control surface**: wrong. The #403 investigation then named a missing
**proc-table registration**: right that it blocked, but it was a duplicated `CliServer`
with a version skew, and fixing it revealed a **second** blocker, an unwritten App-task
registry. Fixing *that* revealed a **third**: the UE's resume was gated on an AS security
context no shipped config creates. Fixing *that* — in four places, one of them on the gNB
and invisible from the UE — revealed a **fourth**: the resume is now sent and still does
not complete. The commands involved (`ue-release`, `ue-suspend`, `ue-list`,
`xn-path-switch`) all exist and are unit-tested; `ue-suspend` is genuinely reachable and
functional, and it is the resume's *completion* that is not.

Everything else in the chain was verified in run 36089664496: the gNB completed NG Setup,
the UE registered, got a PDU session (`PDU Session 1 is now ACTIVE`), the
registration-phase Namf assertion **passed** on notification bodies (`PASS: ... mcc 999
mnc 70 tac 0001 ... delivered NOTHING to the control subscription`), the service-request
probe **SUBSCRIBED**, `ue-list` returned a real UE (`ue_id: 0`), `ue-suspend` suspended it
with both ends agreeing, the UE's NAS went CM-IDLE, a TUN write originated a real Service
Request, and the UE sent a real `RRCResumeRequest1`. The chain breaks at exactly one link,
and it is now the resume's **completion**.

### One thing the runs disproved that was previously only reasoned

A detail worth recording because an earlier pass predicted the opposite, and it has now
reproduced in two consecutive runs. The `ping` through the TUN **succeeded**
(`5 packets transmitted, 5 received, 0% packet loss` in run 36089664496) even though the UE
was CM-IDLE and the procedure that should have re-established the tunnel never completed.
The step deliberately never asserts on ICMP — `|| true`, with the assertion on the NAS
exchange instead — and these runs are why that was right. A step that had asserted "the ping
succeeds" would have gone **green on a UE that never resumed**: a vacuous pass of exactly
the #187 shape. The UPF's session was never torn down (the suspension is RAN-local and the
AMF was never told), so the data path stayed up independently of the UE's RRC state.

## The route, and why it is right once the resume completes

#403's central claim is that the work is blocked on new nextgsim code:

> there is **no control surface on `nr-ue` to request an idle transition from outside
> the process**. So the sequence the E2E would need — register, go idle, come back — is
> not expressible today.

That is **wrong**, and the correct route needs **no nextgsim change at all**. The
issue looked for the control surface on the wrong node. It is on the **gNB**.

`nr-gnb` runs a UDP CLI server (`nextgsim-common/src/cli_server.rs`, started from
`nextgsim-gnb/src/main.rs:136` as node `gnb`), and its command set
(`GnbCliCommandType`, `nextgsim-gnb/src/tasks.rs:215`) already includes **two**
commands that end a UE's RRC connection:

| command | what it does | reaches the fire point? |
|---|---|---|
| `ue-release <ue_id>` | gNB sends `UEContextReleaseRequest` to the AMF (`nextgsim-gnb/src/app/task.rs:171-183` → `ngap/task.rs:2764`), then `AnRelease` → plain `RRCRelease` → UE goes **RRC_IDLE** | **NO — see below** |
| `ue-suspend <ue_id> [t380]` | RAN-local suspension to **RRC_INACTIVE**; `RRCRelease` **carrying a `suspendConfig`** (`rrc/connection.rs:650`), and the **AMF is deliberately not told** | **YES** |

### Why `ue-release` does NOT work, and why that matters

This is the trap, and it is worth recording because it is the obvious first choice.

`ue-release` tells the AMF. The AMF's `handle_ue_context_release`
(`ngap_path.rs:8465`) answers with a `UEContextReleaseCommand` and the gNB then
calls `delete_ue_context` + `ue_manager.delete_ue(ue_id)`
(`nextgsim-gnb/src/rrc/task.rs:1725-1735`). The NGAP UE context is **gone on both
sides**. When the UE later has uplink data it is in `RrcState::Idle`, so
`handle_uplink_nas_delivery` takes the `start_connection_establishment` arm
(`nextgsim-ue/src/rrc/task.rs:3799-3801`) and the gNB emits an
**`InitialUEMessage`**, not an `UplinkNASTransport`.

And nextgcore's `handle_initial_ue_message` has exactly one arm for a Service
Request in an `InitialUEMessage` (`ngap_path.rs:1689`):

```rust
message_type::SERVICE_REQUEST => {
    // UE context unknown (fresh NGAP IDs) -> the UE identity cannot
    // be derived: Service Reject cause #9 forces re-registration
    log::warn!(
        "Service Request in Initial UE Message without stored context: rejecting (#9)"
    );
```

It rejects **unconditionally** — there is no 5G-S-TMSI lookup on that path, even
though the gNB does send the `fiveGSTmsi` IE (`ngap/task.rs:2449-2457`). So a
`ue-release`-based test would drive a Service Request that is answered with a
**Service Reject**, `handle_service_request_nas` would never run, and the probe
would time out. **That is a real nextgcore gap, but it is not this issue**, and it
is recorded as a ceiling below rather than silently worked around.

### Why `ue-suspend` DOES work: the chain, verified link by link

RRC_INACTIVE is the right state because it is **RAN-local**. The comment at the
dispatch site says so (`nextgsim-gnb/src/app/task.rs:132-135`): *"Sent to RRC and
not to NGAP, because suspension is RAN-local and the AMF is deliberately not
told"*. So the **NGAP UE context survives on both sides**, which is precisely what
makes the return leg an `UplinkNASTransport` and therefore reaches the fire point.

Every link below was read in the read-only nextgsim checkout at `bef2a96`. The **status**
column records what run 36089664496 established, so "inspection" and "live" are never
conflated:

| # | link | site | status after run 36089664496 |
|---|---|---|---|
| 1 | `ue-suspend 0` parsed | `nextgsim-gnb/src/app/cmd_handler.rs` | **LIVE** |
| 2 | → `RrcMessage::SuspendUe` (**not** NGAP) | `nextgsim-gnb/src/app/task.rs` | **LIVE** |
| 3 | gNB suspends: needs `reestablishment_security`, which Initial Context Setup supplied | `rrc/connection.rs:680-696`; set from `ngap/task.rs:1015-1027`, called by `activate_as_security` (`:954`) ← `handle_initial_context_setup_request` (`:1094`) | **LIVE** |
| 4 | gNB sends `RRCRelease` **with** `suspendConfig`; stores the context by I-RNTI | `rrc/connection.rs:734-760` | **LIVE** (`I-RNTI=0x1`) |
| 5 | UE reads the `suspendConfig` → `RRC_INACTIVE`, and tells NAS the connection is gone | `nextgsim-ue/src/rrc/task.rs:3279-3295` | **LIVE** |
| 6 | NAS switches to **CM-IDLE** on `RrcConnectionRelease` | `nextgsim-ue/src/main.rs:848` | **LIVE** (`RRC connection released`) |
| 7 | a TUN write raises `UplinkData` → `NasMessage::InitiateServiceRequest { psi }` | `nextgsim-ue/src/tun/task.rs`; `main.rs` | **LIVE** |
| 8 | NAS is registered **and** idle → `start_service_request`, Uplink data status from the real PSI | `nas/mm/orchestrator.rs:2569` | **LIVE** (`Sending Service Request (Data), T3517 started`) |
| 9 | the Service Request NAS PDU goes to RRC; state is `Inactive`, so the **MO resume** arm runs, `initiate_resume` finds an AS context and computes a `resumeMAC-I` | `nextgsim-ue/src/rrc/task.rs:3363-3438`; keys from `store_inactive_as_context` (`:899`) | **LIVE as of nextgsim #202** — `Sending RRCResumeRequest1: cause=mo-data, I-RNTI=0x1, resumeMAC-I=0xc698`. Had never appeared in any prior run |
| 10 | `RRCResumeRequest1` (UL-CCCH1) → gNB decodes it by type, looks the I-RNTI up, verifies `resumeMAC-I` against the **stored** context | dispatch `rrc/task.rs:521`; handler `:1736`; verification `rrc/connection.rs:803-885` | **BROKEN — nextgsim #203.** No `RRC Resume Request from`, no `resumeMAC-I verified`, no rejection line either: run 36089664496's step never captured the gNB log after the resume, so the arm taken is **unknown**. Fixed in this pass so the next run names it |
| 11 | `RRCResumeComplete` carries the pending NAS | `nextgsim-ue/src/rrc/task.rs` (`initial_nas_pdu.take()`) | never reached |
| 12 | gNB forwards it as **`UplinkNASTransport`** (the NGAP context still has `amf_ue_ngap_id`) | `rrc/task.rs:1828-1853` → `ngap/task.rs:2595-2660` | never reached — but the lookup it depends on is **verified by inspection**: `handle_uplink_nas_delivery` reads `amf_ue_ngap_id` from the surviving NGAP context, and `process_rrc_resume_request` restores that context under the resuming `ue_id` |
| 13 | nextgcore dispatches `SERVICE_REQUEST` from `handle_uplink_nas_transport`, deciphering the NAS first | `ngap_path.rs:1718` (handler), `:1807-1850` (`nas_5gs_security_decode`), `:1984-1991` (dispatch) | verified by inspection — and note this path **does** unwrap a ciphered Service Request, which is exactly what the `InitialUEMessage` path cannot do |
| 14 | `handle_service_request_nas`: context present → Service Accept egresses → **the emitters fire** | `ngap_path.rs:4634` (handler), `:4688` (`Service Accept sent to UE`), emitters at `:4759-4762` | verified by inspection |

Link 14 is the one this issue exists to prove. `has_context` is
`security_context_available && registered` (`ngap_path.rs:4647`), and both survive the
suspension because nextgcore was never told about it — the `ue_auth_state` entry
is untouched.

## Criterion-by-criterion, re-checked at `b5b4792` after nextgsim #202

| # | criterion as filed | site | verdict |
|---|---|---|---|
| 1 | the `Docker E2E` job drives a registered UE to CM-IDLE and back through a Service Request, against nextgsim's real gNB | the three `#403` steps of `docker-e2e` in `ci.yml` | **the "to CM-IDLE" half is REAL and LIVE, and the "and back" half now ORIGINATES but does not COMPLETE.** Run 36089664496 suspended a real UE (`ue_id: 0`), both ends agreed, its NAS went CM-IDLE, a TUN write originated a real Service Request, and the UE sent a real `RRCResumeRequest1` — but the resume never completed, so the return leg was still an `InitialUEMessage`. Blocked on nextgsim #203 |
| 2 | `namf_event_probe` asserts `REACHABILITY_REPORT` DELIVERED with `reachability == "REACHABLE"` and the registering SUPI, plus the same site's `LOCATION_REPORT` TAC — positive, on bodies | `namf_event_probe.rs:459-505` | **real — implemented, and it SUBSCRIBED successfully in run 36089664496** (`SUBSCRIBED main=sub-b05facd4… control=sub-0af5e084…`) |
| 3 | the assertion is shown able to FAIL with the `handle_service_request_nas` emitters reverted | — | **real — done and MEASURED** (see revert-verification). Corroborated live a **third** time in run 36089664496: with no Service Request reaching the fire point, the probe reported `FAIL: after 240s the AMF delivered 0 of 2 service-request-path notifications for imsi-999700000000001; MISSING ["REACHABILITY_REPORT", "LOCATION_REPORT"]` and exited 1 |
| 4 | the predecessor spec's ceiling section records the coverage as proven, and the struck-through revert-verification row is restored | predecessor's ceiling and revert table | **still NOT done as asked, and for the same reason.** The coverage runs further than ever but still does not pass, so recording it as proven would be false. The ceiling and the struck row are updated to name #203 and to record what this run *did* establish — the resume is now sent |
| — | the issue's stated BLOCKER: "no control surface on `nr-ue`… not expressible today"; needs nextgsim option **A** or **B** | `GnbCliCommandType::UeSuspend` (`nextgsim-gnb/src/tasks.rs`) | **the CONCLUSION was right, and all four DIAGNOSES were wrong.** nextgsim work IS required, but never option A or B. First a duplicated `CliServer` with a wire-version skew (#197 → PR #198, fixed); then an App-task UE registry with no production writer (#199 → PR #200, fixed); then an unreachable UE resume, four gates deep (#201 → PR #202, fixed); now a resume that is sent and never completes (#203). The control surface was never the problem |
| — | the #403 investigation's own claim: "once nextgsim #197 lands, the step should go green with **no further nextgcore change**" | runs 35957375665, 36045644289, 36089664496 | **VOID as a prediction, three times, though the nextgcore half held each time.** #197/#198, #199/#200 and #201/#202 all landed and no nextgcore *production* change was needed for any of them — but the step still fails. This pass does change nextgcore, and honesty requires naming it: not the wiring, but the **diagnostics**, which could not observe the gNB they blamed |

The issue's own partial claim that `nr-ue` "has both triggers but no external control
surface" is **half right**: the triggers exist (`main.rs:354` TUN-data, `:1027`
handler, `:857` Paging), and no *UE* control surface is needed, because the state
change is driven from the **gNB** and the data trigger is driven by **`ping` on the
UE's TUN**, which the UE image already supports (`iputils-ping` is installed in
`nextgsim/Dockerfile.ue-local`, and `docker/rust/e2e-test.sh:523` already pings
through the tunnel).

**Links 1–9 are now VERIFIED LIVE in run 36089664496**, one link further than the previous
run managed. `ue-suspend` was parsed and dispatched, the gNB suspended the UE with a real
`suspendConfig`, the UE entered RRC_INACTIVE, its NAS went CM-IDLE, the TUN write raised
`UplinkData`, `start_service_request` produced a real Service Request, and `initiate_resume`
found an AS context, computed a `resumeMAC-I` and transmitted a conformant
`RRCResumeRequest1` on UL-CCCH1 — each confirmed by its own log line quoted in the outcome
section above.

**Link 10 is where it stops.** The resume is on the air and the connection is never resumed.
Which arm the gNB took is **not established** by that run, because the step captured no gNB
log after the trigger; the improved diagnostic added in this pass distinguishes "never
arrived" from "arrived undecodable" from "I-RNTI unknown" from "MAC mismatch". Filed as
nextgsim #203 with the UE-side half, which is conclusive.

A trap worth naming for the next reader, and it is the inverse of the previous pass's. Before
#202, the gNB's suspend succeeding was **not** evidence that the UE could resume, because the
two ends consulted `as_security_enabled` asymmetrically. Now the UE's resume being *sent* is
**not** evidence that the gNB can *complete* it: transmission and verification are separate
steps with separate inputs, and the `resumeMAC-I` has to match a key derived independently at
the other end. Do not read link 9's success as evidence for link 10 — that is exactly the
mistake the previous three passes made one link earlier each time.

Links 11–14 remain verified by inspection, with link 12's context-survival argument
strengthened this pass (see the link table).

## What this changes

### 1. `namf_event_probe` gains a second, PHASE-SEPARATED assertion

The probe took nine positional arguments and asserted one fire point. It now takes
a **phase** argument and asserts either, sharing all the subscribe/sink/control
machinery:

* `--phase registration` — unchanged behaviour: `REGISTRATION_STATE_REPORT`,
  `LOCATION_REPORT`, `ACCESS_TYPE_REPORT`.
* `--phase service-request` — `REACHABILITY_REPORT` and `LOCATION_REPORT`.

Two probe **processes** rather than one subscribing to five types, and the reason is
that a single process could not discriminate. `LOCATION_REPORT` fires at **both**
sites (deliberately — see the predecessor spec), so one probe watching all five
types would see the registration `LOCATION_REPORT` and could not tell it from the
service-request one. Splitting by phase means the service-request probe subscribes
**after** the registration has completed, so every notification it receives was
fired after that point.

`REACHABILITY_REPORT` is the discriminating type, and it discriminates hard:
`fire_reachability_report` has **exactly one** caller in the whole tree
(`ngap_path.rs:4760`, inside `handle_service_request_nas`). Verified:

```
$ grep -rn "fire_reachability_report" --include="*.rs" src/
src/bins/nextgcore-amfd/src/namf_server.rs:1376:pub fn fire_reachability_report(...)
src/bins/nextgcore-amfd/src/ngap_path.rs:4760:  fire_reachability_report(&state.amf_ue, true);
```

So a delivered `REACHABILITY_REPORT` on the sink **cannot** have come from anywhere
else.

#### The vacuity trap this deliberately avoids

`build_immediate_reports` (`namf_server.rs:1025-1058`) can synthesise a
`REACHABILITY_REPORT` from current state for a subscription carrying
`immediateFlag`. That would be a **vacuous pass**: the report would describe the
AMF's state rather than prove the fire point ran. Two things prevent it:

1. the probe never sets `immediateFlag` (`subscribe()` builds the body without it);
2. even if it did, immediate reports are returned in the **201 response body**
   (`response_body["reportList"]`, `:1013-1016`), **not** POSTed to the callback —
   and the probe only ever asserts on what the **sink** received.

This is the #187 lesson applied: the probe asserts a body **value** that only one
code path can produce, not the absence of an error.

### 2. Three new `Docker E2E` steps, after the registration assertion

They run in this order, and the order is load-bearing:

1. **Subscribe the service-request probe** — and wait for its `SUBSCRIBED` line, not
   a sleep. Started only *after* the registration assertion has passed, so the
   registration's own `LOCATION_REPORT` is already delivered and cannot be mistaken
   for this phase's.
2. **Drive the UE to CM-IDLE, then back** — `nr-cli gnb --exec 'ue-suspend <id>'`,
   assert both ends agree, then `ping` through the TUN, then assert the UE logged a
   Service Request and the AMF logged a Service Accept.
3. **Read the probe's verdict** — same `/tmp/probe.rc` mechanism as the registration
   phase, for the same reason (a detached `exec` discards its exit status, and a step
   that cannot read the verdict proves nothing).

#### `nr-cli` has to get into the gNB container

`nextgsim/Dockerfile.gnb-local` ships only `nr-gnb`, and the CLI server binds
**`127.0.0.1`** (`cli_server.rs:24,285`) and is discovered through a proc-table file
under `/tmp/nextgsim.proc-table/` (`:21`). Both facts force the same conclusion: the
command must be issued **from inside the gNB container**. So `Dockerfile.builder`
now also builds `nr-cli` (it is already a workspace member,
`nextgsim/Cargo.toml:17`) and the E2E step `docker cp`s it in — exactly the pattern
the two existing probes use, and it adds nothing to nextgsim.

The `ue_id` is **read from `ue-list`** rather than assumed to be 1: it is the gNB's
internal identifier, and hardcoding it would make the step fail for a reason
unrelated to the wiring if allocation ever changed.

#### Why grep strings are exact `info!` text

PR #402 found its own middle-step grep for `NG Setup Response` also matched a
`warn!` about an unexpected PDU *while waiting* for one. Every string added here was
read from source, not paraphrased, and each is checked against the **failure** text
that could also satisfy it:

| assertion | exact string | source | the failure that must NOT match |
|---|---|---|---|
| gNB suspended the UE | `suspended to RRC_INACTIVE: I-RNTI=` | `nextgsim-gnb/src/rrc/connection.rs:764` | `could not be suspended; releasing instead` (`rrc/task.rs:1817`) — the fallback that would put the UE in RRC_IDLE and make the return leg an `InitialUEMessage`. Asserted **absent**. |
| UE reached RRC_INACTIVE | `Suspended to RRC_INACTIVE: I-RNTI=` | `nextgsim-ue/src/rrc/task.rs:3279` | `treating it as a release` (`treating it as a release`, `rrc/task.rs:3267`) |
| UE went CM-IDLE | `RRC connection released` | `nextgsim-ue/src/main.rs:848` | — |
| UE sent a Service Request | `Sending Service Request (` | `nas/mm/orchestrator.rs:2569` | — |
| the UE's request was ACCEPTED | `Service Accept received` | `nas/mm/orchestrator.rs:2585` | a **Service Reject** is the #9 arm; if the return leg were an `InitialUEMessage` this is the line that would be missing |
| the AMF ran the fire point | `Service Accept sent to UE` | `ngap_path.rs:4688` | — |

The gNB-side and UE-side suspension strings differ in case (`suspended` vs
`Suspended`) because they are two different log statements in two different crates;
both are matched with `grep -F` on the exact text.

Logs are captured to a **file** and the file is grepped, never
`docker compose logs | grep -q` — under `pipefail`, `grep -q` exits on first match,
`docker logs` dies with `SIGPIPE` and the pipeline reports failure, turning a real
match into a false negative. `e2e-test.sh` records the same rule.

## Revert-verification: the assertion PROVABLY bites

The claim under test is that the new assertion fails when the wiring is absent — the
thing #187's first CI attempt could not do. Verified by **running the probe against a
stand-in for the AMF's `namf-evts` surface** that delivers exactly the report set each
scenario names, which isolates the probe's verdict from a 25-minute Docker bring-up.
The stand-in was a throwaway example built in-tree, run, and **deleted** — it is not
committed, because a permanent fake AMF is the loopback-peer mistake the owner
refused, one layer up.

Observed, verbatim:

| scenario modelled | probe exit | probe's own message |
|---|---|---|
| **wired** (both emitters present) | **0** | `PASS` — with `ok /supi`, `ok /reachability == "REACHABLE"`, `ok .../mcc == "999"`, `ok .../mnc == "70"`, `ok .../tac == "0001"` |
| **the two `handle_service_request_nas` emitters reverted** (nothing fires) | **1** | `after 10s the AMF delivered 0 of 2 service-request-path notifications for imsi-999700000000001; MISSING ["REACHABILITY_REPORT", "LOCATION_REPORT"]` |
| **`fire_reachability_report(.., false)`** (fires, wrong value) | **1** | `/reachability is Some("UNREACHABLE"), expected "REACHABLE"` |
| **TAC expectation moved to the default `0000`** (proves the location value discriminates) | **1** | `/location/nrLocation/tai/tac is Some("0001"), expected "0000"` |
| **the registration phase fed the service-request report set** (proves the phases are not interchangeable) | **1** | `delivered 2 of 3 registration-path notifications; MISSING ["REGISTRATION_STATE_REPORT", "ACCESS_TYPE_REPORT"]` |

Rows 2 and 3 are the ones that matter: the assertion fails **both** when nothing
arrives **and** when something arrives carrying the wrong value. A delivery-only
assertion would have passed row 3, and a log-grep for the absence of an error would
have passed row 2 — which is precisely #187's vacuous-green failure.

Row 5 shows the two phases discriminate rather than both riding one wire, which is the
sibling-stays-green property the predecessor spec records for its own pairs.

### The one claim NOT proven by the above, stated plainly

`ue-suspend` replaced with `ue-release` is reasoned, not measured: the CM-IDLE step
would still pass (the UE does go idle), but the UE would log a Service **Reject** and
`Service Accept received` would never appear, so the step fails at the named middle
assertion rather than at the probe. That is read off `handle_initial_ue_message`'s
unconditional cause-#9 arm (`ngap_path.rs:1689`) rather than observed, and it is
labelled as such rather than presented as a run.

The middle assertions cannot be revert-verified outside a full bring-up at all: they
assert on nextgsim's log output, and nextgsim is read-only here. What makes them
trustworthy instead is that every string was **read from nextgsim's source** and each
is paired with the failure text that could also have satisfied a looser grep — the
table in the previous section.

## Ceilings, stated rather than implied

0. **The headline one: this does not yet prove the fire point.** Blocked on
   **nextgsim #203** (the UE sends a conformant `RRCResumeRequest1` and the resume is never
   completed, so the UE re-establishes and the return leg is an `InitialUEMessage`). The
   three earlier blockers are **fixed** and all three fixes are confirmed live in run
   36089664496: nextgsim #197 (`nr-cli` could not discover the gNB) by PR #198, nextgsim
   #199 (the App-task UE registry had no production writer) by PR #200, and nextgsim #201
   (the resume was unreachable, four gates deep) by PR #202. The steps keep
   `continue-on-error: true` and self-activate when the resume completes. Restated here
   rather than left to the top section, because a reader who skims to the ceilings must not
   come away thinking the coverage exists.

   **And the trap that goes with it:** because these steps are `continue-on-error`,
   `Docker E2E` reported conclusion `success` in runs 35957375665, 36045644289 **and**
   36089664496 while two steps exited 1 in each, with a green tick beside every step in
   `gh run view`. A green tick on that job is **not** evidence for this fire point; only the
   step's own `PASS:` / `FAIL:` line in `--log` output is. Remove the tolerance the moment
   the resume completes, because a step that cannot fail the job is not coverage.

   **A second-order trap, restated one link along:** before #202, the gNB suspending
   successfully did not imply the UE could resume (the two ends consulted
   `as_security_enabled` asymmetrically). Now the UE *sending* a resume does not imply the
   gNB can *complete* it: transmission and verification are separate steps over
   independently derived keys. Do not read link 9's success as evidence for link 10. This
   trap has now recurred at four consecutive links, which is the single most transferable
   lesson in this spec.

   **A third trap, and this one was ours:** run 36089664496's step blamed nextgsim #201 in
   its error text while holding **no evidence at all** about the gNB, because it captured
   the gNB log before sending the trigger and never re-read it. A diagnostic that cannot
   observe the component it names will misattribute. Fixed in this pass.

1. **A Service Request in an `InitialUEMessage` is always rejected with cause #9.**
   `handle_initial_ue_message` (`ngap_path.rs:1689` for the cause-#9 arm) has no 5G-S-TMSI
   lookup, although the gNB does send the `fiveGSTmsi` IE and nextgcore *has* a GUTI
   resolver (`amf_ue_find_by_guti`, used by the registration path). So a
   UE that goes fully **RRC_IDLE** cannot resume service without re-registering.
   TS 24.501 §5.6.1.1 expects a CM-IDLE UE with a valid 5G-GUTI to be recoverable,
   so this is a genuine gap. It is **not** worked around here: this spec proves the
   fire point over the RRC_INACTIVE path, which is a real 3GPP path in its own
   right (TS 38.331 §5.3.13), and the `InitialUEMessage` gap is left for its own
   issue rather than folded into this one.

2. **The paged (MT) arm of the Service Request is still unproven.**
   `NasMessage::Paging` → `MobileTerminatedServices` (`nextgsim-ue/src/main.rs:857-870`)
   reaches the same handler, and nextgcore has `initiate_paging_for_idle_ue`. This
   E2E drives the **MO data** arm only. Both arms converge on
   `handle_service_request_nas`, so the fire point is proven; the *paging* trigger
   is not.

3. **`CONNECTIVITY_STATE_REPORT` fires from this site too** (`ngap_path.rs:4759`) and
   is not asserted. Subscribing to it would not discriminate: it fires at the N1
   release as well (`start_reachability_supervision`, `:6317`), and the suspension
   deliberately does not tell the AMF, so the IDLE→CONNECTED report is the only one
   this scenario produces — but asserting it adds no discrimination that
   `REACHABILITY_REPORT` does not already give, since the latter has a single caller.

## Test isolation and workspace hygiene

No Rust unit tests are added: the change is to an `example` binary (which has no
test harness by design — it needs a live AMF and a live NG-RAN) and to CI YAML. The
existing suite was unchanged at **6833 passing** when this spec was first written,
**6898** on the first re-dispatch, and **6902** at both `643bb71` and `b5b4792` (the growth
is other issues' work, not this one's — every re-dispatch pass changes only `ci.yml` and the
specs, so no Rust is touched at all). CI's own `Check`, `Format`, `Clippy` and `Test` jobs
all passed on run 36089664496, which is the whole-workspace gate for a diff of this shape.

**On that number, because it is easy to quote wrongly:** `cargo test --workspace` reports
**6902**, and the CI `Test` job's *second* step (`-p nextgcore-easdfd --features dns-udp`,
which the default build cannot see) adds **51**. So "6953" is the two steps summed, not the
workspace figure — measured here rather than carried forward, because an earlier hand-off
quoted the combined total as the workspace one.

This pass's `ci.yml` diff is **diagnostics only** — it adds a post-resume gNB log capture
to the failure branch and corrects comments. It changes no assertion, no threshold and no
`continue-on-error`, so it cannot turn a failing fire point into a passing one. Verified by
parsing the workflow and running `bash -n` over every `run:` block.

The probe's argument parsing moved from nine positional arguments to a leading
phase selector plus the existing positional set. It is an `example`, so there is no
external caller to break; both call sites in `ci.yml` are updated in the same
commit.
