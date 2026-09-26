# Prove the SERVICE REQUEST Namf fire point against nextgsim's real gNB and UE

**Issue:** nextgcore #403 (the ceiling stated by PR #402 / #397) — **the fire point is now
PROVEN and the coverage BLOCKS.**
**Verified against:** nextgcore `main` @ `f8b524e`, nextgsim `main` @ `0cb611b`
(read-only checkout). Originally written against nextgcore `0dc01e4`; re-dispatched
after nextgsim PR #198 landed, then after PR #200, then after PR #202, then after PR #204.
The sections below are corrected to the fifth and final run,
[36270918151](https://github.com/NextgCoreLab/nextgcore/actions/runs/36270918151) —
the first in which the whole chain completed.
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

## OUTCOME FIRST: the fire point is PROVEN, after FIVE blockers in series

All five blockers this spec named are **resolved**, and run 36270918151 is the first in which
the whole chain completed. Every fact below is measured, not reasoned.

```
PASS: imsi-999700000000001 went CM-IDLE and came back through a REAL Service Request over
nextgsim's gNB, and the AMF DELIVERED REACHABILITY_REPORT (REACHABLE) and LOCATION_REPORT
(mcc 999 mnc 70 tac 0001) from `handle_service_request_nas` to the subscribed callback, and
delivered NOTHING to the control subscription for imsi-999709999999999
```

**The `continue-on-error` tolerance is removed from all three `#403` steps in this pass**, and
that removal is what closes the issue: a step that cannot fail the job is not coverage. The
assertion is now known to go **red** on a real bring-up (three runs) and **green** when the
request genuinely arrives (this one) — red-then-green against the same live AMF is the whole
argument for trusting it.

**The one line that settles it is the AMF's, and it is the `amf_ue_ngap_id` that matters:**

```
nextgcore-amf | Service Accept sent to UE 2 (protected)
```

`2` is the id `ue-list` reported **before** the suspension (`amf_ngap_id: 2`). So the return
leg arrived on the *surviving* NGAP context — the `UplinkNASTransport` path — and not as a
fresh `InitialUEMessage`, which is the cause-#9 arm where the fire point never runs. In the
four previous runs the second `InitialUEMessage` and its `Unhandled NAS message type 0x8b` are
both **absent** here.

The shape of this issue remains its most useful lesson: **five defects in series, each masking
the next.** Discovery (#197), an unwritten CLI registry (#199), an unreachable resume (#201),
a resume sent but never completed (#203), and each invisible until the one in front of it was
fixed. Four consecutive passes predicted "the step should go green with no further nextgcore
change". All four were wrong, for four different reasons — even though the *conclusion* they
shared (the remaining work is nextgsim's) was right every time, and no nextgcore production
change was ever in fact required. **A serial chain tells you nothing about its own length.**
The fifth prediction was deliberately not made, and that was the right call.

**And one honest correction to this repo's own work, kept because the step it fixed is what
named the fifth link.** Run 36089664496 could not say *why* the resume failed, and that was a
defect in **this** spec's CI step rather than a finding about nextgsim: the drive step captured
the gNB log *before* sending the trigger and never re-read it, so the gNB's entire reaction to
the resume was missing from the evidence. Fixed in #413. The lesson generalises: a diagnostic
that cannot observe the component it is about to blame will misattribute.

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

### Blocker 4 (the resume never completed): FIXED by nextgsim #204, and it was the last

What run 36089664496 measured: no `RRC resume complete`, no `Service Accept received`, and
~2s later a **new** RRC connection, so nextgcore saw a second `InitialUEMessage` with a fresh
`ran_ue_ngap_id`:

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

**The cause was a KgNB derivation skew on the UE, and it was entirely nextgsim's.**
`send_security_mode_complete` called `derive_kgnb_for_as_security` **after** `protect_uplink`
had already sent the Security Mode Complete — and `protect_uplink` calls
`increment_uplink_count`. So a UE whose SMComplete went out at COUNT 0 derived its KgNB at
COUNT 1. Measured with the defect restored:

```
UE  KgNB [7e,da,8d,ed,d4,5d,18,0c,...]   (derived at COUNT 1)
AMF KgNB [53,05,6a,1e,e2,fe,56,65,...]   (derived at COUNT 0)
```

TS 33.501 §6.8.1.1.2.3 requires the SMC complete to carry "the start value of the uplink NAS
COUNT that is used as freshness parameter in the KgNB derivation", and §6.8.1.1.2.2 names "the
uplink NAS COUNT of the most recent NAS Security Mode Complete" — the message's **own
pre-increment** COUNT. **nextgcore was already conformant**, verified at both sites in this
repo: `nas_security.rs` commits the candidate COUNT reconstructed from the received message's
own SQN octet (`amf_ue.ul_count = candidate`, only after MAC verification), and
`ngap_path.rs:4363` derives KgNB from that committed value. The off-by-one was the UE's.

Why it stayed hidden for four runs: KgNB never crosses the air (§6.2 derives it independently
at both ends from KAMF), so nothing on the wire revealed the skew, and it was **latent rather
than new** — before #202 the UE refused the SMC under `as_security_enabled: false` and
discarded the keys, so nothing ever compared the two copies. #202 made `K_RRCint` the key a
`resumeMAC-I` is verified with, which is the first thing ever to compare them. Every AS key
therefore differed, the `resumeMAC-I` of TS 38.331 §5.3.13.3 could never verify, the gNB
answered with silence, and the UE fell back per §5.3.13.5.

Filed as **nextgsim #203** and **FIXED by nextgsim PR #204** (merged, `0cb611b`), which makes
`derive_kgnb_for_as_security` take the COUNT as a parameter captured by the caller *before* the
send advances it — a signature that cannot silently regress to reading post-increment state.

**Note the trap, which is the most transferable thing in this spec:** the AMF-side symptom (a
second `InitialUEMessage` carrying an unwrappable ciphered byte) was *identical* across **three
different root causes**. A reader comparing only the AMF log would have concluded #201/#202 had
not worked. It had. **Never diagnose this path from the AMF log alone.**

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

### What was ruled out — and the hypothesis that survived, which turned out to be right

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

Offered as a **hypothesis, not a finding** — and **it was correct**, which is the one place in
this five-run history where a prediction held. nextgsim #204 confirmed the key was the
disagreeing term and named the mechanism the hypothesis had not: not *which* COUNT the AMF
uses, but that the UE read its own COUNT one increment too late. Worth recording *why* it was
worth stating: it was falsifiable (it predicted a specific log line), it was labelled as a
hypothesis rather than smuggled in as a finding, and it narrowed the search to one term out of
five. The four terms ruled out above stayed ruled out.

### A nextgcore-side hazard these runs exposed — now REMOVED, but keep reading

Runs 35957375665, 36045644289 **and** 36089664496 all reported job conclusion **`success`**
while the drive step and the probe-verdict step genuinely exited 1 — and `gh run view --job`
printed a **green tick beside every step** in all three. That is `continue-on-error` doing
exactly what it says: the summary views derive from the *tolerated* status, not the exit code.
This is the same family as the vacuous-green failure #187 recorded.

**The tolerance is removed in this pass, so the hazard is gone** — a failing `#403` step now
fails the job, and the tick means what it appears to mean. The warning is kept because the
trap is permanent even though this instance of it is not: **any** `continue-on-error` step
reads as covered while proving nothing, and the only trustworthy evidence for such a step is
its own `PASS:`/`FAIL:` line in `gh run view --job <id> --log`.

**So the status of the SERVICE REQUEST fire point is: PROVEN by automated test, by a step that
can fail.** What this change delivers is (a) the complete machinery, now exercised end to end;
(b) a probe assertion measured to fail when nothing arrives (three live runs) **and** to pass
when it does (this run); (c) the tolerance removed, which is what makes (a) and (b) into
coverage rather than decoration; and (d) a diagnostic that can see the component it blames,
retained for the regression case. #403's premise is answered three times over: CM-IDLE is
reached, the return is originated, **and** it now completes.

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

## The route, and why it was right — now confirmed end to end

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

Every link below was read in the read-only nextgsim checkout at `0cb611b`. The **status**
column records what run 36270918151 established, so "inspection" and "live" are never
conflated — and **all 14 are now LIVE**, which is the first time that has been true:

| # | link | site | status after run 36270918151 |
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
| 10 | `RRCResumeRequest1` (UL-CCCH1) → gNB decodes it by type, looks the I-RNTI up, verifies `resumeMAC-I` against the **stored** context | dispatch `rrc/task.rs:521`; handler `:1736`; verification `rrc/connection.rs:803-885` | **LIVE as of nextgsim #204** — the `resumeMAC-I` verifies once both ends derive KgNB at the same NAS COUNT. This was blocker 4, and no amount of UE-side evidence could have settled it: the MAC is checked against a key derived independently at the far end |
| 11 | `RRCResumeComplete` carries the pending NAS | `nextgsim-ue/src/rrc/task.rs` (`initial_nas_pdu.take()`) | **LIVE** |
| 12 | gNB forwards it as **`UplinkNASTransport`** (the NGAP context still has `amf_ue_ngap_id`) | `rrc/task.rs:1828-1853` → `ngap/task.rs:2595-2660` | **LIVE, and this is the load-bearing observation:** the AMF answered `Service Accept sent to UE 2` — id `2` being the **pre-suspension** `amf_ngap_id` from `ue-list`. The surviving NGAP context was reused, so the leg was an `UplinkNASTransport`; a fresh id would have meant an `InitialUEMessage` |
| 13 | nextgcore dispatches `SERVICE_REQUEST` from `handle_uplink_nas_transport`, deciphering the NAS first | `ngap_path.rs:1718` (handler), `:1807-1850` (`nas_5gs_security_decode`), `:1984-1991` (dispatch) | **LIVE** — and note this path **does** unwrap a ciphered Service Request, which is exactly what the `InitialUEMessage` path cannot do; the `0x8b` of the four failed runs was that failure showing |
| 14 | `handle_service_request_nas`: context present → Service Accept egresses → **the emitters fire** | `ngap_path.rs:4634` (handler), `:4688` (`Service Accept sent to UE`), emitters at `:4759-4762` | **LIVE — this is what #403 exists to prove.** `Service Accept sent to UE 2 (protected)`, then `REACHABILITY_REPORT (REACHABLE)` and `LOCATION_REPORT (mcc 999 mnc 70 tac 0001)` delivered to the probe's callback |

Link 14 is the one this issue exists to prove, and it is now proven. `has_context` is
`security_context_available && registered` (`ngap_path.rs:4647`), and both survive the
suspension because nextgcore was never told about it — the `ue_auth_state` entry
is untouched. That reasoning was only ever inspection; the run has now confirmed it.

## Criterion-by-criterion, re-checked at `f8b524e` after nextgsim #204

| # | criterion as filed | site | verdict |
|---|---|---|---|
| 1 | the `Docker E2E` job drives a registered UE to CM-IDLE and back through a Service Request, against nextgsim's real gNB | the three `#403` steps of `docker-e2e` in `ci.yml` | **DONE, both halves, LIVE.** Run 36270918151 suspended a real UE (`ue_id: 0`), both ends agreed, its NAS went CM-IDLE, a TUN write originated a real Service Request, the UE resumed from RRC_INACTIVE and the AMF answered `Service Accept sent to UE 2` — on the **pre-suspension** `amf_ue_ngap_id`, so the return leg was an `UplinkNASTransport`. The tolerance is removed, so the step now blocks |
| 2 | `namf_event_probe` asserts `REACHABILITY_REPORT` DELIVERED with `reachability == "REACHABLE"` and the registering SUPI, plus the same site's `LOCATION_REPORT` TAC — positive, on bodies | `namf_event_probe.rs:459-505` | **DONE, and the assertions were EXERCISED green** in run 36270918151: `ok /supi`, `ok /reachability == "REACHABLE"`, `ok /location/nrLocation/tai/plmnId/mcc == "999"`, `mnc == "70"`, `tac == "0001"`, with NOTHING delivered to the negative-control subscription |
| 3 | the assertion is shown able to FAIL with the `handle_service_request_nas` emitters reverted | — | **DONE and MEASURED, now both ways.** Red live in runs 35957375665, 36045644289 and 36089664496 (`MISSING ["REACHABILITY_REPORT", "LOCATION_REPORT"]`, exit 1); green live in 36270918151. Red-then-green against the same AMF is what makes the assertion trustworthy rather than merely present |
| 4 | the predecessor spec's ceiling section records the coverage as proven, and the struck-through revert-verification row is restored | predecessor's ceiling and revert table | **DONE at last, because the condition is finally met.** The ceiling is marked **LIFTED** and the struck row is **restored**, both citing run 36270918151. The live-versus-stand-in distinction is kept explicit: failure path and passing path are live, the **wrong-value** variants remain stand-in-only since provoking them needs the AMF mutated |
| — | the issue's stated BLOCKER: "no control surface on `nr-ue`… not expressible today"; needs nextgsim option **A** or **B** | `GnbCliCommandType::UeSuspend` (`nextgsim-gnb/src/tasks.rs`) | **the CONCLUSION was right, and all five DIAGNOSES were wrong.** nextgsim work WAS required, but never option A or B. A duplicated `CliServer` with a wire-version skew (#197 → PR #198); an App-task UE registry with no production writer (#199 → PR #200); an unreachable UE resume, four gates deep (#201 → PR #202); a KgNB derived from the wrong NAS COUNT (#203 → PR #204). All fixed. The control surface was never the problem |
| — | the #403 investigation's own claim: "once nextgsim #197 lands, the step should go green with **no further nextgcore change**" | runs 35957375665, 36045644289, 36089664496, 36270918151 | **VOID as a prediction four times, then finally true on the fifth.** No nextgcore *production* change was ever needed — the nextgcore half held throughout — but the step failed four times anyway. The #204 author declined to make a fifth prediction, which was the correct response to a four-for-four record. **The lesson is about serial chains, not about this chain:** being right that the next link is elsewhere tells you nothing about how many links remain |

The issue's own partial claim that `nr-ue` "has both triggers but no external control
surface" is **half right**: the triggers exist (`main.rs:354` TUN-data, `:1027`
handler, `:857` Paging), and no *UE* control surface is needed, because the state
change is driven from the **gNB** and the data trigger is driven by **`ping` on the
UE's TUN**, which the UE image already supports (`iputils-ping` is installed in
`nextgsim/Dockerfile.ue-local`, and `docker/rust/e2e-test.sh:523` already pings
through the tunnel).

**All 14 links are now VERIFIED LIVE in run 36270918151.** `ue-suspend` was parsed and
dispatched, the gNB suspended the UE with a real `suspendConfig`, the UE entered RRC_INACTIVE,
its NAS went CM-IDLE, the TUN write raised `UplinkData`, `start_service_request` produced a
real Service Request, `initiate_resume` computed a `resumeMAC-I`, the gNB **verified** it, the
`RRCResumeComplete` carried the NAS, the gNB forwarded it as an `UplinkNASTransport` on the
surviving NGAP context, and `handle_service_request_nas` egressed a Service Accept and fired
the emitters — each confirmed by its own log line quoted in the outcome section above.

**The trap that governed the four failed passes, stated once more because it is the reusable
part.** At every stage, the last link observed to work was mistaken for evidence about the next
one. Before #202, the gNB's suspend succeeding was not evidence the UE could resume (the two
ends consulted `as_security_enabled` asymmetrically). After #202, the UE's resume being *sent*
was not evidence the gNB could *complete* it — transmission and verification are separate
steps with separate inputs, and the `resumeMAC-I` must match a key derived **independently at
the other end**, which is exactly where blocker 4 lived. The general form: **in a chain of
independently-implemented peers, link N passing constrains link N+1 only if they share an
input.** A key derived separately at both ends shares none.

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

**All three now BLOCK** (no `continue-on-error`), as of run 36270918151. They run in this
order, and the order is load-bearing:

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

**Which of these rows are now LIVE rather than stand-in, as of run 36270918151.** Row 1
(**wired → PASS**) and row 2 (**nothing arrives → FAIL**) have both executed against the real
AMF on a full compose bring-up — row 2 in runs 35957375665, 36045644289 and 36089664496, row 1
in 36270918151, with the same five `ok` assertions the stand-in produced. Rows 3, 4 and 5
remain **stand-in-only**, because provoking them requires mutating the AMF or the probe's own
expectations, which no CI run does. That distinction is kept rather than averaged away: the
strongest claim the evidence supports is that the assertion goes red when the notifications are
absent and green when they arrive correct, both live, and that it additionally discriminates on
*values* against a stand-in.

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

0. **The headline ceiling is DISCHARGED: the fire point IS proven.** Run 36270918151 drove the
   whole chain and the probe printed `PASS:`, and the `continue-on-error` tolerance is removed
   from all three `#403` steps, so the coverage can fail the job. All **five** nextgsim
   blockers are fixed and every fix is confirmed live here: #197 (`nr-cli` could not discover
   the gNB) by PR #198, #199 (the App-task UE registry had no production writer) by PR #200,
   #201 (the resume was unreachable, four gates deep) by PR #202, and #203 (the UE derived
   KgNB from the wrong NAS COUNT) by PR #204.

   **The traps are kept, because they outlive the ceiling that occasioned them.**

   **Trap 1 — a tolerated step reads as covered while proving nothing.** `Docker E2E` reported
   conclusion `success` in runs 35957375665, 36045644289 **and** 36089664496 while two steps
   exited 1 in each, with a green tick beside every step in `gh run view`: summary views derive
   from the *tolerated* status, not the exit code. Gone here now that the tolerance is off, but
   the rule stands for any `continue-on-error` step — only its own `PASS:`/`FAIL:` line in
   `--log` is evidence, because **a step that cannot fail the job is not coverage.**

   **Trap 2 — link N passing does not constrain link N+1 unless they share an input.** Before
   #202, the gNB suspending successfully did not imply the UE could resume (the two ends
   consulted `as_security_enabled` asymmetrically). After #202, the UE *sending* a resume did
   not imply the gNB could *complete* it: transmission and verification are separate steps over
   **independently derived** keys, which is exactly where blocker 4 lived. This trap recurred at
   four consecutive links and is the single most transferable lesson in this spec.

   **Trap 3 — and this one was ours.** Run 36089664496's step blamed nextgsim #201 in its error
   text while holding **no evidence at all** about the gNB, because it captured the gNB log
   before sending the trigger and never re-read it. A diagnostic that cannot observe the
   component it names will misattribute. Fixed in #413, and retained now that the step passes,
   because it is what will name the arm on a regression.

   **Trap 4 — the AMF-side symptom was identical across three different root causes** (a second
   `InitialUEMessage` carrying an unwrappable ciphered byte). Never diagnose this path from the
   AMF log alone.

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

**This pass's `ci.yml` diff removes the three `continue-on-error: true` lines and corrects
comments. Nothing else.** It adds no assertion, relaxes no threshold and changes no `run:`
logic — so it cannot have manufactured the pass: the step's logic was byte-identical when it
was dispatched, and the tolerance came off only **after** reading the passing log. That
ordering matters, and it is the opposite of the tempting one. Verified by parsing the workflow
(`continue-on-error` count across all jobs: **0**) and running `bash -n` over every `run:`
block.

The previous pass's diff (#413) was diagnostics-only for the same reason: it added the
post-resume gNB log capture to the failure branch without touching an assertion, so it could
not turn a failing fire point into a passing one either. Both of its grep sets were checked
against nextgsim's real log strings — `resumeMAC-I verified` (`gnb/src/rrc/connection.rs:871`),
`RRC Resume Request from` (`rrc/task.rs:1770`), `Discarding an undecodable` (`:1762`),
`refused:` (`:1794`), `does not match the` (`connection.rs:844`) and `Uplink RRC:`
(`rls/task.rs:704`) — because a diagnostic that greps for text nobody emits prints "(nothing)"
and misattributes by silence.

The probe's argument parsing moved from nine positional arguments to a leading
phase selector plus the existing positional set. It is an `example`, so there is no
external caller to break; both call sites in `ci.yml` are updated in the same
commit.
