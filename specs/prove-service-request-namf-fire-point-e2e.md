# Prove the SERVICE REQUEST Namf fire point against nextgsim's real gNB and UE

**Issue:** nextgcore #403 (the ceiling stated by PR #402 / #397)
**Verified against:** nextgcore `main` @ `98603b2`, nextgsim `main` @ `6ec9d47`
(read-only checkout). Originally written against nextgcore `0dc01e4`; re-dispatched
after nextgsim PR #198 landed, and the sections below are corrected to that run.
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

## OUTCOME FIRST: the fire point is still UNPROVEN, but the blocker has MOVED

The first blocker — `nr-cli` could not discover the gNB — is **resolved**. The
coverage is **still not live**, because a second, distinct nextgsim defect sits behind
it. Both facts are measured, not reasoned.

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

### Blocker 2 (an empty UE registry): the current one, filed as nextgsim #199

What that run got instead, in the same step that had just logged
`PDU Session 1 is now ACTIVE (IPv4: Some([10, 45, 0, 2]))`:

```
$ nr-cli gnb --exec 'ue-list'
ues: []
```

That is `handle_ue_list` speaking — the gNB's own code, not a discovery failure — so
discovery, framing, dispatch and the response path all agree. The answer is simply
**wrong**: that UE exists.

Root cause, read in the read-only checkout. `handle_ue_list` and `handle_ue_suspend`
both read `GnbCmdHandler.ue_contexts`, borrowed from `AppTask.ue_contexts`
(`nextgsim-gnb/src/app/task.rs:37`, passed at `:115`). Its only writer,
`AppTask::update_ue_context` (`:245`), has **no production caller in the whole tree**
— every call site is a unit test, including PR #198's own
(`tests/src/gnb_cli_reachability.rs:96`, which seeds the registry by hand). The reason
is structural: `AppMessage` has two variants and neither carries UE state
(`nextgsim-gnb/src/tasks.rs:181-186`), and the gNB's single `app_tx.send`
(`nextgsim-gnb/src/ngap/task.rs:4669`) sends only `StatusType::NgapIsUp`. The real
contexts live in `RrcTask.ue_manager` (`rrc/task.rs:132`); the App task holds a mirror
that is never filled.

So `ue-suspend` cannot fire either, and this is the load-bearing consequence:
`handle_ue_suspend` returns early on the empty map
(`app/cmd_handler.rs:277-279`) and the dispatch to RRC is gated on
`!response.is_error` (`app/task.rs:137-152`), so `RrcMessage::SuspendUe` is
**unreachable in production**. The RRC-side implementation behind it is fine and
unit-tested; it has no reachable trigger.

Filed as **nextgsim #199**. That is a nextgsim defect, so the three steps keep
`continue-on-error: true` rather than going red — reporting a sibling repo's defect as
a nextgcore regression would be worse than stating the ceiling.

### A nextgcore-side hazard this run exposed

Run 35957375665 reported job conclusion **`success`** while the drive step and the
probe-verdict step both genuinely exited 1. That is `continue-on-error` doing exactly
what it says, and it means **a green tick on `Docker E2E` does not mean this fire
point is proven**. The block comment in `ci.yml` now says so explicitly, because the
next reader's most likely error is trusting the tick. This is the same family as the
vacuous-green failure #187 recorded.

**So the honest status of the SERVICE REQUEST fire point is: still unproven by
automated test.** What this change delivers is (a) the complete machinery, which
self-activates the moment nextgsim #199 lands, with no further nextgcore change; (b) a
probe assertion **measured** to fail when the emitters are reverted; and (c) the
precise, evidenced identification of the remaining missing link — which is what #403
actually asked for when it said "if CM-IDLE genuinely cannot be reached from outside
without new nextgsim code, that is a legitimate finding: state it precisely".

Note the shape of the correction, now twice over. #403 claimed the blocker was a
missing **`nr-ue` control surface**: wrong. The #403 investigation then named a
missing **proc-table registration**: right that it blocked, but it was a duplicated
`CliServer` with a version skew, and fixing it revealed that the lever was gated on a
**second** unwritten registry. The commands involved (`ue-release`, `ue-suspend`,
`ue-list`, `xn-path-switch`) all exist and are unit-tested; none of them has ever been
reachable-and-functional in production.

Everything else in the chain was verified in run 35957375665: the gNB completed NG
Setup, the UE registered, got a PDU session (`PDU Session 1 is now ACTIVE`), the
registration-phase Namf assertion **passed** on notification bodies, and the
service-request probe **SUBSCRIBED** successfully. The chain breaks at exactly one
link, and it is the suspend lever.

## The route, and why it is right once #199 lands

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
Request in an `InitialUEMessage` (`ngap_path.rs:1604-1620`):

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

Every link below was read in the read-only nextgsim checkout:

| # | link | site |
|---|---|---|
| 1 | `ue-suspend 1` parsed | `nextgsim-gnb/src/app/cmd_handler.rs:416-432` |
| 2 | → `RrcMessage::SuspendUe` (**not** NGAP) | `nextgsim-gnb/src/app/task.rs:134-150` |
| 3 | gNB suspends: needs `reestablishment_security`, which Initial Context Setup supplied | `rrc/connection.rs:650-676`; set from `ngap/task.rs:948-960`, called by `activate_as_security` ← `handle_initial_context_setup_request` (`:1022`) |
| 4 | gNB sends `RRCRelease` **with** `suspendConfig`; stores the context by I-RNTI | `rrc/connection.rs:690-734` |
| 5 | UE reads the `suspendConfig` → `RRC_INACTIVE`, and tells NAS the connection is gone | `nextgsim-ue/src/rrc/task.rs:2770-2845` |
| 6 | NAS switches to **CM-IDLE** on `RrcConnectionRelease` | `nextgsim-ue/src/main.rs:847-850` |
| 7 | a TUN write raises `UplinkData` → `NasMessage::InitiateServiceRequest { psi }` | `nextgsim-ue/src/tun/task.rs:196-221`; `main.rs:345-356` |
| 8 | NAS is registered **and** idle → `start_service_request`, Uplink data status from the real PSI | `main.rs:1073`; `nas/mm/orchestrator.rs:2533-2560` |
| 9 | the Service Request NAS PDU goes to RRC; state is `Inactive`, so the **MO resume** arm runs and the NAS is **kept to ride the Complete** | `rrc/task.rs:3802-3808` |
| 10 | `RRCResumeRequest1` (UL-CCCH1) → gNB verifies `resumeMAC-I` against the **stored** context | `rrc/task.rs:2942-2962`; `rrc/connection.rs:773-845` |
| 11 | `RRCResumeComplete` carries the pending NAS | `nextgsim-ue/src/rrc/task.rs:2349` (`initial_nas_pdu.take()`) |
| 12 | gNB forwards it as **`UplinkNASTransport`** (the NGAP context still has `amf_ue_ngap_id`) | `rrc/task.rs:1712-1722` → `ngap/task.rs:2515-2560` |
| 13 | nextgcore dispatches `SERVICE_REQUEST` from `handle_uplink_nas_transport` | `ngap_path.rs:1860-1866` |
| 14 | `handle_service_request_nas`: context present → Service Accept egresses → **the three emitters fire** | `ngap_path.rs:4489`, emitters at `:4580-4584` |

Link 14 is the one this issue exists to prove. `has_context` is
`security_context_available && registered` (`:4500-4504`), and both survive the
suspension because nextgcore was never told about it — the `ue_auth_state` entry
is untouched.

## Criterion-by-criterion, re-checked at `98603b2` after nextgsim #198

| # | criterion as filed | site | verdict |
|---|---|---|---|
| 1 | the `Docker E2E` job drives a registered UE to CM-IDLE and back through a Service Request, against nextgsim's real gNB | steps 11-13 of `docker-e2e` in `ci.yml` | **real — machinery implemented and DISPATCHED, still BLOCKED, now on nextgsim #199.** In run 35957375665 the step reached the gNB (discovery fixed) and got `ues: []`, so the suspension never happened |
| 2 | `namf_event_probe` asserts `REACHABILITY_REPORT` DELIVERED with `reachability == "REACHABLE"` and the registering SUPI, plus the same site's `LOCATION_REPORT` TAC — positive, on bodies | `namf_event_probe.rs:461-509` | **real — implemented, and it SUBSCRIBED successfully in run 35957375665** |
| 3 | the assertion is shown able to FAIL with the `handle_service_request_nas` emitters reverted | — | **real — done and MEASURED** (see revert-verification). Independently corroborated in run 35957375665: fed the live AMF with no Service Request reaching the fire point, the probe reported `FAIL … 0 of 2 … MISSING ["REACHABILITY_REPORT", "LOCATION_REPORT"]` and exited 1 |
| 4 | the predecessor spec's ceiling section records the coverage as proven, and the struck-through revert-verification row is restored | predecessor's ceiling and revert table | **still NOT done as asked, for the same reason.** The coverage is dispatched but does not yet pass, so recording it as proven would be false. The ceiling and the struck row are updated to name #199 and to record what the run *did* establish |
| — | the issue's stated BLOCKER: "no control surface on `nr-ue`… not expressible today"; needs nextgsim option **A** or **B** | `GnbCliCommandType::UeSuspend` (`nextgsim-gnb/src/tasks.rs:234`) | **the CONCLUSION was right, the DIAGNOSIS was wrong — and so was the follow-up diagnosis.** nextgsim work IS required, but not option A or B. First it was a duplicated `CliServer` with a wire-version skew (#197 → PR #198, fixed); now it is an App-task UE registry with no production writer (#199) |
| — | the #403 investigation's own claim: "once nextgsim #197 lands, the step should go green with **no further nextgcore change**" | run 35957375665 | **VOID as a prediction, though the nextgcore half held.** #197/#198 landed and no nextgcore change was needed — but the step still fails, on a second nextgsim defect that #197 masked. No nextgcore change is required for #199 either |

The issue's own partial claim that `nr-ue` "has both triggers but no external control
surface" is **half right**: the triggers exist (`main.rs:354` TUN-data, `:1027`
handler, `:857` Paging), and no *UE* control surface is needed, because the state
change is driven from the **gNB** and the data trigger is driven by **`ping` on the
UE's TUN**, which the UE image already supports (`iputils-ping` is installed in
`nextgsim/Dockerfile.ue-local`, and `docker/rust/e2e-test.sh:523` already pings
through the tunnel).

**Link 1 is where run 35957375665 stopped**, and it is one link later than the previous
run managed. The command now reaches the gNB and is parsed, but `handle_ue_suspend`'s
own guard refuses it: the `ue_contexts` map it validates against is empty in
production (nextgsim #199), so the parse never becomes a dispatch and link 2
(`RrcMessage::SuspendUe`) is unreachable. The distinction from the previous failure is
worth keeping: before, the datagram never arrived; now it arrives and is validly
rejected by the gNB's own code.

Links 3–14 are verified by inspection, and links 3–4's precondition
(`reestablishment_security`, set at Initial Context Setup) was confirmed present in the
run's logs — the gNB completed `InitialContextSetup` for this UE, and the UE reached
`PDU Session 1 is now ACTIVE`.

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
(`ngap_path.rs:4582`, inside `handle_service_request_nas`). Verified:

```
$ grep -rn "fire_reachability_report" --include="*.rs" src/
src/bins/nextgcore-amfd/src/namf_server.rs:1376:pub fn fire_reachability_report(...)
src/bins/nextgcore-amfd/src/ngap_path.rs:4582:  fire_reachability_report(&state.amf_ue, true);
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
| gNB suspended the UE | `suspended to RRC_INACTIVE: I-RNTI=` | `nextgsim-gnb/src/rrc/connection.rs:734` | `could not be suspended; releasing instead` (`rrc/task.rs:1687`) — the fallback that would put the UE in RRC_IDLE and make the return leg an `InitialUEMessage`. Asserted **absent**. |
| UE reached RRC_INACTIVE | `Suspended to RRC_INACTIVE: I-RNTI=` | `nextgsim-ue/src/rrc/task.rs:2818` | `treating it as a release` (`:2790`, `:2806`) |
| UE went CM-IDLE | `RRC connection released` | `nextgsim-ue/src/main.rs:848` | — |
| UE sent a Service Request | `Sending Service Request (` | `nas/mm/orchestrator.rs:2557` | — |
| the UE's request was ACCEPTED | `Service Accept received` | `nas/mm/orchestrator.rs:2573` | a **Service Reject** is the #9 arm; if the return leg were an `InitialUEMessage` this is the line that would be missing |
| the AMF ran the fire point | `Service Accept sent to UE` | `ngap_path.rs:4543` | — |

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
unconditional cause-#9 arm (`ngap_path.rs:1604-1620`) rather than observed, and it is
labelled as such rather than presented as a run.

The middle assertions cannot be revert-verified outside a full bring-up at all: they
assert on nextgsim's log output, and nextgsim is read-only here. What makes them
trustworthy instead is that every string was **read from nextgsim's source** and each
is paired with the failure text that could also have satisfied a looser grep — the
table in the previous section.

## Ceilings, stated rather than implied

0. **The headline one: this does not yet prove the fire point.** Blocked on
   **nextgsim #199** (the gNB's App-task UE registry has no production writer, so
   `ue-list` is empty and `ue-suspend` refuses). The earlier blocker, nextgsim #197
   (`nr-cli` could not discover the gNB), is **fixed** by nextgsim PR #198 and that fix
   is confirmed in run 35957375665. The steps keep `continue-on-error: true` and
   self-activate when #199 lands. Restated here rather than left to the top section,
   because a reader who skims to the ceilings must not come away thinking the coverage
   exists.

   **And the trap that goes with it:** because these steps are `continue-on-error`,
   `Docker E2E` reported conclusion `success` in run 35957375665 while two of them
   exited 1. A green tick on that job is **not** evidence for this fire point; only the
   step log is. Remove the tolerance the moment #199 lands, because a step that cannot
   fail the job is not coverage.

1. **A Service Request in an `InitialUEMessage` is always rejected with cause #9.**
   `handle_initial_ue_message` (`ngap_path.rs:1604`) has no 5G-S-TMSI lookup,
   although the gNB does send the `fiveGSTmsi` IE and nextgcore *has* a GUTI
   resolver (`amf_ue_find_by_guti`, used by the registration path at `:2559`). So a
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

3. **`CONNECTIVITY_STATE_REPORT` fires from this site too** (`ngap_path.rs:4581`) and
   is not asserted. Subscribing to it would not discriminate: it fires at the N1
   release as well (`start_reachability_supervision`, `:6317`), and the suspension
   deliberately does not tell the AMF, so the IDLE→CONNECTED report is the only one
   this scenario produces — but asserting it adds no discrimination that
   `REACHABILITY_REPORT` does not already give, since the latter has a single caller.

## Test isolation and workspace hygiene

No Rust unit tests are added: the change is to an `example` binary (which has no
test harness by design — it needs a live AMF and a live NG-RAN) and to CI YAML. The
existing suite was unchanged at **6833 passing** when this spec was first written, and
at **6898 passing** on the re-dispatch at `98603b2` (the growth is other issues'
work, not this one's — the re-dispatch pass changes only `ci.yml` comments and this
spec, so no Rust is touched at all). `cargo fmt --all -- --check` is clean and
`cargo clippy --workspace` reports only the pre-existing style lints the CI Clippy job
tolerates by design.

The probe's argument parsing moved from nine positional arguments to a leading
phase selector plus the existing positional set. It is an `example`, so there is no
external caller to break; both call sites in `ci.yml` are updated in the same
commit.
