# Prove the SERVICE REQUEST Namf fire point against nextgsim's real gNB and UE

**Issue:** nextgcore #403 (the ceiling stated by PR #402 / #397)
**Verified against:** nextgcore `main` @ `0dc01e4`, nextgsim `main` (read-only checkout)
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

## Read this first: the issue's blocker is FALSE, and that makes this much smaller

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

## Criterion-by-criterion, re-located at `0dc01e4`

| # | criterion as filed | site at `0dc01e4` | verdict |
|---|---|---|---|
| 1 | the `Docker E2E` job drives a registered UE to CM-IDLE and back through a Service Request, against nextgsim's real gNB | no such stage; the job ends at the registration assertion (`ci.yml:399-431`) | **real — implemented, via `ue-suspend` (the issue's own route A is unnecessary)** |
| 2 | `namf_event_probe` asserts `REACHABILITY_REPORT` DELIVERED with `reachability == "REACHABLE"` and the registering SUPI, plus the same site's `LOCATION_REPORT` TAC — positive, on bodies | the probe subscribes to three registration types only (`namf_event_probe.rs:236-240`) | **real — implemented** |
| 3 | the assertion is shown able to FAIL with the `handle_service_request_nas` emitters reverted | — | **real — done, see the revert-verification section** |
| 4 | the predecessor spec's ceiling section records the coverage as proven, and the struck-through revert-verification row is restored | ceiling at `:396-412`, struck row at `:425` | **real — implemented** |
| — | the issue's stated BLOCKER: "no control surface on `nr-ue`… not expressible today"; needs nextgsim option **A** or **B** | `GnbCliCommandType::UeSuspend` (`nextgsim-gnb/src/tasks.rs:232`) already reaches RRC_INACTIVE, and the UE's MO-resume arm already carries the Service Request | **VOID — no nextgsim change needed, and no nextgsim issue filed** |

The issue's own partial claim that `nr-ue` "has both triggers but no external control
surface" is **half right**: the triggers exist (`main.rs:354` TUN-data, `:1027`
handler, `:857` Paging), and no *UE* control surface is needed, because the state
change is driven from the **gNB** and the data trigger is driven by **`ping` on the
UE's TUN**, which the UE image already supports (`iputils-ping` is installed in
`nextgsim/Dockerfile.ue-local`, and `docker/rust/e2e-test.sh:523` already pings
through the tunnel).

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
existing suite is unchanged at **6833 passing**, before and after. `cargo fmt --all
-- --check` and `cargo clippy --workspace` are clean.

The probe's argument parsing moved from nine positional arguments to a leading
phase selector plus the existing positional set. It is an `example`, so there is no
external caller to break; both call sites in `ci.yml` are updated in the same
commit.
