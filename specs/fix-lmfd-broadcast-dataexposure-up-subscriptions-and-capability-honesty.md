# nextgcore #104 (lmfd): Nlmf_Broadcast, Nlmf_DataExposure, real UP subscriptions, honest capabilities, LocationQoS and context transfer

Verified against `main` @ `e9c823f` (after #65, #106, #112, #114). Every cite in the issue still held.

All eight acceptance criteria are addressed, one PR — **including** the conditional eighth
("(Broadcast/DataExposure, if implemented)"), because both surfaces are vendored
(`6g_docs/specs/TS29572_Nlmf_Broadcast.yaml`, `..._DataExposure.yaml`) and small: one operation and
three respectively. Nothing had to be guessed.

**Criterion 7 is declined, with evidence.** See "Declined" below.

## Verified against current main

| claim in the issue | check on `e9c823f` | still true? |
|---|---|---|
| only `nlmf-loc` is routed and registered | router matches only `["nlmf-loc", ...]`; one `serviceName` | yes |
| `configure-up` validates then returns 204 with no persistence | `main.rs:1431-1461` | yes |
| `up-subscribe` mints a UUID, echoes, stores nothing | `main.rs:1467-1500` | yes |
| `up-unsubscribe` ignores the id and always 204s | `main.rs:1508-1510` | yes |
| `LocationQoS` has no `lcsQosClass` / `velocityRequested` | `nlmf.rs:155-166` — the members are absent from the struct, so never deserialised | yes |
| `velocity_estimate` is hardcoded `None` | `main.rs:1278` | yes |
| context transfer hardcodes `periodic_event_info: None` | `main.rs:1385` | yes |
| `/capabilities` is ungated and hardcodes both flags `true` | route at `main.rs:386-388`; handler at `2149-2155` | yes |

## Declined: criterion 7 (reject the `DUMMY` eventClass)

The issue calls `DUMMY` "the placeholder `'DUMMY'`… that has no spec meaning" and asks for it to be
rejected. **It is a spec-defined value.** `6g_docs/specs/TS29572_Nlmf_Location.yaml`:

```yaml
    EventClass:
      description: Specifies event classes.
      anyOf:
        - type: string
          enum:
            - SUPPLEMENTARY_SERVICES
            - DUMMY
        - type: string
```

3GPP uses `DUMMY` to keep a single-valued enumeration extensible. Rejecting it would make this LMF
refuse a **conformant** peer — a conformance regression introduced in the name of a conformance fix.
The recorded convention is explicit that the vendored OpenAPI outranks the issue text, so the
validator is unchanged and `test_dummy_event_class_is_accepted_because_the_yaml_defines_it` pins the
acceptance (and asserts that a value genuinely outside the enumeration is still `403`), so a later
reader of the issue does not "fix" it. An unknown value remains refused, which is what
`EVENT_REPORT_UNRECOGNIZED` is for.

## Decision 1: `/capabilities` — gated with the others, and its flags derived

Two changes, both about honesty:

* **Gated behind `debug_endpoints_enabled()`.** It is not a TS 29.572 resource (there is no
  `/capabilities` in §6.1), it discloses this NF's positioning posture, and it was the **one** bespoke
  route left ungated while six siblings were gated. Added to the **existing** gate test rather than a
  new one — two tests toggling the same process-global gate is precisely the disjoint-agreement hazard
  that test's own comment warns about.
* **Flags derived, not hardcoded.** `nrppaSupported` / `nlsInterfaceSupported` now equal
  `measurement_source_available()` — whether this LMF has cell/TRP coordinates to solve against.
  Without them the solvers fall back to a heuristic placeholder and `measure-location` answers
  `403 LOCATION_MEASUREMENT_UNKNOWN`, which is the contradiction the hardcoded `true` created: an
  interop partner selected an NRPPa/NLs method on the strength of the advertisement and had every
  request fail.

## Decision 2: `ASSURED` refuses; `BEST_EFFORT` is unchanged

`lcsQosClass` and `velocityRequested` are added to `LocationQoS` (they were absent from the struct, so
no amount of correct JSON could reach the handler). An `ASSURED` request whose accuracy is unmet now
**discards the estimate** and answers `500 POSITIONING_FAILED` naming both the requested and the
achieved accuracy (TS 29.572 §6.1.6.2.7).

`POSITIONING_FAILED` rather than a new cause: it is a real value in TS 29.572 Table 6.1.7.3-1 ("The
positioning procedure failed"), and an assured procedure that cannot meet its accuracy **has** failed.
Inventing `QOS_NOT_ATTAINABLE` would have put a non-spec cause on the wire.

A request that names no class, or names `BEST_EFFORT`, still answers `200 NOT_FULFILLED` exactly as
before, so no existing consumer changes behaviour.

## Decision 3: velocity is derived from two fixes, and a fix history was added to make that true

`velocity_estimate` was hardcoded `None`. Populating it needed something the context did not have: a
**previous** fix. These solvers produce position only (no Doppler), so a single fix has no velocity —
and `last_location` is the fix being reported, so deriving against it gives a zero time delta. That is
how the first version of this failed.

`UeLocationContext.previous_location` now holds the fix displaced by the current one, and
`derive_velocity` computes `hSpeed` (haversine distance / Δt) and `bearing` (initial azimuth) from the
pair. It returns `None` — and the member is **omitted** — when there is no previous fix, when Δt is
non-positive, or when the implied speed exceeds ~280 m/s (a bad fix pair, not a velocity). A
fabricated zero would claim a stationary UE, which is a different statement from "unknown".

## Decision 4: context transfer re-arms, and refuses to invent a cadence

`periodic_event_info` was hardcoded `None`, so a relocated `PERIODIC` deferred LDR was stored as a
record whose trigger never restarted: periodic reporting stopped silently at AMF relocation — a
routine mobility event — and the stored record made it look live.

The parameters are recovered from `eventReportMessage.eventContent.periodicEventInfo` (that member is
a passthrough `Value` here, so the vendored `PeriodicEventInfo` member names are used, top-level or one
level down) and `spawn_periodic_ldr` is called.

When they are **absent**, the LDR is still stored — `cancel-location` must find it — but nothing is
armed and a warn names the consequence and what the source LMF must send. Defaulting to some interval
would make this LMF report at a rate nobody asked for.

## Decision 5: the two new services are routed unconditionally

The issue suggests an off-by-default cargo feature each. They are **pure additions** — two new
apiRoots no existing path can reach, so no current behaviour changes — and a cargo feature would leave
them uncompiled in CI (which builds default features), where they would rot. Same trade as #112's and
#114's switches.

`Nlmf_Broadcast` answers `CIPHERING_KEY_DATA_NOT_AVAILABLE`, which is **conformant, not a stub**:
nothing provisions ciphering key sets in this tree, `dataAvailability` exists precisely to tell the AMF
not to wait for a notification, and a fabricated key would make a UE decipher assistance data into
noise.

`Nlmf_DataExposure` PATCH applies only a top-level `replace`; any other operation or a nested pointer
is **refused**, because applying part of a patch is worse than refusing all of it — the consumer cannot
tell which part landed. A patch that would empty a mandatory member is refused too.

## What was added / changed

| area | change |
|---|---|
| `broadcast_exposure.rs` (new) | `CipherRequestData`, `CipherResponseData`, `CipheringDataSet`, `CipheringKeyInfo`, `data_availability`, `LmfDataExposureSubscription` + `validate` |
| `context.rs` | `up_subscriptions`, `up_configs`, `exposure_subscriptions` stores + their API; `measurement_source_available`; `ldr_task_is_running`; `UeLocationContext.previous_location` |
| `nlmf.rs` | `LocationQoS.{lcs_qos_class, velocity_requested}`, `lcs_qos_class` constants, `derive_velocity`, `cause::SUBSCRIPTION_NOT_FOUND` |
| `main.rs` | UP handlers persist / 404; `capabilities_body` extracted and derived; `/capabilities` gated; ASSURED refusal + velocity in determine-location; context-transfer restore + re-arm; five new handlers + routes for the two services; `build_lmf_nf_profile` extracted and advertising all three services |

## Verification

Every guard revert-verified: undo the change, watch the **named** test fail, restore.

| guard | revert applied | result |
|---|---|---|
| `test_up_subscribe_201_and_unsubscribe_204` | `up-unsubscribe` always 204 | FAILED ✓ |
| `test_capabilities_flags_track_the_real_measurement_source` | flags hardcoded `true` | FAILED ✓ (after a rewrite — see below) |
| `test_context_transfer_rearms_periodic_reporting` | `periodic_event_info` back to `None` | FAILED ✓ |
| `test_assured_qos_class_refuses_an_unmet_accuracy` | the ASSURED branch disabled | FAILED ✓ (after being added — see below) |

### Two of my own guards proved nothing

1. **The capability test passed with the flags hardcoded back to `true`.** It went through the handler
   and had wired a coordinate itself, so `expected` was `true` either way — the `false` branch was
   never observed. It could not be observed through the handler at all: the process-global cell
   registry is shared with every other test in this binary and only ever gains entries, so a sibling
   makes "no measurement source" unreachable. Fixed by extracting `capabilities_body(&LmfContext)` — a
   **pure function of the context** — and testing both branches on fresh contexts, plus a thin handler
   test asserting it serves that body. The revert then failed.
2. **Nothing covered the ASSURED refusal.** Disabling the branch compiled and the whole suite passed:
   I had tested `LocationQoS` parsing and `derive_velocity` purely and never driven
   determine-location. `test_assured_qos_class_refuses_an_unmet_accuracy` closes it, asserting the
   `500`, the cause, **and** that the response carries no `locationEstimate` (the estimate must be
   discarded, not returned alongside the error).

### And a defect-pinning test, inverted

`test_up_subscribe_201_and_unsubscribe_204` contained the comment *"DELETE any subscriptionId → 204"*
and passed an id that was never issued. It pinned the defect **as** the requirement. It now asserts
`201 → 204 → 404`, that an id never issued is `404`, and that the created subscription is retrievable
from the store — with the inversion and its reason recorded at the site.

## Workspace state

`6118 passed / 0 failed` (main: `6102`) — the full suite run twice, same result;
`cargo clippy --workspace --all-targets` 0 errors; `clippy -p nextgcore-lmfd --all-targets`
**0 warnings**; `cargo fmt --all --check` clean. The lmfd suite alone was run 15 consecutive times
clean while chasing a single unreproduced failure (see Ceilings).

## Ceilings

* **One unreproduced test failure.** During the run a single `-p nextgcore-lmfd` invocation reported
  one failure; it did not recur in 15 consecutive full-suite runs afterwards, and I could not identify
  which test it was. Recorded rather than dismissed: this crate's tests share a process-global
  context, so an order-dependent interaction I have not found may still exist.
* **No ciphering key source.** `Nlmf_Broadcast` always answers
  `CIPHERING_KEY_DATA_NOT_AVAILABLE` and the `CipheringKeyInfo` notification is modelled but never
  sent. The service is conformant and useless until something provisions key sets.
* **`Nlmf_DataExposure` never notifies.** Subscriptions are stored, modified and deleted;
  `LmfDataExposureNotification` is not sent, because the LMF has no sampling pipeline to report from.
  A subscriber gets a resource, not data — the same shape of gap the UP subscriptions had, now at one
  remove.
* **UP subscriptions are stored, not acted on.** `configure-up`/`up-subscribe` persist and are
  retrievable, and `up-unsubscribe` is honest about existence. No UP location reporting happens
  (that needs the LCS-UP data path), and `UPNotify` remains unimplemented.
* **PATCH supports only a top-level `replace`.** A nested JSON Pointer, `add`, `remove`, `copy`,
  `move` and `test` are all refused with a 400 naming the operation.
* **Velocity needs two fixes from the same store.** A UE with one fix gets no velocity even when
  `velocityRequested` is set; there is no Doppler input, and the haversine derivation is
  spherical-earth (sub-percent against WGS-84, which a 0.1 m/s report does not notice).
* **`measurement_source_available()` is a proxy.** It reports whether cell/TRP coordinates are
  configured, which is what the solvers need — not whether a PRU or a live NRPPa peer exists. It is
  strictly more honest than `true`, and still not the same claim as "NRPPa works".
* **Context transfer re-arms from `eventContent`.** A source LMF that carries `periodicEventInfo`
  elsewhere in its event body gets no re-arm (logged at warn). TS 29.556-style verification is not
  possible here: `eventContent` is a passthrough member in this tree.
* **No wire interop.** Everything is in-process against this tree's own router.
* GitNexus impact analysis unrunnable (no MCP server connected — 51st consecutive PR). Blast radius by
  grep: `UeLocationContext` is constructed at 2 sites (both updated), `handle_capabilities` has 1
  caller, the NF profile had 1 inline construction (extracted, 1 caller plus the test), and no crate
  outside `nextgcore-lmfd` names anything touched here.
