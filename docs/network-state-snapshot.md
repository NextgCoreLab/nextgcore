# Aggregate Network-State Snapshot (Design Note)

> **Non-normative 6G research.** A "network digital twin" export has no
> frozen Rel-20/6G Stage-3 specification; this aggregate format is
> **project-defined**. The underlying data models are TS 29.510 (NRF
> NFProfile) and TS 29.536 (NSACF slice quotas), which the source snapshots
> already follow. Research shape for education, not a conformance target.
> Tracking issue: [#25](https://github.com/NextgCoreLab/nextgcore/issues/25).

## What it is

A digital twin needs one coherent, read-only export of network state as its
substrate. `nextgcore_app::state_export` (feature `6g-extensions`, off by
default) is an **offline aggregator**: it composes the state the NRF and
NSACF *already persist to JSON on disk* into one `NetworkStateSnapshot`
document. No live SBI plumbing, no new listening socket, no always-on task.

```
nrfd  --state-file nrf_state.json    ─┐  (persisted on every registry mutation)
                                      ├─► NetworkStateSnapshot::from_persisted
nsacfd --state-file nsacf_state.json ─┘      │
                                             ▼
      { captured_at_ms, nf_registrations, slice_quotas, session_summary }
```

## Snapshot format

- `captured_at_ms` — capture wall-clock, ms since Unix epoch.
- `nf_registrations[]` — one entry per persisted NRF NFProfile: distilled
  `nf_instance_id` / `nf_type` / `nf_status` / `fqdn` / `ipv4_addresses` /
  `service_names`, plus the **verbatim persisted profile document** under
  `profile` (camelCase TS 29.510 keys) so nothing is lost. Profiles missing
  the mandatory `nfInstanceId`/`nfType`/`nfStatus` trio are skipped, exactly
  like the NRF's own lenient restore path.
- `slice_quotas[]` — one entry per NSACF slice: `sst`/`sd` (raw number, as
  persisted), `max_ues`/`max_pdu_sessions`, live `current_ues` /
  `current_pdu_sessions` (lengths of the persisted admission membership
  sets), `eac_active`.
- `session_summary` — totals across slices plus a documented **`note`**
  field stating the limitation: counts are NSACF per-slice admission
  counters; **live SMF/UPF per-session enumeration is a follow-up and is
  not included** — no session list is fabricated.

Optional/empty fields — `fqdn`, `ipv4_addresses`, `service_names`, and
`sd` — are omitted from the serialized JSON entirely when absent or empty
(the NSACF state doc itself persists an explicit `"sd": null`, but the
export drops the key; deserialization accepts either form). Malformed
source entries are skipped with a `log::warn!`, and a skipped quota row's
UE/PDU counts are consequently absent from the `session_summary` totals.

The `nf_hooks` digital-twin types (`NfStateSnapshot`, `NfStatus`,
`NfStateDelta`, `SnapshotHistoryEntry`) now derive serde
Serialize/Deserialize, so per-NF twin snapshots can travel as JSON too.

## Invocation

No NF binary changes. A cargo example (skipped entirely by default builds
via `required-features`) does the export:

```sh
cargo run -p nextgcore-app --features 6g-extensions \
  --example export_network_state -- nrf_state.json nsacf_state.json out.json
```

The source files come from `nextgcore-nrfd --state-file <path>` (or env
`NEXTGCORE_NRF_STATE_FILE`) and `nextgcore-nsacfd --state-file <path>`;
both NFs persist on every mutation, so the files are current as of the last
registry/admission change.

## Scope limits

- **Offline, read-only, point-in-time.** No live cross-process SBI
  collection (the NWDAF `nrf_collector` is the seed for later live work).
- **No SMF/UPF session registry exists** to read — hence the honest
  `session_summary.note` instead of invented per-session data.
- Snapshot ordering follows the source docs; NRF profile order, NSACF
  quota-row order, and NSACF membership-set order are all nondeterministic
  (HashMap/HashSet iteration).

## Verification

```sh
cargo build -p nextgcore-app                                  # default unchanged
cargo test  -p nextgcore-app --features 6g-extensions          # incl. state_export
cargo build -p nextgcore-app --features 6g-extensions --example export_network_state
```
