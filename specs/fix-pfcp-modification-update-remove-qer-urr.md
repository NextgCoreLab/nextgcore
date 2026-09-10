# nextgcore #304 (nextgcore-pfcp, sgwud): model Update/Remove QER and URR on a Session Modification

Verified against `main` @ `b1b2bb5`.

#304 was filed from #59's first ceiling. Every claim in it still holds; nothing was found to be
stale. TS 29.244 Table 7.5.4.1-1, Tables 7.5.4.4-1 / 7.5.4.5-1 / 7.5.4.6-1 / 7.5.4.7-1.

## Verified against current main

| claim in the issue | site on `b1b2bb5` | still true? |
|---|---|---|
| `IeType::UpdateUrr = 13`, `UpdateQer = 14`, `RemoveUrr = 17`, `RemoveQer = 18` exist | `libs/nextgcore-pfcp/src/ie.rs:24,25,28,29` | yes |
| the four structs do not exist | `grep 'struct UpdateQer\|struct RemoveQer\|struct UpdateUrr\|struct RemoveUrr' types.rs` → nothing | yes |
| `SessionModificationRequest` models none of the four | `message.rs:702-714` (11 fields, none of them) | yes |
| a request carrying them decodes cleanly with the lists empty | `decode`'s `_ => {}` arm at `message.rs:876` | yes |
| sgwud's handler HAS the four lists and code that applies each | `sxa_handler.rs:226-234`, applied at `:430,518,526,535` | yes |
| `modification_from_lib` fills all four with `Vec::new()` | `pfcp_path.rs:1417-1420`, with a comment naming this issue | yes |
| upfd decodes modification IEs itself, so it is not affected the same way | `bins/nextgcore-upfd/src/pfcp_path.rs:1391` (its own `ParsedIe` walk) | yes — and see Decision 3 |

## Decision 1: every Update member is optional, and absence is preserved end to end

`UpdateQer` is not `CreateQer` reused, and `UpdateUrr` is not `CreateUrr` reused. TS 29.244's
Update tables make each provisioning IE Conditional, and the sgwud handler already reads that
correctly: `process_update_qer` / `process_update_urr` apply a `Some` and leave a `None` alone.

Reusing the Create types would have made the wrong thing easy. `GateStatus` defaults to **open**,
so an Update QER that named only an MBR would have re-opened a gate the CP function never
mentioned — the exact defect this issue is about, inverted. Same for `MeasurementMethod`: an
Update URR carrying only a new Volume Threshold would have reset the method to 0 and stopped the
rule measuring anything.

The mapping preserves it too. `urr_from_lib` flattens an absent Volume to a default (correct for a
Create, which states the rule's whole shape); the new `volume_from_lib` keeps `Option`, because an
Update that does not mention the Volume Quota must not revoke it. That is guarded by its own
assertion, and the revert of it fails that assertion.

## Decision 2: IE order follows Table 7.5.4.1-1, though nothing decodes by position

Remove URR is encoded before Remove QER, and Update URR before Update QER, matching the table's
row order. PFCP decoders are order-independent (this one included), so this buys nothing
functionally — it is so that a capture from this SGW-C reads like the table for whoever compares
them, and so the URR operations precede the QER ones consistently with how the handler sequences
them (`sxa_handler.rs:422-540`).

## Decision 3: upfd stays on its own decoder, and its own gap is filed separately

Criterion 5 asks for a decision either way. **upfd is not moved onto the library decoder here.**

- The issue itself sizes it separately ("a behaviour-preserving swap that needs its own revert
  pass"), and it is not needed for anything in this issue's criteria.
- upfd's establishment and modification handlers walk `ParsedIe` and feed a *different* internal
  session model (`DataPlaneUrr` with `AtomicU64` counters, not sgwud's `SgwuUrr`), so the swap is
  not a mapping change — it is a re-write of two handlers whose failure mode is silent.

What the verification pass did find is that upfd has the **same functional gap this issue is
about**, in a different place: `handle_session_modification_request`
(`bins/nextgcore-upfd/src/pfcp_path.rs:1345-1508`) parses only Update FAR, Update QER, Create/Update
BAR and the PFCPSMReq-Flags. It parses **no** Create/Update/Remove URR and **no** Remove
QER/PDR/FAR on a modification — so a UPF answers `RequestAccepted` for those too, and unlike sgwud
it has no handler code waiting for them. That is a upfd defect, not a library one, and this PR does
not touch it: filed as its own issue.

## Acceptance criteria

- [x] The four IEs round-trip through `SessionModificationRequest::encode`/`decode`, asserted by a
      test that encodes and then decodes —
      `message::tests::a_session_modification_carries_update_and_remove_qer_and_urr_over_the_wire`.
      Not a field read: each of the four decode arms was reverted individually and each failed it.
- [x] sgwud's `modification_from_lib` populates all four lists, and the "not modelled" comment is
      gone (`pfcp_path.rs`, the four `Vec::new()` lines replaced by mappers).
- [x] A Session Modification that closes a QER gate reaches `SgwuQer.gate_status`, asserted over
      the wire from the transport —
      `pfcp_path::tests::a_modification_over_the_wire_closes_a_qer_gate_and_removes_a_urr` drives a
      real datagram into a bound socket and asserts `0x05` in the store.
- [x] A Remove URR over the wire detaches it: URR 4 is gone from the store and PDR 1's `urr_ids`
      drops 4 while keeping 3.
- [x] Whether upfd moves onto the library decoder is decided and stated — Decision 3: it does not,
      with its own gap filed.

## Verification

`cargo test --workspace`: **6290 passed / 0 failed** (baseline 6288 on `b1b2bb5`; +1
nextgcore-pfcp, +1 nextgcore-sgwud — neither replaces an existing test).
`cargo clippy --workspace --all-targets` and `cargo fmt --all -- --check` clean.

| revert | expected to break | result |
|---|---|---|
| library `UpdateQer` decode arm removed | `a_session_modification_carries_...` | **1 failed** |
| library `UpdateUrr` decode arm removed | same | **1 failed** |
| library `RemoveQer` decode arm removed | same | **1 failed** |
| library `RemoveUrr` decode arm removed | same | **1 failed** |
| `modification_from_lib`: `update_qers` back to `Vec::new()` | `a_modification_over_the_wire_...` | **1 failed** (gate read `Some(0)`) |
| `modification_from_lib`: `update_urrs` back to `Vec::new()` | same | **1 failed** |
| `modification_from_lib`: `remove_qers` back to `Vec::new()` | same | **1 failed** |
| `modification_from_lib`: `remove_urrs` back to `Vec::new()` | same | **1 failed** |
| `volume_from_lib` flattens absence to a default `Volume` | same | **1 failed** (quota revoked) |

Nine reverts, nine bites. The two the run turned on: the four library decode arms are what separate
"the codec carries the IE" from "the struct exists", which is the distinction #59's Volume Quota
revert found the hard way; and the `volume_from_lib` revert is what makes Decision 1 a verified
claim rather than a stated intention.

## Ceilings

- **`process_update_qer` ignores the GBR.** It applies Gate Status and MBR and drops `req.gbr` on
  the floor — pre-existing (`sxa_handler.rs:1078-1084`), not introduced here, and out of this
  issue's scope. The library and the mapping both carry it, so closing this is now a two-line
  handler change; nothing in #304's criteria asked for it, so it was not made.
- **QFI is carried by the library's `UpdateQer` but not mapped**, because sgwud's
  `UpdateQerRequest` has no QFI member — the SGW-U is a 4G user plane and its QER store has none
  either. Left as a modelled-but-unmapped IE rather than adding a field nothing reads.
- **No Query URR / Query All URRs**, so a Remove URR still discards residual volume with a `warn`
  (#215's compromise, unchanged). The removal now genuinely happens over the wire, which makes
  that discard reachable in production for the first time — the existing TASKS entry for Query URR
  is the fix, and its ceiling ("nothing transmits") was already struck by #59.
- **upfd untouched**, per Decision 3. A UPF still ignores Remove QER, and every URR operation, on
  a Session Modification.
- **No E2E**: the Docker jobs are `workflow_dispatch`-only, so the wire assertions are in-process
  datagrams through a bound loopback socket, not an SGW-C container talking to an SGW-U container.
