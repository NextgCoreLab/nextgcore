# fix(pfcp,smfd,upfd,pcfd): the PFCP TSC container codec and the PCF→SMF→UPF hop

Closes #321. Completes #284's criterion 4, which #284 left unmet and named as its
main ceiling.

## What was missing

The IE *identifiers* existed. Nothing else did.

`rg 'CreateBridgeInfoForTsc|TscManagementInformationSmr' src/` returned the enum
declarations and nothing more — no struct, no encoder, no decoder, no carriage, no
consumer. `upfd`'s `tsn_bridge` was initialised to `None` and the only other
reference was a unit test that hand-built its own bridge.

## Claim / site / still true

Every claim #321 makes, re-verified against `main` at `57a0b05`.

| #321's claim | site | still true? |
|---|---|---|
| `PfcpIeType::CreateBridgeInfoForTsc = 194`, no users | `libs/nextgcore-pfcp/src/ie.rs:205` | **YES** — declaration only |
| `CreatedBridgeInfoForTsc = 195`, no users | `ie.rs:206` | **YES** |
| `TscManagementInformationSmr/Smrsp/Srr = 199/200/201`, no users | `ie.rs:210-212` | **YES** |
| `UpFunctionFeatures.tscu` encoded and decoded, never acted on | `types.rs:1626,1693,1778` | **YES** |
| `PfcpSrRspFlags.tmir` flag only | `types.rs:1564` | **PARTLY** — the flag is on `ReportType` (§8.2.21 bit 5), and `ReportType.tmir` was already correctly encoded/decoded; it had no reader |
| `upfd`'s `tsn_bridge: Option<TsnBridge>`, `None` at init, one unit-test reference | `bins/nextgcore-upfd/src/context.rs:1204,1223,1851` | **YES** |
| "a populated `TsnBridge`/`TsnBridgePort`/`TsnGateControlEntry` type set" | `context.rs:472,503,676` | **YES**, but note there are **TWO** `TsnBridge` types: the one #321 means (`context.rs:676`, ports + bridge ID + PTP clock) and a second, unrelated one in `tsn_bridge.rs:121` (VLAN/PCP flow tagging). Only the first is on `UpfSess` |
| grouped-IE pre-check: can Create PDR / Create URR's helpers carry these? | `types.rs:2463` | **YES** — the mechanism is a plain `encode(&self, buf)` / `decode(buf)` pair over `RawIe::decode`. No fourth grouping mechanism was added |

### Two things #321 got wrong, and one it could not have known

1. **The IE is not called what #321 calls it.** TS 29.244 §8.2.157 is not TSC
   Management Information; the grouped IEs are §7.5.4.18, §7.5.5.3 and §7.5.8.5, and
   the containers are §8.2.144 (PMIC) and **§8.2.182 (UMIC)**. #321 (following
   TS 29.512) calls the second one a "Bridge Management Information Container"; on
   N4 it is the **User Plane Node Management Information Container**, IE **266**,
   which was absent from `IeType` entirely. The two specs name the same octet string
   differently, which is exactly the kind of thing to get from the spec rather than
   from memory — this build vendors TS 29.244 k00 at
   `6g_docs/specs/29244-k00.txt`, and every IE number and figure below was read from
   it.
2. **`upfd`'s `tsn_bridge` is in an UNREACHABLE store.** `UpfSess` lives in
   `UpfContext::sess_list`, and **nothing in production calls `sess_add`** — the only
   callers are that module's own tests. `rule_match.rs` *reads* the store
   (`upf_sess_find_by_ipv4`), so every lookup there returns `None`. Populating
   `UpfSess.tsn_bridge` would therefore have been a correct change in a place no wire
   path runs through, and the resulting test could only have asserted against a
   session it built itself — which is precisely the existing unit test at
   `context.rs:1851`, and precisely why #284's criterion 4 stayed unmet. The live
   store is `PfcpServer::sessions: HashMap<u64, PfcpSessionInfo>`, so **that** is
   where the bridge now lives. Filed as its own issue; see Ceilings.
3. **A live wire bug found on the way in.** See the next section.

## The S-NSSAI defect, found while adding IE 199

`smfd`'s `n4_build::pfcp_ie` is a second, hand-maintained copy of TS 29.244
Table 8.1.2-1, 255 constants long. It **omitted IP Multicast Address (191)**, so
every constant from 191 down was shifted by one, and further omissions grew the
shift to seven by IE 202. Concretely:

```
smfd said                                        TS 29.244 says
193  TSC_MANAGEMENT_INFORMATION_..._MOD_REQUEST  193  Packet Rate Status
199  TIME_DOMAIN_NUMBER                          199  TSC Management Information (SMR)
250  S_NSSAI                                     250  DL Data Packets Size
```

**64 of the 65 shifted constants had no caller.** The 65th was `S_NSSAI`, and it was
live: `PfcpMessageBuilder::add_s_nssai` is called from `pfcp_session_establish`, so
**every 5GC PFCP Session Establishment Request this SMF sent carried the slice
identity under IE 250, "DL Data Packets Size"**. TS 29.244 §8.2.176 Figure 8.2.176-1
says `Type = 257`.

Why it went unnoticed, both parts verified: nothing in this tree *reads* S-NSSAI over
N4 (`rg S_NSSAI` across `upfd`, `sgwud`, `sgwcd` returns nothing), so no peer
compensated for it and no test could have caught it; and the other 64 were inert.
Checked before fixing, because a correctness fix is a breaking change to whoever
compensated for the defect — here, nobody did.

The whole `>= 191` region is corrected, and pinned by
`test_pfcp_ie_numbers_match_the_authoritative_table`, which compares 24 constants
against `nextgcore_pfcp::ie::IeType` and asserts S-NSSAI = 257 and the UMIC = 266
against the spec clause directly. A 250-row hand-maintained wire table cannot be kept
correct by review. `upfd`, `sgwcd` and `sgwud` have their own copies; all three stop
before 191 and were checked clean.

## Scope item 4: which hop, and why

**PCF → SMF over `Npcf_SMPolicyControl`, using the members TS 29.512 already
defines.** `SmPolicyDecision` carries `tsnBridgeManCont`, `tsnPortManContDstt`,
`tsnPortManContNwtts`, `tscNotifUri` and `tscNotifCorreId` — read from the official
`TS29512_Npcf_SMPolicyControl.yaml`, lines 696-708 — under **the same names**
TS 29.514's `AppSessionContextReqData` uses on the inbound PolicyAuthorization leg.
So the PCF is a **copier, not a translator**: there is no mapping step in which the
containers could be corrupted, and no member this build had to invent.

The alternative #321 offers — TSCTSF reaching the SMF directly — was declined for
three reasons: TS 23.502 Annex F.1 puts the PCF in the path; the TSCTSF has no Nsmf
consumer role in this tree; and it would need a protocol no spec defines. The
existing `pcf_sbi_send_af_smpolicycontrol_update_notify` already pushes AF-derived
decisions to the SMF, and `smfd`'s `handle_sm_policy_notify` already applies them —
so this hop is a new member on an existing message, not new plumbing.

Note the flow direction this settles: a TSCTSF app session **binds by UE IP**, which
requires the PDU session to exist first. So the containers always arrive on an
*update* to a live session, never on the create. That is why the Session Modification
path is the load-bearing one and the establishment path is not.

## The chain, end to end

1. TSCTSF derives PMIC/UMIC (#284) → PCF over `Npcf_PolicyAuthorization` — *existed*
2. PCF parses the containers, stores them on the bound `PcfSess`, and includes them in
   the `SmPolicyDecision` it pushes to the SMF — **new**
3. SMF parses and base64-decodes them, and carries them over N4 in a Session
   Modification's TSC Management Information IE (199) — **new**, gated on `tscu`
4. UPF decodes 199, populates `tsn_bridge` from `None`, echoes IE 200 — **new**
5. UPF may report asynchronously with IE 201 + the TMIR bit; the SMF decodes and
   records it — **new**
6. Establishment: a `tscu`-advertising UPF is asked for bridge info (IE 194, BII), and
   its Created Bridge/Router Info (IE 195) — DS-TT port + Bridge ID — is decoded and
   held per session — **new**

## Decisions

**One type for IEs 199, 200 and 201.** Tables 7.5.4.18-1, 7.5.5.3-1 and 7.5.8.5-1
list the *same three members*, so `TscManagementInformation` serves all three and the
carrier number is the caller's choice. Three structs would have tripled the codec to
emit identical bytes. The risk this creates is that a copy-paste puts the wrong
carrier number on a message — and a self-round-trip cannot catch it, because each
message would happily decode its own output under any number it agreed with itself
on. So three tests assert the carrier number **on the wire**
(`top_level_ie_types(&buf).contains(&199)`).

**The DS-TT container is deliberately not sent over N4.** §7.5.4.18 gives the TSC
Management Information IE an NW-TT Port Number and no DS-TT one, because the
device-side port's configuration reaches the DS-TT over NAS (TS 24.501 §5.4.5).
Sending it with an NW-TT port number would tell the UPF to apply device-side
configuration to a network-side port. It is still parsed and stored, so the NAS leg
has it when that is built.

**The bridge info request goes out at establishment, gated on `tscu`.** §5.26.2 puts
Create Bridge/Router Info on the Establishment Request only, and the SMF cannot know
at that moment whether a TSCTSF will later authorise the session (see the binding
note above). So a UPF that advertised TSC support is asked once, up front, and the
answer is held. A UPF that did not advertise it is never asked — §6.2.2 lets a UP
function reject a request carrying an unsupported feature's IEs, which would fail
every session establishment against a plain UPF.

**The TSC modification is its own message, not folded into the QER update.** The two
have different failure meanings — a rejected QER update means the authorised bandwidth
is not enforced; a rejected TSC update means the bridge is not configured — and
§7.5.5 gives ONE Cause per message, which cannot express both.

**Containers are transported byte-exact and not interpreted.** §8.2.144 and §8.2.182
say they carry TS 24.539 clause 8 and 9 messages, and this tree has no TS 24.539
codec. For the SMF and the PCF, relaying is the *correct* behaviour, not a shortcut.
For the UPF it is a ceiling, recorded below.

**A PMIC with no NW-TT Port Number is refused, not defaulted.** Port configuration
with no port is unattributable, and defaulting the number to 0 would silently name
the port the TSCTSF's own derivation reserves for the network side. The SMF refuses to
send one; the UPF answers `ConditionalIeMissing` with the NW-TT Port Number as the
Offending IE, and applies nothing.

## Verification

Whole workspace: **6464 passed, 0 failed** (main: 6433), clippy warnings unchanged at
74 (all pre-existing, none in the touched files), `cargo fmt --check` clean.

### Reverts, all of which bite

| revert | named test that failed |
|---|---|
| UMIC IE number 266 → 267 | `test_tsc_management_information_decodes_hand_built_wire`, `test_tsc_management_information_encodes_expected_ie_numbers` |
| Session Modification's carrier 199 → 201 | `test_session_modification_request_carries_tsc_under_ie_199` |
| remove the `tscu` gate (`if false`) | `test_tsc_containers_withheld_from_a_upf_without_tscu` |
| send the DS-TT container over N4 too | `test_tsc_containers_are_carried_on_a_session_modification` |
| never apply the containers in the UPF | `test_tsc_management_information_populates_the_tsn_bridge`, `test_tsc_modification_response_echoes_what_was_applied` |
| accept a PMIC with no port number | `test_tsc_pmic_without_port_number_is_rejected` |
| `S_NSSAI` 257 → 250 | `test_pfcp_ie_numbers_match_the_authoritative_table`, quoting the clause |

### Criterion 1's tests decode hand-built wire buffers

Not only the encoder's own output. A pure round-trip passes for any self-consistent
pair of functions, including one that agrees with itself on the wrong IE number —
which is the mistake worth catching when five IE numbers land at once. `wire_ie()`
builds headers the way a peer would, without touching the encoder under test.

## Ceilings

- ~~**`UpfSess.tsn_bridge` is still unreachable, and so is the rest of that store.**~~
  **RESOLVED by #325**, in the direction this note was waiting for: the dead half was
  deleted rather than populated. `UpfSess`, `UpfContext::sess_list`, the five lookup
  indices, the two framed-route tries and `rule_match`'s two UE-IP lookups are gone,
  so there is no longer a `tsn_bridge` field in an unreachable store — the live bridge
  on `PfcpSessionInfo`, which is where #321 put it and why, is now the only one.
  #325 also found what the dead store cost in production, which this note did not
  reach: `UpfContext::sess_count` had a production caller in `get_load`, so the UPF
  advertised `load: 0` to the NRF and (under `compute-aware-upf`) in the PFCP Load
  Control IE regardless of how many sessions it held. #223 remains open as the same
  defect class in `smfd`.
- **No TS 24.539 codec**, so the UPF stores the containers rather than acting on
  their contents. `TsnBridge.port_management_containers` and
  `user_plane_node_management_container` hold the raw octets; the gate-control lists
  and VLAN configuration a real bridge would derive from them need that codec.
- **The UPF's Bridge ID is derived from the SEID**, not read from configuration.
  §5.26.2 says these identities "may be pre-configured in the UPF based on
  deployment"; this build has no such configuration surface, so the SEID gives a
  value that is stable per session and distinct across sessions without inventing a
  deployment identity.
- **The SMF does not relay a received IE 201 onward to the PCF.** TS 23.502 Annex F.1
  says it should (as `SmPolicyUpdateContextData.tsnBridgeInfo` / the containers), and
  `parse_tsc_containers`' mirror image on the update-context side is not built. The
  report is decoded and recorded against the SEID, which is what criterion 4 asks
  for; the onward leg is the next piece.
- **`tsctsf`'s PMIC is still this build's own TLV encoding, not IEEE 802.1Q clause 12**
  (#321 scope item 5). Unchanged deliberately: replacing it needs the same TS 24.539 /
  802.1Q managed-object codec as the item above, and doing it here would have coupled
  a wire-format change to the plumbing change. The containers now travel end to end,
  which is what makes that substitution a local edit when the codec exists.
- **Direct Reporting Information (IE 295)** is not modelled. §7.5.4.18 makes it
  conditional on the UPF advertising the DRTSC feature, which this build does not.
- **In-process, not Docker E2E** (criterion 6). Every assertion here is a loopback
  request or a real UDP round trip inside one test process. The Docker jobs remain
  `workflow_dispatch`-only and no compose service sets anything TSC-related.

## Criterion table

| # | criterion | status |
|---|---|---|
| 1 | pfcp encodes/decodes TSC Management Information + Create/Created Bridge Info, round-trip against a hand-built buffer | **met** |
| 2 | a Session Modification carries PMIC/UMIC and `upfd` populates `tsn_bridge` from `None`, asserted from the UPF's own state | **met** — asserted from `PfcpServer::sessions`, over a real UDP round trip |
| 3 | `tscu` gates the carriage; a test covers a UPF with the bit clear | **met** — and the default stand-in has the bit clear, so this is the ordinary case |
| 4 | a Session Report carrying IE 201 reaches the SMF and is decoded | **met** — recorded in `TSC_REPORTS`, asserted from state |
| 5 | the PCF → SMF hop is implemented and stated in the PR | **met** — see "Scope item 4" |
| 6 | #284's criterion 4 satisfiable end to end; say which | **met, in-process** — stated above |
| 7 | whole-workspace lint and tests pass | **met** |

## References

- TS 29.244 k00 (vendored at `6g_docs/specs/29244-k00.txt`): §5.26.2, §7.5.3.6,
  §7.5.4.18, §7.5.5.3, §7.5.8.5, §8.2.21, §8.2.140-§8.2.144, §8.2.176, §8.2.182
- TS 29.512 (`6g_docs/specs/TS29512_Npcf_SMPolicyControl.yaml`): `SmPolicyDecision`
  lines 696-708, `PortManagementContainer` / `BridgeManagementContainer` lines
  2361-2379
- TS 23.501 §5.27-§5.28; TS 23.502 Annex F.1; TS 24.501 §5.4.5
- #284 (the actuation half), #113 (the control-plane half), #304 (the modification
  path this rides on), #306 (the accepted-but-not-applied defect class)
