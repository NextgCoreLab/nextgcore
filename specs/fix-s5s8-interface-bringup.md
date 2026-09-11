# nextgcore #52 (sgwcd + smfd): stand up the S5/S8 interface

Verified against `main` @ `b1797d8`. TS 29.274 §7.2.1, §7.2.2, §7.2.5, §8.18, §8.21, §8.34,
Tables 7.2.1-1 / 7.2.2-1; TS 23.401 §5.3.2.1, §4.3.8.1; TS 23.501 §4.3.1 NOTE 2.

#52 is accurate in every particular. Standing the interface up then exposed **three
further layers**, each invisible from either side alone — the same shape #54 found.

## Verified against current main

| claim in the issue | site on `b1797d8` | still true? |
|---|---|---|
| sgwcd answers the S11 CSR locally; no S5/S8 leaves | `gtp_path.rs` sent the Sxa request and answered from the Sxa reply | yes |
| the PAA is merely echoed from the MME | `parsed.paa` copied into `sess.paa` | yes |
| the S5-C builder set exists with `#[cfg(test)]` callers only | `s11_build.rs:449+` | yes |
| `build_s5c_create_session_request` reuses `ctx.s11_address()` | yes, with its own comment saying so | yes |
| `SgwcFsm::handle_s5c_message` is a log-only stub; `s5c_handler` has no production caller | `sm.rs:109` | yes |
| Bearer Resource Command answers `SERVICE_NOT_SUPPORTED` | yes, with a comment naming this issue | yes |
| smfd binds no GTP-C socket | no `UdpSocket` in `gtp_path.rs` | yes |
| smfd's `gtp_handler` is blanket-suppressed and has test-only callers | `#![allow(dead_code)]` etc. | yes |

## The three layers underneath

**Layer 1 — the SGW-C never kept what the anchor needs.** A conformant PGW requires
Serving Network (§8.18) and ULI (§8.21) for an E-UTRAN session; this tree's own smfd
answers `ConditionalIeMissing` without them. sgwcd's `s11_parse` **did not parse either**
— it kept a `uli_presence` boolean and nothing else — because nothing relayed anything.
So the first working relay was refused by the anchor it was built to reach.

**Layer 2 — the MME never sent them either.** #51 gave mmed a conformant CSR, and its
criteria named the Sender F-TEID and the Bearer Contexts. Serving Network and ULI were in
that issue's *prose* and not in its criteria, so they were correctly reported as met and
the chain still could not complete. Both are added to mmed's CSR here, because #52's
criterion 9 is unachievable without them.

**Layer 3 — two PDN-type numberings compared directly.** `build_create_session_response`
chooses between cause 16 and cause 18 ("New PDN type due to network preference") on
`ue_session_type != session_type as u8`. `PduSessionType` is the NAS/5G enum where
`Ipv4 == 0`; the GTP PDN Type IE is 1-based (§8.34). `handle_create_session_request` stored
the raw GTP value, so **every IPv4 session answered 18** — a spurious "the network chose
differently" on a request the network honoured exactly. Latent until #52 because neither
function had a production caller. Fixed at the source, in the handler.

Each layer was found by building the layer above it, not by reading. That is the argument
for the cross-daemon parity test below.

## Decision 1: relay first, then provision — and the S11 answer stays where #54 put it

TS 23.401 §5.3.2.1's order is MME → SGW → **PGW** → SGW → MME, and the PGW's response
carries the PAA and the PGW-U F-TEID that the SGW-U's Sxa session needs. So the S5-C stage
is **inserted before** the Sxa stage rather than replacing it: `S11Continuation` rides
through untouched, and the MME's answer is still produced by #54's `sxa_response` from a
session that now holds the PGW's values.

Keyed by the S5-C sequence number, which is what correlates the PGW's answer. An
uncorrelated Create Session Response is dropped with a warning rather than acted on.

## Decision 2: with no PGW configured, the SGW-C REFUSES

Answering locally is the defect. `SGWC_PGW_S5C` unset means the S11 Create Session Request
is answered `REMOTE_PEER_NOT_RESPONDING` with **no PAA**, and that is asserted. A
fabricated success is worse than a visible refusal, and there is no PGW *selection*
function here — §4.3.8.1 selects by APN via DNS, which this tree does not implement, so
one configured peer is the honest model.

## Decision 3: smfd's server is async; mmed's and sgwcd's are not

Those two are synchronous because the NAS and S1AP paths that originate their messages
are. smfd is the **terminating** end, and answering a Create Session Request requires
awaiting an N4 exchange — so an async receive loop lets the handler await it directly, and
smfd needs none of the deferred-continuation machinery #54 had to build for sgwcd. Each
datagram is handled in its own task, because handling inline would stop the socket
receiving for the duration of an N4 round trip — including the SGW-C's retransmission of
the request being served.

The T3/N3 budget still comes from the shared `Gtp2XactMgr`, so all three GTP-C endpoints
in this tree agree about how long a message may take.

## Decision 4: `has_gx_peer` is passed `true`, and why

smfd has Gx *state* (`gsm_sm.rs`'s CCR/CCA fields) and no Gx transport. The handler rejects
with `RemotePeerNotResponding` when told there is no Gx peer, which would make this
endpoint refuse every Create Session Request — a socket that binds and serves nothing.

TS 23.401 does not require a PCRF for a PGW to serve a session, and
`policy::PolicyDecision::config_default_for_dnn` is a policy source — the same one the 5G
path falls back to when no PCF is configured (recorded precedence: PCF, then subscription,
then config default). So the parameter is passed `true` on the grounds that a policy source
exists. Recorded rather than silently done, because it reinterprets what that argument
means.

## Decision 5: the allocated address is released on every failure path

A leaked address per refused request exhausts a /16 silently, and the UE never received it.
`release_and_reject` is the single exit for every rejection after allocation.

## Verification

| claim | how it was made to fail | result |
|---|---|---|
| the SGW-C relays a CSR to the PGW | suppress the `send_request` | **fails** |
| the PAA comes from the PGW's response | write `None` instead | **fails** |
| no configured PGW is refused, not answered | fall back to a bogus peer | **fails** |
| mmed's CSR carries Serving Network | delete the `add_ie` | **fails** |
| sgwcd relays Serving Network | short-circuit the relay | **fails** |
| sgwcd retains the MME's ULI | store `None` | **fails** |
| smfd allocates the PAA rather than echoing | use the request's PAA | **fails** |
| smfd echoes the request's sequence number | drop the assignment | **fails** |

Eight reverts, eight bites.

**Three of my own mistakes are worth recording**, because each was caught by a different
instrument:

- The first `with_sequence_number` patched three octets at a fixed offset that is only
  right when the TEID-present flag is set. The response went out with sequence 0 and the
  test caught it; it now decodes, sets the header, and re-encodes.
- I set the process-global PGW peer **before** taking the guard that serialises sgwcd's
  ambient configuration, which broke three existing tests — the unlocked-writer race #308
  was about, reintroduced by me two issues later.
- The smfd wire test was failing for several steps while I worked on sgwcd, and I lost
  track of it. The **whole-workspace run** is what surfaced it again. A per-crate run I had
  stopped reading would not have.

Three existing sgwcd tests failed once the relay landed, because they asserted the old
"answer from Sxa alone" behaviour — the defect pinned as the requirement, which this repo
has recorded as systematic. They were given a stand-in anchor rather than reverted.

Workspace **6352 passed / 0 failed** (was 6347), `clippy --workspace` 0, `fmt --check`
clean. sgwcd 81 → 84 tests, smfd 464 → 466, mmed unchanged at 338.

## Ceilings

- **Criterion 9 is verified in two halves, not as one process.** sgwcd's chain is driven end
  to end over real sockets against a **stand-in** anchor; smfd's PGW-C role is driven over
  a real socket by its own test. The two are **not** run against each other, because both
  are binaries with no lib target — the same ceiling #51 recorded for its criterion 3.
  What bridges them is `the_relayed_s5c_request_carries_what_the_anchor_requires`, which
  asserts sgwcd's relayed request carries the IE set smfd's handler requires. That guard is
  load-bearing, not decorative: the first version of this change relayed neither Serving
  Network nor ULI and the real anchor refused it.
- **The EPC compose file is untouched.** `docker-compose-epc.yml` has no PGW-C service (its
  own header comment says bridging EPC↔5GC via SMF+PGW-C is future work), so there is
  nothing to point `SGWC_PGW_S5C` at. Adding that service is #303's stage, and a
  half-wired compose would be worse than none.
- **smfd's restart counter is not persisted.** mmed and sgwcd each persist theirs; smfd's is
  a constant `1`, so a peer cannot detect an smfd restart. Inventing a third answer to the
  same question inside this issue was the wrong place for it.
- **Only Create Session is terminated by smfd.** Delete Session, Modify Bearer and the
  PGW-initiated procedures answer `ServiceNotSupported` with a cause rather than being
  dropped, so the SGW-C's transaction completes instead of expiring on T3 — but they are
  not implemented. The handlers for them exist and remain unreached.
- **The PGW-initiated relay toward the MME is written and not exercised.** Nothing in this
  tree originates a Create/Update/Delete Bearer Request from the PGW, so
  `forward_pgw_bearer_procedure_to_mme` has no test driving it. It is a correct
  implementation in a place nothing reaches yet, and this spec says so rather than implying
  coverage.
- **`sess_find_by_teid` resolves the S5-C TEID only because `sess_add` derives it from the
  SEID** (`context.rs:791-792`). True by construction, not by intent, and commented at the
  call site.
- **smfd serves IPv4 only**, because `ipv4_pool` is its only pool. An IPv6 or IPv4v6 request
  now legitimately gets cause 18.
- **No E2E.** The Docker jobs are `workflow_dispatch`-only and untouched.
