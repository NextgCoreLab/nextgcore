# Read the SGW-U the operator configured, so the SGW-C stops associating with itself

**Issue:** nextgcore #387 (a `bug` found by the `EPC bring-up` CI stage)
**Verified against:** nextgcore `main` @ `89cb764`
**Spec basis:** TS 29.244 §4.2.2 (PFCP on UDP 8805); §5.8.1 (one association per CP/UP
pair, the Node ID identifies it, a CP function may hold several associations);
§6.2.6.2.1 (the CP function retrieves an IP address **of the UP function** and initiates
the association before the first session); §6.2.6.2.2 (the UP function **stores the Node
ID of the CP function as the identifier of the PFCP association**); §7.4.4 (Association
Setup Request); §8.2.38 (Node ID). Spec text read at `6g_docs/specs/29244-k00.txt`.

## The failure

Run [35560858147](https://github.com/NextgCoreLab/nextgcore/actions/runs/35560858147),
step **"Wait for PFCP association (SGW-C <-> SGW-U over Sxa)"**:

```
::error::sgwu_pfcp_associations never reached 1; the SGW-C did not establish Sxa
```

The three steps after it — Sxb/N4, the PGW-C's S5/S8 socket, the NF health loop — never
ran. From the collected container logs of the same run:

```
nextgcore-sgwc | INFO  nextgcore_sgwcd::pfcp_path] PFCP/Sxa listening on 0.0.0.0:8805 (Node ID 127.0.0.1, ...)
nextgcore-sgwc | WARN  nextgcore_sgwcd::pfcp_path] PFCP message type 5 from 127.0.0.1:8805 is not handled on Sxa (CP side)
nextgcore-sgwc | WARN  nextgcore_sgwcd::pfcp_path] PFCP T1 expired: retransmitting type=5 seq=1 to 127.0.0.1:8805 (attempt 2/3)
nextgcore-sgwc | ERROR nextgcore_sgwcd::pfcp_path] PFCP request type=5 seq=1 to 127.0.0.1:8805 unanswered after 3 attempts
```

The SGW-C addressed `127.0.0.1:8805` — its **own** Sxa socket — so it received its own
Association Setup Request back, could not handle a request of type 5 on the CP side,
retransmitted to T1/N1 exhaustion, and gave up. The SGW-U at `172.24.0.6` never saw a
datagram, so `sgwu_pfcp_associations` stayed at 0. The metric was telling the truth.

## Verified against `89cb764`

Every cite in #387 re-checked. All hold.

| claim | check at `89cb764` | still true? |
|---|---|---|
| `configured_sgwu_addr()` reads only `SGWC_SGWU_ADDR`, falling back to `Ipv4Addr::LOCALHOST` | `pfcp_path.rs:782-789` | yes — **real** |
| `grep -rn "SGWC_SGWU_ADDR" docker/` returns nothing | returns nothing; the only tree hit outside `pfcp_path.rs` is `gtp_path.rs:2219`, a test helper | yes — **real** |
| `sgwc.yaml` declares `pfcp.client.sgwu: 172.24.0.6` | `configs/epc/sgwc.yaml:21-23` | yes |
| sgwcd parses no `client` section | `grep -rn client context.rs` returns nothing — and sgwcd has **no config module at all**; `SgwcApp::init` takes `_config_path` (`main.rs:90`) and the crate has no serde dependency | yes — **real, and worse than filed** |
| two call sites depend on it | `main.rs:142` (startup association) and `enqueue()` at `pfcp_path.rs:812`, which every session/report/DROBU send funnels through | yes — **real** |
| the Node ID is loopback for the same reason | `pfcp_open` at `:768` reads `SGWC_PFCP_NODE_IP`, also set nowhere, also defaulting to `127.0.0.1`; used at `:486` in `NodeId::new_ipv4` | yes — **real, same root cause** |
| #380's PGW-C/PGW-U associated correctly in the same run | `nextgcore_smfd::pfcp_path] PFCP association established with 172.24.0.7:8805`; `SMF N4 PFCP socket bound on 172.24.0.4:8805 (UPF peers: [172.24.0.7:8805])` | yes — **#380 is not at fault** |
| #328's assertion exposed rather than caused it | the stage was renamed from "Docker E2E (EPC)"; the last run under the old name, [35540548005](https://github.com/NextgCoreLab/nextgcore/actions/runs/35540548005), passed on fixed sleeps | yes |

### Found while verifying, and not in the issue

**sgwcd had no configuration loader whatsoever.** #387 says `pfcp.client.sgwu` is
"declared and never read", which understates it: *no* key in `sgwc.yaml` is read. The path
is parsed by clap, logged (`main.rs:303`), passed to `init` and discarded. This is exactly
the state `mmed` was in before #157, where the consequence was an empty `served_gummei`
and an MME that refused every eNB association. So the fix is a loader, not a lookup.

## Decision 1: read the YAML; do **not** add `SGWC_SGWU_ADDR` to the compose file

**Taken.** Adding the env var would make the CI stage green in one line and leave
`pfcp.client.sgwu` declared and ignored — the same defect class as the bug, and the one
this tree keeps hitting: a correct value in a place nothing reads.

TS 29.244 §6.2.6.2.1 (`29244-k00.txt:13205`):

> The CP function shall retrieve an IP address of the UP function to send the PFCP
> Association Setup Request, as specified in clause 5.8.1

The address has to come from somewhere, and the operator already wrote it down. The
loader is where "somewhere" is.

## Decision 2: follow `mmed`'s `config.rs`, not `smfd`'s loader

**Taken.** Two precedents exist and they disagree, so this names which and why.

* **`nextgcore-mmed`'s `config.rs` (#157)** — chosen. Same problem (a shipped YAML read by
  nothing), same document layout (`<nf>.<iface>.server` / `.client.<peer>` as lists of
  `{address, port}`), and it already parses `mme.gtpc.client.sgwc` — an S11 **peer list** —
  into exactly the shape `pfcp.client.sgwu` needs, including the "first entry is used, the
  rest are named in a warning" rule and the `parse_socket_addr` helper. `mme.yaml` and
  `sgwc.yaml` are the two halves of the S11 reference point, so the two loaders now accept
  the same spellings of an address.
* **`nextgcore-smfd`'s `main.rs` loader** — rejected as the model. It does parse YAML, but
  it reads its **PFCP peer** from `UPF_PFCP_ADDR` in the environment, not from
  `smf.pfcp.client.upf` — `pgwc.yaml`'s own comment says so, and that is why the PGW-C
  worked in the failing run. It is precedent for the wrong half of this problem.

The 5G `smf`/`upf` pair has the same CP/UP shape and associated fine, but by the
environment route; copying it would reproduce the declared-and-ignored key one NF over.

## Decision 3: `client.sgwu` is a list; only the first entry is used, and that is stated

**Taken, as a ceiling.** TS 29.244 §5.8.1 (`29244-k00.txt:6151`):

> A CP function may have PFCP Associations set up with multiple UP functions.

So more than one entry is legal, and this SGW-C cannot serve it. Choosing *which* UP
function serves a session is a selection function sgwcd does not have: `QueuedRequest`
carries exactly one `to: SocketAddr` and nothing maps a session to a peer. Compare
`smfd`, which has `select_upf`, a client pool and a SEID→peer binding.

Associating with every configured peer would therefore establish associations no session
could ever be placed on — advertising a capability that is not there. So every entry is
**parsed** (so the warning can count them), the first is used, and the rest are named at
load time. Pinned by `several_sgwu_entries_are_kept_and_the_first_is_the_one_used`, so a
later change that starts associating with all of them has to revisit this deliberately.

## Decision 4: the Node ID is the same root cause, and is fixed here

**Taken, not scope creep.** `PFCP/Sxa listening on ... (Node ID 127.0.0.1, ...)` has the
same shape as the peer bug: a value that *is* configured (`sgwc.pfcp.server[0].address:
172.24.0.3`) reached by nothing, defaulting to loopback. It is the same file, the same
section, the same loader, and it would be a second unread key if left.

It also matters on the wire. TS 29.244 §5.8.1 (`29244-k00.txt:6157`):

> In PFCP signaling, a CP function or a UP function shall be identified by a unique Node
> ID. ... When set to an IP address, it indicates that the CP/UP function only exposes one
> IP address for the PFCP Association signalling. Once a PFCP association is set up ... the
> same Node ID ... shall be used in all subsequent PFCP node related messages ... until the
> PFCP association is released.

and §6.2.6.2.2 (`:13232`) has the UP function, on accepting the request:

> shall store the Node ID of the CP function as the identifier of the PFCP association

A CP function advertising `127.0.0.1` asks a remote UP function to key the association on
an address meaningless off-host — wrong independently of the peer-address bug. Would the
association still have come up with a loopback Node ID? Against `sgwud`, yes: it stores
the value without resolving it. That is precisely why this is worth fixing rather than
leaving: it is a latent conformance defect that no assertion in this tree would catch.

`sgwc.pfcp.server` is capped at one entry with a warning, because §5.8.1 gives a CP
function one Node ID.

## Decision 5: the env vars stay, as overrides ahead of the file

**Taken.** `SGWC_SGWU_ADDR` and `SGWC_PFCP_NODE_IP` keep first precedence:

1. the env var — the test escape hatch. `gtp_path::tests::stand_in_sgwu` puts a stand-in
   SGW-U on an **ephemeral loopback port** rather than fighting a live daemon for UDP/8805,
   and twelve tests depend on it. Removing it would mean rewriting them to write global
   context instead, for no gain;
2. the configured peer from YAML — what production uses;
3. `127.0.0.1:8805` — the single-host default.

The loopback fallback is kept rather than made fatal: an unconfigured daemon should still
start and still serve S11 diagnostics. What was missing was not a hard failure but a
**warning**, and `config::apply` now emits one naming the key to set and the clause that
requires it.

## What changed

| file | change |
|---|---|
| `src/bins/nextgcore-sgwcd/src/config.rs` | **new.** `load_config` + `apply`, modelled on `mmed`'s. Parses `sgwc.pfcp.server` → Node ID and `sgwc.pfcp.client.sgwu` → peer list; accepts `sgwc.gtpc` without applying it |
| `src/bins/nextgcore-sgwcd/src/context.rs` | `pfcp_node_ip` / `sgwu_peers` slots + accessors; `PROCESS_STATE_TEST_LOCK`'s doc extended to cover them |
| `src/bins/nextgcore-sgwcd/src/pfcp_path.rs` | `configured_sgwu_addr` falls back to the configured peer instead of loopback; new `configured_node_ip`; the test guard resets both slots |
| `src/bins/nextgcore-sgwcd/src/main.rs` | `init` READS `config_path` (was `_config_path`), before `pfcp_open` |
| `src/bins/nextgcore-sgwcd/Cargo.toml` | `serde`, `serde_yaml` |
| `docker/rust/configs/epc/sgwc.yaml` | comments stating which keys are read, which is not and why, and the one-Node-ID / one-peer rules |

**No compose-file change.** `sgwc.yaml` already carried the right answers.

### Every Sxa send path, not just the association

Both call sites of `configured_sgwu_addr` are corrected by one change because both read the
same resolver:

* `main.rs` — the startup association (TS 29.244 §6.2.6.2.1);
* `pfcp_path::enqueue` — which `send_session_establishment_request`,
  `send_session_modification_request`, `send_bearer_modification_request`,
  `send_bearer_to_modify_list`, `send_indirect_forwarding_tunnels`,
  `send_session_deletion_request`, `send_session_report_response` and
  `send_drop_buffered_packets` all funnel through.

Asserted by `the_sxa_destination_is_the_configured_sgwu_not_loopback`, which checks the
resolver *and* `ctx.sgwu_peer()` — the value both sites read — rather than one site.

## Tests, and how they were revert-verified

Assertions are **positive**: they assert the resolved value EQUALS `172.24.0.6:8805` /
`172.24.0.3`, values reachable only by actually reading the file. "Is not loopback" would
be satisfiable by a second bug.

| test | made to fail by |
|---|---|
| `pfcp_path::tests::the_sxa_destination_is_the_configured_sgwu_not_loopback` | replacing the `sgwc_self().sgwu_peer()` fallback with the old `SocketAddr::from((Ipv4Addr::LOCALHOST, PFCP_PORT))` → FAILED, "every Sxa send must address the SGW-U named in sgwc.pfcp.client.sgwu" |
| the Node ID half of the same test | replacing `configured_node_ip`'s context read with `Ok(Ipv4Addr::LOCALHOST)` → FAILED, "the UP function stores the CP function's Node ID as the association identifier" |
| all four `config::tests` + the above | making `resolve` iterate an empty peer list (the pre-#387 "reads no client section" state) → 5 FAILED |

Restored and re-confirmed green after each.

### Process-global test state

`config::tests` needs no lock: `load_config` returns a value and touches no global. The
`pfcp_path` tests do take `pfcp_path::process_state_test_guard()` — the existing
`context::PROCESS_STATE_TEST_LOCK`, **not** a new one, because #276 showed a second lock
over shared state hangs the suite. `clear_sxa_globals_for_test` (called on both acquire and
drop) now also resets `sgwu_peers` and `pfcp_node_ip`, so cleanup does not depend on a
failing test reaching its own last line — a leaked peer would otherwise choose the
destination of the next test's PFCP request.

## Acceptance criteria

- [x] `sgwcd` parses `sgwc.yaml` and resolves the SGW-U peer to `172.24.0.6:8805` from
      `pfcp.client.sgwu`, asserted as equality.
- [x] Every Sxa send path uses it — the startup association and `enqueue`.
- [x] The Node ID comes from `pfcp.server[0].address`.
- [x] Multi-entry `client.sgwu` has documented, tested behaviour.
- [ ] The `EPC bring-up` job's Sxa step passes on a dispatched run, and the job reaches and
      passes the subsequent Sxb, S5/S8 and NF-health steps. *(Recorded in the PR: the job
      is dispatch-gated, so a green PR proves nothing about it.)*

## Ceilings this does not lift

* **`sgwc.gtpc.server` stays unread.** Applying it would feed `set_gtpu_address`, and the
  SGW's user-plane endpoints are on the SGW-U (`172.24.0.6`), not the SGW-C
  (`172.24.0.3`) — so it would replace today's loud "No GTP-U address configured" with a
  wrong address that fails invisibly, GTP-U being unacknowledged. That needs the SGW-U's
  GTP-U address, which this file does not carry.
* **`SGWC_PGW_S5C` is still env-only.** `gtpc.client` does not exist in `sgwc.yaml` (the
  PGW-C peer is named in `mme.yaml`'s `client.smf` and in the compose environment), so
  there is no declared key going unread. Out of scope here.
* **No UP function selection.** One SGW-U per SGW-C, stated at the site (Decision 3).
* **The attach chain is still not exercised end to end.** No LTE eNB/UE originator exists
  (nextgsim #186); `specs/epc-e2e-scope.md` is unchanged by this.

## References

- #387 (this), #328 (the assertion that exposed it), #380 / #385 (PGW-C/PGW-U — not at
  fault), #157 (`mmed`'s loader, the precedent), #54 (the Sxa transport), #59 (SGW-U side),
  #276 / #368 (why there is one process-state lock)
- Failing run [35560858147](https://github.com/NextgCoreLab/nextgcore/actions/runs/35560858147);
  last green under the old stage name
  [35540548005](https://github.com/NextgCoreLab/nextgcore/actions/runs/35540548005)
- `6g_docs/specs/29244-k00.txt` §4.2.2, §5.8.1, §6.2.6.2, §7.4.4, §8.2.38
