# Declare the PGW-C and PGW-U in the EPC deployment, so the S5/S8 leg has somewhere to land

**Issue:** nextgcore #380 (a `bug` found while answering #328)
**Verified against:** nextgcore `main` @ `3813bd9`
**Spec basis:** TS 23.401 §4.2.1 (single-gateway option), §5.3.2.1 (PDN Address allocation
is a PGW function); TS 23.214 §4.2.2 (combined SGW/PGW with split CP/UP);
TS 29.244 §5.2.6 (combined Sxa/Sxb), §6.2.6 (association scope), §6.2.6.2 (no session
signalling without an association); TS 29.274 §4.1 (GTPv2-C on UDP 2123), §7.2.1 (the SGW
RELAYS a Create Session Request), §8.22 (F-TEID). Spec text read at
`6g_docs/specs/23401-k00.txt` and `6g_docs/specs/29244-k00.txt`.

## Verified against current main

Every cite in #380 re-checked at `3813bd9`. **All four criteria are real** — this is the
first issue in this batch whose premise held completely, and the reason is that #380 was
filed from a `grep` rather than from a code reading.

| claim in the issue | check on `3813bd9` | still true? |
|---|---|---|
| `docker-compose-epc.yml` declares six services: `mongodb-epc`, `hss`, `pcrf`, `sgwc`, `mme`, `sgwu` | exactly those six | yes — **real** |
| `grep -cE 'pgwc\|smfd' docker-compose-epc.yml` returns 0 | returns 0 | yes — **real** |
| the 5G compose returns 2 for `smf`/`upf` | 2 service definitions | yes |
| #52 landed a real PGW-C GTPv2-C endpoint in `smfd` | `gtp_path.rs:1204`/`:1209` dispatch; `main.rs:744` calls `gtp_path::s5s8_open`; `gtpc_addr` parsed at `main.rs:358` | yes — **real**, and it is what makes this a deployment change rather than new protocol work |
| `create_session` allocates the PDN address and provisions over N4 | `gtp_handler.rs:~1074`, `ipv4_pool.allocate()` at `:1107` | yes |
| #52 and #328 are CLOSED; #303 is OPEN | `gh issue view`: CLOSED, CLOSED, OPEN | yes |
| the attach originator is out of scope, tracked as nextgsim #186 | nextgsim #186 is OPEN: "no LTE eNB or UE simulator" | yes |
| the health loop added under #328 cannot catch an undeclared service | `ci.yml` iterates a hard-coded `for svc in hss pcrf sgwc sgwu mme` | yes — **real**, and it is why adding a name to that list is load-bearing rather than cosmetic |

### Found while verifying: three things neither #380 nor #328 records

**1. The SGW-C already refuses every Create Session Request, loudly.** `gtp_path.rs:455`
reads `SGWC_PGW_S5C` from the environment and nothing in any compose file sets it, so
`:466` logs

> no SGWC_PGW_S5C configured: the S5/S8 leg is unavailable, so a Create Session Request
> will be REFUSED rather than answered from local state

This is worse than #380's framing ("the S5/S8 leg is not exercised"): the leg is not merely
unexercised, it is *configured off*. So the fix is two changes, not one — declare the
containers, and point the SGW-C at the PGW-C. Declaring the containers alone would have
left the SGW-C refusing requests against a PGW-C that was up and idle, and the CI stage
would have gone green on it.

**2. `mme.yaml` has named the PGW-C's address all along, against nothing.**
`configs/epc/mme.yaml` declares `mme.gtpc.client.smf: 172.24.0.4`, and
`configs/epc/README.md` documents `SMF/PGW-C | 172.24.0.4` and `UPF/PGW-U | 172.24.0.7`.
The addressing was decided; only the services were missing. This spec therefore changes no
address — it declares services at the addresses already written down, which is the
lowest-risk shape available and removes a documented-but-absent NF from the tree.

**3. Neither `smfd` nor `upfd` had a metrics endpoint, so criterion 2 was not reachable.**
Criterion 2 asks for the association to be "assertable the way `sgwu_pfcp_associations`
is". That metric exists because #59 gave `sgwud` a `/metrics` endpoint
(`sgwud/src/main.rs:41-46`). `grep -rn serve_metrics src` finds three callers — `sgwud`,
`udmd`, `nsacfd` — and neither `smfd` nor `upfd` is among them. So criterion 2 required a
small amount of Rust, and this is the part of #380 that is not a pure compose change.
#380's "if so this is a compose-file and config change rather than new code" is therefore
*almost* right and worth naming: the PGW-C role needs no new code, but making it
**assertable** does.

## Decision 1: `nextgcore-smfd` serves as the PGW-C; no separate binary or build

**Taken.** The PGW-C role is a deployment of the existing binary, not a new one.

TS 23.401 §4.2.1's single-gateway option permits a combined SGW/PGW node
(`23401-k00.txt:1932`, and NOTE 1 at `:1936`: "Also in this configuration option, S5 can be
used between non collocated Serving Gateway and PDN Gateway"). TS 29.244 §5.2.6 is how that
survives a CP/UP split — `29244-k00.txt:4291`:

> The usage of a combined SGW/PGW remains possible in a deployment with separated control
> and user planes, see clause 4.2.2 of TS 23.214. This is enabled by supporting a combined
> Sxa/Sxb interface with a common packet forwarding model, message and parameter structure
> for non-combined and combined cases.

And the code is already shaped that way. `smfd`:

* parses `smf.gtpc.server` into `config.gtpc_addr` (`main.rs:358`) and binds it as the
  S5/S8 socket (`main.rs:717`, `gtp_path::s5s8_open` at `:744`) on TS 29.274 §4.1's
  UDP 2123;
* terminates a Create Session Request in `gtp_handler::create_session`, allocating the PDN
  Address from `ipv4_pool` — a PGW function per TS 23.401 §5.3.2.1 — and provisioning the
  user plane over N4;
* leaves the role **unbound** when `smf.gtpc.server` is absent, logging "the S5/S8 (PGW-C)
  role is NOT bound". That is the state every deployment in this tree was in.

Rejected alternatives:

| option | cost | why not |
|---|---|---|
| **A new `nextgcore-pgwcd` binary** | a second copy of S5/S8, N4, the IPv4 pool and the session model, which would drift from `smfd`'s — and `smfd`'s is the one #52 and #223 are actively building | The spec says one node may be both. A second binary would be a *fork* of the session anchor, and the two would disagree about a session under 5GS↔EPS interworking (TS 23.502 §4.11.1), where one node genuinely must be both the SMF and the PGW-C for the same subscriber. |
| **A `pgwc` cargo feature on `smfd`** | CI would have to build and test both feature states, and the un-built state would rot | There is nothing to gate. The S5/S8 socket binds iff configured; the role is already a runtime property. A feature would make a config question into a compile-time one, which this repo has declined before (`easdf.rs`, `eps_iwk.rs` are both runtime switches for exactly this reason). |
| **A distinct image tag (`nextgcore-rust/pgwc`) from the same binary** | a second `docker build` per release for byte-identical content | One image per binary, not per role. The role is which config and which network a container gets, and `nextgcore-rust/smf` being the PGW-C image here and the SMF image in the 5G stage is the honest description of what it is. |

The **root YAML key stays `smf:`** in `pgwc.yaml`, because that is what `SmfYaml` parses.
Renaming it to `pgwc:` would deserialise to `None`, fall back to defaults, leave
`gtpc_addr` unset, and leave the socket unbound — a silent failure, and the config file is
where it would have been introduced. Stated in a comment at the top of the file.

## Decision 2: the EPC gets its OWN PGW-U; it does not share the 5GC's

**Taken.** A dedicated `upfd` instance on the `epc` network at 172.24.0.7.

Three reasons, each sufficient alone:

**1. Reachability.** `core` (172.23.0.0/24) and `epc` (172.24.0.0/24) are separate Docker
bridge networks with no route between them. The 5G `upf` at 172.23.0.7 is not addressable
from the SGW-C at all. "Share it" is not a deployment that comes up — it is a deployment
whose Sxb association never establishes, which the new CI gate would fail on.

**2. F-TEID addressing** — the consideration #380 flags. The S5-U F-TEID the PGW-C hands
the SGW-U must carry an address the SGW-U can send GTP-U to (TS 29.274 §8.22). A 172.23.x
address in an F-TEID on the `epc` network is a tunnel endpoint that blackholes, and it
blackholes *silently*, because GTP-U is unacknowledged — there is no error to observe.

**3. TS 29.244 §6.2.6 scopes an association to one CP/UP function pair, and `upfd`
implements that literally.** `PfcpServer::association` is
`tokio::sync::RwLock<Option<PfcpAssociation>>` — an `Option`, not a map
(`upfd/src/pfcp_path.rs:518`). A second CP function's Association Setup **overwrites** the
first's (`:1004`), and `check_peer_recovery` (`:912`) then compares the stored
`peer_addr`/`recovery_time_stamp` against the incoming datagram's, so the displaced peer's
next heartbeat is read as a restart and `declare_peer_failure` flushes every session it
held (`:767`). Sharing one UPF between the 5G SMF and the EPC PGW-C is therefore not
merely inelegant; it is a correctness failure the spec already forbids and the
implementation already cannot express.

Rejected alternative: **attach the 5GC's `smf`/`upf` to both networks** via a second
`networks:` key. Costs: (a) the EPC compose file would only work when the 5G stack is also
up, turning a standalone EPC deployment into a dependent one and breaking `./e2e.sh
--overlay epc` in isolation; (b) point 3 above makes it *wrong*, not just coupled — one
`upfd` process would have two CP peers and would flush one peer's sessions each time the
other heartbeated; (c) an operator copying `docker-compose-epc.yml` as a template for a
real EPC would inherit a shared session anchor, which is the misleading-template hazard
#380 raises. Reason (b) alone settles it.

## What changed

### The deployment (criteria 1, and the SGW-C fix #380 does not name)

`docker/rust/docker-compose-epc.yml`:

* **`pgwc`** — `nextgcore-rust/smf:latest` at 172.24.0.4, config `configs/epc/pgwc.yaml`,
  `SMF_PFCP_ADDR`/`UPF_PFCP_ADDR` pointing at itself and the PGW-U.
  `NEXTGCORE_SBI_PROFILE: dev` because `smfd` defaults to the PRODUCTION SBI profile (#63)
  and would otherwise refuse to start naming a missing certificate path — the same explicit
  opt-out `docker-compose.yml` carries, for the same reason. Note what that does **not**
  weaken: S5/S8 is GTPv2-C over UDP and TS 29.274 defines no transport security, so the
  PGW-C role is unaffected by the profile either way.
* **`pgwu`** — `nextgcore-rust/upf:latest` at 172.24.0.7, config `configs/epc/pgwu.yaml`,
  TUN device `epctun` (distinct from the 5GC's `ogstun` so `ip addr` is legible on a host
  running both), UE pool 10.45.0.0/16 matching the PGW-C's `ipv4_pool`.
* **`SGWC_PGW_S5C: "172.24.0.4"`** on the existing `sgwc` service. Without this the SGW-C
  refuses every Create Session Request regardless of what is deployed (see finding 1).
* **`mme` now `depends_on: pgwc: service_healthy`**, not `service_started`: `started` is
  true of a container whose process has not bound its S5/S8 socket yet, which is precisely
  the state a relayed request cannot be answered in.

Both healthchecks are **functional**, following the `sgwu` precedent from #59 rather than
the shared `kill -0 1` anchor: `curl`-and-grep `^smf_up 1$` / `^upf_up 1$` from the live
metrics endpoint, which can only be answered while the runtime is serving. Deliberately
**not** the association gauge on the same body — the PGW-C associates only after both
containers are up, so gating *liveness* on it would report the PGW-C unhealthy during every
normal bring-up and `restart: on-failure:5` would thrash it. Association is a *readiness*
property, which compose has no separate notion of, so the CI stage owns that gate.

`docker/rust/build.sh` gains a comment, not a loop entry: `smfd` and `upfd` are already
built by the 5GC loop, and the coupling (removing either would leave the EPC with no
anchor) is stated where someone editing that loop reads it.

### The assertable association (criterion 2)

Criterion 2 was not reachable without a metrics endpoint on either daemon, so both got one,
modelled on `sgwud`'s:

* **`smfd`**: `render_metrics()` emits `smf_n4_associations`, `smf_n4_peers`,
  `smf_sessions`, `smf_s5s8_bound`, `smf_up`. `smf_n4_associations` counts the pool's live
  association state, and `smf_s5s8_bound` is 1 iff `gtp_path::s5s8_server()` is installed.
* **`upfd`**: `upf_pfcp_associations`, `upf_pfcp_sessions`, `upf_up`.
  `upf_pfcp_associations` is 0-or-1 rather than a count, because TS 29.244 §6.2.6 scopes an
  association to one CP/UP pair and the implementation holds exactly one.

Both needed a **synchronously-readable projection** of association state, because
`serve_metrics` takes a plain `Fn() -> String` and the authoritative state is behind a
`tokio` lock. This is the same shape `sgwud`'s `associated_peers` and `upfd`'s
`session_count` (#325) already use, and it is maintained the same way: a
`publish_associated` that takes the write guard, so it can only be called from inside a
critical section that already holds the state, and always **assigns** what the guard holds
rather than toggling. Every write site that touches the association calls it — three in
`smfd` (`associate`, `teardown_association`, the request-exhaustion path) plus the
test-only setter, two in `upfd` (`handle_association_setup_request`,
`declare_peer_failure`).

`upfd` hands its two handles to a `METRICS_SOURCES` `OnceLock` rather than the render
reading through the server, matching `session_count_handle`'s reasoning: the server owns the
state, and the render owning a copy would be the two-stores-one-path shape #325 rejected.
It also means the metric and the NRF `/load` report read the same store and cannot disagree.

### The CI stage (criterion 3)

`.github/workflows/ci.yml`, `docker-e2e-epc`:

* the EPC image loop gains `smfd upfd`;
* `pgwu` is started **before** `pgwc`, so the first Association Setup has a peer rather than
  waiting out the 10s re-association hold-off;
* a new **"Wait for PFCP association (PGW-C ↔ PGW-U over Sxb/N4)"** step, following the
  existing Sxa gate's shape exactly — poll the daemons' own `/metrics`, 60 one-second
  attempts, dump both services' logs and `exit 1` on timeout. It asserts **both ends**:
  `smf_n4_associations >= 1` says the CP function received an Association Setup *Response*;
  `upf_pfcp_associations >= 1` says the UP function accepted a *Request* and stored the
  peer. Asserting only the CP side would pass on a PGW-C that believed in an association
  the PGW-U had since flushed; only the UP side would pass on an association some other CP
  function set up;
* a new **"Assert the PGW-C's S5/S8 socket is serving"** step on `smf_s5s8_bound == 1`.
  Separate from the association gate because it fails for a different reason and deserves a
  different message: an operator reading "the S5/S8 socket is not bound" goes to
  `pgwc.yaml`; one reading "Sxb never came up" goes to the PGW-U. A PGW-C with an unparsable
  `smf.gtpc.server` logs a warning, comes up healthy, associates over Sxb, and passes the
  association gate with nothing on 2123;
* `pgwc` and `pgwu` added to the health loop's `for svc` list.

All three are **positive** assertions — on state only reachable when the thing genuinely
works. None is an absence-of-error check, which would be satisfied by every path that never
arrives.

### The docs (criterion 4)

`docker/rust/README.md`: the EPC scope note drops "the S5/S8 leg has no container to reach"
and states what is now asserted (both associations, the bound socket) and what still is not.
The EPC network diagram gains the PGW-C/PGW-U with their interfaces. The port table and the
compose-file table follow. `docker/rust/configs/epc/README.md` gains the config column, the
combined-SGW/PGW rationale, and a **cross-file agreement table** — the three values
(PGW-C S5/S8 address, PGW-U PFCP address, UE pool) that appear in several places and whose
mismatch fails silently. The workflow's own "what this stage does NOT assert" heredoc is
updated in step with it, because that is the copy that gets quoted.

## Verification

### Revert-verified

Each behavioural claim written into this spec was made to fail, the named check was watched
to fail, and the change restored.

| claim | how it was broken | what failed |
|---|---|---|
| the sync association gauge follows the real wire path (`smfd`) | removed `self.publish_associated(&assoc)` from `associate()` | `smfd pfcp_path::tests::the_sync_association_gauge_follows_the_wire_association` FAILED: "the gauge must follow a real Association Setup Response" |
| the same, in `upfd` | removed `self.publish_associated(&association)` from `handle_association_setup_request` | `upfd pfcp_path::tests::the_sync_association_gauge_follows_the_wire_association` FAILED: "the gauge must follow a real Association Setup Request" |

Both matter for the same reason, and it is the reason #380 is worth a spec: the defect this
issue describes is *a health assertion that cannot catch a missing service*. A new assertion
on a gauge that never moves would be the same defect one level down — green against a PGW-C
whose Sxb association never came up. Breaking each publish site and watching the named test
go red is what distinguishes "the assertion holds" from "the assertion is not implemented".

The two new CI gates are revert-verified against the dispatched run rather than locally: the
EPC stage is dispatch-only (see below), so the honest check is what the runner does, and the
PR records which gate failed when the service was withheld.

### Tests added

* `smfd` `pfcp_path::the_sync_association_gauge_follows_the_wire_association` — drives a
  real Association Setup against the stand-in UPF, then a teardown, asserting the gauge
  moves both ways and agrees with the async authority. Not the test-only setter: a setter
  proving itself proves nothing.
* `upfd` `pfcp_path::the_sync_association_gauge_follows_the_wire_association` — the same,
  over the socket through the real handlers: Association Setup Request up, Association
  Release Request down.
* `smfd` `the_metrics_render_counts_live_n4_associations_not_configured_peers` — the
  pool-of-one-un-associated case, which is exactly the deployment the gate must reject.
* `upfd` `the_metrics_render_reports_the_association_and_session_state` — asserts 0 **and**
  1, so a render that hard-coded `upf_pfcp_associations 1` would fail.
* both: `the_metrics_port_is_9090_unless_overridden` — the default must not drift from the
  port `prometheus.yml` scrapes and the healthcheck curls.

### Dispatched, not inferred

`ci.yml` gates `Docker Build`, `Docker E2E` and the EPC stage behind
`github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'` (the #349
decision, `specs/cross-repo-e2e-gating.md`). **They do not run on a PR**, so a green PR here
would prove nothing — every file this change touches is exercised only by those jobs. The
workflow was therefore dispatched on the branch and the EPC job's log read; the run URL is
quoted in the PR.

This matters because of a recorded incident: a stale pinned cross-repo ref left all three
heavy jobs unrunnable for two and a half months and nobody noticed, precisely because
dispatch-only gating makes "unrun" and "unrunnable" indistinguishable from outside.

## Ceilings this leaves in place, stated honestly

* **No S5/S8 transaction is asserted.** The socket is bound and the Sxb association is up —
  every precondition for anchoring a session — but nothing sends a Create Session Request,
  because only an attach originates one. This is the *same* ceiling as the missing
  originator, not a second gap, and it is named in the workflow output and the README rather
  than only here.
* **No attach, and so no GTP-U forwarding claim.** Unchanged and out of scope: nextgsim #186.
* **#303 stays open.** Its criterion names an `MME↔SGW-C↔SGW-U↔SMF(PGW)` attach. The last
  hop now has a container to reach, so the blocker #380 identified is gone; the originator
  blocker remains, and #303 continues to depend on nextgsim #186.
* **The PGW-C has Gx state and no Gx transport.** `create_session` passes
  `has_policy_source = true` and serves from `policy::PolicyDecision::config_default_for_dnn`,
  which is the same fallback the 5G path uses with no PCF. TS 23.401 does not require a PCRF
  for a PGW to serve a session, so the `pcrf` container on this network is a peer the PGW-C
  does not talk to. Pre-existing, named in `configs/epc/README.md` rather than fixed here.
* **`smfd`'s S5/S8 recovery counter is derived from process start**, not persisted
  (`main.rs`, `s5s8_open(s5s8_bind, 1)`), so an SGW-C cannot detect a PGW-C restart the way
  TS 23.007 §18 intends. Pre-existing from #52, already stated there as a ceiling, and
  unchanged: fixing it would be a second answer to a question `mmed` and `sgwcd` each answer
  their own way.
* **The PGW-C serves IPv4 only.** `create_session` sets `session_type = Ipv4` because
  `ipv4_pool` is the only pool it has, so an IPv6 or IPv4v6 PDN type gets cause 18.
  Pre-existing from #52; `pgwc.yaml` declares no v6 subnet rather than advertising a
  capability the S5/S8 path does not have.
* **Neither new metrics endpoint is scraped by Prometheus.** `prometheus.yml` covers the
  `core` network only; the EPC stack ships no Prometheus. The metrics exist for the
  healthcheck and the CI gate, which is what criterion 2 asks for. Wiring EPC observability
  is a separate change.
