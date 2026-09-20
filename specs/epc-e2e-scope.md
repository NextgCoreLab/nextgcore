# The EPC E2E stage asserts bring-up, and says what it does not assert

**Issues:** nextgcore #328 (the decision), #303 (the stage)
**Verified against:** nextgcore `main` @ `bfcee3e`

## The decision #328 asks for

> how should an EPC attach be originated for E2E? There is no LTE eNB or UE
> simulator in this tree

**Option D now, option A filed as a nextgsim issue.** This is the issue's own
recommendation, and re-verification supports it: D is the largest honest claim
buildable today, and A is the only option that makes the EPC stage mean what the
5G stage means.

B (a test-only attach trigger in `mmed`) and C (driving S11 straight from the
harness) are both rejected for the same reason: each produces a stage that reads
like an MME attach and is not one. B additionally puts a trigger that exists for
tests inside a production binary, which this project has declined before, and C
removes the MME from the chain while #303's criterion names it.

## Two premises in #328 are stale, and they change what D must cover

#328 lists two "not blocked on this decision" prerequisites as having **zero
callers**. Both are now wired:

| Claimed | Actual at `bfcee3e` |
|---|---|
| `gtp_path::send_create_session_request` has zero callers | Called at `nas_dispatch.rs:1663` |
| `nas_path::nas_eps_send_attach_accept` has zero callers | Called at `s11_handler.rs:511` |

The `"not implemented (#51)"` log the issue cites is gone; the comment at
`nas_dispatch.rs:1328` now records that #51 shipped the sender. #51 and #52 are
both CLOSED, which satisfies #303's criterion 1.

So the MME's attach chain is complete end to end in code — S1AP receive
(`s1ap_handler.rs:682`), NAS dispatch, S11 Create Session Request, Create
Session Response (`s11_handler.rs:258`), Attach Accept. **Only the originator is
missing.** That makes D a narrower gap than #328 assumed: what cannot be
exercised is S1AP and LTE NAS *ingress*, not the attach logic behind it.

## A third finding neither issue records: the chain is missing two containers

`docker-compose-epc.yml` defines six services — `mongodb-epc`, `hss`, `pcrf`,
`sgwc`, `mme`, `sgwu` — and **no PGW-C/SMF and no UPF**
(`grep -cE 'pgwc|smfd' docker-compose-epc.yml` returns 0, against 2 for
`smf`/`upf` in the 5G compose).

#303's criterion names an `MME↔SGW-C↔SGW-U↔SMF(PGW)` attach. The last hop has no
container to reach, so that criterion could not pass even with a working
originator. This is exactly the compose-drifts-from-the-binaries class #328 says
D exists to catch, and it is already present rather than hypothetical.

D therefore covers it: the stage asserts the association topology it can, and
names the absent PGW-C as the reason the S5/S8 leg is not asserted.

## What the stage does, and what it refuses to claim

Replaces the current step — three fixed `sleep`s and a `docker inspect` status
read — with readiness gating on the daemons' own runtime:

- Waits on `sgwu_pfcp_associations >= 1` from the SGW-U's live `/metrics`, rather
  than on a timer. The precedent is in-tree: the `sgwu` healthcheck already
  greps `^sgwu_up 1$` from `localhost:9090/metrics`
  (`docker-compose-epc.yml:147`), because container-reported health cannot
  distinguish "process alive" from "peer associated".
- Asserts every NF reaches a healthy state, so a compose file that drifts from
  the binaries fails the stage.

It does **not** assert, and says so in its own name, its log output and
`docker/rust/README.md`:

- No UE attach. Nothing in either repo speaks S1AP or LTE NAS on the UE side
  (`ls ../nextgsim | grep -icE 'enb|lte|s1ap'` returns 0), and no eNB or UE
  service exists in the compose file.
- No GTP-U user-plane forwarding, and therefore no 0%-loss claim — that needs an
  attach to establish a bearer first.
- No S5/S8 leg, because there is no PGW-C container.

Per this project's rule that a gap belongs in the code rather than only in a PR
body, each of those three is named at the point an operator would read it, not
only here.

## Consequences

- #303's criteria 3 and 4 are struck with the blocker named, and the
  replacement bring-up criteria enumerated. #303 stays open, depending on the
  nextgsim issue.
- The stage's name changes from `Docker E2E (EPC)` to something that does not
  promise an E2E attach, because the name is the part that gets quoted.
- A is filed against nextgsim with its own scope: S1AP (TS 36.413), EMM/ESM
  (TS 24.301) UE-side, and an S1-U GTP-U path. It is a project, not an issue,
  and it belongs in the repo that ships the radio-side simulators.
- The absent PGW-C container is filed separately: it is a compose/deployment gap
  rather than part of this decision, and conflating them would hide it.

## Verification

- `docker/rust/docker-compose-epc.yml` parses and the stage's readiness gate
  polls a metric that exists (`sgwu_pfcp_associations`, rendered at
  `bins/nextgcore-sgwud/src/main.rs:41-43`).
- The stage fails when an NF is absent from the compose file, which is the
  defect class it exists to catch.
- `grep` for the three unasserted procedures finds each named in the workflow,
  the stage output and the README.
