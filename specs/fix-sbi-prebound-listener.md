# nextgcore #313: close the cross-process port window by serving a pre-bound listener

Verified against `main` @ `46a1aa1`.

#313 is the second half of #308. The symptom is a bind failure inside
`SbiServer::start` under `cargo test --workspace`; the mechanism is that
`test_support::free_port` chooses a port and then **releases it** before the caller
binds, and each test binary has its own issued-port set, so two crates running
concurrently can be handed the same number.

Its scope estimates are the part that was stale. The API change it asks for is
exactly right; the counts are out by an order of magnitude, in both directions.

## Verified against current main

| claim in the issue | site on `46a1aa1` | still true? |
|---|---|---|
| `free_port` probes, records the port, drops the probe, returns the number | `test_support.rs:46-60` | yes |
| its own doc states the limit and says the API change is "tracked separately" | `test_support.rs:29-35` — it names #313, which #308 filed | yes, and already corrected once |
| `SbiServer` binds internally, taking only a `SocketAddr` | `server.rs:959` | yes |
| the failure presents as a bind panic, not a wrong answer | `Failed to bind: Address already in use (os error 98)`, reproduced deliberately below | yes |
| "~21 `free_port` callers that start an `SbiServer`" | **243** ephemeral-port server starts | **false — 11.5x low** |
| "`rg 'fn free_port' src/bins` finds 15+ private duplicates that do NOT even have the in-process `ISSUED` guard" | 26 crate-local helpers, of which **19 were one-line delegates** to the shared helper and only **5** had a raw probe-drop body | **false** — the duplicates were migrated by an earlier issue; only 5 were unguarded |
| UDP callers (PFCP/GTP stand-ins) need the same treatment | **they have no window**: every test-side UDP socket binds `127.0.0.1:0` or `loopback(0)` and keeps it | **false, and this is the good news** |

The undercount matters because it changes the shape of the fix: at 21 sites a
hand-migration is a morning's work; at 243 it needs a mechanical transform and the
compiler as the net, which is how this was done.

## Decision 1: the server adopts a listener; it does not consult a registry

`SbiServer::on_listener(config, listener)` stores the listener and `start()` takes
it. `test_support::bound_listener()` returns a `BoundListener` — a bound socket and
its address travelling together, so there is no moment when the port has been
chosen and nothing holds it.

The alternative considered and rejected was a process-global map from address to
reserved listener, which `start()` would consult. It is tempting because it needs a
**one-token diff** at each of 243 call sites instead of a two-line one. Rejected for
three reasons, in order of weight:

1. **It is the #308 defect shape.** A global that one function writes and another
   reads, with no ownership visible at either end, is precisely the ambient state
   that session removed four locks' worth of. Trading a compile-time guarantee for
   an invisible agreement is a bad trade on a test helper.
2. **It would have changed what some tests measure.** Ten callers use `free_port`
   to get an address with *nothing listening* — bounded-timeout transport errors,
   degrade-open paths, discovery of a dead peer. A registry keyed on address is
   only safe if those callers are perfectly separated from the reserving ones
   forever; with an explicit type the compiler enforces the separation.
3. **File descriptors.** A reservation never consumed leaks one fd for the life of
   the test binary. Bounded in practice, unbounded in principle.

`config.addr` is overwritten from the listener rather than checked against it. A
server whose config disagreed with the socket it serves would misreport itself in
`stop()`'s log and in anything deriving a URI from the config, and the disagreement
would be silent. `on_listener_overwrites_a_placeholder_config_address` pins it.

## Decision 2: `free_port` is kept, and its remaining callers are the point

The obvious reading of criterion 4 is that the helper is deleted along with its
stale doc. It is not, and the reason is a real distinction rather than a shortcut:

- **10 callers want an address with nothing bound to it.** `smfd::policy`'s two
  bounded-timeout PCF/NSACF tests, `amfd::sbi_path`'s two degrade-open tests,
  `pcfd`'s dead-UDR and dead-callback tests, `nefd`'s dead-producer test. Handing
  these a bound listener makes the port *reachable*, which inverts what they
  assert. Each site now sits under a doc comment that says so.
- **1 integration test cannot take a socket at all.** `n32_two_sepp.rs` passes two
  ports to a real child process on the command line, and a third to
  `start_n32_listener(host, port, tls)` — a production entry point whose signature
  is a configured host and port. Threading a listener through production API for a
  test's benefit is the wrong trade; the child-process case cannot be fixed at all
  without fd inheritance, which nothing in this tree does.

What did change there: that file's copy of `free_port` was **raw**, with no
in-process issued set, so two threads in one binary could collide. It now delegates
to the shared helper. The same is true of `udmd/tests/sor_upu_strict_peer.rs` and
`pcfd/tests/strict_peer_bsfd.rs` (three nested copies), which became dead once
their callers moved and were deleted.

`free_port`'s doc no longer claims the API change is tracked elsewhere; it now
describes the window it still has and points at `bound_listener` for anything that
will be served.

## Decision 3: two retry loops are deleted rather than kept as belt-and-braces

`http3.rs`'s h2 leg and `benches/transport.rs`'s `start_h2_server` each looped
**five times** over "probe a port, try to start, accept a failure" — local
workarounds for the window this removes. Both are now single-attempt, because a
retry that can absorb a real bind failure is the same instrument #308 removed from
`ci.yml`: it converts a signal into a warning nobody reads. The bench's own
`free_port` (unguarded, no issued set) is deleted with it.

## Decision 4: 19 dead crate-local delegates are removed

Nineteen `fn free_port()` / `fn ephemeral_addr()` one-line delegates became
unreferenced when their callers moved to reservations, across amfd (2), ausfd (2),
bsfd, dccfd, lmfd (3), mbsmfd, nefd, nsacfd, nssfd, nwdafd, pcfd, smfd, udmd (2),
udrd. Deleted rather than left: the issue's criterion 3 asks for exactly this, and a
delegate with no callers makes the shared helper look less used than it is.

Two crate-local helpers are kept and renamed to say what they are:
`scpd::proxy::reserve_port` and `amfd::sbi_path::nsacf_reserved_port`, both
returning a `BoundListener`. `scpd` also keeps its own because its 15 `start_*`
stubs take the reservation as their first parameter, which is what let 109 call
sites migrate by changing one argument each.

## Verification

The load-bearing claim — "no port is unbound between selection and use" — is pinned
by a **differential** test rather than a property test:
`a_reserved_port_is_bound_and_a_free_port_is_not` asserts both that a competing bind
of a reserved port fails with `AddrInUse` **and** that the same bind of a
`free_port` address succeeds. The second half is the defect; without it a
`bound_listener` that had quietly reverted to probe-drop would satisfy the first
half's negative reading.

| claim | how it was made to fail | result |
|---|---|---|
| the reservation actually holds the port | first attempt: revert `bound_listener` to probe-drop-then-rebind | **did NOT bite** — rebinding restores the property, so the revert tested nothing. Recorded because it is the mistake, not the method |
| `start()` genuinely serves the reserved listener | replace `self.prebound.lock().await.take()` with `None`, so `start()` falls back to binding `config.addr` | **fails**: `sbi server start: ServerError("Failed to bind: Address already in use (os error 98)")` — #313's production message, produced on demand |
| a `free_port` address is claimable, i.e. the window is real | the second half of the differential test, on the fixed branch | **passes** — the bind succeeds, which is the window |
| `config.addr` follows the socket, not the caller's placeholder | `on_listener` with a `:0` config | port equals the reservation's |
| both reservation routes share one issued set | 16 reservations held, 200 `free_port` draws | no overlap |
| a reserved server is reachable on exactly the reserved address | real `TcpStream::connect` after `sbi_server_on_free_port` | connects |
| the migration did not change what any test measures | whole workspace | **6357 passed / 0 failed** (baseline 6352 + 5 new) |
| the gate is stable | 36 `cargo test --workspace` runs on the final tree (20 + 12, plus 4 immediately after `clippy --all-targets`), counting `Address already in use` occurrences | **0 failures, 0 bind errors** — but see the first ceiling: two earlier failures went uncaptured |
| the three other gates | `cargo clippy --workspace`; `--all-targets`; `cargo fmt --all --check`; `-p nextgcore-easdfd --features dns-udp` test + clippy | 0 errors each; 51 passed |

## Ceilings

- **Two single-test failures were observed and NEITHER was identified.** This is the
  weakest part of the evidence and it is stated first rather than buried. One
  occurred on a mid-migration tree (amfd's `sbi_path` not yet moved, the dead
  delegates not yet removed) with `failed=1` and **zero** `Address already in use`
  occurrences. The second occurred on the final tree, reporting 1503 passed / 1
  failed — the low count meaning cargo stopped after the failing binary, so the
  crate is not even known. Both loops discarded the output. Three subsequent
  measurements, all with capture, found nothing: 20 runs, then 12 runs, then 4 runs
  immediately after `clippy --all-targets` (which forces a full test-binary rebuild,
  so tests run under heavy compile load — the shape #308 used deliberately to
  surface state races). **36 clean runs; that hypothesis is tested and not
  confirmed.** What the counters do rule out is this issue's subject: a port
  collision presents as `Address already in use`, and the one failure whose bind
  count was recorded had none. The honest summary is that something in this suite
  fails at a rate under roughly 1 in 18 and it is not the port window.
- **36 clean runs bound the port-collision rate; they do not prove zero.** #313's
  measured rate was ~2 in 29 whole-workspace runs, so 36 clean runs put that
  residual under roughly 8% at 95% confidence — enough to say the mechanism is
  closed (there is no unbound window left to lose), not enough to certify the suite
  deterministic. The mechanism argument is the stronger one here and the statistics
  are corroboration.
- **The `stop()`/`start()` restart path re-binds.** The reservation is consumed by
  the first `start()`, so a restarted server binds `config.addr` and reopens the
  window for that one bind. Nothing in this workspace restarts a server on a
  reserved port; if something does, it needs a second reservation.
- **A reserved port accepts into the kernel backlog before `start()` adopts it.** A
  client connecting in that gap is queued rather than refused, where previously it
  was refused. No test asserts refusal on a reserved port — the 10 refusal tests all
  use `free_port`, which is why that helper survives — but the behaviour differs
  from main and is stated rather than discovered later.
- **The child-process case in `n32_two_sepp.rs` is unfixed and unfixable as
  written.** Two ports go to a spawned binary's argv; closing that needs fd
  inheritance. If the workspace gate reddens again with a bind failure, this is the
  first place to look, and it will present as a startup timeout rather than a bind
  panic because the failure happens in the child.
- **`start_n32_listener` keeps its `(host, port)` signature.** A production sibling
  taking a listener would close the third seppd site. No issue has asked for it and
  it is production API churn for a test.
- **No E2E.** Everything here is one process's test binary. The Docker jobs remain
  `workflow_dispatch`-only and untouched.
- **The 243 migrations were mechanical, with the compiler and the suite as the net.**
  Two scripted transforms did the bulk; three syntax errors and one type error were
  caught by `cargo check`, and one of them (a dropped closing paren) would have been
  invisible to review of the script alone. The residual risk is a reservation
  attached to the wrong server in a test with two servers in one function — which
  would fail the test rather than pass silently, because the wrong port would be
  served.
