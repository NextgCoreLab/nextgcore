# fix(diameter): fail a pending request over to an alternate peer with the T flag

Closes #55. Six of its seven criteria were already met by prior work; this is the seventh.

## What was left, verified criterion by criterion against `2e1d985`

#55 is an umbrella whose parts landed separately. Re-verified rather than trusted, because a
stale criterion is the usual reason an umbrella looks bigger than it is:

| # | criterion | state at `2e1d985` |
|---|---|---|
| 1 | `send_cer` emits Host-IP-Address, Vendor-Id, Product-Name, Supported-Vendor-Id, Vendor-Specific-Application-Id | **met** — `peer.rs:333` `applications.append_capabilities` |
| 2 | `handle_cer` answers `5010` on no common application, with a test | **met** — `peer.rs:350`, test at `peer.rs:1127` |
| 3 | `Origin-State-Id` fixed for the process lifetime, with a test | **met** — `peer.rs:773` latches a `OnceLock`, test at `:831` |
| 4a | `send_request` times out within a bounded interval | **met** — `transport.rs:518`, tests `silent_peer_yields_request_timeout`, `watchdog_traffic_does_not_extend_the_deadline` |
| 4b | **on timeout, re-send to an alternate peer with the `T` flag** | **NOT met** — `rg RETRANSMIT src/libs/nextgcore-diameter/` returned the constant declaration and nothing else |
| 5 | mmed S6a no longer holds a shared lock across `send_request` | **met** — `fd_path.rs:379` `s6a_begin_request` returns owned values so the guard drops before any await, and says so |
| 6 | SCTP establishes an association; `no_sctp` honoured | **met** — `kernel-sctp` feature, `sctp_carries_a_full_diameter_exchange` |

So this change is criterion **4b** alone, which is what closes the issue.

## What it does

`DiameterClient` gains `with_alternates(Vec<SocketAddr>)`. On a timeout or a mid-exchange
disconnect the failing peer is marked SUSPECT (RFC 3539 §3.4) and the request is re-sent to
each alternate in turn with the `T` flag set, until one answers or they are exhausted.

`send_request` was split into the failover loop and `attempt_request`, one
request/answer exchange. Not for tidiness: the retransmit path has to do exactly what the
primary path does, and a second copy of a wait loop that skips watchdogs, queues
peer-initiated requests and honours a deadline is a copy that drifts.

## Decisions

**The End-to-End identifier is preserved across the failover; the Hop-by-Hop identifier is
not.** This asymmetry is the entire mechanism §5.5.4 depends on. The `T` flag says "this may
be a duplicate", and the only way a recipient can act on that is by matching the End-to-End
identifier against what it has already processed — §3 makes that identifier unique per
*request*, for exactly this purpose. Assigning a fresh one on the re-send would make the
duplicate undetectable and reduce the flag to decoration. Hop-by-Hop is per-*connection*, so
the new connection must get a new one.

**Opt-in via a builder, not a `new` parameter.** No existing caller changes, and a deployment
with one HSS has nothing to fail over to. With no alternates the behaviour is byte-identical
to before: a timeout is still a timeout, which
`without_alternates_a_timeout_is_still_a_timeout` pins.

**Only peer failures trigger failover.** `is_failover_trigger` admits `RequestTimeout` and
"peer disconnected" and rejects everything else. A malformed request or an unconfigured client
is the caller's problem; failing those over would turn one mistake into one failed exchange
per configured peer, and would report the last peer's error rather than the real one.

**Suspect peers are recorded and skipped, not torn down.** RFC 3539 §3.4 gives the watchdog
the decision to declare a peer down, and this client is not the watchdog — the existing
timeout path already documents that reasoning and deliberately leaves the connection OPEN.
What the set is for is not failing the same request back onto a peer that just failed it.

**The flag is OR-ed, not assigned.** `flags |= RETRANSMIT` — the request bit and any
proxiable bit the caller chose have to survive, and
`a_timed_out_request_fails_over_to_an_alternate_with_the_t_flag` asserts the request bit is
still set afterwards for that reason.

## Verification

Whole workspace **6477 passed / 0 failed**, and **100 passed** with `--features kernel-sctp`
(criterion 7 asks for both configurations). Clippy warnings **74, unchanged from main**.
`cargo fmt --check` clean. 20 consecutive `-p nextgcore-diameter` runs clean.

Six new tests, all driving real TCP listeners and the real peer state machine — a primary that
completes CER/CEA then goes silent, and an alternate that answers and reports back the flags
and identifiers it actually received over a `oneshot`.

### Reverts, both of which bite

| revert | failing test |
|---|---|
| do not set the `T` flag on the re-send | `a_timed_out_request_fails_over_to_an_alternate_with_the_t_flag` |
| assign a fresh End-to-End id on failover | `failover_preserves_end_to_end_and_reassigns_hop_by_hop` |

The first of those initially appeared not to bite — the test-name filter I used (`failover`)
does not match `fails_over`, so the test never ran. Re-run against
`request_timeout_tests` it fails. Recording it because "the revert did not bite" and "the
revert was not exercised" look identical in a passing summary line.

## Ceilings

- **The alternate list is a client-side construct, not configuration.** `DiameterConfig` has a
  `connections: Vec<DiameterConnection>` field that a daemon could map onto
  `with_alternates`, and no daemon does yet — so failover is implemented and tested but not
  reachable from a deployed config. Wiring it needs a per-daemon decision about which peers
  are alternates for which application, which is not this issue's subject.
- **No DRA / realm-based routing.** §6.1's routing table, `Destination-Realm` resolution and
  redirect handling are untouched; the alternates are a flat, ordered list.
- **One pass over the alternates, no retry of the primary.** A request is tried once per peer.
  RFC 6733 does not require more, and looping would need a bound the config does not express.
- **Failback is not implemented.** A peer marked suspect stays suspect for the client's
  lifetime; §5.5.4's companion "failback" (returning to the primary once it recovers) belongs
  with the watchdog that owns peer state, not here.
- **Every test is nextgcore↔nextgcore**, which cannot catch a shared misreading of the RFC —
  the same caveat #55's own comment records for the capabilities work.

## References

- RFC 6733 §3 (Hop-by-Hop and End-to-End identifiers), §5.5.4 (failover and the T flag)
- RFC 3539 §3.4 (watchdog-driven peer failure detection)
- #55 and its two comments recording what had already landed
- `libs/nextgcore-diameter/src/transport.rs`, `message.rs:39` (the `RETRANSMIT` constant that
  had no user)
