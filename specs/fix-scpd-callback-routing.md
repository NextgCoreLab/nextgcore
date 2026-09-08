# nextgcore #210 (scpd): read `3gpp-Sbi-Callback` and route a notification without a discovery or OAuth gate

Verified against `main` @ `29a511d` (after #207, #211, #209, #208 — same file). All three of the
issue's cites still hold.

## Verified against current main

| claim in the issue | site on `29a511d` | still true? |
|---|---|---|
| `custom_header::CALLBACK` defined | `libs/nextgcore-sbi/src/constants.rs:161` | yes |
| duplicate `CALLBACK` in the scpd crate | `bins/nextgcore-scpd/src/sbi_path.rs:51` (lowercased) | yes |
| `grep -c 'CALLBACK' bins/nextgcore-scpd/src/proxy.rs` → `0` | — | yes, `0` |

`grep` for `headers::CALLBACK` across the tree returns **nothing**: the duplicate had no readers
at all, and neither did `custom_header::CALLBACK`. Two spellings of a header, zero users.

## Read this first: over the wire, this change is a no-op

This is the most important thing in the spec, and it was found by revert-verification rather than
by reading.

`libs/nextgcore-sbi/src/server.rs:563` builds the inbound URI from the path only —
`req.uri().path().to_string()` — and over HTTP/2 the `:authority` a peer dialled is the SCP's
own. So **an absolute callback URI cannot reach `route()`**, and the only conveyance that
survives is `3gpp-Sbi-Target-apiRoot`. Which means:

| case | before | after (wire) |
|---|---|---|
| callback + `Target-apiRoot` | Model C: no discovery, no token | **unchanged** — `Target-apiRoot` already outranked the Discovery headers and Model C passes `delegated: None` |
| callback + Discovery headers, no `Target-apiRoot` | `Discover` (query + token, delivered to a discovered producer) | **still `Discover`** — no callback URI is knowable |
| callback + nothing else | `400 MANDATORY_IE_MISSING` | **still 400** |

So what actually lands: the rule is now **explicit** rather than an accident of `Target-apiRoot`
precedence (it cannot be broken by a future reordering), the absolute-URI case is handled
correctly the moment it can reach `route()`, and the duplicate constant is gone. The transport
half is filed as **#259** (`decision`, `needs-human`) with three costed options, because changing
`nextgcore-sbi`'s server to preserve the authority touches all 19 daemons and every handler that
matches on `header.uri` — not a call to make inside a callback-routing change.

Stating this rather than letting the PR read as a functional fix is the point. The first
end-to-end test I wrote **passed with the callback rule disabled**; had I not reverted it, this
would have shipped as a fix for something it does not reach.

## Decision 1: precedence — callback first, and it is not competing with `Target-apiRoot`

```
1. 3gpp-Sbi-Callback   -> Callback  (no discovery, no token)
2. 3gpp-Sbi-Target-apiRoot -> TargetApiRoot
3. 3gpp-Sbi-Routing-Binding (cached) -> StickyBinding
4. any 3gpp-Sbi-Discovery-* -> Discover
5. Reject
```

The issue asks for the precedence against `Target-apiRoot` and `Routing-Binding` to be decided
and documented. The resolution is that the first pair is not a conflict: **the callback header
decides the *mode* (no discovery, no token) and `Target-apiRoot` supplies the *address***, so a
callback carrying one is routed there. It outranks `Routing-Binding` and the Discovery headers
because a notification's destination is fixed by the consumer that registered the callback —
discovering a producer for it addresses the wrong node, and minting a token for that producer is
an NRF round-trip for a credential the callback target never requested.

## Decision 2: an unresolvable callback falls through rather than being rejected

If the header is present but no destination can be determined (no `Target-apiRoot`, relative
request URI — i.e. every wire case), the marker is logged at `warn` and routing continues down
the ordinary precedence.

Rejecting would have been tidier and is wrong: a deployment whose notifications currently reach
their target *via the Discovery headers* — badly, with a needless token, but successfully — would
start failing. A cause-specific rejection only becomes safe once #259 resolves the conveyance,
and it is listed there as option 3 for exactly that reason.

## Decision 3: the absolute-URI arm is kept, and labelled

`split_absolute_uri` handles the case the issue describes, splitting at the **first** `/` after
the authority so a deployment prefix stays in the path — otherwise `forward_once`, which prepends
`target.prefix`, would emit it twice.

It is unreachable over the wire today. Kept because `ScpProxy::handle` is public, because it is
the correct handling the moment #259 option 1 lands, and because deleting it would leave
`handle()` silently mis-handling an absolute URI. **Not claimed as wire behaviour**: its test
drives `handle()` in process and says so in its doc comment, rather than being dressed up as an
end-to-end test.

## Decision 4: `3gpp-Sbi-Callback` is forwarded, not consumed

It is deliberately **not** added to `is_scp_consumed`. It identifies the message as a
notification *to the receiver*; the SCP merely reads it for routing, and stripping it would
remove information the target may need. Contrast `Target-apiRoot` / `Routing-Binding` /
`Discovery-*`, which are addressed *to the SCP* and are stripped.

A callback is also not retargeting — the producer was handed the callback URI by the consumer —
so `RelayContext::default()` applies and no §6.10.4 `Location` fix-up is added.

## Acceptance criteria

- [x] A request bearing `3gpp-Sbi-Callback` is routed without a discovery or OAuth gate.
- [x] A test asserts **no** token acquisition occurs on the callback path (not merely that the
      response is 200) — `test_callback_with_discovery_headers_is_not_discovery_gated` counts
      hits on a live NRF's **token endpoint and discovery endpoint**, and on a decoy producer the
      delegated path would have reached; all three asserted zero.
- [x] Precedence relative to `Target-apiRoot` / `Routing-Binding` is documented in code — on
      `route()`, and pinned by `test_callback_route_precedence` including that a callback beats a
      *known* `Routing-Binding` which would otherwise win.
- [x] The duplicate `CALLBACK` constant is reduced to one spelling — removed from
      `sbi_path::headers`; `custom_header::CALLBACK` is the survivor and the module doc now says
      so.
- [x] Workspace lint and the scpd suite pass.

## Verification

Workspace `5981 passed / 0 failed / 6 ignored` (baseline `5976` after #208; +5 tests). `cargo
clippy --workspace` and `cargo fmt --all -- --check` clean, zero warnings.

Two reverts:

| revert | expected to break | result |
|---|---|---|
| `route()` never reads the callback header | discriminating + absolute-URI + precedence tests | **3 failed** |
| callback checked only when no Discovery headers are present (i.e. after Discover) | precedence test | **1 failed** |

**The first revert is what caught the false guard.** Run against my original test set it broke
only the precedence unit test — the end-to-end `test_callback_routes_without_discovery_or_token`
**passed with the fix removed**, because its request carried `Target-apiRoot` and Model C
precedence was doing all the work. That test is retained, renamed in intent and re-documented as
a *regression* guard for the reordering rather than as evidence the rule does anything; the
discriminating test that the revert now breaks had to drop `Target-apiRoot`, which in turn is what
surfaced the transport limitation and #259. A green test that looks like a guard and is not.

## Ceilings

* **The substantive fix is unreachable over the current transport** — see the second section and
  #259. This is the honest headline of the change.
* No test drives a real producer NF sending a notification through the SCP; the notifications
  here are synthesised by the test client, so the *producer* side of §6.10.7 (that an NF actually
  sets `3gpp-Sbi-Callback` on its notifications) is unverified. `grep` for
  `custom_header::CALLBACK` across the daemons returns no *setter* either, so today no NF in this
  tree marks its notifications — which is a second reason the wire path is untested and is worth
  its own issue if anyone wants §6.10.7 end to end.
* The remaining constants in `sbi_path::headers` are the same duplication with the same zero
  readers. Left in place with a note: #210 asks only about `CALLBACK`, and collapsing the module
  changes this crate's public re-exports, which no issue has requested.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep: `route()`
  has one caller (`handle`), and `RouteDecision` is matched in exactly one place.
