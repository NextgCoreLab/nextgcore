# Preserve the request authority beside the path, not inside it

**Issue:** nextgcore #259 (split out of #210)
**Verified against:** nextgcore `main` @ `b8d0f5c`
**Spec basis:** TS 29.500 §6.10.7 (`3gpp-Sbi-Callback`), §6.10.2.5
(`3gpp-Sbi-Target-apiRoot`); RFC 9113 §8.3.1 (`:authority`)

## The mechanism

`libs/nextgcore-sbi/src/server.rs:594` builds the inbound `SbiRequest` URI from
the path alone:

```rust
let uri = req.uri().path().to_string();
```

So an absolute request URI — the natural way a producer names a notification
target under §6.10.7 — cannot survive the hop into `ScpProxy::route()`. The SCP's
`callback_target` (`proxy.rs:1331-1340`) tries `3gpp-Sbi-Target-apiRoot` first and
then falls back to `split_absolute_uri(&request.header.uri)`, and that fallback is
unreachable over the wire because the authority was already discarded. #210's
routing rule is therefore correct in process and a **no-op on the wire**.

## The decision, and a fourth option the issue does not list

#259 offers: **1** preserve the authority in `header.uri`, **2** declare
`Target-apiRoot` the required conveyance, **3** reject a destination-less
callback. It recommends 2 now and 1 later, because 1's blast radius is the
shared SBI server used by all 19 daemons.

**Taken: a variant of 1 that has no blast radius — carry the authority in a NEW
field rather than changing what `uri` contains.**

The pre-check #259 asks for decides this. Run at `b8d0f5c`:

| Pattern | Count |
|---|---|
| `header.uri ==` (exact path comparison) in `bins/` | 9 |
| `uri.starts_with` in `bins/` | 30 |
| `decompose_uri` callers | 7 |

39 handlers compare a path literally against 7 that decompose. So option 1 as
written — widening `uri` to sometimes hold an absolute URI — is a mis-route
waiting to happen at 39 sites, exactly as #259 warns. That is why it recommends
deferring it.

But the reason those 39 sites break is that option 1 **overloads an existing
field**. Nothing forces that. `SbiHeader` gains:

```rust
/// The authority the peer addressed, from the HTTP/2 `:authority`
/// pseudo-header or an absolute request URI. `None` for an origin-form
/// request.
pub authority: Option<String>,
```

`uri` keeps its present meaning — path only — so all 39 comparisons are
unaffected by construction, not by audit. The SCP consults `authority` when
`Target-apiRoot` is absent, which is precisely the §6.10.7 case that could not
work before.

This is strictly better than option 2, which leaves a producer following §6.10.7
literally mis-routed with no way to learn why; and it does not need option 1's
39-site audit, because it does not change any value an existing handler reads.

Option 3 (reject a destination-less callback) is still **not** taken, and the
reason is unchanged: the fall-through to `Discover` is deliberate, since
rejecting would regress a deployment whose callbacks currently reach their
target via the Discovery headers — badly, but successfully. With this change the
population of destination-less callbacks shrinks to those that really named
nothing, which makes option 3 safe *later*; it is left as its own decision rather
than folded in.

## What changed

- `SbiHeader::authority: Option<String>`, populated in
  `convert_request` from `req.uri().authority()` (set for an absolute-form
  request target) or the `Host` header, in that order. HTTP/2's `:authority`
  arrives through `req.uri()` in hyper, so one read covers both forms.
- `ScpProxy::callback_target` consults, in order:
  1. `3gpp-Sbi-Target-apiRoot` — unchanged, still outranks everything, because a
     producer that names a destination explicitly must win.
  2. An absolute `header.uri` — unchanged, still works in process.
  3. **New:** `header.authority` combined with the request path.
- Nothing else reads the new field, so no existing route changes.

## The trap this avoids

The authority a peer dialled when reaching an SCP is the **SCP's own** address.
Using it as a callback target would send every notification back to the SCP,
which is an infinite loop rather than a mis-route.

So the new arm only applies when the authority is **not** one of the SCP's own
bound addresses, and that check is what the test pins. This is why the field is
`Option<String>` on the header rather than being folded into `uri`: the decision
"is this authority a destination or merely how I was reached" belongs to the SCP,
and every other daemon should keep ignoring it.

## Consequences

- A producer following §6.10.7 literally — absolute callback URI, no
  `Target-apiRoot` — is routed to its callback target instead of being sent
  through delegated discovery to the wrong node.
- `Target-apiRoot` remains the recommended conveyance and is documented as such;
  it is unambiguous and survives any proxy hop, whereas an authority can be
  rewritten in transit.
- The 39 literal path comparisons are untouched. This is the part that makes the
  change safe, and it is an argument from construction rather than from having
  audited them.
- Option 3 becomes safe to consider later, and is left filed rather than taken.

## Verification

- A callback carrying an absolute URI and no `Target-apiRoot` routes to
  `Callback` rather than `Discover` — the case #259 names as broken.
- A callback whose authority is the SCP's own address does **not** route to
  `Callback` (the loop the section above describes).
- `Target-apiRoot` still outranks an absolute URI and an authority.
- `header.uri` is unchanged for an origin-form request, so no existing handler
  sees a new value: asserted directly rather than inferred.
