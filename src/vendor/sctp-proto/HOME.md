# Where this crate lives (nextgcore #467)

This directory is the single home of sctp-proto 0.6.0 with the PPID patch
recorded in `NEXTGSIM-PATCH.md`. Every file except this one is byte-identical to
nextgsim's `vendor/sctp-proto` at NextgCoreLab/nextgsim#224, where the patch was
first made (#220). The file name `NEXTGSIM-PATCH.md` is kept unchanged because
the patched source cites it.

nextgcore uses it through `[patch.crates-io]` in `src/Cargo.toml`. nextgsim
already consumes `nextgcore-sctp` from nextgcore by git rev (#205) and should take
this crate the same way, dropping its own copy: two copies of one patch drift,
which is the problem #205 exists to prevent.

To change the patch, change it here and record it in `NEXTGSIM-PATCH.md`.

## Second patch (nextgcore #813)

Two changes in `src/association/mod.rs`, both about stream counts:

- `Association::max_num_outbound_streams()`, a read-only getter for the
  negotiated outbound-stream count. amfd needs it to put UE-associated NGAP on a
  stream the peer accepts (TS 38.412 §7).
- `handle_init` / `handle_init_ack` bound this endpoint's outbound streams by the
  peer's MIS and its inbound streams by the peer's OS (RFC 9260 §5.1.1).
  Upstream compared inbound with inbound and outbound with outbound, so the
  "negotiated" outbound count was the peer's OS, which can exceed the streams
  the peer accepts. The upstream unit test `test_assoc_handle_init` is updated to
  the RFC values.

No wire octet changes except the counts advertised in an INIT ACK, which are now
the RFC ones. Since this patch the crate is no longer byte-identical to
nextgsim's copy; the PPID patch is unchanged.
