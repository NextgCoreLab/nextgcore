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
