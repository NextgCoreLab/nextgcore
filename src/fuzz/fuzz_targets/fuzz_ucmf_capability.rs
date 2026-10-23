//! UCMF UE radio capability fuzzer (#725)
//!
//! Drives the UCMF's own transcoding and paging-derivation code
//! (`nextgcore-ucmfd/src/rac.rs`, compiled in here unchanged) with arbitrary
//! bytes. Those bytes reach the UCMF from any SBI peer, as the binary parts of a
//! Nucmf_UECapabilityManagement Assign and as the hexadecimal `racsParamEps` /
//! `racsParam5Gs` of a Nucmf_Provisioning request, and the UCMF decodes them
//! while it holds its state write lock. Nothing may panic or abort; malformed
//! input must come back as `Err`. Whatever does transcode is fed on to the
//! paging derivation and the reverse transcoding, which reaches the nested
//! per-RAT containers (`UE-NR-Capability`, `UE-EUTRA-Capability`).
//!
//! `rac::guarded` turns a codec panic into `RacError::CodecFault` in the UCMF,
//! so this target calls the unguarded functions: a panic must fail the run,
//! not be contained.
//!
//! Run with: cargo +nightly fuzz run fuzz_ucmf_capability

#![no_main]

use libfuzzer_sys::fuzz_target;

#[allow(dead_code)]
#[path = "../../bins/nextgcore-ucmfd/src/rac.rs"]
mod rac;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, cap)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        // 5GS format (TS 38.331) in.
        let _ = rac::derive_paging_5gs_unguarded(cap);
        if let Ok(eps) = rac::transcode_5gs_to_eps_unguarded(cap) {
            let _ = rac::derive_paging_eps_unguarded(&eps);
            let _ = rac::transcode_eps_to_5gs_unguarded(&eps);
        }
    } else {
        // EPS format (TS 36.331) in.
        let _ = rac::derive_paging_eps_unguarded(cap);
        if let Ok(nr) = rac::transcode_eps_to_5gs_unguarded(cap) {
            let _ = rac::derive_paging_5gs_unguarded(&nr);
            let _ = rac::transcode_5gs_to_eps_unguarded(&nr);
        }
    }
});
