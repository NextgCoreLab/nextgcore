//! NGAP Message Fuzzer
//!
//! Fuzzes the NGAP (NG Application Protocol) message decoder to find potential
//! crashes, panics, or memory safety issues.
//!
//! Exercises the generated codec (`nextgcore_ngap_gen`), the NGAP codec every
//! production path uses since #417: strict decode, decode skipping unknown IEs,
//! and a re-encode of anything that decodes.
//! The harness must never panic — the decoder is expected to return `Err` on
//! malformed input, not abort.
//!
//! Run with: cargo +nightly fuzz run fuzz_ngap_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pdu) = nextgcore_ngap_gen::decode(data) {
        let _ = nextgcore_ngap_gen::encode(&pdu);
    }
    let _ = nextgcore_ngap_gen::decode_with_unknown_ies(data);
});
