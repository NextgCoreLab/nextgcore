//! S1AP Message Fuzzer
//!
//! Fuzzes the S1AP (S1 Application Protocol) message parser to find potential
//! crashes, panics, or memory safety issues.
//!
//! Exercises the generated S1AP codec (`nextgcore_s1ap_gen`, which mmed decodes
//! every S1AP PDU with since #514) against arbitrary bytes: both the strict
//! decode and the decode that skips unknown IEs. The harness must never panic —
//! the codec is expected to return `Err` on malformed input, not abort.
//!
//! Run with: cargo +nightly fuzz run fuzz_s1ap_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A well-formed decoder must never panic on arbitrary byte input —
    // it should return Err(...) for invalid PDUs. A PDU that decodes must
    // also re-encode without panicking.
    if let Ok(pdu) = nextgcore_s1ap_gen::decode(data) {
        let _ = nextgcore_s1ap_gen::encode(&pdu);
    }
    let _ = nextgcore_s1ap_gen::decode_with_unknown_ies(data);
});
