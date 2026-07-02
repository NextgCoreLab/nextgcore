//! S1AP Message Fuzzer
//!
//! Fuzzes the S1AP (S1 Application Protocol) message parser to find potential
//! crashes, panics, or memory safety issues.
//!
//! Exercises `nextgcore_s1ap::parser::decode_s1ap_pdu` against arbitrary bytes.
//! The harness must never panic — the parser is expected to return `Err` on
//! malformed input, not abort.
//!
//! Run with: cargo +nightly fuzz run fuzz_s1ap_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise the top-level S1AP PDU decoder.
    // A well-formed decoder must never panic on arbitrary byte input —
    // it should return Err(...) for invalid PDUs.
    let _ = nextgcore_s1ap::parser::decode_s1ap_pdu(data);
});
