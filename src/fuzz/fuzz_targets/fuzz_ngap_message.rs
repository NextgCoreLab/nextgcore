//! NGAP Message Fuzzer
//!
//! Fuzzes the NGAP (NG Application Protocol) message parser to find potential
//! crashes, panics, or memory safety issues.
//!
//! Exercises `nextgcore_ngap::parser::decode_ngap_pdu` against arbitrary bytes.
//! The harness must never panic — the parser is expected to return `Err` on
//! malformed input, not abort.
//!
//! Run with: cargo +nightly fuzz run fuzz_ngap_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise the top-level NGAP PDU decoder.
    // A well-formed decoder must never panic on arbitrary byte input —
    // it should return Err(...) for invalid PDUs.
    let _ = nextgcore_ngap::parser::decode_ngap_pdu(data);
});
