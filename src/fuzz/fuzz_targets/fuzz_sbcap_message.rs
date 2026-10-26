//! SBc-AP Message Fuzzer (#1071)
//!
//! mmed decodes every SBc-AP PDU a CBC sends with the generated codec
//! (`nextgcore_sbcap_gen`, TS 29.168 §4.4, APER). Arbitrary bytes must give an
//! `Err`, never a panic, and a PDU that decodes must re-encode without one.
//!
//! Run with: cargo +nightly fuzz run fuzz_sbcap_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pdu) = nextgcore_sbcap_gen::decode(data) {
        let _ = nextgcore_sbcap_gen::encode(&pdu);
    }
});
