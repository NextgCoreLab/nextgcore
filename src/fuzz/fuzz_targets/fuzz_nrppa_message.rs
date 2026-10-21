//! NRPPa Message Fuzzer
//!
//! Exercises the generated NRPPa codec (`nextgcore_nrppa_gen`, TS 38.455 APER)
//! against arbitrary bytes: the strict decode, the decode that skips unknown IEs,
//! and a re-encode of anything that decodes. None of them may panic; malformed
//! input must come back as `Err`.
//!
//! Run with: cargo +nightly fuzz run fuzz_nrppa_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pdu) = nextgcore_nrppa_gen::decode(data) {
        let _ = nextgcore_nrppa_gen::encode(&pdu);
    }
    let _ = nextgcore_nrppa_gen::decode_with_unknown_ies(data);
});
