//! LPP Message Fuzzer
//!
//! Exercises the generated LPP codec (`nextgcore_lpp_gen`, TS 37.355 UPER)
//! against arbitrary bytes, and re-encodes anything that decodes. Neither may
//! panic; malformed input must come back as `Err`.
//!
//! Run with: cargo +nightly fuzz run fuzz_lpp_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = nextgcore_lpp_gen::decode(data) {
        let _ = nextgcore_lpp_gen::encode(&msg);
    }
});
