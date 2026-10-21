//! Diameter Message Fuzzer
//!
//! Exercises the real `nextgcore_diameter` decoders (what hssd/pcrfd/mmed run on
//! S6a/Gx/Rx) against arbitrary bytes: `DiameterMessage::decode`, every decoded
//! AVP re-read as Grouped (RFC 6733 4.4) to a bounded depth, the S6a
//! Authentication-Info parser, and a bare `Avp::decode`. Before #587 this target
//! carried its own hand-written parser and called nothing in `nextgcore_diameter`.
//! No decoder may panic; malformed input is `Err`.
//!
//! Run with: cargo +nightly fuzz run fuzz_diameter_message

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nextgcore_diameter::avp::Avp;
use nextgcore_diameter::DiameterMessage;

/// Re-read AVPs as Grouped, a few levels deep (bounded so a fuzz input cannot
/// make the harness itself recurse without limit).
fn walk_grouped(avps: &[Avp], depth: u8) {
    if depth == 0 {
        return;
    }
    for avp in avps {
        if let Ok(members) = avp.parse_grouped() {
            walk_grouped(&members, depth - 1);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = DiameterMessage::decode(&mut Bytes::copy_from_slice(data)) {
        walk_grouped(&msg.avps, 4);
        let _ = nextgcore_diameter::s6a::parse_authentication_info(&msg);
    }
    let _ = Avp::decode(&mut Bytes::copy_from_slice(data));
});
