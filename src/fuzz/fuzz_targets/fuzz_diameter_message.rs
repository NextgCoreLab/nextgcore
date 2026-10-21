//! Diameter Message Fuzzer
//!
//! Exercises the real `nextgcore_diameter` decoders (what hssd/pcrfd/mmed run on
//! S6a/Gx/Rx) against arbitrary bytes: `DiameterMessage::decode`, every decoded
//! AVP re-read as Grouped (RFC 6733 4.4) to a bounded depth, the S6a
//! Authentication-Info parser, and a bare `Avp::decode`. Since #596 it also
//! runs every typed AVP accessor and the other S6a AVP parsers over each
//! decoded AVP. Before #587 this target
//! carried its own hand-written parser and called nothing in `nextgcore_diameter`.
//! No decoder may panic; malformed input is `Err`.
//!
//! Run with: cargo +nightly fuzz run fuzz_diameter_message

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nextgcore_diameter::avp::Avp;
use nextgcore_diameter::s6a;
use nextgcore_diameter::DiameterMessage;

/// The typed accessors and S6a parsers, run on every AVP the walk reaches.
fn read_avp(avp: &Avp) {
    let _ = avp.as_octet_string();
    let _ = avp.as_u32();
    let _ = avp.as_u64();
    let _ = avp.as_i32();
    let _ = avp.as_utf8_string();
    let _ = avp.as_address();
    let _ = s6a::parse_e_utran_vector(avp);
    let _ = s6a::parse_apn_configuration_avp(avp);
    let _ = s6a::parse_subscription_data_avp(avp);
    let _ = s6a::ChargingCharacteristics::from_avp(avp);
}

/// Re-read AVPs as Grouped, a few levels deep (bounded so a fuzz input cannot
/// make the harness itself recurse without limit).
fn walk_grouped(avps: &[Avp], depth: u8) {
    if depth == 0 {
        return;
    }
    for avp in avps {
        read_avp(avp);
        if let Ok(members) = avp.parse_grouped() {
            walk_grouped(&members, depth - 1);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = DiameterMessage::decode(&mut Bytes::copy_from_slice(data)) {
        walk_grouped(&msg.avps, 4);
        let _ = s6a::parse_authentication_info(&msg);
        let _ = s6a::find_resync_info(&msg);
        let _ = s6a::find_num_requested_vectors(&msg);
    }
    let _ = Avp::decode(&mut Bytes::copy_from_slice(data));
});
