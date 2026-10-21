//! GTP Message Fuzzer
//!
//! Exercises the real `nextgcore_gtp` decoders against arbitrary bytes:
//! GTPv2-C (`Gtp2Message::decode`, what sgwcd/smfd/mmed run on S11/S5-C, then
//! every typed message decoder on a message that parsed) and GTPv1 (`Gtp1Header`
//! for GTP-U, `Gtp1Message` and its typed decoders). Before #587 this target
//! carried its own hand-written parser and called nothing in `nextgcore_gtp`.
//! No decoder may panic; malformed input is `Err`.
//!
//! Run with: cargo +nightly fuzz run fuzz_gtp_message

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nextgcore_gtp::{v1, v2};

const GTP2: &[fn(&v2::Gtp2Message) -> bool] = &[
    |m| v2::CreateSessionRequest::decode(m).is_ok(),
    |m| v2::CreateSessionResponse::decode(m).is_ok(),
    |m| v2::ModifyBearerRequest::decode(m).is_ok(),
    |m| v2::ModifyBearerResponse::decode(m).is_ok(),
    |m| v2::DeleteSessionRequest::decode(m).is_ok(),
    |m| v2::DeleteSessionResponse::decode(m).is_ok(),
    |m| v2::CreateBearerRequest::decode(m).is_ok(),
    |m| v2::CreateBearerResponse::decode(m).is_ok(),
    |m| v2::DeleteBearerRequest::decode(m).is_ok(),
    |m| v2::DeleteBearerResponse::decode(m).is_ok(),
    |m| v2::ReleaseAccessBearersRequest::decode(m).is_ok(),
    |m| v2::ReleaseAccessBearersResponse::decode(m).is_ok(),
    |m| v2::DownlinkDataNotification::decode(m).is_ok(),
    |m| v2::DownlinkDataNotificationAcknowledge::decode(m).is_ok(),
];

const GTP1: &[fn(&v1::Gtp1Message) -> bool] = &[
    |m| v1::EchoRequest::decode(m).is_ok(),
    |m| v1::EchoResponse::decode(m).is_ok(),
    |m| v1::ErrorIndication::decode(m).is_ok(),
    |m| v1::SupportedExtHeadersNotification::decode(m).is_ok(),
    |m| v1::TunnelStatus::decode(m).is_ok(),
];

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = v2::Gtp2Message::decode(&mut Bytes::copy_from_slice(data)) {
        for decode in GTP2 {
            let _ = decode(&msg);
        }
    }
    let _ = v1::Gtp1Header::decode(&mut Bytes::copy_from_slice(data));
    if let Ok(msg) = v1::Gtp1Message::decode(&mut Bytes::copy_from_slice(data)) {
        for decode in GTP1 {
            let _ = decode(&msg);
        }
    }
});
