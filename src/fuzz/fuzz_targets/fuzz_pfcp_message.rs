//! PFCP Message Fuzzer
//!
//! Exercises the real `nextgcore_pfcp` decoders (the code upfd/smfd/sgwud run on
//! every N4/Sxa/Sxb datagram) against arbitrary bytes: `PfcpHeader::decode` on the
//! whole input, then one message-body decoder chosen by the first byte, on the
//! rest. Before #587 this target carried its own hand-written parser and called
//! nothing in `nextgcore_pfcp`. No decoder may panic; malformed input is `Err`.
//!
//! Run with: cargo +nightly fuzz run fuzz_pfcp_message

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use nextgcore_pfcp::message::*;
use nextgcore_pfcp::PfcpHeader;

type Decoder = fn(&mut Bytes) -> bool;

const MESSAGES: &[Decoder] = &[
    |b| HeartbeatRequest::decode(b).is_ok(),
    |b| HeartbeatResponse::decode(b).is_ok(),
    |b| AssociationSetupRequest::decode(b).is_ok(),
    |b| AssociationSetupResponse::decode(b).is_ok(),
    |b| AssociationReleaseRequest::decode(b).is_ok(),
    |b| AssociationReleaseResponse::decode(b).is_ok(),
    |b| SessionEstablishmentRequest::decode(b).is_ok(),
    |b| SessionEstablishmentResponse::decode(b).is_ok(),
    |b| SessionDeletionResponse::decode(b).is_ok(),
    |b| SessionModificationRequest::decode(b).is_ok(),
    |b| SessionModificationResponse::decode(b).is_ok(),
    |b| SessionReportRequest::decode(b).is_ok(),
    |b| SessionReportResponse::decode(b).is_ok(),
    |b| NodeReportRequest::decode(b).is_ok(),
    |b| NodeReportResponse::decode(b).is_ok(),
    |b| AssociationUpdateRequest::decode(b).is_ok(),
    |b| AssociationUpdateResponse::decode(b).is_ok(),
    |b| PfdManagementRequest::decode(b).is_ok(),
    |b| PfdManagementResponse::decode(b).is_ok(),
    |b| SessionSetDeletionRequest::decode(b).is_ok(),
    |b| SessionSetDeletionResponse::decode(b).is_ok(),
    |b| SessionSetModificationRequest::decode(b).is_ok(),
    |b| SessionSetModificationResponse::decode(b).is_ok(),
];

fuzz_target!(|data: &[u8]| {
    let _ = PfcpHeader::decode(&mut Bytes::copy_from_slice(data));
    if let Some((&sel, body)) = data.split_first() {
        let decode = MESSAGES[sel as usize % MESSAGES.len()];
        let _ = decode(&mut Bytes::copy_from_slice(body));
    }
});
