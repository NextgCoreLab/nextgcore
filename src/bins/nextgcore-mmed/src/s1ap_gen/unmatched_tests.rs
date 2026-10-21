//! #514 stage 13: PDUs none of the generated family decodes take.
//!
//! The hand-written `decode_s1ap_pdu` used to be the fallback for these; it is
//! deleted, so the answer now comes from the S1AP-PDU header alone. Every PDU
//! here is written out by hand from X.691: octet 0 is the extension bit plus
//! the 2-bit CHOICE index (0x00 initiating, 0x20 successful, 0x40
//! unsuccessful), octet 1 the ProcedureCode, octet 2 the Criticality in its top
//! two bits (0x00 reject, 0x40 ignore, 0x80 notify), then the open type's
//! length and value.

use super::{classify_unmatched, decode_error_indication, pdu_header, Unmatched};
use crate::context::MmeContext;
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{Cause, CauseProtocol};

fn ctx() -> MmeContext {
    let ctx = MmeContext::new();
    ctx.init();
    ctx
}

/// The one ERROR INDICATION an answer must consist of.
fn only_error_indication(
    sent: &[crate::s1ap_handler::S1apSend],
) -> nextgcore_s1ap::ErrorIndication {
    assert_eq!(
        sent.len(),
        1,
        "expected exactly one PDU, got {}",
        sent.len()
    );
    decode_error_indication(&sent[0].pdu)
        .expect("the answer is an ERROR INDICATION")
        .0
}

#[test]
fn the_header_reader_takes_each_choice_and_criticality() {
    assert_eq!(pdu_header(&[0x00, 0xC8, 0x00, 0x00]), Some((0, 200, 0)));
    assert_eq!(
        pdu_header(&[0x20, 0x11, 0x40, 0x01, 0x00]),
        Some((1, 17, 1))
    );
    assert_eq!(pdu_header(&[0x40, 0x11, 0x80, 0x00]), Some((2, 17, 2)));
    // 2-octet length form: 0x80 | (len >> 8), len & 0xff — 0x0080 = 128 octets.
    let mut long = vec![0x00, 0xC8, 0x00, 0x80, 0x80];
    long.extend(std::iter::repeat_n(0u8, 128));
    assert_eq!(pdu_header(&long), Some((0, 200, 0)));
}

#[test]
fn a_malformed_header_is_a_transfer_syntax_error() {
    for bad in [
        &[][..],
        &[0x00, 0xC8][..],
        // CHOICE index 3 is outside the three root alternatives.
        &[0x60, 0xC8, 0x00, 0x00][..],
        // Extension bit set on the S1AP-PDU CHOICE.
        &[0x80, 0xC8, 0x00, 0x00][..],
        // Criticality value 3 does not exist.
        &[0x00, 0xC8, 0xC0, 0x00][..],
        // Open type says 5 octets, 1 follows.
        &[0x00, 0xC8, 0x00, 0x05, 0x00][..],
    ] {
        assert_eq!(
            classify_unmatched(bad),
            Unmatched::TransferSyntaxError,
            "{bad:02x?}"
        );
    }
}

#[test]
fn an_mme_originated_message_is_classified_as_such() {
    // DOWNLINK NAS TRANSPORT (11), initiating: only the MME sends it.
    assert_eq!(
        classify_unmatched(&[0x00, 0x0B, 0x40, 0x00]),
        Unmatched::MmeOriginated { procedure_code: 11 }
    );
    // S1 SETUP RESPONSE (17, successful outcome).
    assert_eq!(
        classify_unmatched(&[0x20, 0x11, 0x00, 0x00]),
        Unmatched::MmeOriginated { procedure_code: 17 }
    );
}

#[test]
fn a_known_procedure_whose_value_does_not_decode_is_undecodable() {
    // S1 SETUP REQUEST (17, initiating) with two octets of junk as its value.
    assert_eq!(
        classify_unmatched(&[0x00, 0x11, 0x00, 0x02, 0xFF, 0xFF]),
        Unmatched::Undecodable {
            procedure_code: 17,
            triggering_message: 0
        }
    );
}

#[test]
fn an_unknown_procedure_reports_its_code_message_and_criticality() {
    assert_eq!(
        classify_unmatched(&[0x00, 0xC8, 0x80, 0x00]),
        Unmatched::UnknownProcedure {
            procedure_code: 200,
            triggering_message: 0,
            criticality: 2
        }
    );
}

/// TS 36.413 §10.3.4.1 Reject IE: reject the procedure using Error Indication,
/// naming the Procedure Code, Triggering Message and Procedure Criticality.
#[test]
fn an_unknown_reject_procedure_is_rejected_by_error_indication() {
    let ei = only_error_indication(&handle_s1ap_message(&ctx(), 1, &[0x00, 0xC8, 0x00, 0x00]));
    assert_eq!(
        ei.cause,
        Some(Cause::Protocol(CauseProtocol::AbstractSyntaxErrorReject))
    );
    let d = ei.criticality_diagnostics.expect("diagnostics");
    assert_eq!(d.procedure_code, Some(200));
    assert_eq!(d.triggering_message, Some(0));
    assert_eq!(d.procedure_criticality, Some(0));
}

/// §10.3.4.1 Ignore IE and Notify Sender: ignore it and send Error Indication.
#[test]
fn an_unknown_notify_procedure_is_ignored_and_reported() {
    let ei = only_error_indication(&handle_s1ap_message(&ctx(), 1, &[0x20, 0xC8, 0x80, 0x00]));
    assert_eq!(
        ei.cause,
        Some(Cause::Protocol(
            CauseProtocol::AbstractSyntaxErrorIgnoreAndNotify
        ))
    );
    let d = ei.criticality_diagnostics.expect("diagnostics");
    assert_eq!(d.procedure_code, Some(200));
    assert_eq!(d.triggering_message, Some(1));
    assert_eq!(d.procedure_criticality, Some(2));
}

/// §10.3.4.1 Ignore IE: ignore the procedure, send nothing.
#[test]
fn an_unknown_ignore_procedure_is_silently_ignored() {
    assert!(handle_s1ap_message(&ctx(), 1, &[0x00, 0xC8, 0x40, 0x00]).is_empty());
}

#[test]
fn an_mme_originated_message_is_answered_as_incompatible_with_state() {
    let ei = only_error_indication(&handle_s1ap_message(&ctx(), 1, &[0x00, 0x0B, 0x40, 0x00]));
    assert_eq!(
        ei.cause,
        Some(Cause::Protocol(
            CauseProtocol::MessageNotCompatibleWithReceiverState
        ))
    );
}

#[test]
fn an_undecodable_known_procedure_is_a_transfer_syntax_error_naming_it() {
    let ei = only_error_indication(&handle_s1ap_message(
        &ctx(),
        1,
        &[0x00, 0x11, 0x00, 0x02, 0xFF, 0xFF],
    ));
    assert_eq!(
        ei.cause,
        Some(Cause::Protocol(CauseProtocol::TransferSyntaxError))
    );
    let d = ei.criticality_diagnostics.expect("diagnostics");
    assert_eq!(d.procedure_code, Some(17));
    assert_eq!(d.triggering_message, Some(0));
}

#[test]
fn a_malformed_header_is_answered_with_transfer_syntax_error() {
    let ei = only_error_indication(&handle_s1ap_message(&ctx(), 1, &[0x60, 0xC8, 0x00, 0x00]));
    assert_eq!(
        ei.cause,
        Some(Cause::Protocol(CauseProtocol::TransferSyntaxError))
    );
}
