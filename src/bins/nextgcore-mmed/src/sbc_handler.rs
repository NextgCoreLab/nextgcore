//! SBC-AP Handler
//!
//! Port of src/mme/sbc-handler.c, src/mme/sbc-handler.h - SBc-AP message handling
//!
//! Handles Public Warning System (PWS) messages from Cell Broadcast Centre (CBC):
//! - Write-Replace Warning Request: Broadcast new warning message
//! - Stop Warning Request: Stop broadcasting a warning message
//!
//! Reference: 3GPP TS 29.168 (SBc-AP), 3GPP TS 23.041 (CBS)

use log::{debug, error, info, warn};
use std::sync::Arc;

use crate::context::{EpsTai, MmeContext, MmeEnb};
use crate::s1ap_build;
use crate::s1ap_path;
use crate::sbc_message::{SbcCause, SbcPwsData, StopWarningResponse, WriteReplaceWarningResponse};

// The S1AP procedure codes for these messages are not redeclared here: they
// live in `nextgcore_asn1c::s1ap::types::ProcedureCode` (WRITE_REPLACE_WARNING,
// KILL), which is what the builders and parser use. A second copy is the same
// defect as the `S1apProcedureCode` enum #49 removed from `sm.rs`.

// ============================================================================
// Handler Functions
// ============================================================================

/// How an encoded S1AP PDU reaches an eNB, returning whether the transport took
/// it.
///
/// Injected rather than called directly so the fan-out can be tested against a
/// sender that records what went out. The alternative — asserting on
/// [`s1ap_path`]'s process-global downlink queue — cannot be done deterministically
/// from a unit test, because that queue is installed once per process and the
/// order tests run in decides who gets it. This is a safety-critical path
/// (see #167), so it is worth one parameter to be able to assert that the CBC is
/// told success exactly when a real PDU went to a real eNB.
type PduSender<'a> = &'a mut dyn FnMut(u64, Vec<u8>) -> bool;

/// The production sender: hand the PDU to the S1AP transport for that eNB.
fn transport_sender(enb_id: u64, pdu: Vec<u8>) -> bool {
    s1ap_path::s1ap_send_pdu(enb_id, pdu)
}

/// Handle Write-Replace Warning Request from CBC
///
/// Broadcasts the warning message to all eNBs whose TAI matches the warning area.
/// If no TAIs are specified, the warning is broadcast to all eNBs.
///
/// # Arguments
/// * `mme_ctx` - MME context containing eNB list
/// * `sbc_pws` - PWS data containing warning message details
///
/// # Returns
/// * `Ok(WriteReplaceWarningResponse)` - Response to send back to CBC
/// * `Err(SbcCause)` - Error cause if processing failed
pub fn handle_write_replace_warning_request(
    mme_ctx: &Arc<MmeContext>,
    sbc_pws: &SbcPwsData,
) -> Result<WriteReplaceWarningResponse, SbcCause> {
    handle_write_replace_warning_request_with(mme_ctx, sbc_pws, &mut transport_sender)
}

fn handle_write_replace_warning_request_with(
    mme_ctx: &Arc<MmeContext>,
    sbc_pws: &SbcPwsData,
    send: PduSender,
) -> Result<WriteReplaceWarningResponse, SbcCause> {
    info!(
        "[Write-Replace-Warning] message_id={:#06x} serial_number={:#06x}",
        sbc_pws.message_id, sbc_pws.serial_number
    );

    let mut unknown_tai_list = Vec::new();
    let mut enbs_notified = 0u32;

    // Get read lock on eNB pool
    let enb_pool = match mme_ctx.enb_pool.read() {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to acquire eNB pool lock: {e}");
            return Err(SbcCause::MmeCapacityExceeded);
        }
    };

    // Iterate through all eNBs
    for enb in enb_pool.values() {
        let should_send = if sbc_pws.no_of_tai > 0 {
            // Check if any of the eNB's supported TAs match the warning area
            check_tai_match(enb, &sbc_pws.tai)
        } else {
            // No TAI specified - broadcast to all eNBs
            true
        };

        if should_send {
            match send_write_replace_warning_to_enb(enb, sbc_pws, send) {
                Ok(_) => {
                    enbs_notified += 1;
                    debug!("Sent Write-Replace-Warning to eNB {:08x}", enb.enb_id);
                }
                Err(e) => {
                    warn!(
                        "Failed to send Write-Replace-Warning to eNB {:08x}: {:?}",
                        enb.enb_id, e
                    );
                }
            }
        }
    }

    // Check for unknown TAIs (TAIs requested but not served by any eNB)
    if sbc_pws.no_of_tai > 0 {
        for tai in &sbc_pws.tai {
            if !is_tai_served_by_any_enb(&enb_pool, tai) {
                unknown_tai_list.push(tai.clone());
            }
        }
    }

    info!(
        "[Write-Replace-Warning] Notified {} eNBs, {} unknown TAIs",
        enbs_notified,
        unknown_tai_list.len()
    );

    // Remember the warning only when it actually reached an eNB, so a PWS
    // restart cannot re-send something that never went out in the first place.
    if enbs_notified > 0 {
        mme_ctx.pws_record_active_warning(sbc_pws);
    }

    Ok(WriteReplaceWarningResponse {
        message_id: sbc_pws.message_id,
        serial_number: sbc_pws.serial_number,
        // A response with no cause tells the CBC the warning is being broadcast.
        // It must only say that when at least one eNB actually took it
        // (TS 29.168 §5.1.2.2).
        cause: broadcast_cause(enbs_notified),
        unknown_tai_list,
    })
}

/// Handle Stop Warning Request from CBC
///
/// Sends Kill Request to all eNBs to stop broadcasting the warning message.
///
/// # Arguments
/// * `mme_ctx` - MME context containing eNB list
/// * `sbc_pws` - PWS data identifying the warning to stop
///
/// # Returns
/// * `Ok(StopWarningResponse)` - Response to send back to CBC
/// * `Err(SbcCause)` - Error cause if processing failed
pub fn handle_stop_warning_request(
    mme_ctx: &Arc<MmeContext>,
    sbc_pws: &SbcPwsData,
) -> Result<StopWarningResponse, SbcCause> {
    handle_stop_warning_request_with(mme_ctx, sbc_pws, &mut transport_sender)
}

fn handle_stop_warning_request_with(
    mme_ctx: &Arc<MmeContext>,
    sbc_pws: &SbcPwsData,
    send: PduSender,
) -> Result<StopWarningResponse, SbcCause> {
    info!(
        "[Stop-Warning] message_id={:#06x} serial_number={:#06x}",
        sbc_pws.message_id, sbc_pws.serial_number
    );

    let mut unknown_tai_list = Vec::new();
    let mut enbs_notified = 0u32;

    // Get read lock on eNB pool
    let enb_pool = match mme_ctx.enb_pool.read() {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to acquire eNB pool lock: {e}");
            return Err(SbcCause::MmeCapacityExceeded);
        }
    };

    // Iterate through all eNBs
    for enb in enb_pool.values() {
        let should_send = if sbc_pws.no_of_tai > 0 {
            check_tai_match(enb, &sbc_pws.tai)
        } else {
            true
        };

        if should_send {
            match send_kill_to_enb(enb, sbc_pws, send) {
                Ok(_) => {
                    enbs_notified += 1;
                    debug!("Sent Kill to eNB {:08x}", enb.enb_id);
                }
                Err(e) => {
                    warn!("Failed to send Kill to eNB {:08x}: {:?}", enb.enb_id, e);
                }
            }
        }
    }

    // Check for unknown TAIs
    if sbc_pws.no_of_tai > 0 {
        for tai in &sbc_pws.tai {
            if !is_tai_served_by_any_enb(&enb_pool, tai) {
                unknown_tai_list.push(tai.clone());
            }
        }
    }

    info!(
        "[Stop-Warning] Notified {} eNBs, {} unknown TAIs",
        enbs_notified,
        unknown_tai_list.len()
    );

    // The warning is no longer active regardless of how many eNBs took the
    // Kill: the CBC has withdrawn it, so a later PWS restart must not resurrect
    // it. eNBs that missed the Kill are the failure the response reports.
    mme_ctx.pws_forget_active_warning(sbc_pws.message_id, sbc_pws.serial_number);

    Ok(StopWarningResponse {
        message_id: sbc_pws.message_id,
        serial_number: sbc_pws.serial_number,
        cause: broadcast_cause(enbs_notified),
        unknown_tai_list,
    })
}

/// Handle PWS Restart Indication (TS 36.413 §8.14, TS 23.041 §9.3.x).
///
/// An eNB that restarted has lost its PWS state, so any warning the MME believes
/// is broadcasting there is not. Every active warning whose area this eNB serves
/// is re-sent. Returns how many were re-sent.
///
/// `enb_id` is the Global eNB ID from the indication, not a pool id, because
/// that is what the eNB identifies itself by.
pub fn handle_pws_restart_indication(mme_ctx: &Arc<MmeContext>, enb_id: u32) -> usize {
    handle_pws_restart_indication_with(mme_ctx, enb_id, &mut transport_sender)
}

fn handle_pws_restart_indication_with(
    mme_ctx: &Arc<MmeContext>,
    enb_id: u32,
    send: PduSender,
) -> usize {
    let active = mme_ctx.pws_active_warnings();
    if active.is_empty() {
        debug!("[PWS-Restart] eNB {enb_id:08x} restarted; no active warnings to re-send");
        return 0;
    }

    let Some(pool_id) = mme_ctx.enb_find_by_enb_id(enb_id) else {
        warn!(
            "[PWS-Restart] eNB {enb_id:08x} is not registered; cannot re-send \
             {} active warning(s)",
            active.len()
        );
        return 0;
    };
    let Some(enb) = mme_ctx.enb_find_by_id(pool_id) else {
        return 0;
    };

    let mut resent = 0usize;
    for warning in &active {
        // Only warnings whose area this eNB serves, using the same match the
        // original fan-out used, so a restart does not widen a targeted alert.
        let applies = warning.no_of_tai == 0 || check_tai_match(&enb, &warning.tai);
        if !applies {
            continue;
        }
        match send_write_replace_warning_to_enb(&enb, warning, send) {
            Ok(()) => resent += 1,
            Err(e) => warn!(
                "[PWS-Restart] failed to re-send warning {:#06x}/{:#06x} to eNB {enb_id:08x}: \
                 {e:?}",
                warning.message_id, warning.serial_number
            ),
        }
    }

    info!(
        "[PWS-Restart] eNB {enb_id:08x} restarted; re-sent {resent} of {} active warning(s)",
        active.len()
    );
    resent
}

/// Handle PWS Failure Indication
///
/// Called when an eNB reports failure to broadcast a warning.
pub fn handle_pws_failure_indication(
    _mme_ctx: &Arc<MmeContext>,
    enb_id: u32,
    message_id: u16,
    serial_number: u16,
) {
    warn!(
        "[PWS-Failure] eNB {enb_id:08x} failed to broadcast message_id={message_id:#06x} serial_number={serial_number:#06x}"
    );

    // In a full implementation, would:
    // 1. Track failure for this eNB
    // 2. Potentially notify CBC
    // 3. Consider retry logic
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if an eNB's served TAIs match any TAI in the warning area
fn check_tai_match(enb: &MmeEnb, tai_list: &[EpsTai]) -> bool {
    // Check if any of the eNB's supported TAs match the warning area
    for supported_ta in &enb.supported_ta_list {
        for tai in tai_list {
            if supported_ta.plmn_id == tai.plmn_id && supported_ta.tac == tai.tac {
                return true;
            }
        }
    }
    false
}

/// Check if a TAI is served by any eNB in the list
fn is_tai_served_by_any_enb(
    enb_pool: &std::collections::HashMap<u64, MmeEnb>,
    tai: &EpsTai,
) -> bool {
    for enb in enb_pool.values() {
        for supported_ta in &enb.supported_ta_list {
            if supported_ta.plmn_id == tai.plmn_id && supported_ta.tac == tai.tac {
                return true;
            }
        }
    }
    false
}

/// The cause an SBc response carries given how many eNBs took the message.
///
/// `None` means success to the CBC, so it is only returned when at least one eNB
/// was actually reached. Zero is reported as `WarningBroadcastNotOperational`
/// rather than silence: a CBC that believes an alert went out will not retry it.
fn broadcast_cause(enbs_notified: u32) -> Option<SbcCause> {
    (enbs_notified == 0).then_some(SbcCause::WarningBroadcastNotOperational)
}

/// The TAIs of the warning area that this eNB actually serves.
///
/// An empty result means the CBC named no area at all, which per TS 23.041 is a
/// request to broadcast in every cell — the S1AP Warning Area List is then
/// omitted. It is never the "this eNB serves none of them" case, because
/// [`check_tai_match`] has already excluded those eNBs.
fn matched_warning_tais(enb: &MmeEnb, sbc_pws: &SbcPwsData) -> Vec<EpsTai> {
    if sbc_pws.no_of_tai == 0 {
        return Vec::new();
    }
    sbc_pws
        .tai
        .iter()
        .filter(|tai| {
            enb.supported_ta_list
                .iter()
                .any(|ta| ta.plmn_id == tai.plmn_id && ta.tac == tai.tac)
        })
        .cloned()
        .collect()
}

/// What "notified" is allowed to mean, and the one place it is decided.
///
/// The caller turns `Ok` into "one more eNB notified", and a response carrying no
/// cause tells the Cell Broadcast Centre the warning **is** being broadcast
/// (TS 29.168 §5.1.2.2). So `Ok` must rest on evidence, and the strongest
/// evidence available to synchronous code is:
///
/// 1. the eNB completed S1 Setup, so an S1 interface exists to carry
///    non-UE-associated signalling (an eNB is removed from the pool when its
///    SCTP association closes), and
/// 2. the S1AP transport accepted the encoded PDU for it.
///
/// It is deliberately *not* proof of reception — no S1AP Class-1 procedure is,
/// until the eNB's response arrives, which is why
/// [`crate::s1ap_handler`] treats a Write-Replace Warning Response with no
/// Broadcast Completed Area List as a warning. What matters here is that a
/// failure to send is never reported as a success: that was #167's defect, where
/// two `Ok(())` stubs made the MME tell a CBC an ETWS/CMAS alert had gone out
/// while nothing left the daemon.
fn queue_to_enb(
    enb: &MmeEnb,
    pdu: Vec<u8>,
    what: &str,
    message_id: u16,
    send: PduSender,
) -> Result<(), SbcCause> {
    if !enb.state.s1_setup_success {
        warn!(
            "Cannot send {what} to eNB {:08x} (message {message_id:#06x}): S1 Setup has not \
             completed, so there is no S1 interface to carry it",
            enb.enb_id
        );
        return Err(SbcCause::WarningBroadcastNotOperational);
    }
    if !send(enb.id, pdu) {
        warn!(
            "Cannot send {what} to eNB {:08x} (message {message_id:#06x}): the S1AP transport \
             did not accept it",
            enb.enb_id
        );
        return Err(SbcCause::WarningBroadcastNotOperational);
    }
    debug!(
        "{what} queued for eNB {:08x} (message {message_id:#06x})",
        enb.enb_id
    );
    Ok(())
}

/// Encode the WRITE-REPLACE WARNING REQUEST this eNB should receive
/// (TS 36.413 §8.12.1). Split from the send so the encoding is testable without
/// a transport.
fn write_replace_warning_pdu(enb: &MmeEnb, sbc_pws: &SbcPwsData) -> Result<Vec<u8>, SbcCause> {
    let warning_tais = matched_warning_tais(enb, sbc_pws);
    s1ap_build::build_write_replace_warning(sbc_pws, &warning_tais).map_err(|e| {
        error!(
            "Failed to encode WRITE-REPLACE WARNING REQUEST for eNB {:08x} \
             (message {:#06x}): {e}",
            enb.enb_id, sbc_pws.message_id
        );
        SbcCause::WarningBroadcastNotOperational
    })
}

/// Encode the KILL REQUEST this eNB should receive (TS 36.413 §8.12.2).
fn kill_pdu(enb: &MmeEnb, sbc_pws: &SbcPwsData) -> Result<Vec<u8>, SbcCause> {
    let warning_tais = matched_warning_tais(enb, sbc_pws);
    s1ap_build::build_kill(sbc_pws, &warning_tais).map_err(|e| {
        error!(
            "Failed to encode KILL REQUEST for eNB {:08x} (message {:#06x}): {e}",
            enb.enb_id, sbc_pws.message_id
        );
        SbcCause::WarningBroadcastNotOperational
    })
}

/// Send Write-Replace Warning Request to an eNB over S1AP (TS 36.413 §8.12.1).
fn send_write_replace_warning_to_enb(
    enb: &MmeEnb,
    sbc_pws: &SbcPwsData,
    send: PduSender,
) -> Result<(), SbcCause> {
    let pdu = write_replace_warning_pdu(enb, sbc_pws)?;
    queue_to_enb(
        enb,
        pdu,
        "WRITE-REPLACE WARNING REQUEST",
        sbc_pws.message_id,
        send,
    )
}

/// Send Kill Request to an eNB over S1AP (TS 36.413 §8.12.2).
///
/// The more dangerous direction of the two: a false success here tells the CBC a
/// warning was cancelled while eNBs keep broadcasting it.
fn send_kill_to_enb(enb: &MmeEnb, sbc_pws: &SbcPwsData, send: PduSender) -> Result<(), SbcCause> {
    let pdu = kill_pdu(enb, sbc_pws)?;
    queue_to_enb(enb, pdu, "KILL REQUEST", sbc_pws.message_id, send)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PlmnId;
    use crate::sbc_message::{EtwsWarningType, DCS_GSM7, MSG_ID_ETWS_EARTHQUAKE};

    #[test]
    fn test_broadcast_cause_only_claims_success_when_an_enb_took_it() {
        // The bug this fixes: a response with no cause is SUCCESS to the CBC.
        assert_eq!(
            broadcast_cause(0),
            Some(SbcCause::WarningBroadcastNotOperational),
            "a CBC that believes an alert went out will not retry it"
        );
        assert_eq!(broadcast_cause(1), None);
        assert_eq!(broadcast_cause(42), None);
    }

    #[test]
    fn test_pws_send_reports_failure_rather_than_false_success() {
        // An eNB that never completed S1 Setup has no S1 interface to carry
        // non-UE-associated signalling, so neither message can be sent — and
        // saying otherwise on an ETWS/CMAS path can delay an emergency alert.
        // This is #167's guarantee, preserved now that the encoders exist.
        let enb = MmeEnb::default();
        assert!(!enb.state.s1_setup_success);
        let pws = etws_warning();

        // The sender must not even be consulted: there is no S1 interface.
        let mut consulted = false;
        let mut send = |_enb_id: u64, _pdu: Vec<u8>| {
            consulted = true;
            true
        };
        assert_eq!(
            send_write_replace_warning_to_enb(&enb, &pws, &mut send),
            Err(SbcCause::WarningBroadcastNotOperational)
        );
        assert_eq!(
            send_kill_to_enb(&enb, &pws, &mut send),
            Err(SbcCause::WarningBroadcastNotOperational)
        );
        drop(send);
        assert!(!consulted);
    }

    #[test]
    fn test_tai_match_empty_list() {
        // A TAI list with no entries should match nothing
        let enb = MmeEnb::default();
        let tai_list: Vec<EpsTai> = vec![];
        assert!(!check_tai_match(&enb, &tai_list));
    }

    // ------------------------------------------------------------------
    // Real S1AP egress (#49)
    // ------------------------------------------------------------------

    fn test_plmn() -> PlmnId {
        PlmnId::new("310", "410")
    }

    fn test_tai(tac: u16) -> EpsTai {
        EpsTai {
            plmn_id: test_plmn(),
            tac,
        }
    }

    /// An eNB serving TACs 1 and 2, with S1 Setup complete.
    fn setup_enb() -> MmeEnb {
        MmeEnb {
            id: 42,
            enb_id: 0x1234,
            enb_id_presence: true,
            plmn_id: test_plmn(),
            state: crate::context::EnbState {
                s1_setup_success: true,
            },
            supported_ta_list: vec![test_tai(1), test_tai(2)],
            ..Default::default()
        }
    }

    fn etws_warning() -> SbcPwsData {
        let mut pws = SbcPwsData::new(MSG_ID_ETWS_EARTHQUAKE, 0x3000);
        pws.repetition_period = 32;
        pws.number_of_broadcast = 4;
        pws.set_message(b"Earthquake. Take cover.", DCS_GSM7);
        pws.warning_type = Some(EtwsWarningType::new(
            EtwsWarningType::EARTHQUAKE,
            true,
            true,
        ));
        pws
    }

    /// The PDU handed to the transport must be a real, decodable S1AP
    /// WRITE-REPLACE WARNING REQUEST carrying the CBC's message — not a log line.
    #[test]
    fn test_write_replace_warning_encodes_a_real_s1ap_message() {
        let enb = setup_enb();
        let mut pws = etws_warning();
        pws.add_tai(test_tai(1));
        pws.add_tai(test_tai(2));
        // A TAI this eNB does not serve must not appear in its Warning Area List.
        pws.add_tai(test_tai(99));

        let pdu = write_replace_warning_pdu(&enb, &pws).expect("encodes");
        match nextgcore_s1ap::decode_s1ap_pdu(&pdu).expect("decodes") {
            nextgcore_s1ap::S1apMessage::WriteReplaceWarningRequest(req) => {
                assert_eq!(req.message_identifier, MSG_ID_ETWS_EARTHQUAKE);
                assert_eq!(req.serial_number, 0x3000);
                assert_eq!(req.repetition_period, 32);
                assert_eq!(req.number_of_broadcast_request, 4);
                assert_eq!(req.data_coding_scheme, Some(DCS_GSM7));
                assert_eq!(
                    req.warning_message_contents.as_deref(),
                    Some(b"Earthquake. Take cover.".as_slice())
                );
                assert_eq!(
                    req.warning_type,
                    Some(EtwsWarningType::new(EtwsWarningType::EARTHQUAKE, true, true).encode())
                );
                match req.warning_area {
                    Some(nextgcore_s1ap::WarningAreaList::TrackingAreaListForWarning(tais)) => {
                        assert_eq!(
                            tais.len(),
                            2,
                            "only the TAIs this eNB serves belong in its warning area"
                        );
                        let tacs: Vec<u16> = tais.iter().map(|tai| tai.tac).collect();
                        assert_eq!(tacs, vec![1, 2]);
                    }
                    other => panic!("expected a tracking-area warning list, got {other:?}"),
                }
            }
            other => panic!("expected WriteReplaceWarningRequest, got {other:?}"),
        }
    }

    /// A targeted warning whose TAIs this eNB serves none of must NOT be sent
    /// with the area list omitted: omission means "every cell this eNB serves",
    /// so it would widen a targeted emergency alert to the whole eNB. The
    /// handlers already filter such eNBs out, but the encoder fails closed so a
    /// future change to that filter cannot silently widen an alert.
    #[test]
    fn test_targeted_warning_with_no_matching_tai_is_refused() {
        let enb = setup_enb(); // serves TACs 1 and 2
        let mut pws = etws_warning();
        pws.add_tai(test_tai(99));

        assert_eq!(
            write_replace_warning_pdu(&enb, &pws),
            Err(SbcCause::WarningBroadcastNotOperational),
            "broadcasting everywhere is worse than not broadcasting"
        );
        assert_eq!(
            kill_pdu(&enb, &pws),
            Err(SbcCause::WarningBroadcastNotOperational)
        );
    }

    /// A CBC request with no warning area means every cell (TS 23.041), which
    /// S1AP expresses by omitting the Warning Area List — not by sending an
    /// empty one, which the `SIZE(1..)` constraint cannot even encode.
    #[test]
    fn test_untargeted_warning_omits_the_area_list() {
        let enb = setup_enb();
        let pws = etws_warning();
        assert_eq!(pws.no_of_tai, 0);

        let pdu = write_replace_warning_pdu(&enb, &pws).expect("encodes");
        match nextgcore_s1ap::decode_s1ap_pdu(&pdu).unwrap() {
            nextgcore_s1ap::S1apMessage::WriteReplaceWarningRequest(req) => {
                assert!(req.warning_area.is_none());
            }
            other => panic!("expected WriteReplaceWarningRequest, got {other:?}"),
        }
    }

    /// The SBc-AP fields are wider than the S1AP IEs they feed. A wrapped
    /// repetition period would silently change how long an emergency alert is
    /// broadcast, so out-of-range values clamp to the IE's maximum.
    #[test]
    fn test_oversized_sbc_values_clamp_rather_than_wrap() {
        let enb = setup_enb();
        let mut pws = etws_warning();
        pws.repetition_period = 100_000; // > RepetitionPeriod's 4095
        pws.number_of_broadcast = 100_000; // > NumberofBroadcastRequest's 65535

        let pdu = write_replace_warning_pdu(&enb, &pws).expect("encodes");
        match nextgcore_s1ap::decode_s1ap_pdu(&pdu).unwrap() {
            nextgcore_s1ap::S1apMessage::WriteReplaceWarningRequest(req) => {
                assert_eq!(req.repetition_period, 4095);
                assert_eq!(req.number_of_broadcast_request, 65535);
            }
            other => panic!("expected WriteReplaceWarningRequest, got {other:?}"),
        }
    }

    /// A Stop Warning cancels the one message the CBC named. Setting
    /// `KillAllWarningMessages` would cancel every alert the eNB holds.
    #[test]
    fn test_kill_targets_one_message_not_all_of_them() {
        let enb = setup_enb();
        let mut pws = etws_warning();
        pws.add_tai(test_tai(1));

        let pdu = kill_pdu(&enb, &pws).expect("encodes");
        match nextgcore_s1ap::decode_s1ap_pdu(&pdu).unwrap() {
            nextgcore_s1ap::S1apMessage::KillRequest(req) => {
                assert_eq!(req.message_identifier, MSG_ID_ETWS_EARTHQUAKE);
                assert_eq!(req.serial_number, 0x3000);
                assert!(
                    !req.kill_all_warning_messages,
                    "cancelling unrelated live alerts is not what a Stop Warning asks for"
                );
            }
            other => panic!("expected KillRequest, got {other:?}"),
        }
    }

    /// With no eNB reachable the CBC must be told the broadcast failed, and the
    /// warning must NOT be recorded as active — otherwise a later PWS restart
    /// would "re-send" an alert that never went out.
    #[test]
    fn test_unreachable_enbs_yield_failure_and_no_active_warning() {
        let ctx = Arc::new(MmeContext::new());
        ctx.init();
        // An eNB in the pool that never completed S1 Setup.
        ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let pws = etws_warning();
        let mut sent: Vec<(u64, Vec<u8>)> = Vec::new();
        let response = handle_write_replace_warning_request_with(&ctx, &pws, &mut |enb_id, pdu| {
            sent.push((enb_id, pdu));
            true
        })
        .expect("a response is due");

        assert!(sent.is_empty(), "nothing can go to an eNB without S1 Setup");
        assert_eq!(
            response.cause,
            Some(SbcCause::WarningBroadcastNotOperational),
            "a CBC that believes an alert went out will not retry it"
        );
        assert!(
            ctx.pws_active_warnings().is_empty(),
            "nothing reached an eNB, so there is no active warning to restore"
        );
    }

    /// Register an eNB in `ctx` with S1 Setup complete, serving TAC 1.
    fn add_setup_enb(ctx: &MmeContext, addr: &str, enb_id: u32) -> u64 {
        let pool_id = ctx.enb_add(addr.parse().unwrap());
        ctx.enb_set_enb_id(pool_id, enb_id);
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&pool_id) {
            enb.state.s1_setup_success = true;
            enb.supported_ta_list = vec![test_tai(1)];
        }
        pool_id
    }

    /// The success path: one reachable eNB takes the warning, so the CBC is told
    /// the broadcast is happening (no cause) and the warning becomes active. This
    /// is the assertion #167 could not make, because nothing was ever sent.
    #[test]
    fn test_a_reachable_enb_yields_success_and_records_the_warning() {
        let ctx = Arc::new(MmeContext::new());
        ctx.init();
        let pool_id = add_setup_enb(&ctx, "127.0.0.1:36412", 0x1234);
        // A second eNB that cannot take it must not spoil the success.
        ctx.enb_add("127.0.0.9:36412".parse().unwrap());

        let mut pws = etws_warning();
        pws.add_tai(test_tai(1));

        let mut sent: Vec<(u64, Vec<u8>)> = Vec::new();
        let response = handle_write_replace_warning_request_with(&ctx, &pws, &mut |enb_id, pdu| {
            sent.push((enb_id, pdu));
            true
        })
        .expect("a response is due");

        assert_eq!(sent.len(), 1, "exactly the one reachable eNB");
        assert_eq!(sent[0].0, pool_id);
        assert!(
            matches!(
                nextgcore_s1ap::decode_s1ap_pdu(&sent[0].1).unwrap(),
                nextgcore_s1ap::S1apMessage::WriteReplaceWarningRequest(_)
            ),
            "what goes out must be a real S1AP WRITE-REPLACE WARNING REQUEST"
        );
        assert_eq!(
            response.cause, None,
            "an eNB took it, so the CBC is told the warning is being broadcast"
        );
        assert_eq!(ctx.pws_active_warnings().len(), 1);
    }

    /// A transport that refuses the PDU is a failure, not a success: this is the
    /// exact shape of the #167 defect, one layer down.
    #[test]
    fn test_a_refusing_transport_is_reported_as_failure() {
        let ctx = Arc::new(MmeContext::new());
        ctx.init();
        add_setup_enb(&ctx, "127.0.0.1:36412", 0x1234);

        let pws = etws_warning();
        let response =
            handle_write_replace_warning_request_with(&ctx, &pws, &mut |_enb_id, _pdu| false)
                .expect("a response is due");

        assert_eq!(
            response.cause,
            Some(SbcCause::WarningBroadcastNotOperational)
        );
        assert!(ctx.pws_active_warnings().is_empty());
    }

    /// A restarted eNB has lost its PWS state, so every active warning whose area
    /// it serves is re-sent to it.
    #[test]
    fn test_pws_restart_resends_recorded_active_warnings() {
        let ctx = Arc::new(MmeContext::new());
        ctx.init();
        let pool_id = add_setup_enb(&ctx, "127.0.0.1:36412", 0x1234);

        let mut in_area = etws_warning();
        in_area.add_tai(test_tai(1));
        ctx.pws_record_active_warning(&in_area);

        // A warning for a tracking area this eNB does not serve must NOT be
        // re-sent: a restart is not an excuse to widen a targeted alert.
        let mut elsewhere = SbcPwsData::new(MSG_ID_ETWS_EARTHQUAKE, 0x4000);
        elsewhere.set_message(b"other area", DCS_GSM7);
        elsewhere.add_tai(test_tai(77));
        ctx.pws_record_active_warning(&elsewhere);

        let mut sent: Vec<(u64, Vec<u8>)> = Vec::new();
        let resent = handle_pws_restart_indication_with(&ctx, 0x1234, &mut |enb_id, pdu| {
            sent.push((enb_id, pdu));
            true
        });

        assert_eq!(resent, 1, "only the warning covering this eNB's area");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, pool_id);
        match nextgcore_s1ap::decode_s1ap_pdu(&sent[0].1).unwrap() {
            nextgcore_s1ap::S1apMessage::WriteReplaceWarningRequest(req) => {
                assert_eq!(req.serial_number, 0x3000, "the in-area warning");
            }
            other => panic!("expected WriteReplaceWarningRequest, got {other:?}"),
        }
        assert_eq!(
            ctx.pws_active_warnings().len(),
            2,
            "re-sending does not consume the active set"
        );
    }

    /// A restart from an eNB the MME does not know cannot be served, and that is
    /// reported rather than silently counted.
    #[test]
    fn test_pws_restart_from_an_unknown_enb_resends_nothing() {
        let ctx = Arc::new(MmeContext::new());
        ctx.init();
        let mut pws = etws_warning();
        pws.add_tai(test_tai(1));
        ctx.pws_record_active_warning(&pws);

        let mut sent = 0usize;
        let resent = handle_pws_restart_indication_with(&ctx, 0xDEAD, &mut |_enb_id, _pdu| {
            sent += 1;
            true
        });

        assert_eq!(resent, 0);
        assert_eq!(sent, 0);
        assert_eq!(
            ctx.pws_active_warnings().len(),
            1,
            "a failed re-send must not drop the warning"
        );
    }

    /// Write-Replace is a *replace*: a second request with the same message
    /// identifier and serial number supersedes the first rather than stacking.
    #[test]
    fn test_active_warnings_are_replaced_not_accumulated() {
        let ctx = MmeContext::new();
        let mut first = etws_warning();
        first.set_message(b"first", DCS_GSM7);
        ctx.pws_record_active_warning(&first);

        let mut second = etws_warning();
        second.set_message(b"second", DCS_GSM7);
        ctx.pws_record_active_warning(&second);

        let active = ctx.pws_active_warnings();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].message_contents, b"second".to_vec());

        // A different serial number is a different warning.
        let mut other = SbcPwsData::new(MSG_ID_ETWS_EARTHQUAKE, 0x3001);
        other.set_message(b"other", DCS_GSM7);
        ctx.pws_record_active_warning(&other);
        assert_eq!(ctx.pws_active_warnings().len(), 2);
    }

    /// A Kill drops the warning even when no eNB took it: the CBC has withdrawn
    /// it, so a later restart must not resurrect it.
    #[test]
    fn test_stop_warning_forgets_the_warning_even_when_no_enb_took_it() {
        let ctx = Arc::new(MmeContext::new());
        ctx.init();
        let pws = etws_warning();
        ctx.pws_record_active_warning(&pws);

        let response = handle_stop_warning_request_with(&ctx, &pws, &mut |_enb_id, _pdu| false)
            .expect("a response is due");
        assert_eq!(
            response.cause,
            Some(SbcCause::WarningBroadcastNotOperational),
            "no eNB was reachable, and the CBC must know"
        );
        assert!(
            ctx.pws_active_warnings().is_empty(),
            "a cancelled warning must not survive to be re-sent on restart"
        );
    }

    /// A Kill that reaches an eNB sends a real KILL REQUEST and reports success.
    #[test]
    fn test_stop_warning_sends_a_real_kill_and_reports_success() {
        let ctx = Arc::new(MmeContext::new());
        ctx.init();
        let pool_id = add_setup_enb(&ctx, "127.0.0.1:36412", 0x1234);

        let mut pws = etws_warning();
        pws.add_tai(test_tai(1));
        ctx.pws_record_active_warning(&pws);

        let mut sent: Vec<(u64, Vec<u8>)> = Vec::new();
        let response = handle_stop_warning_request_with(&ctx, &pws, &mut |enb_id, pdu| {
            sent.push((enb_id, pdu));
            true
        })
        .expect("a response is due");

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, pool_id);
        match nextgcore_s1ap::decode_s1ap_pdu(&sent[0].1).unwrap() {
            nextgcore_s1ap::S1apMessage::KillRequest(req) => {
                assert_eq!(req.message_identifier, MSG_ID_ETWS_EARTHQUAKE);
                assert_eq!(req.serial_number, 0x3000);
            }
            other => panic!("expected KillRequest, got {other:?}"),
        }
        assert_eq!(response.cause, None);
        assert!(ctx.pws_active_warnings().is_empty());
    }
}
