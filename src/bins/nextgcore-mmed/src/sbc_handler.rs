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
use crate::sbc_message::{SbcCause, SbcPwsData, StopWarningResponse, WriteReplaceWarningResponse};

// ============================================================================
// S1AP Procedure Codes for PWS
// ============================================================================

/// S1AP Write-Replace Warning procedure code
pub const S1AP_PROCEDURE_WRITE_REPLACE_WARNING: u8 = 36;
/// S1AP Kill procedure code
pub const S1AP_PROCEDURE_KILL: u8 = 43;

// ============================================================================
// Handler Functions
// ============================================================================

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
            match send_write_replace_warning_to_enb(enb, sbc_pws) {
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
            match send_kill_to_enb(enb, sbc_pws) {
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

    Ok(StopWarningResponse {
        message_id: sbc_pws.message_id,
        serial_number: sbc_pws.serial_number,
        cause: broadcast_cause(enbs_notified),
        unknown_tai_list,
    })
}

/// Handle PWS Restart Indication
///
/// Called when an eNB indicates it has restarted and lost PWS state.
/// The MME should re-send any active warnings to the eNB.
pub fn handle_pws_restart_indication(_mme_ctx: &Arc<MmeContext>, enb_id: u32) {
    info!("[PWS-Restart] eNB {enb_id:08x} restarted, re-sending active warnings");

    // In a full implementation:
    // 1. Look up active warnings for this eNB's TAIs
    // 2. Re-send Write-Replace Warning for each active warning
    // For now, just log the event
    debug!("PWS restart indication from eNB {enb_id:08x} - stub implementation");
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

/// Send Write-Replace Warning Request to an eNB via S1AP.
///
/// **Not implemented, and it says so.** The S1AP WRITE-REPLACE WARNING REQUEST
/// message has no encoder in `nextgcore-s1ap` (part of #49), so nothing can be put
/// on the wire. This used to log "Would send" and return `Ok(())`, which made the
/// caller count the eNB as notified and answer the Cell Broadcast Centre with
/// success — telling it a public warning had been broadcast when nothing left the
/// MME. On an ETWS/CMAS path that false positive can delay an emergency alert, so
/// it reports `WarningBroadcastNotOperational` (SBc cause 10, TS 29.168 §7.4.4)
/// until the codec exists.
fn send_write_replace_warning_to_enb(enb: &MmeEnb, sbc_pws: &SbcPwsData) -> Result<(), SbcCause> {
    warn!(
        "Cannot broadcast Write-Replace Warning to eNB {:08x} (message {:#06x}): the S1AP \
         WRITE-REPLACE WARNING REQUEST encoder is not implemented (#49)",
        enb.enb_id, sbc_pws.message_id
    );
    Err(SbcCause::WarningBroadcastNotOperational)
}

/// Send Kill Request to an eNB via S1AP.
///
/// Same as [`send_write_replace_warning_to_enb`]: no S1AP KILL REQUEST encoder
/// exists (#49), so a stubbed success would tell the CBC a warning had been
/// cancelled while it kept broadcasting — the more dangerous direction of the two.
fn send_kill_to_enb(enb: &MmeEnb, sbc_pws: &SbcPwsData) -> Result<(), SbcCause> {
    warn!(
        "Cannot cancel the warning on eNB {:08x} (message {:#06x}): the S1AP KILL REQUEST \
         encoder is not implemented (#49)",
        enb.enb_id, sbc_pws.message_id
    );
    Err(SbcCause::WarningBroadcastNotOperational)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_pws_send_stubs_report_failure_rather_than_false_success() {
        let enb = MmeEnb::default();
        let pws = SbcPwsData::default();

        // Until the S1AP encoders exist (#49), nothing can reach an eNB — and
        // saying otherwise on an ETWS/CMAS path can delay an emergency alert.
        assert_eq!(
            send_write_replace_warning_to_enb(&enb, &pws),
            Err(SbcCause::WarningBroadcastNotOperational)
        );
        assert_eq!(
            send_kill_to_enb(&enb, &pws),
            Err(SbcCause::WarningBroadcastNotOperational)
        );
    }

    #[test]
    fn test_tai_match_empty_list() {
        // A TAI list with no entries should match nothing
        let enb = MmeEnb::default();
        let tai_list: Vec<EpsTai> = vec![];
        assert!(!check_tai_match(&enb, &tai_list));
    }
}
