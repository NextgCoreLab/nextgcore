//! SBC-AP Handler
//!
//! Port of src/mme/sbc-handler.c, src/mme/sbc-handler.h - SBc-AP message handling
//!
//! Handles Public Warning System (PWS) messages from Cell Broadcast Centre (CBC):
//! - Write-Replace Warning Request: Broadcast new warning message
//! - Stop Warning Request: Stop broadcasting a warning message
//!
//! Reference: 3GPP TS 29.168 (SBc-AP), 3GPP TS 23.041 (CBS)

use std::sync::Arc;
use log::{debug, error, info, warn};

use crate::context::{MmeContext, MmeEnb, EpsTai};
use crate::sbc_message::{SbcPwsData, SbcCause, WriteReplaceWarningResponse, StopWarningResponse};

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
            error!("Failed to acquire eNB pool lock: {}", e);
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
                    debug!(
                        "Sent Write-Replace-Warning to eNB {:08x}",
                        enb.enb_id
                    );
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
        cause: None,
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
            error!("Failed to acquire eNB pool lock: {}", e);
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
        cause: None,
        unknown_tai_list,
    })
}

/// Handle PWS Restart Indication
///
/// Called when an eNB indicates it has restarted and lost PWS state.
/// The MME should re-send any active warnings to the eNB.
pub fn handle_pws_restart_indication(
    _mme_ctx: &Arc<MmeContext>,
    enb_id: u32,
) {
    info!("[PWS-Restart] eNB {:08x} restarted, re-sending active warnings", enb_id);

    // In a full implementation:
    // 1. Look up active warnings for this eNB's TAIs
    // 2. Re-send Write-Replace Warning for each active warning
    // For now, just log the event
    debug!("PWS restart indication from eNB {:08x} - stub implementation", enb_id);
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
        "[PWS-Failure] eNB {:08x} failed to broadcast message_id={:#06x} serial_number={:#06x}",
        enb_id, message_id, serial_number
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

/// Send Write-Replace Warning Request to an eNB via S1AP
fn send_write_replace_warning_to_enb(
    enb: &MmeEnb,
    sbc_pws: &SbcPwsData,
) -> Result<(), SbcCause> {
    // In a full implementation, would:
    // 1. Build S1AP Write-Replace Warning Request message
    // 2. Send to eNB via SCTP
    // For now, just log and return success (stub)
    debug!(
        "Would send Write-Replace Warning to eNB {:08x} for message {:#06x}",
        enb.enb_id, sbc_pws.message_id
    );
    Ok(())
}

/// Send Kill Request to an eNB via S1AP
fn send_kill_to_enb(
    enb: &MmeEnb,
    sbc_pws: &SbcPwsData,
) -> Result<(), SbcCause> {
    // In a full implementation, would:
    // 1. Build S1AP Kill Request message
    // 2. Send to eNB via SCTP
    // For now, just log and return success (stub)
    debug!(
        "Would send Kill to eNB {:08x} for message {:#06x}",
        enb.enb_id, sbc_pws.message_id
    );
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tai_match_empty_list() {
        // A TAI list with no entries should match nothing
        let enb = MmeEnb::default();
        let tai_list: Vec<EpsTai> = vec![];
        assert!(!check_tai_match(&enb, &tai_list));
    }
}
