//! HSS S6a Diameter Path
//!
//! Port of src/hss/hss-s6a-path.c - S6a interface handlers for EPC authentication
//! Handles AIR (Authentication-Information-Request), ULR (Update-Location-Request),
//! PUR (Purge-UE-Request), CLR (Cancel-Location-Request), IDR (Insert-Subscriber-Data-Request)

use crate::fd_path::diam_stats;

/// S6a Application ID
pub const OGS_DIAM_S6A_APPLICATION_ID: u32 = 16777251;

/// S6a Cancellation Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationType {
    /// MME Update Procedure
    MmeUpdateProcedure = 0,
    /// SGSN Update Procedure
    SgsnUpdateProcedure = 1,
    /// Subscription Withdrawal
    SubscriptionWithdrawal = 2,
    /// Update Procedure IWF
    UpdateProcedureIwf = 3,
    /// Initial Attach Procedure
    InitialAttachProcedure = 4,
}

impl From<u32> for CancellationType {
    fn from(value: u32) -> Self {
        match value {
            0 => CancellationType::MmeUpdateProcedure,
            1 => CancellationType::SgsnUpdateProcedure,
            2 => CancellationType::SubscriptionWithdrawal,
            3 => CancellationType::UpdateProcedureIwf,
            4 => CancellationType::InitialAttachProcedure,
            _ => CancellationType::SubscriptionWithdrawal,
        }
    }
}

/// S6a Subscription Data Mask flags
pub const OGS_DIAM_S6A_SUBDATA_MSISDN: u32 = 0x0001;
pub const OGS_DIAM_S6A_SUBDATA_ARD: u32 = 0x0002;
pub const OGS_DIAM_S6A_SUBDATA_SUB_STATUS: u32 = 0x0004;
pub const OGS_DIAM_S6A_SUBDATA_OP_DET_BARRING: u32 = 0x0008;
pub const OGS_DIAM_S6A_SUBDATA_NAM: u32 = 0x0010;
pub const OGS_DIAM_S6A_SUBDATA_UEAMBR: u32 = 0x0020;
pub const OGS_DIAM_S6A_SUBDATA_RAU_TAU_TIMER: u32 = 0x0040;
pub const OGS_DIAM_S6A_SUBDATA_APN_CONFIG: u32 = 0x0080;

/// S6a Result Codes
pub const OGS_DIAM_S6A_ERROR_USER_UNKNOWN: u32 = 5001;
pub const OGS_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE: u32 = 4181;

/// Initialize S6a interface
pub fn hss_s6a_init() -> Result<(), String> {
    log::info!("Initializing HSS S6a interface");
    // TODO: Register S6a Diameter handlers
    // - AIR callback (Authentication-Information-Request)
    // - ULR callback (Update-Location-Request)
    // - PUR callback (Purge-UE-Request)
    // - CLA callback (Cancel-Location-Answer)
    // - IDA callback (Insert-Subscriber-Data-Answer)
    Ok(())
}

/// Finalize S6a interface
pub fn hss_s6a_final() {
    log::info!("Finalizing HSS S6a interface");
}

/// Send Cancel-Location-Request to MME
///
/// # Arguments
/// * `imsi_bcd` - IMSI in BCD format
/// * `mme_host` - MME Diameter host (optional, will be looked up from DB if None)
/// * `mme_realm` - MME Diameter realm (optional, will be looked up from DB if None)
/// * `cancellation_type` - Type of cancellation
pub fn hss_s6a_send_clr(
    imsi_bcd: &str,
    mme_host: Option<&str>,
    mme_realm: Option<&str>,
    cancellation_type: CancellationType,
) -> Result<(), String> {
    log::info!(
        "[{}] Sending Cancel-Location-Request (type={:?})",
        imsi_bcd,
        cancellation_type
    );

    // TODO: Implement CLR sending
    // 1. Look up MME host/realm from DB if not provided
    // 2. Create CLR message with:
    //    - User-Name (IMSI)
    //    - Cancellation-Type
    //    - Destination-Host
    //    - Destination-Realm
    // 3. Send message and register CLA callback

    diam_stats().s6a.inc_tx_clr();
    Ok(())
}

/// Send Insert-Subscriber-Data-Request to MME
///
/// # Arguments
/// * `imsi_bcd` - IMSI in BCD format
/// * `idr_flags` - IDR flags
/// * `subdata_mask` - Subscription data mask indicating which data to include
pub fn hss_s6a_send_idr(
    imsi_bcd: &str,
    idr_flags: u32,
    subdata_mask: u32,
) -> Result<(), String> {
    log::info!(
        "[{}] Sending Insert-Subscriber-Data-Request (flags={}, mask={})",
        imsi_bcd,
        idr_flags,
        subdata_mask
    );

    // TODO: Implement IDR sending
    // 1. Look up MME host/realm from DB
    // 2. Get subscription data from DB
    // 3. Create IDR message with:
    //    - User-Name (IMSI)
    //    - IDR-Flags
    //    - Subscription-Data (based on subdata_mask)
    //    - Destination-Host
    //    - Destination-Realm
    // 4. Send message and register IDA callback

    diam_stats().s6a.inc_tx_idr();
    Ok(())
}

/// Handle Authentication-Information-Request (AIR)
///
/// This is called when MME requests authentication vectors for a UE
pub fn handle_air(imsi_bcd: &str, visited_plmn_id: &[u8], resync_info: Option<&[u8]>) -> Result<AirResponse, String> {
    log::debug!("[{}] Handling AIR", imsi_bcd);
    diam_stats().s6a.inc_rx_air();

    // TODO: Implement AIR handling
    // 1. Get auth info from DB (K, OPc, SQN, AMF)
    // 2. If resync_info provided, perform re-synchronization
    // 3. Generate authentication vector (RAND, XRES, AUTN, KASME)
    // 4. Update SQN in DB
    // 5. Return AIA with E-UTRAN-Vector

    diam_stats().s6a.inc_tx_aia();
    Ok(AirResponse::default())
}

/// Handle Update-Location-Request (ULR)
///
/// This is called when MME registers a UE's location
pub fn handle_ulr(
    imsi_bcd: &str,
    visited_plmn_id: &[u8],
    ulr_flags: u32,
    mme_host: &str,
    mme_realm: &str,
) -> Result<UlrResponse, String> {
    log::debug!("[{}] Handling ULR", imsi_bcd);
    diam_stats().s6a.inc_rx_ulr();

    // TODO: Implement ULR handling
    // 1. Update MME info in DB
    // 2. Get subscription data from DB
    // 3. Return ULA with Subscription-Data

    diam_stats().s6a.inc_tx_ula();
    Ok(UlrResponse::default())
}

/// Handle Purge-UE-Request (PUR)
///
/// This is called when MME purges a UE
pub fn handle_pur(imsi_bcd: &str, pur_flags: u32) -> Result<PurResponse, String> {
    log::debug!("[{}] Handling PUR", imsi_bcd);
    diam_stats().s6a.inc_rx_pur();

    // TODO: Implement PUR handling
    // 1. Update purge flag in DB
    // 2. Return PUA

    diam_stats().s6a.inc_tx_pua();
    Ok(PurResponse::default())
}

/// AIR Response structure
#[derive(Debug, Default)]
pub struct AirResponse {
    /// RAND value
    pub rand: [u8; 16],
    /// XRES value
    pub xres: Vec<u8>,
    /// AUTN value
    pub autn: [u8; 16],
    /// KASME value
    pub kasme: [u8; 32],
    /// Result code (0 = success)
    pub result_code: u32,
}

/// ULR Response structure
#[derive(Debug, Default)]
pub struct UlrResponse {
    /// Result code (0 = success)
    pub result_code: u32,
    /// Subscription data (serialized)
    pub subscription_data: Vec<u8>,
}

/// PUR Response structure
#[derive(Debug, Default)]
pub struct PurResponse {
    /// Result code (0 = success)
    pub result_code: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cancellation_type_from_u32() {
        assert_eq!(CancellationType::from(0), CancellationType::MmeUpdateProcedure);
        assert_eq!(CancellationType::from(2), CancellationType::SubscriptionWithdrawal);
        assert_eq!(CancellationType::from(99), CancellationType::SubscriptionWithdrawal);
    }

    #[test]
    fn test_s6a_init_final() {
        assert!(hss_s6a_init().is_ok());
        hss_s6a_final();
    }

    #[test]
    fn test_send_clr() {
        let result = hss_s6a_send_clr(
            "123456789012345",
            Some("mme.example.com"),
            Some("example.com"),
            CancellationType::SubscriptionWithdrawal,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_idr() {
        let result = hss_s6a_send_idr(
            "123456789012345",
            0,
            OGS_DIAM_S6A_SUBDATA_UEAMBR | OGS_DIAM_S6A_SUBDATA_APN_CONFIG,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_air() {
        let visited_plmn = [0x00, 0xF1, 0x10]; // MCC=001, MNC=01
        let result = handle_air("123456789012345", &visited_plmn, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_ulr() {
        let visited_plmn = [0x00, 0xF1, 0x10];
        let result = handle_ulr(
            "123456789012345",
            &visited_plmn,
            0,
            "mme.example.com",
            "example.com",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_pur() {
        let result = handle_pur("123456789012345", 0);
        assert!(result.is_ok());
    }
}
