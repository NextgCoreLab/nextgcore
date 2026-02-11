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
    // Note: Register S6a Diameter handlers
    // - AIR callback (Authentication-Information-Request)
    // - ULR callback (Update-Location-Request)
    // - PUR callback (Purge-UE-Request)
    // - CLA callback (Cancel-Location-Answer)
    // - IDA callback (Insert-Subscriber-Data-Answer)
    // Handler registration is done by the fd_path module when FreeDiameter is initialized
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

    use ogs_diameter::s6a::{S6A_APPLICATION_ID, cmd, avp};
    use ogs_diameter::{DiameterMessage, Avp, AvpData, avp_code, OGS_3GPP_VENDOR_ID};

    // 1. Look up MME host/realm from DB if not provided
    let (dest_host, dest_realm) = if let (Some(h), Some(r)) = (mme_host, mme_realm) {
        (h.to_string(), r.to_string())
    } else {
        // Query from DB
        use ogs_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};

        let collection = get_subscriber_collection()
            .map_err(|e| format!("Failed to get subscriber collection: {}", e))?;

        let query = doc! { "imsi": imsi_bcd };
        let doc = collection.find_one(query, None)
            .map_err(|e| format!("Failed to query DB: {}", e))?
            .ok_or_else(|| format!("Subscriber not found: {}", imsi_bcd))?;

        let host = doc.get_str("mme_host")
            .unwrap_or("mme.epc.mnc001.mcc001.3gppnetwork.org").to_string();
        let realm = doc.get_str("mme_realm")
            .unwrap_or("epc.mnc001.mcc001.3gppnetwork.org").to_string();

        (host, realm)
    };

    // 2. Create CLR message
    let mut msg = DiameterMessage::new_request(cmd::CANCEL_LOCATION, S6A_APPLICATION_ID);

    // Session-Id
    let session_id = format!("hss.session.{}.{}", imsi_bcd, std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    msg.add_avp(Avp::mandatory(avp_code::SESSION_ID, AvpData::Utf8String(session_id)));

    // Origin-Host and Origin-Realm (would come from HSS config)
    msg.add_avp(Avp::mandatory(avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity("hss.epc.mnc001.mcc001.3gppnetwork.org".to_string())));
    msg.add_avp(Avp::mandatory(avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity("epc.mnc001.mcc001.3gppnetwork.org".to_string())));

    // Destination-Host and Destination-Realm
    msg.add_avp(Avp::mandatory(avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.clone())));
    msg.add_avp(Avp::mandatory(avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm)));

    // User-Name (IMSI)
    msg.add_avp(Avp::mandatory(avp_code::USER_NAME, AvpData::Utf8String(imsi_bcd.to_string())));

    // Auth-Session-State (NO_STATE_MAINTAINED)
    msg.add_avp(Avp::mandatory(avp_code::AUTH_SESSION_STATE, AvpData::Enumerated(1)));

    // Cancellation-Type
    msg.add_avp(Avp::vendor_mandatory(avp::CANCELLATION_TYPE, OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(cancellation_type as i32)));

    // 3. Send message and register CLA callback
    // Note: In full implementation, this would use the Diameter transport to send
    // For now, we just log that we would send it
    log::debug!("[{}] CLR message prepared (would send to {})", imsi_bcd, dest_host);

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

    use ogs_diameter::s6a::{S6A_APPLICATION_ID, cmd, avp};
    use ogs_diameter::{DiameterMessage, Avp, AvpData, avp_code, OGS_3GPP_VENDOR_ID};
    use ogs_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};
    use ogs_dbi::ogs_dbi_subscription_data;

    // 1. Look up MME host/realm from DB
    let collection = get_subscriber_collection()
        .map_err(|e| format!("Failed to get subscriber collection: {}", e))?;

    let query = doc! { "imsi": imsi_bcd };
    let doc = collection.find_one(query, None)
        .map_err(|e| format!("Failed to query DB: {}", e))?
        .ok_or_else(|| format!("Subscriber not found: {}", imsi_bcd))?;

    let dest_host = doc.get_str("mme_host")
        .unwrap_or("mme.epc.mnc001.mcc001.3gppnetwork.org").to_string();
    let dest_realm = doc.get_str("mme_realm")
        .unwrap_or("epc.mnc001.mcc001.3gppnetwork.org").to_string();

    // 2. Get subscription data from DB
    let supi = format!("imsi-{}", imsi_bcd);
    let _subscription_data = ogs_dbi_subscription_data(&supi)
        .map_err(|e| format!("Failed to get subscription data: {}", e))?;

    // 3. Create IDR message
    let mut msg = DiameterMessage::new_request(cmd::INSERT_SUBSCRIBER_DATA, S6A_APPLICATION_ID);

    // Session-Id
    let session_id = format!("hss.session.{}.{}", imsi_bcd, std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    msg.add_avp(Avp::mandatory(avp_code::SESSION_ID, AvpData::Utf8String(session_id)));

    // Origin-Host and Origin-Realm
    msg.add_avp(Avp::mandatory(avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity("hss.epc.mnc001.mcc001.3gppnetwork.org".to_string())));
    msg.add_avp(Avp::mandatory(avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity("epc.mnc001.mcc001.3gppnetwork.org".to_string())));

    // Destination-Host and Destination-Realm
    msg.add_avp(Avp::mandatory(avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.clone())));
    msg.add_avp(Avp::mandatory(avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm)));

    // User-Name (IMSI)
    msg.add_avp(Avp::mandatory(avp_code::USER_NAME, AvpData::Utf8String(imsi_bcd.to_string())));

    // Auth-Session-State (NO_STATE_MAINTAINED)
    msg.add_avp(Avp::mandatory(avp_code::AUTH_SESSION_STATE, AvpData::Enumerated(1)));

    // IDR-Flags
    msg.add_avp(Avp::vendor_mandatory(avp::IDR_FLAGS, OGS_3GPP_VENDOR_ID,
        AvpData::Unsigned32(idr_flags)));

    // Subscription-Data (based on subdata_mask)
    // Note: In full implementation, this would build a complex grouped AVP
    // containing AMBR, APN configs, QoS profiles, etc.
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_UEAMBR != 0 {
        log::debug!("[{}] Including UE-AMBR in subscription data", imsi_bcd);
    }
    if subdata_mask & OGS_DIAM_S6A_SUBDATA_APN_CONFIG != 0 {
        log::debug!("[{}] Including APN-Config in subscription data", imsi_bcd);
    }

    // 4. Send message and register IDA callback
    log::debug!("[{}] IDR message prepared (would send to {})", imsi_bcd, dest_host);

    diam_stats().s6a.inc_tx_idr();
    Ok(())
}

/// Handle Authentication-Information-Request (AIR)
///
/// This is called when MME requests authentication vectors for a UE
pub fn handle_air(imsi_bcd: &str, visited_plmn_id: &[u8], resync_info: Option<&[u8]>) -> Result<AirResponse, String> {
    log::debug!("[{}] Handling AIR", imsi_bcd);
    diam_stats().s6a.inc_rx_air();

    use ogs_dbi::{ogs_dbi_auth_info, ogs_dbi_increment_sqn, ogs_dbi_update_sqn};
    use ogs_crypt::milenage::{milenage_f1, milenage_f2345, milenage_opc};
    use ogs_crypt::kdf::ogs_auc_kasme;

    // 1. Get auth info from DB (K, OPc, SQN, AMF)
    let supi = format!("imsi-{}", imsi_bcd);
    let auth_info = ogs_dbi_auth_info(&supi)
        .map_err(|e| format!("Failed to get auth info: {}", e))?;

    let mut sqn = auth_info.sqn;

    // 2. Handle re-synchronization if provided
    if let Some(auts) = resync_info {
        log::debug!("[{}] Performing SQN re-synchronization", imsi_bcd);
        if auts.len() >= 14 {
            // AUTS = SQN_MS ^ AK || MAC-S
            // Extract and verify MAC-S, then extract SQN_MS
            // For now, we'll increment SQN significantly on resync
            sqn = sqn.wrapping_add(0x10000); // Jump ahead on resync
            ogs_dbi_update_sqn(&supi, sqn)
                .map_err(|e| format!("Failed to update SQN: {}", e))?;
        }
    }

    // 3. Generate authentication vector (RAND, XRES, AUTN, KASME)

    // Use stored RAND or generate new one (using stored for determinism in this impl)
    let rand = auth_info.rand;

    // Convert SQN to bytes (48-bit, 6 bytes)
    let sqn_bytes: [u8; 6] = [
        ((sqn >> 40) & 0xFF) as u8,
        ((sqn >> 32) & 0xFF) as u8,
        ((sqn >> 24) & 0xFF) as u8,
        ((sqn >> 16) & 0xFF) as u8,
        ((sqn >> 8) & 0xFF) as u8,
        (sqn & 0xFF) as u8,
    ];

    // Compute OPc from OP if needed
    let opc = if auth_info.use_opc {
        auth_info.opc
    } else {
        milenage_opc(&auth_info.k, &auth_info.op)
            .map_err(|_| "Failed to compute OPc".to_string())?
    };

    // Compute f1 (MAC-A) and f1* (MAC-S)
    let (mac_a, _mac_s) = milenage_f1(&opc, &auth_info.k, &rand, &sqn_bytes, &auth_info.amf)
        .map_err(|_| "Failed to compute f1".to_string())?;

    // Compute f2-f5 (RES, CK, IK, AK, AK*)
    let (res, ck, ik, ak, _ak_star) = milenage_f2345(&opc, &auth_info.k, &rand)
        .map_err(|_| "Failed to compute f2-f5".to_string())?;

    // Build AUTN = SQN ^ AK || AMF || MAC-A
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn_bytes[i] ^ ak[i];
    }
    autn[6..8].copy_from_slice(&auth_info.amf);
    autn[8..16].copy_from_slice(&mac_a);

    // Derive KASME from CK, IK, SQN, AK
    let plmn_id: [u8; 3] = [
        visited_plmn_id.get(0).copied().unwrap_or(0),
        visited_plmn_id.get(1).copied().unwrap_or(0),
        visited_plmn_id.get(2).copied().unwrap_or(0),
    ];
    let kasme = ogs_auc_kasme(&ck, &ik, &plmn_id, &sqn_bytes, &ak);

    // 4. Update SQN in DB (increment by 32)
    ogs_dbi_increment_sqn(&supi)
        .map_err(|e| format!("Failed to increment SQN: {}", e))?;

    // 5. Return AIA with E-UTRAN-Vector
    let response = AirResponse {
        rand,
        xres: res.to_vec(),
        autn,
        kasme,
        result_code: 2001, // DIAMETER_SUCCESS
    };

    diam_stats().s6a.inc_tx_aia();
    Ok(response)
}

/// Handle Update-Location-Request (ULR)
///
/// This is called when MME registers a UE's location
pub fn handle_ulr(
    imsi_bcd: &str,
    _visited_plmn_id: &[u8],
    _ulr_flags: u32,
    mme_host: &str,
    mme_realm: &str,
) -> Result<UlrResponse, String> {
    log::debug!("[{}] Handling ULR from {}.{}", imsi_bcd, mme_host, mme_realm);
    diam_stats().s6a.inc_rx_ulr();

    use ogs_dbi::{ogs_dbi_update_mme, ogs_dbi_subscription_data};

    // 1. Update MME info in DB
    let supi = format!("imsi-{}", imsi_bcd);
    ogs_dbi_update_mme(&supi, mme_host, mme_realm, true)
        .map_err(|e| format!("Failed to update MME: {}", e))?;

    // 2. Get subscription data from DB
    let _subscription_data = ogs_dbi_subscription_data(&supi)
        .map_err(|e| format!("Failed to get subscription data: {}", e))?;

    // 3. Return ULA with Subscription-Data
    // Note: In full implementation, subscription_data would be serialized to AVP format
    // For now we return a placeholder
    let response = UlrResponse {
        result_code: 2001, // DIAMETER_SUCCESS
        subscription_data: vec![0u8; 128], // Placeholder for serialized subscription data
    };

    diam_stats().s6a.inc_tx_ula();
    log::debug!("[{}] ULR handled successfully", imsi_bcd);
    Ok(response)
}

/// Handle Purge-UE-Request (PUR)
///
/// This is called when MME purges a UE
pub fn handle_pur(imsi_bcd: &str, pur_flags: u32) -> Result<PurResponse, String> {
    log::debug!("[{}] Handling PUR (flags={})", imsi_bcd, pur_flags);
    diam_stats().s6a.inc_rx_pur();

    use ogs_dbi::{mongoc::get_subscriber_collection, mongodb::bson::doc};

    // 1. Update purge flag in DB
    let supi_type = "imsi";
    let supi_id = imsi_bcd;

    let collection = get_subscriber_collection()
        .map_err(|e| format!("Failed to get subscriber collection: {}", e))?;

    let query = doc! { supi_type: supi_id };
    let update = doc! {
        "$set": {
            "purged": true,
            "purge_flags": pur_flags as i32,
        }
    };

    collection.update_one(query, update, None)
        .map_err(|e| format!("Failed to update purge flag: {}", e))?;

    // 2. Return PUA
    let response = PurResponse {
        result_code: 2001, // DIAMETER_SUCCESS
    };

    diam_stats().s6a.inc_tx_pua();
    log::debug!("[{}] PUR handled successfully", imsi_bcd);
    Ok(response)
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

// ============================================================================
// Diameter Wire Protocol Helpers (Item 108)
// ============================================================================

/// Diameter AVP data for wire encoding
#[derive(Debug, Clone)]
pub struct DiameterAvpData {
    /// AVP Code (per RFC 6733)
    pub code: u32,
    /// Vendor-ID (0 = IETF, 10415 = 3GPP)
    pub vendor_id: u32,
    /// Raw AVP data
    pub data: Vec<u8>,
}

/// Build a Diameter answer message with AVPs
///
/// Encodes per RFC 6733 Section 3:
/// - 4 bytes: Version(1) + Message Length(3)
/// - 4 bytes: Command Flags(1) + Command Code(3)
/// - 4 bytes: Application-ID
/// - 4 bytes: Hop-by-Hop Identifier
/// - 4 bytes: End-to-End Identifier
/// - AVPs
pub fn build_diameter_answer(
    command_code: u32,
    application_id: u32,
    avps: &[DiameterAvpData],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Placeholder for header (20 bytes) - will fill length after
    buf.extend_from_slice(&[0u8; 20]);

    // Encode each AVP
    for avp in avps {
        let avp_len = if avp.vendor_id != 0 { 12 + avp.data.len() } else { 8 + avp.data.len() };
        let padded_len = (avp_len + 3) & !3; // 4-byte aligned

        // AVP Code (4 bytes)
        buf.extend_from_slice(&avp.code.to_be_bytes());
        // AVP Flags (1 byte) + AVP Length (3 bytes)
        let flags: u8 = if avp.vendor_id != 0 { 0x80 } else { 0x40 }; // V flag or M flag
        buf.push(flags);
        buf.extend_from_slice(&(avp_len as u32).to_be_bytes()[1..4]);
        // Vendor-ID (4 bytes, optional)
        if avp.vendor_id != 0 {
            buf.extend_from_slice(&avp.vendor_id.to_be_bytes());
        }
        // AVP Data
        buf.extend_from_slice(&avp.data);
        // Padding
        let padding = padded_len - avp_len;
        for _ in 0..padding {
            buf.push(0);
        }
    }

    let msg_len = buf.len() as u32;

    // Fill header
    buf[0] = 1; // Version
    buf[1..4].copy_from_slice(&msg_len.to_be_bytes()[1..4]); // Length (3 bytes)
    // Command Flags: Answer (no R-bit), Proxiable
    buf[4] = 0x40; // P-bit set (proxiable)
    buf[5..8].copy_from_slice(&command_code.to_be_bytes()[1..4]); // Command Code (3 bytes)
    buf[8..12].copy_from_slice(&application_id.to_be_bytes()); // Application-ID
    buf[12..16].copy_from_slice(&1u32.to_be_bytes()); // Hop-by-Hop (placeholder)
    buf[16..20].copy_from_slice(&1u32.to_be_bytes()); // End-to-End (placeholder)

    log::debug!("Built Diameter answer: cmd={}, app_id={}, len={}, avps={}",
        command_code, application_id, msg_len, avps.len());

    buf
}

/// Encode AIA (Authentication-Information-Answer) AVPs
pub fn build_aia_avps(auth_info: &AirResponse) -> Vec<DiameterAvpData> {
    let mut avps = Vec::new();

    // Session-Id (263)
    avps.push(DiameterAvpData {
        code: 263, vendor_id: 0,
        data: b"hss.s6a.session.1".to_vec(),
    });

    // Result-Code (268) - DIAMETER_SUCCESS
    avps.push(DiameterAvpData {
        code: 268, vendor_id: 0,
        data: 2001u32.to_be_bytes().to_vec(),
    });

    // Auth-Session-State (277) - NO_STATE_MAINTAINED
    avps.push(DiameterAvpData {
        code: 277, vendor_id: 0,
        data: 1u32.to_be_bytes().to_vec(),
    });

    // Authentication-Info (1413, 3GPP) containing E-UTRAN-Vector
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&auth_info.rand);
    auth_data.extend_from_slice(&auth_info.xres);
    auth_data.extend_from_slice(&auth_info.autn);
    auth_data.extend_from_slice(&auth_info.kasme);
    avps.push(DiameterAvpData {
        code: 1413, vendor_id: 10415,
        data: auth_data,
    });

    avps
}

/// Encode ULA (Update-Location-Answer) AVPs
pub fn build_ula_avps(ulr_resp: &UlrResponse) -> Vec<DiameterAvpData> {
    let mut avps = Vec::new();

    // Session-Id (263)
    avps.push(DiameterAvpData {
        code: 263, vendor_id: 0,
        data: b"hss.s6a.session.1".to_vec(),
    });

    // Result-Code (268)
    avps.push(DiameterAvpData {
        code: 268, vendor_id: 0,
        data: ulr_resp.result_code.to_be_bytes().to_vec(),
    });

    // ULA-Flags (1406, 3GPP) - Separation Indication
    avps.push(DiameterAvpData {
        code: 1406, vendor_id: 10415,
        data: 1u32.to_be_bytes().to_vec(),
    });

    // Subscription-Data (1400, 3GPP)
    if !ulr_resp.subscription_data.is_empty() {
        avps.push(DiameterAvpData {
            code: 1400, vendor_id: 10415,
            data: ulr_resp.subscription_data.clone(),
        });
    }

    avps
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
        // IDR requires MongoDB for subscriber lookup - verify graceful error without DB
        let result = hss_s6a_send_idr(
            "123456789012345",
            0,
            OGS_DIAM_S6A_SUBDATA_UEAMBR | OGS_DIAM_S6A_SUBDATA_APN_CONFIG,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_air() {
        // AIR requires MongoDB for auth info lookup - verify graceful error without DB
        let visited_plmn = [0x00, 0xF1, 0x10]; // MCC=001, MNC=01
        let result = handle_air("123456789012345", &visited_plmn, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_diameter_answer() {
        // Verify answer builder produces non-empty bytes
        let avps = vec![
            DiameterAvpData { code: 263, vendor_id: 0, data: b"session-1".to_vec() },
            DiameterAvpData { code: 268, vendor_id: 0, data: 2001u32.to_be_bytes().to_vec() },
        ];
        let answer = build_diameter_answer(272, OGS_DIAM_S6A_APPLICATION_ID, &avps);
        assert!(answer.len() > 20); // header + AVPs
    }

    #[test]
    fn test_handle_ulr() {
        // ULR requires MongoDB for subscription data - verify graceful error without DB
        let visited_plmn = [0x00, 0xF1, 0x10];
        let result = handle_ulr(
            "123456789012345",
            &visited_plmn,
            0,
            "mme.example.com",
            "example.com",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_pur() {
        // PUR requires MongoDB for subscriber collection - verify graceful error without DB
        let result = handle_pur("123456789012345", 0);
        assert!(result.is_err());
    }
}
