//! NAUSF Authentication Handlers
//!
//! Port of src/ausf/nausf-handler.c - NAUSF authentication request handlers

use crate::context::ausf_self;
use crate::sbi_path;
use crate::sbi_response::send_error_response;

/// Handle NAUSF authentication request (POST /ue-authentications)
///
/// Port of ausf_nausf_auth_handle_authenticate()
pub fn ausf_nausf_auth_handle_authenticate(ausf_ue_id: u64, stream_id: u64) -> bool {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("AUSF UE not found [{ausf_ue_id}]");
            return false;
        }
    };

    log::debug!("[{}] Handle authenticate request", ausf_ue.suci);

    // In the C code, this extracts AuthenticationInfo from the request
    // and validates serving_network_name
    // For now, we'll assume the serving_network_name is already set

    if ausf_ue.serving_network_name.is_none() {
        log::error!("[{}] No servingNetworkName", ausf_ue.suci);
        send_error_response(stream_id, 400, "No servingNetworkName");
        return false;
    }

    // Discover UDM and send request
    // In C: ausf_sbi_discover_and_send(OGS_SBI_SERVICE_TYPE_NUDM_UEAU, ...)
    let result = sbi_path::ausf_sbi_discover_and_send_nudm_ueau_get(ausf_ue_id, stream_id, None);

    if result.is_err() {
        log::error!("[{}] Failed to discover and send to UDM", ausf_ue.suci);
        return false;
    }

    true
}

/// Handle NAUSF authentication confirmation (PUT /ue-authentications/{authCtxId}/5g-aka-confirmation)
///
/// Port of ausf_nausf_auth_handle_authenticate_confirmation()
pub fn ausf_nausf_auth_handle_authenticate_confirmation(
    ausf_ue_id: u64,
    stream_id: u64,
) -> bool {
    let ctx = ausf_self();
    let context = ctx.write().unwrap();

    let mut ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("AUSF UE not found [{ausf_ue_id}]");
            return false;
        }
    };

    log::debug!("[{}] Handle authenticate confirmation", ausf_ue.suci);

    // Extract RES* from confirmation data and compare with HXRES*
    // In 5G-AKA, the AUSF receives RES* and computes HRES* from it,
    // then compares HRES* with the stored HXRES*.
    // The actual RES* vs XRES* comparison happens at AUSF after UDM confirmation.
    if let Some(ref res_star_hex) = ausf_ue.res_star_hex.clone() {
        let res_star_bytes = crate::nudm_handler::hex_to_bytes(res_star_hex);
        if res_star_bytes.len() == 16 {
            let mut res_star = [0u8; 16];
            res_star.copy_from_slice(&res_star_bytes);

            // Compute HRES* from RAND and RES* using the same derivation as HXRES*
            let hres_star = ogs_crypt::kdf::ogs_kdf_hxres_star(&ausf_ue.rand, &res_star);

            // Compare HRES* with stored HXRES*
            if compare_res_star(&hres_star, &ausf_ue.hxres_star) {
                ausf_ue.auth_result = crate::context::AuthResult::AuthenticationSuccess;
                log::info!("[{}] 5G-AKA authentication succeeded (HRES* matches HXRES*)", ausf_ue.suci);
            } else {
                ausf_ue.auth_result = crate::context::AuthResult::AuthenticationFailure;
                log::warn!("[{}] 5G-AKA authentication failed (HRES* mismatch)", ausf_ue.suci);
            }
        } else {
            log::error!("[{}] Invalid RES* length: {}", ausf_ue.suci, res_star_bytes.len());
            ausf_ue.auth_result = crate::context::AuthResult::AuthenticationFailure;
        }
    } else {
        log::error!("[{}] No RES* in confirmation data", ausf_ue.suci);
        send_error_response(stream_id, 400, "No ConfirmationData.resStar");
        return false;
    }
    context.ue_update(&ausf_ue);
    drop(context);

    // Discover UDM and send result confirmation
    let result =
        sbi_path::ausf_sbi_discover_and_send_nudm_ueau_result_confirmation(ausf_ue_id, stream_id);

    if result.is_err() {
        log::error!("[{}] Failed to discover and send to UDM", ausf_ue.suci);
        return false;
    }

    true
}

/// Handle NAUSF authentication delete (DELETE /ue-authentications/{authCtxId})
///
/// Port of ausf_nausf_auth_handle_authenticate_delete()
pub fn ausf_nausf_auth_handle_authenticate_delete(ausf_ue_id: u64, stream_id: u64) -> bool {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = match context.ue_find_by_id(ausf_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("AUSF UE not found [{ausf_ue_id}]");
            return false;
        }
    };

    log::debug!("[{}] Handle authenticate delete", ausf_ue.suci);

    // Discover UDM and send auth removal indication
    let result = sbi_path::ausf_sbi_discover_and_send_nudm_ueau_auth_removal(ausf_ue_id, stream_id);

    if result.is_err() {
        log::error!("[{}] Failed to discover and send to UDM", ausf_ue.suci);
        return false;
    }

    true
}

/// Validate authentication info from request
pub fn validate_authentication_info(
    supi_or_suci: Option<&str>,
    serving_network_name: Option<&str>,
) -> Result<(), &'static str> {
    if supi_or_suci.is_none() || supi_or_suci.unwrap().is_empty() {
        return Err("No supiOrSuci");
    }

    if serving_network_name.is_none() || serving_network_name.unwrap().is_empty() {
        return Err("No servingNetworkName");
    }

    Ok(())
}

/// Validate confirmation data from request
pub fn validate_confirmation_data(res_star: Option<&str>) -> Result<(), &'static str> {
    if res_star.is_none() || res_star.unwrap().is_empty() {
        return Err("No ConfirmationData.resStar");
    }

    Ok(())
}

/// Compare RES* with XRES*
pub fn compare_res_star(res_star: &[u8], xres_star: &[u8]) -> bool {
    if res_star.len() != xres_star.len() {
        return false;
    }
    res_star == xres_star
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_authentication_info() {
        // Valid case
        assert!(validate_authentication_info(
            Some("suci-0-001-01-0000-0-0-0000000001"),
            Some("5G:mnc001.mcc001.3gppnetwork.org")
        )
        .is_ok());

        // Missing supi_or_suci
        assert!(validate_authentication_info(None, Some("5G:mnc001.mcc001.3gppnetwork.org")).is_err());

        // Empty supi_or_suci
        assert!(validate_authentication_info(Some(""), Some("5G:mnc001.mcc001.3gppnetwork.org")).is_err());

        // Missing serving_network_name
        assert!(validate_authentication_info(Some("suci-0-001-01-0000-0-0-0000000001"), None).is_err());

        // Empty serving_network_name
        assert!(validate_authentication_info(Some("suci-0-001-01-0000-0-0-0000000001"), Some("")).is_err());
    }

    #[test]
    fn test_validate_confirmation_data() {
        // Valid case
        assert!(validate_confirmation_data(Some("0123456789abcdef0123456789abcdef")).is_ok());

        // Missing res_star
        assert!(validate_confirmation_data(None).is_err());

        // Empty res_star
        assert!(validate_confirmation_data(Some("")).is_err());
    }

    #[test]
    fn test_compare_res_star() {
        let res_star = [0x01, 0x02, 0x03, 0x04];
        let xres_star_match = [0x01, 0x02, 0x03, 0x04];
        let xres_star_no_match = [0x01, 0x02, 0x03, 0x05];

        assert!(compare_res_star(&res_star, &xres_star_match));
        assert!(!compare_res_star(&res_star, &xres_star_no_match));
    }
}
