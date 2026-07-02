//! NAUSF Authentication Handlers
//!
//! Port of src/ausf/nausf-handler.c - NAUSF authentication request handlers.
//!
//! NOTE (ausfd-10): the live `nausf-auth` HTTP path is served directly by
//! `ausf_sbi_request_handler` in `main.rs`, which is the single source of truth
//! for the wire behaviour (response shaping, RES*-vs-XRES* decision, key
//! disclosure). The `ausf_nausf_auth_handle_*` functions below are the
//! state-machine-routed legacy path retained for the FSM unit tests; they share
//! the same pure helpers (`validate_*`, `compare_res_star`) as the live path so
//! the authentication decision can never diverge between the two.

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
    // In C: ausf_sbi_discover_and_send(NEXTGCORE_SBI_SERVICE_TYPE_NUDM_UEAU, ...)
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
pub fn ausf_nausf_auth_handle_authenticate_confirmation(ausf_ue_id: u64, stream_id: u64) -> bool {
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

    // ausfd-02 / ausfd-10: the AUSF compares the received RES* directly against
    // the stored XRES* (TS 33.501 §6.1.3.2 step 11) using a constant-time
    // compare. This is identical to the live path in main.rs; HRES*/HXRES* is
    // reserved for the SEAF only and is not recomputed here.
    if let Some(ref res_star_hex) = ausf_ue.res_star_hex.clone() {
        let res_star_bytes = crate::nudm_handler::hex_to_bytes(res_star_hex);
        if res_star_bytes.len() == 16 {
            let mut res_star = [0u8; 16];
            res_star.copy_from_slice(&res_star_bytes);

            // Compare RES* with stored XRES* (constant-time)
            if compare_res_star(&res_star, &ausf_ue.xres_star) {
                ausf_ue.auth_result = crate::context::AuthResult::AuthenticationSuccess;
                log::info!(
                    "[{}] 5G-AKA authentication succeeded (RES* matches XRES*)",
                    ausf_ue.suci
                );
            } else {
                ausf_ue.auth_result = crate::context::AuthResult::AuthenticationFailure;
                log::warn!(
                    "[{}] 5G-AKA authentication failed (RES* mismatch)",
                    ausf_ue.suci
                );
            }
        } else {
            log::error!(
                "[{}] Invalid RES* length: {}",
                ausf_ue.suci,
                res_star_bytes.len()
            );
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
    if supi_or_suci.is_none() || supi_or_suci.expect("value expected").is_empty() {
        return Err("No supiOrSuci");
    }

    if serving_network_name.is_none() || serving_network_name.expect("value expected").is_empty() {
        return Err("No servingNetworkName");
    }

    Ok(())
}

/// Validate the serving network name format (TS 24.501 §9.12.1 / TS 33.501
/// §6.1.1.4): `5G:mnc<3-digit MNC>.mcc<3-digit MCC>.3gppnetwork.org`, with an
/// optional `:NID` suffix for SNPN.
///
/// TS 33.501 §6.1.2: the AUSF shall check that the requesting AMF is entitled
/// to use the serving network name. The "5G:" prefix is the authentication
/// separation prefix that binds the AV to 5G (anti-bidding-down between
/// EPS and 5GS at AV level).
pub fn validate_serving_network_name(snn: &str) -> bool {
    let rest = match snn.strip_prefix("5G:mnc") {
        Some(r) => r,
        None => return false,
    };
    let (mnc, rest) = match rest.split_once(".mcc") {
        Some(p) => p,
        None => return false,
    };
    let (mcc, tail) = match rest.split_once('.') {
        Some(p) => p,
        None => return false,
    };
    let tail_ok = tail == "3gppnetwork.org" || tail.starts_with("3gppnetwork.org:");
    mnc.len() == 3
        && mcc.len() == 3
        && mnc.bytes().all(|b| b.is_ascii_digit())
        && mcc.bytes().all(|b| b.is_ascii_digit())
        && tail_ok
}

/// Validate confirmation data from request
pub fn validate_confirmation_data(res_star: Option<&str>) -> Result<(), &'static str> {
    if res_star.is_none() || res_star.expect("value expected").is_empty() {
        return Err("No ConfirmationData.resStar");
    }

    Ok(())
}

/// Compare the received RES* against the stored XRES* (ausfd-02).
///
/// TS 33.501 §6.1.3.2 step 11: "the AUSF shall compare the received RES* with
/// the stored XRES*. If the RES* and XRES* are equal, the AUSF shall consider
/// the authentication successful." (The HRES*/HXRES* comparison of step 9 is
/// the SEAF's job, not the AUSF's.)
///
/// The byte comparison is constant-time (fold-XOR over all bytes) so that a
/// mismatching RES* cannot be distinguished from a matching one by timing.
/// A length mismatch (public information) short-circuits to `false`.
pub fn compare_res_star(res_star: &[u8], xres_star: &[u8]) -> bool {
    if res_star.len() != xres_star.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in res_star.iter().zip(xres_star.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Parse the MCC/MNC out of a serving network name (ausfd-05).
///
/// SNN format (TS 24.501 §9.12.1): `5G:mnc<MNC>.mcc<MCC>.3gppnetwork.org[...]`.
/// Returns `(mcc, mnc)` as 3-character digit strings, or `None` if the SNN is
/// not a syntactically valid 5G SNN.
pub fn parse_snn_plmn(snn: &str) -> Option<(String, String)> {
    let rest = snn.strip_prefix("5G:mnc")?;
    let (mnc, rest) = rest.split_once(".mcc")?;
    let (mcc, tail) = rest.split_once('.')?;
    let tail_ok = tail == "3gppnetwork.org" || tail.starts_with("3gppnetwork.org:");
    if mnc.len() == 3
        && mcc.len() == 3
        && mnc.bytes().all(|b| b.is_ascii_digit())
        && mcc.bytes().all(|b| b.is_ascii_digit())
        && tail_ok
    {
        Some((mcc.to_string(), mnc.to_string()))
    } else {
        None
    }
}

/// Left-pad a 2-digit MNC to the 3-digit form used inside an SNN.
fn normalize_mnc3(mnc: &str) -> String {
    if mnc.len() == 2 {
        format!("0{mnc}")
    } else {
        mnc.to_string()
    }
}

/// Check that the serving network name is entitled to the requesting consumer
/// (AMF/SEAF) identity (ausfd-05).
///
/// TS 33.501 §6.1.2: "the AUSF shall check that the serving network name … is
/// allowed for the requesting [AMF/SEAF]." TS 29.509 §6.1.7.3 maps a failure to
/// 403 `SERVING_NETWORK_NOT_AUTHORIZED`.
///
/// DEFAULT-PERMISSIVE: when the consumer's PLMN set cannot be resolved (no
/// OAuth2 access token / no NF profile) `consumer_plmns` is empty and the SNN
/// is allowed. This preserves interop with peers that do not (yet) carry a
/// token. Once the consumer PLMN set is known, the SNN's PLMN must be a member.
pub fn snn_authorized_for_consumer(snn: &str, consumer_plmns: &[(String, String)]) -> bool {
    if consumer_plmns.is_empty() {
        // Consumer PLMN unknown -> permissive (do not break token-less peers).
        return true;
    }
    let (snn_mcc, snn_mnc) = match parse_snn_plmn(snn) {
        Some(p) => p,
        // Format already validated upstream; if it does not parse, stay permissive.
        None => return true,
    };
    consumer_plmns
        .iter()
        .any(|(mcc, mnc)| *mcc == snn_mcc && normalize_mnc3(mnc) == snn_mnc)
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
        assert!(
            validate_authentication_info(None, Some("5G:mnc001.mcc001.3gppnetwork.org")).is_err()
        );

        // Empty supi_or_suci
        assert!(
            validate_authentication_info(Some(""), Some("5G:mnc001.mcc001.3gppnetwork.org"))
                .is_err()
        );

        // Missing serving_network_name
        assert!(
            validate_authentication_info(Some("suci-0-001-01-0000-0-0-0000000001"), None).is_err()
        );

        // Empty serving_network_name
        assert!(
            validate_authentication_info(Some("suci-0-001-01-0000-0-0-0000000001"), Some(""))
                .is_err()
        );
    }

    #[test]
    fn test_validate_serving_network_name() {
        assert!(validate_serving_network_name(
            "5G:mnc001.mcc001.3gppnetwork.org"
        ));
        assert!(validate_serving_network_name(
            "5G:mnc093.mcc208.3gppnetwork.org"
        ));
        // SNPN NID suffix
        assert!(validate_serving_network_name(
            "5G:mnc001.mcc001.3gppnetwork.org:000000125"
        ));

        // Missing 5G: separation prefix (anti-bidding-down)
        assert!(!validate_serving_network_name(
            "mnc001.mcc001.3gppnetwork.org"
        ));
        // EPS-style SNN must be rejected
        assert!(!validate_serving_network_name(
            "EPS:mnc001.mcc001.3gppnetwork.org"
        ));
        // 2-digit MNC (must be 0-padded to 3)
        assert!(!validate_serving_network_name(
            "5G:mnc01.mcc001.3gppnetwork.org"
        ));
        // Non-digit MCC
        assert!(!validate_serving_network_name(
            "5G:mnc001.mccABC.3gppnetwork.org"
        ));
        // Wrong domain
        assert!(!validate_serving_network_name("5G:mnc001.mcc001.evil.org"));
        assert!(!validate_serving_network_name(""));
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

    #[test]
    fn test_compare_res_star_constant_time_xres() {
        // ausfd-02: seed a 16-byte XRES*, an exactly-matching RES* succeeds.
        let xres_star: [u8; 16] = [
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
            0xe1, 0xf0,
        ];
        let res_star = xres_star;
        assert!(
            compare_res_star(&res_star, &xres_star),
            "exact match -> true"
        );

        // Flip a single byte -> failure.
        let mut wrong = xres_star;
        wrong[7] ^= 0x01;
        assert!(
            !compare_res_star(&wrong, &xres_star),
            "one-byte flip -> false"
        );

        // Length mismatch -> false (no panic).
        assert!(!compare_res_star(&xres_star[..8], &xres_star));
        // Empty vs non-empty -> false.
        assert!(!compare_res_star(&[], &xres_star));
    }

    #[test]
    fn test_parse_snn_plmn() {
        // ausfd-05: extract (mcc, mnc) from a valid SNN.
        assert_eq!(
            parse_snn_plmn("5G:mnc093.mcc208.3gppnetwork.org"),
            Some(("208".to_string(), "093".to_string()))
        );
        // SNPN NID suffix still parses.
        assert_eq!(
            parse_snn_plmn("5G:mnc001.mcc001.3gppnetwork.org:000000125"),
            Some(("001".to_string(), "001".to_string()))
        );
        // Malformed / non-5G SNNs do not parse.
        assert_eq!(parse_snn_plmn("EPS:mnc001.mcc001.3gppnetwork.org"), None);
        assert_eq!(parse_snn_plmn("5G:mnc01.mcc001.3gppnetwork.org"), None);
        assert_eq!(parse_snn_plmn(""), None);
    }

    #[test]
    fn test_snn_authorized_for_consumer() {
        // ausfd-05: matching PLMN is authorized.
        let snn = "5G:mnc093.mcc208.3gppnetwork.org";
        let allowed = vec![("208".to_string(), "093".to_string())];
        assert!(snn_authorized_for_consumer(snn, &allowed));

        // 2-digit MNC in the consumer profile is normalized to the SNN's 3-digit form.
        let snn2 = "5G:mnc093.mcc208.3gppnetwork.org";
        let allowed2 = vec![("208".to_string(), "93".to_string())];
        assert!(snn_authorized_for_consumer(snn2, &allowed2));

        // Foreign PLMN is rejected.
        let foreign = vec![("001".to_string(), "001".to_string())];
        assert!(!snn_authorized_for_consumer(snn, &foreign));

        // Empty consumer set -> default-permissive (token-less peers not broken).
        assert!(snn_authorized_for_consumer(snn, &[]));
    }
}
