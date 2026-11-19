//! #1866: which NF types may consume a Nudm service, enforced at the producer.
//!
//! Nudm_UEAU hands out the AKA material (`xresStar`, `kausf`): whoever holds
//! KAUSF derives KSEAF and KAMF. TS 29.503 §5.4.2.2.2 names the AUSF as the one
//! consumer of the service, and TS 33.501 §13.4.1.1 has the producer authorize the
//! consumer. Two layers do that here:
//!
//! 1. **The NRF's grant.** The NFProfile lists `allowedNfTypes: ["AUSF"]` on the
//!    `nudm-ueau` NFService (TS 29.510 Table 6.1.6.2.3-1), so the NRF refuses an
//!    `nudm-ueau` access token to any other NF type (`unauthorized_client`). An
//!    access token has no consumer-type claim (TS 29.510 `AccessTokenClaims`), so
//!    its verified `nudm-ueau` scope is the type proof whenever the direct peer is
//!    not the consumer itself.
//! 2. **This gate**, before the handler: when the direct peer's verified client
//!    certificate names NF types (RFC 9310 NFTypes, TS 33.310 §6.1.3c.3) it must
//!    name an allowed type, or the SCP relaying for the consumer (TS 33.501
//!    §13.3, indirect communication, where the token carries the authorization).
//!    Anything else is refused `403` before any data is read.
//!
//! Written over [`SbiRequest`] alone, with no udmd state, so it can move into
//! nextgcore-sbi unchanged (#1865).

use nextgcore_sbi::message::{SbiRequest, SbiResponse};

/// TS 29.503 §5.4.2.2.2, §5.4.2.3.2, §5.4.2.3.3: every Nudm_UEAU operation this
/// UDM serves (GenerateAuthData, ConfirmAuth, DeleteAuth) is consumed by the
/// AUSF. GetHssAv (HSS) and GetProseAv / GetGbaAv are not routed here.
pub const UEAU_CONSUMER_NF_TYPES: &[&str] = &["AUSF"];

/// NF types whose certificate identifies a relay, not the consumer: for these
/// the verified access token is the authorization (TS 33.501 §13.3.2).
pub const RELAY_NF_TYPES: &[&str] = &["SCP"];

/// The per-NFService `allowedNfTypes` this UDM registers (TS 29.510 Table
/// 6.1.6.2.3-1). A service absent from the table has no per-service restriction
/// beyond the profile-level list.
pub fn service_allowed_nf_types(service_name: &str) -> Option<&'static [&'static str]> {
    match service_name {
        "nudm-ueau" => Some(UEAU_CONSUMER_NF_TYPES),
        _ => None,
    }
}

/// Why `request` may not consume `service`, or `None` if it may.
///
/// `allowed` is the service's consumer NF types. Only an identity this process
/// verified is read (`peer_cert_nf_types`); nothing in the body or the headers.
pub fn consumer_type_refusal(
    request: &SbiRequest,
    service: &str,
    allowed: &[&str],
) -> Option<String> {
    let types = &request.peer_cert_nf_types;
    if types.is_empty() {
        // No type asserted: under OAuth2 the server has already verified a token
        // the NRF granted only to an allowed type (layer 1).
        return None;
    }
    let names = |set: &[&str]| {
        types
            .iter()
            .any(|t| set.iter().any(|a| a.eq_ignore_ascii_case(t)))
    };
    if names(allowed) || names(RELAY_NF_TYPES) {
        return None;
    }
    Some(format!(
        "{service} is served to NF type(s) {allowed:?} only; the requester's certificate \
         names {types:?}"
    ))
}

/// [`consumer_type_refusal`] as the `403` to send. `Some` means refuse and do
/// nothing else.
pub fn refuse_consumer_type(
    request: &SbiRequest,
    service: &str,
    allowed: &[&str],
) -> Option<SbiResponse> {
    let detail = consumer_type_refusal(request, service, allowed)?;
    // debug, not warn: a peer can send these at will (#1620 review m7).
    log::debug!("{service} request refused: {detail}");
    Some(nextgcore_sbi::server::send_forbidden(&detail, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_types(types: &[&str]) -> SbiRequest {
        let mut r = SbiRequest::post("/nudm-ueau/v1/imsi-001010000000001/auth-events");
        r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
        r
    }

    #[test]
    fn a_certificate_naming_another_type_is_refused_1866() {
        for t in ["SMF", "PCF", "AMF", "NEF"] {
            let why = consumer_type_refusal(&with_types(&[t]), "nudm-ueau", UEAU_CONSUMER_NF_TYPES)
                .unwrap_or_else(|| panic!("{t} must be refused"));
            assert!(why.contains(t) && why.contains("AUSF"), "{why}");
        }
    }

    #[test]
    fn the_ausf_and_a_relaying_scp_are_admitted_1866() {
        for types in [&["AUSF"][..], &["ausf"], &["SMF", "AUSF"], &["SCP"]] {
            assert_eq!(
                consumer_type_refusal(&with_types(types), "nudm-ueau", UEAU_CONSUMER_NF_TYPES),
                None,
                "{types:?}"
            );
        }
    }

    #[test]
    fn only_ueau_carries_a_per_service_list_1866() {
        assert_eq!(service_allowed_nf_types("nudm-ueau"), Some(&["AUSF"][..]));
        for s in ["nudm-sdm", "nudm-uecm", "nudm-ee", "nudm-pp", "nudm-mt"] {
            assert_eq!(service_allowed_nf_types(s), None, "{s}");
        }
    }
}
