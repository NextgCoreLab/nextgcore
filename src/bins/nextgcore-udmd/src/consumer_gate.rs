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
//! 2. **The producer's gate**, before the handler: #2082 moved it onto the
//!    shared `nextgcore_sbi::owner_binding::nf_type_refusal` (CONVENTIONS: the
//!    caller's identity and NF type come from the verified-identity helpers). A
//!    typed certificate must name AUSF (RFC 9310 NFTypes, TS 33.310 §6.1.3c.3);
//!    a token, alone or through an SCP (TS 33.501 §13.3), must belong to an
//!    instance the NRF lists as an AUSF; under production a certificate without
//!    NF types, or a relay's, alone is refused. Anything else is refused `403`
//!    before any data is read.

/// TS 29.503 §5.4.2.2.2, §5.4.2.3.2, §5.4.2.3.3: every Nudm_UEAU operation this
/// UDM serves (GenerateAuthData, ConfirmAuth, DeleteAuth) is consumed by the
/// AUSF. GetHssAv (HSS) and GetProseAv / GetGbaAv are not routed here.
pub const UEAU_CONSUMER_NF_TYPES: &[&str] = &["AUSF"];

/// The per-NFService `allowedNfTypes` this UDM registers (TS 29.510 Table
/// 6.1.6.2.3-1). A service absent from the table has no per-service restriction
/// beyond the profile-level list.
pub fn service_allowed_nf_types(service_name: &str) -> Option<&'static [&'static str]> {
    match service_name {
        "nudm-ueau" => Some(UEAU_CONSUMER_NF_TYPES),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ueau_carries_a_per_service_list_1866() {
        assert_eq!(service_allowed_nf_types("nudm-ueau"), Some(&["AUSF"][..]));
        for s in ["nudm-sdm", "nudm-uecm", "nudm-ee", "nudm-pp", "nudm-mt"] {
            assert_eq!(service_allowed_nf_types(s), None, "{s}");
        }
    }
}
