//! Resource/operation-level OAuth2 scopes (#1811).
//!
//! TS 33.501 §13.4.1.1: the basic extent of an access token is the service
//! (the `scope` claim lists service names), and "depending on the NF Service
//! Producer configuration" a token may carry "additional scope" information
//! that authorizes specific resources and operations. TS 29.500 §6.7.3: an
//! operation that needs a resource-level scope is invoked with BOTH the
//! service-level scope and that scope -- "those two scopes, together, grant
//! access to those operations on resources that require a specific
//! authorization". The producer checks the additional scope (TS 33.501
//! §13.4.1.2), and the NRF grants it only to the consumers the producer's
//! `allowedOperationsPerNfType` / `allowedOperationsPerNfInstance` name
//! (TS 29.510 Table 6.1.6.2.3-1 NOTE 11).
//!
//! This module is the ONE table of the resource-level scopes nextgcore
//! enforces, read by both ends so they cannot drift apart:
//! - a producer passes [`required_resource_scope`] to
//!   [`crate::server::SbiServerConfig::with_oauth2_resource_scopes`], and its
//!   server refuses, before the handler runs, a token without that scope;
//! - the client asks the NRF for [`access_token_scope`], the service-level
//!   scope plus the resource-level one the request needs.
//!
//! Spellings are those of the vendored OpenAPI, not of any issue text:
//! `TS29505_Subscription_Data.yaml` `components.securitySchemes` and the
//! `security` of `QueryAuthSubsData` (GET) and
//! `ModifyAuthenticationSubscription` (PATCH) on
//! `/subscription-data/{ueId}/authentication-data/authentication-subscription`
//! (also TS 29.504 Table 6.1.7-1), the same yaml's `subscription-data` and
//! `registrations:write` scopes on the UDM's context-data and
//! authentication-status writes (#2079), and `TS29536_Nnsacf_NSAC.yaml`
//! `LocalNumberUpdate` on `/slices/local-configs/update` (TS 29.536 Table
//! 6.1.9-1, #1892).

/// TS 29.505 / TS 29.504 Table 6.1.7-1: read the AuthenticationSubscription
/// resource (K, OPc/TOPc, SQN).
pub const NUDR_DR_AUTH_SUBSCRIPTION_READ: &str =
    "nudr-dr:subscription-data:authentication-subscription:read";

/// TS 29.505 / TS 29.504 Table 6.1.7-1: update the AuthenticationSubscription
/// resource.
pub const NUDR_DR_AUTH_SUBSCRIPTION_MODIFY: &str =
    "nudr-dr:subscription-data:authentication-subscription:modify";

/// TS 29.504 Table 6.1.7-1: "Access to the SubscriptionData data set" (#2079).
/// `TS29505_Subscription_Data.yaml` lists it, beside `nudr-dr`, in the
/// `security` of every subscription-data operation. nextgcore requires it on
/// the writes of the UDM's own context documents: authentication-status (TS
/// 29.505 §5.2.24, §5.2.24A) and the sdm-subscriptions / ee-subscriptions
/// collections (§5.2.16-5.2.19). It also satisfies
/// [`NUDR_DR_REGISTRATIONS_WRITE`], which the yaml offers as its alternative
/// ([`token_grants`]).
pub const NUDR_DR_SUBSCRIPTION_DATA: &str = "nudr-dr:subscription-data";

/// TS 29.504 Table 6.1.7-1: "Write access to NF registration resources of the
/// SubscriptionData data set" (#2079). `TS29505_Subscription_Data.yaml` lists
/// it on PUT / PATCH / DELETE of amf-3gpp-access, amf-non-3gpp-access,
/// smf-registrations/{pduSessionId}, smsf-3gpp-access, smsf-non-3gpp-access and
/// ip-sm-gw, as an alternative to [`NUDR_DR_SUBSCRIPTION_DATA`].
pub const NUDR_DR_REGISTRATIONS_WRITE: &str = "nudr-dr:subscription-data:registrations:write";

/// The context-data resources whose writes need [`NUDR_DR_REGISTRATIONS_WRITE`]
/// (#2079): the NF registrations the UDM stores in the UDR (TS 29.505 §5.2.6
/// "AMF registrations to be stored in the UDR by the UDM", §5.2.7, §5.2.8,
/// §5.2.9, §5.2.11, §5.2.12, and the IP-SM-GW registration).
const NF_REGISTRATION_RESOURCES: &[&str] = &[
    "amf-3gpp-access",
    "amf-non-3gpp-access",
    "smf-registrations",
    "smsf-3gpp-access",
    "smsf-non-3gpp-access",
    "ip-sm-gw",
];

/// The context-data collections whose writes need [`NUDR_DR_SUBSCRIPTION_DATA`]
/// (#2079): the UDM's own SDM and EE subscriptions, which the yaml scopes with
/// `nudr-dr:subscription-data` alone.
const UDM_SUBSCRIPTION_COLLECTIONS: &[&str] = &["sdm-subscriptions", "ee-subscriptions"];

/// TS 29.509 (`TS29509_Nausf_UEAuthentication.yaml`, the `security` of
/// `/ue-authentications/deregister`): the resource-level scope of the
/// Deregister service operation (§5.2.2.3), which "the NF Service Consumer (e.g.
/// UDM)" invokes (#1918). The AUSF ADMITS it rather than requiring it, so it is
/// not in [`required_resource_scope`]: the OpenAPI lists `nausf-auth` alone as
/// well.
pub const NAUSF_AUTH_UE_AUTHENTICATIONS: &str = "nausf-auth:ue-authentications";

/// TS 29.536 Table 6.1.9-1: "Access (from a primary NSACF) to update the
/// network slice local configuration" of a distributed NSACF (#1892).
pub const NNSACF_NSAC_LOCAL_CONFIGS_UPDATE: &str = "nnsacf-nsac:local-configs-update";

/// The resource-level scope `method uri` needs on top of its service-level
/// scope, or `None` when the service-level scope alone authorizes it.
///
/// `uri` is the request target as the server hands it to the NF router. The
/// path is split exactly as udrd's router splits it (query dropped, leading
/// `/`s trimmed, split on `/`) and matched on the same segment positions the
/// router dispatches on, so every request that router serves from the
/// authentication-subscription arm is classified here -- including a trailing
/// `/` or extra trailing segments, which that arm ignores.
///
/// Mapping (TS 29.505 `security`): GET -> `:read`; PATCH -> `:modify`. PUT,
/// udrd's non-3GPP provisioning write of K and OPc, is a modification of the
/// same resource and needs `:modify` too. Every other method on the resource
/// (and any method spelled in another case) is treated as a modification, so
/// an unexpected method can never fall through to "no extra scope".
///
/// #2079: a write (any method but GET / HEAD) on an NF registration under
/// `context-data` needs [`NUDR_DR_REGISTRATIONS_WRITE`]; one on
/// `authentication-data/authentication-status[/{servingNetworkName}]` or on
/// the `sdm-subscriptions` / `ee-subscriptions` collections needs
/// [`NUDR_DR_SUBSCRIPTION_DATA`]. A token satisfies them per [`token_grants`].
///
/// `nnsacf-nsac` `slices/local-configs/update` (TS 29.536 `LocalNumberUpdate`,
/// POST) needs [`NNSACF_NSAC_LOCAL_CONFIGS_UPDATE`] for every method, so a
/// method nsacfd answers 405 cannot be the one that slips through either.
pub fn required_resource_scope(method: &str, uri: &str) -> Option<&'static str> {
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.first() == Some(&"nnsacf-nsac")
        && parts.get(2) == Some(&"slices")
        && parts.get(3) == Some(&"local-configs")
        && parts.get(4) == Some(&"update")
    {
        return Some(NNSACF_NSAC_LOCAL_CONFIGS_UPDATE);
    }
    if parts.first() != Some(&"nudr-dr") || parts.get(2) != Some(&"subscription-data") {
        return None;
    }
    let read = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
    let auth_data = parts.get(4) == Some(&"authentication-data");
    if auth_data && parts.get(5) == Some(&"authentication-subscription") {
        return Some(if read {
            NUDR_DR_AUTH_SUBSCRIPTION_READ
        } else {
            NUDR_DR_AUTH_SUBSCRIPTION_MODIFY
        });
    }
    // #2079: only the WRITES below need a resource scope; their GETs stay on
    // the service scope. Every method other than GET / HEAD counts as a write,
    // so an unexpected method can never fall through to "no extra scope".
    if read {
        return None;
    }
    if auth_data && parts.get(5) == Some(&"authentication-status") {
        return Some(NUDR_DR_SUBSCRIPTION_DATA);
    }
    // udrd's router serves context-data at parts[4] and, after a servingPlmnId
    // segment, at parts[5]: both positions are classified, so no layout the
    // router dispatches on reaches it unscoped.
    let resource = if parts.get(4) == Some(&"context-data") {
        parts.get(5)
    } else if parts.get(5) == Some(&"context-data") {
        parts.get(6)
    } else {
        None
    };
    match resource {
        Some(r) if NF_REGISTRATION_RESOURCES.contains(r) => Some(NUDR_DR_REGISTRATIONS_WRITE),
        Some(r) if UDM_SUBSCRIPTION_COLLECTIONS.contains(r) => Some(NUDR_DR_SUBSCRIPTION_DATA),
        _ => None,
    }
}

/// Whether a token whose (space-delimited) `scope` claim is `token_scope`
/// carries the resource scope `required` (#2079). It does when it lists
/// `required` itself, or, for [`NUDR_DR_REGISTRATIONS_WRITE`], when it lists
/// [`NUDR_DR_SUBSCRIPTION_DATA`]: `TS29505_Subscription_Data.yaml` offers the
/// two as alternatives on every NF-registration write (`nudr-dr` +
/// `nudr-dr:subscription-data`, OR `nudr-dr` +
/// `nudr-dr:subscription-data:registrations:write`).
pub fn token_grants(token_scope: &str, required: &str) -> bool {
    let has = |s: &str| token_scope.split_whitespace().any(|t| t == s);
    has(required) || (required == NUDR_DR_REGISTRATIONS_WRITE && has(NUDR_DR_SUBSCRIPTION_DATA))
}

/// The space-delimited scope a consumer requests from the NRF to invoke
/// `method uri`: the service-level scope `service` (the apiName) followed by
/// the resource-level scope the operation needs, if any (TS 29.500 §6.7.3).
/// An empty `service` yields an empty scope (no token applies).
pub fn access_token_scope(service: &str, method: &str, uri: &str) -> String {
    if service.is_empty() {
        return String::new();
    }
    match required_resource_scope(method, uri) {
        Some(resource) if resource.split(':').next() == Some(service) => {
            format!("{service} {resource}")
        }
        _ => service.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_SUBS: &str =
        "/nudr-dr/v2/subscription-data/imsi-001010000000001/authentication-data/authentication-subscription";

    #[test]
    fn the_scopes_are_spelled_as_ts29505_defines_them() {
        assert_eq!(
            NUDR_DR_AUTH_SUBSCRIPTION_READ,
            "nudr-dr:subscription-data:authentication-subscription:read"
        );
        assert_eq!(
            NUDR_DR_AUTH_SUBSCRIPTION_MODIFY,
            "nudr-dr:subscription-data:authentication-subscription:modify"
        );
    }

    #[test]
    fn auth_subscription_get_needs_read_and_writes_need_modify() {
        assert_eq!(
            required_resource_scope("GET", AUTH_SUBS),
            Some(NUDR_DR_AUTH_SUBSCRIPTION_READ)
        );
        for m in ["PATCH", "PUT", "DELETE", "patch"] {
            assert_eq!(
                required_resource_scope(m, AUTH_SUBS),
                Some(NUDR_DR_AUTH_SUBSCRIPTION_MODIFY),
                "{m}"
            );
        }
    }

    #[test]
    fn variants_the_udr_router_still_serves_are_classified() {
        for uri in [
            format!("{AUTH_SUBS}?supported-features=1"),
            format!("{AUTH_SUBS}/"),
            format!("/{AUTH_SUBS}"),
            format!("{AUTH_SUBS}/extra"),
            AUTH_SUBS.trim_start_matches('/').to_string(),
        ] {
            assert_eq!(
                required_resource_scope("GET", &uri),
                Some(NUDR_DR_AUTH_SUBSCRIPTION_READ),
                "{uri}"
            );
        }
    }

    /// #1892: spelled as TS 29.536 Table 6.1.9-1 defines it, and required on
    /// the local-configs update only, not on the AMF's and SMF's operations.
    #[test]
    fn the_nsacf_local_configs_update_needs_its_own_scope_1892() {
        assert_eq!(
            NNSACF_NSAC_LOCAL_CONFIGS_UPDATE,
            "nnsacf-nsac:local-configs-update"
        );
        for uri in [
            "/nnsacf-nsac/v1/slices/local-configs/update",
            "/nnsacf-nsac/v1/slices/local-configs/update?x=1",
            "nnsacf-nsac/v1/slices/local-configs/update/",
        ] {
            for m in ["POST", "post", "PUT", "GET"] {
                assert_eq!(
                    required_resource_scope(m, uri),
                    Some(NNSACF_NSAC_LOCAL_CONFIGS_UPDATE),
                    "{m} {uri}"
                );
            }
        }
        assert_eq!(
            access_token_scope(
                "nnsacf-nsac",
                "POST",
                "/nnsacf-nsac/v1/slices/local-configs/update"
            ),
            "nnsacf-nsac nnsacf-nsac:local-configs-update"
        );
        // #1934 review M1: a path a router may split differently (an empty or dot
        // segment) is not classified here, so it must never reach a router: the
        // SBI server refuses each of them 400 first.
        for uri in [
            "/nnsacf-nsac/v1//slices/local-configs/update",
            "/nnsacf-nsac/v1/slices//local-configs/update",
            "/nnsacf-nsac/v1/slices/./local-configs/update",
        ] {
            assert_eq!(required_resource_scope("POST", uri), None, "{uri}");
            assert!(crate::server::path_segment_refusal(uri).is_some(), "{uri}");
        }
        for uri in [
            "/nnsacf-nsac/v1/slices/ues",
            "/nnsacf-nsac/v1/slices/pdus",
            "/nnsacf-nsac/v1/slices/roaming-quotas/query",
        ] {
            assert_eq!(required_resource_scope("POST", uri), None, "{uri}");
        }
    }

    #[test]
    fn other_subscription_data_needs_only_the_service_scope() {
        for uri in [
            "/nudr-dr/v2/subscription-data/imsi-001010000000001/provisioned-data/am-data",
            "/nudr-dr/v2/subscription-data/imsi-001010000000001/authentication-data/authentication-status",
            "/nudr-dr/v2/policy-data/ues/imsi-001010000000001/am-data",
            "/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data",
        ] {
            assert_eq!(required_resource_scope("GET", uri), None, "{uri}");
        }
    }

    /// #2079: the NF-registration writes need `registrations:write`, the UDM's
    /// other context writes `subscription-data`, at both context-data positions
    /// udrd routes; the GETs stay on the service scope.
    #[test]
    fn the_udm_context_writes_need_their_resource_scope_2079() {
        assert_eq!(NUDR_DR_SUBSCRIPTION_DATA, "nudr-dr:subscription-data");
        assert_eq!(
            NUDR_DR_REGISTRATIONS_WRITE,
            "nudr-dr:subscription-data:registrations:write"
        );
        let ue = "/nudr-dr/v2/subscription-data/imsi-001010000020790";
        for base in [
            format!("{ue}/context-data"),
            format!("{ue}/00101/context-data"),
        ] {
            for r in [
                "amf-3gpp-access",
                "amf-non-3gpp-access",
                "smf-registrations/5",
                "smsf-3gpp-access",
                "smsf-non-3gpp-access",
                "ip-sm-gw",
            ] {
                let uri = format!("{base}/{r}");
                for m in ["PUT", "PATCH", "DELETE", "POST", "put"] {
                    assert_eq!(
                        required_resource_scope(m, &uri),
                        Some(NUDR_DR_REGISTRATIONS_WRITE),
                        "{m} {uri}"
                    );
                }
                assert_eq!(required_resource_scope("GET", &uri), None, "{uri}");
            }
            for r in [
                "sdm-subscriptions",
                "sdm-subscriptions/1",
                "ee-subscriptions",
                "ee-subscriptions/1/amf-subscriptions",
            ] {
                let uri = format!("{base}/{r}");
                for m in ["POST", "PUT", "PATCH", "DELETE"] {
                    assert_eq!(
                        required_resource_scope(m, &uri),
                        Some(NUDR_DR_SUBSCRIPTION_DATA),
                        "{m} {uri}"
                    );
                }
                assert_eq!(required_resource_scope("GET", &uri), None, "{uri}");
            }
        }
        for uri in [
            format!("{ue}/authentication-data/authentication-status"),
            format!("{ue}/authentication-data/authentication-status/5G%3Amnc001.mcc001"),
        ] {
            for m in ["PUT", "DELETE"] {
                assert_eq!(
                    required_resource_scope(m, &uri),
                    Some(NUDR_DR_SUBSCRIPTION_DATA),
                    "{m} {uri}"
                );
            }
            assert_eq!(required_resource_scope("GET", &uri), None, "{uri}");
        }
        // Other writes keep the service scope (pp-data has its own consumers).
        assert_eq!(
            required_resource_scope("PATCH", &format!("{ue}/pp-data")),
            None
        );
        assert_eq!(
            access_token_scope(
                "nudr-dr",
                "PUT",
                &format!("{ue}/context-data/amf-3gpp-access")
            ),
            format!("nudr-dr {NUDR_DR_REGISTRATIONS_WRITE}")
        );
        assert_eq!(
            access_token_scope(
                "nudr-dr",
                "PUT",
                &format!("{ue}/authentication-data/authentication-status")
            ),
            format!("nudr-dr {NUDR_DR_SUBSCRIPTION_DATA}")
        );
    }

    /// #2079: the yaml's alternatives. `subscription-data` stands in for
    /// `registrations:write`, never the other way round, and neither stands in
    /// for the AuthenticationSubscription scopes.
    #[test]
    fn subscription_data_also_grants_registration_writes_2079() {
        assert!(token_grants(
            &format!("nudr-dr {NUDR_DR_REGISTRATIONS_WRITE}"),
            NUDR_DR_REGISTRATIONS_WRITE
        ));
        assert!(token_grants(
            &format!("nudr-dr {NUDR_DR_SUBSCRIPTION_DATA}"),
            NUDR_DR_REGISTRATIONS_WRITE
        ));
        assert!(!token_grants(
            &format!("nudr-dr {NUDR_DR_REGISTRATIONS_WRITE}"),
            NUDR_DR_SUBSCRIPTION_DATA
        ));
        assert!(!token_grants("nudr-dr", NUDR_DR_REGISTRATIONS_WRITE));
        assert!(!token_grants("nudr-dr", NUDR_DR_SUBSCRIPTION_DATA));
        assert!(!token_grants(
            &format!("nudr-dr {NUDR_DR_SUBSCRIPTION_DATA}"),
            NUDR_DR_AUTH_SUBSCRIPTION_READ
        ));
        // A scope that merely starts with the required one is not it.
        assert!(!token_grants(
            "nudr-dr nudr-dr:subscription-data:registrations:writex",
            NUDR_DR_REGISTRATIONS_WRITE
        ));
    }

    #[test]
    fn the_token_request_carries_both_scopes() {
        assert_eq!(
            access_token_scope("nudr-dr", "GET", AUTH_SUBS),
            format!("nudr-dr {NUDR_DR_AUTH_SUBSCRIPTION_READ}")
        );
        assert_eq!(
            access_token_scope("nudr-dr", "PATCH", AUTH_SUBS),
            format!("nudr-dr {NUDR_DR_AUTH_SUBSCRIPTION_MODIFY}")
        );
        assert_eq!(
            access_token_scope(
                "nudr-dr",
                "GET",
                "/nudr-dr/v2/subscription-data/imsi-001010000000001/provisioned-data/am-data"
            ),
            "nudr-dr"
        );
        assert_eq!(access_token_scope("", "GET", AUTH_SUBS), "");
    }
}
