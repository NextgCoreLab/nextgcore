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
//! (also TS 29.504 Table 6.1.7-1), and `TS29536_Nnsacf_NSAC.yaml`
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
    let is_auth_subscription = parts.first() == Some(&"nudr-dr")
        && parts.get(2) == Some(&"subscription-data")
        && parts.get(4) == Some(&"authentication-data")
        && parts.get(5) == Some(&"authentication-subscription");
    if !is_auth_subscription {
        return None;
    }
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        Some(NUDR_DR_AUTH_SUBSCRIPTION_READ)
    } else {
        Some(NUDR_DR_AUTH_SUBSCRIPTION_MODIFY)
    }
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
