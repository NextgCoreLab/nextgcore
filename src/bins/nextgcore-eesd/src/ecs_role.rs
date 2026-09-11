//! The Edge Configuration Server role (issue #107, TS 23.558 §8.3, TS 29.558 §5.2).
//!
//! # What was missing
//!
//! The ECS is the entry point through which an EEC bootstraps the edge enabler
//! layer: service provisioning over EDGE-4, EES registration over EDGE-6, and
//! target-EES discovery. **None of the eight ECS-side APIs had a server anywhere
//! in this workspace.** The only ECS-facing code was the EES's own EDGE-6
//! registration *client*, so an EEC had no bootstrap path at all and an EES could
//! not be brought into a deployment through an ECS.
//!
//! # Why a role inside eesd rather than a new binary
//!
//! #107 offers either. This is the role, for three reasons:
//!
//! - **An ECS is not a 5GC NF.** It has no `nfType` in TS 29.510 — the same fact
//!   that made `ecs_registration` replace eesd's old (incorrect) NRF
//!   self-registration. So a separate binary would gain none of the NF machinery
//!   (NRF profile, heartbeat, discovery) that justifies one for nefd/easdfd/tsctsf,
//!   the precedents #107 cites.
//! - **The registry an ECS needs is the registry this process already keeps.** The
//!   EES's own EAS pool is what `Eecs_TargetEESDiscovery` matches against, and
//!   crossing a process boundary to read it would mean inventing a protocol that
//!   TS 29.558 does not define.
//! - **It costs one runtime switch instead of a Dockerfile, a compose service, a
//!   config file and a health probe**, none of which #107 asks for.
//!
//! Gated on `ECS_ROLE=1` and **off by default**, so a deployment that does not
//! want an ECS serves exactly the routes it served before. A **runtime** switch
//! rather than the cargo feature #107 suggests, because this project has a recorded
//! convention for that: a feature-gated path is left uncompiled by CI and rots.
//! With the switch off the routes answer 404 exactly as they did before, which is
//! what makes the default safe.
//!
//! # Scope: three of the eight APIs
//!
//! #107's own suggested approach scopes the initial surface to three, "to stay
//! implementable": `Eecs_ServiceProvisioning`, `Eecs_EESRegistration` and
//! `Eecs_TargetEESDiscovery`. The other five are named in the spec's ceilings
//! rather than stubbed, because a route answering a fabricated 2xx is worse than a
//! 404: the 404 is honest about not being implemented.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_bad_request, send_method_not_allowed, send_not_found};
use serde::{Deserialize, Serialize};

use crate::ecs_registration::{EesProfile, EesRegistration};

/// Is the ECS role enabled for this process?
static ECS_ROLE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable the ECS role (called once at startup when `ECS_ROLE=1`).
pub fn enable() {
    ECS_ROLE_ENABLED.store(true, Ordering::SeqCst);
    log::info!(
        "[EES] ECS role ENABLED: serving eecs-serviceprovisioning/v1, \
         eecs-eesregistration/v1 and eecs-targeteesdiscovery/v1 (TS 29.558 §5.2)"
    );
}

/// Whether the ECS role is enabled.
pub fn enabled() -> bool {
    ECS_ROLE_ENABLED.load(Ordering::SeqCst)
}

/// Read `ECS_ROLE` and enable accordingly. Called once from `main`.
pub fn init_from_env() {
    match std::env::var("ECS_ROLE").as_deref() {
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("on") => enable(),
        _ => log::info!(
            "[EES] ECS role DISABLED (set ECS_ROLE=1 to enable): the eecs-* paths answer 404, \
             exactly as before #107"
        ),
    }
}

/// Test-only: set the switch without going through startup.
///
/// The caller must hold the crate's process-state test lock: this switch and the
/// registry below are process-global.
#[cfg(test)]
pub fn set_for_test(on: bool) {
    ECS_ROLE_ENABLED.store(on, Ordering::SeqCst);
}

// ============================================================================
// The registry
// ============================================================================

/// One EES registration held by this ECS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredEesRegistration {
    /// Server-minted resource id. Never taken from the request: a
    /// consumer-supplied id would let one EES address another's resource.
    pub registration_id: String,
    /// The registration as received, so a member this build does not model is
    /// returned on a refresh rather than silently dropped.
    #[serde(flatten)]
    pub registration: EesRegistration,
}

/// Registered EESs, keyed by `registrationId`.
fn registry() -> &'static Mutex<std::collections::HashMap<String, StoredEesRegistration>> {
    static REG: OnceLock<Mutex<std::collections::HashMap<String, StoredEesRegistration>>> =
        OnceLock::new();
    REG.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Every registration currently held.
pub fn registered_eess() -> Vec<StoredEesRegistration> {
    match registry().lock() {
        Ok(r) => r.values().cloned().collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
pub fn clear_registry_for_test() {
    if let Ok(mut r) = registry().lock() {
        r.clear();
    }
}

/// API prefixes, so criterion 1's grep finds them in one place and the router and
/// the docs cannot drift from each other.
pub const API_SERVICE_PROVISIONING: &str = "eecs-serviceprovisioning/v1";
pub const API_EES_REGISTRATION: &str = "eecs-eesregistration/v1";
pub const API_TARGET_EES_DISCOVERY: &str = "eecs-targeteesdiscovery/v1";

// ============================================================================
// Eecs_EESRegistration (EDGE-6, TS 29.558 §9)
// ============================================================================

/// `POST /eecs-eesregistration/v1/registrations` — CreateEESRegistration.
///
/// 201 with a `Location` header, which is what the EES-side client reads the
/// `registrationId` from. `eesProf.eesId` is mandatory: a registration that names
/// no EES could never be returned by discovery, which is the un-discoverable state
/// worth refusing rather than accepting and never matching.
pub fn handle_registration_create(request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING"));
    };
    let registration: EesRegistration = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid EESRegistration: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    if registration.ees_prof.ees_id.trim().is_empty() {
        return send_bad_request("eesProf.eesId is mandatory", Some("MANDATORY_IE_MISSING"));
    }

    let registration_id = uuid::Uuid::new_v4().to_string();
    let stored = StoredEesRegistration {
        registration_id: registration_id.clone(),
        registration,
    };
    let location = format!("/{API_EES_REGISTRATION}/registrations/{registration_id}");
    if let Ok(mut r) = registry().lock() {
        r.insert(registration_id.clone(), stored.clone());
    }
    log::info!(
        "ECS: EES {} registered (registrationId={registration_id}, easIds={:?})",
        stored.registration.ees_prof.ees_id,
        stored.registration.ees_prof.eas_ids
    );
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(&stored)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// `PUT /eecs-eesregistration/v1/registrations/{registrationId}` — the refresh.
///
/// 200 with the stored resource, or **404 for an id this ECS does not hold** —
/// which is precisely the answer the hardened EES client re-POSTs on, and is what
/// an ECS restart produces. Answering 200 for an unknown id, or silently
/// re-creating it, would hide the very case #107's criterion 4 is about.
pub fn handle_registration_update(registration_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING"));
    };
    let registration: EesRegistration = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid EESRegistration: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let updated = {
        match registry().lock() {
            Ok(mut r) => match r.get_mut(registration_id) {
                Some(existing) => {
                    existing.registration = registration;
                    Some(existing.clone())
                }
                None => None,
            },
            Err(_) => None,
        }
    };
    match updated {
        Some(stored) => SbiResponse::with_status(200)
            .with_json_body(&stored)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("EES registration {registration_id} not found"),
            Some("REGISTRATION_NOT_FOUND"),
        ),
    }
}

/// `GET`/`DELETE /eecs-eesregistration/v1/registrations/{registrationId}`.
pub fn handle_registration_get(registration_id: &str) -> SbiResponse {
    match registry()
        .lock()
        .ok()
        .and_then(|r| r.get(registration_id).cloned())
    {
        Some(stored) => SbiResponse::with_status(200)
            .with_json_body(&stored)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("EES registration {registration_id} not found"),
            Some("REGISTRATION_NOT_FOUND"),
        ),
    }
}

/// `DELETE` — 204, or 404 for an unknown id.
pub fn handle_registration_delete(registration_id: &str) -> SbiResponse {
    let removed = match registry().lock() {
        Ok(mut r) => r.remove(registration_id).is_some(),
        Err(_) => false,
    };
    if removed {
        log::info!("ECS: EES registration {registration_id} removed");
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("EES registration {registration_id} not found"),
            Some("REGISTRATION_NOT_FOUND"),
        )
    }
}

// ============================================================================
// Eecs_ServiceProvisioning (EDGE-4, TS 29.558 §5.2)
// ============================================================================

/// `POST /eecs-serviceprovisioning/v1/provisioning-requests` — the EEC's
/// bootstrap.
///
/// Answers an `EcsServiceProvisioningResponse`-shaped body listing the EES
/// endpoints this ECS knows, which is what lets an EEC reach an EES at all. An ECS
/// with no registered EES answers **200 with an empty list**, not 404: "no EES is
/// available yet" and "this ECS does not serve provisioning" are different states
/// and a consumer must be able to tell them apart.
pub fn handle_service_provisioning(request: &SbiRequest) -> SbiResponse {
    // `eecId` is the one mandatory input (TS 29.558 §5.2). Read to validate, not to
    // filter: this build has no per-EEC provisioning policy, and pretending
    // otherwise by filtering on something else would be worse than serving the
    // whole list.
    let eec_id = request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
        .and_then(|v| v.get("eecId").and_then(|x| x.as_str()).map(str::to_string));
    let Some(eec_id) = eec_id.filter(|s| !s.trim().is_empty()) else {
        return send_bad_request("eecId is mandatory", Some("MANDATORY_IE_MISSING"));
    };

    let profiles: Vec<EesProfile> = registered_eess()
        .into_iter()
        .map(|s| s.registration.ees_prof)
        .collect();
    log::info!(
        "ECS: service provisioning for eecId={eec_id}: {} EES profile(s)",
        profiles.len()
    );
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "provisioningResponses": [{ "edgeDataNetworkConfigs": profiles }],
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ============================================================================
// Eecs_TargetEESDiscovery (TS 29.558 §5.2)
// ============================================================================

/// `POST /eecs-targeteesdiscovery/v1/target-ees-discovery` — return candidate
/// target EESs for an EAS or AC profile.
///
/// Matching is on the registered `eesProf.easIds`, which is exactly why criterion
/// 5's `easIds` population matters: a registration advertising `easIds: null`
/// cannot be matched by this, so before #107 the ECS's view of every EES was
/// unusable for target selection even on the happy path.
///
/// A query naming no EAS returns **every** registered EES rather than none: "which
/// EESs exist" is a legitimate discovery, and answering empty would make an
/// unfiltered query look like a failed one.
pub fn handle_target_ees_discovery(request: &SbiRequest) -> SbiResponse {
    let body: serde_json::Value = match request.http.content.as_deref() {
        Some(b) => match serde_json::from_str(b) {
            Ok(v) => v,
            Err(e) => {
                return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
            }
        },
        None => return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING")),
    };

    // `easId` directly, or via an AC profile's `easIds` — TS 29.558 lets the query
    // be framed either way, and refusing the AC form would make an EEC's natural
    // query fail.
    let mut wanted: Vec<String> = Vec::new();
    if let Some(id) = body.get("easId").and_then(|v| v.as_str()) {
        wanted.push(id.to_string());
    }
    for key in ["easIds", "acProfs"] {
        if let Some(arr) = body.get(key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(id) = item.as_str() {
                    wanted.push(id.to_string());
                } else if let Some(ids) = item.get("easIds").and_then(|v| v.as_array()) {
                    wanted.extend(ids.iter().filter_map(|v| v.as_str()).map(str::to_string));
                }
            }
        }
    }

    let all = registered_eess();
    let matched: Vec<EesProfile> = if wanted.is_empty() {
        all.into_iter().map(|s| s.registration.ees_prof).collect()
    } else {
        all.into_iter()
            .filter(|s| {
                s.registration
                    .ees_prof
                    .eas_ids
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| wanted.contains(id)))
            })
            .map(|s| s.registration.ees_prof)
            .collect()
    };
    log::info!(
        "ECS: target-EES discovery for {wanted:?}: {} candidate(s)",
        matched.len()
    );
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({ "eesProfiles": matched }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ============================================================================
// Routing
// ============================================================================

/// Dispatch an `eecs-*` path, or `None` when this is not an ECS route or the role
/// is off.
///
/// Returning `None` rather than a 404 keeps the caller's own fallback in charge, so
/// with the role disabled these paths answer exactly what they answered before
/// #107 — which is what makes the default safe rather than merely quiet.
pub fn route(parts: &[&str], request: &SbiRequest) -> Option<SbiResponse> {
    if !enabled() {
        return None;
    }
    let method = request.header.method.as_str();
    match parts {
        ["eecs-eesregistration", "v1", "registrations"] => Some(match method {
            "POST" => handle_registration_create(request),
            _ => send_method_not_allowed(method, "registrations"),
        }),
        ["eecs-eesregistration", "v1", "registrations", registration_id] => Some(match method {
            "PUT" => handle_registration_update(registration_id, request),
            "GET" => handle_registration_get(registration_id),
            "DELETE" => handle_registration_delete(registration_id),
            _ => send_method_not_allowed(method, "registrations/{registrationId}"),
        }),
        ["eecs-serviceprovisioning", "v1", "provisioning-requests"] => Some(match method {
            "POST" => handle_service_provisioning(request),
            _ => send_method_not_allowed(method, "provisioning-requests"),
        }),
        ["eecs-targeteesdiscovery", "v1", "target-ees-discovery"] => Some(match method {
            "POST" => handle_target_ees_discovery(request),
            _ => send_method_not_allowed(method, "target-ees-discovery"),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EndPoint;

    fn post(path: &str, body: serde_json::Value) -> SbiRequest {
        SbiRequest::post(path)
            .with_json_body(&body)
            .expect("serialize test body")
    }

    fn registration_body(ees_id: &str, eas_ids: Option<Vec<&str>>) -> serde_json::Value {
        serde_json::json!({
            "eesProf": {
                "eesId": ees_id,
                "endPt": { "ipv4Addrs": ["10.0.0.9"], "port": 7814 },
                "easIds": eas_ids,
            },
            "expTime": "2026-12-31T23:59:59Z",
        })
    }

    /// #107 criterion 2: a create returns 201 with a Location, and a subsequent
    /// PUT refresh returns 2xx.
    #[test]
    fn a_registration_is_created_with_a_location_and_can_be_refreshed() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        set_for_test(true);

        let created = handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            registration_body("ees1.example.com", Some(vec!["eas1.example.com"])),
        ));
        assert_eq!(created.status, 201);
        let location = created
            .http
            .get_header("location")
            .expect("201 must carry a Location, which is where the client reads the id from")
            .clone();
        let registration_id = location.rsplit('/').next().expect("id segment").to_string();
        assert!(
            location.starts_with("/eecs-eesregistration/v1/registrations/"),
            "Location was {location}"
        );
        assert!(!registration_id.is_empty());

        let refreshed = handle_registration_update(
            &registration_id,
            &post(
                &location,
                registration_body("ees1.example.com", Some(vec!["eas1.example.com"])),
            ),
        );
        assert!(
            (200..300).contains(&refreshed.status),
            "the refresh must be 2xx, got {}",
            refreshed.status
        );
        set_for_test(false);
    }

    /// The 404 the hardened client re-POSTs on. Asserted here because the client's
    /// recovery is only correct if the ECS actually produces this for an id it does
    /// not hold — an ECS that answered 200 would make the recovery unreachable.
    #[test]
    fn refreshing_an_unknown_registration_is_404() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        let resp = handle_registration_update(
            "no-such-id",
            &post(
                "/eecs-eesregistration/v1/registrations/no-such-id",
                registration_body("ees1.example.com", None),
            ),
        );
        assert_eq!(
            resp.status, 404,
            "an ECS that lost its registry must say so, or the EES cannot recover"
        );
    }

    #[test]
    fn a_registration_without_an_ees_id_is_refused() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        let resp = handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            serde_json::json!({ "eesProf": { "eesId": "", "endPt": {} } }),
        ));
        assert_eq!(
            resp.status, 400,
            "an EES with no id could never be returned by discovery"
        );
    }

    /// #107 criterion 6: discovery returns a candidate EES for a matching EAS
    /// query, and does not return one for a non-matching query.
    #[test]
    fn target_ees_discovery_matches_on_registered_eas_ids() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            registration_body("ees-a.example.com", Some(vec!["eas-alpha", "eas-beta"])),
        ));
        handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            registration_body("ees-b.example.com", Some(vec!["eas-gamma"])),
        ));

        let hit = handle_target_ees_discovery(&post(
            "/eecs-targeteesdiscovery/v1/target-ees-discovery",
            serde_json::json!({ "easId": "eas-beta" }),
        ));
        assert_eq!(hit.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(hit.http.content.as_deref().expect("body")).expect("json");
        let profiles = body["eesProfiles"].as_array().expect("array");
        assert_eq!(profiles.len(), 1, "got {profiles:?}");
        assert_eq!(profiles[0]["eesId"], "ees-a.example.com");

        let miss = handle_target_ees_discovery(&post(
            "/eecs-targeteesdiscovery/v1/target-ees-discovery",
            serde_json::json!({ "easId": "eas-nobody-serves" }),
        ));
        let body: serde_json::Value =
            serde_json::from_str(miss.http.content.as_deref().expect("body")).expect("json");
        assert!(
            body["eesProfiles"].as_array().expect("array").is_empty(),
            "an EAS nobody serves must return no candidate, not any candidate"
        );
    }

    /// The matching is on `easIds`, so a registration that advertises none cannot
    /// be matched — which is the whole reason criterion 5 matters. Pinned so a
    /// future change cannot make discovery ignore `easIds` and appear to work.
    #[test]
    fn an_ees_advertising_no_eas_ids_is_not_a_discovery_candidate() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            registration_body("ees-silent.example.com", None),
        ));
        let resp = handle_target_ees_discovery(&post(
            "/eecs-targeteesdiscovery/v1/target-ees-discovery",
            serde_json::json!({ "easId": "eas-alpha" }),
        ));
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert!(
            body["eesProfiles"].as_array().expect("array").is_empty(),
            "an EES that advertises no easIds is unmatched -- this is what a static \
             `easIds: None` cost every deployment before #107"
        );

        // An UNFILTERED query still returns it: "which EESs exist" is legitimate.
        let all = handle_target_ees_discovery(&post(
            "/eecs-targeteesdiscovery/v1/target-ees-discovery",
            serde_json::json!({}),
        ));
        let body: serde_json::Value =
            serde_json::from_str(all.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["eesProfiles"].as_array().expect("array").len(), 1);
    }

    /// Service provisioning returns the EES endpoints an EEC needs, and an ECS with
    /// no EES answers 200-with-nothing rather than 404 — two different states.
    #[test]
    fn service_provisioning_lists_registered_ees_endpoints() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();

        let empty = handle_service_provisioning(&post(
            "/eecs-serviceprovisioning/v1/provisioning-requests",
            serde_json::json!({ "eecId": "eec-1" }),
        ));
        assert_eq!(
            empty.status, 200,
            "'no EES available yet' is not 'provisioning not served'"
        );

        handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            registration_body("ees1.example.com", Some(vec!["eas1"])),
        ));
        let resp = handle_service_provisioning(&post(
            "/eecs-serviceprovisioning/v1/provisioning-requests",
            serde_json::json!({ "eecId": "eec-1" }),
        ));
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        let configs = body["provisioningResponses"][0]["edgeDataNetworkConfigs"]
            .as_array()
            .expect("array");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0]["eesId"], "ees1.example.com");
        assert_eq!(
            configs[0]["endPt"]["port"], 7814,
            "the EEC needs the endpoint, not just the name"
        );
    }

    #[test]
    fn service_provisioning_without_an_eec_id_is_refused() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let resp = handle_service_provisioning(&post(
            "/eecs-serviceprovisioning/v1/provisioning-requests",
            serde_json::json!({}),
        ));
        assert_eq!(resp.status, 400);
    }

    /// With the role OFF every ECS route is unrouted, so the caller's own fallback
    /// answers — the behaviour a deployment that does not want an ECS had before.
    #[test]
    fn the_role_off_routes_nothing() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_for_test(false);
        for path in [
            ["eecs-eesregistration", "v1", "registrations"],
            ["eecs-serviceprovisioning", "v1", "provisioning-requests"],
            ["eecs-targeteesdiscovery", "v1", "target-ees-discovery"],
        ] {
            assert!(
                route(&path, &post(&path.join("/"), serde_json::json!({}))).is_none(),
                "{path:?} must not be routed with the role off"
            );
        }
    }

    /// With the role ON they are all routed, and a wrong method is a 405 rather
    /// than a 404 — a consumer must be able to tell "not implemented here" from
    /// "wrong verb".
    #[test]
    fn the_role_on_routes_all_three_apis() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        set_for_test(true);
        let paths = [
            ["eecs-eesregistration", "v1", "registrations"],
            ["eecs-serviceprovisioning", "v1", "provisioning-requests"],
            ["eecs-targeteesdiscovery", "v1", "target-ees-discovery"],
        ];
        for path in paths {
            assert!(
                route(&path, &post(&path.join("/"), serde_json::json!({}))).is_some(),
                "{path:?} must be routed with the role on"
            );
            let get = SbiRequest::get(&path.join("/"));
            let resp = route(&path, &get).expect("routed");
            assert_eq!(
                resp.status, 405,
                "{path:?} with GET must be 405, not 404: the route exists"
            );
        }
        set_for_test(false);
    }

    /// An unmodelled member survives the round trip, so an EES sending a
    /// `supportedFeatures` or vendor extension this build does not type gets it
    /// back on a GET rather than having it silently dropped.
    #[test]
    fn a_registration_is_returned_as_stored() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        let created = handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            registration_body("ees1.example.com", Some(vec!["eas1"])),
        ));
        let id = created
            .http
            .get_header("location")
            .and_then(|l| l.rsplit('/').next().map(str::to_string))
            .expect("id");
        let got = handle_registration_get(&id);
        assert_eq!(got.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(got.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["registrationId"], id);
        assert_eq!(body["eesProf"]["eesId"], "ees1.example.com");
        assert_eq!(
            body["expTime"], "2026-12-31T23:59:59Z",
            "expTime must survive: an ECS that forgot it could not expire the registration"
        );

        assert_eq!(handle_registration_delete(&id).status, 204);
        assert_eq!(handle_registration_get(&id).status, 404);
    }

    /// The registry is keyed by a server-minted id, so two EESs with the SAME
    /// `eesId` do not collide. A consumer-supplied key would let one EES replace
    /// another's registration.
    #[test]
    fn two_registrations_get_distinct_server_minted_ids() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        let ids: Vec<String> = (0..2)
            .map(|_| {
                handle_registration_create(&post(
                    "/eecs-eesregistration/v1/registrations",
                    registration_body("ees-same.example.com", Some(vec!["eas1"])),
                ))
                .http
                .get_header("location")
                .and_then(|l| l.rsplit('/').next().map(str::to_string))
                .expect("id")
            })
            .collect();
        assert_ne!(ids[0], ids[1]);
        assert_eq!(registered_eess().len(), 2);
    }

    /// The endpoint type round-trips through the registry, so the profile a
    /// discovery hands back is the one the EES registered.
    #[test]
    fn the_stored_profile_keeps_the_endpoint_the_ees_registered() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_registry_for_test();
        handle_registration_create(&post(
            "/eecs-eesregistration/v1/registrations",
            registration_body("ees1.example.com", Some(vec!["eas1"])),
        ));
        let stored = registered_eess();
        assert_eq!(
            stored[0].registration.ees_prof.end_pt,
            EndPoint {
                ipv4_addrs: Some(vec!["10.0.0.9".to_string()]),
                port: Some(7814),
                ..Default::default()
            }
        );
    }
}
