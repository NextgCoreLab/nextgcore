//! #2260: UE ID Mapping Information Provisioning, the AF-facing part of the
//! `3gpp-ueid` API (TS 29.522 §4.4.32.4 and §5.25.2.2-3).
//!
//! An AF provisions the mapping between a Ranging/Sidelink Positioning
//! Application Layer ID and a GPSI (TS 23.586 §4.3.7 and §4.3.10). The NEF
//! checks that the AF is authorised, and then stores the mapping in the UDR as
//! application data (TS 29.519 §6.2.27,
//! `PUT /nudr-dr/v2/application-data/ueid-mappings/{ueMappingId}`). lmfd reads
//! the mapping from there to decide which Application Layer IDs a UE may report
//! as (#2260).
//!
//! - **Collection** `{apiRoot}/3gpp-ueid/v1/{afId}/pp`:
//!   - GET lists the AF's provisionings;
//!   - POST creates one: 201, a Location header and the `UeIdMappingInfo`.
//! - **Individual** `{apiRoot}/3gpp-ueid/v1/{afId}/pp/{ppId}`:
//!   - GET returns it;
//!   - PUT updates it (`UeIdMappingInfo`), answered 200;
//!   - PATCH modifies it (`UeIdMappingInfoPatch`), answered 200;
//!   - DELETE removes it, answered 204.
//! - **Ownership:** the caller's identity is the one this process verified
//!   (issue #110), never the `{afId}` alone. A provisioning is visible and
//!   changeable only by the AF that made it. Any other caller gets 404.
//! - **The AF must be allowed for the GPSI's UE** (§4.4.32.4: "the NEF shall
//!   then check whether the AF is authorized to perform this operation"). The
//!   NEF reads the UE's Ranging and Sidelink Positioning privacy profile from
//!   the UDM by the GPSI (TS 23.586 §4.3.4; TS 29.503
//!   `/nudm-sdm/v2/{gpsi}/lcs-privacy-data`, `LcsPrivacyData.rangingSlPrivacyData`).
//!   The AF is authorised only when:
//!   - the profile does not disallow ranging and sidelink positioning for the
//!     UE (`rslppi` is not `RANGINGSL_DISALLOWED`); and
//!   - it names this AF among the identified AFs
//!     (`rangingSlUnrelatedClass.rangingSlExternalUnrelatedClass.rangingSlAfExternals[].afId`),
//!     with a privacy-check action other than `RANGINGSL_NOT_ALLOWED`.
//!
//!   Anything else is 403 (no profile, the AF not named), and a UDM that cannot
//!   be asked is 503. Deviation, stated: TS 29.522 does not name the data the
//!   NEF checks. The Nudm_ServiceSpecificAuthorisation ServiceType enumeration
//!   (TS 29.503 Table 6.8.6.3.2-1) has no ranging value. The UE's ranging
//!   privacy profile is the subscription data that says which AFs may range the
//!   UE.
//! - **1:1 only** (TS 29.522 §4.4.32.1 NOTE). The UDR holds it for every writer,
//!   with its check and its write as one step (udrd `handle_ueid_mappings`). Its
//!   403 is the AF's 403. The NEF does not decide 1:1 from a read it makes
//!   first (R48 on #2265: a value-based check let one AF copy another's mapping
//!   and then move it, and a read-then-write could be overtaken).

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_bad_request, send_method_not_allowed, send_not_found};
use serde_json::Value;

use crate::context::{nef_self, NefUeIdProvisioning};

/// The provisioning's resource URI (Table 5.25.2.2.3.2-4).
pub fn location(af_id: &str, pp_id: &str) -> String {
    format!("/3gpp-ueid/v1/{af_id}/pp/{pp_id}")
}

/// The Ranging/SL mapping a `UeIdMappingInfo` carries: (appLayerId, gpsi),
/// both required (TS 29.522 `RangSlUeIdMappInfo`). The GPSI must be one this
/// core can name (`msisdn-` or `extid-`, TS 29.571 `Gpsi`), and both must be in
/// the identity character set, since they reach southbound paths and queries.
pub fn mapping_of(info: &Value) -> Result<(String, String), String> {
    let m = info
        .get("rsUeIdMappingInfo")
        .ok_or("rsUeIdMappingInfo is mandatory: it is the only mapping this release defines")?;
    let app = m
        .get("appLayerId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("rsUeIdMappingInfo.appLayerId is mandatory")?;
    let gpsi = m
        .get("gpsi")
        .and_then(Value::as_str)
        .ok_or("rsUeIdMappingInfo.gpsi is mandatory")?;
    if !(gpsi.starts_with("msisdn-") || gpsi.starts_with("extid-")) {
        return Err(format!("gpsi {gpsi:?} is not a GPSI (msisdn- or extid-)"));
    }
    if !crate::valid_ue_identity(gpsi) || !crate::valid_ue_identity(app) {
        return Err("appLayerId and gpsi must be in the identity character set".into());
    }
    Ok((app.to_string(), gpsi.to_string()))
}

/// Whether the UE's Ranging/SL privacy profile (TS 29.503 `LcsPrivacyData`)
/// lets `af_id` range it: ranging is not disallowed for the UE, and the AF is
/// one of its identified AFs with an action other than `RANGINGSL_NOT_ALLOWED`
/// (whose absence means `RANGINGSL_ALLOWED_WITHOUT_NOTIFICATION`, Table
/// 6.1.6.2.118-1 NOTE).
pub fn profile_allows(lcs_privacy: &Value, af_id: &str) -> bool {
    let Some(r) = lcs_privacy.get("rangingSlPrivacyData") else {
        return false;
    };
    // The OpenAPI spells it `rslppi`; the table `rslpi`. Either may arrive.
    let ind = r
        .get("rslppi")
        .or_else(|| r.get("rslpi"))
        .and_then(|p| p.get("rangingSlPrivacyInd"))
        .and_then(Value::as_str);
    if ind == Some("RANGINGSL_DISALLOWED") {
        return false;
    }
    r.pointer("/rangingSlUnrelatedClass/rangingSlExternalUnrelatedClass/rangingSlAfExternals")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|a| {
            a.get("afId").and_then(Value::as_str) == Some(af_id)
                && a.get("rangingSlPrivacyCheckRelatedAction")
                    .and_then(Value::as_str)
                    != Some("RANGINGSL_NOT_ALLOWED")
        })
}

/// §4.4.32.4's authorisation of the AF for this mapping's GPSI, from the UE's
/// Ranging/SL privacy profile at the UDM ([`profile_allows`]).
async fn authorise(af_id: &str, info: &Value) -> Result<(), Box<SbiResponse>> {
    let (_, gpsi) = mapping_of(info)
        .map_err(|e| Box::new(send_bad_request(&e, Some("MANDATORY_IE_INCORRECT"))))?;
    let unavailable = |e: String| {
        log::warn!("UE ID mapping authorisation for {gpsi}: {e}");
        Box::new(nextgcore_sbi::server::send_error(
            503,
            "Service Unavailable",
            &e,
            None,
        ))
    };
    let Some(udm) = nef_self().read().ok().and_then(|c| c.udm_sdm_uri()) else {
        return Err(unavailable(
            "no UDM is configured (--udm-sdm-uri / --udm-uri)".into(),
        ));
    };
    let (host, port) =
        crate::parse_host_port(&udm).ok_or_else(|| unavailable("invalid UDM URI".into()))?;
    let client = crate::service_client(&host, port, nextgcore_sbi::types::NfType::Udm);
    let resp = client
        .get(&format!("/nudm-sdm/v2/{gpsi}/lcs-privacy-data"))
        .await
        .map_err(|e| unavailable(format!("UDM read failed: {e}")))?;
    let profile = match resp.status {
        200 => serde_json::from_str::<Value>(resp.http.content.as_deref().unwrap_or("null"))
            .unwrap_or(Value::Null),
        404 => Value::Null,
        s => return Err(unavailable(format!("UDM answered {s}"))),
    };
    if profile_allows(&profile, af_id) {
        return Ok(());
    }
    log::info!("UE ID mapping for {gpsi} refused: AF {af_id} is not authorised for the UE");
    Err(Box::new(nextgcore_sbi::server::send_forbidden(
        "the AF is not authorised for this UE's Ranging/SL positioning (TS 29.522 §4.4.32.4)",
        None,
    )))
}

/// Why a UDR write did not happen.
#[derive(Debug)]
enum UdrWrite {
    /// The UDR refused it: the ID or the GPSI is in another mapping (1:1).
    Conflict,
    /// The UDR could not be reached or failed.
    Failed(String),
}

/// Store `info` in the UDR under `id` (TS 29.519 §6.2.27 PUT). The UDR's 403
/// for an ID or GPSI another mapping already has is [`UdrWrite::Conflict`].
async fn udr_put(udr: &str, id: &str, info: &Value) -> Result<(), UdrWrite> {
    let (host, port) =
        crate::parse_host_port(udr).ok_or_else(|| UdrWrite::Failed("invalid UDR URI".into()))?;
    let client = crate::service_client(&host, port, nextgcore_sbi::types::NfType::Udr);
    let resp = client
        .put_json(
            &format!("/nudr-dr/v2/application-data/ueid-mappings/{id}"),
            info,
        )
        .await
        .map_err(|e| UdrWrite::Failed(format!("UDR write failed: {e}")))?;
    match resp.status {
        200 | 201 | 204 => Ok(()),
        403 => Err(UdrWrite::Conflict),
        s => Err(UdrWrite::Failed(format!("UDR write answered {s}"))),
    }
}

/// Remove the UDR's mapping `id` (TS 29.519 §6.2.27 DELETE). A 404 is gone
/// already.
async fn udr_delete(udr: &str, id: &str) -> Result<(), String> {
    let (host, port) = crate::parse_host_port(udr).ok_or("invalid UDR URI")?;
    let client = crate::service_client(&host, port, nextgcore_sbi::types::NfType::Udr);
    let resp = client
        .delete(&format!("/nudr-dr/v2/application-data/ueid-mappings/{id}"))
        .await
        .map_err(|e| format!("UDR delete failed: {e}"))?;
    matches!(resp.status, 200 | 204 | 404)
        .then_some(())
        .ok_or(format!("UDR delete answered {}", resp.status))
}

/// Serialises every change this NEF makes to a provisioning (its UDR write or
/// delete, and its record), so two requests on one ppId cannot interleave.
static WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn json(status: u16, v: &Value) -> SbiResponse {
    SbiResponse::with_status(status).with_body(v.to_string(), "application/json")
}

fn body_of(request: &SbiRequest) -> Result<Value, Box<SbiResponse>> {
    let raw = request.http.content.as_deref().ok_or_else(|| {
        Box::new(send_bad_request(
            "Missing request body",
            Some("MANDATORY_IE_MISSING"),
        ))
    })?;
    match serde_json::from_str::<Value>(raw) {
        Ok(v) if v.is_object() => Ok(v),
        _ => Err(Box::new(send_bad_request(
            "The body is not a JSON object",
            Some("INVALID_MSG_FORMAT"),
        ))),
    }
}

/// `/3gpp-ueid/v1/{afId}/pp[/{ppId}]`, as dispatched by the router.
pub async fn route(
    method: &str,
    af_id: &str,
    pp_id: Option<&str>,
    request: &SbiRequest,
) -> SbiResponse {
    let caller = match crate::authenticated_client_id(request, crate::northbound_auth()) {
        Ok(id) => id,
        Err(why) => return crate::refuse_unidentified("UE ID mapping provisioning", &why),
    };
    if !crate::valid_ue_identity(af_id) || pp_id.is_some_and(|p| !crate::valid_ue_identity(p)) {
        return send_bad_request("Invalid afId or ppId", Some("INVALID_MSG_FORMAT"));
    }
    let Some(udr) = nef_self().read().ok().and_then(|c| c.udr_uri()) else {
        log::warn!("UE ID mapping provisioning refused: no --udr-uri configured");
        return nextgcore_sbi::server::send_error(
            503,
            "Service Unavailable",
            "no UDR is configured for UE ID mapping provisioning",
            None,
        );
    };
    let caller = caller.as_deref();
    let not_found = || send_not_found("UE ID Mapping Information Provisioning not found", None);
    let owned = |id: &str| {
        nef_self()
            .read()
            .ok()
            .and_then(|c| c.ueid_provisioning_find(id))
            .filter(|p| p.is_owned_by(caller, af_id))
    };
    match (pp_id, method) {
        (None, "GET") => {
            let list: Vec<Value> = nef_self()
                .read()
                .map(|c| c.ueid_provisionings_of(af_id))
                .unwrap_or_default()
                .into_iter()
                .filter(|p| p.is_owned_by(caller, af_id))
                .map(|p| p.info)
                .collect();
            json(200, &Value::Array(list))
        }
        (None, "POST") => {
            let info = match body_of(request) {
                Ok(v) => v,
                Err(r) => return *r,
            };
            if let Err(r) = authorise(af_id, &info).await {
                return *r;
            }
            let id = uuid::Uuid::new_v4().simple().to_string();
            let _w = WRITES.lock().await;
            store(&udr, af_id, &id, caller, info, None, 201).await
        }
        (Some(id), "GET") => match owned(id) {
            Some(p) => json(200, &p.info),
            None => not_found(),
        },
        (Some(id), "PUT" | "PATCH") => {
            let Some(current) = owned(id) else {
                return not_found();
            };
            let body = match body_of(request) {
                Ok(v) => v,
                Err(r) => return *r,
            };
            // PATCH: a UeIdMappingInfoPatch replaces the members it names.
            let info = if method == "PATCH" {
                let mut merged = current.info.clone();
                if let Some(m) = body.get("rsUeIdMappingInfo") {
                    merged["rsUeIdMappingInfo"] = m.clone();
                }
                merged
            } else {
                body
            };
            // The new GPSI is authorised in its own right: an AF allowed for
            // one UE cannot move the mapping onto another.
            if let Err(r) = authorise(af_id, &info).await {
                return *r;
            }
            let _w = WRITES.lock().await;
            // Read again under the lock: a DELETE may have overtaken this.
            let Some(current) = owned(id) else {
                return not_found();
            };
            store(
                &udr,
                af_id,
                id,
                current.owner_id.as_deref(),
                info,
                Some(current.info),
                200,
            )
            .await
        }
        (Some(id), "DELETE") => {
            let _w = WRITES.lock().await;
            if owned(id).is_none() {
                return not_found();
            }
            if let Err(e) = udr_delete(&udr, id).await {
                log::warn!("UE ID mapping {id}: {e}");
                return nextgcore_sbi::server::send_error(503, "Service Unavailable", &e, None);
            }
            nef_self()
                .read()
                .ok()
                .and_then(|c| c.ueid_provisioning_remove(id));
            log::info!("UE ID mapping provisioning {id} of AF {af_id} deleted");
            SbiResponse::with_status(204)
        }
        (None, _) => send_method_not_allowed(method, "pp"),
        (Some(_), _) => send_method_not_allowed(method, "pp/{ppId}"),
    }
}

/// Write `info` to the UDR under `id`, then hold the provisioning, and answer
/// `status` (201 with a Location for a create, 200 for an update). `previous`
/// is an update's mapping before, put back if the provisioning cannot be held.
async fn store(
    udr: &str,
    af_id: &str,
    id: &str,
    owner: Option<&str>,
    info: Value,
    previous: Option<Value>,
    status: u16,
) -> SbiResponse {
    match udr_put(udr, id, &info).await {
        Ok(()) => {}
        Err(UdrWrite::Conflict) => {
            log::info!("UE ID mapping {id} of AF {af_id} refused by the UDR: not 1:1");
            return nextgcore_sbi::server::send_forbidden(
                "the Application Layer ID or the GPSI is already mapped otherwise; only 1:1 \
                 mappings are supported (TS 29.522 §4.4.32.1)",
                None,
            );
        }
        Err(UdrWrite::Failed(e)) => {
            log::warn!("UE ID mapping {id}: {e}");
            return nextgcore_sbi::server::send_error(503, "Service Unavailable", &e, None);
        }
    }
    let pp = NefUeIdProvisioning {
        id: id.to_string(),
        af_id: af_id.to_string(),
        owner_id: owner.map(str::to_string),
        info: info.clone(),
    };
    let held = nef_self()
        .read()
        .map_err(|_| "NEF context lock poisoned".to_string())
        .and_then(|c| c.ueid_provisioning_put(pp).map_err(|e| format!("{e:?}")));
    if let Err(e) = held {
        // Not held: undo the UDR write, so no mapping exists that no AF can
        // manage, and an update leaves the previous mapping in place.
        match &previous {
            Some(prev) => {
                let _ = udr_put(udr, id, prev).await;
            }
            None => {
                let _ = udr_delete(udr, id).await;
            }
        }
        log::warn!("UE ID mapping {id} not held: {e}");
        return nextgcore_sbi::server::send_error(
            503,
            "Service Unavailable",
            &format!("the provisioning could not be held: {e}"),
            None,
        );
    }
    log::info!("UE ID mapping provisioning {id} of AF {af_id} stored at the UDR");
    let resp = json(status, &info);
    if status == 201 {
        resp.with_header("Location", location(af_id, id))
    } else {
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NorthboundAuth, TEST_NORTHBOUND_AUTH};
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type UdrDocs = Arc<Mutex<HashMap<String, Value>>>;

    /// One stub for both southbound peers:
    /// - the UDR's TS 29.519 `ueid-mappings`, from memory, holding 1:1 as udrd
    ///   does (`handle_ueid_mappings`);
    /// - the UDM's `/nudm-sdm/v2/{gpsi}/lcs-privacy-data`, from `profiles`, by
    ///   GPSI (404 without one).
    async fn peers(profiles: HashMap<String, Value>) -> (SbiServer, String, UdrDocs) {
        let docs: UdrDocs = Arc::default();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let held = docs.clone();
        let profiles = Arc::new(profiles);
        server
            .start(move |req: SbiRequest| {
                let (docs, profiles) = (held.clone(), profiles.clone());
                async move {
                    let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                    if let Some(rest) = path.strip_prefix("/nudm-sdm/v2/") {
                        let gpsi = rest.trim_end_matches("/lcs-privacy-data");
                        return match profiles.get(gpsi) {
                            Some(p) => json(200, p),
                            None => SbiResponse::with_status(404),
                        };
                    }
                    let base = "/nudr-dr/v2/application-data/ueid-mappings";
                    let mut docs = docs.lock().unwrap();
                    let member =
                        |d: &Value, m: &str| d["rsUeIdMappingInfo"][m].as_str().map(str::to_string);
                    match (req.header.method.as_str(), path.strip_prefix(base)) {
                        ("PUT", Some(id)) => {
                            let id = id.trim_start_matches('/').to_string();
                            let v: Value =
                                serde_json::from_str(req.http.content.as_deref().unwrap()).unwrap();
                            let taken = docs.iter().any(|(other, d)| {
                                *other != id
                                    && (member(d, "appLayerId") == member(&v, "appLayerId")
                                        || member(d, "gpsi") == member(&v, "gpsi"))
                            });
                            if taken {
                                return SbiResponse::with_status(403);
                            }
                            let created = docs.insert(id, v).is_none();
                            SbiResponse::with_status(if created { 201 } else { 200 })
                        }
                        ("DELETE", Some(id)) => match docs.remove(id.trim_start_matches('/')) {
                            Some(_) => SbiResponse::with_status(204),
                            None => SbiResponse::with_status(404),
                        },
                        _ => SbiResponse::with_status(404),
                    }
                }
            })
            .await
            .expect("stub starts");
        (server, format!("http://127.0.0.1:{}", addr.port()), docs)
    }

    /// A profile naming `afs` as identified AFs allowed to range the UE.
    fn allowing(afs: &[&str]) -> Value {
        let externals: Vec<Value> = afs.iter().map(|a| json!({"afId": a})).collect();
        json!({"rangingSlPrivacyData": {"rangingSlUnrelatedClass": {
            "rangingSlDefaultUnrelatedClass": {},
            "rangingSlExternalUnrelatedClass": {"rangingSlAfExternals": externals}}}})
    }

    fn reset_with(peers_uri: &str) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        crate::nef_context_final();
        crate::nef_context_init(64, 64);
        if let Ok(mut c) = nef_self().write() {
            c.set_endpoints(None, None, None, None);
            c.set_udm_sdm_uri(Some(peers_uri.to_string()));
            c.set_udr_uri(Some(peers_uri.to_string()));
        }
    }

    const ENFORCED: NorthboundAuth = NorthboundAuth {
        oauth2: true,
        mtls: false,
    };

    /// A request from the AF whose verified identity is `af`.
    fn from(af: &str, method: &str, body: Option<Value>) -> SbiRequest {
        let mut r = match method {
            "POST" => SbiRequest::post("/"),
            "PUT" => SbiRequest::put("/"),
            "PATCH" => SbiRequest::patch("/"),
            "DELETE" => SbiRequest::delete("/"),
            _ => SbiRequest::get("/"),
        };
        if let Some(b) = body {
            r = r.with_body(b.to_string(), "application/json");
        }
        r.oauth2_subject = Some(af.to_string());
        r
    }

    async fn call(
        af: &str,
        af_id: &str,
        method: &str,
        pp: Option<&str>,
        body: Option<Value>,
    ) -> SbiResponse {
        TEST_NORTHBOUND_AUTH
            .scope(ENFORCED, route(method, af_id, pp, &from(af, method, body)))
            .await
    }

    fn mapping(app: &str, gpsi: &str) -> Value {
        json!({"rsUeIdMappingInfo": {"appLayerId": app, "gpsi": gpsi}})
    }

    fn body(r: &SbiResponse) -> Value {
        serde_json::from_str(r.http.content.as_deref().unwrap_or("null")).unwrap()
    }

    const AF1: &str = "aaaaaaaa-2260-4000-8000-00000000001a";
    const AF2: &str = "aaaaaaaa-2260-4000-8000-00000000002a";

    /// **#2260, TS 29.522 §4.4.32.4.** An AF's UE ID mapping provisioning is
    /// stored in the UDR (TS 29.519 §6.2.27) under the created resource's id:
    /// - the POST is answered 201 with the Location
    ///   `/3gpp-ueid/v1/{afId}/pp/{ppId}`;
    /// - GET lists it;
    /// - PATCH changes the GPSI at the UDR too;
    /// - DELETE removes it from the UDR.
    ///
    /// REVERT-VERIFIED: with the UDR write skipped in `store`, the UDR holds no
    /// mapping after the 201 ("stored in the UDR").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // the std guard serialises the NEF context
    async fn an_af_provisions_a_mapping_into_the_udr_2260() {
        let _g = crate::context::lock_nef_context_for_test();
        let (_p, uri, docs) = peers(HashMap::from([
            ("msisdn-12260".to_string(), allowing(&["af1"])),
            ("msisdn-22260".to_string(), allowing(&["af1"])),
        ]))
        .await;
        reset_with(&uri);
        let m = mapping("ue-a-2260", "msisdn-12260");
        let resp = call(AF1, "af1", "POST", None, Some(m.clone())).await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
        let loc = resp
            .http
            .headers
            .get("location")
            .cloned()
            .expect("Location");
        let pp = loc
            .strip_prefix("/3gpp-ueid/v1/af1/pp/")
            .expect("the spec's URI")
            .to_string();
        assert_eq!(body(&resp), m);
        assert_eq!(docs.lock().unwrap().get(&pp), Some(&m), "stored in the UDR");
        assert_eq!(body(&call(AF1, "af1", "GET", None, None).await), json!([m]));

        let patch = mapping("ue-a-2260", "msisdn-22260");
        let resp = call(AF1, "af1", "PATCH", Some(&pp), Some(patch.clone())).await;
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        assert_eq!(
            docs.lock().unwrap().get(&pp),
            Some(&patch),
            "the UDR follows"
        );

        assert_eq!(
            call(AF1, "af1", "DELETE", Some(&pp), None).await.status,
            204
        );
        assert!(docs.lock().unwrap().is_empty(), "gone from the UDR");
        assert_eq!(call(AF1, "af1", "GET", Some(&pp), None).await.status, 404);
    }

    /// **#2260, R48 BLOCKER on #2265: 1:1 for every write path.** AF2 may range
    /// both UEs here, so only 1:1 stands in its way. It cannot:
    /// - POST an exact copy of AF1's mapping, nor the same ID to its own GPSI;
    /// - PUT or PATCH its own mapping onto AF1's ID.
    /// In each case the answer is 403 and the UDR still maps the ID to one GPSI.
    /// It also cannot read or delete AF1's provisioning (404).
    ///
    /// REVERT-VERIFIED: with the UDR's 403 taken as a success in `udr_put`, the
    /// copy is stored (201), and the PUT then moves it (200).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // the std guard serialises the NEF context
    async fn an_af_cannot_copy_then_move_another_af_s_mapping_2260() {
        let _g = crate::context::lock_nef_context_for_test();
        let (_p, uri, docs) = peers(HashMap::from([
            ("msisdn-32260".to_string(), allowing(&["af1", "af2"])),
            ("msisdn-42260".to_string(), allowing(&["af2"])),
        ]))
        .await;
        reset_with(&uri);
        let resp = call(
            AF1,
            "af1",
            "POST",
            None,
            Some(mapping("victim-2260", "msisdn-32260")),
        )
        .await;
        assert_eq!(resp.status, 201);
        let pp1 = resp.http.headers["location"]
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        for (what, m) in [
            ("an exact copy", mapping("victim-2260", "msisdn-32260")),
            (
                "the ID to its own GPSI",
                mapping("victim-2260", "msisdn-42260"),
            ),
        ] {
            let resp = call(AF2, "af2", "POST", None, Some(m)).await;
            assert_eq!(resp.status, 403, "{what}: {:?}", resp.http.content);
        }
        // Its own mapping, then moved onto the victim's ID.
        let resp = call(
            AF2,
            "af2",
            "POST",
            None,
            Some(mapping("mine-2260", "msisdn-42260")),
        )
        .await;
        assert_eq!(resp.status, 201);
        let pp2 = resp.http.headers["location"]
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        for method in ["PUT", "PATCH"] {
            let resp = call(
                AF2,
                "af2",
                method,
                Some(&pp2),
                Some(mapping("victim-2260", "msisdn-42260")),
            )
            .await;
            assert_eq!(resp.status, 403, "{method} onto the victim's ID");
        }
        let victims: Vec<Value> = docs
            .lock()
            .unwrap()
            .values()
            .filter(|d| d["rsUeIdMappingInfo"]["appLayerId"] == "victim-2260")
            .cloned()
            .collect();
        assert_eq!(
            victims,
            vec![mapping("victim-2260", "msisdn-32260")],
            "one GPSI"
        );

        for method in ["GET", "DELETE"] {
            let resp = call(AF2, "af1", method, Some(&pp1), None).await;
            assert_eq!(resp.status, 404, "{method} by another AF");
        }
        assert!(docs.lock().unwrap().contains_key(&pp1));
    }

    /// **#2260, R48 MAJOR 3 on #2265, TS 29.522 §4.4.32.4.** The NEF authorises
    /// the AF for the mapping's GPSI with the UE's Ranging/SL privacy profile
    /// from the UDM. It refuses (403), and writes nothing, when:
    /// - the profile does not name the AF (an attacker cannot map a victim's ID,
    ///   still unmapped, to its own UE, nor claim the victim's GPSI with a junk
    ///   ID);
    /// - the profile disallows ranging for the UE;
    /// - the profile names the AF as `RANGINGSL_NOT_ALLOWED`;
    /// - the UE has no profile;
    /// - an update would move a mapping to a GPSI the AF is not allowed.
    ///
    /// REVERT-VERIFIED: with `authorise` not called on POST, the unnamed AF's
    /// mapping is stored (201).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // the std guard serialises the NEF context
    async fn an_af_the_ue_s_profile_does_not_name_cannot_map_its_gpsi_2260() {
        let _g = crate::context::lock_nef_context_for_test();
        let mut disallowed = allowing(&["af2"]);
        disallowed["rangingSlPrivacyData"]["rslppi"] =
            json!({"rangingSlPrivacyInd": "RANGINGSL_DISALLOWED"});
        let not_allowed = json!({"rangingSlPrivacyData": {"rangingSlUnrelatedClass": {
            "rangingSlDefaultUnrelatedClass": {},
            "rangingSlExternalUnrelatedClass": {"rangingSlAfExternals": [
                {"afId": "af2", "rangingSlPrivacyCheckRelatedAction": "RANGINGSL_NOT_ALLOWED"}]}}}});
        let (_p, uri, docs) = peers(HashMap::from([
            ("msisdn-52260".to_string(), allowing(&["af-victim"])),
            ("msisdn-62260".to_string(), disallowed),
            ("msisdn-72260".to_string(), not_allowed),
            ("msisdn-82260".to_string(), allowing(&["af2"])),
        ]))
        .await;
        reset_with(&uri);
        for (what, gpsi) in [
            ("the AF not named", "msisdn-52260"),
            ("ranging disallowed for the UE", "msisdn-62260"),
            ("RANGINGSL_NOT_ALLOWED for the AF", "msisdn-72260"),
            ("no profile", "msisdn-92260"),
        ] {
            let resp = call(
                AF2,
                "af2",
                "POST",
                None,
                Some(mapping("victim-id-2260", gpsi)),
            )
            .await;
            assert_eq!(resp.status, 403, "{what}: {:?}", resp.http.content);
        }
        assert!(docs.lock().unwrap().is_empty(), "nothing written");
        // Its own UE's GPSI is allowed, but it cannot then move the mapping onto
        // the victim's.
        let resp = call(
            AF2,
            "af2",
            "POST",
            None,
            Some(mapping("own-2260", "msisdn-82260")),
        )
        .await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
        let pp = resp.http.headers["location"]
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let resp = call(
            AF2,
            "af2",
            "PATCH",
            Some(&pp),
            Some(mapping("own-2260", "msisdn-52260")),
        )
        .await;
        assert_eq!(resp.status, 403);
        assert_eq!(
            docs.lock().unwrap().get(&pp),
            Some(&mapping("own-2260", "msisdn-82260"))
        );
    }

    #[test]
    fn the_profile_names_the_af_2260() {
        assert!(profile_allows(&allowing(&["af1"]), "af1"));
        assert!(!profile_allows(&allowing(&["af1"]), "af2"));
        assert!(!profile_allows(&json!({}), "af1"));
        let mut p = allowing(&["af1"]);
        p["rangingSlPrivacyData"]["rslpi"] = json!({"rangingSlPrivacyInd": "RANGINGSL_ALLOWED"});
        assert!(profile_allows(&p, "af1"), "the table's spelling");
    }
}
