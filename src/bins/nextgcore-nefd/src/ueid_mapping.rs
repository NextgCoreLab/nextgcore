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
//! - **Authorisation:** the caller's identity is the one this process verified
//!   (issue #110), never the `{afId}` alone. A provisioning is visible and
//!   changeable only by the AF that made it. Any other caller gets 404.
//! - **1:1 only.** TS 29.522 §4.4.32.1 NOTE: "only the Ranging/Sidelink UE ID
//!   Mapping Information between the Application Layer ID and the GPSI with 1:1
//!   mapping is supported". A mapping whose Application Layer ID is already
//!   mapped to another GPSI, or whose GPSI already has another ID, is refused
//!   with 403. Otherwise one AF could map a victim's ID to its own UE, and lmfd
//!   would then let that UE report as the victim.

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
/// the identity character set, since they reach the UDR's query.
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

/// The UDR's mappings for `param=value` (TS 29.519 §6.2.26 GET).
async fn udr_mappings(
    udr: &str,
    param: &str,
    value: &str,
) -> Result<Vec<(String, String)>, String> {
    let (host, port) = crate::parse_host_port(udr).ok_or("invalid UDR URI")?;
    let client = crate::service_client(&host, port, nextgcore_sbi::types::NfType::Udr);
    let resp = client
        .get(&format!(
            "/nudr-dr/v2/application-data/ueid-mappings?{param}={value}"
        ))
        .await
        .map_err(|e| format!("UDR read failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!("UDR read answered {}", resp.status));
    }
    let body: Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or("null"))
        .map_err(|e| format!("UDR read: {e}"))?;
    Ok(body
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| mapping_of(m).ok())
        .collect())
}

/// TS 29.522 §4.4.32.1 NOTE: refuse a mapping that would make the ID or the
/// GPSI map 1:N. `own` is the provisioning's current mapping, which may stay.
async fn one_to_one(
    udr: &str,
    want: &(String, String),
    own: Option<&(String, String)>,
) -> Result<(), SbiResponse> {
    let unavailable = |e: String| {
        log::warn!("UE ID mapping 1:1 check: {e}");
        nextgcore_sbi::server::send_error(503, "Service Unavailable", &e, None)
    };
    let mut existing = udr_mappings(udr, "app-layer-ids", &want.0)
        .await
        .map_err(unavailable)?;
    existing.extend(
        udr_mappings(udr, "gpsis", &want.1)
            .await
            .map_err(unavailable)?,
    );
    let foreign = existing.iter().any(|m| m != want && Some(m) != own);
    if foreign {
        return Err(nextgcore_sbi::server::send_forbidden(
            "the Application Layer ID or the GPSI is already mapped otherwise; only 1:1 \
             mappings are supported (TS 29.522 §4.4.32.1)",
            None,
        ));
    }
    Ok(())
}

/// Store `info` in the UDR under `id` (TS 29.519 §6.2.27 PUT).
async fn udr_put(udr: &str, id: &str, info: &Value) -> Result<(), String> {
    let (host, port) = crate::parse_host_port(udr).ok_or("invalid UDR URI")?;
    let client = crate::service_client(&host, port, nextgcore_sbi::types::NfType::Udr);
    let resp = client
        .put_json(
            &format!("/nudr-dr/v2/application-data/ueid-mappings/{id}"),
            info,
        )
        .await
        .map_err(|e| format!("UDR write failed: {e}"))?;
    matches!(resp.status, 200 | 201 | 204)
        .then_some(())
        .ok_or(format!("UDR write answered {}", resp.status))
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
            let want = match mapping_of(&info) {
                Ok(m) => m,
                Err(e) => return send_bad_request(&e, Some("MANDATORY_IE_INCORRECT")),
            };
            if let Err(r) = one_to_one(&udr, &want, None).await {
                return r;
            }
            let id = uuid::Uuid::new_v4().simple().to_string();
            store(&udr, af_id, &id, caller, info, 201).await
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
            let want = match mapping_of(&info) {
                Ok(m) => m,
                Err(e) => return send_bad_request(&e, Some("MANDATORY_IE_INCORRECT")),
            };
            let own = mapping_of(&current.info).ok();
            if let Err(r) = one_to_one(&udr, &want, own.as_ref()).await {
                return r;
            }
            store(&udr, af_id, id, current.owner_id.as_deref(), info, 200).await
        }
        (Some(id), "DELETE") => {
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
/// `status` (201 with a Location for a create, 200 for an update).
async fn store(
    udr: &str,
    af_id: &str,
    id: &str,
    owner: Option<&str>,
    info: Value,
    status: u16,
) -> SbiResponse {
    if let Err(e) = udr_put(udr, id, &info).await {
        log::warn!("UE ID mapping {id}: {e}");
        return nextgcore_sbi::server::send_error(503, "Service Unavailable", &e, None);
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
        // manage.
        let _ = udr_delete(udr, id).await;
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

    /// A UDR serving TS 29.519 §6.2.26/§6.2.27 `ueid-mappings` from memory.
    async fn udr_stub() -> (SbiServer, String, UdrDocs) {
        let docs: UdrDocs = Arc::default();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        let held = docs.clone();
        server
            .start(move |req: SbiRequest| {
                let docs = held.clone();
                async move {
                    let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                    let base = "/nudr-dr/v2/application-data/ueid-mappings";
                    let mut docs = docs.lock().unwrap();
                    match (req.header.method.as_str(), path.strip_prefix(base)) {
                        ("GET", Some("")) => {
                            let by = |name: &str, member: &str| {
                                req.http
                                    .params
                                    .get(name)
                                    .map(|v| (member.to_string(), v.clone()))
                            };
                            let filter = by("app-layer-ids", "appLayerId").or(by("gpsis", "gpsi"));
                            let hits: Vec<Value> = docs
                                .values()
                                .filter(|d| {
                                    filter.as_ref().is_none_or(|(m, v)| {
                                        d["rsUeIdMappingInfo"][m.as_str()].as_str()
                                            == Some(v.as_str())
                                    })
                                })
                                .cloned()
                                .collect();
                            json(200, &Value::Array(hits))
                        }
                        ("PUT", Some(id)) => {
                            let v: Value =
                                serde_json::from_str(req.http.content.as_deref().unwrap()).unwrap();
                            let created = docs.insert(id.trim_start_matches('/').to_string(), v);
                            SbiResponse::with_status(if created.is_none() { 201 } else { 200 })
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
            .expect("UDR stub starts");
        (server, format!("http://127.0.0.1:{}", addr.port()), docs)
    }

    fn reset_with_udr(udr: &str) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        crate::nef_context_final();
        crate::nef_context_init(64, 64);
        if let Ok(mut c) = nef_self().write() {
            c.set_endpoints(None, None, None, None);
            c.set_udm_sdm_uri(None);
            c.set_udr_uri(Some(udr.to_string()));
        }
    }

    const ENFORCED: NorthboundAuth = NorthboundAuth {
        oauth2: true,
        mtls: false,
    };

    /// A request from the AF whose verified identity is `af`.
    fn from(af: &str, method: &str, path: &str, body: Option<Value>) -> SbiRequest {
        let mut r = match method {
            "POST" => SbiRequest::post(path),
            "PUT" => SbiRequest::put(path),
            "PATCH" => SbiRequest::patch(path),
            "DELETE" => SbiRequest::delete(path),
            _ => SbiRequest::get(path),
        };
        if let Some(b) = body {
            r = r.with_body(b.to_string(), "application/json");
        }
        r.oauth2_subject = Some(af.to_string());
        r
    }

    fn mapping(app: &str, gpsi: &str) -> Value {
        json!({"rsUeIdMappingInfo": {"appLayerId": app, "gpsi": gpsi}})
    }

    fn body(r: &SbiResponse) -> Value {
        serde_json::from_str(r.http.content.as_deref().unwrap_or("null")).unwrap()
    }

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
        let (_udr, udr_uri, docs) = udr_stub().await;
        reset_with_udr(&udr_uri);
        let af = "aaaaaaaa-2260-4000-8000-00000000000a";
        let m = mapping("ue-a-2260", "msisdn-12260");
        let resp = TEST_NORTHBOUND_AUTH
            .scope(
                ENFORCED,
                route(
                    "POST",
                    "af1",
                    None,
                    &from(af, "POST", "/3gpp-ueid/v1/af1/pp", Some(m.clone())),
                ),
            )
            .await;
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

        let list = TEST_NORTHBOUND_AUTH
            .scope(
                ENFORCED,
                route("GET", "af1", None, &from(af, "GET", "/", None)),
            )
            .await;
        assert_eq!(body(&list), json!([m]));

        let patch =
            json!({"rsUeIdMappingInfo": {"appLayerId": "ue-a-2260", "gpsi": "msisdn-22260"}});
        let resp = TEST_NORTHBOUND_AUTH
            .scope(
                ENFORCED,
                route(
                    "PATCH",
                    "af1",
                    Some(&pp),
                    &from(af, "PATCH", "/", Some(patch.clone())),
                ),
            )
            .await;
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        assert_eq!(
            docs.lock().unwrap().get(&pp),
            Some(&patch),
            "the UDR follows"
        );

        let resp = TEST_NORTHBOUND_AUTH
            .scope(
                ENFORCED,
                route("DELETE", "af1", Some(&pp), &from(af, "DELETE", "/", None)),
            )
            .await;
        assert_eq!(resp.status, 204);
        assert!(docs.lock().unwrap().is_empty(), "gone from the UDR");
        let resp = TEST_NORTHBOUND_AUTH
            .scope(
                ENFORCED,
                route("GET", "af1", Some(&pp), &from(af, "GET", "/", None)),
            )
            .await;
        assert_eq!(resp.status, 404);
    }

    /// **#2260, TS 29.522 §4.4.32.1 NOTE (1:1 only), and ownership.** A second
    /// AF cannot map an Application Layer ID that is already mapped to another
    /// GPSI (403, the UDR is unchanged), and it cannot read or delete the first
    /// AF's provisioning (404). Without this, an AF could map a victim's ID to its
    /// own UE, and lmfd would let that UE report as the victim.
    ///
    /// REVERT-VERIFIED: with `one_to_one` accepting everything, the second
    /// mapping is stored (201) and the ID maps to two GPSIs at the UDR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // the std guard serialises the NEF context
    async fn an_id_maps_to_one_gpsi_and_only_its_af_manages_it_2260() {
        let _g = crate::context::lock_nef_context_for_test();
        let (_udr, udr_uri, docs) = udr_stub().await;
        reset_with_udr(&udr_uri);
        let (af1, af2) = (
            "aaaaaaaa-2260-4000-8000-00000000001a",
            "aaaaaaaa-2260-4000-8000-00000000002a",
        );
        let resp = TEST_NORTHBOUND_AUTH
            .scope(
                ENFORCED,
                route(
                    "POST",
                    "af1",
                    None,
                    &from(
                        af1,
                        "POST",
                        "/",
                        Some(mapping("victim-2260", "msisdn-32260")),
                    ),
                ),
            )
            .await;
        assert_eq!(resp.status, 201);
        let pp = resp.http.headers["location"]
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        for (what, m) in [
            (
                "the ID to another GPSI",
                mapping("victim-2260", "msisdn-42260"),
            ),
            (
                "the GPSI to another ID",
                mapping("other-2260", "msisdn-32260"),
            ),
        ] {
            let resp = TEST_NORTHBOUND_AUTH
                .scope(
                    ENFORCED,
                    route("POST", "af2", None, &from(af2, "POST", "/", Some(m))),
                )
                .await;
            assert_eq!(resp.status, 403, "{what}: {:?}", resp.http.content);
        }
        assert_eq!(docs.lock().unwrap().len(), 1, "the UDR is unchanged");

        for method in ["GET", "DELETE"] {
            let resp = TEST_NORTHBOUND_AUTH
                .scope(
                    ENFORCED,
                    route(method, "af1", Some(&pp), &from(af2, method, "/", None)),
                )
                .await;
            assert_eq!(resp.status, 404, "{method} by another AF");
        }
        assert_eq!(docs.lock().unwrap().len(), 1);

        // A mapping without its GPSI is refused before the UDR is asked.
        let resp = TEST_NORTHBOUND_AUTH
            .scope(
                ENFORCED,
                route(
                    "POST",
                    "af1",
                    None,
                    &from(
                        af1,
                        "POST",
                        "/",
                        Some(json!({"rsUeIdMappingInfo": {"appLayerId": "x"}})),
                    ),
                ),
            )
            .await;
        assert_eq!(resp.status, 400);
    }
}
