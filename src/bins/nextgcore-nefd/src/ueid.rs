//! Demo D445A (nextgsim#480): AF-facing UE ID retrieval, `POST
//! /3gpp-ueid/v1/retrieve`.
//!
//! # What it does
//!
//! An AF names a UE by the source address of its traffic and gets back the UE's
//! External Identifier (TS 23.502 §4.15.10, "AF specific UE ID retrieval"):
//!
//! 1. The request is a TS 29.522 `UeIdReq` `{afId, ueIpAddr: {ipv4Addr}}`.
//! 2. Steps 7-8: `Nbsf_Management_Discovery` by `ipv4Addr` (TS 29.521
//!    `GET /nbsf-management/v1/pcfBindings`) gives the UE's SUPI.
//! 3. Steps 9-10: `Nudm_SDM_Get` GetSupiOrGpsi (TS 29.503
//!    `GET /nudm-sdm/v2/{supi}/id-translation-result?requested-gpsi-type=EXT_ID`)
//!    gives the `extid-` GPSI.
//! 4. The answer is a TS 29.522 `UeIdInfo` `{externalId}`: the bare
//!    `username@realm`, with no `extid-` prefix. Without an External Identifier
//!    the answer is 404; an MSISDN is never handed out instead.
//!
//! The AF then names the UE by that `externalId` in a T8 monitoring request,
//! which the existing GPSI resolution ([`crate::resolve_gpsi_to_supi`]) turns back
//! into the SUPI through the same UDM operation.
//!
//! # Labelled deviations (why this is demo code)
//!
//! - **The External Identifier is per subscriber, not per AF.** udmd ignores
//!   `af-id` / `app-port-id`, so every AF gets the same identifier. §4.15.10's
//!   identifier is AF-specific.
//! - **NAT is not handled.** Steps 3-6 (`Nupf_GetUEPrivateIPaddrAndIdentifiers`)
//!   are skipped: the demo runs the UPF without NAT toward the AF's network.
//! - **The token scope `nnef-ueid` is nextgcore NRF policy**, not 3GPP surface:
//!   the 3GPP OpenAPI of this northbound API defines no scope (TS 23.222 and
//!   TS 33.122 put it behind CAPIF). The NEF's NF profile offers `nnef-ueid` with
//!   service-level `allowedNfTypes: [AF]`, so the NRF mints that scope only for
//!   an AF-typed consumer (TS 29.510 §6.1.6.2.3, `authorize_access_token`).
//! - **TS 29.522 is not vendored.** The shapes follow the Rel-18 OpenAPI
//!   `TS29522_UEId.yaml` (3gpp-ueid 1.1.1): `UeIdReq` has `afId` (required) and
//!   exactly one of `ueIpAddr` / `ueMacAddr`; `UeIdInfo` has `externalId`
//!   (required). Only `ueIpAddr.ipv4Addr` is served.
//!
//! # Gating and auth
//!
//! The route exists only in a build with the `demo-d445a-fl-t8` cargo feature,
//! and answers only while `demo.d445a-fl-t8` is active; otherwise it is the
//! router's ordinary 404. It checks its own bearer token whatever the listener
//! does, and fails closed: no or an invalid token is 401, a valid token without
//! the `nnef-ueid` scope is 403, and unavailable verification keys are 503. No
//! identity is returned in any of those cases.
//!
//! The listener-wide `NEXTGCORE_SBI_OAUTH2_REQUIRE` is NOT what protects this
//! route, and must stay off in the demo: nextgcore-sbi applies it to every route,
//! including the producer notification sink, and amfd and udmd send their
//! notifications without a token (TS 33.501 §13.4.1; nextgcore#1421). It would
//! also require the path's API name (`3gpp-ueid`) as the scope.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_method_not_allowed, send_not_found,
};

/// The demo key, as written under `demo:`.
pub const DEMO_KEY: &str = "d445a-fl-t8";

/// The D445A demo as nefd knows it. nefd behaves the same in both modes; the
/// modes are the AF's and the UE's.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: &["t8-exclusion", "poisoned-ue"],
    requires: &[],
};

/// The token scope the route requires, and the NF service name the NEF's
/// profile offers to AF-typed consumers (nextgcore NRF policy).
pub const SERVICE_NAME: &str = "nnef-ueid";

/// The northbound API name of TS 29.522 UE ID retrieval.
pub const API_NAME: &str = "3gpp-ueid";

/// Who the route asks, and what it verifies tokens with.
pub struct UeIdState {
    /// BSF API root (`--bsf-uri`).
    pub bsf_uri: String,
    /// UDM API root for Nudm_SDM (`--udm-sdm-uri`, else `--udm-uri`).
    pub udm_uri: String,
    /// The NRF's keys.
    pub jwks: nextgcore_sbi::oauth::JwksCache,
}

static STATE: OnceLock<Arc<UeIdState>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_STATE: std::cell::RefCell<Option<Arc<UeIdState>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only: serve the route on this thread with `state` for the guard's
/// lifetime, without installing the process-wide state.
#[cfg(test)]
pub(crate) struct ServingOnThisThread;

#[cfg(test)]
impl ServingOnThisThread {
    pub(crate) fn new(state: Arc<UeIdState>) -> Self {
        TEST_STATE.with(|s| *s.borrow_mut() = Some(state));
        Self
    }
}

#[cfg(test)]
impl Drop for ServingOnThisThread {
    fn drop(&mut self) {
        TEST_STATE.with(|s| *s.borrow_mut() = None);
    }
}

fn current() -> Option<Arc<UeIdState>> {
    #[cfg(test)]
    if let Some(s) = TEST_STATE.with(|s| s.borrow().clone()) {
        return Some(s);
    }
    STATE.get().cloned()
}

/// Whether this process serves UE ID retrieval.
pub fn serving() -> bool {
    current().is_some()
}

/// Decide once at startup, before the NRF registration, from the demo's active
/// mode. With the demo active it needs a BSF, a UDM and an NRF; a missing one is
/// a startup error rather than a route that can only answer 503.
pub fn install(
    mode: Option<&str>,
    bsf_uri: Option<String>,
    udm_uri: Option<String>,
    nrf_uri: &str,
) -> Result<bool, String> {
    let Some(mode) = mode else {
        return Ok(false);
    };
    let state = configure(bsf_uri, udm_uri, nrf_uri)?;
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "ueid: on (mode={mode}; POST /{API_NAME}/v1/retrieve, OAuth2 scope {SERVICE_NAME} \
         required, BSF {}, UDM {}, keys {})",
        state.bsf_uri,
        state.udm_uri,
        state.jwks.jwks_uri()
    );
    let _ = STATE.set(Arc::new(state));
    Ok(true)
}

/// The route's state from the startup flags, or why it cannot be served.
fn configure(
    bsf_uri: Option<String>,
    udm_uri: Option<String>,
    nrf_uri: &str,
) -> Result<UeIdState, String> {
    let need = |what: &str, flag: &str, v: Option<String>| -> Result<String, String> {
        match v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            Some(uri)
                if (uri.starts_with("http://") || uri.starts_with("https://"))
                    && crate::parse_host_port(&uri).is_some() =>
            {
                Ok(uri)
            }
            Some(uri) => Err(format!(
                "demo {DEMO_KEY}: {flag} {uri:?} is not an http(s)://host:port URI"
            )),
            None => Err(format!(
                "demo {DEMO_KEY}: UE ID retrieval needs the {what} ({flag})"
            )),
        }
    };
    let bsf_uri = need("BSF", "--bsf-uri", bsf_uri)?;
    let udm_uri = need("UDM", "--udm-sdm-uri or --udm-uri", udm_uri)?;
    let nrf = need(
        "NRF that issues AF tokens",
        "--nrf-uri",
        Some(nrf_uri.to_string()),
    )?;
    Ok(UeIdState {
        bsf_uri,
        udm_uri,
        jwks: nextgcore_sbi::oauth::JwksCache::for_nrf(&nrf),
    })
}

/// The `nfServices[]` entry the NEF profile adds while the route is served: the
/// service the NRF authorises the `nnef-ueid` scope against, for AF consumers
/// only.
pub fn nf_service(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    serde_json::json!({
        "serviceInstanceId": format!("{nf_instance_id}-{SERVICE_NAME}"),
        "serviceName": SERVICE_NAME,
        "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.1.1"}],
        "scheme": "http",
        "nfServiceStatus": "REGISTERED",
        "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
        "allowedNfTypes": ["AF"]
    })
}

// ---------------------------------------------------------------------------
// Outcomes, for /metrics.
// ---------------------------------------------------------------------------

static ANSWERED: AtomicU64 = AtomicU64::new(0);
static UNAUTHORIZED: AtomicU64 = AtomicU64::new(0);
static FORBIDDEN: AtomicU64 = AtomicU64::new(0);
static BAD_REQUEST: AtomicU64 = AtomicU64::new(0);
static NOT_FOUND: AtomicU64 = AtomicU64::new(0);
static UNAVAILABLE: AtomicU64 = AtomicU64::new(0);

const OUTCOMES: &[(&str, &AtomicU64)] = &[
    ("answered", &ANSWERED),
    ("unauthorized", &UNAUTHORIZED),
    ("forbidden", &FORBIDDEN),
    ("bad_request", &BAD_REQUEST),
    ("not_found", &NOT_FOUND),
    ("unavailable", &UNAVAILABLE),
];

/// Append `nef_ueid_requests_total{outcome}`.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# HELP nef_ueid_requests_total UE ID retrieval requests, by outcome (nextgsim#480)"
    );
    let _ = writeln!(out, "# TYPE nef_ueid_requests_total counter");
    for (outcome, n) in OUTCOMES {
        let _ = writeln!(
            out,
            "nef_ueid_requests_total{{outcome=\"{outcome}\"}} {}",
            n.load(Ordering::Relaxed)
        );
    }
}

// ---------------------------------------------------------------------------
// The route.
// ---------------------------------------------------------------------------

/// `/3gpp-ueid/v1/retrieve`, as dispatched by the router. With the demo off this
/// is the router's own 404, so the route does not exist.
pub async fn route(method: &str, path: &str, request: &SbiRequest) -> SbiResponse {
    let Some(state) = current() else {
        return send_not_found(&format!("Resource not found: {path}"), None);
    };
    if method != "POST" {
        return send_method_not_allowed(method, "retrieve");
    }
    retrieve(&state, request).await
}

/// Why a request was refused before any identity was looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No, malformed or unverifiable bearer token (401).
    Unauthorized(String),
    /// A valid token whose scope does not cover [`SERVICE_NAME`] (403).
    Forbidden(String),
    /// The keys to verify with are unavailable (503).
    Unavailable(String),
}

/// Verify the bearer token: signature against the NRF's keys, audience NEF,
/// expiry, and scope [`SERVICE_NAME`]. Returns the token's `sub` (the AF's
/// nfInstanceId).
pub async fn verify_token(
    jwks: &nextgcore_sbi::oauth::JwksCache,
    request: &SbiRequest,
) -> Result<String, Refusal> {
    use nextgcore_sbi::error::SbiError;
    let header = request.http.get_header("authorization").map(|s| s.as_str());
    let claims = match jwks.authorize_aud(header, Some("NEF")).await {
        Ok(c) => c,
        Err(SbiError::AuthorizationFailed(m)) => return Err(Refusal::Unauthorized(m)),
        Err(e) => return Err(Refusal::Unavailable(e.to_string())),
    };
    nextgcore_sbi::oauth::check_token_scope(&claims.scope, SERVICE_NAME)
        .map_err(|e| Refusal::Forbidden(e.to_string()))?;
    Ok(claims.sub)
}

fn problem(counter: &AtomicU64, response: SbiResponse) -> SbiResponse {
    counter.fetch_add(1, Ordering::Relaxed);
    response
}

/// A TS 29.522 `UeIdReq`, as far as this NEF serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeIdReq {
    pub af_id: String,
    pub ipv4: std::net::Ipv4Addr,
}

/// Parse a `UeIdReq` body. `afId` is required, and exactly one of `ueIpAddr` /
/// `ueMacAddr`; only `ueIpAddr.ipv4Addr` is served.
pub fn parse_ue_id_req(body: Option<&str>) -> Result<UeIdReq, String> {
    let body = body.ok_or("missing request body")?;
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let af_id = match v.get("afId").and_then(|a| a.as_str()) {
        Some(a) if !a.is_empty() => a.to_string(),
        _ => return Err("afId is mandatory".into()),
    };
    match (v.get("ueIpAddr"), v.get("ueMacAddr")) {
        (Some(_), Some(_)) => Err("exactly one of ueIpAddr and ueMacAddr is allowed".into()),
        (None, None) => Err("one of ueIpAddr or ueMacAddr is mandatory".into()),
        (None, Some(_)) => Err("ueMacAddr is not supported by this NEF".into()),
        (Some(ip), None) => {
            let raw = ip
                .get("ipv4Addr")
                .and_then(|a| a.as_str())
                .ok_or("only ueIpAddr.ipv4Addr is supported by this NEF")?;
            let ipv4 = raw
                .parse()
                .map_err(|_| format!("ueIpAddr.ipv4Addr {raw:?} is not an IPv4 address"))?;
            Ok(UeIdReq { af_id, ipv4 })
        }
    }
}

/// Handle one retrieval against `state`.
pub async fn retrieve(state: &UeIdState, request: &SbiRequest) -> SbiResponse {
    let af = match verify_token(&state.jwks, request).await {
        Ok(sub) => sub,
        Err(refusal) => {
            nextgcore_demo::demo_log!(
                warn,
                DEMO_KEY,
                "ueid refused: {refusal:?}; no identity returned"
            );
            return match refusal {
                Refusal::Unauthorized(m) => problem(
                    &UNAUTHORIZED,
                    nextgcore_sbi::server::send_unauthorized(&m, None).with_header(
                        "WWW-Authenticate",
                        "Bearer realm=\"5gc-sbi\", error=\"invalid_token\"",
                    ),
                ),
                Refusal::Forbidden(m) => problem(
                    &FORBIDDEN,
                    nextgcore_sbi::server::send_forbidden(&m, None).with_header(
                        "WWW-Authenticate",
                        format!("Bearer realm=\"5gc-sbi\", error=\"insufficient_scope\", scope=\"{SERVICE_NAME}\""),
                    ),
                ),
                Refusal::Unavailable(m) => problem(
                    &UNAVAILABLE,
                    send_error(503, "Service Unavailable", &m, None),
                ),
            };
        }
    };
    let req = match parse_ue_id_req(request.http.content.as_deref()) {
        Ok(r) => r,
        Err(why) => {
            return problem(
                &BAD_REQUEST,
                send_bad_request(&why, Some("MANDATORY_IE_INCORRECT")),
            )
        }
    };
    let supi = match bsf_supi(&state.bsf_uri, req.ipv4).await {
        Lookup::Found(supi) => supi,
        Lookup::NotFound(why) => {
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "ueid ipv4={} afId={} af={af}: no UE ({why})",
                req.ipv4,
                req.af_id
            );
            return problem(
                &NOT_FOUND,
                send_not_found("no UE is known at this address", Some("UE_NOT_FOUND")),
            );
        }
        Lookup::Unavailable(why) => {
            return problem(
                &UNAVAILABLE,
                send_error(503, "Service Unavailable", &why, None),
            )
        }
    };
    let external_id = match udm_external_id(&state.udm_uri, &supi).await {
        Lookup::Found(e) => e,
        Lookup::NotFound(why) => {
            nextgcore_demo::demo_log!(
                info,
                DEMO_KEY,
                "ueid ipv4={} afId={} af={af}: no External Identifier ({why})",
                req.ipv4,
                req.af_id
            );
            return problem(
                &NOT_FOUND,
                send_not_found(
                    "the UE at this address has no External Identifier",
                    Some("UE_NOT_FOUND"),
                ),
            );
        }
        Lookup::Unavailable(why) => {
            return problem(
                &UNAVAILABLE,
                send_error(503, "Service Unavailable", &why, None),
            )
        }
    };
    nextgcore_demo::demo_log!(
        info,
        DEMO_KEY,
        "ueid ipv4={} afId={} af={af} externalId={external_id}",
        req.ipv4,
        req.af_id
    );
    ANSWERED.fetch_add(1, Ordering::Relaxed);
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({ "externalId": external_id }))
        .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed"))
}

/// The outcome of one southbound lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Lookup {
    Found(String),
    NotFound(String),
    Unavailable(String),
}

fn client_for(uri: &str) -> Result<nextgcore_sbi::client::SbiClient, String> {
    let (host, port) = crate::parse_host_port(uri).ok_or_else(|| format!("bad URI {uri}"))?;
    Ok(crate::bounded_client(&host, port))
}

/// §4.15.10 steps 7-8: the SUPI of the PDU session bound to `ipv4`.
async fn bsf_supi(bsf_uri: &str, ipv4: std::net::Ipv4Addr) -> Lookup {
    let client = match client_for(bsf_uri) {
        Ok(c) => c,
        Err(e) => return Lookup::Unavailable(e),
    };
    let path = format!("/nbsf-management/v1/pcfBindings?ipv4Addr={ipv4}");
    match client.get(&path).await {
        Ok(r) if r.status == 200 => {
            let supi = r
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                .and_then(|v| v.get("supi")?.as_str().map(str::to_string));
            match supi {
                Some(s) if s.starts_with("imsi-") && crate::valid_ue_identity(&s) => {
                    Lookup::Found(s)
                }
                Some(s) => Lookup::NotFound(format!("the binding's supi {s:?} is not usable")),
                None => Lookup::NotFound("the binding carries no supi".into()),
            }
        }
        // TS 29.521 §5.3.2.3.1: 204 is "no binding matches".
        Ok(r) if r.status == 204 || r.status == 404 => {
            Lookup::NotFound(format!("BSF discovery answered {}", r.status))
        }
        Ok(r) if r.status == 400 => {
            // MULTIPLE_BINDING_INFO_FOUND: the address is ambiguous, so no one UE.
            Lookup::NotFound("BSF discovery answered 400 (ambiguous address)".into())
        }
        Ok(r) => Lookup::Unavailable(format!("BSF discovery answered {}", r.status)),
        Err(e) => Lookup::Unavailable(format!("BSF discovery failed: {e}")),
    }
}

/// §4.15.10 steps 9-10: the UE's External Identifier, bare (`username@realm`).
async fn udm_external_id(udm_uri: &str, supi: &str) -> Lookup {
    let client = match client_for(udm_uri) {
        Ok(c) => c,
        Err(e) => return Lookup::Unavailable(e),
    };
    let path = format!("/nudm-sdm/v2/{supi}/id-translation-result?requested-gpsi-type=EXT_ID");
    match client.get(&path).await {
        Ok(r) if r.status == 200 => {
            let gpsi = r
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                .and_then(|v| v.get("gpsi")?.as_str().map(str::to_string));
            match gpsi.as_deref().map(external_id_of_gpsi) {
                Some(Some(e)) => Lookup::Found(e.to_string()),
                Some(None) => Lookup::NotFound(format!(
                    "the UDM's gpsi {gpsi:?} is not an extid-username@realm"
                )),
                None => Lookup::NotFound("the UDM returned no EXT_ID gpsi".into()),
            }
        }
        Ok(r) if r.status == 404 => Lookup::NotFound("the UDM answered 404".into()),
        Ok(r) => Lookup::Unavailable(format!("UDM id-translation-result answered {}", r.status)),
        Err(e) => Lookup::Unavailable(format!("UDM id-translation-result failed: {e}")),
    }
}

/// The External Identifier inside an `extid-<username@realm>` GPSI, or `None`
/// for anything else (an `msisdn-` GPSI in particular: never handed out here).
pub fn external_id_of_gpsi(gpsi: &str) -> Option<&str> {
    let e = gpsi.strip_prefix("extid-")?;
    let (user, realm) = e.split_once('@')?;
    (!user.is_empty() && !realm.is_empty() && crate::valid_ue_identity(e)).then_some(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::sync::Mutex;

    const KID: &str = "nrf-es256";
    const IP: &str = "10.45.0.13";
    const SUPI: &str = "imsi-999700000000013";
    const EXT: &str = "ue013@fl.nextg";

    fn signing_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[0x48; 32]).expect("key")
    }

    fn token(sk: &p256::ecdsa::SigningKey, aud: &str, scope: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{KID}"}}"#);
        let claims = serde_json::json!({
            "iss": "NRF", "sub": "fl-af-1", "aud": aud, "scope": scope, "exp": exp, "iat": 0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn jwks(sk: &p256::ecdsa::SigningKey) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":KID,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    /// Every request a stub producer saw: (path, query parameters).
    type Seen = Arc<Mutex<Vec<(String, std::collections::HashMap<String, String>)>>>;

    /// A loopback stub producer answering with `answer`.
    async fn stub(
        answer: fn(&str, &std::collections::HashMap<String, String>) -> SbiResponse,
    ) -> (SbiServer, String, Seen) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Seen = Arc::default();
        let sink = Arc::clone(&seen);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                    let params: std::collections::HashMap<String, String> =
                        req.http.params.clone().into_iter().collect();
                    let resp = answer(&path, &params);
                    sink.lock().expect("seen").push((path, params));
                    resp
                }
            })
            .await
            .expect("stub starts");
        (server, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    /// The BSF: one binding, for [`IP`].
    fn bsf(_path: &str, q: &std::collections::HashMap<String, String>) -> SbiResponse {
        if q.get("ipv4Addr").map(String::as_str) == Some(IP) {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "supi": SUPI, "ipv4Addr": IP, "dnn": "internet",
                    "pcfFqdn": "pcf", "snssai": {"sst": 1}
                }))
                .unwrap()
        } else {
            SbiResponse::with_status(204)
        }
    }

    /// udmd's GetSupiOrGpsi over a subscriber with an MSISDN and an External
    /// Identifier: `requested-gpsi-type` filters exactly as udmd does, and with
    /// no filter the MSISDN comes first.
    fn udm(path: &str, q: &std::collections::HashMap<String, String>) -> SbiResponse {
        if path != format!("/nudm-sdm/v2/{SUPI}/id-translation-result") {
            return SbiResponse::with_status(404);
        }
        let gpsi = match q.get("requested-gpsi-type").map(String::as_str) {
            Some("EXT_ID") => format!("extid-{EXT}"),
            _ => "msisdn-491721070013".to_string(),
        };
        SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({"supi": SUPI, "gpsi": gpsi}))
            .unwrap()
    }

    /// udmd for a subscriber with no External Identifier: EXT_ID filters every
    /// GPSI out, so the result carries the SUPI alone.
    fn udm_msisdn_only(_path: &str, q: &std::collections::HashMap<String, String>) -> SbiResponse {
        let body = match q.get("requested-gpsi-type").map(String::as_str) {
            Some("EXT_ID") => serde_json::json!({"supi": SUPI}),
            _ => serde_json::json!({"supi": SUPI, "gpsi": "msisdn-491721070013"}),
        };
        SbiResponse::with_status(200).with_json_body(&body).unwrap()
    }

    async fn state(bsf_uri: &str, udm_uri: &str) -> Arc<UeIdState> {
        let jwks_cache = nextgcore_sbi::oauth::JwksCache::new("http://127.0.0.1:1/unused");
        jwks_cache.seed(jwks(&signing_key())).await;
        Arc::new(UeIdState {
            bsf_uri: bsf_uri.to_string(),
            udm_uri: udm_uri.to_string(),
            jwks: jwks_cache,
        })
    }

    fn request(ip: &str, bearer: Option<&str>) -> SbiRequest {
        let mut r = SbiRequest::post("/3gpp-ueid/v1/retrieve")
            .with_json_body(&serde_json::json!({"afId": "fl-af", "ueIpAddr": {"ipv4Addr": ip}}))
            .unwrap();
        if let Some(t) = bearer {
            r = r.with_header("Authorization", format!("Bearer {t}"));
        }
        r
    }

    fn body(resp: &SbiResponse) -> serde_json::Value {
        resp.http
            .content
            .as_deref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or(serde_json::Value::Null)
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// The criterion's happy path, end to end over the wire: BSF by address,
    /// then the UDM asked for the EXT_ID GPSI, then the bare `externalId`.
    ///
    /// The UDM stub answers an MSISDN when not asked for `EXT_ID`, so dropping
    /// the query parameter fails here (404), and so does returning the GPSI
    /// with its `extid-` prefix.
    #[test]
    fn retrieval_answers_the_bare_external_identifier() {
        runtime().block_on(async {
            let (_b, bsf_uri, bsf_seen) = stub(bsf).await;
            let (_u, udm_uri, udm_seen) = stub(udm).await;
            let st = state(&bsf_uri, &udm_uri).await;
            let t = token(&signing_key(), "NEF", SERVICE_NAME);
            let resp = retrieve(&st, &request(IP, Some(&t))).await;
            assert_eq!(resp.status, 200, "{:?}", resp.http.content);
            assert_eq!(body(&resp), serde_json::json!({"externalId": EXT}));
            let bsf_seen = bsf_seen.lock().unwrap().clone();
            assert_eq!(bsf_seen.len(), 1);
            assert_eq!(bsf_seen[0].0, "/nbsf-management/v1/pcfBindings");
            let udm_seen = udm_seen.lock().unwrap().clone();
            assert_eq!(
                udm_seen[0].1.get("requested-gpsi-type").map(String::as_str),
                Some("EXT_ID")
            );
        });
    }

    /// No External Identifier is a 404, and never the MSISDN instead. Neither is
    /// an address with no binding.
    #[test]
    fn no_external_identifier_or_no_ue_is_404_and_no_identity() {
        runtime().block_on(async {
            let (_b, bsf_uri, _) = stub(bsf).await;
            let (_u, udm_uri, _) = stub(udm_msisdn_only).await;
            let st = state(&bsf_uri, &udm_uri).await;
            let t = token(&signing_key(), "NEF", SERVICE_NAME);
            for ip in [IP, "10.45.0.99"] {
                let resp = retrieve(&st, &request(ip, Some(&t))).await;
                assert_eq!(resp.status, 404, "{ip}: {:?}", resp.http.content);
                let text = resp.http.content.clone().unwrap_or_default();
                assert!(
                    !text.contains("externalId")
                        && !text.contains("msisdn")
                        && !text.contains(SUPI),
                    "{ip}: a 404 names no identity: {text}"
                );
            }
        });
    }

    /// **Auth criterion**: no token, a token for another NF type's audience, a
    /// forged signature, or a token without the `nnef-ueid` scope (what any
    /// non-AF consumer holds, since the NRF grants that scope to AF types only)
    /// is 401/403, returns no identity, and reaches neither the BSF nor the UDM.
    #[test]
    fn an_unauthorised_caller_gets_401_or_403_and_no_identity() {
        runtime().block_on(async {
            let (_b, bsf_uri, bsf_seen) = stub(bsf).await;
            let (_u, udm_uri, udm_seen) = stub(udm).await;
            let st = state(&bsf_uri, &udm_uri).await;
            let other = p256::ecdsa::SigningKey::from_slice(&[0x11; 32]).unwrap();
            let cases: Vec<(&str, Option<String>, u16)> = vec![
                ("no token", None, 401),
                ("garbage", Some("not.a.jwt".to_string()), 401),
                (
                    "audience AMF",
                    Some(token(&signing_key(), "AMF", SERVICE_NAME)),
                    401,
                ),
                ("forged", Some(token(&other, "NEF", SERVICE_NAME)), 401),
                (
                    "T8 scope only",
                    Some(token(&signing_key(), "NEF", "nnef-eventexposure")),
                    403,
                ),
                (
                    "the API name, not the service",
                    Some(token(&signing_key(), "NEF", API_NAME)),
                    403,
                ),
            ];
            for (what, t, status) in cases {
                let resp = retrieve(&st, &request(IP, t.as_deref())).await;
                assert_eq!(resp.status, status, "{what}: {:?}", resp.http.content);
                let text = resp.http.content.clone().unwrap_or_default();
                assert!(
                    !text.contains(EXT) && !text.contains(SUPI),
                    "{what}: {text}"
                );
                assert!(resp.http.get_header("www-authenticate").is_some(), "{what}");
            }
            assert!(bsf_seen.lock().unwrap().is_empty(), "no lookup before auth");
            assert!(udm_seen.lock().unwrap().is_empty(), "no lookup before auth");
        });
    }

    /// **Demo off**: the route is the router's own 404, the same answer as a
    /// path that does not exist. On, the router reaches it (401 without a
    /// token), and only POST is allowed.
    #[test]
    fn the_route_exists_only_while_the_demo_is_on() {
        let rt = runtime();
        let path = "/3gpp-ueid/v1/retrieve";
        let off = rt.block_on(crate::nef_sbi_request_handler(request(IP, None)));
        let unknown = rt.block_on(crate::nef_sbi_request_handler(SbiRequest::post(
            "/3gpp-ueid/v1/elsewhere",
        )));
        assert_eq!(off.status, 404);
        assert_eq!(unknown.status, 404);
        assert_eq!(
            body(&off)["detail"],
            serde_json::json!(format!("Resource not found: {path}"))
        );

        let st = rt.block_on(state("http://127.0.0.1:1", "http://127.0.0.1:1"));
        let _on = ServingOnThisThread::new(st);
        let on = rt.block_on(crate::nef_sbi_request_handler(request(IP, None)));
        assert_eq!(on.status, 401, "{:?}", on.http.content);
        let get = rt.block_on(crate::nef_sbi_request_handler(SbiRequest::get(path)));
        assert_eq!(get.status, 405);
    }

    /// The NRF policy half of "AF-typed": while the route is served the NEF
    /// profile offers `nnef-ueid` to AF consumers only; otherwise not at all.
    #[test]
    fn the_profile_offers_nnef_ueid_to_af_only_while_serving() {
        let services = |p: &serde_json::Value| -> Vec<serde_json::Value> {
            p["nfServices"].as_array().cloned().unwrap_or_default()
        };
        let off = crate::build_nf_profile("nef-480", "10.0.0.9", 7817);
        assert!(services(&off)
            .iter()
            .all(|s| s["serviceName"] != SERVICE_NAME));

        let rt = runtime();
        let st = rt.block_on(state("http://127.0.0.1:1", "http://127.0.0.1:1"));
        let _on = ServingOnThisThread::new(st);
        let on = crate::build_nf_profile("nef-480", "10.0.0.9", 7817);
        let svc = services(&on)
            .into_iter()
            .find(|s| s["serviceName"] == SERVICE_NAME)
            .expect("nnef-ueid offered");
        assert_eq!(svc["allowedNfTypes"], serde_json::json!(["AF"]));
        assert!(services(&on)
            .iter()
            .any(|s| s["serviceName"] == "nnef-eventexposure"));
    }

    #[test]
    fn ue_id_req_shapes() {
        let ok = parse_ue_id_req(Some(r#"{"afId":"a","ueIpAddr":{"ipv4Addr":"10.45.0.2"}}"#));
        assert_eq!(
            ok,
            Ok(UeIdReq {
                af_id: "a".into(),
                ipv4: "10.45.0.2".parse().unwrap()
            })
        );
        for bad in [
            None,
            Some("{"),
            Some(r#"{"ueIpAddr":{"ipv4Addr":"10.45.0.2"}}"#),
            Some(r#"{"afId":"","ueIpAddr":{"ipv4Addr":"10.45.0.2"}}"#),
            Some(r#"{"afId":"a"}"#),
            Some(r#"{"afId":"a","ueMacAddr":"00-11-22-33-44-55"}"#),
            Some(
                r#"{"afId":"a","ueIpAddr":{"ipv4Addr":"10.45.0.2"},"ueMacAddr":"00-11-22-33-44-55"}"#,
            ),
            Some(r#"{"afId":"a","ueIpAddr":{"ipv6Addr":"2001:db8::1"}}"#),
            Some(r#"{"afId":"a","ueIpAddr":{"ipv4Addr":"10.45.0.300"}}"#),
        ] {
            assert!(parse_ue_id_req(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_an_extid_gpsi_yields_an_external_identifier() {
        assert_eq!(
            external_id_of_gpsi("extid-ue013@fl.nextg"),
            Some("ue013@fl.nextg")
        );
        for g in [
            "msisdn-491721070013",
            "ue013@fl.nextg",
            "extid-",
            "extid-noat",
            "extid-@realm",
            "extid-user@",
            "extid-a b@realm",
        ] {
            assert_eq!(external_id_of_gpsi(g), None, "{g}");
        }
    }

    /// Startup: the demo off needs nothing; on, it needs a BSF and a UDM. (Only
    /// `configure` is driven here: a successful `install` would set the
    /// process-wide state every other test reads.)
    #[test]
    fn startup_needs_a_bsf_and_a_udm_when_on() {
        assert_eq!(install(None, None, None, ""), Ok(false));
        let udm = || Some("http://udm:7777".to_string());
        let bsf = || Some("http://bsf:7777".to_string());
        let err = |r: Result<UeIdState, String>| r.err().expect("refused");
        assert!(err(configure(None, udm(), "http://nrf:7777")).contains("--bsf-uri"));
        assert!(err(configure(bsf(), None, "http://nrf:7777")).contains("--udm-sdm-uri"));
        assert!(
            err(configure(Some("bsf".into()), udm(), "http://nrf:7777")).contains("not an http")
        );
        assert!(err(configure(bsf(), udm(), "")).contains("--nrf-uri"));
        let ok = configure(bsf(), udm(), "http://nrf:7777").expect("configured");
        assert_eq!(ok.bsf_uri, "http://bsf:7777");
        assert!(ok.jwks.jwks_uri().starts_with("http://nrf:7777/"));
    }

    /// The toggle: this build knows the key and its two modes, rejects any
    /// other mode by name, and the kill switch turns it off.
    #[test]
    fn the_demo_block_is_checked_against_this_builds_registry() {
        let parse = |y: &str| {
            let root: serde_yaml::Value = serde_yaml::from_str(y).unwrap();
            nextgcore_demo::DemoConfig::from_root(&root)
                .and_then(|c| c.validate(&crate::demo_registry()))
        };
        for mode in ["t8-exclusion", "poisoned-ue"] {
            let a = parse(&format!(
                "demo: {{enabled: true, d445a-fl-t8: {{enabled: true, mode: {mode}}}}}"
            ))
            .unwrap();
            assert_eq!(a.mode(DEMO_KEY), Some(mode));
        }
        assert_eq!(
            parse("demo: {enabled: true, d445a-fl-t8: {enabled: true, mode: bogus}}"),
            Err(nextgcore_demo::DemoConfigError::UnknownMode {
                demo: DEMO_KEY.into(),
                mode: "bogus".into(),
                known: vec!["t8-exclusion", "poisoned-ue"],
            })
        );
        let killed =
            parse("demo: {enabled: false, d445a-fl-t8: {enabled: true, mode: t8-exclusion}}")
                .unwrap();
        assert!(killed.is_empty(), "the kill switch wins");
    }

    /// **Ordered chain, nefd's step**: while the demo is on, a delivered T8
    /// notification is logged at info with the demo prefix, the NEF
    /// subscription id and the reason, which is the line the EKS check orders
    /// between amfd's delivery and the AF's exclusion. Off, it stays at debug.
    #[test]
    fn a_delivered_t8_notification_is_an_info_demo_line_while_on() {
        nextgcore_core::test_log::init();
        let rt = runtime();
        let (_af, af_uri, _) = rt.block_on(stub(|_, _| SbiResponse::with_status(204)));
        let note = serde_json::json!({
            "subscription": "/3gpp-monitoring-event/v1/fl-af/subscriptions/sub-480-on",
            "monitoringEventReports": [{
                "monitoringType": "LOSS_OF_CONNECTIVITY",
                "lossOfConnectReason": "DEREGISTERED",
                "externalId": EXT
            }]
        });
        let dest = format!("{af_uri}/fl-af/v1/t8-notify/cb");

        let off = nextgcore_core::test_log::watch("sub-480-off");
        rt.block_on(crate::forward_notification_to_af(
            "sub-480-off",
            dest.clone(),
            note.clone(),
        ));
        let off = off.records();
        assert!(
            off.iter()
                .all(|r| r.starts_with("DEBUG") && !r.contains("[demo:")),
            "{off:?}"
        );

        let st = rt.block_on(state("http://127.0.0.1:1", "http://127.0.0.1:1"));
        let _on = ServingOnThisThread::new(st);
        let on = nextgcore_core::test_log::watch("sub-480-on");
        rt.block_on(crate::forward_notification_to_af("sub-480-on", dest, note));
        let on = on.records();
        assert_eq!(on.len(), 1, "{on:?}");
        assert!(on[0].starts_with("INFO"), "{on:?}");
        assert!(
            on[0].contains(
                "[demo:d445a-fl-t8] T8 delivery sub=sub-480-on \
                 monitoringType=LOSS_OF_CONNECTIVITY lossOfConnectReason=DEREGISTERED status=204"
            ),
            "{on:?}"
        );
    }

    /// The `/metrics` body names the outcomes; `nextg_demo_enabled` is
    /// render_common's, present only once a demo is installed.
    #[test]
    fn metrics_render_the_outcomes() {
        let out = crate::render_prometheus();
        for o in ["answered", "unauthorized", "forbidden", "not_found"] {
            assert!(
                out.contains(&format!("nef_ueid_requests_total{{outcome=\"{o}\"}}")),
                "{out}"
            );
        }
    }
}
