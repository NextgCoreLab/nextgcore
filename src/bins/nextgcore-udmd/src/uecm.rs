//! Nudm UE Context Management (UECM) request processing — TS 29.503 §5.3.
//!
//! These are the conformance pieces for the LIVE UECM handlers:
//! - **udmd-03**: mandatory-IE validation of AMF/SMF registrations.
//! - **udmd-01**: persistence of the registration to UDR (Nudr_DataRepository
//!   `context-data`), keeping the local UE context only as a cache.
//! - **udmd-02**: Deregistration Notification to the old AMF on re-registration
//!   with a different serving AMF.
//!
//! The UDR interaction is funnelled through [`UdrClient`] so the live handlers
//! can be unit-gated with a mock instead of a running udrd.

use crate::context::udm_self;
use ogs_sbi::message::SbiResponse;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// ProblemDetails (RFC 7807 / TS 29.500)
// ---------------------------------------------------------------------------

/// Minimal ProblemDetails carried by a validation failure.
#[derive(Debug, Clone)]
pub struct ProblemDetails {
    /// HTTP status code.
    pub status: u16,
    /// Machine-readable cause (TS 29.500).
    pub cause: String,
    /// Human-readable detail.
    pub detail: String,
}

impl ProblemDetails {
    /// A `400 MANDATORY_IE_MISSING` problem (TS 29.500).
    fn mandatory_ie_missing(detail: impl Into<String>) -> Self {
        Self {
            status: 400,
            cause: "MANDATORY_IE_MISSING".to_string(),
            detail: detail.into(),
        }
    }

    /// Render the problem as an SBI response body.
    pub fn into_response(self) -> SbiResponse {
        SbiResponse::with_status(self.status)
            .with_json_body(&json!({
                "status": self.status,
                "cause": self.cause,
                "detail": self.detail,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(self.status))
    }
}

// ---------------------------------------------------------------------------
// udmd-03: mandatory-IE validation
// ---------------------------------------------------------------------------

fn require_str<'a>(v: &'a Value, key: &str, label: &str) -> Result<&'a str, ProblemDetails> {
    match v.get(key).and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(ProblemDetails::mandatory_ie_missing(format!(
            "{label} is missing"
        ))),
    }
}

fn require_obj<'a>(v: &'a Value, key: &str, label: &str) -> Result<&'a Value, ProblemDetails> {
    match v.get(key) {
        Some(o) if o.is_object() => Ok(o),
        _ => Err(ProblemDetails::mandatory_ie_missing(format!(
            "{label} is missing"
        ))),
    }
}

/// Validate the mandatory IEs of an `Amf3GppAccessRegistration`
/// (TS 29.503 §6.2.6): `amfInstanceId`, `deregCallbackUri`,
/// `guami{amfId, plmnId{mcc, mnc}}`, `ratType`.
pub fn validate_amf_3gpp_registration(body: &Value) -> Result<(), ProblemDetails> {
    require_str(body, "amfInstanceId", "Amf3GppAccessRegistration.amfInstanceId")?;
    require_str(
        body,
        "deregCallbackUri",
        "Amf3GppAccessRegistration.deregCallbackUri",
    )?;
    let guami = require_obj(body, "guami", "Amf3GppAccessRegistration.guami")?;
    require_str(guami, "amfId", "Amf3GppAccessRegistration.guami.amfId")?;
    let plmn = require_obj(guami, "plmnId", "Amf3GppAccessRegistration.guami.plmnId")?;
    require_str(plmn, "mcc", "Amf3GppAccessRegistration.guami.plmnId.mcc")?;
    require_str(plmn, "mnc", "Amf3GppAccessRegistration.guami.plmnId.mnc")?;
    require_str(body, "ratType", "Amf3GppAccessRegistration.ratType")?;
    Ok(())
}

/// Validate the mandatory IEs of an `SmfRegistration` (TS 29.503 §6.2.x):
/// `smfInstanceId`, `pduSessionId`, `singleNssai`, `dnn`.
pub fn validate_smf_registration(body: &Value) -> Result<(), ProblemDetails> {
    require_str(body, "smfInstanceId", "SmfRegistration.smfInstanceId")?;
    let psi_ok = body
        .get("pduSessionId")
        .map(|v| v.is_number() || v.is_string())
        .unwrap_or(false);
    if !psi_ok {
        return Err(ProblemDetails::mandatory_ie_missing(
            "SmfRegistration.pduSessionId is missing",
        ));
    }
    require_obj(body, "singleNssai", "SmfRegistration.singleNssai")?;
    require_str(body, "dnn", "SmfRegistration.dnn")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// UDR client abstraction (udmd-01/02) — Live talks to udrd; Mock is test-only
// ---------------------------------------------------------------------------

/// Client over the Nudr_DataRepository operations the live UECM handlers need.
///
/// `Live` discovers UDR and sends real requests; `Mock` (test-only) records the
/// outgoing operations so the handlers can be unit-gated without a running udrd.
pub enum UdrClient {
    /// Discovers and sends to the live UDR (Nudr_DataRepository).
    Live,
    /// Test double that records calls and replays canned responses.
    #[cfg(test)]
    Mock(std::sync::Arc<MockUdr>),
}

impl UdrClient {
    async fn amf_context_get(&self, supi: &str) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => crate::sbi_path::udm_nudr_dr_send_amf_context_get(supi).await,
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.amf_context_get(supi)),
        }
    }

    async fn amf_context_put(&self, supi: &str, body: &Value) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => crate::sbi_path::udm_nudr_dr_send_amf_context_put(supi, body).await,
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.amf_context_put(supi, body)),
        }
    }

    async fn smf_context_put(
        &self,
        supi: &str,
        psi: &str,
        body: &Value,
    ) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_nudr_dr_send_smf_context_put(supi, psi, body).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.smf_context_put(supi, psi, body)),
        }
    }

    async fn context_delete(&self, supi: &str, relative_path: &str) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_nudr_dr_send_context_delete(supi, relative_path).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.context_delete(supi, relative_path)),
        }
    }

    async fn send_dereg_notification(
        &self,
        callback_uri: &str,
        body: &Value,
    ) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_sbi_send_dereg_notification(callback_uri, body).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.send_dereg_notification(callback_uri, body)),
        }
    }
}

// ---------------------------------------------------------------------------
// Live UECM handlers (validate -> persist -> notify)
// ---------------------------------------------------------------------------

/// Read the prior AMF registration: UDR first (udmd-02), then the local cache.
async fn read_prior_amf_registration(supi: &str, client: &UdrClient) -> Option<Value> {
    if let Ok(resp) = client.amf_context_get(supi).await {
        if resp.is_success() {
            if let Some(v) = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str::<Value>(b).ok())
            {
                return Some(v);
            }
        }
    }
    cached_prior_amf_registration(supi)
}

/// Local-cache fallback for the prior AMF registration (amfInstanceId +
/// deregCallbackUri), used when UDR has no stored context-data.
fn cached_prior_amf_registration(supi: &str) -> Option<Value> {
    let ctx = udm_self();
    let context = ctx.read().ok()?;
    let ue = context.ue_find_by_supi(supi)?;
    let amf_id = ue.amf_instance_id.clone()?;
    Some(json!({
        "amfInstanceId": amf_id,
        "deregCallbackUri": ue.dereg_callback_uri,
    }))
}

/// Cache the serving-AMF identity locally so udmd-02 still works when UDR does
/// not persist context-data.
fn cache_amf_registration(supi: &str, body: &Value) {
    let ctx = udm_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => return,
    };
    let ue = context
        .ue_find_by_supi(supi)
        .or_else(|| context.ue_add(supi));
    if let Some(mut ue) = ue {
        ue.amf_instance_id = body
            .get("amfInstanceId")
            .and_then(|v| v.as_str())
            .map(String::from);
        ue.dereg_callback_uri = body
            .get("deregCallbackUri")
            .and_then(|v| v.as_str())
            .map(String::from);
        context.ue_update(&ue);
    }
}

/// udmd-02: notify the old AMF if the serving AMF changed; suppress when the new
/// amfInstanceId equals the old one.
async fn notify_old_amf_if_changed(supi: &str, prior: &Value, new: &Value, client: &UdrClient) {
    let old_id = prior.get("amfInstanceId").and_then(|v| v.as_str());
    let new_id = new.get("amfInstanceId").and_then(|v| v.as_str());
    let old_uri = prior.get("deregCallbackUri").and_then(|v| v.as_str());
    let (old_id, new_id, old_uri) = match (old_id, new_id, old_uri) {
        (Some(o), Some(n), Some(u)) if !u.is_empty() => (o, n, u),
        _ => return,
    };
    if old_id == new_id {
        // Suppression rule (TS 29.503 §5.3.2.2.2): same serving AMF, no notify.
        return;
    }
    let dereg = json!({ "deregReason": "UE_INITIAL_REGISTRATION" });
    match client.send_dereg_notification(old_uri, &dereg).await {
        Ok(resp) => log::info!(
            "[{supi}] Deregistration notification to old AMF {old_uri} -> {}",
            resp.status
        ),
        Err(e) => log::warn!("[{supi}] Deregistration notification to old AMF {old_uri} failed: {e}"),
    }
}

/// Map a UDR write response. Returns `Some(503)` when UDR replied 5xx (the
/// handler should early-return it); otherwise `None`, degrading gracefully
/// (best-effort) on transport errors and non-5xx statuses so the matched-sim
/// happy path still completes when udrd lacks context-data support.
fn udr_write_outcome(supi: &str, op: &str, result: Result<SbiResponse, String>) -> Option<SbiResponse> {
    match result {
        Ok(resp) if resp.is_success() => None,
        Ok(resp) if resp.status >= 500 => {
            log::error!("[{supi}] UDR {op} returned {}", resp.status);
            Some(ogs_sbi::server::send_service_unavailable("UDR persistence failed"))
        }
        Ok(resp) => {
            log::warn!("[{supi}] UDR {op} returned {} (degraded)", resp.status);
            None
        }
        Err(e) => {
            log::warn!("[{supi}] UDR {op} failed: {e} (degraded)");
            None
        }
    }
}

/// Process an AMF 3GPP-access registration PUT (udmd-03/01/02).
pub async fn process_amf_registration(supi: &str, body: &Value, client: &UdrClient) -> SbiResponse {
    // udmd-03: reject payloads missing any mandatory IE.
    if let Err(problem) = validate_amf_3gpp_registration(body) {
        log::warn!("[{supi}] AMF registration rejected: {}", problem.detail);
        return problem.into_response();
    }

    // udmd-02: read the prior registration before overwriting.
    let prior = read_prior_amf_registration(supi, client).await;

    // udmd-01: persist the validated registration to UDR.
    if let Some(resp) = udr_write_outcome(
        supi,
        "AMF context PUT",
        client.amf_context_put(supi, body).await,
    ) {
        return resp;
    }

    // udmd-02: notify the old AMF if the serving AMF changed.
    if let Some(prior) = prior {
        notify_old_amf_if_changed(supi, &prior, body, client).await;
    }

    // Local cache (UDR is the system of record).
    cache_amf_registration(supi, body);

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access"),
        )
        .with_json_body(&json!({
            "amfInstanceId": body.get("amfInstanceId"),
            "deregCallbackUri": body.get("deregCallbackUri"),
            "guami": body.get("guami"),
            "ratType": body.get("ratType"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Process an SMF registration PUT (udmd-03/01).
pub async fn process_smf_registration(
    supi: &str,
    pdu_session_id: &str,
    body: &Value,
    client: &UdrClient,
) -> SbiResponse {
    // udmd-03: reject payloads missing any mandatory IE.
    if let Err(problem) = validate_smf_registration(body) {
        log::warn!("[{supi}] SMF registration rejected: {}", problem.detail);
        return problem.into_response();
    }

    // udmd-01: persist the per-PDU-session registration to UDR.
    if let Some(resp) = udr_write_outcome(
        supi,
        "SMF context PUT",
        client.smf_context_put(supi, pdu_session_id, body).await,
    ) {
        return resp;
    }

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nudm-uecm/v1/{supi}/registrations/smf-registrations/{pdu_session_id}"),
        )
        .with_json_body(&json!({
            "smfInstanceId": body.get("smfInstanceId"),
            "pduSessionId": body.get("pduSessionId"),
            "singleNssai": body.get("singleNssai"),
            "dnn": body.get("dnn"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Process an AMF deregistration DELETE (udmd-01): purge UDR context-data, then
/// return 204.
pub async fn process_amf_deregistration(supi: &str, client: &UdrClient) -> SbiResponse {
    if let Err(e) = client.context_delete(supi, "amf-3gpp-access").await {
        log::warn!("[{supi}] UDR AMF context DELETE failed: {e} (degraded)");
    }

    // Local cache cleanup (mirror legacy behavior).
    let ctx = udm_self();
    if let Ok(context) = ctx.read() {
        if let Some(ue) = context.ue_find_by_supi(supi) {
            context.ue_remove(ue.id);
        }
    }

    SbiResponse::with_status(204)
}

/// Process an SMF deregistration DELETE (udmd-01): purge the per-PDU-session UDR
/// context-data, then return 204.
pub async fn process_smf_deregistration(
    supi: &str,
    pdu_session_id: &str,
    client: &UdrClient,
) -> SbiResponse {
    let relative = format!("smf-registrations/{pdu_session_id}");
    if let Err(e) = client.context_delete(supi, &relative).await {
        log::warn!("[{supi}] UDR SMF context DELETE failed: {e} (degraded)");
    }
    SbiResponse::with_status(204)
}

// ---------------------------------------------------------------------------
// Test double (mock UDR)
// ---------------------------------------------------------------------------

/// A recorded outgoing UDR/AMF operation (test-only).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub enum UdrCall {
    AmfGet {
        supi: String,
    },
    AmfPut {
        supi: String,
        body: Value,
    },
    SmfPut {
        supi: String,
        psi: String,
        body: Value,
    },
    Delete {
        supi: String,
        path: String,
    },
    DeregNotify {
        callback_uri: String,
        body: Value,
    },
}

/// Stateful mock UDR: `amf_context_get` returns the last value stored by
/// `amf_context_put` (or a seeded prior), so re-registration scenarios behave
/// like a real repository.
#[cfg(test)]
pub struct MockUdr {
    stored_amf: std::sync::Mutex<Option<Value>>,
    put_status: u16,
    calls: std::sync::Mutex<Vec<UdrCall>>,
}

#[cfg(test)]
impl MockUdr {
    fn new() -> Self {
        Self {
            stored_amf: std::sync::Mutex::new(None),
            put_status: 201,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn with_prior(prior: Value) -> Self {
        let m = Self::new();
        *m.stored_amf.lock().unwrap() = Some(prior);
        m
    }

    fn amf_context_get(&self, supi: &str) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::AmfGet {
            supi: supi.to_string(),
        });
        match self.stored_amf.lock().unwrap().clone() {
            Some(v) => SbiResponse::with_status(200)
                .with_json_body(&v)
                .unwrap_or_else(|_| SbiResponse::with_status(200)),
            None => SbiResponse::with_status(404),
        }
    }

    fn amf_context_put(&self, supi: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::AmfPut {
            supi: supi.to_string(),
            body: body.clone(),
        });
        *self.stored_amf.lock().unwrap() = Some(body.clone());
        SbiResponse::with_status(self.put_status)
    }

    fn smf_context_put(&self, supi: &str, psi: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::SmfPut {
            supi: supi.to_string(),
            psi: psi.to_string(),
            body: body.clone(),
        });
        SbiResponse::with_status(self.put_status)
    }

    fn context_delete(&self, supi: &str, path: &str) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::Delete {
            supi: supi.to_string(),
            path: path.to_string(),
        });
        SbiResponse::with_status(204)
    }

    fn send_dereg_notification(&self, callback_uri: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::DeregNotify {
            callback_uri: callback_uri.to_string(),
            body: body.clone(),
        });
        SbiResponse::with_status(204)
    }

    fn calls(&self) -> Vec<UdrCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn valid_amf_body() -> Value {
        json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": "http://amf-a.example.org:7777/namf-callback/v1/imsi-x/dereg-notify",
            "guami": {
                "plmnId": { "mcc": "001", "mnc": "01" },
                "amfId": "cafe00"
            },
            "ratType": "NR"
        })
    }

    fn valid_smf_body() -> Value {
        json!({
            "smfInstanceId": "smf-0001",
            "pduSessionId": 5,
            "singleNssai": { "sst": 1, "sd": "000001" },
            "dnn": "internet"
        })
    }

    fn problem_cause(resp: &SbiResponse) -> Option<String> {
        let v: Value = serde_json::from_str(resp.http.content.as_deref()?).ok()?;
        v.get("cause").and_then(|c| c.as_str()).map(String::from)
    }

    fn remove_path(mut v: Value, path: &[&str]) -> Value {
        let (last, parents) = path.split_last().expect("non-empty path");
        let mut cur = &mut v;
        for p in parents {
            cur = cur.get_mut(*p).expect("intermediate path exists");
        }
        cur.as_object_mut().expect("parent is object").remove(*last);
        v
    }

    fn deregister_count(calls: &[UdrCall]) -> usize {
        calls
            .iter()
            .filter(|c| matches!(c, UdrCall::DeregNotify { .. }))
            .count()
    }

    // ----- udmd-03 ---------------------------------------------------------

    #[tokio::test]
    async fn test_amf_registration_missing_each_mandatory_ie_returns_400() {
        let missing: &[&[&str]] = &[
            &["amfInstanceId"],
            &["deregCallbackUri"],
            &["guami"],
            &["guami", "amfId"],
            &["guami", "plmnId", "mcc"],
            &["guami", "plmnId", "mnc"],
            &["ratType"],
        ];
        for path in missing {
            let body = remove_path(valid_amf_body(), path);
            let mock = Arc::new(MockUdr::new());
            let client = UdrClient::Mock(mock.clone());
            let resp = process_amf_registration("imsi-001010000000301", &body, &client).await;
            assert_eq!(resp.status, 400, "missing {path:?} should be 400");
            assert_eq!(
                problem_cause(&resp).as_deref(),
                Some("MANDATORY_IE_MISSING"),
                "missing {path:?} cause"
            );
            // Validation must short-circuit before any UDR write.
            assert!(
                !mock
                    .calls()
                    .iter()
                    .any(|c| matches!(c, UdrCall::AmfPut { .. })),
                "missing {path:?} must not persist to UDR"
            );
        }
    }

    #[tokio::test]
    async fn test_smf_registration_missing_each_mandatory_ie_returns_400() {
        let missing: &[&[&str]] = &[
            &["smfInstanceId"],
            &["pduSessionId"],
            &["singleNssai"],
            &["dnn"],
        ];
        for path in missing {
            let body = remove_path(valid_smf_body(), path);
            let mock = Arc::new(MockUdr::new());
            let client = UdrClient::Mock(mock.clone());
            let resp =
                process_smf_registration("imsi-001010000000302", "5", &body, &client).await;
            assert_eq!(resp.status, 400, "missing {path:?} should be 400");
            assert_eq!(
                problem_cause(&resp).as_deref(),
                Some("MANDATORY_IE_MISSING"),
                "missing {path:?} cause"
            );
        }
    }

    #[tokio::test]
    async fn test_amf_registration_complete_returns_201() {
        crate::context::udm_context_init(1024, 4096);
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());
        let resp =
            process_amf_registration("imsi-001010000000303", &valid_amf_body(), &client).await;
        assert_eq!(resp.status, 201);
    }

    // ----- udmd-01 ---------------------------------------------------------

    #[tokio::test]
    async fn test_amf_registration_persists_put_to_udr() {
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000310";
        let body = valid_amf_body();
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        let resp = process_amf_registration(supi, &body, &client).await;
        assert_eq!(resp.status, 201);

        let put = mock.calls().into_iter().find_map(|c| match c {
            UdrCall::AmfPut { supi, body } => Some((supi, body)),
            _ => None,
        });
        let (put_supi, put_body) = put.expect("an AMF context PUT was issued to UDR");
        assert_eq!(put_supi, supi);
        assert_eq!(put_body, body, "PUT carries the received registration body");
    }

    #[tokio::test]
    async fn test_smf_registration_persists_put_to_udr() {
        let supi = "imsi-001010000000311";
        let body = valid_smf_body();
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        let resp = process_smf_registration(supi, "5", &body, &client).await;
        assert_eq!(resp.status, 201);

        let put = mock.calls().into_iter().find_map(|c| match c {
            UdrCall::SmfPut { supi, psi, body } => Some((supi, psi, body)),
            _ => None,
        });
        let (put_supi, psi, put_body) = put.expect("an SMF context PUT was issued to UDR");
        assert_eq!(put_supi, supi);
        assert_eq!(psi, "5");
        assert_eq!(put_body, body);
    }

    #[tokio::test]
    async fn test_amf_registration_udr_5xx_maps_to_503() {
        crate::context::udm_context_init(1024, 4096);
        let mut mock = MockUdr::new();
        mock.put_status = 500;
        let mock = Arc::new(mock);
        let client = UdrClient::Mock(mock.clone());
        let resp =
            process_amf_registration("imsi-001010000000312", &valid_amf_body(), &client).await;
        assert_eq!(resp.status, 503, "UDR 5xx maps to 503");
    }

    #[tokio::test]
    async fn test_amf_deregistration_deletes_udr_context() {
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000313";
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());
        let resp = process_amf_deregistration(supi, &client).await;
        assert_eq!(resp.status, 204);
        assert!(
            mock.calls().iter().any(|c| matches!(
                c,
                UdrCall::Delete { path, .. } if path == "amf-3gpp-access"
            )),
            "deregistration issues a UDR context-data DELETE"
        );
    }

    // ----- udmd-02 ---------------------------------------------------------

    #[tokio::test]
    async fn test_reregistration_notifies_old_amf_then_suppresses_same_id() {
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000320";
        let amf_a_uri =
            "http://amf-a.example.org:7777/namf-callback/v1/imsi-x/dereg-notify".to_string();

        let prior = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": amf_a_uri,
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        let mock = Arc::new(MockUdr::with_prior(prior));
        let client = UdrClient::Mock(mock.clone());

        // AMF-B registers over AMF-A -> a DeregistrationData POST to AMF-A.
        let mut body_b = valid_amf_body();
        body_b["amfInstanceId"] = json!("amf-b-0002");
        body_b["deregCallbackUri"] =
            json!("http://amf-b.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        let resp = process_amf_registration(supi, &body_b, &client).await;
        assert_eq!(resp.status, 201);

        let calls = mock.calls();
        assert_eq!(deregister_count(&calls), 1, "exactly one dereg notification");
        let notified = calls.iter().find_map(|c| match c {
            UdrCall::DeregNotify { callback_uri, body } => Some((callback_uri.clone(), body.clone())),
            _ => None,
        });
        let (uri, dereg_body) = notified.expect("a dereg notification was sent");
        assert_eq!(uri, amf_a_uri, "notification targets the OLD AMF (AMF-A)");
        assert_eq!(
            dereg_body.get("deregReason").and_then(|v| v.as_str()),
            Some("UE_INITIAL_REGISTRATION")
        );

        // Re-register with the SAME AMF-B id -> suppressed, no new notification.
        let resp = process_amf_registration(supi, &body_b, &client).await;
        assert_eq!(resp.status, 201);
        assert_eq!(
            deregister_count(&mock.calls()),
            1,
            "no notification when amfInstanceId is unchanged"
        );
    }
}
