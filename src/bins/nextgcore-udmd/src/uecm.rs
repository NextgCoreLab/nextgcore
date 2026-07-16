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
use nextgcore_sbi::message::SbiResponse;
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
    require_str(
        body,
        "amfInstanceId",
        "Amf3GppAccessRegistration.amfInstanceId",
    )?;
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

    async fn amf_context_patch(&self, supi: &str, body: &Value) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => {
                crate::sbi_path::udm_nudr_dr_send_amf_context_patch(supi, body).await
            }
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.amf_context_patch(supi, body)),
        }
    }

    async fn smf_context_get(&self, supi: &str, psi: &str) -> Result<SbiResponse, String> {
        match self {
            UdrClient::Live => crate::sbi_path::udm_nudr_dr_send_smf_context_get(supi, psi).await,
            #[cfg(test)]
            UdrClient::Mock(m) => Ok(m.smf_context_get(supi, psi)),
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

/// Build the Nudm_UECM `DeregistrationData` notification body (TS 29.503
/// §5.3.2.3.2): `deregReason` + `accessType`. Both members are mandatory — the
/// old AMF's dereg-notify handler keys its network-initiated deregistration on
/// `accessType` (WSB-4), so it must be present on the wire. The old AMF's
/// registration was superseded by a fresh UE initial registration in the new
/// AMF over 3GPP access. Exposed so peer NF crates (amfd) can drive the exact
/// wire body through their real handler in strict-peer tests.
pub fn build_dereg_notification_body() -> Value {
    json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "3GPP_ACCESS" })
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
    let dereg = build_dereg_notification_body();
    match client.send_dereg_notification(old_uri, &dereg).await {
        Ok(resp) => log::info!(
            "[{supi}] Deregistration notification to old AMF {old_uri} -> {}",
            resp.status
        ),
        Err(e) => {
            log::warn!("[{supi}] Deregistration notification to old AMF {old_uri} failed: {e}")
        }
    }
}

/// Map a UDR write response. Returns `Some(503)` when UDR replied 5xx (the
/// handler should early-return it); otherwise `None`, degrading gracefully
/// (best-effort) on transport errors and non-5xx statuses so the matched-sim
/// happy path still completes when udrd lacks context-data support.
fn udr_write_outcome(
    supi: &str,
    op: &str,
    result: Result<SbiResponse, String>,
) -> Option<SbiResponse> {
    match result {
        Ok(resp) if resp.is_success() => None,
        Ok(resp) if resp.status >= 500 => {
            log::error!("[{supi}] UDR {op} returned {}", resp.status);
            Some(nextgcore_sbi::server::send_service_unavailable(
                "UDR persistence failed",
            ))
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

/// Compare two GUAMI objects for equality (udmd-05).
///
/// Considers amfId + plmnId.mcc + plmnId.mnc. Missing fields never match.
fn guami_matches(a: &Value, b: &Value) -> bool {
    a.get("amfId").and_then(|x| x.as_str()) == b.get("amfId").and_then(|x| x.as_str())
        && a.pointer("/plmnId/mcc").and_then(|x| x.as_str())
            == b.pointer("/plmnId/mcc").and_then(|x| x.as_str())
        && a.pointer("/plmnId/mnc").and_then(|x| x.as_str())
            == b.pointer("/plmnId/mnc").and_then(|x| x.as_str())
}

/// Process an AMF 3GPP-access registration PUT (udmd-03/01/02/06).
pub async fn process_amf_registration(supi: &str, body: &Value, client: &UdrClient) -> SbiResponse {
    // udmd-03: reject payloads missing any mandatory IE.
    if let Err(problem) = validate_amf_3gpp_registration(body) {
        log::warn!("[{supi}] AMF registration rejected: {}", problem.detail);
        return problem.into_response();
    }

    // udmd-02: read the prior registration before overwriting.
    let prior = read_prior_amf_registration(supi, client).await;
    // udmd-06: remember whether a prior registration existed for status-code choice.
    let is_update = prior.is_some();

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

    // udmd-06: 201 on create, 200 on update.
    let status = if is_update { 200 } else { 201 };
    let mut resp = SbiResponse::with_status(status)
        .with_json_body(&json!({
            "amfInstanceId": body.get("amfInstanceId"),
            "deregCallbackUri": body.get("deregCallbackUri"),
            "guami": body.get("guami"),
            "ratType": body.get("ratType"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(status));
    if status == 201 {
        resp = resp.with_header(
            "Location",
            format!("/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access"),
        );
    }
    resp
}

/// Process a PATCH to the AMF 3GPP-access registration (udmd-05).
///
/// Validates that the GUAMI in the PATCH body matches the stored registration
/// (ownership check, TS 29.503 §5.3.2.4); applies the update to UDR on match.
pub async fn process_amf_registration_update(
    supi: &str,
    body: &Value,
    client: &UdrClient,
) -> SbiResponse {
    // Read the stored registration.
    let stored = match client.amf_context_get(supi).await {
        Ok(resp) if resp.is_success() => {
            match resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str::<Value>(b).ok())
            {
                Some(v) => v,
                None => {
                    log::error!("[{supi}] UDR AMF context GET returned unparseable body");
                    return nextgcore_sbi::server::send_service_unavailable("UDR response invalid");
                }
            }
        }
        Ok(resp) if resp.status == 404 => {
            return ProblemDetails {
                status: 404,
                cause: "NOT_FOUND".to_string(),
                detail: "No AMF registration found for this SUPI".to_string(),
            }
            .into_response();
        }
        Ok(resp) => {
            log::error!("[{supi}] UDR AMF context GET returned {}", resp.status);
            return nextgcore_sbi::server::send_service_unavailable("UDR context GET failed");
        }
        Err(e) => {
            log::warn!("[{supi}] UDR AMF context GET failed: {e} (no prior stored)");
            return nextgcore_sbi::server::send_service_unavailable("UDR unavailable");
        }
    };

    // GUAMI ownership check (TS 29.503 §5.3.2.4).
    if let (Some(stored_guami), Some(req_guami)) = (stored.get("guami"), body.get("guami")) {
        if !guami_matches(stored_guami, req_guami) {
            log::warn!("[{supi}] PATCH rejected: GUAMI mismatch");
            return ProblemDetails {
                status: 403,
                cause: "INVALID_GUAMI".to_string(),
                detail: "GUAMI in PATCH body does not match stored registration".to_string(),
            }
            .into_response();
        }
    }

    // Apply the PATCH to UDR.
    if let Some(err_resp) = udr_write_outcome(
        supi,
        "AMF context PATCH",
        client.amf_context_patch(supi, body).await,
    ) {
        return err_resp;
    }

    SbiResponse::with_status(204)
}

/// Process an SMF registration PUT (udmd-03/01/06).
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

    // udmd-06: check whether a prior registration exists.
    let is_update = matches!(
        client.smf_context_get(supi, pdu_session_id).await,
        Ok(resp) if resp.is_success()
    );

    // udmd-01: persist the per-PDU-session registration to UDR.
    if let Some(resp) = udr_write_outcome(
        supi,
        "SMF context PUT",
        client.smf_context_put(supi, pdu_session_id, body).await,
    ) {
        return resp;
    }

    // udmd-06: 201 on create, 200 on update.
    let status = if is_update { 200 } else { 201 };
    let mut resp = SbiResponse::with_status(status)
        .with_json_body(&json!({
            "smfInstanceId": body.get("smfInstanceId"),
            "pduSessionId": body.get("pduSessionId"),
            "singleNssai": body.get("singleNssai"),
            "dnn": body.get("dnn"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(status));
    if status == 201 {
        resp = resp.with_header(
            "Location",
            format!("/nudm-uecm/v1/{supi}/registrations/smf-registrations/{pdu_session_id}"),
        );
    }
    resp
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
    AmfPatch {
        supi: String,
        body: Value,
    },
    SmfGet {
        supi: String,
        psi: String,
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
    stored_smf: std::sync::Mutex<std::collections::HashMap<String, Value>>,
    put_status: u16,
    patch_status: u16,
    dereg_status: u16,
    calls: std::sync::Mutex<Vec<UdrCall>>,
}

#[cfg(test)]
impl MockUdr {
    fn new() -> Self {
        Self {
            stored_amf: std::sync::Mutex::new(None),
            stored_smf: std::sync::Mutex::new(std::collections::HashMap::new()),
            put_status: 201,
            patch_status: 204,
            dereg_status: 204,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn with_prior(prior: Value) -> Self {
        let m = Self::new();
        *m.stored_amf.lock().unwrap() = Some(prior);
        m
    }

    /// Override the status the mocked old-AMF dereg-notify callback returns
    /// (default 204). Used by the H3 step-3 "logs-and-continues" test to prove
    /// a FAILING notification does not wedge udmd's re-registration
    /// (TS 29.503 §5.3.2.2.2 best-effort semantics).
    fn with_dereg_status(mut self, status: u16) -> Self {
        self.dereg_status = status;
        self
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

    fn amf_context_patch(&self, supi: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::AmfPatch {
            supi: supi.to_string(),
            body: body.clone(),
        });
        SbiResponse::with_status(self.patch_status)
    }

    fn smf_context_get(&self, supi: &str, psi: &str) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::SmfGet {
            supi: supi.to_string(),
            psi: psi.to_string(),
        });
        let key = format!("{supi}:{psi}");
        match self.stored_smf.lock().unwrap().get(&key).cloned() {
            Some(v) => SbiResponse::with_status(200)
                .with_json_body(&v)
                .unwrap_or_else(|_| SbiResponse::with_status(200)),
            None => SbiResponse::with_status(404),
        }
    }

    fn smf_context_put(&self, supi: &str, psi: &str, body: &Value) -> SbiResponse {
        self.calls.lock().unwrap().push(UdrCall::SmfPut {
            supi: supi.to_string(),
            psi: psi.to_string(),
            body: body.clone(),
        });
        let key = format!("{supi}:{psi}");
        self.stored_smf.lock().unwrap().insert(key, body.clone());
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
        SbiResponse::with_status(self.dereg_status)
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
            let resp = process_smf_registration("imsi-001010000000302", "5", &body, &client).await;
            assert_eq!(resp.status, 400, "missing {path:?} should be 400");
            assert_eq!(
                problem_cause(&resp).as_deref(),
                Some("MANDATORY_IE_MISSING"),
                "missing {path:?} cause"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_complete_returns_201() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());
        let resp =
            process_amf_registration("imsi-001010000000303", &valid_amf_body(), &client).await;
        assert_eq!(resp.status, 201);
    }

    // ----- udmd-01 ---------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_persists_put_to_udr() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_udr_5xx_maps_to_503() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_deregistration_deletes_udr_context() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

    // ----- udmd-05 ---------------------------------------------------------

    #[tokio::test]
    async fn test_amf_registration_update_wrong_guami_returns_403() {
        let stored = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": "http://amf-a.example.org/dereg",
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        let mock = Arc::new(MockUdr::with_prior(stored));
        let client = UdrClient::Mock(mock.clone());

        let wrong_guami = json!({
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "deadff" },
            "purgeFlag": true
        });
        let resp = process_amf_registration_update("imsi-udmd05-0001", &wrong_guami, &client).await;
        assert_eq!(resp.status, 403, "wrong GUAMI must be 403");
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("INVALID_GUAMI"),
            "cause must be INVALID_GUAMI"
        );
        // No PATCH should have been sent to UDR
        assert!(
            !mock
                .calls()
                .iter()
                .any(|c| matches!(c, UdrCall::AmfPatch { .. })),
            "UDR PATCH must not be issued when GUAMI mismatches"
        );
    }

    #[tokio::test]
    async fn test_amf_registration_update_matching_guami_returns_204_and_patches_udr() {
        let stored = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": "http://amf-a.example.org/dereg",
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        let mock = Arc::new(MockUdr::with_prior(stored));
        let client = UdrClient::Mock(mock.clone());

        let patch = json!({
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "purgeFlag": true
        });
        let resp = process_amf_registration_update("imsi-udmd05-0002", &patch, &client).await;
        assert_eq!(resp.status, 204, "matching GUAMI must be 204");
        assert!(
            mock.calls()
                .iter()
                .any(|c| matches!(c, UdrCall::AmfPatch { .. })),
            "UDR PATCH must be issued when GUAMI matches"
        );
    }

    #[tokio::test]
    async fn test_amf_registration_update_no_prior_returns_404() {
        // Empty mock → no stored registration → 404
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock);
        let patch =
            json!({ "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" } });
        let resp = process_amf_registration_update("imsi-udmd05-0003", &patch, &client).await;
        assert_eq!(resp.status, 404);
    }

    // ----- udmd-06 ---------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_amf_registration_first_put_201_second_put_200() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-udmd06-0001";
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        // First PUT → no prior → 201 + Location
        let resp = process_amf_registration(supi, &valid_amf_body(), &client).await;
        assert_eq!(resp.status, 201, "first PUT must be 201");
        // set_header lowercases all header keys (HTTP/2 convention).
        let loc = resp
            .http
            .headers
            .get("location")
            .cloned()
            .unwrap_or_default();
        assert!(
            loc.contains(supi),
            "Location header must reference the SUPI"
        );

        // Second PUT → prior exists → 200
        let resp = process_amf_registration(supi, &valid_amf_body(), &client).await;
        assert_eq!(resp.status, 200, "second PUT must be 200");
    }

    #[tokio::test]
    async fn test_smf_registration_first_put_201_second_put_200() {
        let supi = "imsi-udmd06-0002";
        let mock = Arc::new(MockUdr::new());
        let client = UdrClient::Mock(mock.clone());

        // First PUT → 201
        let resp = process_smf_registration(supi, "5", &valid_smf_body(), &client).await;
        assert_eq!(resp.status, 201, "first SMF PUT must be 201");

        // Second PUT → prior stored → 200
        let resp = process_smf_registration(supi, "5", &valid_smf_body(), &client).await;
        assert_eq!(resp.status, 200, "second SMF PUT must be 200");
    }

    // ----- udmd-02 ---------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_reregistration_notifies_old_amf_then_suppresses_same_id() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        // The UDR already holds AMF-A's registration, so this is an UPDATE → 200
        // (TS 29.503 §5.3.2.2: resource exists → 200 OK, not 201 Created).
        let mut body_b = valid_amf_body();
        body_b["amfInstanceId"] = json!("amf-b-0002");
        body_b["deregCallbackUri"] =
            json!("http://amf-b.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        let resp = process_amf_registration(supi, &body_b, &client).await;
        assert_eq!(
            resp.status, 200,
            "re-registration over existing AMF-A must be 200 (update)"
        );

        let calls = mock.calls();
        assert_eq!(
            deregister_count(&calls),
            1,
            "exactly one dereg notification"
        );
        let notified = calls.iter().find_map(|c| match c {
            UdrCall::DeregNotify { callback_uri, body } => {
                Some((callback_uri.clone(), body.clone()))
            }
            _ => None,
        });
        let (uri, dereg_body) = notified.expect("a dereg notification was sent");
        assert_eq!(uri, amf_a_uri, "notification targets the OLD AMF (AMF-A)");
        assert_eq!(
            dereg_body.get("deregReason").and_then(|v| v.as_str()),
            Some("UE_INITIAL_REGISTRATION")
        );

        // Re-register with the SAME AMF-B id -> suppressed, no new notification.
        // Still an update (prior = AMF-B now stored) → 200.
        let resp = process_amf_registration(supi, &body_b, &client).await;
        assert_eq!(
            resp.status, 200,
            "same-AMF re-registration still updates the resource → 200"
        );
        assert_eq!(
            deregister_count(&mock.calls()),
            1,
            "no notification when amfInstanceId is unchanged"
        );
    }

    // ----- H3 / WSB-4: udmd -> amfd deregistration-notify STRICT-PEER -------
    //
    // Wave-6 WSB-4 (upgraded from the H3 hand-off). The emission-decision test
    // above proves udmd *decides* to notify; these tests prove udmd's
    // PRODUCTION `DeregistrationData` body is one amfd's REAL Namf_Callback
    // consumer accepts over the WIRE — POSTing the raw JSON through amfd's real
    // `nextgcore_amfd::namf_request_handler` at the `/namf-callback/v1/{supi}/
    // dereg-notify` route amfd itself registers, NOT a lenient mock and no
    // longer just the pre-WSB-4 in-memory `handle_dereg_notify` call.
    //
    // Spec: TS 29.503 §5.3.2.3.2 (Nudm_UECM DeregistrationNotification;
    // DeregistrationData = deregReason + accessType); DeregistrationReason
    // enum values verified against specs/29503-j60.txt:27268-27298. The full
    // WSB-4 round trip (absolute deregCallbackUri, router arm, serde decode,
    // fail-closed 400, network-initiated-dereg enqueue) is exercised here.

    /// Drive udmd's REAL re-registration emission and return the exact
    /// `(callbackUri, DeregistrationData)` JSON body udmd POSTs to the old AMF.
    async fn capture_udmd_dereg_body() -> (String, Value) {
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000399";
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

        // AMF-B registers over the stored AMF-A -> udmd emits a dereg notify.
        let mut body_b = valid_amf_body();
        body_b["amfInstanceId"] = json!("amf-b-0002");
        body_b["deregCallbackUri"] =
            json!("http://amf-b.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        let _ = process_amf_registration(supi, &body_b, &client).await;

        mock.calls()
            .into_iter()
            .find_map(|c| match c {
                UdrCall::DeregNotify { callback_uri, body } => Some((callback_uri, body)),
                _ => None,
            })
            .expect("udmd emitted a DeregistrationData notification")
    }

    /// Seed a real `AmfUe` (resolvable by SUPI) in amfd's process-global
    /// context so `namf_request_handler`'s SUPI lookup succeeds. Returns the
    /// AMF-UE-NGAP-ID (== the enqueued dereg's `amf_ue_ngap_id`).
    fn seed_amf_ue(supi: &str, ran_ue_ngap_id: u64) -> u64 {
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().expect("amf ctx lock");
        let ran = guard
            .ran_ue_add(900_400, ran_ue_ngap_id)
            .expect("ran_ue_add");
        let ue = guard.amf_ue_add(ran.id).expect("amf_ue_add");
        guard.amf_ue_set_supi(ue.id, supi);
        let mut ue = ue;
        ue.supi = Some(supi.to_string());
        guard.amf_ue_update(&ue);
        ue.id
    }

    /// Drain amfd's process-global network-dereg queue, keep only this UE's
    /// items and re-add the rest (queue is process-global; parallel tests must
    /// not steal each other's enqueues).
    fn drain_network_deregs_for(ue_id: u64) -> Vec<nextgcore_amfd::context::PendingNetworkDereg> {
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().expect("amf ctx lock");
        let (mine, others): (Vec<_>, Vec<_>) = guard
            .network_dereg_drain()
            .into_iter()
            .partition(|d| d.amf_ue_ngap_id == ue_id);
        for item in others {
            guard.network_dereg_add(item);
        }
        mine
    }

    /// WSB-4 acceptance: udmd's REAL production DeregistrationData body ->
    /// amfd's REAL Namf_Callback handler over the wire -> 204 + exactly one
    /// network-initiated deregistration enqueued (reregistration_required=true
    /// for UE_INITIAL_REGISTRATION). A relative URI or a missing router arm
    /// would fail this (the whole point of the WSB-4 round trip).
    #[tokio::test]
    // The amf-context guard is intentionally held across the async
    // namf_request_handler await to serialize the shared process-global amf
    // context (current-thread test runtime, so this is deadlock-free).
    #[allow(clippy::await_holding_lock)]
    async fn test_dereg_notify_strict_peer_amfd_accepts_udmd_body() {
        use nextgcore_sbi::message::SbiRequest;

        // Capture udmd's production notify body BEFORE taking the amf guard.
        let (uri, body) = capture_udmd_dereg_body().await;

        // Reverse-shape pins on udmd's production body: absolute URI + both
        // mandatory members present (WSB-4 added accessType).
        assert!(
            uri.starts_with("http://") || uri.starts_with("https://"),
            "dereg callback URI must be absolute so amfd can be reached: {uri}"
        );
        assert_eq!(
            body.get("deregReason").and_then(|v| v.as_str()),
            Some("UE_INITIAL_REGISTRATION")
        );
        assert_eq!(
            body.get("accessType").and_then(|v| v.as_str()),
            Some("3GPP_ACCESS"),
            "WSB-4: udmd's DeregistrationData must carry accessType (amfd keys on it)"
        );

        let supi = "imsi-001010000000399";
        // Hold the guard across seed + real handler + drain so a parallel test
        // cannot re-init (wipe) the global amf context in between — that race
        // was the intermittent "0 vs 1 enqueued" failure.
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_100);

        // Drive udmd's REAL body through amfd's REAL Namf SBI handler at the
        // path amfd itself registers as its absolute deregCallbackUri.
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let req = SbiRequest::post(path).with_json_body(&body).expect("json");
        let resp = nextgcore_amfd::namf_request_handler(req).await;
        assert_eq!(
            resp.status, 204,
            "amfd must 204-accept udmd's dereg body, got {} ({:?})",
            resp.status, resp.http.content
        );

        // The real handler enqueued exactly one network-initiated dereg.
        let queued = drain_network_deregs_for(ue_id);
        assert_eq!(
            queued.len(),
            1,
            "exactly one network-initiated dereg enqueued"
        );
        assert_eq!(queued[0].amf_ue_ngap_id, ue_id);
        assert!(
            queued[0].reregistration_required,
            "UE_INITIAL_REGISTRATION => reregistration_required (TS 23.502 §4.2.2.3.3)"
        );
    }

    /// Negative twin: a non-3GPP-access dereg is accepted (204) but triggers no
    /// 3GPP network-initiated deregistration — proves the accept above is
    /// discriminating, not a blanket 2xx-and-enqueue.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see the twin test above
    async fn test_dereg_notify_strict_peer_non_3gpp_no_enqueue() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000398";
        // Held across the async handler + drain (see the twin test above).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_101);
        let body =
            json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "NON_3GPP_ACCESS" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let req = SbiRequest::post(path).with_json_body(&body).expect("json");
        let resp = nextgcore_amfd::namf_request_handler(req).await;
        assert_eq!(resp.status, 204, "non-3GPP dereg is accepted");
        assert!(
            drain_network_deregs_for(ue_id).is_empty(),
            "no 3GPP network-initiated dereg for a non-3GPP-access notify"
        );
    }

    /// Fail-closed twins: a missing mandatory accessType -> 400; an unknown
    /// SUPI -> 404 CONTEXT_NOT_FOUND (TS 29.500 §5.2.7 / TS 29.518 §6.1.7.3).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_fail_closed_400_and_404() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000397";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let _ue_id = seed_amf_ue(supi, 60_102);

        // 400: mandatory accessType absent (WSB-4 fail-closed).
        let missing = json!({ "deregReason": "UE_INITIAL_REGISTRATION" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let resp = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path)
                .with_json_body(&missing)
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "missing accessType must fail closed (400)"
        );

        // 404: unknown SUPI (never seeded).
        let unknown = "imsi-001019999999999";
        let full = json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "3GPP_ACCESS" });
        let path2 = format!("/namf-callback/v1/{unknown}/dereg-notify");
        let resp2 = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path2).with_json_body(&full).expect("json"),
        )
        .await;
        assert_eq!(
            resp2.status, 404,
            "unknown SUPI must be 404 CONTEXT_NOT_FOUND"
        );
    }

    // ----- H3 finish: reverse-shape cross-decode pin + step-3 negatives ------
    //
    // Wave-6 H3 (TS 29.503 §5.3.2.3.2) implementation steps 2 & 3. Step 1
    // (strict-peer accept + resulting AmfUe/enqueue state) is proven above; the
    // tests below close:
    //   step 2 — the reverse-shape cross-decode pin: amfd's OWN
    //            `DeregistrationData` struct (namf_handler.rs:143) <-> udmd's
    //            serializer, BOTH directions, so a `deregReason`/`accessType`
    //            field-name or enum-string drift on EITHER side fails a test;
    //   step 3 — the negatives: a deregReason amfd's REAL handler rejects
    //            (-> 400 MANDATORY_IE_INCORRECT), and udmd logs-and-continues
    //            (a FAILING notification must not wedge re-registration).

    /// Canonical TS 29.503 §5.3.2.3.2 `DeregistrationReason` wire strings for
    /// amfd's OWN enum. The match is exhaustive so a renamed/added amfd variant
    /// forces this pin to be revisited — the compile-time half of the
    /// field-drift guard the H3 cross-decode step exists to provide.
    fn amfd_dereg_reason_wire(
        r: nextgcore_amfd::namf_handler::DeregistrationReason,
    ) -> &'static str {
        use nextgcore_amfd::namf_handler::DeregistrationReason as R;
        match r {
            R::UeInitialRegistration => "UE_INITIAL_REGISTRATION",
            R::UeRegistrationAreaChange => "UE_REGISTRATION_AREA_CHANGE",
            R::SubscriptionWithdrawn => "SUBSCRIPTION_WITHDRAWN",
            R::FiveGsToEpsMobility => "5GS_TO_EPS_MOBILITY",
            R::FiveGsToEpsMobilityUeInitialRegistration => {
                "5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION"
            }
            R::ReregistrationRequired => "REREGISTRATION_REQUIRED",
            R::SmfContextTransferred => "SMF_CONTEXT_TRANSFERRED",
        }
    }

    /// Canonical TS 29.503 `AccessType` wire strings for amfd's OWN enum
    /// (exhaustive — same compile-time drift-guard rationale as above).
    fn amfd_access_type_wire(a: nextgcore_amfd::namf_handler::AccessType) -> &'static str {
        use nextgcore_amfd::namf_handler::AccessType as A;
        match a {
            A::ThreeGppAccess => "3GPP_ACCESS",
            A::NonThreeGppAccess => "NON_3GPP_ACCESS",
        }
    }

    /// H3 step 2 — reverse-shape cross-decode pin, BOTH directions:
    ///  (1) ENCODE: construct amfd's OWN `DeregistrationData` struct for a UE
    ///      that re-registered in a new AMF over 3GPP access, render it to its
    ///      canonical TS 29.503 wire strings, and assert it is field/value-
    ///      identical to udmd's production `build_dereg_notification_body()`;
    ///  (2) DECODE: feed udmd's production body through amfd's REAL handler and
    ///      assert it decodes to the semantics of that same struct
    ///      (reregistration required for UE_INITIAL_REGISTRATION).
    /// A field-name or enum-string drift on either side breaks one direction.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_cross_decode_amfd_struct_and_udmd_body() {
        use nextgcore_amfd::namf_handler::{AccessType, DeregistrationData, DeregistrationReason};
        use nextgcore_sbi::message::SbiRequest;

        // Direction 1 (encode pin) — amfd's OWN struct rendered to the wire.
        let amfd_struct = DeregistrationData {
            dereg_reason: DeregistrationReason::UeInitialRegistration,
            access_type: AccessType::ThreeGppAccess,
        };
        let from_amfd_struct = json!({
            "deregReason": amfd_dereg_reason_wire(amfd_struct.dereg_reason),
            "accessType": amfd_access_type_wire(amfd_struct.access_type),
        });
        assert_eq!(
            from_amfd_struct,
            build_dereg_notification_body(),
            "amfd's DeregistrationData wire form must be field/value-identical to \
             udmd's emitted body (TS 29.503 §5.3.2.3.2 cross-decode pin)"
        );

        // Direction 2 (decode pin) — udmd's body through amfd's REAL handler.
        let supi = "imsi-001010000000396";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_103);
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let req = SbiRequest::post(path)
            .with_json_body(&build_dereg_notification_body())
            .expect("json");
        let resp = nextgcore_amfd::namf_request_handler(req).await;
        assert_eq!(resp.status, 204, "amfd decodes udmd's body -> 204");
        let queued = drain_network_deregs_for(ue_id);
        assert_eq!(queued.len(), 1, "one network-initiated dereg enqueued");
        assert!(
            queued[0].reregistration_required,
            "UE_INITIAL_REGISTRATION decodes to reregistration_required=true"
        );
    }

    /// Decoder-discrimination pin: a non-initial reason amfd recognises
    /// (SUBSCRIPTION_WITHDRAWN) is accepted (204) and still enqueues a
    /// network-initiated dereg, but with `reregistration_required=false` —
    /// proving amfd's REAL decoder keys on the EXACT deregReason string, not a
    /// blanket accept (TS 23.502 §4.2.2.3.3: only UE_INITIAL_REGISTRATION asks
    /// the UE to re-register).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_strict_peer_non_initial_reason_no_rereg() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000395";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_104);
        let body = json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN", "accessType": "3GPP_ACCESS" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let resp = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path).with_json_body(&body).expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 204,
            "a recognised non-initial reason is accepted"
        );
        let queued = drain_network_deregs_for(ue_id);
        assert_eq!(queued.len(), 1, "3GPP-access dereg is still enqueued");
        assert!(
            !queued[0].reregistration_required,
            "SUBSCRIPTION_WITHDRAWN must NOT set reregistration_required"
        );
    }

    /// H3 step 3 (first half) — a deregReason amfd's REAL handler does not
    /// recognise fails closed: 400 MANDATORY_IE_INCORRECT and NO dereg enqueued
    /// (TS 29.500 §5.2.7). Proves the accept above is discriminating, not a
    /// blanket 2xx.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // guard held across handler await (see twin above)
    async fn test_dereg_notify_strict_peer_rejects_unknown_reason() {
        use nextgcore_sbi::message::SbiRequest;
        let supi = "imsi-001010000000394";
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        nextgcore_amfd::test_support::init_context();
        let ue_id = seed_amf_ue(supi, 60_105);
        let body = json!({ "deregReason": "NOT_A_REAL_REASON", "accessType": "3GPP_ACCESS" });
        let path = format!("/namf-callback/v1/{supi}/dereg-notify");
        let resp = nextgcore_amfd::namf_request_handler(
            SbiRequest::post(path).with_json_body(&body).expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "an unknown deregReason must fail closed (400)"
        );
        assert_eq!(
            problem_cause(&resp).as_deref(),
            Some("MANDATORY_IE_INCORRECT"),
            "unknown deregReason -> MANDATORY_IE_INCORRECT"
        );
        assert!(
            drain_network_deregs_for(ue_id).is_empty(),
            "a rejected notify must not enqueue a network-initiated dereg"
        );
    }

    /// H3 step 3 (second half) — udmd logs-and-continues: a FAILING dereg
    /// notification to the old AMF must not wedge the new registration
    /// (TS 29.503 §5.3.2.2.2 best-effort). The old-AMF callback is mocked to
    /// return 500; udmd's re-registration must still complete (200) and the
    /// notification must have been attempted exactly once.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_reregistration_continues_when_dereg_notify_fails() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::context::udm_context_init(1024, 4096);
        let supi = "imsi-001010000000393";
        let amf_a_uri =
            "http://amf-a.example.org:7777/namf-callback/v1/imsi-x/dereg-notify".to_string();
        let prior = json!({
            "amfInstanceId": "amf-a-0001",
            "deregCallbackUri": amf_a_uri,
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": "NR"
        });
        // The old-AMF dereg-notify callback FAILS (500).
        let mock = Arc::new(MockUdr::with_prior(prior).with_dereg_status(500));
        let client = UdrClient::Mock(mock.clone());

        let mut body_b = valid_amf_body();
        body_b["amfInstanceId"] = json!("amf-b-0002");
        body_b["deregCallbackUri"] =
            json!("http://amf-b.example.org:7777/namf-callback/v1/imsi-x/dereg-notify");
        let resp = process_amf_registration(supi, &body_b, &client).await;
        assert_eq!(
            resp.status, 200,
            "a failing dereg notification must NOT wedge re-registration"
        );
        assert_eq!(
            deregister_count(&mock.calls()),
            1,
            "the (failed) dereg notification was attempted exactly once"
        );
    }
}
