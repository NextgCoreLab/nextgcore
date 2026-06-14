//! Npcf_SMPolicyControl client + N1 SM container codec (TS 29.512 / TS 24.501)
//!
//! This module gives the SMF a real N7 interface:
//! - `sm_policy_create` / `sm_policy_update` / `sm_policy_delete` drive the
//!   PCF SM-policy association lifecycle over HTTP (TS 29.512 §4.2.2-4.2.5)
//!   with bounded timeouts.
//! - `parse_sm_policy_decision` extracts the authorized session AMBR, default
//!   QoS (5QI/ARP) and PCC rules (incl. chgDecs / traffContDecs references)
//!   from the SmPolicyDecision so they can be applied to N1 NAS messages and
//!   PFCP QERs/PDRs.
//! - N1 SM container codec: decode PDU Session Establishment/Modification
//!   Request (PTI, requested PDU session type, SSC mode — TS 24.501 §8.3) and
//!   build Accept/Reject/Modification Command messages with policy-derived
//!   QoS instead of hardcoded values.
//!
//! Config-default fallback (documented per remediation DoD): when no PCF is
//! configured (no `PCF_URI` env and no NRF) the SMF applies
//! [`PolicyDecision::config_default`] (5QI=9, AMBR 100/100 Mbps) and logs a
//! warning. When a PCF *is* configured, a rejection or transport failure is a
//! hard failure for the PDU session (no silent fallback).

use ogs_sbi::client::{SbiClient, SbiClientConfig};
use std::time::Duration;

// ---------------------------------------------------------------------------
// 5GSM cause values (TS 24.501 §9.11.4.2)
// ---------------------------------------------------------------------------
pub mod gsm_cause {
    pub const INSUFFICIENT_RESOURCES: u8 = 26;
    #[allow(dead_code)]
    pub const MISSING_OR_UNKNOWN_DNN: u8 = 27;
    #[allow(dead_code)]
    pub const UNKNOWN_PDU_SESSION_TYPE: u8 = 28;
    pub const USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED: u8 = 29;
    #[allow(dead_code)]
    pub const REQUEST_REJECTED_UNSPECIFIED: u8 = 31;
    pub const NETWORK_FAILURE: u8 = 38;
    pub const PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED: u8 = 50;
    /// #67 Insufficient resources for specific slice (TS 24.501 §9.11.4.2).
    /// Used when the NSACF declines a PDU-session admission for the S-NSSAI
    /// (slice PDU-session quota exhausted, admittedFlag=false).
    pub const INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE: u8 = 67;
}

/// PDU session type values (TS 24.501 §9.11.4.11)
pub mod pdu_session_type {
    pub const IPV4: u8 = 1;
    pub const IPV6: u8 = 2;
    pub const IPV4V6: u8 = 3;
    pub const UNSTRUCTURED: u8 = 4;
    pub const ETHERNET: u8 = 5;
}

// ---------------------------------------------------------------------------
// Policy decision model (subset of TS 29.512 SmPolicyDecision)
// ---------------------------------------------------------------------------

/// A PCC rule extracted from the SmPolicyDecision (TS 29.512 §5.6.2.6)
#[derive(Debug, Clone, Default)]
pub struct PccRule {
    pub id: String,
    pub precedence: u32,
    /// 5QI from the referenced QoS decision (refQosData)
    pub five_qi: u8,
    pub mbr_ul_bps: Option<u64>,
    pub mbr_dl_bps: Option<u64>,
    pub gbr_ul_bps: Option<u64>,
    pub gbr_dl_bps: Option<u64>,
    pub flow_descriptions: Vec<String>,
    /// FlowStatus from the referenced traffic-control decision (refTcData)
    pub flow_enabled: bool,
    /// Charging decision reference present (refChgData)
    pub has_charging: bool,
}

/// Parsed SM policy decision applied to N1 (NAS) and N4 (PFCP QER/PDR)
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub sm_policy_id: String,
    pub sess_ambr_ul_bps: u64,
    pub sess_ambr_dl_bps: u64,
    pub def_five_qi: u8,
    pub arp_priority_level: u8,
    pub pcc_rules: Vec<PccRule>,
    pub triggers: Vec<String>,
    /// True when this decision is the documented config-default fallback
    /// (no PCF configured), not an authorized PCF decision.
    pub is_config_default: bool,
}

impl PolicyDecision {
    /// Documented config-default fallback used ONLY when no PCF is configured
    /// (see module docs). 5QI=9 non-GBR default bearer, 100 Mbps AMBR.
    pub fn config_default() -> Self {
        Self {
            sm_policy_id: String::new(),
            sess_ambr_ul_bps: 100_000_000,
            sess_ambr_dl_bps: 100_000_000,
            def_five_qi: 9,
            arp_priority_level: 8,
            pcc_rules: Vec::new(),
            triggers: Vec::new(),
            is_config_default: true,
        }
    }

    /// DNN-aware config-default fallback (no PCF configured).
    ///
    /// Starts from [`Self::config_default`] and, when the requested DNN maps to
    /// an XR/URLLC service, upgrades the default flow to a delay-critical GBR
    /// XR 5QI (TS 23.501 Table 5.7.4-1, Rel-18) with a populated PCC rule so the
    /// XR-aware QoS-flow binding and PFCP QER/PDR setup get an XR flow to act on.
    ///
    /// This is the local (PCF-less) equivalent of a PCF authorising an XR 5QI;
    /// the DNN is the only XR signal a standard UE conveys at establishment.
    pub fn config_default_for_dnn(dnn: &str) -> Self {
        let mut dec = Self::config_default();
        dec.ensure_xr_for_dnn(dnn);
        dec
    }

    /// Upgrade this decision to the XR delay-critical GBR 5QI (82-85) when the
    /// DNN names an XR service and the decision does not already carry it.
    ///
    /// The DNN is the only XR signal a standard UE conveys at session
    /// establishment, so the SMF owns this mapping regardless of whether the
    /// authorized policy came from the config-default path or from a PCF (which
    /// may not model XR DNNs). Idempotent: a no-op for a non-XR DNN or when the
    /// decision already carries the matching XR 5QI.
    pub fn ensure_xr_for_dnn(&mut self, dnn: &str) {
        let Some(five_qi) = xr_5qi_for_dnn(dnn) else {
            return;
        };
        if self.def_five_qi == five_qi {
            return;
        }
        // XR is delay-critical GBR: provision a GBR equal to a fraction of the
        // session AMBR so the UPF installs guaranteed-rate buckets and never
        // starves the XR flow.
        let gbr_dl = self.sess_ambr_dl_bps / 2;
        let gbr_ul = self.sess_ambr_ul_bps / 4;
        self.def_five_qi = five_qi;
        // XR flows get a higher ARP priority than the best-effort default.
        self.arp_priority_level = 4;
        let rule_id = format!("xr-default-{five_qi}");
        if !self.pcc_rules.iter().any(|r| r.id == rule_id) {
            self.pcc_rules.push(PccRule {
                id: rule_id,
                precedence: 10,
                five_qi,
                mbr_ul_bps: Some(self.sess_ambr_ul_bps),
                mbr_dl_bps: Some(self.sess_ambr_dl_bps),
                gbr_ul_bps: Some(gbr_ul),
                gbr_dl_bps: Some(gbr_dl),
                flow_descriptions: vec!["permit out ip from any to assigned".to_string()],
                flow_enabled: true,
                has_charging: false,
            });
        }
    }

    /// Default QFI: for the default non-GBR rule the QFI equals the 5QI
    /// (standardized 5QI-to-QFI mapping used for the default flow).
    pub fn default_qfi(&self) -> u8 {
        self.def_five_qi & 0x3F
    }
}

/// Map a requested DNN to an XR/URLLC 5QI when the DNN names an XR service.
///
/// Standardised XR 5QIs are 82-85 (TS 23.501 Table 5.7.4-1). With no PCF this
/// is the deterministic DNN-to-5QI mapping the SMF applies locally:
/// - `xr` / `xr-cloud` → 82 (XR/cloud gaming DL, PDB 10 ms)
/// - `xr-split`        → 84 (XR split rendering DL, PDB 30 ms)
/// - `xr-haptic`       → 85 (XR haptic / split rendering UL, PDB 5 ms)
///
/// Any other DNN returns `None` (best-effort default 5QI applies).
pub fn xr_5qi_for_dnn(dnn: &str) -> Option<u8> {
    match dnn.to_ascii_lowercase().as_str() {
        "xr" | "xr-cloud" | "xr-gaming" => Some(82),
        "xr-split" => Some(84),
        "xr-haptic" => Some(85),
        _ => None,
    }
}

/// Outcome of an Npcf_SMPolicyControl operation
#[derive(Debug)]
pub enum PolicyError {
    /// No PCF configured (no PCF_URI env, no NRF) — caller applies the
    /// documented config-default policy.
    NotConfigured,
    /// PCF answered with an error status (policy rejection)
    Rejected { status: u16, detail: String },
    /// Transport-level failure (PCF unreachable / timeout)
    Transport(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::NotConfigured => write!(f, "no PCF configured"),
            PolicyError::Rejected { status, detail } => {
                write!(f, "PCF rejected SM policy: status={status} ({detail})")
            }
            PolicyError::Transport(e) => write!(f, "PCF transport failure: {e}"),
        }
    }
}

/// Resolved PCF endpoint
#[derive(Debug, Clone)]
pub struct PcfEndpoint {
    pub host: String,
    pub port: u16,
}

impl PcfEndpoint {
    fn client(&self) -> SbiClient {
        SbiClient::new(
            SbiClientConfig::new(self.host.clone(), self.port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        )
    }
}

/// Resolve the PCF endpoint: `PCF_URI` env var first, then NRF discovery
/// (GET /nnrf-disc/v1/nf-instances?target-nf-type=PCF&requester-nf-type=SMF).
pub async fn resolve_pcf_endpoint() -> Option<PcfEndpoint> {
    if let Ok(uri) = std::env::var("PCF_URI") {
        if let Some((host, port)) = split_host_port(&uri) {
            return Some(PcfEndpoint { host, port });
        }
        log::warn!("PCF_URI '{uri}' is not a valid URI — ignoring");
    }

    // NRF discovery
    let nrf_uri = ogs_sbi::context::global_context().get_nrf_uri().await?;
    let (nrf_host, nrf_port) = split_host_port(&nrf_uri)?;
    let client = SbiClient::new(
        SbiClientConfig::new(nrf_host, nrf_port)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    );
    let resp = client
        .get("/nnrf-disc/v1/nf-instances?target-nf-type=PCF&requester-nf-type=SMF")
        .await
        .ok()?;
    if resp.status != 200 {
        log::warn!("NRF PCF discovery returned status {}", resp.status);
        return None;
    }
    let body: serde_json::Value = serde_json::from_str(resp.http.content.as_deref()?).ok()?;
    let inst = body.get("nfInstances")?.as_array()?.first()?;
    let host = inst
        .get("ipv4Addresses")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())?
        .to_string();
    let port = inst
        .get("nfServices")
        .and_then(|s| s.as_array())
        .and_then(|svcs| {
            svcs.iter().find(|s| {
                s.get("serviceName").and_then(|n| n.as_str()) == Some("npcf-smpolicycontrol")
            })
        })
        .and_then(|s| s.get("ipEndPoints"))
        .and_then(|e| e.as_array())
        .and_then(|e| e.first())
        .and_then(|e| e.get("port"))
        .and_then(|p| p.as_u64())
        .map(|p| p as u16)
        .unwrap_or(7777);
    Some(PcfEndpoint { host, port })
}

fn split_host_port(uri: &str) -> Option<(String, u16)> {
    let stripped = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    if let Some((host, port)) = host_port.rsplit_once(':') {
        Some((host.to_string(), port.parse().ok()?))
    } else {
        let default = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default))
    }
}

// ---------------------------------------------------------------------------
// Nnsacf_NSAC PDU-session admission (TS 29.536 §5.3 / §6.1.3.2)
// ---------------------------------------------------------------------------

/// Resolved NSACF endpoint.
#[derive(Debug, Clone)]
pub struct NsacfEndpoint {
    pub host: String,
    pub port: u16,
}

impl NsacfEndpoint {
    fn client(&self) -> SbiClient {
        SbiClient::new(
            SbiClientConfig::new(self.host.clone(), self.port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        )
    }
}

/// Resolve the NSACF endpoint: `NSACF_URI` env var first, then NRF discovery
/// (GET /nnrf-disc/v1/nf-instances?target-nf-type=NSACF&requester-nf-type=SMF).
/// Returns `None` when no NSACF is configured/discoverable, so the caller can
/// treat slice admission control as not deployed (skip the check).
pub async fn resolve_nsacf_endpoint() -> Option<NsacfEndpoint> {
    if let Ok(uri) = std::env::var("NSACF_URI") {
        if let Some((host, port)) = split_host_port(&uri) {
            return Some(NsacfEndpoint { host, port });
        }
        log::warn!("NSACF_URI '{uri}' is not a valid URI — ignoring");
    }

    // NRF discovery
    let nrf_uri = ogs_sbi::context::global_context().get_nrf_uri().await?;
    let (nrf_host, nrf_port) = split_host_port(&nrf_uri)?;
    let client = SbiClient::new(
        SbiClientConfig::new(nrf_host, nrf_port)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    );
    let resp = client
        .get("/nnrf-disc/v1/nf-instances?target-nf-type=NSACF&requester-nf-type=SMF")
        .await
        .ok()?;
    if resp.status != 200 {
        log::debug!("NRF NSACF discovery returned status {}", resp.status);
        return None;
    }
    let body: serde_json::Value = serde_json::from_str(resp.http.content.as_deref()?).ok()?;
    let inst = body.get("nfInstances")?.as_array()?.first()?;
    let host = inst
        .get("ipv4Addresses")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())?
        .to_string();
    let port = inst
        .get("nfServices")
        .and_then(|s| s.as_array())
        .and_then(|svcs| {
            svcs.iter()
                .find(|s| s.get("serviceName").and_then(|n| n.as_str()) == Some("nnsacf-nsac"))
        })
        .and_then(|s| s.get("ipEndPoints"))
        .and_then(|e| e.as_array())
        .and_then(|e| e.first())
        .and_then(|e| e.get("port"))
        .and_then(|p| p.as_u64())
        .map(|p| p as u16)
        .unwrap_or(7813);
    Some(NsacfEndpoint { host, port })
}

/// Outcome of an Nnsacf_NSAC PDU-session admission query (TS 29.536).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsacAdmission {
    /// PDU session admitted (admittedFlag=true) — proceed with establishment.
    Admitted,
    /// PDU session rejected (admittedFlag=false) — reject with 5GSM cause #67.
    Rejected,
    /// NSACF could not be reached / returned an error. The caller decides the
    /// fail-open vs fail-closed policy.
    Unavailable,
}

/// Query the NSACF whether a new PDU session may be established on `s_nssai`
/// for `psi` (TS 29.536 §6.1.3.2, POST /nnsacf-nsac/v1/slices/pdu-sessions).
///
/// Per the contract, a rejection is an HTTP 200 with `admittedFlag=false`
/// (NOT a 4xx), so we distinguish [`NsacAdmission::Rejected`] (200 +
/// admittedFlag=false) from [`NsacAdmission::Unavailable`] (transport/HTTP
/// error). `nf_id` is this SMF's NF instance id (the request's `nfId`).
pub async fn nsac_pdu_session_admit(
    nsacf: &NsacfEndpoint,
    nf_id: &str,
    supi: &str,
    psi: u8,
    sst: u8,
    sd: Option<&str>,
) -> NsacAdmission {
    let mut snssai = serde_json::json!({ "sst": sst });
    if let Some(sd) = sd {
        snssai["sd"] = serde_json::json!(sd);
    }
    let body = serde_json::json!({
        "snssai": snssai,
        "nfId": nf_id,
        "updateFlag": "INCREASE",
        "pduSessionId": psi,
        "supi": supi,
    });

    let client = nsacf.client();
    let resp = match client
        .post_json("/nnsacf-nsac/v1/slices/pdu-sessions", &body)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!("NSACF PDU-session admission query failed: {e}");
            client.close().await;
            return NsacAdmission::Unavailable;
        }
    };
    client.close().await;

    if resp.status != 200 {
        log::warn!(
            "NSACF PDU-session admission returned HTTP {} (expected 200)",
            resp.status
        );
        return NsacAdmission::Unavailable;
    }
    let parsed: Option<serde_json::Value> = resp
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok());
    let Some(parsed) = parsed else {
        log::warn!("NSACF PDU-session admission response had no/invalid JSON body");
        return NsacAdmission::Unavailable;
    };
    match parsed.get("admittedFlag").and_then(|v| v.as_bool()) {
        Some(true) => NsacAdmission::Admitted,
        Some(false) => {
            let cause = parsed
                .get("rejectCause")
                .and_then(|v| v.as_str())
                .unwrap_or("UNSPECIFIED");
            log::info!(
                "NSACF rejected PDU session for S-NSSAI[SST:{sst} SD:{sd:?}] (cause={cause})"
            );
            NsacAdmission::Rejected
        }
        None => {
            log::warn!("NSACF PDU-session admission response missing admittedFlag");
            NsacAdmission::Unavailable
        }
    }
}

/// Release a NSACF PDU-session count (DECREASE) for rollback when a later
/// establishment step fails after the slot was admitted. Best-effort.
pub async fn nsac_pdu_session_release(
    nsacf: &NsacfEndpoint,
    nf_id: &str,
    supi: &str,
    psi: u8,
    sst: u8,
    sd: Option<&str>,
) {
    let mut snssai = serde_json::json!({ "sst": sst });
    if let Some(sd) = sd {
        snssai["sd"] = serde_json::json!(sd);
    }
    let body = serde_json::json!({
        "snssai": snssai,
        "nfId": nf_id,
        "updateFlag": "DECREASE",
        "pduSessionId": psi,
        "supi": supi,
    });
    let client = nsacf.client();
    if let Err(e) = client
        .post_json("/nnsacf-nsac/v1/slices/pdu-sessions", &body)
        .await
    {
        log::warn!("NSACF PDU-session release (rollback) failed: {e}");
    }
    client.close().await;
}

// ---------------------------------------------------------------------------
// Npcf_SMPolicyControl operations (TS 29.512)
// ---------------------------------------------------------------------------

/// Context for the SM Policy Create request (TS 29.512 §5.6.2.3
/// SmPolicyContextData mandatory attributes).
pub struct SmPolicyCreateContext<'a> {
    pub supi: &'a str,
    pub psi: u8,
    pub pdu_session_type: u8,
    pub dnn: &'a str,
    pub sst: u8,
    pub sd: Option<&'a str>,
    pub ue_ipv4: [u8; 4],
    pub notification_uri: &'a str,
}

fn pdu_session_type_name(t: u8) -> &'static str {
    match t {
        pdu_session_type::IPV6 => "IPV6",
        pdu_session_type::IPV4V6 => "IPV4V6",
        pdu_session_type::UNSTRUCTURED => "UNSTRUCTURED",
        pdu_session_type::ETHERNET => "ETHERNET",
        _ => "IPV4",
    }
}

/// Npcf_SMPolicyControl_Create (POST /npcf-smpolicycontrol/v1/sm-policies)
pub async fn sm_policy_create(
    pcf: &PcfEndpoint,
    ctx: &SmPolicyCreateContext<'_>,
) -> Result<PolicyDecision, PolicyError> {
    let ip = ctx.ue_ipv4;
    let mut slice_info = serde_json::json!({ "sst": ctx.sst });
    if let Some(sd) = ctx.sd {
        slice_info["sd"] = serde_json::json!(sd);
    }
    let body = serde_json::json!({
        "supi": ctx.supi,
        "pduSessionId": ctx.psi,
        "pduSessionType": pdu_session_type_name(ctx.pdu_session_type),
        "dnn": ctx.dnn,
        "notificationUri": ctx.notification_uri,
        "ipv4Address": format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        "sliceInfo": slice_info,
        "servingNetwork": { "mcc": "001", "mnc": "01" },
        "suppFeat": "0",
    });

    let resp = pcf
        .client()
        .post_json("/npcf-smpolicycontrol/v1/sm-policies", &body)
        .await
        .map_err(|e| PolicyError::Transport(e.to_string()))?;

    if resp.status != 201 && resp.status != 200 {
        return Err(PolicyError::Rejected {
            status: resp.status,
            detail: resp.http.content.clone().unwrap_or_default(),
        });
    }

    let json: serde_json::Value = resp
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .ok_or_else(|| PolicyError::Transport("empty/invalid SmPolicyDecision body".into()))?;

    // smPolicyId: Location header last segment, else body field
    let sm_policy_id = resp
        .http
        .headers
        .get("location")
        .and_then(|l| l.rsplit('/').next())
        .map(str::to_string)
        .or_else(|| json["smPolicyId"].as_str().map(str::to_string))
        .ok_or_else(|| {
            PolicyError::Transport(
                "SmPolicyControl Create response missing Location/smPolicyId".into(),
            )
        })?;

    Ok(parse_sm_policy_decision(&sm_policy_id, &json))
}

/// Npcf_SMPolicyControl_Update
/// (POST /npcf-smpolicycontrol/v1/sm-policies/{id}/update)
pub async fn sm_policy_update(
    pcf: &PcfEndpoint,
    sm_policy_id: &str,
    triggers: &[&str],
    ue_init_res_req: Option<serde_json::Value>,
) -> Result<PolicyDecision, PolicyError> {
    let mut body = serde_json::json!({
        "repPolicyCtrlReqTriggers": triggers,
    });
    if let Some(req) = ue_init_res_req {
        body["ueInitResReq"] = req;
    }
    let path = format!("/npcf-smpolicycontrol/v1/sm-policies/{sm_policy_id}/update");
    let resp = pcf
        .client()
        .post_json(&path, &body)
        .await
        .map_err(|e| PolicyError::Transport(e.to_string()))?;
    if resp.status != 200 {
        return Err(PolicyError::Rejected {
            status: resp.status,
            detail: resp.http.content.clone().unwrap_or_default(),
        });
    }
    let json: serde_json::Value = resp
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .ok_or_else(|| PolicyError::Transport("empty/invalid SmPolicyDecision body".into()))?;
    Ok(parse_sm_policy_decision(sm_policy_id, &json))
}

/// Npcf_SMPolicyControl_Delete
/// (POST /npcf-smpolicycontrol/v1/sm-policies/{id}/delete — TS 29.512 §4.2.5)
pub async fn sm_policy_delete(pcf: &PcfEndpoint, sm_policy_id: &str) -> Result<(), PolicyError> {
    let path = format!("/npcf-smpolicycontrol/v1/sm-policies/{sm_policy_id}/delete");
    let resp = pcf
        .client()
        .post_json(&path, &serde_json::json!({}))
        .await
        .map_err(|e| PolicyError::Transport(e.to_string()))?;
    match resp.status {
        204 | 200 => Ok(()),
        s => Err(PolicyError::Rejected {
            status: s,
            detail: resp.http.content.clone().unwrap_or_default(),
        }),
    }
}

/// Parse an SmPolicyDecision JSON body into a [`PolicyDecision`].
pub fn parse_sm_policy_decision(sm_policy_id: &str, json: &serde_json::Value) -> PolicyDecision {
    let mut dec = PolicyDecision {
        sm_policy_id: sm_policy_id.to_string(),
        ..PolicyDecision::config_default()
    };
    dec.is_config_default = false;

    // Session rules: authorized session AMBR + default QoS
    if let Some(rules) = json.get("sessRules").and_then(|v| v.as_object()) {
        if let Some(rule) = rules.values().next() {
            if let Some(ambr) = rule.get("authSessAmbr") {
                if let Some(ul) = ambr.get("uplink").and_then(|v| v.as_str()) {
                    dec.sess_ambr_ul_bps = parse_bitrate(ul).unwrap_or(dec.sess_ambr_ul_bps);
                }
                if let Some(dl) = ambr.get("downlink").and_then(|v| v.as_str()) {
                    dec.sess_ambr_dl_bps = parse_bitrate(dl).unwrap_or(dec.sess_ambr_dl_bps);
                }
            }
            if let Some(qos) = rule.get("authDefQos") {
                if let Some(q) = qos.get("5qi").and_then(|v| v.as_u64()) {
                    dec.def_five_qi = q as u8;
                }
                if let Some(p) = qos
                    .get("arp")
                    .and_then(|a| a.get("priorityLevel"))
                    .and_then(|v| v.as_u64())
                {
                    dec.arp_priority_level = p as u8;
                }
            }
        }
    }

    // QoS decisions referenced by PCC rules
    let qos_decs = json.get("qosDecs").and_then(|v| v.as_object());
    // Traffic-control decisions (traffContDecs) referenced by PCC rules
    let tc_decs = json.get("traffContDecs").and_then(|v| v.as_object());
    let chg_decs = json.get("chgDecs").and_then(|v| v.as_object());

    if let Some(pcc) = json.get("pccRules").and_then(|v| v.as_object()) {
        for (id, rule) in pcc {
            if rule.is_null() {
                continue; // rule removal entry
            }
            let mut r = PccRule {
                id: id.clone(),
                precedence: rule
                    .get("precedence")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(255) as u32,
                five_qi: dec.def_five_qi,
                flow_enabled: true,
                ..Default::default()
            };
            for fi in rule
                .get("flowInfos")
                .and_then(|v| v.as_array())
                .map(|a| a.as_slice())
                .unwrap_or(&[])
            {
                if let Some(d) = fi.get("flowDescription").and_then(|v| v.as_str()) {
                    r.flow_descriptions.push(d.to_string());
                }
            }
            if let Some(qref) = rule
                .get("refQosData")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                if let Some(q) = qos_decs.and_then(|m| m.get(qref)) {
                    if let Some(v) = q.get("5qi").and_then(|v| v.as_u64()) {
                        r.five_qi = v as u8;
                    }
                    r.mbr_ul_bps = q
                        .get("maxbrUl")
                        .and_then(|v| v.as_str())
                        .and_then(parse_bitrate);
                    r.mbr_dl_bps = q
                        .get("maxbrDl")
                        .and_then(|v| v.as_str())
                        .and_then(parse_bitrate);
                    r.gbr_ul_bps = q
                        .get("gbrUl")
                        .and_then(|v| v.as_str())
                        .and_then(parse_bitrate);
                    r.gbr_dl_bps = q
                        .get("gbrDl")
                        .and_then(|v| v.as_str())
                        .and_then(parse_bitrate);
                }
            }
            if let Some(tref) = rule
                .get("refTcData")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                if let Some(tc) = tc_decs.and_then(|m| m.get(tref)) {
                    r.flow_enabled = tc
                        .get("flowStatus")
                        .and_then(|v| v.as_str())
                        .map(|s| s != "DISABLED" && s != "REMOVED")
                        .unwrap_or(true);
                }
            }
            r.has_charging = rule
                .get("refChgData")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(|cref| chg_decs.map(|m| m.contains_key(cref)).unwrap_or(false))
                .unwrap_or(false);
            dec.pcc_rules.push(r);
        }
    }

    if let Some(triggers) = json.get("policyCtrlReqTriggers").and_then(|v| v.as_array()) {
        dec.triggers = triggers
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }

    dec
}

/// Parse a TS 29.571 BitRate string ("100 Mbps", "1 Gbps", "500 Kbps").
pub fn parse_bitrate(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_once(' ')?;
    let value: f64 = num.parse().ok()?;
    let mult: u64 = match unit {
        "bps" => 1,
        "Kbps" => 1_000,
        "Mbps" => 1_000_000,
        "Gbps" => 1_000_000_000,
        "Tbps" => 1_000_000_000_000,
        _ => return None,
    };
    Some((value * mult as f64) as u64)
}

// ---------------------------------------------------------------------------
// N1 SM container codec (TS 24.501 §8.3)
// ---------------------------------------------------------------------------

/// 5GSM message types (TS 24.501 Table 9.7.2)
pub mod gsm_message_type {
    pub const ESTABLISHMENT_REQUEST: u8 = 0xC1;
    pub const ESTABLISHMENT_ACCEPT: u8 = 0xC2;
    pub const ESTABLISHMENT_REJECT: u8 = 0xC3;
    pub const MODIFICATION_REQUEST: u8 = 0xC9;
    pub const MODIFICATION_COMMAND: u8 = 0xCB;
    #[allow(dead_code)]
    pub const RELEASE_REQUEST: u8 = 0xD1;
    pub const RELEASE_COMMAND: u8 = 0xD3;
}

/// Common 5GSM header (EPD + PSI + PTI + message type)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N1SmHeader {
    pub psi: u8,
    pub pti: u8,
    pub message_type: u8,
}

/// Parse the 4-byte 5GSM header. Returns None unless EPD == 0x2E (5GSM).
pub fn parse_n1_sm_header(buf: &[u8]) -> Option<N1SmHeader> {
    if buf.len() < 4 || buf[0] != 0x2E {
        return None;
    }
    Some(N1SmHeader {
        psi: buf[1],
        pti: buf[2],
        message_type: buf[3],
    })
}

/// Decoded PDU Session Establishment Request (TS 24.501 §8.3.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentRequest {
    pub psi: u8,
    pub pti: u8,
    /// Integrity protection maximum data rate (UL, DL) — mandatory IE
    pub integrity_max_rate: (u8, u8),
    /// Requested PDU session type (IEI 0x9-, TS 24.501 §9.11.4.11)
    pub requested_pdu_session_type: Option<u8>,
    /// Requested SSC mode (IEI 0xA-, TS 24.501 §9.11.4.16)
    pub requested_ssc_mode: Option<u8>,
}

/// Parse a PDU Session Establishment Request N1 SM container.
pub fn parse_establishment_request(buf: &[u8]) -> Option<EstablishmentRequest> {
    let hdr = parse_n1_sm_header(buf)?;
    if hdr.message_type != gsm_message_type::ESTABLISHMENT_REQUEST {
        return None;
    }
    // Mandatory: Integrity protection maximum data rate (2 octets)
    if buf.len() < 6 {
        return None;
    }
    let mut req = EstablishmentRequest {
        psi: hdr.psi,
        pti: hdr.pti,
        integrity_max_rate: (buf[4], buf[5]),
        requested_pdu_session_type: None,
        requested_ssc_mode: None,
    };

    // Optional IEs
    let mut i = 6;
    while i < buf.len() {
        let iei = buf[i];
        match iei >> 4 {
            // PDU session type (type-1 TV, half-octet IEI 0x9)
            0x9 => {
                req.requested_pdu_session_type = Some(iei & 0x07);
                i += 1;
            }
            // SSC mode (type-1 TV, half-octet IEI 0xA)
            0xA => {
                req.requested_ssc_mode = Some(iei & 0x07);
                i += 1;
            }
            _ => match iei {
                // Maximum number of supported packet filters (TV, 3 octets)
                0x55 => i += 3,
                // Extended protocol configuration options (TLV-E, 2-octet len)
                0x7B => {
                    if i + 3 > buf.len() {
                        break;
                    }
                    let len = u16::from_be_bytes([buf[i + 1], buf[i + 2]]) as usize;
                    i += 3 + len;
                }
                // Everything else in this message is TLV (1-octet len)
                _ => {
                    if i + 2 > buf.len() {
                        break;
                    }
                    let len = buf[i + 1] as usize;
                    i += 2 + len;
                }
            },
        }
    }
    Some(req)
}

/// Encode a Session-AMBR component (unit + 2-octet value, TS 24.501
/// §9.11.4.14 Table 9.11.4.14.1). Prefers the canonical decimal units
/// (1 Gbps > 1 Mbps > 1 Kbps) when they represent the rate exactly — this
/// matches the wire encoding the E2E peers already exchange — and falls
/// back to the smallest unit that fits (rounded up) otherwise.
pub fn encode_ambr_component(bps: u64) -> (u8, u16) {
    const CANONICAL: &[(u8, u64)] = &[
        (0x0B, 1_000_000_000), // 1 Gbps
        (0x06, 1_000_000),     // 1 Mbps
        (0x01, 1_000),         // 1 Kbps
    ];
    for &(unit, step) in CANONICAL {
        if bps >= step && bps.is_multiple_of(step) && bps / step <= u16::MAX as u64 {
            return (unit, (bps / step) as u16);
        }
    }
    const UNITS: &[(u8, u64)] = &[
        (0x01, 1_000),         // 1 Kbps
        (0x02, 4_000),         // 4 Kbps
        (0x03, 16_000),        // 16 Kbps
        (0x04, 64_000),        // 64 Kbps
        (0x05, 256_000),       // 256 Kbps
        (0x06, 1_000_000),     // 1 Mbps
        (0x07, 4_000_000),     // 4 Mbps
        (0x08, 16_000_000),    // 16 Mbps
        (0x09, 64_000_000),    // 64 Mbps
        (0x0A, 256_000_000),   // 256 Mbps
        (0x0B, 1_000_000_000), // 1 Gbps
    ];
    for &(unit, step) in UNITS {
        let v = bps.div_ceil(step);
        if v <= u16::MAX as u64 {
            return (unit, v as u16);
        }
    }
    (0x0B, u16::MAX)
}

/// Build a PDU Session Establishment Accept with policy-derived QoS,
/// wire-conformant per TS 24.501 §8.3.2 Table 8.3.2.1.1.
///
/// Octet layout (after the 4-octet SM header EPD/PSI/PTI/message-type):
/// - octet 5: selected SSC mode (bits 5-7) packed with selected PDU
///   session type (bits 1-3) in a SINGLE octet;
/// - Authorized QoS rules: LV-E (2-octet length) carrying the rules
///   produced by [`crate::gsm_build::encode_qos_rules`]
///   (QoS-rule-id / 2-octet rule length / rule-operation+flags / packet
///   filters / precedence / QFI);
/// - Session-AMBR: LV (1-octet length = 6) with DL unit+value and UL
///   unit+value.
///
/// Values are policy-derived (not hardcoded).
#[allow(clippy::too_many_arguments)]
pub fn build_establishment_accept(
    psi: u8,
    pti: u8,
    selected_pdu_session_type: u8,
    selected_ssc_mode: u8,
    qfi: u8,
    ambr_dl_bps: u64,
    ambr_ul_bps: u64,
    ue_ip: [u8; 4],
    dnn: &str,
) -> Vec<u8> {
    use crate::gsm_build::{
        encode_qos_rules, pf_component_type, pf_direction, qos_rule_code, PacketFilterComponent,
        PacketFilterContent, QosRule, QosRulePacketFilter,
    };

    let mut msg = Vec::with_capacity(32 + dnn.len());
    msg.push(0x2E); // EPD: 5GSM
    msg.push(psi);
    msg.push(pti); // echo the UE's PTI (TS 24.501 §6.3.1.3)
    msg.push(gsm_message_type::ESTABLISHMENT_ACCEPT);

    // Octet 5: SSC mode (bits 5-7, high nibble) | PDU session type
    // (bits 1-3, low nibble) — single packed octet per Table 8.3.2.1.1.
    msg.push(((selected_ssc_mode & 0x07) << 4) | (selected_pdu_session_type & 0x07));

    // Authorized QoS rules (mandatory, LV-E): a default CREATE rule with a
    // match-all bidirectional packet filter, lowest precedence and the
    // policy-derived QFI. Encoded by the conformant QoS-rule encoder.
    let default_rule = QosRule {
        identifier: qfi & 0x3F,
        code: qos_rule_code::CREATE_NEW_QOS_RULE,
        dqr_bit: true,
        packet_filters: vec![QosRulePacketFilter {
            direction: pf_direction::BIDIRECTIONAL,
            identifier: 1,
            content: PacketFilterContent {
                components: vec![PacketFilterComponent {
                    component_type: pf_component_type::MATCH_ALL,
                    data: vec![],
                }],
            },
        }],
        precedence: 255,
        segregation: false,
        qfi: qfi & 0x3F,
    };
    let qos_rules = encode_qos_rules(&[default_rule]);
    msg.extend_from_slice(&(qos_rules.len() as u16).to_be_bytes());
    msg.extend_from_slice(&qos_rules);

    // Session-AMBR (mandatory, LV; length 6: DL unit+value, UL unit+value)
    let (dl_unit, dl_val) = encode_ambr_component(ambr_dl_bps);
    let (ul_unit, ul_val) = encode_ambr_component(ambr_ul_bps);
    msg.push(0x06);
    msg.push(dl_unit);
    msg.extend_from_slice(&dl_val.to_be_bytes());
    msg.push(ul_unit);
    msg.extend_from_slice(&ul_val.to_be_bytes());

    // PDU address (IEI 0x29) — IPv4
    msg.push(0x29);
    msg.push(0x05);
    msg.push(0x01);
    msg.extend_from_slice(&ue_ip);
    // DNN (IEI 0x25)
    let dnn_bytes = dnn.as_bytes();
    msg.push(0x25);
    msg.push((dnn_bytes.len() + 1) as u8);
    msg.push(dnn_bytes.len() as u8);
    msg.extend_from_slice(dnn_bytes);
    msg
}

/// Build a PDU Session Establishment Reject with a 5GSM cause
/// (TS 24.501 §8.3.3).
pub fn build_establishment_reject(psi: u8, pti: u8, cause_5gsm: u8) -> Vec<u8> {
    vec![
        0x2E,
        psi,
        pti,
        gsm_message_type::ESTABLISHMENT_REJECT,
        cause_5gsm,
    ]
}

/// Build a PDU Session Modification Command echoing the UE's PTI and
/// carrying the authorized Session-AMBR (TS 24.501 §8.3.9).
pub fn build_modification_command(psi: u8, pti: u8, ambr_dl_bps: u64, ambr_ul_bps: u64) -> Vec<u8> {
    let mut msg = vec![0x2E, psi, pti, gsm_message_type::MODIFICATION_COMMAND];
    // Session-AMBR (optional IEI 0x2A in Modification Command)
    let (dl_unit, dl_val) = encode_ambr_component(ambr_dl_bps);
    let (ul_unit, ul_val) = encode_ambr_component(ambr_ul_bps);
    msg.push(0x2A);
    msg.push(0x06);
    msg.push(dl_unit);
    msg.extend_from_slice(&dl_val.to_be_bytes());
    msg.push(ul_unit);
    msg.extend_from_slice(&ul_val.to_be_bytes());
    msg
}

/// Build a PDU Session Release Command (TS 24.501 §8.3.13).
pub fn build_release_command(psi: u8, pti: u8, cause_5gsm: u8) -> Vec<u8> {
    vec![
        0x2E,
        psi,
        pti,
        gsm_message_type::RELEASE_COMMAND,
        cause_5gsm,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------- N1 SM codec ------------------------------

    #[test]
    fn parse_establishment_request_full() {
        // EPD, PSI=5, PTI=2, type=0xC1, integrity max rate (0xFF,0xFF),
        // PDU session type IPv4v6 (0x93), SSC mode 2 (0xA2),
        // 5GSM capability TLV (0x28, len 1), max packet filters TV (0x55)
        let buf = [
            0x2E, 0x05, 0x02, 0xC1, 0xFF, 0xFF, 0x93, 0xA2, 0x28, 0x01, 0x00, 0x55, 0x00, 0x10,
        ];
        let req = parse_establishment_request(&buf).expect("parse");
        assert_eq!(req.psi, 5);
        assert_eq!(req.pti, 2);
        assert_eq!(req.integrity_max_rate, (0xFF, 0xFF));
        assert_eq!(req.requested_pdu_session_type, Some(3)); // IPv4v6
        assert_eq!(req.requested_ssc_mode, Some(2));
    }

    #[test]
    fn parse_establishment_request_minimal() {
        let buf = [0x2E, 0x01, 0x01, 0xC1, 0x00, 0x00];
        let req = parse_establishment_request(&buf).expect("parse");
        assert_eq!(req.requested_pdu_session_type, None);
        assert_eq!(req.requested_ssc_mode, None);
    }

    #[test]
    fn parse_rejects_wrong_epd_and_type() {
        assert!(parse_n1_sm_header(&[0x7E, 1, 1, 0xC1]).is_none()); // 5GMM EPD
        assert!(parse_establishment_request(&[0x2E, 1, 1, 0xC9, 0, 0]).is_none());
        assert!(parse_establishment_request(&[0x2E, 1, 1, 0xC1]).is_none()); // missing mandatory IE
    }

    #[test]
    fn accept_message_carries_policy_values() {
        // SSC mode 2, PDU type IPv4 (0x01), QFI 9
        let msg = build_establishment_accept(
            5,
            3,
            pdu_session_type::IPV4,
            2,
            9,
            200_000_000,
            50_000_000,
            [10, 45, 0, 2],
            "internet",
        );
        // SM header (TS 24.501 §9.3 / Table 8.3.2.1.1 octets 1-4)
        assert_eq!(msg[0], 0x2E); // EPD: 5GSM
        assert_eq!(msg[1], 5); // PSI
        assert_eq!(msg[2], 3); // PTI echoed
        assert_eq!(msg[3], 0xC2); // message type: Establishment Accept

        // Octet 5: SSC mode (bits 5-7, high nibble) packed with PDU
        // session type (bits 1-3, low nibble) in a SINGLE octet.
        // SSC mode 2 (0b010) << 4 | IPv4 (0b001) = 0x21
        assert_eq!(msg[4], 0x21);

        // Authorized QoS rules as LV-E (2-octet length) per Table 8.3.2.1.1.
        let qos_len = u16::from_be_bytes([msg[5], msg[6]]) as usize;
        // One default CREATE rule with a match-all packet filter encoded by
        // the conformant QoS-rule encoder:
        //   [qfi][len_hi][len_lo][op+flags=0x31][pf_hdr=0x31][pf_len=1]
        //   [match-all=0x01][precedence=0xFF][qfi]
        assert_eq!(qos_len, 9);
        let qos = &msg[7..7 + qos_len];
        assert_eq!(qos[0], 9); // QoS rule identifier == QFI
        assert_eq!(u16::from_be_bytes([qos[1], qos[2]]), 6); // rule length (2-octet)
        // op (CREATE=1)<<5 | DQR(0x10) | num_pf(1) = 0x31
        assert_eq!(qos[3], 0x31);
        // packet filter header: dir BIDIR(3)<<4 | pf id 1 = 0x31
        assert_eq!(qos[4], 0x31);
        assert_eq!(qos[5], 1); // pf content length
        assert_eq!(qos[6], 0x01); // match-all component type
        assert_eq!(qos[7], 0xFF); // precedence
        assert_eq!(qos[8], 9); // QFI (segregation bit clear)

        // Session-AMBR LV (1-octet length = 6) immediately after the QoS LV-E.
        let ambr_off = 7 + qos_len;
        assert_eq!(msg[ambr_off], 0x06); // length (single octet, no double-length bug)
        assert_eq!(msg[ambr_off + 1], 0x06); // DL unit: 1 Mbps
        assert_eq!(
            u16::from_be_bytes([msg[ambr_off + 2], msg[ambr_off + 3]]),
            200
        );
        assert_eq!(msg[ambr_off + 4], 0x06); // UL unit: 1 Mbps
        assert_eq!(
            u16::from_be_bytes([msg[ambr_off + 5], msg[ambr_off + 6]]),
            50
        );

        // PDU address (IEI 0x29) follows the Session-AMBR.
        let pdu_off = ambr_off + 7;
        assert_eq!(msg[pdu_off], 0x29);
        assert_eq!(msg[pdu_off + 1], 0x05); // length
        assert_eq!(msg[pdu_off + 2], 0x01); // IPv4
        assert_eq!(&msg[pdu_off + 3..pdu_off + 7], &[10, 45, 0, 2]);
    }

    #[test]
    fn reject_message_has_cause() {
        let msg = build_establishment_reject(
            1,
            2,
            gsm_cause::USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED,
        );
        assert_eq!(msg, vec![0x2E, 1, 2, 0xC3, 29]);
    }

    #[test]
    fn ambr_component_unit_selection() {
        assert_eq!(encode_ambr_component(100_000_000), (0x06, 100)); // 100 Mbps
        assert_eq!(encode_ambr_component(64_000), (0x01, 64)); // 64 Kbps
        assert_eq!(encode_ambr_component(2_000_000_000), (0x0B, 2)); // 2 Gbps
    }

    // ------------------------- bitrate / decision -----------------------

    #[test]
    fn bitrate_parsing() {
        assert_eq!(parse_bitrate("100 Mbps"), Some(100_000_000));
        assert_eq!(parse_bitrate("1 Gbps"), Some(1_000_000_000));
        assert_eq!(parse_bitrate("500 Kbps"), Some(500_000));
        assert_eq!(parse_bitrate("42 bps"), Some(42));
        assert_eq!(parse_bitrate("bogus"), None);
    }

    #[test]
    fn decision_parsing_with_chg_and_tc_decs() {
        let body = serde_json::json!({
            "sessRules": {
                "SessRule-1": {
                    "authSessAmbr": { "uplink": "50 Mbps", "downlink": "150 Mbps" },
                    "authDefQos": { "5qi": 7, "arp": { "priorityLevel": 3 } }
                }
            },
            "qosDecs": {
                "Q1": { "qosDecId": "Q1", "5qi": 5, "gbrUl": "1 Mbps", "gbrDl": "2 Mbps" }
            },
            "traffContDecs": {
                "T1": { "tcId": "T1", "flowStatus": "DISABLED" }
            },
            "chgDecs": {
                "C1": { "chgId": "C1", "ratingGroup": 1 }
            },
            "pccRules": {
                "rule-1": {
                    "pccRuleId": "rule-1",
                    "precedence": 10,
                    "flowInfos": [ { "flowDescription": "permit out ip from any to assigned" } ],
                    "refQosData": ["Q1"],
                    "refTcData": ["T1"],
                    "refChgData": ["C1"]
                }
            },
            "policyCtrlReqTriggers": ["SE_AMBR_CH"]
        });
        let dec = parse_sm_policy_decision("pid-1", &body);
        assert_eq!(dec.sess_ambr_ul_bps, 50_000_000);
        assert_eq!(dec.sess_ambr_dl_bps, 150_000_000);
        assert_eq!(dec.def_five_qi, 7);
        assert_eq!(dec.arp_priority_level, 3);
        assert!(!dec.is_config_default);
        assert_eq!(dec.pcc_rules.len(), 1);
        let r = &dec.pcc_rules[0];
        assert_eq!(r.five_qi, 5);
        assert_eq!(r.gbr_ul_bps, Some(1_000_000));
        assert_eq!(r.gbr_dl_bps, Some(2_000_000));
        assert!(!r.flow_enabled); // traffContDec DISABLED applied
        assert!(r.has_charging); // chgDec reference resolved
        assert_eq!(dec.triggers, vec!["SE_AMBR_CH"]);
    }

    #[test]
    fn config_default_is_flagged() {
        let dec = PolicyDecision::config_default();
        assert!(dec.is_config_default);
        assert_eq!(dec.def_five_qi, 9);
        assert_eq!(dec.default_qfi(), 9);
    }

    #[test]
    fn xr_5qi_for_dnn_maps_xr_services() {
        assert_eq!(xr_5qi_for_dnn("xr"), Some(82));
        assert_eq!(xr_5qi_for_dnn("XR"), Some(82));
        assert_eq!(xr_5qi_for_dnn("xr-cloud"), Some(82));
        assert_eq!(xr_5qi_for_dnn("xr-split"), Some(84));
        assert_eq!(xr_5qi_for_dnn("xr-haptic"), Some(85));
        assert_eq!(xr_5qi_for_dnn("internet"), None);
    }

    #[test]
    fn config_default_for_xr_dnn_yields_xr_gbr_rule() {
        // Non-XR DNN behaves exactly like config_default (best-effort 5QI 9,
        // no PCC rules).
        let plain = PolicyDecision::config_default_for_dnn("internet");
        assert_eq!(plain.def_five_qi, 9);
        assert!(plain.pcc_rules.is_empty());

        // XR DNN upgrades the default flow to a delay-critical GBR XR 5QI and
        // emits a GBR PCC rule the XR-aware binding can act on.
        let xr = PolicyDecision::config_default_for_dnn("xr");
        assert_eq!(xr.def_five_qi, 82);
        assert!(xr.is_config_default);
        assert_eq!(xr.pcc_rules.len(), 1);
        let rule = &xr.pcc_rules[0];
        assert_eq!(rule.five_qi, 82);
        assert!(rule.gbr_dl_bps.unwrap_or(0) > 0);
        assert!(rule.gbr_ul_bps.unwrap_or(0) > 0);
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(
            split_host_port("http://1.2.3.4:7777"),
            Some(("1.2.3.4".into(), 7777))
        );
        assert_eq!(split_host_port("https://pcf"), Some(("pcf".into(), 443)));
        assert_eq!(
            split_host_port("http://pcf:80/extra/path"),
            Some(("pcf".into(), 80))
        );
    }

    // --------------- HTTP round-trip against a stub PCF -----------------

    async fn stub_pcf_handler(req: ogs_sbi::message::SbiRequest) -> ogs_sbi::message::SbiResponse {
        let path = req.header.uri.split('?').next().unwrap_or("");
        let decision = serde_json::json!({
            "sessRules": {
                "SessRule-x": {
                    "authSessAmbr": { "uplink": "20 Mbps", "downlink": "80 Mbps" },
                    "authDefQos": { "5qi": 8, "arp": { "priorityLevel": 6 } }
                }
            },
            "qosDecs": {}, "pccRules": {}, "chgDecs": {}, "traffContDecs": {},
            "policyCtrlReqTriggers": ["SE_AMBR_CH"]
        });
        if path == "/npcf-smpolicycontrol/v1/sm-policies" && req.header.method == "POST" {
            // Reject sessions for PSI 13 to exercise the rejection path
            let body: serde_json::Value = req
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str(c).ok())
                .unwrap_or_default();
            if body["pduSessionId"].as_u64() == Some(13) {
                return ogs_sbi::message::SbiResponse::with_status(403).with_body(
                    serde_json::json!({"cause": "POLICY_REJECTED"}).to_string(),
                    "application/problem+json",
                );
            }
            return ogs_sbi::message::SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    "/npcf-smpolicycontrol/v1/sm-policies/stub-pol-1",
                )
                .with_body(decision.to_string(), "application/json");
        }
        if path.ends_with("/update") {
            return ogs_sbi::message::SbiResponse::with_status(200)
                .with_body(decision.to_string(), "application/json");
        }
        if path.ends_with("/delete") {
            return ogs_sbi::message::SbiResponse::with_status(204);
        }
        ogs_sbi::message::SbiResponse::with_status(404)
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .expect("probe ephemeral port")
    }

    #[tokio::test]
    async fn sm_policy_lifecycle_http_round_trip() {
        let port = free_port();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(addr));
        server
            .start(stub_pcf_handler)
            .await
            .expect("start stub PCF");

        let pcf = PcfEndpoint {
            host: "127.0.0.1".into(),
            port,
        };
        let ctx = SmPolicyCreateContext {
            supi: "imsi-001010000000001",
            psi: 5,
            pdu_session_type: pdu_session_type::IPV4,
            dnn: "internet",
            sst: 1,
            sd: None,
            ue_ipv4: [10, 45, 0, 2],
            notification_uri: "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
        };

        let run = async {
            // Create (success outcome)
            let dec = sm_policy_create(&pcf, &ctx).await.expect("create");
            assert_eq!(dec.sm_policy_id, "stub-pol-1");
            assert_eq!(dec.sess_ambr_dl_bps, 80_000_000);
            assert_eq!(dec.def_five_qi, 8);

            // Update
            let dec = sm_policy_update(&pcf, "stub-pol-1", &["RES_MO_RE"], None)
                .await
                .expect("update");
            assert_eq!(dec.sess_ambr_ul_bps, 20_000_000);

            // Delete
            sm_policy_delete(&pcf, "stub-pol-1").await.expect("delete");

            // Create (rejection outcome: PSI 13 → 403)
            let rej_ctx = SmPolicyCreateContext { psi: 13, ..ctx };
            match sm_policy_create(&pcf, &rej_ctx).await {
                Err(PolicyError::Rejected { status, .. }) => assert_eq!(status, 403),
                other => panic!("expected Rejected, got {other:?}"),
            }
        };
        tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .expect("round trip timed out");

        server.stop().await.ok();
    }

    #[tokio::test]
    async fn sm_policy_create_transport_failure() {
        // Nothing listens on this port — bounded-timeout transport error
        let pcf = PcfEndpoint {
            host: "127.0.0.1".into(),
            port: free_port(),
        };
        let ctx = SmPolicyCreateContext {
            supi: "imsi-001010000000001",
            psi: 1,
            pdu_session_type: pdu_session_type::IPV4,
            dnn: "internet",
            sst: 1,
            sd: None,
            ue_ipv4: [10, 45, 0, 3],
            notification_uri: "http://127.0.0.1:9/cb",
        };
        let res = tokio::time::timeout(Duration::from_secs(8), sm_policy_create(&pcf, &ctx))
            .await
            .expect("bounded");
        assert!(matches!(res, Err(PolicyError::Transport(_))));
    }

    // ------------------- Nnsacf_NSAC PDU-session admission ----------------

    /// Stub NSACF: admits unless `pduSessionId == 99` (the over-limit marker),
    /// in which case it returns the TS 29.536 200 + admittedFlag=false body.
    async fn stub_nsacf_handler(req: ogs_sbi::message::SbiRequest) -> ogs_sbi::message::SbiResponse {
        let path = req.header.uri.split('?').next().unwrap_or("").to_string();
        if !path.ends_with("/nnsacf-nsac/v1/slices/pdu-sessions") {
            return ogs_sbi::message::SbiResponse::with_status(404);
        }
        let body: serde_json::Value = req
            .http
            .content
            .as_deref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or(serde_json::Value::Null);
        // Mandatory fields must be present (snssai, nfId, updateFlag, pduSessionId).
        assert_eq!(body["snssai"]["sst"], 1, "request must carry snssai");
        assert!(body["nfId"].is_string(), "request must carry nfId");
        assert!(
            body["updateFlag"] == "INCREASE" || body["updateFlag"] == "DECREASE",
            "updateFlag must be INCREASE/DECREASE"
        );
        let psi = body["pduSessionId"].as_u64().unwrap_or(0);
        let admitted = psi != 99;
        let mut resp = serde_json::json!({
            "snssai": {"sst": 1},
            "admittedFlag": admitted,
            "maxNumPduSessions": 100,
        });
        if !admitted {
            resp["rejectCause"] = serde_json::json!("QUOTA_EXCEEDED");
        }
        // TS 29.536: even a rejection is HTTP 200.
        ogs_sbi::message::SbiResponse::with_status(200)
            .with_json_body(&resp)
            .unwrap_or_else(|_| ogs_sbi::message::SbiResponse::with_status(200))
    }

    #[tokio::test]
    async fn nsac_pdu_session_admit_admitted_and_rejected() {
        let port = free_port();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = ogs_sbi::server::SbiServer::new(ogs_sbi::server::SbiServerConfig::new(addr));
        server
            .start(stub_nsacf_handler)
            .await
            .expect("start stub NSACF");

        let nsacf = NsacfEndpoint {
            host: "127.0.0.1".into(),
            port,
        };

        let run = async {
            // Within quota -> Admitted
            let res =
                nsac_pdu_session_admit(&nsacf, "smf-1", "imsi-1", 5, 1, None).await;
            assert_eq!(res, NsacAdmission::Admitted);

            // Over-limit marker (psi 99) -> Rejected (200 + admittedFlag=false)
            let res =
                nsac_pdu_session_admit(&nsacf, "smf-1", "imsi-2", 99, 1, None).await;
            assert_eq!(res, NsacAdmission::Rejected);

            // DECREASE release is best-effort and must not panic
            nsac_pdu_session_release(&nsacf, "smf-1", "imsi-1", 5, 1, None).await;
        };
        tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .expect("round trip timed out");

        server.stop().await.ok();
    }

    #[tokio::test]
    async fn nsac_pdu_session_admit_unavailable_on_transport_error() {
        // Nothing listening -> Unavailable (fail-open at the call site)
        let nsacf = NsacfEndpoint {
            host: "127.0.0.1".into(),
            port: free_port(),
        };
        let res = tokio::time::timeout(
            Duration::from_secs(8),
            nsac_pdu_session_admit(&nsacf, "smf-1", "imsi-1", 5, 1, None),
        )
        .await
        .expect("bounded");
        assert_eq!(res, NsacAdmission::Unavailable);
    }

    #[test]
    fn nsac_reject_uses_slice_specific_5gsm_cause() {
        // TS 24.501 §9.11.4.2 cause #67 (insufficient resources for slice).
        assert_eq!(gsm_cause::INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE, 67);
    }
}
