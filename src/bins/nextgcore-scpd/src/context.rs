//! SCP Context Management
//!
//! Port of src/scp/context.c - SCP context with association management

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// NF Type enumeration (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfType {
    Null,
    Nrf,
    Udm,
    Amf,
    Smf,
    Ausf,
    Nef,
    Pcf,
    Smsf,
    Nssf,
    Udr,
    Lmf,
    Gmlc,
    FiveGEir,
    Sepp,
    Upf,
    N3iwf,
    Af,
    Udsf,
    Bsf,
    Chf,
    Nwdaf,
    Pcscf,
    Cbcf,
    Hss,
    Ucmf,
    Scp,
    Nssaaf,
    Mfaf,
    Mbsmf,
    Easdf,
    Dccf,
    Mbstf,
    Tsctsf,
    Adrf,
    Gba,
    Aanf,
    Nsacf,
    Mme,
    Sgsn,
    Cscf,
    Mnpf,
    Nswof,
    Pkmf,
    Iwmsc,
    Mbsf,
    Panf,
}

impl NfType {
    pub fn to_string(&self) -> &'static str {
        match self {
            NfType::Null => "NULL",
            NfType::Nrf => "NRF",
            NfType::Udm => "UDM",
            NfType::Amf => "AMF",
            NfType::Smf => "SMF",
            NfType::Ausf => "AUSF",
            NfType::Nef => "NEF",
            NfType::Pcf => "PCF",
            NfType::Smsf => "SMSF",
            NfType::Nssf => "NSSF",
            NfType::Udr => "UDR",
            NfType::Lmf => "LMF",
            NfType::Gmlc => "GMLC",
            NfType::FiveGEir => "5G_EIR",
            NfType::Sepp => "SEPP",
            NfType::Upf => "UPF",
            NfType::N3iwf => "N3IWF",
            NfType::Af => "AF",
            NfType::Udsf => "UDSF",
            NfType::Bsf => "BSF",
            NfType::Chf => "CHF",
            NfType::Nwdaf => "NWDAF",
            NfType::Pcscf => "PCSCF",
            NfType::Cbcf => "CBCF",
            NfType::Hss => "HSS",
            NfType::Ucmf => "UCMF",
            NfType::Scp => "SCP",
            NfType::Nssaaf => "NSSAAF",
            NfType::Mfaf => "MFAF",
            NfType::Mbsmf => "MBSMF",
            NfType::Easdf => "EASDF",
            NfType::Dccf => "DCCF",
            NfType::Mbstf => "MBSTF",
            NfType::Tsctsf => "TSCTSF",
            NfType::Adrf => "ADRF",
            NfType::Gba => "GBA",
            NfType::Aanf => "AANF",
            NfType::Nsacf => "NSACF",
            NfType::Mme => "MME",
            NfType::Sgsn => "SGSN",
            NfType::Cscf => "CSCF",
            NfType::Mnpf => "MNPF",
            NfType::Nswof => "NSWOF",
            NfType::Pkmf => "PKMF",
            NfType::Iwmsc => "IWMSC",
            NfType::Mbsf => "MBSF",
            NfType::Panf => "PANF",
        }
    }

    pub fn from_string(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "NRF" => NfType::Nrf,
            "UDM" => NfType::Udm,
            "AMF" => NfType::Amf,
            "SMF" => NfType::Smf,
            "AUSF" => NfType::Ausf,
            "NEF" => NfType::Nef,
            "PCF" => NfType::Pcf,
            "SMSF" => NfType::Smsf,
            "NSSF" => NfType::Nssf,
            "UDR" => NfType::Udr,
            "LMF" => NfType::Lmf,
            "GMLC" => NfType::Gmlc,
            "5G_EIR" => NfType::FiveGEir,
            "SEPP" => NfType::Sepp,
            "UPF" => NfType::Upf,
            "N3IWF" => NfType::N3iwf,
            "AF" => NfType::Af,
            "UDSF" => NfType::Udsf,
            "BSF" => NfType::Bsf,
            "CHF" => NfType::Chf,
            "NWDAF" => NfType::Nwdaf,
            "PCSCF" => NfType::Pcscf,
            "CBCF" => NfType::Cbcf,
            "HSS" => NfType::Hss,
            "UCMF" => NfType::Ucmf,
            "SCP" => NfType::Scp,
            "NSSAAF" => NfType::Nssaaf,
            "MFAF" => NfType::Mfaf,
            "MBSMF" => NfType::Mbsmf,
            "EASDF" => NfType::Easdf,
            "DCCF" => NfType::Dccf,
            "MBSTF" => NfType::Mbstf,
            "TSCTSF" => NfType::Tsctsf,
            "ADRF" => NfType::Adrf,
            "GBA" => NfType::Gba,
            "AANF" => NfType::Aanf,
            "NSACF" => NfType::Nsacf,
            "MME" => NfType::Mme,
            "SGSN" => NfType::Sgsn,
            "CSCF" => NfType::Cscf,
            "MNPF" => NfType::Mnpf,
            "NSWOF" => NfType::Nswof,
            "PKMF" => NfType::Pkmf,
            "IWMSC" => NfType::Iwmsc,
            "MBSF" => NfType::Mbsf,
            "PANF" => NfType::Panf,
            _ => NfType::Null,
        }
    }
}

/// SBI Service Type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SbiServiceType {
    #[default]
    Null,
    NnrfNfm,
    NnrfDisc,
    NnrfOauth2,
    NudrDr,
    NudmUecm,
    NudmSdm,
    NudmUeau,
    NudmEe,
    NudmPp,
    NudmNiddau,
    NudmMt,
    NamfComm,
    NamfEvts,
    NamfMtComm,
    NamfLoc,
    NsmfPdusession,
    NsmfEventExposure,
    NsmfNidd,
    NausfAuth,
    NausfSorprotection,
    NausfUpuprotection,
    NnefPfdmanagement,
    NnefSmcontext,
    NnefEventexposure,
    NpcfAmPolicyControl,
    NpcfSmPolicyControl,
    NpcfPolicyauthorization,
    NpcfBdtpolicycontrol,
    NpcfEventexposure,
    NpcfUepolicycontrol,
    NssfNsselection,
    NssfNssaiavailability,
    NbsfManagement,
    NchfSpendingLimitControl,
    NchfConvergedcharging,
    NchfOfflineonlycharging,
    Nnwdaf,
    Ngmlc,
    Nucmf,
    Nhss,
    Nsepp,
    Nscp,
    Nnssaaf,
    Nmfaf,
    Neasdf,
    Ndccf,
    Ntsctsf,
    Nadrf,
    Ngba,
    Naanf,
    Nnsacf,
    Nmnpf,
    Nnswof,
    Npkmf,
    Nmbsf,
    Npanf,
}

impl SbiServiceType {
    pub fn from_name(name: &str) -> Self {
        match name {
            "nnrf-nfm" => SbiServiceType::NnrfNfm,
            "nnrf-disc" => SbiServiceType::NnrfDisc,
            "nnrf-oauth2" => SbiServiceType::NnrfOauth2,
            "nudr-dr" => SbiServiceType::NudrDr,
            "nudm-uecm" => SbiServiceType::NudmUecm,
            "nudm-sdm" => SbiServiceType::NudmSdm,
            "nudm-ueau" => SbiServiceType::NudmUeau,
            "nudm-ee" => SbiServiceType::NudmEe,
            "nudm-pp" => SbiServiceType::NudmPp,
            "nudm-niddau" => SbiServiceType::NudmNiddau,
            "nudm-mt" => SbiServiceType::NudmMt,
            "namf-comm" => SbiServiceType::NamfComm,
            "namf-evts" => SbiServiceType::NamfEvts,
            "namf-mt-comm" => SbiServiceType::NamfMtComm,
            "namf-loc" => SbiServiceType::NamfLoc,
            "nsmf-pdusession" => SbiServiceType::NsmfPdusession,
            "nsmf-event-exposure" => SbiServiceType::NsmfEventExposure,
            "nsmf-nidd" => SbiServiceType::NsmfNidd,
            "nausf-auth" => SbiServiceType::NausfAuth,
            "nausf-sorprotection" => SbiServiceType::NausfSorprotection,
            "nausf-upuprotection" => SbiServiceType::NausfUpuprotection,
            "nnef-pfdmanagement" => SbiServiceType::NnefPfdmanagement,
            "nnef-smcontext" => SbiServiceType::NnefSmcontext,
            "nnef-eventexposure" => SbiServiceType::NnefEventexposure,
            "npcf-am-policy-control" => SbiServiceType::NpcfAmPolicyControl,
            "npcf-smpolicycontrol" => SbiServiceType::NpcfSmPolicyControl,
            "npcf-policyauthorization" => SbiServiceType::NpcfPolicyauthorization,
            "npcf-bdtpolicycontrol" => SbiServiceType::NpcfBdtpolicycontrol,
            "npcf-eventexposure" => SbiServiceType::NpcfEventexposure,
            "npcf-ue-policy-control" => SbiServiceType::NpcfUepolicycontrol,
            "nssf-nsselection" => SbiServiceType::NssfNsselection,
            "nssf-nssaiavailability" => SbiServiceType::NssfNssaiavailability,
            "nbsf-management" => SbiServiceType::NbsfManagement,
            "nchf-spendinglimitcontrol" => SbiServiceType::NchfSpendingLimitControl,
            "nchf-convergedcharging" => SbiServiceType::NchfConvergedcharging,
            "nchf-offlineonlycharging" => SbiServiceType::NchfOfflineonlycharging,
            _ => SbiServiceType::Null,
        }
    }

    pub fn to_name(&self) -> &'static str {
        match self {
            SbiServiceType::Null => "",
            SbiServiceType::NnrfNfm => "nnrf-nfm",
            SbiServiceType::NnrfDisc => "nnrf-disc",
            SbiServiceType::NnrfOauth2 => "nnrf-oauth2",
            SbiServiceType::NudrDr => "nudr-dr",
            SbiServiceType::NudmUecm => "nudm-uecm",
            SbiServiceType::NudmSdm => "nudm-sdm",
            SbiServiceType::NudmUeau => "nudm-ueau",
            SbiServiceType::NudmEe => "nudm-ee",
            SbiServiceType::NudmPp => "nudm-pp",
            SbiServiceType::NudmNiddau => "nudm-niddau",
            SbiServiceType::NudmMt => "nudm-mt",
            SbiServiceType::NamfComm => "namf-comm",
            SbiServiceType::NamfEvts => "namf-evts",
            SbiServiceType::NamfMtComm => "namf-mt-comm",
            SbiServiceType::NamfLoc => "namf-loc",
            SbiServiceType::NsmfPdusession => "nsmf-pdusession",
            SbiServiceType::NsmfEventExposure => "nsmf-event-exposure",
            SbiServiceType::NsmfNidd => "nsmf-nidd",
            SbiServiceType::NausfAuth => "nausf-auth",
            SbiServiceType::NausfSorprotection => "nausf-sorprotection",
            SbiServiceType::NausfUpuprotection => "nausf-upuprotection",
            SbiServiceType::NnefPfdmanagement => "nnef-pfdmanagement",
            SbiServiceType::NnefSmcontext => "nnef-smcontext",
            SbiServiceType::NnefEventexposure => "nnef-eventexposure",
            SbiServiceType::NpcfAmPolicyControl => "npcf-am-policy-control",
            SbiServiceType::NpcfSmPolicyControl => "npcf-smpolicycontrol",
            SbiServiceType::NpcfPolicyauthorization => "npcf-policyauthorization",
            SbiServiceType::NpcfBdtpolicycontrol => "npcf-bdtpolicycontrol",
            SbiServiceType::NpcfEventexposure => "npcf-eventexposure",
            SbiServiceType::NpcfUepolicycontrol => "npcf-ue-policy-control",
            SbiServiceType::NssfNsselection => "nssf-nsselection",
            SbiServiceType::NssfNssaiavailability => "nssf-nssaiavailability",
            SbiServiceType::NbsfManagement => "nbsf-management",
            SbiServiceType::NchfSpendingLimitControl => "nchf-spendinglimitcontrol",
            SbiServiceType::NchfConvergedcharging => "nchf-convergedcharging",
            SbiServiceType::NchfOfflineonlycharging => "nchf-offlineonlycharging",
            _ => "",
        }
    }
}


/// Discovery option for NF discovery
#[derive(Debug, Clone, Default)]
pub struct DiscoveryOption {
    pub target_nf_instance_id: Option<String>,
    pub requester_nf_instance_id: Option<String>,
    pub service_names: Vec<String>,
    pub dnn: Option<String>,
    pub snssais: Vec<SNssai>,
    pub tai: Option<Tai>,
    pub guami: Option<Guami>,
    pub target_plmn_list: Vec<PlmnId>,
    pub requester_plmn_list: Vec<PlmnId>,
    pub hnrf_uri: Option<String>,
    pub requester_features: u64,
}

impl DiscoveryOption {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_target_nf_instance_id(&mut self, id: &str) {
        self.target_nf_instance_id = Some(id.to_string());
    }

    pub fn set_requester_nf_instance_id(&mut self, id: &str) {
        self.requester_nf_instance_id = Some(id.to_string());
    }

    pub fn set_dnn(&mut self, dnn: &str) {
        self.dnn = Some(dnn.to_string());
    }

    pub fn set_hnrf_uri(&mut self, uri: &str) {
        self.hnrf_uri = Some(uri.to_string());
    }

    pub fn add_service_name(&mut self, name: &str) {
        self.service_names.push(name.to_string());
    }

    pub fn parse_service_names(&mut self, val: &str) {
        for name in val.split(',') {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                self.service_names.push(trimmed.to_string());
            }
        }
    }
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// TAI (Tracking Area Identity)
#[derive(Debug, Clone, Default)]
pub struct Tai {
    pub plmn_id: PlmnId,
    pub tac: u32,
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default)]
pub struct Guami {
    pub plmn_id: PlmnId,
    pub amf_id: AmfId,
}

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// AMF ID
#[derive(Debug, Clone, Default)]
pub struct AmfId {
    pub region: u8,
    pub set: u16,
    pub pointer: u8,
}

/// SCP Association structure
/// Port of scp_assoc_t from context.h
#[derive(Debug, Clone)]
pub struct ScpAssoc {
    /// Association pool ID
    pub id: u64,
    /// Stream ID for the associated HTTP/2 stream
    pub stream_id: u64,
    /// Client reference (for response routing)
    pub client_id: Option<u64>,
    /// Original request (stored for forwarding after discovery)
    pub request: Option<SbiRequest>,
    /// Service type for discovery
    pub service_type: SbiServiceType,
    /// Target NF type for discovery
    pub target_nf_type: NfType,
    /// Requester NF type (from User-Agent header)
    pub requester_nf_type: NfType,
    /// Discovery options
    pub discovery_option: DiscoveryOption,
    /// NF service producer instance ID (after discovery)
    pub nf_service_producer_id: Option<String>,
    /// Target API root (for SEPP routing)
    pub target_apiroot: Option<String>,
}

/// Simplified SBI request for storage
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl ScpAssoc {
    pub fn new(id: u64, stream_id: u64) -> Self {
        Self {
            id,
            stream_id,
            client_id: None,
            request: None,
            service_type: SbiServiceType::Null,
            target_nf_type: NfType::Null,
            requester_nf_type: NfType::Null,
            discovery_option: DiscoveryOption::new(),
            nf_service_producer_id: None,
            target_apiroot: None,
        }
    }

    pub fn set_request(&mut self, request: SbiRequest) {
        self.request = Some(request);
    }

    pub fn set_target_apiroot(&mut self, apiroot: &str) {
        self.target_apiroot = Some(apiroot.to_string());
    }
}

/// SCP Context - main context structure for SCP
/// Port of scp_context_t from context.h
pub struct ScpContext {
    /// Association list (by pool ID)
    assoc_list: RwLock<HashMap<u64, ScpAssoc>>,
    /// Next association ID
    next_assoc_id: AtomicUsize,
    /// Maximum number of associations (pool size)
    max_num_of_assoc: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl ScpContext {
    pub fn new() -> Self {
        Self {
            assoc_list: RwLock::new(HashMap::new()),
            next_assoc_id: AtomicUsize::new(1),
            max_num_of_assoc: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_assoc: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_num_of_assoc = max_assoc;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("SCP context initialized with max {} associations", max_assoc);
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.assoc_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("SCP context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add a new association
    /// Port of scp_assoc_add
    pub fn assoc_add(&self, stream_id: u64) -> Option<ScpAssoc> {
        let mut assoc_list = self.assoc_list.write().ok()?;

        if assoc_list.len() >= self.max_num_of_assoc {
            log::error!("Maximum number of associations [{}] reached", self.max_num_of_assoc);
            return None;
        }

        let id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst) as u64;
        let assoc = ScpAssoc::new(id, stream_id);

        assoc_list.insert(id, assoc.clone());
        log::debug!("SCP association added (id={}, stream_id={})", id, stream_id);

        Some(assoc)
    }

    /// Remove an association
    /// Port of scp_assoc_remove
    pub fn assoc_remove(&self, id: u64) -> Option<ScpAssoc> {
        let mut assoc_list = self.assoc_list.write().ok()?;

        if let Some(assoc) = assoc_list.remove(&id) {
            log::debug!("SCP association removed (id={})", id);
            return Some(assoc);
        }
        None
    }

    /// Remove all associations
    /// Port of scp_assoc_remove_all
    pub fn assoc_remove_all(&self) {
        if let Ok(mut assoc_list) = self.assoc_list.write() {
            assoc_list.clear();
        }
    }

    /// Find association by ID
    pub fn assoc_find(&self, id: u64) -> Option<ScpAssoc> {
        let assoc_list = self.assoc_list.read().ok()?;
        assoc_list.get(&id).cloned()
    }

    /// Find association by stream ID
    pub fn assoc_find_by_stream_id(&self, stream_id: u64) -> Option<ScpAssoc> {
        let assoc_list = self.assoc_list.read().ok()?;
        for assoc in assoc_list.values() {
            if assoc.stream_id == stream_id {
                return Some(assoc.clone());
            }
        }
        None
    }

    /// Update association in the context
    pub fn assoc_update(&self, assoc: &ScpAssoc) -> bool {
        if let Ok(mut assoc_list) = self.assoc_list.write() {
            if let Some(existing) = assoc_list.get_mut(&assoc.id) {
                *existing = assoc.clone();
                return true;
            }
        }
        false
    }

    /// Get association count
    pub fn assoc_count(&self) -> usize {
        self.assoc_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl Default for ScpContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global SCP context (thread-safe singleton)
static GLOBAL_SCP_CONTEXT: std::sync::OnceLock<Arc<RwLock<ScpContext>>> = std::sync::OnceLock::new();

/// Get the global SCP context
pub fn scp_self() -> Arc<RwLock<ScpContext>> {
    GLOBAL_SCP_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(ScpContext::new())))
        .clone()
}

/// Initialize the global SCP context
pub fn scp_context_init(max_assoc: usize) {
    let ctx = scp_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_assoc);
    };
}

/// Finalize the global SCP context
pub fn scp_context_final() {
    let ctx = scp_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scp_context_new() {
        let ctx = ScpContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.assoc_count(), 0);
    }

    #[test]
    fn test_scp_context_init_fini() {
        let mut ctx = ScpContext::new();
        ctx.init(100);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_assoc_add() {
        let mut ctx = ScpContext::new();
        ctx.init(100);

        let assoc = ctx.assoc_add(1).unwrap();
        assert_eq!(assoc.stream_id, 1);
        assert_eq!(ctx.assoc_count(), 1);
    }

    #[test]
    fn test_assoc_remove() {
        let mut ctx = ScpContext::new();
        ctx.init(100);

        let assoc = ctx.assoc_add(1).unwrap();
        assert_eq!(ctx.assoc_count(), 1);

        ctx.assoc_remove(assoc.id);
        assert_eq!(ctx.assoc_count(), 0);
    }

    #[test]
    fn test_assoc_find_by_stream_id() {
        let mut ctx = ScpContext::new();
        ctx.init(100);

        let assoc = ctx.assoc_add(42).unwrap();
        let found = ctx.assoc_find_by_stream_id(42);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, assoc.id);
    }

    #[test]
    fn test_nf_type_conversion() {
        assert_eq!(NfType::from_string("AMF"), NfType::Amf);
        assert_eq!(NfType::from_string("amf"), NfType::Amf);
        assert_eq!(NfType::Amf.to_string(), "AMF");
    }

    #[test]
    fn test_sbi_service_type_conversion() {
        assert_eq!(SbiServiceType::from_name("nnrf-nfm"), SbiServiceType::NnrfNfm);
        assert_eq!(SbiServiceType::NnrfNfm.to_name(), "nnrf-nfm");
    }

    #[test]
    fn test_discovery_option() {
        let mut opt = DiscoveryOption::new();
        opt.set_target_nf_instance_id("test-id");
        opt.set_dnn("internet");
        opt.parse_service_names("namf-comm, nsmf-pdusession");

        assert_eq!(opt.target_nf_instance_id, Some("test-id".to_string()));
        assert_eq!(opt.dnn, Some("internet".to_string()));
        assert_eq!(opt.service_names.len(), 2);
    }
}
