//! SCP Context
//!
//! The SCP forwards inline in [`crate::proxy::ScpProxy`], so it does not keep
//! the per-request association pool the C `scp_context_t` carried; that pool
//! (`scp_assoc_*`) was compiled but never reached by the live path and has
//! been removed (scpd-#102). What remains is the process lifecycle marker every
//! daemon in this tree keeps for symmetric init/fini logging, plus [`NfType`],
//! which the discovery parser in [`crate::sbi_path`] uses to tag candidates.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

/// NF Type enumeration (from OpenAPI, TS 29.510 §6.1.6.3.3).
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

/// SCP process context — a lifecycle marker.
///
/// The association pool that once lived here is gone (the live proxy path does
/// not use it); this now only records whether the process has completed
/// init/fini, matching the symmetric lifecycle logging of the other daemons.
pub struct ScpContext {
    initialized: AtomicBool,
}

impl ScpContext {
    pub fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return;
        }
        log::info!("SCP context initialized");
    }

    pub fn fini(&self) {
        if !self.initialized.swap(false, Ordering::SeqCst) {
            return;
        }
        log::info!("SCP context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }
}

impl Default for ScpContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global SCP context (thread-safe singleton).
static GLOBAL_SCP_CONTEXT: std::sync::OnceLock<Arc<RwLock<ScpContext>>> =
    std::sync::OnceLock::new();

/// Get the global SCP context.
pub fn scp_self() -> Arc<RwLock<ScpContext>> {
    GLOBAL_SCP_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(ScpContext::new())))
        .clone()
}

/// Initialize the global SCP context.
pub fn scp_context_init() {
    let ctx = scp_self();
    if let Ok(context) = ctx.read() {
        context.init();
    };
}

/// Finalize the global SCP context.
pub fn scp_context_final() {
    let ctx = scp_self();
    if let Ok(context) = ctx.read() {
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
    }

    #[test]
    fn test_scp_context_init_fini() {
        let ctx = ScpContext::new();
        ctx.init();
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_nf_type_conversion() {
        assert_eq!(NfType::from_string("AMF"), NfType::Amf);
        assert_eq!(NfType::from_string("amf"), NfType::Amf);
        assert_eq!(NfType::Amf.to_string(), "AMF");
        assert_eq!(NfType::from_string("unknown"), NfType::Null);
    }
}
