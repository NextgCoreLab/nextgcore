//! SNPN (Stand-alone Non-Public Network) Authentication for AMF (Rel-16, TS 23.501 §5.30)
//!
//! Implements SNPN-specific authentication procedures:
//! - SNPN identity validation (NID + PLMN)
//! - Credentials Holder (CH) based authentication
//! - SUPI-to-SNPN mapping and onboarding flow

use std::collections::HashMap;

/// SNPN Network Identity: NID (10 hex digits) + PLMN (MCC+MNC)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnpnId {
    /// Network Identifier (NID) — 44 bits, encoded as 11 hex chars per TS 23.003 §24
    pub nid: String,
    /// PLMN ID of the SNPN operator
    pub plmn_mcc: String,
    pub plmn_mnc: String,
}

impl SnpnId {
    pub fn new(nid: impl Into<String>, mcc: impl Into<String>, mnc: impl Into<String>) -> Self {
        Self {
            nid: nid.into(),
            plmn_mcc: mcc.into(),
            plmn_mnc: mnc.into(),
        }
    }

    /// Formats the SNPN ID as "MCC-MNC:NID"
    pub fn to_display(&self) -> String {
        format!("{}-{}:{}", self.plmn_mcc, self.plmn_mnc, self.nid)
    }

    /// Validates that the NID is exactly 11 hex characters (44 bits per TS 23.003)
    pub fn is_valid_nid(nid: &str) -> bool {
        nid.len() == 11 && nid.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// SNPN authentication context for a UE
#[derive(Debug, Clone)]
pub struct SnpnAuthContext {
    /// SUPI (IMSI or NAI format)
    pub supi: String,
    /// SNPN being accessed
    pub snpn_id: SnpnId,
    /// Authentication method negotiated
    pub auth_method: SnpnAuthMethod,
    /// Onboarding status
    pub onboarding_state: OnboardingState,
    /// Credentials Holder URI (if CH-based auth)
    pub ch_uri: Option<String>,
}

/// SNPN authentication methods (TS 33.501 §6.6a)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpnAuthMethod {
    /// EAP-AKA' via Credentials Holder
    EapAkaPrime,
    /// EAP-TLS via Credentials Holder
    EapTls,
    /// 5G-AKA via local AUSF (if SNPN has own AUSF)
    FiveGAka,
    /// Certificate-based (SUCI from ICI)
    Certificate,
}

/// SNPN onboarding state for a UE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingState {
    /// UE not yet onboarded
    NotOnboarded,
    /// Onboarding in progress (limited service)
    Onboarding,
    /// Fully onboarded and authorized
    Onboarded,
    /// Onboarding failed
    Failed,
}

/// SNPN configuration for AMF
#[derive(Debug, Clone)]
pub struct SnpnConfig {
    /// List of SNPNs this AMF serves
    pub served_snpns: Vec<SnpnId>,
    /// Whether to allow onboarding connections
    pub onboarding_allowed: bool,
    /// Credentials Holder base URI
    pub credentials_holder_uri: Option<String>,
}

impl Default for SnpnConfig {
    fn default() -> Self {
        Self {
            served_snpns: Vec::new(),
            onboarding_allowed: true,
            credentials_holder_uri: None,
        }
    }
}

impl SnpnConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if a given SNPN ID is served by this AMF
    pub fn is_served(&self, snpn_id: &SnpnId) -> bool {
        self.served_snpns.iter().any(|s| s == snpn_id)
    }
}

/// AMF SNPN context: tracks authenticated SNPN UE sessions
#[derive(Debug, Default)]
pub struct AmfSnpnContext {
    config: SnpnConfig,
    /// Active SNPN auth contexts keyed by SUPI
    auth_contexts: HashMap<String, SnpnAuthContext>,
}

impl AmfSnpnContext {
    pub fn new(config: SnpnConfig) -> Self {
        Self {
            config,
            auth_contexts: HashMap::new(),
        }
    }

    /// Validates a SNPN access request
    ///
    /// Returns Ok(auth_method) if access is permitted, Err(reason) otherwise.
    pub fn validate_access(&self, snpn_id: &SnpnId) -> Result<SnpnAuthMethod, String> {
        if !SnpnId::is_valid_nid(&snpn_id.nid) {
            return Err(format!("Invalid NID format: {}", snpn_id.nid));
        }
        if !self.config.is_served(snpn_id) {
            return Err(format!("SNPN {} not served by this AMF", snpn_id.to_display()));
        }
        // Default to EAP-AKA' if CH URI is configured, else 5G-AKA
        let method = if self.config.credentials_holder_uri.is_some() {
            SnpnAuthMethod::EapAkaPrime
        } else {
            SnpnAuthMethod::FiveGAka
        };
        Ok(method)
    }

    /// Creates an SNPN auth context for a UE
    pub fn create_auth_context(
        &mut self,
        supi: String,
        snpn_id: SnpnId,
        auth_method: SnpnAuthMethod,
    ) -> &SnpnAuthContext {
        let ctx = SnpnAuthContext {
            supi: supi.clone(),
            snpn_id,
            auth_method,
            onboarding_state: OnboardingState::Onboarding,
            ch_uri: self.config.credentials_holder_uri.clone(),
        };
        self.auth_contexts.insert(supi.clone(), ctx);
        self.auth_contexts.get(&supi).unwrap_or_default()
    }

    /// Marks onboarding complete for a UE
    pub fn complete_onboarding(&mut self, supi: &str) -> bool {
        if let Some(ctx) = self.auth_contexts.get_mut(supi) {
            ctx.onboarding_state = OnboardingState::Onboarded;
            true
        } else {
            false
        }
    }

    /// Marks onboarding failed
    pub fn fail_onboarding(&mut self, supi: &str) -> bool {
        if let Some(ctx) = self.auth_contexts.get_mut(supi) {
            ctx.onboarding_state = OnboardingState::Failed;
            true
        } else {
            false
        }
    }

    /// Returns number of onboarded UEs
    pub fn onboarded_count(&self) -> usize {
        self.auth_contexts.values()
            .filter(|c| c.onboarding_state == OnboardingState::Onboarded)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_snpn_id() -> SnpnId {
        SnpnId::new("7AB01234567", "001", "01")
    }

    fn test_config() -> SnpnConfig {
        SnpnConfig {
            served_snpns: vec![test_snpn_id()],
            onboarding_allowed: true,
            credentials_holder_uri: Some("https://ch.example.com".into()),
        }
    }

    #[test]
    fn test_valid_nid() {
        assert!(SnpnId::is_valid_nid("7AB01234567"));
        assert!(!SnpnId::is_valid_nid("SHORT"));
        assert!(!SnpnId::is_valid_nid("ZZZZZZZZZZ1")); // non-hex
    }

    #[test]
    fn test_snpn_id_display() {
        assert_eq!(test_snpn_id().to_display(), "001-01:7AB01234567");
    }

    #[test]
    fn test_validate_access_served() {
        let ctx = AmfSnpnContext::new(test_config());
        let result = ctx.validate_access(&test_snpn_id());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SnpnAuthMethod::EapAkaPrime);
    }

    #[test]
    fn test_validate_access_not_served() {
        let ctx = AmfSnpnContext::new(test_config());
        let unknown = SnpnId::new("00000000000", "999", "99");
        assert!(ctx.validate_access(&unknown).is_err());
    }

    #[test]
    fn test_onboarding_lifecycle() {
        let mut ctx = AmfSnpnContext::new(test_config());
        ctx.create_auth_context(
            "imsi-001011234567890".into(),
            test_snpn_id(),
            SnpnAuthMethod::EapAkaPrime,
        );
        assert_eq!(ctx.onboarded_count(), 0);
        assert!(ctx.complete_onboarding("imsi-001011234567890"));
        assert_eq!(ctx.onboarded_count(), 1);
    }

    #[test]
    fn test_onboarding_fail() {
        let mut ctx = AmfSnpnContext::new(test_config());
        ctx.create_auth_context(
            "imsi-001011234567890".into(),
            test_snpn_id(),
            SnpnAuthMethod::FiveGAka,
        );
        assert!(ctx.fail_onboarding("imsi-001011234567890"));
        assert_eq!(ctx.onboarded_count(), 0);
    }
}
