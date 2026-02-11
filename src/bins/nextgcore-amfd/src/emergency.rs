//! Emergency Services Support (Item #203)
//!
//! Implements IMS emergency and 5G emergency PDU session handling per:
//! - TS 23.167: IMS Emergency Sessions
//! - TS 23.501: 5G Emergency Services
//! - TS 24.501: NAS Emergency Registration

use std::collections::HashMap;

// ============================================================================
// Emergency Registration
// ============================================================================

/// Emergency registration type (TS 24.501 9.11.3.47)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyRegistrationType {
    /// Emergency registration without SUPI
    EmergencyNoSupi,
    /// Emergency registration with valid SUPI
    EmergencyWithSupi,
    /// Normal registration with emergency bearer
    NormalWithEmergency,
}

/// Emergency service category (TS 24.008 10.5.4.33)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmergencyCategory {
    /// Police
    Police = 1,
    /// Ambulance
    Ambulance = 2,
    /// Fire brigade
    FireBrigade = 4,
    /// Marine guard
    MarineGuard = 8,
    /// Mountain rescue
    MountainRescue = 16,
    /// Manually initiated eCall
    ManualEcall = 32,
    /// Automatically initiated eCall
    AutomaticEcall = 64,
}

/// Emergency service fallback indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyFallback {
    /// Emergency services via 5G NR
    Nr5g,
    /// Fallback to EPS (4G)
    EpsFallback,
    /// CSFB to 3G/2G
    CsFallback,
}

/// Emergency number entry from PLMN
#[derive(Debug, Clone)]
pub struct EmergencyNumber {
    /// Dialed number (e.g., "911", "112")
    pub number: String,
    /// Service categories (bitmask)
    pub categories: u8,
    /// Sub-services URL (optional)
    pub sub_services_uri: Option<String>,
}

// ============================================================================
// Emergency Context
// ============================================================================

/// Emergency UE context within AMF
#[derive(Debug, Clone)]
pub struct EmergencyContext {
    /// Emergency registration type
    pub reg_type: EmergencyRegistrationType,
    /// Emergency service category
    pub category: Option<EmergencyCategory>,
    /// Whether UE is authenticated
    pub authenticated: bool,
    /// Emergency PDU session ID (if established)
    pub pdu_session_id: Option<u8>,
    /// IMS voice over PS session indication
    pub ims_voice_ps: bool,
    /// Location information (TAI + Cell ID)
    pub location_tai: Option<[u8; 5]>,
    /// Emergency fallback type
    pub fallback: EmergencyFallback,
}

impl EmergencyContext {
    /// Creates an emergency context for unauthenticated UE
    pub fn unauthenticated() -> Self {
        Self {
            reg_type: EmergencyRegistrationType::EmergencyNoSupi,
            category: None,
            authenticated: false,
            pdu_session_id: None,
            ims_voice_ps: false,
            location_tai: None,
            fallback: EmergencyFallback::Nr5g,
        }
    }

    /// Creates an emergency context for authenticated UE
    pub fn authenticated() -> Self {
        Self {
            reg_type: EmergencyRegistrationType::EmergencyWithSupi,
            category: None,
            authenticated: true,
            pdu_session_id: None,
            ims_voice_ps: false,
            location_tai: None,
            fallback: EmergencyFallback::Nr5g,
        }
    }

    /// Sets the emergency category
    pub fn with_category(mut self, category: EmergencyCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Whether this is an emergency-only registration
    pub fn is_emergency_only(&self) -> bool {
        self.reg_type == EmergencyRegistrationType::EmergencyNoSupi
    }
}

// ============================================================================
// Emergency Services Handler
// ============================================================================

/// Emergency services handler in AMF
pub struct EmergencyHandler {
    /// Emergency number list per PLMN
    emergency_numbers: HashMap<[u8; 3], Vec<EmergencyNumber>>,
    /// Active emergency contexts (keyed by AMF UE NGAP ID)
    active_contexts: HashMap<u32, EmergencyContext>,
    /// Emergency DNN name
    emergency_dnn: String,
    /// IMS P-CSCF address for emergency
    ims_pcscf_addr: Option<String>,
    /// Emergency call count
    emergency_count: u64,
}

impl EmergencyHandler {
    /// Creates a new emergency handler
    pub fn new() -> Self {
        Self {
            emergency_numbers: HashMap::new(),
            active_contexts: HashMap::new(),
            emergency_dnn: "sos".to_string(),
            ims_pcscf_addr: None,
            emergency_count: 0,
        }
    }

    /// Registers emergency numbers for a PLMN
    pub fn register_plmn_numbers(&mut self, plmn_id: [u8; 3], numbers: Vec<EmergencyNumber>) {
        self.emergency_numbers.insert(plmn_id, numbers);
    }

    /// Checks if a dialed number is an emergency number
    pub fn is_emergency_number(&self, plmn_id: &[u8; 3], number: &str) -> bool {
        if let Some(numbers) = self.emergency_numbers.get(plmn_id) {
            numbers.iter().any(|n| n.number == number)
        } else {
            // Default emergency numbers (globally recognized)
            matches!(number, "911" | "112" | "999" | "000" | "110" | "119")
        }
    }

    /// Handles emergency registration
    pub fn handle_emergency_registration(
        &mut self,
        amf_ue_ngap_id: u32,
        has_supi: bool,
    ) -> EmergencyContext {
        self.emergency_count += 1;

        let ctx = if has_supi {
            EmergencyContext::authenticated()
        } else {
            EmergencyContext::unauthenticated()
        };

        self.active_contexts.insert(amf_ue_ngap_id, ctx.clone());
        ctx
    }

    /// Assigns an emergency PDU session
    pub fn assign_emergency_pdu_session(&mut self, amf_ue_ngap_id: u32, psi: u8) -> bool {
        if let Some(ctx) = self.active_contexts.get_mut(&amf_ue_ngap_id) {
            ctx.pdu_session_id = Some(psi);
            true
        } else {
            false
        }
    }

    /// Gets the emergency DNN
    pub fn emergency_dnn(&self) -> &str {
        &self.emergency_dnn
    }

    /// Gets the IMS P-CSCF address for emergency
    pub fn ims_pcscf(&self) -> Option<&str> {
        self.ims_pcscf_addr.as_deref()
    }

    /// Sets IMS P-CSCF for emergency
    pub fn set_ims_pcscf(&mut self, addr: impl Into<String>) {
        self.ims_pcscf_addr = Some(addr.into());
    }

    /// Releases an emergency context
    pub fn release_emergency(&mut self, amf_ue_ngap_id: u32) -> bool {
        self.active_contexts.remove(&amf_ue_ngap_id).is_some()
    }

    /// Returns active emergency session count
    pub fn active_count(&self) -> usize {
        self.active_contexts.len()
    }

    /// Returns total emergency calls handled
    pub fn total_emergency_count(&self) -> u64 {
        self.emergency_count
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emergency_number_check() {
        let mut handler = EmergencyHandler::new();
        let plmn = [0x99, 0xF9, 0x07]; // 999/07

        handler.register_plmn_numbers(plmn, vec![
            EmergencyNumber { number: "112".to_string(), categories: 0xFF, sub_services_uri: None },
            EmergencyNumber { number: "911".to_string(), categories: 0xFF, sub_services_uri: None },
        ]);

        assert!(handler.is_emergency_number(&plmn, "112"));
        assert!(handler.is_emergency_number(&plmn, "911"));
        assert!(!handler.is_emergency_number(&plmn, "12345"));
    }

    #[test]
    fn test_default_emergency_numbers() {
        let handler = EmergencyHandler::new();
        let unknown_plmn = [0x00, 0x00, 0x00];

        // Should recognize globally standard numbers
        assert!(handler.is_emergency_number(&unknown_plmn, "911"));
        assert!(handler.is_emergency_number(&unknown_plmn, "112"));
    }

    #[test]
    fn test_emergency_registration_unauthenticated() {
        let mut handler = EmergencyHandler::new();
        let ctx = handler.handle_emergency_registration(1, false);

        assert!(!ctx.authenticated);
        assert!(ctx.is_emergency_only());
        assert_eq!(ctx.reg_type, EmergencyRegistrationType::EmergencyNoSupi);
        assert_eq!(handler.active_count(), 1);
    }

    #[test]
    fn test_emergency_registration_authenticated() {
        let mut handler = EmergencyHandler::new();
        let ctx = handler.handle_emergency_registration(1, true);

        assert!(ctx.authenticated);
        assert!(!ctx.is_emergency_only());
        assert_eq!(ctx.reg_type, EmergencyRegistrationType::EmergencyWithSupi);
    }

    #[test]
    fn test_emergency_pdu_session() {
        let mut handler = EmergencyHandler::new();
        handler.handle_emergency_registration(42, true);

        assert!(handler.assign_emergency_pdu_session(42, 5));
        assert!(!handler.assign_emergency_pdu_session(99, 5)); // Unknown UE
    }

    #[test]
    fn test_emergency_release() {
        let mut handler = EmergencyHandler::new();
        handler.handle_emergency_registration(1, true);
        assert_eq!(handler.active_count(), 1);

        assert!(handler.release_emergency(1));
        assert_eq!(handler.active_count(), 0);
    }

    #[test]
    fn test_emergency_context_with_category() {
        let ctx = EmergencyContext::unauthenticated()
            .with_category(EmergencyCategory::Ambulance);
        assert_eq!(ctx.category, Some(EmergencyCategory::Ambulance));
    }

    #[test]
    fn test_ims_pcscf_config() {
        let mut handler = EmergencyHandler::new();
        assert!(handler.ims_pcscf().is_none());

        handler.set_ims_pcscf("10.0.0.100:5060");
        assert_eq!(handler.ims_pcscf(), Some("10.0.0.100:5060"));
    }

    #[test]
    fn test_emergency_dnn() {
        let handler = EmergencyHandler::new();
        assert_eq!(handler.emergency_dnn(), "sos");
    }
}
