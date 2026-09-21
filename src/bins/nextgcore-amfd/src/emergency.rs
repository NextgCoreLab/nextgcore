//! Emergency Services Support (Item #203)
//!
//! Implements IMS emergency and 5G emergency PDU session handling per:
//! - TS 23.167: IMS Emergency Sessions
//! - TS 23.501: 5G Emergency Services
//! - TS 24.501: NAS Emergency Registration

use std::collections::HashMap;

// ============================================================================
// Unauthenticated-emergency policy (#361)
// ============================================================================

/// Whether this deployment may admit an emergency registration the network could not
/// authenticate (TS 33.501 §10.2.2, TS 23.502 §4.2.2.2.2 step 8).
///
/// This is a REGULATORY switch, not a tuning knob, and TS 33.501 §5.1.2 is the reason it
/// has to exist at all. It states two obligations pointing opposite ways in one paragraph:
/// "the 5G system shall support unauthenticated access for emergency services ... only to
/// those serving networks where regulatory requirements for unauthenticated emergency
/// services exist. Serving networks located in regions where unauthenticated emergency
/// services are forbidden shall not support this feature." TS 33.501 §10.2.2.2 and §6.7.3.6
/// then say the choice "shall be possible to configure".
///
/// **The default is ON**, and the asymmetry that decides it is not legal symmetry but
/// consequence: a wrong ON admits an unauthenticated UE to an emergency-only,
/// null-ciphered, single-DNN, no-subscription session fenced by §5.16.4.9a — which is
/// precisely the fence the spec specifies for it. A wrong OFF is an emergency call that
/// does not connect. An operator in a forbidding jurisdiction knows they are in one and can
/// set this false; a shipped default cannot know. See
/// `specs/decide-unauthenticated-emergency-registration.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyPolicy {
    /// Admit an EMERGENCY registration whose authentication could not be completed.
    pub allow_unauthenticated: bool,
}

impl Default for EmergencyPolicy {
    fn default() -> Self {
        Self {
            allow_unauthenticated: true,
        }
    }
}

impl EmergencyPolicy {
    /// Resolve the policy from the `AMF_EMERGENCY_ALLOW_UNAUTHENTICATED` env override
    /// (highest precedence, docker-friendly) then the `amf.emergency
    /// .allow_unauthenticated` YAML value, else the default.
    ///
    /// Takes both as parameters rather than reading the environment itself so the
    /// precedence is testable without mutating process state — the same shape
    /// `context::resolve_nas_security_canary` uses.
    pub fn resolve(env: Option<&str>, yaml: Option<bool>) -> Self {
        let allow_unauthenticated = match env {
            Some(v) => matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            None => yaml.unwrap_or(Self::default().allow_unauthenticated),
        };
        Self {
            allow_unauthenticated,
        }
    }
}

/// Process-wide resolved policy, seeded once at AMF startup.
///
/// A global rather than a constructor argument because of the startup ORDER: `load_config`
/// runs inside `AmfApp::init`, and the `EmergencyHandler` that needs the answer is built
/// later, inside `NgapServer::new` under `init_ngap`. Threading it would mean carrying the
/// value through `amf_ngap_open`'s signature for one bool. Same arrangement, and same
/// reason, as `context::NAS_SECURITY_CANARY`.
static ALLOW_UNAUTHENTICATED_EMERGENCY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// The ONE lock over [`ALLOW_UNAUTHENTICATED_EMERGENCY`] and the environment variable it is
/// resolved from.
///
/// Declared HERE, beside the global it guards, and never inside a `mod tests`: `ngap_path`'s
/// #361 tests set this posture too, and a lock private to this file's test module could not
/// order against them. A second lock over one variable has hung this suite before.
#[cfg(test)]
pub(crate) static EMERGENCY_POLICY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serialise on [`EMERGENCY_POLICY_TEST_LOCK`] and hand the caller the shipped default
/// posture, so a test that forgets to set one is not reading its predecessor's.
#[cfg(test)]
pub(crate) fn emergency_policy_test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = EMERGENCY_POLICY_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_allow_unauthenticated_emergency(EmergencyPolicy::default());
    guard
}

/// Seed the process-wide unauthenticated-emergency policy (called once after config load).
pub fn set_allow_unauthenticated_emergency(policy: EmergencyPolicy) {
    ALLOW_UNAUTHENTICATED_EMERGENCY.store(
        policy.allow_unauthenticated,
        std::sync::atomic::Ordering::SeqCst,
    );
    if policy.allow_unauthenticated {
        log::info!(
            "Unauthenticated emergency registration is PERMITTED (TS 33.501 §10.2.2): an \
             EMERGENCY registration whose AUSF cannot be reached proceeds with NIA0/NEA0 on \
             the emergency DNN only. Set amf.emergency.allow_unauthenticated: false where \
             local regulation forbids it (TS 33.501 §5.1.2)."
        );
    } else {
        log::warn!(
            "Unauthenticated emergency registration is REFUSED by configuration \
             (amf.emergency.allow_unauthenticated: false): an EMERGENCY registration whose \
             AUSF cannot be reached is rejected and released like any other. TS 33.501 \
             §5.1.2 requires this setting only where local regulation FORBIDS unauthenticated \
             emergency services."
        );
    }
}

/// The process-wide unauthenticated-emergency policy.
pub fn allow_unauthenticated_emergency() -> EmergencyPolicy {
    EmergencyPolicy {
        allow_unauthenticated: ALLOW_UNAUTHENTICATED_EMERGENCY
            .load(std::sync::atomic::Ordering::SeqCst),
    }
}

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
    /// Active emergency contexts, keyed by AMF UE NGAP ID.
    ///
    /// `u64`, not `u32`: the AMF UE NGAP ID is `INTEGER (0..2^40-1)` on the wire
    /// (TS 38.413 §9.3.3.1) and the rest of amfd carries it as `u64`. A `u32` key
    /// truncated the top 8 bits, so two UEs whose ids differed only above bit 32
    /// shared one entry -- the second overwriting the first's authentication state
    /// and assigned PDU session, and either one's release freeing the other's
    /// context (#353).
    active_contexts: HashMap<u64, EmergencyContext>,
    /// Emergency DNN name
    emergency_dnn: String,
    /// IMS P-CSCF address for emergency
    ims_pcscf_addr: Option<String>,
    /// Emergency call count
    emergency_count: u64,
    /// Whether an emergency registration the network could not authenticate may proceed
    /// (#361, TS 33.501 §10.2.2 / §5.1.2). Seeded at startup from configuration.
    policy: EmergencyPolicy,
}

impl Default for EmergencyHandler {
    fn default() -> Self {
        Self::new()
    }
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
            // Read from the process-wide seed rather than the type default: this handler is
            // constructed in `NgapServer::new`, which runs AFTER `load_config`, so the
            // operator's answer is already available (#361).
            policy: allow_unauthenticated_emergency(),
        }
    }

    /// The unauthenticated-emergency policy in force (#361).
    pub fn policy(&self) -> EmergencyPolicy {
        self.policy
    }

    /// Install the policy resolved from configuration at startup.
    pub fn set_policy(&mut self, policy: EmergencyPolicy) {
        self.policy = policy;
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

    /// Handles emergency registration.
    ///
    /// `authenticated` is the authentication OUTCOME, not the presence of an identity. The
    /// live caller used to pass `req.suci.is_some()` here (#361): at the point the emergency
    /// branch runs, `AmfUe::supi` is always `None` because it is written only from the AUSF
    /// confirmation, so the predicate reduced to "the UE sent some SUCI" — and every
    /// emergency registration that presented one, INCLUDING one the AUSF then refused or
    /// could not be asked about, was recorded `authenticated: true` with
    /// `reg_type: EmergencyWithSupi`. `is_emergency_only()` reads `reg_type`, so it answered
    /// `false` for exactly the UEs TS 33.501 §10.2.2 calls unauthenticated — and this is the
    /// field an operator and a PSAP consult to know whether the caller's identity was
    /// verified (§10.2.2.1 requires the unauthenticated case to be distinguishable).
    ///
    /// A registration therefore starts here as NOT authenticated and is promoted by
    /// [`Self::mark_authenticated`] when the AUSF confirms, rather than being guessed.
    pub fn handle_emergency_registration(
        &mut self,
        amf_ue_ngap_id: u64,
        authenticated: bool,
    ) -> EmergencyContext {
        self.emergency_count += 1;

        let ctx = if authenticated {
            EmergencyContext::authenticated()
        } else {
            EmergencyContext::unauthenticated()
        };

        self.active_contexts.insert(amf_ue_ngap_id, ctx.clone());
        ctx
    }

    /// Promote an emergency context to authenticated once 5G-AKA has actually succeeded
    /// (TS 33.501 §10.2.2.2 NOTE: on authentication success the AMF selects a non-NULL
    /// integrity algorithm, i.e. this is an ordinary emergency session).
    ///
    /// Returns whether a context was present to promote, so a caller can tell "promoted"
    /// from "this UE is not emergency registered" rather than having both look alike.
    pub fn mark_authenticated(&mut self, amf_ue_ngap_id: u64) -> bool {
        match self.active_contexts.get_mut(&amf_ue_ngap_id) {
            Some(ctx) => {
                ctx.authenticated = true;
                ctx.reg_type = EmergencyRegistrationType::EmergencyWithSupi;
                true
            }
            None => false,
        }
    }

    /// Demote an emergency context to unauthenticated once authentication has been
    /// established to be unobtainable (TS 33.501 §10.2.2.2: the AMF "cannot obtain
    /// authentication vector").
    ///
    /// The counterpart to [`Self::mark_authenticated`], and the one the AUSF-failure arm
    /// needs: the context was created when the Registration Request arrived, before the
    /// outcome was known. Returns whether a context was present to demote, so the caller can
    /// create one rather than silently proceeding with no record of the session.
    pub fn mark_unauthenticated(&mut self, amf_ue_ngap_id: u64) -> bool {
        match self.active_contexts.get_mut(&amf_ue_ngap_id) {
            Some(ctx) => {
                ctx.authenticated = false;
                ctx.reg_type = EmergencyRegistrationType::EmergencyNoSupi;
                true
            }
            None => false,
        }
    }

    /// Whether this UE holds an emergency context the network could NOT authenticate, i.e.
    /// the TS 33.501 §10.2.2 case: NIA0/NEA0, no UDM update, emergency DNN only.
    ///
    /// Distinct from `is_emergency_only()` on the context: that reads `reg_type` and so is a
    /// statement about which §10.2.2.1 shape this is, while this is the predicate every
    /// downstream restriction branches on.
    pub fn is_unauthenticated_emergency(&self, amf_ue_ngap_id: u64) -> bool {
        self.active_contexts
            .get(&amf_ue_ngap_id)
            .is_some_and(|ctx| !ctx.authenticated)
    }

    /// Assigns an emergency PDU session
    pub fn assign_emergency_pdu_session(&mut self, amf_ue_ngap_id: u64, psi: u8) -> bool {
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
    pub fn release_emergency(&mut self, amf_ue_ngap_id: u64) -> bool {
        self.active_contexts.remove(&amf_ue_ngap_id).is_some()
    }

    /// The emergency context recorded for `amf_ue_ngap_id`, if any.
    ///
    /// Companion to [`Self::active_count`]: without it the stored context is
    /// write-only — `assign_emergency_pdu_session` records a PDU session id that
    /// nothing could read back, so a context silently replaced by a colliding key
    /// was undetectable from outside this type.
    pub fn emergency_context(&self, amf_ue_ngap_id: u64) -> Option<&EmergencyContext> {
        self.active_contexts.get(&amf_ue_ngap_id)
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

    /// **#361:** the unauthenticated-emergency policy DEFAULTS ON, and the precedence is env
    /// over YAML over default.
    ///
    /// The default is the assertion that matters most, and it is a regulatory one. TS 33.501
    /// §5.1.2 makes unauthenticated emergency access something the 5G system "shall support" in
    /// regions that require it, while a network in a region that forbids it "shall not support
    /// this feature" -- so the knob must exist, and the shipped value decides which of the two
    /// obligations a deployment breaches by doing nothing. Defaulting OFF would ship a build
    /// that is non-conformant out of the box in every mandatory-E911 jurisdiction, and would
    /// fail in the direction where the failure is a caller who cannot reach a PSAP. Defaulting
    /// ON fails, at worst, into the emergency-only, null-ciphered, single-DNN,
    /// no-subscription session TS 33.501 §10.2.2 and TS 23.501 §5.16.4.9a specify for exactly
    /// this case.
    ///
    /// So: if this assertion is ever flipped, it must be flipped with a spec argument, not for
    /// caution. See `specs/decide-unauthenticated-emergency-registration.md`.
    #[test]
    fn the_unauthenticated_emergency_policy_defaults_on_and_env_outranks_yaml() {
        assert!(
            EmergencyPolicy::default().allow_unauthenticated,
            "the SHIPPED default must permit unauthenticated emergency service (TS 33.501 \
             §5.1.2 'shall support'); an operator whose regulation forbids it sets \
             amf.emergency.allow_unauthenticated: false"
        );
        assert!(
            EmergencyPolicy::resolve(None, None).allow_unauthenticated,
            "absent config resolves to the default"
        );

        // YAML alone.
        assert!(
            !EmergencyPolicy::resolve(None, Some(false)).allow_unauthenticated,
            "an explicit YAML false must actually refuse -- a knob whose off setting did \
             nothing would leave a forbidding jurisdiction non-conformant with no way out"
        );
        assert!(EmergencyPolicy::resolve(None, Some(true)).allow_unauthenticated);

        // Env OUTRANKS yaml, in both directions. Both are asserted because a precedence rule
        // tested in one direction is satisfied by an implementation that ignores the yaml.
        assert!(
            !EmergencyPolicy::resolve(Some("0"), Some(true)).allow_unauthenticated,
            "AMF_EMERGENCY_ALLOW_UNAUTHENTICATED=0 must override a yaml true"
        );
        assert!(
            EmergencyPolicy::resolve(Some("1"), Some(false)).allow_unauthenticated,
            "and =1 must override a yaml false"
        );

        // Accepted truthy spellings, matching the tree's other env knobs.
        for truthy in ["1", "true", "TRUE", "yes", "on", " true "] {
            assert!(
                EmergencyPolicy::resolve(Some(truthy), None).allow_unauthenticated,
                "{truthy:?} must read as enabled"
            );
        }
        // Anything else is OFF rather than defaulted: an operator who set the variable meant
        // something by it, and silently falling back to the default would hide a typo in a
        // regulatory setting.
        for falsy in ["0", "false", "no", "off", "", "maybe"] {
            assert!(
                !EmergencyPolicy::resolve(Some(falsy), Some(true)).allow_unauthenticated,
                "{falsy:?} must read as disabled, not fall through to the yaml or the default"
            );
        }
    }

    /// **#361:** an emergency context records the authentication OUTCOME, and can be promoted
    /// or demoted as the procedure learns it.
    ///
    /// The bug this guards: the live caller passed `req.suci.is_some()` as `has_supi`, and the
    /// field it fed is read as "was this caller authenticated". At the Registration Request
    /// nothing has been authenticated yet, so every emergency UE that presented a SUCI -- the
    /// normal case -- was recorded `authenticated: true` and `is_emergency_only()` answered
    /// `false` for precisely the UEs TS 33.501 §10.2.2.1 calls unauthenticated. That is the
    /// field a PSAP and an operator consult to know whether the caller's identity was verified.
    #[test]
    fn an_emergency_context_records_the_authentication_outcome_not_the_identity() {
        let mut handler = EmergencyHandler::new();
        // Distinct literal ids: `active_contexts` is keyed on the AMF UE NGAP ID, so reusing
        // one would have the second registration overwrite the first and hide a defect.
        let pending = 361_001u64;
        let never = 361_002u64;

        // A registration starts UNauthenticated, whatever identity it carried.
        let ctx = handler.handle_emergency_registration(pending, false);
        assert!(!ctx.authenticated);
        assert!(handler.is_unauthenticated_emergency(pending));

        // Promoted when 5G-AKA actually succeeds (TS 33.501 §10.2.1.2).
        assert!(
            handler.mark_authenticated(pending),
            "a present context must report that it was promoted"
        );
        assert!(!handler.is_unauthenticated_emergency(pending));
        let ctx = handler
            .emergency_context(pending)
            .expect("still present after promotion");
        assert!(ctx.authenticated);
        assert_eq!(ctx.reg_type, EmergencyRegistrationType::EmergencyWithSupi);
        assert!(
            !ctx.is_emergency_only(),
            "an authenticated emergency UE is not the §10.2.2.1 no-SUPI case"
        );

        // And demoted when it turns out no vector can be obtained (§10.2.2.2).
        assert!(handler.mark_unauthenticated(pending));
        let ctx = handler.emergency_context(pending).expect("still present");
        assert!(!ctx.authenticated);
        assert_eq!(ctx.reg_type, EmergencyRegistrationType::EmergencyNoSupi);
        assert!(ctx.is_emergency_only());

        // Both transitions report absence rather than silently succeeding, so a caller can
        // create a context instead of proceeding with no record of the session.
        assert!(
            !handler.mark_authenticated(never),
            "promoting a UE with no emergency context must report false"
        );
        assert!(!handler.mark_unauthenticated(never));
        assert!(
            !handler.is_unauthenticated_emergency(never),
            "and a UE that is not emergency registered at all is not an unauthenticated \
             emergency one -- otherwise every ordinary UE would inherit the restrictions"
        );
    }

    #[test]
    fn test_emergency_number_check() {
        let mut handler = EmergencyHandler::new();
        let plmn = [0x99, 0xF9, 0x07]; // 999/07

        handler.register_plmn_numbers(
            plmn,
            vec![
                EmergencyNumber {
                    number: "112".to_string(),
                    categories: 0xFF,
                    sub_services_uri: None,
                },
                EmergencyNumber {
                    number: "911".to_string(),
                    categories: 0xFF,
                    sub_services_uri: None,
                },
            ],
        );

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
        let ctx = EmergencyContext::unauthenticated().with_category(EmergencyCategory::Ambulance);
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

    /// #353: two UEs whose AMF UE NGAP IDs differ ONLY above bit 32 keep separate
    /// emergency contexts.
    ///
    /// The AMF UE NGAP ID is `INTEGER (0..2^40-1)` (TS 38.413 §9.3.3.1). `1` and
    /// `1 + (1 << 32)` are both legal ids and are chosen because they are
    /// indistinguishable under the old `u32` key: `(1 + (1 << 32)) as u32 == 1`. So
    /// every assertion below is reachable only if the key really is 40-bit-wide.
    ///
    /// Content, not just count: the two UEs are registered with OPPOSITE `has_supi`
    /// and given DIFFERENT PDU sessions, so an overwrite is visible as the wrong
    /// authentication state rather than only as a smaller `active_count`.
    #[test]
    fn ids_differing_above_bit_32_keep_separate_emergency_contexts() {
        let low = 1u64;
        let high = 1u64 + (1u64 << 32);
        assert_eq!(low as u32, high as u32, "the fixture must actually collide");

        let mut handler = EmergencyHandler::new();
        handler.handle_emergency_registration(low, false);
        handler.handle_emergency_registration(high, true);

        assert_eq!(
            handler.active_count(),
            2,
            "each UE needs its own emergency context; a truncating key merges them"
        );
        assert!(handler.assign_emergency_pdu_session(low, 5));
        assert!(handler.assign_emergency_pdu_session(high, 6));

        let low_ctx = handler
            .emergency_context(low)
            .expect("the low id must still have its own context");
        assert!(
            !low_ctx.authenticated,
            "the low UE registered without a SUPI and must not inherit the high UE's \
             authenticated state"
        );
        assert_eq!(low_ctx.pdu_session_id, Some(5));

        let high_ctx = handler
            .emergency_context(high)
            .expect("the high id must have a context of its own, not the low id's");
        assert!(high_ctx.authenticated);
        assert_eq!(high_ctx.pdu_session_id, Some(6));

        // Releasing one must not free the other. On the old key the first release
        // removed the single shared entry, so this second one returned false and the
        // surviving UE was left believing it still held an emergency context.
        assert!(handler.release_emergency(low));
        assert_eq!(handler.active_count(), 1);
        assert!(
            handler.release_emergency(high),
            "the high UE's context must survive the low UE's release"
        );
        assert_eq!(handler.active_count(), 0);
    }
}
