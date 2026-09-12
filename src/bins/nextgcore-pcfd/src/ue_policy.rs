//! UE Policy Management for PCF (Rel-16, TS 23.503 §6.6)
//!
//! Implements URSP (UE Route Selection Policy) rule generation,
//! Traffic Descriptor matching, and Route Selection Descriptor provisioning.

use std::collections::HashMap;

/// Traffic Descriptor component types (TS 24.526 §5.2)
#[derive(Debug, Clone, PartialEq)]
pub enum TrafficDescriptorComponent {
    /// Application identifier (OSId + OSAppId)
    ///
    /// An OPAQUE operator string. TS 24.526 Table 5.2.1's "OS Id + OS App Id type"
    /// needs a structured 16-octet UUID plus a length-prefixed app id, which this
    /// cannot supply, so it remains unencodable -- use
    /// [`TrafficDescriptorComponent::OsIdOsAppId`] for anything that must reach the
    /// wire (#91).
    AppId(String),
    /// OS Id + OS App Id (TS 24.526 Table 5.2.1, type `0b00001000`): a 16-octet
    /// RFC 4122 UUID and an OS App Id.
    OsIdOsAppId { os_id: [u8; 16], app_id: String },
    /// IPv4 remote address + mask (type `0b00010000`).
    Ipv4RemoteAddress { addr: [u8; 4], mask: [u8; 4] },
    /// IPv6 remote address + prefix length (type `0b00100001`).
    Ipv6RemoteAddress { addr: [u8; 16], prefix_len: u8 },
    /// IPv4 protocol identifier / IPv6 next header (type `0b00110000`).
    ProtocolIdentifier(u8),
    /// Single remote port (type `0b01010000`).
    SingleRemotePort(u16),
    /// Remote port range, low limit first (type `0b01010001`).
    RemotePortRange { low: u16, high: u16 },
    /// IP 3-tuple: dest IP prefix, protocol, port range
    IpDesc {
        dest_ip_prefix: String, // e.g., "192.168.0.0/16"
        protocol: Option<u8>,
        dest_port_min: Option<u16>,
        dest_port_max: Option<u16>,
    },
    /// DNN (Data Network Name)
    Dnn(String),
    /// S-NSSAI (SST + SD)
    SNssai { sst: u8, sd: Option<u32> },
    /// Non-IP traffic (any non-IP)
    NonIp,
    /// Ethernet traffic
    Ethernet,
    /// Domain name pattern (wildcard DNS matching)
    DomainName(String),
}

/// Traffic Descriptor: a set of components (AND-logic within, OR across TDs per URSP rule)
#[derive(Debug, Clone)]
pub struct TrafficDescriptor {
    pub components: Vec<TrafficDescriptorComponent>,
}

impl TrafficDescriptor {
    pub fn new(components: Vec<TrafficDescriptorComponent>) -> Self {
        Self { components }
    }

    /// Creates a simple DNN-based descriptor
    pub fn for_dnn(dnn: impl Into<String>) -> Self {
        Self::new(vec![TrafficDescriptorComponent::Dnn(dnn.into())])
    }

    /// Creates an app-based descriptor
    pub fn for_app(app_id: impl Into<String>) -> Self {
        Self::new(vec![TrafficDescriptorComponent::AppId(app_id.into())])
    }
}

/// PDU session type for route selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSelectionPduType {
    Ipv4,
    Ipv6,
    Ipv4v6,
    Unstructured,
    Ethernet,
}

/// Route Selection Descriptor (RSD) — specifies which PDU session to use
#[derive(Debug, Clone)]
pub struct RouteSelectionDescriptor {
    /// Route selection descriptor precedence (lower = higher priority)
    pub precedence: u8,
    /// DNN to use
    pub dnn: Option<String>,
    /// S-NSSAI for the PDU session
    pub snssai: Option<(u8, Option<u32>)>, // (SST, SD)
    /// PDU session type
    pub pdu_type: RouteSelectionPduType,
    /// SSC mode (1=steady, 2=break-before-make, 3=make-before-break)
    pub ssc_mode: u8,
    /// Preferred access type (3GPP or non-3GPP)
    pub access_type: Option<AccessType>,
}

/// Access type for PDU session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    ThreeGpp,
    NonThreeGpp,
}

impl RouteSelectionDescriptor {
    /// Default internet access descriptor
    pub fn default_internet() -> Self {
        Self {
            precedence: 255,
            dnn: Some("internet".into()),
            snssai: Some((1, None)), // eMBB SST=1
            pdu_type: RouteSelectionPduType::Ipv4v6,
            ssc_mode: 1,
            access_type: Some(AccessType::ThreeGpp),
        }
    }

    /// IMS voice descriptor
    pub fn ims_voice() -> Self {
        Self {
            precedence: 10,
            dnn: Some("ims".into()),
            snssai: Some((1, None)),
            pdu_type: RouteSelectionPduType::Ipv4v6,
            ssc_mode: 1,
            access_type: Some(AccessType::ThreeGpp),
        }
    }
}

/// URSP Rule: maps traffic descriptors to route selection descriptors
#[derive(Debug, Clone)]
pub struct UrspRule {
    /// Rule precedence (lower = higher priority, evaluated first)
    pub precedence: u8,
    /// Traffic descriptors (evaluated as OR: any matching TD triggers this rule)
    pub traffic_descriptors: Vec<TrafficDescriptor>,
    /// Route selection descriptors (ordered by precedence)
    pub route_selection_descriptors: Vec<RouteSelectionDescriptor>,
}

impl UrspRule {
    /// Creates a catch-all rule (matches all traffic, uses default internet)
    pub fn catch_all() -> Self {
        Self {
            precedence: 255,
            traffic_descriptors: vec![
                TrafficDescriptor::new(vec![]), // empty TD matches all
            ],
            route_selection_descriptors: vec![RouteSelectionDescriptor::default_internet()],
        }
    }

    /// Creates an IMS voice rule
    pub fn ims_rule() -> Self {
        Self {
            precedence: 10,
            traffic_descriptors: vec![TrafficDescriptor::for_dnn("ims")],
            route_selection_descriptors: vec![RouteSelectionDescriptor::ims_voice()],
        }
    }
}

/// PCF UE Policy context: manages URSP policies per UE
#[derive(Debug, Default)]
pub struct UePolicyContext {
    /// URSP rules per SUPI, sorted by precedence
    ursp_rules: HashMap<String, Vec<UrspRule>>,
}

impl UePolicyContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Provisions URSP rules for a UE
    pub fn provision_ursp(&mut self, supi: String, mut rules: Vec<UrspRule>) {
        // Sort by precedence (lowest number = highest priority)
        rules.sort_by_key(|r| r.precedence);
        self.ursp_rules.insert(supi, rules);
    }

    /// Returns the URSP rules for a UE, or empty slice
    pub fn get_ursp(&self, supi: &str) -> &[UrspRule] {
        self.ursp_rules
            .get(supi)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the first matching rule for a given DNN (simplified matching)
    pub fn find_rule_for_dnn<'a>(&'a self, supi: &str, dnn: &str) -> Option<&'a UrspRule> {
        self.ursp_rules.get(supi)?.iter().find(|rule| {
            rule.traffic_descriptors.iter().any(|td| {
                td.components
                    .iter()
                    .any(|c| matches!(c, TrafficDescriptorComponent::Dnn(d) if d == dnn))
                    || td.components.is_empty() // catch-all
            })
        })
    }

    /// Returns total number of UEs with URSP policies
    pub fn policy_count(&self) -> usize {
        self.ursp_rules.len()
    }
}

// --- Wave-6 E3: process-global UE-policy context (the mapping target) --------

/// Process-global [`UePolicyContext`]: the per-SUPI URSP rule store the E3
/// delivery path provisions the resolved rules into (TS 23.503 §6.6.2.2 keeps
/// the applicable UE policy keyed by the UE). Written by
/// [`provision_context_ursp`] on each delivery and readable by SUPI via
/// [`context_ursp_for`] — E6 (delivery-result loop) reads it to correlate a
/// MANAGE UE POLICY COMPLETE/REJECT back to the rules that were sent.
fn ue_policy_context() -> &'static Mutex<UePolicyContext> {
    static CTX: OnceLock<Mutex<UePolicyContext>> = OnceLock::new();
    CTX.get_or_init(|| Mutex::new(UePolicyContext::new()))
}

/// Provision the resolved URSP rules for `supi` into the process-global
/// [`UePolicyContext`] (E3 step: `provision_ursp` keyed by SUPI). Delivery uses
/// these over the static defaults whenever a UDR-provisioned set was resolved.
pub fn provision_context_ursp(supi: &str, rules: Vec<UrspRule>) {
    if let Ok(mut ctx) = ue_policy_context().lock() {
        ctx.provision_ursp(supi.to_string(), rules);
    }
}

/// The URSP rules currently provisioned for `supi` in the process-global
/// context (sorted by precedence), or empty when none. Lets E6 / tests read
/// back what was delivered without re-querying UDR.
pub fn context_ursp_for(supi: &str) -> Vec<UrspRule> {
    ue_policy_context()
        .lock()
        .map(|ctx| ctx.get_ursp(supi).to_vec())
        .unwrap_or_default()
}

// --- Npcf_UEPolicyControl association store (TS 29.525 §5.6.2.2) ---
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use nextgcore_nas::fiveg::ue_policy as nas_updp;

/// URSP-delivery outcome for one UE policy association (Wave-6 E4). The
/// transfer is NEVER reported `Delivered` on the `Namf_Communication`
/// N1N2MessageTransfer 200 alone — 200 only means the AMF accepted the
/// downlink; delivery is confirmed by a MANAGE UE POLICY COMPLETE from the UE
/// (item E6). Until then it stays `Pending` (fail-closed against fake success).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryState {
    /// Command built and (attempted to be) transferred; awaiting the UE's
    /// MANAGE UE POLICY COMPLETE (TS 24.501 D.2.1.3, delivered by item E6).
    Pending,
    /// UE acknowledged with MANAGE UE POLICY COMPLETE (set by item E6).
    Delivered,
    /// Encode error, or the AMF rejected/could-not-reach the UE (504 etc.).
    /// Carries the human-readable cause for logs/tests. Fail-closed: a
    /// delivery that could not start is `Failed`, never silently `Delivered`.
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct UePolicyAssociation {
    pub pol_asso_id: String,
    pub supi: String,
    pub notification_uri: String,
    pub supp_feat: String,
    /// PCF-allocated procedure transaction identity for the UE-policy
    /// delivery procedure, 80H-FEH (TS 24.501 D.1.2). `0` until a delivery is
    /// configured (kill-switch off / no delivery attempted).
    pub pti: u8,
    /// UE policy section code assigned to the delivered section (Table
    /// D.6.2.1). Monotonic per association; the first section is `1`.
    pub upsc: u16,
    /// Source PLMN (mcc, mnc) used to build the D.6.2 sublist; taken from the
    /// PolicyAssociationRequest `servingPlmn`/`guami` when present.
    pub plmn: Option<(String, String)>,
    /// The URSP rules assembled for this association (the pcfd model; encoded
    /// to wire via [`build_manage_ue_policy_command`]).
    pub rules: Vec<UrspRule>,
    /// Delivery outcome (see [`DeliveryState`]).
    pub delivery_state: DeliveryState,
    /// Wave-6 E6: the `n1n2NotifySubscriptionId` the AMF minted for this
    /// association's `N1N2MessageSubscribe` (n1MessageClass "UPDP"), so the
    /// association delete leg can `N1N2MessageUnSubscribe`. `None` until the
    /// delivery task subscribes (or when no AMF/self-identity is available).
    pub n1n2_subscription_id: Option<String>,
    /// Wave-6 E6: the UPSC the UE confirmed installed via MANAGE UE POLICY
    /// COMPLETE (D.2.1.3 — the section becomes an installed UPSI). `None` until
    /// a COMPLETE with the matching PTI arrives.
    pub installed_upsc: Option<u16>,
    /// Every section UPSC the delivered command carried (#91). `upsc` above stays
    /// the FIRST one, which is what the existing COMPLETE correlation uses; this is
    /// the whole set, so a multi-section delivery is not misreported as one section.
    pub delivered_upscs: Vec<u16>,
    /// The request triggers the consumer last said it observes (TS 29.525
    /// §5.6.2.4). Defaults to `["UE_POLICY"]`, which is what the create answers with
    /// and what an update omitting the member means (#91).
    pub triggers: Vec<String>,
    /// The UPSIs the UE reported as already installed, from the UE STATE INDICATION
    /// in its Registration Request's UE policy container, as `(mcc, mnc, upsc)`
    /// (#91, TS 24.501 §5.5.1.2.2 / D.6.4).
    ///
    /// Empty means the UE reported nothing, which is NOT the same as reporting an
    /// empty list -- both lead to a full delivery, but only the second is a statement
    /// by the UE, and the log distinguishes them.
    pub reported_upsis: Vec<(String, String, u16)>,
}

fn ue_policy_store() -> &'static Mutex<HashMap<String, UePolicyAssociation>> {
    static STORE: OnceLock<Mutex<HashMap<String, UePolicyAssociation>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}
pub fn ue_policy_add(supi: &str, notification_uri: &str, supp_feat: &str) -> UePolicyAssociation {
    let assoc = UePolicyAssociation {
        pol_asso_id: uuid::Uuid::new_v4().to_string(),
        supi: supi.to_string(),
        notification_uri: notification_uri.to_string(),
        supp_feat: supp_feat.to_string(),
        pti: 0,
        upsc: 0,
        plmn: None,
        rules: Vec::new(),
        delivery_state: DeliveryState::Pending,
        delivered_upscs: Vec::new(),
        triggers: vec!["UE_POLICY".to_string()],
        reported_upsis: Vec::new(),
        n1n2_subscription_id: None,
        installed_upsc: None,
    };
    if let Ok(mut m) = ue_policy_store().lock() {
        m.insert(assoc.pol_asso_id.clone(), assoc.clone());
    }
    assoc
}
pub fn ue_policy_find(pol_asso_id: &str) -> Option<UePolicyAssociation> {
    ue_policy_store().lock().ok()?.get(pol_asso_id).cloned()
}
pub fn ue_policy_remove(pol_asso_id: &str) -> bool {
    ue_policy_store()
        .lock()
        .map(|mut m| m.remove(pol_asso_id).is_some())
        .unwrap_or(false)
}

/// Record the delivery parameters (PTI, UPSC, PLMN, rules) chosen for an
/// association at create time, leaving `delivery_state = Pending`. No-op if
/// the association was already deleted (cancel-on-delete).
pub fn ue_policy_set_delivery(
    pol_asso_id: &str,
    pti: u8,
    upsc: u16,
    plmn: Option<(String, String)>,
    rules: Vec<UrspRule>,
) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.pti = pti;
            a.upsc = upsc;
            a.plmn = plmn;
            a.rules = rules;
            a.delivery_state = DeliveryState::Pending;
        }
    }
}

/// Update the delivery state of an association. No-op if the association was
/// deleted meanwhile — the async delivery task must not resurrect a
/// cancelled association (E4 risk note: "must not outlive association
/// deletion").
pub fn ue_policy_update_delivery_state(pol_asso_id: &str, state: DeliveryState) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.delivery_state = state;
        }
    }
}

/// Current delivery state of an association (clone-out), or `None` if it was
/// deleted. The T3501 driver reads this each expiry to decide whether to
/// retransmit — once the state leaves `Pending` (COMPLETE→Delivered,
/// REJECT/encode→Failed) or the association is gone, the driver stops.
pub fn ue_policy_delivery_state(pol_asso_id: &str) -> Option<DeliveryState> {
    ue_policy_store()
        .lock()
        .ok()?
        .get(pol_asso_id)
        .map(|a| a.delivery_state.clone())
}

/// Record the `N1N2MessageSubscribe` id the AMF minted for this association's
/// "UPDP" notify callback (Wave-6 E6), so the delete leg can unsubscribe. No-op
/// if the association was already deleted (cancel-on-delete).
pub fn ue_policy_set_subscription_id(pol_asso_id: &str, subscription_id: &str) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.n1n2_subscription_id = Some(subscription_id.to_string());
        }
    }
}

/// Mark an association `Delivered` and record `upsc` as the installed UPSI
/// (TS 24.501 D.2.1.3), set on a MANAGE UE POLICY COMPLETE with the matching
/// PTI. No-op if the association was deleted meanwhile.
pub fn ue_policy_mark_delivered(pol_asso_id: &str, upsc: u16) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.delivery_state = DeliveryState::Delivered;
            a.installed_upsc = Some(upsc);
        }
    }
}

// --- Wave-6 E4: URSP delivery command builder (TS 24.501 Annex D / 24.526) ---

/// Whether the kill-switch `PCF_UE_POLICY_DELIVERY` leaves URSP delivery ON
/// (the default). Set it to `off`/`0`/`false`/`disabled` to restore the
/// pre-Wave-6 behaviour (association only, no N1N2 transfer) byte-for-byte.
/// Justification for the flag: E4 puts a new DL NAS message on the live
/// registration path; the matched-sim E2E (item E9) must sign it off before
/// it ships default-on.
pub fn delivery_enabled() -> bool {
    match std::env::var("PCF_UE_POLICY_DELIVERY") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "disabled" | "no"
        ),
        Err(_) => true,
    }
}

/// PCF-initiated PTI allocator (TS 24.501 D.1.2: 80H-FEH). Monotonic, wrapping
/// within the PCF range so PTIs stay inside 0x80..=0xFE.
pub fn alloc_pti() -> u8 {
    static NEXT: AtomicU8 = AtomicU8::new(nas_updp::PCF_PTI_MIN);
    // fetch_update keeps every issued value inside [MIN, MAX].
    NEXT.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
        Some(if cur >= nas_updp::PCF_PTI_MAX {
            nas_updp::PCF_PTI_MIN
        } else {
            cur + 1
        })
    })
    .unwrap_or(nas_updp::PCF_PTI_MIN)
}

// --- Wave-6 E6: T3501 retransmission + delivery-result correlation ----------

/// Maximum number of MANAGE UE POLICY COMMAND retransmissions on T3501 expiry.
/// TS 24.501 D.2.1.5 abnormal case: on the FIRST T3501 expiry the PCF
/// retransmits the SAME command (same PTI) and restarts T3501; on the SECOND
/// expiry it aborts the procedure. So exactly ONE retransmission.
pub const UE_POLICY_MAX_RETRANSMISSIONS: u8 = 1;

/// T3501 default duration (TS 24.501 D.7). Env-tunable via `PCF_T3501_SECS`
/// (seconds); defaults to 30s. A zero/invalid value falls back to the default.
pub fn t3501_duration() -> std::time::Duration {
    let secs = std::env::var("PCF_T3501_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

/// The action to take on a T3501 expiry given the number of retransmissions
/// already performed (TS 24.501 D.2.1.5). Pure state machine — unit-testable
/// without any timer/network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T3501Expiry {
    /// Retransmit the SAME MANAGE UE POLICY COMMAND (same PTI) and restart T3501.
    Retransmit,
    /// Abort: no COMPLETE after the single retransmission → mark delivery Failed.
    Abort,
}

/// Decide the T3501 expiry action. `retransmissions_done` counts retransmits
/// already sent (0 on the first expiry). `Retransmit` while below the cap,
/// `Abort` once the single retransmission was already sent.
pub fn t3501_on_expiry(retransmissions_done: u8) -> T3501Expiry {
    if retransmissions_done < UE_POLICY_MAX_RETRANSMISSIONS {
        T3501Expiry::Retransmit
    } else {
        T3501Expiry::Abort
    }
}

/// Drive the T3501 retransmission loop for one association (Wave-6 E6). On each
/// expiry, if the association is still `Pending` it retransmits the command
/// exactly once (via `resend`), then on the next expiry aborts to `Failed`. It
/// stops immediately once the state leaves `Pending` (a COMPLETE flipped it to
/// `Delivered`, a REJECT to `Failed`) or the association was deleted — i.e. a
/// COMPLETE "stops T3501".
///
/// Generic over an async `resend` closure so it is unit-testable without the
/// SBI client (and to avoid a `sbi_path`↔`ue_policy` dependency cycle).
pub async fn run_t3501<F, Fut>(pol_asso_id: &str, duration: std::time::Duration, mut resend: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut retransmissions_done: u8 = 0;
    loop {
        tokio::time::sleep(duration).await;
        match ue_policy_delivery_state(pol_asso_id) {
            Some(DeliveryState::Pending) => match t3501_on_expiry(retransmissions_done) {
                T3501Expiry::Retransmit => {
                    retransmissions_done += 1;
                    log::info!(
                        "[{pol_asso_id}] UE policy: T3501 expired, retransmitting MANAGE UE \
                         POLICY COMMAND (attempt {retransmissions_done}, TS 24.501 D.2.1.5)"
                    );
                    resend().await;
                }
                T3501Expiry::Abort => {
                    log::warn!(
                        "[{pol_asso_id}] UE policy: T3501 expired after {UE_POLICY_MAX_RETRANSMISSIONS} \
                         retransmission(s); no MANAGE UE POLICY COMPLETE — marking delivery Failed"
                    );
                    ue_policy_update_delivery_state(
                        pol_asso_id,
                        DeliveryState::Failed(
                            "T3501 expired: no MANAGE UE POLICY COMPLETE after one \
                             retransmission (TS 24.501 D.2.1.5)"
                                .to_string(),
                        ),
                    );
                    return;
                }
            },
            // Delivered / Failed / association deleted → stop the timer.
            _ => return,
        }
    }
}

/// Outcome of applying an uplink UE-policy container to an association
/// (Wave-6 E6, TS 24.501 D.2.1.3/D.2.1.4). Returned by
/// [`apply_ue_policy_ul_container`] so the callback route can log/answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UePolicyResultOutcome {
    /// MANAGE UE POLICY COMPLETE with the matching PTI → association Delivered,
    /// carries the installed UPSC.
    Delivered(u16),
    /// MANAGE UE POLICY COMMAND REJECT with the matching PTI → association
    /// Failed, carries the human-readable D.6.3 cause summary.
    Rejected(String),
    /// A COMPLETE/REJECT whose PTI does not match the association's (stale /
    /// duplicate command, D.2.1.6) — dropped, state unchanged (never panics).
    PtiMismatch { expected: u8, got: u8 },
    /// UE STATE INDICATION (0x04): the UE reported the UPSIs it already has
    /// installed. Recorded on the association so the next delivery can be a delta
    /// (#91); the delivery state itself is unchanged, since this is not a result.
    /// Carries how many UPSIs were reported.
    StateReported(usize),
    /// A decodable message that is not a COMPLETE/REJECT/UE STATE INDICATION —
    /// not part of this loop; state unchanged.
    Ignored(u8),
    /// The container did not decode as a UPDP message (malformed) — dropped,
    /// state unchanged (fail-closed, no crash).
    Undecodable,
    /// No association with the given id (deleted / unknown).
    UnknownAssociation,
}

/// Correlate an uplink UE-policy container (the verbatim N1 payload the AMF
/// relayed) against association `pol_asso_id` and update its delivery state
/// (Wave-6 E6). A MANAGE UE POLICY COMPLETE with the matching PTI flips it to
/// `Delivered` (recording the UPSC as installed UPSI, D.2.1.3); a MANAGE UE
/// POLICY COMMAND REJECT with the matching PTI flips it to `Failed` with the
/// decoded D.6.3 per-instruction cause(s) (D.2.1.4). A PTI mismatch, a non
/// COMPLETE/REJECT message, or an undecodable container leaves the state
/// unchanged (fail-closed — Delivered is reached ONLY via a matching COMPLETE).
pub fn apply_ue_policy_ul_container(pol_asso_id: &str, container: &[u8]) -> UePolicyResultOutcome {
    let Some(assoc) = ue_policy_find(pol_asso_id) else {
        return UePolicyResultOutcome::UnknownAssociation;
    };
    let Ok(msg_type) = nas_updp::peek_message_type(container) else {
        return UePolicyResultOutcome::Undecodable;
    };
    match msg_type {
        nas_updp::UPDP_MSG_MANAGE_UE_POLICY_COMPLETE => {
            let Ok(complete) = nas_updp::ManageUePolicyComplete::decode(container) else {
                return UePolicyResultOutcome::Undecodable;
            };
            if complete.pti != assoc.pti {
                log::warn!(
                    "[{pol_asso_id}] UE policy: MANAGE UE POLICY COMPLETE PTI {:#04x} != \
                     association PTI {:#04x}; dropping stale COMPLETE (TS 24.501 D.2.1.6)",
                    complete.pti,
                    assoc.pti
                );
                return UePolicyResultOutcome::PtiMismatch {
                    expected: assoc.pti,
                    got: complete.pti,
                };
            }
            ue_policy_mark_delivered(pol_asso_id, assoc.upsc);
            log::info!(
                "[{pol_asso_id}] UE policy Delivered (MANAGE UE POLICY COMPLETE, PTI={:#04x}, \
                 UPSC={} installed)",
                assoc.pti,
                assoc.upsc
            );
            UePolicyResultOutcome::Delivered(assoc.upsc)
        }
        nas_updp::UPDP_MSG_MANAGE_UE_POLICY_COMMAND_REJECT => {
            let Ok(reject) = nas_updp::ManageUePolicyCommandReject::decode(container) else {
                return UePolicyResultOutcome::Undecodable;
            };
            if reject.pti != assoc.pti {
                log::warn!(
                    "[{pol_asso_id}] UE policy: MANAGE UE POLICY COMMAND REJECT PTI {:#04x} != \
                     association PTI {:#04x}; dropping stale REJECT (TS 24.501 D.2.1.6)",
                    reject.pti,
                    assoc.pti
                );
                return UePolicyResultOutcome::PtiMismatch {
                    expected: assoc.pti,
                    got: reject.pti,
                };
            }
            let cause = summarize_reject_result(&reject.result);
            log::warn!(
                "[{pol_asso_id}] UE policy REJECTED (PTI={:#04x}): {cause}",
                reject.pti
            );
            ue_policy_update_delivery_state(
                pol_asso_id,
                DeliveryState::Failed(format!("MANAGE UE POLICY COMMAND REJECT: {cause}")),
            );
            UePolicyResultOutcome::Rejected(cause)
        }
        nas_updp::UPDP_MSG_UE_STATE_INDICATION => {
            // #91: this used to fall into the `other` arm and be logged-and-ignored, so
            // the UE's installed-UPSI list never reached the PCF and no delta was
            // possible. It is NOT a delivery result -- D.2.1.6's PTI correlation does
            // not apply -- so the PTI is recorded rather than matched, and the delivery
            // state is left alone.
            let Ok(indication) = nas_updp::UeStateIndication::decode(container) else {
                return UePolicyResultOutcome::Undecodable;
            };
            let reported = flatten_upsi_list(&indication.upsi_list);
            log::info!(
                "[{pol_asso_id}] UE policy: UE STATE INDICATION (PTI={:#04x}) reports {} \
                 installed UPSI(s): {reported:?}",
                indication.pti,
                reported.len()
            );
            ue_policy_set_reported_upsis(pol_asso_id, reported.clone());
            UePolicyResultOutcome::StateReported(reported.len())
        }
        other => {
            log::info!(
                "[{pol_asso_id}] UE policy: uplink UPDP message type {other:#04x} is not a \
                 COMPLETE/REJECT/UE STATE INDICATION; ignoring (not part of the \
                 delivery-result loop)"
            );
            UePolicyResultOutcome::Ignored(other)
        }
    }
}

/// Flatten a D.6.4 UPSI list into `(mcc, mnc, upsc)` triples.
///
/// The PLMN is carried per SUBLIST, so a UPSC on its own is ambiguous: the same code
/// means different content in different PLMNs (Table D.6.2.1). Keeping the PLMN with
/// each UPSC is what lets the delta be computed against the serving PLMN only.
pub fn flatten_upsi_list(list: &nas_updp::UpsiList) -> Vec<(String, String, u16)> {
    let mut out = Vec::new();
    for sublist in &list.sublists {
        let (mcc, mnc) = plmn_id_to_strings(&sublist.plmn_id);
        for upsc in &sublist.upscs {
            out.push((mcc.clone(), mnc.clone(), *upsc));
        }
    }
    out
}

/// Render a NAS [`PlmnId`](nextgcore_nas::common::types::PlmnId) back to decimal
/// MCC/MNC strings, so a reported UPSI can be compared with the association's
/// configured `plmn` pair.
fn plmn_id_to_strings(plmn: &nextgcore_nas::common::types::PlmnId) -> (String, String) {
    let digits = |ds: &[u8]| -> String {
        ds.iter()
            .filter(|d| **d <= 9)
            .map(|d| char::from(b'0' + d))
            .collect()
    };
    // MNC length comes from `mnc_len`, not from spotting the 0x0F filler: the BCD
    // decoder normalises the filler nibble to 0, so a 2-digit MNC "01" arrives as
    // `[0, 1, 0]` and filtering on the value alone would render it "010".
    let mnc_len = usize::from(plmn.mnc_len).clamp(2, 3);
    (digits(&plmn.mcc), digits(&plmn.mnc[..mnc_len.min(3)]))
}

/// Point an association's notifications at a new URI (#91, TS 29.525 §5.6.2.4).
pub fn ue_policy_set_notification_uri(pol_asso_id: &str, uri: &str) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.notification_uri = uri.to_string();
        }
    }
}

/// Record the request triggers the consumer says it observes (#91).
pub fn ue_policy_set_triggers(pol_asso_id: &str, triggers: Vec<String>) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.triggers = triggers;
        }
    }
}

/// Record which section UPSCs a delivery actually carried (#91). No-op once the
/// association is gone.
pub fn ue_policy_set_delivered_upscs(pol_asso_id: &str, upscs: Vec<u16>) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.delivered_upscs = upscs;
        }
    }
}

/// Record the UPSIs a UE reported as installed. No-op once the association is gone,
/// like every other setter here.
pub fn ue_policy_set_reported_upsis(pol_asso_id: &str, upsis: Vec<(String, String, u16)>) {
    if let Ok(mut m) = ue_policy_store().lock() {
        if let Some(a) = m.get_mut(pol_asso_id) {
            a.reported_upsis = upsis;
        }
    }
}

/// The UPSCs the UE reported installed FOR THIS PLMN, which is the set a delta must
/// skip. UPSCs reported for another PLMN are deliberately not counted: they name
/// different content.
pub fn installed_upscs_for_plmn(pol_asso_id: &str, mcc: &str, mnc: &str) -> Vec<u16> {
    let Ok(m) = ue_policy_store().lock() else {
        return Vec::new();
    };
    let Some(a) = m.get(pol_asso_id) else {
        return Vec::new();
    };
    a.reported_upsis
        .iter()
        .filter(|(rm, rn, _)| rm == mcc && rn == mnc)
        .map(|(_, _, upsc)| *upsc)
        .collect()
}

/// Decode a base64 `uePolReq` from a PolicyAssociation(Update)Request and, when it is
/// a UE STATE INDICATION, record the reported UPSIs on the association (#91).
///
/// Returns how many UPSIs were recorded. A `uePolReq` that is not base64, or not a UPDP
/// message, or a UPDP message of some other type, records nothing and says why -- the
/// association create must not fail on it, since TS 29.525 makes the member optional
/// and a malformed one is the consumer's mistake, not a reason to refuse policy.
pub fn ingest_ue_policy_request(pol_asso_id: &str, ue_pol_req_b64: &str) -> usize {
    use base64::Engine as _;
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(ue_pol_req_b64) else {
        log::warn!("[{pol_asso_id}] uePolReq is not valid base64; ignoring");
        return 0;
    };
    match nas_updp::peek_message_type(&bytes) {
        Ok(nas_updp::UPDP_MSG_UE_STATE_INDICATION) => {}
        Ok(other) => {
            log::warn!(
                "[{pol_asso_id}] uePolReq carries UPDP message type {other:#04x}, not a UE \
                 STATE INDICATION; no UPSI list to record"
            );
            return 0;
        }
        Err(e) => {
            log::warn!("[{pol_asso_id}] uePolReq is not a decodable UPDP message ({e}); ignoring");
            return 0;
        }
    }
    let Ok(indication) = nas_updp::UeStateIndication::decode(&bytes) else {
        log::warn!("[{pol_asso_id}] uePolReq UE STATE INDICATION did not decode; ignoring");
        return 0;
    };
    let reported = flatten_upsi_list(&indication.upsi_list);
    log::info!(
        "[{pol_asso_id}] uePolReq: UE reports {} installed UPSI(s) {reported:?}; the next \
         delivery will be a delta",
        reported.len()
    );
    let n = reported.len();
    ue_policy_set_reported_upsis(pol_asso_id, reported);
    n
}

/// Summarize a decoded D.6.3 UE policy section management result into a
/// grep-able, human-readable per-instruction failure string for logs/tests.
fn summarize_reject_result(result: &nas_updp::UePolicySectionManagementResult) -> String {
    let mut parts = Vec::new();
    for sub in &result.subresults {
        for r in &sub.results {
            parts.push(format!(
                "UPSC={:#06x} instr#{} cause={:#04x}",
                r.upsc, r.failed_instruction_order, r.cause
            ));
        }
    }
    if parts.is_empty() {
        "no per-instruction results".to_string()
    } else {
        parts.join("; ")
    }
}

/// The default URSP rule set delivered when no operator provisioning is
/// present (item E3 upgrades the source to UDR). A SINGLE catch-all rule that
/// maps byte-exactly to TS 24.526 golden vector (a) — i.e. it produces the
/// complete MANAGE UE POLICY COMMAND golden vector (f) when built with
/// PTI 0x80 / UPSC 1 / PLMN 001-01. Preferred-access is intentionally omitted
/// (vector (a) has none); `PCF_URSP_RULES` (JSON) overrides this whole set.
pub fn default_wire_rules() -> Vec<UrspRule> {
    if let Ok(json) = std::env::var("PCF_URSP_RULES") {
        match parse_ursp_rules_json(&json) {
            Ok(rules) if !rules.is_empty() => return rules,
            Ok(_) => log::warn!(
                "PCF_URSP_RULES parsed to an empty rule set; using the built-in catch-all default"
            ),
            Err(e) => log::warn!(
                "PCF_URSP_RULES is not valid URSP-rule JSON ({e}); using the built-in \
                 catch-all default"
            ),
        }
    }
    vec![UrspRule {
        precedence: 255,
        traffic_descriptors: vec![TrafficDescriptor::new(vec![])], // empty TD => match-all
        route_selection_descriptors: vec![RouteSelectionDescriptor {
            precedence: 255,
            dnn: Some("internet".into()),
            snssai: Some((1, None)),
            pdu_type: RouteSelectionPduType::Ipv4v6,
            ssc_mode: 1,
            access_type: None, // vector (a) has no preferred-access component
        }],
    }]
}

// --- Wave-6 E3: UDR ue-policy-set as the URSP rule source -------------------

/// Operator provisioning convention for URSP rules inside the TS 29.519
/// UePolicySet document (`GET /nudr-dr/v2/policy-data/ues/{supi}/ue-policy-set`).
///
/// TS 29.519 §5.4 models the standardized UE policy section contents
/// (`subscPolicySections`/`uePolicySections`) as OPAQUE octet strings — hand
/// provisioning binary URSP is impractical and error-prone. This deployment
/// therefore carries a structured, self-describing extension member,
/// **`urspRules`**, alongside the 3GPP fields: a JSON array of rule objects in
/// exactly the [`parse_ursp_rules_json`] shape. pcfd compiles it to the
/// TS 24.501 Annex D / TS 24.526 wire bytes via the E2 codec, so the WIRE
/// artifact stays fully spec-conformant while provisioning stays operator
/// friendly. `urspRules` is a provisioning-side convention only — it never
/// appears on any 3GPP interface.
const URSP_RULES_PROVISIONING_KEY: &str = "urspRules";

/// Map a provisioned TS 29.519 UePolicySet document to pcfd URSP rules by
/// reading the [`URSP_RULES_PROVISIONING_KEY`] extension array. Returns:
/// - `Ok(Some(rules))` when the doc carries a valid, non-empty `urspRules`;
/// - `Ok(None)` when the doc has no `urspRules` (caller falls back to static);
/// - `Err(msg)` when `urspRules` is present but malformed / unrepresentable /
///   has duplicate precedences — fail-closed against a half-parsed set (the
///   caller then WARNs with `msg` naming the offending component and falls back
///   to the static default rather than delivering a partial policy).
pub fn map_ue_policy_set_to_rules(
    doc: &serde_json::Value,
) -> Result<Option<Vec<UrspRule>>, String> {
    let Some(rules_json) = doc.get(URSP_RULES_PROVISIONING_KEY) else {
        return Ok(None);
    };
    let rules = parse_ursp_rules_value(rules_json)
        .map_err(|e| format!("UePolicySet.{URSP_RULES_PROVISIONING_KEY}: {e}"))?;
    if rules.is_empty() {
        return Ok(None);
    }
    Ok(Some(rules))
}

/// Resolve the URSP rule set to deliver for an association (E3). Prefers the
/// operator-provisioned rules from the UDR UePolicySet (`doc`) when present and
/// valid; otherwise falls back to the static default set ([`default_wire_rules`]):
/// - `doc == None` (no UDR / 404 / unreachable) → static default;
/// - `doc` present without `urspRules` → static default;
/// - `doc` present with valid `urspRules` → the provisioned rules;
/// - `doc` present with MALFORMED `urspRules` → static default, and a WARN that
///   names the offending component (grep-able; fail-closed — never delivers a
///   half-parsed provisioned set).
pub fn resolve_ursp_rules(doc: Option<&serde_json::Value>) -> Vec<UrspRule> {
    match doc.map(map_ue_policy_set_to_rules) {
        Some(Ok(Some(rules))) => {
            log::info!(
                "UE policy: using {} operator-provisioned URSP rule(s) from UDR ue-policy-set",
                rules.len()
            );
            rules
        }
        Some(Err(e)) => {
            log::warn!(
                "UE policy: provisioned URSP rules rejected ({e}); falling back to static default"
            );
            default_wire_rules()
        }
        // No doc, or a doc without the urspRules extension: static default.
        Some(Ok(None)) | None => default_wire_rules(),
    }
}

/// Map one pcfd [`UrspRule`] to the nextgcore-nas UPDP codec model
/// ([`nas_updp::UrspRule`]). Fail-closed (returns `Err`, never drops a
/// component): a URSP rule has exactly one traffic descriptor per TS 24.526
/// Figure 5.2.2, and RSD components are emitted in the canonical order
/// SSC mode / S-NSSAI / DNN / PDU-session-type / preferred-access.
pub fn map_pcfd_rule_to_wire(rule: &UrspRule) -> Result<nas_updp::UrspRule, String> {
    // TS 24.526 Figure 5.2.2: one URSP rule carries exactly ONE traffic
    // descriptor (a set of components). pcfd's model allows several; only a
    // single descriptor is representable on the wire.
    let td = match rule.traffic_descriptors.as_slice() {
        [only] => only,
        [] => return Err("URSP rule has no traffic descriptor (TS 24.526 Figure 5.2.2)".into()),
        many => {
            return Err(format!(
                "URSP rule has {} traffic descriptors; TS 24.526 Figure 5.2.2 allows exactly one",
                many.len()
            ))
        }
    };

    let traffic_descriptor = if td.components.is_empty() {
        // Empty component set == "match all" (TS 24.526 Table 5.2.1 match-all).
        vec![nas_updp::TrafficDescriptorComponent::MatchAll]
    } else {
        let mut out = Vec::with_capacity(td.components.len());
        for c in &td.components {
            out.push(map_td_component(c)?);
        }
        out
    };

    let mut route_selection_descriptors =
        Vec::with_capacity(rule.route_selection_descriptors.len());
    for rsd in &rule.route_selection_descriptors {
        route_selection_descriptors.push(map_rsd(rsd)?);
    }

    Ok(nas_updp::UrspRule {
        precedence: rule.precedence,
        traffic_descriptor,
        route_selection_descriptors,
        ureri: None,
    })
}

fn map_td_component(
    c: &TrafficDescriptorComponent,
) -> Result<nas_updp::TrafficDescriptorComponent, String> {
    use nas_updp::TrafficDescriptorComponent as N;
    Ok(match c {
        // Match-all is represented by an empty component set (handled above);
        // an explicit match-all component here would still be valid.
        TrafficDescriptorComponent::Dnn(d) => N::Dnn(d.clone()),
        TrafficDescriptorComponent::DomainName(fqdn) => N::DestinationFqdn(fqdn.clone()),
        // #91: the structured components. Each maps 1:1 onto a Table 5.2.1 type,
        // which is exactly why they were added to the pcfd model -- the pre-#91
        // `AppId(String)` and `IpDesc { dest_ip_prefix: String, .. }` could not, and
        // fail-closing on them was correct rather than lazy.
        TrafficDescriptorComponent::OsIdOsAppId { os_id, app_id } => N::OsIdOsAppId {
            os_id: *os_id,
            os_app_id: app_id.as_bytes().to_vec(),
        },
        TrafficDescriptorComponent::Ipv4RemoteAddress { addr, mask } => N::Ipv4RemoteAddress {
            addr: *addr,
            mask: *mask,
        },
        TrafficDescriptorComponent::Ipv6RemoteAddress { addr, prefix_len } => {
            N::Ipv6RemoteAddress {
                addr: *addr,
                prefix_len: *prefix_len,
            }
        }
        TrafficDescriptorComponent::ProtocolIdentifier(p) => N::ProtocolIdentifier(*p),
        TrafficDescriptorComponent::SingleRemotePort(p) => N::SingleRemotePort(*p),
        TrafficDescriptorComponent::RemotePortRange { low, high } => {
            if low > high {
                return Err(format!(
                    "remote port range {low}-{high} is inverted; Table 5.2.1 transmits the LOW \
                     limit first, so an inverted range matches nothing"
                ));
            }
            N::RemotePortRange {
                low: *low,
                high: *high,
            }
        }
        // Still unrepresentable, fail-closed rather than silently dropped:
        //
        // - `AppId` is an opaque operator string where Table 5.2.1 needs a 16-octet
        //   UUID + length-prefixed app id (use `OsIdOsAppId`);
        // - `IpDesc` is a CIDR string where the table needs an explicit address+mask
        //   (use `Ipv4RemoteAddress`/`Ipv6RemoteAddress` + `ProtocolIdentifier` +
        //   `SingleRemotePort`/`RemotePortRange`, which is what an IP 3-tuple
        //   decomposes into);
        // - `SNssai` has NO traffic-descriptor component identifier at all.
        //   #91's criterion 6 asks for one, but TS 24.526 V18.5.0 Table 5.2.1 lists
        //   none and says "all other values are spare"
        //   (`specs/24526-i50.txt:2467-2498`). S-NSSAI is a ROUTE SELECTION
        //   descriptor component, which `map_rsd` already emits. That part of the
        //   criterion is void, not unimplemented;
        // - `NonIp`/`Ethernet` likewise have no component identifier.
        other => {
            return Err(format!(
                "traffic descriptor component {other:?} is not representable on the wire \
                 (TS 24.526 Table 5.2.1); refusing to emit"
            ))
        }
    })
}

fn map_rsd(rsd: &RouteSelectionDescriptor) -> Result<nas_updp::RouteSelectionDescriptor, String> {
    use nas_updp::RouteSelectionDescriptorComponent as C;
    let ssc = match rsd.ssc_mode {
        1 => nextgcore_nas::fiveg::ie::SscMode::SscMode1,
        2 => nextgcore_nas::fiveg::ie::SscMode::SscMode2,
        3 => nextgcore_nas::fiveg::ie::SscMode::SscMode3,
        other => return Err(format!("invalid SSC mode {other} (TS 24.501 §9.11.4.16)")),
    };
    // Canonical component order (matches the TS 24.526 golden vectors):
    // SSC mode, S-NSSAI, DNN, PDU session type, preferred access type.
    let mut components = vec![C::SscMode(ssc)];
    if let Some((sst, sd)) = rsd.snssai {
        let sd = sd.map(|v| [(v >> 16) as u8, (v >> 8) as u8, v as u8]);
        components.push(C::SNssai { sst, sd });
    }
    if let Some(dnn) = &rsd.dnn {
        components.push(C::Dnn(dnn.clone()));
    }
    let pdu = match rsd.pdu_type {
        RouteSelectionPduType::Ipv4 => nextgcore_nas::fiveg::ie::PduSessionType::Ipv4,
        RouteSelectionPduType::Ipv6 => nextgcore_nas::fiveg::ie::PduSessionType::Ipv6,
        RouteSelectionPduType::Ipv4v6 => nextgcore_nas::fiveg::ie::PduSessionType::Ipv4v6,
        RouteSelectionPduType::Unstructured => {
            nextgcore_nas::fiveg::ie::PduSessionType::Unstructured
        }
        RouteSelectionPduType::Ethernet => nextgcore_nas::fiveg::ie::PduSessionType::Ethernet,
    };
    components.push(C::PduSessionType(pdu));
    if let Some(at) = rsd.access_type {
        components.push(C::PreferredAccessType(match at {
            AccessType::ThreeGpp => nas_updp::PreferredAccessType::ThreeGpp,
            AccessType::NonThreeGpp => nas_updp::PreferredAccessType::NonThreeGpp,
        }));
    }
    Ok(nas_updp::RouteSelectionDescriptor {
        precedence: rsd.precedence,
        components,
    })
}

/// Build the MANAGE UE POLICY COMMAND (TS 24.501 Table D.5.1.1.1) carried in
/// the "UE policy container" (0x05) of the DL NAS TRANSPORT: PTI + message
/// type + a UE policy section management list of ONE PLMN sublist
/// (`mcc`/`mnc`) → ONE instruction (`upsc`) → ONE URSP part built from
/// `rules`. Fail-closed: any unrepresentable rule/component or over-length
/// container returns `Err` (never Ok-with-holes).
/// The largest UE policy part CONTENTS a single section can carry.
///
/// Figure D.6.2.7's contents length is a 2-octet field, and Table D.6.2.1 NOTE 2 makes
/// it cover the part-type octet as well, so the URSP bytes themselves get one less than
/// `u16::MAX`. This is the bound the encoder fails closed on, and therefore the bound
/// [`build_manage_ue_policy_command`] partitions against.
pub const MAX_UE_POLICY_PART_CONTENTS: usize = u16::MAX as usize - 1;

/// Build a MANAGE UE POLICY COMMAND, partitioning the rules across as many UE policy
/// sections as they need (#91, TS 23.502 §4.2.4.3 / TS 24.501 Annex D).
///
/// Returns the PDU and the UPSCs of the sections it contains, first section first.
///
/// This used to build exactly ONE section with ONE part and `Err` when the result was
/// over-length -- so a policy larger than one section was undeliverable rather than
/// split, and the UPSC was a hard-coded `1`. Sections are numbered from `first_upsc`
/// upward; each is its own instruction inside the PLMN sublist, which is how D.6.2.4
/// expresses more than one section for one PLMN.
pub fn build_manage_ue_policy_command_sections(
    pti: u8,
    first_upsc: u16,
    mcc: &str,
    mnc: &str,
    rules: &[UrspRule],
    max_part_contents: usize,
) -> Result<(Vec<u8>, Vec<u16>), String> {
    build_manage_ue_policy_delta(pti, first_upsc, mcc, mnc, rules, max_part_contents, &[])?
        .ok_or_else(|| "no sections to deliver".to_string())
}

/// The same partitioning, minus the sections the UE already reports installed (#91,
/// TS 24.501 §5.5.1.2.2 / TS 29.525 §4.2.2.2.1).
///
/// `installed_upscs` comes from the UE's UPSI list in a UE STATE INDICATION. A section
/// whose UPSC the UE already holds is OMITTED: that is the delta the PSI list exists to
/// make possible, and re-pushing an installed section is the behaviour #91 describes as
/// the PCF "only ever pushing a full, statically-built policy".
///
/// `Ok(None)` means every section is already installed, so there is nothing to send at
/// all. Distinguished from `Ok(Some(..))` rather than returned as an empty PDU, because
/// a MANAGE UE POLICY COMMAND whose sublist has no instructions is not a conformant
/// message (D.6.2.3 requires at least one) and would also start a T3501 the UE has no
/// reason to answer.
pub fn build_manage_ue_policy_delta(
    pti: u8,
    first_upsc: u16,
    mcc: &str,
    mnc: &str,
    rules: &[UrspRule],
    max_part_contents: usize,
    installed_upscs: &[u16],
) -> Result<Option<(Vec<u8>, Vec<u16>)>, String> {
    if rules.is_empty() {
        return Err("no URSP rules to deliver".into());
    }
    let mut wire_rules = Vec::with_capacity(rules.len());
    for r in rules {
        wire_rules.push(map_pcfd_rule_to_wire(r)?);
    }

    // Partition on ENCODED size, one rule at a time, because a rule's encoded length
    // depends on its components and cannot be predicted from the count. Encoding each
    // candidate group is the only way to know it fits.
    let mut groups: Vec<Vec<nas_updp::UrspRule>> = Vec::new();
    let mut current: Vec<nas_updp::UrspRule> = Vec::new();
    for rule in wire_rules {
        let mut candidate = current.clone();
        candidate.push(rule.clone());
        let size = nas_updp::encode_ursp_rules(&candidate)
            .map_err(|e| e.to_string())?
            .len();
        if size <= max_part_contents {
            current = candidate;
            continue;
        }
        // The candidate is too big. If the group already holds something, close it and
        // start a new one with this rule. If it does not, this SINGLE rule exceeds a
        // whole section on its own -- there is nothing left to split, so it is a real
        // error rather than an infinite loop.
        if current.is_empty() {
            return Err(format!(
                "a single URSP rule encodes to {size} octets, which exceeds the \
                 {max_part_contents}-octet UE policy part limit (TS 24.501 Figure D.6.2.7); \
                 it cannot be split across sections"
            ));
        }
        groups.push(std::mem::take(&mut current));
        current = vec![rule];
    }
    if !current.is_empty() {
        groups.push(current);
    }

    let plmn_id = parse_plmn(mcc, mnc)?;
    let mut instructions = Vec::with_capacity(groups.len());
    let mut upscs = Vec::with_capacity(groups.len());
    for (i, group) in groups.iter().enumerate() {
        // A distinct UPSC per section, which is what makes them separately
        // installable, separately confirmable and separately deletable (D.2.1.3).
        //
        // Numbered from `first_upsc` over ALL sections, including skipped ones, so a
        // section's code does not shift when a neighbour is already installed -- a
        // shifting code would make the UE's reported UPSI list refer to different
        // content on the next delivery, which is worse than re-pushing.
        let upsc = first_upsc
            .checked_add(u16::try_from(i).map_err(|_| "too many UE policy sections")?)
            .ok_or("UE policy section codes would wrap past 65535")?;
        if installed_upscs.contains(&upsc) {
            log::info!(
                "UE policy: section UPSC={upsc} is already installed at the UE; omitted from \
                 the delta"
            );
            continue;
        }
        let part = nas_updp::UePolicyPart::ursp(group).map_err(|e| e.to_string())?;
        instructions.push(nas_updp::Instruction {
            upsc,
            parts: vec![part],
        });
        upscs.push(upsc);
    }

    if instructions.is_empty() {
        return Ok(None);
    }

    let list = nas_updp::UePolicySectionManagementList {
        sublists: vec![nas_updp::PlmnSublist {
            plmn_id,
            instructions,
        }],
    };
    let pdu = nas_updp::ManageUePolicyCommand { pti, list }
        .encode()
        .map_err(|e| e.to_string())?;
    Ok(Some((pdu, upscs)))
}

/// [`build_manage_ue_policy_command_sections`] against the spec's own section bound,
/// keeping the single-PDU signature the delivery path and the golden vectors use.
pub fn build_manage_ue_policy_command(
    pti: u8,
    upsc: u16,
    mcc: &str,
    mnc: &str,
    rules: &[UrspRule],
) -> Result<Vec<u8>, String> {
    build_manage_ue_policy_command_sections(pti, upsc, mcc, mnc, rules, MAX_UE_POLICY_PART_CONTENTS)
        .map(|(pdu, _)| pdu)
}

/// Parse an MCC/MNC decimal string pair into a NAS [`PlmnId`] (MCC is always 3
/// digits; MNC is 2 or 3 digits, TS 23.003 §2.2).
fn parse_plmn(mcc: &str, mnc: &str) -> Result<nextgcore_nas::common::types::PlmnId, String> {
    fn digits<const N: usize>(s: &str, label: &str) -> Result<[u8; N], String> {
        let ds: Vec<u8> = s
            .chars()
            .map(|c| c.to_digit(10).map(|d| d as u8))
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(|| format!("{label} '{s}' is not decimal"))?;
        let mut out = [0u8; N];
        if ds.len() > N {
            return Err(format!("{label} '{s}' has more than {N} digits"));
        }
        out[..ds.len()].copy_from_slice(&ds);
        Ok(out)
    }
    if mcc.len() != 3 {
        return Err(format!("MCC '{mcc}' must be 3 digits"));
    }
    if mnc.len() != 2 && mnc.len() != 3 {
        return Err(format!("MNC '{mnc}' must be 2 or 3 digits"));
    }
    let mcc_arr = digits::<3>(mcc, "MCC")?;
    let mnc_arr = digits::<3>(mnc, "MNC")?;
    Ok(nextgcore_nas::common::types::PlmnId::new(
        mcc_arr,
        mnc_arr,
        mnc.len() as u8,
    ))
}

/// Documented `PCF_URSP_RULES` provisioning JSON (item E4 static-config
/// fallback; item E3 upgrades the source to UDR). A JSON array of rule
/// objects:
/// ```json
/// [{
///   "precedence": 255,
///   "trafficDescriptor": { "matchAll": true },        // or {"dnn":"ims"} / {"fqdn":"example.com"}
///   "routeSelectionDescriptors": [{
///     "precedence": 255, "sscMode": 1, "snssai": {"sst": 1},
///     "dnn": "internet", "pduSessionType": "ipv4v6", "preferredAccess": "3gpp"
///   }]
/// }]
/// ```
/// Maps to the pcfd [`UrspRule`] model (then to wire via
/// [`map_pcfd_rule_to_wire`]). Strict: unknown fields/values are errors so a
/// half-parsed rule set never reaches the wire.
pub fn parse_ursp_rules_json(json: &str) -> Result<Vec<UrspRule>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    parse_ursp_rules_value(&v)
}

/// Parse a JSON *array* of URSP rule objects (already deserialized) into the
/// pcfd model. Shared by the `PCF_URSP_RULES` static config
/// ([`parse_ursp_rules_json`]) and the UDR `urspRules` provisioning extension
/// ([`map_ue_policy_set_to_rules`]). Strict throughout: an unknown field/value
/// is an `Err` (never a half-parsed rule set), and the assembled set is
/// validated for precedence uniqueness (TS 23.503 §6.6.2.1).
pub fn parse_ursp_rules_value(v: &serde_json::Value) -> Result<Vec<UrspRule>, String> {
    let arr = v
        .as_array()
        .ok_or("URSP rules must be a JSON array of rule objects")?;
    let mut rules = Vec::with_capacity(arr.len());
    for (i, r) in arr.iter().enumerate() {
        rules.push(parse_one_rule(r).map_err(|e| format!("rule[{i}]: {e}"))?);
    }
    validate_rule_precedences(&rules)?;
    Ok(rules)
}

/// Reject a URSP rule set with duplicate rule precedences. TS 23.503 §6.6.2.1
/// requires each URSP rule to have a distinct precedence value so the UE can
/// order them unambiguously; a duplicate is a fail-closed error (never a
/// silently ambiguous set on the wire).
fn validate_rule_precedences(rules: &[UrspRule]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(rules.len());
    for r in rules {
        if !seen.insert(r.precedence) {
            return Err(format!(
                "duplicate URSP rule precedence {} (TS 23.503 §6.6.2.1 requires unique \
                 rule precedences)",
                r.precedence
            ));
        }
    }
    Ok(())
}

fn parse_one_rule(v: &serde_json::Value) -> Result<UrspRule, String> {
    let precedence = v
        .get("precedence")
        .and_then(|p| p.as_u64())
        .and_then(|p| u8::try_from(p).ok())
        .ok_or("missing/invalid u8 'precedence'")?;
    let td = v
        .get("trafficDescriptor")
        .ok_or("missing 'trafficDescriptor'")?;
    let td = parse_td(td)?;
    let rsds_json = v
        .get("routeSelectionDescriptors")
        .and_then(|r| r.as_array())
        .ok_or("missing 'routeSelectionDescriptors' array")?;
    if rsds_json.is_empty() {
        return Err(
            "'routeSelectionDescriptors' must be non-empty (TS 24.526 Figure 5.2.3)".into(),
        );
    }
    let mut route_selection_descriptors = Vec::with_capacity(rsds_json.len());
    for rsd in rsds_json {
        route_selection_descriptors.push(parse_rsd(rsd)?);
    }
    Ok(UrspRule {
        precedence,
        traffic_descriptors: vec![td],
        route_selection_descriptors,
    })
}

/// Parse a provisioned traffic descriptor into the pcfd model.
///
/// #91: this used to accept `matchAll`/`dnn`/`fqdn` only, and to RETURN ON THE FIRST
/// MATCH -- so a descriptor naming two components silently became one. TS 24.526 §5.2
/// gives the components of one traffic descriptor AND semantics, so every recognised
/// key now contributes and the descriptor carries all of them.
///
/// `matchAll` is exclusive by rule, not by convenience: Table 5.2.1 says "if the
/// match-all type traffic descriptor component is included in a traffic descriptor,
/// there shall be no traffic descriptor component with a type other than match-all".
/// A descriptor combining them is rejected rather than silently narrowed.
fn parse_td(v: &serde_json::Value) -> Result<TrafficDescriptor, String> {
    let match_all = v.get("matchAll").and_then(|m| m.as_bool()) == Some(true);
    let mut components = Vec::new();

    if let Some(dnn) = v.get("dnn").and_then(|d| d.as_str()) {
        components.push(TrafficDescriptorComponent::Dnn(dnn.to_string()));
    }
    if let Some(fqdn) = v.get("fqdn").and_then(|d| d.as_str()) {
        components.push(TrafficDescriptorComponent::DomainName(fqdn.to_string()));
    }
    if let Some(os) = v.get("osAppId") {
        let os_id_str = os
            .get("osId")
            .and_then(|s| s.as_str())
            .ok_or("osAppId.osId is required and must be a UUID string")?;
        let app_id = os
            .get("appId")
            .and_then(|s| s.as_str())
            .ok_or("osAppId.appId is required and must be a string")?;
        components.push(TrafficDescriptorComponent::OsIdOsAppId {
            os_id: parse_uuid_bytes(os_id_str)?,
            app_id: app_id.to_string(),
        });
    }
    if let Some(ip) = v.get("ipv4RemoteAddress") {
        let addr = ip
            .get("addr")
            .and_then(|s| s.as_str())
            .ok_or("ipv4RemoteAddress.addr is required")?;
        // The MASK is required, not defaulted to /32: Table 5.2.1 transmits address
        // then mask, and guessing a mask changes which traffic the rule matches.
        let mask = ip
            .get("mask")
            .and_then(|s| s.as_str())
            .ok_or("ipv4RemoteAddress.mask is required (Table 5.2.1 encodes address + mask)")?;
        components.push(TrafficDescriptorComponent::Ipv4RemoteAddress {
            addr: parse_ipv4_octets(addr)?,
            mask: parse_ipv4_octets(mask)?,
        });
    }
    if let Some(ip) = v.get("ipv6RemoteAddress") {
        let addr = ip
            .get("addr")
            .and_then(|s| s.as_str())
            .ok_or("ipv6RemoteAddress.addr is required")?;
        let prefix_len = ip
            .get("prefixLength")
            .and_then(|p| p.as_u64())
            .ok_or("ipv6RemoteAddress.prefixLength is required")?;
        if prefix_len > 128 {
            return Err(format!(
                "ipv6RemoteAddress.prefixLength {prefix_len} exceeds 128"
            ));
        }
        components.push(TrafficDescriptorComponent::Ipv6RemoteAddress {
            addr: parse_ipv6_octets(addr)?,
            prefix_len: prefix_len as u8,
        });
    }
    if let Some(p) = v.get("protocol") {
        let p = p.as_u64().ok_or("protocol must be a number")?;
        let p = u8::try_from(p).map_err(|_| format!("protocol {p} exceeds one octet"))?;
        components.push(TrafficDescriptorComponent::ProtocolIdentifier(p));
    }
    if let Some(p) = v.get("remotePort") {
        let p = p.as_u64().ok_or("remotePort must be a number")?;
        let p = u16::try_from(p).map_err(|_| format!("remotePort {p} exceeds two octets"))?;
        components.push(TrafficDescriptorComponent::SingleRemotePort(p));
    }
    if let Some(r) = v.get("remotePortRange") {
        let low = r
            .get("low")
            .and_then(|p| p.as_u64())
            .ok_or("remotePortRange.low is required")?;
        let high = r
            .get("high")
            .and_then(|p| p.as_u64())
            .ok_or("remotePortRange.high is required")?;
        let low = u16::try_from(low).map_err(|_| format!("remotePortRange.low {low} too large"))?;
        let high =
            u16::try_from(high).map_err(|_| format!("remotePortRange.high {high} too large"))?;
        if low > high {
            return Err(format!(
                "remotePortRange {low}-{high} is inverted (Table 5.2.1 sends the low limit first)"
            ));
        }
        components.push(TrafficDescriptorComponent::RemotePortRange { low, high });
    }

    if match_all {
        if !components.is_empty() {
            return Err(
                "trafficDescriptor combines matchAll with other components; Table 5.2.1 \
                 forbids it"
                    .into(),
            );
        }
        // An EMPTY component set is how this module represents match-all, which
        // `map_pcfd_rule_to_wire` turns into the explicit match-all component.
        return Ok(TrafficDescriptor::new(vec![]));
    }
    if components.is_empty() {
        return Err(
            "unknown trafficDescriptor (expected matchAll, or one or more of dnn / fqdn / \
             osAppId / ipv4RemoteAddress / ipv6RemoteAddress / protocol / remotePort / \
             remotePortRange)"
                .into(),
        );
    }
    Ok(TrafficDescriptor::new(components))
}

/// Parse an RFC 4122 UUID string into its 16 octets.
///
/// Hyphens are optional so both `PCF_URSP_RULES` hand-authoring styles work; anything
/// that is not 32 hex digits is an error rather than a zero-padded guess, since a
/// wrong OS Id matches a different application.
fn parse_uuid_bytes(s: &str) -> Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!(
            "osId '{s}' is not a 16-octet UUID (expected 32 hex digits, got {})",
            hex.len()
        ));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("osId '{s}' is not hexadecimal"))?;
    }
    Ok(out)
}

/// Parse a dotted-quad into four octets. Used for both address and mask, since
/// Table 5.2.1 encodes the mask as a full four-octet field rather than a prefix length.
fn parse_ipv4_octets(s: &str) -> Result<[u8; 4], String> {
    s.parse::<std::net::Ipv4Addr>()
        .map(|a| a.octets())
        .map_err(|_| format!("'{s}' is not a dotted-quad IPv4 address"))
}

/// Parse an IPv6 literal into sixteen octets.
fn parse_ipv6_octets(s: &str) -> Result<[u8; 16], String> {
    s.parse::<std::net::Ipv6Addr>()
        .map(|a| a.octets())
        .map_err(|_| format!("'{s}' is not an IPv6 address"))
}

fn parse_rsd(v: &serde_json::Value) -> Result<RouteSelectionDescriptor, String> {
    let precedence = v
        .get("precedence")
        .and_then(|p| p.as_u64())
        .and_then(|p| u8::try_from(p).ok())
        .ok_or("RSD missing/invalid u8 'precedence'")?;
    let ssc_mode = v
        .get("sscMode")
        .and_then(|s| s.as_u64())
        .and_then(|s| u8::try_from(s).ok())
        .unwrap_or(1);
    let snssai = match v.get("snssai") {
        None => None,
        Some(s) => {
            let sst = s
                .get("sst")
                .and_then(|x| x.as_u64())
                .and_then(|x| u8::try_from(x).ok())
                .ok_or("snssai missing/invalid u8 'sst'")?;
            let sd = match s.get("sd") {
                None => None,
                Some(sd) => Some(
                    sd.as_u64()
                        .and_then(|x| u32::try_from(x).ok())
                        .ok_or("snssai 'sd' must be a u32")?,
                ),
            };
            Some((sst, sd))
        }
    };
    let dnn = v.get("dnn").and_then(|d| d.as_str()).map(str::to_string);
    let pdu_type = match v.get("pduSessionType").and_then(|p| p.as_str()) {
        None | Some("ipv4v6") => RouteSelectionPduType::Ipv4v6,
        Some("ipv4") => RouteSelectionPduType::Ipv4,
        Some("ipv6") => RouteSelectionPduType::Ipv6,
        Some("unstructured") => RouteSelectionPduType::Unstructured,
        Some("ethernet") => RouteSelectionPduType::Ethernet,
        Some(other) => return Err(format!("unknown pduSessionType '{other}'")),
    };
    let access_type = match v.get("preferredAccess").and_then(|a| a.as_str()) {
        None => None,
        Some("3gpp") => Some(AccessType::ThreeGpp),
        Some("non-3gpp") => Some(AccessType::NonThreeGpp),
        Some(other) => return Err(format!("unknown preferredAccess '{other}'")),
    };
    Ok(RouteSelectionDescriptor {
        precedence,
        dnn,
        snssai,
        pdu_type,
        ssc_mode,
        access_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_descriptor_for_dnn() {
        let td = TrafficDescriptor::for_dnn("internet");
        assert_eq!(
            td.components[0],
            TrafficDescriptorComponent::Dnn("internet".into())
        );
    }

    #[test]
    fn test_ursp_rule_catch_all() {
        let rule = UrspRule::catch_all();
        assert_eq!(rule.precedence, 255);
        assert_eq!(rule.traffic_descriptors.len(), 1);
    }

    #[test]
    fn test_ue_policy_provision_and_find() {
        let mut ctx = UePolicyContext::new();
        ctx.provision_ursp(
            "imsi-001011234567890".into(),
            vec![UrspRule::ims_rule(), UrspRule::catch_all()],
        );
        let rule = ctx
            .find_rule_for_dnn("imsi-001011234567890", "ims")
            .unwrap();
        assert_eq!(rule.precedence, 10);
    }

    #[test]
    fn test_find_catch_all_for_unknown_dnn() {
        let mut ctx = UePolicyContext::new();
        ctx.provision_ursp("imsi-001011234567890".into(), vec![UrspRule::catch_all()]);
        let rule = ctx
            .find_rule_for_dnn("imsi-001011234567890", "foobar")
            .unwrap();
        assert_eq!(rule.precedence, 255);
    }

    #[test]
    fn test_policy_count() {
        let mut ctx = UePolicyContext::new();
        assert_eq!(ctx.policy_count(), 0);
        ctx.provision_ursp("ue1".into(), vec![UrspRule::catch_all()]);
        ctx.provision_ursp("ue2".into(), vec![UrspRule::catch_all()]);
        assert_eq!(ctx.policy_count(), 2);
    }

    #[test]
    fn test_rules_sorted_by_precedence() {
        let mut ctx = UePolicyContext::new();
        ctx.provision_ursp(
            "ue1".into(),
            vec![
                UrspRule::catch_all(), // precedence 255
                UrspRule::ims_rule(),  // precedence 10
            ],
        );
        let rules = ctx.get_ursp("ue1");
        assert_eq!(rules[0].precedence, 10); // lowest number first
        assert_eq!(rules[1].precedence, 255);
    }

    #[test]
    fn test_rsd_default_internet() {
        let rsd = RouteSelectionDescriptor::default_internet();
        assert_eq!(rsd.dnn.as_deref(), Some("internet"));
        assert_eq!(rsd.ssc_mode, 1);
    }

    // --- Wave-6 E4 delivery-command tests -------------------------------------

    /// Wave-6 E1 golden vector (f) — complete MANAGE UE POLICY COMMAND for the
    /// default catch-all rule set, re-cited verbatim from
    /// `nextgcore-nas/tests/ue_policy_golden_vectors/data.rs`
    /// (`VEC_F_MANAGE_UE_POLICY_COMMAND`, TS 24.501 Table D.5.1.1.1 /
    /// TS 24.526 §5.2). PTI 0x80, PLMN 001-01, UPSC 0x0001, one URSP part =
    /// catch-all rule. The independent cross-check that pcfd's builder emits
    /// exactly these bytes is item E4's golden gate.
    const VEC_F_MANAGE_UE_POLICY_COMMAND: &[u8] = &[
        0x80, 0x01, // PTI 0x80, message type = MANAGE UE POLICY COMMAND
        0x00, 0x2B, // section management list contents length = 43
        0x00, 0x29, 0x00, 0xF1, 0x10, // sublist: len 41, PLMN 001/01
        0x00, 0x24, 0x00, 0x01, // instruction: contents len 36, UPSC 0x0001
        0x00, 0x20, 0x01, // part: contents len 32, type URSP (0001)
        0x00, 0x1D, 0xFF, 0x00, 0x01, 0x01, 0x00, 0x17, // URSP rule == VEC_A
        0x00, 0x15, 0xFF, 0x00, 0x12, //
        0x01, 0x01, // SSC mode 1
        0x02, 0x01, 0x01, // S-NSSAI SST=1
        0x04, 0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, // DNN internet
        0x08, 0x03, // PDU session type IPv4v6
    ];

    /// Wave-6 E3 golden vector — complete MANAGE UE POLICY COMMAND for a
    /// UDR-*provisioned* rule set (a single DNN "ims" rule; distinct from the
    /// default catch-all so the test proves the provisioned DNN/S-NSSAI is
    /// reflected on the wire). PTI 0x80, PLMN 001-01, UPSC 0x0001, one URSP part
    /// = the E1 vector (b) DNN-ims rule (`VEC_B_URSP_RULE_DNN_IMS`, 33 octets).
    ///
    /// Hand-derived from the E1 provenance (TS 24.501 Table D.5.1.1.1 framing +
    /// Table D.6.2.1 NOTE 2 length convention, TS 24.526 §5.2 rule contents),
    /// swapping VEC_A→VEC_B into the vector (f) skeleton and recomputing the
    /// four nested length fields:
    ///   part contents      = 1 (type octet) + 33 (rule) = 34 = 0x22
    ///   instruction contents = 2 (UPSC) + (2 + 34) part field = 38 = 0x26
    ///   sublist contents   = 3 (MCC/MNC) + (2 + 38) instr field = 43 = 0x2B
    ///   list contents      = (2 + 43) sublist field           = 45 = 0x2D
    const VEC_IMS_MANAGE_UE_POLICY_COMMAND: &[u8] = &[
        0x80, 0x01, // PTI 0x80, message type = MANAGE UE POLICY COMMAND
        0x00, 0x2D, // section management list contents length = 45
        0x00, 0x2B, 0x00, 0xF1, 0x10, // sublist: len 43, PLMN 001/01
        0x00, 0x26, 0x00, 0x01, // instruction: contents len 38, UPSC 0x0001
        0x00, 0x22, 0x01, // part: contents len 34, type URSP (0001)
        // URSP rule == VEC_B_URSP_RULE_DNN_IMS (E1 vector (b), 33 octets):
        0x00, 0x1F, 0x0A, 0x00, 0x06, // rule len 31, precedence 10, TD len 6
        0x88, 0x04, 0x03, 0x69, 0x6D, 0x73, // TD: DNN type, len 4, APN "ims"
        0x00, 0x14, 0x00, 0x12, 0x0A, 0x00, 0x0F, // RSD list 20, RSD 18, prec 10, contents 15
        0x01, 0x01, // SSC mode 1
        0x02, 0x01, 0x01, // S-NSSAI SST=1
        0x04, 0x04, 0x03, 0x69, 0x6D, 0x73, // DNN type, len 4, APN "ims"
        0x08, 0x03, // PDU session type IPv4v6
        0x10, 0x01, // preferred access type: 3GPP
    ];

    /// The documented `urspRules` provisioning array that maps to the DNN "ims"
    /// rule (== pcfd `UrspRule::ims_rule()`), used by the E3 tests and the
    /// strict-peer integration test (`tests/strict_peer_udr_ue_policy.rs`).
    fn provisioned_ims_ursp_rules_json() -> serde_json::Value {
        serde_json::json!([{
            "precedence": 10,
            "trafficDescriptor": { "dnn": "ims" },
            "routeSelectionDescriptors": [{
                "precedence": 10, "sscMode": 1, "snssai": {"sst": 1},
                "dnn": "ims", "pduSessionType": "ipv4v6", "preferredAccess": "3gpp"
            }]
        }])
    }

    /// E4 golden gate (falsifiable): the exact bytes pcfd hands to the N1N2
    /// multipart binary part for the default (catch-all) rule set MUST equal
    /// the E1 golden command vector (f).
    #[test]
    fn build_default_command_matches_golden_vector_f() {
        std::env::remove_var("PCF_URSP_RULES");
        let rules = default_wire_rules();
        let bytes = build_manage_ue_policy_command(0x80, 1, "001", "01", &rules)
            .expect("catch-all command encodes");
        assert_eq!(
            bytes, VEC_F_MANAGE_UE_POLICY_COMMAND,
            "default catch-all MANAGE UE POLICY COMMAND must be byte-exact E1(f)"
        );
    }

    /// The pcfd `UrspRule::ims_rule()` model — "finally serialized" via the
    /// wire mapping — maps to a valid, decodable URSP rule (DNN "ims" TD with a
    /// preferred-access RSD). Guards the pcfd-model→nas-codec mapping.
    #[test]
    fn ims_rule_maps_and_round_trips() {
        let wire = map_pcfd_rule_to_wire(&UrspRule::ims_rule()).expect("ims rule maps");
        assert_eq!(wire.precedence, 10);
        let bytes = nas_updp::encode_ursp_rules(std::slice::from_ref(&wire)).expect("encode");
        let back = nas_updp::decode_ursp_rules(&bytes).expect("decode");
        assert_eq!(back, vec![wire]);
    }

    /// Fail-closed: a traffic descriptor component with no wire representation
    /// (opaque `AppId` string) returns `Err`, never a silently-dropped rule.
    #[test]
    fn unrepresentable_td_component_is_err() {
        let rule = UrspRule {
            precedence: 5,
            traffic_descriptors: vec![TrafficDescriptor::for_app("com.example.app")],
            route_selection_descriptors: vec![RouteSelectionDescriptor::default_internet()],
        };
        assert!(map_pcfd_rule_to_wire(&rule).is_err());
        assert!(build_manage_ue_policy_command(0x80, 1, "001", "01", &[rule]).is_err());
    }

    /// A URSP rule with more than one traffic descriptor is unrepresentable
    /// (TS 24.526 Figure 5.2.2: exactly one per rule) — fail-closed.
    #[test]
    fn multiple_traffic_descriptors_is_err() {
        let rule = UrspRule {
            precedence: 5,
            traffic_descriptors: vec![
                TrafficDescriptor::for_dnn("ims"),
                TrafficDescriptor::for_dnn("internet"),
            ],
            route_selection_descriptors: vec![RouteSelectionDescriptor::default_internet()],
        };
        assert!(map_pcfd_rule_to_wire(&rule).is_err());
    }

    /// The PTI allocator stays inside the PCF-initiated range 80H-FEH
    /// (TS 24.501 D.1.2) across many allocations.
    #[test]
    fn pti_allocator_stays_in_pcf_range() {
        for _ in 0..1000 {
            let pti = alloc_pti();
            assert!(
                (0x80..=0xFE).contains(&pti),
                "PTI {pti:#04x} left the PCF range"
            );
        }
    }

    /// `PCF_URSP_RULES` JSON parses to the pcfd model; a catch-all config maps
    /// byte-exactly to vector (f) (the "catch-all config" of the golden gate).
    #[test]
    fn ursp_rules_json_catch_all_matches_golden() {
        let json = r#"[{
            "precedence": 255,
            "trafficDescriptor": { "matchAll": true },
            "routeSelectionDescriptors": [{
                "precedence": 255, "sscMode": 1, "snssai": {"sst": 1},
                "dnn": "internet", "pduSessionType": "ipv4v6"
            }]
        }]"#;
        let rules = parse_ursp_rules_json(json).expect("valid URSP JSON");
        let bytes =
            build_manage_ue_policy_command(0x80, 1, "001", "01", &rules).expect("encode config");
        assert_eq!(bytes, VEC_F_MANAGE_UE_POLICY_COMMAND);
    }

    /// Strict config parsing: an unknown component value is an error (never a
    /// half-parsed rule set reaching the wire).
    #[test]
    fn ursp_rules_json_rejects_unknown_values() {
        let json = r#"[{
            "precedence": 1,
            "trafficDescriptor": { "dnn": "ims" },
            "routeSelectionDescriptors": [{ "precedence": 1, "pduSessionType": "carrier-pigeon" }]
        }]"#;
        assert!(parse_ursp_rules_json(json).is_err());
    }

    /// The kill-switch restores association-only behaviour when disabled.
    #[test]
    fn delivery_kill_switch() {
        std::env::set_var("PCF_UE_POLICY_DELIVERY", "off");
        assert!(!delivery_enabled());
        std::env::set_var("PCF_UE_POLICY_DELIVERY", "on");
        assert!(delivery_enabled());
        std::env::remove_var("PCF_UE_POLICY_DELIVERY");
        assert!(delivery_enabled());
    }

    // --- Wave-6 E3: UDR ue-policy-set rule source ----------------------------

    /// E3 primary acceptance: a provisioned UePolicySet doc carrying our
    /// `urspRules` extension (DNN "ims" rule) compiles byte-exactly to the E3
    /// golden command vector — i.e. the delivered MANAGE UE POLICY COMMAND
    /// reflects the provisioned DNN/S-NSSAI, not the static catch-all default.
    #[test]
    fn provisioned_ue_policy_set_maps_and_matches_golden() {
        let doc = serde_json::json!({
            "subscPolicySections": {},
            "urspRules": provisioned_ims_ursp_rules_json(),
        });
        let rules = map_ue_policy_set_to_rules(&doc)
            .expect("provisioned doc maps")
            .expect("urspRules present");
        assert_eq!(rules.len(), 1);
        let bytes = build_manage_ue_policy_command(0x80, 1, "001", "01", &rules)
            .expect("provisioned command encodes");
        assert_eq!(
            bytes, VEC_IMS_MANAGE_UE_POLICY_COMMAND,
            "provisioned DNN-ims command must be byte-exact E3 golden vector"
        );
        // ...and must differ from the static catch-all default (proves the
        // provisioned source actually changed the wire artifact).
        assert_ne!(bytes, VEC_F_MANAGE_UE_POLICY_COMMAND);
    }

    /// `resolve_ursp_rules` prefers the provisioned rules when present and valid,
    /// and delivers the static default (catch-all == E1(f)) when the doc is
    /// absent.
    #[test]
    fn resolve_prefers_provisioned_else_default() {
        std::env::remove_var("PCF_URSP_RULES");
        // Provisioned → ims command.
        let doc = serde_json::json!({ "urspRules": provisioned_ims_ursp_rules_json() });
        let rules = resolve_ursp_rules(Some(&doc));
        let bytes = build_manage_ue_policy_command(0x80, 1, "001", "01", &rules).expect("encode");
        assert_eq!(bytes, VEC_IMS_MANAGE_UE_POLICY_COMMAND);

        // No doc → static default (catch-all) == E1(f).
        let default_rules = resolve_ursp_rules(None);
        let default_bytes =
            build_manage_ue_policy_command(0x80, 1, "001", "01", &default_rules).expect("encode");
        assert_eq!(default_bytes, VEC_F_MANAGE_UE_POLICY_COMMAND);
    }

    /// Fail-closed: a doc whose `urspRules` carries an unrepresentable component
    /// (unknown pduSessionType) makes `map_*` err, and `resolve_ursp_rules`
    /// falls back to the static default rather than delivering a partial policy.
    #[test]
    fn resolve_malformed_provisioning_falls_back_to_default() {
        std::env::remove_var("PCF_URSP_RULES");
        let doc = serde_json::json!({
            "urspRules": [{
                "precedence": 1,
                "trafficDescriptor": { "dnn": "ims" },
                "routeSelectionDescriptors": [{ "precedence": 1, "pduSessionType": "carrier-pigeon" }]
            }]
        });
        // map errors and names the offending component (grep-able WARN source).
        let err = map_ue_policy_set_to_rules(&doc).expect_err("malformed urspRules must err");
        assert!(
            err.contains("carrier-pigeon"),
            "error must name the component: {err}"
        );
        // resolve falls back to the static default (E1(f)).
        let rules = resolve_ursp_rules(Some(&doc));
        let bytes = build_manage_ue_policy_command(0x80, 1, "001", "01", &rules).expect("encode");
        assert_eq!(bytes, VEC_F_MANAGE_UE_POLICY_COMMAND);
    }

    /// A UePolicySet with no `urspRules` extension → `Ok(None)` (caller uses the
    /// static default); duplicate rule precedences are rejected
    /// (TS 23.503 §6.6.2.1).
    #[test]
    fn map_none_without_extension_and_rejects_duplicate_precedence() {
        // No urspRules extension.
        let bare = serde_json::json!({ "subscPolicySections": { "01": { "upsi": [] } } });
        assert!(map_ue_policy_set_to_rules(&bare).expect("maps").is_none());

        // Duplicate precedences → Err (TS 23.503 §6.6.2.1 uniqueness).
        let dup = serde_json::json!({
            "urspRules": [
                { "precedence": 5, "trafficDescriptor": {"dnn":"ims"},
                  "routeSelectionDescriptors": [{"precedence":1,"pduSessionType":"ipv4v6"}] },
                { "precedence": 5, "trafficDescriptor": {"matchAll":true},
                  "routeSelectionDescriptors": [{"precedence":1,"pduSessionType":"ipv4v6"}] }
            ]
        });
        let err = map_ue_policy_set_to_rules(&dup).expect_err("duplicate precedence must err");
        assert!(
            err.contains("precedence"),
            "error must mention precedence: {err}"
        );
    }

    /// E3 step: resolved rules are provisioned into the process-global
    /// UePolicyContext keyed by SUPI and read back (the mapping target that
    /// E6 correlates COMPLETE/REJECT against).
    #[test]
    fn context_provision_round_trips_by_supi() {
        std::env::remove_var("PCF_URSP_RULES");
        let supi = "imsi-001019900000e3a";
        assert!(
            context_ursp_for(supi).is_empty(),
            "unprovisioned SUPI is empty"
        );
        let doc = serde_json::json!({ "urspRules": provisioned_ims_ursp_rules_json() });
        let rules = resolve_ursp_rules(Some(&doc));
        provision_context_ursp(supi, rules);
        let back = context_ursp_for(supi);
        assert_eq!(back.len(), 1, "provisioned rule readable by SUPI");
        assert_eq!(
            back[0].precedence, 10,
            "the provisioned ims rule (precedence 10)"
        );
    }

    // --- Wave-6 E6: T3501 + delivery-result correlation ----------------------

    /// Seed a Pending association carrying a fixed PTI/UPSC, return its id.
    fn seed_pending_assoc(pti: u8) -> String {
        let assoc = ue_policy_add("imsi-001010000006e6a", "http://127.0.0.1:9/notify", "");
        ue_policy_set_delivery(
            &assoc.pol_asso_id,
            pti,
            1,
            Some(("001".into(), "01".into())),
            default_wire_rules(),
        );
        assoc.pol_asso_id
    }

    /// A UE STATE INDICATION reporting `upscs` installed for PLMN 001-01.
    fn ue_state_indication(pti: u8, upscs: &[u16]) -> Vec<u8> {
        let plmn = nextgcore_nas::common::types::PlmnId {
            mcc: [0, 0, 1],
            mnc: [0, 1, 0x0F],
            mnc_len: 2,
        };
        let sublists = if upscs.is_empty() {
            Vec::new()
        } else {
            vec![nas_updp::UpsiSublist {
                plmn_id: plmn,
                upscs: upscs.to_vec(),
            }]
        };
        nas_updp::UeStateIndication {
            pti,
            upsi_list: nas_updp::UpsiList { sublists },
            classmark: nas_updp::UePolicyClassmark::default(),
            os_ids: Vec::new(),
        }
        .encode()
        .expect("encode UE STATE INDICATION")
    }

    /// #91 criterion 3: a UE STATE INDICATION is DECODED and its UPSI list recorded,
    /// where it used to be logged-and-ignored.
    #[test]
    fn ue_state_indication_records_the_reported_upsi_list() {
        let id = seed_pending_assoc(0x88);
        let container = ue_state_indication(0x01, &[1, 7]);

        assert_eq!(
            apply_ue_policy_ul_container(&id, &container),
            UePolicyResultOutcome::StateReported(2),
            "the UE reported two installed UPSIs; Ignored(0x04) is the pre-#91 answer"
        );

        let assoc = ue_policy_find(&id).expect("assoc");
        assert_eq!(
            assoc.reported_upsis,
            vec![
                ("001".to_string(), "01".to_string(), 1),
                ("001".to_string(), "01".to_string(), 7),
            ],
            "the PLMN must travel with each UPSC: the same code means different content \
             in a different PLMN"
        );
        // A UE STATE INDICATION is not a delivery result, so the state must not move.
        assert_eq!(assoc.delivery_state, DeliveryState::Pending);

        // And the PLMN filter is a filter: a UPSC reported for 001-01 is not installed
        // for 002-02.
        assert_eq!(installed_upscs_for_plmn(&id, "001", "01"), vec![1, 7]);
        assert!(installed_upscs_for_plmn(&id, "002", "02").is_empty());
    }

    /// #91 criterion 3: with the UE's installed list known, only the MISSING sections
    /// are scheduled -- and when none are missing, nothing is sent at all.
    #[test]
    fn the_delta_omits_sections_the_ue_already_has() {
        // Two rules, forced into two sections by a tiny part limit.
        let rules = two_rule_set();
        let (_, all) =
            build_manage_ue_policy_command_sections(0x80, 1, "001", "01", &rules, ONE_RULE_FITS)
                .expect("two sections");
        assert_eq!(
            all,
            vec![1, 2],
            "the fixture must really produce two sections"
        );

        // The UE has section 1 → only section 2 is delivered, and it keeps the code 2
        // rather than being renumbered to 1.
        let (_, delta) =
            build_manage_ue_policy_delta(0x80, 1, "001", "01", &rules, ONE_RULE_FITS, &[1])
                .expect("delta builds")
                .expect("one section still missing");
        assert_eq!(
            delta,
            vec![2],
            "a delivered section must keep its code when a neighbour is skipped, or the \
             UE's reported UPSI would come to mean different content"
        );

        // The UE has both → nothing to send.
        assert!(
            build_manage_ue_policy_delta(0x80, 1, "001", "01", &rules, ONE_RULE_FITS, &[1, 2])
                .expect("delta builds")
                .is_none(),
            "an empty delta must be None, not a command with an empty sublist"
        );

        // The UE has a code we never assigned → full delivery.
        let (_, delta) =
            build_manage_ue_policy_delta(0x80, 1, "001", "01", &rules, ONE_RULE_FITS, &[99])
                .expect("delta builds")
                .expect("nothing was skipped");
        assert_eq!(delta, vec![1, 2]);
    }

    /// #91 criterion 5: an over-length policy is PARTITIONED into ≥2 sections with
    /// distinct UPSCs instead of failing closed.
    #[test]
    fn an_over_length_policy_is_partitioned_into_multiple_sections() {
        let rules = two_rule_set();

        // Against the spec's own bound both rules fit one section.
        let (_, upscs) = build_manage_ue_policy_command_sections(
            0x80,
            1,
            "001",
            "01",
            &rules,
            MAX_UE_POLICY_PART_CONTENTS,
        )
        .expect("one section");
        assert_eq!(upscs, vec![1], "nothing to partition at the real limit");

        // With a limit that one rule fits and two do not, the policy is SPLIT rather
        // than refused -- which is the behaviour change. Before #91 this was `Err`.
        let (pdu, upscs) =
            build_manage_ue_policy_command_sections(0x80, 1, "001", "01", &rules, ONE_RULE_FITS)
                .expect("partitioned, not refused");
        assert_eq!(upscs, vec![1, 2], "two sections, distinct UPSCs");

        // The PDU really carries two instructions, read back through the decoder.
        let decoded = nas_updp::ManageUePolicyCommand::decode(&pdu).expect("decode");
        assert_eq!(decoded.pti, 0x80);
        assert_eq!(decoded.list.sublists.len(), 1, "one PLMN sublist");
        let instructions = &decoded.list.sublists[0].instructions;
        assert_eq!(instructions.len(), 2, "two sections in one command");
        assert_eq!(instructions[0].upsc, 1);
        assert_eq!(instructions[1].upsc, 2);
        assert!(
            instructions.iter().all(|i| i.parts.len() == 1),
            "one URSP part per section"
        );

        // A single rule that cannot fit a section at all is still an honest error:
        // there is nothing left to split.
        let err = build_manage_ue_policy_command_sections(0x80, 1, "001", "01", &rules, 20)
            .expect_err("one rule alone exceeds a 4-octet part");
        assert!(
            err.contains("cannot be split across sections"),
            "unexpected error: {err}"
        );
    }

    /// A part limit that fits exactly ONE rule of [`two_rule_set`] and not two.
    ///
    /// Measured rather than guessed: one rule of that set encodes to 41 octets, so 60
    /// admits one and refuses two. A hard-coded 40 would refuse even one and the
    /// partitioning tests would fail for the wrong reason.
    const ONE_RULE_FITS: usize = 60;

    #[test]
    fn the_partition_fixture_limit_really_fits_exactly_one_rule() {
        let rules = two_rule_set();
        let wire: Vec<_> = rules
            .iter()
            .map(|r| map_pcfd_rule_to_wire(r).expect("map"))
            .collect();
        let one = nas_updp::encode_ursp_rules(&wire[..1])
            .expect("encode one")
            .len();
        let both = nas_updp::encode_ursp_rules(&wire)
            .expect("encode both")
            .len();
        assert!(
            one <= ONE_RULE_FITS && both > ONE_RULE_FITS,
            "the partitioning tests depend on this: one rule is {one} octets and both are \
             {both}, against a limit of {ONE_RULE_FITS}"
        );
    }

    /// Two distinct URSP rules, used by the partitioning tests. Distinct precedences so
    /// they are not deduplicated, and distinct DNNs so they encode differently.
    fn two_rule_set() -> Vec<UrspRule> {
        vec![
            UrspRule {
                precedence: 10,
                traffic_descriptors: vec![TrafficDescriptor::for_dnn("internet")],
                route_selection_descriptors: vec![RouteSelectionDescriptor {
                    precedence: 1,
                    dnn: Some("internet".into()),
                    snssai: Some((1, None)),
                    pdu_type: RouteSelectionPduType::Ipv4v6,
                    ssc_mode: 1,
                    access_type: None,
                }],
            },
            UrspRule {
                precedence: 20,
                traffic_descriptors: vec![TrafficDescriptor::for_dnn("ims")],
                route_selection_descriptors: vec![RouteSelectionDescriptor {
                    precedence: 1,
                    dnn: Some("ims".into()),
                    snssai: Some((1, None)),
                    pdu_type: RouteSelectionPduType::Ipv4v6,
                    ssc_mode: 1,
                    access_type: None,
                }],
            },
        ]
    }

    /// #91 criterion 6: every TS 24.526 Table 5.2.1 component the issue names, except
    /// the one the table does not define.
    ///
    /// A round trip through `parse_td` and the wire encoder, since the criterion is
    /// about both halves: parsing the provisioned JSON and emitting the component.
    #[test]
    fn traffic_descriptor_components_cover_table_5_2_1() {
        let json = serde_json::json!({
            "osAppId": { "osId": "97a498e3-fc92-5c94-8986-0333d06e4e47", "appId": "com.example" },
            "ipv4RemoteAddress": { "addr": "192.0.2.1", "mask": "255.255.255.0" },
            "ipv6RemoteAddress": { "addr": "2001:db8::1", "prefixLength": 64 },
            "protocol": 6,
            "remotePort": 443,
            "remotePortRange": { "low": 1000, "high": 2000 },
            "dnn": "internet",
            "fqdn": "example.com",
        });
        let td = parse_td(&json).expect("all components parse");
        assert_eq!(
            td.components.len(),
            8,
            "TS 24.526 §5.2 gives the components of ONE descriptor AND semantics, so every \
             recognised key must contribute -- the pre-#91 parser returned on the first match"
        );

        // Every one of them reaches the wire.
        for c in &td.components {
            map_td_component(c).unwrap_or_else(|e| panic!("{c:?} must encode: {e}"));
        }

        // The structured OS Id really is the 16 octets of the UUID.
        let os = td
            .components
            .iter()
            .find_map(|c| match c {
                TrafficDescriptorComponent::OsIdOsAppId { os_id, .. } => Some(*os_id),
                _ => None,
            })
            .expect("OsIdOsAppId present");
        assert_eq!(os[0], 0x97);
        assert_eq!(os[15], 0x47);

        // S-NSSAI is the void half of criterion 6: Table 5.2.1 defines no traffic
        // descriptor component identifier for it (specs/24526-i50.txt:2467-2498), so it
        // must still fail closed rather than be silently dropped.
        let err = map_td_component(&TrafficDescriptorComponent::SNssai { sst: 1, sd: None })
            .expect_err("S-NSSAI has no traffic-descriptor component type");
        assert!(err.contains("not representable"), "unexpected error: {err}");

        // matchAll is exclusive by rule, not by convenience.
        let err = parse_td(&serde_json::json!({ "matchAll": true, "dnn": "internet" }))
            .expect_err("matchAll cannot be combined");
        assert!(err.contains("matchAll"), "unexpected error: {err}");
        // And alone it is the empty component set this module uses for match-all.
        assert!(parse_td(&serde_json::json!({ "matchAll": true }))
            .expect("matchAll alone")
            .components
            .is_empty());

        // A required sub-member missing is an error, not a default: guessing an IPv4
        // mask changes which traffic the rule matches.
        let err = parse_td(&serde_json::json!({ "ipv4RemoteAddress": { "addr": "192.0.2.1" } }))
            .expect_err("mask is required");
        assert!(err.contains("mask is required"), "unexpected error: {err}");
    }

    /// #91: `uePolReq` is base64 UPDP. A UE STATE INDICATION in it moves the installed
    /// baseline; anything else is ignored without failing the association.
    #[test]
    fn ue_pol_req_ingest_records_only_a_ue_state_indication() {
        use base64::Engine as _;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

        let id = seed_pending_assoc(0x89);
        assert_eq!(
            ingest_ue_policy_request(&id, &b64(&ue_state_indication(0x00, &[3]))),
            1
        );
        assert_eq!(installed_upscs_for_plmn(&id, "001", "01"), vec![3]);

        // Not base64 → 0, and the previously recorded baseline is untouched.
        assert_eq!(ingest_ue_policy_request(&id, "not base64!!"), 0);
        assert_eq!(installed_upscs_for_plmn(&id, "001", "01"), vec![3]);

        // A MANAGE UE POLICY COMPLETE (0x02) is a delivery result, not an installed-set
        // report, so it records nothing here.
        assert_eq!(ingest_ue_policy_request(&id, &b64(&[0x89, 0x02])), 0);
        assert_eq!(installed_upscs_for_plmn(&id, "001", "01"), vec![3]);
    }

    /// T3501 state machine (TS 24.501 D.2.1.5): first expiry retransmits, the
    /// second aborts — exactly ONE retransmission.
    #[test]
    fn t3501_state_machine_one_retransmit_then_abort() {
        assert_eq!(t3501_on_expiry(0), T3501Expiry::Retransmit);
        assert_eq!(t3501_on_expiry(1), T3501Expiry::Abort);
        assert_eq!(t3501_on_expiry(2), T3501Expiry::Abort);
    }

    /// `PCF_T3501_SECS` overrides the 30s default; a zero/invalid value falls
    /// back to the default.
    #[test]
    fn t3501_duration_env_tunable() {
        std::env::set_var("PCF_T3501_SECS", "5");
        assert_eq!(t3501_duration(), std::time::Duration::from_secs(5));
        std::env::set_var("PCF_T3501_SECS", "0");
        assert_eq!(t3501_duration(), std::time::Duration::from_secs(30));
        std::env::remove_var("PCF_T3501_SECS");
        assert_eq!(t3501_duration(), std::time::Duration::from_secs(30));
    }

    /// A UE that never answers yields exactly one retransmission then Failed at
    /// 2 x T3501 (the falsifiable timer-state assert of the E6 acceptance).
    #[tokio::test]
    async fn t3501_driver_retransmits_once_then_fails() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let id = seed_pending_assoc(0x81);
        let sends = Arc::new(AtomicUsize::new(0));
        let s = sends.clone();
        run_t3501(&id, std::time::Duration::from_millis(1), move || {
            let s = s.clone();
            async move {
                s.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;
        assert_eq!(
            sends.load(Ordering::SeqCst),
            1,
            "exactly one retransmission before abort"
        );
        assert!(
            matches!(
                ue_policy_delivery_state(&id),
                Some(DeliveryState::Failed(_))
            ),
            "association aborts to Failed at 2 x T3501"
        );
    }

    /// A COMPLETE stops T3501: once the association is Delivered the driver
    /// returns immediately without retransmitting.
    #[tokio::test]
    async fn t3501_driver_stops_when_delivered() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let id = seed_pending_assoc(0x82);
        ue_policy_mark_delivered(&id, 1); // COMPLETE arrived before the first expiry
        let sends = Arc::new(AtomicUsize::new(0));
        let s = sends.clone();
        run_t3501(&id, std::time::Duration::from_millis(1), move || {
            let s = s.clone();
            async move {
                s.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;
        assert_eq!(
            sends.load(Ordering::SeqCst),
            0,
            "a Delivered association triggers no retransmission (COMPLETE stops T3501)"
        );
    }

    /// A MANAGE UE POLICY COMPLETE with the matching PTI flips Pending→Delivered
    /// and records the UPSC as installed (D.2.1.3).
    #[test]
    fn apply_complete_matching_pti_delivers() {
        let id = seed_pending_assoc(0x83);
        let complete = nas_updp::ManageUePolicyComplete { pti: 0x83 }
            .encode()
            .expect("complete encodes");
        let outcome = apply_ue_policy_ul_container(&id, &complete);
        assert_eq!(outcome, UePolicyResultOutcome::Delivered(1));
        let a = ue_policy_find(&id).expect("assoc");
        assert_eq!(a.delivery_state, DeliveryState::Delivered);
        assert_eq!(a.installed_upsc, Some(1));
    }

    /// A COMPLETE with a NON-matching PTI is dropped (stale/duplicate command,
    /// D.2.1.6) — Delivered is reached ONLY via a matching PTI.
    #[test]
    fn apply_complete_wrong_pti_dropped() {
        let id = seed_pending_assoc(0x84);
        let complete = nas_updp::ManageUePolicyComplete { pti: 0x8A }
            .encode()
            .expect("complete encodes");
        let outcome = apply_ue_policy_ul_container(&id, &complete);
        assert_eq!(
            outcome,
            UePolicyResultOutcome::PtiMismatch {
                expected: 0x84,
                got: 0x8A
            }
        );
        assert_eq!(
            ue_policy_find(&id).expect("assoc").delivery_state,
            DeliveryState::Pending,
            "PTI mismatch must NOT deliver"
        );
    }

    /// A MANAGE UE POLICY COMMAND REJECT with the matching PTI flips
    /// Pending→Failed and logs the decoded D.6.3 cause(s) (D.2.1.4).
    #[test]
    fn apply_reject_matching_pti_fails_with_cause() {
        let id = seed_pending_assoc(0x85);
        let reject = nas_updp::ManageUePolicyCommandReject {
            pti: 0x85,
            result: nas_updp::UePolicySectionManagementResult {
                subresults: vec![nas_updp::UePolicySectionManagementSubresult {
                    plmn_id: nextgcore_nas::common::types::PlmnId::new([0, 0, 1], [0, 1, 0xf], 2),
                    results: vec![nas_updp::UePolicyResult {
                        upsc: 0x0001,
                        failed_instruction_order: 1,
                        cause: nas_updp::UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                    }],
                }],
            },
        }
        .encode()
        .expect("reject encodes");
        let outcome = apply_ue_policy_ul_container(&id, &reject);
        match outcome {
            UePolicyResultOutcome::Rejected(cause) => {
                assert!(
                    cause.contains("UPSC"),
                    "cause names the failed UPSC: {cause}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(matches!(
            ue_policy_find(&id).expect("assoc").delivery_state,
            DeliveryState::Failed(_)
        ));
    }

    /// A truncated / non-UPDP container is dropped (fail-closed, no panic) and
    /// leaves the association Pending.
    #[test]
    fn apply_undecodable_container_dropped() {
        let id = seed_pending_assoc(0x86);
        assert_eq!(
            apply_ue_policy_ul_container(&id, &[0x86]),
            UePolicyResultOutcome::Undecodable
        );
        // #91: a TRUNCATED UE STATE INDICATION (PTI + type, no UPSI list) is
        // Undecodable, not Ignored. It used to be Ignored because 0x04 fell into the
        // catch-all arm and was never decoded at all -- so a malformed one and a valid
        // one were indistinguishable.
        assert_eq!(
            apply_ue_policy_ul_container(&id, &[0x00, 0x04]),
            UePolicyResultOutcome::Undecodable
        );
        // A UPDP type that really is outside this loop is still Ignored.
        assert_eq!(
            apply_ue_policy_ul_container(&id, &[0x00, 0x09]),
            UePolicyResultOutcome::Ignored(0x09)
        );
        assert_eq!(
            ue_policy_find(&id).expect("assoc").delivery_state,
            DeliveryState::Pending
        );
    }

    /// An unknown association id yields `UnknownAssociation` (no panic).
    #[test]
    fn apply_unknown_association() {
        let complete = nas_updp::ManageUePolicyComplete { pti: 0x80 }
            .encode()
            .unwrap();
        assert_eq!(
            apply_ue_policy_ul_container("does-not-exist", &complete),
            UePolicyResultOutcome::UnknownAssociation
        );
    }
}
