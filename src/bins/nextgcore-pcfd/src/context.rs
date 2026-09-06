//! PCF Context Management
//!
//! Port of src/pcf/context.c - PCF context with UE AM/SM lists, session list, and hash tables

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Access type (TS 29.571 `AccessType`).
///
/// PERSISTED (issue #66/#192). The serialised form is the **3GPP token**, not the
/// Rust variant name: `StateStore` refuses to overwrite a snapshot it cannot
/// parse, so a variant rename would make pcfd fail startup after an upgrade. The
/// spec text is the stable contract; the Rust identifier is ours to change.
///
/// `#[serde(rename)]` rather than a delegating codec because pcfd has **no**
/// existing wire codec for this enum, so these attributes are the only token
/// table and cannot drift from one. Contrast `FlowStatus` in `npcf_handler`,
/// which has `from_wire`/`as_wire` and therefore delegates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum AccessType {
    #[default]
    #[serde(rename = "3GPP_ACCESS")]
    ThreeGppAccess,
    #[serde(rename = "NON_3GPP_ACCESS")]
    NonThreeGppAccess,
}

/// RAT type (TS 29.571 `RatType`). PERSISTED -- see [`AccessType`] for why the
/// on-disk token is the 3GPP spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum RatType {
    #[default]
    #[serde(rename = "NR")]
    Nr,
    #[serde(rename = "EUTRA")]
    Eutra,
    #[serde(rename = "WLAN")]
    Wlan,
    #[serde(rename = "VIRTUAL")]
    Virtual,
}

/// PDU Session Type (TS 29.571 `PduSessionType`). PERSISTED -- see
/// [`AccessType`] for why the on-disk token is the 3GPP spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum PduSessionType {
    #[default]
    #[serde(rename = "IPV4")]
    Ipv4,
    #[serde(rename = "IPV6")]
    Ipv6,
    #[serde(rename = "IPV4V6")]
    Ipv4v6,
    #[serde(rename = "UNSTRUCTURED")]
    Unstructured,
    #[serde(rename = "ETHERNET")]
    Ethernet,
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Guami {
    pub plmn_id: PlmnId,
    pub amf_id: AmfId,
}

/// PLMN ID
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// AMF ID
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AmfId {
    pub region: u8,
    pub set: u16,
    pub pointer: u8,
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// AMBR (Aggregate Maximum Bit Rate)
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Ambr {
    pub uplink: String,
    pub downlink: String,
}

/// Subscribed Default QoS
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SubscribedDefaultQos {
    pub five_qi: u8,
    pub priority_level: u8,
    pub arp_priority_level: u8,
    pub arp_preempt_cap: bool,
    pub arp_preempt_vuln: bool,
}

/// PCF UE AM (Access Management) context
/// Port of pcf_ue_am_t from context.h
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcfUeAm {
    pub id: u64,
    pub association_id: String,
    pub supi: String,
    pub notification_uri: Option<String>,
    pub gpsi: Option<String>,
    pub access_type: AccessType,
    pub pei: Option<String>,
    pub guami: Guami,
    pub rat_type: RatType,
    /// SBI Features - AM Policy Control features
    pub am_policy_control_features: u64,
    /// Subscribed UE AMBR
    pub subscribed_ue_ambr: Option<Ambr>,
    /// Associated stream ID
    pub stream_id: Option<u64>,
    /// URSP rules for this UE (Rel-17, TS 24.526)
    pub ursp_rules: Vec<UrspRule>,
    /// RedCap UE flag (Rel-17)
    pub is_redcap: bool,
    /// SNPN NID (Rel-17)
    pub snpn_nid: Option<String>,
}

/// UE Route Selection Policy rule (TS 24.526)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UrspRule {
    /// Rule precedence (lower = higher priority, range 0-255)
    pub precedence: u8,
    /// Traffic descriptors for matching packets
    pub traffic_descriptors: Vec<TrafficDescriptor>,
    /// Route selection descriptors (ordered by precedence)
    pub route_selection_descriptors: Vec<RouteSelectionDescriptor>,
}

/// Traffic Descriptor for URSP matching (TS 24.526 5.2)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrafficDescriptor {
    /// Application ID (from OSID/OMA)
    pub app_id: Option<String>,
    /// IP packet filter descriptor (5-tuple)
    pub ip_descriptor: Option<IpPacketFilterDescriptor>,
    /// DNN for this traffic
    pub dnn: Option<String>,
    /// S-NSSAI for this traffic
    pub s_nssai: Option<SNssai>,
    /// Connection capabilities (IMS, MMS, SUPL, Internet)
    pub connection_caps: Option<String>,
}

/// IP Packet Filter Descriptor (5-tuple matching)
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IpPacketFilterDescriptor {
    /// Source IP address
    pub src_ip: Option<String>,
    /// Source port range
    pub src_port: Option<(u16, u16)>,
    /// Destination IP address
    pub dst_ip: Option<String>,
    /// Destination port range
    pub dst_port: Option<(u16, u16)>,
    /// Protocol (TCP=6, UDP=17, etc.)
    pub protocol: Option<u8>,
}

/// Route Selection Descriptor (TS 24.526 5.2)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteSelectionDescriptor {
    /// Precedence within route descriptors (lower = higher priority)
    pub precedence: u8,
    /// S-NSSAI for route selection
    pub s_nssai: Option<SNssai>,
    /// DNN for route selection
    pub dnn: Option<String>,
    /// PDU Session Type (IPv4, IPv6, IPv4v6, Ethernet, Unstructured)
    pub pdu_session_type: Option<PduSessionType>,
    /// SSC Mode (1, 2, 3)
    pub ssc_mode: Option<u8>,
    /// Access type preference (3GPP, Non-3GPP)
    pub access_type: Option<Vec<AccessType>>,
}

impl PcfUeAm {
    pub fn new(id: u64, supi: &str) -> Self {
        Self {
            id,
            association_id: Uuid::new_v4().to_string(),
            supi: supi.to_string(),
            notification_uri: None,
            gpsi: None,
            access_type: AccessType::default(),
            pei: None,
            guami: Guami::default(),
            rat_type: RatType::default(),
            am_policy_control_features: 0,
            subscribed_ue_ambr: None,
            stream_id: None,
            ursp_rules: Vec::new(),
            is_redcap: false,
            snpn_nid: None,
        }
    }

    /// Build complete URSP rules from UE subscription data
    /// This creates properly structured URSP rules per TS 24.526
    pub fn build_ursp_rules(&mut self, subscription_data: &UrspSubscriptionData) {
        self.ursp_rules.clear();

        // Build rules from subscription data
        for rule_template in &subscription_data.rule_templates {
            self.ursp_rules.push(UrspRule {
                precedence: rule_template.precedence,
                traffic_descriptors: rule_template.traffic_descriptors.clone(),
                route_selection_descriptors: rule_template.route_selection_descriptors.clone(),
            });
        }

        log::info!(
            "[PCF URSP] Built {} URSP rules for SUPI={}",
            self.ursp_rules.len(),
            self.supi
        );
    }

    /// Generate default URSP rules based on UE subscription.
    ///
    /// In production, rules would come from UDR subscription data.
    /// This creates sensible defaults for standard slice types with full URSP structure.
    pub fn generate_default_ursp_rules(&mut self) {
        self.ursp_rules = vec![
            // Rule 1: IMS traffic → eMBB slice, IMS DNN
            UrspRule {
                precedence: 1,
                traffic_descriptors: vec![TrafficDescriptor {
                    app_id: Some("ims".to_string()),
                    ip_descriptor: None,
                    dnn: Some("ims".to_string()),
                    s_nssai: Some(SNssai { sst: 1, sd: None }),
                    connection_caps: Some("IMS".to_string()),
                }],
                route_selection_descriptors: vec![RouteSelectionDescriptor {
                    precedence: 1,
                    s_nssai: Some(SNssai { sst: 1, sd: None }),
                    dnn: Some("ims".to_string()),
                    pdu_session_type: Some(PduSessionType::Ipv4v6),
                    ssc_mode: Some(1),
                    access_type: Some(vec![AccessType::ThreeGppAccess]),
                }],
            },
            // Rule 2: Internet traffic → eMBB slice, Internet DNN
            UrspRule {
                precedence: 2,
                traffic_descriptors: vec![TrafficDescriptor {
                    app_id: Some("internet".to_string()),
                    ip_descriptor: None,
                    dnn: Some("internet".to_string()),
                    s_nssai: Some(SNssai { sst: 1, sd: None }),
                    connection_caps: Some("Internet".to_string()),
                }],
                route_selection_descriptors: vec![RouteSelectionDescriptor {
                    precedence: 1,
                    s_nssai: Some(SNssai { sst: 1, sd: None }),
                    dnn: Some("internet".to_string()),
                    pdu_session_type: Some(PduSessionType::Ipv4),
                    ssc_mode: Some(1),
                    access_type: Some(vec![
                        AccessType::ThreeGppAccess,
                        AccessType::NonThreeGppAccess,
                    ]),
                }],
            },
            // Rule 3: V2X traffic → URLLC slice, V2X DNN
            UrspRule {
                precedence: 3,
                traffic_descriptors: vec![TrafficDescriptor {
                    app_id: Some("v2x".to_string()),
                    ip_descriptor: None,
                    dnn: Some("v2x".to_string()),
                    s_nssai: Some(SNssai { sst: 4, sd: None }),
                    connection_caps: Some("V2X".to_string()),
                }],
                route_selection_descriptors: vec![RouteSelectionDescriptor {
                    precedence: 1,
                    s_nssai: Some(SNssai { sst: 4, sd: None }),
                    dnn: Some("v2x".to_string()),
                    pdu_session_type: Some(PduSessionType::Ipv4),
                    ssc_mode: Some(2),
                    access_type: Some(vec![AccessType::ThreeGppAccess]),
                }],
            },
        ];
        log::info!(
            "[PCF URSP] Generated {} default URSP rules for SUPI={}",
            self.ursp_rules.len(),
            self.supi
        );
    }

    /// Provision UE policy (URSP) to AMF via UE Configuration Update
    /// Returns true if provisioning was successful
    pub fn provision_ue_policy(&self) -> bool {
        if self.ursp_rules.is_empty() {
            log::warn!(
                "[PCF URSP] No URSP rules to provision for SUPI={}",
                self.supi
            );
            return false;
        }

        log::info!(
            "[PCF URSP] Provisioning {} URSP rules to AMF for SUPI={} via UE Configuration Update",
            self.ursp_rules.len(),
            self.supi
        );

        // In production, this would:
        // 1. Send Namf_Communication_N1N2MessageTransfer to AMF
        // 2. AMF sends NAS UE Configuration Update Command to UE
        // 3. UE acknowledges with UE Configuration Update Complete
        true
    }
}

/// URSP subscription data from UDR
#[derive(Debug, Clone, Default)]
pub struct UrspSubscriptionData {
    /// URSP rule templates from subscription
    pub rule_templates: Vec<UrspRuleTemplate>,
}

/// URSP rule template from subscription
#[derive(Debug, Clone)]
pub struct UrspRuleTemplate {
    /// Rule precedence
    pub precedence: u8,
    /// Traffic descriptors
    pub traffic_descriptors: Vec<TrafficDescriptor>,
    /// Route selection descriptors
    pub route_selection_descriptors: Vec<RouteSelectionDescriptor>,
}

/// PCF UE SM (Session Management) context
/// Port of pcf_ue_sm_t from context.h
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcfUeSm {
    pub id: u64,
    pub supi: String,
    pub gpsi: Option<String>,
    /// List of session IDs belonging to this UE
    pub sess_ids: Vec<u64>,
}

impl PcfUeSm {
    pub fn new(id: u64, supi: &str) -> Self {
        Self {
            id,
            supi: supi.to_string(),
            gpsi: None,
            sess_ids: Vec::new(),
        }
    }

    pub fn is_last_session(&self) -> bool {
        self.sess_ids.len() == 1
    }
}

/// BSF Binding information
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PcfBinding {
    pub resource_uri: Option<String>,
    pub id: Option<String>,
}

impl PcfBinding {
    pub fn is_associated(&self) -> bool {
        self.id.is_some()
    }

    pub fn clear(&mut self) {
        self.resource_uri = None;
        self.id = None;
    }

    pub fn store(&mut self, resource_uri: &str, id: &str) {
        self.resource_uri = Some(resource_uri.to_string());
        self.id = Some(id.to_string());
    }
}

/// Serving/Home PLMN presence
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PlmnPresence {
    pub presence: bool,
    pub plmn_id: PlmnId,
}

/// PCF Session context
/// Port of pcf_sess_t from context.h
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcfSess {
    pub id: u64,
    pub sm_policy_id: String,
    pub binding: PcfBinding,
    /// PDU Session Identity
    pub psi: u8,
    pub pdu_session_type: PduSessionType,
    /// DNN
    pub dnn: Option<String>,
    pub full_dnn: Option<String>,
    /// Serving PLMN
    pub serving: PlmnPresence,
    /// Home PLMN
    pub home: PlmnPresence,
    pub notification_uri: Option<String>,
    /// IPv4 address string
    pub ipv4addr_string: Option<String>,
    /// IPv6 prefix string
    pub ipv6prefix_string: Option<String>,
    /// IPv4 address (network byte order)
    pub ipv4addr: u32,
    /// IPv6 prefix
    pub ipv6prefix: Option<(u8, [u8; 16])>,
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// SBI Features
    pub smpolicycontrol_features: u64,
    pub management_features: u64,
    pub policyauthorization_features: u64,
    /// Subscribed session AMBR
    pub subscribed_sess_ambr: Option<Ambr>,
    /// Subscribed default QoS
    pub subscribed_default_qos: Option<SubscribedDefaultQos>,
    /// App session IDs
    pub app_ids: Vec<u64>,
    /// Parent UE SM ID
    pub pcf_ue_sm_id: u64,
    /// Associated stream ID
    pub stream_id: Option<u64>,
    /// PCC rules installed for AF application sessions bound to this PDU
    /// session (TS 29.514 PolicyAuthorization → TS 29.512 SmPolicyDecision).
    /// Pushed to the SMF in the SM policy update notification.
    pub af_pcc_rules: Vec<crate::npcf_handler::AfPccRule>,
}

impl PcfSess {
    pub fn new(id: u64, pcf_ue_sm_id: u64, psi: u8) -> Self {
        Self {
            id,
            sm_policy_id: Uuid::new_v4().to_string(),
            binding: PcfBinding::default(),
            psi,
            pdu_session_type: PduSessionType::default(),
            dnn: None,
            full_dnn: None,
            serving: PlmnPresence::default(),
            home: PlmnPresence::default(),
            notification_uri: None,
            ipv4addr_string: None,
            ipv6prefix_string: None,
            ipv4addr: 0,
            ipv6prefix: None,
            s_nssai: SNssai::default(),
            smpolicycontrol_features: 0,
            management_features: 0,
            policyauthorization_features: 0,
            subscribed_sess_ambr: None,
            subscribed_default_qos: None,
            app_ids: Vec::new(),
            pcf_ue_sm_id,
            stream_id: None,
            af_pcc_rules: Vec::new(),
        }
    }

    /// Set IPv4 address from string
    pub fn set_ipv4addr(&mut self, ipv4addr: &str) -> bool {
        if let Ok(addr) = ipv4addr.parse::<std::net::Ipv4Addr>() {
            self.ipv4addr_string = Some(ipv4addr.to_string());
            self.ipv4addr = u32::from(addr);
            true
        } else {
            false
        }
    }

    /// Set IPv6 prefix from string
    pub fn set_ipv6prefix(&mut self, ipv6prefix: &str) -> bool {
        // Parse format like "2001:db8::/64"
        let parts: Vec<&str> = ipv6prefix.split('/').collect();
        if parts.len() != 2 {
            return false;
        }
        if let (Ok(addr), Ok(len)) = (
            parts[0].parse::<std::net::Ipv6Addr>(),
            parts[1].parse::<u8>(),
        ) {
            self.ipv6prefix_string = Some(ipv6prefix.to_string());
            self.ipv6prefix = Some((len, addr.octets()));
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Rel-18 PCF Analytics Integration (NWDAF)
// ============================================================================

/// Traffic classification for analytics-based policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrafficClass {
    /// Standard best-effort traffic
    #[default]
    BestEffort,
    /// XR interactive traffic (5QI 82-85)
    XrInteractive,
    /// Video streaming
    VideoStreaming,
    /// Voice/VoNR
    Voice,
    /// Machine-type communication
    Mtc,
    /// V2X traffic
    V2x,
}

/// Analytics-based policy adjustment state.
#[derive(Debug, Clone, Default)]
pub struct AnalyticsState {
    /// NWDAF analytics subscription ID (if subscribed)
    pub analytics_subscription_id: Option<String>,
    /// Predicted congestion level from NWDAF (0.0-1.0)
    pub predicted_congestion: f32,
    /// Classified traffic type
    pub traffic_class: TrafficClass,
    /// QoS sustainability score from NWDAF (0.0-1.0)
    pub qos_sustainability: f32,
    /// Whether energy-optimized policy is active
    pub energy_optimized: bool,
    /// Anomaly detection alerts
    pub anomaly_alerts: Vec<AnomalyAlert>,
    /// Last NWDAF query timestamp (epoch seconds)
    pub last_query_epoch: u64,
}

/// Anomaly alert from NWDAF analytics (Rel-18, TS 23.288)
#[derive(Debug, Clone)]
pub struct AnomalyAlert {
    /// Alert type
    pub alert_type: AnomalyAlertType,
    /// Severity (0.0 = info, 1.0 = critical)
    pub severity: f32,
    /// Affected S-NSSAI (if slice-specific)
    pub affected_snssai: Option<SNssai>,
    /// Recommended action
    pub recommended_action: AnomalyAction,
}

/// Types of anomaly alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyAlertType {
    /// Unexpected traffic spike
    TrafficSpike,
    /// DDoS-like pattern detected
    DdosPattern,
    /// Slice SLA violation predicted
    SlaSlaViolation,
    /// Abnormal UE behavior
    AbnormalUeBehavior,
    /// Network congestion predicted
    CongestionPredicted,
}

/// Recommended action for anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyAction {
    /// No action, informational only
    None,
    /// Throttle affected traffic
    Throttle,
    /// Re-route to different slice
    ReRoute,
    /// Tighten admission control
    TightenAdmission,
    /// Trigger energy saving
    EnergySaving,
}

/// Analytics-based policy engine (Rel-18, TS 23.288 integration)
#[derive(Debug)]
pub struct AnalyticsPolicyEngine {
    /// Congestion threshold for policy downgrade (0.0-1.0)
    pub congestion_threshold: f32,
    /// QoS sustainability floor before adjustment
    pub qos_sustainability_floor: f32,
    /// Number of policies dynamically adjusted
    pub adjustments_count: u64,
}

impl Default for AnalyticsPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyticsPolicyEngine {
    /// Create a new analytics policy engine with default thresholds
    pub fn new() -> Self {
        Self {
            congestion_threshold: 0.75,
            qos_sustainability_floor: 0.5,
            adjustments_count: 0,
        }
    }

    /// Evaluate analytics state and produce a policy adjustment if needed.
    /// Returns (adjusted_5qi, adjusted_arp, reason) or None if no change needed.
    pub fn evaluate(
        &mut self,
        analytics: &AnalyticsState,
        current_5qi: u8,
        current_arp: u8,
    ) -> Option<PolicyAdjustment> {
        // Check for anomaly-driven adjustments first
        for alert in &analytics.anomaly_alerts {
            if alert.severity >= 0.8 {
                self.adjustments_count += 1;
                return Some(PolicyAdjustment {
                    adjusted_5qi: current_5qi,
                    adjusted_arp: current_arp.min(14) + 1, // lower priority
                    reason: AdjustmentReason::AnomalyDetected,
                    action: alert.recommended_action,
                });
            }
        }

        // Congestion-based downgrade
        if analytics.predicted_congestion >= self.congestion_threshold {
            self.adjustments_count += 1;
            // Downgrade non-critical traffic to best-effort
            let new_5qi = match analytics.traffic_class {
                TrafficClass::BestEffort | TrafficClass::Mtc => current_5qi,
                _ => 9, // fallback to non-GBR best-effort
            };
            return Some(PolicyAdjustment {
                adjusted_5qi: new_5qi,
                adjusted_arp: current_arp.min(14) + 1,
                reason: AdjustmentReason::CongestionAvoidance,
                action: AnomalyAction::Throttle,
            });
        }

        // QoS sustainability below floor
        if analytics.qos_sustainability < self.qos_sustainability_floor
            && analytics.qos_sustainability > 0.0
        {
            self.adjustments_count += 1;
            return Some(PolicyAdjustment {
                adjusted_5qi: current_5qi,
                adjusted_arp: current_arp,
                reason: AdjustmentReason::QosSustainability,
                action: AnomalyAction::ReRoute,
            });
        }

        None
    }

    /// Number of dynamic adjustments made
    pub fn adjustment_count(&self) -> u64 {
        self.adjustments_count
    }
}

/// Result of analytics-based policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyAdjustment {
    /// Adjusted 5QI value
    pub adjusted_5qi: u8,
    /// Adjusted ARP priority level
    pub adjusted_arp: u8,
    /// Reason for adjustment
    pub reason: AdjustmentReason,
    /// Recommended action
    pub action: AnomalyAction,
}

/// Reason for policy adjustment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjustmentReason {
    /// Congestion avoidance
    CongestionAvoidance,
    /// QoS sustainability below threshold
    QosSustainability,
    /// Anomaly detected by NWDAF
    AnomalyDetected,
    /// Energy optimization
    EnergyOptimization,
}

/// Energy-aware policy parameters.
#[derive(Debug, Clone, Default)]
pub struct EnergyAwarePolicy {
    /// Allow extended DRX cycles
    pub allow_extended_drx: bool,
    /// Reduce measurement frequency for idle UEs
    pub reduce_measurement_frequency: bool,
    /// Optimize QoS for battery life
    pub optimize_for_battery: bool,
    /// Maximum inactivity before session release (seconds)
    pub max_inactivity_before_release: u32,
}

// ============================================================================
// Rel-18 UAV Policy Authorization (TS 23.256, TS 23.503)
// ============================================================================

/// UAV communication constraint type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UavCommConstraint {
    /// Maximum uplink data rate (kbps)
    MaxUplinkRate,
    /// Maximum downlink data rate (kbps)
    MaxDownlinkRate,
    /// Maximum session duration (seconds)
    MaxSessionDuration,
    /// Prohibited during specific time windows
    TimeRestriction,
}

/// UAV flight zone type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UavFlightZoneType {
    /// Unrestricted zone
    #[default]
    Unrestricted,
    /// Restricted zone (requires authorization)
    Restricted,
    /// Prohibited zone (no-fly)
    Prohibited,
    /// Conditional zone (authorization based on conditions)
    Conditional,
}

/// UAV flight zone definition
#[derive(Debug, Clone, Default)]
pub struct UavFlightZone {
    /// Zone identifier
    pub zone_id: String,
    /// Zone type
    pub zone_type: UavFlightZoneType,
    /// Minimum latitude
    pub min_latitude: f64,
    /// Maximum latitude
    pub max_latitude: f64,
    /// Minimum longitude
    pub min_longitude: f64,
    /// Maximum longitude
    pub max_longitude: f64,
    /// Minimum altitude (meters)
    pub min_altitude: f64,
    /// Maximum altitude (meters)
    pub max_altitude: f64,
    /// Time window start (UTC timestamp)
    pub time_start: Option<u64>,
    /// Time window end (UTC timestamp)
    pub time_end: Option<u64>,
}

impl UavFlightZone {
    /// Create a new flight zone
    pub fn new(zone_id: &str, zone_type: UavFlightZoneType) -> Self {
        Self {
            zone_id: zone_id.to_string(),
            zone_type,
            min_latitude: -90.0,
            max_latitude: 90.0,
            min_longitude: -180.0,
            max_longitude: 180.0,
            min_altitude: 0.0,
            max_altitude: 120.0, // Default max altitude per regulations
            time_start: None,
            time_end: None,
        }
    }

    /// Check if position is within zone
    pub fn contains_position(&self, latitude: f64, longitude: f64, altitude: f64) -> bool {
        latitude >= self.min_latitude
            && latitude <= self.max_latitude
            && longitude >= self.min_longitude
            && longitude <= self.max_longitude
            && altitude >= self.min_altitude
            && altitude <= self.max_altitude
    }

    /// Check if zone is active at given time
    pub fn is_active_at(&self, timestamp: u64) -> bool {
        match (self.time_start, self.time_end) {
            (Some(start), Some(end)) => timestamp >= start && timestamp <= end,
            (Some(start), None) => timestamp >= start,
            (None, Some(end)) => timestamp <= end,
            (None, None) => true,
        }
    }
}

/// UAV Policy Authorization (per TS 23.256)
#[derive(Debug, Clone, Default)]
pub struct UavPolicyAuthorization {
    /// UAV ID (UAVID)
    pub uav_id: Option<String>,
    /// Authorization status
    pub authorized: bool,
    /// Authorized flight zones
    pub flight_zones: Vec<UavFlightZone>,
    /// Global altitude limits (meters)
    pub min_altitude_limit: f64,
    pub max_altitude_limit: f64,
    /// Communication constraints
    pub max_uplink_rate_kbps: Option<u32>,
    pub max_downlink_rate_kbps: Option<u32>,
    pub max_session_duration_sec: Option<u32>,
    /// Priority level for UAV traffic (1-15, lower is higher priority)
    pub priority_level: u8,
    /// Allowed S-NSSAIs for UAV
    pub allowed_snssai: Vec<SNssai>,
    /// CAA (Civil Aviation Authority) authorization reference
    pub caa_authorization_ref: Option<String>,
    /// Emergency override enabled
    pub emergency_override: bool,
    /// Policy creation time
    pub created_at: u64,
    /// Policy expiration time
    pub expires_at: u64,
}

impl UavPolicyAuthorization {
    /// Create a new UAV policy authorization
    pub fn new(uav_id: &str) -> Self {
        Self {
            uav_id: Some(uav_id.to_string()),
            authorized: false,
            flight_zones: Vec::new(),
            min_altitude_limit: 0.0,
            max_altitude_limit: 120.0,
            max_uplink_rate_kbps: Some(1000),     // Default 1 Mbps
            max_downlink_rate_kbps: Some(5000),   // Default 5 Mbps
            max_session_duration_sec: Some(3600), // Default 1 hour
            priority_level: 10,
            allowed_snssai: Vec::new(),
            caa_authorization_ref: None,
            emergency_override: false,
            created_at: 0,
            expires_at: 0,
        }
    }

    /// Authorize UAV for flight
    pub fn grant_authorization(&mut self, caa_ref: &str, duration_sec: u64) {
        self.authorized = true;
        self.caa_authorization_ref = Some(caa_ref.to_string());
        self.created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
        self.expires_at = self.created_at + duration_sec;
        log::info!(
            "[UAV Policy] Authorization granted for UAV {:?}, CAA ref: {}, expires at: {}",
            self.uav_id,
            caa_ref,
            self.expires_at
        );
    }

    /// Revoke UAV authorization
    pub fn revoke_authorization(&mut self, reason: &str) {
        self.authorized = false;
        self.expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
        log::warn!(
            "[UAV Policy] Authorization revoked for UAV {:?}: {}",
            self.uav_id,
            reason
        );
    }

    /// Add a flight zone
    pub fn add_flight_zone(&mut self, zone: UavFlightZone) {
        log::info!(
            "[UAV Policy] Adding flight zone {} ({:?}) for UAV {:?}",
            zone.zone_id,
            zone.zone_type,
            self.uav_id
        );
        self.flight_zones.push(zone);
    }

    /// Check if UAV is authorized at current time
    pub fn is_authorized(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
        self.authorized && now >= self.created_at && now <= self.expires_at
    }

    /// Check if position is within authorized zones
    pub fn check_position_authorized(
        &self,
        latitude: f64,
        longitude: f64,
        altitude: f64,
        timestamp: u64,
    ) -> bool {
        // Check global altitude limits
        if altitude < self.min_altitude_limit || altitude > self.max_altitude_limit {
            log::warn!(
                "[UAV Policy] Altitude {:.1}m outside limits [{:.1}, {:.1}] for UAV {:?}",
                altitude,
                self.min_altitude_limit,
                self.max_altitude_limit,
                self.uav_id
            );
            return false;
        }

        // If no zones defined, any position is allowed (subject to altitude)
        if self.flight_zones.is_empty() {
            return true;
        }

        // Check if position is in any authorized zone
        for zone in &self.flight_zones {
            if zone.is_active_at(timestamp) {
                match zone.zone_type {
                    UavFlightZoneType::Prohibited => {
                        if zone.contains_position(latitude, longitude, altitude) {
                            log::warn!(
                                "[UAV Policy] Position in prohibited zone {} for UAV {:?}",
                                zone.zone_id,
                                self.uav_id
                            );
                            return false;
                        }
                    }
                    UavFlightZoneType::Restricted | UavFlightZoneType::Conditional => {
                        if zone.contains_position(latitude, longitude, altitude) {
                            return true;
                        }
                    }
                    UavFlightZoneType::Unrestricted => {
                        if zone.contains_position(latitude, longitude, altitude) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Set communication constraints
    pub fn set_comm_constraints(
        &mut self,
        max_ul_kbps: u32,
        max_dl_kbps: u32,
        max_duration_sec: u32,
    ) {
        self.max_uplink_rate_kbps = Some(max_ul_kbps);
        self.max_downlink_rate_kbps = Some(max_dl_kbps);
        self.max_session_duration_sec = Some(max_duration_sec);
    }
}

/// PCF App Session context
/// Port of pcf_app_t from context.h
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcfApp {
    pub id: u64,
    pub app_session_id: String,
    pub notif_uri: Option<String>,
    /// Parent session ID
    pub sess_id: u64,
}

impl PcfApp {
    pub fn new(id: u64, sess_id: u64) -> Self {
        Self {
            id,
            app_session_id: Uuid::new_v4().to_string(),
            notif_uri: None,
            sess_id,
        }
    }
}

/// PCF Context - main context structure for PCF
/// Port of pcf_context_t from context.h
pub struct PcfContext {
    /// UE AM list (by pool ID)
    ue_am_list: RwLock<HashMap<u64, PcfUeAm>>,
    /// UE SM list (by pool ID)
    ue_sm_list: RwLock<HashMap<u64, PcfUeSm>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, PcfSess>>,
    /// App session list (by pool ID)
    app_list: RwLock<HashMap<u64, PcfApp>>,
    /// SUPI -> UE AM ID hash
    supi_am_hash: RwLock<HashMap<String, u64>>,
    /// SUPI -> UE SM ID hash
    supi_sm_hash: RwLock<HashMap<String, u64>>,
    /// IPv4 address -> Session ID hash
    ipv4addr_hash: RwLock<HashMap<u32, u64>>,
    /// IPv6 prefix -> Session ID hash
    ipv6prefix_hash: RwLock<HashMap<String, u64>>,
    /// Association ID -> UE AM ID hash
    association_id_hash: RwLock<HashMap<String, u64>>,
    /// SM Policy ID -> Session ID hash
    sm_policy_id_hash: RwLock<HashMap<String, u64>>,
    /// App Session ID -> App ID hash
    app_session_id_hash: RwLock<HashMap<String, u64>>,
    /// Next UE AM ID
    next_ue_am_id: AtomicUsize,
    /// Next UE SM ID
    next_ue_sm_id: AtomicUsize,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// Next app ID
    next_app_id: AtomicUsize,
    /// Maximum number of UE AMs
    max_num_of_ue: usize,
    /// Maximum number of sessions
    max_num_of_sess: usize,
    /// Context initialized flag
    initialized: AtomicBool,
    /// Durable snapshot of the four primary lists (issue #66/#192). Disabled
    /// unless a state file is configured, in which case behaviour is
    /// byte-identical to before.
    ///
    /// `StateStore` rather than the `read_snapshot`/`write_snapshot` free
    /// functions: it enforces "never overwrite a snapshot you could not read"
    /// internally, and a new adopter has no reason to take that on manually.
    state: nextgcore_core::state_store::StateStore,
}

/// Why durable state could not be loaded (issue #66/#192).
#[derive(Debug, thiserror::Error)]
pub enum PcfStateError {
    /// The snapshot file itself could not be read or parsed.
    #[error(transparent)]
    Store(#[from] nextgcore_core::state_store::StateStoreError),
    /// The snapshot was written by a newer build. Refused rather than partially
    /// restored: restoring only what this build recognises and then persisting
    /// would rewrite a newer-format file in the older format, discarding the
    /// rest.
    #[error(
        "state file {path} was written by a newer pcfd (snapshot version {found}; this build \
         understands {supported}). Refusing to restore or overwrite it. Run the newer build, or \
         move the file aside to start fresh."
    )]
    UnsupportedVersion {
        path: std::path::PathBuf,
        found: u64,
        supported: u64,
    },
}

impl PcfContext {
    pub fn new() -> Self {
        Self {
            ue_am_list: RwLock::new(HashMap::new()),
            ue_sm_list: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            app_list: RwLock::new(HashMap::new()),
            supi_am_hash: RwLock::new(HashMap::new()),
            supi_sm_hash: RwLock::new(HashMap::new()),
            ipv4addr_hash: RwLock::new(HashMap::new()),
            ipv6prefix_hash: RwLock::new(HashMap::new()),
            association_id_hash: RwLock::new(HashMap::new()),
            sm_policy_id_hash: RwLock::new(HashMap::new()),
            app_session_id_hash: RwLock::new(HashMap::new()),
            next_ue_am_id: AtomicUsize::new(1),
            next_ue_sm_id: AtomicUsize::new(1),
            next_sess_id: AtomicUsize::new(1),
            next_app_id: AtomicUsize::new(1),
            max_num_of_ue: 0,
            max_num_of_sess: 0,
            initialized: AtomicBool::new(false),
            state: nextgcore_core::state_store::StateStore::disabled(),
        }
    }

    pub fn init(&mut self, max_ue: usize, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_num_of_ue = max_ue;
        self.max_num_of_sess = max_sess;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("PCF context initialized with max {max_ue} UEs, {max_sess} sessions");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        // Issue #66/#192: DISABLE the store before clearing anything. `fini`
        // empties every list, and pcfd has background tasks (the event loop and
        // the intent loop) that can still reach a mutation during shutdown -- so a
        // persist reached afterwards would write an empty snapshot over a good one
        // and lose every live policy association. Disabling first is the only
        // ordering that cannot lose data regardless of what runs next.
        self.state = nextgcore_core::state_store::StateStore::disabled();
        self.ue_am_remove_all();
        self.ue_sm_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("PCF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // ── durable state (issue #66/#192) ───────────────────────────────────────

    /// Snapshot document version. Bump ONLY for a change no `#[serde(default)]`
    /// can absorb; a bump makes every older snapshot unreadable.
    pub const SNAPSHOT_VERSION: u64 = 1;

    /// Point this context at a snapshot file and restore any prior state,
    /// returning how many records were installed.
    ///
    /// Call once at startup, **after** [`init`](Self::init) and **before** the SBI
    /// server can accept a request, so a restored association is never shadowed
    /// by a fresh one.
    ///
    /// An unreadable snapshot is an **error**: the caller should refuse to start
    /// rather than answer "no such association" for associations that exist.
    pub fn set_state_file(&mut self, path: std::path::PathBuf) -> Result<usize, PcfStateError> {
        use nextgcore_core::state_store::{Loaded, StateStore};
        self.state = StateStore::new(Some(path.clone()));
        match self.state.load()? {
            Loaded::Snapshot(doc) => {
                let restored = self.restore_from(&doc, &path);
                if restored.is_err() {
                    // The store is not poisoned (the load itself succeeded), so a
                    // caller that logs and carries on could otherwise overwrite a
                    // snapshot this build cannot fully read. Disable instead.
                    self.state = StateStore::disabled();
                }
                restored
            }
            Loaded::Absent => Ok(0),
        }
    }

    /// Serialize the four primary lists to one snapshot document.
    ///
    /// **Takes one lock at a time, holding at most one at any instant.**
    /// `context.rs` carries six documented AB-BA lock-inversion fixes, each
    /// naming a pair that deadlocked; a function holding four guards at once
    /// would be a seventh waiting to happen. Cloning each list out and dropping
    /// its guard before taking the next means this function cannot participate in
    /// any cycle, whatever order the mutators use.
    ///
    /// The cost is that the document is not one atomic instant across all four
    /// lists. That is acceptable: every mutation persists immediately after its
    /// guards drop, so the next write reconciles any skew — and the alternative
    /// risks wedging the NF, which no amount of snapshot precision is worth.
    ///
    /// The seven secondary indexes are deliberately absent; see
    /// [`restore_from`](Self::restore_from).
    fn snapshot(&self) -> serde_json::Value {
        fn sorted<T: Clone, K: Ord>(
            lock: &RwLock<HashMap<u64, T>>,
            key: impl Fn(&T) -> K,
        ) -> Vec<T> {
            let mut v: Vec<T> = lock
                .read()
                .map(|m| m.values().cloned().collect())
                .unwrap_or_default();
            v.sort_by_key(|t| key(t));
            v
        }
        // Each of these acquires and releases before the next begins.
        let ue_ams = sorted(&self.ue_am_list, |u: &PcfUeAm| u.id);
        let ue_sms = sorted(&self.ue_sm_list, |u: &PcfUeSm| u.id);
        let sessions = sorted(&self.sess_list, |s: &PcfSess| s.id);
        let apps = sorted(&self.app_list, |a: &PcfApp| a.id);

        serde_json::json!({
            "version": Self::SNAPSHOT_VERSION,
            "ueAms": ue_ams,
            "ueSms": ue_sms,
            "sessions": sessions,
            "apps": apps,
            // Persisted AND recomputed on restore -- see restore_from.
            "nextIds": {
                "ueAm": self.next_ue_am_id.load(Ordering::SeqCst),
                "ueSm": self.next_ue_sm_id.load(Ordering::SeqCst),
                "sess": self.next_sess_id.load(Ordering::SeqCst),
                "app": self.next_app_id.load(Ordering::SeqCst),
            },
        })
    }

    /// Restore the four primary lists, **rebuild all seven secondary indexes**,
    /// and lift every id allocator above the restored maximum.
    ///
    /// # Why indexes are rebuilt rather than persisted
    ///
    /// All seven are derivable from the primary lists, and a persisted index can
    /// *disagree* with its list — after a schema change, or a snapshot written
    /// mid-mutation. A disagreeing index is worse than a missing one:
    /// `sess_find_by_sm_policy_id` would return a stale id resolving to a
    /// **different** session, or to nothing while the session is sitting right
    /// there. Deriving makes disagreement impossible by construction.
    ///
    /// This is #192's BSF criterion generalised — *"a restored binding is
    /// discoverable by the same query that found it before the restart"* — and
    /// here that means all six lookup paths, not just the primary key.
    ///
    /// # Why every allocator must be lifted
    ///
    /// The counters start at 1. Left alone, the first association created after a
    /// restart takes id 1, which a restored record already holds, and
    /// `insert` **silently replaces it** — leaving `supi_am_hash` and
    /// `association_id_hash` pointing at a record for a different subscriber.
    /// That is data *substitution*, not loss, and nothing logs it. Same shape as
    /// #191's IP pool, times four.
    ///
    /// Each counter becomes `max(persisted, max_restored_id + 1)`: persisting
    /// alone trusts a value that could predate the records, recomputing alone
    /// would reuse a deleted record's id.
    fn restore_from(
        &self,
        doc: &serde_json::Value,
        path: &std::path::Path,
    ) -> Result<usize, PcfStateError> {
        let found = doc
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(Self::SNAPSHOT_VERSION);
        if found > Self::SNAPSHOT_VERSION {
            return Err(PcfStateError::UnsupportedVersion {
                path: path.to_path_buf(),
                found,
                supported: Self::SNAPSHOT_VERSION,
            });
        }

        /// Deserialize an array member, skipping individual malformed records:
        /// the file was already validated as JSON by the store, so a bad record
        /// means a schema change, not corruption.
        fn records<T: serde::de::DeserializeOwned>(doc: &serde_json::Value, key: &str) -> Vec<T> {
            doc.get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| match serde_json::from_value::<T>(v.clone()) {
                            Ok(t) => Some(t),
                            Err(e) => {
                                log::warn!("skipping unreadable PCF {key} record: {e}");
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default()
        }

        let ue_ams: Vec<PcfUeAm> = records(doc, "ueAms");
        let ue_sms: Vec<PcfUeSm> = records(doc, "ueSms");
        let sessions: Vec<PcfSess> = records(doc, "sessions");
        let apps: Vec<PcfApp> = records(doc, "apps");
        let restored = ue_ams.len() + ue_sms.len() + sessions.len() + apps.len();

        let mut max_ue_am = 0u64;
        let mut max_ue_sm = 0u64;
        let mut max_sess = 0u64;
        let mut max_app = 0u64;

        // ── primary lists + the indexes derived from each ────────────────────
        if let (Ok(mut list), Ok(mut supi_hash), Ok(mut assoc_hash)) = (
            self.ue_am_list.write(),
            self.supi_am_hash.write(),
            self.association_id_hash.write(),
        ) {
            for ue_am in ue_ams {
                max_ue_am = max_ue_am.max(ue_am.id);
                supi_hash.insert(ue_am.supi.clone(), ue_am.id);
                assoc_hash.insert(ue_am.association_id.clone(), ue_am.id);
                list.insert(ue_am.id, ue_am);
            }
        }
        if let (Ok(mut list), Ok(mut supi_hash)) =
            (self.ue_sm_list.write(), self.supi_sm_hash.write())
        {
            for ue_sm in ue_sms {
                max_ue_sm = max_ue_sm.max(ue_sm.id);
                supi_hash.insert(ue_sm.supi.clone(), ue_sm.id);
                list.insert(ue_sm.id, ue_sm);
            }
        }
        if let (Ok(mut list), Ok(mut policy_hash), Ok(mut v4), Ok(mut v6)) = (
            self.sess_list.write(),
            self.sm_policy_id_hash.write(),
            self.ipv4addr_hash.write(),
            self.ipv6prefix_hash.write(),
        ) {
            for sess in sessions {
                max_sess = max_sess.max(sess.id);
                policy_hash.insert(sess.sm_policy_id.clone(), sess.id);
                // Same conditions sess_remove/sess_update use, so the rebuilt
                // index has exactly the entries the live one would have.
                if sess.ipv4addr != 0 {
                    v4.insert(sess.ipv4addr, sess.id);
                }
                if let Some(ref prefix) = sess.ipv6prefix_string {
                    v6.insert(prefix.clone(), sess.id);
                }
                list.insert(sess.id, sess);
            }
        }
        if let (Ok(mut list), Ok(mut app_hash)) =
            (self.app_list.write(), self.app_session_id_hash.write())
        {
            for app in apps {
                max_app = max_app.max(app.id);
                app_hash.insert(app.app_session_id.clone(), app.id);
                list.insert(app.id, app);
            }
        }

        // ── allocators, lifted above both the persisted counter and the data ──
        let persisted = |key: &str| -> usize {
            doc.pointer(&format!("/nextIds/{key}"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize
        };
        for (counter, key, max_id) in [
            (&self.next_ue_am_id, "ueAm", max_ue_am),
            (&self.next_ue_sm_id, "ueSm", max_ue_sm),
            (&self.next_sess_id, "sess", max_sess),
            (&self.next_app_id, "app", max_app),
        ] {
            let floor = (max_id as usize).saturating_add(1);
            let next = persisted(key).max(floor).max(1);
            counter.store(next, Ordering::SeqCst);
        }

        log::info!(
            "PCF durable state restored: {restored} record(s); next ids am={} sm={} sess={} app={}",
            self.next_ue_am_id.load(Ordering::SeqCst),
            self.next_ue_sm_id.load(Ordering::SeqCst),
            self.next_sess_id.load(Ordering::SeqCst),
            self.next_app_id.load(Ordering::SeqCst),
        );
        Ok(restored)
    }

    /// Write the snapshot after a mutation. A no-op with no state file, and
    /// refused (loudly) when the previous load failed.
    ///
    /// **Every caller must have dropped its write guards first.** `persist` ->
    /// `snapshot` takes read locks on the same lists and `std::sync::RwLock` is
    /// not reentrant; the mutators here hold up to five guards at once, so this is
    /// the sharpest version of the rule #197 and #198 already follow.
    ///
    /// Synchronous on every mutation, with no deferred flush: unlike nwdafd,
    /// pcfd has no periodic sweep rewriting every record, so each write is one
    /// consumer request rather than N-per-tick.
    fn persist(&self) {
        if !self.state.is_enabled() {
            return;
        }
        let doc = self.snapshot();
        if let Err(e) = self.state.persist(&doc) {
            // The association exists in memory but not on disk: the request was
            // answered and will not survive a restart.
            log::error!("PCF state was NOT persisted: {e}");
        }
    }

    /// Whether durable state is configured (introspection/tests).
    pub fn state_is_enabled(&self) -> bool {
        self.state.is_enabled()
    }

    // UE AM management

    pub fn ue_am_add(&self, supi: &str) -> Option<PcfUeAm> {
        let mut ue_am_list = self.ue_am_list.write().ok()?;
        let mut supi_am_hash = self.supi_am_hash.write().ok()?;
        let mut association_id_hash = self.association_id_hash.write().ok()?;

        if ue_am_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UE AMs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_am_id.fetch_add(1, Ordering::SeqCst) as u64;
        let ue_am = PcfUeAm::new(id, supi);

        supi_am_hash.insert(supi.to_string(), id);
        association_id_hash.insert(ue_am.association_id.clone(), id);
        ue_am_list.insert(id, ue_am.clone());

        log::debug!("[{supi}] PCF UE AM added (id={id})");
        // Guards MUST drop before persisting: persist -> snapshot read-locks this
        // same list and std RwLock is not reentrant (issue #66/#192).
        drop((ue_am_list, supi_am_hash, association_id_hash));
        self.persist();
        Some(ue_am)
    }

    pub fn ue_am_remove(&self, id: u64) -> Option<PcfUeAm> {
        let mut ue_am_list = self.ue_am_list.write().ok()?;
        let mut supi_am_hash = self.supi_am_hash.write().ok()?;
        let mut association_id_hash = self.association_id_hash.write().ok()?;

        if let Some(ue_am) = ue_am_list.remove(&id) {
            supi_am_hash.remove(&ue_am.supi);
            association_id_hash.remove(&ue_am.association_id);
            log::debug!("[{}] PCF UE AM removed (id={})", ue_am.supi, id);
            // Guards dropped before persisting (see ue_am_add). Removals are
            // persisted too, or a restart resurrects an association the AMF
            // explicitly deleted.
            drop((ue_am_list, supi_am_hash, association_id_hash));
            self.persist();
            return Some(ue_am);
        }
        None
    }

    pub fn ue_am_remove_all(&self) {
        if let (Ok(mut ue_am_list), Ok(mut supi_am_hash), Ok(mut association_id_hash)) = (
            self.ue_am_list.write(),
            self.supi_am_hash.write(),
            self.association_id_hash.write(),
        ) {
            ue_am_list.clear();
            supi_am_hash.clear();
            association_id_hash.clear();
        }
    }

    pub fn ue_am_find_by_supi(&self, supi: &str) -> Option<PcfUeAm> {
        // AB-BA: ue_am_list before supi_am_hash (canonical primary-list-first).
        // ue_am_add/remove take ue_am_list then supi_am_hash, so a hash-first
        // read here inverts that order and deadlocks a concurrent writer
        // (read(supi_am_hash) waits on write, while write(ue_am_list) waits on read).
        let ue_am_list = self.ue_am_list.read().ok()?;
        let supi_am_hash = self.supi_am_hash.read().ok()?;
        supi_am_hash
            .get(supi)
            .and_then(|&id| ue_am_list.get(&id).cloned())
    }

    pub fn ue_am_find_by_association_id(&self, association_id: &str) -> Option<PcfUeAm> {
        // AB-BA: ue_am_list before association_id_hash (canonical
        // primary-list-first; matches ue_am_add/remove).
        let ue_am_list = self.ue_am_list.read().ok()?;
        let association_id_hash = self.association_id_hash.read().ok()?;
        association_id_hash
            .get(association_id)
            .and_then(|&id| ue_am_list.get(&id).cloned())
    }

    pub fn ue_am_find_by_id(&self, id: u64) -> Option<PcfUeAm> {
        let ue_am_list = self.ue_am_list.read().ok()?;
        ue_am_list.get(&id).cloned()
    }

    pub fn ue_am_update(&self, ue_am: &PcfUeAm) -> bool {
        let updated = match self.ue_am_list.write() {
            Ok(mut ue_am_list) => match ue_am_list.get_mut(&ue_am.id) {
                Some(existing) => {
                    *existing = ue_am.clone();
                    true
                }
                None => false,
            },
            Err(_) => false,
        };
        // Guard dropped by the match arm ending -- see ue_am_add.
        if updated {
            self.persist();
        }
        updated
    }

    // UE SM management

    pub fn ue_sm_add(&self, supi: &str) -> Option<PcfUeSm> {
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;
        let mut supi_sm_hash = self.supi_sm_hash.write().ok()?;

        if ue_sm_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UE SMs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_sm_id.fetch_add(1, Ordering::SeqCst) as u64;
        let ue_sm = PcfUeSm::new(id, supi);

        supi_sm_hash.insert(supi.to_string(), id);
        ue_sm_list.insert(id, ue_sm.clone());

        log::debug!("[{supi}] PCF UE SM added (id={id})");
        drop((ue_sm_list, supi_sm_hash));
        self.persist();
        Some(ue_sm)
    }

    pub fn ue_sm_remove(&self, id: u64) -> Option<PcfUeSm> {
        // Remove the UE-SM under the ue_sm_list/supi_sm_hash guards, then DROP
        // them before touching sess_list. Holding ue_sm_list while acquiring
        // sess_list (via sess_remove_all_for_ue) inverts the canonical
        // sess_list -> ue_sm_list order used by sess_add/sess_remove and
        // deadlocks under concurrent SBI requests (AB-BA lock inversion).
        let ue_sm = {
            let mut ue_sm_list = self.ue_sm_list.write().ok()?;
            let mut supi_sm_hash = self.supi_sm_hash.write().ok()?;
            let ue_sm = ue_sm_list.remove(&id)?;
            supi_sm_hash.remove(&ue_sm.supi);
            ue_sm
        };
        // Guards released: safe to take sess_list in the canonical order.
        self.sess_remove_all_for_ue(id);
        log::debug!("[{}] PCF UE SM removed (id={})", ue_sm.supi, id);
        // Persisted once, after the cascade: sess_remove_all_for_ue drops the
        // UE's sessions too, so a persist before it would snapshot sessions whose
        // parent is already gone.
        self.persist();
        Some(ue_sm)
    }

    pub fn ue_sm_remove_all(&self) {
        if let (Ok(mut ue_sm_list), Ok(mut supi_sm_hash)) =
            (self.ue_sm_list.write(), self.supi_sm_hash.write())
        {
            ue_sm_list.clear();
            supi_sm_hash.clear();
        }
        // Clear sessions and apps
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.clear();
        }
        if let Ok(mut app_list) = self.app_list.write() {
            app_list.clear();
        }
    }

    pub fn ue_sm_find_by_supi(&self, supi: &str) -> Option<PcfUeSm> {
        // AB-BA: ue_sm_list before supi_sm_hash (canonical primary-list-first;
        // matches ue_sm_add, which takes ue_sm_list then supi_sm_hash).
        let ue_sm_list = self.ue_sm_list.read().ok()?;
        let supi_sm_hash = self.supi_sm_hash.read().ok()?;
        supi_sm_hash
            .get(supi)
            .and_then(|&id| ue_sm_list.get(&id).cloned())
    }

    pub fn ue_sm_find_by_id(&self, id: u64) -> Option<PcfUeSm> {
        let ue_sm_list = self.ue_sm_list.read().ok()?;
        ue_sm_list.get(&id).cloned()
    }

    pub fn ue_sm_update(&self, ue_sm: &PcfUeSm) -> bool {
        let updated = match self.ue_sm_list.write() {
            Ok(mut ue_sm_list) => match ue_sm_list.get_mut(&ue_sm.id) {
                Some(existing) => {
                    *existing = ue_sm.clone();
                    true
                }
                None => false,
            },
            Err(_) => false,
        };
        if updated {
            self.persist();
        }
        updated
    }

    // Session management

    pub fn sess_add(&self, pcf_ue_sm_id: u64, psi: u8) -> Option<PcfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sm_policy_id_hash = self.sm_policy_id_hash.write().ok()?;
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!(
                "Maximum number of sessions [{}] reached",
                self.max_num_of_sess
            );
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let sess = PcfSess::new(id, pcf_ue_sm_id, psi);

        sm_policy_id_hash.insert(sess.sm_policy_id.clone(), id);
        sess_list.insert(id, sess.clone());

        // Add session ID to UE SM
        if let Some(ue_sm) = ue_sm_list.get_mut(&pcf_ue_sm_id) {
            ue_sm.sess_ids.push(id);
        }

        log::debug!("[ue_sm_id={pcf_ue_sm_id}, psi={psi}] PCF session added (id={id})");
        drop((sess_list, sm_policy_id_hash, ue_sm_list));
        self.persist();
        Some(sess)
    }

    pub fn sess_remove(&self, id: u64) -> Option<PcfSess> {
        // The five guards are scoped so they DROP before persisting: persist ->
        // snapshot read-locks sess_list and ue_sm_list, and std RwLock is not
        // reentrant, so persisting inside this block deadlocks (issue #66/#192).
        let sess = {
            let mut sess_list = self.sess_list.write().ok()?;
            let mut sm_policy_id_hash = self.sm_policy_id_hash.write().ok()?;
            let mut ipv4addr_hash = self.ipv4addr_hash.write().ok()?;
            let mut ipv6prefix_hash = self.ipv6prefix_hash.write().ok()?;
            let mut ue_sm_list = self.ue_sm_list.write().ok()?;

            let sess = sess_list.remove(&id)?;
            sm_policy_id_hash.remove(&sess.sm_policy_id);
            if sess.ipv4addr != 0 {
                ipv4addr_hash.remove(&sess.ipv4addr);
            }
            if let Some(ref prefix_str) = sess.ipv6prefix_string {
                ipv6prefix_hash.remove(prefix_str);
            }
            // Remove session ID from UE SM
            if let Some(ue_sm) = ue_sm_list.get_mut(&sess.pcf_ue_sm_id) {
                ue_sm.sess_ids.retain(|&sid| sid != id);
            }
            sess
        };
        // Remove all apps for this session. Outside the block: it takes app_list,
        // and the canonical order is sess_list before app_list -- which held here
        // would be an inversion the moment app_remove_all_for_sess grew a
        // sess_list access.
        self.app_remove_all_for_sess(id);
        log::debug!("[psi={}] PCF session removed (id={})", sess.psi, id);
        // Persisted after the app cascade, so the snapshot cannot contain app
        // sessions whose parent session is already gone.
        self.persist();
        Some(sess)
    }

    fn sess_remove_all_for_ue(&self, pcf_ue_sm_id: u64) {
        if let Ok(mut sess_list) = self.sess_list.write() {
            let sess_ids: Vec<u64> = sess_list
                .values()
                .filter(|s| s.pcf_ue_sm_id == pcf_ue_sm_id)
                .map(|s| s.id)
                .collect();
            for id in sess_ids {
                sess_list.remove(&id);
            }
        }
    }

    pub fn sess_find_by_id(&self, id: u64) -> Option<PcfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&id).cloned()
    }

    pub fn sess_find_by_sm_policy_id(&self, sm_policy_id: &str) -> Option<PcfSess> {
        // AB-BA: sess_list before sm_policy_id_hash (canonical primary-list-first).
        // sess_add/sess_remove take sess_list then sm_policy_id_hash, so a
        // hash-first read here inverts that order and deadlocks a concurrent
        // create/delete — this is the cycle the concurrent sm_policy_* handler
        // tests hit (the 2fbcae0 fix normalized only the list<->list edges).
        let sess_list = self.sess_list.read().ok()?;
        let sm_policy_id_hash = self.sm_policy_id_hash.read().ok()?;
        sm_policy_id_hash
            .get(sm_policy_id)
            .and_then(|&id| sess_list.get(&id).cloned())
    }

    pub fn sess_find_by_psi(&self, pcf_ue_sm_id: u64, psi: u8) -> Option<PcfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list
            .values()
            .find(|s| s.pcf_ue_sm_id == pcf_ue_sm_id && s.psi == psi)
            .cloned()
    }

    pub fn sess_find_by_ipv4addr(&self, ipv4addr_string: &str) -> Option<PcfSess> {
        if let Ok(addr) = ipv4addr_string.parse::<std::net::Ipv4Addr>() {
            let ipv4addr = u32::from(addr);
            // AB-BA: sess_list before ipv4addr_hash (canonical primary-list-first;
            // sess_remove/sess_update take sess_list then ipv4addr_hash).
            let sess_list = self.sess_list.read().ok()?;
            let ipv4addr_hash = self.ipv4addr_hash.read().ok()?;
            return ipv4addr_hash
                .get(&ipv4addr)
                .and_then(|&id| sess_list.get(&id).cloned());
        }
        None
    }

    pub fn sess_find_by_ipv6addr(&self, ipv6prefix_string: &str) -> Option<PcfSess> {
        // AB-BA: sess_list before ipv6prefix_hash (canonical primary-list-first;
        // sess_remove/sess_update take sess_list then ipv6prefix_hash).
        let sess_list = self.sess_list.read().ok()?;
        let ipv6prefix_hash = self.ipv6prefix_hash.read().ok()?;
        ipv6prefix_hash
            .get(ipv6prefix_string)
            .and_then(|&id| sess_list.get(&id).cloned())
    }

    pub fn sess_update(&self, sess: &PcfSess) -> bool {
        let updated = self.sess_update_locked(sess);
        // Guards dropped inside the helper -- see sess_remove.
        if updated {
            self.persist();
        }
        updated
    }

    /// The lock-holding half of [`sess_update`](Self::sess_update). Split out so
    /// the guards are released by returning, which is what lets the caller
    /// persist without deadlocking.
    fn sess_update_locked(&self, sess: &PcfSess) -> bool {
        if let (Ok(mut sess_list), Ok(mut ipv4addr_hash), Ok(mut ipv6prefix_hash)) = (
            self.sess_list.write(),
            self.ipv4addr_hash.write(),
            self.ipv6prefix_hash.write(),
        ) {
            if let Some(existing) = sess_list.get_mut(&sess.id) {
                // Update IPv4 hash if changed
                if existing.ipv4addr != sess.ipv4addr {
                    if existing.ipv4addr != 0 {
                        ipv4addr_hash.remove(&existing.ipv4addr);
                    }
                    if sess.ipv4addr != 0 {
                        ipv4addr_hash.insert(sess.ipv4addr, sess.id);
                    }
                }
                // Update IPv6 hash if changed
                if existing.ipv6prefix_string != sess.ipv6prefix_string {
                    if let Some(ref old_prefix) = existing.ipv6prefix_string {
                        ipv6prefix_hash.remove(old_prefix);
                    }
                    if let Some(ref new_prefix) = sess.ipv6prefix_string {
                        ipv6prefix_hash.insert(new_prefix.clone(), sess.id);
                    }
                }
                *existing = sess.clone();
                return true;
            }
        }
        false
    }

    pub fn sessions_number_by_snssai_and_dnn(
        &self,
        pcf_ue_sm_id: u64,
        s_nssai: &SNssai,
        dnn: &str,
    ) -> usize {
        if let Ok(sess_list) = self.sess_list.read() {
            return sess_list
                .values()
                .filter(|s| {
                    s.pcf_ue_sm_id == pcf_ue_sm_id
                        && &s.s_nssai == s_nssai
                        && s.dnn.as_deref() == Some(dnn)
                })
                .count();
        }
        0
    }

    // App session management

    pub fn app_add(&self, sess_id: u64) -> Option<PcfApp> {
        // Canonical lock order is sess_list before app_list: sess_remove holds
        // sess_list then takes app_list (via app_remove_all_for_sess), so
        // app_add/app_remove MUST take sess_list first too — acquiring app_list
        // then sess_list here would deadlock against a concurrent sess_remove
        // (AB-BA lock inversion).
        let mut sess_list = self.sess_list.write().ok()?;
        let mut app_list = self.app_list.write().ok()?;
        let mut app_session_id_hash = self.app_session_id_hash.write().ok()?;

        let id = self.next_app_id.fetch_add(1, Ordering::SeqCst) as u64;
        let app = PcfApp::new(id, sess_id);

        app_session_id_hash.insert(app.app_session_id.clone(), id);
        app_list.insert(id, app.clone());

        // Add app ID to session
        if let Some(sess) = sess_list.get_mut(&sess_id) {
            sess.app_ids.push(id);
        }

        log::debug!("[sess_id={sess_id}] PCF app added (id={id})");
        drop((sess_list, app_list, app_session_id_hash));
        self.persist();
        Some(app)
    }

    pub fn app_remove(&self, id: u64) -> Option<PcfApp> {
        // Canonical lock order: sess_list before app_list (see app_add).
        let mut sess_list = self.sess_list.write().ok()?;
        let mut app_list = self.app_list.write().ok()?;
        let mut app_session_id_hash = self.app_session_id_hash.write().ok()?;

        if let Some(app) = app_list.remove(&id) {
            app_session_id_hash.remove(&app.app_session_id);
            // Remove app ID from session
            if let Some(sess) = sess_list.get_mut(&app.sess_id) {
                sess.app_ids.retain(|&aid| aid != id);
            }
            log::debug!("PCF app removed (id={id})");
            drop((sess_list, app_list, app_session_id_hash));
            self.persist();
            return Some(app);
        }
        None
    }

    fn app_remove_all_for_sess(&self, sess_id: u64) {
        if let Ok(mut app_list) = self.app_list.write() {
            let app_ids: Vec<u64> = app_list
                .values()
                .filter(|a| a.sess_id == sess_id)
                .map(|a| a.id)
                .collect();
            for id in app_ids {
                app_list.remove(&id);
            }
        }
    }

    pub fn app_find_by_id(&self, id: u64) -> Option<PcfApp> {
        let app_list = self.app_list.read().ok()?;
        app_list.get(&id).cloned()
    }

    pub fn app_find_by_app_session_id(&self, app_session_id: &str) -> Option<PcfApp> {
        // AB-BA: app_list before app_session_id_hash (canonical primary-list-first;
        // app_add/app_remove take sess_list then app_list then app_session_id_hash).
        let app_list = self.app_list.read().ok()?;
        let app_session_id_hash = self.app_session_id_hash.read().ok()?;
        app_session_id_hash
            .get(app_session_id)
            .and_then(|&id| app_list.get(&id).cloned())
    }

    pub fn app_update(&self, app: &PcfApp) -> bool {
        let updated = match self.app_list.write() {
            Ok(mut app_list) => match app_list.get_mut(&app.id) {
                Some(existing) => {
                    *existing = app.clone();
                    true
                }
                None => false,
            },
            Err(_) => false,
        };
        if updated {
            self.persist();
        }
        updated
    }

    /// Get instance load percentage
    pub fn get_load(&self) -> i32 {
        let ue_am_count = self.ue_am_list.read().map(|l| l.len()).unwrap_or(0);
        let ue_sm_count = self.ue_sm_list.read().map(|l| l.len()).unwrap_or(0);
        let total = ue_am_count + ue_sm_count;
        let max = self.max_num_of_ue * 2;
        if max == 0 {
            return 0;
        }
        ((total * 100) / max) as i32
    }

    pub fn ue_am_count(&self) -> usize {
        self.ue_am_list.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn ue_sm_count(&self) -> usize {
        self.ue_sm_list.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn app_count(&self) -> usize {
        self.app_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl Default for PcfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global PCF context (thread-safe singleton)
static GLOBAL_PCF_CONTEXT: std::sync::OnceLock<Arc<RwLock<PcfContext>>> =
    std::sync::OnceLock::new();

/// Get the global PCF context
pub fn pcf_self() -> Arc<RwLock<PcfContext>> {
    GLOBAL_PCF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(PcfContext::new())))
        .clone()
}

/// Initialize the global PCF context
pub fn pcf_context_init(max_ue: usize, max_sess: usize) {
    let ctx = pcf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_ue, max_sess);
    };
}

/// Finalize the global PCF context
pub fn pcf_context_final() {
    let ctx = pcf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get instance load (for NF instance load reporting)
pub fn pcf_instance_get_load() -> i32 {
    let ctx = pcf_self();
    if let Ok(context) = ctx.read() {
        return context.get_load();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcf_context_new() {
        let ctx = PcfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.ue_am_count(), 0);
        assert_eq!(ctx.ue_sm_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_pcf_context_init_fini() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_ue_am_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_am = ctx.ue_am_add("imsi-001010000000001").unwrap();
        assert_eq!(ue_am.supi, "imsi-001010000000001");
        assert_eq!(ctx.ue_am_count(), 1);

        let found = ctx.ue_am_find_by_supi("imsi-001010000000001");
        assert!(found.is_some());

        ctx.ue_am_remove(ue_am.id);
        assert_eq!(ctx.ue_am_count(), 0);
    }

    #[test]
    fn test_ue_sm_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        assert_eq!(ue_sm.supi, "imsi-001010000000001");
        assert_eq!(ctx.ue_sm_count(), 1);

        ctx.ue_sm_remove(ue_sm.id);
        assert_eq!(ctx.ue_sm_count(), 0);
    }

    #[test]
    fn test_sess_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add(ue_sm.id, 1).unwrap();
        assert_eq!(sess.psi, 1);
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_psi(ue_sm.id, 1);
        assert!(found.is_some());

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_app_add_remove() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        let sess = ctx.sess_add(ue_sm.id, 1).unwrap();
        let app = ctx.app_add(sess.id).unwrap();
        assert_eq!(ctx.app_count(), 1);

        ctx.app_remove(app.id);
        assert_eq!(ctx.app_count(), 0);
    }

    #[test]
    fn test_sess_ipv4_lookup() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").unwrap();
        let mut sess = ctx.sess_add(ue_sm.id, 1).unwrap();
        sess.set_ipv4addr("10.45.0.1");
        ctx.sess_update(&sess);

        let found = ctx.sess_find_by_ipv4addr("10.45.0.1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().psi, 1);
    }

    // ── durable state (issue #66/#192) ───────────────────────────────────────

    /// Unique snapshot path per test so parallel runs cannot collide.
    fn temp_state_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nextgcore-pcf-state-{}-{tag}-{nanos}.json",
            std::process::id()
        ))
    }

    fn ctx_with_state(path: &std::path::Path) -> PcfContext {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);
        ctx.set_state_file(path.to_path_buf())
            .expect("arming a fresh state file must succeed");
        ctx
    }

    /// Populate one of everything, with the nested trees filled in so a round
    /// trip exercises more than the top level.
    fn populate(ctx: &PcfContext) -> (PcfUeAm, PcfUeSm, PcfSess, PcfApp) {
        let mut ue_am = ctx.ue_am_add("imsi-001010000000001").expect("am");
        ue_am.gpsi = Some("msisdn-491700000001".to_string());
        ue_am.access_type = AccessType::NonThreeGppAccess;
        ue_am.rat_type = RatType::Eutra;
        ue_am.subscribed_ue_ambr = Some(Ambr {
            uplink: "1 Gbps".to_string(),
            downlink: "2 Gbps".to_string(),
        });
        ue_am.generate_default_ursp_rules();
        assert!(ctx.ue_am_update(&ue_am));

        let ue_sm = ctx.ue_sm_add("imsi-001010000000001").expect("sm");
        let mut sess = ctx.sess_add(ue_sm.id, 5).expect("sess");
        sess.dnn = Some("internet".to_string());
        sess.pdu_session_type = PduSessionType::Ipv4v6;
        sess.s_nssai = SNssai {
            sst: 1,
            sd: Some(0x0a_bc_de),
        };
        sess.binding.store("http://bsf/pcfBindings/b1", "b1");
        sess.subscribed_default_qos = Some(SubscribedDefaultQos {
            five_qi: 9,
            priority_level: 8,
            arp_priority_level: 7,
            arp_preempt_cap: true,
            arp_preempt_vuln: false,
        });
        assert!(sess.set_ipv4addr("10.45.0.7"));
        assert!(sess.set_ipv6prefix("2001:db8::/64"));
        assert!(ctx.sess_update(&sess));

        let app = ctx.app_add(sess.id).expect("app");
        // Re-read so the callers see the stored (index-consistent) copies.
        (
            ctx.ue_am_find_by_id(ue_am.id).expect("am stored"),
            ctx.ue_sm_find_by_id(ue_sm.id).expect("sm stored"),
            ctx.sess_find_by_id(sess.id).expect("sess stored"),
            ctx.app_find_by_id(app.id).expect("app stored"),
        )
    }

    /// **Issue #192, the acceptance criterion.** All four primary lists survive a
    /// simulated restart with their nested trees intact.
    #[test]
    fn associations_survive_a_restart() {
        let path = temp_state_path("restart");
        let (ue_am, ue_sm, sess, app) = {
            let ctx = ctx_with_state(&path);
            populate(&ctx)
        };

        let restored = ctx_with_state(&path);
        assert_eq!(restored.ue_am_count(), 1);
        assert_eq!(restored.ue_sm_count(), 1);
        assert_eq!(restored.sess_count(), 1);
        assert_eq!(restored.app_count(), 1);

        let r_am = restored.ue_am_find_by_id(ue_am.id).expect("am back");
        assert_eq!(r_am.supi, "imsi-001010000000001");
        assert_eq!(r_am.gpsi.as_deref(), Some("msisdn-491700000001"));
        assert_eq!(r_am.access_type, AccessType::NonThreeGppAccess);
        assert_eq!(r_am.rat_type, RatType::Eutra);
        assert_eq!(r_am.association_id, ue_am.association_id);
        assert_eq!(
            r_am.subscribed_ue_ambr.as_ref().map(|a| a.uplink.as_str()),
            Some("1 Gbps")
        );
        assert_eq!(r_am.ursp_rules.len(), 3, "the URSP tree must survive");
        assert_eq!(
            r_am.ursp_rules[0].route_selection_descriptors[0].pdu_session_type,
            Some(PduSessionType::Ipv4v6)
        );
        assert_eq!(
            r_am.ursp_rules[2].traffic_descriptors[0].s_nssai,
            Some(SNssai { sst: 4, sd: None })
        );

        let r_sess = restored.sess_find_by_id(sess.id).expect("sess back");
        assert_eq!(r_sess.psi, 5);
        assert_eq!(r_sess.dnn.as_deref(), Some("internet"));
        assert_eq!(r_sess.pdu_session_type, PduSessionType::Ipv4v6);
        assert_eq!(
            r_sess.s_nssai,
            SNssai {
                sst: 1,
                sd: Some(0x0a_bc_de)
            }
        );
        assert_eq!(r_sess.sm_policy_id, sess.sm_policy_id);
        assert!(
            r_sess.binding.is_associated(),
            "the BSF binding must survive"
        );
        assert_eq!(r_sess.binding.id.as_deref(), Some("b1"));
        assert_eq!(
            r_sess.subscribed_default_qos.as_ref().map(|q| q.five_qi),
            Some(9)
        );
        assert_eq!(r_sess.ipv4addr, sess.ipv4addr);
        assert_eq!(r_sess.pcf_ue_sm_id, ue_sm.id);

        let r_sm = restored.ue_sm_find_by_id(ue_sm.id).expect("sm back");
        assert_eq!(
            r_sm.sess_ids,
            vec![sess.id],
            "the parent's session list must survive, or is_last_session lies"
        );
        let r_app = restored.app_find_by_id(app.id).expect("app back");
        assert_eq!(r_app.app_session_id, app.app_session_id);
        assert_eq!(r_app.sess_id, sess.id);

        let _ = std::fs::remove_file(&path);
    }

    /// **The #192 BSF criterion, generalised.** A restored record must be
    /// discoverable by the *same query* that found it before the restart — for
    /// every one of the six lookup paths, not just the primary key.
    ///
    /// The seven secondary indexes are rebuilt from the primary lists rather than
    /// persisted, so this is what proves the rebuild covers them all. Revert-verified:
    /// dropping any one index insert from `restore_from` fails exactly its assertion.
    #[test]
    fn every_lookup_index_is_rebuilt_after_a_restart() {
        let path = temp_state_path("indexes");
        let (ue_am, ue_sm, sess, app) = {
            let ctx = ctx_with_state(&path);
            populate(&ctx)
        };

        let r = ctx_with_state(&path);

        // ue_am_list: supi_am_hash, association_id_hash
        assert_eq!(
            r.ue_am_find_by_supi("imsi-001010000000001").map(|u| u.id),
            Some(ue_am.id),
            "supi_am_hash"
        );
        assert_eq!(
            r.ue_am_find_by_association_id(&ue_am.association_id)
                .map(|u| u.id),
            Some(ue_am.id),
            "association_id_hash"
        );
        // ue_sm_list: supi_sm_hash
        assert_eq!(
            r.ue_sm_find_by_supi("imsi-001010000000001").map(|u| u.id),
            Some(ue_sm.id),
            "supi_sm_hash"
        );
        // sess_list: sm_policy_id_hash, ipv4addr_hash, ipv6prefix_hash
        assert_eq!(
            r.sess_find_by_sm_policy_id(&sess.sm_policy_id)
                .map(|s| s.id),
            Some(sess.id),
            "sm_policy_id_hash -- the SMF's resource URI resolves through this"
        );
        assert_eq!(
            r.sess_find_by_ipv4addr("10.45.0.7").map(|s| s.id),
            Some(sess.id),
            "ipv4addr_hash"
        );
        assert_eq!(
            r.sess_find_by_ipv6addr("2001:db8::/64").map(|s| s.id),
            Some(sess.id),
            "ipv6prefix_hash"
        );
        // app_list: app_session_id_hash
        assert_eq!(
            r.app_find_by_app_session_id(&app.app_session_id)
                .map(|a| a.id),
            Some(app.id),
            "app_session_id_hash"
        );
        // And the non-indexed scan still works.
        assert_eq!(
            r.sess_find_by_psi(ue_sm.id, 5).map(|s| s.id),
            Some(sess.id),
            "sess_find_by_psi"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// **The substitution bug.** Every id allocator must resume above the restored
    /// maximum.
    ///
    /// Left at 1, the first association created after a restart takes an id a
    /// restored record already holds, and `HashMap::insert` SILENTLY REPLACES it —
    /// leaving the indexes pointing at a record for a different subscriber. That is
    /// data substitution rather than loss, and nothing logs it. Same class as
    /// #191's IP pool, once per allocator.
    ///
    /// Revert-verified: removing the allocator lift from `restore_from` fails this.
    #[test]
    fn id_allocators_do_not_collide_with_restored_records() {
        let path = temp_state_path("allocators");
        let (ue_am, ue_sm, sess, app) = {
            let ctx = ctx_with_state(&path);
            populate(&ctx)
        };

        let r = ctx_with_state(&path);

        // Each allocator, exercised by creating a fresh record of that kind.
        let new_am = r.ue_am_add("imsi-001010000000002").expect("new am");
        assert_ne!(new_am.id, ue_am.id, "UE AM id collided with a restored one");
        let new_sm = r.ue_sm_add("imsi-001010000000002").expect("new sm");
        assert_ne!(new_sm.id, ue_sm.id, "UE SM id collided");
        let new_sess = r.sess_add(new_sm.id, 6).expect("new sess");
        assert_ne!(new_sess.id, sess.id, "session id collided");
        let new_app = r.app_add(new_sess.id).expect("new app");
        assert_ne!(new_app.id, app.id, "app id collided");

        // Nothing restored was replaced, and both generations coexist.
        assert_eq!(r.ue_am_count(), 2);
        assert_eq!(r.ue_sm_count(), 2);
        assert_eq!(r.sess_count(), 2);
        assert_eq!(r.app_count(), 2);
        assert_eq!(
            r.ue_am_find_by_id(ue_am.id).map(|u| u.supi),
            Some("imsi-001010000000001".to_string()),
            "the restored association must still be itself, not the new subscriber"
        );
        assert_eq!(
            r.ue_am_find_by_supi("imsi-001010000000001").map(|u| u.id),
            Some(ue_am.id),
            "and its index entry must still resolve to it"
        );
        assert_eq!(
            r.sess_find_by_sm_policy_id(&sess.sm_policy_id)
                .map(|s| s.psi),
            Some(5)
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The representation decision, pinned: the on-disk enum token is the TS
    /// 29.571 spelling, never the Rust variant name.
    ///
    /// A switch to `#[derive]` defaults would write `"NonThreeGppAccess"` and make
    /// every existing snapshot unreadable — and because the store refuses to
    /// overwrite what it cannot parse, that surfaces as pcfd FAILING STARTUP after
    /// an upgrade, at the operator's site rather than here.
    #[test]
    fn the_on_disk_enum_representation_is_the_ts_29571_token() {
        let path = temp_state_path("tokens");
        {
            let ctx = ctx_with_state(&path);
            populate(&ctx);
        }
        let raw = std::fs::read_to_string(&path).expect("snapshot written");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

        assert_eq!(doc["ueAms"][0]["access_type"], "NON_3GPP_ACCESS");
        assert_eq!(doc["ueAms"][0]["rat_type"], "EUTRA");
        assert_eq!(doc["sessions"][0]["pdu_session_type"], "IPV4V6");
        assert_eq!(doc["version"], 1);
        for rust_name in [
            "NonThreeGppAccess",
            "ThreeGppAccess",
            "Eutra",
            "Ipv4v6",
            "Unstructured",
        ] {
            assert!(
                !raw.contains(rust_name),
                "{rust_name} is a Rust identifier and must not reach the snapshot"
            );
        }
        // The secondary indexes must NOT be in the document at all -- they are
        // derived, and persisting them is what allows index/list disagreement.
        for index in [
            "supi_am_hash",
            "association_id_hash",
            "supi_sm_hash",
            "sm_policy_id_hash",
            "ipv4addr_hash",
            "ipv6prefix_hash",
            "app_session_id_hash",
        ] {
            assert!(
                !raw.contains(index),
                "{index} is derived on restore and must not be persisted"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    /// The only test that can catch a representation change: every other one
    /// writes and reads with the same build, so it passes whatever the format is.
    /// This restores a snapshot literal committed in the source.
    ///
    /// If it fails, the format changed — restore compatibility, or bump
    /// `SNAPSHOT_VERSION` and accept that older snapshots stop loading. Do NOT
    /// regenerate this literal to make a failure go away; that IS the failure.
    #[test]
    fn a_committed_fixture_snapshot_still_loads() {
        const FIXTURE: &str = r#"{
          "version": 1,
          "ueAms": [{
            "id": 3,
            "association_id": "assoc-fixture",
            "supi": "imsi-001010000000001",
            "notification_uri": "http://amf/npcf-am-policy-notify",
            "gpsi": "msisdn-491700000001",
            "access_type": "NON_3GPP_ACCESS",
            "pei": null,
            "guami": {"plmn_id": {"mcc": "001", "mnc": "01"},
                      "amf_id": {"region": 1, "set": 2, "pointer": 3}},
            "rat_type": "EUTRA",
            "am_policy_control_features": 0,
            "subscribed_ue_ambr": {"uplink": "1 Gbps", "downlink": "2 Gbps"},
            "stream_id": null,
            "ursp_rules": [{
              "precedence": 1,
              "traffic_descriptors": [{
                "app_id": "ims", "ip_descriptor": null, "dnn": "ims",
                "s_nssai": {"sst": 1, "sd": null}, "connection_caps": "IMS"
              }],
              "route_selection_descriptors": [{
                "precedence": 1, "s_nssai": {"sst": 1, "sd": null}, "dnn": "ims",
                "pdu_session_type": "IPV4V6", "ssc_mode": 1,
                "access_type": ["3GPP_ACCESS"]
              }]
            }],
            "is_redcap": false,
            "snpn_nid": null
          }],
          "ueSms": [{"id": 4, "supi": "imsi-001010000000001",
                     "gpsi": null, "sess_ids": [7]}],
          "sessions": [{
            "id": 7,
            "sm_policy_id": "smpol-fixture",
            "binding": {"resource_uri": "http://bsf/pcfBindings/b1", "id": "b1"},
            "psi": 5,
            "pdu_session_type": "IPV4V6",
            "dnn": "internet",
            "full_dnn": null,
            "serving": {"presence": false, "plmn_id": {"mcc": "", "mnc": ""}},
            "home": {"presence": false, "plmn_id": {"mcc": "", "mnc": ""}},
            "notification_uri": null,
            "ipv4addr_string": "10.45.0.7",
            "ipv6prefix_string": "2001:db8::/64",
            "ipv4addr": 170721287,
            "ipv6prefix": null,
            "s_nssai": {"sst": 1, "sd": 703710},
            "smpolicycontrol_features": 0,
            "management_features": 0,
            "policyauthorization_features": 0,
            "subscribed_sess_ambr": null,
            "subscribed_default_qos": {"five_qi": 9, "priority_level": 8,
              "arp_priority_level": 7, "arp_preempt_cap": true,
              "arp_preempt_vuln": false},
            "app_ids": [9],
            "pcf_ue_sm_id": 4,
            "stream_id": null,
            "af_pcc_rules": [{
              "pcc_rule_id": "pcc-1",
              "precedence": 100,
              "flow_infos": [{"flow_description": "permit out ip from any to any",
                              "flow_direction": "BIDIRECTIONAL",
                              "pack_filt_id": "pf1"}],
              "qos_data": {"qos_id": "qos-1", "five_qi": 5, "maxbr_ul": null,
                           "maxbr_dl": null, "gbr_ul": null, "gbr_dl": null},
              "flow_status": "ENABLED_UPLINK"
            }]
          }],
          "apps": [{"id": 9, "app_session_id": "appsess-fixture",
                    "notif_uri": null, "sess_id": 7}],
          "nextIds": {"ueAm": 4, "ueSm": 5, "sess": 8, "app": 10}
        }"#;

        let path = temp_state_path("fixture");
        std::fs::write(&path, FIXTURE).expect("write fixture");
        let ctx = ctx_with_state(&path);

        let am = ctx
            .ue_am_find_by_id(3)
            .expect("the fixture UE AM must restore");
        assert_eq!(am.access_type, AccessType::NonThreeGppAccess);
        assert_eq!(am.rat_type, RatType::Eutra);
        assert_eq!(am.guami.amf_id.set, 2);
        assert_eq!(
            am.ursp_rules[0].traffic_descriptors[0].app_id.as_deref(),
            Some("ims")
        );
        assert_eq!(
            am.ursp_rules[0].route_selection_descriptors[0].access_type,
            Some(vec![AccessType::ThreeGppAccess])
        );

        let sess = ctx
            .sess_find_by_id(7)
            .expect("the fixture session must restore");
        assert_eq!(sess.pdu_session_type, PduSessionType::Ipv4v6);
        assert_eq!(
            sess.s_nssai,
            SNssai {
                sst: 1,
                sd: Some(703_710)
            }
        );
        assert_eq!(
            sess.af_pcc_rules.len(),
            1,
            "the AF PCC rule tree must restore"
        );
        assert_eq!(sess.af_pcc_rules[0].qos_data.five_qi, 5);
        assert_eq!(
            sess.af_pcc_rules[0].flow_status,
            crate::npcf_handler::FlowStatus::EnabledUplink,
            "FlowStatus round-trips through its own wire codec"
        );

        // Indexes rebuilt from the fixture, and allocators lifted clear of it.
        assert_eq!(
            ctx.sess_find_by_sm_policy_id("smpol-fixture").map(|s| s.id),
            Some(7)
        );
        assert_eq!(
            ctx.ue_am_find_by_association_id("assoc-fixture")
                .map(|u| u.id),
            Some(3)
        );
        assert_eq!(
            ctx.app_find_by_app_session_id("appsess-fixture")
                .map(|a| a.id),
            Some(9)
        );
        assert_eq!(
            ctx.sess_find_by_ipv4addr("10.45.0.7").map(|s| s.id),
            Some(7)
        );
        assert_ne!(ctx.ue_am_add("imsi-999").expect("new").id, 3);

        let _ = std::fs::remove_file(&path);
    }

    /// Removals are persisted, or a restart resurrects an association the peer
    /// explicitly deleted — and the PCF would then answer for a policy the SMF
    /// has torn down.
    ///
    /// Revert-verified: dropping the `persist()` from `sess_remove` fails the
    /// on-disk assertion below.
    #[test]
    fn a_deleted_association_is_not_resurrected_by_a_restart() {
        let path = temp_state_path("removal");
        let on_disk_ids = |key: &str| -> Vec<u64> {
            let raw = std::fs::read_to_string(&path).expect("snapshot exists");
            let doc: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
            doc[key]
                .as_array()
                .expect("array")
                .iter()
                .map(|v| v["id"].as_u64().expect("id"))
                .collect()
        };

        let (keep_sess, drop_sess, ue_am) = {
            let ctx = ctx_with_state(&path);
            let ue_sm = ctx.ue_sm_add("imsi-001010000000001").expect("sm");
            let keep = ctx.sess_add(ue_sm.id, 1).expect("s1");
            let drop_s = ctx.sess_add(ue_sm.id, 2).expect("s2");
            let am = ctx.ue_am_add("imsi-001010000000001").expect("am");

            // Each removal must reach disk on its own -- checked immediately, so a
            // later write cannot cover for a missing persist.
            assert!(ctx.sess_remove(drop_s.id).is_some());
            assert_eq!(
                on_disk_ids("sessions"),
                vec![keep.id],
                "the session removal must reach disk by itself"
            );
            assert!(ctx.ue_am_remove(am.id).is_some());
            assert!(
                on_disk_ids("ueAms").is_empty(),
                "and likewise the AM association removal"
            );
            (keep, drop_s, am)
        };

        let r = ctx_with_state(&path);
        assert!(r.sess_find_by_id(keep_sess.id).is_some());
        assert!(
            r.sess_find_by_id(drop_sess.id).is_none(),
            "a deleted session must not come back"
        );
        assert!(r.ue_am_find_by_id(ue_am.id).is_none());
        assert!(
            r.sess_find_by_sm_policy_id(&drop_sess.sm_policy_id)
                .is_none(),
            "nor may its index entry be rebuilt from a resurrected record"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// An unreadable snapshot is an error at startup, not a silent empty boot, and
    /// the file survives for recovery (issue #66/#190).
    #[test]
    fn a_corrupt_snapshot_fails_startup_and_survives() {
        let path = temp_state_path("corrupt");
        let original = r#"{"version": 1, "ueAms": [{"id": 1, "supi"#;
        std::fs::write(&path, original).expect("write");

        let mut ctx = PcfContext::new();
        ctx.init(100, 200);
        let err = ctx
            .set_state_file(path.clone())
            .expect_err("a corrupt snapshot must fail rather than boot empty");
        assert!(matches!(err, PcfStateError::Store(_)), "got {err:?}");
        assert_eq!(ctx.ue_am_count(), 0);

        // The store poisons itself, so a later mutation cannot overwrite the file.
        ctx.ue_am_add("imsi-001010000000009").expect("add");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            original,
            "the unreadable snapshot must survive for recovery"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A snapshot from a NEWER build is refused rather than partially restored,
    /// and persisting is disabled even if the caller ignores the error.
    #[test]
    fn a_newer_snapshot_version_is_refused() {
        let path = temp_state_path("newer");
        let original = r#"{"version": 999, "ueAms": [], "somethingNew": 1}"#;
        std::fs::write(&path, original).expect("write");

        let mut ctx = PcfContext::new();
        ctx.init(100, 200);
        let err = ctx
            .set_state_file(path.clone())
            .expect_err("a newer snapshot must not be restored");
        assert!(
            matches!(
                err,
                PcfStateError::UnsupportedVersion {
                    found: 999,
                    supported: 1,
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(!ctx.state_is_enabled());
        ctx.ue_am_add("imsi-001010000000009").expect("add");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            original,
            "the newer snapshot must survive untouched"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The shipped default: no state file means no file operations at all.
    #[test]
    fn without_a_state_file_nothing_is_persisted() {
        let mut ctx = PcfContext::new();
        ctx.init(100, 200);
        assert!(!ctx.state_is_enabled());
        let (_am, _sm, sess, app) = populate(&ctx);
        assert!(ctx.app_remove(app.id).is_some());
        assert!(ctx.sess_remove(sess.id).is_some());
        assert_eq!(ctx.sess_count(), 0);
    }

    /// **The shutdown trap.** `fini` clears every list, and pcfd runs background
    /// loops that can still reach a mutation during shutdown — so a persist
    /// reached after `fini` would write an empty snapshot over a good one and lose
    /// every live association.
    ///
    /// Revert-verified: removing the `StateStore::disabled()` from `fini` fails this.
    #[test]
    fn fini_cannot_overwrite_a_good_snapshot_with_an_empty_one() {
        let path = temp_state_path("fini");
        let mut ctx = ctx_with_state(&path);
        populate(&ctx);
        let good = std::fs::read_to_string(&path).expect("snapshot written");

        ctx.fini();
        assert_eq!(ctx.ue_am_count(), 0, "fini clears the lists");
        // Anything a background task might still reach must not write.
        ctx.ue_am_add("imsi-001010000000009");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            good,
            "an emptied context must never be written over a good snapshot"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_analytics_policy_engine_no_adjustment() {
        let mut engine = AnalyticsPolicyEngine::new();
        let analytics = AnalyticsState {
            predicted_congestion: 0.3,
            qos_sustainability: 0.8,
            ..Default::default()
        };
        let result = engine.evaluate(&analytics, 9, 8);
        assert!(result.is_none());
        assert_eq!(engine.adjustment_count(), 0);
    }

    #[test]
    fn test_analytics_policy_engine_congestion() {
        let mut engine = AnalyticsPolicyEngine::new();
        let analytics = AnalyticsState {
            predicted_congestion: 0.85,
            traffic_class: TrafficClass::VideoStreaming,
            qos_sustainability: 0.7,
            ..Default::default()
        };
        let result = engine.evaluate(&analytics, 4, 5).unwrap();
        assert_eq!(result.reason, AdjustmentReason::CongestionAvoidance);
        assert_eq!(result.adjusted_5qi, 9); // downgraded to best-effort
        assert_eq!(result.adjusted_arp, 6); // priority lowered
    }

    #[test]
    fn test_analytics_policy_engine_anomaly() {
        let mut engine = AnalyticsPolicyEngine::new();
        let analytics = AnalyticsState {
            predicted_congestion: 0.2,
            qos_sustainability: 0.9,
            anomaly_alerts: vec![AnomalyAlert {
                alert_type: AnomalyAlertType::DdosPattern,
                severity: 0.95,
                affected_snssai: None,
                recommended_action: AnomalyAction::TightenAdmission,
            }],
            ..Default::default()
        };
        let result = engine.evaluate(&analytics, 9, 8).unwrap();
        assert_eq!(result.reason, AdjustmentReason::AnomalyDetected);
        assert_eq!(result.action, AnomalyAction::TightenAdmission);
    }

    #[test]
    fn test_analytics_policy_engine_qos_sustainability() {
        let mut engine = AnalyticsPolicyEngine::new();
        let analytics = AnalyticsState {
            predicted_congestion: 0.3,
            qos_sustainability: 0.3,
            ..Default::default()
        };
        let result = engine.evaluate(&analytics, 5, 3).unwrap();
        assert_eq!(result.reason, AdjustmentReason::QosSustainability);
        assert_eq!(result.action, AnomalyAction::ReRoute);
    }
}
