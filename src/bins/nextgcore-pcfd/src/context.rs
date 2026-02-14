//! PCF Context Management
//!
//! Port of src/pcf/context.c - PCF context with UE AM/SM lists, session list, and hash tables

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Access type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessType {
    #[default]
    ThreeGppAccess,
    NonThreeGppAccess,
}

/// RAT type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RatType {
    #[default]
    Nr,
    Eutra,
    Wlan,
    Virtual,
}

/// PDU Session Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PduSessionType {
    #[default]
    Ipv4,
    Ipv6,
    Ipv4v6,
    Unstructured,
    Ethernet,
}

/// GUAMI (Globally Unique AMF Identifier)
#[derive(Debug, Clone, Default)]
pub struct Guami {
    pub plmn_id: PlmnId,
    pub amf_id: AmfId,
}

/// PLMN ID
#[derive(Debug, Clone, Default)]
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

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

/// AMBR (Aggregate Maximum Bit Rate)
#[derive(Debug, Clone, Default)]
pub struct Ambr {
    pub uplink: String,
    pub downlink: String,
}

/// Subscribed Default QoS
#[derive(Debug, Clone, Default)]
pub struct SubscribedDefaultQos {
    pub five_qi: u8,
    pub priority_level: u8,
    pub arp_priority_level: u8,
    pub arp_preempt_cap: bool,
    pub arp_preempt_vuln: bool,
}

/// PCF UE AM (Access Management) context
/// Port of pcf_ue_am_t from context.h
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct UrspRule {
    /// Rule precedence (lower = higher priority, range 0-255)
    pub precedence: u8,
    /// Traffic descriptors for matching packets
    pub traffic_descriptors: Vec<TrafficDescriptor>,
    /// Route selection descriptors (ordered by precedence)
    pub route_selection_descriptors: Vec<RouteSelectionDescriptor>,
}

/// Traffic Descriptor for URSP matching (TS 24.526 5.2)
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone)]
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
                    access_type: Some(vec![AccessType::ThreeGppAccess, AccessType::NonThreeGppAccess]),
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
        log::info!("[PCF URSP] Generated {} default URSP rules for SUPI={}", self.ursp_rules.len(), self.supi);
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone, Default)]
pub struct PlmnPresence {
    pub presence: bool,
    pub plmn_id: PlmnId,
}

/// PCF Session context
/// Port of pcf_sess_t from context.h
#[derive(Debug, Clone)]
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
        if let (Ok(addr), Ok(len)) = (parts[0].parse::<std::net::Ipv6Addr>(), parts[1].parse::<u8>()) {
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
            max_uplink_rate_kbps: Some(1000), // Default 1 Mbps
            max_downlink_rate_kbps: Some(5000), // Default 5 Mbps
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
            .unwrap_or_default()
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
            .unwrap_or_default()
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
            .unwrap_or_default()
            .as_secs();
        self.authorized && now >= self.created_at && now <= self.expires_at
    }

    /// Check if position is within authorized zones
    pub fn check_position_authorized(&self, latitude: f64, longitude: f64, altitude: f64, timestamp: u64) -> bool {
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
    pub fn set_comm_constraints(&mut self, max_ul_kbps: u32, max_dl_kbps: u32, max_duration_sec: u32) {
        self.max_uplink_rate_kbps = Some(max_ul_kbps);
        self.max_downlink_rate_kbps = Some(max_dl_kbps);
        self.max_session_duration_sec = Some(max_duration_sec);
    }
}

/// PCF App Session context
/// Port of pcf_app_t from context.h
#[derive(Debug, Clone)]
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
        self.ue_am_remove_all();
        self.ue_sm_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("PCF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
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
        let supi_am_hash = self.supi_am_hash.read().ok()?;
        let ue_am_list = self.ue_am_list.read().ok()?;
        supi_am_hash.get(supi).and_then(|&id| ue_am_list.get(&id).cloned())
    }

    pub fn ue_am_find_by_association_id(&self, association_id: &str) -> Option<PcfUeAm> {
        let association_id_hash = self.association_id_hash.read().ok()?;
        let ue_am_list = self.ue_am_list.read().ok()?;
        association_id_hash.get(association_id).and_then(|&id| ue_am_list.get(&id).cloned())
    }

    pub fn ue_am_find_by_id(&self, id: u64) -> Option<PcfUeAm> {
        let ue_am_list = self.ue_am_list.read().ok()?;
        ue_am_list.get(&id).cloned()
    }

    pub fn ue_am_update(&self, ue_am: &PcfUeAm) -> bool {
        if let Ok(mut ue_am_list) = self.ue_am_list.write() {
            if let Some(existing) = ue_am_list.get_mut(&ue_am.id) {
                *existing = ue_am.clone();
                return true;
            }
        }
        false
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
        Some(ue_sm)
    }

    pub fn ue_sm_remove(&self, id: u64) -> Option<PcfUeSm> {
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;
        let mut supi_sm_hash = self.supi_sm_hash.write().ok()?;

        if let Some(ue_sm) = ue_sm_list.remove(&id) {
            supi_sm_hash.remove(&ue_sm.supi);
            // Remove all sessions for this UE
            self.sess_remove_all_for_ue(id);
            log::debug!("[{}] PCF UE SM removed (id={})", ue_sm.supi, id);
            return Some(ue_sm);
        }
        None
    }

    pub fn ue_sm_remove_all(&self) {
        if let (Ok(mut ue_sm_list), Ok(mut supi_sm_hash)) = (
            self.ue_sm_list.write(),
            self.supi_sm_hash.write(),
        ) {
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
        let supi_sm_hash = self.supi_sm_hash.read().ok()?;
        let ue_sm_list = self.ue_sm_list.read().ok()?;
        supi_sm_hash.get(supi).and_then(|&id| ue_sm_list.get(&id).cloned())
    }

    pub fn ue_sm_find_by_id(&self, id: u64) -> Option<PcfUeSm> {
        let ue_sm_list = self.ue_sm_list.read().ok()?;
        ue_sm_list.get(&id).cloned()
    }

    pub fn ue_sm_update(&self, ue_sm: &PcfUeSm) -> bool {
        if let Ok(mut ue_sm_list) = self.ue_sm_list.write() {
            if let Some(existing) = ue_sm_list.get_mut(&ue_sm.id) {
                *existing = ue_sm.clone();
                return true;
            }
        }
        false
    }

    // Session management

    pub fn sess_add(&self, pcf_ue_sm_id: u64, psi: u8) -> Option<PcfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sm_policy_id_hash = self.sm_policy_id_hash.write().ok()?;
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!("Maximum number of sessions [{}] reached", self.max_num_of_sess);
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
        Some(sess)
    }

    pub fn sess_remove(&self, id: u64) -> Option<PcfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sm_policy_id_hash = self.sm_policy_id_hash.write().ok()?;
        let mut ipv4addr_hash = self.ipv4addr_hash.write().ok()?;
        let mut ipv6prefix_hash = self.ipv6prefix_hash.write().ok()?;
        let mut ue_sm_list = self.ue_sm_list.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
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
            // Remove all apps for this session
            self.app_remove_all_for_sess(id);
            log::debug!("[psi={}] PCF session removed (id={})", sess.psi, id);
            return Some(sess);
        }
        None
    }

    fn sess_remove_all_for_ue(&self, pcf_ue_sm_id: u64) {
        if let Ok(mut sess_list) = self.sess_list.write() {
            let sess_ids: Vec<u64> = sess_list.values()
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
        let sm_policy_id_hash = self.sm_policy_id_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        sm_policy_id_hash.get(sm_policy_id).and_then(|&id| sess_list.get(&id).cloned())
    }

    pub fn sess_find_by_psi(&self, pcf_ue_sm_id: u64, psi: u8) -> Option<PcfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.values().find(|s| s.pcf_ue_sm_id == pcf_ue_sm_id && s.psi == psi).cloned()
    }

    pub fn sess_find_by_ipv4addr(&self, ipv4addr_string: &str) -> Option<PcfSess> {
        if let Ok(addr) = ipv4addr_string.parse::<std::net::Ipv4Addr>() {
            let ipv4addr = u32::from(addr);
            let ipv4addr_hash = self.ipv4addr_hash.read().ok()?;
            let sess_list = self.sess_list.read().ok()?;
            return ipv4addr_hash.get(&ipv4addr).and_then(|&id| sess_list.get(&id).cloned());
        }
        None
    }

    pub fn sess_find_by_ipv6addr(&self, ipv6prefix_string: &str) -> Option<PcfSess> {
        let ipv6prefix_hash = self.ipv6prefix_hash.read().ok()?;
        let sess_list = self.sess_list.read().ok()?;
        ipv6prefix_hash.get(ipv6prefix_string).and_then(|&id| sess_list.get(&id).cloned())
    }

    pub fn sess_update(&self, sess: &PcfSess) -> bool {
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

    pub fn sessions_number_by_snssai_and_dnn(&self, pcf_ue_sm_id: u64, s_nssai: &SNssai, dnn: &str) -> usize {
        if let Ok(sess_list) = self.sess_list.read() {
            return sess_list.values()
                .filter(|s| s.pcf_ue_sm_id == pcf_ue_sm_id && &s.s_nssai == s_nssai && s.dnn.as_deref() == Some(dnn))
                .count();
        }
        0
    }


    // App session management

    pub fn app_add(&self, sess_id: u64) -> Option<PcfApp> {
        let mut app_list = self.app_list.write().ok()?;
        let mut app_session_id_hash = self.app_session_id_hash.write().ok()?;
        let mut sess_list = self.sess_list.write().ok()?;

        let id = self.next_app_id.fetch_add(1, Ordering::SeqCst) as u64;
        let app = PcfApp::new(id, sess_id);

        app_session_id_hash.insert(app.app_session_id.clone(), id);
        app_list.insert(id, app.clone());

        // Add app ID to session
        if let Some(sess) = sess_list.get_mut(&sess_id) {
            sess.app_ids.push(id);
        }

        log::debug!("[sess_id={sess_id}] PCF app added (id={id})");
        Some(app)
    }

    pub fn app_remove(&self, id: u64) -> Option<PcfApp> {
        let mut app_list = self.app_list.write().ok()?;
        let mut app_session_id_hash = self.app_session_id_hash.write().ok()?;
        let mut sess_list = self.sess_list.write().ok()?;

        if let Some(app) = app_list.remove(&id) {
            app_session_id_hash.remove(&app.app_session_id);
            // Remove app ID from session
            if let Some(sess) = sess_list.get_mut(&app.sess_id) {
                sess.app_ids.retain(|&aid| aid != id);
            }
            log::debug!("PCF app removed (id={id})");
            return Some(app);
        }
        None
    }

    fn app_remove_all_for_sess(&self, sess_id: u64) {
        if let Ok(mut app_list) = self.app_list.write() {
            let app_ids: Vec<u64> = app_list.values()
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
        let app_session_id_hash = self.app_session_id_hash.read().ok()?;
        let app_list = self.app_list.read().ok()?;
        app_session_id_hash.get(app_session_id).and_then(|&id| app_list.get(&id).cloned())
    }

    pub fn app_update(&self, app: &PcfApp) -> bool {
        if let Ok(mut app_list) = self.app_list.write() {
            if let Some(existing) = app_list.get_mut(&app.id) {
                *existing = app.clone();
                return true;
            }
        }
        false
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
static GLOBAL_PCF_CONTEXT: std::sync::OnceLock<Arc<RwLock<PcfContext>>> = std::sync::OnceLock::new();

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
