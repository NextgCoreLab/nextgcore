//! UE Policy Management for PCF (Rel-16, TS 23.503 §6.6)
//!
//! Implements URSP (UE Route Selection Policy) rule generation,
//! Traffic Descriptor matching, and Route Selection Descriptor provisioning.

use std::collections::HashMap;

/// Traffic Descriptor component types (TS 24.526 §5.2)
#[derive(Debug, Clone, PartialEq)]
pub enum TrafficDescriptorComponent {
    /// Application identifier (OSId + OSAppId)
    AppId(String),
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
                TrafficDescriptor::new(vec![]) // empty TD matches all
            ],
            route_selection_descriptors: vec![
                RouteSelectionDescriptor::default_internet()
            ],
        }
    }

    /// Creates an IMS voice rule
    pub fn ims_rule() -> Self {
        Self {
            precedence: 10,
            traffic_descriptors: vec![
                TrafficDescriptor::for_dnn("ims"),
            ],
            route_selection_descriptors: vec![
                RouteSelectionDescriptor::ims_voice()
            ],
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
        self.ursp_rules.get(supi).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Returns the first matching rule for a given DNN (simplified matching)
    pub fn find_rule_for_dnn<'a>(&'a self, supi: &str, dnn: &str) -> Option<&'a UrspRule> {
        self.ursp_rules.get(supi)?.iter().find(|rule| {
            rule.traffic_descriptors.iter().any(|td| {
                td.components.iter().any(|c| {
                    matches!(c, TrafficDescriptorComponent::Dnn(d) if d == dnn)
                }) || td.components.is_empty() // catch-all
            })
        })
    }

    /// Returns total number of UEs with URSP policies
    pub fn policy_count(&self) -> usize {
        self.ursp_rules.len()
    }
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
        ctx.provision_ursp("imsi-001011234567890".into(), vec![
            UrspRule::ims_rule(),
            UrspRule::catch_all(),
        ]);
        let rule = ctx.find_rule_for_dnn("imsi-001011234567890", "ims").unwrap();
        assert_eq!(rule.precedence, 10);
    }

    #[test]
    fn test_find_catch_all_for_unknown_dnn() {
        let mut ctx = UePolicyContext::new();
        ctx.provision_ursp("imsi-001011234567890".into(), vec![
            UrspRule::catch_all(),
        ]);
        let rule = ctx.find_rule_for_dnn("imsi-001011234567890", "foobar").unwrap();
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
        ctx.provision_ursp("ue1".into(), vec![
            UrspRule::catch_all(),    // precedence 255
            UrspRule::ims_rule(),     // precedence 10
        ]);
        let rules = ctx.get_ursp("ue1");
        assert_eq!(rules[0].precedence, 10);  // lowest number first
        assert_eq!(rules[1].precedence, 255);
    }

    #[test]
    fn test_rsd_default_internet() {
        let rsd = RouteSelectionDescriptor::default_internet();
        assert_eq!(rsd.dnn.as_deref(), Some("internet"));
        assert_eq!(rsd.ssc_mode, 1);
    }
}
