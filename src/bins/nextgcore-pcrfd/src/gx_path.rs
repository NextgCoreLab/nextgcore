//! PCRF Gx Interface Path
//!
//! Port of src/pcrf/pcrf-gx-path.c - Gx interface (CCR/CCA handling, RAR building)
//! 3GPP TS 29.212 section 5.6 (Gx messages) and section 5.3 (Gx AVPs).
//!
//! All messages on this path are real Diameter messages (RFC 6733 wire
//! format) built with the shared `nextgcore-diameter` codec. Grouped AVPs use
//! 3GPP vendor-id 10415 with the M/V bits required by the TS 29.212 AVP
//! table.

use bytes::Bytes;

use nextgcore_diameter::avp::{find_all_avps, find_avp, Avp, AvpData};
use nextgcore_diameter::common::avp_code;
use nextgcore_diameter::gx::{avp as gx_avp, cmd as gx_cmd, GX_APPLICATION_ID};
use nextgcore_diameter::message::DiameterMessage;
use nextgcore_diameter::NEXTGCORE_3GPP_VENDOR_ID;

use crate::context::{pcrf_self, NEXTGCORE_IPV6_LEN};
use crate::fd_path::{pcrf_diam_stats, LocalIdentity};

/// Base-protocol AVP codes used on this path that are not exported by the
/// shared `nextgcore-diameter` common module.
pub mod base_avp {
    /// Failed-AVP (RFC 6733 section 7.5)
    pub const FAILED_AVP: u32 = 279;
    /// Error-Message (RFC 6733 section 7.3)
    pub const ERROR_MESSAGE: u32 = 281;
    /// Network-Request-Support (TS 29.212 section 5.3.24)
    pub const NETWORK_REQUEST_SUPPORT: u32 = 1024;
}

/// CC-Request-Type values applicable on Gx (TS 29.212 section 5.6.2).
/// EVENT_REQUEST (4) is defined by RFC 4006 but is NOT used on Gx.
pub mod cc_request_type {
    pub const INITIAL_REQUEST: u32 = 1;
    pub const UPDATE_REQUEST: u32 = 2;
    pub const TERMINATION_REQUEST: u32 = 3;
    pub const EVENT_REQUEST: u32 = 4;
}

/// Re-Auth-Request-Type values (RFC 6733 section 8.12)
pub mod re_auth_request_type {
    pub const AUTHORIZE_ONLY: u32 = 0;
}

/// Event-Trigger values (TS 29.212 section 5.3.7)
pub mod event_trigger {
    pub const SGSN_CHANGE: u32 = 0;
    pub const QOS_CHANGE: u32 = 1;
    pub const RAT_CHANGE: u32 = 2;
    pub const PLMN_CHANGE: u32 = 4;
    pub const IP_CAN_CHANGE: u32 = 7;
    pub const UE_IP_ADDRESS_ALLOCATE: u32 = 18;
    pub const UE_IP_ADDRESS_RELEASE: u32 = 19;
}

/// Flow-Direction values (TS 29.212 section 5.3.65)
pub mod flow_direction {
    pub const UNSPECIFIED: i32 = 0;
    pub const DOWNLINK: i32 = 1;
    pub const UPLINK: i32 = 2;
    pub const BIDIRECTIONAL: i32 = 3;
}

/// Pre-emption-Capability values (TS 29.212 section 5.3.46)
pub mod pre_emption_capability {
    pub const ENABLED: i32 = 0;
    pub const DISABLED: i32 = 1;
}

/// Pre-emption-Vulnerability values (TS 29.212 section 5.3.47)
pub mod pre_emption_vulnerability {
    pub const ENABLED: i32 = 0;
    pub const DISABLED: i32 = 1;
}

/// Bearer-Control-Mode values (TS 29.212 section 5.3.23)
pub mod bearer_control_mode {
    pub const UE_ONLY: i32 = 0;
    pub const RESERVED: i32 = 1;
    pub const UE_NW: i32 = 2;
}

/// Flow Status Values (TS 29.214 section 5.3.11)
pub mod flow_status {
    pub const ENABLED_UPLINK: i32 = 0;
    pub const ENABLED_DOWNLINK: i32 = 1;
    pub const ENABLED: i32 = 2;
    pub const DISABLED: i32 = 3;
    pub const REMOVED: i32 = 4;
}

/// Diameter result codes used on this path
pub mod result_code {
    pub const DIAMETER_SUCCESS: u32 = 2001;
    pub const DIAMETER_COMMAND_UNSUPPORTED: u32 = 3001;
    pub const DIAMETER_APPLICATION_UNSUPPORTED: u32 = 3007;
    pub const DIAMETER_UNKNOWN_SESSION_ID: u32 = 5002;
    pub const DIAMETER_INVALID_AVP_VALUE: u32 = 5004;
    pub const DIAMETER_MISSING_AVP: u32 = 5005;
    pub const DIAMETER_UNABLE_TO_COMPLY: u32 = 5012;
}

/// Media type values (TS 29.214 section 5.3.19)
pub mod media_type {
    pub const AUDIO: i32 = 0;
    pub const VIDEO: i32 = 1;
    pub const DATA: i32 = 2;
    pub const APPLICATION: i32 = 3;
    pub const CONTROL: i32 = 4;
    pub const TEXT: i32 = 5;
    pub const MESSAGE: i32 = 6;
    pub const OTHER: i32 = 0xFFFFFFFF_u32 as i32;
}

// ============================================================================
// Policy data structures
// ============================================================================

/// Gx session policy data used to build CCA / RAR provisioning AVPs
#[derive(Debug, Clone, Default)]
pub struct GxSessionData {
    /// APN-AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// APN-AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// Default bearer QoS class identifier
    pub qos_index: u8,
    /// Default bearer ARP priority level
    pub arp_priority_level: u8,
    /// Default bearer ARP pre-emption capability (true = may pre-empt)
    pub arp_pre_emption_capability: bool,
    /// Default bearer ARP pre-emption vulnerability (true = may be pre-empted)
    pub arp_pre_emption_vulnerability: bool,
    /// PCC rules
    pub pcc_rules: Vec<PccRuleData>,
    /// Event triggers to arm at the PCEF
    pub event_triggers: Vec<u32>,
}

/// PCC rule data
#[derive(Debug, Clone, Default)]
pub struct PccRuleData {
    /// Rule name
    pub name: String,
    /// QoS index (QCI)
    pub qos_index: u8,
    /// ARP priority level
    pub arp_priority_level: u8,
    /// ARP pre-emption capability
    pub arp_pre_emption_capability: bool,
    /// ARP pre-emption vulnerability
    pub arp_pre_emption_vulnerability: bool,
    /// Flow status
    pub flow_status: i32,
    /// Precedence
    pub precedence: u32,
    /// MBR downlink (bps)
    pub mbr_downlink: u64,
    /// MBR uplink (bps)
    pub mbr_uplink: u64,
    /// GBR downlink (bps)
    pub gbr_downlink: u64,
    /// GBR uplink (bps)
    pub gbr_uplink: u64,
    /// Flow descriptions
    pub flows: Vec<FlowData>,
}

/// Flow data (Flow-Information content)
#[derive(Debug, Clone, Default)]
pub struct FlowData {
    /// Flow direction (TS 29.212 Flow-Direction values)
    pub direction: i32,
    /// Flow description (IPFilterRule)
    pub description: String,
}

/// IMS data from the Rx interface used to derive PCC rules
#[derive(Debug, Clone, Default)]
pub struct ImsData {
    /// Media components
    pub media_components: Vec<MediaComponent>,
}

/// Media component
#[derive(Debug, Clone, Default)]
pub struct MediaComponent {
    /// Media component number
    pub media_component_number: i32,
    /// Media type
    pub media_type: i32,
    /// Max requested bandwidth DL
    pub max_requested_bandwidth_dl: u32,
    /// Max requested bandwidth UL
    pub max_requested_bandwidth_ul: u32,
    /// Flow status
    pub flow_status: i32,
    /// Sub-components
    pub sub_components: Vec<MediaSubComponent>,
}

/// Media sub-component
#[derive(Debug, Clone, Default)]
pub struct MediaSubComponent {
    /// Flow number
    pub flow_number: i32,
    /// Flow usage
    pub flow_usage: i32,
    /// Flow descriptions
    pub flows: Vec<String>,
}

// ============================================================================
// CCR parsing (TS 29.212 section 5.6.2)
// ============================================================================

/// Parsed CCR content
#[derive(Debug, Clone, Default)]
pub struct CcrInfo {
    /// Session-Id
    pub session_id: String,
    /// Origin-Host of the PCEF
    pub origin_host: String,
    /// Origin-Realm of the PCEF
    pub origin_realm: String,
    /// CC-Request-Type
    pub cc_request_type: u32,
    /// CC-Request-Number
    pub cc_request_number: u32,
    /// IMSI from Subscription-Id (END_USER_IMSI)
    pub imsi: Option<String>,
    /// APN from Called-Station-Id
    pub apn: Option<String>,
    /// Framed-IP-Address
    pub framed_ipv4: Option<[u8; 4]>,
    /// Framed-IPv6-Prefix (prefix bytes, zero padded)
    pub framed_ipv6: Option<[u8; NEXTGCORE_IPV6_LEN]>,
    /// Network-Request-Support was present in the CCR
    pub network_request_support: bool,
}

/// Errors detected while validating a CCR against the TS 29.212 message table
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GxRequestError {
    /// A mandatory AVP is absent; carries the missing AVP code
    MissingAvp(u32),
    /// An AVP carries an invalid value; carries the offending AVP code
    InvalidAvpValue(u32),
    /// Auth-Application-Id does not match the Gx application
    ApplicationUnsupported,
    /// CC-Request-Type UPDATE/TERMINATION for a session the PCRF does not know
    UnknownSession,
}

impl GxRequestError {
    /// Diameter Result-Code for this error
    pub fn result_code(&self) -> u32 {
        match self {
            GxRequestError::MissingAvp(_) => result_code::DIAMETER_MISSING_AVP,
            GxRequestError::InvalidAvpValue(_) => result_code::DIAMETER_INVALID_AVP_VALUE,
            GxRequestError::ApplicationUnsupported => result_code::DIAMETER_APPLICATION_UNSUPPORTED,
            GxRequestError::UnknownSession => result_code::DIAMETER_UNKNOWN_SESSION_ID,
        }
    }

    /// AVP code to report in Failed-AVP (if applicable)
    pub fn failed_avp_code(&self) -> Option<u32> {
        match self {
            GxRequestError::MissingAvp(code) | GxRequestError::InvalidAvpValue(code) => Some(*code),
            _ => None,
        }
    }
}

/// Parse and validate a CCR against the TS 29.212 section 5.6.2 message table.
///
/// Mandatory AVPs: Session-Id, Auth-Application-Id, Origin-Host, Origin-Realm,
/// Destination-Realm, CC-Request-Type, CC-Request-Number.
pub fn parse_ccr(msg: &DiameterMessage) -> Result<CcrInfo, GxRequestError> {
    let session_id = msg
        .session_id()
        .ok_or(GxRequestError::MissingAvp(avp_code::SESSION_ID))?
        .to_string();

    let auth_app = msg
        .find_avp(avp_code::AUTH_APPLICATION_ID)
        .and_then(|a| a.as_u32())
        .ok_or(GxRequestError::MissingAvp(avp_code::AUTH_APPLICATION_ID))?;
    if auth_app != GX_APPLICATION_ID {
        return Err(GxRequestError::ApplicationUnsupported);
    }

    let origin_host = msg
        .origin_host()
        .ok_or(GxRequestError::MissingAvp(avp_code::ORIGIN_HOST))?
        .to_string();
    let origin_realm = msg
        .origin_realm()
        .ok_or(GxRequestError::MissingAvp(avp_code::ORIGIN_REALM))?
        .to_string();
    if msg.destination_realm().is_none() {
        return Err(GxRequestError::MissingAvp(avp_code::DESTINATION_REALM));
    }

    let cc_request_type = msg
        .find_avp(gx_avp::CC_REQUEST_TYPE)
        .and_then(|a| a.as_u32())
        .ok_or(GxRequestError::MissingAvp(gx_avp::CC_REQUEST_TYPE))?;
    // EVENT_REQUEST is not applicable on Gx (TS 29.212 section 5.6.2)
    if !(cc_request_type::INITIAL_REQUEST..=cc_request_type::TERMINATION_REQUEST)
        .contains(&cc_request_type)
    {
        return Err(GxRequestError::InvalidAvpValue(gx_avp::CC_REQUEST_TYPE));
    }

    let cc_request_number = msg
        .find_avp(gx_avp::CC_REQUEST_NUMBER)
        .and_then(|a| a.as_u32())
        .ok_or(GxRequestError::MissingAvp(gx_avp::CC_REQUEST_NUMBER))?;

    // Subscription-Id (conditional): extract END_USER_IMSI
    let mut imsi = None;
    for sub_id in find_all_avps(&msg.avps, avp_code::SUBSCRIPTION_ID) {
        if let Ok(members) = sub_id.parse_grouped() {
            let id_type = find_avp(&members, avp_code::SUBSCRIPTION_ID_TYPE)
                .and_then(|a| a.as_u32())
                .unwrap_or(u32::MAX);
            let id_data = find_avp(&members, avp_code::SUBSCRIPTION_ID_DATA)
                .and_then(|a| a.as_utf8_string().map(str::to_string));
            // END_USER_IMSI = 1
            if id_type == 1 {
                imsi = id_data;
            }
        }
    }

    let apn = msg
        .find_avp(gx_avp::CALLED_STATION_ID)
        .and_then(|a| a.as_utf8_string().map(str::to_string));

    let framed_ipv4 = msg
        .find_avp(gx_avp::FRAMED_IP_ADDRESS)
        .and_then(|a| a.as_octet_string())
        .and_then(|b| {
            if b.len() >= 4 {
                Some([b[0], b[1], b[2], b[3]])
            } else {
                None
            }
        });

    // Framed-IPv6-Prefix: 1 byte reserved + 1 byte prefix length + prefix bytes
    let framed_ipv6 = msg
        .find_avp(gx_avp::FRAMED_IPV6_PREFIX)
        .and_then(|a| a.as_octet_string())
        .and_then(|b| {
            if b.len() < 2 {
                return None;
            }
            let mut prefix = [0u8; NEXTGCORE_IPV6_LEN];
            let n = (b.len() - 2).min(NEXTGCORE_IPV6_LEN);
            prefix[..n].copy_from_slice(&b[2..2 + n]);
            Some(prefix)
        });

    let network_request_support = msg.find_avp(base_avp::NETWORK_REQUEST_SUPPORT).is_some();

    Ok(CcrInfo {
        session_id,
        origin_host,
        origin_realm,
        cc_request_type,
        cc_request_number,
        imsi,
        apn,
        framed_ipv4,
        framed_ipv6,
        network_request_support,
    })
}

// ============================================================================
// Grouped AVP builders (TS 29.212 section 5.3)
// ============================================================================

/// Build Allocation-Retention-Priority grouped AVP (1034)
pub fn build_arp_avp(
    priority_level: u8,
    pre_emption_cap_enabled: bool,
    pre_emption_vuln_enabled: bool,
) -> Avp {
    let cap = if pre_emption_cap_enabled {
        pre_emption_capability::ENABLED
    } else {
        pre_emption_capability::DISABLED
    };
    let vuln = if pre_emption_vuln_enabled {
        pre_emption_vulnerability::ENABLED
    } else {
        pre_emption_vulnerability::DISABLED
    };
    Avp::vendor_mandatory(
        gx_avp::ALLOCATION_RETENTION_PRIORITY,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![
            Avp::vendor_mandatory(
                gx_avp::PRIORITY_LEVEL,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Unsigned32(priority_level as u32),
            ),
            Avp::vendor_mandatory(
                gx_avp::PRE_EMPTION_CAPABILITY,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Enumerated(cap),
            ),
            Avp::vendor_mandatory(
                gx_avp::PRE_EMPTION_VULNERABILITY,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Enumerated(vuln),
            ),
        ]),
    )
}

/// Build Default-EPS-Bearer-QoS grouped AVP (1049):
/// QoS-Class-Identifier + Allocation-Retention-Priority
pub fn build_default_eps_bearer_qos_avp(data: &GxSessionData) -> Avp {
    Avp::vendor_mandatory(
        gx_avp::DEFAULT_EPS_BEARER_QOS,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![
            Avp::vendor_mandatory(
                gx_avp::QOS_CLASS_IDENTIFIER,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Enumerated(data.qos_index as i32),
            ),
            build_arp_avp(
                data.arp_priority_level,
                data.arp_pre_emption_capability,
                data.arp_pre_emption_vulnerability,
            ),
        ]),
    )
}

/// Build session-level QoS-Information grouped AVP (1016) carrying APN-AMBR
pub fn build_session_qos_information_avp(ambr_ul: u64, ambr_dl: u64) -> Avp {
    Avp::vendor_mandatory(
        gx_avp::QOS_INFORMATION,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![
            Avp::vendor_mandatory(
                gx_avp::APN_AGGREGATE_MAX_BITRATE_UL,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Unsigned32(ambr_ul.min(u32::MAX as u64) as u32),
            ),
            Avp::vendor_mandatory(
                gx_avp::APN_AGGREGATE_MAX_BITRATE_DL,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Unsigned32(ambr_dl.min(u32::MAX as u64) as u32),
            ),
        ]),
    )
}

/// Build per-rule QoS-Information grouped AVP (1016)
fn build_rule_qos_information_avp(rule: &PccRuleData) -> Avp {
    let mut members = vec![Avp::vendor_mandatory(
        gx_avp::QOS_CLASS_IDENTIFIER,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Enumerated(rule.qos_index as i32),
    )];
    members.push(Avp::vendor_mandatory(
        gx_avp::MAX_REQUESTED_BANDWIDTH_UL,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Unsigned32(rule.mbr_uplink.min(u32::MAX as u64) as u32),
    ));
    members.push(Avp::vendor_mandatory(
        gx_avp::MAX_REQUESTED_BANDWIDTH_DL,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Unsigned32(rule.mbr_downlink.min(u32::MAX as u64) as u32),
    ));
    if rule.gbr_uplink > 0 {
        members.push(Avp::vendor_mandatory(
            gx_avp::GUARANTEED_BITRATE_UL,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(rule.gbr_uplink.min(u32::MAX as u64) as u32),
        ));
    }
    if rule.gbr_downlink > 0 {
        members.push(Avp::vendor_mandatory(
            gx_avp::GUARANTEED_BITRATE_DL,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(rule.gbr_downlink.min(u32::MAX as u64) as u32),
        ));
    }
    members.push(build_arp_avp(
        rule.arp_priority_level,
        rule.arp_pre_emption_capability,
        rule.arp_pre_emption_vulnerability,
    ));
    Avp::vendor_mandatory(
        gx_avp::QOS_INFORMATION,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(members),
    )
}

/// Build a Flow-Information grouped AVP (1058):
/// Flow-Description + Flow-Direction
fn build_flow_information_avp(flow: &FlowData) -> Avp {
    Avp::vendor_mandatory(
        gx_avp::FLOW_INFORMATION,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![
            Avp::vendor_mandatory(
                gx_avp::FLOW_DESCRIPTION,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::OctetString(Bytes::copy_from_slice(flow.description.as_bytes())),
            ),
            Avp::vendor_mandatory(
                gx_avp::FLOW_DIRECTION,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Enumerated(flow.direction),
            ),
        ]),
    )
}

/// Build a Charging-Rule-Definition grouped AVP (1003):
/// Charging-Rule-Name + Flow-Information* + Flow-Status + QoS-Information +
/// Precedence
pub fn build_charging_rule_definition_avp(rule: &PccRuleData) -> Avp {
    let mut members = vec![Avp::vendor_mandatory(
        gx_avp::CHARGING_RULE_NAME,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(rule.name.as_bytes())),
    )];
    for flow in &rule.flows {
        members.push(build_flow_information_avp(flow));
    }
    members.push(Avp::vendor_mandatory(
        gx_avp::FLOW_STATUS,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Enumerated(rule.flow_status),
    ));
    members.push(build_rule_qos_information_avp(rule));
    members.push(Avp::vendor_mandatory(
        gx_avp::PRECEDENCE,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Unsigned32(rule.precedence),
    ));
    Avp::vendor_mandatory(
        gx_avp::CHARGING_RULE_DEFINITION,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(members),
    )
}

/// Build a Charging-Rule-Install grouped AVP (1001) containing the
/// Charging-Rule-Definition of each rule
pub fn build_charging_rule_install_avp(rules: &[PccRuleData]) -> Avp {
    let members = rules
        .iter()
        .map(build_charging_rule_definition_avp)
        .collect();
    Avp::vendor_mandatory(
        gx_avp::CHARGING_RULE_INSTALL,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(members),
    )
}

/// Build a Charging-Rule-Remove grouped AVP (1002) containing the
/// Charging-Rule-Name of each rule to remove
pub fn build_charging_rule_remove_avp(rule_names: &[String]) -> Avp {
    let members = rule_names
        .iter()
        .map(|name| {
            Avp::vendor_mandatory(
                gx_avp::CHARGING_RULE_NAME,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::OctetString(Bytes::copy_from_slice(name.as_bytes())),
            )
        })
        .collect();
    Avp::vendor_mandatory(
        gx_avp::CHARGING_RULE_REMOVE,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(members),
    )
}

/// Build an Event-Trigger AVP (1006)
pub fn build_event_trigger_avp(trigger: u32) -> Avp {
    Avp::vendor_mandatory(
        gx_avp::EVENT_TRIGGER,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Enumerated(trigger as i32),
    )
}

// ============================================================================
// CCA building (TS 29.212 section 5.6.3)
// ============================================================================

/// Append the AVPs that are mandatory in every CCA:
/// Session-Id, Auth-Application-Id, Origin-Host, Origin-Realm,
/// CC-Request-Type, CC-Request-Number.
fn add_cca_base_avps(
    cca: &mut DiameterMessage,
    ccr: &DiameterMessage,
    local: &LocalIdentity,
    cc_request_type: Option<u32>,
    cc_request_number: Option<u32>,
) {
    if let Some(sid) = ccr.session_id() {
        cca.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(sid.to_string()),
        ));
    }
    cca.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(GX_APPLICATION_ID),
    ));
    cca.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(local.host.clone()),
    ));
    cca.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(local.realm.clone()),
    ));
    if let Some(t) = cc_request_type {
        cca.add_avp(Avp::mandatory(
            gx_avp::CC_REQUEST_TYPE,
            AvpData::Enumerated(t as i32),
        ));
    }
    if let Some(n) = cc_request_number {
        cca.add_avp(Avp::mandatory(
            gx_avp::CC_REQUEST_NUMBER,
            AvpData::Unsigned32(n),
        ));
    }
}

/// Build a successful CCA for the given CCR.
///
/// For INITIAL_REQUEST the CCA provisions Charging-Rule-Install,
/// Default-EPS-Bearer-QoS, QoS-Information (APN-AMBR) and Event-Trigger
/// AVPs. For UPDATE_REQUEST the QoS and triggers are re-affirmed without
/// re-installing rules. For TERMINATION_REQUEST only the mandatory AVPs
/// are present.
pub fn build_cca_success(
    ccr: &DiameterMessage,
    info: &CcrInfo,
    local: &LocalIdentity,
    session_data: Option<&GxSessionData>,
) -> DiameterMessage {
    let mut cca = DiameterMessage::new_answer(ccr);
    add_cca_base_avps(
        &mut cca,
        ccr,
        local,
        Some(info.cc_request_type),
        Some(info.cc_request_number),
    );
    cca.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(result_code::DIAMETER_SUCCESS),
    ));

    // Echo Supported-Features if the PCEF advertised them (TS 29.212 5.4.1)
    if let Some(sf) = ccr.find_avp(gx_avp::SUPPORTED_FEATURES) {
        cca.add_avp(sf.clone());
    }

    if let Some(data) = session_data {
        // Event-Trigger AVPs (conditional: provisioning state)
        for trigger in &data.event_triggers {
            cca.add_avp(build_event_trigger_avp(*trigger));
        }
        // Default-EPS-Bearer-QoS (conditional: IP-CAN session provisioning)
        cca.add_avp(build_default_eps_bearer_qos_avp(data));
        // QoS-Information with APN-AMBR
        cca.add_avp(build_session_qos_information_avp(
            data.ambr_uplink,
            data.ambr_downlink,
        ));
        // Charging-Rule-Install only at initial provisioning
        if info.cc_request_type == cc_request_type::INITIAL_REQUEST && !data.pcc_rules.is_empty() {
            cca.add_avp(build_charging_rule_install_avp(&data.pcc_rules));
        }
        // Bearer-Control-Mode (conditional: only when the PCEF indicated
        // Network-Request-Support, TS 29.212 section 4.5.1)
        if info.network_request_support {
            cca.add_avp(Avp::vendor_mandatory(
                gx_avp::BEARER_CONTROL_MODE,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Enumerated(bearer_control_mode::UE_NW),
            ));
        }
    }

    cca
}

/// Build an error CCA with the proper Result-Code, E-bit and Failed-AVP.
pub fn build_cca_error(
    ccr: &DiameterMessage,
    local: &LocalIdentity,
    error: &GxRequestError,
) -> DiameterMessage {
    let mut cca = DiameterMessage::new_answer(ccr);
    // The E-bit is only set for protocol errors (3xxx), RFC 6733 7.1.3
    if (3000..4000).contains(&error.result_code()) {
        cca.header.set_error();
    }

    let cc_request_type = ccr
        .find_avp(gx_avp::CC_REQUEST_TYPE)
        .and_then(|a| a.as_u32());
    let cc_request_number = ccr
        .find_avp(gx_avp::CC_REQUEST_NUMBER)
        .and_then(|a| a.as_u32());
    add_cca_base_avps(&mut cca, ccr, local, cc_request_type, cc_request_number);

    cca.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(error.result_code()),
    ));
    if let Some(code) = error.failed_avp_code() {
        // Failed-AVP carries the offending AVP (with empty data when absent)
        cca.add_avp(Avp::mandatory(
            base_avp::FAILED_AVP,
            AvpData::Grouped(vec![Avp::mandatory(
                code,
                AvpData::OctetString(Bytes::new()),
            )]),
        ));
    }
    cca
}

/// Build an answer for an unsupported command (Result-Code 3001) or
/// unsupported application (Result-Code 3007).
pub fn build_unsupported_answer(
    request: &DiameterMessage,
    local: &LocalIdentity,
    code: u32,
) -> DiameterMessage {
    let mut answer = DiameterMessage::new_answer(request);
    // The E-bit is only set for protocol errors (3xxx), RFC 6733 7.1.3
    if (3000..4000).contains(&code) {
        answer.header.set_error();
    }
    if let Some(sid) = request.session_id() {
        answer.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String(sid.to_string()),
        ));
    }
    answer.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(code),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(local.host.clone()),
    ));
    answer.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(local.realm.clone()),
    ));
    answer
}

// ============================================================================
// CCR handling (state machine, TS 29.212 section 4.5.1/4.5.2/4.5.4)
// ============================================================================

/// An Rx session that must be aborted (ASR) because its bound Gx session
/// terminated.
#[derive(Debug, Clone)]
pub struct RxAbortTarget {
    /// Rx Session-Id
    pub rx_sid: String,
    /// AF Origin-Host (Destination-Host for the ASR)
    pub peer_host: Option<String>,
    /// AF Origin-Realm (Destination-Realm for the ASR)
    pub peer_realm: Option<String>,
}

/// Handle a CCR and produce the CCA, plus any Rx sessions that need an ASR
/// because the IP-CAN session terminated.
pub fn handle_ccr(
    msg: &DiameterMessage,
    local: &LocalIdentity,
) -> (DiameterMessage, Vec<RxAbortTarget>) {
    pcrf_diam_stats().gx.inc_rx_ccr();

    let info = match parse_ccr(msg) {
        Ok(info) => info,
        Err(e) => {
            log::warn!("CCR rejected: {e:?}");
            pcrf_diam_stats().gx.inc_rx_ccr_error();
            return (build_cca_error(msg, local, &e), Vec::new());
        }
    };

    let ctx = pcrf_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to read context: {e}");
            pcrf_diam_stats().gx.inc_rx_ccr_error();
            return (
                build_cca_error(msg, local, &GxRequestError::UnknownSession),
                Vec::new(),
            );
        }
    };

    let mut abort_targets = Vec::new();

    let result = match info.cc_request_type {
        cc_request_type::INITIAL_REQUEST => {
            context.gx_session_add(&info.session_id);
            context.gx_session_update(&info.session_id, |session| {
                session.set_peer_host(&info.origin_host);
                if let Some(ref imsi) = info.imsi {
                    session.set_imsi(imsi);
                }
                if let Some(ref apn) = info.apn {
                    session.set_apn(apn);
                }
                if let Some(addr) = info.framed_ipv4 {
                    session.set_ipv4(std::net::Ipv4Addr::from(addr));
                }
                if let Some(addr) = info.framed_ipv6 {
                    session.set_ipv6(addr);
                }
            });
            if let Some(addr) = info.framed_ipv4 {
                context.set_ipv4_mapping(&addr, Some(&info.session_id));
            }
            if let Some(addr) = info.framed_ipv6 {
                context.set_ipv6_mapping(&addr, Some(&info.session_id));
            }
            Ok(true)
        }
        cc_request_type::UPDATE_REQUEST => {
            if context.gx_session_find_by_sid(&info.session_id).is_none() {
                Err(GxRequestError::UnknownSession)
            } else {
                Ok(true)
            }
        }
        cc_request_type::TERMINATION_REQUEST => {
            match context.gx_session_find_by_sid(&info.session_id) {
                None => Err(GxRequestError::UnknownSession),
                Some(session) => {
                    // Collect bound Rx sessions for ASR before removal
                    for rx_idx in &session.rx_sessions {
                        // rx_sessions stores indices; resolve to sessions
                        if let Some(rx) = context_rx_session_by_idx(&context, *rx_idx) {
                            abort_targets.push(RxAbortTarget {
                                rx_sid: rx.sid.clone(),
                                peer_host: rx.peer_host.clone(),
                                peer_realm: Some(info.origin_realm.clone()),
                            });
                        }
                    }
                    // Clear IP mappings
                    if let Some(addr) = session.ipv4_addr {
                        context.set_ipv4_mapping(&addr.octets(), None);
                    }
                    if let Some(addr) = session.ipv6_addr {
                        context.set_ipv6_mapping(&addr, None);
                    }
                    // Remove Rx bindings then the Gx session itself
                    for target in &abort_targets {
                        context.rx_session_remove(&target.rx_sid);
                    }
                    context.gx_session_remove(&info.session_id);
                    Ok(false)
                }
            }
        }
        _ => Err(GxRequestError::InvalidAvpValue(gx_avp::CC_REQUEST_TYPE)),
    };

    drop(context);

    match result {
        Ok(provision) => {
            let session_data = if provision {
                Some(build_subscriber_session_data(
                    info.imsi.as_deref().unwrap_or(""),
                    info.apn.as_deref().unwrap_or(""),
                ))
            } else {
                None
            };
            pcrf_diam_stats().gx.inc_tx_cca();
            (
                build_cca_success(msg, &info, local, session_data.as_ref()),
                abort_targets,
            )
        }
        Err(e) => {
            log::warn!(
                "CCR type={} for session {} rejected: {e:?}",
                info.cc_request_type,
                info.session_id
            );
            pcrf_diam_stats().gx.inc_rx_ccr_error();
            (build_cca_error(msg, local, &e), Vec::new())
        }
    }
}

/// Resolve an Rx session by its index in the context list
fn context_rx_session_by_idx(
    context: &crate::context::PcrfContext,
    idx: usize,
) -> Option<crate::context::PcrfRxSession> {
    context.rx_session_find_by_idx(idx)
}

// ============================================================================
// RAR building / RAA parsing (TS 29.212 sections 5.6.4 / 5.6.5)
// ============================================================================

/// PCC rule action carried in a RAR
#[derive(Debug, Clone)]
pub enum RarAction {
    /// Install / modify the given rules (Charging-Rule-Install)
    Install(Vec<PccRuleData>),
    /// Remove the rules with the given names (Charging-Rule-Remove)
    Remove(Vec<String>),
}

/// Build a Re-Auth-Request toward the PCEF for the given Gx session.
///
/// Mandatory AVPs (TS 29.212 section 5.6.4): Session-Id,
/// Auth-Application-Id, Origin-Host, Origin-Realm, Destination-Realm,
/// Destination-Host, Re-Auth-Request-Type.
pub fn build_rar(
    gx_sid: &str,
    local: &LocalIdentity,
    dest_host: &str,
    dest_realm: &str,
    action: &RarAction,
) -> DiameterMessage {
    let mut rar = DiameterMessage::new_request(gx_cmd::RE_AUTH, GX_APPLICATION_ID);

    rar.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(gx_sid.to_string()),
    ));
    rar.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(GX_APPLICATION_ID),
    ));
    rar.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(local.host.clone()),
    ));
    rar.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(local.realm.clone()),
    ));
    rar.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(dest_realm.to_string()),
    ));
    rar.add_avp(Avp::mandatory(
        avp_code::DESTINATION_HOST,
        AvpData::DiameterIdentity(dest_host.to_string()),
    ));
    rar.add_avp(Avp::mandatory(
        avp_code::RE_AUTH_REQUEST_TYPE,
        AvpData::Enumerated(re_auth_request_type::AUTHORIZE_ONLY as i32),
    ));

    match action {
        RarAction::Install(rules) => {
            rar.add_avp(build_charging_rule_install_avp(rules));
        }
        RarAction::Remove(names) => {
            rar.add_avp(build_charging_rule_remove_avp(names));
        }
    }

    rar
}

/// Build a Re-Auth-Answer for a RAR the PCRF received (the PCRF normally
/// only sends RAR; this is used to answer unexpected RARs with an error).
pub fn build_raa_error(rar: &DiameterMessage, local: &LocalIdentity, code: u32) -> DiameterMessage {
    build_unsupported_answer(rar, local, code)
}

/// Parse a Re-Auth-Answer, returning the Result-Code (or the
/// Experimental-Result-Code when Result-Code is absent).
pub fn parse_raa(msg: &DiameterMessage) -> Result<u32, String> {
    if let Some(code) = msg.result_code() {
        return Ok(code);
    }
    if let Some(exp) = msg.find_avp(avp_code::EXPERIMENTAL_RESULT) {
        if let Ok(members) = exp.parse_grouped() {
            if let Some(code) =
                find_avp(&members, avp_code::EXPERIMENTAL_RESULT_CODE).and_then(|a| a.as_u32())
            {
                return Ok(code);
            }
        }
    }
    Err("RAA carries neither Result-Code nor Experimental-Result".to_string())
}

/// Send a RAR for the given Gx session and wait for the RAA.
///
/// Returns the RAA result code. Used by the Rx path to push / remove PCC
/// rules (AAR -> RAR install, STR -> RAR remove).
pub async fn pcrf_gx_send_rar(gx_sid: &str, action: RarAction) -> Result<u32, String> {
    let local = crate::fd_path::pcrf_local_identity();

    // Look up the Gx session to learn the PCEF peer identity
    let (dest_host, dest_realm) = {
        let ctx = pcrf_self();
        let context = ctx.read().map_err(|e| format!("context lock: {e}"))?;
        let session = context
            .gx_session_find_by_sid(gx_sid)
            .ok_or_else(|| format!("Gx session not found: {gx_sid}"))?;
        let host = session.peer_host.clone().ok_or_else(|| {
            pcrf_diam_stats().gx.inc_tx_rar_error();
            "No peer host in Gx session".to_string()
        })?;
        (host, local.realm.clone())
    };

    let rar = build_rar(gx_sid, &local, &dest_host, &dest_realm, &action);

    pcrf_diam_stats().gx.inc_tx_rar();
    let raa = crate::fd_path::pcrf_fd_send_request(&dest_host, rar)
        .await
        .inspect_err(|_| {
            pcrf_diam_stats().gx.inc_tx_rar_error();
        })?;

    pcrf_diam_stats().gx.inc_rx_raa();
    let code = parse_raa(&raa)?;
    if code != result_code::DIAMETER_SUCCESS {
        log::warn!("RAA for {gx_sid} returned error result code {code}");
    }
    Ok(code)
}

// ============================================================================
// Policy data derivation
// ============================================================================

/// Default policy profile applied when the subscriber has no DB entry.
/// These are configuration fallbacks, not wire constants: any value found
/// in the subscription database takes precedence.
mod default_profile {
    pub const AMBR_DL: u64 = 100_000_000;
    pub const AMBR_UL: u64 = 50_000_000;
    pub const QCI: u8 = 9;
}

/// Build GxSessionData with charging rules for a subscriber/APN pair.
///
/// Looks up the subscriber's policy profile (QoS index, ARP, AMBR) from the
/// subscription DB. If the DB is not available (e.g. unit-test
/// environments), falls back to a permissive default profile.
pub fn build_subscriber_session_data(imsi: &str, apn: &str) -> GxSessionData {
    let policy = lookup_subscriber_policy(imsi, apn);

    let (qci, arp_prio, arp_cap, arp_vuln, ambr_dl, ambr_ul) = match &policy {
        Some(p) => (
            if p.qos.index > 0 {
                p.qos.index
            } else {
                default_profile::QCI
            },
            if p.qos.arp.priority_level > 0 {
                p.qos.arp.priority_level
            } else {
                qci_to_qos(default_profile::QCI).priority
            },
            p.qos.arp.pre_emption_capability == arp_db_value::CAPABILITY_ENABLED,
            p.qos.arp.pre_emption_vulnerability == arp_db_value::VULNERABILITY_ENABLED,
            if p.ambr.downlink > 0 {
                p.ambr.downlink
            } else {
                default_profile::AMBR_DL
            },
            if p.ambr.uplink > 0 {
                p.ambr.uplink
            } else {
                default_profile::AMBR_UL
            },
        ),
        None => (
            default_profile::QCI,
            qci_to_qos(default_profile::QCI).priority,
            false,
            true,
            default_profile::AMBR_DL,
            default_profile::AMBR_UL,
        ),
    };

    // Build a catch-all PCC rule for the APN.
    // Flow descriptions use IPFilterRule syntax (RFC 6733 / TS 29.212):
    // "permit out" = downlink (towards the UE), "permit in" = uplink.
    let rule_name = format!("pcrf-{}-default", apn.replace('.', "-"));
    let default_pcc_rule = PccRuleData {
        name: rule_name,
        qos_index: qci,
        arp_priority_level: arp_prio,
        arp_pre_emption_capability: arp_cap,
        arp_pre_emption_vulnerability: arp_vuln,
        flow_status: flow_status::ENABLED,
        precedence: 100,
        mbr_downlink: ambr_dl,
        mbr_uplink: ambr_ul,
        gbr_downlink: 0, // non-GBR default bearer
        gbr_uplink: 0,
        flows: vec![
            FlowData {
                direction: flow_direction::DOWNLINK,
                description: "permit out ip from any to assigned".to_string(),
            },
            FlowData {
                direction: flow_direction::UPLINK,
                description: "permit in ip from any to assigned".to_string(),
            },
        ],
    };

    GxSessionData {
        ambr_downlink: ambr_dl,
        ambr_uplink: ambr_ul,
        qos_index: qci,
        arp_priority_level: arp_prio,
        arp_pre_emption_capability: arp_cap,
        arp_pre_emption_vulnerability: arp_vuln,
        pcc_rules: vec![default_pcc_rule],
        event_triggers: vec![
            event_trigger::QOS_CHANGE,
            event_trigger::RAT_CHANGE,
            event_trigger::UE_IP_ADDRESS_ALLOCATE,
            event_trigger::UE_IP_ADDRESS_RELEASE,
        ],
    }
}

/// Subscriber policy from the DB: QoS profile + AMBR for the APN
struct SubscriberPolicy {
    qos: nextgcore_dbi::types::NextgcoreQos,
    ambr: nextgcore_dbi::types::NextgcoreAmbr,
}

/// Query the DB for a subscriber's session policy (QoS, ARP, AMBR) for the
/// given APN. Returns None if the DB is not reachable or the subscriber
/// has no matching session entry.
fn lookup_subscriber_policy(imsi: &str, apn: &str) -> Option<SubscriberPolicy> {
    use nextgcore_dbi::nextgcore_dbi_subscription_data;
    let supi = format!("imsi-{imsi}");
    let subscription_data = nextgcore_dbi_subscription_data(&supi).ok()?;

    // Find the session matching the APN
    for slice in &subscription_data.slice {
        for session in &slice.session {
            if session.name.as_deref().unwrap_or("") == apn {
                let ambr = if session.ambr.downlink > 0 || session.ambr.uplink > 0 {
                    session.ambr
                } else {
                    subscription_data.ambr
                };
                return Some(SubscriberPolicy {
                    qos: session.qos,
                    ambr,
                });
            }
        }
    }
    // Fall back to UE-level AMBR if present
    if subscription_data.ambr.downlink > 0 || subscription_data.ambr.uplink > 0 {
        return Some(SubscriberPolicy {
            qos: nextgcore_dbi::types::NextgcoreQos::default(),
            ambr: subscription_data.ambr,
        });
    }
    None
}

// ============================================================================
// QCI -> QoS Mapping (TS 23.203 Table 6.1.7)
// ============================================================================

/// QoS characteristics for a given QCI
#[derive(Debug, Clone)]
pub struct QciQosMapping {
    pub qci: u8,
    pub resource_type: QciResourceType,
    pub priority: u8,
    pub packet_delay_budget_ms: u32,
    pub packet_error_loss_rate: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QciResourceType {
    Gbr,
    NonGbr,
}

/// Get QoS parameters for a given QCI value (TS 23.203 Table 6.1.7)
pub fn qci_to_qos(qci: u8) -> QciQosMapping {
    match qci {
        1 => QciQosMapping {
            qci: 1,
            resource_type: QciResourceType::Gbr,
            priority: 2,
            packet_delay_budget_ms: 100,
            packet_error_loss_rate: 1e-2,
        },
        2 => QciQosMapping {
            qci: 2,
            resource_type: QciResourceType::Gbr,
            priority: 4,
            packet_delay_budget_ms: 150,
            packet_error_loss_rate: 1e-3,
        },
        3 => QciQosMapping {
            qci: 3,
            resource_type: QciResourceType::Gbr,
            priority: 3,
            packet_delay_budget_ms: 50,
            packet_error_loss_rate: 1e-3,
        },
        4 => QciQosMapping {
            qci: 4,
            resource_type: QciResourceType::Gbr,
            priority: 5,
            packet_delay_budget_ms: 300,
            packet_error_loss_rate: 1e-6,
        },
        5 => QciQosMapping {
            qci: 5,
            resource_type: QciResourceType::NonGbr,
            priority: 1,
            packet_delay_budget_ms: 100,
            packet_error_loss_rate: 1e-6,
        },
        6 => QciQosMapping {
            qci: 6,
            resource_type: QciResourceType::NonGbr,
            priority: 6,
            packet_delay_budget_ms: 300,
            packet_error_loss_rate: 1e-6,
        },
        7 => QciQosMapping {
            qci: 7,
            resource_type: QciResourceType::NonGbr,
            priority: 7,
            packet_delay_budget_ms: 100,
            packet_error_loss_rate: 1e-3,
        },
        8 => QciQosMapping {
            qci: 8,
            resource_type: QciResourceType::NonGbr,
            priority: 8,
            packet_delay_budget_ms: 300,
            packet_error_loss_rate: 1e-6,
        },
        9 => QciQosMapping {
            qci: 9,
            resource_type: QciResourceType::NonGbr,
            priority: 9,
            packet_delay_budget_ms: 300,
            packet_error_loss_rate: 1e-6,
        },
        65 => QciQosMapping {
            qci: 65,
            resource_type: QciResourceType::Gbr,
            priority: 0,
            packet_delay_budget_ms: 75,
            packet_error_loss_rate: 1e-2,
        },
        66 => QciQosMapping {
            qci: 66,
            resource_type: QciResourceType::Gbr,
            priority: 2,
            packet_delay_budget_ms: 100,
            packet_error_loss_rate: 1e-2,
        },
        _ => QciQosMapping {
            qci,
            resource_type: QciResourceType::NonGbr,
            priority: 9,
            packet_delay_budget_ms: 300,
            packet_error_loss_rate: 1e-6,
        },
    }
}

// ============================================================================
// PCC Rule Derivation from Rx Media Components (TS 29.213 section 7.1.4)
// ============================================================================

/// Derive PCC rules from IMS media components (Rx -> Gx)
pub fn derive_pcc_rules(ims_data: &ImsData, base_rule_name: &str) -> Vec<PccRuleData> {
    let mut rules = Vec::new();

    for (idx, mc) in ims_data.media_components.iter().enumerate() {
        let rule_name = format!("{}-mc{}", base_rule_name, mc.media_component_number);

        // Determine QCI from media type (TS 29.213 section 7.1.4)
        let qci = match mc.media_type {
            media_type::AUDIO => 1,       // Conversational Voice
            media_type::VIDEO => 2,       // Conversational Video (live)
            media_type::APPLICATION => 5, // IMS signalling
            media_type::CONTROL => 5,     // IMS signalling
            _ => 9,                       // Default non-GBR
        };
        let qos = qci_to_qos(qci);

        // Determine flow status
        let rule_flow_status = if mc.flow_status != 0 {
            mc.flow_status
        } else {
            flow_status::ENABLED
        };

        // Build flow descriptions from sub-components.
        // IPFilterRule direction: "permit out ..." = downlink (towards UE),
        // "permit in ..." = uplink (TS 29.214 section 5.3.8).
        let mut flows = Vec::new();
        for sub in &mc.sub_components {
            for flow_desc in &sub.flows {
                let direction = if flow_desc.starts_with("permit out") {
                    flow_direction::DOWNLINK
                } else if flow_desc.starts_with("permit in") {
                    flow_direction::UPLINK
                } else {
                    flow_direction::BIDIRECTIONAL
                };
                flows.push(FlowData {
                    direction,
                    description: flow_desc.clone(),
                });
            }
        }

        // If no sub-components, create a default permit-all flow pair
        if flows.is_empty() {
            flows.push(FlowData {
                direction: flow_direction::DOWNLINK,
                description: "permit out ip from any to any".to_string(),
            });
            flows.push(FlowData {
                direction: flow_direction::UPLINK,
                description: "permit in ip from any to any".to_string(),
            });
        }

        let rule = PccRuleData {
            name: rule_name,
            qos_index: qci,
            arp_priority_level: qos.priority,
            arp_pre_emption_capability: false,
            arp_pre_emption_vulnerability: true,
            flow_status: rule_flow_status,
            precedence: (idx as u32 + 1) * 10,
            mbr_downlink: mc.max_requested_bandwidth_dl as u64,
            mbr_uplink: mc.max_requested_bandwidth_ul as u64,
            gbr_downlink: if qos.resource_type == QciResourceType::Gbr {
                mc.max_requested_bandwidth_dl as u64
            } else {
                0
            },
            gbr_uplink: if qos.resource_type == QciResourceType::Gbr {
                mc.max_requested_bandwidth_ul as u64
            } else {
                0
            },
            flows,
        };

        rules.push(rule);
    }

    log::debug!(
        "Derived {} PCC rules from {} media components",
        rules.len(),
        ims_data.media_components.len()
    );

    rules
}

// ============================================================================
// Init / final
// ============================================================================

/// Initialize Gx interface
pub fn pcrf_gx_init() -> Result<(), String> {
    log::info!("PCRF Gx interface initialized (application id {GX_APPLICATION_ID})");
    Ok(())
}

/// Finalize Gx interface
pub fn pcrf_gx_final() {
    log::info!("PCRF Gx interface finalized");
}

/// ARP pre-emption values as stored in the subscription DB.
/// The DB stores the TS 29.212 wire enumeration directly
/// (0 = ENABLED, 1 = DISABLED).
mod arp_db_value {
    /// DB value meaning pre-emption capability enabled
    pub const CAPABILITY_ENABLED: u8 = 0;
    /// DB value meaning pre-emption vulnerability enabled
    pub const VULNERABILITY_ENABLED: u8 = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd_path::LocalIdentity;
    use nextgcore_diameter::rx::RX_APPLICATION_ID;

    fn local() -> LocalIdentity {
        LocalIdentity {
            host: "pcrf.epc.mnc001.mcc001.3gppnetwork.org".to_string(),
            realm: "epc.mnc001.mcc001.3gppnetwork.org".to_string(),
        }
    }

    fn build_test_ccr(
        session_id: &str,
        cc_request_type: u32,
        cc_request_number: u32,
    ) -> DiameterMessage {
        let mut ccr = nextgcore_diameter::gx::create_ccr(
            session_id,
            "pgw.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            nextgcore_diameter::gx::CcRequestType::from(cc_request_type),
            cc_request_number,
        );
        ccr.header.hop_by_hop_id = 0x1234;
        ccr.header.end_to_end_id = 0x5678;
        // Subscription-Id with IMSI
        let sub_id = Avp::mandatory(
            avp_code::SUBSCRIPTION_ID,
            AvpData::Grouped(vec![
                Avp::mandatory(avp_code::SUBSCRIPTION_ID_TYPE, AvpData::Enumerated(1)),
                Avp::mandatory(
                    avp_code::SUBSCRIPTION_ID_DATA,
                    AvpData::Utf8String("001010123456789".to_string()),
                ),
            ]),
        );
        ccr.add_avp(sub_id);
        nextgcore_diameter::gx::add_called_station_id(&mut ccr, "internet");
        nextgcore_diameter::gx::add_framed_ip_address(
            &mut ccr,
            std::net::Ipv4Addr::new(10, 45, 0, 2),
        );
        ccr
    }

    /// Encode + decode helper to force a real wire round trip
    fn roundtrip(msg: &DiameterMessage) -> DiameterMessage {
        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        DiameterMessage::decode(&mut bytes).expect("decode")
    }

    // ------------------------------------------------------------------
    // CCR parse / round trip
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_ccr_roundtrip() {
        let ccr = roundtrip(&build_test_ccr("gx-parse-1", 1, 0));
        let info = parse_ccr(&ccr).expect("parse_ccr");
        assert_eq!(info.session_id, "gx-parse-1");
        assert_eq!(info.cc_request_type, cc_request_type::INITIAL_REQUEST);
        assert_eq!(info.cc_request_number, 0);
        assert_eq!(info.imsi.as_deref(), Some("001010123456789"));
        assert_eq!(info.apn.as_deref(), Some("internet"));
        assert_eq!(info.framed_ipv4, Some([10, 45, 0, 2]));
        assert_eq!(info.origin_host, "pgw.epc.mnc001.mcc001.3gppnetwork.org");
    }

    #[test]
    fn test_parse_ccr_missing_cc_request_type() {
        let mut ccr = DiameterMessage::new_request(gx_cmd::CREDIT_CONTROL, GX_APPLICATION_ID);
        ccr.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("gx-strict-1".to_string()),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::AUTH_APPLICATION_ID,
            AvpData::Unsigned32(GX_APPLICATION_ID),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity("pgw.example.com".to_string()),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity("example.com".to_string()),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::DESTINATION_REALM,
            AvpData::DiameterIdentity("example.com".to_string()),
        ));
        // CC-Request-Type and CC-Request-Number intentionally omitted
        let ccr = roundtrip(&ccr);
        let err = parse_ccr(&ccr).unwrap_err();
        assert_eq!(err, GxRequestError::MissingAvp(gx_avp::CC_REQUEST_TYPE));
        assert_eq!(err.result_code(), result_code::DIAMETER_MISSING_AVP);
    }

    #[test]
    fn test_parse_ccr_missing_session_id() {
        let ccr = DiameterMessage::new_request(gx_cmd::CREDIT_CONTROL, GX_APPLICATION_ID);
        let err = parse_ccr(&ccr).unwrap_err();
        assert_eq!(err, GxRequestError::MissingAvp(avp_code::SESSION_ID));
    }

    #[test]
    fn test_parse_ccr_wrong_application() {
        let mut ccr = build_test_ccr("gx-wrong-app", 1, 0);
        // Replace Auth-Application-Id with the Rx application
        ccr.avps.retain(|a| a.code != avp_code::AUTH_APPLICATION_ID);
        ccr.add_avp(Avp::mandatory(
            avp_code::AUTH_APPLICATION_ID,
            AvpData::Unsigned32(RX_APPLICATION_ID),
        ));
        let ccr = roundtrip(&ccr);
        let err = parse_ccr(&ccr).unwrap_err();
        assert_eq!(err, GxRequestError::ApplicationUnsupported);
        assert_eq!(
            err.result_code(),
            result_code::DIAMETER_APPLICATION_UNSUPPORTED
        );
    }

    #[test]
    fn test_parse_ccr_event_request_rejected() {
        let ccr = roundtrip(&build_test_ccr("gx-event-1", 4, 0));
        let err = parse_ccr(&ccr).unwrap_err();
        assert_eq!(
            err,
            GxRequestError::InvalidAvpValue(gx_avp::CC_REQUEST_TYPE)
        );
        assert_eq!(err.result_code(), result_code::DIAMETER_INVALID_AVP_VALUE);
    }

    // ------------------------------------------------------------------
    // CCA building / round trip
    // ------------------------------------------------------------------

    #[test]
    fn test_handle_ccr_initial_full_cca() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        let ccr = roundtrip(&build_test_ccr("gx-cca-initial", 1, 0));
        let (cca, aborts) = handle_ccr(&ccr, &local());
        assert!(aborts.is_empty());

        // Wire round trip of the CCA itself
        let cca = roundtrip(&cca);
        assert!(cca.header.is_answer());
        assert_eq!(cca.header.command_code, gx_cmd::CREDIT_CONTROL);
        assert_eq!(cca.header.hop_by_hop_id, 0x1234);
        assert_eq!(cca.header.end_to_end_id, 0x5678);
        assert_eq!(cca.session_id(), Some("gx-cca-initial"));
        assert_eq!(cca.result_code(), Some(result_code::DIAMETER_SUCCESS));
        assert_eq!(
            cca.find_avp(gx_avp::CC_REQUEST_TYPE)
                .and_then(|a| a.as_u32()),
            Some(cc_request_type::INITIAL_REQUEST)
        );
        assert_eq!(
            cca.find_avp(gx_avp::CC_REQUEST_NUMBER)
                .and_then(|a| a.as_u32()),
            Some(0)
        );

        // Default-EPS-Bearer-QoS: QCI + ARP
        let deq = cca
            .find_vendor_avp(gx_avp::DEFAULT_EPS_BEARER_QOS, NEXTGCORE_3GPP_VENDOR_ID)
            .expect("Default-EPS-Bearer-QoS present");
        assert!(deq.is_mandatory());
        let deq_members = deq.parse_grouped().unwrap();
        let qci = find_avp(&deq_members, gx_avp::QOS_CLASS_IDENTIFIER)
            .and_then(|a| a.as_u32())
            .expect("QCI");
        assert!(qci >= 1);
        let arp =
            find_avp(&deq_members, gx_avp::ALLOCATION_RETENTION_PRIORITY).expect("ARP present");
        assert_eq!(arp.vendor_id, Some(NEXTGCORE_3GPP_VENDOR_ID));
        let arp_members = arp.parse_grouped().unwrap();
        assert!(find_avp(&arp_members, gx_avp::PRIORITY_LEVEL).is_some());
        assert!(find_avp(&arp_members, gx_avp::PRE_EMPTION_CAPABILITY).is_some());
        assert!(find_avp(&arp_members, gx_avp::PRE_EMPTION_VULNERABILITY).is_some());

        // QoS-Information with APN-AMBR
        let qi = cca
            .find_vendor_avp(gx_avp::QOS_INFORMATION, NEXTGCORE_3GPP_VENDOR_ID)
            .expect("QoS-Information present");
        let qi_members = qi.parse_grouped().unwrap();
        let ambr_dl = find_avp(&qi_members, gx_avp::APN_AGGREGATE_MAX_BITRATE_DL)
            .and_then(|a| a.as_u32())
            .expect("APN-AMBR-DL");
        assert!(ambr_dl > 0);

        // Charging-Rule-Install with full Charging-Rule-Definition
        let cri = cca
            .find_vendor_avp(gx_avp::CHARGING_RULE_INSTALL, NEXTGCORE_3GPP_VENDOR_ID)
            .expect("Charging-Rule-Install present");
        let cri_members = cri.parse_grouped().unwrap();
        let crd = find_avp(&cri_members, gx_avp::CHARGING_RULE_DEFINITION)
            .expect("Charging-Rule-Definition present");
        let crd_members = crd.parse_grouped().unwrap();
        let name = find_avp(&crd_members, gx_avp::CHARGING_RULE_NAME)
            .and_then(|a| a.as_octet_string())
            .expect("Charging-Rule-Name");
        assert_eq!(&name[..], b"pcrf-internet-default");
        assert!(find_avp(&crd_members, gx_avp::PRECEDENCE).is_some());
        assert!(find_avp(&crd_members, gx_avp::FLOW_STATUS).is_some());
        // Flow-Information sub-AVPs
        let flow_infos = find_all_avps(&crd_members, gx_avp::FLOW_INFORMATION);
        assert_eq!(flow_infos.len(), 2);
        let fi_members = flow_infos[0].parse_grouped().unwrap();
        let desc = find_avp(&fi_members, gx_avp::FLOW_DESCRIPTION)
            .and_then(|a| a.as_octet_string())
            .expect("Flow-Description");
        assert!(desc.starts_with(b"permit out"));
        assert_eq!(
            find_avp(&fi_members, gx_avp::FLOW_DIRECTION).and_then(|a| a.as_i32()),
            Some(flow_direction::DOWNLINK)
        );
        // Per-rule QoS-Information
        assert!(find_avp(&crd_members, gx_avp::QOS_INFORMATION).is_some());

        // Event-Triggers
        let triggers = find_all_avps(&cca.avps, gx_avp::EVENT_TRIGGER);
        assert!(!triggers.is_empty());
    }

    #[test]
    fn test_handle_ccr_update_unknown_session() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        let ccr = roundtrip(&build_test_ccr("gx-unknown-update", 2, 1));
        let (cca, _) = handle_ccr(&ccr, &local());
        let cca = roundtrip(&cca);
        // 5xxx is a permanent failure, not a protocol error: no E-bit
        assert!(!cca.header.is_error());
        assert_eq!(
            cca.result_code(),
            Some(result_code::DIAMETER_UNKNOWN_SESSION_ID)
        );
    }

    #[test]
    fn test_handle_ccr_termination_unknown_session() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        let ccr = roundtrip(&build_test_ccr("gx-unknown-term", 3, 2));
        let (cca, _) = handle_ccr(&ccr, &local());
        assert_eq!(
            roundtrip(&cca).result_code(),
            Some(result_code::DIAMETER_UNKNOWN_SESSION_ID)
        );
    }

    #[test]
    fn test_handle_ccr_lifecycle_initial_update_termination() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        let sid = "gx-lifecycle-1";
        // INITIAL
        let (cca, _) = handle_ccr(&roundtrip(&build_test_ccr(sid, 1, 0)), &local());
        assert_eq!(cca.result_code(), Some(result_code::DIAMETER_SUCCESS));
        // Session exists with peer host recorded
        {
            let ctx = pcrf_self();
            let context = ctx.read().unwrap();
            let session = context.gx_session_find_by_sid(sid).expect("session");
            assert_eq!(
                session.peer_host.as_deref(),
                Some("pgw.epc.mnc001.mcc001.3gppnetwork.org")
            );
            assert!(session.has_ipv4);
        }
        // UPDATE re-affirms QoS but does not reinstall rules
        let (cca, _) = handle_ccr(&roundtrip(&build_test_ccr(sid, 2, 1)), &local());
        let cca = roundtrip(&cca);
        assert_eq!(cca.result_code(), Some(result_code::DIAMETER_SUCCESS));
        assert!(cca
            .find_vendor_avp(gx_avp::CHARGING_RULE_INSTALL, NEXTGCORE_3GPP_VENDOR_ID)
            .is_none());
        assert!(cca
            .find_vendor_avp(gx_avp::DEFAULT_EPS_BEARER_QOS, NEXTGCORE_3GPP_VENDOR_ID)
            .is_some());
        // TERMINATION removes the session
        let (cca, aborts) = handle_ccr(&roundtrip(&build_test_ccr(sid, 3, 2)), &local());
        let cca = roundtrip(&cca);
        assert_eq!(cca.result_code(), Some(result_code::DIAMETER_SUCCESS));
        assert!(aborts.is_empty());
        assert!(cca
            .find_vendor_avp(gx_avp::CHARGING_RULE_INSTALL, NEXTGCORE_3GPP_VENDOR_ID)
            .is_none());
        {
            let ctx = pcrf_self();
            let context = ctx.read().unwrap();
            assert!(context.gx_session_find_by_sid(sid).is_none());
        }
        // Second termination is now an unknown session
        let (cca, _) = handle_ccr(&roundtrip(&build_test_ccr(sid, 3, 3)), &local());
        assert_eq!(
            cca.result_code(),
            Some(result_code::DIAMETER_UNKNOWN_SESSION_ID)
        );
    }

    #[test]
    fn test_cca_error_carries_failed_avp() {
        crate::context::pcrf_context_init(1024);
        crate::fd_path::pcrf_fd_set_local_identity(local());

        let mut ccr = DiameterMessage::new_request(gx_cmd::CREDIT_CONTROL, GX_APPLICATION_ID);
        ccr.header.hop_by_hop_id = 7;
        ccr.header.end_to_end_id = 8;
        ccr.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("gx-failed-avp".to_string()),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::AUTH_APPLICATION_ID,
            AvpData::Unsigned32(GX_APPLICATION_ID),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity("pgw.example.com".to_string()),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity("example.com".to_string()),
        ));
        ccr.add_avp(Avp::mandatory(
            avp_code::DESTINATION_REALM,
            AvpData::DiameterIdentity("example.com".to_string()),
        ));

        let (cca, _) = handle_ccr(&roundtrip(&ccr), &local());
        let cca = roundtrip(&cca);
        assert_eq!(cca.result_code(), Some(result_code::DIAMETER_MISSING_AVP));
        let failed = cca.find_avp(base_avp::FAILED_AVP).expect("Failed-AVP");
        let members = failed.parse_grouped().unwrap();
        assert_eq!(members[0].code, gx_avp::CC_REQUEST_TYPE);
    }

    // ------------------------------------------------------------------
    // RAR / RAA round trip
    // ------------------------------------------------------------------

    #[test]
    fn test_build_rar_install_roundtrip() {
        let rules = derive_pcc_rules(
            &ImsData {
                media_components: vec![MediaComponent {
                    media_component_number: 1,
                    media_type: media_type::AUDIO,
                    max_requested_bandwidth_dl: 64000,
                    max_requested_bandwidth_ul: 64000,
                    flow_status: flow_status::ENABLED,
                    sub_components: vec![MediaSubComponent {
                        flow_number: 1,
                        flow_usage: 0,
                        flows: vec![
                            "permit out 17 from 10.0.0.1 to 10.0.0.2".to_string(),
                            "permit in 17 from 10.0.0.2 to 10.0.0.1".to_string(),
                        ],
                    }],
                }],
            },
            "rx-rule",
        );

        let rar = build_rar(
            "gx-rar-1",
            &local(),
            "pgw.example.com",
            "example.com",
            &RarAction::Install(rules),
        );
        let rar = roundtrip(&rar);

        assert!(rar.header.is_request());
        assert_eq!(rar.header.command_code, gx_cmd::RE_AUTH);
        assert_eq!(rar.header.application_id, GX_APPLICATION_ID);
        assert_eq!(rar.session_id(), Some("gx-rar-1"));
        assert_eq!(rar.destination_host(), Some("pgw.example.com"));
        assert_eq!(rar.destination_realm(), Some("example.com"));
        assert_eq!(
            rar.find_avp(avp_code::RE_AUTH_REQUEST_TYPE)
                .and_then(|a| a.as_u32()),
            Some(re_auth_request_type::AUTHORIZE_ONLY)
        );

        let cri = rar
            .find_vendor_avp(gx_avp::CHARGING_RULE_INSTALL, NEXTGCORE_3GPP_VENDOR_ID)
            .expect("install present");
        let members = cri.parse_grouped().unwrap();
        let crd = find_avp(&members, gx_avp::CHARGING_RULE_DEFINITION).expect("definition");
        let crd_members = crd.parse_grouped().unwrap();
        let name = find_avp(&crd_members, gx_avp::CHARGING_RULE_NAME)
            .and_then(|a| a.as_octet_string())
            .unwrap();
        assert_eq!(&name[..], b"rx-rule-mc1");
        // GBR rule (QCI 1): GBR AVPs present in rule QoS-Information
        let qi = find_avp(&crd_members, gx_avp::QOS_INFORMATION).unwrap();
        let qi_members = qi.parse_grouped().unwrap();
        assert_eq!(
            find_avp(&qi_members, gx_avp::QOS_CLASS_IDENTIFIER).and_then(|a| a.as_u32()),
            Some(1)
        );
        assert!(find_avp(&qi_members, gx_avp::GUARANTEED_BITRATE_DL).is_some());
    }

    #[test]
    fn test_build_rar_remove_roundtrip() {
        let rar = build_rar(
            "gx-rar-2",
            &local(),
            "pgw.example.com",
            "example.com",
            &RarAction::Remove(vec!["rx-rule-mc1".to_string(), "rx-rule-mc2".to_string()]),
        );
        let rar = roundtrip(&rar);

        let crr = rar
            .find_vendor_avp(gx_avp::CHARGING_RULE_REMOVE, NEXTGCORE_3GPP_VENDOR_ID)
            .expect("remove present");
        let members = crr.parse_grouped().unwrap();
        let names: Vec<_> = find_all_avps(&members, gx_avp::CHARGING_RULE_NAME)
            .iter()
            .map(|a| a.as_octet_string().unwrap().to_vec())
            .collect();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], b"rx-rule-mc1");
        assert_eq!(names[1], b"rx-rule-mc2");
    }

    #[test]
    fn test_parse_raa_result_code() {
        let rar = build_rar(
            "gx-raa-1",
            &local(),
            "pgw.example.com",
            "example.com",
            &RarAction::Remove(vec!["r1".to_string()]),
        );
        let mut raa = DiameterMessage::new_answer(&rar);
        raa.add_avp(Avp::mandatory(
            avp_code::SESSION_ID,
            AvpData::Utf8String("gx-raa-1".to_string()),
        ));
        raa.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(result_code::DIAMETER_SUCCESS),
        ));
        let raa = roundtrip(&raa);
        assert_eq!(parse_raa(&raa), Ok(result_code::DIAMETER_SUCCESS));
    }

    #[test]
    fn test_parse_raa_experimental_result() {
        let rar = build_rar(
            "gx-raa-2",
            &local(),
            "pgw.example.com",
            "example.com",
            &RarAction::Remove(vec!["r1".to_string()]),
        );
        let mut raa = DiameterMessage::new_answer(&rar);
        raa.add_avp(Avp::mandatory(
            avp_code::EXPERIMENTAL_RESULT,
            AvpData::Grouped(vec![
                Avp::mandatory(
                    avp_code::VENDOR_ID,
                    AvpData::Unsigned32(NEXTGCORE_3GPP_VENDOR_ID),
                ),
                Avp::mandatory(
                    avp_code::EXPERIMENTAL_RESULT_CODE,
                    AvpData::Unsigned32(nextgcore_diameter::gx::exp_result::PCC_RULE_EVENT),
                ),
            ]),
        ));
        let raa = roundtrip(&raa);
        assert_eq!(
            parse_raa(&raa),
            Ok(nextgcore_diameter::gx::exp_result::PCC_RULE_EVENT)
        );
        // No result codes at all -> error
        let empty = DiameterMessage::new_answer(&rar);
        assert!(parse_raa(&roundtrip(&empty)).is_err());
    }

    // ------------------------------------------------------------------
    // Policy derivation
    // ------------------------------------------------------------------

    #[test]
    fn test_qci_to_qos() {
        let qos1 = qci_to_qos(1);
        assert_eq!(qos1.qci, 1);
        assert_eq!(qos1.resource_type, QciResourceType::Gbr);
        assert_eq!(qos1.priority, 2);
        assert_eq!(qos1.packet_delay_budget_ms, 100);

        let qos5 = qci_to_qos(5);
        assert_eq!(qos5.resource_type, QciResourceType::NonGbr);
        assert_eq!(qos5.priority, 1);

        let qos9 = qci_to_qos(9);
        assert_eq!(qos9.resource_type, QciResourceType::NonGbr);
        assert_eq!(qos9.priority, 9);

        let qos_unknown = qci_to_qos(200);
        assert_eq!(qos_unknown.resource_type, QciResourceType::NonGbr);
    }

    #[test]
    fn test_derive_pcc_rules_audio() {
        let ims_data = ImsData {
            media_components: vec![MediaComponent {
                media_component_number: 1,
                media_type: media_type::AUDIO,
                max_requested_bandwidth_dl: 64000,
                max_requested_bandwidth_ul: 64000,
                flow_status: flow_status::ENABLED,
                sub_components: vec![MediaSubComponent {
                    flow_number: 1,
                    flow_usage: 0,
                    flows: vec![
                        "permit out 17 from 10.0.0.1 to 10.0.0.2".to_string(),
                        "permit in 17 from 10.0.0.2 to 10.0.0.1".to_string(),
                    ],
                }],
            }],
        };

        let rules = derive_pcc_rules(&ims_data, "test-rule");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].qos_index, 1); // Audio -> QCI 1
        assert_eq!(rules[0].mbr_downlink, 64000);
        assert_eq!(rules[0].gbr_downlink, 64000); // GBR for QCI 1
        assert_eq!(rules[0].flows.len(), 2);
        assert_eq!(rules[0].flows[0].direction, flow_direction::DOWNLINK);
        assert_eq!(rules[0].flows[1].direction, flow_direction::UPLINK);
    }

    #[test]
    fn test_derive_pcc_rules_video_and_data() {
        let ims_data = ImsData {
            media_components: vec![
                MediaComponent {
                    media_component_number: 1,
                    media_type: media_type::VIDEO,
                    max_requested_bandwidth_dl: 1000000,
                    max_requested_bandwidth_ul: 500000,
                    flow_status: 0,
                    sub_components: vec![],
                },
                MediaComponent {
                    media_component_number: 2,
                    media_type: media_type::APPLICATION,
                    max_requested_bandwidth_dl: 100000,
                    max_requested_bandwidth_ul: 100000,
                    flow_status: 0,
                    sub_components: vec![],
                },
            ],
        };

        let rules = derive_pcc_rules(&ims_data, "multi");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].qos_index, 2); // Video -> QCI 2
        assert_eq!(rules[1].qos_index, 5); // Application -> QCI 5
        assert_eq!(rules[1].gbr_downlink, 0); // Non-GBR for QCI 5
    }

    #[test]
    fn test_build_subscriber_session_data_fallback() {
        // No DB in unit tests -> default profile with one catch-all rule
        let data = build_subscriber_session_data("001010123456789", "internet");
        assert!(data.ambr_downlink > 0);
        assert!(data.ambr_uplink > 0);
        assert!(data.qos_index > 0);
        assert!(data.arp_priority_level > 0);
        assert_eq!(data.pcc_rules.len(), 1);
        assert!(!data.event_triggers.is_empty());
        assert_eq!(data.pcc_rules[0].name, "pcrf-internet-default");
    }

    #[test]
    fn test_pcrf_gx_init_final() {
        assert!(pcrf_gx_init().is_ok());
        pcrf_gx_final();
    }
}
