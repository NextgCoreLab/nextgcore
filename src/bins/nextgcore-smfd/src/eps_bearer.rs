//! #619: dedicated EPS bearers at the PGW-C: activation (TS 23.401 §5.4.1),
//! modification (§5.4.2.1) and deactivation (§5.4.4.1).
//!
//! Before this, an S5/S8 session on this PGW-C only ever held its default bearer:
//! `build_create_bearer_request` and `handle_create_bearer_response` existed with no
//! production caller. This module is the procedure that calls them.
//!
//! **Triggers.**
//! - A PCC rule. This PGW-C has no Gx transport and does not call a PCF for an EPS
//!   session, so the rules are the locally configured ones (`smf.pcc_rules`), activated
//!   when the PDN connection is established. TS 23.203 §6.3 calls these predefined
//!   rules; a PCEF may activate them without a PCRF.
//! - The UE's Bearer Resource Command (TS 23.401 §5.4.5) asking for new packet filters
//!   with a Flow QoS. The Create Bearer Request then carries the UE's PTI and the
//!   Command's sequence number (TS 29.274 §7.6).
//!
//! **The procedure** (§5.4.1 steps 1-2 and 7-8 on S5/S8):
//! 1. Store the bearer and its packet filters, with EBI 0.
//! 2. N4: create the bearer's S5/S8-U uplink PDR on a UPF-chosen F-TEID, and its QER.
//! 3. Send the Create Bearer Request with that F-TEID, the Bearer QoS and the TFT.
//! 4. On an accepted Create Bearer Response, record the EBI the MME assigned and the SGW's
//!    S5/S8-U F-TEID, and create the downlink PDR on the TFT's downlink filters and its
//!    FAR toward that F-TEID.
//!
//! Any failure removes what was installed, so a refused bearer leaves no rule at the
//! PGW-U and no entry in the store.
//!
//! **Modification and deactivation** on the UE's Bearer Resource Command naming an
//! existing dedicated bearer (TS 23.401 §5.4.5, [`modify_on_command`]): the TAD and the
//! requested QoS are applied, then an Update Bearer Request (TFT and, when it changed,
//! Bearer QoS; TS 29.274 §7.2.15) goes out. Once it is accepted, the store and the
//! PGW-U's QER and downlink PDR follow. A Command that leaves the bearer no packet
//! filter becomes a Delete Bearer Request (§7.2.9.2). Both are the Command's
//! Triggered message, carrying the UE's PTI. The MME's Delete Bearer Command
//! ([`deactivate_on_command`]) shares the deletion. These requests run on the
//! paging-dependent bearer-procedure N3 of `nextgcore_gtp::v2::xact` (#1228).
//!
//! **Rule ids.** The EBI is unknown until step 4, so the ids come from the bearer's
//! `eps_rule_index` k (1..=15): UL PDR and QER `0x60 + k`, DL PDR and FAR `0x80 + k`.
//! None collides with the ids #583's EPS→5GS handover uses (`0x10`, `0x30`, `0x50` + EBI).
//! The handover removes these rules when it completes.

use crate::context::{self, FlowDirection, SmfBearer, SmfSess};
use crate::eps_tft::{self, PacketFilter};
use crate::gtp_build::{gtp2_message_type, Gtp2Cause};
use crate::gtp_handler::{
    handle_create_bearer_response, BearerContextCreated, CreateBearerResponse,
    CreateBearerResponseResult,
};
use crate::gtp_path::S5S8Server;
use nextgcore_gtp::v2::{Gtp2FTeidIe, Gtp2IeType, Gtp2Message};
use serde::Deserialize;

/// UL PDR / QER base for a dedicated EPS bearer's PGW-U rules.
pub(crate) const EPS_UL_RULE_BASE: u16 = 0x60;
/// DL PDR / FAR base.
pub(crate) const EPS_DL_RULE_BASE: u16 = 0x80;
/// Precedence of a dedicated bearer's DL PDR: ahead of the default bearer's PDR 2
/// (precedence 100; lower wins, TS 29.244 §8.2.11), as #583's are.
const DEDICATED_DL_PRECEDENCE: u32 = 50;

/// The PGW-U rule ids of a bearer with rule index `k`: (UL PDR/QER, DL PDR/FAR).
pub(crate) fn rule_ids(k: u8) -> (u16, u16) {
    (
        EPS_UL_RULE_BASE + u16::from(k),
        EPS_DL_RULE_BASE + u16::from(k),
    )
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// A bit rate pair in bit/s.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub struct BitRates {
    #[serde(default)]
    pub uplink: u64,
    #[serde(default)]
    pub downlink: u64,
}

/// Allocation and Retention Priority (TS 23.401 §4.7.3).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct Arp {
    pub priority_level: u8,
    #[serde(default)]
    pub pre_emption_capability: bool,
    #[serde(default = "yes")]
    pub pre_emption_vulnerability: bool,
}

fn yes() -> bool {
    true
}

impl Default for Arp {
    fn default() -> Self {
        Self {
            priority_level: 8,
            pre_emption_capability: false,
            pre_emption_vulnerability: true,
        }
    }
}

/// The direction of a configured flow.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Downlink,
    Uplink,
    Bidirectional,
}

/// One flow of a local PCC rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LocalFlow {
    pub direction: Direction,
    /// A TS 29.212 flow description in the downlink orientation:
    /// `permit out <proto> from <remote> [<port>] to assigned [<port>]`.
    pub description: String,
}

/// `smf.pcc_rules[]`: a PCC rule this PGW-C activates as a dedicated EPS bearer.
///
/// ```yaml
/// smf:
///   pcc_rules:
///     - name: voice
///       apn: internet        # every APN when omitted
///       qci: 1
///       arp: { priority_level: 2, pre_emption_vulnerability: true }
///       mbr: { uplink: 128000, downlink: 128000 }   # bit/s
///       gbr: { uplink: 64000, downlink: 64000 }     # bit/s
///       flows:
///         - direction: downlink
///           description: permit out 17 from any 5004 to assigned
///         - direction: uplink
///           description: permit out 17 from any to assigned 5004
/// ```
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LocalPccRule {
    pub name: String,
    #[serde(default)]
    pub apn: Option<String>,
    pub qci: u8,
    #[serde(default)]
    pub arp: Arp,
    #[serde(default)]
    pub mbr: BitRates,
    #[serde(default)]
    pub gbr: BitRates,
    pub flows: Vec<LocalFlow>,
}

impl LocalPccRule {
    /// Whether the rule applies to a PDN connection to `apn` (case-insensitive, TS 23.003
    /// §9.1 makes APNs case-insensitive).
    pub fn applies_to(&self, apn: &str) -> bool {
        self.apn
            .as_deref()
            .is_none_or(|a| a.eq_ignore_ascii_case(apn))
    }

    /// The activation request this rule makes.
    pub fn to_request(&self) -> DedicatedBearerRequest {
        DedicatedBearerRequest {
            qos: context::Qos {
                index: self.qci,
                arp_priority_level: self.arp.priority_level,
                arp_preempt_cap: self.arp.pre_emption_capability,
                arp_preempt_vuln: self.arp.pre_emption_vulnerability,
                mbr_uplink: self.mbr.uplink,
                mbr_downlink: self.mbr.downlink,
                gbr_uplink: self.gbr.uplink,
                gbr_downlink: self.gbr.downlink,
            },
            filters: self
                .flows
                .iter()
                .enumerate()
                .map(|(n, f)| PacketFilter {
                    direction: match f.direction {
                        Direction::Downlink => FlowDirection::DownlinkOnly,
                        Direction::Uplink => FlowDirection::UplinkOnly,
                        Direction::Bidirectional => FlowDirection::Bidirectional,
                    },
                    identifier: (n as u8 + 1) & 0x0f,
                    precedence: n as u8,
                    flow_description: f.description.clone(),
                })
                .collect(),
            pcc_rule_name: Some(self.name.clone()),
            pti: None,
            command: None,
        }
    }
}

// ---------------------------------------------------------------------------
// The procedure
// ---------------------------------------------------------------------------

/// What a trigger asks for.
#[derive(Debug, Clone)]
pub struct DedicatedBearerRequest {
    /// The bearer's QoS, rates in bit/s.
    pub qos: context::Qos,
    pub filters: Vec<PacketFilter>,
    pub pcc_rule_name: Option<String>,
    /// The UE's PTI, when the UE asked (Bearer Resource Command).
    pub pti: Option<u8>,
    /// The Command's source and sequence number, when a Bearer Resource Command
    /// triggered this. The Create Bearer Request is then the Command's Triggered message:
    /// it carries the Command's sequence number (TS 29.274 §7.6) and goes back to the
    /// Command's source address and port (§4.2.1.2). Otherwise it is an Initial message,
    /// sent to the SGW's S5/S8-C address at port 2123 (§4.2.1.1).
    pub command: Option<(std::net::SocketAddr, u32)>,
}

/// Why an activation did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationError {
    /// Nothing was sent to the SGW-C; the cause is what a Command is answered with.
    NotSent(Gtp2Cause, String),
    /// The Create Bearer Request was sent and the bearer was not established.
    Failed(String),
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSent(cause, why) => write!(f, "not requested ({cause:?}): {why}"),
            Self::Failed(why) => write!(f, "{why}"),
        }
    }
}

/// The EBI of the session's default bearer: the first bearer stored for it, which is the
/// one Create Session established.
fn default_ebi(ctx: &context::SmfContext, sess: &SmfSess) -> Option<u8> {
    sess.bearer_ids
        .iter()
        .filter_map(|&id| ctx.bearer_find_by_id(id))
        .find_map(|b| b.assigned_ebi())
}

/// Held while a bearer's rule index is chosen and claimed (#1182 review), so two
/// activations on one session cannot take the same one.
static RULE_INDEX_CLAIM: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The lowest rule index no other bearer of the session uses.
fn free_rule_index(ctx: &context::SmfContext, sess: &SmfSess) -> Option<u8> {
    let used: Vec<u8> = sess
        .bearer_ids
        .iter()
        .filter_map(|&id| ctx.bearer_find_by_id(id))
        .map(|b| b.eps_rule_index)
        .collect();
    (1..=15u8).find(|k| !used.contains(k))
}

/// The downlink SDF filters of a set of packet filters.
fn downlink_descriptions(filters: &[PacketFilter]) -> Vec<String> {
    filters
        .iter()
        .filter(|f| f.direction != FlowDirection::UplinkOnly)
        .map(|f| f.flow_description.clone())
        .collect()
}

/// The Outer Header Creation toward the bearer's SGW S5/S8-U endpoint, IPv4 or IPv6
/// (TS 29.244 §8.2.56: GTP-U/UDP/IPv4 is 0x0100, GTP-U/UDP/IPv6 0x0200; IPv4 when the
/// F-TEID carries both). `None` when the F-TEID carries no address.
fn sgw_outer_header(bearer: &SmfBearer) -> Option<(u16, Option<[u8; 4]>, Option<[u8; 16]>)> {
    match (bearer.sgw_s5u_ip.ipv4, bearer.sgw_s5u_ip.ipv6) {
        (Some(v4), _) => Some((0x0100, Some(v4.octets()), None)),
        (None, Some(v6)) => Some((0x0200, None, Some(v6.octets()))),
        (None, None) => None,
    }
}

/// The bearer's downlink rules at the PGW-U: FAR `0x80+k` toward the SGW's S5/S8-U
/// F-TEID and PDR `0x80+k` on the TFT's downlink filters, metered by QER `0x60+k`.
fn downlink_rules(
    bearer: &SmfBearer,
    ue_ipv4: std::net::Ipv4Addr,
    dl_filters: Vec<String>,
) -> Option<(crate::n4_build::FarParams, crate::n4_build::PdrParams)> {
    let (ohc, v4, v6) = sgw_outer_header(bearer)?;
    let (ul, dl) = rule_ids(bearer.eps_rule_index);
    Some((
        crate::n4_build::FarParams {
            far_id: u32::from(dl),
            apply_action: crate::n4_build::apply_action::FORW,
            destination_interface: Some(0), // Access: toward the SGW-U
            outer_header_creation: Some((ohc, bearer.sgw_s5u_teid, v4, v6)),
            network_instance: None,
        },
        crate::n4_build::PdrParams {
            pdr_id: dl,
            precedence: DEDICATED_DL_PRECEDENCE,
            source_interface: 1, // Core
            ue_ip_address: Some((Some(ue_ipv4.octets()), None, false)),
            sdf_filters: dl_filters,
            far_id: Some(u32::from(dl)),
            qer_id: Some(u32::from(ul)),
            urr_ids: vec![crate::SESSION_URR_ID],
            ..Default::default()
        },
    ))
}

/// The QER of a bearer with QoS `qos`: its MBR and GBR, in bit/s as `n4_build` takes
/// them.
fn bearer_qer(qer_id: u16, qos: &context::Qos) -> crate::n4_build::QerParams {
    crate::n4_build::QerParams {
        qer_id: u32::from(qer_id),
        gate_status: (0, 0),
        mbr: (qos.mbr_uplink > 0 || qos.mbr_downlink > 0)
            .then_some((qos.mbr_uplink, qos.mbr_downlink)),
        gbr: (qos.gbr_uplink > 0 || qos.gbr_downlink > 0)
            .then_some((qos.gbr_uplink, qos.gbr_downlink)),
        qfi: None,
    }
}

/// Remove the bearer and whatever PGW-U rules it has (`with_dl` when step 4 ran).
async fn roll_back(sess: &SmfSess, bearer: &SmfBearer, with_dl: bool) {
    let (ul, dl) = rule_ids(bearer.eps_rule_index);
    let mut params = crate::n4_build::SessionModificationParams {
        remove_pdr_ids: vec![ul],
        remove_qer_ids: vec![u32::from(ul)],
        ..Default::default()
    };
    if with_dl {
        params.remove_pdr_ids.push(dl);
        params.remove_far_ids.push(u32::from(dl));
    }
    if let Err(e) = crate::pfcp_modify_with(sess.smf_n4_seid, sess.upf_n4_seid, &params).await {
        log::warn!(
            "dedicated bearer rollback: the PGW-U rules of rule index {} were not removed: {e}",
            bearer.eps_rule_index
        );
    }
    if let Ok(ctx) = context::smf_self().read() {
        ctx.bearer_remove(bearer.id);
    }
}

/// Delete a dedicated bearer here and its PGW-U rules, sending nothing over S5/S8
/// (#1194, a Create Session Request collided with it, TS 29.274 §7.2.1). `false` for a
/// bearer this module did not install (`eps_rule_index` 0, e.g. one that came over N26):
/// its rules are not this module's to remove.
pub(crate) async fn delete_dedicated_bearer_locally(sess: &SmfSess, bearer: &SmfBearer) -> bool {
    if bearer.eps_rule_index == 0 {
        return false;
    }
    let with_dl = !downlink_descriptions(&stored_filters(bearer)).is_empty();
    roll_back(sess, bearer, with_dl).await;
    true
}

/// Decode a Create Bearer Response (TS 29.274 §7.2.4) into the handler's struct.
///
/// The SGW's S5/S8-U F-TEID is instance 2 of the Bearer Context (Table 7.2.4-2), the
/// PGW's own instance 3; instance 0 and 1 are the S1-U eNodeB and SGW F-TEIDs, which a
/// Serving GW does not send on S5/S8.
pub(crate) fn parse_create_bearer_response(raw: &[u8]) -> Result<CreateBearerResponse, String> {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = Gtp2Message::decode(&mut bytes).map_err(|e| format!("undecodable: {e}"))?;
    if msg.header.message_type != gtp2_message_type::CREATE_BEARER_RESPONSE {
        return Err(format!(
            "message type {} is not a Create Bearer Response",
            msg.header.message_type
        ));
    }
    // A cause value this node does not know is a refusal it cannot name: it is not an
    // acceptance (TS 29.274 §8.4, 16-63 are acceptances and all of them are known).
    let cause_of = |v: Option<u8>| {
        v.map_or(Gtp2Cause::MandatoryIeMissing, |c| {
            Gtp2Cause::try_from(c).unwrap_or(Gtp2Cause::RequestRejectedReasonNotSpecified)
        })
    };
    let cause = cause_of(
        msg.get_ie(Gtp2IeType::Cause as u8, 0)
            .and_then(|ie| ie.value.first().copied()),
    );
    let bearer_context = match msg.bearer_context(0) {
        Ok(Some(bc)) => {
            let fteid = |inst: u8| {
                bc.get_ie(Gtp2IeType::FTeid as u8, inst)
                    .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok())
                    .map(|f| crate::gtp_build::FTeid {
                        interface_type: f.interface_type,
                        teid_present: true,
                        ipv4_present: f.ipv4_addr.is_some(),
                        ipv6_present: f.ipv6_addr.is_some(),
                        teid: f.teid,
                        ipv4_addr: f.ipv4_addr.map(std::net::Ipv4Addr::from),
                        ipv6_addr: f.ipv6_addr.map(std::net::Ipv6Addr::from),
                    })
            };
            Some(BearerContextCreated {
                ebi: bc.ebi().unwrap_or(0),
                cause: cause_of(
                    bc.get_ie(Gtp2IeType::Cause as u8, 0)
                        .and_then(|ie| ie.value.first().copied()),
                ),
                s5u_sgw_f_teid: fteid(2),
                s5u_pgw_f_teid: fteid(3),
                ..Default::default()
            })
        }
        Ok(None) => None,
        Err(e) => return Err(format!("Bearer Context undecodable: {e}")),
    };
    Ok(CreateBearerResponse {
        cause,
        bearer_context,
    })
}

/// Activate a dedicated EPS bearer on session `sess_id` (TS 23.401 §5.4.1).
///
/// Returns the stored bearer, with the EBI the MME assigned.
pub async fn activate(
    server: &S5S8Server,
    sess_id: u64,
    mut req: DedicatedBearerRequest,
) -> Result<SmfBearer, ActivationError> {
    use ActivationError::{Failed, NotSent};

    let handle = context::smf_self();
    // Everything read from the store is read here, and the guard dropped before any await.
    let prepared = {
        let ctx = handle
            .read()
            .map_err(|_| NotSent(Gtp2Cause::SystemFailure, "context poisoned".into()))?;
        let sess = ctx
            .sess_find_by_id(sess_id)
            .ok_or_else(|| NotSent(Gtp2Cause::ContextNotFound, format!("no session {sess_id}")))?;
        // The SGW's current S5/S8-C F-TEID: an SGW relocation's Modify Bearer Request
        // replaces it, so a later bearer goes to the new SGW.
        let sgw_ip = sess
            .sgw_s5c_ip
            .ipv4
            .map(std::net::IpAddr::V4)
            .or(sess.sgw_s5c_ip.ipv6.map(std::net::IpAddr::V6));
        let peer = match (req.command, sgw_ip) {
            (Some((from, _)), _) => from,
            (None, Some(ip)) => std::net::SocketAddr::new(ip, crate::gtp_path::sgw_port()),
            (None, None) => {
                return Err(NotSent(
                    Gtp2Cause::ContextNotFound,
                    "the session has no SGW-C S5/S8-C address".into(),
                ))
            }
        };
        let linked_ebi = default_ebi(&ctx, &sess).ok_or_else(|| {
            NotSent(
                Gtp2Cause::ContextNotFound,
                "the session has no default bearer".into(),
            )
        })?;
        let ue_ipv4 = sess.ipv4_addr.ok_or_else(|| {
            NotSent(
                Gtp2Cause::ContextNotFound,
                "the session has no PDN address".into(),
            )
        })?;
        // The precedences the PDN connection's TFTs already use (TS 24.301 §6.4.2.4 d)).
        let taken: Vec<u8> = sess
            .bearer_ids
            .iter()
            .filter_map(|&id| ctx.bearer_find_by_id(id))
            .flat_map(|b| b.pf_ids)
            .filter_map(|id| ctx.pf_find_by_id(id))
            .map(|pf| pf.precedence)
            .collect();
        (sess, peer, linked_ebi, ue_ipv4, taken)
    };
    let (sess, peer, linked_ebi, ue_ipv4, taken) = prepared;

    if req.filters.is_empty() {
        return Err(NotSent(
            Gtp2Cause::SemanticErrorInTheTadOperation,
            "a dedicated bearer needs at least one packet filter".into(),
        ));
    }
    // TS 23.401 §5.4.5 step 5, TS 24.301 §6.4.2.4 c) 2): a dedicated bearer's TFT holds
    // an uplink filter; a downlink-only one gets the PGW's disallowing filter.
    ensure_uplink_filter(&mut req.filters, &taken);
    let tft = eps_tft::encode(eps_tft::op::CREATE_NEW_TFT, &req.filters)
        .map_err(|e| NotSent(Gtp2Cause::SemanticErrorInTheTadOperation, e))?;

    // Step 1: the bearer and its packet filters, stored with EBI 0. Its rule index is
    // chosen and claimed in one critical section (#1182 review): two activations on
    // one session (a local rule and a Bearer Resource Command) run on different tasks,
    // and must not both take k, or their PGW-U rules would collide.
    let (mut bearer, rule_index) = {
        let ctx = handle
            .read()
            .map_err(|_| NotSent(Gtp2Cause::SystemFailure, "context poisoned".into()))?;
        let _claim = RULE_INDEX_CLAIM.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = ctx
            .sess_find_by_id(sess.id)
            .ok_or_else(|| NotSent(Gtp2Cause::ContextNotFound, format!("no session {sess_id}")))?;
        let rule_index = free_rule_index(&ctx, &fresh).ok_or_else(|| {
            NotSent(
                Gtp2Cause::NoResourcesAvailable,
                "the session already holds 15 dedicated bearers".into(),
            )
        })?;
        let mut bearer = ctx.bearer_add(sess.id).ok_or_else(|| {
            NotSent(
                Gtp2Cause::NoResourcesAvailable,
                "the bearer table is full".into(),
            )
        })?;
        bearer.ebi = 0;
        bearer.qos = req.qos.clone();
        bearer.pcc_rule_name = req.pcc_rule_name.clone();
        bearer.eps_rule_index = rule_index;
        ctx.bearer_update(&bearer);
        for f in &req.filters {
            if let Some(mut pf) = ctx.pf_add(bearer.id) {
                pf.direction = f.direction;
                pf.identifier = f.identifier;
                pf.precedence = f.precedence;
                pf.flow_description = Some(f.flow_description.clone());
                ctx.pf_update(&pf);
            }
        }
        // `pf_add` linked the filters into the stored bearer; take that copy.
        (
            ctx.bearer_find_by_id(bearer.id).unwrap_or(bearer),
            rule_index,
        )
    };

    // Step 2: the S5/S8-U uplink at the PGW-U, on an F-TEID it chooses.
    let (ul, dl) = rule_ids(rule_index);
    let qer = bearer_qer(ul, &req.qos);
    let params = crate::n4_build::SessionModificationParams {
        create_qers: vec![qer],
        create_pdrs: vec![crate::n4_build::PdrParams {
            pdr_id: ul,
            precedence: 100,
            source_interface: 0,           // Access: from the SGW-U
            f_teid: Some((0, None, None)), // CHOOSE
            outer_header_removal: Some(0), // GTP-U/UDP/IPv4
            far_id: Some(1),               // the session's uplink FAR, to the PDN
            qer_id: Some(u32::from(ul)),
            urr_ids: vec![crate::SESSION_URR_ID],
            ..Default::default()
        }],
        ..Default::default()
    };
    let pgw_s5u = match crate::pfcp_modify_with(sess.smf_n4_seid, sess.upf_n4_seid, &params).await {
        Ok(body) => crate::parse_created_pdr_fteid(&body),
        Err(e) => {
            roll_back_store_only(&bearer);
            return Err(NotSent(
                Gtp2Cause::NoResourcesAvailable,
                format!("the PGW-U did not install the uplink: {e}"),
            ));
        }
    };
    let Some((pgw_teid, pgw_addr)) = pgw_s5u else {
        roll_back(&sess, &bearer, false).await;
        return Err(NotSent(
            Gtp2Cause::NoResourcesAvailable,
            "the PGW-U allocated no S5/S8-U F-TEID".into(),
        ));
    };
    bearer.pgw_s5u_teid = pgw_teid;
    bearer.pgw_s5u_addr = Some(std::net::Ipv4Addr::from(pgw_addr));
    if let Ok(ctx) = handle.read() {
        ctx.bearer_update(&bearer);
    }

    // Step 3: the Create Bearer Request.
    let encoded =
        crate::gtp_build::build_create_bearer_request(&sess, &bearer, linked_ebi, &tft, req.pti);
    log::info!(
        "S5/S8 Create Bearer Request to {peer}: LBI {linked_ebi}, QCI {}, GBR UL/DL {}/{} bps, \
         {} packet filter(s), PGW S5/S8-U TEID {pgw_teid:#x}{}",
        req.qos.index,
        req.qos.gbr_uplink,
        req.qos.gbr_downlink,
        req.filters.len(),
        req.pti
            .map(|p| format!(", PTI {p} (UE-requested)"))
            .unwrap_or_default()
    );
    let answer = server
        .request(
            peer,
            encoded,
            gtp2_message_type::CREATE_BEARER_REQUEST,
            req.command.map(|(_, seq)| seq),
        )
        .await;
    let raw = match answer {
        Ok(raw) => raw,
        Err(e) => {
            roll_back(&sess, &bearer, false).await;
            return Err(Failed(e));
        }
    };

    // Step 4: the answer.
    let rsp = match parse_create_bearer_response(&raw) {
        Ok(rsp) => rsp,
        Err(e) => {
            roll_back(&sess, &bearer, false).await;
            return Err(Failed(format!("Create Bearer Response {e}")));
        }
    };
    let assigned = rsp.bearer_context.as_ref().map(|bc| bc.ebi).unwrap_or(0);
    // #1182 review: once the SGW-C (and the MME behind it) has ACCEPTED the bearer under
    // a valid EBI, every exit that does not keep it here must delete it there too (TS
    // 23.401 §5.4.4.1), or they hold an active bearer this PGW has removed. Not for the
    // LBI: a Delete Bearer Request naming it releases the whole PDN connection.
    let accepted_there = matches!(
        rsp.cause,
        Gtp2Cause::RequestAccepted | Gtp2Cause::RequestAcceptedPartially
    ) && rsp
        .bearer_context
        .as_ref()
        .is_some_and(|bc| bc.cause == Gtp2Cause::RequestAccepted)
        && (5..=15).contains(&assigned)
        && assigned != linked_ebi;
    let delete_there = |why: &'static str| {
        let del = crate::gtp_build::build_delete_bearer_request(
            &sess,
            assigned,
            linked_ebi,
            None,
            Some(Gtp2Cause::NoResourcesAvailable),
        );
        async move {
            log::warn!(
                "dedicated bearer EBI {assigned}: accepted by the SGW-C but not kept here \
                 ({why}); Delete Bearer Request sent"
            );
            server
                .send_request(peer, del, gtp2_message_type::DELETE_BEARER_REQUEST)
                .await;
        }
    };
    let ebi_taken = handle
        .read()
        .ok()
        .and_then(|ctx| ctx.bearer_find_by_ebi(sess.id, assigned))
        .is_some_and(|b| b.id != bearer.id);
    if !(5..=15).contains(&assigned) || ebi_taken {
        roll_back(&sess, &bearer, false).await;
        if accepted_there {
            delete_there("its EBI is taken here").await;
        }
        return Err(Failed(format!(
            "the Create Bearer Response assigned EBI {assigned}, which is not a free EPS \
             bearer identity of this PDN connection"
        )));
    }
    if let CreateBearerResponseResult::Rejected { .. } =
        handle_create_bearer_response(&sess, &mut bearer, &rsp)
    {
        roll_back(&sess, &bearer, false).await;
        if accepted_there {
            // Accepted, but without the SGW's S5/S8-U F-TEID.
            delete_there("no S5/S8-U SGW F-TEID").await;
        }
        return Err(Failed(format!(
            "the Create Bearer Response refused the bearer (cause {:?}, bearer cause {:?})",
            rsp.cause,
            rsp.bearer_context.as_ref().map(|bc| bc.cause)
        )));
    }
    if sgw_outer_header(&bearer).is_none() {
        roll_back(&sess, &bearer, false).await;
        if accepted_there {
            delete_there("the S5/S8-U SGW F-TEID carries no address").await;
        }
        return Err(Failed("the SGW's S5/S8-U F-TEID carries no address".into()));
    }
    let sgw_addr = bearer
        .sgw_s5u_ip
        .ipv4
        .map(std::net::IpAddr::V4)
        .or(bearer.sgw_s5u_ip.ipv6.map(std::net::IpAddr::V6))
        .expect("an address, checked above");

    let dl_filters = downlink_descriptions(&req.filters);
    if dl_filters.is_empty() {
        // A DL PDR with no SDF filter would match everything and take the default
        // bearer's downlink; an uplink-only bearer has no downlink to carry.
        log::warn!(
            "dedicated bearer EBI {assigned}: no downlink packet filter, so no downlink rule is \
             installed at the PGW-U"
        );
    } else {
        let (far, pdr) =
            downlink_rules(&bearer, ue_ipv4, dl_filters).expect("an address, checked above");
        let params = crate::n4_build::SessionModificationParams {
            create_fars: vec![far],
            create_pdrs: vec![pdr],
            ..Default::default()
        };
        if let Err(e) = crate::pfcp_modify_with(sess.smf_n4_seid, sess.upf_n4_seid, &params).await {
            roll_back(&sess, &bearer, true).await;
            // The SGW-C and the MME hold the bearer now; TS 23.401 §5.4.4.1 has the PGW
            // delete it rather than leave them a bearer it cannot carry.
            delete_there("the PGW-U did not install its downlink").await;
            return Err(Failed(format!(
                "the PGW-U did not install the downlink ({e}); Delete Bearer Request sent"
            )));
        }
    }

    // The EPS bearer maps onto the QoS flow with QFI = EBI (#583, TS 23.502 §4.11.1.1).
    bearer.qfi = assigned;
    if let Ok(ctx) = handle.read() {
        ctx.bearer_update(&bearer);
    }
    log::info!(
        "dedicated bearer EBI {assigned} (LBI {linked_ebi}) active: PGW S5/S8-U TEID \
         {pgw_teid:#x}, SGW S5/S8-U {sgw_addr} TEID {:#x}, PGW-U rules {ul:#x}/{dl:#x}",
        bearer.sgw_s5u_teid
    );
    Ok(bearer)
}

/// Remove a bearer that never reached the PGW-U.
fn roll_back_store_only(bearer: &SmfBearer) {
    if let Ok(ctx) = context::smf_self().read() {
        ctx.bearer_remove(bearer.id);
    }
}

/// Activate every local PCC rule that applies to a just-established PDN connection.
pub async fn activate_local_rules(server: &S5S8Server, sess_id: u64, apn: &str) {
    for rule in server.local_pcc_rules_for(apn) {
        match activate(server, sess_id, rule.to_request()).await {
            Ok(bearer) => log::info!(
                "local PCC rule '{}' active on APN '{apn}' as EBI {}",
                rule.name,
                bearer.ebi
            ),
            Err(e) => log::warn!(
                "local PCC rule '{}' on APN '{apn}' was not activated: {e}",
                rule.name
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Deactivation on the MME's request (#1182 review)
// ---------------------------------------------------------------------------

/// The MME's Delete Bearer Command for `ebis` of session `sess_id`, relayed by the SGW-C
/// from `peer` under `seq` (TS 23.401 §5.4.4.2, TS 29.274 §7.2.17.1).
///
/// The PGW answers with a Delete Bearer Request for the dedicated bearers it holds, the
/// Command's Triggered message: under the Command's sequence number, back to its source
/// (TS 29.274 §7.6, §4.2.1.2). Once the Delete Bearer Response comes back, or the request
/// runs out its N3, each bearer the answer does not refuse is removed with its PGW-U
/// rules (UL PDR/QER `0x60+k`, DL PDR/FAR `0x80+k`). A Command naming no dedicated bearer
/// of the PDN connection gets a Delete Bearer Failure Indication instead (Table
/// 7.2.18-1): "Context not found" for an unknown EBI, "Request rejected" for the default
/// bearer, which a Delete Bearer Command cannot delete.
pub async fn deactivate_on_command(
    server: &S5S8Server,
    sess_id: u64,
    ebis: &[u8],
    peer: std::net::SocketAddr,
    seq: u32,
) {
    let handle = context::smf_self();
    let Some((sess, linked_ebi, bearers, refused)) = handle.read().ok().and_then(|ctx| {
        let sess = ctx.sess_find_by_id(sess_id)?;
        let linked = default_ebi(&ctx, &sess)?;
        let mut bearers = Vec::new();
        let mut refused = Vec::new();
        for &ebi in ebis {
            match ctx.bearer_find_by_ebi(sess.id, ebi) {
                _ if ebi == linked => {
                    refused.push((ebi, Gtp2Cause::RequestRejectedReasonNotSpecified))
                }
                // #1182 review: a dedicated bearer this PGW-C did not create here (one that
                // came over N26 / EPS interworking, with #583's rule ids) is REFUSED, not
                // deleted locally: its PGW-U rules are not this module's to remove, and
                // dropping only the store entry would leave them steering its traffic.
                Some(b) if b.eps_rule_index == 0 => {
                    refused.push((ebi, Gtp2Cause::RequestRejectedReasonNotSpecified))
                }
                Some(b) => bearers.push(b),
                None => refused.push((ebi, Gtp2Cause::ContextNotFound)),
            }
        }
        Some((sess, linked, bearers, refused))
    }) else {
        return;
    };
    if bearers.is_empty() {
        let cause = refused
            .first()
            .map(|r| r.1)
            .unwrap_or(Gtp2Cause::MandatoryIeMissing);
        let mut b = crate::gtp_build::Gtp2MessageBuilder::new(
            gtp2_message_type::DELETE_BEARER_FAILURE_INDICATION,
        )
        .teid(sess.sgw_s5c_teid)
        .add_cause(cause);
        for (ebi, c) in &refused {
            b = b.start_bearer_context(0).add_ebi(*ebi).add_cause(*c).end();
        }
        let fi = crate::gtp_handler::with_sequence_number(b.build(), seq);
        log::warn!(
            "S5/S8 Delete Bearer Command seq={seq} from {peer}: no dedicated bearer to delete \
             ({refused:?}); Delete Bearer Failure Indication"
        );
        server.send_response_public(peer, &fi).await;
        return;
    }
    let Some(serving) = server.begin_command_guard(peer, seq) else {
        log::debug!("S5/S8 Delete Bearer Command seq={seq} from {peer} is a retransmission");
        return;
    };
    log::info!(
        "S5/S8 Delete Bearer Command seq={seq} from {peer}: Delete Bearer Request for EBIs {:?} \
         (LBI {linked_ebi})",
        bearers.iter().map(|b| b.ebi).collect::<Vec<_>>()
    );
    let _ = delete_bearers(server, &sess, linked_ebi, &bearers, peer, Some(seq), None).await;
    drop(serving);
}

/// The SGW-C's S5/S8-C endpoint for an Initial message of this PGW-C (TS 29.274
/// §4.2.1.1: its address, port 2123).
fn sgw_peer(sess: &SmfSess) -> Option<std::net::SocketAddr> {
    sess.sgw_s5c_ip
        .ipv4
        .map(std::net::IpAddr::V4)
        .or(sess.sgw_s5c_ip.ipv6.map(std::net::IpAddr::V6))
        .map(|ip| std::net::SocketAddr::new(ip, crate::gtp_path::sgw_port()))
}

/// Delete dedicated `bearers` of a PDN connection (TS 23.401 §5.4.4.1): one Delete
/// Bearer Request naming their EBIs (TS 29.274 §7.2.9.2: EPS Bearer IDs at instance 1;
/// the PTI when a Bearer Resource Command asked), then each bearer that the answer
/// does not refuse goes, with its PGW-U rules (UL PDR/QER `0x60+k`, DL PDR/FAR
/// `0x80+k`).
///
/// `command` is the sequence number of the Command this answers (a Delete Bearer
/// Command or a Bearer Resource Command), sent back to `peer`. Without one, the
/// request is an Initial message to the SGW-C's S5/S8-C address.
///
/// An unanswered request still deletes them: this PGW-C, the MME or the UE asked for
/// it, and the SGW-C has nothing to keep them for. `Err` when the answer refused
/// them all.
async fn delete_bearers(
    server: &S5S8Server,
    sess: &SmfSess,
    linked_ebi: u8,
    bearers: &[SmfBearer],
    peer: std::net::SocketAddr,
    command: Option<u32>,
    pti: Option<u8>,
) -> Result<(), String> {
    let handle = context::smf_self();
    let mut b = crate::gtp_build::Gtp2MessageBuilder::new(gtp2_message_type::DELETE_BEARER_REQUEST)
        .teid(sess.sgw_s5c_teid);
    if let Some(pti) = pti {
        b = b.add_pti(pti);
    }
    for bearer in bearers {
        // Dedicated bearers: EPS Bearer IDs, instance 1 (Table 7.2.9.2-1).
        b = b.add_ebi(bearer.ebi, 1);
    }
    let peer = match command {
        Some(_) => peer,
        None => sgw_peer(sess).unwrap_or(peer),
    };
    let answer = server
        .request(
            peer,
            b.build(),
            gtp2_message_type::DELETE_BEARER_REQUEST,
            command,
        )
        .await;
    // Which bearers the answer refused; the rest go.
    let kept: Vec<u8> = match answer {
        Ok(raw) => {
            let mut bytes = bytes::Bytes::copy_from_slice(&raw);
            match Gtp2Message::decode(&mut bytes) {
                Ok(msg) => {
                    let cause = msg
                        .get_ie(Gtp2IeType::Cause as u8, 0)
                        .and_then(|ie| ie.value.first().copied())
                        .unwrap_or(0);
                    let gone = |c: u8| matches!(c, 16 | 17 | 64);
                    let mut kept = Vec::new();
                    let contexts: Vec<(u8, Option<u8>)> = msg
                        .get_ies(Gtp2IeType::BearerContext as u8)
                        .into_iter()
                        .filter(|ie| ie.instance == 0)
                        .filter_map(|ie| {
                            let bc =
                                nextgcore_gtp::v2::Gtp2BearerContextIe::decode(&ie.value).ok()?;
                            Some((bc.ebi().ok()?, bc.cause().ok().flatten().map(|c| c.cause)))
                        })
                        .collect();
                    for bearer in bearers {
                        let c = contexts
                            .iter()
                            .find(|(e, _)| *e == bearer.ebi)
                            .and_then(|(_, c)| *c)
                            .unwrap_or(cause);
                        if !gone(c) || !gone(cause) {
                            kept.push(bearer.ebi);
                        }
                    }
                    kept
                }
                Err(_) => Vec::new(),
            }
        }
        Err(e) => {
            log::warn!("Delete Bearer Request (LBI {linked_ebi}): {e}; deleted here anyway");
            Vec::new()
        }
    };
    for bearer in bearers.iter().filter(|b| !kept.contains(&b.ebi)) {
        // Every bearer here is one of this module's (`eps_rule_index != 0`).
        // One lock at a time: `stored_filters` takes its own.
        let stored = handle
            .read()
            .ok()
            .and_then(|ctx| ctx.bearer_find_by_id(bearer.id));
        let with_dl =
            stored.is_some_and(|b| !downlink_descriptions(&stored_filters(&b)).is_empty());
        roll_back(sess, bearer, with_dl).await;
        log::info!("dedicated bearer EBI {} deleted", bearer.ebi);
    }
    if !bearers.is_empty() && kept.len() == bearers.len() {
        return Err(format!(
            "the Delete Bearer Response refused the deletion of EBIs {kept:?}"
        ));
    }
    Ok(())
}

/// The packet filters stored for `bearer`, as [`PacketFilter`]s.
fn stored_filters(bearer: &SmfBearer) -> Vec<PacketFilter> {
    let handle = context::smf_self();
    let Ok(ctx) = handle.read() else {
        return Vec::new();
    };
    bearer
        .pf_ids
        .iter()
        .filter_map(|id| ctx.pf_find_by_id(*id))
        .filter_map(|pf| {
            Some(PacketFilter {
                direction: pf.direction,
                identifier: pf.identifier,
                precedence: pf.precedence,
                flow_description: pf.flow_description.clone()?,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Modification and deactivation on the UE's Bearer Resource Command (#619)
// ---------------------------------------------------------------------------

/// The uplink packet filter the PGW adds when a dedicated bearer's TFT would hold
/// downlink filters only. TS 23.401 §5.4.5 step 5 requires it ("a packet filter which
/// effectively disallows any useful packet flows in uplink direction", after TS 23.060
/// §15.3.3.4), and the UE refuses a TFT without one (TS 24.301 §6.4.2.4 / §6.4.3.4
/// c) 2), cause #44). It matches UDP from the loopback address to the discard port,
/// which no uplink packet carries.
pub(crate) const DISALLOW_UPLINK: &str = "permit out 17 from 127.0.0.1 9 to assigned";

/// Give a dedicated bearer's TFT an uplink filter when it has downlink filters only
/// (see [`DISALLOW_UPLINK`]). Its identifier is the lowest one the TFT does not use.
/// Its precedence is the highest one no filter of the PDN connection uses
/// (`taken`), because precedences are unique across the connection's TFTs (TS 24.301
/// §6.4.3.4 d) 2)). Returns the filter it added.
fn ensure_uplink_filter(filters: &mut Vec<PacketFilter>, taken: &[u8]) -> Option<PacketFilter> {
    if filters.is_empty()
        || filters
            .iter()
            .any(|f| f.direction != FlowDirection::DownlinkOnly)
    {
        return None;
    }
    let identifier = free_filter_identifier(filters)?;
    let precedence = (0..=255u8)
        .rev()
        .find(|p| !taken.contains(p) && !filters.iter().any(|f| f.precedence == *p))?;
    let f = PacketFilter {
        direction: FlowDirection::UplinkOnly,
        identifier,
        precedence,
        flow_description: DISALLOW_UPLINK.into(),
    };
    filters.push(f.clone());
    Some(f)
}

/// The lowest packet filter identifier (4 bits) a TFT does not use.
fn free_filter_identifier(filters: &[PacketFilter]) -> Option<u8> {
    (1..=15u8)
        .chain(std::iter::once(0))
        .find(|i| !filters.iter().any(|f| f.identifier == *i))
}

/// Whether a QCI is of resource type GBR (TS 23.203 Table 6.1.7-A).
fn is_gbr_qci(qci: u8) -> bool {
    matches!(qci, 1..=4 | 65..=67 | 71..=76 | 82..=85)
}

/// Why a Bearer Resource Command on an existing bearer was not carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// Refused before any request was sent: the Command is answered with a Bearer
    /// Resource Failure Indication with this cause (TS 23.401 §5.4.5 step 5, TS 29.274
    /// §7.2.6).
    Refused(Gtp2Cause, String),
    /// The Update or Delete Bearer Request was sent, and the procedure did not succeed.
    /// The bearer is left as it was, or deleted when the PGW-U could not follow.
    Failed(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(cause, why) => write!(f, "refused ({cause:?}): {why}"),
            Self::Failed(why) => write!(f, "{why}"),
        }
    }
}

/// What a Bearer Resource Command on an existing dedicated bearer became.
#[derive(Debug, Clone)]
pub enum CommandOutcome {
    /// TS 23.401 §5.4.2.1: the bearer's TFT or QoS was updated.
    Modified(Box<SmfBearer>),
    /// TS 23.401 §5.4.4.1: the Command left the bearer no packet filter, so it was
    /// deleted.
    Deactivated(u8),
}

/// The bearer's TFT after a TAD operation, and the TFT the Update Bearer Request carries.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TftChange {
    /// No TFT operation: only the QoS changes.
    None,
    /// The resulting packet filters, and the TFT to send.
    Filters(Vec<PacketFilter>, Vec<u8>),
    /// The bearer is left no packet filter: it is deactivated (TS 23.401 §5.4.5).
    Deactivate,
}

/// Apply a TAD (TS 24.301 §9.9.4.15, coded as the TFT) to a dedicated bearer's packet
/// filters `current` (TS 23.401 §5.4.5 steps 1 and 5). `taken` holds the precedences
/// of the PDN connection's other bearers.
///
/// The TFT sent to the UE uses the TAD's operation:
/// - add: the PGW assigns each new filter an identifier unique in the TFT;
/// - replace: each named filter must exist (TS 24.301 §6.5.4.4 b));
/// - delete: likewise. Deleting the last filter deactivates the bearer.
///
/// When the result would hold downlink filters only, [`DISALLOW_UPLINK`] is added.
/// It goes out with the added or replaced filters; a replace naming an identifier
/// the TFT does not have adds it (TS 24.301 §6.4.3.4 b) 3)). After a delete, which
/// cannot carry it, the whole TFT goes out as a new one; TS 24.301 §6.4.3.4 a) 1)
/// has the UE take that as the bearer's TFT.
fn apply_tad(
    current: &[PacketFilter],
    tad: &eps_tft::Tft,
    taken: &[u8],
) -> Result<TftChange, (Gtp2Cause, String)> {
    use eps_tft::op;
    let semantic = |why: &str| (Gtp2Cause::SemanticErrorInTheTadOperation, why.to_string());
    match tad.operation {
        op::NO_TFT_OPERATION => Ok(TftChange::None),
        op::DELETE_EXISTING_TFT => Ok(TftChange::Deactivate),
        op::ADD_PACKET_FILTERS => {
            if tad.filters.is_empty() {
                return Err(semantic("an add operation with no packet filter"));
            }
            let mut result = current.to_vec();
            let mut sent = Vec::new();
            for f in &tad.filters {
                let identifier = free_filter_identifier(&result).ok_or((
                    Gtp2Cause::SemanticErrorsInPacketFilter,
                    "the TFT already holds 16 packet filters".to_string(),
                ))?;
                let added = PacketFilter {
                    identifier,
                    ..f.clone()
                };
                result.push(added.clone());
                sent.push(added);
            }
            sent.extend(ensure_uplink_filter(&mut result, taken));
            let tft = eps_tft::encode(op::ADD_PACKET_FILTERS, &sent)
                .map_err(|e| (Gtp2Cause::SemanticErrorsInPacketFilter, e))?;
            Ok(TftChange::Filters(result, tft))
        }
        op::REPLACE_PACKET_FILTERS => {
            if tad.filters.is_empty() {
                return Err(semantic("a replace operation with no packet filter"));
            }
            let mut result = current.to_vec();
            for f in &tad.filters {
                let slot = result
                    .iter_mut()
                    .find(|c| c.identifier == f.identifier)
                    .ok_or((
                        Gtp2Cause::SemanticErrorsInPacketFilter,
                        format!("packet filter {} is not in the bearer's TFT", f.identifier),
                    ))?;
                *slot = f.clone();
            }
            let mut sent = tad.filters.clone();
            sent.extend(ensure_uplink_filter(&mut result, taken));
            let tft = eps_tft::encode(op::REPLACE_PACKET_FILTERS, &sent)
                .map_err(|e| (Gtp2Cause::SemanticErrorsInPacketFilter, e))?;
            Ok(TftChange::Filters(result, tft))
        }
        op::DELETE_PACKET_FILTERS => {
            if tad.filters.is_empty() {
                return Err(semantic("a delete operation with no packet filter"));
            }
            let ids: Vec<u8> = tad.filters.iter().map(|f| f.identifier).collect();
            if let Some(id) = ids
                .iter()
                .find(|id| !current.iter().any(|c| c.identifier == **id))
            {
                return Err((
                    Gtp2Cause::SemanticErrorsInPacketFilter,
                    format!("packet filter {id} is not in the bearer's TFT"),
                ));
            }
            let mut result: Vec<PacketFilter> = current
                .iter()
                .filter(|c| !ids.contains(&c.identifier))
                .cloned()
                .collect();
            // Only the disallow filter the PGW itself added would be left: the UE's
            // traffic is gone from this bearer.
            if result.iter().all(|f| f.flow_description == DISALLOW_UPLINK) {
                return Ok(TftChange::Deactivate);
            }
            let tft = if ensure_uplink_filter(&mut result, taken).is_some() {
                eps_tft::encode(op::CREATE_NEW_TFT, &result)
            } else {
                eps_tft::encode_delete(&ids)
            }
            .map_err(|e| (Gtp2Cause::SemanticErrorsInPacketFilter, e))?;
            Ok(TftChange::Filters(result, tft))
        }
        op::CREATE_NEW_TFT => Err(semantic(
            "a create-new-TFT operation names an existing bearer",
        )),
        other => Err((
            Gtp2Cause::SyntacticErrorInTheTadOperation,
            format!("TAD operation {other} is reserved"),
        )),
    }
}

/// Decode an Update Bearer Response (TS 29.274 §7.2.16): its Cause, and the Bearer
/// Context's EBI and Cause.
pub(crate) fn parse_update_bearer_response(
    raw: &[u8],
) -> Result<crate::gtp_handler::UpdateBearerResponse, String> {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = Gtp2Message::decode(&mut bytes).map_err(|e| format!("undecodable: {e}"))?;
    if msg.header.message_type != gtp2_message_type::UPDATE_BEARER_RESPONSE {
        return Err(format!(
            "message type {} is not an Update Bearer Response",
            msg.header.message_type
        ));
    }
    let cause_of = |v: Option<u8>| {
        v.map_or(Gtp2Cause::MandatoryIeMissing, |c| {
            Gtp2Cause::try_from(c).unwrap_or(Gtp2Cause::RequestRejectedReasonNotSpecified)
        })
    };
    let cause = cause_of(
        msg.get_ie(Gtp2IeType::Cause as u8, 0)
            .and_then(|ie| ie.value.first().copied()),
    );
    let bearer_context = match msg.bearer_context(0) {
        Ok(Some(bc)) => Some(crate::gtp_handler::BearerContextUpdated {
            ebi: bc.ebi().unwrap_or(0),
            cause: cause_of(
                bc.get_ie(Gtp2IeType::Cause as u8, 0)
                    .and_then(|ie| ie.value.first().copied()),
            ),
        }),
        Ok(None) => None,
        Err(e) => return Err(format!("Bearer Context undecodable: {e}")),
    };
    Ok(crate::gtp_handler::UpdateBearerResponse {
        cause,
        bearer_context,
    })
}

/// The UE's Bearer Resource Command for an existing dedicated bearer, relayed by the
/// SGW-C from `peer` under `seq` (TS 23.401 §5.4.5, TS 29.274 §7.2.5).
///
/// The PGW-C applies the TAD and the requested QoS to the bearer. It does not change
/// the QoS the UE asked for (step 5). Then it runs one of two procedures, each the
/// Command's Triggered message under its sequence number and with the UE's PTI
/// (TS 29.274 §7.6):
/// - the bearer modification of §5.4.2.1: an Update Bearer Request with the TFT and,
///   when the QoS changed, the Bearer QoS (TS 29.274 §7.2.15). Once it is accepted,
///   the bearer's packet filters and QoS are stored, and the PGW-U's QER and downlink
///   rules are brought to them;
/// - the deactivation of §5.4.4.1, when no packet filter is left: a Delete Bearer
///   Request (§7.2.9.2), then the bearer and its PGW-U rules are removed.
///
/// A refused or unanswered Update Bearer Request leaves the bearer as it was. A
/// Command the PGW-C refuses is answered by the caller with a Bearer Resource Failure
/// Indication.
pub async fn modify_on_command(
    server: &S5S8Server,
    sess_id: u64,
    cmd: &crate::gtp_handler::BearerResourceCommand,
    peer: std::net::SocketAddr,
    seq: u32,
) -> Result<CommandOutcome, CommandError> {
    use CommandError::{Failed, Refused};
    let ebi = cmd.ebi.filter(|&e| e != 0).ok_or_else(|| {
        Refused(
            Gtp2Cause::MandatoryIeMissing,
            "no EPS Bearer ID names the bearer".into(),
        )
    })?;
    let handle = context::smf_self();
    let (sess, linked_ebi, bearer, taken) = {
        let ctx = handle
            .read()
            .map_err(|_| Refused(Gtp2Cause::SystemFailure, "context poisoned".into()))?;
        let sess = ctx
            .sess_find_by_id(sess_id)
            .ok_or_else(|| Refused(Gtp2Cause::ContextNotFound, format!("no session {sess_id}")))?;
        let linked = default_ebi(&ctx, &sess).ok_or_else(|| {
            Refused(
                Gtp2Cause::ContextNotFound,
                "the session has no default bearer".into(),
            )
        })?;
        if cmd.linked_ebi != linked {
            return Err(Refused(
                Gtp2Cause::ContextNotFound,
                format!(
                    "the Linked EPS Bearer ID {} is not this PDN connection's default bearer {linked}",
                    cmd.linked_ebi
                ),
            ));
        }
        if ebi == linked {
            // The default bearer's QoS is the subscription's (TS 23.401 §5.4.2.2), and
            // its TFT is not the UE's to shape here: this PGW-C has no PCC policy that
            // would authorise either.
            return Err(Refused(
                Gtp2Cause::ServiceNotSupported,
                "the Command names the default bearer".into(),
            ));
        }
        let bearer = ctx
            .bearer_find_by_ebi(sess.id, ebi)
            .ok_or_else(|| Refused(Gtp2Cause::ContextNotFound, format!("no bearer EBI {ebi}")))?;
        if bearer.eps_rule_index == 0 {
            // Not one of this module's (a bearer that came over EPS interworking): its
            // PGW-U rules are not the ones this procedure would rewrite.
            return Err(Refused(
                Gtp2Cause::RequestRejectedReasonNotSpecified,
                format!("bearer EBI {ebi} was not set up by this PGW-C"),
            ));
        }
        let taken: Vec<u8> = sess
            .bearer_ids
            .iter()
            .filter(|&&id| id != bearer.id)
            .filter_map(|&id| ctx.bearer_find_by_id(id))
            .flat_map(|b| b.pf_ids)
            .filter_map(|id| ctx.pf_find_by_id(id))
            .map(|pf| pf.precedence)
            .collect();
        (sess, linked, bearer, taken)
    };
    let current = stored_filters(&bearer);

    let tad = eps_tft::decode(cmd.tad.as_deref().ok_or_else(|| {
        Refused(
            Gtp2Cause::MandatoryIeMissing,
            "no Traffic Aggregate Description".into(),
        )
    })?)
    .map_err(|e| Refused(Gtp2Cause::SyntacticErrorInTheTadOperation, e))?;
    let change = apply_tad(&current, &tad, &taken).map_err(|(c, why)| Refused(c, why))?;

    // The QoS the UE asked for, with the bearer's ARP (Flow QoS carries none).
    let new_qos = cmd.flow_qos.as_ref().map(|f| context::Qos {
        index: f.qci,
        mbr_uplink: crate::gtp_build::gtp2_kbps_to_bps(f.ul_mbr),
        mbr_downlink: crate::gtp_build::gtp2_kbps_to_bps(f.dl_mbr),
        gbr_uplink: crate::gtp_build::gtp2_kbps_to_bps(f.ul_gbr),
        gbr_downlink: crate::gtp_build::gtp2_kbps_to_bps(f.dl_gbr),
        ..bearer.qos.clone()
    });
    if let Some(q) = &new_qos {
        // TS 23.401 §5.4.2.1: "Modification from a QCI of resource type non-GBR to a
        // QCI of resource type GBR and vice versa is not supported".
        if is_gbr_qci(q.index) != is_gbr_qci(bearer.qos.index) {
            return Err(Refused(
                Gtp2Cause::ServiceNotSupported,
                format!(
                    "QCI {} -> {} changes the bearer's resource type",
                    bearer.qos.index, q.index
                ),
            ));
        }
    }
    let qos_changed = new_qos.as_ref().is_some_and(|q| {
        (
            q.index,
            q.mbr_uplink,
            q.mbr_downlink,
            q.gbr_uplink,
            q.gbr_downlink,
        ) != (
            bearer.qos.index,
            bearer.qos.mbr_uplink,
            bearer.qos.mbr_downlink,
            bearer.qos.gbr_uplink,
            bearer.qos.gbr_downlink,
        )
    });

    if change == TftChange::Deactivate {
        return delete_bearers(
            server,
            &sess,
            linked_ebi,
            &[bearer],
            peer,
            Some(seq),
            Some(cmd.pti),
        )
        .await
        .map(|_| CommandOutcome::Deactivated(ebi))
        .map_err(Failed);
    }
    let (filters, tft) = match change {
        TftChange::Filters(filters, tft) => (filters, Some(tft)),
        _ => (current.clone(), None),
    };
    if tft.is_none() && !qos_changed {
        return Err(Refused(
            Gtp2Cause::SemanticErrorInTheTadOperation,
            "the Command changes neither the TFT nor the QoS".into(),
        ));
    }

    // TS 29.274 §7.2.15: the Bearer Context carries the TFT when it changed and the
    // Bearer QoS when the QoS did.
    let mut proposed = bearer.clone();
    if let Some(q) = &new_qos {
        proposed.qos = q.clone();
    }
    let ubr = crate::gtp_build::build_update_bearer_request(
        &sess,
        &proposed,
        Some(cmd.pti),
        tft.as_deref(),
        qos_changed,
    );
    log::info!(
        "S5/S8 Update Bearer Request to {peer}: EBI {ebi}, PTI {}, TFT {}, QoS {}",
        cmd.pti,
        if tft.is_some() {
            "changed"
        } else {
            "unchanged"
        },
        if qos_changed { "changed" } else { "unchanged" }
    );
    let raw = server
        .request(
            peer,
            ubr,
            gtp2_message_type::UPDATE_BEARER_REQUEST,
            Some(seq),
        )
        .await
        .map_err(|e| Failed(format!("{e}; bearer EBI {ebi} left as it was")))?;
    let rsp = parse_update_bearer_response(&raw)
        .map_err(|e| Failed(format!("Update Bearer Response {e}; bearer left as it was")))?;
    let accepted = rsp.cause == Gtp2Cause::RequestAccepted
        && rsp
            .bearer_context
            .as_ref()
            .is_some_and(|bc| bc.ebi == ebi && bc.cause == Gtp2Cause::RequestAccepted);
    if !accepted {
        return Err(Failed(format!(
            "the Update Bearer Response refused the modification (cause {:?}, bearer {:?}); \
             bearer EBI {ebi} left as it was",
            rsp.cause,
            rsp.bearer_context.as_ref().map(|bc| (bc.ebi, bc.cause))
        )));
    }

    // Accepted: the store, then the PGW-U.
    let stored = {
        let ctx = handle
            .read()
            .map_err(|_| Failed("context poisoned".into()))?;
        let mut fresh = ctx
            .bearer_find_by_id(bearer.id)
            .ok_or_else(|| Failed(format!("bearer EBI {ebi} went away meanwhile")))?;
        if tft.is_some() {
            for id in std::mem::take(&mut fresh.pf_ids) {
                ctx.pf_remove(id);
            }
            ctx.bearer_update(&fresh);
            for f in &filters {
                if let Some(mut pf) = ctx.pf_add(fresh.id) {
                    pf.direction = f.direction;
                    pf.identifier = f.identifier;
                    pf.precedence = f.precedence;
                    pf.flow_description = Some(f.flow_description.clone());
                    ctx.pf_update(&pf);
                }
            }
            fresh = ctx.bearer_find_by_id(fresh.id).unwrap_or(fresh);
        }
        fresh.qos = proposed.qos.clone();
        ctx.bearer_update(&fresh);
        fresh
    };
    let (ul, dl) = rule_ids(stored.eps_rule_index);
    let dl_before = downlink_descriptions(&current);
    let dl_after = downlink_descriptions(&filters);
    let mut params = crate::n4_build::SessionModificationParams::default();
    if qos_changed {
        params.update_qers.push(bearer_qer(ul, &stored.qos));
    }
    let ue_ipv4 = sess.ipv4_addr.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
    match (dl_before.is_empty(), dl_after.is_empty()) {
        (_, _) if dl_before == dl_after => {}
        (false, false) => {
            if let Some((_, pdr)) = downlink_rules(&stored, ue_ipv4, dl_after.clone()) {
                params.replace_pdrs.push(pdr);
            }
        }
        (true, false) => {
            if let Some((far, pdr)) = downlink_rules(&stored, ue_ipv4, dl_after.clone()) {
                params.create_fars.push(far);
                params.create_pdrs.push(pdr);
            }
        }
        (false, true) => {
            params.remove_pdr_ids.push(dl);
            params.remove_far_ids.push(u32::from(dl));
        }
        (true, true) => {}
    }
    let n4_needed = !params.update_qers.is_empty()
        || !params.replace_pdrs.is_empty()
        || !params.create_pdrs.is_empty()
        || !params.remove_pdr_ids.is_empty();
    if n4_needed {
        if let Err(e) = crate::pfcp_modify_with(sess.smf_n4_seid, sess.upf_n4_seid, &params).await {
            // The UE and the MME now hold the new TFT and QoS, and the PGW-U does not
            // enforce them. As at activation (TS 23.401 §5.4.4.1), the bearer is
            // deleted rather than left carrying traffic it was not authorised for.
            log::warn!(
                "dedicated bearer EBI {ebi}: the PGW-U did not take the modification ({e}); \
                 deleting the bearer"
            );
            let _ = delete_bearers(server, &sess, linked_ebi, &[stored], peer, None, None).await;
            return Err(Failed(format!(
                "the PGW-U did not take the modification of EBI {ebi} ({e}); the bearer is \
                 deleted"
            )));
        }
    }
    log::info!(
        "dedicated bearer EBI {ebi} modified on the UE's request (PTI {}): {} packet filter(s), \
         QCI {}, GBR UL/DL {}/{} bps",
        cmd.pti,
        filters.len(),
        stored.qos.index,
        stored.qos.gbr_uplink,
        stored.qos.gbr_downlink
    );
    Ok(CommandOutcome::Modified(Box::new(stored)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eps_tft::{op, Tft};

    fn pf(id: u8, direction: FlowDirection, precedence: u8, flow: &str) -> PacketFilter {
        PacketFilter {
            direction,
            identifier: id,
            precedence,
            flow_description: flow.into(),
        }
    }

    const DL: &str = "permit out 17 from 198.51.100.7 5004 to assigned";
    const UL: &str = "permit out 17 from 198.51.100.7 5004 to assigned 6000";

    fn current() -> Vec<PacketFilter> {
        vec![
            pf(1, FlowDirection::DownlinkOnly, 0, DL),
            pf(2, FlowDirection::UplinkOnly, 1, UL),
        ]
    }

    /// #619: a replace or delete naming a packet filter the bearer does not have is a
    /// semantic error in the packet filters (TS 24.301 §6.5.4.4 b)); a create-new-TFT
    /// naming an existing bearer, and a delete with nothing to delete, are TAD errors.
    #[test]
    fn a_tad_naming_unknown_filters_is_refused() {
        let tad = |operation, filters| Tft { operation, filters };
        let e = apply_tad(
            &current(),
            &tad(
                op::REPLACE_PACKET_FILTERS,
                vec![pf(7, FlowDirection::Bidirectional, 3, DL)],
            ),
            &[],
        )
        .unwrap_err();
        assert_eq!(e.0, Gtp2Cause::SemanticErrorsInPacketFilter);
        let e = apply_tad(
            &current(),
            &tad(
                op::DELETE_PACKET_FILTERS,
                vec![pf(7, FlowDirection::Bidirectional, 0, "")],
            ),
            &[],
        )
        .unwrap_err();
        assert_eq!(e.0, Gtp2Cause::SemanticErrorsInPacketFilter);
        for t in [
            tad(
                op::CREATE_NEW_TFT,
                vec![pf(1, FlowDirection::Bidirectional, 0, DL)],
            ),
            tad(op::DELETE_PACKET_FILTERS, vec![]),
            tad(op::ADD_PACKET_FILTERS, vec![]),
        ] {
            assert_eq!(
                apply_tad(&current(), &t, &[]).unwrap_err().0,
                Gtp2Cause::SemanticErrorInTheTadOperation,
                "{t:?}"
            );
        }
    }

    /// #619: a replace keeps the identifiers and sends the replaced filters; a delete
    /// of the downlink filter sends identifiers only; deleting every filter, or
    /// "delete existing TFT", deactivates.
    #[test]
    fn replace_and_delete_build_the_tft_the_ue_receives() {
        let new_dl = "permit out 17 from 198.51.100.7 5010 to assigned";
        let replaced = pf(1, FlowDirection::DownlinkOnly, 0, new_dl);
        let TftChange::Filters(result, tft) = apply_tad(
            &current(),
            &Tft {
                operation: op::REPLACE_PACKET_FILTERS,
                filters: vec![replaced.clone()],
            },
            &[],
        )
        .unwrap() else {
            panic!("a change");
        };
        assert_eq!(result, vec![replaced.clone(), current()[1].clone()]);
        assert_eq!(
            tft,
            eps_tft::encode(op::REPLACE_PACKET_FILTERS, &[replaced]).unwrap()
        );

        let TftChange::Filters(result, tft) = apply_tad(
            &current(),
            &Tft {
                operation: op::DELETE_PACKET_FILTERS,
                filters: vec![pf(1, FlowDirection::Bidirectional, 0, "")],
            },
            &[],
        )
        .unwrap() else {
            panic!("a change");
        };
        assert_eq!(result, vec![current()[1].clone()]);
        assert_eq!(tft, vec![0xA1, 0x01], "delete, one identifier: 1");

        for t in [
            Tft {
                operation: op::DELETE_PACKET_FILTERS,
                filters: vec![
                    pf(1, FlowDirection::Bidirectional, 0, ""),
                    pf(2, FlowDirection::Bidirectional, 0, ""),
                ],
            },
            Tft {
                operation: op::DELETE_EXISTING_TFT,
                filters: vec![],
            },
        ] {
            assert_eq!(
                apply_tad(&current(), &t, &[]).unwrap(),
                TftChange::Deactivate
            );
        }
    }

    /// #619: the disallowing uplink filter takes the lowest free identifier and the
    /// highest precedence no filter of the PDN connection uses; it is not added when an
    /// uplink filter exists; and a delete that would leave only it deactivates.
    #[test]
    fn the_disallowing_filter_is_added_once_and_only_when_needed() {
        let mut dl_only = vec![pf(1, FlowDirection::DownlinkOnly, 0, DL)];
        let added = ensure_uplink_filter(&mut dl_only, &[255]).expect("added");
        assert_eq!(
            (added.identifier, added.direction, added.precedence),
            (2, FlowDirection::UplinkOnly, 254)
        );
        assert!(ensure_uplink_filter(&mut dl_only, &[]).is_none(), "once");
        let mut both = current();
        assert!(ensure_uplink_filter(&mut both, &[]).is_none());

        let TftChange::Filters(with_disallow, _) = apply_tad(
            &current(),
            &Tft {
                operation: op::DELETE_PACKET_FILTERS,
                filters: vec![pf(2, FlowDirection::Bidirectional, 0, "")],
            },
            &[],
        )
        .unwrap() else {
            panic!("a change");
        };
        assert_eq!(
            apply_tad(
                &with_disallow,
                &Tft {
                    operation: op::DELETE_PACKET_FILTERS,
                    filters: vec![pf(1, FlowDirection::Bidirectional, 0, "")],
                },
                &[],
            )
            .unwrap(),
            TftChange::Deactivate,
            "only the PGW's own filter would be left"
        );
    }

    /// TS 23.203 Table 6.1.7-A: the GBR QCIs.
    #[test]
    fn gbr_qcis() {
        for q in [
            1, 2, 3, 4, 65, 66, 67, 71, 72, 73, 74, 75, 76, 82, 83, 84, 85,
        ] {
            assert!(is_gbr_qci(q), "{q}");
        }
        for q in [5, 6, 7, 8, 9, 69, 70, 79, 80] {
            assert!(!is_gbr_qci(q), "{q}");
        }
    }
}
