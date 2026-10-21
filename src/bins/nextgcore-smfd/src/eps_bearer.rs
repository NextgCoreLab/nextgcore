//! #619: dedicated EPS bearer activation by the PGW-C (TS 23.401 §5.4.1).
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
            command_sequence: None,
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
    /// The Command's sequence number, when a Command triggered this (TS 29.274 §7.6).
    pub command_sequence: Option<u32>,
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
    let cause_of = |v: Option<u8>| v.map_or(Gtp2Cause::MandatoryIeMissing, Gtp2Cause::from);
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
    req: DedicatedBearerRequest,
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
        let peer = sess.sgw_s5c_peer.ok_or_else(|| {
            NotSent(
                Gtp2Cause::ContextNotFound,
                "the session has no SGW-C S5/S8-C endpoint".into(),
            )
        })?;
        let linked_ebi = default_ebi(&ctx, &sess).ok_or_else(|| {
            NotSent(
                Gtp2Cause::ContextNotFound,
                "the session has no default bearer".into(),
            )
        })?;
        let rule_index = free_rule_index(&ctx, &sess).ok_or_else(|| {
            NotSent(
                Gtp2Cause::NoResourcesAvailable,
                "the session already holds 15 dedicated bearers".into(),
            )
        })?;
        let ue_ipv4 = sess.ipv4_addr.ok_or_else(|| {
            NotSent(
                Gtp2Cause::ContextNotFound,
                "the session has no PDN address".into(),
            )
        })?;
        (sess, peer, linked_ebi, rule_index, ue_ipv4)
    };
    let (sess, peer, linked_ebi, rule_index, ue_ipv4) = prepared;

    if req.filters.is_empty() {
        return Err(NotSent(
            Gtp2Cause::SemanticErrorInTheTad,
            "a dedicated bearer needs at least one packet filter".into(),
        ));
    }
    let tft = eps_tft::encode(eps_tft::op::CREATE_NEW_TFT, &req.filters)
        .map_err(|e| NotSent(Gtp2Cause::SemanticErrorInTheTad, e))?;

    // Step 1: the bearer and its packet filters, stored with EBI 0.
    let mut bearer = {
        let ctx = handle
            .read()
            .map_err(|_| NotSent(Gtp2Cause::SystemFailure, "context poisoned".into()))?;
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
        ctx.bearer_find_by_id(bearer.id).unwrap_or(bearer)
    };

    // Step 2: the S5/S8-U uplink at the PGW-U, on an F-TEID it chooses.
    let (ul, dl) = rule_ids(rule_index);
    let qer = crate::n4_build::QerParams {
        qer_id: u32::from(ul),
        gate_status: (0, 0),
        mbr: (req.qos.mbr_uplink > 0 || req.qos.mbr_downlink > 0)
            .then_some((req.qos.mbr_uplink, req.qos.mbr_downlink)),
        gbr: (req.qos.gbr_uplink > 0 || req.qos.gbr_downlink > 0)
            .then_some((req.qos.gbr_uplink, req.qos.gbr_downlink)),
        qfi: None,
    };
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
    let encoded = crate::gtp_build::build_create_bearer_request(
        &sess,
        &bearer,
        linked_ebi,
        Some(&tft),
        req.pti,
    );
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
            req.command_sequence,
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
    let ebi_taken = handle
        .read()
        .ok()
        .and_then(|ctx| ctx.bearer_find_by_ebi(sess.id, assigned))
        .is_some_and(|b| b.id != bearer.id);
    if !(5..=15).contains(&assigned) || ebi_taken {
        roll_back(&sess, &bearer, false).await;
        return Err(Failed(format!(
            "the Create Bearer Response assigned EBI {assigned}, which is not a free EPS \
             bearer identity of this PDN connection"
        )));
    }
    if let CreateBearerResponseResult::Rejected { .. } =
        handle_create_bearer_response(&sess, &mut bearer, &rsp)
    {
        roll_back(&sess, &bearer, false).await;
        return Err(Failed(format!(
            "the Create Bearer Response refused the bearer (cause {:?}, bearer cause {:?})",
            rsp.cause,
            rsp.bearer_context.as_ref().map(|bc| bc.cause)
        )));
    }
    let Some(sgw_addr) = bearer.sgw_s5u_ip.ipv4 else {
        roll_back(&sess, &bearer, false).await;
        return Err(Failed(
            "the SGW's S5/S8-U F-TEID carries no IPv4 address".into(),
        ));
    };

    let dl_filters = downlink_descriptions(&req.filters);
    if dl_filters.is_empty() {
        // A DL PDR with no SDF filter would match everything and take the default
        // bearer's downlink; an uplink-only bearer has no downlink to carry.
        log::warn!(
            "dedicated bearer EBI {assigned}: no downlink packet filter, so no downlink rule is \
             installed at the PGW-U"
        );
    } else {
        let params = crate::n4_build::SessionModificationParams {
            create_fars: vec![crate::n4_build::FarParams {
                far_id: u32::from(dl),
                apply_action: crate::n4_build::apply_action::FORW,
                destination_interface: Some(0), // Access: toward the SGW-U
                outer_header_creation: Some((
                    0x0100,
                    bearer.sgw_s5u_teid,
                    Some(sgw_addr.octets()),
                    None,
                )),
                network_instance: None,
            }],
            create_pdrs: vec![crate::n4_build::PdrParams {
                pdr_id: dl,
                precedence: DEDICATED_DL_PRECEDENCE,
                source_interface: 1, // Core
                ue_ip_address: Some((Some(ue_ipv4.octets()), None, false)),
                sdf_filters: dl_filters,
                far_id: Some(u32::from(dl)),
                qer_id: Some(u32::from(ul)),
                urr_ids: vec![crate::SESSION_URR_ID],
                ..Default::default()
            }],
            ..Default::default()
        };
        if let Err(e) = crate::pfcp_modify_with(sess.smf_n4_seid, sess.upf_n4_seid, &params).await {
            roll_back(&sess, &bearer, true).await;
            // The SGW-C and the MME hold the bearer now; TS 23.401 §5.4.4.1 has the PGW
            // delete it rather than leave them a bearer it cannot carry.
            let del = crate::gtp_build::build_delete_bearer_request(
                &sess,
                assigned,
                linked_ebi,
                None,
                Some(Gtp2Cause::NoResourcesAvailable),
            );
            server
                .send_request(peer, del, gtp2_message_type::DELETE_BEARER_REQUEST)
                .await;
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
