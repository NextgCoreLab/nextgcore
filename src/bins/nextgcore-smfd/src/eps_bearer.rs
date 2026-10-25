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
        (sess, peer, linked_ebi, ue_ipv4)
    };
    let (sess, peer, linked_ebi, ue_ipv4) = prepared;

    if req.filters.is_empty() {
        return Err(NotSent(
            Gtp2Cause::SemanticErrorInTheTadOperation,
            "a dedicated bearer needs at least one packet filter".into(),
        ));
    }
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
    // The SGW's endpoint, IPv4 or IPv6 (TS 29.244 §8.2.56: GTP-U/UDP/IPv4 is 0x0100,
    // GTP-U/UDP/IPv6 0x0200; IPv4 when the F-TEID carries both).
    let sgw_ohc = match (bearer.sgw_s5u_ip.ipv4, bearer.sgw_s5u_ip.ipv6) {
        (Some(v4), _) => (0x0100u16, Some(v4.octets()), None),
        (None, Some(v6)) => (0x0200u16, None, Some(v6.octets())),
        (None, None) => {
            roll_back(&sess, &bearer, false).await;
            if accepted_there {
                delete_there("the S5/S8-U SGW F-TEID carries no address").await;
            }
            return Err(Failed("the SGW's S5/S8-U F-TEID carries no address".into()));
        }
    };
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
        let params = crate::n4_build::SessionModificationParams {
            create_fars: vec![crate::n4_build::FarParams {
                far_id: u32::from(dl),
                apply_action: crate::n4_build::apply_action::FORW,
                destination_interface: Some(0), // Access: toward the SGW-U
                outer_header_creation: Some((sgw_ohc.0, bearer.sgw_s5u_teid, sgw_ohc.1, sgw_ohc.2)),
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
    if !server.begin_command(peer, seq) {
        log::debug!("S5/S8 Delete Bearer Command seq={seq} from {peer} is a retransmission");
        return;
    }
    let mut b = crate::gtp_build::Gtp2MessageBuilder::new(gtp2_message_type::DELETE_BEARER_REQUEST)
        .teid(sess.sgw_s5c_teid);
    for bearer in &bearers {
        // Dedicated bearers: EPS Bearer IDs, instance 1 (Table 7.2.9.2-1).
        b = b.add_ebi(bearer.ebi, 1);
    }
    log::info!(
        "S5/S8 Delete Bearer Command seq={seq} from {peer}: Delete Bearer Request for EBIs {:?} \
         (LBI {linked_ebi})",
        bearers.iter().map(|b| b.ebi).collect::<Vec<_>>()
    );
    let answer = server
        .request(
            peer,
            b.build(),
            gtp2_message_type::DELETE_BEARER_REQUEST,
            Some(seq),
        )
        .await;
    server.end_command(peer, seq);
    // Which bearers the answer refused; the rest go. An unanswered request still
    // deletes them: the MME asked for it, and the SGW-C has nothing to keep them for.
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
                    for bearer in &bearers {
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
            log::warn!("Delete Bearer Request for the MME's Command: {e}; deleted here anyway");
            Vec::new()
        }
    };
    for bearer in bearers.iter().filter(|b| !kept.contains(&b.ebi)) {
        // Every bearer here is one of this module's (`eps_rule_index != 0`, see above).
        // One lock at a time: `stored_filters` takes its own.
        let stored = handle
            .read()
            .ok()
            .and_then(|ctx| ctx.bearer_find_by_id(bearer.id));
        let with_dl =
            stored.is_some_and(|b| !downlink_descriptions(&stored_filters(&b)).is_empty());
        roll_back(&sess, bearer, with_dl).await;
        log::info!(
            "dedicated bearer EBI {} deleted on the MME's command",
            bearer.ebi
        );
    }
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
// Modification on the UE's request (#619 step 4)
// ---------------------------------------------------------------------------

/// What a Bearer Resource Command asks of an existing dedicated bearer (TS 23.401
/// §5.4.5): a change of its packet filters (the TAD), of its QoS (the Flow QoS), or both.
#[derive(Debug, Clone)]
pub struct ModificationRequest {
    /// The bearer, by EBI.
    pub ebi: u8,
    /// The decoded TAD, when the Command carries one.
    pub tad: Option<eps_tft::Tft>,
    /// The new QCI and rates in bit/s (ARP unchanged), when the Command carries a Flow QoS.
    pub qos: Option<(u8, u64, u64, u64, u64)>,
    /// The UE's PTI.
    pub pti: u8,
}

/// The packet filters `bearer` will have after `tad`, and the TFT the Update Bearer Request
/// carries for it; `Err` with the cause a Bearer Resource Failure Indication gives.
/// `Ok(None)` when the TAD would leave the bearer with no filter (deactivate it instead).
#[allow(clippy::type_complexity)]
fn apply_tad(
    current: &[PacketFilter],
    tad: &eps_tft::Tft,
) -> Result<Option<(Vec<PacketFilter>, Vec<u8>)>, Gtp2Cause> {
    use eps_tft::op;
    let free = |used: &[u8]| (1..=15u8).find(|i| !used.contains(i));
    let mut filters = current.to_vec();
    let tft = match tad.operation {
        op::ADD_PACKET_FILTERS | op::CREATE_NEW_TFT => {
            if tad.operation == op::CREATE_NEW_TFT {
                filters.clear();
            }
            let mut added = Vec::new();
            for f in &tad.filters {
                let used: Vec<u8> = filters.iter().map(|f| f.identifier).collect();
                let id = if used.contains(&f.identifier) || f.identifier == 0 {
                    free(&used).ok_or(Gtp2Cause::SemanticErrorsInPacketFilter)?
                } else {
                    f.identifier
                };
                let mut f = f.clone();
                f.identifier = id;
                filters.push(f.clone());
                added.push(f);
            }
            eps_tft::encode(tad.operation, &added)
                .map_err(|_| Gtp2Cause::SemanticErrorsInPacketFilter)?
        }
        op::REPLACE_PACKET_FILTERS => {
            for f in &tad.filters {
                let slot = filters
                    .iter_mut()
                    .find(|e| e.identifier == f.identifier)
                    .ok_or(Gtp2Cause::SemanticErrorsInPacketFilter)?;
                *slot = f.clone();
            }
            eps_tft::encode(op::REPLACE_PACKET_FILTERS, &tad.filters)
                .map_err(|_| Gtp2Cause::SemanticErrorsInPacketFilter)?
        }
        op::DELETE_PACKET_FILTERS => {
            for f in &tad.filters {
                if !filters.iter().any(|e| e.identifier == f.identifier) {
                    return Err(Gtp2Cause::SemanticErrorsInPacketFilter);
                }
                filters.retain(|e| e.identifier != f.identifier);
            }
            if filters.is_empty() {
                return Ok(None);
            }
            let mut tft = vec![(op::DELETE_PACKET_FILTERS << 5) | tad.filters.len() as u8];
            tft.extend(tad.filters.iter().map(|f| f.identifier & 0x0f));
            tft
        }
        _ => return Err(Gtp2Cause::SemanticErrorInTheTadOperation),
    };
    if tad.operation != op::DELETE_PACKET_FILTERS && filters.is_empty() {
        return Err(Gtp2Cause::SemanticErrorInTheTadOperation);
    }
    Ok(Some((filters, tft)))
}

/// Modify a dedicated bearer on the UE's Bearer Resource Command (TS 23.401 §5.4.5 step
/// 3, §5.4.2.1). Called with the Command's `peer` and `seq`.
///
/// The Update Bearer Request is the Command's Triggered message: under its sequence
/// number, back to its source, with the UE's PTI, the APN-AMBR, and the Bearer Context
/// carrying the TFT change and/or the new Bearer QoS (Table 7.2.15-2). Nothing changes
/// here until the SGW-C accepts; then the packet filters and QoS are stored and the
/// PGW-U follows (QER `0x60+k` rates, DL PDR `0x80+k` filters). A TAD that would leave
/// the bearer without a packet filter deactivates it instead (TS 24.301 §6.5.4.4: an
/// empty TFT is not a valid result), through the Delete Bearer Request.
///
/// `Err` carries the cause the Command is refused with, when nothing was sent.
pub async fn modify_on_command(
    server: &S5S8Server,
    sess_id: u64,
    req: ModificationRequest,
    peer: std::net::SocketAddr,
    seq: u32,
) -> Result<(), Gtp2Cause> {
    let handle = context::smf_self();
    let (sess, bearer, linked) = {
        let ctx = handle.read().map_err(|_| Gtp2Cause::SystemFailure)?;
        let sess = ctx
            .sess_find_by_id(sess_id)
            .ok_or(Gtp2Cause::ContextNotFound)?;
        let linked = default_ebi(&ctx, &sess).ok_or(Gtp2Cause::ContextNotFound)?;
        let bearer = ctx
            .bearer_find_by_ebi(sess.id, req.ebi)
            .ok_or(Gtp2Cause::ContextNotFound)?;
        (sess, bearer, linked)
    };
    if bearer.ebi == linked || bearer.eps_rule_index == 0 {
        // Not a dedicated bearer this PGW-C created: its rules are not 0x60+k / 0x80+k.
        return Err(Gtp2Cause::RequestRejectedReasonNotSpecified);
    }
    let current = stored_filters(&bearer);
    let change = match req
        .tad
        .as_ref()
        .filter(|t| t.operation != eps_tft::op::NO_TFT_OPERATION)
    {
        Some(tad) => match apply_tad(&current, tad)? {
            Some(c) => Some(c),
            None => {
                log::info!(
                    "Bearer Resource Command seq={seq}: the TAD leaves EBI {} with no packet \
                     filter; it is deactivated",
                    bearer.ebi
                );
                deactivate_on_command(server, sess.id, &[bearer.ebi], peer, seq).await;
                return Ok(());
            }
        },
        None => None,
    };
    let mut target = bearer.clone();
    if let Some((qci, mbr_ul, mbr_dl, gbr_ul, gbr_dl)) = req.qos {
        target.qos.index = qci;
        target.qos.mbr_uplink = mbr_ul;
        target.qos.mbr_downlink = mbr_dl;
        target.qos.gbr_uplink = gbr_ul;
        target.qos.gbr_downlink = gbr_dl;
    }
    if change.is_none() && req.qos.is_none() {
        return Err(Gtp2Cause::SemanticErrorInTheTadOperation);
    }
    if !server.begin_command(peer, seq) {
        log::debug!("Bearer Resource Command seq={seq} from {peer} is a retransmission");
        return Ok(());
    }
    let ubr = crate::gtp_build::build_update_bearer_request(
        &sess,
        &target,
        Some(req.pti),
        change.as_ref().map(|(_, tft)| tft.as_slice()),
        req.qos.is_some(),
    );
    log::info!(
        "S5/S8 Update Bearer Request for EBI {} (Command seq={seq}, PTI {}): TFT {}, QoS {}",
        bearer.ebi,
        req.pti,
        if change.is_some() { "changed" } else { "kept" },
        if req.qos.is_some() { "changed" } else { "kept" },
    );
    let answer = server
        .request(
            peer,
            ubr,
            gtp2_message_type::UPDATE_BEARER_REQUEST,
            Some(seq),
        )
        .await;
    server.end_command(peer, seq);
    let raw = match answer {
        Ok(raw) => raw,
        Err(e) => {
            log::warn!(
                "Update Bearer Request for EBI {}: {e}; nothing changed",
                bearer.ebi
            );
            return Ok(());
        }
    };
    let mut bytes = bytes::Bytes::copy_from_slice(&raw);
    let accepted = Gtp2Message::decode(&mut bytes).is_ok_and(|msg| {
        let cause = msg
            .get_ie(Gtp2IeType::Cause as u8, 0)
            .and_then(|ie| ie.value.first().copied());
        let bearer_cause = msg
            .bearer_context(0)
            .ok()
            .flatten()
            .and_then(|bc| bc.cause().ok().flatten().map(|c| c.cause));
        cause == Some(16) && bearer_cause.is_none_or(|c| c == 16)
    });
    if !accepted {
        log::warn!(
            "Update Bearer Request for EBI {}: refused by the SGW-C; nothing changed",
            bearer.ebi
        );
        return Ok(());
    }

    // The SGW-C, the MME and the UE hold the new bearer: store it, then the PGW-U.
    let new_filters = change
        .as_ref()
        .map(|(f, _)| f.clone())
        .unwrap_or_else(|| current.clone());
    if let Ok(ctx) = handle.read() {
        if change.is_some() {
            for id in &bearer.pf_ids {
                ctx.pf_remove(*id);
            }
            for f in &new_filters {
                if let Some(mut pf) = ctx.pf_add(bearer.id) {
                    pf.direction = f.direction;
                    pf.identifier = f.identifier;
                    pf.precedence = f.precedence;
                    pf.flow_description = Some(f.flow_description.clone());
                    ctx.pf_update(&pf);
                }
            }
        }
        if let Some(mut stored) = ctx.bearer_find_by_id(bearer.id) {
            stored.qos = target.qos.clone();
            ctx.bearer_update(&stored);
        }
    }
    let (ul, dl) = rule_ids(bearer.eps_rule_index);
    let mut params = crate::n4_build::SessionModificationParams::default();
    if req.qos.is_some() {
        params.update_qers.push(crate::n4_build::QerParams {
            qer_id: u32::from(ul),
            gate_status: (0, 0),
            mbr: Some((target.qos.mbr_uplink, target.qos.mbr_downlink)),
            gbr: Some((target.qos.gbr_uplink, target.qos.gbr_downlink)),
            qfi: None,
        });
    }
    if change.is_some() {
        let had_dl = !downlink_descriptions(&current).is_empty();
        let dl_filters = downlink_descriptions(&new_filters);
        if had_dl {
            params.remove_pdr_ids.push(dl);
        }
        match (had_dl, dl_filters.is_empty(), sess.ipv4_addr) {
            (_, false, Some(ue_ipv4)) => {
                if !had_dl {
                    let (desc, v4, v6) = match (bearer.sgw_s5u_ip.ipv4, bearer.sgw_s5u_ip.ipv6) {
                        (Some(a), _) => (0x0100u16, Some(a.octets()), None),
                        (None, Some(a)) => (0x0200u16, None, Some(a.octets())),
                        (None, None) => (0x0100u16, None, None),
                    };
                    params.create_fars.push(crate::n4_build::FarParams {
                        far_id: u32::from(dl),
                        apply_action: crate::n4_build::apply_action::FORW,
                        destination_interface: Some(0),
                        outer_header_creation: Some((desc, bearer.sgw_s5u_teid, v4, v6)),
                        network_instance: None,
                    });
                }
                params.create_pdrs.push(crate::n4_build::PdrParams {
                    pdr_id: dl,
                    precedence: DEDICATED_DL_PRECEDENCE,
                    source_interface: 1,
                    ue_ip_address: Some((Some(ue_ipv4.octets()), None, false)),
                    sdf_filters: dl_filters,
                    far_id: Some(u32::from(dl)),
                    qer_id: Some(u32::from(ul)),
                    urr_ids: vec![crate::SESSION_URR_ID],
                    ..Default::default()
                });
            }
            (true, true, _) => params.remove_far_ids.push(u32::from(dl)),
            _ => {}
        }
    }
    if let Err(e) = crate::pfcp_modify_with(sess.smf_n4_seid, sess.upf_n4_seid, &params).await {
        log::error!(
            "EBI {}: modified at the SGW-C, MME and UE, but the PGW-U did not follow ({e}); \
             it keeps the previous rules",
            bearer.ebi
        );
    }
    Ok(())
}
