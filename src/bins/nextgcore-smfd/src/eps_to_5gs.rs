//! #475: this SMF's side of the EPS→5GS handover over N26 (TS 23.502 §4.11.1.2.2), the
//! counterpart of amfd's #418.
//!
//! The PGW-C+SMF already serves the UE's PDN connection over S5/S8 (`gtp_handler`). The
//! initial AMF's `Nsmf_PDUSession_CreateSMContext` (TS 29.502 §5.2.2.2.3) asks it to turn
//! that PDN connection into a PDU session **without** a `pduSessionId`, `dnn`, `sNssai` or
//! `n1SmMsg` — Table 6.1.6.2.2-1 exempts each of them during *"handover using the N26
//! interface"* — so the SMF *"finds the corresponding PDU Session based on EPS Bearer
//! Context(s)"* (step 4) rather than establishing one.
//!
//! What each step does here:
//!
//! - **Step 4 → 7 (the create):** find the S5/S8 session the `ueEpsPdnConnection` names,
//!   take the PDU session ID the UE allocated for it at PDN establishment (#475's PCO leg in
//!   `gtp_handler`), allocate the **N3** uplink tunnel at the UPF (step 6), and answer with
//!   `pduSessionId`, `sNssai`, `allocatedEbiList` and the N2 SM information the target
//!   NG-RAN needs (QoS profile, EBI↔QFI mapping, CN Tunnel Info).
//! - **Step 11 → 13 (PREPARED):** keep the target NG-RAN's DL N3 endpoint from its
//!   `HandoverRequestAcknowledgeTransfer`, and answer the EPS Bearer Setup List generated
//!   from the accepted QFIs. The DL path is NOT switched yet.
//! - **Execution step 7 → 10 (COMPLETED):** switch the UPF's downlink to the target NG-RAN,
//!   with end markers on the old S5/S8-U tunnel, and release the S5/S8-U uplink PDR.
//! - **CANCELLED:** release the N3 uplink PDR and forget the SM context; the PDN connection
//!   is left exactly as EPS was using it.

use crate::context::{self, smf_self, SmfSess};
use crate::eps_iwk;
use nextgcore_sbi::message::SbiResponse;

/// PDR id of the S5/S8-U uplink the EPS establishment installed (`gtp_handler::create_session`
/// → `pfcp_session_establish`, PDR 1).
const S5U_UL_PDR_ID: u16 = 1;
/// PDR id this handover creates for the N3 uplink at step 6. PDRs 1 and 2 are the EPS
/// session's uplink and downlink.
const N3_UL_PDR_ID: u16 = 3;
/// The FAR the EPS establishment created for the downlink (FAR 2), which execution switches
/// to the target NG-RAN.
const DL_FAR_ID: u32 = 2;
/// The EPS establishment's uplink FAR (FAR 1, to the data network) and its URR.
const UL_FAR_ID: u32 = 1;

/// #583: per-bearer N4 rule ids, offset by the EBI (5..=15), so every bearer's rules are
/// distinct, stable across the procedure, and removable without having been recorded.
///
/// - `0x10 + EBI`: a dedicated bearer's N3 uplink PDR (QFI = EBI) and its QER (MBR, GBR).
/// - `0x30 + EBI`: a dedicated bearer's downlink PDR (its TFT's downlink filters), installed
///   at execution through FAR 2 and the bearer's QER, so its packets leave on N3 marked with
///   its QFI.
/// - `0x50 + EBI`: a bearer's indirect-forwarding PDR and QER (TS 23.502 §4.11.1.2.2.2 step
///   12); `FORWARDING_FAR_ID` is the one FAR they share, toward the target NG-RAN's DL
///   forwarding tunnel.
const DEDICATED_RULE_BASE: u8 = 0x10;
const DEDICATED_DL_PDR_BASE: u16 = 0x30;
const FORWARDING_RULE_BASE: u8 = 0x50;
const FORWARDING_FAR_ID: u32 = 0x50;
/// Precedence of a dedicated bearer's DL PDR: ahead of the default bearer's catch-all PDR 2
/// (precedence 100; lower wins, TS 29.244 §8.2.11), as a TFT's filters are ahead of the
/// match-all default.
const DEDICATED_DL_PRECEDENCE: u32 = 50;
/// Precedence of a forwarding PDR. It detects on its own F-TEID only, so it can never
/// shadow another PDR's traffic.
const FORWARDING_PRECEDENCE: u32 = 10;

/// GTPv2 F-TEID interface types (TS 29.274 §8.22).
const IFTYPE_ENB_GNB_DL_FORWARDING: u8 = 19;
const IFTYPE_SGW_UPF_DL_FORWARDING: u8 = 23;
/// Bearer Context (Table 7.3.2-2) F-TEID instances: *"eNodeB/gNodeB F-TEID for DL data
/// forwarding"* (direct) and *"SGW/UPF F-TEID for DL data forwarding"* (indirect).
const BC_INSTANCE_DIRECT_DL_FORWARDING: u8 = 0;
const BC_INSTANCE_INDIRECT_DL_FORWARDING: u8 = 2;

/// How long the UPF keeps the indirect forwarding tunnels after execution (TS 23.502
/// §4.11.1.2.2.3 step 7 / step 14: *"a timer ... is started to supervise when resources in
/// UPF (for indirect data forwarding) shall be released"*). The spec gives no value;
/// `SMF_INDIRECT_FORWARDING_TIMER_MS` overrides this default.
const INDIRECT_FORWARDING_TIMER_MS: u64 = 3_000;

fn indirect_forwarding_timer() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("SMF_INDIRECT_FORWARDING_TIMER_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(INDIRECT_FORWARDING_TIMER_MS),
    )
}

/// Whether a `SmContextCreateData` is an EPS→5GS handover preparation using N26 (TS 29.502
/// §5.2.2.2.3): `hoState: PREPARING` with the UE EPS PDN connection.
pub(crate) fn is_handover_create(body: &serde_json::Value) -> bool {
    eps_iwk::HoPreparation::from_body(body).is_preparing()
        && body["ueEpsPdnConnection"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
}

/// `imsi-<digits>` → `<digits>`, the spelling the S5/S8 path keys UEs by (`imsi_bcd`).
fn imsi_digits(supi: &str) -> Option<&str> {
    supi.strip_prefix("imsi-").filter(|d| !d.is_empty())
}

/// Find the S5/S8 session a `ueEpsPdnConnection` names (step 4).
///
/// By the PGW-C S5/S8 control-plane F-TEID first: Table 7.3.6-2 makes it mandatory, and its
/// TEID is the one this node allocated (`sess.smf_n4_teid`) and put in the Create Session
/// Response — the identity least open to collision. Falls back to the SUPI plus the default
/// bearer's EBI, which is the collision rule of TS 29.502 §5.2.2.2.3 NOTE 2. Either way the
/// session must belong to the SUPI the AMF named: a TEID that resolves to another
/// subscriber's PDN connection is not this UE's.
fn find_eps_session(supi: &str, pdn: &eps_iwk::EpsPdnConnection) -> Option<SmfSess> {
    let digits = imsi_digits(supi)?;
    let handle = smf_self();
    let ctx = handle.read().ok()?;
    let owned_by_supi = |sess: &SmfSess| {
        ctx.ue_find_by_id(sess.smf_ue_id)
            .is_some_and(|ue| ue.imsi_bcd == digits || ue.supi.as_deref() == Some(supi))
    };
    if let Some((teid, _)) = pdn.pgw_c_control_fteid {
        if let Some(sess) = ctx.sess_find_by_teid(teid) {
            if sess.epc && owned_by_supi(&sess) {
                return Some(sess);
            }
        }
    }
    let linked = pdn.linked_ebi?;
    let ue = ctx
        .ue_find_by_imsi_bcd(digits)
        .or_else(|| ctx.ue_find_by_supi(supi))?;
    ue.sess_ids
        .iter()
        .filter_map(|&id| ctx.sess_find_by_id(id))
        .find(|sess| {
            sess.epc
                && sess.bearer_ids.iter().any(|&b| {
                    ctx.bearer_find_by_id(b)
                        .is_some_and(|bearer| bearer.ebi == linked)
                })
        })
}

/// The EPS bearers of a session, default first.
pub(crate) fn session_bearers(sess: &SmfSess) -> Vec<context::SmfBearer> {
    let handle = smf_self();
    let Ok(ctx) = handle.read() else {
        return Vec::new();
    };
    sess.bearer_ids
        .iter()
        .filter_map(|&id| ctx.bearer_find_by_id(id))
        .collect()
}

/// Build step 7's N2 SM information: a `PDUSessionResourceSetupRequestTransfer` (TS 38.413
/// §9.3.4.1) for the target NG-RAN.
///
/// One QoS flow per EPS bearer, with QFI = EBI — the QFI the EPS establishment already
/// installed on this session's N4 PDRs — and the E-RAB ID carrying the EBI↔QFI mapping step
/// 7 requires. *"Data forwarding not possible"* and *"Direct Forwarding Path Availability"*
/// follow the AMF's indications exactly as step 7 and TS 29.502 §5.2.2.2.3 step 2a say.
fn build_handover_setup_request_transfer(
    sess: &SmfSess,
    bearers: &[context::SmfBearer],
    n3_ul: (u32, [u8; 4]),
    forwarding: eps_iwk::DataForwarding,
) -> Result<Vec<u8>, crate::n2_transfer::TransferError> {
    use crate::n2_transfer::{Arp, Gbr, QosFlowSetup, SetupRequest};
    let flows = bearers
        .iter()
        .map(|b| QosFlowSetup {
            qfi: b.ebi,
            // TS 23.501 §5.7.4: the standardized QCIs 1..9 and their 5QIs share values,
            // which is what lets a PGW-C+SMF map one onto the other.
            five_qi: u16::from(b.qos.index),
            arp: Arp {
                priority_level: b.qos.arp_priority_level.clamp(1, 15),
                // PCI / PVI are "disable" flags in the Bearer QoS IE (TS 29.274 §8.15);
                // see `eps_iwk::ebi_arp_mapping`.
                may_trigger_pre_emption: !b.qos.arp_preempt_cap,
                pre_emptable: !b.qos.arp_preempt_vuln,
            },
            gbr: (b.qos.gbr_uplink > 0 || b.qos.gbr_downlink > 0).then_some(Gbr {
                mfbr_dl: b.qos.mbr_downlink,
                mfbr_ul: b.qos.mbr_uplink,
                gfbr_dl: b.qos.gbr_downlink,
                gfbr_ul: b.qos.gbr_uplink,
            }),
            e_rab_id: Some(b.ebi),
        })
        .collect();
    crate::n2_transfer::setup_request_transfer(&SetupRequest {
        ambr: (sess.session_ambr.downlink > 0 || sess.session_ambr.uplink > 0)
            .then_some((sess.session_ambr.downlink, sess.session_ambr.uplink)),
        ul_tunnel: n3_ul,
        data_forwarding_not_possible: forwarding.not_possible(),
        direct_forwarding_path_availability: forwarding.direct,
        flows,
    })
}

/// Step 6: allocate the N3 uplink CN tunnel at the PGW-U+UPF with an N4 Session
/// Modification creating an uplink PDR whose F-TEID the UPF chooses (TS 29.244 §5.5.3).
///
/// The new PDR forwards through the EPS session's existing uplink FAR, QER and URR, so the
/// traffic arriving over N3 is policed and counted exactly as it was over S5/S8-U.
async fn pfcp_create_n3_uplink(
    smf_n4_seid: u64,
    upf_seid: u64,
    ue_ip: [u8; 4],
    qfi: u8,
) -> anyhow::Result<(u32, [u8; 4])> {
    use crate::n4_build::{PdrParams, SessionModificationParams};
    let params = SessionModificationParams {
        create_pdrs: vec![PdrParams {
            pdr_id: N3_UL_PDR_ID,
            precedence: 100,
            source_interface: 0,           // Access
            f_teid: Some((0, None, None)), // CHOOSE: the UPF allocates
            ue_ip_address: Some((Some(ue_ip), None, true)),
            outer_header_removal: Some(0), // GTP-U/UDP/IPv4
            far_id: Some(1),
            qer_id: Some(1),
            qfi: Some(qfi),
            urr_ids: vec![crate::SESSION_URR_ID],
            ..Default::default()
        }],
        ..Default::default()
    };
    let body = crate::pfcp_modify_with(smf_n4_seid, upf_seid, &params).await?;
    crate::parse_created_pdr_fteid(&body).ok_or_else(|| {
        anyhow::anyhow!("Session Modification Response carries no Created PDR F-TEID")
    })
}

/// Execution step 8: switch the downlink to the target NG-RAN and release the S5/S8-U
/// uplink.
///
/// One modification, so there is no instant at which the session forwards downlink to the
/// target while still accepting uplink from a source that has already gone — or the other
/// way round. SNDEM is set: *"For each EPS Bearer one or more 'end marker' is sent to Serving
/// GW by the UPF+PGW-U immediately after switching the path"*.
///
/// #583: the same modification installs each dedicated bearer's downlink as a QoS flow --
/// a PDR on its TFT's downlink filters, through FAR 2 (now the target's N3 tunnel) and the
/// bearer's QER, so its packets leave marked with its QFI. `dedicated_dl` is `(EBI, filters)`.
async fn pfcp_switch_to_ngran(
    smf_n4_seid: u64,
    upf_seid: u64,
    gnb_teid: u32,
    gnb_addr: [u8; 4],
    ue_ip: Option<[u8; 4]>,
    dedicated_dl: &[(u8, Vec<String>)],
) -> anyhow::Result<()> {
    use crate::n4_build::SessionModificationParams;
    let params = SessionModificationParams {
        update_fars_activate: vec![(
            DL_FAR_ID,
            0,                                              // Access
            Some((0x0100, gnb_teid, Some(gnb_addr), None)), // GTP-U/UDP/IPv4
            true,
        )],
        remove_pdr_ids: vec![S5U_UL_PDR_ID],
        create_pdrs: dedicated_dl
            .iter()
            .map(|(ebi, filters)| dedicated_dl_pdr(*ebi, filters, ue_ip, DL_FAR_ID))
            .collect(),
        ..Default::default()
    };
    crate::pfcp_modify_with(smf_n4_seid, upf_seid, &params)
        .await
        .map(|_| ())
}

/// A dedicated bearer's downlink PDR (`0x30 + EBI`): its TFT's downlink filters, its QER
/// (QFI = EBI), forwarding through `far_id` -- FAR 2 at execution, or (#582) the FAR of the
/// additional NG-U tunnel a split PDU session carries it on.
pub(crate) fn dedicated_dl_pdr(
    ebi: u8,
    filters: &[String],
    ue_ip: Option<[u8; 4]>,
    far_id: u32,
) -> crate::n4_build::PdrParams {
    crate::n4_build::PdrParams {
        pdr_id: dedicated_dl_pdr_id(ebi),
        precedence: DEDICATED_DL_PRECEDENCE,
        source_interface: 1, // Core
        ue_ip_address: ue_ip.map(|ip| (Some(ip), None, false)),
        sdf_filters: filters.to_vec(),
        far_id: Some(far_id),
        qer_id: Some(u32::from(DEDICATED_RULE_BASE + ebi)),
        qfi: Some(ebi),
        urr_ids: vec![crate::SESSION_URR_ID],
        ..Default::default()
    }
}

/// The id of a dedicated bearer's downlink PDR.
pub(crate) fn dedicated_dl_pdr_id(ebi: u8) -> u16 {
    DEDICATED_DL_PDR_BASE + u16::from(ebi)
}

/// CANCELLED: remove what the preparation installed -- the N3 uplink PDR step 6 created,
/// the dedicated bearers' uplink PDRs and QERs, and any indirect forwarding tunnel.
async fn pfcp_remove_n3_uplink(
    smf_n4_seid: u64,
    upf_seid: u64,
    dedicated_ebis: &[u8],
    forwarding_ebis: &[u8],
) -> anyhow::Result<()> {
    use crate::n4_build::SessionModificationParams;
    let mut params = SessionModificationParams {
        remove_pdr_ids: std::iter::once(N3_UL_PDR_ID)
            .chain(
                dedicated_ebis
                    .iter()
                    .map(|&e| u16::from(DEDICATED_RULE_BASE + e)),
            )
            .collect(),
        remove_qer_ids: dedicated_ebis
            .iter()
            .map(|&e| u32::from(DEDICATED_RULE_BASE + e))
            .collect(),
        ..Default::default()
    };
    remove_forwarding(&mut params, forwarding_ebis);
    crate::pfcp_modify_with(smf_n4_seid, upf_seid, &params)
        .await
        .map(|_| ())
}

/// Remove the dedicated bearers' uplink PDRs and QERs a failed step 6 may have
/// left at the UPF (#751). Best effort: logged, not returned.
async fn remove_dedicated_uplinks(smf_n4_seid: u64, upf_seid: u64, ebis: &[u8]) {
    if ebis.is_empty() {
        return;
    }
    let params = crate::n4_build::SessionModificationParams {
        remove_pdr_ids: ebis
            .iter()
            .map(|&e| u16::from(DEDICATED_RULE_BASE + e))
            .collect(),
        remove_qer_ids: ebis
            .iter()
            .map(|&e| u32::from(DEDICATED_RULE_BASE + e))
            .collect(),
        ..Default::default()
    };
    if let Err(e) = crate::pfcp_modify_with(smf_n4_seid, upf_seid, &params).await {
        log::warn!("EPS→5GS: the dedicated bearers' rules {ebis:?} were not removed: {e}");
    }
}

/// A data-forwarding tunnel for one EPS bearer, as the MME receives it in the Forward
/// Relocation Response's Bearer Context (TS 29.274 Table 7.3.2-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerForwarding {
    /// Direct: the target NG-RAN's per-E-RAB DL forwarding tunnel (instance 0, type 19).
    Direct(u32, [u8; 4]),
    /// Indirect: the UPF's F-TEID the source SGW forwards into (instance 2, type 23).
    Indirect(u32, [u8; 4]),
}

/// A TS 29.274 §8.28 Bearer Context IE (type 93, header included) -- the `EpsBearerContainer`
/// element of `SmContextUpdatedData.epsBearerSetup` (TS 29.502 §6.1.6.2.3; TS 23.502 step 13:
/// *"The data forwarding information is included in the EPS Bearer Setup List"*): the EBI and,
/// when the bearer's downlink is forwarded, the tunnel the source forwards it to.
fn eps_bearer_setup_element(ebi: u8, forwarding: Option<BearerForwarding>) -> Vec<u8> {
    use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2EbiIe, Gtp2FTeidIe};
    let mut bearer = Gtp2BearerContextIe::new();
    bearer.add_ie(Gtp2EbiIe::new(ebi).to_ie(0));
    match forwarding {
        Some(BearerForwarding::Direct(teid, addr)) => bearer.add_ie(
            Gtp2FTeidIe::new_ipv4(IFTYPE_ENB_GNB_DL_FORWARDING, teid, addr)
                .to_ie(BC_INSTANCE_DIRECT_DL_FORWARDING),
        ),
        Some(BearerForwarding::Indirect(teid, addr)) => bearer.add_ie(
            Gtp2FTeidIe::new_ipv4(IFTYPE_SGW_UPF_DL_FORWARDING, teid, addr)
                .to_ie(BC_INSTANCE_INDIRECT_DL_FORWARDING),
        ),
        None => {}
    }
    let mut buf = bytes::BytesMut::new();
    bearer.to_ie(0).encode(&mut buf);
    buf.to_vec()
}

/// Every Created PDR (IE 8) in a Session Modification Response, as `(PDR ID, F-TEID, IPv4)`
/// (TS 29.244 §7.5.5.2). The F-TEID's V4 flag is bit 1 (§8.2.3).
fn created_pdr_fteids(body: &[u8]) -> Vec<(u16, u32, [u8; 4])> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let t = u16::from_be_bytes([body[off], body[off + 1]]);
        let l = usize::from(u16::from_be_bytes([body[off + 2], body[off + 3]]));
        let Some(v) = body.get(off + 4..off + 4 + l) else {
            break;
        };
        if t == 8 {
            let id = crate::pfcp_path::find_ie(v, 56)
                .filter(|id| id.len() >= 2)
                .map(|id| u16::from_be_bytes([id[0], id[1]]));
            let fteid = crate::pfcp_path::find_ie(v, 21)
                .filter(|f| f.len() >= 9 && f[0] & 0x01 != 0)
                .map(|f| {
                    (
                        u32::from_be_bytes([f[1], f[2], f[3], f[4]]),
                        [f[5], f[6], f[7], f[8]],
                    )
                });
            if let (Some(id), Some((teid, addr))) = (id, fteid) {
                out.push((id, teid, addr));
            }
        }
        off += 4 + l;
    }
    out
}

/// A dedicated bearer's QER: its MBR and, for a GBR bearer, its GBR, with QFI = EBI so the
/// UPF marks its N3 packets (TS 29.244 §5.4.1; TS 23.501 §5.7.1).
fn dedicated_qer(bearer: &context::SmfBearer) -> crate::n4_build::QerParams {
    let q = &bearer.qos;
    crate::n4_build::QerParams {
        qer_id: u32::from(DEDICATED_RULE_BASE + bearer.ebi),
        gate_status: (0, 0),
        mbr: (q.mbr_uplink > 0 || q.mbr_downlink > 0).then_some((q.mbr_uplink, q.mbr_downlink)),
        gbr: (q.gbr_uplink > 0 || q.gbr_downlink > 0).then_some((q.gbr_uplink, q.gbr_downlink)),
        qfi: Some(bearer.ebi),
    }
}

/// The downlink SDF filters of a bearer's TFT (its packet filters that apply downlink).
pub(crate) fn downlink_filters(bearer: &context::SmfBearer) -> Vec<String> {
    let handle = smf_self();
    let Ok(ctx) = handle.read() else {
        return Vec::new();
    };
    bearer
        .pf_ids
        .iter()
        .filter_map(|&id| ctx.pf_find_by_id(id))
        .filter(|pf| pf.direction != context::FlowDirection::UplinkOnly)
        .filter_map(|pf| pf.flow_description)
        .collect()
}

/// #583, step 6 for the dedicated bearers: every EPS bearer becomes a QoS flow at the UPF.
///
/// One uplink PDR per dedicated bearer on the SAME N3 F-TEID the default flow got (a PDU
/// session has one N3 tunnel; its flows are told apart by QFI, TS 29.244 §5.2.1), forwarding
/// through the session's uplink FAR and URR, policed by the bearer's own QER (MBR, GBR). It
/// is a second modification because the F-TEID is only known from the first one's answer.
async fn pfcp_create_dedicated_uplinks(
    smf_n4_seid: u64,
    upf_seid: u64,
    n3_ul: (u32, [u8; 4]),
    dedicated: &[context::SmfBearer],
) -> anyhow::Result<()> {
    use crate::n4_build::{PdrParams, SessionModificationParams};
    let params = SessionModificationParams {
        create_qers: dedicated.iter().map(dedicated_qer).collect(),
        create_pdrs: dedicated
            .iter()
            .map(|b| PdrParams {
                pdr_id: u16::from(DEDICATED_RULE_BASE + b.ebi),
                precedence: 100,
                source_interface: 0, // Access
                f_teid: Some((n3_ul.0, Some(n3_ul.1), None)),
                outer_header_removal: Some(0),
                far_id: Some(UL_FAR_ID),
                qer_id: Some(u32::from(DEDICATED_RULE_BASE + b.ebi)),
                qfi: Some(b.ebi),
                urr_ids: vec![crate::SESSION_URR_ID],
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    crate::pfcp_modify_with(smf_n4_seid, upf_seid, &params)
        .await
        .map(|_| ())
}

/// #583, preparation step 12, indirect forwarding: *"SMF+PGW-C indicates the mapping between
/// the TEID where the UPF receives data forwarded by the source SGW and the QFI(s) and N3
/// Tunnel Info for data forwarding"*.
///
/// Per bearer: a PDR on a UPF-chosen F-TEID (the tunnel the SGW forwards that bearer into)
/// and a QER with QFI = EBI; all share one FAR toward the target NG-RAN's DL forwarding
/// tunnel. Returns the UPF's F-TEID per EBI.
async fn pfcp_create_indirect_forwarding(
    smf_n4_seid: u64,
    upf_seid: u64,
    target: (u32, [u8; 4]),
    ebis: &[u8],
) -> Result<Vec<(u8, (u32, [u8; 4]))>, ForwardingError> {
    use crate::n4_build::{FarParams, PdrParams, QerParams, SessionModificationParams};
    let params = SessionModificationParams {
        create_fars: vec![FarParams {
            far_id: FORWARDING_FAR_ID,
            apply_action: crate::n4_build::apply_action::FORW,
            destination_interface: Some(0), // Access: toward the target NG-RAN
            outer_header_creation: Some((0x0100, target.0, Some(target.1), None)),
            network_instance: None,
        }],
        create_qers: ebis
            .iter()
            .map(|&ebi| QerParams {
                qer_id: u32::from(FORWARDING_RULE_BASE + ebi),
                gate_status: (0, 0),
                mbr: None,
                gbr: None,
                qfi: Some(ebi),
            })
            .collect(),
        create_pdrs: ebis
            .iter()
            .map(|&ebi| PdrParams {
                pdr_id: u16::from(FORWARDING_RULE_BASE + ebi),
                precedence: FORWARDING_PRECEDENCE,
                source_interface: 0,           // Access: from the source SGW
                f_teid: Some((0, None, None)), // CHOOSE
                outer_header_removal: Some(0),
                far_id: Some(FORWARDING_FAR_ID),
                qer_id: Some(u32::from(FORWARDING_RULE_BASE + ebi)),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let body = crate::pfcp_modify_with(smf_n4_seid, upf_seid, &params)
        .await
        .map_err(ForwardingError::NotAccepted)?;
    let created = created_pdr_fteids(&body);
    ebis.iter()
        .map(|&ebi| {
            created
                .iter()
                .find(|(id, ..)| *id == u16::from(FORWARDING_RULE_BASE + ebi))
                .map(|&(_, teid, addr)| (ebi, (teid, addr)))
                .ok_or(ForwardingError::Incomplete(ebi))
        })
        .collect()
}

/// Why the indirect-forwarding modification gave no tunnels (#751).
#[derive(Debug)]
enum ForwardingError {
    /// The UPF accepted the modification but allocated no F-TEID for this EBI. The
    /// FAR, PDRs and QERs are installed all the same.
    Incomplete(u8),
    /// No accepted answer: refused (nothing installed), or no answer at all (the
    /// request may or may not have been applied).
    NotAccepted(anyhow::Error),
}

impl std::fmt::Display for ForwardingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete(ebi) => {
                write!(f, "the UPF allocated no forwarding F-TEID for EBI {ebi}")
            }
            Self::NotAccepted(e) => write!(f, "{e}"),
        }
    }
}

/// The N4 rules that remove the indirect forwarding tunnels of `ebis`.
fn remove_forwarding(params: &mut crate::n4_build::SessionModificationParams, ebis: &[u8]) {
    if ebis.is_empty() {
        return;
    }
    params
        .remove_pdr_ids
        .extend(ebis.iter().map(|&e| u16::from(FORWARDING_RULE_BASE + e)));
    params.remove_far_ids.push(FORWARDING_FAR_ID);
    params
        .remove_qer_ids
        .extend(ebis.iter().map(|&e| u32::from(FORWARDING_RULE_BASE + e)));
}

/// Execution step 14: release the indirect forwarding tunnels once the timer started at
/// step 7 expires.
async fn pfcp_release_forwarding(smf_n4_seid: u64, upf_seid: u64, ebis: &[u8], why: &str) {
    let mut params = crate::n4_build::SessionModificationParams::default();
    remove_forwarding(&mut params, ebis);
    match crate::pfcp_modify_with(smf_n4_seid, upf_seid, &params).await {
        Ok(_) => log::info!(
            "EPS→5GS ({why}): indirect forwarding tunnels for EBIs {ebis:?} released at the UPF"
        ),
        Err(e) => log::warn!(
            "EPS→5GS ({why}): the indirect forwarding tunnels for EBIs {ebis:?} were not \
             released: {e}"
        ),
    }
}

/// Whether `sm_context_ref` names a live SM context: a policy binding, or a session
/// that still carries the reference. `sess_find_by_sm_context_ref` resolves a
/// reference by session index alone, so it also finds an EPS PDN connection whose
/// handover was CANCELLED (its `sm_context_ref` cleared); that is not an SM context.
fn is_live_sm_context(sm_context_ref: &str) -> bool {
    let handle = smf_self();
    let Ok(ctx) = handle.read() else {
        return false;
    };
    ctx.policy_bindings
        .read()
        .map(|b| b.contains_key(sm_context_ref))
        .unwrap_or(false)
        || ctx
            .sess_find_by_sm_context_ref(sm_context_ref)
            .is_some_and(|s| s.sm_context_ref.as_deref() == Some(sm_context_ref))
}

/// Record PREPARED's forwarding EBIs on the session as it is now (#894 review B1).
fn record_forwarding_intent(sm_context_ref: &str, sess_id: u64, ebis: &[u8]) {
    if let Ok(ctx) = smf_self().read() {
        if let Some(mut fresh) = ctx
            .sess_find_by_sm_context_ref(sm_context_ref)
            .filter(|f| f.sm_context_ref.as_deref() == Some(sm_context_ref))
            .filter(|f| f.id == sess_id)
        {
            fresh.handover.forwarding_ebis = ebis.to_vec();
            ctx.sess_update(&fresh);
        }
    }
}

/// The handover procedure lock of one SM context (#750).
///
/// PREPARED, COMPLETED and CANCELLED each read the session, await the UPF, and
/// write back. Run concurrently for one SM context (an AMF whose PREPARED call
/// timed out sends CANCELLED while the SMF still awaits the UPF), the later writer
/// replaced the earlier one's outcome: a cancelled context came back, and the
/// forwarding rules PREPARED installed were never removed. Holding this lock for
/// the whole handler serialises them; the entry is dropped when the last holder
/// or waiter goes.
struct HandoverLock {
    key: String,
    lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

fn handover_locks() -> &'static std::sync::Mutex<
    std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>,
> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    LOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

async fn handover_lock(sm_context_ref: &str) -> HandoverLock {
    let lock = handover_locks()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(sm_context_ref.to_string())
        .or_default()
        .clone();
    let guard = lock.clone().lock_owned().await;
    HandoverLock {
        key: sm_context_ref.to_string(),
        lock,
        guard: Some(guard),
    }
}

impl Drop for HandoverLock {
    fn drop(&mut self) {
        self.guard.take();
        let mut locks = handover_locks().lock().unwrap_or_else(|e| e.into_inner());
        // The map's reference and this one: nobody else holds or awaits it.
        if std::sync::Arc::strong_count(&self.lock) == 2 {
            locks.remove(&self.key);
        }
    }
}

/// The error answer of an SM Context Create or Update the SMF itself originates:
/// SmContextCreateError (TS 29.502 §6.1.6.2.35, Table 6.1.3.2.3.1-3) or
/// SmContextUpdateError (§6.1.6.2.36, Table 6.1.3.3.4.2.2-2), the ProblemDetails
/// with its "cause" in the mandatory "error", as application/json (#1072 round 3
/// m11, #1097). Every create and update error goes through this, or through
/// [`sm_context_update_error_with`] when the error carries more than the
/// ProblemDetails. A bare ProblemDetails is for errors an SCP originates; 401, 411,
/// 413, 415 and 429 and the Retrieve and Release errors keep theirs.
pub(crate) fn sm_context_error(status: u16, cause: &str, detail: &str) -> SbiResponse {
    let body = serde_json::json!({
        "error": { "status": status, "cause": cause, "detail": detail },
    });
    SbiResponse::with_status(status).with_body(
        body.to_string(),
        nextgcore_sbi::constants::content_type::APPLICATION_JSON,
    )
}

/// [`sm_context_error`] with more SmContextUpdateError attributes beside "error"
/// (#1097 review M2, M3): `upCnxState: DEACTIVATED` when a user-plane activation
/// failed (TS 29.502 §5.2.2.3.2.2 step 2b), `hoState: NONE` when a handover
/// preparation did (§5.2.2.3.4.2 step 2b), and with `n2` the N2 SM information
/// (`n2SmInfo` + `n2SmInfoType`) as a binary NGAP part.
pub(crate) fn sm_context_update_error_with(
    status: u16,
    cause: &str,
    detail: &str,
    extra: serde_json::Value,
    n2: Option<(&str, Vec<u8>)>,
) -> SbiResponse {
    let mut body = serde_json::json!({
        "error": { "status": status, "cause": cause, "detail": detail },
    });
    if let (Some(root), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            root.insert(k.clone(), v.clone());
        }
    }
    if let Some((n2_type, _)) = &n2 {
        body["n2SmInfo"] = serde_json::json!({ "contentId": "n2SmInfo" });
        body["n2SmInfoType"] = serde_json::json!(n2_type);
    }
    let mut resp = SbiResponse::with_status(status).with_body(
        body.to_string(),
        nextgcore_sbi::constants::content_type::APPLICATION_JSON,
    );
    if let Some((_, bytes)) = n2 {
        resp = resp.with_part(nextgcore_sbi::message::SbiPart::with_content(
            "n2SmInfo",
            nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
            bytes::Bytes::from(bytes),
        ));
    }
    resp
}

/// TS 29.502 §5.2.2.2.3: the SMF's answer to an EPS→5GS handover preparation.
pub(crate) async fn handle_create(body: &serde_json::Value) -> SbiResponse {
    let body = body.clone();
    detached(async move { handle_create_inner(&body).await }).await
}

/// Run a handover handler to completion whatever happens to its caller (#894 review
/// B1).
///
/// The SBI server runs a handler inline in the HTTP/2 stream's service future. When
/// the AMF's request times out it resets the stream, and hyper drops that future at
/// whatever await it had reached: a PREPARED dropped mid-modification left the UPF's
/// new forwarding rules recorded nowhere, and released the handover lock to a
/// CANCELLED that then had nothing to remove. Spawned, the handler finishes and leaves
/// the session consistent; only its answer is lost.
async fn detached(
    handler: impl std::future::Future<Output = SbiResponse> + Send + 'static,
) -> SbiResponse {
    match tokio::spawn(handler).await {
        Ok(response) => response,
        Err(e) => {
            log::error!("EPS→5GS handover handler failed: {e}");
            sm_context_error(500, "SYSTEM_FAILURE", "the handover handler failed")
        }
    }
}

async fn handle_create_inner(body: &serde_json::Value) -> SbiResponse {
    let Some(supi) = body["supi"].as_str().filter(|s| !s.is_empty()) else {
        return sm_context_error(
            400,
            "MANDATORY_IE_MISSING",
            "supi is required to find the UE's EPS PDN connection (TS 29.502 6.1.6.2.2)",
        );
    };
    let pdn = {
        use base64::Engine as _;
        let raw = body["ueEpsPdnConnection"].as_str().unwrap_or_default();
        match base64::engine::general_purpose::STANDARD
            .decode(raw)
            .ok()
            .and_then(|b| eps_iwk::parse_eps_pdn_connection(&b))
        {
            Some(pdn) => pdn,
            None => {
                return sm_context_error(
                    400,
                    "MANDATORY_IE_INCORRECT",
                    "ueEpsPdnConnection is not a TS 29.274 PDN Connection this SMF can read",
                )
            }
        }
    };
    let forwarding = eps_iwk::DataForwarding::from_body(body);

    let Some(mut sess) = find_eps_session(supi, &pdn) else {
        log::warn!(
            "[{supi}] EPS→5GS: no PDN connection on this PGW-C+SMF matches the \
             ueEpsPdnConnection (control F-TEID {:?}, linked EBI {:?})",
            pdn.pgw_c_control_fteid,
            pdn.linked_ebi
        );
        return sm_context_error(
            404,
            "CONTEXT_NOT_FOUND",
            "no PDN connection on this SMF corresponds to the EPS bearer contexts",
        );
    };

    // Step 4 / TS 29.502 §5.2.2.2.3 step 2b: no PDU session ID was received for this PDN
    // connection, so seamless continuity is not supported for it.
    let Some(psi) = sess.eps_psi else {
        log::info!(
            "[{supi}] EPS→5GS: PDN connection for APN {:?} has no PDU session ID (the UE \
             sent none in its PCO), so it does not move to 5GS",
            sess.session_name
        );
        return sm_context_error(
            403,
            "NO_EPS_5GS_CONTINUITY",
            "no PDU session ID was received for this PDN connection in EPS",
        );
    };
    if let Some(requested) = body["pduSessionId"].as_u64() {
        if requested != u64::from(psi) {
            log::warn!(
                "[{supi}] EPS→5GS create names pduSessionId {requested}, which TS 29.502 \
                 exempts from an N26 handover; the PDN connection's own PSI {psi} is used"
            );
        }
    }
    let Some(ue_ip) = sess.ipv4_addr.map(|a| a.octets()) else {
        return sm_context_error(
            500,
            "SYSTEM_FAILURE",
            "the PDN connection holds no IPv4 address",
        );
    };
    let bearers = session_bearers(&sess);
    let Some(default_bearer) = bearers
        .iter()
        .find(|b| pdn.linked_ebi.is_none_or(|ebi| b.ebi == ebi))
        .or_else(|| bearers.first())
        .cloned()
    else {
        return sm_context_error(
            500,
            "SYSTEM_FAILURE",
            "the PDN connection holds no EPS bearer",
        );
    };

    let sm_context_ref = format!("{}", sess.index);
    // #894 review m1: serialised with PREPARED, COMPLETED and CANCELLED of the same SM
    // context, and the session re-read under the lock.
    let _procedure = handover_lock(&sm_context_ref).await;
    if let Some(fresh) = smf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_id(sess.id))
    {
        sess = fresh;
    }
    let (smf_n4_seid, upf_seid) = (sess.smf_n4_seid, sess.upf_n4_seid);

    // Step 6. NOTE 2 of §5.2.2.2.3: a POST colliding with an existing SM context for the same
    // SUPI and default EBI gets the same answer, so a repeated preparation reuses the N3
    // tunnel it already allocated instead of installing a second uplink PDR.
    let existing = sess
        .handover
        .eps_to_5gs
        .then(|| crate::lookup_upf_ul_endpoint(&sm_context_ref))
        .flatten();

    // #1072 review m4, m9: NSAC for the PDU session this PDN connection becomes, before
    // anything is installed for it. This SMF+PGW-C does no EPS counting, so the count
    // happens at the move (TS 23.501 §5.15.11.5), and a session the NSACF does not
    // admit is not transferred: TS 29.502 Table 6.1.3.2.3.1-3,
    // INSUFFICIENT_RESOURCES_SLICE. A repeated preparation (NOTE 2) keeps the first
    // one's admission.
    let nsac_sst = sess.s_nssai.sst;
    let nsac_sd = sess.s_nssai.sd.map(|sd| format!("{sd:06x}"));
    let nsac_admitted = if existing.is_some() {
        crate::lookup_policy_binding(&sm_context_ref).is_some_and(|b| b.nsac_admitted)
    } else {
        match crate::nsac_admit_migrated_session(supi, psi, nsac_sst, nsac_sd.as_deref()).await {
            Some(admitted) => admitted,
            None => {
                return sm_context_error(
                    500,
                    "INSUFFICIENT_RESOURCES_SLICE",
                    "the NSACF did not admit the PDU session on its S-NSSAI",
                )
            }
        }
    };
    let n3_ul = match existing {
        Some(endpoint) => endpoint,
        None => match pfcp_create_n3_uplink(smf_n4_seid, upf_seid, ue_ip, default_bearer.ebi).await
        {
            Ok(endpoint) => endpoint,
            Err(e) => {
                log::error!("[{supi}] EPS→5GS step 6: the UPF did not allocate the N3 tunnel: {e}");
                crate::rollback_nsac(nsac_admitted, supi, psi, nsac_sst, nsac_sd.as_deref()).await;
                return sm_context_error(
                    504,
                    "UPF_NOT_RESPONDING",
                    "the UPF did not allocate the N3 uplink tunnel",
                );
            }
        },
    };

    // #583: every mapped EPS bearer is a QoS flow at the UPF, not the default one only.
    let dedicated: Vec<context::SmfBearer> = bearers
        .iter()
        .filter(|b| b.ebi != default_bearer.ebi)
        .cloned()
        .collect();
    if existing.is_none() && !dedicated.is_empty() {
        if let Err(e) =
            pfcp_create_dedicated_uplinks(smf_n4_seid, upf_seid, n3_ul, &dedicated).await
        {
            log::error!(
                "[{supi}] EPS→5GS step 6: the UPF did not install the dedicated bearers' QoS \
                 flows (EBIs {:?}): {e}",
                dedicated.iter().map(|b| b.ebi).collect::<Vec<_>>()
            );
            if let Err(e) = pfcp_remove_n3_uplink(smf_n4_seid, upf_seid, &[], &[]).await {
                log::warn!("[{supi}] and the N3 uplink PDR was not removed: {e}");
            }
            // #751: the failed request may still have installed some of them. Separate
            // from the N3 uplink's removal, so a UPF refusing an unknown rule id cannot
            // keep the N3 uplink PDR in place too.
            let ebis: Vec<u8> = dedicated.iter().map(|b| b.ebi).collect();
            remove_dedicated_uplinks(smf_n4_seid, upf_seid, &ebis).await;
            crate::rollback_nsac(nsac_admitted, supi, psi, nsac_sst, nsac_sd.as_deref()).await;
            return sm_context_error(
                504,
                "UPF_NOT_RESPONDING",
                "the UPF did not install the dedicated bearers' QoS flows",
            );
        }
    }

    let n2 = match build_handover_setup_request_transfer(&sess, &bearers, n3_ul, forwarding) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("[{supi}] EPS→5GS: PDUSessionResourceSetupRequestTransfer: {e:?}");
            // #751: step 6 installed the N3 uplink PDR and the dedicated bearers' rules
            // for a preparation that now fails; nothing would ever remove them.
            if existing.is_none() {
                let ebis: Vec<u8> = dedicated.iter().map(|b| b.ebi).collect();
                if let Err(e) = pfcp_remove_n3_uplink(smf_n4_seid, upf_seid, &ebis, &[]).await {
                    log::warn!("[{supi}] and the step-6 rules were not removed: {e}");
                }
                crate::rollback_nsac(nsac_admitted, supi, psi, nsac_sst, nsac_sd.as_deref()).await;
            }
            return sm_context_error(500, "SYSTEM_FAILURE", "N2 SM information encoding failed");
        }
    };

    // The PDN connection becomes PDU session `psi`, still `epc` until execution completes.
    sess.psi = psi;
    sess.sm_context_ref = Some(sm_context_ref.clone());
    sess.pdu_session_ref = Some(sm_context_ref.clone());
    sess.sm_context_status_uri = body["smContextStatusUri"].as_str().map(str::to_string);
    sess.full_dnn = sess.session_name.clone();
    sess.handover.eps_to_5gs = true;
    if existing.is_none() {
        // A new preparation. A repeated one (NOTE 2 of §5.2.2.2.3) keeps what PREPARED
        // already recorded: clearing `forwarding_ebis` forgot FAR 0x50, so no later
        // CANCELLED or step 14 removed it (#894 review m1).
        sess.handover.prepared = false;
        sess.handover.target_dl_known = false;
        sess.handover.forwarding_ebis.clear();
    }
    sess.handover.n3_ul_pdr_id = Some(N3_UL_PDR_ID);
    sess.handover.data_forwarding_not_possible = forwarding.not_possible();
    sess.handover.indirect_data_forwarding = forwarding.indirect;
    sess.handover.direct_data_forwarding = forwarding.direct;
    // #894 review m1: onto the session as it is after the step-6 round trips, so an
    // S5/S11-side change made meanwhile is not overwritten by the copy read before.
    if let Some(mut fresh) = smf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_id(sess.id))
    {
        fresh.psi = sess.psi;
        fresh.sm_context_ref = sess.sm_context_ref.clone();
        fresh.pdu_session_ref = sess.pdu_session_ref.clone();
        fresh.sm_context_status_uri = sess.sm_context_status_uri.clone();
        fresh.full_dnn = sess.full_dnn.clone();
        fresh.handover = sess.handover.clone();
        sess = fresh;
    }
    let dnn = sess.session_name.clone().unwrap_or_default();
    let sd_hex = sess.s_nssai.sd.map(|sd| format!("{sd:06x}"));
    {
        let handle = smf_self();
        if let Ok(ctx) = handle.read() {
            ctx.sess_update(&sess);
            if let Ok(mut m) = ctx.pfcp_sessions.write() {
                m.insert(sm_context_ref.clone(), upf_seid);
            }
            if let Ok(mut m) = ctx.cp_n4_seids.write() {
                m.insert(sm_context_ref.clone(), smf_n4_seid);
            }
            if let Ok(mut m) = ctx.upf_ul_endpoints.write() {
                m.insert(sm_context_ref.clone(), n3_ul);
            }
            if let Ok(mut m) = ctx.policy_bindings.write() {
                let mut fsm = crate::gsm_sm::GsmFsm::new(u64::from(sess.index));
                fsm.init();
                m.insert(
                    sm_context_ref.clone(),
                    context::PolicyBinding {
                        sm_policy_id: None,
                        supi: supi.to_string(),
                        psi,
                        pti: 0,
                        pdu_session_type: crate::policy::pdu_session_type::IPV4,
                        ssc_mode: 1,
                        ue_ip,
                        dnn: dnn.clone(),
                        qfi: default_bearer.ebi,
                        five_qi: default_bearer.qos.index,
                        arp_priority_level: default_bearer.qos.arp_priority_level,
                        ambr_ul_bps: sess.session_ambr.uplink,
                        ambr_dl_bps: sess.session_ambr.downlink,
                        sm_context_status_uri: sess.sm_context_status_uri.clone(),
                        fsm,
                        easdf_dns_context_id: None,
                        easdf_reported_eas: Vec::new(),
                        mapped_eps_bearer_id: Some(default_bearer.ebi),
                        sst: sess.s_nssai.sst,
                        sd: sd_hex.clone(),
                        sdm_subscription_id: None,
                        nsac_admitted,
                    },
                );
            }
            // After every write guard above has dropped (`SmfContext::persist`).
            ctx.persist();
        };
    }

    let allocated: Vec<serde_json::Value> = bearers
        .iter()
        .map(|b| eps_iwk::ebi_arp_mapping(b.ebi, &b.qos))
        .collect();
    let mut snssai = serde_json::json!({ "sst": sess.s_nssai.sst });
    if let Some(sd) = sd_hex {
        snssai["sd"] = serde_json::json!(sd);
    }
    let root = serde_json::json!({
        "smContextRef": sm_context_ref,
        "pduSessionId": psi,
        "sNssai": snssai,
        "hoState": "PREPARING",
        "allocatedEbiList": allocated,
        "n2SmInfo": { "contentId": "n2SmInfo" },
        "n2SmInfoType": "PDU_RES_SETUP_REQ",
    });
    log::info!(
        "[{supi}] EPS→5GS step 7: PDN connection APN '{dnn}' answered as PDU session {psi} \
         (ref {sm_context_ref}), EBIs {:?}, N3 UL TEID 0x{:08x}, forwarding: {}",
        bearers.iter().map(|b| b.ebi).collect::<Vec<_>>(),
        n3_ul.0,
        if forwarding.not_possible() {
            "not possible"
        } else if forwarding.direct {
            "direct"
        } else {
            "indirect"
        }
    );
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiPart;
    SbiResponse::with_status(201)
        .with_body(root.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n2SmInfo",
            content_type::APPLICATION_NGAP,
            bytes::Bytes::from(n2),
        ))
        .with_header(
            "Location",
            format!(
                "{}/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}",
                crate::self_sbi_uri()
            ),
        )
}

/// TS 29.502 §5.2.2.3.4.2 step 3 → 4a: the target NG-RAN's acknowledge, relayed in a
/// PREPARED update. Records its DL N3 endpoint and answers the EPS Bearer Setup List for an
/// EPS→5GS context. The DL path is NOT switched (§5.2.2.3.4.1, PREPARED).
///
/// #583, TS 23.502 §4.11.1.2.2.2 steps 10-13, data forwarding. Each bearer whose QoS flow
/// the target accepted for forwarding gets a forwarding tunnel in its Bearer Context:
///
/// - **direct** (the AMF said `directForwardingFlag`): the target's own per-E-RAB tunnel from
///   the Data Forwarding Response E-RAB List, nothing at the UPF;
/// - **indirect** (`indirectForwardingFlag`): step 12's UPF tunnel, one per bearer, which the
///   UPF relays to the target's per-session DL Forwarding UP TNL Information, adding the QFI.
pub(crate) async fn handle_prepared(sm_context_ref: &str, transfer: &[u8]) -> SbiResponse {
    let (reference, transfer) = (sm_context_ref.to_string(), transfer.to_vec());
    detached(async move { handle_prepared_inner(&reference, &transfer).await }).await
}

async fn handle_prepared_inner(sm_context_ref: &str, transfer: &[u8]) -> SbiResponse {
    let _procedure = handover_lock(sm_context_ref).await;
    let ack = match crate::n2_transfer::parse_handover_request_acknowledge_transfer(transfer) {
        Ok(ack) => ack,
        Err(e) => {
            log::warn!("SM Context Update (PREPARED) for ref={sm_context_ref}: undecodable HandoverRequestAcknowledgeTransfer: {e}");
            return sm_context_error(
                400,
                "N2_SM_ERROR",
                "n2SmInfo is not a HandoverRequestAcknowledgeTransfer",
            );
        }
    };
    let Some(gnb_addr) = ack.dl.ipv4() else {
        return sm_context_error(
            400,
            "N2_SM_ERROR",
            "the target's DL N3 endpoint is not an IPv4 address this SMF can forward to",
        );
    };
    let gnb_teid = ack.dl.teid;
    let accepted: Vec<u8> = ack.dl.qfis.clone();

    let Some(mut sess) = smf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_sm_context_ref(sm_context_ref))
    else {
        return sm_context_error(
            404,
            "CONTEXT_NOT_FOUND",
            "No SM context for this smContextRef",
        );
    };
    sess.handover.gnb_n3_teid = gnb_teid;
    sess.handover.gnb_n3_ip.ipv4 = Some(std::net::Ipv4Addr::from(gnb_addr));
    sess.handover.target_dl_known = true;
    sess.handover.prepared = true;
    let eps = sess.handover.eps_to_5gs;

    let mut root = serde_json::json!({ "hoState": "PREPARED" });
    if eps {
        // TS 23.502 §4.11.1.2.2.2 step 12: *"The EPS Bearer Setup list is a list of EPS bearer
        // Identifiers successfully handover to 5GC, which is generated based on the list of
        // accepted QFI(s)"* — QFI = EBI on this path, so an accepted QFI names its bearer.
        let set_up: Vec<u8> = session_bearers(&sess)
            .iter()
            .filter(|b| accepted.contains(&b.ebi))
            .map(|b| b.ebi)
            .collect();
        let forwarded: Vec<u8> = set_up
            .iter()
            .copied()
            .filter(|ebi| ack.forwarding_accepted_qfis.contains(ebi))
            .collect();
        let mut tunnels: Vec<(u8, BearerForwarding)> = Vec::new();
        if sess.handover.direct_data_forwarding {
            for (erab, tunnel) in &ack.erab_forwarding {
                match tunnel.ipv4() {
                    Some(addr) if set_up.contains(erab) => {
                        tunnels.push((*erab, BearerForwarding::Direct(tunnel.teid, addr)))
                    }
                    _ => log::warn!(
                        "PREPARED for ref={sm_context_ref}: direct forwarding tunnel for E-RAB \
                         {erab} not used (not a set-up bearer, or not IPv4)"
                    ),
                }
            }
        }
        let indirect: Vec<u8> = forwarded
            .iter()
            .copied()
            .filter(|ebi| !tunnels.iter().any(|(e, _)| e == ebi))
            .collect();
        let target_forwarding = ack
            .dl_forwarding
            .as_ref()
            .and_then(|t| t.ipv4().map(|addr| (t.teid, addr)));
        if sess.handover.indirect_data_forwarding && !indirect.is_empty() {
            match (target_forwarding, crate::lookup_upf_seid(sm_context_ref)) {
                (Some(target), Some(upf_seid)) => {
                    // #894 review B1: the intent is recorded BEFORE the request, so a
                    // PREPARED that never resumes (or whose answer is lost) still leaves
                    // CANCELLED and step 14 the rules to remove.
                    sess.handover.forwarding_ebis = indirect.clone();
                    record_forwarding_intent(sm_context_ref, sess.id, &indirect);
                    match pfcp_create_indirect_forwarding(
                        crate::smf_n4_seid_for(sm_context_ref),
                        upf_seid,
                        target,
                        &indirect,
                    )
                    .await
                    {
                        Ok(allocated) => {
                            sess.handover.forwarding_ebis = indirect.clone();
                            for (ebi, (teid, addr)) in allocated {
                                tunnels.push((ebi, BearerForwarding::Indirect(teid, addr)));
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "PREPARED for ref={sm_context_ref}: the UPF did not set up \
                                 indirect forwarding for EBIs {indirect:?} ({e}); the bearers \
                                 hand over without it and their in-flight downlink is lost"
                            );
                            match e {
                                // #751: an accepted but incomplete answer means the FAR,
                                // PDRs and QERs ARE installed and no tunnel will ever use
                                // them: remove them now.
                                ForwardingError::Incomplete(_) => {
                                    pfcp_release_forwarding(
                                        crate::smf_n4_seid_for(sm_context_ref),
                                        upf_seid,
                                        &indirect,
                                        "incomplete forwarding answer",
                                    )
                                    .await;
                                    sess.handover.forwarding_ebis.clear();
                                }
                                // Refused (nothing installed) or unanswered (a dead UPF
                                // would time a removal out the same way, holding the lock
                                // for another T1 x (N1+1)). The recorded intent stays, so
                                // CANCELLED or step 14 removes whatever did land
                                // (#894 review m6).
                                ForwardingError::NotAccepted(_) => {}
                            }
                        }
                    }
                }
                (None, _) => log::info!(
                    "PREPARED for ref={sm_context_ref}: the target accepted forwarding for \
                     EBIs {indirect:?} but assigned no IPv4 DL Forwarding UP TNL Information"
                ),
                (_, None) => log::warn!(
                    "PREPARED for ref={sm_context_ref}: no N4 session for indirect forwarding"
                ),
            }
        }
        let elements: Vec<String> = set_up
            .iter()
            .map(|&ebi| {
                use base64::Engine as _;
                let forwarding = tunnels.iter().find(|(e, _)| *e == ebi).map(|(_, t)| *t);
                base64::engine::general_purpose::STANDARD
                    .encode(eps_bearer_setup_element(ebi, forwarding))
            })
            .collect();
        log::info!(
            "SM Context Update (PREPARED) for ref={sm_context_ref}: target DL N3 \
             {}.{}.{}.{} TEID 0x{gnb_teid:08x}, accepted QFIs {accepted:?}, EPS bearers set up \
             {set_up:?}, forwarding {tunnels:?}; DL still on S5/S8-U until execution",
            gnb_addr[0],
            gnb_addr[1],
            gnb_addr[2],
            gnb_addr[3],
        );
        root["epsBearerSetup"] = serde_json::json!(elements);
    } else {
        // #964, TS 29.502 §5.2.2.3.4.2, TS 23.502 §4.9.1.3.2 step 11: an intra-5GS
        // handover's PREPARED answer carries the source's Handover Command Transfer
        // (`HANDOVER_CMD`). With a direct forwarding path (the source's Handover Required
        // Transfer said so at PREPARING) and a forwarding tunnel from the target, it names
        // that tunnel and the QoS flows the target accepted for forwarding; otherwise the
        // source forwards nothing.
        let forwarding = sess
            .handover
            .direct_data_forwarding
            .then_some(ack.dl_forwarding.as_ref())
            .flatten()
            .and_then(|t| t.ipv4().map(|addr| (t.teid, addr)));
        let command = match crate::n2_transfer::handover_command_transfer(
            forwarding.map(|tunnel| (tunnel, ack.forwarding_accepted_qfis.as_slice())),
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!(
                    "SM Context Update (PREPARED) for ref={sm_context_ref}: \
                     HandoverCommandTransfer encode failed: {e:?}"
                );
                return sm_context_error(500, "SYSTEM_FAILURE", "N2 SM information encode failed");
            }
        };
        log::info!(
            "SM Context Update (PREPARED) for ref={sm_context_ref}: target DL N3 \
             {}.{}.{}.{} TEID 0x{gnb_teid:08x}, accepted QFIs {accepted:?}, direct \
             forwarding {forwarding:?} for QFIs {:?}; DL still on the source until COMPLETED",
            gnb_addr[0],
            gnb_addr[1],
            gnb_addr[2],
            gnb_addr[3],
            ack.forwarding_accepted_qfis,
        );
        // #964 follow-up: #894's write-back, as for EPS→5GS below -- only what PREPARED
        // decided, onto the session as it is now, and only if it is still this context.
        if !apply_prepared(sm_context_ref, &sess) {
            log::warn!(
                "SM Context Update (PREPARED) for ref={sm_context_ref}: the SM context went \
                 away during the preparation; nothing kept"
            );
            return sm_context_error(
                404,
                "CONTEXT_NOT_FOUND",
                "the SM context was released during the handover preparation",
            );
        }
        root["n2SmInfoType"] = serde_json::json!("HANDOVER_CMD");
        root["n2SmInfo"] = serde_json::json!({ "contentId": "n2SmInfo" });
        return SbiResponse::with_status(200)
            .with_body(root.to_string(), "application/json")
            .with_part(nextgcore_sbi::message::SbiPart::with_content(
                "n2SmInfo",
                nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
                bytes::Bytes::from(command),
            ));
    }
    // #750: write back only what PREPARED decided, onto the session as it is NOW,
    // and only if it is still this SM context. The copy read above predates the UPF
    // round trip; writing it whole replaced whatever happened meanwhile.
    if !apply_prepared(sm_context_ref, &sess) {
        log::warn!(
            "SM Context Update (PREPARED) for ref={sm_context_ref}: the SM context went away \
             during the UPF round trip; nothing kept"
        );
        if !sess.handover.forwarding_ebis.is_empty() {
            if let Some(upf_seid) = (sess.upf_n4_seid != 0).then_some(sess.upf_n4_seid) {
                pfcp_release_forwarding(
                    sess.smf_n4_seid,
                    upf_seid,
                    &sess.handover.forwarding_ebis,
                    "context gone during PREPARED",
                )
                .await;
            }
        }
        return sm_context_error(
            404,
            "CONTEXT_NOT_FOUND",
            "the SM context was released during the handover preparation",
        );
    }
    SbiResponse::with_status(200).with_body(root.to_string(), "application/json")
}

/// Write back what PREPARED decided -- the target's DL N3 endpoint, `prepared`, and the
/// forwarding EBIs -- onto the session as it is NOW, and only if it is still this SM
/// context (#750, #894; #964 follow-up for the intra-5GS answer). The copy `decided` was
/// read from may predate a UPF round trip; writing it whole would replace whatever
/// happened meanwhile. `false` when the context went away.
fn apply_prepared(sm_context_ref: &str, decided: &SmfSess) -> bool {
    smf_self()
        .read()
        .ok()
        .and_then(|ctx| {
            let mut fresh = ctx
                .sess_find_by_sm_context_ref(sm_context_ref)
                .filter(|f| f.sm_context_ref.as_deref() == Some(sm_context_ref))
                .filter(|f| f.id == decided.id)?;
            fresh.handover.gnb_n3_teid = decided.handover.gnb_n3_teid;
            fresh.handover.gnb_n3_ip = decided.handover.gnb_n3_ip.clone();
            fresh.handover.target_dl_known = true;
            fresh.handover.prepared = true;
            fresh.handover.forwarding_ebis = decided.handover.forwarding_ebis.clone();
            ctx.sess_update(&fresh);
            Some(())
        })
        .is_some()
}

/// TS 29.502 §5.2.2.3.4.3: COMPLETED — switch the downlink to the target NG-RAN.
///
/// `transfer_endpoint` is the legacy `HANDOVER_COMPLETE` carrier some consumers send; a
/// conformant COMPLETED carries no N2 SM information, so the endpoint recorded at PREPARED
/// is used. The caller has already established that the SM context exists; a context with
/// no session record (a binding only) is completed the way a 5GS N2 handover always was.
pub(crate) async fn handle_completed(
    sm_context_ref: &str,
    transfer_endpoint: Option<(u32, [u8; 4])>,
) -> SbiResponse {
    let reference = sm_context_ref.to_string();
    detached(async move { handle_completed_inner(&reference, transfer_endpoint).await }).await
}

async fn handle_completed_inner(
    sm_context_ref: &str,
    transfer_endpoint: Option<(u32, [u8; 4])>,
) -> SbiResponse {
    let _procedure = handover_lock(sm_context_ref).await;
    // #894 review m2: the caller checked the context before the lock wait; a
    // CANCELLED that held the lock may have released it meanwhile.
    if !is_live_sm_context(sm_context_ref) {
        return sm_context_error(
            404,
            "CONTEXT_NOT_FOUND",
            "the SM context was released before the handover completed",
        );
    }
    let completed = || {
        SbiResponse::with_status(200).with_body(
            serde_json::json!({ "hoState": "COMPLETED" }).to_string(),
            "application/json",
        )
    };
    let sess = smf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_sm_context_ref(sm_context_ref));
    let stored = sess.as_ref().and_then(|s| {
        s.handover.target_dl_known.then(|| {
            (
                s.handover.gnb_n3_teid,
                s.handover
                    .gnb_n3_ip
                    .ipv4
                    .map(|a| a.octets())
                    .unwrap_or_default(),
            )
        })
    });
    let was_eps = sess.as_ref().is_some_and(|s| s.handover.eps_to_5gs);
    let target = transfer_endpoint.or(stored);
    let upf_seid = crate::lookup_upf_seid(sm_context_ref);
    let (Some((teid, addr)), Some(upf_seid)) = (target, upf_seid) else {
        // Stated rather than silently returned as success: a completed handover whose DL
        // tunnel was not switched leaves downlink traffic pointed at the source, and an
        // operator reading a bare 200 would have no way to know.
        log::warn!(
            "SM Context Update (COMPLETED) for ref={sm_context_ref}: no target DL endpoint \
             (learned={}) or no N4 session (present={}): the UPF still points at the source",
            target.is_some(),
            upf_seid.is_some()
        );
        // #964 review: an error, not `200 COMPLETED`, so the AMF sees that the downlink was
        // not switched (it retries once and logs), rather than a success that did nothing.
        return sm_context_error(
            500,
            "SYSTEM_FAILURE",
            "The handover cannot complete: no target DL endpoint or no N4 session",
        );
    };
    let smf_n4_seid = crate::smf_n4_seid_for(sm_context_ref);
    let forwarding_ebis = sess
        .as_ref()
        .map(|s| s.handover.forwarding_ebis.clone())
        .unwrap_or_default();
    let switched = if was_eps {
        let (ue_ip, dedicated_dl) = sess.as_ref().map_or((None, Vec::new()), |s| {
            let bearers = session_bearers(s);
            let default_ebi = bearers.first().map(|b| b.ebi);
            let dedicated = bearers
                .iter()
                .filter(|b| Some(b.ebi) != default_ebi)
                .filter_map(|b| {
                    let filters = downlink_filters(b);
                    if filters.is_empty() {
                        // A match-all PDR here would take the default flow's traffic.
                        log::warn!(
                            "COMPLETED for ref={sm_context_ref}: dedicated EBI {} has no \
                             downlink packet filter, so its downlink stays on the default flow",
                            b.ebi
                        );
                        None
                    } else {
                        Some((b.ebi, filters))
                    }
                })
                .collect();
            (s.ipv4_addr.map(|a| a.octets()), dedicated)
        });
        pfcp_switch_to_ngran(smf_n4_seid, upf_seid, teid, addr, ue_ip, &dedicated_dl).await
    } else {
        crate::pfcp_session_modify(smf_n4_seid, upf_seid, teid, addr).await
    };
    if let Err(e) = switched {
        log::warn!("SM Context Update (COMPLETED) for ref={sm_context_ref}: DL switch failed: {e}");
        return sm_context_error(
            504,
            "UPF_NOT_RESPONDING",
            "the UPF did not switch the downlink to the target",
        );
    }
    // #750: onto the session as it is now, not the copy read before the UPF round trip.
    let mut sess = sess.and_then(|old| {
        smf_self()
            .read()
            .ok()
            .and_then(|ctx| ctx.sess_find_by_sm_context_ref(sm_context_ref))
            .filter(|f| f.sm_context_ref.as_deref() == Some(sm_context_ref))
            .filter(|f| f.id == old.id)
    });
    if let Some(sess) = sess.as_mut() {
        // §5.2.2.3.4.3: "set the hoState to NONE".
        sess.handover.prepared = false;
        sess.handover.target_dl_known = false;
        sess.handover.eps_to_5gs = false;
        sess.handover.n3_ul_pdr_id = None;
        sess.handover.forwarding_ebis.clear();
        // The UE is CONNECTED on the target and the downlink FAR forwards to it, so the
        // user plane is ACTIVATED whatever it was before -- including after the source's
        // AN release DEACTIVATED it mid-handover (#805, the #738 ordering). Left
        // DEACTIVATED, a Downlink Data Report would page a connected UE.
        sess.up_cnx_state = context::UpCnxState::Activated;
        if was_eps {
            // The PDN connection is a PDU session now; its S5/S8 leg was released above.
            sess.epc = false;
            sess.establishment_accept_sent = true;
        }
        if let Ok(ctx) = smf_self().read() {
            ctx.sess_update(sess);
        }
    }
    if was_eps {
        // Execution step 10: *"If the SMF has not yet registered for this PDU Session ID, then
        // the SMF registers with the UDM using Nudm_UECM_Registration"*.
        let binding = smf_self().read().ok().and_then(|ctx| {
            ctx.policy_bindings
                .read()
                .ok()
                .and_then(|b| b.get(sm_context_ref).cloned())
        });
        if let Some(b) = binding {
            crate::udm::register_as_serving_smf(
                &b.supi,
                b.psi,
                &b.dnn,
                b.sst,
                b.sd.as_deref(),
                None,
                crate::udm::EpsInterworkingInd::from_body(&serde_json::json!({})),
            )
            .await;
        }
        if !forwarding_ebis.is_empty() {
            // Execution step 7: *"If indirect forwarding is used, a timer in SMF+PGW-C ... is
            // started to supervise when resources in UPF (for indirect data forwarding) shall
            // be released"*; step 14 releases them on expiry.
            let timer = indirect_forwarding_timer();
            tokio::spawn(async move {
                tokio::time::sleep(timer).await;
                pfcp_release_forwarding(smf_n4_seid, upf_seid, &forwarding_ebis, "step 14").await;
            });
        }
        log::info!(
            "SM Context Update (COMPLETED) for ref={sm_context_ref}: EPS→5GS executed — DL \
             switched to the NG-RAN (end markers on S5/S8-U), S5/S8-U uplink released"
        );
    } else {
        log::info!("SM Context Update (COMPLETED) for ref={sm_context_ref}: DL tunnel switched");
    }
    completed()
}

/// TS 29.502 §5.2.2.3.4.4: CANCELLED — release what the preparation reserved.
///
/// Neither PREPARING nor PREPARED touched the downlink, so a 5GS-internal handover has
/// nothing to undo; an EPS→5GS one releases the N3 uplink step 6 created.
pub(crate) async fn handle_cancelled(sm_context_ref: &str) -> SbiResponse {
    let reference = sm_context_ref.to_string();
    detached(async move { handle_cancelled_inner(&reference).await }).await
}

async fn handle_cancelled_inner(sm_context_ref: &str) -> SbiResponse {
    let _procedure = handover_lock(sm_context_ref).await;
    let sess = smf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_sm_context_ref(sm_context_ref));
    if let Some(mut sess) = sess {
        if sess.handover.eps_to_5gs {
            if let Some(upf_seid) = crate::lookup_upf_seid(sm_context_ref) {
                let bearers = session_bearers(&sess);
                let dedicated: Vec<u8> = bearers.iter().skip(1).map(|b| b.ebi).collect();
                if let Err(e) = pfcp_remove_n3_uplink(
                    crate::smf_n4_seid_for(sm_context_ref),
                    upf_seid,
                    &dedicated,
                    &sess.handover.forwarding_ebis,
                )
                .await
                {
                    log::warn!(
                        "EPS→5GS cancel for ref={sm_context_ref}: N3 uplink PDR not removed: {e}"
                    );
                }
            }
            // #750: the session as it is now, not as read before the UPF round trip.
            if let Some(fresh) = smf_self()
                .read()
                .ok()
                .and_then(|ctx| ctx.sess_find_by_sm_context_ref(sm_context_ref))
                .filter(|f| f.sm_context_ref.as_deref() == Some(sm_context_ref))
                .filter(|f| f.id == sess.id)
            {
                sess = fresh;
            }
            // The PDN connection is left exactly as EPS was using it: it never became a PDU
            // session, so the SM context the preparation created goes away.
            let mut counted = None;
            if let Ok(ctx) = smf_self().read() {
                for map in [&ctx.pfcp_sessions, &ctx.cp_n4_seids] {
                    if let Ok(mut m) = map.write() {
                        m.remove(sm_context_ref);
                    }
                }
                if let Ok(mut m) = ctx.upf_ul_endpoints.write() {
                    m.remove(sm_context_ref);
                }
                if let Ok(mut m) = ctx.policy_bindings.write() {
                    counted = m
                        .remove(sm_context_ref)
                        .filter(|b| b.nsac_admitted)
                        .map(|b| (b.supi, b.psi, b.sst, b.sd));
                }
                sess.psi = 0;
                sess.sm_context_ref = None;
                sess.pdu_session_ref = None;
                ctx.persist();
            }
            // #1072 round 2 m8: and the 5G count the preparation took is given back,
            // under the handover lock, so a retried preparation counts in after it.
            if let Some((supi, psi, sst, sd)) = counted {
                crate::rollback_nsac(true, &supi, psi, sst, sd.as_deref()).await;
            }
            log::info!(
                "SM Context Update (CANCELLED) for ref={sm_context_ref}: EPS→5GS handover \
                 abandoned; the PDN connection stays on EPS"
            );
        } else {
            log::info!(
                "SM Context Update (CANCELLED) for ref={sm_context_ref}: handover abandoned, \
                 session retained"
            );
        }
        sess.handover = context::HandoverInfo::default();
        if let Ok(ctx) = smf_self().read() {
            ctx.sess_update(&sess);
        }
    }
    SbiResponse::with_status(200).with_body(
        serde_json::json!({ "hoState": "CANCELLED" }).to_string(),
        "application/json",
    )
}

/// Whether a request body asks to drive the handover state machine without N2 SM
/// information — a conformant COMPLETED or CANCELLED (§5.2.2.3.4.3, §5.2.2.3.4.4).
pub(crate) fn bare_ho_state(body: &serde_json::Value) -> Option<&'static str> {
    if !body["n2SmInfoType"].as_str().unwrap_or("").is_empty() {
        return None;
    }
    match body["hoState"].as_str() {
        Some("COMPLETED") => Some("COMPLETED"),
        Some("CANCELLED") => Some("CANCELLED"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_gtp::v2::{
        Gtp2AmbrIe, Gtp2ApnIe, Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2CauseIe, Gtp2EbiIe,
        Gtp2FTeidIe, Gtp2Header, Gtp2Ie, Gtp2IeType, Gtp2IndicationIe, Gtp2Message,
        Gtp2MessageType, Gtp2PaaIe, Gtp2PdnConnectionIe, Gtp2RatTypeIe,
    };
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::time::Duration;

    const IMSI: &str = "001010000004750";
    const PGW_FQDN: &str = "pgw475.epc.test";
    const MME_TEID: u32 = 0xCAFE_0475;
    const FRR_SEQ: u32 = 0x0475;
    const GNB_ID: u32 = 0x1A2;
    const TARGET_ASSOC: u64 = 0x475;
    const GNB_DL: ([u8; 4], u32) = ([10, 1, 2, 3], 0x0000_ABCD);

    /// A UE→network PCO carrying only `001AH` = `psi` (TS 24.008 Table 10.5.154).
    fn pco_with_psi(psi: u8) -> Vec<u8> {
        vec![0x80, 0x00, 0x1A, 0x01, psi]
    }

    /// An S5/S8 Create Session Request for `IMSI`, EBI 5, QCI 9, ARP 8 with PCI/PVI set, an
    /// APN-AMBR of 100/50 Mbps, and the given PCO.
    fn csr(seq: u32, sgw_c_teid: u32, pco: Option<&[u8]>) -> bytes::BytesMut {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            crate::gtp_build::gtp2_message_type::CREATE_SESSION_REQUEST,
            0,
            seq,
        ));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &nextgcore_amfd::n26_path::string_to_bcd(IMSI),
        ));
        let mut buf = bytes::BytesMut::new();
        Gtp2RatTypeIe::new(6).encode(&mut buf, 0);
        msg.add_ie(Gtp2Ie::decode(&mut buf.freeze()).unwrap());
        msg.add_ie(Gtp2FTeidIe::new_ipv4(7, sgw_c_teid, [127, 0, 0, 1]).to_ie(0));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::ServingNetwork as u8,
            0,
            &[0x99, 0xf9, 0x07],
        ));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Uli as u8,
            0,
            &[
                0x18, 0x99, 0xf9, 0x07, 0x00, 0x01, 0x99, 0xf9, 0x07, 0x00, 0x00, 0x00, 0x01,
            ],
        ));
        let mut buf = bytes::BytesMut::new();
        Gtp2ApnIe::from_string("internet").encode(&mut buf, 0);
        msg.add_ie(Gtp2Ie::decode(&mut buf.freeze()).unwrap());
        msg.add_ie(Gtp2PaaIe::ipv4([0, 0, 0, 0]).to_ie(0));
        msg.add_ie(Gtp2AmbrIe::new(50_000, 100_000).to_ie(0));
        if let Some(pco) = pco {
            msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Pco as u8, 0, pco));
        }
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        // ARP 8, PCI = 1 (shall not trigger pre-emption), PVI = 1 (not pre-emptable).
        let mut qos = Gtp2BearerQosIe::new(9, 0, 0, 0, 0);
        qos.pl = 8;
        qos.pci = true;
        qos.pvi = true;
        bc.set_bearer_qos(&qos);
        bc.set_fteid(2, &Gtp2FTeidIe::new_ipv4(4, 0x0505_0505, [127, 0, 0, 1]));
        msg.add_bearer_context(0, &bc);
        msg.encode()
    }

    /// The stand-in's Session Modification bodies once `done` holds for them, waiting at
    /// most 10 s (#791): an asynchronous effect is asserted when it has happened, not
    /// when the test happens to look. Returns what was seen either way, so the caller's
    /// assertion reports it.
    async fn poll_modifications(
        upf: &crate::pfcp_path::stand_in::StandInUpf,
        done: impl Fn(&[Vec<u8>]) -> bool,
    ) -> Vec<Vec<u8>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let mods = upf.modification_bodies();
            if done(&mods) || std::time::Instant::now() >= deadline {
                return mods;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn recv_gtp(sock: &tokio::net::UdpSocket) -> Gtp2Message {
        let mut buf = vec![0u8; 8192];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("a GTPv2-C answer")
            .expect("recv");
        Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).expect("decode")
    }

    /// Establish the PDN connection over the real S5/S8 socket; returns the PGW-C S5/S8
    /// control F-TEID this node answered with, and the response's PCO.
    async fn establish_pdn(
        pco: Option<&[u8]>,
    ) -> (
        std::sync::Arc<crate::gtp_path::S5S8Server>,
        (u32, [u8; 4]),
        Option<Vec<u8>>,
    ) {
        let server = crate::gtp_path::S5S8Server::open("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .expect("bind S5/S8");
        let sgw = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sgw.send_to(&csr(0x47, 0x0A0A_0475, pco), server.local_addr())
            .await
            .unwrap();
        let resp = recv_gtp(&sgw).await;
        assert_eq!(
            resp.get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(16),
            "the PDN connection must be established"
        );
        let fteid =
            Gtp2FTeidIe::decode(&resp.get_ie(Gtp2IeType::FTeid as u8, 1).unwrap().value).unwrap();
        let pco = resp
            .get_ie(Gtp2IeType::Pco as u8, 0)
            .map(|ie| ie.value.to_vec());
        (server, (fteid.teid, fteid.ipv4_addr.unwrap()), pco)
    }

    /// The MME's PDN Connection (TS 29.274 Table 7.3.1-2) naming the PGW-C F-TEID this SMF
    /// handed out, its FQDN, and the default bearer.
    fn pdn_connection(pgw_c: (u32, [u8; 4])) -> Vec<u8> {
        let mut pdn = Gtp2PdnConnectionIe::new();
        pdn.add_ie(Gtp2ApnIe::from_string("internet").to_ie(0));
        pdn.add_ie(Gtp2EbiIe::new(5).to_ie(0));
        pdn.add_ie(Gtp2FTeidIe::new_ipv4(7, pgw_c.0, pgw_c.1).to_ie(0));
        let mut fqdn = Vec::new();
        for label in PGW_FQDN.split('.') {
            fqdn.push(label.len() as u8);
            fqdn.extend_from_slice(label.as_bytes());
        }
        pdn.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Fqdn as u8, 0, &fqdn));
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(5);
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        pdn.add_ie(bearer.to_ie(0));
        pdn.add_ie(Gtp2AmbrIe::new(50_000, 100_000).to_ie(0));
        let mut v = bytes::BytesMut::new();
        pdn.encode_value(&mut v);
        v.to_vec()
    }

    /// A Figure 8.38-5 MM Context: KSI 3, EIA2/EEA1, K_ASME, NH with NCC 2.
    fn mm_context() -> Vec<u8> {
        let mut v = vec![(4 << 5) | 0x10 | 0x03, 0x00, (2 << 4) | 1];
        v.extend_from_slice(&[0, 0, 7, 0, 0, 9]);
        v.extend_from_slice(&[0xA5; 32]);
        v.extend_from_slice(&[0x5C; 32]);
        v.push(0x02);
        v.extend_from_slice(&[2, 0xF0, 0x70, 0, 0, 0]);
        v
    }

    fn forward_relocation_request(pgw_c: (u32, [u8; 4])) -> Vec<u8> {
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ForwardRelocationRequest as u8,
            0,
            FRR_SEQ,
        ));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &nextgcore_amfd::n26_path::string_to_bcd(IMSI),
        ));
        msg.add_ie(Gtp2FTeidIe::new_ipv4(12, MME_TEID, [127, 0, 0, 1]).to_ie(0));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::MmContext as u8,
            0,
            &mm_context(),
        ));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::PdnConnection as u8,
            0,
            &pdn_connection(pgw_c),
        ));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::FContainer as u8,
            0,
            &[3, 0x40, 0x41, 0x42],
        ));
        let plmn = nextgcore_amfd::n26_build::encode_plmn_bcd(
            &nextgcore_amfd::context::PlmnId::new("999", "70"),
        );
        let mut target = vec![5, plmn[0], plmn[1], plmn[2], 22];
        target.extend_from_slice(&GNB_ID.to_be_bytes());
        target.extend_from_slice(&[0x00, 0x00, 0x01]);
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::TargetIdentification as u8,
            0,
            &target,
        ));
        msg.add_ie(Gtp2IndicationIe::new().to_ie(0));
        msg.encode().to_vec()
    }

    /// The real smfd SBI handler on a loopback listener.
    async fn start_smf_sbi() -> (SbiServer, u16) {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = addr.port();
        let server = SbiServer::on_listener(
            SbiServerConfig::new(format!("127.0.0.1:{port}").parse().unwrap()),
            listener,
        );
        server
            .start(|req: SbiRequest| async move { crate::smf_sbi_request_handler(req).await })
            .await
            .expect("SMF SBI");
        (server, port)
    }

    /// The one stand-in left on the SBI side: an NRF answering discovery with THIS SMF's
    /// own NF profile, built by the production `build_smf_nf_profile` — so the `pgwFqdn`
    /// advertisement is what the AMF's step-3 selection actually reads.
    async fn start_nrf(smf_port: u16) -> (SbiServer, u16) {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = addr.port();
        let profile = crate::build_smf_nf_profile("smf-475", "127.0.0.1", smf_port);
        let server = SbiServer::on_listener(
            SbiServerConfig::new(format!("127.0.0.1:{port}").parse().unwrap()),
            listener,
        );
        server
            .start(move |_req: SbiRequest| {
                let profile = profile.clone();
                async move {
                    SbiResponse::with_status(200).with_body(
                        serde_json::json!({ "nfInstances": [profile] }).to_string(),
                        "application/json",
                    )
                }
            })
            .await
            .expect("NRF stand-in");
        (server, port)
    }

    /// The UE's dedicated GBR bearer, EBI 6 (QCI 1, ARP 2, GBR 64/32 kbps, MBR 128/64 kbps)
    /// with a downlink packet filter, added to the session the PDN establishment stored.
    ///
    /// Seeded into the store because no production path on this PGW-C creates a dedicated
    /// bearer over S5/S8 yet (filed separately); the EPS→5GS handover must move every bearer
    /// the session holds, whoever created it.
    fn seed_dedicated_gbr_bearer(pgw_c_teid: u32) {
        seed_dedicated_gbr_bearer_with(pgw_c_teid, DEDICATED_DL_FILTER);
    }

    fn seed_dedicated_gbr_bearer_with(pgw_c_teid: u32, dl_filter: &str) {
        let handle = smf_self();
        let ctx = handle.read().unwrap();
        let sess = ctx
            .sess_find_by_teid(pgw_c_teid)
            .expect("the PDN connection");
        let mut bearer = ctx.bearer_add(sess.id).expect("a bearer slot");
        bearer.ebi = DEDICATED_EBI;
        bearer.qfi = DEDICATED_EBI;
        bearer.qos = context::Qos {
            index: 1,
            arp_priority_level: 2,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            mbr_uplink: 64_000,
            mbr_downlink: 128_000,
            gbr_uplink: 32_000,
            gbr_downlink: 64_000,
        };
        ctx.bearer_update(&bearer);
        let mut pf = ctx.pf_add(bearer.id).expect("a packet filter slot");
        pf.direction = context::FlowDirection::DownlinkOnly;
        pf.flow_description = Some(dl_filter.to_string());
        assert!(ctx.pf_update(&pf));
    }

    const DEDICATED_EBI: u8 = 6;
    const DEDICATED_DL_FILTER: &str = "permit out 17 from 198.51.100.7 to assigned";
    /// The target NG-RAN's DL Forwarding UP TNL Information (indirect forwarding).
    const GNB_FWD: ([u8; 4], u32) = ([10, 1, 2, 3], 0x0000_F0D0);

    /// The target's acknowledge for an indirect-forwarding handover: both flows accepted,
    /// both accepted for forwarding, one DL forwarding tunnel for the session.
    fn ho_ack_transfer_with_forwarding() -> Vec<u8> {
        use nextgcore_ngap::transfer::{
            GtpTunnel, HandoverRequestAcknowledgeTransfer, QosFlowItemWithDataForwarding,
            TransportLayerAddress, UpTransportLayerInformation,
        };
        HandoverRequestAcknowledgeTransfer {
            dl_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                transport_layer_address: TransportLayerAddress::from_ipv4(GNB_DL.0),
                gtp_teid: GNB_DL.1.to_be_bytes(),
            }),
            dl_forwarding_up_tnl_information: Some(UpTransportLayerInformation::GtpTunnel(
                GtpTunnel {
                    transport_layer_address: TransportLayerAddress::from_ipv4(GNB_FWD.0),
                    gtp_teid: GNB_FWD.1.to_be_bytes(),
                },
            )),
            security_result: None,
            qos_flow_setup_response_list: [5, DEDICATED_EBI]
                .into_iter()
                .map(|qfi| QosFlowItemWithDataForwarding {
                    qos_flow_identifier: qfi,
                    data_forwarding_accepted: true,
                })
                .collect(),
            qos_flow_failed_to_setup_list: Vec::new(),
            data_forwarding_response_drb_list: Vec::new(),
        }
        .encode()
        .unwrap()
    }

    /// The F-TEID at `instance` in a Bearer Context, as (interface type, TEID, IPv4).
    fn bearer_fteid(bc: &Gtp2BearerContextIe, instance: u8) -> Option<(u8, u32, [u8; 4])> {
        let ie = bc.get_ie(Gtp2IeType::FTeid as u8, instance)?;
        let f = Gtp2FTeidIe::decode(&ie.value).ok()?;
        Some((f.interface_type, f.teid, f.ipv4_addr?))
    }

    fn ho_ack_transfer() -> Vec<u8> {
        use nextgcore_ngap::transfer::{
            GtpTunnel, HandoverRequestAcknowledgeTransfer, QosFlowItemWithDataForwarding,
            TransportLayerAddress, UpTransportLayerInformation,
        };
        HandoverRequestAcknowledgeTransfer {
            dl_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                transport_layer_address: TransportLayerAddress::from_ipv4(GNB_DL.0),
                gtp_teid: GNB_DL.1.to_be_bytes(),
            }),
            dl_forwarding_up_tnl_information: None,
            security_result: None,
            qos_flow_setup_response_list: vec![QosFlowItemWithDataForwarding {
                qos_flow_identifier: 5,
                data_forwarding_accepted: false,
            }],
            qos_flow_failed_to_setup_list: Vec::new(),
            data_forwarding_response_drb_list: Vec::new(),
        }
        .encode()
        .unwrap()
    }

    /// Does an N4 Session Modification body carry an IE of `ie_type` whose value contains
    /// `needle`? (Flat walk: Update FAR / Remove PDR / Create PDR are top-level grouped IEs.)
    fn n4_has(body: &[u8], ie_type: u16, needle: &[u8]) -> bool {
        let mut off = 0usize;
        while off + 4 <= body.len() {
            let t = u16::from_be_bytes([body[off], body[off + 1]]);
            let l = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
            let v = &body[off + 4..(off + 4 + l).min(body.len())];
            if t == ie_type && v.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
            off += 4 + l;
        }
        false
    }

    /// **#475 acceptance, end to end**: amfd's REAL #418 path against this SMF's REAL
    /// handlers. A PDN connection is established over S5/S8 with the UE's PSI in the PCO; a
    /// real type-133 datagram then drives the AMF's NRF lookup by the S5/S8 FQDN (answered
    /// with this SMF's own profile), the conformant CreateSMContext, the HandoverRequest to
    /// the target gNB, the HandoverRequestAcknowledge → PREPARED → Forward Relocation
    /// Response, and the HandoverNotify → COMPLETED → Forward Relocation Complete
    /// Notification. Asserted on the wire at the MME socket, the UPF stand-in and the SMF's
    /// own state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    // Both locks are held across the awaits on purpose: the SMF context, the UPF client,
    // the AMF context and the N26 preparation queue are process-global, and the whole
    // exchange must run without a sibling test touching them.
    #[allow(clippy::await_holding_lock)]
    async fn an_eps_to_5gs_handover_runs_end_to_end_against_the_real_amf() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        let _amf_guard = nextgcore_amfd::test_support::CONTEXT_GUARD.lock().await;
        nextgcore_amfd::test_support::init_context();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        crate::context::smf_context_init(64, 256, 512);
        std::env::set_var("SMF_PGW_FQDN", PGW_FQDN);
        let _ = nextgcore_amfd::n26_path::drain_eps_to_5gs_preparations();
        let previous_guami = {
            let ctx = nextgcore_amfd::context::amf_self();
            let mut guard = ctx.write().unwrap_or_else(|e| e.into_inner());
            let previous = guard.served_guami.clone();
            guard.served_guami = vec![nextgcore_amfd::context::Guami {
                plmn_id: nextgcore_amfd::context::PlmnId::new("999", "70"),
                amf_id: nextgcore_amfd::context::AmfId {
                    region: 2,
                    set: 1,
                    pointer: 0,
                },
            }];
            previous
        };

        // EPS: the PDN connection, with PSI 5 in the PCO.
        let (s5, pgw_c, answered_pco) = establish_pdn(Some(&pco_with_psi(5))).await;
        seed_dedicated_gbr_bearer(pgw_c.0);
        // Long enough that the step-14 release cannot land before the execution check
        // reads the UPF's modifications, which asserts exactly one (#900 review m1).
        std::env::set_var("SMF_INDIRECT_FORWARDING_TIMER_MS", "1500");
        let answered_pco = answered_pco.expect("the PGW-C answers the PCO");
        assert_eq!(
            eps_iwk::pco_container(&answered_pco, false, eps_iwk::pco_container::NW_S_NSSAI),
            Some(vec![0x01, 0x99, 0xf9, 0x07]),
            "mapped S-NSSAI (SST 1) with the PLMN it relates to"
        );
        upf.clear_seen();

        let (_smf, smf_port) = start_smf_sbi().await;
        let (_nrf, nrf_port) = start_nrf(smf_port).await;
        nextgcore_amfd::sbi_path::set_pgw_discovery_nrf_for_test(Some(format!(
            "http://127.0.0.1:{nrf_port}"
        )));

        let n26 = nextgcore_amfd::n26_path::N26Server::open("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .expect("N26");
        let mme = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        mme.send_to(&forward_relocation_request(pgw_c), n26.local_addr())
            .await
            .unwrap();

        // Steps 3-7 ran inside the AMF; the preparation reaches its NGAP queue only if the
        // SMF answered the create.
        let prep = {
            let mut found = None;
            for _ in 0..100 {
                if let Some(p) = nextgcore_amfd::n26_path::drain_eps_to_5gs_preparations().pop() {
                    found = Some(p);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            found.expect("the SMF must accept the conformant create (#475)")
        };

        // Step 6 at the UPF: the N3 uplink PDR 3, then (#583) the dedicated bearer as a QoS
        // flow on the same N3 tunnel -- its uplink PDR 0x16 with QFI 6 and its QER with the
        // bearer's GBR.
        let mods = upf.modification_bodies();
        assert_eq!(
            mods.len(),
            2,
            "step 6: the N3 tunnel, then the dedicated flow"
        );
        assert!(
            n4_has(&mods[0], 1, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x03]),
            "Create PDR with PDR ID 3"
        );
        let mut n3_fteid = vec![0x00, 0x15, 0x00, 0x09, 0x01];
        n3_fteid.extend_from_slice(&crate::pfcp_path::stand_in::N3_STAND_IN_TEID.to_be_bytes());
        n3_fteid.extend_from_slice(&upf.upf_ip);
        assert!(
            n4_has(&mods[1], 1, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x16])
                && n4_has(&mods[1], 1, &n3_fteid)
                && n4_has(&mods[1], 1, &[0x00, 0x7C, 0x00, 0x01, DEDICATED_EBI]),
            "Create PDR 0x16 on the N3 F-TEID, QFI 6"
        );
        // GBR IE (type 27): UL 32 kbps, DL 64 kbps, 5 octets each.
        assert!(
            n4_has(
                &mods[1],
                7,
                &[0x00, 0x1B, 0x00, 0x0A, 0, 0, 0, 0, 32, 0, 0, 0, 0, 64]
            ),
            "Create QER with the dedicated bearer's GBR"
        );

        // SMF state after step 7.
        let ref_ = {
            let ctx = smf_self();
            let ctx = ctx.read().unwrap();
            let sess = ctx.sess_find_by_teid(pgw_c.0).expect("the session");
            assert_eq!(sess.psi, 5);
            assert!(sess.handover.eps_to_5gs && sess.epc);
            let r = sess.sm_context_ref.clone().unwrap();
            assert_eq!(
                ctx.upf_ul_endpoints.read().unwrap().get(&r).copied(),
                Some((crate::pfcp_path::stand_in::N3_STAND_IN_TEID, upf.upf_ip))
            );
            assert_eq!(
                ctx.cp_n4_seids.read().unwrap().get(&r).copied(),
                Some(sess.smf_n4_seid),
                "the inherited S5/S8 N4 SEID, not one derived from the reference"
            );
            let seid = sess.smf_n4_seid;
            drop(ctx);
            assert_eq!(
                crate::smf_n4_seid_for(&r),
                seid,
                "every later N4 procedure on this context addresses the S5/S8 session's SEID"
            );
            r
        };

        let mut ngap = nextgcore_amfd::ngap_path::NgapServer::new(
            "127.0.0.1:0".parse().unwrap(),
            nextgcore_amfd::ngap_path::SctpBackend::Userspace,
            tokio::sync::mpsc::channel(64).0,
        )
        .await
        .unwrap();
        ngap.harness_add_target_gnb(
            TARGET_ASSOC,
            GNB_ID,
            22,
            nextgcore_amfd::context::PlmnId::new("999", "70"),
        )
        .await;
        let (amf_ue_ngap_id, target, request) = ngap
            .harness_prepare_eps_to_5gs(prep)
            .await
            .expect("HandoverRequest");
        assert_eq!(target, TARGET_ASSOC);

        // Step 9: the target receives THIS SMF's N2 SM information. Decoded with the
        // generated codec the AMF encoded it with (#417): the eps-to-5gs HandoverRequest
        // carries IEs (NASC, id 41) the hand-written parser does not model.
        let nextgcore_ngap_gen::NGAP_PDU::InitiatingMessage(hr) =
            nextgcore_ngap_gen::decode(&request).unwrap()
        else {
            panic!("a HandoverRequest is an initiating message");
        };
        let nextgcore_ngap_gen::generated::InitiatingMessageValue::Id_HandoverResourceAllocation(
            hr,
        ) = hr.value
        else {
            panic!("HandoverRequest expected");
        };
        let items: Vec<(u8, u8, Vec<u8>)> = hr
            .protocol_i_es
            .0
            .iter()
            .filter_map(|ie| match &ie.value {
                nextgcore_ngap_gen::generated::HandoverRequestProtocolIEs_EntryValue::Id_PDUSessionResourceSetupListHOReq(l) => Some(
                    l.0.iter()
                        .map(|item| (item.pdu_session_id.0, item.s_nssai.sst.0[0], item.handover_request_transfer.0.clone()))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(items.len(), 1);
        assert_eq!(
            (items[0].0, items[0].1),
            (5, 1),
            "PDU session 5, S-NSSAI SST 1"
        );
        let n2 =
            nextgcore_ngap::transfer::PduSessionResourceSetupRequestTransfer::decode(&items[0].2)
                .expect("the SMF's PDUSessionResourceSetupRequestTransfer");
        let nextgcore_ngap::transfer::UpTransportLayerInformation::GtpTunnel(ul) =
            &n2.ul_ngu_up_tnl_information;
        assert_eq!(
            u32::from_be_bytes(ul.gtp_teid),
            crate::pfcp_path::stand_in::N3_STAND_IN_TEID,
            "CN Tunnel Info is the N3 tunnel step 6 allocated"
        );
        let flows: Vec<_> = n2
            .qos_flow_setup_request_list
            .iter()
            .map(|f| {
                (
                    f.qos_flow_identifier,
                    f.e_rab_id,
                    f.qos_flow_level_qos_parameters
                        .gbr_qos_information
                        .as_ref()
                        .map(|g| g.guaranteed_flow_bit_rate_dl),
                )
            })
            .collect();
        assert_eq!(
            flows,
            vec![(5, Some(5), None), (6, Some(6), Some(64_000))],
            "step 7: one QoS flow per EPS bearer, the EBI↔QFI mapping, the GBR"
        );
        assert!(
            !n2.data_forwarding_not_possible && !n2.direct_forwarding_path_availability,
            "the MME offered no direct path, so the AMF asked for indirect forwarding"
        );
        let ue_ebis: Vec<_> = ngap
            .harness_assigned_ebis(amf_ue_ngap_id)
            .into_iter()
            .map(|(ebi, psi, arp)| (ebi, psi, arp.priority_level, arp.preempt_cap))
            .collect();
        assert_eq!(
            ue_ebis,
            vec![
                (5, 5, 8, "NOT_PREEMPT".to_string()),
                (6, 5, 2, "MAY_PREEMPT".to_string())
            ],
            "allocatedEbiList with each bearer's ARP (PCI set → NOT_PREEMPT)"
        );

        // Steps 10-14.
        upf.clear_seen();
        let ack = nextgcore_ngap::builder::build_handover_request_acknowledge(
            &nextgcore_ngap::types::HandoverRequestAcknowledge {
                amf_ue_ngap_id,
                ran_ue_ngap_id: 77,
                admitted_list: vec![nextgcore_ngap::types::PduSessionResourceAdmittedItemHoAck {
                    pdu_session_id: 5,
                    transfer: ho_ack_transfer_with_forwarding(),
                }],
                failed_list: None,
                target_to_source_container: vec![0xC0, 0xFE],
            },
        )
        .unwrap();
        ngap.harness_handover_request_acknowledge(TARGET_ASSOC, &ack)
            .await
            .unwrap();
        let response = recv_gtp(&mme).await;
        assert_eq!(
            response.header.message_type, 134,
            "Forward Relocation Response"
        );
        assert_eq!(response.header.sequence_number, FRR_SEQ);
        assert_eq!(
            Gtp2CauseIe::decode(&response.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
                .unwrap()
                .cause,
            16
        );
        // #583, steps 12-14: each bearer's indirect forwarding tunnel at the UPF, in its
        // Bearer Context as the "SGW/UPF F-TEID for DL data forwarding" (instance 2, type 23).
        let set_up: Vec<(u8, Option<(u8, u32, [u8; 4])>)> = response
            .get_ies(Gtp2IeType::BearerContext as u8)
            .iter()
            .map(|ie| {
                let bc = Gtp2BearerContextIe::decode(&ie.value).unwrap();
                (bc.ebi().unwrap(), bearer_fteid(&bc, 2))
            })
            .collect();
        let teid = crate::pfcp_path::stand_in::N3_STAND_IN_TEID;
        assert_eq!(
            set_up,
            vec![
                (5, Some((23, teid, upf.upf_ip))),
                (6, Some((23, teid + 1, upf.upf_ip)))
            ],
            "the EPS Bearer Setup List carries a forwarding tunnel per bearer (#791 \
             diagnostics: N4 messages {:?}, {} modification(s), handover {:?})",
            upf.seen(),
            upf.modification_bodies().len(),
            smf_self()
                .read()
                .ok()
                .and_then(|c| c.sess_find_by_sm_context_ref(&ref_))
                .map(|s| s.handover)
        );
        // Step 12 at the UPF: one FAR to the target's forwarding tunnel, one PDR per bearer
        // on a UPF-chosen F-TEID, each with a QER adding the bearer's QFI. The DL path is
        // not switched.
        let mods = upf.modification_bodies();
        assert_eq!(mods.len(), 1, "PREPARED: the forwarding tunnels only");
        let mut fwd_ohc = vec![0x01, 0x00];
        fwd_ohc.extend_from_slice(&GNB_FWD.1.to_be_bytes());
        fwd_ohc.extend_from_slice(&GNB_FWD.0);
        assert!(
            n4_has(&mods[0], 3, &fwd_ohc),
            "Create FAR to the forwarding tunnel"
        );
        for pdr in [0x55u8, 0x56] {
            assert!(
                n4_has(&mods[0], 1, &[0x00, 0x38, 0x00, 0x02, 0x00, pdr]),
                "Create PDR 0x{pdr:x}"
            );
        }
        assert!(
            !n4_has(&mods[0], 10, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 2]),
            "no Update FAR 2: the DL is not switched"
        );
        upf.clear_seen();

        // Execution.
        let plmn = nextgcore_amfd::n26_build::encode_plmn_bcd(
            &nextgcore_amfd::context::PlmnId::new("999", "70"),
        );
        let notify = nextgcore_ngap::builder::build_handover_notify(
            &nextgcore_ngap::types::HandoverNotify {
                amf_ue_ngap_id,
                ran_ue_ngap_id: 77,
                user_location_info: nextgcore_ngap::types::UserLocationInformation::Nr {
                    nr_cgi_plmn: plmn,
                    nr_cell_identity: 0x1A2001,
                    tai_plmn: plmn,
                    tai_tac: [0, 0, 1],
                },
            },
        )
        .unwrap();
        ngap.harness_handover_notify(TARGET_ASSOC, &notify)
            .await
            .unwrap();
        let complete = recv_gtp(&mme).await;
        assert_eq!(
            complete.header.message_type, 135,
            "Forward Relocation Complete Notification"
        );

        // Execution step 8 at the UPF: DL FAR 2 → the target gNB, PDR 1 removed. #945: the
        // AMF sends the FRCN first (TS 23.502 §4.11.1.2.2.3 step 5) and COMPLETED (step 7)
        // off its NGAP task after it, so the switch is waited for here, up to 5 s. #791's
        // `left: 0` was the SMF finding no N4 session (an unlocked sibling had wiped
        // `pfcp_sessions`, closed by #762); the diagnostics say which state it was in.
        let mut mods = upf.modification_bodies();
        for _ in 0..100 {
            if !mods.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            mods = upf.modification_bodies();
        }
        assert_eq!(
            mods.len(),
            1,
            "execution is one N4 Session Modification (#791 diagnostics: N4 messages {:?}, \
             handover {:?})",
            upf.seen(),
            smf_self()
                .read()
                .ok()
                .and_then(|c| c.sess_find_by_sm_context_ref(&ref_))
                .map(|s| s.handover)
        );
        let mut ohc = vec![0x01, 0x00]; // GTP-U/UDP/IPv4
        ohc.extend_from_slice(&GNB_DL.1.to_be_bytes());
        ohc.extend_from_slice(&GNB_DL.0);
        assert!(
            n4_has(&mods[0], 10, &ohc),
            "Update FAR to the target's DL N3 endpoint"
        );
        assert!(
            n4_has(&mods[0], 15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x01]),
            "Remove PDR 1, the S5/S8-U uplink"
        );
        // #583: the dedicated bearer's downlink, as a QoS flow on the target's N3 tunnel.
        let mut sdf = DEDICATED_DL_FILTER.as_bytes().to_vec();
        sdf.truncate(16);
        assert!(
            n4_has(&mods[0], 1, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x36]) && n4_has(&mods[0], 1, &sdf),
            "Create PDR 0x36 on the dedicated bearer's downlink filter"
        );
        assert!(
            !n4_has(&mods[0], 15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x55]),
            "the forwarding tunnels outlive execution"
        );
        // Step 14: the forwarding timer expires and the tunnels go. Found by content,
        // with a bounded wait (#791), not by position.
        let far_0x50: &[u8] = &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50];
        let released = poll_modifications(&upf, |m| m.iter().any(|b| n4_has(b, 16, far_0x50)))
            .await
            .into_iter()
            .find(|b| n4_has(b, 16, far_0x50))
            .expect("the indirect forwarding resources are released on the timer");
        for pdr in [0x55u8, 0x56] {
            assert!(
                n4_has(&released, 15, &[0x00, 0x38, 0x00, 0x02, 0x00, pdr]),
                "Remove PDR 0x{pdr:x}"
            );
        }
        assert!(
            n4_has(&released, 16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50]),
            "Remove FAR 0x50"
        );
        std::env::remove_var("SMF_INDIRECT_FORWARDING_TIMER_MS");
        {
            let ctx = smf_self();
            let ctx = ctx.read().unwrap();
            let sess = ctx.sess_find_by_sm_context_ref(&ref_).unwrap();
            assert!(!sess.epc && !sess.handover.eps_to_5gs, "a PDU session now");
            assert_eq!(sess.up_cnx_state, context::UpCnxState::Activated);
        }

        nextgcore_amfd::sbi_path::set_pgw_discovery_nrf_for_test(None);
        std::env::remove_var("SMF_PGW_FQDN");
        {
            let ctx = nextgcore_amfd::context::amf_self();
            ctx.write().unwrap_or_else(|e| e.into_inner()).served_guami = previous_guami;
        }
        s5.close();
    }

    /// TS 29.502 §5.2.2.2.3 step 2b: a PDN connection with no PSI is refused with
    /// NO_EPS_5GS_CONTINUITY, and nothing is asked of the UPF.
    #[tokio::test]
    async fn a_pdn_connection_without_a_psi_has_no_eps_to_5gs_continuity() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, answered_pco) = establish_pdn(None).await;
        assert!(answered_pco.is_none(), "no PCO asked, none answered");
        upf.clear_seen();
        use base64::Engine as _;
        let body = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": base64::engine::general_purpose::STANDARD.encode(pdn_connection(pgw_c)),
        });
        let resp = handle_create(&body).await;
        assert_eq!(resp.status, 403);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("NO_EPS_5GS_CONTINUITY"));
        assert!(
            upf.seen().is_empty(),
            "nothing reserved for a PDN connection that cannot move"
        );
        s5.close();
    }

    /// A ueEpsPdnConnection naming a PDN connection this SMF does not hold is 404, and one
    /// owned by ANOTHER subscriber is not handed over to this one.
    #[tokio::test]
    async fn a_pdn_connection_this_smf_does_not_hold_or_another_ue_owns_is_not_found() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        use base64::Engine as _;
        let b64 = |pdn: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(pdn);
        let unknown = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": b64(pdn_connection((pgw_c.0 ^ 0xFFFF, pgw_c.1))),
        });
        // The F-TEID resolves to nothing; the EBI fallback would find the session, so the
        // linked EBI is changed too.
        let mut pdn = Gtp2PdnConnectionIe::new();
        pdn.add_ie(Gtp2ApnIe::from_string("internet").to_ie(0));
        pdn.add_ie(Gtp2EbiIe::new(9).to_ie(0));
        pdn.add_ie(Gtp2FTeidIe::new_ipv4(7, pgw_c.0 ^ 0xFFFF, pgw_c.1).to_ie(0));
        let mut v = bytes::BytesMut::new();
        pdn.encode_value(&mut v);
        let mut unknown = unknown;
        unknown["ueEpsPdnConnection"] = serde_json::json!(b64(v.to_vec()));
        assert_eq!(handle_create(&unknown).await.status, 404);
        let other_ue = serde_json::json!({
            "supi": "imsi-001019999999999",
            "hoState": "PREPARING",
            "ueEpsPdnConnection": b64(pdn_connection(pgw_c)),
        });
        assert_eq!(
            handle_create(&other_ue).await.status,
            404,
            "a PDN connection is never handed over to a SUPI that does not own it"
        );
        s5.close();
        // #941 review: the PDN connection this test established is removed, or a later
        // test's EPC sweep (the shutdown's PGW-U deletions) sees it as its own.
        if let Ok(ctx) = crate::context::smf_self().read() {
            for sess in ctx.sess_find_all_by(|s| s.epc) {
                ctx.sess_remove(sess.id);
            }
        }
    }

    /// #583, direct forwarding: the AMF's `directForwardingFlag` becomes Direct Forwarding
    /// Path Availability in the N2 SM information, and at PREPARED the target's per-E-RAB
    /// tunnels from its Data Forwarding Response E-RAB List go to the MME as each bearer's
    /// "eNodeB/gNodeB F-TEID for DL data forwarding" (instance 0, type 19) -- with nothing
    /// installed at the UPF, which direct forwarding bypasses.
    #[tokio::test]
    async fn direct_forwarding_returns_the_targets_per_e_rab_tunnels() {
        use nextgcore_ngap_gen::generated as g;
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        seed_dedicated_gbr_bearer(pgw_c.0);
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": b64.encode(pdn_connection(pgw_c)),
            "directForwardingFlag": true,
            "indirectForwardingFlag": false,
        });
        let created = handle_create(&body).await;
        assert_eq!(created.status, 201);
        let n2 = nextgcore_ngap::transfer::PduSessionResourceSetupRequestTransfer::decode(
            &created.http.parts[0].data,
        )
        .unwrap();
        assert!(n2.direct_forwarding_path_availability && !n2.data_forwarding_not_possible);
        let reference =
            serde_json::from_str::<serde_json::Value>(created.http.content.as_deref().unwrap())
                .unwrap()["smContextRef"]
                .as_str()
                .unwrap()
                .to_string();
        upf.clear_seen();

        let erab = |ebi: u8, teid: u32| g::DataForwardingResponseERABListItem {
            e_rab_id: g::E_RAB_ID(ebi),
            dl_forwarding_up_tnl_information: crate::n2_transfer::gtp_tunnel((
                teid,
                [10, 9, 9, ebi],
            )),
            ie_extensions: None,
        };
        let ack = g::HandoverRequestAcknowledgeTransfer {
            dl_ngu_up_tnl_information: crate::n2_transfer::gtp_tunnel((GNB_DL.1, GNB_DL.0)),
            dl_forwarding_up_tnl_information: None,
            security_result: None,
            qos_flow_setup_response_list: g::QosFlowListWithDataForwarding(
                [5, DEDICATED_EBI]
                    .into_iter()
                    .map(|q| g::QosFlowItemWithDataForwarding {
                        qos_flow_identifier: g::QosFlowIdentifier(q),
                        data_forwarding_accepted: Some(g::DataForwardingAccepted(0)),
                        ie_extensions: None,
                    })
                    .collect(),
            ),
            qos_flow_failed_to_setup_list: None,
            data_forwarding_response_drb_list: None,
            ie_extensions: Some(g::HandoverRequestAcknowledgeTransferIE_Extensions(vec![
                g::HandoverRequestAcknowledgeTransferIE_Extensions_Entry {
                    id: g::ProtocolExtensionID(249),
                    criticality: g::Criticality(g::Criticality::IGNORE),
                    extension_value:
                        g::HandoverRequestAcknowledgeTransferIE_Extensions_EntryExtensionValue::Id_DataForwardingResponseERABList(
                            g::DataForwardingResponseERABList(vec![
                                erab(5, 0xD5),
                                erab(DEDICATED_EBI, 0xD6),
                            ]),
                        ),
                },
            ])),
        };
        let transfer = nextgcore_ngap_gen::encode_contained(&ack).unwrap();
        let resp = handle_prepared(&reference, &transfer).await;
        assert_eq!(resp.status, 200);
        let root: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let set_up: Vec<(u8, Option<(u8, u32, [u8; 4])>, Option<(u8, u32, [u8; 4])>)> = root
            ["epsBearerSetup"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let raw = b64.decode(e.as_str().unwrap()).unwrap();
                let bc =
                    nextgcore_amfd::n26_eps_to_5gs::bearer_context_from_container(&raw).unwrap();
                (
                    bc.ebi().unwrap(),
                    bearer_fteid(&bc, 0),
                    bearer_fteid(&bc, 2),
                )
            })
            .collect();
        assert_eq!(
            set_up,
            vec![
                (5, Some((19, 0xD5, [10, 9, 9, 5])), None),
                (6, Some((19, 0xD6, [10, 9, 9, 6])), None),
            ]
        );
        assert!(
            upf.modification_bodies().is_empty(),
            "direct forwarding installs nothing at the UPF"
        );
        s5.close();
    }

    /// A G-PDU (TS 29.281) on `teid` carrying `inner`, with a PDU Session Container (TS
    /// 38.415 §5.5.2) of `pdu_type` (0 DL, 1 UL) and `qfi` when given.
    fn gpdu(teid: u32, inner: &[u8], container: Option<(u8, u8)>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some((pdu_type, qfi)) = container {
            ext = vec![0, 0, 0, 0x85, 1, pdu_type << 4, qfi & 0x3F, 0];
        }
        let mut out = vec![if ext.is_empty() { 0x30 } else { 0x34 }, 0xFF];
        out.extend_from_slice(&((ext.len() + inner.len()) as u16).to_be_bytes());
        out.extend_from_slice(&teid.to_be_bytes());
        out.extend_from_slice(&ext);
        out.extend_from_slice(inner);
        out
    }

    /// An IPv4/UDP packet with a valid header checksum.
    fn ipv4_udp(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let payload = b"nextg-583";
        let total = (20 + 8 + payload.len()) as u16;
        let mut p = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0];
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        let sum = p
            .chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], c[1]])))
            .sum::<u32>();
        let sum = (sum & 0xFFFF) + (sum >> 16);
        p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        p.extend_from_slice(&5000u16.to_be_bytes());
        p.extend_from_slice(&5000u16.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    /// The (TEID, QFI, inner packet) of a G-PDU with at most one PDU Session Container.
    fn parse_gpdu(pkt: &[u8]) -> (u32, Option<u8>, Vec<u8>) {
        let teid = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        if pkt[0] & 0x07 == 0 {
            return (teid, None, pkt[8..].to_vec());
        }
        let mut off = 12;
        let mut qfi = None;
        let mut next = pkt[11];
        while next != 0 {
            let len = usize::from(pkt[off]) * 4;
            if next == 0x85 {
                qfi = Some(pkt[off + 2] & 0x3F);
            }
            next = pkt[off + len - 1];
            off += len;
        }
        (teid, qfi, pkt[off..].to_vec())
    }

    async fn recv_gpdu(
        sock: &tokio::net::UdpSocket,
        wait: Duration,
    ) -> Option<(u32, Option<u8>, Vec<u8>)> {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, _) = tokio::time::timeout(wait, sock.recv_from(&mut buf))
                .await
                .ok()?
                .ok()?;
            // Skip End Markers (message type 254) and echoes: only G-PDUs carry traffic.
            if buf[1] == 0xFF {
                return Some(parse_gpdu(&buf[..n]));
            }
        }
    }

    fn upf_ul_packets(upf: std::net::Ipv4Addr) -> u64 {
        use std::io::{Read, Write};
        let mut tcp = std::net::TcpStream::connect((upf, 9090)).expect("UPF metrics");
        tcp.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").unwrap();
        let mut body = String::new();
        tcp.read_to_string(&mut body).unwrap();
        body.lines()
            .find_map(|l| l.strip_prefix("upf_dataplane_ul_packets_total "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }

    /// **#583 across the REAL `nextgcore-upfd` binary.** smfd's production N4 path (this
    /// process) drives a running upfd; this test then plays the source SGW-U and the target
    /// gNB on the wire and asserts on the GTP-U the UPF actually emits:
    ///
    /// 1. the indirect forwarding tunnels the UPF allocated relay the source's downlink to the
    ///    target's DL forwarding tunnel, QFI added per bearer;
    /// 2. uplink on the dedicated QoS flow's QFI is accepted on the N3 tunnel;
    /// 3. after execution, downlink entering the UPF's TUN leaves on the target's N3 tunnel
    ///    marked with the dedicated flow's QFI when it matches its TFT, the default one
    ///    otherwise;
    /// 4. the forwarding tunnels stop relaying when the step-14 timer expires.
    ///
    /// Ignored: needs `NEXTG_REAL_UPF` (the upfd's PFCP/GTP-U IPv4), `NEXTG_REAL_UPF_LOCAL`
    /// (this host's IPv4 on that network) and `NEXTG_REAL_UPF_CONTAINER` (to inject the
    /// downlink into its TUN with `docker exec`). The runbook is in the #583 spec.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs a running nextgcore-upfd; see the #583 spec"]
    #[allow(clippy::await_holding_lock)]
    async fn eps_to_5gs_forwarding_and_qos_flows_cross_the_real_upf() {
        let ip = |var: &str| -> std::net::Ipv4Addr {
            std::env::var(var)
                .unwrap_or_else(|_| panic!("{var} is not set"))
                .parse()
                .unwrap()
        };
        let (upf_ip, local) = (ip("NEXTG_REAL_UPF"), ip("NEXTG_REAL_UPF_LOCAL"));
        let container = std::env::var("NEXTG_REAL_UPF_CONTAINER").expect("container name");
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf =
            crate::pfcp_path::stand_in::real_upf((local, 0).into(), (upf_ip, 8805).into()).await;
        crate::context::smf_context_init(64, 256, 512);
        std::env::set_var("SMF_INDIRECT_FORWARDING_TIMER_MS", "2500");
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        let ue = smf_self()
            .read()
            .unwrap()
            .sess_find_by_teid(pgw_c.0)
            .unwrap()
            .ipv4_addr
            .unwrap();
        eprintln!("UE {ue}");
        // The dedicated bearer's TFT: UDP from the UPF's own TUN address, so `docker exec`
        // can produce a matching downlink packet.
        seed_dedicated_gbr_bearer_with(pgw_c.0, &format!("permit out 17 from 10.45.0.1 to {ue}"));

        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let created = handle_create(&serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": b64.encode(pdn_connection(pgw_c)),
            "indirectForwardingFlag": true,
        }))
        .await;
        assert_eq!(created.status, 201, "step 6 on the real UPF");
        let reference =
            serde_json::from_str::<serde_json::Value>(created.http.content.as_deref().unwrap())
                .unwrap()["smContextRef"]
                .as_str()
                .unwrap()
                .to_string();
        let n3 = crate::lookup_upf_ul_endpoint(&reference).expect("the N3 F-TEID");
        eprintln!("N3 uplink F-TEID {:#x} @ {:?}", n3.0, n3.1);
        assert_eq!(n3.1, upf_ip.octets(), "allocated by the real UPF");

        // The target gNB: N3 and forwarding tunnels on the GTP-U port of this host.
        let gnb = tokio::net::UdpSocket::bind((local, 2152))
            .await
            .expect("gNB GTP-U");
        const N3_DL: u32 = 0x0000_ABCD;
        const FWD_DL: u32 = 0x0000_F0D0;
        let ack = {
            use nextgcore_ngap::transfer::{
                GtpTunnel, HandoverRequestAcknowledgeTransfer, QosFlowItemWithDataForwarding,
                TransportLayerAddress, UpTransportLayerInformation,
            };
            let tunnel = |teid: u32| {
                UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                    transport_layer_address: TransportLayerAddress::from_ipv4(local.octets()),
                    gtp_teid: teid.to_be_bytes(),
                })
            };
            HandoverRequestAcknowledgeTransfer {
                dl_ngu_up_tnl_information: tunnel(N3_DL),
                dl_forwarding_up_tnl_information: Some(tunnel(FWD_DL)),
                security_result: None,
                qos_flow_setup_response_list: [5, DEDICATED_EBI]
                    .into_iter()
                    .map(|qfi| QosFlowItemWithDataForwarding {
                        qos_flow_identifier: qfi,
                        data_forwarding_accepted: true,
                    })
                    .collect(),
                qos_flow_failed_to_setup_list: Vec::new(),
                data_forwarding_response_drb_list: Vec::new(),
            }
            .encode()
            .unwrap()
        };
        let prepared = handle_prepared(&reference, &ack).await;
        assert_eq!(prepared.status, 200);
        let root: serde_json::Value =
            serde_json::from_str(prepared.http.content.as_deref().unwrap()).unwrap();
        let forwarding: Vec<(u8, u32, [u8; 4])> = root["epsBearerSetup"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let raw = b64.decode(e.as_str().unwrap()).unwrap();
                let bc =
                    nextgcore_amfd::n26_eps_to_5gs::bearer_context_from_container(&raw).unwrap();
                let (_, teid, addr) = bearer_fteid(&bc, 2).expect("an indirect tunnel");
                (bc.ebi().unwrap(), teid, addr)
            })
            .collect();
        eprintln!("indirect forwarding tunnels at the UPF: {forwarding:x?}");
        assert_eq!(forwarding.len(), 2);

        // 1. The source SGW-U forwards in-flight downlink into each bearer's tunnel.
        let sgw = tokio::net::UdpSocket::bind((local, 0)).await.unwrap();
        for &(ebi, teid, addr) in &forwarding {
            assert_eq!(addr, upf_ip.octets());
            let inner = ipv4_udp([198, 51, 100, 7], ue.octets());
            sgw.send_to(&gpdu(teid, &inner, None), (upf_ip, 2152))
                .await
                .unwrap();
            let got = recv_gpdu(&gnb, Duration::from_secs(3))
                .await
                .expect("the UPF relays the forwarded packet to the target");
            eprintln!(
                "EBI {ebi}: forwarded G-PDU at the target: TEID {:#x} QFI {:?}",
                got.0, got.1
            );
            assert_eq!(got, (FWD_DL, Some(ebi), inner), "EBI {ebi}");
        }

        // 2. Uplink on the dedicated flow, on the N3 tunnel.
        let before = upf_ul_packets(upf_ip);
        let ul = ipv4_udp(ue.octets(), [198, 51, 100, 7]);
        sgw.send_to(&gpdu(n3.0, &ul, Some((1, DEDICATED_EBI))), (upf_ip, 2152))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after = upf_ul_packets(upf_ip);
        eprintln!("UPF uplink packets: {before} -> {after}");
        assert_eq!(
            after,
            before + 1,
            "the dedicated QFI's uplink reached the N6 side"
        );

        // 3. Execution, then downlink from the data network side of the UPF.
        assert_eq!(handle_completed(&reference, None).await.status, 200);
        let exec = |cmd: String| {
            let out = std::process::Command::new("docker")
                .args(["exec", &container, "bash", "-c", &cmd])
                .output()
                .expect("docker exec");
            eprintln!("docker exec {cmd}: {:?}", out.status);
        };
        exec(format!("echo nextg-583 > /dev/udp/{ue}/5000"));
        let dedicated = recv_gpdu(&gnb, Duration::from_secs(3))
            .await
            .expect("downlink on the dedicated flow reaches the target");
        eprintln!(
            "DL UDP from 10.45.0.1: TEID {:#x} QFI {:?}",
            dedicated.0, dedicated.1
        );
        assert_eq!((dedicated.0, dedicated.1), (N3_DL, Some(DEDICATED_EBI)));
        exec(format!("ping -c 1 -W 1 {ue} || true"));
        let default = recv_gpdu(&gnb, Duration::from_secs(3))
            .await
            .expect("downlink on the default flow reaches the target");
        eprintln!("DL ICMP: TEID {:#x} QFI {:?}", default.0, default.1);
        assert_eq!((default.0, default.1), (N3_DL, Some(5)));

        // 3b. #582: dual connectivity -- the dedicated flow moves to a secondary node's
        // tunnel; the UPF sends it there and keeps the default flow on the master's.
        const SN_DL: u32 = 0x0000_B002;
        let resp = crate::an_initiated_modification(
            &reference,
            &split_indication(
                ((N3_DL, local.octets()), &[5]),
                &[((SN_DL, local.octets()), &[DEDICATED_EBI])],
            ),
        )
        .await;
        assert_eq!(resp.status, 200, "PDU_RES_MOD_CFM from the real UPF path");
        exec(format!("echo nextg-582 > /dev/udp/{ue}/5000"));
        let split = recv_gpdu(&gnb, Duration::from_secs(3))
            .await
            .expect("the dedicated flow's downlink reaches the SN tunnel");
        eprintln!(
            "DC: DL UDP from 10.45.0.1: TEID {:#x} QFI {:?}",
            split.0, split.1
        );
        assert_eq!((split.0, split.1), (SN_DL, Some(DEDICATED_EBI)));
        exec(format!("ping -c 1 -W 1 {ue} || true"));
        let master = recv_gpdu(&gnb, Duration::from_secs(3))
            .await
            .expect("the default flow stays on the MN tunnel");
        eprintln!("DC: DL ICMP: TEID {:#x} QFI {:?}", master.0, master.1);
        assert_eq!((master.0, master.1), (N3_DL, Some(5)));

        // 4. The forwarding tunnels go when the timer expires.
        tokio::time::sleep(Duration::from_millis(2600)).await;
        let (_, teid, _) = forwarding[0];
        sgw.send_to(
            &gpdu(teid, &ipv4_udp([198, 51, 100, 7], ue.octets()), None),
            (upf_ip, 2152),
        )
        .await
        .unwrap();
        assert!(
            recv_gpdu(&gnb, Duration::from_millis(800)).await.is_none(),
            "no relay once the forwarding resources are released"
        );
        eprintln!("after the timer: nothing relayed");
        std::env::remove_var("SMF_INDIRECT_FORWARDING_TIMER_MS");
        s5.close();
    }

    /// A PDUSessionResourceModifyIndicationTransfer (TS 38.413 §9.3.4.20, generated
    /// codec): the primary DL tunnel and the Additional DL QoS Flow per TNL Information of
    /// a split PDU session, each `((TEID, IPv4), QFIs)`.
    fn split_indication(
        primary: ((u32, [u8; 4]), &[u8]),
        additional: &[((u32, [u8; 4]), &[u8])],
    ) -> Vec<u8> {
        use nextgcore_ngap_gen::generated as g;
        let per_tnl = |(tunnel, qfis): ((u32, [u8; 4]), &[u8])| g::QosFlowPerTNLInformation {
            up_transport_layer_information: crate::n2_transfer::gtp_tunnel(tunnel),
            associated_qos_flow_list: g::AssociatedQosFlowList(
                qfis.iter()
                    .map(|&q| g::AssociatedQosFlowItem {
                        qos_flow_identifier: g::QosFlowIdentifier(q),
                        qos_flow_mapping_indication: None,
                        ie_extensions: None,
                    })
                    .collect(),
            ),
            ie_extensions: None,
        };
        nextgcore_ngap_gen::encode_contained(&g::PDUSessionResourceModifyIndicationTransfer {
            dl_qos_flow_per_tnl_information: per_tnl(primary),
            additional_dl_qos_flow_per_tnl_information: (!additional.is_empty()).then(|| {
                g::QosFlowPerTNLInformationList(
                    additional
                        .iter()
                        .map(|&a| g::QosFlowPerTNLInformationItem {
                            qos_flow_per_tnl_information: per_tnl(a),
                            ie_extensions: None,
                        })
                        .collect(),
                )
            }),
            ie_extensions: None,
        })
        .unwrap()
    }

    /// An EPS→5GS-moved session with its default flow (QFI 5) and dedicated GBR flow
    /// (QFI 6, DL PDR 0x36), executed toward `GNB_DL`; returns its SM context reference.
    async fn moved_session_with_a_dedicated_flow(pgw_c: (u32, [u8; 4])) -> String {
        use base64::Engine as _;
        seed_dedicated_gbr_bearer(pgw_c.0);
        let created = handle_create(&serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": base64::engine::general_purpose::STANDARD.encode(pdn_connection(pgw_c)),
        }))
        .await;
        assert_eq!(created.status, 201);
        let reference =
            serde_json::from_str::<serde_json::Value>(created.http.content.as_deref().unwrap())
                .unwrap()["smContextRef"]
                .as_str()
                .unwrap()
                .to_string();
        assert_eq!(
            handle_prepared(&reference, &ho_ack_transfer()).await.status,
            200
        );
        assert_eq!(handle_completed(&reference, None).await.status, 200);
        reference
    }

    /// #582, TS 38.413 §8.2.5.2: a Modify Indication for a split PDU session (dual
    /// connectivity) installs the additional NG-U tunnel at the UPF -- a FAR of its own, the
    /// flows it carries re-pointed at it -- and the Modify Confirm Transfer confirms those
    /// flows, gives the tunnel's (UL, DL) pair, and fails a QFI the session has no flow for.
    /// A later indication with the primary tunnel only takes the flows back and removes the
    /// tunnel's FAR.
    #[tokio::test]
    async fn a_split_pdu_session_installs_and_confirms_its_additional_tunnel() {
        use nextgcore_ngap_gen::generated as g;
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        let reference = moved_session_with_a_dedicated_flow(pgw_c).await;
        upf.clear_seen();

        const MN: (u32, [u8; 4]) = (0x0000_A001, [10, 1, 2, 3]);
        const SN: (u32, [u8; 4]) = (0x0000_B002, [10, 7, 7, 7]);
        let resp = crate::an_initiated_modification(
            &reference,
            &split_indication((MN, &[5]), &[(SN, &[DEDICATED_EBI, 9])]),
        )
        .await;
        assert_eq!(resp.status, 200);
        let root: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(root["n2SmInfoType"], "PDU_RES_MOD_CFM");
        let confirm: g::PDUSessionResourceModifyConfirmTransfer =
            nextgcore_ngap_gen::decode_contained::<g::PDUSessionResourceModifyConfirmTransfer>(
                &resp.http.parts[0].data,
            )
            .unwrap();
        let confirmed: Vec<u8> = confirm
            .qos_flow_modify_confirm_list
            .0
            .iter()
            .map(|f| f.qos_flow_identifier.0)
            .collect();
        assert_eq!(confirmed, vec![5, DEDICATED_EBI]);
        let pairs = confirm
            .additional_ng_uuptnl_information
            .expect("the SN tunnel's pair")
            .0;
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].dl_ngu_up_tnl_information,
            crate::n2_transfer::gtp_tunnel(SN),
            "the pair names the additional DL tunnel"
        );
        assert_eq!(
            pairs[0].ul_ngu_up_tnl_information,
            crate::n2_transfer::gtp_tunnel((
                crate::pfcp_path::stand_in::N3_STAND_IN_TEID,
                upf.upf_ip
            )),
            "with the session's N3 uplink"
        );
        let failed = confirm.qos_flow_failed_to_modify_list.expect("QFI 9").0;
        assert_eq!(
            (failed.len(), failed[0].qos_flow_identifier.0),
            (1, 9),
            "a QFI the session has no flow for"
        );

        let ohc = |(teid, addr): (u32, [u8; 4])| {
            let mut v = vec![0x01, 0x00];
            v.extend_from_slice(&teid.to_be_bytes());
            v.extend_from_slice(&addr);
            v
        };
        let mods = upf.modification_bodies();
        assert_eq!(mods.len(), 1, "one N4 Session Modification");
        assert!(
            n4_has(&mods[0], 10, &ohc(MN)),
            "Update FAR 2 → the MN tunnel"
        );
        assert!(
            n4_has(&mods[0], 3, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x71])
                && n4_has(&mods[0], 3, &ohc(SN)),
            "Create FAR 0x71 → the SN tunnel"
        );
        assert!(
            n4_has(&mods[0], 15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x36])
                && n4_has(&mods[0], 1, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x71]),
            "the dedicated flow's DL PDR 0x36 re-created on FAR 0x71"
        );

        // Back to one tunnel.
        upf.clear_seen();
        let resp = crate::an_initiated_modification(
            &reference,
            &split_indication((MN, &[5, DEDICATED_EBI]), &[]),
        )
        .await;
        assert_eq!(resp.status, 200);
        let confirm: g::PDUSessionResourceModifyConfirmTransfer =
            nextgcore_ngap_gen::decode_contained::<g::PDUSessionResourceModifyConfirmTransfer>(
                &resp.http.parts[0].data,
            )
            .unwrap();
        assert!(confirm.additional_ng_uuptnl_information.is_none());
        let mods = upf.modification_bodies();
        assert!(
            n4_has(&mods[0], 16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x71]),
            "Remove FAR 0x71"
        );
        assert!(
            n4_has(&mods[0], 1, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 2])
                && !n4_has(&mods[0], 3, &[0x00, 0x6C]),
            "PDR 0x36 back on FAR 2, no tunnel FAR created"
        );
        s5.close();
    }

    /// The stand-in's modification bodies once `done` holds for them, at most 5 s.
    async fn wait_for_modifications(
        upf: &crate::pfcp_path::stand_in::StandInUpf,
        done: impl Fn(&[Vec<u8>]) -> bool,
    ) -> Vec<Vec<u8>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let mods = upf.modification_bodies();
            if done(&mods) || std::time::Instant::now() >= deadline {
                return mods;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The `smContextRef` of a PREPARING create's 201.
    fn created_reference(created: &SbiResponse) -> String {
        serde_json::from_str::<serde_json::Value>(created.http.content.as_deref().expect("body"))
            .unwrap()["smContextRef"]
            .as_str()
            .expect("smContextRef")
            .to_string()
    }

    /// A PREPARING create for the EPS PDN connection with indirect forwarding.
    async fn prepare_eps_to_5gs_with_forwarding(pgw_c: (u32, [u8; 4])) -> String {
        use base64::Engine as _;
        let body = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": base64::engine::general_purpose::STANDARD.encode(pdn_connection(pgw_c)),
            "indirectForwardingFlag": true,
        });
        let created = handle_create(&body).await;
        assert_eq!(created.status, 201);
        created_reference(&created)
    }

    /// #750: the AMF's PREPARED call times out while the UPF is slow, and it sends
    /// CANCELLED. The SMF finishes PREPARED (installing the forwarding tunnels), then
    /// runs CANCELLED against the session as PREPARED left it: the forwarding FAR is
    /// removed with the rest, and the SM context stays gone. Before, CANCELLED ran
    /// during PREPARED's UPF round trip with no forwarding to remove, and PREPARED
    /// then wrote back its stale copy: the cancelled context came back, and FAR 0x50
    /// with its PDRs and QERs leaked on the live EPS session.
    #[tokio::test]
    async fn a_cancel_during_a_slow_prepared_leaves_no_context_and_no_forwarding() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        let reference = prepare_eps_to_5gs_with_forwarding(pgw_c).await;
        upf.clear_seen();
        upf.delay_modifications(400);

        let transfer = ho_ack_transfer_with_forwarding();
        let (prepared, cancelled) = tokio::join!(handle_prepared(&reference, &transfer), async {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            handle_cancelled(&reference).await
        });
        upf.delay_modifications(0);
        let mods = upf.modification_bodies();
        let removed_far = mods
            .iter()
            .any(|m| n4_has(m, 16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50]));
        let ctx = smf_self();
        let ctx = ctx.read().unwrap();
        let sess = ctx.sess_find_by_teid(pgw_c.0).unwrap();
        let resurrected = sess.sm_context_ref.is_some() || sess.handover.prepared;
        let forwarding_left = !sess.handover.forwarding_ebis.is_empty();
        drop(ctx);
        s5.close();

        assert_eq!(cancelled.status, 200);
        assert_eq!(prepared.status, 200, "PREPARED ran first, under the lock");
        assert!(!resurrected, "the cancelled SM context stays gone");
        assert!(!forwarding_left);
        assert!(
            removed_far,
            "the forwarding FAR 0x50 PREPARED installed is removed: {} modification(s)",
            mods.len()
        );
    }

    /// #894 review B1: the AMF's SBI timeout resets the stream, and the server drops
    /// the PREPARED handler future mid-modification. The handler runs on regardless
    /// (detached), so the CANCELLED that follows finds the forwarding EBIs it recorded
    /// and removes FAR 0x50. Before, the dropped future released the lock to a
    /// CANCELLED with nothing to remove, and the rules leaked.
    #[tokio::test]
    async fn a_prepared_dropped_by_its_caller_still_leaves_nothing_behind() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        let reference = prepare_eps_to_5gs_with_forwarding(pgw_c).await;
        upf.clear_seen();
        upf.delay_modifications(400);

        let transfer = ho_ack_transfer_with_forwarding();
        // The caller gives up after 100 ms, as the AMF's SBI timeout does.
        let dropped = tokio::time::timeout(
            Duration::from_millis(100),
            handle_prepared(&reference, &transfer),
        )
        .await;
        let cancelled = handle_cancelled(&reference).await;
        upf.delay_modifications(0);
        let removed_far = wait_for_modifications(&upf, |m| {
            m.iter()
                .any(|b| n4_has(b, 16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50]))
        })
        .await
        .iter()
        .any(|b| n4_has(b, 16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50]));
        s5.close();

        assert!(dropped.is_err(), "the caller gave up on PREPARED");
        assert_eq!(cancelled.status, 200);
        assert!(removed_far, "Remove FAR 0x50 reached the UPF");
    }

    /// #894 review m4: the SM context goes away during PREPARED's UPF round trip by
    /// another path than CANCELLED (here its reference is simply dropped, as a Delete
    /// Session would). PREPARED answers 404 and removes the forwarding it installed.
    #[tokio::test]
    async fn a_context_gone_during_prepared_is_answered_404_and_its_forwarding_removed() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        let reference = prepare_eps_to_5gs_with_forwarding(pgw_c).await;
        upf.clear_seen();
        upf.delay_modifications(300);

        let transfer = ho_ack_transfer_with_forwarding();
        let (prepared, ()) = tokio::join!(handle_prepared(&reference, &transfer), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Ok(ctx) = smf_self().read() {
                let mut sess = ctx.sess_find_by_teid(pgw_c.0).unwrap();
                sess.sm_context_ref = None;
                ctx.sess_update(&sess);
            }
        });
        upf.delay_modifications(0);
        let mods = upf.modification_bodies();
        s5.close();

        assert_eq!(prepared.status, 404);
        assert!(
            mods.iter()
                .any(|b| n4_has(b, 16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50])),
            "Remove FAR 0x50: {} modification(s)",
            mods.len()
        );
    }

    /// #894 review m2: COMPLETED after the handover was CANCELLED is a 404, not a 200
    /// for a context that no longer exists.
    #[tokio::test]
    async fn completed_after_cancelled_is_context_not_found() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        let reference = prepare_eps_to_5gs_with_forwarding(pgw_c).await;
        assert_eq!(handle_cancelled(&reference).await.status, 200);
        let completed = handle_completed(&reference, None).await;
        s5.close();
        assert_eq!(completed.status, 404);
    }

    /// #751: the UPF answers the indirect-forwarding modification without the Created
    /// PDRs. Its FAR, PDRs and QERs may be installed all the same, and nothing records
    /// them for step 14 or CANCELLED, so the SMF removes them at once.
    #[tokio::test]
    async fn an_incomplete_forwarding_answer_removes_what_was_requested() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        let reference = prepare_eps_to_5gs_with_forwarding(pgw_c).await;
        upf.clear_seen();
        upf.omit_created_pdrs(true);

        let prepared = handle_prepared(&reference, &ho_ack_transfer_with_forwarding()).await;
        upf.omit_created_pdrs(false);
        let mods = upf.modification_bodies();
        let forwarding_ebis = smf_self()
            .read()
            .unwrap()
            .sess_find_by_teid(pgw_c.0)
            .unwrap()
            .handover
            .forwarding_ebis;
        s5.close();

        assert_eq!(
            prepared.status, 200,
            "the handover goes on without forwarding"
        );
        assert_eq!(mods.len(), 2, "the create, then its removal");
        assert!(n4_has(
            &mods[0],
            3,
            &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50]
        ));
        assert!(
            n4_has(&mods[1], 16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50]),
            "Remove FAR 0x50"
        );
        assert!(forwarding_ebis.is_empty());
    }

    /// #751, step 6: the UPF refuses the dedicated bearers' rules after it created the
    /// N3 uplink PDR. The SMF removes the N3 uplink PDR and, separately, the dedicated
    /// bearers' PDRs and QERs the failed request may have left.
    #[tokio::test]
    async fn a_failed_step_6_removes_the_dedicated_rules_too() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        seed_dedicated_gbr_bearer(pgw_c.0);
        upf.clear_seen();
        // The first modification (the N3 uplink) is accepted, the second (the
        // dedicated bearers) refused.
        upf.reject_modification(2);
        use base64::Engine as _;
        let body = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": base64::engine::general_purpose::STANDARD.encode(pdn_connection(pgw_c)),
        });
        let created = handle_create(&body).await;
        upf.reject_modification(0);
        let mods = upf.modification_bodies();
        s5.close();

        assert_eq!(created.status, 504);
        assert_eq!(
            mods.len(),
            4,
            "create N3, create dedicated, remove N3, remove dedicated"
        );
        assert!(
            n4_has(&mods[2], 15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x03]),
            "Remove PDR 3"
        );
        assert!(
            n4_has(&mods[3], 15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x16])
                && n4_has(&mods[3], 18, &[0x00, 0x6D, 0x00, 0x04, 0, 0, 0, 0x16]),
            "Remove the dedicated UL PDR 0x16 and QER 0x16"
        );
    }

    /// The INC/DEC order the recording NSACF saw for the test UE.
    fn nsac_ops(seen: &std::sync::Mutex<Vec<(String, String)>>) -> Vec<String> {
        let supi = format!("imsi-{IMSI}");
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| *s == supi)
            .map(|(op, _)| op.clone())
            .collect()
    }

    /// #1072 round 2 m8: an EPS→5GS move counts the PDU session in at the NSACF
    /// (TS 23.501 §5.15.11.5, no EPS counting here), and CANCELLED, which leaves the
    /// PDN connection on EPS, counts it out again.
    #[tokio::test]
    async fn an_eps_to_5gs_move_is_counted_in_and_a_cancel_counts_it_out() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        crate::context::smf_context_init(64, 256, 512);
        let zero = std::time::Duration::ZERO;
        let (nsacf, seen) = crate::tests::recording_nsacf(204, 204, zero, zero).await;
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        use base64::Engine as _;
        let body = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": base64::engine::general_purpose::STANDARD.encode(pdn_connection(pgw_c)),
        });
        let created = handle_create(&body).await;
        let after_create = nsac_ops(&seen);
        let reference = serde_json::from_str::<serde_json::Value>(
            created.http.content.as_deref().unwrap_or("{}"),
        )
        .unwrap_or_default()["smContextRef"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let cancelled = handle_cancelled(&reference).await.status;
        let after_cancel = nsac_ops(&seen);
        std::env::remove_var("NSACF_URI");
        nsacf.stop().await.ok();
        s5.close();

        assert_eq!(created.status, 201);
        assert_eq!(after_create, vec!["INC"], "counted in at the move");
        assert_eq!(cancelled, 200);
        assert_eq!(after_cancel, vec!["INC", "DEC"], "and out at the cancel");
    }

    /// #1072 round 2 m9: a PDU session the NSACF does not admit is not transferred
    /// (TS 23.501 §5.15.11.5): INSUFFICIENT_RESOURCES_SLICE (TS 29.502 Table
    /// 6.1.3.2.3.1-3), nothing installed at the UPF, and the PDN connection stays on
    /// EPS.
    #[tokio::test]
    async fn an_eps_to_5gs_move_the_nsacf_rejects_is_not_transferred() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        crate::context::smf_context_init(64, 256, 512);
        let zero = std::time::Duration::ZERO;
        let (nsacf, seen) = crate::tests::recording_nsacf(403, 204, zero, zero).await;
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        upf.clear_seen();
        use base64::Engine as _;
        let body = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": base64::engine::general_purpose::STANDARD.encode(pdn_connection(pgw_c)),
        });
        let created = handle_create(&body).await;
        let error = serde_json::from_str::<serde_json::Value>(
            created.http.content.as_deref().unwrap_or("{}"),
        )
        .unwrap_or_default();
        let content_type = created.http.get_header("content-type").cloned();
        let mods = upf.modification_bodies();
        let ops = nsac_ops(&seen);
        let stays_on_eps = {
            let ctx = smf_self();
            let ctx = ctx.read().unwrap();
            ctx.sess_find_by_teid(pgw_c.0)
                .is_some_and(|s| s.epc && s.sm_context_ref.is_none())
        };
        std::env::remove_var("NSACF_URI");
        nsacf.stop().await.ok();
        s5.close();

        assert_eq!(created.status, 500);
        // #1072 round 3 m11: an SmContextCreateError, the cause in "error".
        assert_eq!(
            error["error"]["cause"], "INSUFFICIENT_RESOURCES_SLICE",
            "{error}"
        );
        assert_eq!(content_type.as_deref(), Some("application/json"));
        assert!(
            mods.is_empty(),
            "nothing installed: {} modification(s)",
            mods.len()
        );
        assert_eq!(ops, vec!["INC"], "asked once, nothing to count out");
        assert!(stays_on_eps, "the PDN connection stays on EPS");
    }

    /// TS 29.502 §5.2.2.3.4.4: CANCELLED releases the N3 uplink step 6 created and forgets
    /// the SM context, leaving the PDN connection exactly as EPS was using it.
    #[tokio::test]
    async fn a_cancelled_eps_to_5gs_handover_releases_the_n3_uplink_and_the_sm_context() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);
        let (s5, pgw_c, _) = establish_pdn(Some(&pco_with_psi(5))).await;
        seed_dedicated_gbr_bearer(pgw_c.0);
        use base64::Engine as _;
        let body = serde_json::json!({
            "supi": format!("imsi-{IMSI}"),
            "hoState": "PREPARING",
            "ueEpsPdnConnection": base64::engine::general_purpose::STANDARD.encode(pdn_connection(pgw_c)),
            "indirectForwardingFlag": true,
        });
        let created = handle_create(&body).await;
        assert_eq!(created.status, 201);
        let reference_ = serde_json::from_str::<serde_json::Value>(
            created.http.content.as_deref().expect("body"),
        )
        .unwrap()["smContextRef"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            handle_prepared(&reference_, &ho_ack_transfer_with_forwarding())
                .await
                .status,
            200
        );
        let reference = serde_json::from_str::<serde_json::Value>(
            created.http.content.as_deref().expect("body"),
        )
        .unwrap()["smContextRef"]
            .as_str()
            .expect("smContextRef")
            .to_string();
        upf.clear_seen();

        let resp = handle_cancelled(&reference).await;
        assert_eq!(resp.status, 200);
        let mods = upf.modification_bodies();
        assert_eq!(mods.len(), 1);
        assert!(
            n4_has(&mods[0], 15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x03]),
            "Remove PDR 3, the N3 uplink"
        );
        // #583: and everything else the preparation installed.
        for (ie, needle) in [
            (15u16, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x16][..]), // the dedicated UL PDR
            (18, &[0x00, 0x6D, 0x00, 0x04, 0, 0, 0, 0x16][..]), // its QER
            (15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x55][..]),    // the forwarding PDRs
            (15, &[0x00, 0x38, 0x00, 0x02, 0x00, 0x56][..]),
            (16, &[0x00, 0x6C, 0x00, 0x04, 0, 0, 0, 0x50][..]), // the forwarding FAR
        ] {
            assert!(n4_has(&mods[0], ie, needle), "IE {ie} {needle:02x?}");
        }
        let ctx = smf_self();
        let ctx = ctx.read().unwrap();
        let sess = ctx.sess_find_by_teid(pgw_c.0).unwrap();
        assert!(sess.epc && sess.sm_context_ref.is_none() && sess.psi == 0);
        assert_eq!(
            sess.eps_psi,
            Some(5),
            "the UE's PSI survives for a later attempt"
        );
        assert!(ctx.pfcp_sessions.read().unwrap().get(&reference).is_none());
        assert!(ctx.cp_n4_seids.read().unwrap().get(&reference).is_none());
        drop(ctx);
        s5.close();
    }

    #[test]
    fn the_psi_is_read_from_the_pco_or_the_epco_and_only_when_valid() {
        assert_eq!(
            eps_iwk::pdu_session_id_from_pco(Some(&pco_with_psi(5)), None),
            Some(5)
        );
        // ePCO: two-octet container length.
        let epco = [0x80, 0x00, 0x1A, 0x00, 0x01, 0x07];
        assert_eq!(eps_iwk::pdu_session_id_from_pco(None, Some(&epco)), Some(7));
        // After another container (P-CSCF IPv4 request, empty).
        let pco = [0x80, 0x00, 0x0C, 0x00, 0x00, 0x1A, 0x01, 0x03];
        assert_eq!(eps_iwk::pdu_session_id_from_pco(Some(&pco), None), Some(3));
        // 0 and 16 are not allocatable PDU session identities (TS 24.007 §11.2.3.1b).
        assert_eq!(
            eps_iwk::pdu_session_id_from_pco(Some(&pco_with_psi(0)), None),
            None
        );
        assert_eq!(
            eps_iwk::pdu_session_id_from_pco(Some(&pco_with_psi(16)), None),
            None
        );
        // A length past the buffer is not read as contents.
        assert_eq!(
            eps_iwk::pdu_session_id_from_pco(Some(&[0x80, 0x00, 0x1A, 0x05, 0x05]), None),
            None
        );
    }

    /// The mapped-5GS PCO, octet by octet from TS 24.008 Table 10.5.154 and the TS 24.501
    /// value parts (§9.11.2.8, §9.11.4.14, §9.11.4.13, §9.11.4.12):
    ///
    /// ```text
    /// 80                         ext 1, configuration protocol 0
    /// 00 1B 04 01 99 F9 07       S-NSSAI: SST 1, then PLMN 999-70
    /// 00 1D 06 02 61 A8 01 C3 50 Session-AMBR: DL unit 4 kbps x 25000 (100 Mbps),
    ///                            UL unit 1 kbps x 50000 (50 Mbps)
    /// 00 1C 09 05 00 06 31 31 01 01 FF 05
    ///                            QoS rule 5, length 6: create | DQR | 1 filter (0x31);
    ///                            filter bidirectional id 1 (0x31), length 1, match-all;
    ///                            precedence 255; QFI 5
    /// 00 1F 06 05 20 41 01 01 09 QoS flow description QFI 5: create (0x20),
    ///                            E | 1 parameter (0x41), 5QI (id 1) length 1 = 9
    /// ```
    #[test]
    fn the_mapped_5gs_pco_golden_bytes() {
        let flow = context::SmfBearer {
            ebi: 5,
            qfi: 5,
            qos: context::Qos {
                index: 9,
                ..Default::default()
            },
            ..Default::default()
        };
        let pco = eps_iwk::build_mapped_5gs_pco(
            &context::SNssai { sst: 1, sd: None },
            [0x99, 0xf9, 0x07],
            100_000_000,
            50_000_000,
            &flow,
            false,
        );
        assert_eq!(
            pco,
            [
                0x80, 0x00, 0x1B, 0x04, 0x01, 0x99, 0xF9, 0x07, 0x00, 0x1D, 0x06, 0x02, 0x61, 0xA8,
                0x01, 0xC3, 0x50, 0x00, 0x1C, 0x09, 0x05, 0x00, 0x06, 0x31, 0x31, 0x01, 0x01, 0xFF,
                0x05, 0x00, 0x1F, 0x06, 0x05, 0x20, 0x41, 0x01, 0x01, 0x09,
            ]
        );
        // The ePCO form differs only in its two-octet container lengths.
        let epco = eps_iwk::build_mapped_5gs_pco(
            &context::SNssai { sst: 1, sd: None },
            [0x99, 0xf9, 0x07],
            100_000_000,
            50_000_000,
            &flow,
            true,
        );
        assert_eq!(
            &epco[..8],
            &[0x80, 0x00, 0x1B, 0x00, 0x04, 0x01, 0x99, 0xF9]
        );
        assert_eq!(
            eps_iwk::pco_container(
                &epco,
                true,
                eps_iwk::pco_container::NW_QOS_FLOW_DESCRIPTIONS
            ),
            Some(vec![0x05, 0x20, 0x41, 0x01, 0x01, 0x09])
        );
    }

    #[test]
    fn the_nf_profile_advertises_the_pgw_fqdn_only_when_configured() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
        std::env::remove_var("SMF_PGW_FQDN");
        assert!(crate::build_smf_nf_profile("i", "127.0.0.1", 1)
            .get("smfInfo")
            .is_none());
        std::env::set_var("SMF_PGW_FQDN", PGW_FQDN);
        let profile = crate::build_smf_nf_profile("i", "127.0.0.1", 1);
        std::env::remove_var("SMF_PGW_FQDN");
        assert_eq!(profile["smfInfo"]["pgwFqdn"], PGW_FQDN);
        assert_eq!(
            profile["smfInfo"]["sNssaiSmfInfoList"][0]["dnnSmfInfoList"][0]["dnn"], "*",
            "SmfInfo's required sNssaiSmfInfoList, with the wildcard DNN"
        );
    }

    /// #417: the EPS→5GS Setup Request Transfer, now encoded by the generated codec, is
    /// byte for byte what the hand-written codec built from the same session -- over GBR and
    /// non-GBR bearers, both PCI / PVI settings, with and without a Session-AMBR, and every
    /// forwarding indication. The oracle below is the pre-#417 builder, verbatim.
    #[test]
    fn the_handover_setup_request_transfer_is_the_hand_written_bytes() {
        use nextgcore_ngap::transfer::{
            AllocationAndRetentionPriority, GbrQosInformation, GtpTunnel, NonDynamic5qiDescriptor,
            PduSessionAggregateMaximumBitRate, PduSessionResourceSetupRequestTransfer,
            PduSessionType, PreEmptionCapability, PreEmptionVulnerability, QosCharacteristics,
            QosFlowLevelQosParameters, QosFlowSetupRequestItem, TransportLayerAddress,
            UpTransportLayerInformation,
        };
        fn oracle(
            sess: &SmfSess,
            bearers: &[context::SmfBearer],
            n3_ul: (u32, [u8; 4]),
            forwarding: eps_iwk::DataForwarding,
        ) -> Vec<u8> {
            let flows = bearers
                .iter()
                .map(|b| {
                    let gbr = (b.qos.gbr_uplink > 0 || b.qos.gbr_downlink > 0).then_some(
                        GbrQosInformation {
                            maximum_flow_bit_rate_dl: b.qos.mbr_downlink,
                            maximum_flow_bit_rate_ul: b.qos.mbr_uplink,
                            guaranteed_flow_bit_rate_dl: b.qos.gbr_downlink,
                            guaranteed_flow_bit_rate_ul: b.qos.gbr_uplink,
                            notification_control: false,
                            maximum_packet_loss_rate_dl: None,
                            maximum_packet_loss_rate_ul: None,
                        },
                    );
                    QosFlowSetupRequestItem {
                        qos_flow_identifier: b.ebi,
                        qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                            qos_characteristics: QosCharacteristics::NonDynamic5qi(
                                NonDynamic5qiDescriptor::new(u16::from(b.qos.index)),
                            ),
                            allocation_and_retention_priority: AllocationAndRetentionPriority {
                                priority_level_arp: b.qos.arp_priority_level.clamp(1, 15),
                                pre_emption_capability: if b.qos.arp_preempt_cap {
                                    PreEmptionCapability::ShallNotTriggerPreEmption
                                } else {
                                    PreEmptionCapability::MayTriggerPreEmption
                                },
                                pre_emption_vulnerability: if b.qos.arp_preempt_vuln {
                                    PreEmptionVulnerability::NotPreEmptable
                                } else {
                                    PreEmptionVulnerability::PreEmptable
                                },
                            },
                            gbr_qos_information: gbr,
                            reflective_qos_attribute: false,
                            additional_qos_flow_information: false,
                        },
                        e_rab_id: Some(b.ebi),
                    }
                })
                .collect();
            PduSessionResourceSetupRequestTransfer {
                pdu_session_aggregate_maximum_bit_rate: (sess.session_ambr.downlink > 0
                    || sess.session_ambr.uplink > 0)
                    .then_some(PduSessionAggregateMaximumBitRate {
                        dl: sess.session_ambr.downlink,
                        ul: sess.session_ambr.uplink,
                    }),
                ul_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
                    transport_layer_address: TransportLayerAddress::from_ipv4(n3_ul.1),
                    gtp_teid: n3_ul.0.to_be_bytes(),
                }),
                data_forwarding_not_possible: forwarding.not_possible(),
                pdu_session_type: PduSessionType::Ipv4,
                security_indication: None,
                network_instance: None,
                qos_flow_setup_request_list: flows,
                direct_forwarding_path_availability: forwarding.direct,
            }
            .encode()
            .unwrap()
        }

        let bearer =
            |ebi: u8, qci: u8, arp: u8, cap: bool, vuln: bool, gbr: u64| context::SmfBearer {
                ebi,
                qfi: ebi,
                qos: context::Qos {
                    index: qci,
                    arp_priority_level: arp,
                    arp_preempt_cap: cap,
                    arp_preempt_vuln: vuln,
                    gbr_downlink: gbr,
                    gbr_uplink: gbr / 2,
                    mbr_downlink: gbr * 2,
                    mbr_uplink: gbr,
                },
                ..Default::default()
            };
        let bearers = [
            bearer(5, 9, 8, true, true, 0),
            bearer(6, 1, 2, false, true, 64_000),
            bearer(7, 2, 0, true, false, 0),
            bearer(15, 4, 20, false, false, 4_000_000_000),
        ];
        for (dl, ul) in [(0, 0), (100_000_000, 50_000_000), (0, 1)] {
            let mut sess = SmfSess::new(1, 0, 1);
            sess.session_ambr.downlink = dl;
            sess.session_ambr.uplink = ul;
            for (indirect, direct) in [(false, false), (true, false), (false, true), (true, true)] {
                let forwarding = eps_iwk::DataForwarding { indirect, direct };
                for n in 1..=bearers.len() {
                    let n3 = (0x0102_0304, [10, 45, 0, n as u8]);
                    assert_eq!(
                        build_handover_setup_request_transfer(&sess, &bearers[..n], n3, forwarding)
                            .unwrap(),
                        oracle(&sess, &bearers[..n], n3, forwarding),
                        "AMBR ({dl}, {ul}), forwarding {forwarding:?}, {n} bearers"
                    );
                }
            }
        }
    }
}
