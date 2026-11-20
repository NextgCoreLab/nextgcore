//! An intermediate UPF on N9 (#2208, TS 23.502 §4.3.5.4 "Addition of an
//! intermediate UPF", TS 23.501 §5.6.4).
//!
//! When `smf.intermediate_upf` names an I-UPF (and, with `dnns`, the session's
//! DNN is one of them), a new PDU session gets two N4 sessions: the PSA's, as
//! before, and the I-UPF's, established right after it (TS 23.502 §4.3.5.4 steps
//! 3-4: the I-UPF gets the PSA's N9 tunnel, then the PSA the I-UPF's):
//!
//! - **I-UPF.** PDR 1: Source Interface Access, CHOOSE F-TEID (the N3 tunnel the
//!   NG-RAN is given), Outer Header Removal, FAR 1: FORW toward Core with the
//!   PSA's UL F-TEID as Outer Header Creation (N9). PDR 2: Source Interface Core,
//!   CHOOSE F-TEID (the N9 downlink tunnel), Outer Header Removal, FAR 2: toward
//!   Access, BUFF until the NG-RAN's tunnel is known. TS 29.244 §5.2.1 / §8.2.2
//!   NOTE 1: Access and Core are the UL and DL directions on N3 and N9 alike.
//! - **PSA.** Unchanged, except that its FAR 2 (Access side) forwards to the
//!   I-UPF's N9 tunnel instead of the NG-RAN's.
//!
//! The NG-RAN gets the I-UPF's N3 F-TEID. Every later Session Modification the
//! SMF sends for the session is split at one place ([`split_modification`],
//! called from `PfcpClient::session_request`), so no procedure has to know:
//! - an Update FAR 2 that activates the NG-RAN tunnel (activation, Xn and N2
//!   handover, path switch) goes to the I-UPF, and the PSA's FAR 2 is pointed
//!   (again) at the I-UPF's N9 tunnel;
//! - an Update FAR 2 that only changes the Apply Action (BUFF|NOCP at AN release,
//!   #1707's policy) goes to both: the PSA buffers and reports downlink data
//!   (TS 23.502 §4.2.6, the PSA buffering because this tree's I-UPF does not),
//!   and the I-UPF's NG-RAN tunnel stops;
//! - PFCPSMReq-Flags (SNDEM) go with the tunnel change to the I-UPF, which sends
//!   the End Markers toward the old NG-RAN;
//! - everything else (QERs, URRs, SRRs, TSC, the PSA's IE 271) stays at the PSA.
//!
//! A Session Deletion deletes the I-UPF's session first. The record of the I-UPF
//! leg is in the durable snapshot (`iupfLegs`), so a restarted SMF keeps splitting.
//!
//! Not done, stated: an I-UPF chosen per location (one configured I-UPF serves
//! every session it applies to), relocation or removal of the I-UPF mid-session
//! (TS 23.502 §4.3.5.5-6), a split PDU session (additional NG-RAN tunnels, #619)
//! on an I-UPF session (refused, `split_pdu_session_modification`), and the
//! I-UPF's own path failure / restart handling (#2225).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::n4_build::{self, pfcp_ie, FarParams, PdrParams, PfcpMessageBuilder};
use crate::pfcp_path::{self, PfcpClient};

/// `smf.intermediate_upf` in the SMF's YAML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IupfYaml {
    /// The I-UPF's PFCP endpoint: `addr`, `addr:port` or a host name.
    pub pfcp: String,
    /// The DNNs whose sessions get the I-UPF; empty for every session.
    #[serde(default)]
    pub dnns: Vec<String>,
}

/// The bit that marks the SMF-side SEID of an I-UPF leg: the PSA session's CP
/// SEID with bit 47 set. CP SEIDs are `FIVE_G_CP_SEID_BASE` (bit 48) plus a
/// derivation below bit 47, so the two never collide.
pub const LEG_SEID_BIT: u64 = 1 << 47;

/// The SMF-side SEID of the I-UPF leg of the PSA session `psa_seid`.
pub fn leg_seid(psa_seid: u64) -> u64 {
    psa_seid | LEG_SEID_BIT
}

/// Whether `seid` is an I-UPF leg's.
pub fn is_leg_seid(seid: u64) -> bool {
    seid & LEG_SEID_BIT != 0
}

/// The PSA session SEID of a leg SEID.
pub fn psa_seid_of(seid: u64) -> u64 {
    seid & !LEG_SEID_BIT
}

/// The I-UPF leg of one PDU session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IupfLeg {
    /// The SMF-side SEID of the I-UPF's N4 session ([`leg_seid`]).
    pub smf_seid: u64,
    /// The I-UPF's SEID.
    pub upf_seid: u64,
    /// The I-UPF's N3 F-TEID (PDR 1), the one the NG-RAN sends to.
    pub n3: (u32, [u8; 4]),
    /// The I-UPF's N9 F-TEID (PDR 2), the one the PSA's FAR 2 forwards to.
    pub n9: (u32, [u8; 4]),
    /// The PSA's UL F-TEID, the I-UPF's FAR 1 Outer Header Creation.
    pub psa_ul: (u32, [u8; 4]),
}

struct Config {
    client: Arc<PfcpClient>,
    dnns: Vec<String>,
}

static CONFIG: RwLock<Option<Config>> = RwLock::new(None);

/// Install the configured I-UPF (startup, and tests).
pub fn set(client: Option<(Arc<PfcpClient>, Vec<String>)>) {
    *CONFIG.write().unwrap_or_else(|e| e.into_inner()) =
        client.map(|(client, dnns)| Config { client, dnns });
}

/// The I-UPF's PFCP client, when one is configured.
pub fn client() -> Option<Arc<PfcpClient>> {
    CONFIG
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|c| c.client.clone())
}

/// Whether a session on `dnn` gets the I-UPF.
fn applies_to(dnn: &str) -> Option<Arc<PfcpClient>> {
    let g = CONFIG.read().unwrap_or_else(|e| e.into_inner());
    let c = g.as_ref()?;
    (c.dnns.is_empty() || c.dnns.iter().any(|d| d == dnn)).then(|| c.client.clone())
}

/// The I-UPF leg of the PSA session `psa_seid`, if it has one.
pub fn leg_of(psa_seid: u64) -> Option<IupfLeg> {
    let ctx = crate::context::smf_self();
    let ctx = ctx.read().ok()?;
    let legs = ctx.iupf_legs.read().ok()?;
    legs.get(&psa_seid).copied()
}

fn store_leg(psa_seid: u64, leg: Option<IupfLeg>) {
    if let Ok(ctx) = crate::context::smf_self().read() {
        if let Ok(mut legs) = ctx.iupf_legs.write() {
            match leg {
                Some(l) => {
                    legs.insert(psa_seid, l);
                }
                None => {
                    legs.remove(&psa_seid);
                }
            }
        }
    }
}

/// The I-UPF's Session Establishment Request body for the leg of `psa_seid`
/// (see the module docs), flow `qfi`, toward the PSA's UL F-TEID `psa_ul`.
pub fn establishment_body(
    client: &PfcpClient,
    psa_seid: u64,
    qfi: u8,
    psa_ul: (u32, [u8; 4]),
) -> Vec<u8> {
    let mut b = PfcpMessageBuilder::new();
    let mut node_id = bytes::BytesMut::new();
    client.node_id().encode(&mut node_id);
    b.add_node_id(&node_id);
    b.add_f_seid(leg_seid(psa_seid), Some(client.node_ip()), None);
    let pdr = |pdr_id: u16, source_interface: u8, far_id: u32| PdrParams {
        pdr_id,
        precedence: 100,
        source_interface,
        f_teid: Some((0, None, None)),
        outer_header_removal: Some(0),
        far_id: Some(far_id),
        qfi: Some(qfi),
        ..Default::default()
    };
    b.add_tlv(
        pfcp_ie::CREATE_PDR,
        &n4_build::build_create_pdr(&pdr(1, 0, 1)),
    );
    b.add_tlv(
        pfcp_ie::CREATE_FAR,
        &n4_build::build_create_far(&FarParams {
            far_id: 1,
            apply_action: n4_build::apply_action::FORW,
            destination_interface: Some(1),
            outer_header_creation: Some((0x0100, psa_ul.0, Some(psa_ul.1), None)),
            ..Default::default()
        }),
    );
    b.add_tlv(
        pfcp_ie::CREATE_PDR,
        &n4_build::build_create_pdr(&pdr(2, 1, 2)),
    );
    b.add_tlv(
        pfcp_ie::CREATE_FAR,
        &n4_build::build_create_far(&FarParams {
            far_id: 2,
            apply_action: n4_build::apply_action::BUFF,
            destination_interface: Some(0),
            ..Default::default()
        }),
    );
    b.build()
}

/// The UP F-SEID and the F-TEID of each Created PDR (by PDR ID) of a Session
/// Establishment Response body.
pub fn parse_establishment_response(body: &[u8]) -> (Option<u64>, HashMap<u16, (u32, [u8; 4])>) {
    let mut seid = None;
    let mut fteids = HashMap::new();
    for (t, v) in tlvs(body) {
        match t {
            57 if v.len() >= 9 => seid = Some(u64::from_be_bytes(v[1..9].try_into().unwrap())),
            8 => {
                let inner = tlvs(v);
                let id = inner
                    .iter()
                    .find(|(t, v)| *t == pfcp_ie::PDR_ID && v.len() >= 2)
                    .map(|(_, v)| u16::from_be_bytes([v[0], v[1]]));
                let f = inner
                    .iter()
                    .find(|(t, v)| *t == pfcp_ie::F_TEID && v.len() >= 9 && v[0] & 0x01 != 0)
                    .map(|(_, v)| {
                        (
                            u32::from_be_bytes(v[1..5].try_into().unwrap()),
                            [v[5], v[6], v[7], v[8]],
                        )
                    });
                if let (Some(id), Some(f)) = (id, f) {
                    fteids.insert(id, f);
                }
            }
            _ => {}
        }
    }
    (seid, fteids)
}

fn tlvs(d: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= d.len() {
        let t = u16::from_be_bytes([d[at], d[at + 1]]);
        let l = u16::from_be_bytes([d[at + 2], d[at + 3]]) as usize;
        let Some(v) = d.get(at + 4..at + 4 + l) else {
            break;
        };
        out.push((t, v));
        at += 4 + l;
    }
    out
}

/// Insert the I-UPF on the new session `psa_seid` (DNN `dnn`, flow `qfi`, PSA
/// UL F-TEID `psa_ul`) when one is configured for it (TS 23.502 §4.3.5.4).
/// Returns the leg, whose N3 F-TEID the NG-RAN is then given; `None` when no
/// I-UPF applies, or when it could not be inserted, in which case the session is
/// served by the PSA alone (logged).
pub async fn insert(psa_seid: u64, dnn: &str, qfi: u8, psa_ul: (u32, [u8; 4])) -> Option<IupfLeg> {
    let client = applies_to(dnn)?;
    if !client.is_associated().await {
        log::warn!(
            "I-UPF {} has no PFCP association: the session on DNN {dnn} is served by its PSA \
             alone",
            client.peer()
        );
        return None;
    }
    let body = establishment_body(&client, psa_seid, qfi, psa_ul);
    let resp = client
        .session_request(
            pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST,
            leg_seid(psa_seid),
            Some(0),
            &body,
        )
        .await;
    let resp = match resp {
        Ok((t, r)) if t == pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_RESPONSE => r,
        Ok((t, _)) => {
            log::warn!(
                "I-UPF answered Session Establishment with type {t}: served by the PSA alone"
            );
            return None;
        }
        Err(e) => {
            log::warn!("I-UPF Session Establishment failed ({e}): served by the PSA alone");
            return None;
        }
    };
    if pfcp_path::parse_cause(&resp) != Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) {
        log::warn!(
            "I-UPF rejected the Session Establishment (cause {:?}): served by the PSA alone",
            pfcp_path::parse_cause(&resp)
        );
        return None;
    }
    let (seid, fteids) = parse_establishment_response(&resp);
    let (Some(upf_seid), Some(n3), Some(n9)) = (seid, fteids.get(&1), fteids.get(&2)) else {
        log::warn!(
            "I-UPF Session Establishment Response lacks its F-SEID or the N3/N9 F-TEIDs: \
             served by the PSA alone"
        );
        return None;
    };
    let leg = IupfLeg {
        smf_seid: leg_seid(psa_seid),
        upf_seid,
        n3: *n3,
        n9: *n9,
        psa_ul,
    };
    store_leg(psa_seid, Some(leg));
    log::info!(
        "I-UPF {} inserted on N9 (TS 23.502 §4.3.5.4): N3 F-TEID 0x{:08x}@{:?}, N9 F-TEID \
         0x{:08x}@{:?}, toward the PSA's 0x{:08x}@{:?}",
        client.peer(),
        n3.0,
        n3.1,
        n9.0,
        n9.1,
        psa_ul.0,
        psa_ul.1
    );
    Some(leg)
}

/// The I-UPF leg went with its session.
pub fn forget(psa_seid: u64) {
    store_leg(psa_seid, None);
}

/// Split a Session Modification Request `body` for the PSA session with I-UPF
/// `leg` (see the module docs): the PSA's body, and the I-UPF's when it gets
/// anything.
pub fn split_modification(body: &[u8], leg: &IupfLeg) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut psa = Vec::new();
    let mut iupf = Vec::new();
    let mut flags = None;
    let push = |out: &mut Vec<u8>, t: u16, v: &[u8]| {
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
        out.extend_from_slice(v);
    };
    for (t, v) in tlvs(body) {
        if t == pfcp_ie::PFCPSMREQ_FLAGS {
            flags = Some(v.to_vec());
            continue;
        }
        if t != pfcp_ie::UPDATE_FAR {
            push(&mut psa, t, v);
            continue;
        }
        let inner = tlvs(v);
        let far_id = inner
            .iter()
            .find(|(t, v)| *t == pfcp_ie::FAR_ID && v.len() >= 4)
            .map(|(_, v)| u32::from_be_bytes(v[..4].try_into().unwrap()));
        if far_id != Some(crate::DL_FAR_ID) {
            push(&mut psa, t, v);
            continue;
        }
        let tunnel = inner.iter().any(|(t, v)| {
            *t == pfcp_ie::UPDATE_FORWARDING_PARAMETERS
                && tlvs(v)
                    .iter()
                    .any(|(t, _)| *t == pfcp_ie::OUTER_HEADER_CREATION)
        });
        push(&mut iupf, t, v);
        if tunnel {
            // The NG-RAN tunnel is the I-UPF's; the PSA forwards to the I-UPF.
            let far = n4_build::build_update_far_activate(
                crate::DL_FAR_ID,
                0,
                Some((0x0100, leg.n9.0, Some(leg.n9.1), None)),
                false,
            );
            push(&mut psa, pfcp_ie::UPDATE_FAR, &far);
        } else {
            push(&mut psa, t, v);
        }
    }
    if iupf.is_empty() {
        if let Some(f) = flags {
            push(&mut psa, pfcp_ie::PFCPSMREQ_FLAGS, &f);
        }
        return (psa, None);
    }
    if let Some(f) = flags {
        let mut with = Vec::new();
        push(&mut with, pfcp_ie::PFCPSMREQ_FLAGS, &f);
        with.extend_from_slice(&iupf);
        iupf = with;
    }
    (psa, Some(iupf))
}

#[cfg(test)]
#[path = "iupf_tests.rs"]
mod tests;
