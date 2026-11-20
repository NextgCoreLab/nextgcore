//! The apply of the PFCP server's session events to the data plane (moved out of
//! `main.rs` unchanged by #2208, so the library exposes it).

use crate::data_plane::{self, DataPlane};
use crate::pfcp_path::PfcpSessionEvent;
use std::net::SocketAddr;

/// #2208: record the Source Interface Type of each `(PDR ID, PDI)`: the PDI's
/// IE 160 when it has one, else none; `None` for a removed PDR.
fn note_source_types<'a>(
    session: &data_plane::DataPlaneSession,
    pdrs: impl Iterator<Item = (u16, Option<&'a crate::n4_build::ParsedPdi>)>,
) {
    let mut m = session.pdr_source_types.write().unwrap();
    for (id, pdi) in pdrs {
        match pdi.and_then(|p| p.source_interface_type) {
            Some(t) => {
                m.insert(id, t);
            }
            None => {
                m.remove(&id);
            }
        }
    }
}

/// Build a data-plane PDR from a wire-parsed Create/Update PDR.
///
/// Extracted by #306 so the establishment path and the modification path install
/// PDRs through ONE builder. They were about to be two, and two builders for one
/// rule is how the SDF-filter compilation (or the QFI, or the precedence) ends up
/// present on one path and missing on the other.
fn data_plane_pdr_from_parsed(p: &crate::n4_build::ParsedCreatePdr) -> data_plane::DataPlanePdr {
    // Compile SDF filter's flow description into an IpfwRule
    let sdf_rule = p.pdi.sdf_flow_description.as_ref().and_then(|desc| {
        match nextgcore_ipfw::compile_rule(desc) {
            Ok(rule) => Some(rule),
            Err(e) => {
                log::warn!("Failed to compile SDF filter '{desc}': {e}");
                None
            }
        }
    });
    data_plane::DataPlanePdr {
        pdr_id: p.pdr_id,
        precedence: p.precedence,
        source_interface: p.pdi.source_interface,
        far_id: p.far_id,
        qer_ids: p.qer_ids.clone().into(),
        urr_ids: p.urr_ids.clone(),
        outer_header_removal: p.outer_header_removal,
        sdf_rule,
        qfi: p.pdi.qfi,
    }
}

/// WARN for each PDR of `session` whose QERs carry more than one QFI (#1685
/// review): only the first QER's QFI marks its packets.
fn warn_several_qfis(session: &data_plane::DataPlaneSession) {
    for (pdr_id, qfis) in session.pdrs_with_several_qfis() {
        log::warn!(
            "SEID={:#x} PDR {pdr_id}: its QERs carry several QFIs {qfis:?}; packets are \
             marked with the first (TS 29.244 Table 7.5.2.2-1 lists QERs, one QoS flow \
             per PDR)",
            session.upf_seid
        );
    }
}

/// Merge an Update PDR into the PDR the data plane holds (#1673, TS 29.244
/// §5.6.3 and Table 7.5.4.2-1): an IE the update does not carry keeps its value,
/// a present one replaces it (a PDI whole, with its SDF filter and QFI), and a
/// null-length URR ID, QER ID or Outer Header Removal removes it (a null FAR ID
/// is refused at parse, #1672).
fn apply_update_pdr(pdr: &mut data_plane::DataPlanePdr, u: &crate::n4_build::ParsedUpdatePdr) {
    if let Some(precedence) = u.precedence {
        pdr.precedence = precedence;
    }
    if let Some(pdi) = &u.pdi {
        let parsed = crate::n4_build::ParsedCreatePdr {
            pdi: pdi.clone(),
            ..Default::default()
        };
        let fresh = data_plane_pdr_from_parsed(&parsed);
        pdr.source_interface = fresh.source_interface;
        pdr.sdf_rule = fresh.sdf_rule;
        pdr.qfi = fresh.qfi;
    }
    if let Some(ohr) = u.outer_header_removal {
        pdr.outer_header_removal = ohr;
    }
    if let Some(far_id) = u.far_id {
        pdr.far_id = Some(far_id);
    }
    if let Some(urr_ids) = &u.urr_ids {
        pdr.urr_ids = urr_ids.clone();
    }
    if let Some(qer_ids) = &u.qer_ids {
        pdr.qer_ids = qer_ids.clone().into();
    }
}

/// #1450: provision PDR `pdr_id` of `upf_seid` with the Transport Delay
/// Reporting IE value `tdr` (TS 29.244 Table 7.5.2.2-6), or remove it (`None`).
/// A malformed IE is logged and not acted on, as a malformed establishment SRR is
/// (#1389): the PDR itself is installed.
fn apply_transport_delay(data_plane: &DataPlane, upf_seid: u64, pdr_id: u16, tdr: Option<&[u8]>) {
    use nextgcore_pfcp::qos_monitoring::{TransportDelayReporting, TypedIe};
    let cfg = match tdr.map(TransportDelayReporting::decode_value) {
        None => None,
        Some(Ok(ie)) => crate::transport_delay::TransportDelayPdr::from_ie(&ie),
        Some(Err(e)) => {
            log::warn!(
                "SEID={upf_seid:#x} PDR {pdr_id}: malformed Transport Delay Reporting ({e}): \
                 not acted on"
            );
            None
        }
    };
    if tdr.is_none() && !data_plane.transport_delay_active() {
        return;
    }
    if let Some(c) = cfg {
        log::info!(
            "SEID={upf_seid:#x} PDR {pdr_id}: Transport Delay Reporting, preceding UL GTP-U \
             peer {} (DSCP {:?})",
            c.peer,
            c.dscp
        );
    }
    data_plane.with_transport_delay(|m| m.set_pdr(upf_seid, pdr_id, cfg));
}

/// A FAR as the data plane holds it, from a PFCP Create FAR or Update FAR (#918).
///
/// The Outer Header Creation endpoint is the IPv4 address when the OHC carries one,
/// else the IPv6 address. TS 29.244 §8.2.56 lets an OHC carry both and leaves the
/// choice to the UP function; IPv4 wins because the IPv4 N3 socket always exists,
/// while the IPv6 one exists only with `--gtpu-addr6`.
fn data_plane_far_from_parsed(f: &crate::n4_build::ParsedCreateFar) -> data_plane::DataPlaneFar {
    let ohc = f
        .forwarding_parameters
        .as_ref()
        .and_then(|fp| fp.outer_header_creation.as_ref());
    data_plane::DataPlaneFar {
        far_id: f.far_id,
        apply_action: f.apply_action,
        destination_interface: f
            .forwarding_parameters
            .as_ref()
            .map(|fp| fp.destination_interface)
            .unwrap_or(data_plane::SRC_INTF_CORE),
        ohc_teid: ohc.map(|ohc| ohc.teid),
        ohc_addr: ohc.and_then(|ohc| {
            ohc.ipv4
                .map(std::net::IpAddr::V4)
                .or(ohc.ipv6.map(std::net::IpAddr::V6))
        }),
        bar_id: f.bar_id,
    }
}

/// Handle PFCP session events (connect PFCP to data plane)
pub async fn handle_pfcp_session_event(data_plane: &DataPlane, event: PfcpSessionEvent) {
    use data_plane::{
        DataPlaneBar, DataPlanePdr, DataPlaneQer, DataPlaneUrr, FAR_ACTION_FORW, GTPU_PORT,
    };
    use std::net::IpAddr;
    use std::sync::Arc;

    match event {
        PfcpSessionEvent::SessionEstablished {
            upf_seid,
            smf_seid,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
            pdrs,
            fars,
            qers,
            urrs,
            bars,
        } => {
            log::info!(
                "PFCP Session Established: UPF_SEID={upf_seid:#x}, SMF_SEID={smf_seid:#x}, UE={ue_ipv4:?}, UL_TEID={ul_teid:#x}, DL_TEID={dl_teid:#x}"
            );

            // #1450: an I-UPF's session need not name the UE's address (TS 29.244
            // Table 7.5.2.2-2: the UE IP Address is conditional in the PDI); it is
            // one that forwards over a GTP-U tunnel toward the PSA.
            let iupf = fars.iter().any(|f| {
                f.forwarding_parameters.as_ref().is_some_and(|fp| {
                    fp.destination_interface == data_plane::SRC_INTF_CORE
                        && fp.outer_header_creation.is_some()
                })
            });
            if ue_ipv4.is_some() || iupf {
                let gnb_socket = if let Some(addr) = gnb_addr {
                    SocketAddr::new(IpAddr::V4(addr), GTPU_PORT)
                } else {
                    // #1345: no N3 endpoint until the Session Modification brings
                    // one; DL traffic before then is buffered or counted as
                    // `no_dl_endpoint`, not sent to the loopback.
                    log::info!(
                        "No gNB address at establishment: DL endpoint pending the \
                         Session Modification"
                    );
                    data_plane::NO_DL_ENDPOINT
                };

                // Extract QFI from QERs
                let qfi = qers.iter().find_map(|q| q.qfi);

                // #1348: every rule the Establishment Request created is built first and
                // the session is published once, with them (TS 29.244 §5.2.1, §7.5.2).
                // It used to be published with invented match-all FORW rules that the
                // SMF's were then written over one lock at a time, so a packet in
                // between was forwarded, unpoliced and uncharged, even when the SMF's
                // FAR said BUFF or DROP. No PDR in the request matches nothing.
                let mut dp_pdrs: Vec<DataPlanePdr> =
                    pdrs.iter().map(data_plane_pdr_from_parsed).collect();
                dp_pdrs.sort_by_key(|p| p.precedence);
                let dp_fars: std::collections::HashMap<u32, data_plane::DataPlaneFar> = fars
                    .iter()
                    .map(|f| (f.far_id, data_plane_far_from_parsed(f)))
                    .collect();
                // #619 review: the FARs with a tunnel of their own, by the PFCP layer's
                // rule for an establishment.
                let own_tunnel_fars = crate::pfcp_path::own_tunnel_fars_established(
                    &pdrs,
                    &fars,
                    (dl_teid, gnb_addr),
                );
                let mut dp_bars = std::collections::HashMap::new();
                for b in &bars {
                    dp_bars.insert(
                        b.bar_id,
                        DataPlaneBar {
                            bar_id: b.bar_id,
                            suggested_buffering_packets_count: b.suggested_buffering_packets_count,
                            ddn_delay: b.ddn_delay,
                        },
                    );
                }
                let mut dp_qers = std::collections::HashMap::new();
                for q in &qers {
                    let mut qer = DataPlaneQer::new(q.qer_id);
                    // Reflective QoS / paging policy the SMF asked for.
                    // Parsed since #81; previously decoded nowhere, so a
                    // QER requesting them had no effect on the wire.
                    qer.rqi = q.rqi;
                    qer.ppi = q.ppi;
                    qer.ul_gate_open = q.ul_gate == 0;
                    qer.dl_gate_open = q.dl_gate == 0;
                    qer.set_mbr(q.ul_mbr, q.dl_mbr);
                    qer.set_gbr(q.ul_gbr, q.dl_gbr);
                    if let Some(qfi_val) = q.qfi {
                        qer.set_qfi(qfi_val);
                    }
                    if qer.is_xr {
                        log::info!(
                            "Installed XR QER {} (5QI={:?}, DSCP={}, GBR UL/DL={}/{} kbps) for SEID={upf_seid:#x}",
                            qer.qer_id, qer.qfi, qer.dscp, qer.ul_gbr, qer.dl_gbr
                        );
                    }
                    dp_qers.insert(q.qer_id, qer);
                }
                let mut dp_urrs = std::collections::HashMap::new();
                for u in &urrs {
                    let urr = DataPlaneUrr::new(u.urr_id);
                    urr.set_reporting(
                        u.volume_threshold_total,
                        u.volume_threshold_ul,
                        u.volume_threshold_dl,
                        u.time_threshold_secs,
                        // #306: parsed from the wire since the Measurement
                        // Period IE is; before that the PERIO trigger flag
                        // arrived with no cadence behind it.
                        u.measurement_period_secs,
                    );
                    // #80: the quota half. Propagated since Volume Quota (IE
                    // 73) and Time Quota (IE 74) are now parsed; before that a
                    // conformant SMF's quota decoded into nothing and the
                    // subscriber was never gated.
                    urr.set_quotas(
                        u.volume_quota_total,
                        u.volume_quota_ul,
                        u.volume_quota_dl,
                        u.time_quota_secs,
                    );
                    // #820: how TIME is measured (§5.2.2.2).
                    // #818: a URR measuring time reports a Duration Measurement.
                    urr.set_measure_duration(u.measure_duration);
                    urr.set_time_metering(
                        u.inactivity_detection_secs,
                        u.immediate_start_time_metering,
                    );
                    dp_urrs.insert(u.urr_id, Arc::new(urr));
                }
                let session = data_plane.add_established_session(
                    upf_seid,
                    smf_seid,
                    ue_ipv4,
                    ul_teid,
                    dl_teid,
                    gnb_socket,
                    qfi,
                    data_plane::EstablishedRules {
                        pdrs: dp_pdrs,
                        fars: dp_fars,
                        own_tunnel_fars,
                        qers: dp_qers,
                        urrs: dp_urrs,
                        bars: dp_bars,
                    },
                );
                // #2208: each PDR's Source Interface Type (IE 160), when its PDI has one.
                note_source_types(&session, pdrs.iter().map(|p| (p.pdr_id, Some(&p.pdi))));
                // #1450: an I-UPF's downlink PDR detects on its N9 F-TEID (the PFCP
                // layer wrote the chosen TEID into its PDI).
                {
                    let mut tunnels = session.pdr_teids.write().unwrap();
                    for p in pdrs
                        .iter()
                        .filter(|p| p.pdi.source_interface == data_plane::SRC_INTF_CORE)
                    {
                        if let Some(f) =
                            p.pdi.local_f_teid.as_ref().filter(|f| !f.ch && f.teid != 0)
                        {
                            tunnels.insert(p.pdr_id, f.teid);
                            data_plane.sessions.bind_ul_teid(f.teid, upf_seid);
                        }
                    }
                }
                for p in &pdrs {
                    apply_transport_delay(
                        data_plane,
                        upf_seid,
                        p.pdr_id,
                        p.transport_delay_reporting.as_deref(),
                    );
                }
                if pdrs.is_empty() {
                    log::warn!(
                        "PFCP Session Establishment SEID={upf_seid:#x} created no PDR: the \
                         session matches no packet"
                    );
                }
                if let Some(session) = data_plane.sessions.find_by_seid(upf_seid) {
                    warn_several_qfis(&session);
                }
            } else {
                log::warn!("Session established without UE IP address");
            }
        }

        PfcpSessionEvent::SessionModified {
            upf_seid,
            dl_teid,
            gnb_addr,
            removed_pdr_ids,
            removed_far_ids,
            removed_qer_ids,
            removed_urr_ids,
            created_pdrs,
            created_fars,
            created_qers,
            created_urrs,
            updated_pdrs,
            updated_fars,
            updated_qers,
            updated_urrs,
            updated_bars,
            send_end_marker,
            drop_buffered,
            old_dl_tunnel,
        } => {
            log::info!("PFCP Session Modified: UPF_SEID={upf_seid:#x}");

            let gnb_socket = gnb_addr.map(|addr| SocketAddr::new(IpAddr::V4(addr), GTPU_PORT));

            // SNDEM (TS 29.244 8.2.50): send End Marker packets on the OLD
            // DL tunnel before switching to the new endpoint
            if send_end_marker {
                if let Some((old_teid, old_ip)) = old_dl_tunnel {
                    let old_addr = SocketAddr::new(IpAddr::V4(old_ip), GTPU_PORT);
                    data_plane.send_end_marker(old_teid, old_addr).await;
                } else {
                    log::warn!("SNDEM set but no previous DL tunnel known for {upf_seid:#x}");
                }
            }

            // Update basic session info
            if dl_teid.is_some() || gnb_socket.is_some() {
                data_plane.update_session_from_pfcp(upf_seid, dl_teid, gnb_socket);
            }

            // Update FAR rules in the data plane session
            let mut any_far_forwards = false;
            if let Some(session) = data_plane.sessions.find_by_seid(upf_seid) {
                // Removals first, in TS 29.244 §7.5.4's order, so a modification that
                // removes and re-creates one rule id ends holding the NEW rule
                // (#306). Every one of these was parsed nowhere before, so the UPF
                // answered `RequestAccepted` and kept detecting, policing and
                // measuring on rules the SMF believed were gone.
                if !removed_pdr_ids.is_empty() {
                    let mut dp_pdrs = session.pdrs.write().unwrap();
                    let before = dp_pdrs.len();
                    dp_pdrs.retain(|p| !removed_pdr_ids.contains(&p.pdr_id));
                    log::info!(
                        "Removed {} PDRs for SEID={upf_seid:#x}",
                        before - dp_pdrs.len()
                    );
                }
                if !removed_far_ids.is_empty() {
                    let mut dp_fars = session.fars.write().unwrap();
                    for id in &removed_far_ids {
                        dp_fars.remove(id);
                    }
                }
                if !removed_qer_ids.is_empty() {
                    let mut dp_qers = session.qers.write().unwrap();
                    for id in &removed_qer_ids {
                        dp_qers.remove(id);
                    }
                    log::info!(
                        "Removed {} QERs for SEID={upf_seid:#x}: policing no longer applied",
                        removed_qer_ids.len()
                    );
                }
                if !removed_urr_ids.is_empty() {
                    // The residual volume has already been reported in the Session
                    // Modification Response (TERMR), so dropping the rule here loses
                    // no measurement. Dropping the `Arc` is what stops the counters:
                    // `urr_record`'s only route to them is this map.
                    let mut dp_urrs = session.urrs.write().unwrap();
                    for id in &removed_urr_ids {
                        dp_urrs.remove(id);
                    }
                    log::info!(
                        "Removed {} URRs for SEID={upf_seid:#x}: measurement stopped",
                        removed_urr_ids.len()
                    );
                }

                // Creates: rules added to a session that is already running.
                // Provisioning charging mid-session is the normal way it is added.
                // #2208: the Source Interface Types follow the PDRs and their PDIs.
                note_source_types(
                    &session,
                    removed_pdr_ids
                        .iter()
                        .map(|id| (*id, None))
                        .chain(created_pdrs.iter().map(|p| (p.pdr_id, Some(&p.pdi))))
                        .chain(
                            updated_pdrs
                                .iter()
                                .filter_map(|u| u.pdi.as_ref().map(|pdi| (u.pdr_id, Some(pdi)))),
                        ),
                );
                if !removed_pdr_ids.is_empty() {
                    let mut tunnels = session.pdr_teids.write().unwrap();
                    for id in &removed_pdr_ids {
                        // #2197 review M1: a removed PDR's own F-TEID stops routing
                        // to the session once no PDR of it detects on that TEID
                        // (TS 29.244 §5.5.3), so a stale N9 TEID is no longer
                        // matched (a G-PDU on it is an unknown TEID, §7.3.1).
                        if let Some(teid) = tunnels.remove(id) {
                            if teid != session.ul_teid && !tunnels.values().any(|t| *t == teid) {
                                data_plane.sessions.unbind_ul_teid(teid, upf_seid);
                            }
                        }
                        apply_transport_delay(data_plane, upf_seid, *id, None);
                    }
                }
                // #1450: a Create PDR's Transport Delay Reporting, or an Update PDR's
                // (activated, or deactivated by a null IE). The PFCP layer passes it
                // on only with GPQM.
                for p in &created_pdrs {
                    apply_transport_delay(
                        data_plane,
                        upf_seid,
                        p.pdr_id,
                        p.transport_delay_reporting.as_deref(),
                    );
                }
                for u in &updated_pdrs {
                    if let Some(tdr) = &u.transport_delay_reporting {
                        apply_transport_delay(data_plane, upf_seid, u.pdr_id, tdr.as_deref());
                    }
                }
                if !created_pdrs.is_empty() {
                    // #583: a PDR created on its own F-TEID (chosen by the PFCP handler, or
                    // named by the SMF) detects on that tunnel, and the tunnel routes to
                    // this session.
                    {
                        let mut tunnels = session.pdr_teids.write().unwrap();
                        for p in &created_pdrs {
                            match p.pdi.local_f_teid.as_ref().filter(|f| !f.ch && f.teid != 0) {
                                Some(f) => {
                                    tunnels.insert(p.pdr_id, f.teid);
                                    data_plane.sessions.bind_ul_teid(f.teid, upf_seid);
                                }
                                None => {
                                    tunnels.remove(&p.pdr_id);
                                }
                            }
                        }
                    }
                    let mut dp_pdrs = session.pdrs.write().unwrap();
                    for p in &created_pdrs {
                        dp_pdrs.retain(|e| e.pdr_id != p.pdr_id);
                        dp_pdrs.push(data_plane_pdr_from_parsed(p));
                    }
                    // The fast path takes the first match, so precedence order is
                    // load-bearing rather than cosmetic (lower value wins).
                    dp_pdrs.sort_by_key(|p| p.precedence);
                }
                if !created_urrs.is_empty() {
                    let mut dp_urrs = session.urrs.write().unwrap();
                    for u in &created_urrs {
                        let urr = DataPlaneUrr::new(u.urr_id);
                        urr.set_reporting(
                            u.volume_threshold_total,
                            u.volume_threshold_ul,
                            u.volume_threshold_dl,
                            u.time_threshold_secs,
                            u.measurement_period_secs,
                        );
                        urr.set_quotas(
                            u.volume_quota_total,
                            u.volume_quota_ul,
                            u.volume_quota_dl,
                            u.time_quota_secs,
                        );
                        // #820: how TIME is measured (§5.2.2.2).
                        // #818: a URR measuring time reports a Duration Measurement.
                        urr.set_measure_duration(u.measure_duration);
                        urr.set_time_metering(
                            u.inactivity_detection_secs,
                            u.immediate_start_time_metering,
                        );
                        dp_urrs.insert(u.urr_id, Arc::new(urr));
                    }
                    log::info!(
                        "Created {} URRs for SEID={upf_seid:#x}: measurement provisioned",
                        created_urrs.len()
                    );
                }
                if !updated_urrs.is_empty() {
                    // Re-threshold IN PLACE. Rebuilding the rule would zero the
                    // volume measured so far, which the CP function is accounting on
                    // — a wrong bill rather than a lost setting.
                    let dp_urrs = session.urrs.read().unwrap();
                    for u in &updated_urrs {
                        match dp_urrs.get(&u.urr_id) {
                            Some(urr) => {
                                // #842 review (TS 29.244 §7.5.4): only the IEs the Update
                                // URR CARRIES change; an absent one is unchanged. Applying
                                // it through the Create setters turned every absent IE
                                // into "unprovisioned".
                                urr.update_reporting(
                                    u.volume_threshold_total,
                                    u.volume_threshold_ul,
                                    u.volume_threshold_dl,
                                    u.time_threshold_secs,
                                    u.measurement_period_secs,
                                );
                                // #80: an Update URR carrying a quota is how a CP
                                // function TOPS A SUBSCRIBER UP -- `set_quotas` clears
                                // the exhaustion latch, so a gated session resumes
                                // forwarding. That is what makes a quota a quota rather
                                // than a teardown, and it is the reason the latch lives
                                // where a re-provision can reach it.
                                // #953 review: a Measurement Method in the Update URR changes DURAT.
                                if u.measurement_method_present {
                                    urr.set_measure_duration(u.measure_duration);
                                }
                                urr.update_time_metering(
                                    u.inactivity_detection_secs,
                                    u.immediate_start_time_metering,
                                );
                                urr.update_quotas(
                                    u.volume_quota_total,
                                    u.volume_quota_ul,
                                    u.volume_quota_dl,
                                    u.time_quota_secs,
                                );
                            }
                            // Unreachable in practice: the handler refuses an Update
                            // for a rule the session does not hold, so this arm means
                            // the two stores have diverged. Logged rather than
                            // silently created, because inventing the rule here would
                            // hide that divergence.
                            None => log::warn!(
                                "Update URR {} applied to no rule on SEID {upf_seid:#x}: \
                                 PFCP and data-plane rule sets have diverged",
                                u.urr_id
                            ),
                        }
                    }
                }
                // #1673: an Update PDR changes only what it carries (TS 29.244
                // §5.6.3). It used to replace the stored PDR with one built from
                // the update alone, so a precedence-only update dropped the PDR's
                // FAR, URRs, QER and PDI.
                if !updated_pdrs.is_empty() {
                    let mut dp_pdrs = session.pdrs.write().unwrap();
                    for u in &updated_pdrs {
                        match dp_pdrs.iter_mut().find(|e| e.pdr_id == u.pdr_id) {
                            Some(stored) => apply_update_pdr(stored, u),
                            // The PFCP layer already answered this one as a rule
                            // failure (TS 29.244 §7.5.5); nothing to merge into.
                            None => log::warn!(
                                "Update PDR {}: the data plane holds no such PDR",
                                u.pdr_id
                            ),
                        }
                    }
                    dp_pdrs.sort_by_key(|p| p.precedence);
                    // #1682: a replaced PDI moves the PDR's tunnel and the session's
                    // UE IP address with it (Table 7.5.4.2-1), still under the PDR
                    // lock, so no packet matches the new PDI on the old keys. The
                    // PFCP layer has already chosen any CHOOSE F-TEID and refused a
                    // key another session holds.
                    for u in &updated_pdrs {
                        let Some(pdi) = u.pdi.as_ref() else {
                            continue;
                        };
                        if !dp_pdrs.iter().any(|e| e.pdr_id == u.pdr_id) {
                            continue;
                        }
                        let teid = pdi
                            .local_f_teid
                            .as_ref()
                            .filter(|f| !f.ch && f.teid != 0)
                            .map(|f| f.teid);
                        data_plane
                            .sessions
                            .move_pdr_teid(&session, &dp_pdrs, u.pdr_id, teid);
                        if let Some(ip) = crate::pfcp_path::update_pdr_ue_ipv4(pdi) {
                            data_plane.sessions.rebind_ue_ip(&session, ip);
                        }
                    }
                }

                // Create FAR and Update FAR install the same shape, so they run
                // through one loop.
                let far_writes: Vec<&crate::n4_build::ParsedCreateFar> =
                    created_fars.iter().chain(updated_fars.iter()).collect();
                // #1631: the FAR this modification set to BUFF|NOCP, for the backlog
                // report below.
                let mut rearmed_far: Option<u32> = None;
                if !far_writes.is_empty() {
                    let mut dp_fars = session.fars.write().unwrap();
                    for f in &far_writes {
                        if f.apply_action & FAR_ACTION_FORW != 0 {
                            any_far_forwards = true;
                        }
                        // #1629 review: BUFF with NOCP instructs the UP function to
                        // notify the first downlink packet (TS 29.244 §5.2.3.1),
                        // which starts a new buffering episode.
                        let buff_nocp = data_plane::FAR_ACTION_BUFF | data_plane::FAR_ACTION_NOCP;
                        if f.apply_action & buff_nocp == buff_nocp {
                            session.rearm_dl_notification();
                            rearmed_far.get_or_insert(f.far_id);
                        }
                        dp_fars.insert(f.far_id, data_plane_far_from_parsed(f));
                    }
                    log::info!("Installed {} FARs for SEID={upf_seid:#x}", far_writes.len());
                }
                // #619: which FARs have a tunnel of their own, by the PFCP layer's rule,
                // so a later move of the session's tunnel leaves them where they point.
                if !removed_far_ids.is_empty() || !created_fars.is_empty() {
                    let own =
                        crate::pfcp_path::own_tunnel_fars_created(&created_pdrs, &created_fars);
                    let mut set = session.own_tunnel_fars.write().unwrap();
                    for id in removed_far_ids
                        .iter()
                        .chain(created_fars.iter().map(|f| &f.far_id))
                    {
                        set.remove(id);
                    }
                    set.extend(own);
                }

                if !created_qers.is_empty() || !updated_qers.is_empty() {
                    let mut dp_qers = session.qers.write().unwrap();
                    for q in &created_qers {
                        let mut qer = DataPlaneQer::new(q.qer_id);
                        // Reflective QoS / paging policy the SMF asked for.
                        // Parsed since #81; previously decoded nowhere, so a
                        // QER requesting them had no effect on the wire.
                        qer.rqi = q.rqi;
                        qer.ppi = q.ppi;
                        qer.ul_gate_open = q.ul_gate == 0;
                        qer.dl_gate_open = q.dl_gate == 0;
                        qer.set_mbr(q.ul_mbr, q.dl_mbr);
                        qer.set_gbr(q.ul_gbr, q.dl_gbr);
                        if let Some(qfi_val) = q.qfi {
                            qer.set_qfi(qfi_val);
                        }
                        dp_qers.insert(q.qer_id, qer);
                    }
                    // #1478, TS 29.244 Table 7.5.4.5-1: an Update QER changes only the
                    // IEs it carries. It used to rebuild the QER from them, so one
                    // without MBR lifted the rate cap and one without Gate Status
                    // opened closed gates.
                    for u in &updated_qers {
                        dp_qers
                            .entry(u.qer_id)
                            .or_insert_with(|| DataPlaneQer::new(u.qer_id))
                            .apply_update(u);
                    }
                    for qer in created_qers
                        .iter()
                        .map(|q| q.qer_id)
                        .chain(updated_qers.iter().map(|u| u.qer_id))
                        .filter_map(|id| dp_qers.get(&id))
                        .filter(|q| q.is_xr)
                    {
                        log::info!(
                            "Updated XR QER {} (5QI={:?}, DSCP={}, GBR UL/DL={}/{} kbps) for SEID={upf_seid:#x}",
                            qer.qer_id, qer.qfi, qer.dscp, qer.ul_gbr, qer.dl_gbr
                        );
                    }
                    log::info!(
                        "Installed {} QERs for SEID={upf_seid:#x}",
                        created_qers.len() + updated_qers.len()
                    );
                }

                if !updated_bars.is_empty() {
                    let mut dp_bars = session.bars.write().unwrap();
                    for b in &updated_bars {
                        dp_bars.insert(
                            b.bar_id,
                            DataPlaneBar {
                                bar_id: b.bar_id,
                                suggested_buffering_packets_count: b
                                    .suggested_buffering_packets_count,
                                ddn_delay: b.ddn_delay,
                            },
                        );
                    }
                }

                // DROBU: discard buffered DL packets without forwarding
                if drop_buffered {
                    let dropped = session.drain_dl_buffer().len();
                    if dropped > 0 {
                        log::info!(
                            "DROBU: discarded {dropped} buffered DL packets for SEID={upf_seid:#x}"
                        );
                    }
                }

                // #1631 (#1635 review m3): the instruction to buffer and notify makes
                // the packets already buffered the episode's first (TS 29.244
                // §5.2.3.1), so they are reported now, once, rather than when a later
                // packet arrives, which may be never. After DROBU, so a discarded
                // buffer is not reported.
                if let Some(far_id) = rearmed_far {
                    if session.claim_dl_backlog_report() {
                        data_plane.report_dl_backlog(&session, far_id);
                    }
                }
            }

            if let Some(session) = data_plane.sessions.find_by_seid(upf_seid) {
                warn_several_qfis(&session);
            }

            // FAR switched to FORW → flush packets buffered under BUFF.
            // flush_buffered_dl looks the session up by SEID; since #822 it is the
            // same session object update_session_from_pfcp moved in place.
            if any_far_forwards && !drop_buffered {
                data_plane.flush_buffered_dl(upf_seid).await;
            }
        }

        PfcpSessionEvent::SessionDeleted {
            upf_seid,
            ue_ipv4: _,
        } => {
            log::info!("PFCP Session Deleted: UPF_SEID={upf_seid:#x}");
            data_plane.remove_session_from_pfcp(upf_seid);
        }

        PfcpSessionEvent::PeerFailure { peer } => {
            // CP peer restarted or released the association: every session
            // it controlled is stale (TS 23.527 4.2) — remove them all
            let seids: Vec<u64> = data_plane
                .get_all_session_stats()
                .iter()
                .map(|(seid, ..)| *seid)
                .collect();
            log::warn!(
                "PFCP peer {peer} failed — removing {} stale sessions",
                seids.len()
            );
            for seid in seids {
                data_plane.remove_session_from_pfcp(seid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pfcp_path::PfcpSessionEvent;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn far_with_ohc(
        far_id: u32,
        v4: Option<Ipv4Addr>,
        v6: Option<std::net::Ipv6Addr>,
    ) -> crate::n4_build::ParsedCreateFar {
        crate::n4_build::ParsedCreateFar {
            far_id,
            apply_action: data_plane::FAR_ACTION_FORW,
            forwarding_parameters: Some(crate::n4_build::ParsedForwardingParameters {
                destination_interface: 0, // Access
                network_instance: None,
                outer_header_creation: Some(crate::n4_build::ParsedOuterHeaderCreation {
                    description: if v6.is_some() { 0x0200 } else { 0x0100 },
                    teid: 0x4000 + far_id,
                    ipv4: v4,
                    ipv6: v6,
                    port: None,
                }),
            }),
            bar_id: None,
        }
    }

    /// A Create PDR on `source` (0 Access, 1 Core) through `far_id`.
    fn pdr_through(pdr_id: u16, source: u8, far_id: u32) -> crate::n4_build::ParsedCreatePdr {
        crate::n4_build::ParsedCreatePdr {
            pdr_id,
            precedence: 255,
            pdi: crate::n4_build::ParsedPdi {
                source_interface: source,
                ..Default::default()
            },
            outer_header_removal: (source == 0).then_some(0),
            far_id: Some(far_id),
            urr_ids: Vec::new(),
            qer_ids: Default::default(),
            transport_delay_reporting: None,
        }
    }

    /// The establishment of smfd's 5G session: UL PDR 1 -> FAR 1 FORW to Core, DL PDR
    /// 2 -> FAR 2 BUFF (no N3 endpoint yet; smfd's `dl_far apply_action: 0x04`).
    fn established_with_buffering_dl(seid: u64, ue: Ipv4Addr) -> PfcpSessionEvent {
        let mut dl = far_with_ohc(2, None, None);
        dl.apply_action = data_plane::FAR_ACTION_BUFF;
        dl.forwarding_parameters = None;
        let mut ul = far_with_ohc(1, None, None);
        ul.forwarding_parameters = Some(crate::n4_build::ParsedForwardingParameters {
            destination_interface: 1, // Core
            network_instance: None,
            outer_header_creation: None,
        });
        PfcpSessionEvent::SessionEstablished {
            upf_seid: seid,
            smf_seid: seid | 0x1_0000,
            ue_ipv4: Some(ue),
            ul_teid: 0x100 + seid as u32,
            dl_teid: 0,
            gnb_addr: None,
            pdrs: vec![pdr_through(1, 0, 1), pdr_through(2, 1, 2)],
            fars: vec![ul, dl],
            qers: Vec::new(),
            urrs: Vec::new(),
            bars: Vec::new(),
        }
    }

    /// **#1450.** An I-UPF's establishment, as the PFCP layer hands it over: UL PDR 1
    /// (Access, Transport Delay Reporting toward 10.45.0.7) -> FAR 1 FORW to the Core
    /// over N9; DL PDR 2 (Core, on its N9 F-TEID 0x1450b) -> FAR 2 FORW to the gNB.
    /// No UE address (TS 29.244 Table 7.5.2.2-2: conditional at an I-UPF).
    fn i_upf_established(seid: u64) -> PfcpSessionEvent {
        let mut ul = far_with_ohc(1, Some(Ipv4Addr::new(10, 9, 0, 1)), None);
        ul.forwarding_parameters
            .as_mut()
            .unwrap()
            .destination_interface = data_plane::SRC_INTF_CORE;
        let mut ul_pdr = pdr_through(1, 0, 1);
        // Remote GTP-U Peer (IE 103, §8.2.70): flags V4 (0x02), 10.45.0.7.
        ul_pdr.transport_delay_reporting = Some(vec![0x00, 0x67, 0x00, 0x05, 0x02, 10, 45, 0, 7]);
        let mut dl_pdr = pdr_through(2, 1, 2);
        dl_pdr.pdi.local_f_teid = Some(crate::n4_build::ParsedFTeid {
            teid: 0x1450b,
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 4)),
            ipv6: None,
            v4: true,
            v6: false,
            ch: false,
            chid: false,
            choose_id: None,
        });
        PfcpSessionEvent::SessionEstablished {
            upf_seid: seid,
            smf_seid: seid | 0x1_0000,
            ue_ipv4: None,
            ul_teid: 0x1450a,
            dl_teid: 0x4002,
            gnb_addr: Some(Ipv4Addr::new(10, 9, 0, 2)),
            pdrs: vec![ul_pdr, dl_pdr],
            fars: vec![ul, far_with_ohc(2, Some(Ipv4Addr::new(10, 9, 0, 2)), None)],
            qers: Vec::new(),
            urrs: Vec::new(),
            bars: Vec::new(),
        }
    }

    /// **#1450.** The data plane installs an I-UPF session with no UE address,
    /// routes its N9 F-TEID to the Core PDR, and provisions the UL PDR's Transport
    /// Delay Reporting; a null Transport Delay Reporting in an Update PDR
    /// deactivates it, and the session's deletion drops it.
    ///
    /// REVERT-VERIFIED: with the establishment requiring a UE address (the `iupf`
    /// arm removed), no session is installed; with the Core PDRs' F-TEIDs not bound,
    /// the N9 TEID finds no session.
    #[tokio::test]
    async fn an_i_upf_session_is_installed_with_its_n9_tunnel_and_transport_delay() {
        let dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
        let seid = 0x1450;
        handle_pfcp_session_event(&dp, i_upf_established(seid)).await;
        let session = dp.sessions.find_by_seid(seid).expect("installed");
        assert_eq!(session.ue_ipv4(), None);
        let by_n9 = dp
            .sessions
            .find_by_ul_teid(0x1450b)
            .expect("N9 TEID routed");
        assert_eq!(by_n9.upf_seid, seid);
        let m = session
            .match_tunnel_pdr(0x1450b, None, None)
            .expect("a PDR");
        assert_eq!(
            (m.pdr_id, m.source_interface),
            (2, data_plane::SRC_INTF_CORE)
        );
        let m = session
            .match_tunnel_pdr(0x1450a, None, None)
            .expect("a PDR");
        assert_eq!(m.pdr_id, 1, "the N3 uplink");
        assert_eq!(
            dp.with_transport_delay(|m| m.pdr(seid, 1)).map(|c| c.peer),
            Some("10.45.0.7".parse().unwrap())
        );
        assert_eq!(dp.with_transport_delay(|m| m.pdr(seid, 2)), None);
        // Deactivated by an Update PDR with a null IE (§5.6.3).
        let modified = PfcpSessionEvent::SessionModified {
            upf_seid: seid,
            dl_teid: None,
            gnb_addr: None,
            removed_pdr_ids: Vec::new(),
            removed_far_ids: Vec::new(),
            removed_qer_ids: Vec::new(),
            removed_urr_ids: Vec::new(),
            created_pdrs: Vec::new(),
            created_fars: Vec::new(),
            created_qers: Vec::new(),
            created_urrs: Vec::new(),
            updated_pdrs: vec![crate::n4_build::ParsedUpdatePdr {
                pdr_id: 1,
                transport_delay_reporting: Some(None),
                ..Default::default()
            }],
            updated_fars: Vec::new(),
            updated_qers: Vec::new(),
            updated_urrs: Vec::new(),
            updated_bars: Vec::new(),
            send_end_marker: false,
            drop_buffered: false,
            old_dl_tunnel: None,
        };
        handle_pfcp_session_event(&dp, modified).await;
        assert_eq!(dp.with_transport_delay(|m| m.pdr(seid, 1)), None);
        assert!(!dp.transport_delay_active());
        // Provisioned again, then gone with the PDR (Remove PDR).
        handle_pfcp_session_event(&dp, i_upf_established(seid + 2)).await;
        assert!(dp.transport_delay_active());
        let removal = PfcpSessionEvent::SessionModified {
            upf_seid: seid + 2,
            dl_teid: None,
            gnb_addr: None,
            removed_pdr_ids: vec![1],
            removed_far_ids: Vec::new(),
            removed_qer_ids: Vec::new(),
            removed_urr_ids: Vec::new(),
            created_pdrs: Vec::new(),
            created_fars: Vec::new(),
            created_qers: Vec::new(),
            created_urrs: Vec::new(),
            updated_pdrs: Vec::new(),
            updated_fars: Vec::new(),
            updated_qers: Vec::new(),
            updated_urrs: Vec::new(),
            updated_bars: Vec::new(),
            send_end_marker: false,
            drop_buffered: false,
            old_dl_tunnel: None,
        };
        handle_pfcp_session_event(&dp, removal).await;
        assert!(!dp.transport_delay_active(), "gone with its PDR");
        // #2197 review M1: Remove PDR 2 (the Core PDR on the N9 F-TEID): the N9
        // TEID no longer routes to the session, the N3 one still does.
        handle_pfcp_session_event(&dp, i_upf_established(seid + 3)).await;
        assert_eq!(
            dp.sessions.find_by_ul_teid(0x1450b).map(|s| s.upf_seid),
            Some(seid + 3)
        );
        let remove_dl = PfcpSessionEvent::SessionModified {
            upf_seid: seid + 3,
            dl_teid: None,
            gnb_addr: None,
            removed_pdr_ids: vec![2],
            removed_far_ids: Vec::new(),
            removed_qer_ids: Vec::new(),
            removed_urr_ids: Vec::new(),
            created_pdrs: Vec::new(),
            created_fars: Vec::new(),
            created_qers: Vec::new(),
            created_urrs: Vec::new(),
            updated_pdrs: Vec::new(),
            updated_fars: Vec::new(),
            updated_qers: Vec::new(),
            updated_urrs: Vec::new(),
            updated_bars: Vec::new(),
            send_end_marker: false,
            drop_buffered: false,
            old_dl_tunnel: None,
        };
        handle_pfcp_session_event(&dp, remove_dl).await;
        assert!(
            dp.sessions.find_by_ul_teid(0x1450b).is_none(),
            "a stale N9 TEID routes nowhere"
        );
        assert!(dp.sessions.find_by_ul_teid(0x1450a).is_some());
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionDeleted {
                upf_seid: seid + 3,
                ue_ipv4: None,
            },
        )
        .await;
        // Provisioned again, then gone with the session.
        handle_pfcp_session_event(&dp, i_upf_established(seid + 1)).await;
        assert!(dp.transport_delay_active());
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionDeleted {
                upf_seid: seid + 1,
                ue_ipv4: None,
            },
        )
        .await;
        assert!(!dp.transport_delay_active());
    }

    /// **#1348, TS 29.244 §5.2.1 / §7.5.2.** A session is never visible without the
    /// rules its Establishment Request created. A reader spinning on the UE-IP map (as
    /// the data-plane loop does) while sessions are established must never find one
    /// whose DL FAR forwards when the SMF's says BUFF, nor one holding the invented
    /// match-all PDRs. Before #1348 the session was published with FORW-all defaults
    /// and the SMF's rules were written over them afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_is_never_visible_without_the_rules_its_establishment_created() {
        let dp = Arc::new(DataPlane::new(Arc::new(AtomicBool::new(false))));
        let ue = Ipv4Addr::new(10, 45, 13, 48);
        let stop = Arc::new(AtomicBool::new(false));
        // #1373: how often the reader has found a session, shared so the writer can
        // wait for it. The reader is a plain thread the scheduler may not run while
        // the writer establishes and removes 400 sessions; on a loaded CI runner it
        // once saw none, which proves nothing about the invariant. The writer now
        // waits for the reader to have started and, every `CHECKPOINT` sessions,
        // holds a session published until the reader has found it, so the reader
        // provably runs concurrently with the establishments.
        let seen = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let started = Arc::new(AtomicBool::new(false));
        let (reader_dp, reader_stop, reader_seen, reader_started) = (
            Arc::clone(&dp),
            Arc::clone(&stop),
            Arc::clone(&seen),
            Arc::clone(&started),
        );
        // #1373 review: stopped and joined on every exit, a failed bounded wait
        // included, so a failing test never leaves its reader spinning.
        struct Reader {
            stop: Arc<AtomicBool>,
            handle: Option<std::thread::JoinHandle<Vec<String>>>,
        }
        impl Reader {
            fn finish(mut self) -> Vec<String> {
                self.stop.store(true, Ordering::Relaxed);
                self.handle.take().expect("joined once").join().unwrap()
            }
        }
        impl Drop for Reader {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
        }
        let reader_handle = std::thread::spawn(move || {
            let mut bad = Vec::new();
            reader_started.store(true, Ordering::Release);
            while !reader_stop.load(Ordering::Relaxed) {
                if let Some(sess) = reader_dp.sessions.find_by_ue_ip(ue) {
                    let fars = sess.fars.read().unwrap();
                    let dl_buffers = fars
                        .get(&2)
                        .is_some_and(|f| f.apply_action == data_plane::FAR_ACTION_BUFF);
                    let pdrs = sess.pdrs.read().unwrap().len();
                    if !dl_buffers || pdrs != 2 {
                        bad.push(format!(
                            "SEID {:#x}: FAR 2 {:?}, {pdrs} PDRs",
                            sess.upf_seid,
                            fars.get(&2).map(|f| f.apply_action)
                        ));
                    }
                    reader_seen.fetch_add(1, Ordering::AcqRel);
                }
            }
            bad
        });
        let reader = Reader {
            stop: Arc::clone(&stop),
            handle: Some(reader_handle),
        };

        // Wait for the reader to observe `predicate`, bounded so a broken reader fails
        // the test instead of hanging it.
        async fn wait_for(what: &str, predicate: impl Fn() -> bool) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !predicate() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for {what}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
        wait_for("the reader to start", || started.load(Ordering::Acquire)).await;
        const CHECKPOINT: u64 = 50;
        for i in 0..400u64 {
            let seid = 0x1348_0000 + i;
            handle_pfcp_session_event(&dp, established_with_buffering_dl(seid, ue)).await;
            if i % CHECKPOINT == 0 {
                let before = seen.load(Ordering::Acquire);
                wait_for("the reader to find the published session", || {
                    seen.load(Ordering::Acquire) > before
                })
                .await;
            }
            dp.remove_session_from_pfcp(seid);
        }
        let bad = reader.finish();
        let seen = seen.load(Ordering::Acquire);
        assert!(
            seen >= 400 / CHECKPOINT,
            "the reader observed the sessions: {seen}"
        );
        assert!(
            bad.is_empty(),
            "observed {} of {seen} without their rules: {:?}",
            bad.len(),
            &bad[..bad.len().min(3)]
        );
    }

    /// **#1348.** Nothing forwards on defaults: an Establishment Request that created
    /// no PDR gives a session that matches no packet, and holds only the FARs the
    /// request created (before, invented PDRs 1/2 and FORW FARs 1/2).
    #[tokio::test]
    async fn an_establishment_with_no_pdr_forwards_nothing_on_invented_rules() {
        let dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
        let ue = Ipv4Addr::new(10, 45, 13, 49);
        let PfcpSessionEvent::SessionEstablished {
            upf_seid,
            smf_seid,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
            fars,
            qers,
            urrs,
            bars,
            ..
        } = established_with_buffering_dl(0x1349, ue)
        else {
            unreachable!()
        };
        let only_dl: Vec<_> = fars.into_iter().filter(|f| f.far_id == 2).collect();
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionEstablished {
                upf_seid,
                smf_seid,
                ue_ipv4,
                ul_teid,
                dl_teid,
                gnb_addr,
                pdrs: Vec::new(),
                fars: only_dl,
                qers,
                urrs,
                bars,
            },
        )
        .await;
        let sess = dp.sessions.find_by_ue_ip(ue).expect("established");
        assert!(sess.pdrs.read().unwrap().is_empty(), "no invented PDR");
        let fars = sess.fars.read().unwrap();
        assert_eq!(
            fars.keys().copied().collect::<Vec<_>>(),
            vec![2],
            "only the request's FAR"
        );
        assert_eq!(fars[&2].apply_action, data_plane::FAR_ACTION_BUFF);
    }

    /// #960 review, MAJOR 1: the PFCP -> data-plane FAR wiring carries an IPv6 gNB
    /// endpoint, on Create FAR at establishment, Create FAR on a modification and
    /// Update FAR. An IPv6-only OHC yields the IPv6 address (before #918 the FAR got no
    /// endpoint at all), and an OHC carrying both yields the IPv4 one (§8.2.56 leaves
    /// the choice to the UP function; the IPv4 N3 socket always exists).
    #[tokio::test]
    async fn create_and_update_far_carry_an_ipv6_ohc_into_the_data_plane() {
        use std::net::{IpAddr, Ipv6Addr};
        let v4 = Ipv4Addr::new(192, 0, 2, 10);
        let v6: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
        let seid = 0x918;
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionEstablished {
                upf_seid: seid,
                smf_seid: 0x1918,
                ue_ipv4: Some(Ipv4Addr::new(10, 45, 9, 18)),
                ul_teid: 0x100,
                dl_teid: 0x200,
                gnb_addr: None,
                pdrs: Vec::new(),
                fars: vec![
                    far_with_ohc(1, None, Some(v6)),
                    far_with_ohc(2, Some(v4), Some(v6)),
                ],
                qers: Vec::new(),
                urrs: Vec::new(),
                bars: Vec::new(),
            },
        )
        .await;
        let session = dp.sessions.find_by_seid(seid).expect("installed");
        let ohc = |id: u32| session.fars.read().unwrap()[&id].ohc_addr;
        assert_eq!(ohc(1), Some(IpAddr::V6(v6)), "Create FAR, IPv6-only OHC");
        assert_eq!(
            ohc(2),
            Some(IpAddr::V4(v4)),
            "Create FAR, dual OHC: IPv4 wins"
        );

        let v6b: Ipv6Addr = "2001:db8::20".parse().unwrap();
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionModified {
                upf_seid: seid,
                dl_teid: None,
                gnb_addr: None,
                removed_pdr_ids: Vec::new(),
                removed_far_ids: Vec::new(),
                removed_qer_ids: Vec::new(),
                removed_urr_ids: Vec::new(),
                created_pdrs: Vec::new(),
                created_fars: vec![far_with_ohc(3, None, Some(v6b))],
                created_qers: Vec::new(),
                created_urrs: Vec::new(),
                updated_pdrs: Vec::new(),
                updated_fars: vec![
                    far_with_ohc(2, None, Some(v6b)),
                    far_with_ohc(1, Some(v4), Some(v6b)),
                ],
                updated_qers: Vec::new(),
                updated_urrs: Vec::new(),
                updated_bars: Vec::new(),
                send_end_marker: false,
                drop_buffered: false,
                old_dl_tunnel: None,
            },
        )
        .await;
        assert_eq!(
            ohc(3),
            Some(IpAddr::V6(v6b)),
            "Create FAR on a modification"
        );
        assert_eq!(ohc(2), Some(IpAddr::V6(v6b)), "Update FAR, IPv6-only OHC");
        assert_eq!(
            ohc(1),
            Some(IpAddr::V4(v4)),
            "Update FAR, dual OHC: IPv4 wins"
        );
    }

    /// #1629 review: a Session Modification that sets a FAR to BUFF with NOCP
    /// instructs the UP function to notify the first downlink packet (TS 29.244
    /// §5.2.3.1), so it starts a new buffering episode: the next buffered packet
    /// is a first one again, though a packet was buffered before. A BUFF without
    /// NOCP, or a FORW with no flush yet, does not re-arm.
    ///
    /// REVERT-VERIFIED: without the re-arm in the FAR loop, the packet after the
    /// BUFF|NOCP modification is not a first one.
    #[tokio::test]
    async fn a_buff_nocp_modification_starts_a_new_buffering_episode_1629() {
        let dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
        let seid = 0x1629;
        let far = |apply_action: u16| crate::n4_build::ParsedCreateFar {
            far_id: 2,
            apply_action,
            ..Default::default()
        };
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionEstablished {
                upf_seid: seid,
                smf_seid: 0x1629,
                ue_ipv4: Some(Ipv4Addr::new(10, 45, 16, 29)),
                ul_teid: 0x1629,
                dl_teid: 0,
                gnb_addr: None,
                pdrs: Vec::new(),
                fars: vec![far(data_plane::FAR_ACTION_BUFF)],
                qers: Vec::new(),
                urrs: Vec::new(),
                bars: Vec::new(),
            },
        )
        .await;
        let session = dp.sessions.find_by_seid(seid).expect("installed");
        let modify = |f| PfcpSessionEvent::SessionModified {
            upf_seid: seid,
            dl_teid: None,
            gnb_addr: None,
            removed_pdr_ids: Vec::new(),
            removed_far_ids: Vec::new(),
            removed_qer_ids: Vec::new(),
            removed_urr_ids: Vec::new(),
            created_pdrs: Vec::new(),
            created_fars: Vec::new(),
            created_qers: Vec::new(),
            created_urrs: Vec::new(),
            updated_pdrs: Vec::new(),
            updated_fars: vec![f],
            updated_qers: Vec::new(),
            updated_urrs: Vec::new(),
            updated_bars: Vec::new(),
            send_end_marker: false,
            drop_buffered: false,
            old_dl_tunnel: None,
        };
        let first = |n: u8| session.buffer_dl_packet(vec![n], None).1;

        assert!(first(1), "the create's BUFF FAR: the first packet");
        assert!(!first(2), "the same episode");
        handle_pfcp_session_event(&dp, modify(far(data_plane::FAR_ACTION_BUFF))).await;
        assert!(
            !first(3),
            "BUFF without NOCP asks for no report: no new episode"
        );
        handle_pfcp_session_event(
            &dp,
            modify(far(
                data_plane::FAR_ACTION_BUFF | data_plane::FAR_ACTION_NOCP
            )),
        )
        .await;
        // #1631: a new episode, whose first packets are the three already buffered;
        // they take its one report at the modification
        // (`a_buff_nocp_modification_reports_the_packets_already_buffered_1631`).
        assert!(
            !first(4),
            "BUFF|NOCP: a new episode, already reported for the buffered packets"
        );
        assert_eq!(
            session.dl_buffer.lock().unwrap().len(),
            4,
            "the packets buffered before stay buffered"
        );
        // With nothing buffered, the next packet is the episode's first.
        session.drain_dl_buffer();
        handle_pfcp_session_event(
            &dp,
            modify(far(
                data_plane::FAR_ACTION_BUFF | data_plane::FAR_ACTION_NOCP
            )),
        )
        .await;
        assert!(
            first(5),
            "BUFF|NOCP: a new episode, this packet is a first one"
        );
        assert!(!first(6), "and only one");
    }

    /// #1631 (#1635 review m3): a Session Modification that sets a FAR to BUFF|NOCP
    /// while packets are already buffered reports them at once, in one Downlink Data
    /// Report naming the FAR's core PDR. The packets are the episode's first, so the
    /// next packet does not report again. With an empty buffer, or with the buffer
    /// discarded by the same modification (DROBU), nothing is reported until a packet
    /// arrives.
    ///
    /// REVERT-VERIFIED: without the backlog report, no report follows the
    /// modification; with the claim not taking the episode, the next packet reports a
    /// second time; with the report before DROBU, the discarded buffer is reported.
    #[tokio::test]
    async fn a_buff_nocp_modification_reports_the_packets_already_buffered_1631() {
        let dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
        let seid = 0x1631;
        let far = |apply_action: u16| crate::n4_build::ParsedCreateFar {
            far_id: 2,
            apply_action,
            ..Default::default()
        };
        let core_pdr = crate::n4_build::ParsedCreatePdr {
            pdr_id: 9,
            precedence: 100,
            pdi: crate::n4_build::ParsedPdi {
                source_interface: data_plane::SRC_INTF_CORE,
                ..Default::default()
            },
            far_id: Some(2),
            ..Default::default()
        };
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionEstablished {
                upf_seid: seid,
                smf_seid: 0x1631_0000,
                ue_ipv4: Some(Ipv4Addr::new(10, 45, 16, 31)),
                ul_teid: 0x1631,
                dl_teid: 0,
                gnb_addr: None,
                pdrs: vec![core_pdr],
                fars: vec![far(data_plane::FAR_ACTION_BUFF)],
                qers: Vec::new(),
                urrs: Vec::new(),
                bars: Vec::new(),
            },
        )
        .await;
        let (tx, mut reports) = tokio::sync::mpsc::channel(16);
        dp.set_report_channel(tx);
        let session = dp.sessions.find_by_seid(seid).expect("installed");
        let modify = |drop_buffered: bool| PfcpSessionEvent::SessionModified {
            upf_seid: seid,
            dl_teid: None,
            gnb_addr: None,
            removed_pdr_ids: Vec::new(),
            removed_far_ids: Vec::new(),
            removed_qer_ids: Vec::new(),
            removed_urr_ids: Vec::new(),
            created_pdrs: Vec::new(),
            created_fars: Vec::new(),
            created_qers: Vec::new(),
            created_urrs: Vec::new(),
            updated_pdrs: Vec::new(),
            updated_fars: vec![far(
                data_plane::FAR_ACTION_BUFF | data_plane::FAR_ACTION_NOCP
            )],
            updated_qers: Vec::new(),
            updated_urrs: Vec::new(),
            updated_bars: Vec::new(),
            send_end_marker: false,
            drop_buffered,
            old_dl_tunnel: None,
        };
        let mut drain = || {
            let mut out = Vec::new();
            while let Ok(event) = reports.try_recv() {
                out.push(event);
            }
            out
        };

        // Buffered under the create's BUFF (no NOCP): nothing was reported.
        session.buffer_dl_packet(vec![1], None);
        session.buffer_dl_packet(vec![2], None);
        handle_pfcp_session_event(&dp, modify(false)).await;
        let got = drain();
        assert_eq!(got.len(), 1, "one report for the backlog: {got:?}");
        assert!(
            matches!(
                got[0],
                data_plane::UpfReportEvent::DownlinkDataReport {
                    upf_seid: 0x1631,
                    smf_seid: 0x1631_0000,
                    pdr_id: 9,
                    ..
                }
            ),
            "{got:?}"
        );
        assert!(
            !session.buffer_dl_packet(vec![3], None).1,
            "the backlog took the episode's report"
        );

        // The buffer discarded by the same modification: nothing to report.
        handle_pfcp_session_event(&dp, modify(true)).await;
        assert!(drain().is_empty(), "a discarded buffer is not reported");
        assert!(
            session.buffer_dl_packet(vec![4], None).1,
            "the episode's report is still owed to the next packet"
        );

        // An empty buffer: the next packet reports, as before.
        session.drain_dl_buffer();
        handle_pfcp_session_event(&dp, modify(false)).await;
        assert!(drain().is_empty(), "nothing buffered, nothing reported");
        assert!(session.buffer_dl_packet(vec![5], None).1);
    }

    /// #953 review (minor): an Update URR that CARRIES a Measurement Method changes
    /// whether the URR measures time (DURAT, TS 29.244 Table 7.5.4.4-1); one that does
    /// not leaves it as it was. An absent IE parses as `measure_duration == false`, so
    /// applying it unconditionally would switch Duration reporting off.
    #[tokio::test]
    async fn an_update_urr_changes_durat_only_when_it_carries_a_measurement_method() {
        let dp = DataPlane::new(Arc::new(AtomicBool::new(false)));
        let seid = 0x818;
        let urr = |present: bool, durat: bool| crate::n4_build::ParsedCreateUrr {
            urr_id: 1,
            measurement_method_present: present,
            measure_duration: durat,
            measure_volume: true,
            ..Default::default()
        };
        handle_pfcp_session_event(
            &dp,
            PfcpSessionEvent::SessionEstablished {
                upf_seid: seid,
                smf_seid: 0x1818,
                ue_ipv4: Some(Ipv4Addr::new(10, 45, 8, 18)),
                ul_teid: 0x100,
                dl_teid: 0x200,
                gnb_addr: None,
                pdrs: Vec::new(),
                fars: Vec::new(),
                qers: Vec::new(),
                urrs: vec![urr(true, true)],
                bars: Vec::new(),
            },
        )
        .await;
        let session = dp.sessions.find_by_seid(seid).expect("installed");
        let durat = || session.urrs.read().unwrap()[&1].measures_duration();
        assert!(durat(), "created with DURAT");

        let modify = |u| PfcpSessionEvent::SessionModified {
            upf_seid: seid,
            dl_teid: None,
            gnb_addr: None,
            removed_pdr_ids: Vec::new(),
            removed_far_ids: Vec::new(),
            removed_qer_ids: Vec::new(),
            removed_urr_ids: Vec::new(),
            created_pdrs: Vec::new(),
            created_fars: Vec::new(),
            created_qers: Vec::new(),
            created_urrs: Vec::new(),
            updated_pdrs: Vec::new(),
            updated_fars: Vec::new(),
            updated_qers: Vec::new(),
            updated_urrs: vec![u],
            updated_bars: Vec::new(),
            send_end_marker: false,
            drop_buffered: false,
            old_dl_tunnel: None,
        };
        handle_pfcp_session_event(&dp, modify(urr(false, false))).await;
        assert!(
            durat(),
            "no Measurement Method in the Update URR: DURAT unchanged"
        );
        handle_pfcp_session_event(&dp, modify(urr(true, false))).await;
        assert!(!durat(), "a volume-only Measurement Method turns DURAT off");
        handle_pfcp_session_event(&dp, modify(urr(true, true))).await;
        assert!(durat(), "and DURAT back on");
    }
}
