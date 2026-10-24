//! The gNB half of NR Multi-RTT (#807; TS 38.305 §8.10.3.2, TS 38.455).
//!
//! A Multi-RTT range for one TRP is the UE Rx–Tx time difference (LPP) plus the
//! gNB Rx–Tx time difference (NRPPa), over two (TS 38.305 §8.10). The UE half is
//! asked for by the LPP request. This module obtains the gNB half, in the order of
//! TS 38.305 §8.10.3.2:
//!
//! 1. **TRP Information Exchange** (TS 38.455 §8.2.8, non-UE-associated) with each
//!    configured NG-RAN node, once: TRP-ID → NR PCI and position. The PCI is what
//!    the UE half names its TRP by, so it is the key the two halves meet on.
//! 2. **Positioning Information Exchange** (§8.2.6, UE-associated) with the serving
//!    gNB: it configures the UE's SRS and returns the SRS configuration.
//! 3. **Positioning Activation** (§8.2.9, UE-associated) of semi-persistent or
//!    aperiodic SRS. Periodic SRS needs none.
//! 4. **Measurement** (§8.5.1, non-UE-associated) toward each node: MEASUREMENT
//!    REQUEST for `gNB-RxTxTimeDiff` of its TRPs, with the UE's SRS configuration,
//!    on demand. All of this is done before the LPP request goes to the UE (step 8
//!    of §8.10.3.2), by [`prepare`].
//! 5. The MEASUREMENT RESPONSEs are collected by [`collect`], turned into
//!    [`CellMeasurement`]s keyed `pci-<n>` with the gNB's time stamp, and the
//!    semi-persistent SRS is deactivated (§8.2.10).
//!
//! Every answer is correlated by `(procedure code, NRPPa transaction id)` through
//! the context's NRPPa waiters, which the uplink notify feeds.

use std::future::Future;
use std::time::Duration;

use crate::context::{lmf_self, CellMeasurement};
use crate::nrppa_downlink::{self, SrsActivation};
use crate::nrppa_positioning as answers;
use crate::site_config::NgRanNode;
use nextgcore_nrppa_gen::generated as nrppa;

/// How NRPPa reaches NG-RAN: through the AMF in production, a test double in tests.
pub trait NrppaTransport: Send + Sync {
    /// Send a UE-associated NRPPa PDU to the target UE's serving gNB.
    fn send_ue(&self, pdu: Vec<u8>) -> impl Future<Output = bool> + Send;
    /// Send a non-UE-associated NRPPa PDU to `node`.
    fn send_non_ue(&self, node: &NgRanNode, pdu: Vec<u8>) -> impl Future<Output = bool> + Send;
    /// The session the UE-associated answers must name (#903 review).
    fn session(&self) -> Option<String> {
        None
    }
}

/// The DL-PRS assistance data of a session (#911), and the TRPs it names.
pub struct Assistance {
    pub built: crate::dl_prs_assistance::Built,
    /// DL-PRS ID → registry key of its TRP, for the session's measurements.
    pub keys: std::collections::HashMap<u8, String>,
    /// The TRPs described, with their DL-PRS IDs.
    pub trps: Vec<(NgRanNode, u16, u8)>,
}

/// Build the DL-PRS assistance data (TS 38.305 §8.10.3.2 step 7, §8.12) from the
/// TRP Information of the configured nodes, learning it first where it is
/// missing (#911). `serving` is the AMF's serving cell, whose TRP becomes the
/// reference and the a-priori UE position. `None` when no TRP reported a PRS
/// configuration this LMF can describe: the UE is then asked without one, as
/// before.
pub async fn prepare_assistance<T: NrppaTransport>(
    t: &T,
    timeout: Duration,
    serving: Option<&crate::nlmf::Ncgi>,
) -> Option<Assistance> {
    use crate::dl_prs_assistance::{build, APriori, TrpPrs};
    ensure_trp_information(t, timeout).await;
    let ctx = lmf_self();
    let c = ctx.read().ok()?;
    let all = c.trp_information();
    let ambiguous = answers::ambiguous_pcis(all.iter().map(|(_, t)| t));
    let registry = c.build_trp_registry();
    let mut trps: Vec<TrpPrs> = Vec::new();
    let mut named: Vec<(NgRanNode, u16, u8)> = Vec::new();
    for (node, info) in &all {
        let Some(prs) = info.prs.clone() else {
            continue;
        };
        let Some(dl_prs_id) = c.dl_prs_id_assign(node, info.trp_id) else {
            log::warn!("DL-PRS assistance: all 256 DL-PRS IDs are assigned; TRP {} of {node:?} is not described", info.trp_id);
            continue;
        };
        // The position: what the gNB reported, else what the operator configured
        // for its CGI, or for its PCI when no other TRP has that PCI.
        let key = crate::context::trp_key(node, info.trp_id);
        let coord = info
            .coord
            .or_else(|| info.nr_cgi.as_deref().and_then(|k| registry.lookup(k)))
            .or_else(|| {
                info.pci
                    .filter(|p| !ambiguous.contains(p))
                    .and_then(|p| registry.lookup(&format!("pci-{p}")))
            });
        // #990 review: a position NG-RAN corrects later replaces the one learned
        // before. The key is this LMF's own, never configured.
        if let Some(coord) = coord {
            match registry.lookup(&key) {
                Some(old) if old == coord => {}
                Some(old) => {
                    log::info!("DL-PRS assistance: {key} moved from {old:?} to {coord:?}");
                    c.set_cell_coord(key.clone(), coord);
                }
                None => c.set_cell_coord(key.clone(), coord),
            }
        }
        trps.push(TrpPrs {
            dl_prs_id,
            pci: info.pci,
            ncgi: info.ncgi.clone(),
            arfcn: info.arfcn,
            coord,
            sfn_init: info.sfn_init,
            prs,
        });
        named.push((node.clone(), info.trp_id, dl_prs_id));
    }
    drop(c);
    if trps.is_empty() {
        log::info!("DL-PRS assistance: no TRP reported a PRS configuration; none is sent");
        return None;
    }
    // The serving TRP is the reference, and the UE is within reach of it: as far
    // as its nearest neighbour TRP, at least 100 m. Without it, the centroid, and
    // as far as the farthest TRP.
    let serving_index = serving.and_then(|s| {
        trps.iter().position(|t| {
            t.ncgi
                .as_ref()
                .is_some_and(|n| n.matches(&s.plmn_id.mcc, &s.plmn_id.mnc, &s.nr_cell_id))
        })
    });
    let coords: Vec<crate::positioning::TrpCoord> = trps.iter().filter_map(|t| t.coord).collect();
    let distance = |a: crate::positioning::TrpCoord, b: crate::positioning::TrpCoord| {
        let p = crate::positioning::geodetic_to_enu(b, a);
        (p.e * p.e + p.n * p.n + p.u * p.u).sqrt()
    };
    let a_priori = match serving_index.and_then(|i| trps[i].coord) {
        Some(here) => {
            let nearest = coords
                .iter()
                .map(|c| distance(here, *c))
                .filter(|d| *d > 1.0)
                .fold(f64::INFINITY, f64::min);
            Some(APriori {
                coord: here,
                radius_m: if nearest.is_finite() {
                    nearest.max(100.0)
                } else {
                    1_000.0
                },
            })
        }
        None if !coords.is_empty() => {
            let n = coords.len() as f64;
            let centroid = crate::positioning::TrpCoord::new(
                coords.iter().map(|c| c.lat_deg).sum::<f64>() / n,
                coords.iter().map(|c| c.lon_deg).sum::<f64>() / n,
                coords.iter().map(|c| c.height_m).sum::<f64>() / n,
            );
            let farthest = coords
                .iter()
                .map(|c| distance(centroid, *c))
                .fold(0.0, f64::max);
            Some(APriori {
                coord: centroid,
                radius_m: farthest.max(100.0),
            })
        }
        None => None,
    };
    let built = match build(&trps, serving_index.unwrap_or(0), a_priori) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("DL-PRS assistance: {e}; none is sent");
            return None;
        }
    };
    named.retain(|(_, _, id)| built.dl_prs_ids.contains(id));
    let keys = named
        .iter()
        .map(|(node, trp, id)| (*id, crate::context::trp_key(node, *trp)))
        .collect();
    log::info!(
        "DL-PRS assistance: {} TRP(s), reference DL-PRS ID {}",
        named.len(),
        built.reference
    );
    Some(Assistance {
        built,
        keys,
        trps: named,
    })
}

/// One MEASUREMENT REQUEST in flight.
pub struct PendingMeasurement {
    node: NgRanNode,
    lmf_measurement_id: u32,
    procedure_txn: u16,
    answer: tokio::sync::oneshot::Receiver<Vec<u8>>,
}

/// The gNB half, set up and waiting for its measurements.
pub struct PreparedGnbLeg {
    measurements: Vec<PendingMeasurement>,
    /// The SRS that was activated, to deactivate afterwards.
    activated: Option<SrsActivation>,
    /// The TRPs the session's assistance data named, with their DL-PRS IDs (#911).
    assisted: Vec<(NgRanNode, u16, u8)>,
}

/// Send `pdu` and wait up to `timeout` for the answer to `procedure`/`txn`.
async fn exchange(
    procedure: u8,
    txn: u16,
    session: Option<&str>,
    send: impl Future<Output = bool>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let rx = match lmf_self().read() {
        Ok(c) => c.nrppa_wait(procedure, txn, session),
        Err(_) => return Err("context lock poisoned".to_string()),
    };
    let unwait = || {
        if let Ok(c) = lmf_self().read() {
            c.nrppa_unwait(procedure, txn);
        }
    };
    if !send.await {
        unwait();
        return Err(format!("NRPPa procedure {procedure} not sent"));
    }
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(bytes)) => Ok(bytes),
        _ => {
            unwait();
            Err(format!(
                "no answer to NRPPa procedure {procedure} (transaction {txn}) within {timeout:?}"
            ))
        }
    }
}

/// Learn the TRPs of every configured node that has not told us yet, or told us
/// more than [`crate::context::TRP_INFORMATION_MAX_AGE`] ago.
pub async fn ensure_trp_information<T: NrppaTransport>(t: &T, timeout: Duration) {
    let (nodes, known) = match lmf_self().read() {
        Ok(c) => (c.ng_ran_nodes(), c.trp_information()),
        Err(_) => return,
    };
    for node in nodes {
        // #990 review: asked again once its answer is TRP_INFORMATION_MAX_AGE old.
        let stale = lmf_self()
            .read()
            .is_ok_and(|c| c.trp_information_stale(&node));
        if known.iter().any(|(n, _)| *n == node) && !stale {
            continue;
        }
        if lmf_self()
            .read()
            .is_ok_and(|c| c.trp_information_backed_off(&node))
        {
            continue;
        }
        let Ok((txn, pdu)) = nrppa_downlink::build_trp_information(&[]) else {
            continue;
        };
        match exchange(
            nrppa::ID_T_RP_INFORMATION_EXCHANGE,
            txn.0,
            None,
            t.send_non_ue(&node, pdu),
            timeout,
        )
        .await
        .and_then(|b| answers::decode_trp_information_response(&b))
        {
            Ok(trps) => {
                log::info!("Multi-RTT: {node:?} has {} TRP(s)", trps.len());
                if let Ok(c) = lmf_self().read() {
                    c.note_trp_information(&node, trps);
                }
            }
            Err(e) => {
                log::warn!(
                    "Multi-RTT: TRP Information Exchange with {node:?}: {e}; not asked again for \
                     {:?}",
                    crate::context::TRP_INFORMATION_RETRY
                );
                if let Ok(c) = lmf_self().read() {
                    c.note_trp_information_failed(&node);
                }
            }
        }
    }
}

/// Steps 1–4: set the gNB half up. `Err` means no gNB half can be had for this
/// session, and the caller asks the UE for a method that needs none.
///
/// `step_timeout` bounds each exchange; `response_time_ms` is what the gNBs are
/// told they have to measure in.
///
/// `assisted` are the TRPs the session's DL-PRS assistance data named (#911).
/// They are measured even when their PCI is on another TRP too, because the
/// UE names them by their DL-PRS ID.
pub async fn prepare<T: NrppaTransport>(
    t: &T,
    step_timeout: Duration,
    response_time_ms: u32,
    assisted: &[(NgRanNode, u16, u8)],
) -> Result<PreparedGnbLeg, String> {
    ensure_trp_information(t, step_timeout).await;
    let all = lmf_self()
        .read()
        .map(|c| c.trp_information())
        .unwrap_or_default();
    // #903 review: a PCI on several TRPs cannot key a TRP, so those TRPs are not
    // measured (their halves could not be paired with the right UE half).
    let ambiguous = answers::ambiguous_pcis(all.iter().map(|(_, t)| t));
    if !ambiguous.is_empty() {
        log::warn!(
            "Multi-RTT: PCIs {ambiguous:?} are on more than one TRP; those TRPs are not measured"
        );
    }
    let is_assisted =
        |node: &NgRanNode, trp: u16| assisted.iter().any(|(n, t, _)| n == node && *t == trp);
    let trps: Vec<(NgRanNode, u16)> = all
        .into_iter()
        .filter(|(node, info)| {
            is_assisted(node, info.trp_id) || info.pci.is_some_and(|p| !ambiguous.contains(&p))
        })
        .map(|(node, info)| (node, info.trp_id))
        .collect();
    if trps.is_empty() {
        return Err(
            "no NG-RAN node reported a TRP with an unambiguous NR PCI or a DL-PRS ID".to_string(),
        );
    }

    let session = t.session();
    let (txn, pdu) = nrppa_downlink::build_positioning_information_request()?;
    let info = exchange(
        nrppa::ID_POSITIONING_INFORMATION_EXCHANGE,
        txn.0,
        session.as_deref(),
        t.send_ue(pdu),
        step_timeout,
    )
    .await
    .and_then(|b| answers::decode_positioning_information_response(&b))?;
    let Some(srs) = info.srs_configuration else {
        return Err(
            "the serving gNB returned no SRS configuration, so no TRP can measure the UE"
                .to_string(),
        );
    };

    let activated = answers::srs_activation(&srs);
    if let Some(activation) = activated {
        let (txn, pdu) = nrppa_downlink::build_positioning_activation_request(activation)?;
        exchange(
            nrppa::ID_POSITIONING_ACTIVATION,
            txn.0,
            session.as_deref(),
            t.send_ue(pdu),
            step_timeout,
        )
        .await
        .and_then(|b| answers::decode_positioning_activation_response(&b))?;
    }

    let mut nodes: Vec<NgRanNode> = Vec::new();
    for (node, _) in &trps {
        if !nodes.contains(node) {
            nodes.push(node.clone());
        }
    }
    let mut measurements = Vec::new();
    for node in nodes {
        let ids: Vec<u16> = trps
            .iter()
            .filter(|(n, _)| *n == node)
            .map(|(_, id)| *id)
            .take(64) // maxNoOfMeasTRPs
            .collect();
        let lmf_measurement_id = nrppa_downlink::next_lmf_measurement_id();
        let (txn, pdu) =
            nrppa_downlink::build_measurement_request(&nrppa_downlink::MeasurementRequest {
                lmf_measurement_id,
                trp_ids: &ids,
                srs_configuration: Some(&srs),
                sfn_initialisation_time: info.sfn_initialisation_time.as_ref(),
                response_time_ms: Some(response_time_ms),
            })?;
        let answer = match lmf_self().read() {
            Ok(c) => c.nrppa_wait(nrppa::ID_MEASUREMENT, txn.0, None),
            Err(_) => continue,
        };
        if t.send_non_ue(&node, pdu).await {
            measurements.push(PendingMeasurement {
                node,
                lmf_measurement_id,
                procedure_txn: txn.0,
                answer,
            });
        } else {
            log::warn!("Multi-RTT: Measurement Request to {node:?} not sent");
            if let Ok(c) = lmf_self().read() {
                c.nrppa_unwait(nrppa::ID_MEASUREMENT, txn.0);
            }
        }
    }
    if measurements.is_empty() {
        if let Some(activation) = activated {
            deactivate(t, activation).await;
        }
        return Err("no Measurement Request could be sent".to_string());
    }
    Ok(PreparedGnbLeg {
        measurements,
        activated,
        assisted: assisted.to_vec(),
    })
}

async fn deactivate<T: NrppaTransport>(t: &T, activation: SrsActivation) {
    let set = match activation {
        SrsActivation::SemiPersistent(set) => Some(set),
        SrsActivation::Aperiodic => None,
    };
    match nrppa_downlink::build_positioning_deactivation(set) {
        Ok((_, pdu)) => {
            if !t.send_ue(pdu).await {
                log::warn!("Multi-RTT: Positioning Deactivation not sent");
            }
        }
        Err(e) => log::warn!("Multi-RTT: Positioning Deactivation: {e}"),
    }
}

/// Step 5: wait up to `timeout` for every MEASUREMENT RESPONSE, then deactivate
/// the SRS. Returns the gNB halves, keyed `pci-<n>` by the TRP information.
pub async fn collect<T: NrppaTransport>(
    t: &T,
    prepared: PreparedGnbLeg,
    timeout: Duration,
) -> Vec<CellMeasurement> {
    let deadline = tokio::time::Instant::now() + timeout;
    let trps = lmf_self()
        .read()
        .map(|c| c.trp_information())
        .unwrap_or_default();
    let ambiguous = answers::ambiguous_pcis(trps.iter().map(|(_, t)| t));
    let mut cells = Vec::new();
    for m in prepared.measurements {
        let answer = tokio::time::timeout_at(deadline, m.answer).await;
        let bytes = match answer {
            Ok(Ok(bytes)) => bytes,
            _ => {
                log::warn!(
                    "Multi-RTT: no Measurement Response from {:?} in time; its TRPs give no \
                     gNB half",
                    m.node
                );
                if let Ok(c) = lmf_self().read() {
                    c.nrppa_unwait(nrppa::ID_MEASUREMENT, m.procedure_txn);
                }
                continue;
            }
        };
        match answers::decode_measurement_response(&bytes, m.lmf_measurement_id) {
            Ok(halves) => {
                for h in halves {
                    // #911: a TRP the assistance data named is keyed by its TRP.
                    if let Some((_, _, id)) = prepared
                        .assisted
                        .iter()
                        .find(|(n, t, _)| *n == m.node && *t == h.trp_id)
                    {
                        match h.rx_tx_ns {
                            Some(rx_tx) => cells.push(CellMeasurement {
                                nr_cgi: crate::context::trp_key(&m.node, h.trp_id),
                                dl_prs_id: Some(*id),
                                ..gnb_half(0, rx_tx, h.time)
                            }),
                            None => log::warn!(
                                "Multi-RTT: TRP {} of {:?}: an open-ended gNB Rx-Tx report; \
                                 not used",
                                h.trp_id,
                                m.node
                            ),
                        }
                        continue;
                    }
                    let pci = trps
                        .iter()
                        .find(|(n, info)| *n == m.node && info.trp_id == h.trp_id)
                        .and_then(|(_, info)| info.pci)
                        .filter(|p| !ambiguous.contains(p));
                    let (Some(pci), Some(rx_tx)) = (pci, h.rx_tx_ns) else {
                        log::warn!(
                            "Multi-RTT: TRP {} of {:?}: no PCI known or an open-ended gNB \
                             Rx-Tx report; not used",
                            h.trp_id,
                            m.node
                        );
                        continue;
                    };
                    cells.push(gnb_half(pci, rx_tx, h.time));
                }
            }
            Err(e) => log::warn!("Multi-RTT: Measurement Response from {:?}: {e}", m.node),
        }
    }
    if let Some(activation) = prepared.activated {
        deactivate(t, activation).await;
    }
    cells
}

/// The gNB half of TRP `pci` as a measurement.
pub fn gnb_half(pci: u16, rx_tx_ns: f64, time: Option<answers::SlotTime>) -> CellMeasurement {
    CellMeasurement {
        nr_cgi: format!("pci-{pci}"),
        rsrp: None,
        rsrq: None,
        timing_advance: None,
        ecid_rtt_ns: None,
        ecid_rtt_width_ns: None,
        aoa: None,
        rtt_ns: None,
        rstd_ns: None,
        rstd_reference: None,
        ue_rx_tx_ns: None,
        gnb_rx_tx_ns: Some(rx_tx_ns),
        meas_time: time,
        dl_prs_id: None,
        eutra: false,
    }
}

#[cfg(test)]
mod tests;
