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
}

/// Send `pdu` and wait up to `timeout` for the answer to `procedure`/`txn`.
async fn exchange(
    procedure: u8,
    txn: u16,
    send: impl Future<Output = bool>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let rx = match lmf_self().read() {
        Ok(c) => c.nrppa_wait(procedure, txn),
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

/// Learn the TRPs of every configured node that has not told us yet.
async fn ensure_trp_information<T: NrppaTransport>(t: &T, timeout: Duration) {
    let (nodes, known) = match lmf_self().read() {
        Ok(c) => (c.ng_ran_nodes(), c.trp_information()),
        Err(_) => return,
    };
    for node in nodes {
        if known.iter().any(|(n, _)| *n == node) {
            continue;
        }
        let Ok((txn, pdu)) = nrppa_downlink::build_trp_information(&[]) else {
            continue;
        };
        match exchange(
            nrppa::ID_T_RP_INFORMATION_EXCHANGE,
            txn.0,
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
            Err(e) => log::warn!("Multi-RTT: TRP Information Exchange with {node:?}: {e}"),
        }
    }
}

/// Steps 1–4: set the gNB half up. `Err` means no gNB half can be had for this
/// session, and the caller asks the UE for a method that needs none.
///
/// `step_timeout` bounds each exchange; `response_time_ms` is what the gNBs are
/// told they have to measure in.
pub async fn prepare<T: NrppaTransport>(
    t: &T,
    step_timeout: Duration,
    response_time_ms: u32,
) -> Result<PreparedGnbLeg, String> {
    ensure_trp_information(t, step_timeout).await;
    let trps: Vec<(NgRanNode, u16)> = lmf_self()
        .read()
        .map(|c| c.trp_information())
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, info)| info.pci.is_some())
        .map(|(node, info)| (node, info.trp_id))
        .collect();
    if trps.is_empty() {
        return Err("no NG-RAN node reported a TRP with an NR PCI".to_string());
    }

    let (txn, pdu) = nrppa_downlink::build_positioning_information_request()?;
    let info = exchange(
        nrppa::ID_POSITIONING_INFORMATION_EXCHANGE,
        txn.0,
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
            Ok(c) => c.nrppa_wait(nrppa::ID_MEASUREMENT, txn.0),
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
                    let pci = trps
                        .iter()
                        .find(|(n, info)| *n == m.node && info.trp_id == h.trp_id)
                        .and_then(|(_, info)| info.pci);
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
