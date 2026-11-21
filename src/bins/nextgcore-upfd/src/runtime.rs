//! The UPF's running tasks (#2208): moved out of `main.rs` unchanged, so the
//! binary and an in-process test (another crate's, through this library) start
//! the same ones over one PFCP server and one data plane: the report forwarding
//! toward the CP function, heartbeats, N3 path management, the optional GTP-U path
//! QoS, per QoS flow and N6 delay measurements, the data plane, the PFCP server,
//! the apply of its session events, and the URR checks.

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::data_plane::{self, DataPlane};
use crate::n6_delay;
use crate::pfcp_path::{PfcpServer, PfcpSessionEvent};

/// Where N6 traffic goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N6 {
    /// The data plane's TUN device (the binary).
    Tun,
    /// A file descriptor in its place (an in-process test's datagram socket):
    /// uplink IP packets are written to it, downlink ones read from it.
    Fd(RawFd),
    /// No data plane task (`--no-dataplane`).
    Disabled,
}

/// What [`start`] runs besides the always-on tasks.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeOptions {
    pub n6: N6,
    /// GTP-U path QoS monitoring (#1389), its probe interval.
    pub path_qos_probe_interval: Option<Duration>,
    /// Per QoS flow QoS monitoring (#1389 part 3): its probe interval, and
    /// whether the clocks are synchronised.
    pub qos_flow_monitoring: Option<(Duration, bool)>,
    /// N6 delay measurement (#1389 part 2), its probe interval.
    pub n6_delay_probe_interval: Option<Duration>,
}

/// The tasks [`start`] spawned that [`Runtime::abort`] stops (the optional
/// measurement tasks end with `shutdown`, as they always did).
pub struct Runtime {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Runtime {
    /// Stop the tasks.
    pub fn abort(&self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

/// Start the UPF's tasks over `pfcp_server` and `data_plane`, applying the
/// session events of `pfcp_session_rx` (the server's channel).
pub fn start(
    pfcp_server: Arc<PfcpServer>,
    data_plane: Arc<DataPlane>,
    pfcp_session_rx: tokio::sync::mpsc::Receiver<PfcpSessionEvent>,
    shutdown: Arc<AtomicBool>,
    opts: RuntimeOptions,
) -> Runtime {
    // Let the PFCP server read final URR counters on session deletion
    pfcp_server.set_data_plane(data_plane.clone());
    // #2287: and know which session events are in effect, so it answers a Session
    // Establishment, Modification or Deletion only once its change is applied.
    let (events_applied, applied_events) = crate::pfcp_path::applied_events();
    pfcp_server.set_applied_events(applied_events);

    // Data plane → PFCP report channel (Downlink Data Reports on first
    // buffered packet, Error Indication Reports from GTP-U)
    let (report_tx, mut report_rx) = tokio::sync::mpsc::channel::<data_plane::UpfReportEvent>(100);
    data_plane.set_report_channel(report_tx);
    let pfcp_for_reports = pfcp_server.clone();
    let report_handle = tokio::spawn(async move {
        while let Some(event) = report_rx.recv().await {
            match event {
                data_plane::UpfReportEvent::DownlinkDataReport {
                    upf_seid,
                    smf_seid,
                    pdr_id,
                    qfi,
                } => {
                    if let Err(e) = pfcp_for_reports
                        .send_downlink_data_report(upf_seid, smf_seid, pdr_id, qfi)
                        .await
                    {
                        log::error!("Failed to send Downlink Data Report: {e}");
                    }
                }
                data_plane::UpfReportEvent::ErrorIndicationReport {
                    upf_seid,
                    smf_seid,
                    remote_teid,
                    peer,
                } => {
                    if let Err(e) = pfcp_for_reports
                        .send_error_indication_report(upf_seid, smf_seid, remote_teid, peer)
                        .await
                    {
                        log::error!("Failed to send Error Indication Report: {e}");
                    }
                }
                // #80: a quota exhausted on the forwarding path. Reported IMMEDIATELY
                // rather than waiting for the 10-second harvest, because TS 29.244
                // §5.2.2.2.2 has the UP function report when the quota is exhausted --
                // and for online charging the moment a subscriber is cut off is the one
                // moment the CP function needs promptly. The harvest still reports it as
                // a backstop if this event is dropped (the URR's `threshold_exceeded` is
                // also set), so the report cannot be lost, only duplicated -- and a
                // duplicate carries its own UR-SEQN, which is what §8.2.60 exists for.
                // #935: N3 path failure/recovery -> PFCP Node Report (§7.4.5.1).
                // #1389: GTP-U path QoS -> PFCP Node Report with GPQR (§5.24.5.2).
                data_plane::UpfReportEvent::PathQosReport { reports } => {
                    if let Err(e) = pfcp_for_reports.send_gtpu_path_qos_report(&reports).await {
                        log::warn!("GTP-U path QoS report was NOT sent: {e}");
                    }
                }
                // #1389 part 2: N6 delay -> PFCP Node Report with N6DR (§5.33.8.3).
                data_plane::UpfReportEvent::N6DelayReport { reports } => {
                    if let Err(e) = pfcp_for_reports.send_n6_delay_report(&reports).await {
                        log::warn!("N6 delay measurement report was NOT sent: {e}");
                    }
                }
                // #1389 part 3: per QoS flow QoS monitoring -> PFCP Session Report
                // with SESR (§5.24.4.3).
                data_plane::UpfReportEvent::QosMonitoringReport { upf_seid, reports } => {
                    if let Err(e) = pfcp_for_reports
                        .send_qos_monitoring_report(upf_seid, &reports)
                        .await
                    {
                        log::warn!("QoS monitoring report was NOT sent: {e}");
                    }
                }
                data_plane::UpfReportEvent::PathReport { failure, peers } => {
                    if let Err(e) = pfcp_for_reports.send_node_report(failure, &peers).await {
                        log::warn!("User-plane path report for {peers:?} was NOT sent: {e}");
                    }
                }
                data_plane::UpfReportEvent::QuotaExhausted {
                    upf_seid,
                    smf_seid,
                    urr_id,
                } => {
                    if let Err(e) = pfcp_for_reports
                        .send_quota_exhausted_report(upf_seid, smf_seid, urr_id)
                        .await
                    {
                        log::error!("Failed to send quota-exhausted Usage Report: {e}");
                    }
                }
            }
        }
    });

    // UPF-initiated PFCP heartbeats toward the associated CP function
    // (TS 29.244 6.2.2: either node may initiate heartbeats)
    let pfcp_for_hb = pfcp_server.clone();
    let shutdown_hb = shutdown.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            if shutdown_hb.load(Ordering::SeqCst) {
                break;
            }
            if pfcp_for_hb.is_associated().await {
                // Close the PREVIOUS round first: whatever was sent last tick
                // has had a full interval to be answered, so anything still
                // outstanding is a miss. Three consecutive misses declare the
                // peer down (TS 23.007 Section 19A). Without this the heartbeat
                // was fire-and-forget and a silently dead CP function was never
                // detected.
                pfcp_for_hb.close_heartbeat_round().await;
                if pfcp_for_hb.is_associated().await {
                    pfcp_for_hb.send_heartbeat_request().await;
                }
            }
        }
    });
    // GTP-U N3 path management (upfd-04): periodic Echo Request / path-failure detection
    let dp_for_path = data_plane.clone();
    let path_mgmt_handle = tokio::spawn(async move {
        dp_for_path.run_path_management().await;
    });
    // #1389: GTP-U path QoS monitoring probes, only when the operator enabled it.
    if let Some(interval) = opts.path_qos_probe_interval {
        let dp_for_qos = data_plane.clone();
        tokio::spawn(async move {
            dp_for_qos.run_path_qos_monitoring(interval).await;
        });
    }

    // #1389 part 3: the QoS Monitoring Packet rounds, only when the operator
    // enabled per QoS flow monitoring.
    if let Some((interval, qos_flow_clock_synced)) = opts.qos_flow_monitoring {
        data_plane.set_qos_flow_clock_synced(qos_flow_clock_synced);
        let dp_for_qfm = data_plane.clone();
        tokio::spawn(async move {
            dp_for_qfm.run_qos_flow_monitoring(interval).await;
        });
    }

    // #1389 part 2: the STAMP Session-Sender, only when the operator enabled N6
    // delay measurement. It needs no TUN data plane.
    if let Some(interval) = opts.n6_delay_probe_interval {
        let dp_for_n6 = data_plane.clone();
        tokio::spawn(async move {
            n6_delay::run_n6_delay_measurement(dp_for_n6, interval).await;
        });
    }

    let data_plane_handle = match opts.n6 {
        N6::Disabled => None,
        n6 => {
            log::info!("Starting data plane task...");
            let dp_clone = data_plane.clone();
            Some(tokio::spawn(async move {
                log::info!("Data plane task spawned, calling run()");
                let result = match n6 {
                    N6::Fd(fd) => dp_clone.run_on(fd).await,
                    _ => dp_clone.run().await,
                };
                if let Err(e) = result {
                    log::error!("Data plane error: {e}");
                }
                log::info!("Data plane task finished");
            }))
        }
    };

    // Run PFCP server
    log::info!("Starting PFCP server task...");
    let pfcp_server_clone = pfcp_server.clone();
    let pfcp_server_handle = tokio::spawn(async move {
        log::info!("PFCP server task spawned");
        if let Err(e) = pfcp_server_clone.run().await {
            log::error!("PFCP server error: {e}");
        }
        log::info!("PFCP server task finished");
    });

    // Run PFCP session event handler (connects PFCP to data plane)
    log::info!("Starting PFCP session event handler...");
    let dp_for_pfcp = data_plane.clone();
    let shutdown_events = shutdown.clone();
    let mut pfcp_session_rx = pfcp_session_rx;
    let pfcp_event_handle = tokio::spawn(async move {
        log::info!("PFCP session event handler started");
        while let Some(event) = pfcp_session_rx.recv().await {
            if shutdown_events.load(Ordering::SeqCst) {
                break;
            }
            #[cfg(any(test, feature = "test-support"))]
            if let Some(d) = dp_for_pfcp.apply_delay_for_test() {
                tokio::time::sleep(d).await;
            }
            crate::handle_pfcp_session_event(&dp_for_pfcp, event).await;
            events_applied.mark_applied();
        }
        log::info!("PFCP session event handler finished");
    });

    // Run URR threshold check task (periodic usage report generation)
    log::info!("Starting URR threshold check task...");
    let dp_for_urr = data_plane.clone();
    let pfcp_for_urr = pfcp_server.clone();
    let shutdown_urr = shutdown.clone();
    let urr_check_handle = tokio::spawn(async move {
        // #772: every second, so a periodic report goes out within 1 s of its period
        // boundary (it was up to 10 s, and the old reset-anchored check added that
        // lateness to every following period). Detection is a read of atomics and one
        // instant per URR; nothing is taken unless a report is due.
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if shutdown_urr.load(Ordering::SeqCst) {
                break;
            }
            // #821: detect here, TAKE inside the PFCP server while it holds the session,
            // so a Session Deletion cannot slip between the take and the send.
            for (upf_seid, smf_seid) in dp_for_urr.due_urr_sessions() {
                match pfcp_for_urr.send_due_urr_reports(upf_seid, smf_seid).await {
                    Ok(0) => {}
                    Ok(n) => log::info!("Sent {n} URR reports for SEID={upf_seid:#x}"),
                    // The usage was handed back to its URRs (#780 m2).
                    Err(e) => log::error!("Failed to send URR report: {e}"),
                }
            }
        }
    });

    // Main async event loop (control plane)

    let mut handles = vec![
        pfcp_server_handle,
        pfcp_event_handle,
        urr_check_handle,
        report_handle,
        heartbeat_handle,
        path_mgmt_handle,
    ];
    handles.extend(data_plane_handle);
    Runtime { handles }
}
