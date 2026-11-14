//! N6 delay measurement and reporting, the SMF half (#1502).
//!
//! TS 23.501 §5.8.2.23: *"The SMF may also trigger the N6 delay measurement based on
//! local configuration ... The SMF requests the candidate UPF(s) (via N4 association
//! procedures ...) to perform the N6 delay measurement between the UPF and
//! measurement endpoint and to report the N6 delay measurement to SMF."* upfd already
//! measures and reports (#1389, UN6DM). Until this module, no SMF in the tree asked it
//! to, and the N6DR Node Reports were answered and thrown away.
//!
//! - **Provisioning** (TS 29.244 §5.33.8.2): the SMF may ask only a UPF *"known to
//!   support N6 delay measurement and reporting (e.g. using the UP Function IE)"*. An
//!   SMF-initiated Association Setup learns UN6DM only from the response, so the N6
//!   Delay Measurement Control Information instances go in the **Association Update
//!   Request** sent right after every successful Association Setup whose response
//!   advertises UN6DM. A re-association re-provisions; a UPF without UN6DM is asked
//!   nothing.
//! - **Configuration**: `smf.n6_delay_measurement`, absent by default. Absent means no
//!   Association Update, no change to any N4 message, and no new metric family. The
//!   endpoints come from local configuration. EAS Deployment Information from an AF
//!   (TS 23.548 §6.2.3.4) is not modelled.
//! - **Reports** (§5.33.8.3, Table 7.4.5.1.8-1): an N6DR Node Report carries one N6
//!   Delay Measurement Report IE per endpoint. Each one holds a one-way measurement
//!   (average, optional min and max, in ms) or a failure. The latest per (UPF, endpoint)
//!   is kept, exported as `smf_n6_delay_ms{upf,endpoint,stat}`, and failures are
//!   counted in `smf_n6_delay_failures_total{upf,endpoint}`. Losing the association
//!   drops that UPF's results.
//! - **No consumer** is added here. The SMF *may* use the result for PSA UPF
//!   (re)selection or EAS (re)discovery (TS 23.548 §6.2.3.2). Neither is implemented.
//!
//! **Security, a labelled departure.** TS 33.501 clause T.5 says the measurement
//! protocol should be authenticated, integrity protected and replay protected. upfd
//! implements only unauthenticated STAMP, and this SMF requests no security mode. A
//! configured block therefore logs a startup WARN that names the departure. The
//! feature is opt-in by configuration only.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use bytes::{Bytes, BytesMut};
use nextgcore_pfcp::ie::{IeType, RawIe};
use nextgcore_pfcp::message::{AssociationUpdateRequest, AssociationUpdateResponse};
use nextgcore_pfcp::qos_monitoring::{
    MeasurementEndpointAddress, MeasurementEndpointPortNumber, MeasurementReportingType,
    N6DelayMeasurementControlInformation, N6DelayMeasurementProtocols, N6DelayMeasurementReport,
    Timer, TypedIe,
};
use nextgcore_pfcp::types::{NodeId, PfcpCause};
use serde::Deserialize;

use crate::pfcp_path::{pfcp_message_type, PfcpClient};

/// The Network Instance used when the block names none: the DNN the shipped
/// configurations serve.
pub const DEFAULT_NETWORK_INSTANCE: &str = "internet";

// ============================================================================
// Configuration
// ============================================================================

/// `smf.n6_delay_measurement`, as written in the YAML.
///
/// `deny_unknown_fields`: a mistyped key would otherwise leave a measurement silently
/// unconfigured.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct N6DelayYaml {
    /// The measurement endpoints in the DN, each an IPv4 or IPv6 address, with an
    /// optional STAMP Session-Reflector port (the UPF uses 862 when none is given).
    pub endpoints: Vec<EndpointYaml>,
    /// The Network Instance the UPF reaches the endpoints through.
    #[serde(default)]
    pub network_instance: Option<String>,
    /// The measurement protocol: `stamp`, the only one upfd implements.
    #[serde(default)]
    pub protocol: Option<String>,
    /// Any of `immediate`, `periodic` and `event`. `periodic` and `event` exclude each
    /// other (§5.33.8.2).
    pub reporting: Vec<String>,
    /// Measurement Period in seconds, required with `periodic`.
    #[serde(default)]
    pub period: Option<u32>,
    /// Event-triggered thresholds, one-way delay in ms.
    #[serde(default)]
    pub thresholds: Option<ThresholdsYaml>,
    /// Minimum wait time between two event reports, in seconds.
    #[serde(default)]
    pub minimum_wait_time: Option<u32>,
}

/// One measurement endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointYaml {
    pub address: String,
    #[serde(default)]
    pub port: Option<u16>,
}

/// Event-triggered reporting thresholds, ms.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdsYaml {
    #[serde(default)]
    pub average: Option<u32>,
    #[serde(default)]
    pub minimum: Option<u32>,
    #[serde(default)]
    pub maximum: Option<u32>,
}

/// The validated configuration: the IE 355 instances this SMF provisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N6DelayConfig {
    pub instances: Vec<N6DelayMeasurementControlInformation>,
}

/// The Minimum Waiting Time as a Timer IE (TS 29.244 §8.2.35, TS 24.008 GPRS Timer
/// units): the smallest unit that holds `secs` in 5 bits, rounded up.
pub fn timer_for_secs(secs: u32) -> Result<Timer, String> {
    const UNITS: [(u8, u32); 5] = [(0, 2), (1, 60), (2, 600), (3, 3600), (4, 36_000)];
    for (unit, step) in UNITS {
        let value = secs.div_ceil(step);
        if value <= 31 {
            return Ok(Timer {
                unit,
                value: value as u8,
            });
        }
    }
    Err(format!(
        "minimum_wait_time {secs} s exceeds the Timer IE range (310 hours)"
    ))
}

impl N6DelayYaml {
    /// Validate the block into the IE 355 instances. Endpoints that share a port (or
    /// that name none) share one instance, because the port is per instance (Protocol
    /// Specific Configuration Parameters, IE 378). Instance IDs are 1, 2, ... in port
    /// order.
    pub fn validate(self) -> Result<N6DelayConfig, String> {
        const W: &str = "smf.n6_delay_measurement";
        if self.endpoints.is_empty() {
            return Err(format!("{W}: no endpoints"));
        }
        match self.protocol.as_deref().map(str::to_ascii_lowercase) {
            None => {}
            Some(p) if p == "stamp" => {}
            Some(p) => {
                return Err(format!(
                    "{W}: protocol {p:?} is not supported; only \"stamp\" is"
                ))
            }
        }
        let mut reporting = MeasurementReportingType::default();
        for r in &self.reporting {
            match r.to_ascii_lowercase().as_str() {
                "immediate" => reporting.ire = true,
                "periodic" => reporting.per = true,
                "event" => reporting.evt = true,
                other => {
                    return Err(format!(
                        "{W}: reporting {other:?} is not one of immediate, periodic, event"
                    ))
                }
            }
        }
        if !(reporting.ire || reporting.per || reporting.evt) {
            return Err(format!("{W}: reporting names no type"));
        }
        // §5.33.8.2: "Periodic reporting and event triggered reporting shall be
        // exclusive from each other."
        if reporting.per && reporting.evt {
            return Err(format!("{W}: periodic and event reporting are exclusive"));
        }
        let period = match (reporting.per, self.period) {
            (true, Some(0)) | (true, None) => {
                return Err(format!(
                    "{W}: periodic reporting needs a period of 1 s or more"
                ))
            }
            (true, Some(p)) => Some(p),
            (false, Some(_)) => {
                return Err(format!(
                    "{W}: period is only meaningful with periodic reporting"
                ))
            }
            (false, None) => None,
        };
        let thresholds = self.thresholds.unwrap_or_default();
        let any_threshold = thresholds.average.is_some()
            || thresholds.minimum.is_some()
            || thresholds.maximum.is_some();
        if !reporting.evt && (any_threshold || self.minimum_wait_time.is_some()) {
            return Err(format!(
                "{W}: thresholds and minimum_wait_time are only meaningful with event reporting"
            ));
        }
        let minimum_waiting_time = self.minimum_wait_time.map(timer_for_secs).transpose()?;
        let network_instance = self
            .network_instance
            .unwrap_or_else(|| DEFAULT_NETWORK_INSTANCE.to_string());
        if network_instance.is_empty() {
            return Err(format!("{W}: network_instance is empty"));
        }

        let mut by_port: BTreeMap<Option<u16>, Vec<MeasurementEndpointAddress>> = BTreeMap::new();
        for e in &self.endpoints {
            let addr: IpAddr = e
                .address
                .trim()
                .parse()
                .map_err(|_| format!("{W}: endpoint {:?} is not an IP address", e.address))?;
            let mea = match addr {
                IpAddr::V4(v4) => MeasurementEndpointAddress {
                    ipv4: Some(v4.octets()),
                    ipv6: None,
                },
                IpAddr::V6(v6) => MeasurementEndpointAddress {
                    ipv4: None,
                    ipv6: Some(v6.octets()),
                },
            };
            let list = by_port.entry(e.port).or_default();
            if list.contains(&mea) {
                return Err(format!("{W}: endpoint {addr} is listed twice"));
            }
            list.push(mea);
        }

        let stamp = N6DelayMeasurementProtocols {
            stamp: true,
            ..Default::default()
        };
        let instances = by_port
            .into_iter()
            .zip(1u16..)
            .map(|((port, addrs), id)| N6DelayMeasurementControlInformation {
                id,
                measurement_endpoint_addresses: addrs,
                network_instance: network_instance.as_bytes().to_vec(),
                measurement_protocols: vec![stamp],
                measurement_reporting_type: reporting,
                measurement_period: period,
                average_packet_delay_threshold: thresholds.average,
                minimum_packet_delay_threshold: thresholds.minimum,
                maximum_packet_delay_threshold: thresholds.maximum,
                minimum_waiting_time,
                extra: port.map(stamp_port_parameters).into_iter().collect(),
            })
            .collect();
        Ok(N6DelayConfig { instances })
    }
}

/// Protocol Specific Configuration Parameters (IE 378) for STAMP naming the
/// Session-Reflector port: the protocol (IE 354) it applies to, then the Measurement
/// Endpoint Port Number (IE 379).
fn stamp_port_parameters(port: u16) -> RawIe {
    let mut value = BytesMut::new();
    N6DelayMeasurementProtocols {
        stamp: true,
        ..Default::default()
    }
    .encode_ie(&mut value);
    MeasurementEndpointPortNumber(port).encode_ie(&mut value);
    RawIe::new(
        IeType::ProtocolSpecificConfigurationParameters as u16,
        value.freeze(),
    )
}

/// The process-wide configuration, set once at startup.
static CONFIG: RwLock<Option<Arc<N6DelayConfig>>> = RwLock::new(None);

/// The latest result per (UPF key, endpoint).
static RESULTS: Mutex<BTreeMap<(String, IpAddr), Measured>> = Mutex::new(BTreeMap::new());

/// Failure reports per (UPF key, endpoint) since startup.
static FAILURES: Mutex<BTreeMap<(String, IpAddr), u64>> = Mutex::new(BTreeMap::new());

/// Serialises the tests that touch [`CONFIG`], [`RESULTS`] or [`FAILURES`]. Taken after
/// `PROCESS_STATE_TEST_LOCK` and `N4_TEST_LOCK`, never before them.
#[cfg(test)]
pub(crate) static N6_TEST_LOCK: crate::context::TestLock = crate::context::TestLock::new();

/// Install the startup configuration (or clear it).
pub fn set_config(config: Option<N6DelayConfig>) {
    if let Some(c) = &config {
        log::warn!(
            "N6 delay measurement configured: {} endpoint(s) in {} instance(s), unauthenticated \
             STAMP (a departure from TS 33.501 clause T.5, which asks for authentication, \
             integrity and replay protection)",
            c.instances
                .iter()
                .map(|i| i.measurement_endpoint_addresses.len())
                .sum::<usize>(),
            c.instances.len()
        );
    }
    *CONFIG.write().unwrap_or_else(|e| e.into_inner()) = config.map(Arc::new);
}

fn config() -> Option<Arc<N6DelayConfig>> {
    CONFIG.read().unwrap_or_else(|e| e.into_inner()).clone()
}

// ============================================================================
// Provisioning
// ============================================================================

/// The Association Update Request body (TS 29.244 Table 7.4.4.3-1) carrying this
/// SMF's Node ID and the IE 355 instances.
pub fn update_request_body(node_id: &NodeId, config: &N6DelayConfig) -> BytesMut {
    let mut body = BytesMut::new();
    AssociationUpdateRequest {
        node_id: node_id.clone(),
        up_function_features: None,
        cp_function_features: None,
        pfcp_association_release_request: None,
        graceful_release_period: None,
    }
    .encode(&mut body);
    for instance in &config.instances {
        instance.encode_ie(&mut body);
    }
    body
}

/// What [`provision`] did, for the caller's log and the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provisioned {
    /// No `smf.n6_delay_measurement` block.
    NotConfigured,
    /// The UPF does not advertise UN6DM, so nothing was asked.
    NotSupported,
    /// The UPF accepted the Association Update.
    Accepted,
    /// The UPF answered with another cause, or not at all.
    Failed,
}

/// Ask a newly associated UPF to measure N6 delay (§5.33.8.2), if configured and the
/// UPF advertised UN6DM. Called after every successful Association Setup. A failure
/// is logged and never fails the association: N6 delay measurement is optional, and
/// the sessions do not depend on it.
pub async fn provision(client: &PfcpClient) -> Provisioned {
    let Some(config) = config() else {
        return Provisioned::NotConfigured;
    };
    let un6dm = client
        .association()
        .await
        .up_function_features
        .is_some_and(|f| f.un6dm);
    if !un6dm {
        log::info!(
            "UPF {} does not advertise UN6DM: N6 delay measurement not requested",
            client.peer()
        );
        return Provisioned::NotSupported;
    }
    let body = update_request_body(client.node_id(), &config);
    let answer = client
        .request(pfcp_message_type::ASSOCIATION_UPDATE_REQUEST, None, &body)
        .await;
    match answer {
        Ok((pfcp_message_type::ASSOCIATION_UPDATE_RESPONSE, resp)) => {
            let mut b = Bytes::copy_from_slice(&resp);
            match AssociationUpdateResponse::decode(&mut b) {
                Ok(r) if r.cause == PfcpCause::RequestAccepted => {
                    log::info!(
                        "UPF {} accepted N6 Delay Measurement Control Information x{} \
                         (Association Update, TS 29.244 §5.33.8.2)",
                        client.peer(),
                        config.instances.len()
                    );
                    Provisioned::Accepted
                }
                Ok(r) => {
                    log::warn!(
                        "UPF {} refused the N6 delay measurement Association Update: cause {}",
                        client.peer(),
                        r.cause as u8
                    );
                    Provisioned::Failed
                }
                Err(e) => {
                    log::warn!(
                        "UPF {}: malformed Association Update Response: {e}",
                        client.peer()
                    );
                    Provisioned::Failed
                }
            }
        }
        Ok((other, _)) => {
            log::warn!(
                "UPF {}: unexpected response type {other} to the N6 delay measurement \
                 Association Update",
                client.peer()
            );
            Provisioned::Failed
        }
        Err(e) => {
            log::warn!(
                "UPF {}: N6 delay measurement Association Update failed: {e}",
                client.peer()
            );
            Provisioned::Failed
        }
    }
}

// ============================================================================
// Reports
// ============================================================================

/// The latest one-way N6 delay reported for an endpoint, ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    pub average_ms: u32,
    pub minimum_ms: Option<u32>,
    pub maximum_ms: Option<u32>,
}

fn endpoint_ip(a: &MeasurementEndpointAddress) -> Option<IpAddr> {
    a.ipv4
        .map(IpAddr::from)
        .or_else(|| a.ipv6.map(|v6| IpAddr::from(v6).to_canonical()))
}

/// Store the N6 Delay Measurement Reports of one Node Report from the UPF `upf_key`.
pub fn on_reports(upf_key: &str, reports: &[N6DelayMeasurementReport]) {
    for r in reports {
        let Some(ip) = endpoint_ip(&r.measurement_endpoint_address) else {
            continue;
        };
        let key = (upf_key.to_string(), ip);
        if let Some(info) = r.information {
            let m = Measured {
                average_ms: info.average_packet_delay,
                minimum_ms: info.minimum_packet_delay,
                maximum_ms: info.maximum_packet_delay,
            };
            log::info!(
                "UPF {upf_key}: N6 delay to {ip}: avg {} ms{}{}",
                m.average_ms,
                m.minimum_ms
                    .map(|v| format!(", min {v} ms"))
                    .unwrap_or_default(),
                m.maximum_ms
                    .map(|v| format!(", max {v} ms"))
                    .unwrap_or_default()
            );
            RESULTS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, m);
        } else if let Some(f) = r.failure_information {
            log::warn!(
                "UPF {upf_key}: N6 delay measurement to {ip} failed: cause {}",
                f.effective_cause()
            );
            // The last value is no longer current: drop it rather than export it.
            RESULTS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            *FAILURES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(key)
                .or_default() += 1;
        }
    }
}

/// Forget the results of the UPF `upf_key` (its association is gone).
pub fn forget_upf(upf_key: &str) {
    RESULTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(upf, _), _| upf != upf_key);
}

/// Decode the N6 Delay Measurement Report IEs (type 356) of a Node Report body.
/// `Err((cause, 356))` when there is none, or when one does not decode or carries
/// neither a measurement nor a failure (Table 7.4.5.1.8-1 NOTE: exactly one).
pub fn parse_reports(
    ies: &[(u16, &[u8])],
    conditional_missing: u8,
    incorrect: u8,
) -> Result<Vec<N6DelayMeasurementReport>, (u8, u16)> {
    const IE: u16 = IeType::N6DelayMeasurementReport as u16;
    let mut out = Vec::new();
    for (t, v) in ies {
        if *t != IE {
            continue;
        }
        let r = N6DelayMeasurementReport::decode_value(v).map_err(|_| (incorrect, IE))?;
        if r.information.is_some() == r.failure_information.is_some() {
            return Err((incorrect, IE));
        }
        out.push(r);
    }
    if out.is_empty() {
        return Err((conditional_missing, IE));
    }
    Ok(out)
}

/// Append the N6 delay families to `/metrics`. Nothing at all unless the block is
/// configured or a UPF reported, so an unconfigured SMF's metrics are unchanged.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let failures = FAILURES.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if config().is_none() && results.is_empty() && failures.is_empty() {
        return;
    }
    nextgcore_metrics::nf::write_header(
        out,
        "smf_n6_delay_ms",
        "gauge",
        "Latest one-way N6 delay a UPF reported toward a measurement endpoint, ms (TS 29.244 §5.33.8.3)",
    );
    for ((upf, ip), m) in &results {
        for (stat, v) in [
            ("avg", Some(m.average_ms)),
            ("min", m.minimum_ms),
            ("max", m.maximum_ms),
        ] {
            if let Some(v) = v {
                let _ = writeln!(
                    out,
                    "smf_n6_delay_ms{{upf=\"{upf}\",endpoint=\"{ip}\",stat=\"{stat}\"}} {v}"
                );
            }
        }
    }
    nextgcore_metrics::nf::write_header(
        out,
        "smf_n6_delay_failures_total",
        "counter",
        "N6 delay measurement failures a UPF reported toward a measurement endpoint",
    );
    for ((upf, ip), n) in &failures {
        let _ = writeln!(
            out,
            "smf_n6_delay_failures_total{{upf=\"{upf}\",endpoint=\"{ip}\"}} {n}"
        );
    }
}

/// Test only: clear the configuration and every result.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    set_config(None);
    RESULTS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    FAILURES.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Test only: the stored result for (UPF key, endpoint).
#[cfg(test)]
pub(crate) fn result_for_test(upf_key: &str, ip: IpAddr) -> Option<Measured> {
    RESULTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(upf_key.to_string(), ip))
        .copied()
}

#[cfg(test)]
#[path = "n6_delay_tests.rs"]
mod tests;
