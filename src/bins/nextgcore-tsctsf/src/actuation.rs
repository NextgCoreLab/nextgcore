//! Actuation: making a stored TSCTSF configuration *do* something (issue #284).
//!
//! #113 delivered the control plane — three conformant services, typed IEs,
//! ConfigUpdate, the capability subscribe/notify/unsubscribe cycle. Nothing read
//! those records outside the SBI handlers, so an AF request produced a stored
//! record with no policy or user-plane effect at all.
//!
//! This module is the half that reads them:
//!
//! 1. **A pure derivation** from a stored configuration to the port- and
//!    bridge-management information the 5GS needs ([`derive_tsn_management`]),
//!    and from a QoS/TSC session to the TSC Assistance Information a PCF
//!    consumes ([`derive_tscai`]). Pure, so it is testable with no peer at all,
//!    which is where most of the value is.
//! 2. **A PCF client** that turns a create into `Npcf_PolicyAuthorization_Create`
//!    and a delete into the matching delete (TS 23.502 §5.2.27, TS 29.514).
//! 3. **A capability source**: the derived capability set is recomputed on every
//!    configuration change, and a change in it drives `CapsNotify` — replacing
//!    #113's administrative poke with something the deployment actually knows.
//!
//! # Off by default, behind a RUNTIME switch
//!
//! Gated on `TSCTSF_ACTUATION=1`. A runtime switch rather than a cargo feature
//! for this project's recorded reason (a feature-gated path is left uncompiled by
//! CI and rots), and **off by default** because a create that silently issues
//! policy toward a PCF is behaviour-changing for every existing deployment. With
//! the switch off, the control-plane behaviour is byte-identical to #113 and no
//! outbound request is made; `the_switch_off_makes_no_outbound_request` asserts
//! it.
//!
//! # What TS 29.514 requires that a time-sync configuration does not carry
//!
//! `AppSessionContextReqData` has exactly the members this needs —
//! `tsnPortManContDstt`, `tsnPortManContNwtts` (an array), `tsnBridgeManCont`
//! ("Contains the UMIC"), `tscNotifUri`, `tscNotifCorreId`, `supi` — and it
//! **also** requires `oneOf [ueIpv4, ueIpv6, ueMac]`.
//!
//! A TS 23.502 §5.2.27.2.2 time-synchronization configuration carries SUPIs and a
//! user-plane node id. It carries **no UE address**. So a time-sync create cannot
//! build a conformant `AppSessionContextReqData` from its mandatory inputs alone,
//! and #284's criterion 2 is not literally satisfiable for every such create.
//!
//! Rather than send a body that violates the schema, or invent an address, this
//! reads an optional UE address from the configuration when the consumer supplies
//! one (`ueMac`, `ueIpv4` or `ueIpv6` — a DS-TT behind an Ethernet PDU session has
//! a MAC, which is the TS 23.501 §5.28 case) and **declines to actuate with a
//! named reason** when it does not. A QoS/TSC session, by contrast, carries
//! `ueIpv4`/`ueIpv6` as a mandated input, so its actuation is unconditional.
//!
//! As in #113, `TS29565_Ntsctsf_*.yaml` is not vendored here, so the added
//! optional member names are the camelCase form of the Stage-2 parameter names
//! rather than a spelling verified against the Stage-3 schema.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::context::{ClockQualityAcceptanceCriteria, QosTscSession, TimeSyncExposureConfig};

/// Is actuation enabled for this process?
static ACTUATION_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable actuation (called once at startup when `TSCTSF_ACTUATION=1`).
pub fn enable() {
    ACTUATION_ENABLED.store(true, Ordering::SeqCst);
    log::info!(
        "[TSCTSF] actuation ENABLED: time-sync and QoS/TSC creates will issue \
         Npcf_PolicyAuthorization toward the serving PCF (TS 23.502 §5.2.27)"
    );
}

/// Whether actuation is enabled.
pub fn enabled() -> bool {
    ACTUATION_ENABLED.load(Ordering::SeqCst)
}

/// Read `TSCTSF_ACTUATION` and enable accordingly. Called once from `main`.
pub fn init_from_env() {
    match std::env::var("TSCTSF_ACTUATION").as_deref() {
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("on") => enable(),
        _ => log::info!(
            "[TSCTSF] actuation DISABLED (set TSCTSF_ACTUATION=1 to enable): stored \
             configurations have no policy or user-plane effect, exactly as before #284"
        ),
    }
}

/// Test-only: set the switch without going through startup.
///
/// The caller must hold [`crate::context::PROCESS_STATE_TEST_LOCK`]: this switch
/// is process-global, so a test that flips it races every sibling that reads it.
#[cfg(test)]
pub fn set_for_test(on: bool) {
    ACTUATION_ENABLED.store(on, Ordering::SeqCst);
}

// ============================================================================
// The pure derivation (criterion 1)
// ============================================================================

/// Which side of the 5GS TSN bridge a port sits on (TS 23.501 §5.28.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsnPortSide {
    /// Device-Side TT: one per UE, facing the TSN end station.
    DeviceSide,
    /// Network-Side TT: the N6 termination, facing the TSN network.
    NetworkSide,
}

/// One port's management information (the PMIC), with the port it applies to.
///
/// `container` is the octet string TS 29.512's `PortManagementContainer.portManCont`
/// carries. **It is this build's own TLV encoding of the managed objects the
/// configuration determines, not the IEEE 802.1Q clause 12 encoding**, because no
/// 802.1Q managed-object codec exists in this tree. The derivation — which objects
/// a given configuration determines, per port and per side — is the part that is
/// specified and testable, and it is what a real encoder would consume. Stated
/// here rather than left for a reader to assume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortManagementInfo {
    /// TS 29.512 `TsnPortNumber`.
    pub port_num: u32,
    /// Which side of the bridge.
    pub side: TsnPortSide,
    /// The PMIC octet string.
    pub container: Vec<u8>,
}

/// Whether a configuration's clock-quality acceptance criteria can ever be met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockQualityVerdict {
    /// The configuration states no criteria, so there is nothing to evaluate.
    /// Not the same as satisfiable: a caller that treats "no criteria" as "all
    /// criteria met" would report success for a configuration that asked for
    /// nothing.
    NoCriteria,
    /// Every stated criterion names a value the 5GS can report.
    Satisfiable,
    /// At least one criterion names a value outside what IEEE 1588-2019 defines,
    /// so no clock can ever satisfy it. Carries every reason, not the first: an
    /// operator fixing one and re-submitting should not have to discover the rest
    /// one round trip at a time.
    Unsatisfiable(Vec<String>),
}

impl ClockQualityVerdict {
    /// Whether actuation should proceed. `NoCriteria` and `Satisfiable` both
    /// proceed; only an impossible criterion stops it.
    pub fn permits_actuation(&self) -> bool {
        !matches!(self, Self::Unsatisfiable(_))
    }
}

/// IEEE 1588-2019 §7.6.2.5 Table 4: the specified `clockClass` values. Everything
/// else in 0..=255 is Reserved, so a criterion naming one can never be met.
const SPECIFIED_CLOCK_CLASSES: [u8; 10] = [6, 7, 13, 14, 52, 58, 187, 193, 248, 255];

/// IEEE 1588-2019 §7.6.2.6 Table 5: `clockAccuracy` enumerates 0x20 (25 ns)
/// through 0x31 (> 10 s), plus 0xFE "unknown". 0x00..=0x1F and 0x32..=0xFD are
/// Reserved, and 0xFF is Reserved — so a criterion demanding better than 0x20 is
/// asking for an accuracy the standard has no way to report.
const CLOCK_ACCURACY_MIN: u8 = 0x20;
const CLOCK_ACCURACY_MAX: u8 = 0x31;
const CLOCK_ACCURACY_UNKNOWN: u8 = 0xFE;

/// The synchronisation states the 5GS reports (TS 23.501 §5.27.1.8).
const SYNC_STATES: [&str; 2] = ["SYNCHRONIZED", "NOT_SYNCHRONIZED"];

/// Evaluate the clock-quality acceptance criteria against what IEEE 1588 can
/// report.
///
/// This is a **static** check, deliberately: it asks whether a criterion is
/// satisfiable at all, not whether the current clock satisfies it. A criterion
/// naming a Reserved `clockClass` or an accuracy finer than the enumeration's
/// best value can never be met by any clock, and answering 201 to it commits the
/// TSCTSF to a service it cannot deliver — the failure mode #284 calls out.
pub fn evaluate_clock_quality(
    criteria: Option<&ClockQualityAcceptanceCriteria>,
) -> ClockQualityVerdict {
    let Some(c) = criteria else {
        return ClockQualityVerdict::NoCriteria;
    };
    if c.clock_class.is_none()
        && c.clock_accuracy.is_none()
        && c.offset_scaled_log_variance.is_none()
        && c.synchronization_state.is_none()
    {
        return ClockQualityVerdict::NoCriteria;
    }

    let mut reasons = Vec::new();
    if let Some(class) = c.clock_class {
        if !SPECIFIED_CLOCK_CLASSES.contains(&class) {
            reasons.push(format!(
                "clockClass {class} is Reserved in IEEE 1588-2019 Table 4 (specified values are \
                 {SPECIFIED_CLOCK_CLASSES:?}), so no clock can report it"
            ));
        }
    }
    if let Some(acc) = c.clock_accuracy {
        let ok = (CLOCK_ACCURACY_MIN..=CLOCK_ACCURACY_MAX).contains(&acc)
            || acc == CLOCK_ACCURACY_UNKNOWN;
        if !ok {
            reasons.push(format!(
                "clockAccuracy {acc:#04x} is outside the IEEE 1588-2019 Table 5 enumeration \
                 ({CLOCK_ACCURACY_MIN:#04x}..={CLOCK_ACCURACY_MAX:#04x}, or \
                 {CLOCK_ACCURACY_UNKNOWN:#04x} for unknown)"
            ));
        }
    }
    if let Some(state) = c.synchronization_state.as_deref() {
        if !SYNC_STATES.contains(&state) {
            reasons.push(format!(
                "synchronizationState '{state}' is not one of {SYNC_STATES:?}"
            ));
        }
    }
    // `offsetScaledLogVariance` is a u16 and every value is representable, so
    // there is nothing here that can be unsatisfiable. Named rather than omitted,
    // so the absence is visibly deliberate.

    if reasons.is_empty() {
        ClockQualityVerdict::Satisfiable
    } else {
        ClockQualityVerdict::Unsatisfiable(reasons)
    }
}

/// Everything a stored time-synchronization configuration determines about the
/// 5GS TSN bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedTsnManagement {
    /// One PMIC per UE in the configuration — each UE's DS-TT port.
    pub dstt_ports: Vec<PortManagementInfo>,
    /// The NW-TT ports: exactly one, for the `upNodeId` this configuration names,
    /// which is the N6 termination.
    pub nwtt_ports: Vec<PortManagementInfo>,
    /// The UMIC — bridge-level managed objects.
    pub bridge_container: Vec<u8>,
    /// Whether the (g)PTP grandmaster is enabled by this configuration. `false`
    /// when `gmEnable` is absent: TS 23.501 §5.27.1.8 makes activation explicit,
    /// so an absent flag is "not activated" rather than "activate by default".
    pub gm_enabled: bool,
    /// Whether the stated clock-quality criteria can ever be met.
    pub clock_quality: ClockQualityVerdict,
}

/// Managed-object tags in the PMIC/UMIC TLV. See [`PortManagementInfo::container`]
/// for what this encoding is and is not.
mod tag {
    /// gPTP instance enabled (1 octet, 0 or 1) — IEEE 802.1AS `ptpInstanceEnable`.
    pub const GM_ENABLE: u8 = 0x01;
    /// Grandmaster priority1 (1 octet) — IEEE 802.1AS `priority1`.
    pub const GM_PRIORITY: u8 = 0x02;
    /// gPTP domain number (2 octets, big endian) — IEEE 802.1AS `domainNumber`.
    pub const TIME_DOMAIN: u8 = 0x03;
    /// PTP profile identifier (UTF-8).
    pub const PTP_PROFILE: u8 = 0x04;
    /// Port side: 0 = DS-TT, 1 = NW-TT.
    pub const PORT_SIDE: u8 = 0x05;
    /// The SUPI this DS-TT port serves (UTF-8).
    pub const SUPI: u8 = 0x06;
    /// The user-plane node this NW-TT port belongs to (UTF-8).
    pub const UP_NODE_ID: u8 = 0x07;
    /// Clock-quality detail level (UTF-8).
    pub const CLOCK_QUALITY_DETAIL: u8 = 0x08;
}

fn tlv(out: &mut Vec<u8>, t: u8, value: &[u8]) {
    // One-octet length: every value here is a flag, a small integer, or an
    // identifier, and truncating silently would encode a different object than
    // the one derived. A value that does not fit is dropped with a warning
    // instead.
    if value.len() > u8::MAX as usize {
        log::warn!(
            "TSN managed object {t:#04x} is {} octets; dropped",
            value.len()
        );
        return;
    }
    out.push(t);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// The managed objects every port in a configuration shares.
fn common_objects(cfg: &TimeSyncExposureConfig, out: &mut Vec<u8>) {
    tlv(
        out,
        tag::GM_ENABLE,
        &[u8::from(cfg.gm_enable.unwrap_or(false))],
    );
    if let Some(p) = cfg.gm_priority {
        tlv(out, tag::GM_PRIORITY, &[p]);
    }
    if let Some(d) = cfg.time_domain {
        tlv(out, tag::TIME_DOMAIN, &d.to_be_bytes());
    }
    if let Some(profile) = cfg.ptp_profile.as_deref() {
        tlv(out, tag::PTP_PROFILE, profile.as_bytes());
    }
    if let Some(detail) = cfg.clock_quality_detail_level.as_deref() {
        tlv(out, tag::CLOCK_QUALITY_DETAIL, detail.as_bytes());
    }
}

/// Derive the port- and bridge-management information a stored
/// time-synchronization configuration determines (TS 23.501 §6.2.29).
///
/// Pure: no peer, no clock, no I/O. That is the point — it can be asserted
/// exactly, and it is where #284 says the value is.
///
/// Port numbering: DS-TT ports are numbered from 1 in the order the SUPIs appear,
/// and the NW-TT port takes 0. TS 29.512 types `TsnPortNumber` as an integer and
/// does not assign it, so *some* rule is needed; this one is stable across
/// derivations of the same configuration, which is what matters when the result is
/// compared to a previously reported one.
pub fn derive_tsn_management(cfg: &TimeSyncExposureConfig) -> DerivedTsnManagement {
    let gm_enabled = cfg.gm_enable.unwrap_or(false);

    let mut dstt_ports = Vec::with_capacity(cfg.supis.len());
    for (idx, supi) in cfg.supis.iter().enumerate() {
        let mut container = Vec::new();
        common_objects(cfg, &mut container);
        tlv(&mut container, tag::PORT_SIDE, &[0]);
        tlv(&mut container, tag::SUPI, supi.as_bytes());
        dstt_ports.push(PortManagementInfo {
            port_num: (idx as u32) + 1,
            side: TsnPortSide::DeviceSide,
            container,
        });
    }

    // Exactly one NW-TT port, for the `upNodeId` the configuration names. A
    // configuration with no SUPIs still has this one: the N6 termination is a
    // property of the user-plane node, not of any UE, which is the asymmetry
    // #284's criterion 1 asks to be covered.
    let mut nwtt = Vec::new();
    common_objects(cfg, &mut nwtt);
    tlv(&mut nwtt, tag::PORT_SIDE, &[1]);
    tlv(&mut nwtt, tag::UP_NODE_ID, cfg.up_node_id.as_bytes());
    let nwtt_ports = vec![PortManagementInfo {
        port_num: 0,
        side: TsnPortSide::NetworkSide,
        container: nwtt,
    }];

    // The UMIC is bridge-level: the common objects, with no port identity.
    let mut bridge_container = Vec::new();
    common_objects(cfg, &mut bridge_container);
    tlv(
        &mut bridge_container,
        tag::UP_NODE_ID,
        cfg.up_node_id.as_bytes(),
    );

    DerivedTsnManagement {
        dstt_ports,
        nwtt_ports,
        bridge_container,
        gm_enabled,
        clock_quality: evaluate_clock_quality(cfg.clock_quality_acceptance_criteria.as_ref()),
    }
}

/// The TSC Assistance Information a QoS/TSC session determines, in the shape
/// TS 29.514 `TscaiInputContainer` defines.
///
/// Returns `None` when the session states no traffic pattern at all: a container
/// with every member absent tells the PCF nothing, and TS 29.514 types the whole
/// container as nullable, so omitting it is the conformant way to say "no pattern"
/// rather than sending `{}`.
pub fn derive_tscai(session: &QosTscSession) -> Option<serde_json::Value> {
    let mut c = serde_json::Map::new();
    if let Some(p) = session.periodicity {
        c.insert("periodicity".to_string(), serde_json::json!(p));
    }
    if let Some(bat) = &session.burst_arrival_time {
        c.insert("burstArrivalTime".to_string(), bat.clone());
    }
    if let Some(s) = session.survival_time {
        // TS 29.514 has two survival-time members: a message count and a
        // duration. Stage-2's single `survivalTime` is a duration, so it maps to
        // `surTimeInTime`; mapping it to the message count would silently change
        // the unit.
        c.insert("surTimeInTime".to_string(), serde_json::json!(s));
    }
    if let Some(w) = &session.bat_window {
        c.insert("burstArrivalTimeWnd".to_string(), w.clone());
    }
    if let Some(r) = &session.periodicity_range {
        c.insert("periodicityRange".to_string(), r.clone());
    }
    if c.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(c))
    }
}

/// Which direction a QoS/TSC session's TSCAI applies to.
///
/// TS 29.514 carries `tscaiInputUl` and `tscaiInputDl` separately, so a session
/// with a stated `flowDirection` populates one and a session without states both
/// — the honest reading of "direction unspecified" being "applies either way",
/// rather than silently picking downlink.
fn tscai_direction_keys(session: &QosTscSession) -> &'static [&'static str] {
    match session.flow_direction.as_deref() {
        Some("UPLINK") => &["tscaiInputUl"],
        Some("DOWNLINK") => &["tscaiInputDl"],
        _ => &["tscaiInputUl", "tscaiInputDl"],
    }
}

// ============================================================================
// The PCF client (criterion 2)
// ============================================================================

/// A resolved PCF endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcfEndpoint {
    pub host: String,
    pub port: u16,
}

/// Resolve the serving PCF: `PCF_URI` first, then NRF discovery, in the same
/// shape `smfd::policy::resolve_pcf_endpoint` uses (#284 names it as the model).
///
/// Discovery asks for `target-nf-type=PCF&requester-nf-type=TSCTSF` and takes the
/// `npcf-policyauthorization` service's endpoint, not the first service in the
/// profile: a PCF advertising several services on different ports would otherwise
/// be dialled on whichever one happened to be listed first.
pub async fn resolve_pcf_endpoint() -> Option<PcfEndpoint> {
    if let Ok(uri) = std::env::var("PCF_URI") {
        if let Some((host, port)) = split_authority(&uri) {
            return Some(PcfEndpoint { host, port });
        }
        log::warn!("PCF_URI '{uri}' is not a usable URI -- ignoring");
    }
    let nrf_uri = nextgcore_sbi::context::global_context()
        .get_nrf_uri()
        .await?;
    let (nrf_host, nrf_port) = split_authority(&nrf_uri)?;
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&nrf_host, nrf_port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );
    let resp = client
        .get("/nnrf-disc/v1/nf-instances?target-nf-type=PCF&requester-nf-type=TSCTSF")
        .await
        .ok()?;
    if resp.status != 200 {
        log::warn!("NRF PCF discovery returned status {}", resp.status);
        return None;
    }
    let body: serde_json::Value = serde_json::from_str(resp.http.content.as_deref()?).ok()?;
    let inst = body.get("nfInstances")?.as_array()?.first()?;
    let host = inst
        .get("ipv4Addresses")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())?
        .to_string();
    let port = inst
        .get("nfServices")
        .and_then(|s| s.as_array())
        .and_then(|svcs| {
            svcs.iter().find(|s| {
                s.get("serviceName").and_then(|n| n.as_str()) == Some("npcf-policyauthorization")
            })
        })
        .and_then(|s| s.get("ipEndPoints"))
        .and_then(|e| e.as_array())
        .and_then(|e| e.first())
        .and_then(|e| e.get("port"))
        .and_then(|p| p.as_u64())
        .map(|p| p as u16)
        .unwrap_or(7777);
    Some(PcfEndpoint { host, port })
}

/// Split a URI or bare authority into host and port.
fn split_authority(uri: &str) -> Option<(String, u16)> {
    let stripped = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let authority = stripped.split('/').next().unwrap_or(stripped);
    let (host, port) = authority.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// `appSessionId` per actuated resource, so a delete can find what a create made.
///
/// A process-global map rather than a member on the stored record: tsctsf has no
/// durable store, so this is exactly as durable as the record it keys, and
/// threading it through `TimeSyncConfig`/`QosTscSession` would put a PCF
/// implementation detail into the types the SBI handlers echo back to consumers.
fn app_sessions() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static MAP: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// The `appSessionId` recorded for `resource_id`, if any.
pub fn app_session_for(resource_id: &str) -> Option<String> {
    app_sessions()
        .lock()
        .ok()
        .and_then(|m| m.get(resource_id).cloned())
}

#[cfg(test)]
pub fn clear_app_sessions_for_test() {
    if let Ok(mut m) = app_sessions().lock() {
        m.clear();
    }
}

/// The UE address a time-synchronization configuration supplies, if any, as the
/// `AppSessionContextReqData` member name it maps to.
///
/// TS 29.514 requires `oneOf [ueIpv4, ueIpv6, ueMac]`, and a TS 23.502 §5.2.27.2.2
/// time-sync configuration has no such mandatory input, so this is read from the
/// optional members and its absence is a reason to decline rather than an error.
fn ue_address_member(cfg: &TimeSyncExposureConfig) -> Option<(&'static str, String)> {
    if let Some(mac) = cfg.ue_mac.as_deref().filter(|m| !m.trim().is_empty()) {
        return Some(("ueMac", mac.to_string()));
    }
    if let Some(v4) = cfg.ue_ipv4.as_deref().filter(|m| !m.trim().is_empty()) {
        return Some(("ueIpv4", v4.to_string()));
    }
    if let Some(v6) = cfg.ue_ipv6.as_deref().filter(|m| !m.trim().is_empty()) {
        return Some(("ueIpv6", v6.to_string()));
    }
    None
}

/// The `AppSessionContext` body for a time-synchronization configuration
/// (TS 29.514 §4.2.2, TS 23.502 §5.2.27).
///
/// Returns the reason it cannot be built rather than a partial body: a request
/// that omits a `oneOf`-required member is a 400 waiting to happen, and getting
/// one back from the PCF would look like a PCF problem.
pub fn build_time_sync_app_session(
    cfg: &TimeSyncExposureConfig,
    derived: &DerivedTsnManagement,
    notif_uri: &str,
) -> Result<serde_json::Value, String> {
    let Some((member, value)) = ue_address_member(cfg) else {
        return Err(
            "TS 29.514 AppSessionContextReqData requires oneOf [ueIpv4, ueIpv6, ueMac] and this \
             time-synchronization configuration supplies none (its mandatory TS 23.502 \
             §5.2.27.2.2 inputs carry SUPIs and a upNodeId, not a UE address)"
                .to_string(),
        );
    };
    if let ClockQualityVerdict::Unsatisfiable(reasons) = &derived.clock_quality {
        return Err(format!(
            "the clock-quality acceptance criteria can never be met, so authorising the service \
             would commit to something undeliverable: {}",
            reasons.join("; ")
        ));
    }

    let mut asc = serde_json::Map::new();
    asc.insert("notifUri".to_string(), serde_json::json!(notif_uri));
    // suppFeat is mandatory. "0" is the honest value: this consumer negotiates no
    // optional feature of TS 29.514, and claiming one it does not implement would
    // make the PCF send responses it cannot read.
    asc.insert("suppFeat".to_string(), serde_json::json!("0"));
    asc.insert(member.to_string(), serde_json::json!(value));
    if let Some(supi) = cfg.supis.first() {
        asc.insert("supi".to_string(), serde_json::json!(supi));
    }
    asc.insert(
        "tsnBridgeManCont".to_string(),
        serde_json::json!({ "bridgeManCont": b64(&derived.bridge_container) }),
    );
    if let Some(dstt) = derived.dstt_ports.first() {
        asc.insert(
            "tsnPortManContDstt".to_string(),
            serde_json::json!({
                "portManCont": b64(&dstt.container),
                "portNum": dstt.port_num,
            }),
        );
    }
    // `tsnPortManContNwtts` has minItems: 1, so it is present only when there is
    // at least one NW-TT port. The derivation always produces exactly one.
    if !derived.nwtt_ports.is_empty() {
        asc.insert(
            "tsnPortManContNwtts".to_string(),
            serde_json::Value::Array(
                derived
                    .nwtt_ports
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "portManCont": b64(&p.container),
                            "portNum": p.port_num,
                        })
                    })
                    .collect(),
            ),
        );
    }
    asc.insert("tscNotifUri".to_string(), serde_json::json!(notif_uri));
    if let Some(id) = cfg.notification_correlation_id.as_deref() {
        asc.insert("tscNotifCorreId".to_string(), serde_json::json!(id));
    }
    Ok(serde_json::json!({ "ascReqData": serde_json::Value::Object(asc) }))
}

/// The `AppSessionContext` body for a QoS/TSC assistance session.
///
/// Unconditional, unlike the time-sync case: TS 23.502 §5.2.27.3.2 makes a UE
/// address (or a GPSI/group id) a required input, so the `oneOf` member is always
/// available for a session that passed `validate`.
pub fn build_qos_tsc_app_session(
    session: &QosTscSession,
    notif_uri: &str,
) -> Result<serde_json::Value, String> {
    let mut asc = serde_json::Map::new();
    asc.insert("notifUri".to_string(), serde_json::json!(notif_uri));
    asc.insert("suppFeat".to_string(), serde_json::json!("0"));
    match (session.ue_ipv4.as_deref(), session.ue_ipv6.as_deref()) {
        (Some(v4), _) if !v4.trim().is_empty() => {
            asc.insert("ueIpv4".to_string(), serde_json::json!(v4));
        }
        (_, Some(v6)) if !v6.trim().is_empty() => {
            asc.insert("ueIpv6".to_string(), serde_json::json!(v6));
        }
        _ => {
            return Err(
                "TS 29.514 AppSessionContextReqData requires oneOf [ueIpv4, ueIpv6, ueMac] and \
                 this session identifies its UE by GPSI or external group id only"
                    .to_string(),
            )
        }
    }
    if let Some(gpsi) = session.gpsi.as_deref() {
        asc.insert("gpsi".to_string(), serde_json::json!(gpsi));
    }

    // One media component carrying the TSC assistance information. `medCompN` is
    // the map key AND a required member of the value (TS 29.514 MediaComponent),
    // so it appears in both places rather than only in the key.
    let mut med = serde_json::Map::new();
    med.insert("medCompN".to_string(), serde_json::json!(0));
    if let Some(qref) = session.qos_reference.as_deref() {
        med.insert("qosReference".to_string(), serde_json::json!(qref));
    }
    if let Some(br) = session.max_br_ul.as_deref() {
        med.insert("marBwUl".to_string(), serde_json::json!(br));
    }
    if let Some(br) = session.max_br_dl.as_deref() {
        med.insert("marBwDl".to_string(), serde_json::json!(br));
    }
    if let Some(tscai) = derive_tscai(session) {
        for key in tscai_direction_keys(session) {
            med.insert((*key).to_string(), tscai.clone());
        }
    }
    if let Some(domain) = session.time_domain {
        med.insert("tscaiTimeDom".to_string(), serde_json::json!(domain));
    }
    asc.insert(
        "medComponents".to_string(),
        serde_json::json!({ "0": serde_json::Value::Object(med) }),
    );
    Ok(serde_json::json!({ "ascReqData": serde_json::Value::Object(asc) }))
}

/// Base64 (standard alphabet, padded) — TS 29.571 `Bytes`.
fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `Npcf_PolicyAuthorization_Create`: POST the app-session context and record the
/// `appSessionId` from the `Location` header against `resource_id`.
///
/// Returns the `appSessionId` on success. Best-effort in the sense that a failure
/// does not fail the consumer's request -- the configuration is stored either way,
/// which is #113's behaviour -- but it is logged at warn with the status, because a
/// deployment that turned actuation ON and is getting silence needs to know.
pub async fn policy_authorization_create(
    resource_id: &str,
    body: &serde_json::Value,
) -> Option<String> {
    let pcf = resolve_pcf_endpoint().await?;
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&pcf.host, pcf.port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );
    let resp = match client
        .post_json("/npcf-policyauthorization/v1/app-sessions", body)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "Npcf_PolicyAuthorization_Create to {}:{} failed: {e}",
                pcf.host,
                pcf.port
            );
            return None;
        }
    };
    if resp.status != 201 {
        log::warn!(
            "Npcf_PolicyAuthorization_Create for {resource_id} returned status {} (expected 201)",
            resp.status
        );
        return None;
    }
    // The appSessionId is the last path segment of Location. Taken from the header
    // rather than from the body: TS 29.514 makes Location the authoritative
    // statement of where the resource lives.
    let app_session_id = resp
        .http
        .get_header("Location")
        .and_then(|l| l.rsplit('/').next())
        .map(str::to_string)?;
    if let Ok(mut m) = app_sessions().lock() {
        m.insert(resource_id.to_string(), app_session_id.clone());
    }
    log::info!("Npcf_PolicyAuthorization_Create for {resource_id}: appSessionId={app_session_id}");
    Some(app_session_id)
}

/// `Npcf_PolicyAuthorization_Delete`: POST `.../app-sessions/{id}/delete`
/// (TS 29.514 §4.2.5 -- a custom operation, not an HTTP DELETE).
///
/// Returns true when the PCF accepted it. A resource that was never actuated has
/// no `appSessionId` and is not an error: with the switch off at create time there
/// is nothing to delete.
pub async fn policy_authorization_delete(resource_id: &str) -> bool {
    let Some(app_session_id) = ({
        match app_sessions().lock() {
            Ok(mut m) => m.remove(resource_id),
            Err(_) => None,
        }
    }) else {
        log::debug!("no PCF app session recorded for {resource_id}; nothing to delete");
        return false;
    };
    let Some(pcf) = resolve_pcf_endpoint().await else {
        log::warn!(
            "cannot delete PCF app session {app_session_id} for {resource_id}: no PCF resolved"
        );
        return false;
    };
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&pcf.host, pcf.port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );
    let path = format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}/delete");
    match client.post_json(&path, &serde_json::json!({})).await {
        Ok(resp) if (200..300).contains(&resp.status) => {
            log::info!(
                "Npcf_PolicyAuthorization_Delete for {resource_id} (appSessionId={app_session_id}): \
                 status={}",
                resp.status
            );
            true
        }
        Ok(resp) => {
            log::warn!(
                "Npcf_PolicyAuthorization_Delete for {resource_id} returned status {}",
                resp.status
            );
            false
        }
        Err(e) => {
            log::warn!("Npcf_PolicyAuthorization_Delete for {resource_id} failed: {e}");
            false
        }
    }
}

// ============================================================================
// The capability source (criterion 5)
// ============================================================================

/// The time-synchronization capabilities this deployment can currently report,
/// derived from the stored configurations.
///
/// This replaces #113's administrative poke as the trigger for `CapsNotify`. It is
/// a real in-tree source in the sense that matters: the value is computed from
/// actual state rather than supplied by whoever called an admin route, so a change
/// in it means something changed. What it is NOT is a 5GS capability report — the
/// UPF/gNB do not report their (g)PTP capability into this tree at all, and the
/// PFCP TSC container that would carry it has no codec here (see the spec's
/// ceilings). So this reports what the TSCTSF has been asked to support and can
/// derive, which is strictly more than nothing and strictly less than the spec's
/// source.
pub fn derive_capabilities(configs: &[crate::context::TimeSyncConfig]) -> serde_json::Value {
    let mut domains: Vec<u16> = configs
        .iter()
        .filter_map(|c| c.config.time_domain)
        .collect();
    domains.sort_unstable();
    domains.dedup();
    let mut profiles: Vec<String> = configs
        .iter()
        .filter_map(|c| c.config.ptp_profile.clone())
        .collect();
    profiles.sort();
    profiles.dedup();
    let gm_capable = configs.iter().any(|c| c.config.gm_enable.unwrap_or(false));
    let unsatisfiable = configs
        .iter()
        .filter(|c| {
            !evaluate_clock_quality(c.config.clock_quality_acceptance_criteria.as_ref())
                .permits_actuation()
        })
        .count();
    serde_json::json!({
        "timeDomains": domains,
        "ptpProfiles": profiles,
        "gmCapable": gm_capable,
        "configurationsWithUnmeetableCriteria": unsatisfiable,
    })
}

/// The last reported capability set, so a change can be detected.
fn last_capabilities() -> &'static std::sync::Mutex<Option<serde_json::Value>> {
    static LAST: std::sync::OnceLock<std::sync::Mutex<Option<serde_json::Value>>> =
        std::sync::OnceLock::new();
    LAST.get_or_init(|| std::sync::Mutex::new(None))
}

/// Record `caps` and report whether it differs from the last recorded set.
///
/// The comparison is what makes this a *change* trigger rather than a per-request
/// one: a create that alters nothing about the derived capabilities must not wake
/// every subscriber, and TS 29.500 §6.5's spirit is that a notification means
/// something happened.
pub fn capabilities_changed(caps: &serde_json::Value) -> bool {
    match last_capabilities().lock() {
        Ok(mut last) => {
            let changed = last.as_ref() != Some(caps);
            if changed {
                *last = Some(caps.clone());
            }
            changed
        }
        // A poisoned lock must not suppress the notification: reporting an
        // unchanged set is harmless, missing a real change is not.
        Err(_) => true,
    }
}

#[cfg(test)]
pub fn reset_capabilities_for_test() {
    if let Ok(mut last) = last_capabilities().lock() {
        *last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(supis: &[&str], gm: Option<bool>) -> TimeSyncExposureConfig {
        TimeSyncExposureConfig {
            notification_target_addr: "http://af.example/cb".to_string(),
            up_node_id: "upf-1".to_string(),
            supis: supis.iter().map(|s| s.to_string()).collect(),
            time_domain: Some(24),
            gm_enable: gm,
            gm_priority: Some(128),
            ptp_profile: Some("gPTP".to_string()),
            ..Default::default()
        }
    }

    /// Read one TLV value out of a container, so assertions are about the managed
    /// OBJECT rather than about a byte offset that any reordering would break.
    fn object(container: &[u8], want: u8) -> Option<Vec<u8>> {
        let mut i = 0usize;
        while i + 2 <= container.len() {
            let t = container[i];
            let len = container[i + 1] as usize;
            let start = i + 2;
            if start + len > container.len() {
                return None;
            }
            if t == want {
                return Some(container[start..start + len].to_vec());
            }
            i = start + len;
        }
        None
    }

    // ── criterion 1: grandmaster enabled vs disabled ──

    #[test]
    fn a_grandmaster_enabled_configuration_derives_the_enable_object_set() {
        let d = derive_tsn_management(&cfg_with(&["imsi-1"], Some(true)));
        assert!(d.gm_enabled);
        for port in d.dstt_ports.iter().chain(d.nwtt_ports.iter()) {
            assert_eq!(
                object(&port.container, tag::GM_ENABLE),
                Some(vec![1]),
                "every port must carry the gPTP enable, or half the bridge is unsynchronised"
            );
            assert_eq!(object(&port.container, tag::GM_PRIORITY), Some(vec![128]));
            assert_eq!(
                object(&port.container, tag::TIME_DOMAIN),
                Some(vec![0, 24]),
                "the domain number is two octets, big endian"
            );
        }
        assert_eq!(object(&d.bridge_container, tag::GM_ENABLE), Some(vec![1]));
    }

    #[test]
    fn a_grandmaster_disabled_configuration_derives_the_disable_object() {
        let d = derive_tsn_management(&cfg_with(&["imsi-1"], Some(false)));
        assert!(!d.gm_enabled);
        assert_eq!(
            object(&d.dstt_ports[0].container, tag::GM_ENABLE),
            Some(vec![0])
        );
    }

    /// An ABSENT `gmEnable` is "not activated", not "activate by default".
    /// TS 23.501 §5.27.1.8 makes activation explicit, and defaulting it on would
    /// start distributing time for a configuration that never asked.
    #[test]
    fn an_absent_grandmaster_flag_is_not_activation() {
        let d = derive_tsn_management(&cfg_with(&["imsi-1"], None));
        assert!(!d.gm_enabled);
        assert_eq!(
            object(&d.dstt_ports[0].container, tag::GM_ENABLE),
            Some(vec![0])
        );
    }

    // ── criterion 1: a per-UE DS-TT port vs the N6 (NW-TT) termination ──

    #[test]
    fn each_ue_gets_its_own_dstt_port_and_the_up_node_gets_the_nwtt_port() {
        let d = derive_tsn_management(&cfg_with(&["imsi-1", "imsi-2", "imsi-3"], Some(true)));

        assert_eq!(d.dstt_ports.len(), 3, "one DS-TT port per UE");
        assert_eq!(
            d.dstt_ports.iter().map(|p| p.port_num).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "DS-TT numbering is stable and starts at 1, leaving 0 for the NW-TT"
        );
        for (port, supi) in d.dstt_ports.iter().zip(["imsi-1", "imsi-2", "imsi-3"]) {
            assert_eq!(port.side, TsnPortSide::DeviceSide);
            assert_eq!(
                object(&port.container, tag::SUPI).as_deref(),
                Some(supi.as_bytes()),
                "a DS-TT port names the UE it serves, or the PCF cannot route the PMIC"
            );
            assert_eq!(object(&port.container, tag::PORT_SIDE), Some(vec![0]));
            assert!(
                object(&port.container, tag::UP_NODE_ID).is_none(),
                "a DS-TT port is not the network-side termination"
            );
        }

        assert_eq!(
            d.nwtt_ports.len(),
            1,
            "one N6 termination per configuration"
        );
        let nwtt = &d.nwtt_ports[0];
        assert_eq!(nwtt.side, TsnPortSide::NetworkSide);
        assert_eq!(nwtt.port_num, 0);
        assert_eq!(object(&nwtt.container, tag::PORT_SIDE), Some(vec![1]));
        assert_eq!(
            object(&nwtt.container, tag::UP_NODE_ID).as_deref(),
            Some(b"upf-1".as_slice())
        );
        assert!(
            object(&nwtt.container, tag::SUPI).is_none(),
            "the N6 termination belongs to the user-plane node, not to any UE"
        );
    }

    /// The asymmetry stated as its own case: a configuration with NO UEs still has
    /// an N6 termination, because that port is a property of the user-plane node.
    #[test]
    fn a_configuration_with_no_ues_still_derives_the_n6_termination() {
        let d = derive_tsn_management(&cfg_with(&[], Some(true)));
        assert!(d.dstt_ports.is_empty());
        assert_eq!(d.nwtt_ports.len(), 1);
        assert_eq!(
            object(&d.nwtt_ports[0].container, tag::UP_NODE_ID).as_deref(),
            Some(b"upf-1".as_slice())
        );
    }

    // ── criterion 1: criteria that cannot be met ──

    #[test]
    fn a_reserved_clock_class_is_unsatisfiable() {
        let mut cfg = cfg_with(&["imsi-1"], Some(true));
        cfg.clock_quality_acceptance_criteria = Some(ClockQualityAcceptanceCriteria {
            clock_class: Some(100), // Reserved in IEEE 1588-2019 Table 4
            ..Default::default()
        });
        let d = derive_tsn_management(&cfg);
        let ClockQualityVerdict::Unsatisfiable(reasons) = &d.clock_quality else {
            panic!("expected Unsatisfiable, got {:?}", d.clock_quality);
        };
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("clockClass 100"), "{}", reasons[0]);
        assert!(!d.clock_quality.permits_actuation());
    }

    #[test]
    fn an_accuracy_finer_than_the_enumeration_is_unsatisfiable() {
        let mut cfg = cfg_with(&["imsi-1"], Some(true));
        cfg.clock_quality_acceptance_criteria = Some(ClockQualityAcceptanceCriteria {
            clock_accuracy: Some(0x10), // better than 0x20 = 25 ns, which is the best defined
            ..Default::default()
        });
        let d = derive_tsn_management(&cfg);
        assert!(!d.clock_quality.permits_actuation());
    }

    /// Every reason, not the first: an operator fixing one and re-submitting
    /// should not discover the rest one round trip at a time.
    #[test]
    fn all_unsatisfiable_criteria_are_reported_together() {
        let mut cfg = cfg_with(&["imsi-1"], Some(true));
        cfg.clock_quality_acceptance_criteria = Some(ClockQualityAcceptanceCriteria {
            clock_class: Some(100),
            clock_accuracy: Some(0xFF),
            synchronization_state: Some("MAYBE".to_string()),
            offset_scaled_log_variance: Some(0xFFFF),
        });
        let d = derive_tsn_management(&cfg);
        let ClockQualityVerdict::Unsatisfiable(reasons) = &d.clock_quality else {
            panic!("expected Unsatisfiable, got {:?}", d.clock_quality);
        };
        assert_eq!(
            reasons.len(),
            3,
            "three impossible criteria, three reasons: {reasons:?}"
        );
    }

    #[test]
    fn satisfiable_criteria_permit_actuation() {
        let mut cfg = cfg_with(&["imsi-1"], Some(true));
        cfg.clock_quality_acceptance_criteria = Some(ClockQualityAcceptanceCriteria {
            clock_class: Some(6),
            clock_accuracy: Some(0x20),
            synchronization_state: Some("SYNCHRONIZED".to_string()),
            offset_scaled_log_variance: Some(0x4E5D),
        });
        let d = derive_tsn_management(&cfg);
        assert_eq!(d.clock_quality, ClockQualityVerdict::Satisfiable);
        assert!(d.clock_quality.permits_actuation());
    }

    /// "No criteria" is distinct from "all criteria met", and both actuate. A
    /// single boolean would conflate them, and a caller reporting "criteria met"
    /// for a configuration that stated none would be inventing a guarantee.
    #[test]
    fn no_criteria_is_its_own_verdict_and_still_actuates() {
        let d = derive_tsn_management(&cfg_with(&["imsi-1"], Some(true)));
        assert_eq!(d.clock_quality, ClockQualityVerdict::NoCriteria);
        assert!(d.clock_quality.permits_actuation());

        // An empty criteria object is also "no criteria", not "satisfiable":
        // a consumer that sent `{}` stated nothing.
        let mut cfg = cfg_with(&["imsi-1"], Some(true));
        cfg.clock_quality_acceptance_criteria = Some(ClockQualityAcceptanceCriteria::default());
        assert_eq!(
            derive_tsn_management(&cfg).clock_quality,
            ClockQualityVerdict::NoCriteria
        );
    }

    // ── TSCAI derivation ──

    #[test]
    fn tscai_maps_the_stated_traffic_pattern_and_omits_the_rest() {
        let session = QosTscSession {
            periodicity: Some(2000),
            survival_time: Some(1000),
            ..Default::default()
        };
        let tscai = derive_tscai(&session).expect("a stated pattern derives a container");
        assert_eq!(tscai["periodicity"], 2000);
        assert_eq!(
            tscai["surTimeInTime"], 1000,
            "Stage-2's survivalTime is a DURATION, so it maps to surTimeInTime, not to the \
             message count surTimeInNumMsg"
        );
        assert!(
            tscai.get("burstArrivalTime").is_none(),
            "an absent member must be absent, not null"
        );
    }

    #[test]
    fn a_session_with_no_traffic_pattern_derives_no_container() {
        assert!(
            derive_tscai(&QosTscSession::default()).is_none(),
            "TS 29.514 types the container nullable, so omitting it is how to say 'no pattern'; \
             sending {{}} claims a pattern with every member absent"
        );
    }

    #[test]
    fn an_unstated_direction_populates_both_tscai_members() {
        let both = QosTscSession::default();
        assert_eq!(
            tscai_direction_keys(&both),
            ["tscaiInputUl", "tscaiInputDl"]
        );
        let ul = QosTscSession {
            flow_direction: Some("UPLINK".to_string()),
            ..Default::default()
        };
        assert_eq!(tscai_direction_keys(&ul), ["tscaiInputUl"]);
        let dl = QosTscSession {
            flow_direction: Some("DOWNLINK".to_string()),
            ..Default::default()
        };
        assert_eq!(tscai_direction_keys(&dl), ["tscaiInputDl"]);
    }
}
