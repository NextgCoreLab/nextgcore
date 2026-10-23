//! LMF Context Management
//!
//! Location Management Function context (TS 23.273)
//! Includes NRPPa (NR Positioning Protocol A) support

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::positioning::{
    rtt_ns_to_range_m, solve_aoa, solve_ecid, solve_multi_rtt, solve_tdoa, AoaObservation,
    RttObservation, TdoaObservation, TrpCoord, TrpRegistry,
};

/// Current Unix time in whole seconds (0 when the clock is before the epoch).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Positioning method (TS 23.273 6.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositioningMethod {
    /// Enhanced Cell ID
    Ecid,
    /// Observed Time Difference of Arrival
    Otdoa,
    /// NR-based positioning (DL-TDOA, UL-TDOA, DL-AoD, UL-AoA, Multi-RTT)
    NrBased,
    /// GNSS (Global Navigation Satellite System)
    Gnss,
    /// WLAN-based
    Wlan,
    /// Bluetooth-based
    Bluetooth,
    /// Barometric pressure sensor
    Sensor,
}

/// NRPPa positioning method detail for NR-based
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrPositioningMethod {
    DlTdoa,
    UlTdoa,
    DlAoD,
    UlAoA,
    MultiRtt,
}

/// Location estimate
#[derive(Debug, Clone, Default)]
pub struct LocationEstimate {
    /// Latitude in degrees (-90 to 90)
    pub latitude: f64,
    /// Longitude in degrees (-180 to 180)
    pub longitude: f64,
    /// Altitude in meters
    pub altitude: Option<f64>,
    /// Horizontal accuracy in meters
    pub horizontal_accuracy: f64,
    /// Vertical accuracy in meters
    pub vertical_accuracy: Option<f64>,
    /// Positioning method used
    pub method_used: Option<String>,
    /// Timestamp (NTP)
    pub timestamp: u64,
}

/// NRPPa measurement request
#[derive(Debug, Clone)]
pub struct NrppaMeasurementRequest {
    /// Request ID
    pub request_id: u64,
    /// Target UE AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// Positioning method requested
    pub method: PositioningMethod,
    /// NR positioning sub-method (if NR-based)
    pub nr_method: Option<NrPositioningMethod>,
    /// Target gNB ID
    pub gnb_id: Option<String>,
    /// QoS class (response time requirement)
    pub qos_class: PositioningQos,
    /// State
    pub state: MeasurementState,
}

/// Measurement state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeasurementState {
    #[default]
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// NRPPa measurement report from gNB
#[derive(Debug, Clone)]
pub struct NrppaMeasurementReport {
    /// Request ID this report responds to
    pub request_id: u64,
    /// Measurement results (cell-specific)
    pub cell_measurements: Vec<CellMeasurement>,
    /// Computed location estimate
    pub location: Option<LocationEstimate>,
}

/// Cell-level measurement for positioning
#[derive(Debug, Clone)]
pub struct CellMeasurement {
    /// Cell global ID (NR CGI)
    pub nr_cgi: String,
    /// Reference Signal Received Power (dBm)
    pub rsrp: Option<i16>,
    /// Reference Signal Received Quality (dB)
    pub rsrq: Option<i16>,
    /// Timing advance, as an NR Timing Advance command `T_A` (TS 38.213
    /// §4.2, ranged at μ = 1). Only the debug JSON route fills it; the wire
    /// adapters fill `ecid_rtt_ns`.
    pub timing_advance: Option<u32>,
    /// The E-CID timing term as a round trip, in ns (#832). It is decoded from its
    /// own report mapping, where the old code passed the raw report value on as
    /// an NR TA command:
    /// - E-UTRA TADV Type 1 or Type 2 (NRPPa, TS 36.133 §10.3);
    /// - the E-UTRA UE Rx–Tx (LPP, TS 36.133 §9.1.9.2).
    ///
    /// It is the serving cell's round trip only, never a Multi-RTT range.
    pub ecid_rtt_ns: Option<f64>,
    /// Angle of Arrival (degrees)
    pub aoa: Option<f64>,
    /// Round-trip time (nanoseconds)
    pub rtt_ns: Option<u64>,
    /// NR DL-TDOA reference-signal time difference vs the DL-PRS reference TRP
    /// (nanoseconds, SIGNED; the reference TRP itself reports 0). TS 37.355.
    pub rstd_ns: Option<f64>,
    /// The DL-PRS ID of the reference TRP that `rstd_ns` is relative to, for an
    /// LPP DL-TDOA measurement. Reports with different references are rebased
    /// onto each other before they are solved together (#824 review).
    pub rstd_reference: Option<u8>,
    /// UE Rx–Tx time difference against this TRP (TS 38.215 §5.1.30), signed
    /// nanoseconds: the UE half of a Multi-RTT measurement (LPP
    /// `nr-UE-RxTxTimeDiff-r16`). Not an RTT on its own (#713).
    pub ue_rx_tx_ns: Option<f64>,
    /// gNB Rx–Tx time difference at this TRP (TS 38.215 §5.2.3), signed
    /// nanoseconds: the gNB half of a Multi-RTT measurement (NRPPa
    /// `gNB-RxTxTimeDiff`, TS 38.455). `RTT = ue_rx_tx_ns + gnb_rx_tx_ns`
    /// (TS 38.305 §8.10).
    pub gnb_rx_tx_ns: Option<f64>,
    /// The DL-PRS ID (TS 37.355 `dl-PRS-ID-r16`, 0..255) the measurement was made
    /// on, when it is an LPP NR measurement. `nr_cgi` keys by PCI when the UE gave
    /// one; this is the fallback key `prs-<id>` a registry may hold instead (#714).
    pub dl_prs_id: Option<u8>,
    /// The measurement is of an E-UTRA cell (LPP `ECID-SignalMeasurementInformation`,
    /// or an NRPPa E-CID report whose serving cell is an E-UTRA CGI). It decides
    /// whether an E-CID fix is reported as `ECID` or `NR_ECID` (TS 29.572, #715).
    pub eutra: bool,
}

/// Positioning QoS requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PositioningQos {
    #[default]
    BestEffort,
    /// Response within 1 second
    LowLatency,
    /// High accuracy (<10m)
    HighAccuracy,
    /// Emergency (E911 compliant)
    Emergency,
}

/// UE location context
#[derive(Debug, Clone)]
pub struct UeLocationContext {
    /// SUPI
    pub supi: String,
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// Current serving cell
    pub serving_cell: String,
    /// Last known location
    pub last_location: Option<LocationEstimate>,
    /// The location this UE had BEFORE `last_location` (#104).
    ///
    /// Kept because velocity needs two fixes: these solvers produce position
    /// only (no Doppler), so a single fix has no velocity, and `velocityRequested`
    /// could never be honoured against a store that remembered one. Set by
    /// [`LmfContext::ue_location_update`] when it displaces an existing fix.
    pub previous_location: Option<LocationEstimate>,
    /// Active measurement request ID
    pub active_measurement: Option<u64>,
}

/// Periodic-reporting parameters for a deferred LDR (A8, TS 29.572
/// `PeriodicEventInfo` — `reportingAmount`, `reportingInterval` seconds, optional
/// `reportingIntervalMs`). A `Copy` mirror kept in `context` so `LdrContext`
/// stays independent of the `nlmf` serde models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodicReporting {
    /// `ReportingAmount` (TS 29.572, yaml:2083) — number of periodic reports.
    pub reporting_amount: u32,
    /// `ReportingInterval` (TS 29.572, yaml:2089) — interval in **seconds**.
    pub reporting_interval_secs: u32,
    /// `ReportingIntervalMs` (TS 29.572, yaml:2095) — interval in
    /// **milliseconds** (1..999) when a sub-second cadence is requested.
    pub reporting_interval_ms: Option<u32>,
}

/// Registered deferred/periodic/triggered LDR session context (lmfd#1).
/// Keyed by `ldrReference` in `ldr_sessions`; created on `determine-location`
/// or `location-context-transfer`; removed by `cancel-location`.
#[derive(Debug, Clone)]
pub struct LdrContext {
    /// The `ldrReference` that identifies this session (TS 29.572 §6.1.4.2.2).
    pub ldr_reference: String,
    /// `LdrType` enum value (UE_AVAILABLE/PERIODIC/ENTERING_INTO_AREA/…).
    pub ldr_type: String,
    /// HGMLC callback URI for EventNotify (TS 29.572 §6.1.5).
    pub hgmlc_callback_uri: Option<String>,
    /// Target SUPI when known.
    pub supi: Option<String>,
    /// A8: periodic-reporting parameters, present only for `ldrType == PERIODIC`
    /// with a `periodicEventInfo` IE. Drives the EventNotify trigger scheduler.
    pub periodic_event_info: Option<PeriodicReporting>,
}

/// Outcome of a pending network-induced positioning procedure (Wave-6 A2,
/// TS 23.273 §6.11.2 5GC-MT-LR). Delivered on the session's completion
/// channel by [`LmfContext::measurement_report`] (fed by the A4 N1/N2 notify
/// callbacks or the A1-relayed NRPPa uplink).
#[derive(Debug, Clone)]
pub enum PositioningOutcome {
    /// A REAL measurement-derived fix (from the geometric solvers only —
    /// never the heuristic placeholder).
    Fix(LocationEstimate),
    /// A report arrived but the solver could not produce a fix
    /// (→ 500 `POSITIONING_FAILED`, TS 29.572 Table 6.1.7.3-1).
    SolverFailed,
}

/// A pending DetermineLocation correlation session (Wave-6 A2).
///
/// Registered BEFORE the outbound Namf `N1N2MessageTransfer` POST so an
/// uplink report can never race the registration. Indexed by
/// `lcsCorrelationId` (TS 29.572 CorrelationID, 1..255 chars) AND by the LPP
/// `transactionNumber` (TS 37.355 §6.1; wrap-around means the transaction
/// index is last-writer-wins — `lcsCorrelationId` stays unique).
pub struct PositioningSession {
    /// Minted LCS correlation identifier (UUID, TS 29.572 CorrelationID).
    pub lcs_correlation_id: String,
    /// LPP transaction number of the RequestLocationInformation we sent.
    pub lpp_transaction: u8,
    /// Target SUPI when known.
    pub supi: Option<String>,
    /// The measurement-store request id measurements are reported against.
    pub request_id: u64,
    /// Session creation instant (timeout bookkeeping).
    pub created_at: std::time::Instant,
    /// Where this session's NRPPa leg went (#515): the serving AMF and UE context
    /// the E-CID Measurement Initiation was relayed through, so an ERROR
    /// INDICATION for the gNB's report can go back the same way.
    pub nrppa_peer: Option<NrppaPeer>,
    /// The measurement legs this session waits for (#715, #807). LPP always; the
    /// NRPPa legs once they are solicited.
    expected_legs: Vec<MeasurementLeg>,
    /// The legs that have reported.
    reported_legs: Vec<MeasurementLeg>,
    /// Every measurement the reported legs carried, solved together.
    accumulated: Vec<CellMeasurement>,
    /// One-shot completion channel to the awaiting DetermineLocation handler.
    sender: Option<tokio::sync::oneshot::Sender<PositioningOutcome>>,
}

/// One source of measurements for a positioning session (#715, #807).
///
/// A fix may need more than one: an NR E-CID fix takes the serving cell from the
/// UE's LPP report and its timing term from the gNB's NRPPa E-CID measurement
/// (#834 review), and a Multi-RTT range is the UE's Rx–Tx half (LPP) plus the
/// gNB's (NRPPa Measurement, #807). Each leg arrives in its own notification, so the session collects
/// them and solves once every expected leg has reported, or when the response-time
/// budget runs out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasurementLeg {
    /// The UE's LPP `ProvideLocationInformation`.
    Lpp,
    /// The serving gNB's NRPPa E-CID measurement.
    NrppaEcid,
}

/// What a leg's report did to its session.
#[derive(Debug, Clone)]
pub enum LegProgress {
    /// Every expected leg is in; the session was solved and completed.
    Completed(Option<LocationEstimate>),
    /// The session waits for more legs.
    Waiting,
    /// No pending session has this request id.
    NoSession,
}

/// Cloneable lookup view of a [`PositioningSession`] (the completion channel
/// is not cloneable and stays in the store).
#[derive(Debug, Clone)]
pub struct PositioningSessionInfo {
    pub lcs_correlation_id: String,
    pub lpp_transaction: u8,
    pub supi: Option<String>,
    pub request_id: u64,
    pub nrppa_peer: Option<NrppaPeer>,
}

/// The serving AMF and UE context an NRPPa exchange is relayed through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrppaPeer {
    pub amf: crate::namf_client::DiscoveredAmf,
    pub ue_context_id: String,
}

/// LMF Context
pub struct LmfContext {
    /// UE location contexts (SUPI -> context)
    ue_locations: RwLock<HashMap<String, UeLocationContext>>,
    /// Active measurement requests (request_id -> request)
    measurements: RwLock<HashMap<u64, NrppaMeasurementRequest>>,
    /// Measurement reports (request_id -> report)
    reports: RwLock<HashMap<u64, NrppaMeasurementReport>>,
    /// Next measurement request ID
    next_request_id: AtomicUsize,
    /// Maximum concurrent measurements
    max_measurements: usize,
    /// Supported positioning methods
    supported_methods: Vec<PositioningMethod>,
    /// Context initialized
    initialized: AtomicBool,
    /// Cell coordinate registry (NR-CGI -> geodetic coord) for the real solvers.
    /// Populated via [`LmfContext::set_cell_coord`] from config or tests.
    /// Empty means unconfigured; real solvers fall back to the heuristic placeholder.
    cell_registry: RwLock<HashMap<String, TrpCoord>>,

    /// Per-UE LPP positioning capability, as reported over LPP (#103). Absent means
    /// no exchange happened, which `UeLppCapability::Unknown` is distinct from
    /// `EcidOnly` precisely to express.
    ue_capabilities: RwLock<HashMap<String, crate::codec_glue::UeLppCapability>>,
    /// Sidelink ranges reported by each UE (TS 23.586 §5.3.3, nextgsim #138), keyed
    /// by SUPI. The LATEST report per UE replaces the previous one: a range is a
    /// snapshot, and accumulating them would make an LMF answer with a distance the
    /// UE has since re-measured.
    ///
    /// Held separately from `cell_registry` and from the positioning sessions, and
    /// not fed to any solver: a range to a peer UE is not a measurement of a cell,
    /// and this LMF has no coordinates for peer UEs, so a position derived from it
    /// would be invented. Lock discipline: taken alone, like every map here.
    sidelink_ranges: RwLock<HashMap<String, Vec<crate::codec_glue::SidelinkRange>>>,
    /// Registered deferred/periodic/triggered LDR sessions (ldrReference -> ctx). lmfd#1.
    ldr_sessions: RwLock<HashMap<String, LdrContext>>,
    /// A8: running EventNotify trigger tasks (ldrReference -> abort handle). A
    /// PERIODIC LDR spawns a tokio interval task whose [`AbortHandle`] is stored
    /// here so `cancel-location` and `fini` can stop it (no task leaks on
    /// cancel or shutdown). Only ever taken alone (no lock-order inversion).
    ldr_tasks: RwLock<HashMap<String, tokio::task::AbortHandle>>,
    /// Pending DetermineLocation sessions keyed by lcsCorrelationId (A2).
    /// Lock discipline: the session maps below are only ever taken ONE at a
    /// time (acquire → mutate → drop before the next) so no lock ordering
    /// exists to invert (nf-context-lock-deadlocks sweep convention).
    positioning_sessions: RwLock<HashMap<String, PositioningSession>>,
    /// LPP transactionNumber -> lcsCorrelationId (last-writer-wins on wrap).
    positioning_txn_index: RwLock<HashMap<u8, String>>,
    /// Measurement-store request_id -> lcsCorrelationId.
    positioning_request_index: RwLock<HashMap<u64, String>>,
    /// Cached AMF N1N2 subscription ids: "host:port|ueContextId" -> subscriptionId
    /// (TS 29.518 §5.2.2.6; reused across DetermineLocation requests).
    amf_subscriptions: RwLock<HashMap<String, String>>,
    /// Advertised base URI for our A4 notify callback routes
    /// (e.g. `http://10.0.0.5:7816`), set at startup from the SBI bind args.
    callback_base: RwLock<Option<String>>,
    /// Our NF instance id (servingLMFIdentification, TS 29.518).
    nf_instance_id: RwLock<Option<String>>,
    /// UP-location subscriptions (`up-subscriptions`, TS 29.572 §6.1.4.8),
    /// keyed by the LMF-minted `subscriptionId` (#104).
    ///
    /// `up-subscribe` used to mint a UUID, echo the body and store NOTHING, and
    /// `up-unsubscribe` ignored the id and always answered 204 — so a consumer
    /// deleting a subscription that never existed was told it succeeded, and a
    /// subscribed consumer's state was unretrievable. Fabricated success in both
    /// directions.
    up_subscriptions: RwLock<HashMap<String, crate::nlmf::UpSubscription>>,
    /// UP-location configurations (`configure-up`, TS 29.572 §6.1.4.7), keyed by
    /// the UE identity the configuration is for (`supi`, else `gpsi`) — #104.
    /// Previously validated and discarded.
    up_configs: RwLock<HashMap<String, crate::nlmf::UpConfig>>,
    /// `Nlmf_DataExposure` subscriptions (TS 29.572 §5.4), keyed by the
    /// LMF-minted `subscriptionId` (#104). The whole service was absent before.
    exposure_subscriptions:
        RwLock<HashMap<String, crate::broadcast_exposure::LmfDataExposureSubscription>>,
}

impl LmfContext {
    pub fn new() -> Self {
        Self {
            ue_locations: RwLock::new(HashMap::new()),
            measurements: RwLock::new(HashMap::new()),
            reports: RwLock::new(HashMap::new()),
            next_request_id: AtomicUsize::new(1),
            max_measurements: 0,
            supported_methods: vec![
                PositioningMethod::Ecid,
                PositioningMethod::Otdoa,
                PositioningMethod::NrBased,
                PositioningMethod::Gnss,
            ],
            initialized: AtomicBool::new(false),
            cell_registry: RwLock::new(HashMap::new()),
            ue_capabilities: RwLock::new(HashMap::new()),
            sidelink_ranges: RwLock::new(HashMap::new()),
            up_subscriptions: RwLock::new(HashMap::new()),
            up_configs: RwLock::new(HashMap::new()),
            exposure_subscriptions: RwLock::new(HashMap::new()),
            ldr_sessions: RwLock::new(HashMap::new()),
            ldr_tasks: RwLock::new(HashMap::new()),
            positioning_sessions: RwLock::new(HashMap::new()),
            positioning_txn_index: RwLock::new(HashMap::new()),
            positioning_request_index: RwLock::new(HashMap::new()),
            amf_subscriptions: RwLock::new(HashMap::new()),
            callback_base: RwLock::new(None),
            nf_instance_id: RwLock::new(None),
        }
    }

    pub fn init(&mut self, max_measurements: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_measurements = max_measurements;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("LMF context initialized with max {max_measurements} concurrent measurements");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut locs) = self.ue_locations.write() {
            locs.clear();
        }
        if let Ok(mut meas) = self.measurements.write() {
            meas.clear();
        }
        if let Ok(mut reps) = self.reports.write() {
            reps.clear();
        }
        if let Ok(mut ldrs) = self.ldr_sessions.write() {
            ldrs.clear();
        }
        // A8: abort every running EventNotify trigger task so no periodic
        // producer outlives the LMF (shutdown-token discipline).
        if let Ok(mut tasks) = self.ldr_tasks.write() {
            for (_ref, handle) in tasks.drain() {
                handle.abort();
            }
        }
        // Dropping the sessions drops their completion senders, so any
        // still-awaiting DetermineLocation handler unblocks with a recv error.
        if let Ok(mut s) = self.positioning_sessions.write() {
            s.clear();
        }
        if let Ok(mut t) = self.positioning_txn_index.write() {
            t.clear();
        }
        if let Ok(mut r) = self.positioning_request_index.write() {
            r.clear();
        }
        if let Ok(mut a) = self.amf_subscriptions.write() {
            a.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("LMF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn supported_methods(&self) -> &[PositioningMethod] {
        &self.supported_methods
    }

    // ---- #104: UP-location subscriptions and configurations ------------------

    /// Store a UP-location subscription under a freshly minted id; returns the id.
    pub fn up_subscription_insert(&self, sub: crate::nlmf::UpSubscription) -> Option<String> {
        let mut subs = self.up_subscriptions.write().ok()?;
        let id = uuid::Uuid::new_v4().to_string();
        subs.insert(id.clone(), sub);
        Some(id)
    }

    /// The stored subscription for `id`, if any.
    pub fn up_subscription_find(&self, id: &str) -> Option<crate::nlmf::UpSubscription> {
        self.up_subscriptions.read().ok()?.get(id).cloned()
    }

    /// Remove a UP-location subscription. `None` when the id is unknown, which is
    /// what lets `up-unsubscribe` answer 404 instead of a fabricated 204.
    pub fn up_subscription_remove(&self, id: &str) -> Option<crate::nlmf::UpSubscription> {
        self.up_subscriptions.write().ok()?.remove(id)
    }

    pub fn up_subscription_count(&self) -> usize {
        self.up_subscriptions.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Record a UP-location configuration for a UE, keyed by `supi` else `gpsi`.
    /// Returns the key used, so the caller can log what it stored against.
    pub fn up_config_store(&self, config: crate::nlmf::UpConfig) -> Option<String> {
        let key = config.supi.clone().or_else(|| config.gpsi.clone())?;
        self.up_configs.write().ok()?.insert(key.clone(), config);
        Some(key)
    }

    /// The stored UP configuration for a UE identity.
    pub fn up_config_find(&self, ue_id: &str) -> Option<crate::nlmf::UpConfig> {
        self.up_configs.read().ok()?.get(ue_id).cloned()
    }

    // ---- #104: Nlmf_DataExposure subscriptions -------------------------------

    /// Store a data-exposure subscription under a freshly minted id.
    pub fn exposure_subscription_insert(
        &self,
        sub: crate::broadcast_exposure::LmfDataExposureSubscription,
    ) -> Option<String> {
        let mut subs = self.exposure_subscriptions.write().ok()?;
        let id = uuid::Uuid::new_v4().to_string();
        subs.insert(id.clone(), sub);
        Some(id)
    }

    pub fn exposure_subscription_find(
        &self,
        id: &str,
    ) -> Option<crate::broadcast_exposure::LmfDataExposureSubscription> {
        self.exposure_subscriptions.read().ok()?.get(id).cloned()
    }

    /// Replace an existing subscription (the PATCH result). `false` when the id is
    /// unknown, so a modify cannot create a resource at a consumer-chosen id.
    pub fn exposure_subscription_replace(
        &self,
        id: &str,
        sub: crate::broadcast_exposure::LmfDataExposureSubscription,
    ) -> bool {
        let Ok(mut subs) = self.exposure_subscriptions.write() else {
            return false;
        };
        if !subs.contains_key(id) {
            return false;
        }
        subs.insert(id.to_string(), sub);
        true
    }

    pub fn exposure_subscription_remove(
        &self,
        id: &str,
    ) -> Option<crate::broadcast_exposure::LmfDataExposureSubscription> {
        self.exposure_subscriptions.write().ok()?.remove(id)
    }

    /// Is a real positioning measurement source wired (#104)?
    ///
    /// `/capabilities` used to hardcode `nrppaSupported: true` and
    /// `nlsInterfaceSupported: true` while the mainline measure-location path
    /// answered `403 LOCATION_MEASUREMENT_UNKNOWN` for want of one — so an
    /// interop partner selected a method that then failed at request time.
    ///
    /// "Wired" means this LMF has cell/TRP coordinates to solve against: without
    /// them the solvers fall back to a heuristic placeholder and the measurement
    /// path cannot produce a real fix. That makes the advertised flag a function
    /// of configuration rather than a constant, which is the honesty the issue
    /// asks for.
    pub fn measurement_source_available(&self) -> bool {
        self.cell_registry
            .read()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    }

    /// Create a measurement request (NLs: AMF -> LMF)
    pub fn measurement_request(
        &self,
        amf_ue_ngap_id: u64,
        method: PositioningMethod,
        nr_method: Option<NrPositioningMethod>,
        gnb_id: Option<String>,
        qos: PositioningQos,
    ) -> Option<NrppaMeasurementRequest> {
        let mut measurements = self.measurements.write().ok()?;

        if measurements.len() >= self.max_measurements {
            log::error!(
                "Maximum concurrent measurements [{}] reached",
                self.max_measurements
            );
            return None;
        }

        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst) as u64;
        let request = NrppaMeasurementRequest {
            request_id,
            amf_ue_ngap_id,
            method,
            nr_method,
            gnb_id,
            qos_class: qos,
            state: MeasurementState::Pending,
        };

        measurements.insert(request_id, request.clone());
        log::info!(
            "Measurement request created: id={request_id} method={method:?} ue_ngap_id={amf_ue_ngap_id}"
        );
        Some(request)
    }

    /// Process a measurement report (NRPPa: gNB -> LMF via AMF).
    ///
    /// A2: when the report belongs to a pending DetermineLocation session
    /// (request_id indexed by [`Self::positioning_session_register`]), the
    /// session is completed with a **strict** outcome: only a real-solver fix
    /// yields [`PositioningOutcome::Fix`]; anything else maps to
    /// [`PositioningOutcome::SolverFailed`] (→ 500 `POSITIONING_FAILED`).
    ///
    /// A7 (lmfd-11): the runtime path NEVER fabricates coordinates. The return
    /// value and the stored [`NrppaMeasurementReport::location`] are exactly the
    /// real-solver fix ([`try_real_solve`]) or `None` — the old heuristic
    /// `compute_location_placeholder` lat/lon 0.0 fallback has been removed from
    /// the runtime path entirely (it now lives under `#[cfg(test)]`). `None`
    /// means "no location fix could be solved" and every caller treats it as
    /// no-fix (debug routes → 404; the MT-LR session → `SolverFailed` → 500).
    pub fn measurement_report(
        &self,
        request_id: u64,
        cell_measurements: Vec<CellMeasurement>,
    ) -> Option<LocationEstimate> {
        // Build the registry snapshot while holding only the cell_registry read
        // lock; drop it before acquiring the write locks below to avoid deadlock.
        let registry = self.build_trp_registry();

        // Scope the store locks so the session completion below runs lock-free.
        let strict_fix = {
            let mut measurements = self.measurements.write().ok()?;
            let mut reports = self.reports.write().ok()?;

            let measurement = measurements.get_mut(&request_id)?;
            measurement.state = MeasurementState::Completed;

            // Real geometric solve (None on empty registry / no solvable set).
            // A7: no placeholder fallback — an unsolvable report yields no fix.
            let strict_fix = if cell_measurements.is_empty() || registry.is_empty() {
                None
            } else {
                try_real_solve(&cell_measurements, &registry)
            };

            let report = NrppaMeasurementReport {
                request_id,
                cell_measurements,
                location: strict_fix.clone(),
            };

            reports.insert(request_id, report);
            strict_fix
        };

        match &strict_fix {
            Some(location) => log::info!(
                "Measurement report processed: id={} lat={:.6} lon={:.6} accuracy={:.1}m",
                request_id,
                location.latitude,
                location.longitude,
                location.horizontal_accuracy
            ),
            None => log::info!(
                "Measurement report processed: id={request_id} — no location fix solvable \
                 (empty TRP registry or no solvable measurement set); reporting no fix"
            ),
        }

        // A2: complete a pending DetermineLocation session (if any) with the
        // strict outcome — a real fix, else SolverFailed (never a placeholder).
        let outcome = match strict_fix.clone() {
            Some(fix) => PositioningOutcome::Fix(fix),
            None => PositioningOutcome::SolverFailed,
        };
        self.positioning_session_complete_by_request(request_id, outcome);

        strict_fix
    }

    /// Get measurement by request ID
    pub fn measurement_find(&self, request_id: u64) -> Option<NrppaMeasurementRequest> {
        self.measurements.read().ok()?.get(&request_id).cloned()
    }

    /// Get report by request ID
    pub fn report_find(&self, request_id: u64) -> Option<NrppaMeasurementReport> {
        self.reports.read().ok()?.get(&request_id).cloned()
    }

    /// Store/update UE location
    pub fn ue_location_update(&self, supi: &str, location: LocationEstimate) -> bool {
        if let Ok(mut locs) = self.ue_locations.write() {
            if let Some(ctx) = locs.get_mut(supi) {
                // #104: the displaced fix becomes `previous_location`, giving the
                // two-fix history a velocity can be derived from. Only ever
                // displaced by a NEWER fix, so `previous` is older than `last`.
                ctx.previous_location = ctx.last_location.take();
                ctx.last_location = Some(location);
                return true;
            }
            locs.insert(
                supi.to_string(),
                UeLocationContext {
                    supi: supi.to_string(),
                    amf_ue_ngap_id: 0,
                    serving_cell: String::new(),
                    last_location: Some(location),
                    previous_location: None,
                    active_measurement: None,
                },
            );
            return true;
        }
        false
    }

    /// Get UE location
    pub fn ue_location_get(&self, supi: &str) -> Option<UeLocationContext> {
        self.ue_locations.read().ok()?.get(supi).cloned()
    }

    /// Return the target UE's stored **per-SUPI** location fix, or `None`.
    ///
    /// A2: this replaces the retired `latest_location` global newest-report
    /// fallback, which could serve a fix computed for a DIFFERENT UE on the
    /// DetermineLocation MT-LR path. Only the UE's own stored fix (with a
    /// real horizontal accuracy > 0) is ever returned; the caller MUST NOT
    /// fabricate a location when this is `None`.
    pub fn stored_fix(&self, supi: &str) -> Option<LocationEstimate> {
        self.ue_location_get(supi)
            .and_then(|c| c.last_location)
            .filter(|l| l.horizontal_accuracy > 0.0)
    }

    pub fn measurement_count(&self) -> usize {
        self.measurements.read().map(|m| m.len()).unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // LDR session store (lmfd#1): deferred/periodic/triggered LDR contexts
    // -----------------------------------------------------------------------

    /// Register (or replace) an LDR session keyed by `ldrReference`.
    /// Returns `true` on success. Used by `determine-location` (ldrType present)
    /// and `location-context-transfer` (TS 29.572 §6.1.4.2.2, §6.1.4.5.2).
    pub fn register_ldr(&self, ctx: LdrContext) -> bool {
        if let Ok(mut l) = self.ldr_sessions.write() {
            l.insert(ctx.ldr_reference.clone(), ctx);
            return true;
        }
        false
    }

    /// Remove an LDR session by `ldrReference`.
    /// Returns `true` if the session existed (it was cancelled), `false` if not
    /// found (→ caller should return 403 LOCATION_SESSION_UNKNOWN).
    /// Used by `cancel-location` (TS 29.572 §6.1.4.3.2).
    ///
    /// A8: also aborts any running EventNotify trigger task for the session so a
    /// PERIODIC producer stops immediately on cancel (wire `cancel` to abort).
    pub fn cancel_ldr(&self, ldr_reference: &str) -> bool {
        let existed = if let Ok(mut l) = self.ldr_sessions.write() {
            l.remove(ldr_reference).is_some()
        } else {
            false
        };
        // Abort the trigger task regardless of `existed` (idempotent).
        if let Ok(mut tasks) = self.ldr_tasks.write() {
            if let Some(handle) = tasks.remove(ldr_reference) {
                handle.abort();
            }
        }
        existed
    }

    /// Look up an LDR session by `ldrReference`. Returns a clone, or `None`.
    pub fn ldr_find(&self, ldr_reference: &str) -> Option<LdrContext> {
        self.ldr_sessions.read().ok()?.get(ldr_reference).cloned()
    }

    /// A8: register the [`AbortHandle`] of a PERIODIC LDR's trigger task,
    /// keyed by `ldrReference`. Aborts and replaces any prior task for the same
    /// reference (last-writer-wins; a re-registration supersedes the old task).
    pub fn ldr_task_register(&self, ldr_reference: &str, handle: tokio::task::AbortHandle) {
        if let Ok(mut tasks) = self.ldr_tasks.write() {
            if let Some(prev) = tasks.insert(ldr_reference.to_string(), handle) {
                prev.abort();
            }
        }
    }

    /// A8: mark a trigger task finished — removes the LDR session and its task
    /// handle WITHOUT aborting (the task itself is completing: normal
    /// reporting-amount exhaustion or an auto-cancel after repeated GMLC POST
    /// failure). Distinct from [`Self::cancel_ldr`], which aborts a still-running
    /// task from the outside.
    pub fn ldr_finish(&self, ldr_reference: &str) {
        if let Ok(mut l) = self.ldr_sessions.write() {
            l.remove(ldr_reference);
        }
        if let Ok(mut tasks) = self.ldr_tasks.write() {
            tasks.remove(ldr_reference);
        }
    }

    /// A8: number of running EventNotify trigger tasks (test/observability).
    pub fn ldr_task_count(&self) -> usize {
        self.ldr_tasks.read().map(|t| t.len()).unwrap_or(0)
    }

    /// A8/#104: is a trigger task armed for this `ldrReference`?
    ///
    /// The per-key form of [`Self::ldr_task_count`]. Needed because #104's
    /// context-transfer criterion is about ONE LDR's trigger resuming, and a count
    /// cannot distinguish "this LDR was re-armed" from "some other test's LDR is
    /// still ticking".
    pub fn ldr_task_is_running(&self, ldr_reference: &str) -> bool {
        self.ldr_tasks
            .read()
            .map(|t| t.contains_key(ldr_reference))
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    // A2: pending DetermineLocation positioning-session store (TS 23.273
    // §6.11.2 correlation; TS 29.572 CorrelationID; TS 37.355 transactionID).
    // -----------------------------------------------------------------------

    /// Register a pending positioning session BEFORE the outbound Namf
    /// N1N2MessageTransfer POST. Mints the `lcsCorrelationId` (UUID — 36
    /// chars, inside the TS 29.572 CorrelationID 1..255 bound) and returns it
    /// with the completion receiver the DetermineLocation handler awaits.
    /// The transaction index is last-writer-wins on `u8` wrap; uniqueness is
    /// carried by the correlation id.
    pub fn positioning_session_register(
        &self,
        supi: Option<String>,
        lpp_transaction: u8,
        request_id: u64,
    ) -> (String, tokio::sync::oneshot::Receiver<PositioningOutcome>) {
        let corr = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let session = PositioningSession {
            lcs_correlation_id: corr.clone(),
            lpp_transaction,
            supi,
            request_id,
            created_at: std::time::Instant::now(),
            nrppa_peer: None,
            expected_legs: vec![MeasurementLeg::Lpp],
            reported_legs: Vec::new(),
            accumulated: Vec::new(),
            sender: Some(tx),
        };
        if let Ok(mut s) = self.positioning_sessions.write() {
            s.insert(corr.clone(), session);
        }
        if let Ok(mut t) = self.positioning_txn_index.write() {
            t.insert(lpp_transaction, corr.clone());
        }
        if let Ok(mut r) = self.positioning_request_index.write() {
            r.insert(request_id, corr.clone());
        }
        (corr, rx)
    }

    /// Remove a session from all three maps. Returns the removed session.
    fn positioning_session_take(&self, corr: &str) -> Option<PositioningSession> {
        let session = self.positioning_sessions.write().ok()?.remove(corr)?;
        if let Ok(mut t) = self.positioning_txn_index.write() {
            if t.get(&session.lpp_transaction).map(String::as_str) == Some(corr) {
                t.remove(&session.lpp_transaction);
            }
        }
        if let Ok(mut r) = self.positioning_request_index.write() {
            r.remove(&session.request_id);
        }
        Some(session)
    }

    /// Complete (and remove) a pending session by `lcsCorrelationId`, firing
    /// its completion channel with `outcome`. On a real fix the estimate is
    /// also cached as the UE's stored fix with a REAL capture timestamp so a
    /// later request can honour `ageOfLocationEstimate`. Returns `false` when
    /// no such session exists (fail-closed: unknown correlations are never
    /// ingested globally).
    pub fn positioning_session_complete(&self, corr: &str, outcome: PositioningOutcome) -> bool {
        let Some(mut session) = self.positioning_session_take(corr) else {
            return false;
        };
        if let (PositioningOutcome::Fix(fix), Some(supi)) = (&outcome, session.supi.as_ref()) {
            let mut cached = fix.clone();
            cached.timestamp = unix_now();
            self.ue_location_update(supi, cached);
        }
        if let Some(tx) = session.sender.take() {
            // A dropped receiver just means the waiter timed out first.
            let _ = tx.send(outcome);
        }
        true
    }

    /// Complete a pending session by measurement-store `request_id`
    /// (the [`Self::measurement_report`] ingest path).
    pub fn positioning_session_complete_by_request(
        &self,
        request_id: u64,
        outcome: PositioningOutcome,
    ) -> bool {
        let corr = self
            .positioning_request_index
            .read()
            .ok()
            .and_then(|r| r.get(&request_id).cloned());
        match corr {
            Some(corr) => self.positioning_session_complete(&corr, outcome),
            None => false,
        }
    }

    /// Expire (remove) a pending session without firing its channel — the
    /// waiter already timed out (→ 504 `UNREACHABLE_USER`). Returns `true`
    /// when a session was removed.
    pub fn positioning_session_expire(&self, corr: &str) -> bool {
        self.positioning_session_take(corr).is_some()
    }

    /// Look up a pending session by `lcsCorrelationId` (A4 correlation).
    pub fn positioning_session_find(&self, corr: &str) -> Option<PositioningSessionInfo> {
        self.positioning_sessions
            .read()
            .ok()?
            .get(corr)
            .map(|s| PositioningSessionInfo {
                lcs_correlation_id: s.lcs_correlation_id.clone(),
                lpp_transaction: s.lpp_transaction,
                supi: s.supi.clone(),
                request_id: s.request_id,
                nrppa_peer: s.nrppa_peer.clone(),
            })
    }

    /// Record where a session's NRPPa leg was relayed (#515).
    pub fn positioning_session_set_nrppa_peer(&self, corr: &str, peer: NrppaPeer) {
        if let Ok(mut sessions) = self.positioning_sessions.write() {
            if let Some(session) = sessions.get_mut(corr) {
                session.nrppa_peer = Some(peer);
            }
        }
    }

    /// Add `leg` to the legs session `corr` waits for. Call it BEFORE the leg is
    /// solicited, so its report cannot arrive first and find the session complete.
    pub fn positioning_session_expect_leg(&self, corr: &str, leg: MeasurementLeg) {
        if let Ok(mut sessions) = self.positioning_sessions.write() {
            if let Some(s) = sessions.get_mut(corr) {
                if !s.expected_legs.contains(&leg) {
                    s.expected_legs.push(leg);
                }
            }
        }
    }

    /// Stop waiting for `leg` (its solicitation failed). When every other leg has
    /// already reported, the session is solved now.
    pub fn positioning_session_withdraw_leg(&self, corr: &str, leg: MeasurementLeg) -> LegProgress {
        let ready = {
            let Ok(mut sessions) = self.positioning_sessions.write() else {
                return LegProgress::NoSession;
            };
            let Some(s) = sessions.get_mut(corr) else {
                return LegProgress::NoSession;
            };
            if s.reported_legs.contains(&leg) {
                return LegProgress::Waiting;
            }
            s.expected_legs.retain(|l| *l != leg);
            Self::all_legs_in(s).then(|| (s.request_id, s.accumulated.clone()))
        };
        match ready {
            Some((request_id, cells)) => {
                LegProgress::Completed(self.measurement_report(request_id, cells))
            }
            None => LegProgress::Waiting,
        }
    }

    fn all_legs_in(s: &PositioningSession) -> bool {
        !s.reported_legs.is_empty() && s.expected_legs.iter().all(|l| s.reported_legs.contains(l))
    }

    /// Report one leg's measurements for the session with measurement-store
    /// `request_id` (#715, #807).
    ///
    /// The measurements are added to the session's. When every expected leg has
    /// reported, all of them are solved together ([`Self::measurement_report`]) and
    /// the session completes. Until then nothing is solved, so a leg that arrives
    /// first (an NR E-CID LPP report with no timing term, a UE-only Multi-RTT
    /// report) can no longer end the session as `SolverFailed` before the leg that
    /// completes it arrives. A leg that reports twice adds its measurements again;
    /// the solvers count each TRP once.
    ///
    /// With no pending session (a debug route, or a session that already ended)
    /// the report is solved on its own, as before.
    pub fn measurement_leg_report(
        &self,
        request_id: u64,
        leg: MeasurementLeg,
        cells: Vec<CellMeasurement>,
    ) -> LegProgress {
        let corr = self
            .positioning_request_index
            .read()
            .ok()
            .and_then(|r| r.get(&request_id).cloned());
        let Some(corr) = corr else {
            return LegProgress::NoSession;
        };
        let ready = {
            let Ok(mut sessions) = self.positioning_sessions.write() else {
                return LegProgress::NoSession;
            };
            let Some(s) = sessions.get_mut(&corr) else {
                return LegProgress::NoSession;
            };
            s.accumulated.extend(cells);
            if !s.reported_legs.contains(&leg) {
                s.reported_legs.push(leg);
            }
            if Self::all_legs_in(s) {
                Some(s.accumulated.clone())
            } else {
                log::info!(
                    "Positioning session {corr}: {leg:?} reported; waiting for {:?}",
                    s.expected_legs
                        .iter()
                        .filter(|l| !s.reported_legs.contains(l))
                        .collect::<Vec<_>>()
                );
                None
            }
        };
        match ready {
            Some(cells) => LegProgress::Completed(self.measurement_report(request_id, cells)),
            None => LegProgress::Waiting,
        }
    }

    /// The response-time budget of session `corr` ran out (#807): solve with the
    /// legs that did report and complete the session. `None`, and the session left
    /// in place, when no leg reported at all, which the caller answers as
    /// unreachable.
    pub fn positioning_session_solve_now(&self, corr: &str) -> Option<PositioningOutcome> {
        let (request_id, cells, missing) = {
            let sessions = self.positioning_sessions.read().ok()?;
            let s = sessions.get(corr)?;
            if s.reported_legs.is_empty() {
                return None;
            }
            let missing: Vec<MeasurementLeg> = s
                .expected_legs
                .iter()
                .copied()
                .filter(|l| !s.reported_legs.contains(l))
                .collect();
            (s.request_id, s.accumulated.clone(), missing)
        };
        log::info!(
            "Positioning session {corr}: response-time budget expired without {missing:?}; \
             solving with the legs that reported"
        );
        Some(match self.measurement_report(request_id, cells) {
            Some(fix) => PositioningOutcome::Fix(fix),
            None => PositioningOutcome::SolverFailed,
        })
    }

    /// Look up the `lcsCorrelationId` of the newest session that used LPP
    /// `transactionNumber` `txn` (A4 fallback correlation; last-writer-wins).
    pub fn positioning_session_find_by_transaction(&self, txn: u8) -> Option<String> {
        self.positioning_txn_index.read().ok()?.get(&txn).cloned()
    }

    /// Number of pending positioning sessions.
    pub fn positioning_session_count(&self) -> usize {
        self.positioning_sessions
            .read()
            .map(|s| s.len())
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // A2: outbound-leg bookkeeping (AMF subscription cache + self identity).
    // -----------------------------------------------------------------------

    /// Cached N1N2 subscription id for `key` = "host:port|ueContextId".
    pub fn amf_subscription_get(&self, key: &str) -> Option<String> {
        self.amf_subscriptions.read().ok()?.get(key).cloned()
    }

    /// Cache an N1N2 subscription id (TS 29.518 §5.2.2.6) for reuse.
    pub fn amf_subscription_set(&self, key: impl Into<String>, subscription_id: impl Into<String>) {
        if let Ok(mut a) = self.amf_subscriptions.write() {
            a.insert(key.into(), subscription_id.into());
        }
    }

    /// Advertised base URI for the lmfd notify-callback routes.
    pub fn callback_base(&self) -> Option<String> {
        self.callback_base.read().ok()?.clone()
    }

    /// Set the advertised callback base URI (from the SBI bind address).
    pub fn set_callback_base(&self, base: impl Into<String>) {
        if let Ok(mut b) = self.callback_base.write() {
            *b = Some(base.into());
        }
    }

    /// Our NF instance id (used as servingLMFIdentification).
    pub fn nf_instance_id(&self) -> Option<String> {
        self.nf_instance_id.read().ok()?.clone()
    }

    /// Set our NF instance id at startup.
    pub fn set_nf_instance_id(&self, id: impl Into<String>) {
        if let Ok(mut n) = self.nf_instance_id.write() {
            *n = Some(id.into());
        }
    }

    /// Register (or update) a cell geodetic coordinate for use by the real
    /// positioning solvers. `nr_cgi` is the NR-CGI string that matches
    /// [`CellMeasurement::nr_cgi`]. Call this from config loading or tests.
    pub fn set_cell_coord(&self, nr_cgi: impl Into<String>, coord: TrpCoord) {
        if let Ok(mut reg) = self.cell_registry.write() {
            reg.insert(nr_cgi.into(), coord);
        }
    }

    /// What this LMF knows about `supi`'s LPP positioning capability (#103).
    ///
    /// `Unknown` unless a `ProvideCapabilities` has been decoded for that UE. Kept on
    /// the context rather than passed through the request path because the capability
    /// exchange and the positioning request are separate LPP transactions, possibly
    /// minutes apart.
    pub fn ue_lpp_capability(&self, supi: &str) -> crate::codec_glue::UeLppCapability {
        self.ue_capabilities
            .read()
            .ok()
            .and_then(|c| c.get(supi).copied())
            .unwrap_or_default()
    }

    /// Record what a UE reported (#103). Called from the N1 uplink path when a
    /// `ProvideCapabilities` arrives.
    pub fn note_ue_lpp_capability(&self, supi: &str, cap: crate::codec_glue::UeLppCapability) {
        if let Ok(mut c) = self.ue_capabilities.write() {
            c.insert(supi.to_string(), cap);
        }
    }

    /// The sidelink ranges this LMF holds for `supi` (nextgsim #138).
    ///
    /// Empty when the UE has reported none — which is every UE that does not do
    /// sidelink ranging, so empty is the normal answer and not a failure.
    pub fn sidelink_ranges(&self, supi: &str) -> Vec<crate::codec_glue::SidelinkRange> {
        self.sidelink_ranges
            .read()
            .ok()
            .and_then(|r| r.get(supi).cloned())
            .unwrap_or_default()
    }

    /// Record the ranges a UE reported (nextgsim #138), replacing any previous set.
    ///
    /// An EMPTY report clears the entry rather than being ignored: a UE that reports
    /// no ranges has told the LMF it no longer holds any, and keeping the old ones
    /// would have the LMF answer with a distance to a peer that may be gone.
    pub fn note_sidelink_ranges(&self, supi: &str, ranges: Vec<crate::codec_glue::SidelinkRange>) {
        if let Ok(mut map) = self.sidelink_ranges.write() {
            if ranges.is_empty() {
                map.remove(supi);
            } else {
                map.insert(supi.to_string(), ranges);
            }
        }
    }

    /// Empty the cell-coordinate registry (#103).
    ///
    /// Test-only, and needed because neither `init` nor `fini` clears it (see
    /// [`PROCESS_STATE_TEST_LOCK`]): a test that needs a KNOWN set of reference
    /// points has to remove whatever a sibling left, or it asserts against a scene it
    /// did not build.
    #[cfg(test)]
    pub fn clear_cell_registry_for_test(&self) {
        if let Ok(mut reg) = self.cell_registry.write() {
            reg.clear();
        }
    }

    /// The centroid of the configured reference points, with the spread around it
    /// (#103).
    ///
    /// Returns `(lat, lon, spread_m)` where the spread is the greatest distance from
    /// the centroid to any point — the honest uncertainty of "somewhere in this
    /// deployment", which is what a GNSS reference location amounts to. `None` when
    /// nothing is configured, so a caller cannot accidentally send (0, 0).
    ///
    /// A single reference point yields a spread of 0, which is correct: the reference
    /// location IS that point.
    pub fn reference_centroid(&self) -> Option<(f64, f64, f64)> {
        let cells = self.cell_registry.read().ok()?;
        if cells.is_empty() {
            return None;
        }
        let n = cells.len() as f64;
        let lat = cells.values().map(|c| c.lat_deg).sum::<f64>() / n;
        let lon = cells.values().map(|c| c.lon_deg).sum::<f64>() / n;
        // Equirectangular metres: exact enough for an uncertainty figure, and the
        // alternative (a geodesic) would be precision the input does not have.
        const M_PER_DEG: f64 = 111_320.0;
        let spread = cells
            .values()
            .map(|c| {
                let dy = (c.lat_deg - lat) * M_PER_DEG;
                let dx = (c.lon_deg - lon) * M_PER_DEG * lat.to_radians().cos();
                dy.hypot(dx)
            })
            .fold(0.0f64, f64::max);
        Some((lat, lon, spread))
    }

    /// How many reference points the registry holds (#103).
    ///
    /// Read by the positioning path to decide two things before spending a
    /// measurement campaign: whether a fix is possible at all (zero points means it
    /// is not, and the request is refused loudly rather than answered with a
    /// fabricated coordinate), and whether a multilateration method is worth
    /// requesting (`select_lpp_method` needs at least three).
    pub fn reference_point_count(&self) -> usize {
        self.cell_registry.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Build an owned [`TrpRegistry`] snapshot from the current cell
    /// coordinates (centroid-anchored origin). The caller drops the read lock
    /// before any write operations.
    pub fn build_trp_registry(&self) -> TrpRegistry {
        if let Ok(cells) = self.cell_registry.read() {
            TrpRegistry::from_entries(cells.iter().map(|(k, v)| (k.clone(), *v)))
        } else {
            TrpRegistry::from_entries(std::iter::empty())
        }
    }
}

/// Compute a location estimate from cell measurements.
///
/// When `registry` is non-empty and contains coordinates for the reported
/// cells, this calls the real geometric solvers from [`crate::positioning`].
/// Solver priority (highest confidence first):
///
/// 1. **Multi-RTT** — if ≥ 3 registry TRPs have a two-sided RTT: `rtt_ns`, or
///    `ue_rx_tx_ns + gnb_rx_tx_ns` (TS 38.305 §8.10, #713).
/// 2. **NR DL-TDOA** — if ≥ 3 cells report `rstd_ns` and are in the registry.
/// 3. **AoA** — if ≥ 2 cells report `aoa` and are in the registry.
/// 4. **ECID** — if the best-RSRP cell has a timing term (`ecid_rtt_ns`, or a
///    debug-route `timing_advance`) and is in the registry.
///
/// On any solver failure or when the registry is empty / has no matching
/// cells, falls back to the heuristic placeholder (lat/lon 0.0, method-based
/// accuracy estimate).
///
/// A7 (lmfd-11): this helper is now **test-only** (`#[cfg(test)]`). The runtime
/// path uses [`try_real_solve`] directly (via
/// [`LmfContext::measurement_report`]) and NEVER falls back to the placeholder —
/// an unsolvable report yields `None`, not a fabricated (0,0) fix. This helper
/// is retained only so the solver-selection tests can assert placeholder shapes.
#[cfg(test)]
fn compute_location(
    method: &PositioningMethod,
    measurements: &[CellMeasurement],
    registry: &TrpRegistry,
) -> LocationEstimate {
    if measurements.is_empty() {
        return LocationEstimate::default();
    }

    if !registry.is_empty() {
        if let Some(est) = try_real_solve(measurements, registry) {
            return est;
        }
    }

    compute_location_placeholder(method, measurements)
}

/// Attempt a real geometric solve using the positioning solvers.
/// Returns `None` when there are insufficient registry-matched measurements.
fn try_real_solve(
    measurements: &[CellMeasurement],
    registry: &TrpRegistry,
) -> Option<LocationEstimate> {
    // --- Multi-RTT (≥3 TRPs with a two-sided RTT known to the registry) ------
    let rtt_obs = multi_rtt_observations(measurements, registry);

    if rtt_obs.len() >= 3 {
        match solve_multi_rtt(registry, &rtt_obs) {
            Ok(est) => {
                return Some(LocationEstimate {
                    latitude: est.lat_deg,
                    longitude: est.lon_deg,
                    altitude: est.height_m,
                    horizontal_accuracy: est.horizontal_uncertainty_m(),
                    vertical_accuracy: None,
                    method_used: Some(est.method.as_spec_str().to_string()),
                    timestamp: 0,
                })
            }
            Err(e) => log::warn!("Multi-RTT solve failed: {e}"),
        }
    }

    // --- NR DL-TDOA (≥3 TRPs with an RSTD known to the registry) ------------
    let (tdoa_obs, rebased) = tdoa_observations(measurements, registry);

    if tdoa_obs.len() >= 3 {
        match solve_tdoa(registry, &tdoa_obs) {
            Ok(est) => {
                // Losing the reporting reference costs one TRP of redundancy; with
                // three TRPs left the residual is zero by construction and says
                // nothing about the error. The reported accuracy is doubled so a
                // consumer does not read that as precision (#824 review).
                let widen = if rebased { 2.0 } else { 1.0 };
                return Some(LocationEstimate {
                    latitude: est.lat_deg,
                    longitude: est.lon_deg,
                    altitude: est.height_m,
                    horizontal_accuracy: est.horizontal_uncertainty_m() * widen,
                    vertical_accuracy: None,
                    method_used: Some(est.method.as_spec_str().to_string()),
                    timestamp: 0,
                });
            }
            Err(e) => log::warn!("DL-TDOA solve failed: {e}"),
        }
    }

    // --- AoA (≥2 cells with aoa known to the registry) ----------------------
    let aoa_obs: Vec<AoaObservation> = measurements
        .iter()
        .filter(|m| m.aoa.is_some() && registry.lookup(&m.nr_cgi).is_some())
        .map(|m| AoaObservation {
            trp_id: m.nr_cgi.clone(),
            azimuth_deg: m.aoa.unwrap(),
        })
        .collect();

    if aoa_obs.len() >= 2 {
        match solve_aoa(registry, &aoa_obs) {
            Ok(est) => {
                return Some(LocationEstimate {
                    latitude: est.lat_deg,
                    longitude: est.lon_deg,
                    altitude: est.height_m,
                    horizontal_accuracy: est.horizontal_uncertainty_m(),
                    vertical_accuracy: None,
                    method_used: Some(est.method.as_spec_str().to_string()),
                    timestamp: 0,
                })
            }
            Err(e) => log::warn!("AoA solve failed: {e}"),
        }
    }

    // --- ECID (serving cell = best RSRP; needs a timing term + registry hit) -
    let serving = measurements
        .iter()
        .filter(|m| {
            (m.ecid_rtt_ns.is_some() || m.timing_advance.is_some())
                && registry.lookup(&m.nr_cgi).is_some()
        })
        .max_by_key(|m| m.rsrp.unwrap_or(i16::MIN))?;

    // #832: a decoded round trip when the wire gave one, ranged with its own bin
    // width; a raw NR TA command only from the debug JSON route.
    let solved = match serving.ecid_rtt_ns {
        Some(rtt) => {
            let bin = if rtt < 4096.0 * crate::positioning::TS_NS {
                2.0
            } else {
                8.0
            };
            crate::positioning::solve_ecid_round_trip(
                registry,
                &serving.nr_cgi,
                rtt,
                bin * crate::positioning::TS_NS,
            )
        }
        None => solve_ecid(registry, &serving.nr_cgi, serving.timing_advance, 1),
    };
    match solved {
        Ok(est) => Some(LocationEstimate {
            latitude: est.lat_deg,
            longitude: est.lon_deg,
            altitude: est.height_m,
            horizontal_accuracy: est.horizontal_uncertainty_m(),
            vertical_accuracy: None,
            // TS 29.572 PositioningMethod: E-CID of an E-UTRA serving cell is
            // ECID, of an NR one NR_ECID (#715).
            method_used: Some(
                if serving.eutra {
                    crate::nlmf::positioning_method::ECID
                } else {
                    est.method.as_spec_str()
                }
                .to_string(),
            ),
            timestamp: 0,
        }),
        Err(e) => {
            log::warn!("ECID solve failed: {e}");
            None
        }
    }
}

/// The registry key of the TRP `m` was measured on (#714): `nr_cgi` when the
/// registry holds it, else `prs-<dl_prs_id>`.
///
/// The LPP adapters key a measurement by PCI when the UE gave one, which is what
/// a PCI-keyed registry needs. The DL-TDOA reference can only be keyed by its
/// DL-PRS ID, because `DL-PRS-ID-Info-r16` has no PCI. So a registry keyed by
/// DL-PRS ID would otherwise miss every neighbour that reported a PCI.
fn resolve_trp(m: &CellMeasurement, registry: &TrpRegistry) -> Option<String> {
    if registry.lookup(&m.nr_cgi).is_some() {
        return Some(m.nr_cgi.clone());
    }
    let alias = format!("prs-{}", m.dl_prs_id?);
    registry.lookup(&alias).map(|_| alias)
}

/// The DL-TDOA observations in `measurements`, with element 0 the reference
/// that `solve_tdoa` expects, and whether a reported reference had to be
/// replaced (#714).
///
/// Every RSTD in a report is relative to that report's DL-PRS reference TRP r
/// (TS 38.215 §5.1.29): `rstd_i = t_i − t_r`. So for any TRP j of the same
/// report, `t_i − t_j = rstd_i − rstd_j`, and a report can be re-expressed
/// relative to any TRP the registry knows.
///
/// Measurements are grouped by `rstd_reference`, one group per reference TRP.
/// An MO-LR can carry several LPP reports, and reports may use different
/// references (#824 review). The group with the most known TRPs is the base.
/// Another group joins it through a TRP both hold: the offset
/// `rstd_base(s) − rstd_group(s)` moves the whole group onto the base's
/// reference. A group that shares no known TRP with the base cannot be related
/// to it, and is dropped and logged rather than mixed in. Finally every RSTD is
/// rebased on element 0, the known TRP with the smallest |RSTD|: the reporting
/// reference itself when the registry knows it.
///
/// Before #714 the entries were sorted by |RSTD| and the first one was used as
/// the reference without rebasing. When the registry did not know the true
/// reference, a neighbour with a non-zero RSTD became the reference while the
/// other RSTDs stayed relative to the absent one, and the solver converged to a
/// wrong fix and reported it as valid.
///
/// A TRP reported twice (e.g. once by PCI, once by DL-PRS ID) is used once.
fn tdoa_observations(
    measurements: &[CellMeasurement],
    registry: &TrpRegistry,
) -> (Vec<TdoaObservation>, bool) {
    // One observation and the TRP identity it is joined on. Within a session a
    // DL-PRS ID names exactly one TRP (TS 37.355 associates each `dl-PRS-ID` with a
    // single TRP), while a PCI does not: a multi-TRP cell puts one PCI on several
    // TRPs, and PCIs are reused across sites (#824 review). So two observations are
    // of the same TRP when their DL-PRS IDs are equal, and only an observation
    // without a DL-PRS ID falls back to the registry key.
    struct Obs {
        key: String,
        prs: Option<u8>,
        tdoa_ns: f64,
    }
    fn same(a: &Obs, b: &Obs) -> bool {
        match (a.prs, b.prs) {
            (Some(x), Some(y)) => x == y,
            _ => a.key == b.key,
        }
    }

    // A DL-PRS ID names one TRP across the reports of a session. A neighbour that
    // resolves by its PCI therefore also tells which TRP its DL-PRS ID is, and a
    // reference TRP, which only carries a DL-PRS ID, can be found through it.
    let mut by_prs: HashMap<u8, String> = HashMap::new();
    for m in measurements {
        if let (Some(prs), Some(key)) = (m.dl_prs_id, resolve_trp(m, registry)) {
            by_prs.entry(prs).or_insert(key);
        }
    }
    let resolve = |m: &CellMeasurement| {
        resolve_trp(m, registry).or_else(|| m.dl_prs_id.and_then(|p| by_prs.get(&p).cloned()))
    };
    // A registry key reached from two DL-PRS IDs is two TRPs under one key (a
    // reused PCI, or one PCI across a multi-TRP cell). Its coordinate is right for
    // at most one of them, and which one cannot be told, so the key is not used.
    let mut prs_of_key: HashMap<String, Vec<u8>> = HashMap::new();
    for m in measurements.iter().filter(|m| m.rstd_ns.is_some()) {
        if let (Some(prs), Some(key)) = (m.dl_prs_id, resolve(m)) {
            let ids = prs_of_key.entry(key).or_default();
            if !ids.contains(&prs) {
                ids.push(prs);
            }
        }
    }
    let ambiguous: Vec<String> = prs_of_key
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(key, ids)| {
            log::warn!(
                "DL-TDOA: registry key {key} is reached from DL-PRS IDs {ids:?}, i.e. from \
                 more than one TRP; its RSTDs are not used (key the registry by prs-<id> for \
                 multi-TRP cells or reused PCIs)"
            );
            key
        })
        .collect();

    // Per reference, the known TRPs and their RSTDs in report order.
    let mut groups: Vec<(Option<u8>, Vec<Obs>)> = Vec::new();
    for m in measurements {
        let (Some(rstd), Some(key)) = (m.rstd_ns, resolve(m)) else {
            continue;
        };
        if !rstd.is_finite() || ambiguous.contains(&key) {
            continue;
        }
        let g = match groups.iter().position(|(r, _)| *r == m.rstd_reference) {
            Some(g) => g,
            None => {
                groups.push((m.rstd_reference, Vec::new()));
                groups.len() - 1
            }
        };
        let o = Obs {
            key,
            prs: m.dl_prs_id,
            tdoa_ns: rstd,
        };
        if !groups[g].1.iter().any(|b| same(b, &o)) {
            groups[g].1.push(o);
        }
    }
    let Some(base_group) = (0..groups.len()).max_by_key(|&g| groups[g].1.len()) else {
        return (Vec::new(), false);
    };
    let mut obs = groups.swap_remove(base_group).1;
    // Join the other groups through a shared TRP, until no more join.
    loop {
        let joinable = groups.iter().enumerate().find_map(|(g, (_, group))| {
            group.iter().find_map(|o| {
                obs.iter()
                    .find(|b| same(b, o))
                    .map(|b| (g, b.tdoa_ns - o.tdoa_ns))
            })
        });
        let Some((g, offset)) = joinable else {
            break;
        };
        for o in groups.swap_remove(g).1 {
            if !obs.iter().any(|b| same(b, &o)) {
                obs.push(Obs {
                    tdoa_ns: o.tdoa_ns + offset,
                    ..o
                });
            }
        }
    }
    for (reference, group) in &groups {
        log::warn!(
            "DL-TDOA: a report relative to DL-PRS reference {reference:?} shares no known TRP \
             with the others; its {} RSTD(s) are dropped, not mixed in",
            group.len()
        );
    }
    // The solver keys by registry key, so each key may appear once. Two
    // observations with one key and no DL-PRS ID between them are one TRP.
    let mut out: Vec<TdoaObservation> = Vec::new();
    for o in obs {
        if !out.iter().any(|b| b.trp_id == o.key) {
            out.push(TdoaObservation {
                trp_id: o.key,
                tdoa_ns: o.tdoa_ns,
            });
        }
    }
    let mut obs = out;
    let Some(reference) = (0..obs.len()).min_by(|&a, &b| {
        obs[a]
            .tdoa_ns
            .abs()
            .partial_cmp(&obs[b].tdoa_ns.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    }) else {
        return (obs, false);
    };
    obs.swap(0, reference);
    let base = obs[0].tdoa_ns;
    let rebased = base != 0.0;
    if rebased {
        log::info!(
            "DL-TDOA: the reporting reference TRP is not in the registry; RSTDs rebased \
             on {} ({base} ns)",
            obs[0].trp_id
        );
    }
    for o in &mut obs {
        o.tdoa_ns -= base;
    }
    (obs, rebased)
}

/// The Multi-RTT range observations in `measurements`, one per TRP the registry
/// knows (#713).
///
/// TS 38.305 §8.10 defines the Multi-RTT observable as the sum of the two Rx–Tx
/// time differences of one TRP: the UE's (TS 38.215 §5.1.30, measured on that
/// TRP's DL-PRS and reported over LPP) and the gNB's (TS 38.215 §5.2.3, measured
/// on the UE's UL SRS and reported over NRPPa). With `t` the propagation time,
/// `UE Rx–Tx = t_UE-RX − t_UE-TX` and `gNB Rx–Tx = t_gNB-RX − t_gNB-TX`, so the
/// sum is `2t` whatever the two clocks' offset, and the range is `c·RTT/2`.
///
/// Either half alone is NOT a range: it carries the unknown offset between the UE
/// and the gNB clocks. So a TRP contributes only when:
/// - a measurement carries a two-sided `rtt_ns` already, or
/// - both halves are present for it, in one measurement or two with the same key.
///
/// UE halves without a gNB half are counted and logged, never ranged. A
/// negative sum is a measurement error, not a distance, and that TRP is dropped.
fn multi_rtt_observations(
    measurements: &[CellMeasurement],
    registry: &TrpRegistry,
) -> Vec<RttObservation> {
    // One pass: the first value of each quantity per TRP, in first-seen order.
    #[derive(Default)]
    struct Halves {
        rtt_ns: Option<f64>,
        ue: Option<f64>,
        gnb: Option<f64>,
    }
    let mut order: Vec<String> = Vec::new();
    let mut by_trp: HashMap<String, Halves> = HashMap::new();
    for m in measurements {
        if m.rtt_ns.is_none() && m.ue_rx_tx_ns.is_none() && m.gnb_rx_tx_ns.is_none() {
            continue;
        }
        let Some(key) = resolve_trp(m, registry) else {
            continue;
        };
        let h = by_trp.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            Halves::default()
        });
        h.rtt_ns = h.rtt_ns.or(m.rtt_ns.map(|r| r as f64));
        h.ue = h.ue.or(m.ue_rx_tx_ns);
        h.gnb = h.gnb.or(m.gnb_rx_tx_ns);
    }
    let mut obs: Vec<RttObservation> = Vec::new();
    let mut unpaired: Vec<&str> = Vec::new();
    for key in &order {
        let h = &by_trp[key];
        let rtt_ns = h.rtt_ns.or_else(|| Some(h.ue? + h.gnb?));
        match rtt_ns {
            Some(rtt) if rtt.is_finite() && rtt >= 0.0 => obs.push(RttObservation {
                trp_id: key.to_string(),
                range_m: rtt_ns_to_range_m(rtt),
            }),
            Some(rtt) => log::warn!(
                "Multi-RTT: TRP {key} has a negative or non-finite RTT ({rtt} ns); dropped"
            ),
            None => unpaired.push(key.as_str()),
        }
    }
    if !unpaired.is_empty() {
        log::warn!(
            "Multi-RTT: {} TRP(s) ({}) have one Rx-Tx half but not the other; TS 38.305 \
             §8.10 ranges on UE Rx-Tx + gNB Rx-Tx, so they are not ranged",
            unpaired.len(),
            unpaired.join(", ")
        );
    }
    obs
}

/// Heuristic placeholder that returns a lat/lon 0.0 fix with a method-derived
/// accuracy estimate.
///
/// A7 (lmfd-11): this is a **fabrication** (fake 0.0/0.0 coordinates) and is now
/// **test-only** (`#[cfg(test)]`). It is NOT reachable from any served path —
/// the runtime positioning path returns `None` (no fix → 500 POSITIONING_FAILED
/// / 404) rather than a made-up location. Retained only so the solver-selection
/// unit tests can assert the placeholder's shape.
#[cfg(test)]
fn compute_location_placeholder(
    method: &PositioningMethod,
    measurements: &[CellMeasurement],
) -> LocationEstimate {
    let accuracy = match method {
        PositioningMethod::Ecid => {
            // ECID accuracy: ~100-300m typically
            let best_rsrp = measurements
                .iter()
                .filter_map(|m| m.rsrp)
                .max()
                .unwrap_or(-100);
            // Better signal = slightly better accuracy
            200.0 - (best_rsrp as f64 + 100.0).max(0.0) * 2.0
        }
        PositioningMethod::NrBased => {
            // NR DL-TDOA / Multi-RTT: ~3-10m
            if measurements.iter().any(|m| m.rtt_ns.is_some()) {
                5.0 // Multi-RTT
            } else {
                10.0 // TDOA
            }
        }
        PositioningMethod::Otdoa => 15.0,
        PositioningMethod::Gnss => 3.0,
        _ => 100.0,
    };
    LocationEstimate {
        latitude: 0.0,
        longitude: 0.0,
        altitude: None,
        horizontal_accuracy: accuracy,
        vertical_accuracy: None,
        method_used: Some(format!("{method:?}")),
        timestamp: 0,
    }
}

impl Default for LmfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global LMF context
static GLOBAL_LMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<LmfContext>>> =
    std::sync::OnceLock::new();

pub fn lmf_self() -> Arc<RwLock<LmfContext>> {
    GLOBAL_LMF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(LmfContext::new())))
        .clone()
}

pub fn lmf_context_init(max_measurements: usize) {
    let ctx = lmf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_measurements);
        // #103, TEST BUILDS ONLY: empty the cell-coordinate registry.
        //
        // `init` does not clear it (and never did, despite what
        // `PROCESS_STATE_TEST_LOCK`'s doc used to claim), so coordinates written by one
        // test persisted for the life of the binary and every later test's behaviour
        // depended on the ORDER it ran in. That was invisible until #103 made an empty
        // registry change an outcome -- and then it produced four separate flakes at
        // roughly 1 whole-workspace run in 8, each of which passed a first green run.
        //
        // Clearing here makes the registry a function of each test's own seeding, so a
        // test that needs coordinates fails DETERMINISTICALLY without them instead of
        // depending on a sibling. That is the difference between a bug found by a
        // 20-run loop and one found by a single `cargo test`.
        //
        // Production is untouched: `lmf_context_init` runs once at startup, before
        // `site_config::load_into_context` fills the registry.
        #[cfg(test)]
        context.clear_cell_registry_for_test();
    };
}

/// The ONE agreement about the process-global LMF context, for tests (#308).
///
/// # Correction (#103): what init and fini actually clear
///
/// This doc used to say that `lmf_context_init` "clears the measurement, session and
/// **cell-coordinate** registries for the whole process". **It clears none of them.**
/// `LmfContext::init` early-returns when the context is already initialized and
/// otherwise only records `max_measurements`; `fini` clears UE locations,
/// measurements, reports and LDR sessions, and **not** the cell-coordinate registry.
///
/// So coordinates written by any test persist for the life of the test binary. That
/// makes the lock below MORE necessary rather than less — the sharing is
/// unconditional rather than dependent on a wipe — but the mechanism #308 recorded
/// was wrong, and a test that relied on `init` for isolation would silently inherit
/// a sibling's scene. #103's own assistance-data tests did exactly that and failed
/// on the first run, which is how this was found; they now call
/// [`LmfContext::clear_cell_registry_for_test`].
///
/// `seed_scene_and_build_multi_rtt_lpp` writes coordinates INTO the global registry
/// via [`LmfContext::set_cell_coord`] and never removes them, and `capabilities_body`
/// derives `nrppaSupported` / `nlsInterfaceSupported` from exactly that registry.
///
/// So `test_capabilities_handler_serves_the_derived_body` had a genuine TOCTOU: it
/// reads the served body from `handle_capabilities()` and then recomputes the
/// expected body from the context, and a sibling seeding coordinates between the two
/// reads makes them disagree. Its own doc comment said the equality "holds whatever
/// state a sibling test has left behind" — true of state left behind, false of state
/// changed in the gap, which is why it failed 2 of 20 `cargo test --workspace` runs
/// while `-p nextgcore-lmfd` alone was always green.
///
/// Declared beside the global rather than inside `mod tests` so a sibling module
/// reaches this static instead of declaring a second one, and taken by every test
/// that touches the context — readers included. #308 measured what guarding only the
/// writers is worth: nothing, with a lock to look at.
#[cfg(test)]
pub(crate) static PROCESS_STATE_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

pub fn lmf_context_final() {
    let ctx = lmf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lmf_context_new() {
        let ctx = LmfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.measurement_count(), 0);
    }

    #[test]
    fn test_lmf_init_fini() {
        let mut ctx = LmfContext::new();
        ctx.init(256);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_supported_methods() {
        let ctx = LmfContext::new();
        let methods = ctx.supported_methods();
        assert!(methods.contains(&PositioningMethod::Ecid));
        assert!(methods.contains(&PositioningMethod::NrBased));
    }

    #[test]
    fn test_measurement_request_report() {
        let mut ctx = LmfContext::new();
        ctx.init(256);

        let req = ctx
            .measurement_request(
                1001,
                PositioningMethod::Ecid,
                None,
                Some("gnb-001".to_string()),
                PositioningQos::BestEffort,
            )
            .unwrap();
        assert_eq!(req.method, PositioningMethod::Ecid);
        assert_eq!(req.state, MeasurementState::Pending);

        let found = ctx.measurement_find(req.request_id).unwrap();
        assert_eq!(found.amf_ue_ngap_id, 1001);

        // Submit report
        let cells = vec![CellMeasurement {
            nr_cgi: "001-01-0001-01".to_string(),
            rsrp: Some(-80),
            rsrq: Some(-10),
            timing_advance: Some(100),
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            rstd_reference: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }];

        // A7 (lmfd-11): with no TRP registry configured the report cannot be
        // solved to a real fix, so NO (fabricated) location is returned — the
        // runtime path no longer falls back to the (0,0) placeholder. The report
        // is still recorded and the request marked Completed.
        let location = ctx.measurement_report(req.request_id, cells);
        assert!(location.is_none());

        let report = ctx.report_find(req.request_id).unwrap();
        assert_eq!(report.cell_measurements.len(), 1);
        assert!(report.location.is_none());

        let completed = ctx.measurement_find(req.request_id).unwrap();
        assert_eq!(completed.state, MeasurementState::Completed);
    }

    #[test]
    fn test_nr_based_measurement() {
        let mut ctx = LmfContext::new();
        ctx.init(256);

        let req = ctx
            .measurement_request(
                2001,
                PositioningMethod::NrBased,
                Some(NrPositioningMethod::MultiRtt),
                Some("gnb-002".to_string()),
                PositioningQos::HighAccuracy,
            )
            .unwrap();

        let cells = vec![
            CellMeasurement {
                nr_cgi: "001-01-0002-01".to_string(),
                rsrp: Some(-75),
                rsrq: Some(-8),
                timing_advance: None,
                aoa: Some(45.0),
                rtt_ns: Some(1000),
                rstd_ns: None,
                ue_rx_tx_ns: None,
                rstd_reference: None,
                ecid_rtt_ns: None,
                gnb_rx_tx_ns: None,
                dl_prs_id: None,
                eutra: false,
            },
            CellMeasurement {
                nr_cgi: "001-01-0002-02".to_string(),
                rsrp: Some(-85),
                rsrq: Some(-12),
                timing_advance: None,
                aoa: Some(120.0),
                rtt_ns: Some(2000),
                rstd_ns: None,
                ue_rx_tx_ns: None,
                rstd_reference: None,
                ecid_rtt_ns: None,
                gnb_rx_tx_ns: None,
                dl_prs_id: None,
                eutra: false,
            },
        ];

        // A7 (lmfd-11): no TRP registry ⇒ no real solve ⇒ no fix returned (the
        // runtime path never fabricates a placeholder estimate). The real
        // solver path with a populated registry is covered by
        // `test_compute_location_multi_rtt_real_solve` and
        // `test_measurement_report_completes_session_with_real_fix`.
        let location = ctx.measurement_report(req.request_id, cells);
        assert!(location.is_none());
    }

    #[test]
    fn test_ue_location_update() {
        let mut ctx = LmfContext::new();
        ctx.init(256);

        let loc = LocationEstimate {
            latitude: 37.7749,
            longitude: -122.4194,
            horizontal_accuracy: 10.0,
            ..Default::default()
        };
        assert!(ctx.ue_location_update("imsi-001010000000001", loc));

        let found = ctx.ue_location_get("imsi-001010000000001").unwrap();
        let loc = found.last_location.unwrap();
        assert!((loc.latitude - 37.7749).abs() < 0.001);
    }

    // -- A8: LDR trigger-task lifecycle -------------------------------------

    #[test]
    fn test_register_ldr_carries_periodic_event_info() {
        let ctx = LmfContext::new();
        assert!(ctx.register_ldr(LdrContext {
            ldr_reference: "aa10".to_string(),
            ldr_type: "PERIODIC".to_string(),
            hgmlc_callback_uri: Some("http://gmlc/cb".to_string()),
            supi: Some("imsi-1".to_string()),
            periodic_event_info: Some(PeriodicReporting {
                reporting_amount: 3,
                reporting_interval_secs: 60,
                reporting_interval_ms: None,
            }),
        }));
        let found = ctx.ldr_find("aa10").unwrap();
        let pei = found.periodic_event_info.unwrap();
        assert_eq!(pei.reporting_amount, 3);
        assert_eq!(pei.reporting_interval_secs, 60);
    }

    // A8 risk: task leakage on shutdown. `fini` must abort every running
    // trigger task (shutdown-token discipline). Uses a LOCAL context (never the
    // process-global one) so it is safe under parallel test execution.
    #[tokio::test]
    async fn test_fini_aborts_trigger_tasks() {
        let mut ctx = LmfContext::new();
        ctx.init(16);
        // A never-completing task stands in for a long-interval periodic producer.
        let jh = tokio::spawn(async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
        ctx.ldr_task_register("ref-shutdown", jh.abort_handle());
        assert_eq!(ctx.ldr_task_count(), 1);

        ctx.fini();
        assert_eq!(ctx.ldr_task_count(), 0, "fini must drop all task handles");

        // The task was aborted (awaiting it yields a cancellation JoinError).
        let joined = jh.await;
        assert!(
            joined.is_err() && joined.unwrap_err().is_cancelled(),
            "fini must abort the running trigger task"
        );
    }

    // A8: `cancel_ldr` aborts a running trigger task from the outside;
    // `ldr_task_register` replacing an existing handle aborts the superseded one.
    #[tokio::test]
    async fn test_cancel_ldr_aborts_trigger_task() {
        let mut ctx = LmfContext::new();
        ctx.init(16);
        ctx.register_ldr(LdrContext {
            ldr_reference: "ref-cancel".to_string(),
            ldr_type: "PERIODIC".to_string(),
            hgmlc_callback_uri: Some("http://gmlc/cb".to_string()),
            supi: Some("imsi-2".to_string()),
            periodic_event_info: None,
        });
        let jh = tokio::spawn(async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
        ctx.ldr_task_register("ref-cancel", jh.abort_handle());

        assert!(ctx.cancel_ldr("ref-cancel"), "the LDR session existed");
        assert_eq!(ctx.ldr_task_count(), 0);
        let joined = jh.await;
        assert!(joined.is_err() && joined.unwrap_err().is_cancelled());
    }

    #[test]
    fn test_compute_location_ecid() {
        // Empty registry -> placeholder path (lat/lon 0.0, coarse accuracy).
        let registry = TrpRegistry::from_entries(std::iter::empty());
        let cells = vec![CellMeasurement {
            nr_cgi: "test-cell".to_string(),
            rsrp: Some(-70),
            rsrq: None,
            timing_advance: None,
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            rstd_reference: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }];
        let loc = compute_location(&PositioningMethod::Ecid, &cells, &registry);
        assert!(loc.horizontal_accuracy > 50.0); // ECID is coarse
        assert_eq!(loc.latitude, 0.0);
        assert_eq!(loc.longitude, 0.0);
    }

    #[test]
    fn test_compute_location_gnss() {
        // Empty registry -> placeholder path.
        let registry = TrpRegistry::from_entries(std::iter::empty());
        let cells = vec![CellMeasurement {
            nr_cgi: "test-cell".to_string(),
            rsrp: None,
            rsrq: None,
            timing_advance: None,
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            rstd_reference: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }];
        let loc = compute_location(&PositioningMethod::Gnss, &cells, &registry);
        assert!(loc.horizontal_accuracy <= 5.0); // GNSS is accurate
    }
}

// ===========================================================================
// Real-solver integration tests (lmfd-08)
// ===========================================================================
// These build a known synthetic scene (4 cells at known ENU offsets from a
// reference origin, a UE at a known geodetic point), feed consistent
// measurements into compute_location via a populated LmfContext registry, and
// assert the returned lat/lon recovers the known position within tolerance.
#[cfg(test)]
mod tests_real_solve {
    use super::*;
    use crate::positioning::{
        enu_to_geodetic, geodetic_to_enu, EnuPoint, TrpCoord, SPEED_OF_LIGHT_M_S,
    };

    const ORIGIN_LAT: f64 = 37.7749;
    const ORIGIN_LON: f64 = -122.4194;

    /// Build a 4-cell scene at known ENU offsets, plus a UE at a known point.
    /// Returns (ctx_with_registry, trp_coords, true_ue_geodetic, true_ue_enu, origin).
    fn scene() -> (
        LmfContext,
        Vec<(String, TrpCoord)>,
        TrpCoord,
        EnuPoint,
        TrpCoord,
    ) {
        let origin = TrpCoord::new(ORIGIN_LAT, ORIGIN_LON, 0.0);
        let trp_enu = [
            (
                "cell-a",
                EnuPoint {
                    e: 0.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
            (
                "cell-b",
                EnuPoint {
                    e: 1000.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
            (
                "cell-c",
                EnuPoint {
                    e: 0.0,
                    n: 1000.0,
                    u: 0.0,
                },
            ),
            (
                "cell-d",
                EnuPoint {
                    e: 1000.0,
                    n: 1000.0,
                    u: 0.0,
                },
            ),
        ];
        let entries: Vec<(String, TrpCoord)> = trp_enu
            .iter()
            .map(|(id, p)| (id.to_string(), enu_to_geodetic(*p, origin)))
            .collect();

        let mut ctx = LmfContext::new();
        ctx.init(256);
        for (id, coord) in &entries {
            ctx.set_cell_coord(id.clone(), *coord);
        }

        let true_enu = EnuPoint {
            e: 350.0,
            n: 600.0,
            u: 0.0,
        };
        let true_geo = enu_to_geodetic(true_enu, origin);
        (ctx, entries, true_geo, true_enu, origin)
    }

    /// Horizontal distance (metres) between two geodetic coords via a shared origin.
    fn geo_dist_m(a: TrpCoord, b: TrpCoord) -> f64 {
        let origin = TrpCoord::new(ORIGIN_LAT, ORIGIN_LON, 0.0);
        let pa = geodetic_to_enu(a, origin);
        let pb = geodetic_to_enu(b, origin);
        (pa.e - pb.e).hypot(pa.n - pb.n)
    }

    /// Exact one-way range (m) from a TRP geodetic coord to a UE ENU point.
    fn exact_range_m(trp: TrpCoord, ue_enu: EnuPoint, origin: TrpCoord) -> f64 {
        let p = geodetic_to_enu(trp, origin);
        (ue_enu.e - p.e).hypot(ue_enu.n - p.n)
    }

    // -- Multi-RTT path -------------------------------------------------------
    #[test]
    fn test_compute_location_multi_rtt_real_solve() {
        let (ctx, entries, true_geo, true_enu, origin) = scene();
        let registry = ctx.build_trp_registry();

        // Derive exact RTT (ns) for each cell from the known UE position.
        let cells: Vec<CellMeasurement> = entries
            .iter()
            .map(|(id, coord)| {
                let range_m = exact_range_m(*coord, true_enu, origin);
                // rtt_ns is round-trip; rtt_ns_to_range_m divides by 2.
                let rtt_ns = (range_m * 2.0 / SPEED_OF_LIGHT_M_S * 1e9) as u64;
                CellMeasurement {
                    nr_cgi: id.clone(),
                    rsrp: Some(-80),
                    rsrq: Some(-10),
                    timing_advance: None,
                    aoa: None,
                    rtt_ns: Some(rtt_ns),
                    rstd_ns: None,
                    ue_rx_tx_ns: None,
                    rstd_reference: None,
                    ecid_rtt_ns: None,
                    gnb_rx_tx_ns: None,
                    dl_prs_id: None,
                    eutra: false,
                }
            })
            .collect();

        let loc = compute_location(&PositioningMethod::NrBased, &cells, &registry);
        let got = TrpCoord::new(loc.latitude, loc.longitude, 0.0);
        let err_m = geo_dist_m(got, true_geo);
        assert!(
            err_m < 50.0,
            "Multi-RTT position error {err_m:.2}m exceeds 50 m tolerance"
        );
        assert!(loc.horizontal_accuracy > 0.0);
        assert_eq!(loc.method_used.as_deref(), Some("MULTI-RTT"));
    }

    // -- NR DL-TDOA path ------------------------------------------------------
    #[test]
    fn test_compute_location_dl_tdoa_real_solve() {
        let (ctx, entries, true_geo, true_enu, origin) = scene();
        let registry = ctx.build_trp_registry();

        // Reference TRP = entries[0] (RSTD 0). Each cell's RSTD is the signed
        // range difference vs the reference, in ns: (range_i − range_ref)/c.
        let ref_range = exact_range_m(entries[0].1, true_enu, origin);
        let cells: Vec<CellMeasurement> = entries
            .iter()
            .map(|(id, coord)| {
                let range_m = exact_range_m(*coord, true_enu, origin);
                let rstd_ns = (range_m - ref_range) / SPEED_OF_LIGHT_M_S * 1e9;
                CellMeasurement {
                    nr_cgi: id.clone(),
                    rsrp: Some(-80),
                    rsrq: None,
                    timing_advance: None,
                    aoa: None,
                    rtt_ns: None,
                    rstd_ns: Some(rstd_ns),
                    ue_rx_tx_ns: None,
                    rstd_reference: None,
                    ecid_rtt_ns: None,
                    gnb_rx_tx_ns: None,
                    dl_prs_id: None,
                    eutra: false,
                }
            })
            .collect();

        let loc = compute_location(&PositioningMethod::NrBased, &cells, &registry);
        let got = TrpCoord::new(loc.latitude, loc.longitude, 0.0);
        let err_m = geo_dist_m(got, true_geo);
        assert!(
            err_m < 50.0,
            "DL-TDOA position error {err_m:.2}m exceeds 50 m tolerance"
        );
        assert!(loc.horizontal_accuracy > 0.0);
        // Only rstd_ns is set (no rtt/aoa/ta), so the TDOA branch must be what
        // produced the fix.
        assert!(
            loc.method_used.is_some(),
            "expected a method from the DL-TDOA solver"
        );
    }

    // -- ECID path ------------------------------------------------------------
    #[test]
    fn test_compute_location_ecid_real_solve() {
        let (ctx, entries, _true_geo, _true_enu, _origin) = scene();
        let registry = ctx.build_trp_registry();

        // ECID: only one cell (serving), with timing_advance, no rtt_ns.
        let cell_a_coord = entries.iter().find(|(id, _)| id == "cell-a").unwrap().1;
        let ta = 50u32;
        let cells = vec![CellMeasurement {
            nr_cgi: "cell-a".to_string(),
            rsrp: Some(-75),
            rsrq: Some(-8),
            timing_advance: Some(ta),
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            rstd_reference: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }];

        let loc = compute_location(&PositioningMethod::Ecid, &cells, &registry);
        // ECID places the estimate exactly on the serving cell.
        assert!(
            (loc.latitude - cell_a_coord.lat_deg).abs() < 1e-9,
            "ECID lat mismatch: {} vs {}",
            loc.latitude,
            cell_a_coord.lat_deg
        );
        assert!(
            (loc.longitude - cell_a_coord.lon_deg).abs() < 1e-9,
            "ECID lon mismatch: {} vs {}",
            loc.longitude,
            cell_a_coord.lon_deg
        );
        assert!(loc.horizontal_accuracy > 0.0);
        assert_eq!(loc.method_used.as_deref(), Some("NR_ECID"));
    }

    // -- AoA path -------------------------------------------------------------
    #[test]
    fn test_compute_location_aoa_real_solve() {
        let (ctx, entries, true_geo, true_enu, origin) = scene();
        let registry = ctx.build_trp_registry();

        // Exact azimuth (clockwise from North) from each cell toward the UE.
        let cells: Vec<CellMeasurement> = entries
            .iter()
            .map(|(id, coord)| {
                let p = geodetic_to_enu(*coord, origin);
                let de = true_enu.e - p.e;
                let dn = true_enu.n - p.n;
                let azimuth_deg = de.atan2(dn).to_degrees();
                CellMeasurement {
                    nr_cgi: id.clone(),
                    rsrp: Some(-80),
                    rsrq: Some(-10),
                    timing_advance: None,
                    aoa: Some(azimuth_deg),
                    rtt_ns: None,
                    rstd_ns: None,
                    ue_rx_tx_ns: None,
                    rstd_reference: None,
                    ecid_rtt_ns: None,
                    gnb_rx_tx_ns: None,
                    dl_prs_id: None,
                    eutra: false,
                }
            })
            .collect();

        let loc = compute_location(&PositioningMethod::NrBased, &cells, &registry);
        let got = TrpCoord::new(loc.latitude, loc.longitude, 0.0);
        let err_m = geo_dist_m(got, true_geo);
        assert!(
            err_m < 50.0,
            "AoA position error {err_m:.2}m exceeds 50 m tolerance"
        );
        assert_eq!(loc.method_used.as_deref(), Some("UL_AOA"));
    }

    // -- Solver priority: Multi-RTT wins when both rtt_ns and aoa present -----
    #[test]
    fn test_multi_rtt_takes_priority_over_aoa() {
        let (ctx, entries, _true_geo, true_enu, origin) = scene();
        let registry = ctx.build_trp_registry();

        let cells: Vec<CellMeasurement> = entries
            .iter()
            .map(|(id, coord)| {
                let range_m = exact_range_m(*coord, true_enu, origin);
                let rtt_ns = (range_m * 2.0 / SPEED_OF_LIGHT_M_S * 1e9) as u64;
                let p = geodetic_to_enu(*coord, origin);
                let azimuth_deg = (true_enu.e - p.e).atan2(true_enu.n - p.n).to_degrees();
                CellMeasurement {
                    nr_cgi: id.clone(),
                    rsrp: Some(-80),
                    rsrq: None,
                    timing_advance: None,
                    aoa: Some(azimuth_deg),
                    rtt_ns: Some(rtt_ns),
                    rstd_ns: None,
                    ue_rx_tx_ns: None,
                    rstd_reference: None,
                    ecid_rtt_ns: None,
                    gnb_rx_tx_ns: None,
                    dl_prs_id: None,
                    eutra: false,
                }
            })
            .collect();

        let loc = compute_location(&PositioningMethod::NrBased, &cells, &registry);
        assert_eq!(
            loc.method_used.as_deref(),
            Some("MULTI-RTT"),
            "Multi-RTT should be chosen over AoA when rtt_ns is present"
        );
    }

    // -- Empty registry falls back to placeholder (no lat/lon change) ---------
    #[test]
    fn test_empty_registry_placeholder_fallback() {
        let registry = TrpRegistry::from_entries(std::iter::empty());
        let cells = vec![CellMeasurement {
            nr_cgi: "cell-x".to_string(),
            rsrp: Some(-80),
            rsrq: None,
            timing_advance: Some(100),
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            rstd_reference: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }];
        let loc = compute_location(&PositioningMethod::Ecid, &cells, &registry);
        // Placeholder: origin 0/0 with heuristic accuracy.
        assert_eq!(loc.latitude, 0.0);
        assert_eq!(loc.longitude, 0.0);
        assert!(loc.horizontal_accuracy > 50.0);
    }

    // -- Registry API ---------------------------------------------------------
    // -- LDR session store (lmfd#1) -------------------------------------------

    /// A2: measurement_report against a REGISTERED registry completes the
    /// linked session with `PositioningOutcome::Fix` from the real solver
    /// (ECID pins the estimate to the serving cell) and caches the per-SUPI
    /// stored fix with a real capture timestamp.
    #[test]
    fn test_measurement_report_completes_session_with_real_fix() {
        let (ctx, entries, _true_geo, _true_enu, _origin) = scene();
        let cell_a_coord = entries.iter().find(|(id, _)| id == "cell-a").unwrap().1;
        let req = ctx
            .measurement_request(
                77,
                PositioningMethod::Ecid,
                None,
                None,
                PositioningQos::BestEffort,
            )
            .unwrap();
        let (corr, mut rx) = ctx.positioning_session_register(
            Some("imsi-001010000000777".into()),
            21,
            req.request_id,
        );
        let cells = vec![CellMeasurement {
            nr_cgi: "cell-a".to_string(),
            rsrp: Some(-75),
            rsrq: Some(-8),
            timing_advance: Some(50),
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            rstd_reference: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }];
        ctx.measurement_report(req.request_id, cells).unwrap();
        match rx.try_recv() {
            Ok(PositioningOutcome::Fix(fix)) => {
                assert!((fix.latitude - cell_a_coord.lat_deg).abs() < 1e-9);
                assert!((fix.longitude - cell_a_coord.lon_deg).abs() < 1e-9);
                assert!(fix.horizontal_accuracy > 0.0);
            }
            other => panic!("expected a real-solver Fix, got {other:?}"),
        }
        assert!(ctx.positioning_session_find(&corr).is_none());
        // Cached per-SUPI with a real timestamp (honest age on later reads).
        let cached = ctx.stored_fix("imsi-001010000000777").expect("cached");
        assert!(cached.timestamp > 0);
    }

    #[test]
    fn test_ldr_register_cancel() {
        let ctx = LmfContext::new();
        let ldr = LdrContext {
            ldr_reference: "ldr-test-001".to_string(),
            ldr_type: "PERIODIC".to_string(),
            hgmlc_callback_uri: Some("http://gmlc/cb".to_string()),
            supi: Some("imsi-001010000000099".to_string()),
            periodic_event_info: None,
        };
        // Register: find should return Some
        assert!(ctx.register_ldr(ldr));
        let found = ctx.ldr_find("ldr-test-001");
        assert!(found.is_some());
        assert_eq!(found.unwrap().ldr_type, "PERIODIC");
        // Cancel: returns true (was present)
        assert!(ctx.cancel_ldr("ldr-test-001"));
        // ldr_find now None
        assert!(ctx.ldr_find("ldr-test-001").is_none());
        // Second cancel: returns false (already gone)
        assert!(!ctx.cancel_ldr("ldr-test-001"));
    }

    #[test]
    fn test_set_cell_coord_and_build_registry() {
        let mut ctx = LmfContext::new();
        ctx.init(256);
        ctx.set_cell_coord("cell-1", TrpCoord::new(37.7749, -122.4194, 0.0));
        ctx.set_cell_coord("cell-2", TrpCoord::new(37.7760, -122.4180, 0.0));
        let reg = ctx.build_trp_registry();
        assert_eq!(reg.len(), 2);
        assert!(reg.lookup("cell-1").is_some());
        assert!(reg.lookup("no-such-cell").is_none());
    }

    // -----------------------------------------------------------------------
    // A2: positioning-session store (insert / complete / expire / indexes)
    // -----------------------------------------------------------------------

    #[test]
    fn test_positioning_session_register_and_complete() {
        let ctx = LmfContext::new();
        let (corr, mut rx) =
            ctx.positioning_session_register(Some("imsi-001010000000001".into()), 7, 42);
        // TS 29.572 CorrelationID bounds: 1..255 chars (UUID = 36).
        assert!((1..=255).contains(&corr.len()));
        assert_eq!(ctx.positioning_session_count(), 1);

        // Both indexes resolve.
        let info = ctx.positioning_session_find(&corr).expect("session");
        assert_eq!(info.lpp_transaction, 7);
        assert_eq!(info.request_id, 42);
        assert_eq!(info.supi.as_deref(), Some("imsi-001010000000001"));
        assert_eq!(
            ctx.positioning_session_find_by_transaction(7).as_deref(),
            Some(corr.as_str())
        );

        // Complete fires the channel and removes the session + indexes.
        let fix = LocationEstimate {
            latitude: 1.0,
            longitude: 2.0,
            horizontal_accuracy: 30.0,
            ..Default::default()
        };
        assert!(ctx.positioning_session_complete(&corr, PositioningOutcome::Fix(fix)));
        match rx.try_recv() {
            Ok(PositioningOutcome::Fix(f)) => assert_eq!(f.latitude, 1.0),
            other => panic!("expected Fix outcome, got {other:?}"),
        }
        assert_eq!(ctx.positioning_session_count(), 0);
        assert!(ctx.positioning_session_find(&corr).is_none());
        assert!(ctx.positioning_session_find_by_transaction(7).is_none());
        // Double-complete: fail-closed false (no orphan ingestion).
        assert!(!ctx.positioning_session_complete(&corr, PositioningOutcome::SolverFailed));
        // The fix was cached per-SUPI with a REAL capture timestamp.
        let cached = ctx.stored_fix("imsi-001010000000001").expect("cached fix");
        assert!(cached.timestamp > 0);
    }

    #[test]
    fn test_positioning_session_expire_drops_without_firing() {
        let ctx = LmfContext::new();
        let (corr, mut rx) = ctx.positioning_session_register(None, 9, 43);
        assert!(ctx.positioning_session_expire(&corr));
        // The sender was dropped, not fired.
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
        // Second expire: nothing left.
        assert!(!ctx.positioning_session_expire(&corr));
        assert_eq!(ctx.positioning_session_count(), 0);
    }

    /// LPP transactionNumber wraps at 256 requests: uniqueness is carried by
    /// the lcsCorrelationId; the txn index is last-writer-wins and never
    /// mis-routes a completion addressed by correlation id.
    #[test]
    fn test_positioning_session_transaction_wrap_uniqueness() {
        let ctx = LmfContext::new();
        let (corr_a, mut rx_a) = ctx.positioning_session_register(None, 5, 100);
        let (corr_b, mut rx_b) = ctx.positioning_session_register(None, 5, 101); // wrapped txn
        assert_ne!(corr_a, corr_b, "correlation ids stay unique across wrap");
        assert_eq!(ctx.positioning_session_count(), 2);
        // Transaction index points at the NEWEST session (last-writer-wins).
        assert_eq!(
            ctx.positioning_session_find_by_transaction(5).as_deref(),
            Some(corr_b.as_str())
        );
        // Completing the OLD session by correlation id still works and does
        // NOT disturb the newer session's txn index entry.
        assert!(ctx.positioning_session_complete(&corr_a, PositioningOutcome::SolverFailed));
        assert!(matches!(
            rx_a.try_recv(),
            Ok(PositioningOutcome::SolverFailed)
        ));
        assert_eq!(
            ctx.positioning_session_find_by_transaction(5).as_deref(),
            Some(corr_b.as_str())
        );
        assert!(ctx.positioning_session_complete(&corr_b, PositioningOutcome::SolverFailed));
        assert!(rx_b.try_recv().is_ok());
        assert!(ctx.positioning_session_find_by_transaction(5).is_none());
    }

    /// A7 (lmfd-11): measurement_report on a session-linked request with an
    /// EMPTY registry returns NO fix (the placeholder fabrication was removed
    /// from the runtime path) AND completes the session `SolverFailed` — no
    /// fabricated (0,0) coordinate escapes on any path.
    #[test]
    fn test_measurement_report_completes_session_solver_failed_on_empty_registry() {
        let mut ctx = LmfContext::new();
        ctx.init(256);
        let req = ctx
            .measurement_request(
                1,
                PositioningMethod::Ecid,
                None,
                None,
                PositioningQos::BestEffort,
            )
            .unwrap();
        let (corr, mut rx) = ctx.positioning_session_register(None, 11, req.request_id);
        let cells = vec![CellMeasurement {
            nr_cgi: "unregistered-cell".to_string(),
            rsrp: Some(-80),
            rsrq: None,
            timing_advance: Some(100),
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            rstd_reference: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }];
        // A7: no fabricated placeholder — an unsolvable report yields None.
        let no_fix = ctx.measurement_report(req.request_id, cells);
        assert!(no_fix.is_none());
        // Strict session outcome: SolverFailed, session removed.
        assert!(matches!(
            rx.try_recv(),
            Ok(PositioningOutcome::SolverFailed)
        ));
        assert!(ctx.positioning_session_find(&corr).is_none());
    }

    #[test]
    fn test_amf_subscription_cache_and_identity() {
        let ctx = LmfContext::new();
        assert!(ctx.amf_subscription_get("10.0.0.1:80|imsi-1").is_none());
        ctx.amf_subscription_set("10.0.0.1:80|imsi-1", "n1n2sub-abc");
        assert_eq!(
            ctx.amf_subscription_get("10.0.0.1:80|imsi-1").as_deref(),
            Some("n1n2sub-abc")
        );
        assert!(ctx.callback_base().is_none());
        ctx.set_callback_base("http://127.0.0.1:7816");
        assert_eq!(
            ctx.callback_base().as_deref(),
            Some("http://127.0.0.1:7816")
        );
        ctx.set_nf_instance_id("lmf-test");
        assert_eq!(ctx.nf_instance_id().as_deref(), Some("lmf-test"));
    }
}

/// #713: Multi-RTT ranges on UE Rx–Tx + gNB Rx–Tx (TS 38.305 §8.10), with the UE
/// half decoded from LPP bytes through the real adapter.
#[cfg(test)]
mod tests_multi_rtt_two_sided {
    use super::*;
    use crate::positioning::{enu_to_geodetic, geodetic_to_enu, EnuPoint, SPEED_OF_LIGHT_M_S};

    /// T_c in ns (TS 38.211 §4.1), written out independently of codec_glue.
    const TC_NS: f64 = 1e9 / (480_000.0 * 4_096.0);
    /// TS 38.133 §10.1.25.3: the k0 report value of a zero Rx–Tx difference.
    const MIDPOINT: f64 = 985_024.0;
    const ORIGIN: (f64, f64) = (51.4778, -0.0015);

    /// Four TRPs on a 1 km square and a UE at (350, 600) m. The UE clock runs
    /// `UE_CLOCK_OFFSET_NS` ahead of the gNBs', and the UE transmits its SRS
    /// `SRS_AFTER_PRS_NS` after the gNBs transmit their PRS. So, with t_i the
    /// one-way propagation time to TRP i:
    /// - UE Rx–Tx_i = (t_i + offset) − gap
    /// - gNB Rx–Tx_i = (gap − offset) + t_i
    ///
    /// Neither is a range; their sum is 2·t_i.
    const TRPS: [(u16, f64, f64); 4] = [
        (201, 0.0, 0.0),
        (202, 1000.0, 0.0),
        (203, 0.0, 1000.0),
        (204, 1000.0, 1000.0),
    ];
    const UE: (f64, f64) = (350.0, 600.0);
    const UE_CLOCK_OFFSET_NS: f64 = 3_000.0;
    const SRS_AFTER_PRS_NS: f64 = 1_000.0;

    fn origin() -> TrpCoord {
        TrpCoord::new(ORIGIN.0, ORIGIN.1, 0.0)
    }

    fn registry() -> TrpRegistry {
        TrpRegistry::from_entries(TRPS.iter().map(|(pci, e, n)| {
            (
                format!("pci-{pci}"),
                enu_to_geodetic(
                    EnuPoint {
                        e: *e,
                        n: *n,
                        u: 0.0,
                    },
                    origin(),
                ),
            )
        }))
    }

    fn propagation_ns(e: f64, n: f64) -> f64 {
        (UE.0 - e).hypot(UE.1 - n) / SPEED_OF_LIGHT_M_S * 1e9
    }

    /// The UE's LPP report: each TRP's UE Rx–Tx as a k0 code, (T/T_c) + 985024.
    fn ue_report() -> Vec<CellMeasurement> {
        let cells: Vec<(u16, u32)> = TRPS
            .iter()
            .map(|(pci, e, n)| {
                let ue_rx_tx = propagation_ns(*e, *n) + UE_CLOCK_OFFSET_NS - SRS_AFTER_PRS_NS;
                (*pci, (ue_rx_tx / TC_NS + MIDPOINT).round() as u32)
            })
            .collect();
        let bytes = crate::lpp_fixtures::multi_rtt_lpp(&cells, 3);
        crate::codec_glue::decode_lpp_provide_report(&bytes)
            .expect("decodes")
            .1
    }

    /// The gNBs' halves, as their own measurements of the same TRPs.
    fn gnb_report() -> Vec<CellMeasurement> {
        TRPS.iter()
            .map(|(pci, e, n)| CellMeasurement {
                nr_cgi: format!("pci-{pci}"),
                rsrp: None,
                rsrq: None,
                timing_advance: None,
                aoa: None,
                rtt_ns: None,
                rstd_ns: None,
                ue_rx_tx_ns: None,
                rstd_reference: None,
                ecid_rtt_ns: None,
                gnb_rx_tx_ns: Some(propagation_ns(*e, *n) - UE_CLOCK_OFFSET_NS + SRS_AFTER_PRS_NS),
                dl_prs_id: None,
                eutra: false,
            })
            .collect()
    }

    #[test]
    fn the_ue_half_decodes_signed_with_the_ts_38_133_midpoint() {
        let cells = ue_report();
        assert_eq!(cells.len(), 4);
        for (c, (pci, e, n)) in cells.iter().zip(TRPS) {
            assert_eq!(c.nr_cgi, format!("pci-{pci}"));
            assert_eq!(c.rtt_ns, None, "the UE half is not an RTT");
            let want = propagation_ns(e, n) + UE_CLOCK_OFFSET_NS - SRS_AFTER_PRS_NS;
            let got = c.ue_rx_tx_ns.expect("ue_rx_tx_ns");
            assert!(
                (got - want).abs() <= TC_NS / 2.0 + 1e-9,
                "{pci}: {got} vs {want}"
            );
        }
    }

    #[test]
    fn ranges_are_ue_plus_gnb_rx_tx_over_two() {
        let mut cells = ue_report();
        cells.extend(gnb_report());
        let obs = multi_rtt_observations(&cells, &registry());
        assert_eq!(obs.len(), 4);
        for (o, (pci, e, n)) in obs.iter().zip(TRPS) {
            assert_eq!(o.trp_id, format!("pci-{pci}"));
            let want = (UE.0 - e).hypot(UE.1 - n);
            // One k0 step is T_c ≈ 0.51 ns, ±0.25 ns after rounding: ±0.04 m of range.
            assert!(
                (o.range_m - want).abs() < 0.05,
                "{pci}: {} vs {want}",
                o.range_m
            );
        }
    }

    /// Hand-computed geometry in, the UE position out.
    #[test]
    fn the_solver_recovers_the_ue_from_paired_halves() {
        let mut cells = ue_report();
        cells.extend(gnb_report());
        let fix = try_real_solve(&cells, &registry()).expect("a Multi-RTT fix");
        assert_eq!(fix.method_used.as_deref(), Some("MULTI-RTT"));
        let p = geodetic_to_enu(TrpCoord::new(fix.latitude, fix.longitude, 0.0), origin());
        let err = (p.e - UE.0).hypot(p.n - UE.1);
        assert!(err < 0.1, "position error {err:.3} m");
    }

    /// The issue's scenario: a conformant UE alone. Its Rx–Tx carries the clock
    /// offset and is not a range, so there is no Multi-RTT fix (before #713 these
    /// decoded to ≈ 501 µs, ranges of ≈ 75 km).
    #[test]
    fn the_ue_half_alone_is_never_ranged() {
        let cells = ue_report();
        assert!(multi_rtt_observations(&cells, &registry()).is_empty());
        assert!(try_real_solve(&cells, &registry()).is_none());
    }

    /// Two TRPs paired and two with the UE half only: two ranges, fewer than
    /// trilateration needs, so no Multi-RTT fix.
    #[test]
    fn two_paired_and_two_ue_only_trps_give_no_fix() {
        let mut cells = ue_report();
        cells.extend(
            gnb_report()
                .into_iter()
                .filter(|c| c.nr_cgi == "pci-201" || c.nr_cgi == "pci-202"),
        );
        let obs = multi_rtt_observations(&cells, &registry());
        assert_eq!(
            obs.iter().map(|o| o.trp_id.as_str()).collect::<Vec<_>>(),
            ["pci-201", "pci-202"]
        );
        assert!(try_real_solve(&cells, &registry()).is_none());
    }

    /// A TRP reported many times is aggregated in one pass (#812 review: the
    /// old per-key rescan was quadratic).
    #[test]
    fn repeated_reports_of_one_trp_count_once() {
        let mut cells = Vec::new();
        for _ in 0..1000 {
            cells.extend(ue_report());
        }
        cells.extend(gnb_report());
        assert_eq!(multi_rtt_observations(&cells, &registry()).len(), 4);
    }

    #[test]
    fn the_gnb_half_alone_is_never_ranged() {
        assert!(multi_rtt_observations(&gnb_report(), &registry()).is_empty());
    }

    #[test]
    fn a_negative_round_trip_is_dropped_not_ranged() {
        let mut cells = ue_report();
        cells.extend(gnb_report());
        cells
            .iter_mut()
            .filter(|c| c.nr_cgi == "pci-204" && c.gnb_rx_tx_ns.is_some())
            .for_each(|c| c.gnb_rx_tx_ns = Some(-1e6));
        let obs = multi_rtt_observations(&cells, &registry());
        assert_eq!(
            obs.iter().map(|o| o.trp_id.as_str()).collect::<Vec<_>>(),
            ["pci-201", "pci-202", "pci-203"]
        );
    }
}

/// #714: DL-TDOA reference keying and RSTD rebasing, with the report decoded from
/// LPP bytes through the real adapter.
#[cfg(test)]
mod tests_dl_tdoa_reference {
    use super::*;
    use crate::positioning::{enu_to_geodetic, geodetic_to_enu, EnuPoint, SPEED_OF_LIGHT_M_S};

    /// T_c in ns (TS 38.211 §4.1) and the k0 RSTD of a zero difference
    /// (TS 38.133 §10.1.23.3), written out independently of codec_glue.
    const TC_NS: f64 = 1e9 / (480_000.0 * 4_096.0);
    const MIDPOINT: f64 = 985_024.0;
    const ORIGIN: (f64, f64) = (48.8566, 2.3522);
    /// (DL-PRS ID, PCI, east, north): TRP 1 is the UE's DL-PRS reference.
    const TRPS: [(u8, u16, f64, f64); 4] = [
        (0, 1, 0.0, 0.0),
        (1, 2, 1000.0, 0.0),
        (2, 3, 0.0, 1000.0),
        (3, 4, 1000.0, 1000.0),
    ];
    const UE: (f64, f64) = (350.0, 600.0);

    fn origin() -> TrpCoord {
        TrpCoord::new(ORIGIN.0, ORIGIN.1, 0.0)
    }

    fn registry(key: impl Fn(u8, u16) -> String) -> TrpRegistry {
        TrpRegistry::from_entries(TRPS.iter().map(|(prs, pci, e, n)| {
            (
                key(*prs, *pci),
                enu_to_geodetic(
                    EnuPoint {
                        e: *e,
                        n: *n,
                        u: 0.0,
                    },
                    origin(),
                ),
            )
        }))
    }

    fn range(e: f64, n: f64) -> f64 {
        (UE.0 - e).hypot(UE.1 - n)
    }

    /// What a UE reports: reference DL-PRS ID 0, and each neighbour by DL-PRS ID
    /// and PCI with its RSTD as a k0 code. RSTD_i = (d_i − d_ref)/c.
    fn report() -> Vec<CellMeasurement> {
        let d_ref = range(TRPS[0].2, TRPS[0].3);
        let neighbours: Vec<(u8, Option<u16>, u32)> = TRPS[1..]
            .iter()
            .map(|(prs, pci, e, n)| {
                let rstd = (range(*e, *n) - d_ref) / SPEED_OF_LIGHT_M_S * 1e9;
                (*prs, Some(*pci), (rstd / TC_NS + MIDPOINT).round() as u32)
            })
            .collect();
        let bytes = crate::lpp_fixtures::dl_tdoa_lpp(TRPS[0].0, &neighbours, 9);
        crate::codec_glue::decode_lpp_provide_report(&bytes)
            .expect("decodes")
            .1
    }

    fn error_m(fix: &LocationEstimate) -> f64 {
        let p = geodetic_to_enu(TrpCoord::new(fix.latitude, fix.longitude, 0.0), origin());
        (p.e - UE.0).hypot(p.n - UE.1)
    }

    /// The issue's scenario: a PCI-keyed registry. The reference arrives as
    /// `prs-0` (it cannot carry a PCI) and is not found; the neighbours are.
    /// Rebasing on one of them still gives the true position. Before #714 the
    /// neighbour with the smallest |RSTD| became the reference unrebased, and
    /// the fix was wrong.
    #[test]
    fn a_pci_keyed_registry_without_the_reference_still_gets_the_true_fix() {
        let reg = registry(|_, pci| format!("pci-{pci}"));
        let cells = report();
        assert_eq!(cells[0].nr_cgi, "prs-0");
        assert!(reg.lookup("prs-0").is_none());

        let (obs, _) = tdoa_observations(&cells, &reg);
        assert_eq!(obs.len(), 3);
        assert_eq!(obs[0].tdoa_ns, 0.0, "element 0 is the rebased reference");
        // Each rebased RSTD is the true range difference to the new reference.
        let new_ref = TRPS
            .iter()
            .find(|t| format!("pci-{}", t.1) == obs[0].trp_id)
            .unwrap();
        for o in &obs[1..] {
            let t = TRPS
                .iter()
                .find(|t| format!("pci-{}", t.1) == o.trp_id)
                .unwrap();
            let want = (range(t.2, t.3) - range(new_ref.2, new_ref.3)) / SPEED_OF_LIGHT_M_S * 1e9;
            assert!(
                (o.tdoa_ns - want).abs() < TC_NS,
                "{}: {} vs {want}",
                o.trp_id,
                o.tdoa_ns
            );
        }

        let fix = try_real_solve(&cells, &reg).expect("a DL-TDOA fix");
        assert_eq!(fix.method_used.as_deref(), Some("DL_TDOA"));
        assert!(error_m(&fix) < 1.0, "position error {:.3} m", error_m(&fix));
    }

    /// A registry keyed by DL-PRS ID: the neighbours reported a PCI, which the
    /// registry does not hold, so they resolve through their DL-PRS ID.
    #[test]
    fn a_prs_keyed_registry_resolves_neighbours_that_reported_a_pci() {
        let reg = registry(|prs, _| format!("prs-{prs}"));
        let cells = report();
        let (obs, _) = tdoa_observations(&cells, &reg);
        assert_eq!(
            obs.iter().map(|o| o.trp_id.as_str()).collect::<Vec<_>>(),
            ["prs-0", "prs-1", "prs-2", "prs-3"]
        );
        let fix = try_real_solve(&cells, &reg).expect("a DL-TDOA fix");
        assert!(error_m(&fix) < 1.0, "position error {:.3} m", error_m(&fix));
    }

    /// The reference is in the registry: it stays element 0, nothing moves.
    #[test]
    fn a_known_reference_is_used_as_reported() {
        let reg = registry(|prs, pci| {
            if prs == 0 {
                "prs-0".into()
            } else {
                format!("pci-{pci}")
            }
        });
        let cells = report();
        let (obs, _) = tdoa_observations(&cells, &reg);
        assert_eq!(obs[0].trp_id, "prs-0");
        assert_eq!(obs.len(), 4);
        for (o, c) in obs.iter().zip(&cells) {
            assert_eq!(Some(o.tdoa_ns), c.rstd_ns, "{}", o.trp_id);
        }
        let fix = try_real_solve(&cells, &reg).expect("a DL-TDOA fix");
        assert!(error_m(&fix) < 1.0, "position error {:.3} m", error_m(&fix));
    }

    /// A report relative to TRP `reference` (by index into TRPS), with the
    /// neighbours `neighbours` reported by DL-PRS ID and PCI.
    fn report_with(reference: usize, neighbours: &[usize], txn: u8) -> Vec<CellMeasurement> {
        let (rp, _, re, rn) = TRPS[reference];
        let d_ref = range(re, rn);
        let list: Vec<(u8, Option<u16>, u32)> = neighbours
            .iter()
            .map(|&t| {
                let (prs, pci, e, n) = TRPS[t];
                let rstd = (range(e, n) - d_ref) / SPEED_OF_LIGHT_M_S * 1e9;
                (prs, Some(pci), (rstd / TC_NS + MIDPOINT).round() as u32)
            })
            .collect();
        let bytes = crate::lpp_fixtures::dl_tdoa_lpp(rp, &list, txn);
        crate::codec_glue::decode_lpp_provide_report(&bytes)
            .expect("decodes")
            .1
    }

    /// A report relative to the TRP at `reference` (east, north; DL-PRS ID
    /// `ref_prs`), with neighbours `(DL-PRS ID, PCI, east, north)`.
    fn report_at(
        ref_prs: u8,
        reference: (f64, f64),
        neighbours: &[(u8, u16, f64, f64)],
        txn: u8,
    ) -> Vec<CellMeasurement> {
        let d_ref = range(reference.0, reference.1);
        let list: Vec<(u8, Option<u16>, u32)> = neighbours
            .iter()
            .map(|&(prs, pci, e, n)| {
                let rstd = (range(e, n) - d_ref) / SPEED_OF_LIGHT_M_S * 1e9;
                (prs, Some(pci), (rstd / TC_NS + MIDPOINT).round() as u32)
            })
            .collect();
        let bytes = crate::lpp_fixtures::dl_tdoa_lpp(ref_prs, &list, txn);
        crate::codec_glue::decode_lpp_provide_report(&bytes)
            .expect("decodes")
            .1
    }

    /// #824 review MAJOR: a PCI does not identify a TRP. Report B's neighbour T5'
    /// reuses PCI 2 (T2's) at another site. Joined on the registry key, B was
    /// joined to A through "pci-2" and the fix came out 705 m off with nothing
    /// flagging it. Joined on the DL-PRS ID, B shares no TRP with A, and pci-2,
    /// reached from DL-PRS IDs 1 and 4, is not used: too few TRPs, no fix.
    #[test]
    fn a_reused_pci_is_not_a_shared_trp() {
        let reg = registry(|_, pci| format!("pci-{pci}"));
        let mut cells = report_at(
            0,
            (0.0, 0.0),
            &[(1, 2, 1000.0, 0.0), (2, 3, 0.0, 1000.0)],
            1,
        );
        cells.extend(report_at(
            9,
            (-500.0, 1500.0),
            &[(4, 2, 2000.0, 300.0), (3, 4, 1000.0, 1000.0)],
            2,
        ));
        let (obs, _) = tdoa_observations(&cells, &reg);
        assert!(
            obs.iter().all(|o| o.trp_id != "pci-2"),
            "pci-2 is two TRPs here and must not be used: {:?}",
            obs.iter().map(|o| &o.trp_id).collect::<Vec<_>>()
        );
        assert!(
            try_real_solve(&cells, &reg).is_none(),
            "no fix is the right answer; a wrong one is not"
        );
    }

    /// The single-report form: one PCI on two TRPs of a multi-TRP cell (DL-PRS IDs
    /// 1 and 4). The key is ambiguous and dropped; the other three still solve.
    #[test]
    fn one_pci_on_two_trps_of_one_report_is_dropped() {
        let reg = registry(|prs, pci| {
            if prs == 0 {
                "prs-0".to_string()
            } else {
                format!("pci-{pci}")
            }
        });
        let five = report_at(
            0,
            (0.0, 0.0),
            &[
                (1, 2, 1000.0, 0.0),
                (4, 2, 2000.0, 300.0),
                (2, 3, 0.0, 1000.0),
                (3, 4, 1000.0, 1000.0),
            ],
            3,
        );
        let (obs, _) = tdoa_observations(&five, &reg);
        let keys: Vec<&str> = obs.iter().map(|o| o.trp_id.as_str()).collect();
        assert!(!keys.contains(&"pci-2"), "{keys:?}");
        assert_eq!(keys.len(), 3, "prs-0, pci-3 and pci-4 remain: {keys:?}");
        let fix = try_real_solve(&five, &reg).expect("three unambiguous TRPs solve");
        assert!(error_m(&fix) < 1.0, "position error {:.3} m", error_m(&fix));
    }

    /// #824 review: an MO-LR carrying two LPP reports with different reference
    /// TRPs. Report A is relative to TRP 1 (neighbours PCI 2, 3); report B is
    /// relative to TRP 2 (neighbours PCI 1, 4). Mixed as one set they gave a fix
    /// 69.65 m off. Joined through the TRPs they share, they give the UE.
    #[test]
    fn two_reports_with_different_references_are_joined_not_mixed() {
        let reg = registry(|_, pci| format!("pci-{pci}"));
        let mut cells = report_with(0, &[1, 2], 1);
        cells.extend(report_with(1, &[0, 3], 2));
        let (obs, _) = tdoa_observations(&cells, &reg);
        assert_eq!(
            obs.len(),
            4,
            "all four TRPs, B joined to A through PCI 1 / PCI 2"
        );
        let fix = try_real_solve(&cells, &reg).expect("a DL-TDOA fix");
        assert!(error_m(&fix) < 1.0, "position error {:.3} m", error_m(&fix));
    }

    /// A report that shares no known TRP with the others cannot be related to
    /// them: it is dropped, not mixed in.
    #[test]
    fn a_report_sharing_no_trp_is_dropped() {
        // TRP 1 known as prs-0, TRPs 2..4 by PCI.
        let reg = registry(|prs, pci| {
            if prs == 0 {
                "prs-0".into()
            } else {
                format!("pci-{pci}")
            }
        });
        // A: reference TRP 1, neighbours TRP 2 and 3. B: one RSTD for TRP 4 relative
        // to a reference (DL-PRS 7) no other report names, so it shares no TRP with A.
        let mut cells = report_with(0, &[1, 2], 1);
        cells.push(CellMeasurement {
            nr_cgi: "pci-4".into(),
            rsrp: None,
            rsrq: None,
            timing_advance: None,
            aoa: None,
            rtt_ns: None,
            rstd_ns: Some(1234.0),
            ue_rx_tx_ns: None,
            rstd_reference: Some(7),
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: Some(3),
            eutra: false,
        });
        let (obs, rebased) = tdoa_observations(&cells, &reg);
        assert_eq!(
            obs.iter().map(|o| o.trp_id.as_str()).collect::<Vec<_>>(),
            ["prs-0", "pci-2", "pci-3"]
        );
        assert!(!rebased);
        let fix = try_real_solve(&cells, &reg).expect("A alone still solves");
        assert!(error_m(&fix) < 1.0, "position error {:.3} m", error_m(&fix));
    }

    /// Losing the reporting reference doubles the reported accuracy (#824 review).
    #[test]
    fn a_rebased_fix_reports_a_wider_accuracy() {
        let known = registry(|prs, pci| {
            if prs == 0 {
                "prs-0".into()
            } else {
                format!("pci-{pci}")
            }
        });
        let unknown = registry(|_, pci| format!("pci-{pci}"));
        // Three TRPs in both cases, so only the rebase differs.
        let cells = report_with(0, &[1, 2], 1);
        let mut unknown_cells = report_with(0, &[1, 2, 3], 1);
        unknown_cells.retain(|c| c.nr_cgi != "pci-2");
        let (_, rebased) = tdoa_observations(&cells, &known);
        assert!(!rebased);
        let (obs, rebased) = tdoa_observations(&unknown_cells, &unknown);
        assert!(rebased);
        assert_eq!(obs.len(), 2, "too few to solve after the rebase");
        let a = try_real_solve(&report_with(0, &[1, 2, 3], 1), &known).unwrap();
        let b = try_real_solve(&report_with(0, &[1, 2, 3], 1), &unknown).unwrap();
        let est = solve_tdoa(
            &unknown,
            &tdoa_observations(&report_with(0, &[1, 2, 3], 1), &unknown).0,
        )
        .unwrap();
        assert!((b.horizontal_accuracy - 2.0 * est.horizontal_uncertainty_m()).abs() < 1e-9);
        assert!(a.horizontal_accuracy.is_finite());
    }

    /// TS 38.133 §10.1.23.3: an open-ended RSTD report value is not decoded.
    #[test]
    fn an_open_ended_rstd_is_not_decoded() {
        let bytes = crate::lpp_fixtures::dl_tdoa_lpp(
            0,
            &[
                (1, Some(2), 0),
                (2, Some(3), 1_970_049),
                (3, Some(4), 985_024),
            ],
            1,
        );
        let (_, cells) = crate::codec_glue::decode_lpp_provide_report(&bytes).unwrap();
        let rstd: Vec<Option<f64>> = cells.iter().map(|c| c.rstd_ns).collect();
        assert_eq!(rstd, [Some(0.0), None, None, Some(0.0)]);
    }

    /// Two entries for one TRP (once by PCI, once by DL-PRS ID) count once.
    #[test]
    fn a_trp_reported_twice_is_used_once() {
        let reg = registry(|_, pci| format!("pci-{pci}"));
        let mut cells = report();
        let dup = cells[1].clone();
        cells.push(dup);
        assert_eq!(tdoa_observations(&cells, &reg).0.len(), 3);
    }
}

/// #715: an E-CID fix names the RAT it was measured on (TS 29.572).
#[cfg(test)]
mod tests_ecid_label {
    use super::*;

    fn serving(eutra: bool) -> CellMeasurement {
        CellMeasurement {
            nr_cgi: "cell-1".into(),
            rsrp: Some(-80),
            rsrq: None,
            timing_advance: Some(10),
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            ue_rx_tx_ns: None,
            ecid_rtt_ns: None,
            gnb_rx_tx_ns: None,
            rstd_reference: None,
            dl_prs_id: None,
            eutra,
        }
    }

    #[test]
    fn an_eutra_serving_cell_is_ecid_and_an_nr_one_nr_ecid() {
        let reg = TrpRegistry::from_entries([("cell-1".to_string(), TrpCoord::new(1.0, 2.0, 0.0))]);
        let label = |eutra| try_real_solve(&[serving(eutra)], &reg).unwrap().method_used;
        assert_eq!(label(true).as_deref(), Some("ECID"));
        assert_eq!(label(false).as_deref(), Some("NR_ECID"));
    }
}

/// #832: the E-CID timing term is decoded from its own report mapping. An NRPPa
/// TADV of 500 is [1000, 1002) T_s (TS 36.133 §10.3.1), a 1001 T_s round trip,
/// so the ring is c·1001·T_s/2 ≈ 4884.5 m plus half the one-way bin width. The
/// old code read 500 as an NR TA command (512 T_c each), a ring of ≈ 19.5 km.
#[cfg(test)]
mod tests_ecid_timing_units {
    use super::*;
    use crate::nrppa_uplink::test_support::{ecid_report, nr_cgi, rsrp, ta1};
    use crate::positioning::SPEED_OF_LIGHT_M_S;

    #[test]
    fn an_nrppa_tadv_is_ranged_in_e_utra_t_s_not_as_an_nr_ta_command() {
        let bytes = ecid_report(
            1,
            42,
            7,
            nr_cgi([0x02, 0xF8, 0x39], 1),
            [0, 0x12, 0x34],
            Some(vec![ta1(500), rsrp(&[60])]),
        );
        let (_, cells) = crate::codec_glue::decode_nrppa_ecid_report(&bytes).unwrap();
        let reg =
            TrpRegistry::from_entries([(cells[0].nr_cgi.clone(), TrpCoord::new(40.0, -74.0, 0.0))]);
        let fix = try_real_solve(&cells, &reg).expect("an E-CID fix");
        // By hand: T_s = 1/(15000·2048) s.
        let ts = 1.0 / (15_000.0 * 2_048.0);
        let want = SPEED_OF_LIGHT_M_S * 1001.0 * ts / 2.0 + SPEED_OF_LIGHT_M_S * 2.0 * ts / 4.0;
        assert!(
            (fix.horizontal_accuracy - want).abs() < 0.01,
            "{} vs {want}",
            fix.horizontal_accuracy
        );
        assert!(
            fix.horizontal_accuracy < 5_000.0,
            "not the ≈19.5 km of an NR TA reading"
        );
        assert_eq!((fix.latitude, fix.longitude), (40.0, -74.0));
    }

    #[test]
    fn an_open_ended_tadv_gives_no_timing_term() {
        let bytes = ecid_report(
            1,
            42,
            7,
            nr_cgi([0x02, 0xF8, 0x39], 1),
            [0, 0x12, 0x34],
            Some(vec![ta1(7690)]),
        );
        let (_, cells) = crate::codec_glue::decode_nrppa_ecid_report(&bytes).unwrap();
        assert_eq!(cells[0].ecid_rtt_ns, None);
        let reg =
            TrpRegistry::from_entries([(cells[0].nr_cgi.clone(), TrpCoord::new(40.0, -74.0, 0.0))]);
        assert!(try_real_solve(&cells, &reg).is_none());
    }
}

/// #715 review MAJOR: the legs of one session are solved together, once all of them
/// are in or when the budget runs out, and the first one no longer decides alone.
#[cfg(test)]
mod tests_session_legs {
    use super::*;

    fn ctx() -> LmfContext {
        let mut c = LmfContext::new();
        c.init(16);
        c.set_cell_coord("pci-77", TrpCoord::new(40.1, -74.5, 0.0));
        c
    }

    /// The UE's NR E-CID report: the serving cell and its SS-RSRP, no timing term.
    fn lpp_leg() -> Vec<CellMeasurement> {
        vec![cell(Some(-80), None)]
    }

    /// The gNB's E-CID measurement of the same cell, with its timing advance.
    fn nrppa_leg() -> Vec<CellMeasurement> {
        vec![cell(None, Some(100))]
    }

    fn cell(rsrp: Option<i16>, ta: Option<u32>) -> CellMeasurement {
        CellMeasurement {
            nr_cgi: "pci-77".to_string(),
            rsrp,
            rsrq: None,
            timing_advance: ta,
            aoa: None,
            rtt_ns: None,
            rstd_ns: None,
            rstd_reference: None,
            ue_rx_tx_ns: None,
            gnb_rx_tx_ns: None,
            dl_prs_id: None,
            eutra: false,
        }
    }

    fn session(
        c: &LmfContext,
    ) -> (
        u64,
        String,
        tokio::sync::oneshot::Receiver<PositioningOutcome>,
    ) {
        let req = c
            .measurement_request(
                0,
                PositioningMethod::Ecid,
                None,
                None,
                PositioningQos::BestEffort,
            )
            .unwrap();
        let (corr, rx) = c.positioning_session_register(Some("imsi-1".into()), 3, req.request_id);
        c.positioning_session_expect_leg(&corr, MeasurementLeg::NrppaEcid);
        (req.request_id, corr, rx)
    }

    /// The race the review describes: the LPP report arrives first. It must wait
    /// for the NRPPa leg, and the two together give an NR_ECID fix.
    #[test]
    fn the_lpp_leg_first_waits_for_the_nrppa_leg_and_both_solve() {
        let c = ctx();
        let (request_id, _corr, mut rx) = session(&c);
        assert!(matches!(
            c.measurement_leg_report(request_id, MeasurementLeg::Lpp, lpp_leg()),
            LegProgress::Waiting
        ));
        assert!(
            rx.try_recv().is_err(),
            "the LPP leg alone must not end the session"
        );
        let LegProgress::Completed(Some(fix)) =
            c.measurement_leg_report(request_id, MeasurementLeg::NrppaEcid, nrppa_leg())
        else {
            panic!("both legs in: solved");
        };
        assert_eq!(fix.method_used.as_deref(), Some("NR_ECID"));
        assert!(matches!(rx.try_recv(), Ok(PositioningOutcome::Fix(_))));
    }

    /// The other order gives the same answer.
    #[test]
    fn the_nrppa_leg_first_waits_for_the_lpp_leg() {
        let c = ctx();
        let (request_id, _corr, _rx) = session(&c);
        assert!(matches!(
            c.measurement_leg_report(request_id, MeasurementLeg::NrppaEcid, nrppa_leg()),
            LegProgress::Waiting
        ));
        assert!(matches!(
            c.measurement_leg_report(request_id, MeasurementLeg::Lpp, lpp_leg()),
            LegProgress::Completed(Some(_))
        ));
    }

    /// A gNB that never answers: when the budget runs out, the legs that did
    /// report are solved. Here the LPP leg alone has no timing term: no fix.
    #[test]
    fn budget_expiry_solves_with_the_legs_that_reported() {
        let c = ctx();
        let (request_id, corr, _rx) = session(&c);
        c.measurement_leg_report(request_id, MeasurementLeg::Lpp, lpp_leg());
        assert!(matches!(
            c.positioning_session_solve_now(&corr),
            Some(PositioningOutcome::SolverFailed)
        ));
        assert_eq!(c.positioning_session_count(), 0, "the session is complete");
    }

    /// Nothing reported at all: no outcome, which the caller answers 504.
    #[test]
    fn budget_expiry_with_no_leg_is_no_outcome() {
        let c = ctx();
        let (_request_id, corr, _rx) = session(&c);
        assert!(c.positioning_session_solve_now(&corr).is_none());
        assert_eq!(c.positioning_session_count(), 1);
    }

    /// A leg whose solicitation failed is withdrawn: the session is solved as soon
    /// as the others are in, with no wait for a gNB that was never asked.
    #[test]
    fn a_withdrawn_leg_is_not_waited_for() {
        let c = ctx();
        let (request_id, corr, _rx) = session(&c);
        assert!(matches!(
            c.measurement_leg_report(request_id, MeasurementLeg::Lpp, lpp_leg()),
            LegProgress::Waiting
        ));
        assert!(matches!(
            c.positioning_session_withdraw_leg(&corr, MeasurementLeg::NrppaEcid),
            LegProgress::Completed(None)
        ));
    }
}
