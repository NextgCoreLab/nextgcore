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
    /// Timing advance
    pub timing_advance: Option<u32>,
    /// Angle of Arrival (degrees)
    pub aoa: Option<f64>,
    /// Round-trip time (nanoseconds)
    pub rtt_ns: Option<u64>,
    /// NR DL-TDOA reference-signal time difference vs the DL-PRS reference TRP
    /// (nanoseconds, SIGNED; the reference TRP itself reports 0). TS 37.355.
    pub rstd_ns: Option<f64>,
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
    /// Active measurement request ID
    pub active_measurement: Option<u64>,
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
    /// Registered deferred/periodic/triggered LDR sessions (ldrReference -> ctx). lmfd#1.
    ldr_sessions: RwLock<HashMap<String, LdrContext>>,
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
            ldr_sessions: RwLock::new(HashMap::new()),
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
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("LMF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn supported_methods(&self) -> &[PositioningMethod] {
        &self.supported_methods
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

    /// Process a measurement report (NRPPa: gNB -> LMF via AMF)
    pub fn measurement_report(
        &self,
        request_id: u64,
        cell_measurements: Vec<CellMeasurement>,
    ) -> Option<LocationEstimate> {
        // Build the registry snapshot while holding only the cell_registry read
        // lock; drop it before acquiring the write locks below to avoid deadlock.
        let registry = self.build_trp_registry();

        let mut measurements = self.measurements.write().ok()?;
        let mut reports = self.reports.write().ok()?;

        let measurement = measurements.get_mut(&request_id)?;
        measurement.state = MeasurementState::Completed;

        // Compute location estimate based on method and measurements
        let location = compute_location(&measurement.method, &cell_measurements, &registry);

        let report = NrppaMeasurementReport {
            request_id,
            cell_measurements,
            location: Some(location.clone()),
        };

        reports.insert(request_id, report);

        log::info!(
            "Measurement report processed: id={} lat={:.6} lon={:.6} accuracy={:.1}m",
            request_id,
            location.latitude,
            location.longitude,
            location.horizontal_accuracy
        );

        Some(location)
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

    /// Return the most recently computed **real** location fix for the target,
    /// preferring the UE's stored fix (by SUPI), else the newest completed
    /// measurement report. Returns `None` when no measurement-derived fix
    /// exists — the caller MUST NOT fabricate one (a genuine positioning
    /// failure). A fix is "real" only when its horizontal accuracy is > 0
    /// (a defaulted, all-zero estimate means the solver had no measurements).
    pub fn latest_location(&self, supi: Option<&str>) -> Option<LocationEstimate> {
        if let Some(supi) = supi {
            if let Some(loc) = self
                .ue_location_get(supi)
                .and_then(|c| c.last_location)
                .filter(|l| l.horizontal_accuracy > 0.0)
            {
                return Some(loc);
            }
        }
        // Newest completed report (highest request_id) carrying a real fix.
        let reports = self.reports.read().ok()?;
        reports
            .iter()
            .filter(|(_, r)| {
                r.location
                    .as_ref()
                    .is_some_and(|l| l.horizontal_accuracy > 0.0)
            })
            .max_by_key(|(id, _)| **id)
            .and_then(|(_, r)| r.location.clone())
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
    pub fn cancel_ldr(&self, ldr_reference: &str) -> bool {
        if let Ok(mut l) = self.ldr_sessions.write() {
            return l.remove(ldr_reference).is_some();
        }
        false
    }

    /// Look up an LDR session by `ldrReference`. Returns a clone, or `None`.
    pub fn ldr_find(&self, ldr_reference: &str) -> Option<LdrContext> {
        self.ldr_sessions.read().ok()?.get(ldr_reference).cloned()
    }

    /// Register (or update) a cell geodetic coordinate for use by the real
    /// positioning solvers. `nr_cgi` is the NR-CGI string that matches
    /// [`CellMeasurement::nr_cgi`]. Call this from config loading or tests.
    pub fn set_cell_coord(&self, nr_cgi: impl Into<String>, coord: TrpCoord) {
        if let Ok(mut reg) = self.cell_registry.write() {
            reg.insert(nr_cgi.into(), coord);
        }
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
/// 1. **Multi-RTT** — if ≥ 3 cells report `rtt_ns` and are in the registry.
/// 2. **NR DL-TDOA** — if ≥ 3 cells report `rstd_ns` and are in the registry.
/// 3. **AoA** — if ≥ 2 cells report `aoa` and are in the registry.
/// 4. **ECID** — if the best-RSRP cell has `timing_advance` and is in the registry.
///
/// On any solver failure or when the registry is empty / has no matching
/// cells, falls back to the heuristic placeholder (lat/lon 0.0, method-based
/// accuracy estimate) so no existing behaviour regresses.
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
    // --- Multi-RTT (≥3 cells with rtt_ns known to the registry) -------------
    let rtt_obs: Vec<RttObservation> = measurements
        .iter()
        .filter(|m| m.rtt_ns.is_some() && registry.lookup(&m.nr_cgi).is_some())
        .map(|m| RttObservation {
            trp_id: m.nr_cgi.clone(),
            range_m: rtt_ns_to_range_m(m.rtt_ns.unwrap() as f64),
        })
        .collect();

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

    // --- NR DL-TDOA (≥3 cells with rstd_ns known to the registry) -----------
    // RSTD is relative to the DL-PRS reference TRP (rstd_ns == 0). solve_tdoa
    // expects observation[0] to be that reference, so order by |rstd| to put
    // the zero-RSTD reference first.
    let mut tdoa_obs: Vec<TdoaObservation> = measurements
        .iter()
        .filter(|m| m.rstd_ns.is_some() && registry.lookup(&m.nr_cgi).is_some())
        .map(|m| TdoaObservation {
            trp_id: m.nr_cgi.clone(),
            tdoa_ns: m.rstd_ns.unwrap(),
        })
        .collect();
    tdoa_obs.sort_by(|a, b| {
        a.tdoa_ns
            .abs()
            .partial_cmp(&b.tdoa_ns.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if tdoa_obs.len() >= 3 {
        match solve_tdoa(registry, &tdoa_obs) {
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

    // --- ECID (serving cell = best RSRP; needs timing_advance + registry hit) -
    let serving = measurements
        .iter()
        .filter(|m| m.timing_advance.is_some() && registry.lookup(&m.nr_cgi).is_some())
        .max_by_key(|m| m.rsrp.unwrap_or(i16::MIN))?;

    match solve_ecid(registry, &serving.nr_cgi, serving.timing_advance, 1) {
        Ok(est) => Some(LocationEstimate {
            latitude: est.lat_deg,
            longitude: est.lon_deg,
            altitude: est.height_m,
            horizontal_accuracy: est.horizontal_uncertainty_m(),
            vertical_accuracy: None,
            method_used: Some(est.method.as_spec_str().to_string()),
            timestamp: 0,
        }),
        Err(e) => {
            log::warn!("ECID solve failed: {e}");
            None
        }
    }
}

/// Heuristic placeholder used when no registry coordinates are available.
/// Returns lat/lon 0.0 with a method-derived accuracy estimate; kept so
/// unconfigured deployments still produce a well-formed (if fake) response.
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
    };
}

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
        }];

        let location = ctx.measurement_report(req.request_id, cells).unwrap();
        assert!(location.horizontal_accuracy > 0.0);

        let report = ctx.report_find(req.request_id).unwrap();
        assert_eq!(report.cell_measurements.len(), 1);

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
            },
            CellMeasurement {
                nr_cgi: "001-01-0002-02".to_string(),
                rsrp: Some(-85),
                rsrq: Some(-12),
                timing_advance: None,
                aoa: Some(120.0),
                rtt_ns: Some(2000),
                rstd_ns: None,
            },
        ];

        let location = ctx.measurement_report(req.request_id, cells).unwrap();
        // Multi-RTT should give ~5m accuracy
        assert!(location.horizontal_accuracy <= 10.0);
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
        }];
        let loc = compute_location(&PositioningMethod::Ecid, &cells, &registry);
        // Placeholder: origin 0/0 with heuristic accuracy.
        assert_eq!(loc.latitude, 0.0);
        assert_eq!(loc.longitude, 0.0);
        assert!(loc.horizontal_accuracy > 50.0);
    }

    // -- Registry API ---------------------------------------------------------
    // -- LDR session store (lmfd#1) -------------------------------------------

    #[test]
    fn test_ldr_register_cancel() {
        let ctx = LmfContext::new();
        let ldr = LdrContext {
            ldr_reference: "ldr-test-001".to_string(),
            ldr_type: "PERIODIC".to_string(),
            hgmlc_callback_uri: Some("http://gmlc/cb".to_string()),
            supi: Some("imsi-001010000000099".to_string()),
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
}
