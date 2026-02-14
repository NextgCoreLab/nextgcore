//! LMF Context Management
//!
//! Location Management Function context (TS 23.273)
//! Includes NRPPa (NR Positioning Protocol A) support

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

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
        if let Ok(mut locs) = self.ue_locations.write() { locs.clear(); }
        if let Ok(mut meas) = self.measurements.write() { meas.clear(); }
        if let Ok(mut reps) = self.reports.write() { reps.clear(); }
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
            log::error!("Maximum concurrent measurements [{}] reached", self.max_measurements);
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
        let mut measurements = self.measurements.write().ok()?;
        let mut reports = self.reports.write().ok()?;

        let measurement = measurements.get_mut(&request_id)?;
        measurement.state = MeasurementState::Completed;

        // Compute location estimate based on method and measurements
        let location = compute_location(&measurement.method, &cell_measurements);

        let report = NrppaMeasurementReport {
            request_id,
            cell_measurements,
            location: Some(location.clone()),
        };

        reports.insert(request_id, report);

        log::info!(
            "Measurement report processed: id={} lat={:.6} lon={:.6} accuracy={:.1}m",
            request_id, location.latitude, location.longitude, location.horizontal_accuracy
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
            locs.insert(supi.to_string(), UeLocationContext {
                supi: supi.to_string(),
                amf_ue_ngap_id: 0,
                serving_cell: String::new(),
                last_location: Some(location),
                active_measurement: None,
            });
            return true;
        }
        false
    }

    /// Get UE location
    pub fn ue_location_get(&self, supi: &str) -> Option<UeLocationContext> {
        self.ue_locations.read().ok()?.get(supi).cloned()
    }

    pub fn measurement_count(&self) -> usize {
        self.measurements.read().map(|m| m.len()).unwrap_or(0)
    }
}

/// Compute location estimate from cell measurements (simplified)
fn compute_location(method: &PositioningMethod, measurements: &[CellMeasurement]) -> LocationEstimate {
    if measurements.is_empty() {
        return LocationEstimate::default();
    }

    // Simplified ECID: use serving cell's RSRP for rough accuracy estimate
    let accuracy = match method {
        PositioningMethod::Ecid => {
            // ECID accuracy: ~100-300m typically
            let best_rsrp = measurements.iter()
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

    // In a real implementation, these would be computed from the measurements
    // For now we return a placeholder location with the computed accuracy
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
static GLOBAL_LMF_CONTEXT: std::sync::OnceLock<Arc<RwLock<LmfContext>>> = std::sync::OnceLock::new();

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

        let req = ctx.measurement_request(
            1001, PositioningMethod::Ecid, None, Some("gnb-001".to_string()),
            PositioningQos::BestEffort,
        ).unwrap();
        assert_eq!(req.method, PositioningMethod::Ecid);
        assert_eq!(req.state, MeasurementState::Pending);

        let found = ctx.measurement_find(req.request_id).unwrap();
        assert_eq!(found.amf_ue_ngap_id, 1001);

        // Submit report
        let cells = vec![
            CellMeasurement {
                nr_cgi: "001-01-0001-01".to_string(),
                rsrp: Some(-80),
                rsrq: Some(-10),
                timing_advance: Some(100),
                aoa: None,
                rtt_ns: None,
            },
        ];

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

        let req = ctx.measurement_request(
            2001, PositioningMethod::NrBased,
            Some(NrPositioningMethod::MultiRtt),
            Some("gnb-002".to_string()),
            PositioningQos::HighAccuracy,
        ).unwrap();

        let cells = vec![
            CellMeasurement {
                nr_cgi: "001-01-0002-01".to_string(),
                rsrp: Some(-75),
                rsrq: Some(-8),
                timing_advance: None,
                aoa: Some(45.0),
                rtt_ns: Some(1000),
            },
            CellMeasurement {
                nr_cgi: "001-01-0002-02".to_string(),
                rsrp: Some(-85),
                rsrq: Some(-12),
                timing_advance: None,
                aoa: Some(120.0),
                rtt_ns: Some(2000),
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
        let cells = vec![CellMeasurement {
            nr_cgi: "test-cell".to_string(),
            rsrp: Some(-70),
            rsrq: None,
            timing_advance: None,
            aoa: None,
            rtt_ns: None,
        }];
        let loc = compute_location(&PositioningMethod::Ecid, &cells);
        assert!(loc.horizontal_accuracy > 50.0); // ECID is coarse
    }

    #[test]
    fn test_compute_location_gnss() {
        let cells = vec![CellMeasurement {
            nr_cgi: "test-cell".to_string(),
            rsrp: None, rsrq: None, timing_advance: None, aoa: None, rtt_ns: None,
        }];
        let loc = compute_location(&PositioningMethod::Gnss, &cells);
        assert!(loc.horizontal_accuracy <= 5.0); // GNSS is accurate
    }
}
