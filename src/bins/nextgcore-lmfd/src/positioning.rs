//! Real multilateration / positioning solvers (lmfd-08).
//!
//! This module replaces the SIMULATED placeholder estimator with genuine
//! geometric positioning math: ECID (Enhanced Cell-ID with a Timing-Advance
//! ring), Multi-RTT trilateration, TDOA hyperbolic multilateration and
//! AoA/AoD angle-intersection. Every solver returns a [`PositioningEstimate`]
//! whose `lat_deg`/`lon_deg`/`uncertainty` feed straight into
//! [`crate::nlmf::to_gad`] for TS 23.032 GAD encoding.
//!
//! ## Status (lmfd-08, Wave-3)
//!
//! This file is STANDALONE (no dependency on the NRPPa / LPP ASN.1 codecs
//! lmfd-LIB-01/02) and is **wired into
//! [`crate::context::LmfContext::measurement_report`]** (via the runtime
//! `try_real_solve` helper) as of lmfd-08. The solver selection order is:
//! Multi-RTT (≥3 cells with `rtt_ns`) → AoA (≥2 cells with `aoa`) → ECID
//! (serving cell with `timing_advance`). A7 (lmfd-11): when the cell coordinate
//! registry is empty or no matching cells are found the runtime path returns
//! `None` (no fabricated fix) — the heuristic placeholder is now test-only.
//!
//! `solve_tdoa` and `TdoaObservation` remain available for lmfd-05/06 (NRPPa
//! TDOA measurements) but are not yet called on the runtime path; the
//! workspace `dead_code = "allow"` suppresses the lint. The solver math is
//! exercised against closed-form synthetic geometries (known TRP coordinates +
//! a known UE position) below.
//!
//! ## Coordinate model — local ENU tangent plane
//!
//! All solving is done in a **local East/North/Up (ENU) tangent plane** anchored
//! at a reference origin (the centroid of the registered TRPs). Geodetic
//! lat/lon are mapped to metres via the WGS-84 radii of curvature evaluated at
//! the origin latitude (an *equirectangular* / first-order linearization):
//!
//! ```text
//! east  = (lon - lon0) * (pi/180) * N(lat0) * cos(lat0)
//! north = (lat - lat0) * (pi/180) * M(lat0)
//! ```
//!
//! where `N` is the prime-vertical and `M` the meridional radius of curvature.
//! This is accurate to well under a metre over the few-kilometre spans typical
//! of cellular TRP deployments (the dropped curvature term is O(d^3 / R^2); at
//! d = 10 km that is ~2.5 mm). It is NOT valid for inter-continental spans —
//! re-anchor the origin per positioning session, which the registry does.

use std::collections::HashMap;
use std::fmt;

/// WGS-84 semi-major axis (equatorial radius), metres.
pub const WGS84_A: f64 = 6_378_137.0;
/// WGS-84 flattening.
pub const WGS84_F: f64 = 1.0 / 298.257_223_563;
/// Speed of light in vacuum, metres per second (exact, SI).
pub const SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// Default reported confidence level for the covariance confidence ellipse.
///
/// The covariance-derived ellipse is scaled to this probability mass (see
/// [`covariance_to_ellipse`]); positioning systems conventionally report the
/// 95 % ellipse.
pub const DEFAULT_CONFIDENCE: f64 = 0.95;

/// Singularity threshold on the 2x2 normal-equation determinant. Below this the
/// geometry is treated as degenerate (collinear TRPs / parallel bearings).
const DET_EPSILON: f64 = 1e-9;

// ===========================================================================
// Public model types
// ===========================================================================

/// Geodetic coordinate of a TRP / cell (WGS-84 decimal degrees + ellipsoidal
/// height in metres).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrpCoord {
    /// Latitude, decimal degrees (-90..90).
    pub lat_deg: f64,
    /// Longitude, decimal degrees (-180..180).
    pub lon_deg: f64,
    /// Height above the WGS-84 ellipsoid, metres.
    pub height_m: f64,
}

impl TrpCoord {
    /// Construct a TRP coordinate.
    pub fn new(lat_deg: f64, lon_deg: f64, height_m: f64) -> Self {
        Self {
            lat_deg,
            lon_deg,
            height_m,
        }
    }
}

/// A point in the local ENU tangent plane (metres).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnuPoint {
    /// East offset from the origin, metres.
    pub e: f64,
    /// North offset from the origin, metres.
    pub n: f64,
    /// Up offset from the origin, metres.
    pub u: f64,
}

/// The positioning method that produced an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositioningMethodKind {
    /// Enhanced Cell-ID (serving cell + Timing-Advance ring).
    Ecid,
    /// Multi-RTT trilateration (>=3 ranges).
    MultiRtt,
    /// Time-Difference-of-Arrival hyperbolic multilateration (>=3 TRPs).
    Tdoa,
    /// Angle-of-Arrival / Angle-of-Departure bearing intersection (>=2 TRPs).
    AngleOfArrival,
}

impl PositioningMethodKind {
    /// The TS 29.572 `PositioningMethod` string for this method.
    pub fn as_spec_str(self) -> &'static str {
        match self {
            PositioningMethodKind::Ecid => "NR_ECID",
            PositioningMethodKind::MultiRtt => "MULTI-RTT",
            PositioningMethodKind::Tdoa => "UL_TDOA",
            PositioningMethodKind::AngleOfArrival => "UL_AOA",
        }
    }
}

/// A 1-axis confidence ellipse (TS 23.032 `UncertaintyEllipse` semantics).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UncertaintyEllipse {
    /// Semi-major axis length, metres.
    pub semi_major_m: f64,
    /// Semi-minor axis length, metres.
    pub semi_minor_m: f64,
    /// Orientation of the major axis, degrees clockwise from North, in [0,180).
    pub orientation_deg: f64,
}

/// A computed position estimate. The `lat_deg`/`lon_deg`/`uncertainty` fields
/// feed [`crate::nlmf::to_gad`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PositioningEstimate {
    /// Latitude, decimal degrees.
    pub lat_deg: f64,
    /// Longitude, decimal degrees.
    pub lon_deg: f64,
    /// Height above the WGS-84 ellipsoid, metres (when vertically resolved).
    pub height_m: Option<f64>,
    /// Confidence ellipse derived from the LS residual covariance.
    pub uncertainty: UncertaintyEllipse,
    /// The method that produced this estimate.
    pub method: PositioningMethodKind,
    /// Confidence level the ellipse is scaled to (0..1).
    pub confidence: f64,
}

impl PositioningEstimate {
    /// Horizontal uncertainty as a single radius (the semi-major axis), metres.
    /// Convenience for `POINT_UNCERTAINTY_CIRCLE` GAD encoding.
    pub fn horizontal_uncertainty_m(&self) -> f64 {
        self.uncertainty.semi_major_m
    }
}

/// Typed positioning failure modes (degenerate input, bad geometry,
/// non-convergence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PositioningError {
    /// Fewer TRPs/measurements than the method requires.
    InsufficientTrps {
        /// Minimum number of TRPs the method needs.
        needed: usize,
        /// Number actually supplied.
        got: usize,
    },
    /// An observation referenced a TRP id absent from the registry.
    UnknownTrp(String),
    /// Coincident / collinear TRPs or parallel bearings: the normal-equation
    /// system is singular and the position is not observable.
    DegenerateGeometry(String),
    /// Iterative least-squares did not converge within the iteration budget.
    NoConvergence {
        /// Iterations attempted before giving up.
        iterations: usize,
    },
    /// A measurement was missing or physically invalid (e.g. negative range).
    InvalidMeasurement(String),
}

impl fmt::Display for PositioningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PositioningError::InsufficientTrps { needed, got } => {
                write!(f, "insufficient TRPs: need {needed}, got {got}")
            }
            PositioningError::UnknownTrp(id) => write!(f, "unknown TRP id: {id}"),
            PositioningError::DegenerateGeometry(d) => write!(f, "degenerate geometry: {d}"),
            PositioningError::NoConvergence { iterations } => {
                write!(
                    f,
                    "least-squares did not converge in {iterations} iterations"
                )
            }
            PositioningError::InvalidMeasurement(d) => write!(f, "invalid measurement: {d}"),
        }
    }
}

impl std::error::Error for PositioningError {}

// ===========================================================================
// TRP / cell coordinate registry
// ===========================================================================

/// Maps NR-CGI / TRP-id strings to geodetic coordinates and anchors the local
/// ENU tangent plane used by the solvers.
///
/// The ENU origin defaults to the centroid of all registered TRPs (best
/// linearization accuracy); override with [`TrpRegistry::with_origin`]. The
/// `lmf.yaml` config wiring is a follow-up (lmfd-08 wiring) — for now build
/// with [`TrpRegistry::from_entries`].
#[derive(Debug, Clone)]
pub struct TrpRegistry {
    coords: HashMap<String, TrpCoord>,
    origin: TrpCoord,
}

impl TrpRegistry {
    /// Build a registry from `(id, coord)` entries. The ENU origin is the
    /// centroid of the supplied coordinates. An empty input yields an origin at
    /// (0,0,0); add TRPs before solving.
    pub fn from_entries<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (String, TrpCoord)>,
    {
        let coords: HashMap<String, TrpCoord> = entries.into_iter().collect();
        let origin = centroid(coords.values());
        Self { coords, origin }
    }

    /// Build a registry with an explicit ENU origin (e.g. the serving cell, or
    /// a configured reference point).
    pub fn with_origin<I>(entries: I, origin: TrpCoord) -> Self
    where
        I: IntoIterator<Item = (String, TrpCoord)>,
    {
        Self {
            coords: entries.into_iter().collect(),
            origin,
        }
    }

    /// The reference origin of the ENU tangent plane.
    pub fn origin(&self) -> TrpCoord {
        self.origin
    }

    /// Number of registered TRPs.
    pub fn len(&self) -> usize {
        self.coords.len()
    }

    /// Whether the registry holds no TRPs.
    pub fn is_empty(&self) -> bool {
        self.coords.is_empty()
    }

    /// Insert / update a single TRP. Does NOT move the ENU origin (use
    /// [`TrpRegistry::reanchor`] to recompute it).
    pub fn insert(&mut self, id: impl Into<String>, coord: TrpCoord) {
        self.coords.insert(id.into(), coord);
    }

    /// Recompute the ENU origin as the centroid of the current TRPs.
    pub fn reanchor(&mut self) {
        self.origin = centroid(self.coords.values());
    }

    /// Geodetic coordinate of a TRP, if registered.
    pub fn lookup(&self, id: &str) -> Option<TrpCoord> {
        self.coords.get(id).copied()
    }

    /// ENU position of a TRP relative to the registry origin, if registered.
    pub fn enu_of(&self, id: &str) -> Option<EnuPoint> {
        self.lookup(id).map(|c| geodetic_to_enu(c, self.origin))
    }

    /// Map a geodetic coordinate to ENU relative to the registry origin.
    pub fn to_enu(&self, coord: TrpCoord) -> EnuPoint {
        geodetic_to_enu(coord, self.origin)
    }

    /// Map an ENU position (relative to the registry origin) back to geodetic.
    pub fn geodetic_of(&self, p: EnuPoint) -> TrpCoord {
        enu_to_geodetic(p, self.origin)
    }
}

fn centroid<'a, I>(coords: I) -> TrpCoord
where
    I: IntoIterator<Item = &'a TrpCoord>,
{
    let mut n = 0.0f64;
    let (mut lat, mut lon, mut h) = (0.0f64, 0.0f64, 0.0f64);
    for c in coords {
        lat += c.lat_deg;
        lon += c.lon_deg;
        h += c.height_m;
        n += 1.0;
    }
    if n == 0.0 {
        return TrpCoord::new(0.0, 0.0, 0.0);
    }
    TrpCoord::new(lat / n, lon / n, h / n)
}

// ===========================================================================
// Geodetic <-> ENU conversion (WGS-84, local tangent plane)
// ===========================================================================

/// WGS-84 first eccentricity squared, `e^2 = f(2 - f)`.
fn wgs84_e2() -> f64 {
    WGS84_F * (2.0 - WGS84_F)
}

/// Prime-vertical radius of curvature `N(lat)` (metres).
fn radius_n(lat_rad: f64) -> f64 {
    let s = lat_rad.sin();
    WGS84_A / (1.0 - wgs84_e2() * s * s).sqrt()
}

/// Meridional radius of curvature `M(lat)` (metres).
fn radius_m(lat_rad: f64) -> f64 {
    let s = lat_rad.sin();
    let e2 = wgs84_e2();
    WGS84_A * (1.0 - e2) / (1.0 - e2 * s * s).powf(1.5)
}

/// Map geodetic `coord` to the local ENU plane anchored at `origin`
/// (equirectangular linearization; see module docs for validity).
pub fn geodetic_to_enu(coord: TrpCoord, origin: TrpCoord) -> EnuPoint {
    let lat0 = origin.lat_deg.to_radians();
    let dlat = (coord.lat_deg - origin.lat_deg).to_radians();
    let dlon = (coord.lon_deg - origin.lon_deg).to_radians();
    let east = dlon * radius_n(lat0) * lat0.cos();
    let north = dlat * radius_m(lat0);
    EnuPoint {
        e: east,
        n: north,
        u: coord.height_m - origin.height_m,
    }
}

/// Inverse of [`geodetic_to_enu`]: map an ENU point back to geodetic.
pub fn enu_to_geodetic(p: EnuPoint, origin: TrpCoord) -> TrpCoord {
    let lat0 = origin.lat_deg.to_radians();
    let dlat = p.n / radius_m(lat0);
    let dlon = p.e / (radius_n(lat0) * lat0.cos());
    TrpCoord {
        lat_deg: origin.lat_deg + dlat.to_degrees(),
        lon_deg: origin.lon_deg + dlon.to_degrees(),
        height_m: origin.height_m + p.u,
    }
}

// ===========================================================================
// Measurement-unit conversion helpers
// ===========================================================================

/// Convert an NR round-trip time (nanoseconds) to a one-way range (metres):
/// `d = c * rtt / 2`.
pub fn rtt_ns_to_range_m(rtt_ns: f64) -> f64 {
    SPEED_OF_LIGHT_M_S * rtt_ns * 1e-9 / 2.0
}

/// Convert a time-difference-of-arrival (nanoseconds) to a range difference
/// (metres): `dd = c * tdoa`.
pub fn tdoa_ns_to_range_diff_m(tdoa_ns: f64) -> f64 {
    SPEED_OF_LIGHT_M_S * tdoa_ns * 1e-9
}

/// Convert an NR Timing-Advance command value to a one-way range (metres).
///
/// Per TS 38.213 the applied uplink advance is `N_TA = T_A * 16 * 64 / 2^mu`
/// expressed in units of the basic time `Tc = 1 / (480000 * 4096)` s. `N_TA`
/// is the round-trip timing, so the one-way distance is `c * N_TA * Tc / 2`.
/// `scs_mu` is the numerology (0 = 15 kHz, 1 = 30 kHz, ...).
pub fn nr_ta_to_range_m(ta: u32, scs_mu: u8) -> f64 {
    let tc = 1.0 / (480_000.0 * 4096.0);
    let n_ta = f64::from(ta) * 16.0 * 64.0 / f64::from(1u32 << scs_mu);
    let round_trip_s = n_ta * tc;
    SPEED_OF_LIGHT_M_S * round_trip_s / 2.0
}

// ===========================================================================
// Observation input types
// ===========================================================================

/// A Multi-RTT range observation: one-way range (metres) to a TRP.
#[derive(Debug, Clone, PartialEq)]
pub struct RttObservation {
    /// TRP / NR-CGI id (must be present in the registry).
    pub trp_id: String,
    /// One-way range to the TRP, metres.
    pub range_m: f64,
}

/// A TDOA observation: time difference of arrival (nanoseconds) of the signal
/// at `trp_id` relative to the reference TRP.
#[derive(Debug, Clone, PartialEq)]
pub struct TdoaObservation {
    /// TRP / NR-CGI id (must be present in the registry).
    pub trp_id: String,
    /// Time difference of arrival relative to the reference TRP, nanoseconds.
    /// Positive => signal reaches `trp_id` later than the reference.
    pub tdoa_ns: f64,
}

/// An AoA/AoD observation: azimuth (degrees, clockwise from North) of the UE as
/// seen from `trp_id`.
#[derive(Debug, Clone, PartialEq)]
pub struct AoaObservation {
    /// TRP / NR-CGI id (must be present in the registry).
    pub trp_id: String,
    /// Azimuth to the UE, degrees clockwise from North.
    pub azimuth_deg: f64,
}

// ===========================================================================
// Linear-algebra helpers (all 2x2 — hand-rolled, no external deps)
// ===========================================================================

/// Solve the 2x2 system `A x = b` via Cramer's rule. Returns `None` when `A` is
/// (near-)singular.
fn solve_2x2(a: [[f64; 2]; 2], b: [f64; 2]) -> Option<[f64; 2]> {
    let det = a[0][0] * a[1][1] - a[0][1] * a[1][0];
    if det.abs() < DET_EPSILON {
        return None;
    }
    let x = (b[0] * a[1][1] - a[0][1] * b[1]) / det;
    let y = (a[0][0] * b[1] - b[0] * a[1][0]) / det;
    Some([x, y])
}

/// Invert a symmetric 2x2 matrix. Returns `None` when (near-)singular.
fn invert_2x2_sym(m: [[f64; 2]; 2]) -> Option<[[f64; 2]; 2]> {
    let det = m[0][0] * m[1][1] - m[0][1] * m[1][0];
    if det.abs() < DET_EPSILON {
        return None;
    }
    let inv_det = 1.0 / det;
    Some([
        [m[1][1] * inv_det, -m[0][1] * inv_det],
        [-m[1][0] * inv_det, m[0][0] * inv_det],
    ])
}

/// Eigen-decomposition of a symmetric 2x2 matrix `[[a, b],[b, c]]`.
/// Returns `(lambda_major, lambda_minor, orientation_rad)` where the
/// orientation is the angle (radians) of the major-axis eigenvector measured in
/// the (East, North) plane as `atan2(e, n)` — i.e. clockwise from North.
fn eigen_2x2_sym(m: [[f64; 2]; 2]) -> (f64, f64, f64) {
    let a = m[0][0];
    let b = m[0][1];
    let c = m[1][1];
    let tr = a + c;
    let disc = (((a - c) * 0.5).powi(2) + b * b).max(0.0).sqrt();
    let l1 = tr * 0.5 + disc; // major
    let l2 = (tr * 0.5 - disc).max(0.0); // minor (clamp tiny negatives)
                                         // Eigenvector for l1: (b, l1 - a) unless b ~ 0 (already diagonal).
    let (ve, vn) = if b.abs() > 1e-15 {
        (b, l1 - a)
    } else if a >= c {
        (1.0, 0.0)
    } else {
        (0.0, 1.0)
    };
    // Orientation as a compass bearing of the major axis (clockwise from North).
    let orientation = ve.atan2(vn);
    (l1, l2, orientation)
}

/// Convert a 2x2 position covariance (in ENU East/North metres^2) to a scaled
/// confidence ellipse. `confidence` in (0,1); for 2 degrees of freedom the
/// scale is `k = sqrt(-2 ln(1 - confidence))` (exact Rayleigh quantile).
pub fn covariance_to_ellipse(cov: [[f64; 2]; 2], confidence: f64) -> UncertaintyEllipse {
    let (l1, l2, orient_rad) = eigen_2x2_sym(cov);
    let p = confidence.clamp(1e-6, 1.0 - 1e-12);
    let k = (-2.0 * (1.0 - p).ln()).sqrt();
    let mut orientation_deg = orient_rad.to_degrees();
    // Normalize an axis orientation to [0, 180).
    orientation_deg = orientation_deg.rem_euclid(180.0);
    UncertaintyEllipse {
        semi_major_m: k * l1.sqrt(),
        semi_minor_m: k * l2.sqrt(),
        orientation_deg,
    }
}

// ===========================================================================
// Solver: ECID (serving cell + Timing-Advance ring)
// ===========================================================================

/// Enhanced Cell-ID: place the estimate at the serving cell and bound the UE to
/// the Timing-Advance ring around it.
///
/// The UE lies on a ring of radius `d = nr_ta_to_range_m(ta, scs_mu)` centred on
/// the serving cell. Absent any angle information the best point estimate is the
/// cell itself, with a circular uncertainty equal to the ring radius plus half
/// the TA quantization step (a geometric, not statistical, bound — reported at
/// [`DEFAULT_CONFIDENCE`]).
pub fn solve_ecid(
    registry: &TrpRegistry,
    serving_trp: &str,
    ta: Option<u32>,
    scs_mu: u8,
) -> Result<PositioningEstimate, PositioningError> {
    let cell = registry
        .lookup(serving_trp)
        .ok_or_else(|| PositioningError::UnknownTrp(serving_trp.to_string()))?;
    let ta = ta.ok_or_else(|| {
        PositioningError::InvalidMeasurement("ECID requires a timing-advance value".to_string())
    })?;
    let d = nr_ta_to_range_m(ta, scs_mu);
    let quant = nr_ta_to_range_m(1, scs_mu); // one-step distance
    let radius = d + quant / 2.0;
    Ok(PositioningEstimate {
        lat_deg: cell.lat_deg,
        lon_deg: cell.lon_deg,
        height_m: Some(cell.height_m),
        uncertainty: UncertaintyEllipse {
            semi_major_m: radius,
            semi_minor_m: radius,
            orientation_deg: 0.0,
        },
        method: PositioningMethodKind::Ecid,
        confidence: DEFAULT_CONFIDENCE,
    })
}

// ===========================================================================
// Solver: Multi-RTT trilateration (Gauss-Newton least squares)
// ===========================================================================

/// Maximum Gauss-Newton iterations before declaring non-convergence.
const MAX_GN_ITERS: usize = 50;
/// Gauss-Newton step convergence threshold (metres).
const GN_TOL_M: f64 = 1e-6;

/// Multi-RTT trilateration: recover the 2-D position from >=3 one-way ranges via
/// iterative (Gauss-Newton) nonlinear least squares, then derive the confidence
/// ellipse from the residual covariance.
pub fn solve_multi_rtt(
    registry: &TrpRegistry,
    observations: &[RttObservation],
) -> Result<PositioningEstimate, PositioningError> {
    const MIN: usize = 3;
    if observations.len() < MIN {
        return Err(PositioningError::InsufficientTrps {
            needed: MIN,
            got: observations.len(),
        });
    }
    // Resolve TRP ENU positions and validate ranges.
    let mut anchors: Vec<(f64, f64, f64)> = Vec::with_capacity(observations.len());
    for o in observations {
        if !(o.range_m.is_finite() && o.range_m >= 0.0) {
            return Err(PositioningError::InvalidMeasurement(format!(
                "range for {} is not a non-negative finite number",
                o.trp_id
            )));
        }
        let p = registry
            .enu_of(&o.trp_id)
            .ok_or_else(|| PositioningError::UnknownTrp(o.trp_id.clone()))?;
        anchors.push((p.e, p.n, o.range_m));
    }
    require_non_collinear(anchors.iter().map(|a| (a.0, a.1)))?;

    // Initial guess: range-weighted centroid of the anchors.
    let mut x = anchors.iter().map(|a| a.0).sum::<f64>() / anchors.len() as f64;
    let mut y = anchors.iter().map(|a| a.1).sum::<f64>() / anchors.len() as f64;

    let mut at_a;
    let mut iters = 0;
    loop {
        iters += 1;
        // Build normal equations for residual r_i = |x - p_i| - d_i.
        at_a = [[0.0; 2]; 2];
        let mut at_r = [0.0; 2];
        for &(px, py, d) in &anchors {
            let dx = x - px;
            let dy = y - py;
            let rng = (dx * dx + dy * dy).sqrt();
            if rng < 1e-9 {
                // Estimate sitting on an anchor: nudge to avoid a zero Jacobian.
                continue;
            }
            // Jacobian row = unit vector from anchor to estimate.
            let jx = dx / rng;
            let jy = dy / rng;
            let res = rng - d;
            at_a[0][0] += jx * jx;
            at_a[0][1] += jx * jy;
            at_a[1][0] += jx * jy;
            at_a[1][1] += jy * jy;
            at_r[0] += jx * res;
            at_r[1] += jy * res;
        }
        let step = match solve_2x2(at_a, [-at_r[0], -at_r[1]]) {
            Some(s) => s,
            None => {
                return Err(PositioningError::DegenerateGeometry(
                    "RTT normal equations are singular (collinear anchors)".to_string(),
                ))
            }
        };
        x += step[0];
        y += step[1];
        if step[0].hypot(step[1]) < GN_TOL_M {
            break;
        }
        if iters >= MAX_GN_ITERS {
            return Err(PositioningError::NoConvergence { iterations: iters });
        }
    }

    // Residual covariance: sigma^2 (A^T A)^-1, sigma^2 = RSS / dof.
    let mut rss = 0.0;
    for &(px, py, d) in &anchors {
        let r = ((x - px).hypot(y - py)) - d;
        rss += r * r;
    }
    let dof = (anchors.len() as f64 - 2.0).max(1.0);
    let sigma2 = rss / dof;
    let cov = scaled_covariance(at_a, sigma2)?;
    finish(registry, x, y, cov, PositioningMethodKind::MultiRtt)
}

// ===========================================================================
// Solver: TDOA hyperbolic multilateration (Gauss-Newton least squares)
// ===========================================================================

/// TDOA hyperbolic multilateration: recover the 2-D position from >=3 TRPs
/// (a reference + >=2 others) using iterative least squares on the range-
/// difference residuals `r_i = (|x - p_i| - |x - p_ref|) - dd_i`.
///
/// The reference TRP is `observations[0]`; its `tdoa_ns` is ignored (it is the
/// zero reference). Remaining observations carry TDOA relative to it.
pub fn solve_tdoa(
    registry: &TrpRegistry,
    observations: &[TdoaObservation],
) -> Result<PositioningEstimate, PositioningError> {
    const MIN: usize = 3;
    if observations.len() < MIN {
        return Err(PositioningError::InsufficientTrps {
            needed: MIN,
            got: observations.len(),
        });
    }
    // Resolve ENU anchors; element 0 is the reference.
    let mut anchors: Vec<(f64, f64)> = Vec::with_capacity(observations.len());
    for o in observations {
        let p = registry
            .enu_of(&o.trp_id)
            .ok_or_else(|| PositioningError::UnknownTrp(o.trp_id.clone()))?;
        if !o.tdoa_ns.is_finite() {
            return Err(PositioningError::InvalidMeasurement(format!(
                "TDOA for {} is not finite",
                o.trp_id
            )));
        }
        anchors.push((p.e, p.n));
    }
    require_non_collinear(anchors.iter().copied())?;
    let (rx, ry) = anchors[0];
    // Range differences dd_i = c * tdoa_i (relative to the reference).
    let dd: Vec<f64> = observations
        .iter()
        .skip(1)
        .map(|o| tdoa_ns_to_range_diff_m(o.tdoa_ns))
        .collect();

    // Initial guess: centroid of the non-reference anchors.
    let mut x = anchors.iter().skip(1).map(|a| a.0).sum::<f64>() / (anchors.len() - 1) as f64;
    let mut y = anchors.iter().skip(1).map(|a| a.1).sum::<f64>() / (anchors.len() - 1) as f64;

    let mut at_a;
    let mut iters = 0;
    loop {
        iters += 1;
        at_a = [[0.0; 2]; 2];
        let mut at_r = [0.0; 2];
        let rref = (x - rx).hypot(y - ry).max(1e-9);
        let jref = [(x - rx) / rref, (y - ry) / rref];
        for (k, &(px, py)) in anchors.iter().enumerate().skip(1) {
            let rng = (x - px).hypot(y - py).max(1e-9);
            // Jacobian of (rng - rref): unit(anchor->x) - unit(ref->x).
            let jx = (x - px) / rng - jref[0];
            let jy = (y - py) / rng - jref[1];
            let res = (rng - rref) - dd[k - 1];
            at_a[0][0] += jx * jx;
            at_a[0][1] += jx * jy;
            at_a[1][0] += jx * jy;
            at_a[1][1] += jy * jy;
            at_r[0] += jx * res;
            at_r[1] += jy * res;
        }
        let step = match solve_2x2(at_a, [-at_r[0], -at_r[1]]) {
            Some(s) => s,
            None => {
                return Err(PositioningError::DegenerateGeometry(
                    "TDOA normal equations are singular (collinear anchors)".to_string(),
                ))
            }
        };
        x += step[0];
        y += step[1];
        if step[0].hypot(step[1]) < GN_TOL_M {
            break;
        }
        if iters >= MAX_GN_ITERS {
            return Err(PositioningError::NoConvergence { iterations: iters });
        }
    }

    // Residual covariance over the (m-1) range-difference equations.
    let rref = (x - rx).hypot(y - ry).max(1e-9);
    let mut rss = 0.0;
    for (k, &(px, py)) in anchors.iter().enumerate().skip(1) {
        let r = ((x - px).hypot(y - py) - rref) - dd[k - 1];
        rss += r * r;
    }
    let n_eq = (anchors.len() - 1) as f64;
    let dof = (n_eq - 2.0).max(1.0);
    let sigma2 = rss / dof;
    let cov = scaled_covariance(at_a, sigma2)?;
    finish(registry, x, y, cov, PositioningMethodKind::Tdoa)
}

// ===========================================================================
// Solver: AoA/AoD bearing intersection (linear least squares)
// ===========================================================================

/// AoA/AoD angle intersection: recover the 2-D position from >=2 azimuth
/// bearings via linear least squares (each bearing is a line; the position is
/// their LS intersection).
///
/// A TRP at `(e_i, n_i)` observing azimuth `theta_i` (clockwise from North)
/// constrains the UE to the line
/// `cos(theta_i) * e - sin(theta_i) * n = cos(theta_i) e_i - sin(theta_i) n_i`.
pub fn solve_aoa(
    registry: &TrpRegistry,
    observations: &[AoaObservation],
) -> Result<PositioningEstimate, PositioningError> {
    const MIN: usize = 2;
    if observations.len() < MIN {
        return Err(PositioningError::InsufficientTrps {
            needed: MIN,
            got: observations.len(),
        });
    }
    // Stack the linear constraints into normal equations A^T A x = A^T b.
    let mut at_a = [[0.0; 2]; 2];
    let mut at_b = [0.0; 2];
    let mut rows: Vec<([f64; 2], f64)> = Vec::with_capacity(observations.len());
    for o in observations {
        if !o.azimuth_deg.is_finite() {
            return Err(PositioningError::InvalidMeasurement(format!(
                "azimuth for {} is not finite",
                o.trp_id
            )));
        }
        let p = registry
            .enu_of(&o.trp_id)
            .ok_or_else(|| PositioningError::UnknownTrp(o.trp_id.clone()))?;
        let th = o.azimuth_deg.to_radians();
        let (s, c) = th.sin_cos();
        // Row: [c, -s] . [e, n] = c*e_i - s*n_i.
        let a = [c, -s];
        let b = c * p.e - s * p.n;
        at_a[0][0] += a[0] * a[0];
        at_a[0][1] += a[0] * a[1];
        at_a[1][0] += a[0] * a[1];
        at_a[1][1] += a[1] * a[1];
        at_b[0] += a[0] * b;
        at_b[1] += a[1] * b;
        rows.push((a, b));
    }
    let sol = solve_2x2(at_a, at_b).ok_or_else(|| {
        PositioningError::DegenerateGeometry(
            "AoA normal equations are singular (parallel bearings)".to_string(),
        )
    })?;
    let (x, y) = (sol[0], sol[1]);

    // Residual covariance from the perpendicular-distance residuals.
    let mut rss = 0.0;
    for (a, b) in &rows {
        let r = a[0] * x + a[1] * y - b;
        rss += r * r;
    }
    let dof = (rows.len() as f64 - 2.0).max(1.0);
    let sigma2 = rss / dof;
    let cov = scaled_covariance(at_a, sigma2)?;
    finish(registry, x, y, cov, PositioningMethodKind::AngleOfArrival)
}

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Build `sigma^2 (A^T A)^-1`, flooring a singular/near-zero σ² so noiseless
/// solutions report a tiny (non-degenerate) ellipse instead of failing.
fn scaled_covariance(at_a: [[f64; 2]; 2], sigma2: f64) -> Result<[[f64; 2]; 2], PositioningError> {
    let inv = invert_2x2_sym(at_a).ok_or_else(|| {
        PositioningError::DegenerateGeometry("information matrix is singular".to_string())
    })?;
    // Floor sigma^2 so exact (noiseless) fits still yield a finite, tiny ellipse.
    let s2 = if sigma2.is_finite() && sigma2 > 1e-12 {
        sigma2
    } else {
        1e-6
    };
    Ok([
        [inv[0][0] * s2, inv[0][1] * s2],
        [inv[1][0] * s2, inv[1][1] * s2],
    ])
}

/// Reject collinear (or coincident) anchor geometry by checking that the
/// anchors span a non-degenerate triangle (max triangle area over the set is
/// above an absolute floor).
fn require_non_collinear<I>(points: I) -> Result<(), PositioningError>
where
    I: IntoIterator<Item = (f64, f64)>,
{
    let pts: Vec<(f64, f64)> = points.into_iter().collect();
    if pts.len() < 3 {
        // 2-point methods (AoA) are validated by the normal-equation determinant
        // instead; nothing to check here.
        return Ok(());
    }
    let (ax, ay) = pts[0];
    let mut max_area2 = 0.0f64;
    for i in 1..pts.len() {
        for j in (i + 1)..pts.len() {
            let (bx, by) = pts[i];
            let (cx, cy) = pts[j];
            // Twice the triangle area = |(b-a) x (c-a)|.
            let area2 = ((bx - ax) * (cy - ay) - (cx - ax) * (by - ay)).abs();
            if area2 > max_area2 {
                max_area2 = area2;
            }
        }
    }
    // Floor: 1 m^2 of (2x) area across the whole set => effectively collinear.
    if max_area2 < 1.0 {
        return Err(PositioningError::DegenerateGeometry(
            "anchors are collinear or coincident".to_string(),
        ));
    }
    Ok(())
}

/// Convert a solved ENU position + covariance into a geodetic
/// [`PositioningEstimate`].
fn finish(
    registry: &TrpRegistry,
    x: f64,
    y: f64,
    cov: [[f64; 2]; 2],
    method: PositioningMethodKind,
) -> Result<PositioningEstimate, PositioningError> {
    let geo = registry.geodetic_of(EnuPoint { e: x, n: y, u: 0.0 });
    let uncertainty = covariance_to_ellipse(cov, DEFAULT_CONFIDENCE);
    Ok(PositioningEstimate {
        lat_deg: geo.lat_deg,
        lon_deg: geo.lon_deg,
        height_m: None,
        uncertainty,
        method,
        confidence: DEFAULT_CONFIDENCE,
    })
}

// ===========================================================================
// Tests — synthetic geometries with known ground truth
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Reference origin shared by the synthetic scenes (San Francisco-ish, to
    // match the existing lmfd simulator origin).
    const ORIGIN_LAT: f64 = 37.7749;
    const ORIGIN_LON: f64 = -122.4194;

    /// Build a registry of four TRPs placed at known ENU offsets (metres) from
    /// the reference origin, plus the geodetic position of a UE at a known ENU
    /// point. Returns (registry, true_ue_geodetic, true_ue_enu).
    fn scene() -> (TrpRegistry, TrpCoord, EnuPoint) {
        let origin = TrpCoord::new(ORIGIN_LAT, ORIGIN_LON, 0.0);
        // TRP ENU layout (metres): a non-collinear quad around the area.
        let trp_enu = [
            (
                "trp-a",
                EnuPoint {
                    e: 0.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
            (
                "trp-b",
                EnuPoint {
                    e: 1000.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
            (
                "trp-c",
                EnuPoint {
                    e: 0.0,
                    n: 1000.0,
                    u: 0.0,
                },
            ),
            (
                "trp-d",
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
        // Anchor the registry origin explicitly so the synthetic ENU frame and
        // the solver frame coincide exactly.
        let registry = TrpRegistry::with_origin(entries, origin);
        // True UE at a known interior ENU point.
        let true_enu = EnuPoint {
            e: 350.0,
            n: 600.0,
            u: 0.0,
        };
        let true_geo = enu_to_geodetic(true_enu, origin);
        (registry, true_geo, true_enu)
    }

    /// Exact one-way range (metres) from a TRP to the UE in the ENU frame.
    fn exact_range(registry: &TrpRegistry, trp: &str, ue: EnuPoint) -> f64 {
        let p = registry.enu_of(trp).unwrap();
        (ue.e - p.e).hypot(ue.n - p.n)
    }

    /// Horizontal distance (metres) between two geodetic points in the scene
    /// ENU frame.
    fn geo_dist_m(registry: &TrpRegistry, a: TrpCoord, b: TrpCoord) -> f64 {
        let pa = registry.to_enu(a);
        let pb = registry.to_enu(b);
        (pa.e - pb.e).hypot(pa.n - pb.n)
    }

    // -- Geodetic <-> ENU round-trip ----------------------------------------
    #[test]
    fn test_enu_geodetic_roundtrip() {
        let origin = TrpCoord::new(ORIGIN_LAT, ORIGIN_LON, 12.0);
        let p = EnuPoint {
            e: 1234.5,
            n: -678.9,
            u: 7.0,
        };
        let geo = enu_to_geodetic(p, origin);
        let back = geodetic_to_enu(geo, origin);
        assert!((back.e - p.e).abs() < 1e-6, "east {} vs {}", back.e, p.e);
        assert!((back.n - p.n).abs() < 1e-6, "north {} vs {}", back.n, p.n);
        assert!((back.u - p.u).abs() < 1e-9);
    }

    // -- ECID ----------------------------------------------------------------
    #[test]
    fn test_nr_ta_to_range_scaling() {
        // mu=0, ta=1 => ~78.07 m one-way (LTE-like step); doubling mu halves it.
        let d0 = nr_ta_to_range_m(1, 0);
        assert!((d0 - 78.07).abs() < 0.1, "ta1 mu0 = {d0}");
        let d1 = nr_ta_to_range_m(1, 1);
        assert!((d0 / d1 - 2.0).abs() < 1e-9);
        // Linear in ta.
        assert!((nr_ta_to_range_m(10, 0) - 10.0 * d0).abs() < 1e-6);
    }

    #[test]
    fn test_ecid_estimate_at_cell_with_ta_ring() {
        let (registry, _ue, _enu) = scene();
        let ta = 12u32;
        let scs_mu = 1u8;
        let est = solve_ecid(&registry, "trp-a", Some(ta), scs_mu).unwrap();
        let cell = registry.lookup("trp-a").unwrap();
        // Estimate sits exactly on the serving cell.
        assert!((est.lat_deg - cell.lat_deg).abs() < 1e-12);
        assert!((est.lon_deg - cell.lon_deg).abs() < 1e-12);
        // Uncertainty radius ~ the TA-derived range (+ half a quant step).
        let d = nr_ta_to_range_m(ta, scs_mu);
        let quant = nr_ta_to_range_m(1, scs_mu);
        assert!((est.uncertainty.semi_major_m - (d + quant / 2.0)).abs() < 1e-9);
        assert_eq!(est.method, PositioningMethodKind::Ecid);
    }

    #[test]
    fn test_ecid_unknown_cell_errors() {
        let (registry, _ue, _enu) = scene();
        let err = solve_ecid(&registry, "trp-zzz", Some(10), 0).unwrap_err();
        assert_eq!(err, PositioningError::UnknownTrp("trp-zzz".to_string()));
    }

    #[test]
    fn test_ecid_missing_ta_errors() {
        let (registry, _ue, _enu) = scene();
        let err = solve_ecid(&registry, "trp-a", None, 0).unwrap_err();
        assert!(matches!(err, PositioningError::InvalidMeasurement(_)));
    }

    // -- Multi-RTT trilateration --------------------------------------------
    #[test]
    fn test_multi_rtt_recovers_known_position() {
        let (registry, true_geo, true_enu) = scene();
        let obs: Vec<RttObservation> = ["trp-a", "trp-b", "trp-c", "trp-d"]
            .iter()
            .map(|id| RttObservation {
                trp_id: id.to_string(),
                range_m: exact_range(&registry, id, true_enu),
            })
            .collect();
        let est = solve_multi_rtt(&registry, &obs).unwrap();
        let got = TrpCoord::new(est.lat_deg, est.lon_deg, 0.0);
        assert!(
            geo_dist_m(&registry, got, true_geo) < 1e-3,
            "RTT recovered position off by {} m",
            geo_dist_m(&registry, got, true_geo)
        );
        assert_eq!(est.method, PositioningMethodKind::MultiRtt);
        // Noiseless: ellipse collapses to ~0.
        assert!(est.uncertainty.semi_major_m < 0.1);
    }

    #[test]
    fn test_multi_rtt_noise_grows_uncertainty() {
        let (registry, _true_geo, true_enu) = scene();
        let ids = ["trp-a", "trp-b", "trp-c", "trp-d"];
        let clean: Vec<RttObservation> = ids
            .iter()
            .map(|id| RttObservation {
                trp_id: id.to_string(),
                range_m: exact_range(&registry, id, true_enu),
            })
            .collect();
        // Deterministic, inconsistent perturbations (cannot be fit exactly).
        let noisy: Vec<RttObservation> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| RttObservation {
                trp_id: id.to_string(),
                range_m: exact_range(&registry, id, true_enu) + [5.0, -4.0, 6.0, -3.0][i],
            })
            .collect();
        let clean_est = solve_multi_rtt(&registry, &clean).unwrap();
        let noisy_est = solve_multi_rtt(&registry, &noisy).unwrap();
        assert!(
            noisy_est.uncertainty.semi_major_m > clean_est.uncertainty.semi_major_m + 1.0,
            "noisy ellipse {} should exceed clean {}",
            noisy_est.uncertainty.semi_major_m,
            clean_est.uncertainty.semi_major_m
        );
    }

    #[test]
    fn test_multi_rtt_too_few_trps() {
        let (registry, _g, true_enu) = scene();
        let obs: Vec<RttObservation> = ["trp-a", "trp-b"]
            .iter()
            .map(|id| RttObservation {
                trp_id: id.to_string(),
                range_m: exact_range(&registry, id, true_enu),
            })
            .collect();
        let err = solve_multi_rtt(&registry, &obs).unwrap_err();
        assert_eq!(
            err,
            PositioningError::InsufficientTrps { needed: 3, got: 2 }
        );
    }

    #[test]
    fn test_multi_rtt_collinear_trps() {
        // Three TRPs on a straight East line => collinear geometry rejected.
        let origin = TrpCoord::new(ORIGIN_LAT, ORIGIN_LON, 0.0);
        let entries: Vec<(String, TrpCoord)> = [
            (
                "c0",
                EnuPoint {
                    e: 0.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
            (
                "c1",
                EnuPoint {
                    e: 500.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
            (
                "c2",
                EnuPoint {
                    e: 1000.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
        ]
        .iter()
        .map(|(id, p)| (id.to_string(), enu_to_geodetic(*p, origin)))
        .collect();
        let registry = TrpRegistry::with_origin(entries, origin);
        let ue = EnuPoint {
            e: 400.0,
            n: 300.0,
            u: 0.0,
        };
        let obs: Vec<RttObservation> = ["c0", "c1", "c2"]
            .iter()
            .map(|id| RttObservation {
                trp_id: id.to_string(),
                range_m: exact_range(&registry, id, ue),
            })
            .collect();
        let err = solve_multi_rtt(&registry, &obs).unwrap_err();
        assert!(matches!(err, PositioningError::DegenerateGeometry(_)));
    }

    #[test]
    fn test_multi_rtt_unknown_trp() {
        let (registry, _g, true_enu) = scene();
        let obs = vec![
            RttObservation {
                trp_id: "trp-a".to_string(),
                range_m: exact_range(&registry, "trp-a", true_enu),
            },
            RttObservation {
                trp_id: "trp-b".to_string(),
                range_m: exact_range(&registry, "trp-b", true_enu),
            },
            RttObservation {
                trp_id: "ghost".to_string(),
                range_m: 100.0,
            },
        ];
        let err = solve_multi_rtt(&registry, &obs).unwrap_err();
        assert_eq!(err, PositioningError::UnknownTrp("ghost".to_string()));
    }

    // -- TDOA hyperbolic -----------------------------------------------------
    #[test]
    fn test_tdoa_recovers_known_position() {
        let (registry, true_geo, true_enu) = scene();
        let ids = ["trp-a", "trp-b", "trp-c", "trp-d"];
        let r_ref = exact_range(&registry, ids[0], true_enu);
        let obs: Vec<TdoaObservation> = ids
            .iter()
            .map(|id| {
                let r = exact_range(&registry, id, true_enu);
                // TDOA (ns) relative to the reference TRP.
                let dd = r - r_ref;
                TdoaObservation {
                    trp_id: id.to_string(),
                    tdoa_ns: dd / SPEED_OF_LIGHT_M_S * 1e9,
                }
            })
            .collect();
        let est = solve_tdoa(&registry, &obs).unwrap();
        let got = TrpCoord::new(est.lat_deg, est.lon_deg, 0.0);
        assert!(
            geo_dist_m(&registry, got, true_geo) < 1e-2,
            "TDOA recovered position off by {} m",
            geo_dist_m(&registry, got, true_geo)
        );
        assert_eq!(est.method, PositioningMethodKind::Tdoa);
        assert!(est.uncertainty.semi_major_m < 0.5);
    }

    #[test]
    fn test_tdoa_noise_grows_uncertainty() {
        let (registry, _true_geo, true_enu) = scene();
        let ids = ["trp-a", "trp-b", "trp-c", "trp-d"];
        let r_ref = exact_range(&registry, ids[0], true_enu);
        let mk = |perturb: [f64; 4]| -> Vec<TdoaObservation> {
            ids.iter()
                .enumerate()
                .map(|(i, id)| {
                    let r = exact_range(&registry, id, true_enu) + perturb[i];
                    TdoaObservation {
                        trp_id: id.to_string(),
                        tdoa_ns: (r - r_ref) / SPEED_OF_LIGHT_M_S * 1e9,
                    }
                })
                .collect()
        };
        let clean = solve_tdoa(&registry, &mk([0.0; 4])).unwrap();
        let noisy = solve_tdoa(&registry, &mk([0.0, 7.0, -6.0, 5.0])).unwrap();
        assert!(
            noisy.uncertainty.semi_major_m > clean.uncertainty.semi_major_m + 0.5,
            "noisy {} vs clean {}",
            noisy.uncertainty.semi_major_m,
            clean.uncertainty.semi_major_m
        );
    }

    #[test]
    fn test_tdoa_too_few_trps() {
        let (registry, _g, true_enu) = scene();
        let r_ref = exact_range(&registry, "trp-a", true_enu);
        let obs = vec![
            TdoaObservation {
                trp_id: "trp-a".to_string(),
                tdoa_ns: 0.0,
            },
            TdoaObservation {
                trp_id: "trp-b".to_string(),
                tdoa_ns: (exact_range(&registry, "trp-b", true_enu) - r_ref) / SPEED_OF_LIGHT_M_S
                    * 1e9,
            },
        ];
        let err = solve_tdoa(&registry, &obs).unwrap_err();
        assert_eq!(
            err,
            PositioningError::InsufficientTrps { needed: 3, got: 2 }
        );
    }

    // -- AoA bearing intersection -------------------------------------------
    #[test]
    fn test_aoa_recovers_known_position() {
        let (registry, true_geo, true_enu) = scene();
        // Azimuth (clockwise from North) from each TRP toward the UE.
        let bearing = |trp: &str| -> f64 {
            let p = registry.enu_of(trp).unwrap();
            let de = true_enu.e - p.e;
            let dn = true_enu.n - p.n;
            de.atan2(dn).to_degrees()
        };
        let obs: Vec<AoaObservation> = ["trp-a", "trp-b", "trp-c"]
            .iter()
            .map(|id| AoaObservation {
                trp_id: id.to_string(),
                azimuth_deg: bearing(id),
            })
            .collect();
        let est = solve_aoa(&registry, &obs).unwrap();
        let got = TrpCoord::new(est.lat_deg, est.lon_deg, 0.0);
        assert!(
            geo_dist_m(&registry, got, true_geo) < 1e-3,
            "AoA recovered position off by {} m",
            geo_dist_m(&registry, got, true_geo)
        );
        assert_eq!(est.method, PositioningMethodKind::AngleOfArrival);
        assert!(est.uncertainty.semi_major_m < 0.1);
    }

    #[test]
    fn test_aoa_two_trp_intersection() {
        // Exactly two bearings still resolve a unique intersection.
        let (registry, true_geo, true_enu) = scene();
        let bearing = |trp: &str| -> f64 {
            let p = registry.enu_of(trp).unwrap();
            (true_enu.e - p.e).atan2(true_enu.n - p.n).to_degrees()
        };
        let obs = vec![
            AoaObservation {
                trp_id: "trp-a".to_string(),
                azimuth_deg: bearing("trp-a"),
            },
            AoaObservation {
                trp_id: "trp-d".to_string(),
                azimuth_deg: bearing("trp-d"),
            },
        ];
        let est = solve_aoa(&registry, &obs).unwrap();
        let got = TrpCoord::new(est.lat_deg, est.lon_deg, 0.0);
        assert!(geo_dist_m(&registry, got, true_geo) < 1e-3);
    }

    #[test]
    fn test_aoa_noise_grows_uncertainty() {
        let (registry, _true_geo, true_enu) = scene();
        let ids = ["trp-a", "trp-b", "trp-c", "trp-d"];
        let bearing = |trp: &str| -> f64 {
            let p = registry.enu_of(trp).unwrap();
            (true_enu.e - p.e).atan2(true_enu.n - p.n).to_degrees()
        };
        let mk = |perturb: [f64; 4]| -> Vec<AoaObservation> {
            ids.iter()
                .enumerate()
                .map(|(i, id)| AoaObservation {
                    trp_id: id.to_string(),
                    azimuth_deg: bearing(id) + perturb[i],
                })
                .collect()
        };
        let clean = solve_aoa(&registry, &mk([0.0; 4])).unwrap();
        let noisy = solve_aoa(&registry, &mk([1.5, -1.0, 1.2, -0.8])).unwrap();
        assert!(
            noisy.uncertainty.semi_major_m > clean.uncertainty.semi_major_m + 0.5,
            "noisy {} vs clean {}",
            noisy.uncertainty.semi_major_m,
            clean.uncertainty.semi_major_m
        );
    }

    #[test]
    fn test_aoa_too_few_trps() {
        let (registry, _g, true_enu) = scene();
        let bearing = |trp: &str| -> f64 {
            let p = registry.enu_of(trp).unwrap();
            (true_enu.e - p.e).atan2(true_enu.n - p.n).to_degrees()
        };
        let obs = vec![AoaObservation {
            trp_id: "trp-a".to_string(),
            azimuth_deg: bearing("trp-a"),
        }];
        let err = solve_aoa(&registry, &obs).unwrap_err();
        assert_eq!(
            err,
            PositioningError::InsufficientTrps { needed: 2, got: 1 }
        );
    }

    #[test]
    fn test_aoa_parallel_bearings_degenerate() {
        // Two TRPs with identical bearings (parallel lines) => singular system.
        let origin = TrpCoord::new(ORIGIN_LAT, ORIGIN_LON, 0.0);
        let entries: Vec<(String, TrpCoord)> = [
            (
                "p0",
                EnuPoint {
                    e: 0.0,
                    n: 0.0,
                    u: 0.0,
                },
            ),
            (
                "p1",
                EnuPoint {
                    e: 0.0,
                    n: 500.0,
                    u: 0.0,
                },
            ),
        ]
        .iter()
        .map(|(id, p)| (id.to_string(), enu_to_geodetic(*p, origin)))
        .collect();
        let registry = TrpRegistry::with_origin(entries, origin);
        // Both look due North (azimuth 0): parallel lines, no intersection.
        let obs = vec![
            AoaObservation {
                trp_id: "p0".to_string(),
                azimuth_deg: 0.0,
            },
            AoaObservation {
                trp_id: "p1".to_string(),
                azimuth_deg: 0.0,
            },
        ];
        let err = solve_aoa(&registry, &obs).unwrap_err();
        assert!(matches!(err, PositioningError::DegenerateGeometry(_)));
    }

    // -- Registry / covariance helpers --------------------------------------
    #[test]
    fn test_registry_centroid_origin() {
        let (registry, _g, _e) = scene();
        assert_eq!(registry.len(), 4);
        // Explicit origin used in the scene.
        assert!((registry.origin().lat_deg - ORIGIN_LAT).abs() < 1e-12);
        assert!(registry.lookup("trp-a").is_some());
        assert!(registry.lookup("nope").is_none());
    }

    #[test]
    fn test_registry_from_entries_centroid() {
        // from_entries anchors the origin at the TRP centroid.
        let origin = TrpCoord::new(ORIGIN_LAT, ORIGIN_LON, 0.0);
        let pts = [
            EnuPoint {
                e: -100.0,
                n: -100.0,
                u: 0.0,
            },
            EnuPoint {
                e: 100.0,
                n: -100.0,
                u: 0.0,
            },
            EnuPoint {
                e: 0.0,
                n: 200.0,
                u: 0.0,
            },
        ];
        let entries: Vec<(String, TrpCoord)> = pts
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("t{i}"), enu_to_geodetic(*p, origin)))
            .collect();
        let registry = TrpRegistry::from_entries(entries);
        // Centroid ENU ~ (0,0) => origin ~ the scene origin.
        assert!((registry.origin().lat_deg - ORIGIN_LAT).abs() < 1e-6);
        assert!((registry.origin().lon_deg - ORIGIN_LON).abs() < 1e-6);
    }

    #[test]
    fn test_covariance_to_ellipse_orientation_and_scale() {
        // Diagonal covariance with major axis along North (variance larger in N).
        let cov = [[4.0, 0.0], [0.0, 16.0]];
        let e = covariance_to_ellipse(cov, 0.95);
        // k = sqrt(-2 ln 0.05) ~ 2.4477.
        let k = (-2.0 * (1.0f64 - 0.95).ln()).sqrt();
        assert!((e.semi_major_m - k * 4.0).abs() < 1e-9); // sqrt(16)=4
        assert!((e.semi_minor_m - k * 2.0).abs() < 1e-9); // sqrt(4)=2
                                                          // Major axis along North => orientation 0 deg.
        assert!(e.orientation_deg.abs() < 1e-6 || (e.orientation_deg - 180.0).abs() < 1e-6);
    }

    #[test]
    fn test_solve_2x2_singular() {
        assert!(solve_2x2([[1.0, 2.0], [2.0, 4.0]], [1.0, 2.0]).is_none());
        let s = solve_2x2([[2.0, 0.0], [0.0, 4.0]], [6.0, 8.0]).unwrap();
        assert!((s[0] - 3.0).abs() < 1e-12 && (s[1] - 2.0).abs() < 1e-12);
    }

    #[test]
    fn test_method_spec_strings() {
        assert_eq!(PositioningMethodKind::MultiRtt.as_spec_str(), "MULTI-RTT");
        assert_eq!(PositioningMethodKind::Tdoa.as_spec_str(), "UL_TDOA");
        assert_eq!(
            PositioningMethodKind::AngleOfArrival.as_spec_str(),
            "UL_AOA"
        );
        assert_eq!(PositioningMethodKind::Ecid.as_spec_str(), "NR_ECID");
    }
}
