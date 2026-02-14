//! NTN Constellation-Level Network Planning (Item #213)
//!
//! Implements constellation planning for LEO/MEO/GEO satellite networks:
//! - Walker constellation design (Walker-Delta, Walker-Star)
//! - Coverage analysis (minimum elevation angle)
//! - Inter-satellite link topology
//! - Handover planning between orbital planes

use std::f64::consts::PI;

/// Earth radius in km
const EARTH_RADIUS_KM: f64 = 6371.0;

// ============================================================================
// Constellation Design
// ============================================================================

/// Walker constellation pattern type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkerPattern {
    /// Walker-Delta: evenly distributed orbital planes
    Delta,
    /// Walker-Star: polar orbit constellation
    Star,
}

/// Constellation design parameters
#[derive(Debug, Clone)]
pub struct ConstellationDesign {
    /// Constellation name
    pub name: String,
    /// Walker pattern
    pub pattern: WalkerPattern,
    /// Total number of satellites
    pub total_satellites: u32,
    /// Number of orbital planes
    pub num_planes: u32,
    /// Satellites per plane
    pub sats_per_plane: u32,
    /// Orbital altitude (km)
    pub altitude_km: f64,
    /// Orbital inclination (degrees)
    pub inclination_deg: f64,
    /// Phase offset between planes (Walker F parameter)
    pub phase_offset: u32,
    /// Minimum elevation angle for coverage (degrees)
    pub min_elevation_deg: f64,
}

impl ConstellationDesign {
    /// Creates a Starlink-like LEO constellation
    pub fn starlink_like() -> Self {
        Self {
            name: "LEO-550".to_string(),
            pattern: WalkerPattern::Delta,
            total_satellites: 1584,
            num_planes: 72,
            sats_per_plane: 22,
            altitude_km: 550.0,
            inclination_deg: 53.0,
            phase_offset: 1,
            min_elevation_deg: 25.0,
        }
    }

    /// Creates an O3b-like MEO constellation
    pub fn o3b_like() -> Self {
        Self {
            name: "MEO-8000".to_string(),
            pattern: WalkerPattern::Delta,
            total_satellites: 20,
            num_planes: 1,
            sats_per_plane: 20,
            altitude_km: 8062.0,
            inclination_deg: 0.0,
            phase_offset: 0,
            min_elevation_deg: 10.0,
        }
    }

    /// Creates a custom Walker constellation
    pub fn walker(
        name: impl Into<String>,
        pattern: WalkerPattern,
        total: u32,
        planes: u32,
        altitude_km: f64,
        inclination_deg: f64,
    ) -> Self {
        Self {
            name: name.into(),
            pattern,
            total_satellites: total,
            num_planes: planes,
            sats_per_plane: total / planes,
            altitude_km,
            inclination_deg,
            phase_offset: 1,
            min_elevation_deg: 25.0,
        }
    }

    /// Orbital period in seconds
    pub fn orbital_period_s(&self) -> f64 {
        let r = EARTH_RADIUS_KM + self.altitude_km;
        2.0 * PI * (r.powi(3) / 398600.4418).sqrt()
    }

    /// RAAN spacing between planes (degrees)
    pub fn raan_spacing_deg(&self) -> f64 {
        match self.pattern {
            WalkerPattern::Delta => 360.0 / self.num_planes as f64,
            WalkerPattern::Star => 180.0 / self.num_planes as f64,
        }
    }

    /// In-plane spacing between satellites (degrees)
    pub fn in_plane_spacing_deg(&self) -> f64 {
        360.0 / self.sats_per_plane as f64
    }
}

// ============================================================================
// Coverage Analysis
// ============================================================================

/// Coverage footprint of a single satellite
#[derive(Debug, Clone)]
pub struct SatelliteFootprint {
    /// Sub-satellite point latitude (degrees)
    pub center_lat_deg: f64,
    /// Sub-satellite point longitude (degrees)
    pub center_lon_deg: f64,
    /// Coverage radius on ground (km)
    pub coverage_radius_km: f64,
    /// Nadir angle at edge of coverage (degrees)
    pub nadir_angle_deg: f64,
}

/// Computes the coverage radius for a satellite at given altitude
/// with minimum elevation angle constraint.
///
/// Uses the geometric relation from the Earth-Satellite-Ground triangle:
/// lambda = PI/2 - epsilon - arcsin(R_e * cos(epsilon) / (R_e + h))
pub fn coverage_radius_km(altitude_km: f64, min_elevation_deg: f64) -> f64 {
    let h = altitude_km;
    let r_e = EARTH_RADIUS_KM;
    let elev_rad = min_elevation_deg.to_radians();

    // Nadir angle at satellite
    let sin_nadir = r_e * elev_rad.cos() / (r_e + h);
    if sin_nadir.abs() > 1.0 { return 0.0; }
    let nadir_angle = sin_nadir.asin();

    // Earth central angle of coverage
    let lambda = PI / 2.0 - elev_rad - nadir_angle;
    if lambda <= 0.0 { return 0.0; }

    // Ground distance = R_e * lambda
    r_e * lambda
}

/// Computes the number of satellites needed for continuous global coverage
pub fn min_satellites_for_coverage(altitude_km: f64, min_elevation_deg: f64) -> u32 {
    let radius = coverage_radius_km(altitude_km, min_elevation_deg);
    if radius <= 0.0 { return u32::MAX; }

    // Earth surface area / single satellite coverage area
    let earth_area = 4.0 * PI * EARTH_RADIUS_KM.powi(2);
    let sat_area = PI * radius.powi(2);

    // With overlap factor (~2.5 for reliable coverage)
    let overlap_factor = 2.5;
    ((earth_area / sat_area) * overlap_factor).ceil() as u32
}

/// Checks if a latitude is covered by a constellation
pub fn is_latitude_covered(constellation: &ConstellationDesign, latitude_deg: f64) -> bool {
    let lat = latitude_deg.abs();
    let max_lat = constellation.inclination_deg
        + coverage_radius_km(constellation.altitude_km, constellation.min_elevation_deg)
            / EARTH_RADIUS_KM * (180.0 / PI);
    lat <= max_lat
}

// ============================================================================
// Inter-Satellite Links (ISL)
// ============================================================================

/// ISL type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IslType {
    /// Intra-plane ISL (same orbital plane, adjacent satellites)
    IntraPlane,
    /// Inter-plane ISL (adjacent planes, similar latitude)
    InterPlane,
}

/// Inter-satellite link
#[derive(Debug, Clone)]
pub struct InterSatelliteLink {
    /// ISL type
    pub isl_type: IslType,
    /// Source satellite (plane, index)
    pub source: (u32, u32),
    /// Target satellite (plane, index)
    pub target: (u32, u32),
    /// Link distance (km)
    pub distance_km: f64,
    /// Propagation delay (ms)
    pub delay_ms: f64,
    /// Data rate (Gbps)
    pub data_rate_gbps: f64,
}

/// Generates ISL topology for a constellation
pub fn generate_isl_topology(constellation: &ConstellationDesign) -> Vec<InterSatelliteLink> {
    let mut links = Vec::new();
    let speed_of_light_km_s = 299792.458;

    for plane in 0..constellation.num_planes {
        for sat in 0..constellation.sats_per_plane {
            // Intra-plane: connect to next satellite in same plane
            let next_sat = (sat + 1) % constellation.sats_per_plane;
            let r = EARTH_RADIUS_KM + constellation.altitude_km;
            let angle = constellation.in_plane_spacing_deg().to_radians();
            let dist = 2.0 * r * (angle / 2.0).sin();

            links.push(InterSatelliteLink {
                isl_type: IslType::IntraPlane,
                source: (plane, sat),
                target: (plane, next_sat),
                distance_km: dist,
                delay_ms: dist / speed_of_light_km_s * 1000.0,
                data_rate_gbps: 10.0,
            });

            // Inter-plane: connect to same-index satellite in adjacent plane
            if constellation.num_planes > 1 {
                let next_plane = (plane + 1) % constellation.num_planes;
                let raan_angle = constellation.raan_spacing_deg().to_radians();
                let inter_dist = 2.0 * r * (raan_angle / 2.0).sin();

                links.push(InterSatelliteLink {
                    isl_type: IslType::InterPlane,
                    source: (plane, sat),
                    target: (next_plane, sat),
                    distance_km: inter_dist,
                    delay_ms: inter_dist / speed_of_light_km_s * 1000.0,
                    data_rate_gbps: 5.0,
                });
            }
        }
    }

    links
}

// ============================================================================
// Handover Planning
// ============================================================================

/// Satellite visibility window
#[derive(Debug, Clone)]
pub struct VisibilityWindow {
    /// Satellite (plane, index)
    pub satellite: (u32, u32),
    /// Start time (seconds from epoch)
    pub start_s: f64,
    /// End time (seconds from epoch)
    pub end_s: f64,
    /// Maximum elevation during pass (degrees)
    pub max_elevation_deg: f64,
}

/// Estimates the average visibility duration for a LEO satellite pass
pub fn avg_visibility_duration_s(altitude_km: f64, min_elevation_deg: f64) -> f64 {
    let radius = coverage_radius_km(altitude_km, min_elevation_deg);
    if radius <= 0.0 { return 0.0; }

    let r = EARTH_RADIUS_KM + altitude_km;
    let orbital_velocity = (398600.4418 / r).sqrt(); // km/s
    let ground_track_velocity = orbital_velocity * EARTH_RADIUS_KM / r;

    // Time = 2 * coverage_radius / ground_track_velocity
    2.0 * radius / ground_track_velocity
}

/// Estimates handover frequency (handovers per hour)
pub fn handover_frequency_per_hour(altitude_km: f64, min_elevation_deg: f64) -> f64 {
    let duration = avg_visibility_duration_s(altitude_km, min_elevation_deg);
    if duration <= 0.0 { return 0.0; }
    3600.0 / duration
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starlink_constellation() {
        let c = ConstellationDesign::starlink_like();
        assert_eq!(c.total_satellites, 1584);
        assert_eq!(c.num_planes, 72);
        assert_eq!(c.sats_per_plane, 22);

        let period = c.orbital_period_s();
        assert!(period > 5000.0 && period < 7000.0, "Period = {period}s");
    }

    #[test]
    fn test_raan_spacing() {
        let c = ConstellationDesign::starlink_like();
        let spacing = c.raan_spacing_deg();
        assert!((spacing - 5.0).abs() < 0.1); // 360/72 = 5°
    }

    #[test]
    fn test_coverage_radius_leo() {
        let radius = coverage_radius_km(550.0, 25.0);
        assert!(radius > 200.0 && radius < 1500.0, "Radius = {radius}km");
    }

    #[test]
    fn test_coverage_radius_geo() {
        let radius = coverage_radius_km(35786.0, 10.0);
        assert!(radius > 5000.0, "GEO coverage radius = {radius}km");
    }

    #[test]
    fn test_min_satellites() {
        let min_sats = min_satellites_for_coverage(550.0, 25.0);
        assert!(min_sats > 100 && min_sats < 5000, "Min sats = {min_sats}");
    }

    #[test]
    fn test_latitude_coverage() {
        let c = ConstellationDesign::starlink_like();
        assert!(is_latitude_covered(&c, 0.0));   // Equator
        assert!(is_latitude_covered(&c, 45.0));  // Mid-latitude
        // With 53° inclination, coverage extends beyond 53° with footprint
        assert!(is_latitude_covered(&c, 53.0));
    }

    #[test]
    fn test_isl_topology() {
        let c = ConstellationDesign::walker(
            "test", WalkerPattern::Delta, 20, 4, 550.0, 53.0,
        );
        let links = generate_isl_topology(&c);

        // Each satellite has 1 intra-plane + 1 inter-plane link
        // 20 sats * 2 types = 40 links
        assert_eq!(links.len(), 40);

        // Check link distances are reasonable
        for link in &links {
            assert!(link.distance_km > 0.0);
            assert!(link.delay_ms > 0.0);
        }
    }

    #[test]
    fn test_isl_intra_plane_distance() {
        // Use a denser constellation (22 sats/plane like Starlink) for reasonable ISL distance
        let c = ConstellationDesign::walker(
            "test", WalkerPattern::Delta, 88, 4, 550.0, 53.0,
        );
        let links = generate_isl_topology(&c);
        let intra: Vec<_> = links.iter().filter(|l| l.isl_type == IslType::IntraPlane).collect();

        // With 22 sats/plane: 360/22 ≈ 16.4° spacing, distance ≈ 1980 km
        for link in &intra {
            assert!(link.distance_km < 5000.0, "Intra-plane distance = {}km", link.distance_km);
        }
    }

    #[test]
    fn test_visibility_duration_leo() {
        let duration = avg_visibility_duration_s(550.0, 25.0);
        // LEO visibility: typically 3-10 minutes
        assert!(duration > 100.0 && duration < 800.0, "Duration = {duration}s");
    }

    #[test]
    fn test_handover_frequency() {
        let freq = handover_frequency_per_hour(550.0, 25.0);
        // LEO: several handovers per hour
        assert!(freq > 2.0 && freq < 30.0, "HO freq = {freq}/hr");
    }

    #[test]
    fn test_o3b_constellation() {
        let c = ConstellationDesign::o3b_like();
        assert_eq!(c.total_satellites, 20);

        // MEO at 8062 km: period ≈ 17256s (4.79 hours)
        let period = c.orbital_period_s();
        assert!(period > 15000.0 && period < 20000.0, "MEO period = {period}s");
    }

    #[test]
    fn test_walker_custom() {
        let c = ConstellationDesign::walker("custom", WalkerPattern::Star, 24, 6, 1200.0, 87.0);
        assert_eq!(c.sats_per_plane, 4);

        // Star pattern: RAAN spacing = 180/planes
        let spacing = c.raan_spacing_deg();
        assert!((spacing - 30.0).abs() < 0.1);
    }
}
