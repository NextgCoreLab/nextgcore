//! Integrated Sensing and Communication (ISAC) Types (6G - Item #216)
//!
//! Provides sensing-related types for 6G ISAC functionality per:
//! - 3GPP TR 22.837: Feasibility Study on Integrated Sensing and Communication
//! - TS 23.700-86: Study on Integrated Sensing & Communication (SA WG2)
//!
//! ISAC allows the 5G/6G network to use communication waveforms for radar-like
//! sensing operations (positioning, mapping, gesture recognition, etc.)

use serde::{Deserialize, Serialize};

// ============================================================================
// Sensing Types
// ============================================================================

/// Type of ISAC sensing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensingType {
    /// Radar-like target detection (presence, range, velocity).
    TargetDetection,
    /// Object tracking over time.
    ObjectTracking,
    /// Environment mapping / imaging.
    EnvironmentMapping,
    /// Gesture recognition via RF sensing.
    GestureRecognition,
    /// Weather monitoring (rain, humidity).
    WeatherSensing,
    /// Intrusion detection for security.
    IntrusionDetection,
    /// Passive localization of non-communicating objects.
    PassiveLocalization,
}

/// Sensing mode: how the network and UE interact for sensing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensingMode {
    /// gNB transmits and receives (monostatic radar).
    GnbMonostatic,
    /// gNB transmits, UE receives (bistatic).
    GnbTxUeRx,
    /// UE transmits, gNB receives (bistatic).
    UeTxGnbRx,
    /// gNB transmits, another gNB receives (multistatic).
    GnbTxGnbRx,
    /// UE-based sensing (UE both Tx and Rx).
    UeMonostatic,
}

/// Sensing quality of service requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensingQos {
    /// Maximum detection range (meters).
    pub max_range_m: f64,
    /// Range resolution (meters).
    pub range_resolution_m: f64,
    /// Velocity resolution (m/s).
    pub velocity_resolution_mps: f64,
    /// Angular resolution (degrees).
    pub angular_resolution_deg: f64,
    /// Update rate (Hz).
    pub update_rate_hz: f64,
    /// Detection probability (0.0-1.0).
    pub detection_probability: f64,
    /// False alarm rate (0.0-1.0).
    pub false_alarm_rate: f64,
}

impl Default for SensingQos {
    fn default() -> Self {
        Self {
            max_range_m: 200.0,
            range_resolution_m: 0.5,
            velocity_resolution_mps: 0.5,
            angular_resolution_deg: 5.0,
            update_rate_hz: 10.0,
            detection_probability: 0.9,
            false_alarm_rate: 1e-6,
        }
    }
}

/// Result of a sensing measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensingResult {
    /// Sensing type performed.
    pub sensing_type: SensingType,
    /// Sensing mode used.
    pub mode: SensingMode,
    /// Measurement timestamp (epoch microseconds).
    pub timestamp_us: u64,
    /// Detected targets.
    pub targets: Vec<DetectedTarget>,
    /// Signal-to-noise ratio of the measurement (dB).
    pub snr_db: f64,
}

/// A detected target from a sensing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTarget {
    /// Target identifier (assigned by sensing engine).
    pub target_id: u32,
    /// Range from sensor (meters).
    pub range_m: f64,
    /// Radial velocity (m/s, positive = approaching).
    pub velocity_mps: f64,
    /// Azimuth angle (degrees from boresight).
    pub azimuth_deg: f64,
    /// Elevation angle (degrees from horizontal).
    pub elevation_deg: f64,
    /// Radar cross section estimate (dBsm).
    pub rcs_dbsm: f64,
    /// Detection confidence (0.0-1.0).
    pub confidence: f64,
}

/// ISAC resource allocation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsacResourceConfig {
    /// Fraction of time-frequency resources allocated to sensing (0.0-1.0).
    pub sensing_resource_ratio: f64,
    /// Sensing signal bandwidth (MHz).
    pub sensing_bandwidth_mhz: f64,
    /// Number of OFDM symbols per sensing burst.
    pub symbols_per_burst: u32,
    /// Sensing periodicity (ms).
    pub periodicity_ms: u32,
    /// Maximum transmit power for sensing (dBm).
    pub max_tx_power_dbm: f64,
}

impl Default for IsacResourceConfig {
    fn default() -> Self {
        Self {
            sensing_resource_ratio: 0.1,  // 10% for sensing
            sensing_bandwidth_mhz: 100.0,
            symbols_per_burst: 14,
            periodicity_ms: 100,
            max_tx_power_dbm: 23.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensing_qos_default() {
        let qos = SensingQos::default();
        assert_eq!(qos.max_range_m, 200.0);
        assert!(qos.detection_probability > 0.0);
    }

    #[test]
    fn test_sensing_result() {
        let result = SensingResult {
            sensing_type: SensingType::TargetDetection,
            mode: SensingMode::GnbMonostatic,
            timestamp_us: 1_000_000,
            targets: vec![DetectedTarget {
                target_id: 1,
                range_m: 50.0,
                velocity_mps: -10.0,
                azimuth_deg: 30.0,
                elevation_deg: 5.0,
                rcs_dbsm: -5.0,
                confidence: 0.95,
            }],
            snr_db: 20.0,
        };
        assert_eq!(result.targets.len(), 1);
        assert_eq!(result.targets[0].range_m, 50.0);
    }

    #[test]
    fn test_isac_resource_config() {
        let config = IsacResourceConfig::default();
        assert!((config.sensing_resource_ratio - 0.1).abs() < f64::EPSILON);
        assert_eq!(config.symbols_per_burst, 14);
    }

    #[test]
    fn test_sensing_type_variants() {
        let types = [
            SensingType::TargetDetection,
            SensingType::ObjectTracking,
            SensingType::EnvironmentMapping,
            SensingType::GestureRecognition,
            SensingType::WeatherSensing,
            SensingType::IntrusionDetection,
            SensingType::PassiveLocalization,
        ];
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_sensing_mode_variants() {
        let modes = [
            SensingMode::GnbMonostatic,
            SensingMode::GnbTxUeRx,
            SensingMode::UeTxGnbRx,
            SensingMode::GnbTxGnbRx,
            SensingMode::UeMonostatic,
        ];
        assert_eq!(modes.len(), 5);
    }
}
