//! Sub-THz / Spectrum & Higher-Frequency Types (6G - Item #217)
//!
//! Provides types for sub-terahertz and higher-frequency bands used in 6G.
//! Sub-THz frequencies (100 GHz - 300 GHz) offer extreme bandwidth for
//! short-range ultra-high-throughput communications.
//!
//! References:
//! - 3GPP TR 38.901: Channel model above 6 GHz
//! - ITU-R WRC-23: 6G spectrum allocation decisions

use serde::{Deserialize, Serialize};

// ============================================================================
// Sub-THz Spectrum Types
// ============================================================================

/// Spectrum band classification for 6G.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpectrumBand {
    /// FR1: Sub-6 GHz (existing 5G NR).
    Fr1,
    /// FR2: mmWave 24.25-52.6 GHz (existing 5G NR).
    Fr2,
    /// FR3: Upper mid-band 7-24 GHz (6G candidate).
    Fr3,
    /// FR4: Sub-THz 92-300 GHz (6G research).
    Fr4SubThz,
    /// Visible Light Communication (VLC) band.
    Vlc,
}

impl SpectrumBand {
    /// Typical maximum bandwidth available (MHz).
    pub fn max_bandwidth_mhz(&self) -> f64 {
        match self {
            Self::Fr1 => 100.0,
            Self::Fr2 => 400.0,
            Self::Fr3 => 800.0,
            Self::Fr4SubThz => 10_000.0, // 10 GHz contiguous
            Self::Vlc => 100_000.0,
        }
    }

    /// Whether this band requires line-of-sight.
    pub fn requires_los(&self) -> bool {
        matches!(self, Self::Fr4SubThz | Self::Vlc)
    }
}

/// Sub-THz channel characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubThzChannel {
    /// Center frequency (GHz).
    pub center_freq_ghz: f64,
    /// Channel bandwidth (GHz).
    pub bandwidth_ghz: f64,
    /// Free-space path loss at reference distance (dB).
    pub fspl_ref_db: f64,
    /// Atmospheric absorption coefficient (dB/km) at this frequency.
    pub atmospheric_absorption_db_per_km: f64,
    /// Molecular absorption peaks present.
    pub has_absorption_peak: bool,
    /// Maximum practical link distance (meters).
    pub max_link_distance_m: f64,
}

impl SubThzChannel {
    /// Create a channel at a common sub-THz frequency window.
    pub fn d_band() -> Self {
        // D-band: 110-170 GHz (atmospheric window)
        Self {
            center_freq_ghz: 140.0,
            bandwidth_ghz: 10.0,
            fspl_ref_db: 82.4, // FSPL at 1m for 140 GHz
            atmospheric_absorption_db_per_km: 3.0,
            has_absorption_peak: false,
            max_link_distance_m: 200.0,
        }
    }

    /// H-band: 220-330 GHz
    pub fn h_band() -> Self {
        Self {
            center_freq_ghz: 275.0,
            bandwidth_ghz: 20.0,
            fspl_ref_db: 88.3, // FSPL at 1m for 275 GHz
            atmospheric_absorption_db_per_km: 10.0,
            has_absorption_peak: true,
            max_link_distance_m: 50.0,
        }
    }

    /// Calculate path loss at a given distance (meters).
    /// Uses free-space path loss + atmospheric absorption.
    pub fn path_loss_db(&self, distance_m: f64) -> f64 {
        if distance_m <= 0.0 {
            return 0.0;
        }
        // FSPL = 20*log10(d) + FSPL_ref (ref is at 1m)
        let fspl = self.fspl_ref_db + 20.0 * distance_m.log10();
        let atm = self.atmospheric_absorption_db_per_km * distance_m / 1000.0;
        fspl + atm
    }

    /// Theoretical maximum throughput (Gbps) assuming ideal Shannon capacity.
    pub fn max_throughput_gbps(&self, snr_db: f64) -> f64 {
        let snr_linear = 10.0_f64.powf(snr_db / 10.0);
        self.bandwidth_ghz * (1.0 + snr_linear).log2() // GHz * bits/Hz = Gbps
    }
}

/// Sub-THz beamforming parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubThzBeamConfig {
    /// Number of antenna elements in the array.
    pub num_elements: u32,
    /// Array gain (dBi).
    pub array_gain_dbi: f64,
    /// Half-power beamwidth (degrees).
    pub hpbw_deg: f64,
    /// Beam switching time (microseconds).
    pub beam_switch_us: f64,
    /// Maximum number of simultaneous beams.
    pub max_beams: u32,
}

impl Default for SubThzBeamConfig {
    fn default() -> Self {
        Self {
            num_elements: 1024,   // Large array for sub-THz
            array_gain_dbi: 40.0, // High gain needed to overcome path loss
            hpbw_deg: 2.0,        // Very narrow beam
            beam_switch_us: 10.0,
            max_beams: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spectrum_band_bandwidth() {
        assert_eq!(SpectrumBand::Fr1.max_bandwidth_mhz(), 100.0);
        assert_eq!(SpectrumBand::Fr4SubThz.max_bandwidth_mhz(), 10_000.0);
    }

    #[test]
    fn test_spectrum_band_los() {
        assert!(!SpectrumBand::Fr1.requires_los());
        assert!(SpectrumBand::Fr4SubThz.requires_los());
        assert!(SpectrumBand::Vlc.requires_los());
    }

    #[test]
    fn test_d_band_channel() {
        let ch = SubThzChannel::d_band();
        assert_eq!(ch.center_freq_ghz, 140.0);
        assert!(!ch.has_absorption_peak);

        // Path loss at 10m should be reasonable
        let pl = ch.path_loss_db(10.0);
        assert!(pl > 90.0 && pl < 120.0);
    }

    #[test]
    fn test_h_band_channel() {
        let ch = SubThzChannel::h_band();
        assert_eq!(ch.center_freq_ghz, 275.0);
        assert!(ch.has_absorption_peak);
    }

    #[test]
    fn test_path_loss_increases_with_distance() {
        let ch = SubThzChannel::d_band();
        let pl_10m = ch.path_loss_db(10.0);
        let pl_100m = ch.path_loss_db(100.0);
        assert!(pl_100m > pl_10m);
    }

    #[test]
    fn test_max_throughput() {
        let ch = SubThzChannel::d_band();
        // At 20 dB SNR with 10 GHz bandwidth, throughput should be very high
        let tp = ch.max_throughput_gbps(20.0);
        assert!(tp > 50.0); // Should be > 50 Gbps
    }

    #[test]
    fn test_beam_config_default() {
        let cfg = SubThzBeamConfig::default();
        assert_eq!(cfg.num_elements, 1024);
        assert!(cfg.hpbw_deg < 5.0); // Very narrow beam
    }
}
