//! Network Slicing for SMF (Rel-17, TS 23.501 §5.15)
//!
//! Implements per-slice PDU session policies:
//! URLLC, V2X, eMBB, and mIoT profile selection for PDR/FAR configuration.

use std::collections::HashMap;

/// URLLC slice profile constants (TS 22.261 Table 7.1-1)
pub const URLLC_MAX_LATENCY_MS: u32 = 1;
pub const URLLC_RELIABILITY: f64 = 0.999_999; // 10^-6 PER
pub const URLLC_DEFAULT_5QI: u8 = 82;          // 5QI 82: URLLC, delay-critical GBR

/// V2X slice profile constants (TS 22.185)
pub const V2X_MAX_LATENCY_MS: u32 = 3;
pub const V2X_RELIABILITY: f64 = 0.9999;
pub const V2X_DEFAULT_5QI: u8 = 85;            // 5QI 85: V2X messages

/// eMBB slice profile constants
pub const EMBB_MAX_LATENCY_MS: u32 = 20;
pub const EMBB_RELIABILITY: f64 = 0.99;
pub const EMBB_DEFAULT_5QI: u8 = 9;            // 5QI 9: default non-GBR

/// mIoT (massive IoT) slice profile constants
pub const MIOT_MAX_LATENCY_MS: u32 = 6000;
pub const MIOT_RELIABILITY: f64 = 0.99;
pub const MIOT_DEFAULT_5QI: u8 = 8;

/// Network slice type derived from S-NSSAI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SliceType {
    /// Enhanced Mobile Broadband (SST=1)
    EMbb,
    /// Ultra-Reliable Low-Latency (SST=2)
    Urllc,
    /// Massive IoT (SST=3)
    MassiveIot,
    /// Vehicle-to-Everything (SST=4, or vendor-specific)
    V2x,
    /// Custom/vendor slice
    Custom(u8),
}

impl SliceType {
    /// Infer slice type from S-NSSAI SST value (TS 23.501 §5.15.2)
    pub fn from_sst(sst: u8) -> Self {
        match sst {
            1 => Self::EMbb,
            2 => Self::Urllc,
            3 => Self::MassiveIot,
            4 => Self::V2x,
            other => Self::Custom(other),
        }
    }

    pub fn sst(&self) -> u8 {
        match self {
            Self::EMbb => 1,
            Self::Urllc => 2,
            Self::MassiveIot => 3,
            Self::V2x => 4,
            Self::Custom(v) => *v,
        }
    }
}

/// Per-slice PDU session QoS profile
#[derive(Debug, Clone)]
pub struct SliceProfile {
    pub slice_type: SliceType,
    /// Maximum latency in milliseconds
    pub max_latency_ms: u32,
    /// Required reliability (packet delivery ratio)
    pub reliability: f64,
    /// Default 5QI to assign to default bearer
    pub default_5qi: u8,
    /// Maximum bitrate uplink (kbps), 0 = unlimited
    pub max_ul_mbr_kbps: u64,
    /// Maximum bitrate downlink (kbps), 0 = unlimited
    pub max_dl_mbr_kbps: u64,
    /// Whether DSCP marking is required for this slice
    pub dscp_marking_required: bool,
    /// DSCP value to use (per TS 23.501 Table 5.7.4-1)
    pub dscp_value: u8,
}

impl SliceProfile {
    /// URLLC profile (delay-critical GBR)
    pub fn urllc() -> Self {
        Self {
            slice_type: SliceType::Urllc,
            max_latency_ms: URLLC_MAX_LATENCY_MS,
            reliability: URLLC_RELIABILITY,
            default_5qi: URLLC_DEFAULT_5QI,
            max_ul_mbr_kbps: 10_000,  // 10 Mbps default GBR for URLLC
            max_dl_mbr_kbps: 10_000,
            dscp_marking_required: true,
            dscp_value: 46, // EF (Expedited Forwarding) per RFC 3246
        }
    }

    /// V2X profile
    pub fn v2x() -> Self {
        Self {
            slice_type: SliceType::V2x,
            max_latency_ms: V2X_MAX_LATENCY_MS,
            reliability: V2X_RELIABILITY,
            default_5qi: V2X_DEFAULT_5QI,
            max_ul_mbr_kbps: 50_000,
            max_dl_mbr_kbps: 100_000,
            dscp_marking_required: true,
            dscp_value: 34, // AF41 per RFC 2597
        }
    }

    /// eMBB profile (default)
    pub fn embb() -> Self {
        Self {
            slice_type: SliceType::EMbb,
            max_latency_ms: EMBB_MAX_LATENCY_MS,
            reliability: EMBB_RELIABILITY,
            default_5qi: EMBB_DEFAULT_5QI,
            max_ul_mbr_kbps: 0,   // unlimited
            max_dl_mbr_kbps: 0,
            dscp_marking_required: false,
            dscp_value: 0,
        }
    }

    /// mIoT profile
    pub fn miot() -> Self {
        Self {
            slice_type: SliceType::MassiveIot,
            max_latency_ms: MIOT_MAX_LATENCY_MS,
            reliability: MIOT_RELIABILITY,
            default_5qi: MIOT_DEFAULT_5QI,
            max_ul_mbr_kbps: 200,  // 200 kbps uplink typical mIoT
            max_dl_mbr_kbps: 200,
            dscp_marking_required: false,
            dscp_value: 0,
        }
    }

    /// Returns the profile for a given slice type
    pub fn for_slice_type(st: SliceType) -> Self {
        match st {
            SliceType::Urllc => Self::urllc(),
            SliceType::V2x => Self::v2x(),
            SliceType::MassiveIot => Self::miot(),
            _ => Self::embb(),
        }
    }
}

/// SMF slice policy registry: maps SST to a SliceProfile
#[derive(Debug, Default)]
pub struct SlicePolicyRegistry {
    profiles: HashMap<u8, SliceProfile>,
}

impl SlicePolicyRegistry {
    pub fn new() -> Self {
        let mut reg = Self::default();
        // Pre-populate standard profiles
        for sst in [1u8, 2, 3, 4] {
            let st = SliceType::from_sst(sst);
            reg.profiles.insert(sst, SliceProfile::for_slice_type(st));
        }
        reg
    }

    /// Look up the profile for a given SST, returns eMBB default if unknown
    pub fn get(&self, sst: u8) -> &SliceProfile {
        // Safe: eMBB (sst=1) is always registered
        self.profiles.get(&sst).unwrap_or_else(|| self.profiles.get(&1).unwrap_or_default())
    }

    /// Register or override a profile for an SST
    pub fn register(&mut self, sst: u8, profile: SliceProfile) {
        self.profiles.insert(sst, profile);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_type_from_sst() {
        assert_eq!(SliceType::from_sst(1), SliceType::EMbb);
        assert_eq!(SliceType::from_sst(2), SliceType::Urllc);
        assert_eq!(SliceType::from_sst(3), SliceType::MassiveIot);
        assert_eq!(SliceType::from_sst(4), SliceType::V2x);
        assert_eq!(SliceType::from_sst(99), SliceType::Custom(99));
    }

    #[test]
    fn test_urllc_profile_has_ef_dscp() {
        let p = SliceProfile::urllc();
        assert_eq!(p.dscp_value, 46);
        assert!(p.dscp_marking_required);
        assert_eq!(p.default_5qi, 82);
    }

    #[test]
    fn test_v2x_profile() {
        let p = SliceProfile::v2x();
        assert_eq!(p.default_5qi, 85);
        assert_eq!(p.max_latency_ms, 3);
    }

    #[test]
    fn test_embb_no_dscp_marking() {
        let p = SliceProfile::embb();
        assert!(!p.dscp_marking_required);
        assert_eq!(p.max_ul_mbr_kbps, 0);
    }

    #[test]
    fn test_registry_default_profiles() {
        let reg = SlicePolicyRegistry::new();
        let urllc = reg.get(2);
        assert_eq!(urllc.default_5qi, 82);
        let unknown = reg.get(99);
        assert_eq!(unknown.slice_type, SliceType::EMbb); // falls back to eMBB
    }

    #[test]
    fn test_registry_custom_profile() {
        let mut reg = SlicePolicyRegistry::new();
        let custom = SliceProfile {
            slice_type: SliceType::Custom(10),
            max_latency_ms: 5,
            reliability: 0.9,
            default_5qi: 7,
            max_ul_mbr_kbps: 1000,
            max_dl_mbr_kbps: 2000,
            dscp_marking_required: false,
            dscp_value: 0,
        };
        reg.register(10, custom);
        assert_eq!(reg.get(10).default_5qi, 7);
    }
}
