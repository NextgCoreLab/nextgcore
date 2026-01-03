//! Configuration Management
//!
//! This module provides configuration structures and parsing functionality,
//! ported from lib/app/ogs-config.c and lib/app/ogs-config.h.

use crate::yaml::{OgsYamlIter, YamlNodeType};
use ogs_core::OgsSockopt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration validation error: {0}")]
    ValidationError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Not initialized")]
    NotInitialized,
    #[error("Already initialized")]
    AlreadyInitialized,
}

/// Maximum number of PLMNs
pub const OGS_MAX_NUM_OF_PLMN: usize = 6;
/// Maximum number of slices
pub const OGS_MAX_NUM_OF_SLICE: usize = 8;
/// Maximum number of sessions per slice
pub const OGS_MAX_NUM_OF_SESS: usize = 4;
/// Maximum number of bearers per session
pub const OGS_MAX_NUM_OF_BEARER: usize = 4;
/// Maximum number of SUPI ranges
pub const OGS_MAX_NUM_OF_SUPI_RANGE: usize = 16;
/// Maximum number of GTP-U buffers per UE
pub const OGS_MAX_NUM_OF_GTPU_BUFFER: u64 = 8;

/// Default maximum number of UEs
pub const MAX_NUM_OF_UE: u64 = 1024;
/// Default maximum number of peers
pub const MAX_NUM_OF_PEER: u64 = 64;

/// Parameter configuration flags
/// Mirrors the parameter struct in ogs_app_global_conf_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterConf {
    // Element flags (NF disable flags)
    pub no_mme: bool,
    pub no_hss: bool,
    pub no_sgw: bool,
    pub no_sgwc: bool,
    pub no_sgwu: bool,
    pub no_pgw: bool,
    pub no_pcrf: bool,
    pub no_amf: bool,
    pub no_smf: bool,
    pub no_upf: bool,
    pub no_ausf: bool,
    pub no_udm: bool,
    pub no_pcf: bool,
    pub no_nssf: bool,
    pub no_bsf: bool,
    pub no_udr: bool,
    pub no_sepp: bool,
    pub no_scp: bool,
    pub no_nrf: bool,

    // NF counts
    pub amf_count: i32,
    pub smf_count: i32,
    pub upf_count: i32,
    pub ausf_count: i32,
    pub udm_count: i32,
    pub pcf_count: i32,
    pub nssf_count: i32,
    pub bsf_count: i32,
    pub udr_count: i32,

    // Network flags
    pub no_ipv4: bool,
    pub no_ipv6: bool,
    pub prefer_ipv4: bool,
    pub multicast: bool,

    // Feature flags
    pub use_openair: bool,
    pub fake_csfb: bool,
    pub use_upg_vpp: bool,
    pub no_ipv4v6_local_addr_in_packet_filter: bool,
    pub no_pfcp_rr_select: bool,
    pub no_time_zone_information: bool,
}

/// Maximum values configuration
/// Mirrors the max struct in ogs_app_global_conf_t
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaxConf {
    pub ue: u64,
    pub peer: u64,
    pub gtp_peer: u64,
}

impl Default for MaxConf {
    fn default() -> Self {
        MaxConf {
            ue: MAX_NUM_OF_UE,
            peer: MAX_NUM_OF_PEER,
            gtp_peer: 0,
        }
    }
}

/// Socket options configuration
/// Mirrors the sockopt struct in ogs_app_global_conf_t
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SockoptConf {
    pub no_delay: bool,
    pub l_onoff: bool,
    pub l_linger: i32,
}

impl Default for SockoptConf {
    fn default() -> Self {
        SockoptConf {
            no_delay: true,
            l_onoff: false,
            l_linger: 0,
        }
    }
}

/// Packet buffer pool configuration
/// Mirrors ogs_pkbuf_config_t
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkbufConfig {
    pub cluster_128_pool: u32,
    pub cluster_256_pool: u32,
    pub cluster_512_pool: u32,
    pub cluster_1024_pool: u32,
    pub cluster_2048_pool: u32,
    pub cluster_8192_pool: u32,
    pub cluster_32768_pool: u32,
    pub cluster_big_pool: u32,
}

impl Default for PkbufConfig {
    fn default() -> Self {
        // Default values from ogs_pkbuf_default_init
        PkbufConfig {
            cluster_128_pool: 65536,
            cluster_256_pool: 16384,
            cluster_512_pool: 4096,
            cluster_1024_pool: 2048,
            cluster_2048_pool: 1024,
            cluster_8192_pool: 256,
            cluster_32768_pool: 64,
            cluster_big_pool: 8,
        }
    }
}


/// Global configuration
/// Mirrors ogs_app_global_conf_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsGlobalConf {
    pub parameter: ParameterConf,
    pub max: MaxConf,
    pub sockopt: SockoptConf,
    pub pkbuf_config: PkbufConfig,
}

impl OgsGlobalConf {
    /// Create a new global configuration with default values
    pub fn new() -> Self {
        let mut conf = OgsGlobalConf::default();
        conf.sockopt.no_delay = true;
        conf.max.ue = MAX_NUM_OF_UE;
        conf.max.peer = MAX_NUM_OF_PEER;
        conf
    }

    /// Prepare global configuration with defaults
    /// Mirrors ogs_app_global_conf_prepare()
    pub fn prepare(&mut self) {
        self.sockopt.no_delay = true;
        self.max.ue = MAX_NUM_OF_UE;
        self.max.peer = MAX_NUM_OF_PEER;
        self.pkbuf_config = PkbufConfig::default();
    }

    /// Validate the configuration
    /// Mirrors global_conf_validation()
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.parameter.no_ipv4 && self.parameter.no_ipv6 {
            return Err(ConfigError::ValidationError(
                "Both `no_ipv4` and `no_ipv6` set to `true`".to_string(),
            ));
        }
        Ok(())
    }

    /// Parse global configuration from YAML iterator
    /// Mirrors ogs_app_parse_global_conf()
    pub fn parse(&mut self, parent: &mut OgsYamlIter) -> Result<(), ConfigError> {
        if let Some(mut global_iter) = parent.recurse() {
            while global_iter.next() {
                let global_key = match global_iter.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                match global_key.as_str() {
                    "parameter" => {
                        self.parse_parameter(&mut global_iter)?;
                    }
                    "sockopt" => {
                        self.parse_sockopt(&mut global_iter)?;
                    }
                    "max" => {
                        self.parse_max(&mut global_iter)?;
                    }
                    "pool" => {
                        self.parse_pool(&mut global_iter)?;
                    }
                    _ => {
                        // Unknown key, ignore with warning
                    }
                }
            }
        }

        self.validate()
    }

    fn parse_parameter(&mut self, global_iter: &mut OgsYamlIter) -> Result<(), ConfigError> {
        if let Some(mut param_iter) = global_iter.recurse() {
            while param_iter.next() {
                let param_key = match param_iter.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                if let Some(child) = param_iter.recurse() {
                    let value = child.bool_value();
                    match param_key.as_str() {
                        "no_hss" => self.parameter.no_hss = value,
                        "no_mme" => self.parameter.no_mme = value,
                        "no_sgwu" => self.parameter.no_sgwu = value,
                        "no_sgwc" => self.parameter.no_sgwc = value,
                        "no_sgw" => self.parameter.no_sgw = value,
                        "no_pgw" => self.parameter.no_pgw = value,
                        "no_pcrf" => self.parameter.no_pcrf = value,
                        "no_nrf" => self.parameter.no_nrf = value,
                        "no_scp" => self.parameter.no_scp = value,
                        "no_sepp" => self.parameter.no_sepp = value,
                        "no_amf" => self.parameter.no_amf = value,
                        "no_smf" => self.parameter.no_smf = value,
                        "no_upf" => self.parameter.no_upf = value,
                        "no_ausf" => self.parameter.no_ausf = value,
                        "no_udm" => self.parameter.no_udm = value,
                        "no_pcf" => self.parameter.no_pcf = value,
                        "no_nssf" => self.parameter.no_nssf = value,
                        "no_bsf" => self.parameter.no_bsf = value,
                        "no_udr" => self.parameter.no_udr = value,
                        "no_ipv4" => self.parameter.no_ipv4 = value,
                        "no_ipv6" => self.parameter.no_ipv6 = value,
                        "prefer_ipv4" => self.parameter.prefer_ipv4 = value,
                        "multicast" => self.parameter.multicast = value,
                        "use_openair" => self.parameter.use_openair = value,
                        "use_upg_vpp" => self.parameter.use_upg_vpp = value,
                        "fake_csfb" => self.parameter.fake_csfb = value,
                        "no_ipv4v6_local_addr_in_packet_filter" => {
                            self.parameter.no_ipv4v6_local_addr_in_packet_filter = value
                        }
                        "no_pfcp_rr_select" => self.parameter.no_pfcp_rr_select = value,
                        "no_time_zone_information" => {
                            self.parameter.no_time_zone_information = value
                        }
                        _ => {} // Unknown key
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_sockopt(&mut self, global_iter: &mut OgsYamlIter) -> Result<(), ConfigError> {
        if let Some(mut sockopt_iter) = global_iter.recurse() {
            while sockopt_iter.next() {
                let sockopt_key = match sockopt_iter.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                match sockopt_key.as_str() {
                    "no_delay" => {
                        if let Some(child) = sockopt_iter.recurse() {
                            self.sockopt.no_delay = child.bool_value();
                        }
                    }
                    "linger" => {
                        if let Some(v) = sockopt_iter.recurse().and_then(|c| c.int_value()) {
                            self.sockopt.l_linger = v as i32;
                            self.sockopt.l_onoff = true;
                        }
                    }
                    _ => {} // Unknown key
                }
            }
        }
        Ok(())
    }

    fn parse_max(&mut self, global_iter: &mut OgsYamlIter) -> Result<(), ConfigError> {
        if let Some(mut max_iter) = global_iter.recurse() {
            while max_iter.next() {
                let max_key = match max_iter.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                match max_key.as_str() {
                    "ue" => {
                        if let Some(v) = max_iter.recurse().and_then(|c| c.uint_value()) {
                            self.max.ue = v;
                        }
                    }
                    "peer" | "enb" => {
                        if let Some(v) = max_iter.recurse().and_then(|c| c.uint_value()) {
                            self.max.peer = v;
                        }
                    }
                    "gtp_peer" => {
                        if let Some(v) = max_iter.recurse().and_then(|c| c.uint_value()) {
                            self.max.gtp_peer = v;
                        }
                    }
                    _ => {} // Unknown key
                }
            }
        }
        Ok(())
    }

    fn parse_pool(&mut self, global_iter: &mut OgsYamlIter) -> Result<(), ConfigError> {
        if let Some(mut pool_iter) = global_iter.recurse() {
            while pool_iter.next() {
                let pool_key = match pool_iter.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                if let Some(v) = pool_iter.recurse().and_then(|c| c.uint_value()) {
                    match pool_key.as_str() {
                        "128" => self.pkbuf_config.cluster_128_pool = v as u32,
                        "256" => self.pkbuf_config.cluster_256_pool = v as u32,
                        "512" => self.pkbuf_config.cluster_512_pool = v as u32,
                        "1024" => self.pkbuf_config.cluster_1024_pool = v as u32,
                        "2048" => self.pkbuf_config.cluster_2048_pool = v as u32,
                        "8192" => self.pkbuf_config.cluster_8192_pool = v as u32,
                        "32768" => self.pkbuf_config.cluster_32768_pool = v as u32,
                        "big" => self.pkbuf_config.cluster_big_pool = v as u32,
                        _ => {} // Unknown key
                    }
                }
            }
        }
        Ok(())
    }

    /// Count NF configuration sections
    /// Mirrors ogs_app_count_nf_conf_sections()
    pub fn count_nf_conf_section(&mut self, conf_section: &str) {
        match conf_section {
            "amf" => self.parameter.amf_count += 1,
            "smf" => self.parameter.smf_count += 1,
            "upf" => self.parameter.upf_count += 1,
            "ausf" => self.parameter.ausf_count += 1,
            "udm" => self.parameter.udm_count += 1,
            "pcf" => self.parameter.pcf_count += 1,
            "nssf" => self.parameter.nssf_count += 1,
            "bsf" => self.parameter.bsf_count += 1,
            "udr" => self.parameter.udr_count += 1,
            _ => {}
        }
    }
}


/// Time type (microseconds)
pub type OgsTime = i64;

/// Convert seconds to OgsTime
pub fn ogs_time_from_sec(sec: i64) -> OgsTime {
    sec * 1_000_000
}

/// Convert milliseconds to OgsTime
pub fn ogs_time_from_msec(msec: i64) -> OgsTime {
    msec * 1_000
}

/// NF instance time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NfInstanceTimeConf {
    pub heartbeat_interval: i32,
    pub no_heartbeat_margin: i32,
    pub validity_duration: i32,
}

/// Subscription time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionTimeConf {
    pub validity_duration: i32,
}

/// SBI message time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SbiTimeConf {
    pub client_wait_duration: OgsTime,
    pub connection_deadline: OgsTime,
    pub reconnect_interval: OgsTime,
    pub reconnect_interval_in_exception: OgsTime,
}

/// GTP message time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GtpTimeConf {
    pub t3_response_duration: OgsTime,
    pub n3_response_rcount: i32,
    pub t3_holding_duration: OgsTime,
    pub n3_holding_rcount: i32,
}

/// PFCP message time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PfcpTimeConf {
    pub t1_response_duration: OgsTime,
    pub n1_response_rcount: i32,
    pub t1_holding_duration: OgsTime,
    pub n1_holding_rcount: i32,
    pub association_interval: OgsTime,
    pub no_heartbeat_duration: OgsTime,
}

/// Message time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageTimeConf {
    pub duration: OgsTime,
    pub sbi: SbiTimeConf,
    pub gtp: GtpTimeConf,
    pub pfcp: PfcpTimeConf,
}

/// Handover time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HandoverTimeConf {
    pub duration: OgsTime,
    pub complete_delay: OgsTime,
}

/// Time configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeConf {
    pub nf_instance: NfInstanceTimeConf,
    pub subscription: SubscriptionTimeConf,
    pub message: MessageTimeConf,
    pub handover: HandoverTimeConf,
}

/// PLMN ID structure
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OgsPlmnId {
    pub mcc: [u8; 3],
    pub mnc: [u8; 3],
    pub mnc_len: u8,
}

impl OgsPlmnId {
    /// Build PLMN ID from MCC and MNC
    pub fn build(mcc: u16, mnc: u16, mnc_len: u8) -> Self {
        let mut plmn = OgsPlmnId::default();

        plmn.mcc[0] = ((mcc / 100) % 10) as u8;
        plmn.mcc[1] = ((mcc / 10) % 10) as u8;
        plmn.mcc[2] = (mcc % 10) as u8;

        plmn.mnc[0] = ((mnc / 100) % 10) as u8;
        plmn.mnc[1] = ((mnc / 10) % 10) as u8;
        plmn.mnc[2] = (mnc % 10) as u8;

        plmn.mnc_len = mnc_len;
        plmn
    }
}

/// SUPI range structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsSupiRange {
    pub num: usize,
    pub start: [u64; OGS_MAX_NUM_OF_SUPI_RANGE],
    pub end: [u64; OGS_MAX_NUM_OF_SUPI_RANGE],
}

/// Local configuration
/// Mirrors ogs_app_local_conf_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OgsLocalConf {
    pub time: TimeConf,
    pub serving_plmn_id: Vec<OgsPlmnId>,
}

impl OgsLocalConf {
    /// Create a new local configuration with default values
    pub fn new() -> Self {
        let mut conf = OgsLocalConf::default();
        conf.prepare();
        conf
    }

    /// Prepare local configuration with defaults
    /// Mirrors local_conf_prepare()
    pub fn prepare(&mut self) {
        // Heartbeat checking interval
        self.time.nf_instance.no_heartbeat_margin = 1;

        // 30 seconds validity
        self.time.nf_instance.validity_duration = 30;

        // 86400 seconds = 1 day
        self.time.subscription.validity_duration = 86400;

        // Message wait duration: 10 seconds (default)
        self.time.message.duration = ogs_time_from_sec(10);

        // Handover wait duration: 300 ms (default)
        self.time.handover.duration = ogs_time_from_msec(300);

        self.regenerate_timer_durations();
    }

    /// Regenerate all timer durations based on message duration
    /// Mirrors regenerate_all_timer_duration()
    pub fn regenerate_timer_durations(&mut self) {
        if self.time.message.duration == 0 {
            return;
        }

        // SBI timers
        self.time.message.sbi.client_wait_duration = self.time.message.duration;
        self.time.message.sbi.connection_deadline =
            self.time.message.sbi.client_wait_duration + ogs_time_from_sec(1);
        self.time.message.sbi.reconnect_interval = std::cmp::max(
            ogs_time_from_sec(3),
            self.time.message.sbi.client_wait_duration + ogs_time_from_sec(1),
        );
        self.time.message.sbi.reconnect_interval_in_exception = ogs_time_from_sec(2);

        // PFCP timers
        const PFCP_N1_RESPONSE_RETRY_COUNT: i32 = 3;
        self.time.message.pfcp.n1_response_rcount = PFCP_N1_RESPONSE_RETRY_COUNT;
        self.time.message.pfcp.t1_response_duration =
            self.time.message.duration / (PFCP_N1_RESPONSE_RETRY_COUNT as i64 + 1);

        const PFCP_N1_HOLDING_RETRY_COUNT: i32 = 1;
        self.time.message.pfcp.n1_holding_rcount = PFCP_N1_HOLDING_RETRY_COUNT;
        self.time.message.pfcp.t1_holding_duration = self.time.message.pfcp.n1_response_rcount
            as i64
            * self.time.message.pfcp.t1_response_duration;

        self.time.message.pfcp.association_interval = std::cmp::max(
            ogs_time_from_sec(3),
            self.time.message.sbi.client_wait_duration + ogs_time_from_sec(1),
        );

        self.time.message.pfcp.no_heartbeat_duration = std::cmp::max(
            ogs_time_from_sec(10),
            self.time.message.sbi.client_wait_duration + ogs_time_from_sec(1),
        );

        // GTP timers
        const GTP_N3_RESPONSE_RETRY_COUNT: i32 = 3;
        self.time.message.gtp.n3_response_rcount = GTP_N3_RESPONSE_RETRY_COUNT;
        self.time.message.gtp.t3_response_duration =
            self.time.message.duration / (GTP_N3_RESPONSE_RETRY_COUNT as i64 + 1);

        const GTP_N3_HOLDING_RETRY_COUNT: i32 = 1;
        self.time.message.gtp.n3_holding_rcount = GTP_N3_HOLDING_RETRY_COUNT;
        self.time.message.gtp.t3_holding_duration = self.time.message.gtp.n3_response_rcount
            as i64
            * self.time.message.gtp.t3_response_duration;
    }

    /// Validate the configuration
    /// Mirrors local_conf_validation()
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.time.nf_instance.validity_duration == 0 {
            return Err(ConfigError::ValidationError(
                "NF Instance validity-time should not be 0".to_string(),
            ));
        }
        Ok(())
    }

    /// Parse local configuration from YAML iterator
    /// Mirrors ogs_app_parse_local_conf()
    pub fn parse(&mut self, local_iter: &mut OgsYamlIter) -> Result<(), ConfigError> {
        while local_iter.next() {
            let local_key = match local_iter.key() {
                Some(k) => k.to_string(),
                None => continue,
            };

            match local_key.as_str() {
                "serving" => {
                    self.parse_serving(local_iter)?;
                }
                "time" => {
                    self.parse_time(local_iter)?;
                }
                _ => {} // Unknown key or handled elsewhere
            }
        }

        self.validate()
    }

    fn parse_serving(&mut self, local_iter: &mut OgsYamlIter) -> Result<(), ConfigError> {
        if let Some(mut serving_array) = local_iter.recurse() {
            loop {
                if serving_array.node_type() == YamlNodeType::Sequence {
                    if !serving_array.next() {
                        break;
                    }
                }

                if let Some(mut serving_iter) = serving_array.recurse() {
                    while serving_iter.next() {
                        let serving_key = match serving_iter.key() {
                            Some(k) => k.to_string(),
                            None => continue,
                        };

                        if serving_key == "plmn_id" {
                            if let Some(mut plmn_iter) = serving_iter.recurse() {
                                let mut mcc: Option<u16> = None;
                                let mut mnc: Option<u16> = None;
                                let mut mnc_len: u8 = 2;

                                while plmn_iter.next() {
                                    let id_key = match plmn_iter.key() {
                                        Some(k) => k.to_string(),
                                        None => continue,
                                    };

                                    match id_key.as_str() {
                                        "mcc" => {
                                            if let Some(child) = plmn_iter.recurse() {
                                                if let Some(v) = child.value_string() {
                                                    mcc = v.parse().ok();
                                                }
                                            }
                                        }
                                        "mnc" => {
                                            if let Some(child) = plmn_iter.recurse() {
                                                if let Some(v) = child.value_string() {
                                                    mnc_len = v.len() as u8;
                                                    mnc = v.parse().ok();
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                if let (Some(mcc_val), Some(mnc_val)) = (mcc, mnc) {
                                    if self.serving_plmn_id.len() < OGS_MAX_NUM_OF_PLMN {
                                        self.serving_plmn_id.push(OgsPlmnId::build(
                                            mcc_val, mnc_val, mnc_len,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                if serving_array.node_type() != YamlNodeType::Sequence {
                    break;
                }
            }
        }
        Ok(())
    }

    fn parse_time(&mut self, local_iter: &mut OgsYamlIter) -> Result<(), ConfigError> {
        if let Some(mut time_iter) = local_iter.recurse() {
            while time_iter.next() {
                let time_key = match time_iter.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                match time_key.as_str() {
                    "nf_instance" => {
                        if let Some(mut sbi_iter) = time_iter.recurse() {
                            while sbi_iter.next() {
                                let sbi_key = match sbi_iter.key() {
                                    Some(k) => k.to_string(),
                                    None => continue,
                                };

                                match sbi_key.as_str() {
                                    "heartbeat" => {
                                        if let Some(child) = sbi_iter.recurse() {
                                            if let Some(v) = child.int_value() {
                                                self.time.nf_instance.heartbeat_interval = v as i32;
                                            }
                                        }
                                    }
                                    "validity" => {
                                        if let Some(child) = sbi_iter.recurse() {
                                            if let Some(v) = child.int_value() {
                                                self.time.nf_instance.validity_duration = v as i32;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    "subscription" => {
                        if let Some(mut sub_iter) = time_iter.recurse() {
                            while sub_iter.next() {
                                let sub_key = match sub_iter.key() {
                                    Some(k) => k.to_string(),
                                    None => continue,
                                };

                                if sub_key == "validity" {
                                    if let Some(child) = sub_iter.recurse() {
                                        if let Some(v) = child.int_value() {
                                            self.time.subscription.validity_duration = v as i32;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "message" => {
                        if let Some(mut msg_iter) = time_iter.recurse() {
                            while msg_iter.next() {
                                let msg_key = match msg_iter.key() {
                                    Some(k) => k.to_string(),
                                    None => continue,
                                };

                                if msg_key == "duration" {
                                    if let Some(child) = msg_iter.recurse() {
                                        if let Some(v) = child.int_value() {
                                            self.time.message.duration = ogs_time_from_msec(v);
                                            self.regenerate_timer_durations();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "handover" => {
                        if let Some(mut ho_iter) = time_iter.recurse() {
                            while ho_iter.next() {
                                let ho_key = match ho_iter.key() {
                                    Some(k) => k.to_string(),
                                    None => continue,
                                };

                                if ho_key == "duration" {
                                    if let Some(child) = ho_iter.recurse() {
                                        if let Some(v) = child.int_value() {
                                            self.time.handover.duration = ogs_time_from_msec(v);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {} // Other time keys handled elsewhere
                }
            }
        }
        Ok(())
    }
}

/// Parse socket options from YAML
/// Mirrors ogs_app_parse_sockopt_config()
pub fn parse_sockopt_config(parent: &mut OgsYamlIter) -> OgsSockopt {
    let mut option = OgsSockopt::default();

    if let Some(mut sockopt_iter) = parent.recurse() {
        while sockopt_iter.next() {
            let sockopt_key = match sockopt_iter.key() {
                Some(k) => k.to_string(),
                None => continue,
            };

            if sockopt_key == "sctp" {
                if let Some(mut sctp_iter) = sockopt_iter.recurse() {
                    while sctp_iter.next() {
                        let sctp_key = match sctp_iter.key() {
                            Some(k) => k.to_string(),
                            None => continue,
                        };

                        match sctp_key.as_str() {
                            "spp_hbinterval" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.spp_hbinterval = v as u32;
                                    }
                                }
                            }
                            "spp_sackdelay" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.spp_sackdelay = v as u32;
                                    }
                                }
                            }
                            "srto_initial" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.srto_initial = v as u32;
                                    }
                                }
                            }
                            "srto_min" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.srto_min = v as u32;
                                    }
                                }
                            }
                            "srto_max" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.srto_max = v as u32;
                                    }
                                }
                            }
                            "sinit_num_ostreams" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.sinit_num_ostreams = v as u16;
                                    }
                                }
                            }
                            "sinit_max_instreams" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.sinit_max_instreams = v as u16;
                                    }
                                }
                            }
                            "sinit_max_attempts" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.sinit_max_attempts = v as u16;
                                    }
                                }
                            }
                            "sinit_max_init_timeo" => {
                                if let Some(child) = sctp_iter.recurse() {
                                    if let Some(v) = child.uint_value() {
                                        option.sctp.sinit_max_init_timeo = v as u16;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    option
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::OgsYamlDocument;

    #[test]
    fn test_global_conf_default() {
        let conf = OgsGlobalConf::new();
        assert!(conf.sockopt.no_delay);
        assert_eq!(conf.max.ue, MAX_NUM_OF_UE);
        assert_eq!(conf.max.peer, MAX_NUM_OF_PEER);
    }

    #[test]
    fn test_global_conf_validation() {
        let mut conf = OgsGlobalConf::new();
        assert!(conf.validate().is_ok());

        conf.parameter.no_ipv4 = true;
        conf.parameter.no_ipv6 = true;
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_local_conf_default() {
        let conf = OgsLocalConf::new();
        assert_eq!(conf.time.nf_instance.validity_duration, 30);
        assert_eq!(conf.time.subscription.validity_duration, 86400);
        assert_eq!(conf.time.message.duration, ogs_time_from_sec(10));
    }

    #[test]
    fn test_local_conf_validation() {
        let mut conf = OgsLocalConf::new();
        assert!(conf.validate().is_ok());

        conf.time.nf_instance.validity_duration = 0;
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_plmn_id_build() {
        let plmn = OgsPlmnId::build(310, 410, 3);
        assert_eq!(plmn.mcc, [3, 1, 0]);
        assert_eq!(plmn.mnc, [4, 1, 0]);
        assert_eq!(plmn.mnc_len, 3);
    }

    #[test]
    fn test_parse_global_conf() {
        let yaml = r#"
global:
  parameter:
    no_ipv4: false
    no_ipv6: true
    prefer_ipv4: true
  max:
    ue: 2048
    peer: 128
  sockopt:
    no_delay: true
    linger: 5
"#;
        let doc = OgsYamlDocument::from_str(yaml).unwrap();
        let mut iter = doc.iter();
        
        let mut conf = OgsGlobalConf::new();
        
        while iter.next() {
            if iter.key() == Some("global") {
                conf.parse(&mut iter).unwrap();
            }
        }

        assert!(!conf.parameter.no_ipv4);
        assert!(conf.parameter.no_ipv6);
        assert!(conf.parameter.prefer_ipv4);
        assert_eq!(conf.max.ue, 2048);
        assert_eq!(conf.max.peer, 128);
        assert!(conf.sockopt.no_delay);
        assert!(conf.sockopt.l_onoff);
        assert_eq!(conf.sockopt.l_linger, 5);
    }

    #[test]
    fn test_time_conversion() {
        assert_eq!(ogs_time_from_sec(1), 1_000_000);
        assert_eq!(ogs_time_from_msec(1), 1_000);
        assert_eq!(ogs_time_from_sec(10), 10_000_000);
    }
}
