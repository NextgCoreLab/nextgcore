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
                if serving_array.node_type() == YamlNodeType::Sequence
                    && !serving_array.next() {
                        break;
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

//
// Dynamic Reconfiguration Support (B3.1)
//

use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Configuration reload event
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigEvent {
    /// Configuration file changed
    FileChanged(PathBuf),
    /// Configuration reloaded successfully
    Reloaded,
    /// Configuration reload failed
    ReloadFailed(String),
    /// Shutdown requested
    Shutdown,
}

/// Configuration watcher
pub struct ConfigWatcher {
    config_path: PathBuf,
    event_tx: Sender<ConfigEvent>,
    event_rx: Arc<Mutex<Receiver<ConfigEvent>>>,
    running: Arc<Mutex<bool>>,
}

impl ConfigWatcher {
    /// Create a new configuration watcher
    pub fn new(config_path: PathBuf) -> Self {
        let (event_tx, event_rx) = channel();
        ConfigWatcher {
            config_path,
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Start watching the configuration file
    pub fn start(&self) {
        let config_path = self.config_path.clone();
        let event_tx = self.event_tx.clone();
        let running = Arc::clone(&self.running);

        *running.lock().unwrap() = true;

        std::thread::spawn(move || {
            // Get initial modification time
            let mut last_modified = std::fs::metadata(&config_path)
                .and_then(|m| m.modified())
                .ok();

            while *running.lock().unwrap() {
                // Check file modification time
                if let Ok(metadata) = std::fs::metadata(&config_path) {
                    if let Ok(modified) = metadata.modified() {
                        if Some(modified) != last_modified {
                            last_modified = Some(modified);
                            // Notify about file change
                            let _ = event_tx.send(ConfigEvent::FileChanged(config_path.clone()));
                        }
                    }
                }

                // Check every second
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    /// Stop watching
    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
        let _ = self.event_tx.send(ConfigEvent::Shutdown);
    }

    /// Get next event (blocking)
    pub fn recv(&self) -> Result<ConfigEvent, std::sync::mpsc::RecvError> {
        let rx = self.event_rx.lock().unwrap();
        rx.recv()
    }

    /// Try to get next event (non-blocking)
    pub fn try_recv(&self) -> Result<ConfigEvent, std::sync::mpsc::TryRecvError> {
        let rx = self.event_rx.lock().unwrap();
        rx.try_recv()
    }

    /// Notify reload success
    pub fn notify_reloaded(&self) {
        let _ = self.event_tx.send(ConfigEvent::Reloaded);
    }

    /// Notify reload failure
    pub fn notify_reload_failed(&self, error: String) {
        let _ = self.event_tx.send(ConfigEvent::ReloadFailed(error));
    }

    /// Get config path
    pub fn config_path(&self) -> &PathBuf {
        &self.config_path
    }
}

impl Drop for ConfigWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

impl OgsGlobalConf {
    /// Reload configuration from file
    pub fn reload(&mut self, config_path: &str) -> Result<(), ConfigError> {
        use crate::yaml::OgsYamlDocument;

        // Parse YAML document
        let doc = OgsYamlDocument::from_file(config_path)
            .map_err(|e| ConfigError::ParseError(format!("Failed to parse YAML: {e:?}")))?;

        let mut iter = doc.iter();

        // Find and parse global section
        while iter.next() {
            if iter.key() == Some("global") {
                self.parse(&mut iter)?;
                return Ok(());
            }
        }

        Err(ConfigError::ParseError(
            "No 'global' section found in config".to_string(),
        ))
    }
}

impl OgsLocalConf {
    /// Reload configuration from file
    pub fn reload(&mut self, config_path: &str) -> Result<(), ConfigError> {
        use crate::yaml::OgsYamlDocument;

        // Parse YAML document
        let doc = OgsYamlDocument::from_file(config_path)
            .map_err(|e| ConfigError::ParseError(format!("Failed to parse YAML: {e:?}")))?;

        let mut iter = doc.iter();

        // Find local config sections (usually under NF-specific section)
        while iter.next() {
            let key = iter.key().unwrap_or("");

            // Look for common NF sections that contain local config
            if key == "amf" || key == "smf" || key == "upf" || key == "nrf" || key == "local" {
                if let Some(mut local_iter) = iter.recurse() {
                    self.parse(&mut local_iter)?;
                    return Ok(());
                }
            }
        }

        Err(ConfigError::ParseError(
            "No local config section found in config".to_string(),
        ))
    }
}

/// Configuration reload manager
pub struct ConfigReloadManager {
    watcher: ConfigWatcher,
    global_conf: Arc<Mutex<OgsGlobalConf>>,
    local_conf: Arc<Mutex<OgsLocalConf>>,
}

impl ConfigReloadManager {
    /// Create a new reload manager
    pub fn new(
        config_path: PathBuf,
        global_conf: Arc<Mutex<OgsGlobalConf>>,
        local_conf: Arc<Mutex<OgsLocalConf>>,
    ) -> Self {
        ConfigReloadManager {
            watcher: ConfigWatcher::new(config_path),
            global_conf,
            local_conf,
        }
    }

    /// Start watching and auto-reloading
    pub fn start_auto_reload(&self) {
        self.watcher.start();

        let watcher = ConfigWatcher::new(self.watcher.config_path().clone());
        let event_rx = Arc::clone(&self.watcher.event_rx);
        let global_conf = Arc::clone(&self.global_conf);
        let local_conf = Arc::clone(&self.local_conf);
        let config_path = self.watcher.config_path().clone();

        std::thread::spawn(move || {
            loop {
                let rx = event_rx.lock().unwrap();
                match rx.recv() {
                    Ok(ConfigEvent::FileChanged(_)) => {
                        drop(rx); // Release lock before reloading

                        eprintln!("Configuration file changed, reloading...");

                        // Try to reload global config
                        let config_path_str = match config_path.to_str() {
                            Some(s) => s,
                            None => {
                                eprintln!("Invalid config path: contains invalid UTF-8");
                                watcher.notify_reload_failed("Invalid config path".to_string());
                                continue;
                            }
                        };

                        let mut global = global_conf.lock().unwrap();
                        if let Err(e) = global.reload(config_path_str) {
                            eprintln!("Failed to reload global config: {e}");
                            watcher.notify_reload_failed(format!("Global config: {e}"));
                            continue;
                        }
                        drop(global);

                        // Try to reload local config
                        let mut local = local_conf.lock().unwrap();
                        if let Err(e) = local.reload(config_path_str) {
                            eprintln!("Failed to reload local config: {e}");
                            watcher.notify_reload_failed(format!("Local config: {e}"));
                            continue;
                        }
                        drop(local);

                        eprintln!("Configuration reloaded successfully");
                        watcher.notify_reloaded();
                    }
                    Ok(ConfigEvent::Shutdown) => {
                        eprintln!("Config reload manager shutting down");
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }

    /// Stop auto-reload
    pub fn stop(&self) {
        self.watcher.stop();
    }

    /// Get watcher reference
    pub fn watcher(&self) -> &ConfigWatcher {
        &self.watcher
    }
}

#[cfg(test)]
mod config_reload_tests {
    use super::*;
    use std::fs;
    

    #[test]
    fn test_config_watcher_create() {
        let watcher = ConfigWatcher::new(PathBuf::from("/tmp/test.yaml"));
        assert_eq!(watcher.config_path(), &PathBuf::from("/tmp/test.yaml"));
    }

    #[test]
    fn test_config_watcher_events() {
        let watcher = ConfigWatcher::new(PathBuf::from("/tmp/test.yaml"));

        watcher.notify_reloaded();
        let event = watcher.try_recv();
        assert!(event.is_ok());
        assert_eq!(event.unwrap(), ConfigEvent::Reloaded);

        watcher.notify_reload_failed("test error".to_string());
        let event = watcher.try_recv();
        assert!(event.is_ok());
        assert!(matches!(event.unwrap(), ConfigEvent::ReloadFailed(_)));
    }

    #[test]
    fn test_global_conf_reload() {
        // Create temporary config file
        let temp_file = "/tmp/test_global_conf.yaml";
        let yaml = r#"
global:
  parameter:
    no_ipv4: false
    no_ipv6: true
  max:
    ue: 2048
"#;
        fs::write(temp_file, yaml).unwrap();

        let mut conf = OgsGlobalConf::new();
        let result = conf.reload(temp_file);

        fs::remove_file(temp_file).ok();

        assert!(result.is_ok());
        assert_eq!(conf.max.ue, 2048);
    }
}

//
// B3.3: Configuration Versioning and Rollback (6G Feature)
//

/// Configuration version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    /// Version number
    pub version: u64,
    /// Timestamp when version was created
    pub timestamp: u64,
    /// Description of changes
    pub description: String,
    /// Git commit hash (if available)
    pub commit_hash: Option<String>,
}

impl ConfigVersion {
    /// Create a new config version
    pub fn new(version: u64, description: impl Into<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        ConfigVersion {
            version,
            timestamp,
            description: description.into(),
            commit_hash: None,
        }
    }

    /// Set commit hash
    pub fn with_commit_hash(mut self, hash: impl Into<String>) -> Self {
        self.commit_hash = Some(hash.into());
        self
    }
}

/// Versioned configuration snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    /// Version information
    pub version: ConfigVersion,
    /// Global configuration
    pub global_conf: OgsGlobalConf,
    /// Local configuration
    pub local_conf: OgsLocalConf,
}

impl ConfigSnapshot {
    /// Create a new snapshot
    pub fn new(
        version: ConfigVersion,
        global_conf: OgsGlobalConf,
        local_conf: OgsLocalConf,
    ) -> Self {
        ConfigSnapshot {
            version,
            global_conf,
            local_conf,
        }
    }
}

/// Configuration history manager with versioning and rollback support
pub struct ConfigHistoryManager {
    /// Configuration snapshots (newest first)
    snapshots: Vec<ConfigSnapshot>,
    /// Maximum number of snapshots to keep
    max_history: usize,
    /// Current version number
    current_version: u64,
}

impl ConfigHistoryManager {
    /// Create a new history manager
    pub fn new(max_history: usize) -> Self {
        ConfigHistoryManager {
            snapshots: Vec::new(),
            max_history,
            current_version: 0,
        }
    }

    /// Take a snapshot of current configuration
    pub fn take_snapshot(
        &mut self,
        global_conf: &OgsGlobalConf,
        local_conf: &OgsLocalConf,
        description: impl Into<String>,
    ) -> u64 {
        self.current_version += 1;

        let version = ConfigVersion::new(self.current_version, description);
        let snapshot = ConfigSnapshot::new(
            version,
            global_conf.clone(),
            local_conf.clone(),
        );

        // Add to beginning
        self.snapshots.insert(0, snapshot);

        // Trim history if needed
        if self.snapshots.len() > self.max_history {
            self.snapshots.truncate(self.max_history);
        }

        self.current_version
    }

    /// Get snapshot by version
    pub fn get_snapshot(&self, version: u64) -> Option<&ConfigSnapshot> {
        self.snapshots.iter().find(|s| s.version.version == version)
    }

    /// Get latest snapshot
    pub fn get_latest(&self) -> Option<&ConfigSnapshot> {
        self.snapshots.first()
    }

    /// Get all versions
    pub fn list_versions(&self) -> Vec<&ConfigVersion> {
        self.snapshots.iter().map(|s| &s.version).collect()
    }

    /// Rollback to a specific version
    pub fn rollback(
        &mut self,
        version: u64,
        current_global: &mut OgsGlobalConf,
        current_local: &mut OgsLocalConf,
    ) -> Result<(), ConfigError> {
        // Clone the snapshot data before borrowing self mutably
        let snapshot_data = {
            let snapshot = self.get_snapshot(version)
                .ok_or_else(|| ConfigError::ParseError(format!("Version {version} not found")))?;
            (snapshot.global_conf.clone(), snapshot.local_conf.clone())
        };

        // Before rollback, take a snapshot of current state
        self.take_snapshot(current_global, current_local, format!("Before rollback to v{version}"));

        // Apply snapshot
        *current_global = snapshot_data.0;
        *current_local = snapshot_data.1;

        Ok(())
    }

    /// Rollback to previous version
    pub fn rollback_previous(
        &mut self,
        current_global: &mut OgsGlobalConf,
        current_local: &mut OgsLocalConf,
    ) -> Result<(), ConfigError> {
        if self.snapshots.len() < 2 {
            return Err(ConfigError::ParseError("No previous version available".to_string()));
        }

        // Get second snapshot (first is current)
        let prev_version = self.snapshots[1].version.version;
        self.rollback(prev_version, current_global, current_local)
    }

    /// Get number of snapshots
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Clear all history
    pub fn clear(&mut self) {
        self.snapshots.clear();
        self.current_version = 0;
    }

    /// Export snapshot to JSON
    pub fn export_snapshot(&self, version: u64) -> Result<String, ConfigError> {
        let snapshot = self.get_snapshot(version)
            .ok_or_else(|| ConfigError::ParseError(format!("Version {version} not found")))?;

        serde_json::to_string_pretty(snapshot)
            .map_err(|e| ConfigError::ParseError(format!("Export failed: {e}")))
    }

    /// Import snapshot from JSON
    pub fn import_snapshot(&mut self, json: &str) -> Result<u64, ConfigError> {
        let snapshot: ConfigSnapshot = serde_json::from_str(json)
            .map_err(|e| ConfigError::ParseError(format!("Import failed: {e}")))?;

        // Assign new version number
        self.current_version += 1;
        let mut new_snapshot = snapshot;
        new_snapshot.version.version = self.current_version;

        self.snapshots.insert(0, new_snapshot);

        if self.snapshots.len() > self.max_history {
            self.snapshots.truncate(self.max_history);
        }

        Ok(self.current_version)
    }

    /// Compare two versions and get differences
    pub fn diff_versions(&self, v1: u64, v2: u64) -> Result<Vec<String>, ConfigError> {
        let snap1 = self.get_snapshot(v1)
            .ok_or_else(|| ConfigError::ParseError(format!("Version {v1} not found")))?;
        let snap2 = self.get_snapshot(v2)
            .ok_or_else(|| ConfigError::ParseError(format!("Version {v2} not found")))?;

        let mut diffs = Vec::new();

        // Compare global config
        if snap1.global_conf.max.ue != snap2.global_conf.max.ue {
            diffs.push(format!("max.ue: {} -> {}", snap1.global_conf.max.ue, snap2.global_conf.max.ue));
        }
        if snap1.global_conf.max.peer != snap2.global_conf.max.peer {
            diffs.push(format!("max.peer: {} -> {}", snap1.global_conf.max.peer, snap2.global_conf.max.peer));
        }

        // Compare local config
        if snap1.local_conf.time.nf_instance.validity_duration != snap2.local_conf.time.nf_instance.validity_duration {
            diffs.push(format!(
                "time.nf_instance.validity: {} -> {}",
                snap1.local_conf.time.nf_instance.validity_duration,
                snap2.local_conf.time.nf_instance.validity_duration
            ));
        }

        Ok(diffs)
    }
}

impl Default for ConfigHistoryManager {
    fn default() -> Self {
        Self::new(10) // Keep last 10 versions by default
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn test_config_version_creation() {
        let version = ConfigVersion::new(1, "Initial version");
        assert_eq!(version.version, 1);
        assert_eq!(version.description, "Initial version");
        assert!(version.commit_hash.is_none());
    }

    #[test]
    fn test_config_version_with_commit() {
        let version = ConfigVersion::new(1, "Initial")
            .with_commit_hash("abc123");
        assert_eq!(version.commit_hash, Some("abc123".to_string()));
    }

    #[test]
    fn test_history_manager_snapshot() {
        let mut manager = ConfigHistoryManager::new(5);
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();

        let v1 = manager.take_snapshot(&global, &local, "Version 1");
        assert_eq!(v1, 1);
        assert_eq!(manager.snapshot_count(), 1);

        let v2 = manager.take_snapshot(&global, &local, "Version 2");
        assert_eq!(v2, 2);
        assert_eq!(manager.snapshot_count(), 2);
    }

    #[test]
    fn test_history_manager_get_snapshot() {
        let mut manager = ConfigHistoryManager::new(5);
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();

        manager.take_snapshot(&global, &local, "Version 1");
        manager.take_snapshot(&global, &local, "Version 2");

        let snapshot = manager.get_snapshot(1);
        assert!(snapshot.is_some());
        assert_eq!(snapshot.unwrap().version.description, "Version 1");
    }

    #[test]
    fn test_history_manager_get_latest() {
        let mut manager = ConfigHistoryManager::new(5);
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();

        manager.take_snapshot(&global, &local, "Version 1");
        manager.take_snapshot(&global, &local, "Version 2");

        let latest = manager.get_latest();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().version.version, 2);
        assert_eq!(latest.unwrap().version.description, "Version 2");
    }

    #[test]
    fn test_history_manager_max_history() {
        let mut manager = ConfigHistoryManager::new(3);
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();

        for i in 1..=5 {
            manager.take_snapshot(&global, &local, format!("Version {i}"));
        }

        // Should only keep last 3
        assert_eq!(manager.snapshot_count(), 3);

        // Should have versions 5, 4, 3 (newest first)
        assert!(manager.get_snapshot(5).is_some());
        assert!(manager.get_snapshot(4).is_some());
        assert!(manager.get_snapshot(3).is_some());
        assert!(manager.get_snapshot(2).is_none());
        assert!(manager.get_snapshot(1).is_none());
    }

    #[test]
    fn test_history_manager_rollback() {
        let mut manager = ConfigHistoryManager::new(5);
        let mut global = OgsGlobalConf::new();
        let mut local = OgsLocalConf::new();

        // Take initial snapshot
        manager.take_snapshot(&global, &local, "Initial");

        // Modify config
        global.max.ue = 2048;
        manager.take_snapshot(&global, &local, "Modified");

        // Rollback to initial
        let result = manager.rollback(1, &mut global, &mut local);
        assert!(result.is_ok());
        assert_eq!(global.max.ue, MAX_NUM_OF_UE); // Should be reset to default
    }

    #[test]
    fn test_history_manager_rollback_previous() {
        let mut manager = ConfigHistoryManager::new(5);
        let mut global = OgsGlobalConf::new();
        let mut local = OgsLocalConf::new();

        manager.take_snapshot(&global, &local, "V1");
        global.max.ue = 2048;
        manager.take_snapshot(&global, &local, "V2");

        // Rollback to previous
        let result = manager.rollback_previous(&mut global, &mut local);
        assert!(result.is_ok());
        assert_eq!(global.max.ue, MAX_NUM_OF_UE);
    }

    #[test]
    fn test_history_manager_export_import() {
        let mut manager = ConfigHistoryManager::new(5);
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();

        let v1 = manager.take_snapshot(&global, &local, "Export test");
        let json = manager.export_snapshot(v1).unwrap();

        let mut manager2 = ConfigHistoryManager::new(5);
        let v2 = manager2.import_snapshot(&json).unwrap();

        let snapshot = manager2.get_snapshot(v2).unwrap();
        assert_eq!(snapshot.version.description, "Export test");
    }

    #[test]
    fn test_list_versions() {
        let mut manager = ConfigHistoryManager::new(5);
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();

        manager.take_snapshot(&global, &local, "V1");
        manager.take_snapshot(&global, &local, "V2");
        manager.take_snapshot(&global, &local, "V3");

        let versions = manager.list_versions();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, 3); // Newest first
        assert_eq!(versions[1].version, 2);
        assert_eq!(versions[2].version, 1);
    }
}

//
// B3.4: Configuration Drift Detection (6G Feature)
//

/// Drift severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftSeverity {
    /// Cosmetic difference, no operational impact.
    Info,
    /// Minor drift, may affect performance.
    Warning,
    /// Significant drift, likely affects SLA compliance.
    Error,
    /// Critical drift, immediate remediation required.
    Critical,
}

/// A single detected configuration drift.
#[derive(Debug, Clone)]
pub struct ConfigDrift {
    /// Human-readable path to the drifted parameter (e.g. "max.ue").
    pub path: String,
    /// Expected value (from desired/golden config).
    pub expected: String,
    /// Actual value (from running config).
    pub actual: String,
    /// Severity of this drift.
    pub severity: DriftSeverity,
    /// Detection timestamp (epoch seconds).
    pub detected_at: u64,
}

/// Result of a drift detection scan.
#[derive(Debug, Clone)]
pub struct DriftReport {
    /// Detected drifts.
    pub drifts: Vec<ConfigDrift>,
    /// Scan timestamp.
    pub scanned_at: u64,
    /// Whether the configuration is fully compliant (no drifts).
    pub compliant: bool,
}

/// Configuration drift detector compares running config against a desired baseline.
pub struct ConfigDriftDetector {
    /// Desired/golden global configuration.
    desired_global: OgsGlobalConf,
    /// Desired/golden local configuration.
    desired_local: OgsLocalConf,
    /// Total scans performed.
    scan_count: u64,
    /// Total drifts ever detected.
    total_drifts: u64,
}

impl ConfigDriftDetector {
    /// Create a new drift detector with desired baseline configs.
    pub fn new(desired_global: OgsGlobalConf, desired_local: OgsLocalConf) -> Self {
        Self {
            desired_global,
            desired_local,
            scan_count: 0,
            total_drifts: 0,
        }
    }

    /// Update the desired baseline.
    pub fn update_baseline(&mut self, global: OgsGlobalConf, local: OgsLocalConf) {
        self.desired_global = global;
        self.desired_local = local;
    }

    /// Detect drifts between running config and desired baseline.
    pub fn detect(
        &mut self,
        running_global: &OgsGlobalConf,
        running_local: &OgsLocalConf,
    ) -> DriftReport {
        self.scan_count += 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut drifts = Vec::new();

        // Check global config drifts
        if running_global.max.ue != self.desired_global.max.ue {
            drifts.push(ConfigDrift {
                path: "max.ue".to_string(),
                expected: self.desired_global.max.ue.to_string(),
                actual: running_global.max.ue.to_string(),
                severity: DriftSeverity::Warning,
                detected_at: now,
            });
        }
        if running_global.max.peer != self.desired_global.max.peer {
            drifts.push(ConfigDrift {
                path: "max.peer".to_string(),
                expected: self.desired_global.max.peer.to_string(),
                actual: running_global.max.peer.to_string(),
                severity: DriftSeverity::Warning,
                detected_at: now,
            });
        }
        if running_global.parameter.no_ipv4 != self.desired_global.parameter.no_ipv4 {
            drifts.push(ConfigDrift {
                path: "parameter.no_ipv4".to_string(),
                expected: self.desired_global.parameter.no_ipv4.to_string(),
                actual: running_global.parameter.no_ipv4.to_string(),
                severity: DriftSeverity::Error,
                detected_at: now,
            });
        }
        if running_global.parameter.no_ipv6 != self.desired_global.parameter.no_ipv6 {
            drifts.push(ConfigDrift {
                path: "parameter.no_ipv6".to_string(),
                expected: self.desired_global.parameter.no_ipv6.to_string(),
                actual: running_global.parameter.no_ipv6.to_string(),
                severity: DriftSeverity::Error,
                detected_at: now,
            });
        }

        // Check local config drifts
        if running_local.time.nf_instance.validity_duration != self.desired_local.time.nf_instance.validity_duration {
            drifts.push(ConfigDrift {
                path: "time.nf_instance.validity_duration".to_string(),
                expected: self.desired_local.time.nf_instance.validity_duration.to_string(),
                actual: running_local.time.nf_instance.validity_duration.to_string(),
                severity: DriftSeverity::Warning,
                detected_at: now,
            });
        }
        if running_local.time.nf_instance.heartbeat_interval != self.desired_local.time.nf_instance.heartbeat_interval {
            drifts.push(ConfigDrift {
                path: "time.nf_instance.heartbeat_interval".to_string(),
                expected: self.desired_local.time.nf_instance.heartbeat_interval.to_string(),
                actual: running_local.time.nf_instance.heartbeat_interval.to_string(),
                severity: DriftSeverity::Warning,
                detected_at: now,
            });
        }
        if running_local.time.message.duration != self.desired_local.time.message.duration {
            drifts.push(ConfigDrift {
                path: "time.message.duration".to_string(),
                expected: self.desired_local.time.message.duration.to_string(),
                actual: running_local.time.message.duration.to_string(),
                severity: DriftSeverity::Critical,
                detected_at: now,
            });
        }

        self.total_drifts += drifts.len() as u64;
        let compliant = drifts.is_empty();

        DriftReport {
            drifts,
            scanned_at: now,
            compliant,
        }
    }

    /// Get the worst severity from a drift report.
    pub fn worst_severity(report: &DriftReport) -> Option<DriftSeverity> {
        report.drifts.iter().map(|d| d.severity).max()
    }

    /// Number of scans performed.
    pub fn scan_count(&self) -> u64 {
        self.scan_count
    }

    /// Total drifts ever detected.
    pub fn total_drifts(&self) -> u64 {
        self.total_drifts
    }
}

#[cfg(test)]
mod drift_tests {
    use super::*;

    #[test]
    fn test_no_drift() {
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();
        let mut detector = ConfigDriftDetector::new(global.clone(), local.clone());

        let report = detector.detect(&global, &local);
        assert!(report.compliant);
        assert!(report.drifts.is_empty());
    }

    #[test]
    fn test_detect_ue_drift() {
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();
        let mut detector = ConfigDriftDetector::new(global.clone(), local.clone());

        let mut drifted_global = global.clone();
        drifted_global.max.ue = 4096;

        let report = detector.detect(&drifted_global, &local);
        assert!(!report.compliant);
        assert_eq!(report.drifts.len(), 1);
        assert_eq!(report.drifts[0].path, "max.ue");
        assert_eq!(report.drifts[0].severity, DriftSeverity::Warning);
    }

    #[test]
    fn test_detect_message_duration_drift() {
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();
        let mut detector = ConfigDriftDetector::new(global.clone(), local.clone());

        let mut drifted_local = local.clone();
        drifted_local.time.message.duration = ogs_time_from_sec(30);

        let report = detector.detect(&global, &drifted_local);
        assert!(!report.compliant);
        assert_eq!(ConfigDriftDetector::worst_severity(&report), Some(DriftSeverity::Critical));
    }

    #[test]
    fn test_drift_detector_counters() {
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();
        let mut detector = ConfigDriftDetector::new(global.clone(), local.clone());

        let mut drifted = global.clone();
        drifted.max.ue = 999;

        detector.detect(&drifted, &local);
        detector.detect(&drifted, &local);

        assert_eq!(detector.scan_count(), 2);
        assert_eq!(detector.total_drifts(), 2);
    }

    #[test]
    fn test_update_baseline() {
        let global = OgsGlobalConf::new();
        let local = OgsLocalConf::new();
        let mut detector = ConfigDriftDetector::new(global.clone(), local.clone());

        let mut updated = global.clone();
        updated.max.ue = 4096;

        // Before baseline update, this is a drift
        let report = detector.detect(&updated, &local);
        assert!(!report.compliant);

        // After baseline update, no drift
        detector.update_baseline(updated.clone(), local.clone());
        let report = detector.detect(&updated, &local);
        assert!(report.compliant);
    }
}
