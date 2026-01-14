//! Diameter configuration types

/// Diameter configuration
#[derive(Debug, Clone)]
pub struct DiameterConfig {
    /// Diameter Identity of the local peer (FQDN)
    pub diameter_id: String,

    /// Diameter realm of the local peer
    pub diameter_realm: String,

    /// IP address of the local peer
    pub address: Option<String>,

    /// Local port for legacy Diameter (default: 3868)
    pub port: u16,

    /// Local port for Diameter/TLS (default: 5658)
    pub port_tls: u16,

    /// Default Tc timer value
    pub timer_tc: u32,

    /// Configuration flags
    pub flags: DiameterConfigFlags,

    /// Extensions
    pub extensions: Vec<DiameterExtension>,

    /// Peer connections
    pub connections: Vec<DiameterConnection>,

    /// Statistics configuration
    pub stats: DiameterStatsConfig,
}

impl Default for DiameterConfig {
    fn default() -> Self {
        Self {
            diameter_id: String::new(),
            diameter_realm: String::new(),
            address: None,
            port: crate::DIAMETER_PORT,
            port_tls: crate::DIAMETER_TLS_PORT,
            timer_tc: 30,
            flags: DiameterConfigFlags::default(),
            extensions: Vec::new(),
            connections: Vec::new(),
            stats: DiameterStatsConfig::default(),
        }
    }
}

/// Diameter configuration flags
#[derive(Debug, Clone, Default)]
pub struct DiameterConfigFlags {
    /// The peer does not relay messages (0xffffff app id)
    pub no_fwd: bool,

    /// Disable the use of SCTP
    pub no_sctp: bool,
}

/// Diameter extension configuration
#[derive(Debug, Clone)]
pub struct DiameterExtension {
    /// Module name
    pub module: String,

    /// Configuration file
    pub conf: Option<String>,
}

/// Diameter peer connection configuration
#[derive(Debug, Clone)]
pub struct DiameterConnection {
    /// Diameter Identity of the remote peer
    pub identity: String,

    /// IP address of the remote peer
    pub address: String,

    /// Port to connect to (0 for default)
    pub port: u16,

    /// TcTimer value for this peer (0 for default)
    pub tc_timer: u32,
}

/// Diameter statistics configuration
#[derive(Debug, Clone)]
pub struct DiameterStatsConfig {
    /// Frequency at which stats are updated (0 = default 60 seconds)
    pub interval_sec: u32,

    /// Size of private statistics structure
    pub priv_stats_size: usize,
}

impl Default for DiameterStatsConfig {
    fn default() -> Self {
        Self {
            interval_sec: 60,
            priv_stats_size: 0,
        }
    }
}
