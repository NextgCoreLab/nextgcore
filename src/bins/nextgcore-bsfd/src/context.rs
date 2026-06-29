//! BSF Context Management
//!
//! Port of src/bsf/context.c - BSF context with session management and IP address hashing

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use ogs_dbi::mongoc::{ogs_mongoc, DbiResult};

/// Maximum number of IP addresses for PCF
pub const MAX_NUM_OF_PCF_IP: usize = 8;

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

impl SNssai {
    pub fn new(sst: u8, sd: Option<u32>) -> Self {
        Self { sst, sd }
    }

    /// Create S-NSSAI from SST and SD values
    pub fn from_sst_sd(sst: u8, sd: u32) -> Self {
        let sd_opt = if sd == 0xFFFFFF { None } else { Some(sd) };
        Self { sst, sd: sd_opt }
    }

    /// Convert SD to string representation
    pub fn sd_to_string(&self) -> Option<String> {
        self.sd.map(|sd| format!("{sd:06X}"))
    }

    /// Parse SD from string
    pub fn sd_from_string(s: &str) -> Option<u32> {
        u32::from_str_radix(s, 16).ok()
    }
}

/// PCF IP endpoint information
#[derive(Debug, Clone, Default)]
pub struct PcfIpEndpoint {
    pub addr: Option<String>,
    pub addr6: Option<String>,
    pub is_port: bool,
    pub port: u16,
}

/// PCF for UE binding (TS 29.521 §4.2.2.3, pcf-ue-bindings resource).
/// Keyed by `binding_id`; discoverable by supi or gpsi.
#[derive(Debug, Clone)]
pub struct PcfUeBinding {
    pub binding_id: String,
    pub supi: Option<String>,
    pub gpsi: Option<String>,
    pub pcf_fqdn: Option<String>,
    pub pcf_ip: Vec<PcfIpEndpoint>,
    pub pcf_id: Option<String>,
    pub pcf_set_id: Option<String>,
    pub bind_level: Option<String>,
    pub recovery_time: Option<String>,
    pub pcf_diam_host: Option<String>,
    pub pcf_diam_realm: Option<String>,
    pub management_features: u64,
}

/// PCF for MBS binding (TS 29.521 §4.2.2.4, pcf-mbs-bindings resource).
/// Keyed by `binding_id`; discoverable by `mbs_session_id`.
#[derive(Debug, Clone)]
pub struct PcfMbsBinding {
    pub binding_id: String,
    /// Opaque MBS Session ID (TMGI or SSM form per TS 29.571).
    pub mbs_session_id: String,
    pub pcf_fqdn: Option<String>,
    pub pcf_ip: Vec<PcfIpEndpoint>,
    pub pcf_id: Option<String>,
    pub pcf_set_id: Option<String>,
    pub management_features: u64,
}

/// IPv6 prefix structure
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    pub len: u8,
    pub addr6: [u8; 16],
}

impl Ipv6Prefix {
    pub fn from_string(prefix_str: &str) -> Option<Self> {
        let parts: Vec<&str> = prefix_str.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let addr: Ipv6Addr = parts[0].parse().ok()?;
        let len: u8 = parts[1].parse().ok()?;

        Some(Self {
            len,
            addr6: addr.octets(),
        })
    }

    /// Get hash key bytes (prefix length / 8 + 1 bytes)
    pub fn hash_key(&self) -> Vec<u8> {
        let key_len = (self.len as usize >> 3) + 1;
        let mut key = vec![self.len];
        key.extend_from_slice(&self.addr6[..key_len.min(16)]);
        key
    }

    /// TS 29.521 §4.2.4.2: true when `addr` is within the address range covered
    /// by this prefix, i.e. the first `len` bits of `addr` equal the first `len`
    /// bits of the prefix. The final partial byte (when `len` is not a multiple
    /// of 8) is compared under a high-bit mask.
    pub fn contains(&self, addr: &Ipv6Addr) -> bool {
        let len = self.len as usize;
        if len > 128 {
            return false;
        }
        let octets = addr.octets();
        let full_bytes = len / 8;
        if self.addr6[..full_bytes] != octets[..full_bytes] {
            return false;
        }
        let rem_bits = len % 8;
        if rem_bits != 0 {
            let mask: u8 = 0xFFu8 << (8 - rem_bits);
            if (self.addr6[full_bytes] & mask) != (octets[full_bytes] & mask) {
                return false;
            }
        }
        true
    }

    /// True when the (typically /128) `query` prefix's address falls within this
    /// prefix. The query's own length is ignored; its address is treated as a
    /// single host address per the longest-prefix-match rule.
    pub fn contains_prefix(&self, query: &Ipv6Prefix) -> bool {
        self.contains(&Ipv6Addr::from(query.addr6))
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = Ipv6Addr::from(self.addr6);
        write!(f, "{addr}/{}", self.len)
    }
}

/// Parse an RFC 3339 date-time (e.g. `2026-06-12T10:00:00Z`,
/// `2026-06-12T10:00:00.5+02:00`) into Unix epoch seconds.
///
/// Implements the subset required by the TS 29.571 DateTime type without an
/// external date crate. Returns `None` on any malformed input.
pub fn rfc3339_to_epoch(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    // Optional fractional seconds (ignored)
    let mut idx = 19;
    if b.get(idx) == Some(&b'.') {
        idx += 1;
        let frac_start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == frac_start {
            return None;
        }
    }
    // Offset: Z or +HH:MM / -HH:MM
    let offset_secs: i64 = match b.get(idx)? {
        b'Z' | b'z' => {
            if idx + 1 != b.len() {
                return None;
            }
            0
        }
        sign @ (b'+' | b'-') => {
            if idx + 6 != b.len() || b[idx + 3] != b':' {
                return None;
            }
            let oh: i64 = s.get(idx + 1..idx + 3)?.parse().ok()?;
            let om: i64 = s.get(idx + 4..idx + 6)?.parse().ok()?;
            if oh > 23 || om > 59 {
                return None;
            }
            let total = oh * 3600 + om * 60;
            if *sign == b'+' {
                total
            } else {
                -total
            }
        }
        _ => return None,
    };
    // Days-from-civil (Howard Hinnant's algorithm)
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec - offset_secs)
}

/// Current Unix epoch seconds.
pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Normalize a MAC address to the TS 29.571 MacAddr48 canonical form
/// (lowercase, `-` separated). Returns `None` when the input is not a valid
/// 48-bit MAC address.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = if s.contains('-') {
        s.split('-').collect()
    } else {
        s.split(':').collect()
    };
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("-"),
    )
}

/// Discovery filter for TS 29.521 GET /pcfBindings query parameters.
#[derive(Debug, Clone, Default)]
pub struct BindingFilter {
    pub ipv4addr: Option<String>,
    pub ipv6prefix: Option<String>,
    pub mac_addr48: Option<String>,
    pub supi: Option<String>,
    pub gpsi: Option<String>,
    pub dnn: Option<String>,
    pub ip_domain: Option<String>,
    pub snssai: Option<SNssai>,
}

impl BindingFilter {
    /// At least one UE identity/address parameter must be present.
    pub fn has_ue_identifier(&self) -> bool {
        self.ipv4addr.is_some()
            || self.ipv6prefix.is_some()
            || self.mac_addr48.is_some()
            || self.supi.is_some()
            || self.gpsi.is_some()
    }

    /// TS 29.521 §4.2.4.2: a discovery query "shall include: UE address",
    /// where a UE address is one of `ipv4Addr` / `ipv6Prefix` / `macAddr48`.
    /// SUPI/GPSI/DNN/S-NSSAI are supplementary "may include" filters and do
    /// not by themselves satisfy the mandatory UE-address requirement.
    pub fn has_ue_address(&self) -> bool {
        self.ipv4addr.is_some() || self.ipv6prefix.is_some() || self.mac_addr48.is_some()
    }
}

/// Parse a discovery IPv6 query value into a host address, accepting both the
/// bare-address form (`2001:db8::1`) and the `addr/len` form (`2001:db8::1/128`)
/// the TS 29.521 spec describes ("formatted as … /128"). The prefix length, if
/// present, is ignored — the query is always treated as a single host address.
fn parse_query_ipv6(v: &str) -> Option<Ipv6Addr> {
    let addr_part = v.split('/').next().unwrap_or(v);
    addr_part.parse::<Ipv6Addr>().ok()
}

/// True when `addr` falls within the IPv4 CIDR `cidr` (`a.b.c.d/n`).
fn ipv4_in_cidr(addr: Ipv4Addr, cidr: &str) -> bool {
    let (net_str, len_str) = match cidr.split_once('/') {
        Some(parts) => parts,
        None => return cidr.parse::<Ipv4Addr>().map(|n| n == addr).unwrap_or(false),
    };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(len) = len_str.parse::<u8>() else {
        return false;
    };
    if len > 32 {
        return false;
    }
    let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

/// True when `addr` falls within the IPv6 CIDR `cidr` (`addr/len`).
fn ipv6_in_cidr(addr: &Ipv6Addr, cidr: &str) -> bool {
    Ipv6Prefix::from_string(cidr).is_some_and(|p| p.contains(addr))
}

/// BSF Session structure
/// Port of bsf_sess_t from context.h
#[derive(Debug, Clone)]
pub struct BsfSess {
    /// Session pool ID
    pub id: u64,
    /// Binding ID (string representation of pool index)
    pub binding_id: String,

    /// SUPI (Subscription Permanent Identifier)
    pub supi: Option<String>,
    /// GPSI (Generic Public Subscription Identifier)
    pub gpsi: Option<String>,

    /// IPv4 address string
    pub ipv4addr_string: Option<String>,
    /// IPv6 prefix string
    pub ipv6prefix_string: Option<String>,
    /// MAC address (TS 29.571 MacAddr48, canonical lowercase `-` form).
    /// Supports MAC-only bindings for Ethernet PDU sessions (no UE IP).
    pub mac_addr48: Option<String>,
    /// IPv4 address domain identifier (ipDomain)
    pub ip_domain: Option<String>,
    /// Binding expiry as RFC 3339 DateTime (TS 29.571 DateTime)
    pub expiry: Option<String>,
    /// Parsed expiry (Unix epoch seconds), derived from `expiry`
    pub expiry_epoch: Option<i64>,

    /// IPv4 frame route list
    pub ipv4_frame_route_list: Vec<String>,
    /// IPv6 frame route list
    pub ipv6_frame_route_list: Vec<String>,

    /// Parsed IPv4 address
    pub ipv4addr: Option<u32>,
    /// Parsed IPv6 prefix
    pub ipv6prefix: Option<Ipv6Prefix>,

    /// S-NSSAI
    pub s_nssai: SNssai,
    /// DNN (Data Network Name)
    pub dnn: Option<String>,

    /// PCF FQDN
    pub pcf_fqdn: Option<String>,
    /// PCF IP endpoints
    pub pcf_ip: Vec<PcfIpEndpoint>,
    /// PCF instance ID (TS 29.512 NF instance ID, bsfd-08)
    pub pcf_id: Option<String>,
    /// PCF set ID (bsfd-08)
    pub pcf_set_id: Option<String>,
    /// PCF binding level: NF_SET or NF_INSTANCE (bsfd-08)
    pub bind_level: Option<String>,
    /// PCF recovery time as RFC 3339 DateTime (TS 23.527, bsfd-08)
    pub recovery_time: Option<String>,
    /// PCF Diameter host for Rx interface (bsfd-08)
    pub pcf_diam_host: Option<String>,
    /// PCF Diameter realm for Rx interface (bsfd-08)
    pub pcf_diam_realm: Option<String>,

    /// SBI management features
    pub management_features: u64,
}

/// SBI feature flag for binding update
pub const SBI_NBSF_MANAGEMENT_BINDING_UPDATE: u64 = 1 << 0;

impl BsfSess {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            binding_id: id.to_string(),
            supi: None,
            gpsi: None,
            ipv4addr_string: None,
            ipv6prefix_string: None,
            mac_addr48: None,
            ip_domain: None,
            expiry: None,
            expiry_epoch: None,
            ipv4_frame_route_list: Vec::new(),
            ipv6_frame_route_list: Vec::new(),
            ipv4addr: None,
            ipv6prefix: None,
            s_nssai: SNssai::default(),
            dnn: None,
            pcf_fqdn: None,
            pcf_ip: Vec::new(),
            pcf_id: None,
            pcf_set_id: None,
            bind_level: None,
            recovery_time: None,
            pcf_diam_host: None,
            pcf_diam_realm: None,
            management_features: SBI_NBSF_MANAGEMENT_BINDING_UPDATE,
        }
    }

    /// Set IPv4 address from string
    pub fn set_ipv4addr(&mut self, ipv4addr_string: &str) -> bool {
        match ipv4addr_string.parse::<Ipv4Addr>() {
            Ok(addr) => {
                self.ipv4addr = Some(u32::from(addr));
                self.ipv4addr_string = Some(ipv4addr_string.to_string());
                true
            }
            Err(_) => {
                log::error!("Failed to parse IPv4 address: {ipv4addr_string}");
                false
            }
        }
    }

    /// Set IPv6 prefix from string
    pub fn set_ipv6prefix(&mut self, ipv6prefix_string: &str) -> bool {
        match Ipv6Prefix::from_string(ipv6prefix_string) {
            Some(prefix) => {
                self.ipv6prefix = Some(prefix);
                self.ipv6prefix_string = Some(ipv6prefix_string.to_string());
                true
            }
            None => {
                log::error!("Failed to parse IPv6 prefix: {ipv6prefix_string}");
                false
            }
        }
    }

    /// Set MAC address (normalized); returns false on invalid MAC.
    pub fn set_mac_addr48(&mut self, mac: &str) -> bool {
        match normalize_mac(mac) {
            Some(m) => {
                self.mac_addr48 = Some(m);
                true
            }
            None => {
                log::error!("Failed to parse MAC address: {mac}");
                false
            }
        }
    }

    /// Set expiry from an RFC 3339 DateTime; returns false on parse failure.
    pub fn set_expiry(&mut self, expiry: &str) -> bool {
        match rfc3339_to_epoch(expiry) {
            Some(epoch) => {
                self.expiry = Some(expiry.to_string());
                self.expiry_epoch = Some(epoch);
                true
            }
            None => {
                log::error!("Failed to parse RFC 3339 expiry: {expiry}");
                false
            }
        }
    }

    /// True when the binding has an expiry in the past.
    pub fn is_expired(&self, now: i64) -> bool {
        self.expiry_epoch.is_some_and(|e| e <= now)
    }

    /// TS 29.521 §4.2.4.2: true when an IPv4 query address is covered by any of
    /// this binding's `ipv4FrameRouteList` CIDRs.
    pub fn ipv4_in_frame_routes(&self, addr: Ipv4Addr) -> bool {
        self.ipv4_frame_route_list
            .iter()
            .any(|r| ipv4_in_cidr(addr, r))
    }

    /// TS 29.521 §4.2.4.2: true when an IPv6 query address is covered by any of
    /// this binding's `ipv6FrameRouteList` CIDRs.
    pub fn ipv6_in_frame_routes(&self, addr: &Ipv6Addr) -> bool {
        self.ipv6_frame_route_list
            .iter()
            .any(|r| ipv6_in_cidr(addr, r))
    }

    /// Longest prefix length (0..=128) by which this binding matches the IPv6
    /// query `addr`, considering both the primary UE prefix and any
    /// `ipv6FrameRouteList` route that contains it. Used for longest-prefix
    /// selection across candidate bindings (TS 29.521 §4.2.4.2).
    pub fn ipv6_best_match_len(&self, addr: &Ipv6Addr) -> Option<u8> {
        let mut best: Option<u8> = None;
        if let Some(ref p) = self.ipv6prefix {
            if p.contains(addr) {
                best = Some(best.map_or(p.len, |b| b.max(p.len)));
            }
        }
        for r in &self.ipv6_frame_route_list {
            if let Some(p) = Ipv6Prefix::from_string(r) {
                if p.contains(addr) {
                    best = Some(best.map_or(p.len, |b| b.max(p.len)));
                }
            }
        }
        best
    }

    /// True when this binding matches every provided discovery filter.
    ///
    /// IPv4/IPv6 addresses match either the binding's primary UE address (exact
    /// for IPv4, longest-prefix containment for IPv6) or any framed route. MAC
    /// and the remaining identity filters match exactly (DNN case-insensitively).
    pub fn matches(&self, f: &BindingFilter) -> bool {
        f.ipv4addr
            .as_deref()
            .is_none_or(|v| match v.parse::<Ipv4Addr>() {
                Ok(addr) => {
                    self.ipv4addr_string.as_deref() == Some(v) || self.ipv4_in_frame_routes(addr)
                }
                // Unparseable query: fall back to exact string comparison.
                Err(_) => self.ipv4addr_string.as_deref() == Some(v),
            })
            && f.ipv6prefix
                .as_deref()
                .is_none_or(|v| match parse_query_ipv6(v) {
                    Some(addr) => {
                        self.ipv6prefix.as_ref().is_some_and(|p| p.contains(&addr))
                            || self.ipv6_in_frame_routes(&addr)
                    }
                    // Unparseable query: fall back to exact string comparison.
                    None => self.ipv6prefix_string.as_deref() == Some(v),
                })
            && f.mac_addr48
                .as_deref()
                .is_none_or(|v| normalize_mac(v).as_deref() == self.mac_addr48.as_deref())
            && f.supi
                .as_deref()
                .is_none_or(|v| self.supi.as_deref() == Some(v))
            && f.gpsi
                .as_deref()
                .is_none_or(|v| self.gpsi.as_deref() == Some(v))
            && f.dnn.as_deref().is_none_or(|v| {
                self.dnn
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case(v))
            })
            && f.ip_domain
                .as_deref()
                .is_none_or(|v| self.ip_domain.as_deref() == Some(v))
            && f.snssai
                .as_ref()
                .is_none_or(|v| self.s_nssai.sst == v.sst && self.s_nssai.sd == v.sd)
    }

    /// Check if session has PCF IP information
    pub fn has_pcf_ip(&self) -> bool {
        !self.pcf_ip.is_empty()
    }

    /// Get number of PCF IP endpoints
    pub fn num_of_pcf_ip(&self) -> usize {
        self.pcf_ip.len()
    }
}

/// BSF Context - main context structure for BSF
/// Port of bsf_context_t from context.h
pub struct BsfContext {
    /// IPv4 address -> session ID hash
    ipv4addr_hash: RwLock<HashMap<u32, u64>>,
    /// IPv6 prefix -> session ID hash
    ipv6prefix_hash: RwLock<HashMap<Vec<u8>, u64>>,
    /// MAC address (canonical form) -> session ID hash
    mac_hash: RwLock<HashMap<String, u64>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, BsfSess>>,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// Maximum number of sessions (pool size)
    max_num_of_sess: usize,
    /// Context initialized flag
    initialized: AtomicBool,
    /// UE policy bindings (pcf-ue-bindings, keyed by binding_id, bsfd-11)
    ue_binding_list: RwLock<HashMap<String, PcfUeBinding>>,
    /// MBS bindings (pcf-mbs-bindings, keyed by binding_id, bsfd-12)
    mbs_binding_list: RwLock<HashMap<String, PcfMbsBinding>>,
}

impl BsfContext {
    pub fn new() -> Self {
        Self {
            ipv4addr_hash: RwLock::new(HashMap::new()),
            ipv6prefix_hash: RwLock::new(HashMap::new()),
            mac_hash: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            next_sess_id: AtomicUsize::new(1),
            max_num_of_sess: 0,
            initialized: AtomicBool::new(false),
            ue_binding_list: RwLock::new(HashMap::new()),
            mbs_binding_list: RwLock::new(HashMap::new()),
        }
    }

    pub fn init(&mut self, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_num_of_sess = max_sess;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("BSF context initialized with max {max_sess} sessions");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.sess_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("BSF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add session by IP address
    /// Port of bsf_sess_add_by_ip_address
    pub fn sess_add_by_ip_address(
        &self,
        ipv4addr_string: Option<&str>,
        ipv6prefix_string: Option<&str>,
    ) -> Option<BsfSess> {
        self.sess_add_binding(ipv4addr_string, ipv6prefix_string, None)
    }

    /// Add a session keyed by any combination of UE addresses.
    ///
    /// MAC-only bindings (Ethernet PDU sessions, no UE IP) are supported per
    /// TS 29.521 PcfBinding. At least one of ipv4/ipv6/MAC is required.
    pub fn sess_add_binding(
        &self,
        ipv4addr_string: Option<&str>,
        ipv6prefix_string: Option<&str>,
        mac_addr48: Option<&str>,
    ) -> Option<BsfSess> {
        if ipv4addr_string.is_none() && ipv6prefix_string.is_none() && mac_addr48.is_none() {
            log::error!("At least one of IPv4 address, IPv6 prefix, or MAC address is required");
            return None;
        }

        let mut sess_list = self.sess_list.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess {
            log::error!(
                "Maximum number of sessions [{}] reached",
                self.max_num_of_sess
            );
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut sess = BsfSess::new(id);

        // Set IPv4 address
        if let Some(ipv4) = ipv4addr_string {
            if !sess.set_ipv4addr(ipv4) {
                return None;
            }
            // Add to IPv4 hash
            if let (Ok(mut hash), Some(addr)) = (self.ipv4addr_hash.write(), sess.ipv4addr) {
                hash.insert(addr, id);
            }
        }

        // Set IPv6 prefix
        if let Some(ipv6) = ipv6prefix_string {
            if !sess.set_ipv6prefix(ipv6) {
                return None;
            }
            // Add to IPv6 hash
            if let (Ok(mut hash), Some(ref prefix)) =
                (self.ipv6prefix_hash.write(), &sess.ipv6prefix)
            {
                hash.insert(prefix.hash_key(), id);
            }
        }

        // Set MAC address
        if let Some(mac) = mac_addr48 {
            if !sess.set_mac_addr48(mac) {
                return None;
            }
            if let (Ok(mut hash), Some(ref m)) = (self.mac_hash.write(), &sess.mac_addr48) {
                hash.insert(m.clone(), id);
            }
        }

        sess_list.insert(id, sess.clone());
        log::debug!(
            "BSF session added (id={id}, ipv4={ipv4addr_string:?}, ipv6={ipv6prefix_string:?}, mac={mac_addr48:?})"
        );

        Some(sess)
    }

    /// Remove session
    pub fn sess_remove(&self, id: u64) -> Option<BsfSess> {
        let mut sess_list = self.sess_list.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
            // Remove from IPv4 hash
            if let (Ok(mut hash), Some(addr)) = (self.ipv4addr_hash.write(), sess.ipv4addr) {
                hash.remove(&addr);
            }
            // Remove from IPv6 hash
            if let (Ok(mut hash), Some(ref prefix)) =
                (self.ipv6prefix_hash.write(), &sess.ipv6prefix)
            {
                hash.remove(&prefix.hash_key());
            }
            // Remove from MAC hash
            if let (Ok(mut hash), Some(ref mac)) = (self.mac_hash.write(), &sess.mac_addr48) {
                hash.remove(mac);
            }
            log::debug!("BSF session removed (id={id})");
            return Some(sess);
        }
        None
    }

    /// Remove all sessions
    pub fn sess_remove_all(&self) {
        if let (Ok(mut sess_list), Ok(mut ipv4_hash), Ok(mut ipv6_hash), Ok(mut mac_hash)) = (
            self.sess_list.write(),
            self.ipv4addr_hash.write(),
            self.ipv6prefix_hash.write(),
            self.mac_hash.write(),
        ) {
            sess_list.clear();
            ipv4_hash.clear();
            ipv6_hash.clear();
            mac_hash.clear();
        }
        if let Ok(mut list) = self.ue_binding_list.write() {
            list.clear();
        }
        if let Ok(mut list) = self.mbs_binding_list.write() {
            list.clear();
        }
    }

    /// Find session by MAC address (any accepted format)
    pub fn sess_find_by_mac(&self, mac: &str) -> Option<BsfSess> {
        let canonical = normalize_mac(mac)?;
        let mac_hash = self.mac_hash.read().ok()?;
        let sess_id = *mac_hash.get(&canonical)?;
        drop(mac_hash);
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&sess_id).cloned()
    }

    /// Find all non-expired sessions matching a discovery filter (TS 29.521
    /// GET /pcfBindings query parameter combination).
    pub fn sess_find_matching(&self, filter: &BindingFilter, now: i64) -> Vec<BsfSess> {
        let sess_list = match self.sess_list.read() {
            Ok(l) => l,
            Err(_) => return Vec::new(),
        };
        let matches: Vec<BsfSess> = sess_list
            .values()
            .filter(|s| !s.is_expired(now) && s.matches(filter))
            .cloned()
            .collect();
        drop(sess_list);

        // TS 29.521 §4.2.4.2: for an IPv6 query, select the binding(s) with the
        // longest matching prefix. A single longest match wins (200); an
        // equal-length true multi-match is left for the caller to reject (400).
        if let Some(query) = filter.ipv6prefix.as_deref() {
            if let Some(addr) = parse_query_ipv6(query) {
                if matches.len() > 1 {
                    let scored: Vec<(Option<u8>, BsfSess)> = matches
                        .into_iter()
                        .map(|s| (s.ipv6_best_match_len(&addr), s))
                        .collect();
                    if let Some(max_len) = scored.iter().filter_map(|(l, _)| *l).max() {
                        return scored
                            .into_iter()
                            .filter(|(l, _)| *l == Some(max_len))
                            .map(|(_, s)| s)
                            .collect();
                    }
                    return scored.into_iter().map(|(_, s)| s).collect();
                }
            }
        }
        matches
    }

    /// Remove every expired binding; returns the removed binding ids so the
    /// caller can unpersist them (expired bindings excluded + swept).
    pub fn sweep_expired(&self, now: i64) -> Vec<String> {
        let expired: Vec<(u64, String)> = match self.sess_list.read() {
            Ok(list) => list
                .values()
                .filter(|s| s.is_expired(now))
                .map(|s| (s.id, s.binding_id.clone()))
                .collect(),
            Err(_) => return Vec::new(),
        };
        // Guard dropped above; remove each expired session (re-locks per id).
        let mut removed = Vec::with_capacity(expired.len());
        for (id, binding_id) in expired {
            if self.sess_remove(id).is_some() {
                log::info!("PCF Binding {binding_id} expired, swept");
                removed.push(binding_id);
            }
        }
        removed
    }

    /// Find session by pool index
    pub fn sess_find(&self, index: u64) -> Option<BsfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&index).cloned()
    }

    /// Find session by binding ID
    pub fn sess_find_by_binding_id(&self, binding_id: &str) -> Option<BsfSess> {
        let index: u64 = binding_id.parse().ok()?;
        self.sess_find(index)
    }

    /// Find session by IPv4 address string
    pub fn sess_find_by_ipv4addr(&self, ipv4addr_string: &str) -> Option<BsfSess> {
        let addr: Ipv4Addr = ipv4addr_string.parse().ok()?;
        let addr_u32 = u32::from(addr);

        let ipv4_hash = self.ipv4addr_hash.read().ok()?;
        let sess_id = ipv4_hash.get(&addr_u32)?;

        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(sess_id).cloned()
    }

    /// Find session by IPv6 prefix string
    pub fn sess_find_by_ipv6prefix(&self, ipv6prefix_string: &str) -> Option<BsfSess> {
        let prefix = Ipv6Prefix::from_string(ipv6prefix_string)?;
        let key = prefix.hash_key();

        let ipv6_hash = self.ipv6prefix_hash.read().ok()?;
        let sess_id = ipv6_hash.get(&key)?;

        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(sess_id).cloned()
    }

    /// Find session by S-NSSAI and DNN
    pub fn sess_find_by_snssai_and_dnn(&self, s_nssai: &SNssai, dnn: &str) -> Option<BsfSess> {
        let sess_list = self.sess_list.read().ok()?;
        for sess in sess_list.values() {
            if sess.s_nssai.sst == s_nssai.sst {
                if let Some(ref sess_dnn) = sess.dnn {
                    if sess_dnn.eq_ignore_ascii_case(dnn) {
                        return Some(sess.clone());
                    }
                }
            }
        }
        None
    }

    /// Update session in the context
    pub fn sess_update(&self, sess: &BsfSess) -> bool {
        if let Ok(mut sess_list) = self.sess_list.write() {
            if let Some(existing) = sess_list.get_mut(&sess.id) {
                *existing = sess.clone();
                return true;
            }
        }
        false
    }

    /// Set or clear a binding's UE IPv4 address, keeping the `ipv4addr_hash`
    /// lookup index consistent (bsfd-10).
    ///
    /// `Some(addr)` parses and sets the address, removing the old hash key and
    /// inserting the new one; `None` clears the address (and, per
    /// TS 29.521 §4.2.5.2, the dependent `ipDomain`) and drops the old hash key.
    /// Returns `false` only when a provided address fails to parse (the session
    /// is left unchanged in that case).
    pub fn set_ue_ipv4(&self, sess: &mut BsfSess, value: Option<&str>) -> bool {
        let old = sess.ipv4addr;
        match value {
            Some(v) => {
                if !sess.set_ipv4addr(v) {
                    return false;
                }
                if let Ok(mut hash) = self.ipv4addr_hash.write() {
                    if let Some(o) = old {
                        hash.remove(&o);
                    }
                    if let Some(addr) = sess.ipv4addr {
                        hash.insert(addr, sess.id);
                    }
                }
            }
            None => {
                sess.ipv4addr = None;
                sess.ipv4addr_string = None;
                // ipv4 removal also clears ipDomain (TS 29.521 §4.2.5.2).
                sess.ip_domain = None;
                if let (Ok(mut hash), Some(o)) = (self.ipv4addr_hash.write(), old) {
                    hash.remove(&o);
                }
            }
        }
        true
    }

    /// Set or clear a binding's UE IPv6 prefix, keeping the `ipv6prefix_hash`
    /// lookup index consistent (bsfd-10).
    pub fn set_ue_ipv6(&self, sess: &mut BsfSess, value: Option<&str>) -> bool {
        let old_key = sess.ipv6prefix.as_ref().map(|p| p.hash_key());
        match value {
            Some(v) => {
                if !sess.set_ipv6prefix(v) {
                    return false;
                }
                if let Ok(mut hash) = self.ipv6prefix_hash.write() {
                    if let Some(k) = old_key {
                        hash.remove(&k);
                    }
                    if let Some(ref p) = sess.ipv6prefix {
                        hash.insert(p.hash_key(), sess.id);
                    }
                }
            }
            None => {
                sess.ipv6prefix = None;
                sess.ipv6prefix_string = None;
                if let (Ok(mut hash), Some(k)) = (self.ipv6prefix_hash.write(), old_key) {
                    hash.remove(&k);
                }
            }
        }
        true
    }

    /// Set or clear a binding's UE MAC address, keeping the `mac_hash` lookup
    /// index consistent (bsfd-10).
    pub fn set_ue_mac(&self, sess: &mut BsfSess, value: Option<&str>) -> bool {
        let old = sess.mac_addr48.clone();
        match value {
            Some(v) => {
                if !sess.set_mac_addr48(v) {
                    return false;
                }
                if let Ok(mut hash) = self.mac_hash.write() {
                    if let Some(ref o) = old {
                        hash.remove(o);
                    }
                    if let Some(ref m) = sess.mac_addr48 {
                        hash.insert(m.clone(), sess.id);
                    }
                }
            }
            None => {
                sess.mac_addr48 = None;
                if let (Ok(mut hash), Some(ref o)) = (self.mac_hash.write(), old) {
                    hash.remove(o);
                }
            }
        }
        true
    }

    /// Get session load percentage
    pub fn get_sess_load(&self) -> i32 {
        let sess_count = self.sess_list.read().map(|l| l.len()).unwrap_or(0);
        if self.max_num_of_sess == 0 {
            return 0;
        }
        ((sess_count * 100) / self.max_num_of_sess) as i32
    }

    /// Get session count
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ------------------------------------------------------------------
    // bsfd-07: duplicate detection for SamePcf feature
    // ------------------------------------------------------------------

    /// Find a PDU-session binding with matching dnn + snssai + supi (used by
    /// the SamePcf duplicate-detection check in `handle_pcf_binding_create`).
    pub fn sess_find_by_dnn_snssai_supi(
        &self,
        dnn: &str,
        snssai: &SNssai,
        supi: &str,
    ) -> Option<BsfSess> {
        let sess_list = self.sess_list.read().ok()?;
        for sess in sess_list.values() {
            if sess
                .dnn
                .as_deref()
                .is_some_and(|d| d.eq_ignore_ascii_case(dnn))
                && sess.s_nssai.sst == snssai.sst
                && sess.s_nssai.sd == snssai.sd
                && sess.supi.as_deref() == Some(supi)
            {
                return Some(sess.clone());
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // bsfd-11: pcf-ue-bindings CRUD
    // ------------------------------------------------------------------

    pub fn ue_binding_add(&self, binding: PcfUeBinding) {
        if let Ok(mut list) = self.ue_binding_list.write() {
            list.insert(binding.binding_id.clone(), binding);
        }
    }

    pub fn ue_binding_find_by_id(&self, id: &str) -> Option<PcfUeBinding> {
        let list = self.ue_binding_list.read().ok()?;
        list.get(id).cloned()
    }

    /// Return all UE bindings whose supi/gpsi match the provided filters
    /// (None means "no filter on this field").
    pub fn ue_binding_find_matching(
        &self,
        supi: Option<&str>,
        gpsi: Option<&str>,
    ) -> Vec<PcfUeBinding> {
        match self.ue_binding_list.read() {
            Ok(list) => list
                .values()
                .filter(|b| {
                    supi.is_none_or(|s| b.supi.as_deref() == Some(s))
                        && gpsi.is_none_or(|g| b.gpsi.as_deref() == Some(g))
                })
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn ue_binding_remove(&self, id: &str) -> Option<PcfUeBinding> {
        self.ue_binding_list.write().ok()?.remove(id)
    }

    pub fn ue_binding_update(&self, binding: &PcfUeBinding) -> bool {
        if let Ok(mut list) = self.ue_binding_list.write() {
            if let Some(existing) = list.get_mut(&binding.binding_id) {
                *existing = binding.clone();
                return true;
            }
        }
        false
    }

    // ------------------------------------------------------------------
    // bsfd-12: pcf-mbs-bindings CRUD
    // ------------------------------------------------------------------

    pub fn mbs_binding_add(&self, binding: PcfMbsBinding) {
        if let Ok(mut list) = self.mbs_binding_list.write() {
            list.insert(binding.binding_id.clone(), binding);
        }
    }

    pub fn mbs_binding_find_by_id(&self, id: &str) -> Option<PcfMbsBinding> {
        let list = self.mbs_binding_list.read().ok()?;
        list.get(id).cloned()
    }

    /// Return all MBS bindings keyed by the given mbs_session_id.
    /// TS 29.521 §4.2.2.4: a duplicate is 403; multi-match is 400.
    pub fn mbs_binding_find_by_mbs_session_id(
        &self,
        mbs_session_id: &str,
    ) -> Vec<PcfMbsBinding> {
        match self.mbs_binding_list.read() {
            Ok(list) => list
                .values()
                .filter(|b| b.mbs_session_id == mbs_session_id)
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn mbs_binding_remove(&self, id: &str) -> Option<PcfMbsBinding> {
        self.mbs_binding_list.write().ok()?.remove(id)
    }

    pub fn mbs_binding_update(&self, binding: &PcfMbsBinding) -> bool {
        if let Ok(mut list) = self.mbs_binding_list.write() {
            if let Some(existing) = list.get_mut(&binding.binding_id) {
                *existing = binding.clone();
                return true;
            }
        }
        false
    }
}

impl BsfContext {
    /// Install a binding loaded from the database (startup restore path).
    ///
    /// Re-populates every lookup hash (including MAC) and advances the
    /// session-id allocator past the loaded id to avoid collisions.
    pub fn install_loaded_binding(&self, sess: BsfSess) {
        let id = sess.id;
        if let (Ok(mut ipv4_hash), Some(addr)) = (self.ipv4addr_hash.write(), sess.ipv4addr) {
            ipv4_hash.insert(addr, id);
        }
        if let (Ok(mut ipv6_hash), Some(ref prefix)) =
            (self.ipv6prefix_hash.write(), &sess.ipv6prefix)
        {
            ipv6_hash.insert(prefix.hash_key(), id);
        }
        if let (Ok(mut mac_hash), Some(ref mac)) = (self.mac_hash.write(), &sess.mac_addr48) {
            mac_hash.insert(mac.clone(), id);
        }
        if let Ok(mut sess_list) = self.sess_list.write() {
            sess_list.insert(id, sess);
        }
        // Keep the allocator ahead of restored ids.
        let mut current = self.next_sess_id.load(Ordering::SeqCst);
        while current <= id as usize {
            match self.next_sess_id.compare_exchange(
                current,
                id as usize + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
}

/// Get the BSF bindings collection from MongoDB
fn get_bsf_bindings_collection(
) -> DbiResult<ogs_dbi::mongodb::sync::Collection<ogs_dbi::mongodb::bson::Document>> {
    let dbi = ogs_mongoc();
    let dbi_guard = dbi.lock().unwrap();
    let db = dbi_guard
        .mongoc
        .database
        .as_ref()
        .ok_or(ogs_dbi::DbiError::NotInitialized)?;
    Ok(db.collection("bsf_bindings"))
}

/// Convert a session to its MongoDB document representation.
///
/// Pure function (no I/O) so the round-trip can be unit-tested without a
/// database. Persists pcfIpEndPoints, MAC, ipDomain, and expiry so
/// bindings survive BSF restarts intact.
pub fn sess_to_doc(sess: &BsfSess) -> ogs_dbi::mongodb::bson::Document {
    use ogs_dbi::mongodb::bson::{doc, Bson, Document};

    let mut d = doc! {
        "binding_id": &sess.binding_id,
        "id": sess.id as i64,
    };
    if let Some(ref supi) = sess.supi {
        d.insert("supi", supi);
    }
    if let Some(ref gpsi) = sess.gpsi {
        d.insert("gpsi", gpsi);
    }
    if let Some(ref ipv4) = sess.ipv4addr_string {
        d.insert("ipv4Addr", ipv4);
    }
    if let Some(ref ipv6) = sess.ipv6prefix_string {
        d.insert("ipv6Prefix", ipv6);
    }
    if let Some(ref mac) = sess.mac_addr48 {
        d.insert("macAddr48", mac);
    }
    if let Some(ref ip_domain) = sess.ip_domain {
        d.insert("ipDomain", ip_domain);
    }
    if let Some(ref expiry) = sess.expiry {
        d.insert("expiry", expiry);
    }
    if let Some(ref dnn) = sess.dnn {
        d.insert("dnn", dnn);
    }
    d.insert("sst", sess.s_nssai.sst as i32);
    if let Some(sd) = sess.s_nssai.sd {
        d.insert("sd", sd as i64);
    }
    if let Some(ref pcf_fqdn) = sess.pcf_fqdn {
        d.insert("pcf_fqdn", pcf_fqdn);
    }
    if let Some(ref v) = sess.pcf_id {
        d.insert("pcf_id", v);
    }
    if let Some(ref v) = sess.pcf_set_id {
        d.insert("pcf_set_id", v);
    }
    if let Some(ref v) = sess.bind_level {
        d.insert("bind_level", v);
    }
    if let Some(ref v) = sess.recovery_time {
        d.insert("recovery_time", v);
    }
    if let Some(ref v) = sess.pcf_diam_host {
        d.insert("pcf_diam_host", v);
    }
    if let Some(ref v) = sess.pcf_diam_realm {
        d.insert("pcf_diam_realm", v);
    }
    if !sess.pcf_ip.is_empty() {
        let endpoints: Vec<Bson> = sess
            .pcf_ip
            .iter()
            .map(|ep| {
                let mut e = Document::new();
                if let Some(ref a) = ep.addr {
                    e.insert("ipv4Address", a);
                }
                if let Some(ref a6) = ep.addr6 {
                    e.insert("ipv6Address", a6);
                }
                if ep.is_port {
                    e.insert("port", ep.port as i32);
                }
                Bson::Document(e)
            })
            .collect();
        d.insert("pcfIpEndPoints", endpoints);
    }
    d
}

/// Reconstruct a session from its MongoDB document representation.
pub fn doc_to_sess(doc: &ogs_dbi::mongodb::bson::Document) -> BsfSess {
    let id = doc.get_i64("id").unwrap_or(0) as u64;
    let mut sess = BsfSess::new(id);

    if let Ok(binding_id) = doc.get_str("binding_id") {
        sess.binding_id = binding_id.to_string();
    }
    if let Ok(supi) = doc.get_str("supi") {
        sess.supi = Some(supi.to_string());
    }
    if let Ok(gpsi) = doc.get_str("gpsi") {
        sess.gpsi = Some(gpsi.to_string());
    }
    if let Ok(ipv4) = doc.get_str("ipv4Addr") {
        sess.set_ipv4addr(ipv4);
    }
    if let Ok(ipv6) = doc.get_str("ipv6Prefix") {
        sess.set_ipv6prefix(ipv6);
    }
    if let Ok(mac) = doc.get_str("macAddr48") {
        sess.set_mac_addr48(mac);
    }
    if let Ok(ip_domain) = doc.get_str("ipDomain") {
        sess.ip_domain = Some(ip_domain.to_string());
    }
    if let Ok(expiry) = doc.get_str("expiry") {
        sess.set_expiry(expiry);
    }
    if let Ok(dnn) = doc.get_str("dnn") {
        sess.dnn = Some(dnn.to_string());
    }
    if let Ok(sst) = doc.get_i32("sst") {
        sess.s_nssai.sst = sst as u8;
    }
    if let Ok(sd) = doc.get_i64("sd") {
        sess.s_nssai.sd = Some(sd as u32);
    }
    if let Ok(pcf_fqdn) = doc.get_str("pcf_fqdn") {
        sess.pcf_fqdn = Some(pcf_fqdn.to_string());
    }
    if let Ok(v) = doc.get_str("pcf_id") {
        sess.pcf_id = Some(v.to_string());
    }
    if let Ok(v) = doc.get_str("pcf_set_id") {
        sess.pcf_set_id = Some(v.to_string());
    }
    if let Ok(v) = doc.get_str("bind_level") {
        sess.bind_level = Some(v.to_string());
    }
    if let Ok(v) = doc.get_str("recovery_time") {
        sess.recovery_time = Some(v.to_string());
    }
    if let Ok(v) = doc.get_str("pcf_diam_host") {
        sess.pcf_diam_host = Some(v.to_string());
    }
    if let Ok(v) = doc.get_str("pcf_diam_realm") {
        sess.pcf_diam_realm = Some(v.to_string());
    }
    if let Ok(endpoints) = doc.get_array("pcfIpEndPoints") {
        sess.pcf_ip = endpoints
            .iter()
            .filter_map(|b| b.as_document())
            .map(|e| PcfIpEndpoint {
                addr: e.get_str("ipv4Address").ok().map(|s| s.to_string()),
                addr6: e.get_str("ipv6Address").ok().map(|s| s.to_string()),
                is_port: e.get_i32("port").is_ok(),
                port: e.get_i32("port").unwrap_or(0) as u16,
            })
            .collect();
    }
    sess
}

/// Upsert a BSF binding to MongoDB
fn bsf_db_upsert_binding(sess: &BsfSess) -> DbiResult<()> {
    let collection = get_bsf_bindings_collection()?;
    let filter = ogs_dbi::mongodb::bson::doc! { "binding_id": &sess.binding_id };
    let doc = sess_to_doc(sess);

    let opts = ogs_dbi::mongodb::options::ReplaceOptions::builder()
        .upsert(true)
        .build();
    collection.replace_one(filter, doc, opts)?;

    log::debug!("BSF binding {} persisted to DB", sess.binding_id);
    Ok(())
}

/// Delete a BSF binding from MongoDB
fn bsf_db_delete_binding(binding_id: &str) -> DbiResult<()> {
    let collection = get_bsf_bindings_collection()?;
    let filter = ogs_dbi::mongodb::bson::doc! { "binding_id": binding_id };
    collection.delete_one(filter, None)?;
    log::debug!("BSF binding {binding_id} removed from DB");
    Ok(())
}

/// Load all BSF bindings from MongoDB
fn bsf_db_load_all_bindings() -> DbiResult<Vec<BsfSess>> {
    let collection = get_bsf_bindings_collection()?;
    let cursor = collection.find(ogs_dbi::mongodb::bson::doc! {}, None)?;

    let mut bindings = Vec::new();
    for result in cursor {
        bindings.push(doc_to_sess(&result?));
    }
    Ok(bindings)
}

// ---------------------------------------------------------------------------
// Async persistence wrappers (sync -> async Mongo)
//
// The mongodb sync driver blocks; calling it from SBI handlers stalls the
// tokio runtime. These wrappers offload to `tokio::task::spawn_blocking`,
// mirroring the ogs-dbi `*_async` pattern. Failures are logged at debug level
// (DB persistence is best-effort; bindings remain in memory).
// ---------------------------------------------------------------------------

/// Persist a binding off-thread.
pub async fn persist_binding_async(sess: BsfSess) {
    let binding_id = sess.binding_id.clone();
    let result = tokio::task::spawn_blocking(move || bsf_db_upsert_binding(&sess)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::debug!("DB persistence unavailable for {binding_id}: {e}"),
        Err(e) => log::warn!("persist_binding_async join error: {e}"),
    }
}

/// Remove a persisted binding off-thread.
pub async fn unpersist_binding_async(binding_id: String) {
    let id = binding_id.clone();
    let result = tokio::task::spawn_blocking(move || bsf_db_delete_binding(&id)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::debug!("DB persistence unavailable for delete {binding_id}: {e}"),
        Err(e) => log::warn!("unpersist_binding_async join error: {e}"),
    }
}

/// Load persisted bindings off-thread and install them into the context.
pub async fn load_persisted_bindings_async() {
    let result = tokio::task::spawn_blocking(bsf_db_load_all_bindings).await;
    match result {
        Ok(Ok(bindings)) => {
            let count = bindings.len();
            let ctx = bsf_self();
            if let Ok(context) = ctx.read() {
                for sess in bindings {
                    context.install_loaded_binding(sess);
                }
            };
            log::info!("Loaded {count} persisted BSF bindings from database");
        }
        Ok(Err(e)) => log::debug!("No persisted bindings loaded (DB unavailable): {e}"),
        Err(e) => log::warn!("load_persisted_bindings_async join error: {e}"),
    }
}

impl Default for BsfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global BSF context (thread-safe singleton)
static GLOBAL_BSF_CONTEXT: std::sync::OnceLock<Arc<RwLock<BsfContext>>> =
    std::sync::OnceLock::new();

/// Get the global BSF context
pub fn bsf_self() -> Arc<RwLock<BsfContext>> {
    GLOBAL_BSF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(BsfContext::new())))
        .clone()
}

/// Initialize the global BSF context
pub fn bsf_context_init(max_sess: usize) {
    let ctx = bsf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_sess);
    };
}

/// Finalize the global BSF context
pub fn bsf_context_final() {
    let ctx = bsf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

/// Get session load (for NF instance load reporting)
pub fn get_sess_load() -> i32 {
    let ctx = bsf_self();
    if let Ok(context) = ctx.read() {
        return context.get_sess_load();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsf_context_new() {
        let ctx = BsfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_bsf_context_init_fini() {
        let mut ctx = BsfContext::new();
        ctx.init(100);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_sess_add_by_ipv4() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx
            .sess_add_by_ip_address(Some("192.168.1.1"), None)
            .unwrap();
        assert_eq!(sess.ipv4addr_string, Some("192.168.1.1".to_string()));
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_ipv4addr("192.168.1.1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, sess.id);
    }

    #[test]
    fn test_sess_add_by_ipv6() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx
            .sess_add_by_ip_address(None, Some("2001:db8::1/128"))
            .unwrap();
        assert_eq!(sess.ipv6prefix_string, Some("2001:db8::1/128".to_string()));
        assert_eq!(ctx.sess_count(), 1);

        let found = ctx.sess_find_by_ipv6prefix("2001:db8::1/128");
        assert!(found.is_some());
    }

    #[test]
    fn test_sess_add_by_both() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx
            .sess_add_by_ip_address(Some("10.0.0.1"), Some("fd00::1/128"))
            .unwrap();

        assert!(sess.ipv4addr_string.is_some());
        assert!(sess.ipv6prefix_string.is_some());
    }

    #[test]
    fn test_sess_remove() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx
            .sess_add_by_ip_address(Some("192.168.1.1"), None)
            .unwrap();
        assert_eq!(ctx.sess_count(), 1);

        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);

        let found = ctx.sess_find_by_ipv4addr("192.168.1.1");
        assert!(found.is_none());
    }

    #[test]
    fn test_sess_find_by_binding_id() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx
            .sess_add_by_ip_address(Some("192.168.1.1"), None)
            .unwrap();
        let binding_id = sess.binding_id.clone();

        let found = ctx.sess_find_by_binding_id(&binding_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, sess.id);
    }

    #[test]
    fn test_get_sess_load() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        assert_eq!(ctx.get_sess_load(), 0);

        // Add 10 sessions
        for i in 0..10 {
            ctx.sess_add_by_ip_address(Some(&format!("192.168.1.{i}")), None);
        }

        assert_eq!(ctx.get_sess_load(), 10); // 10/100 = 10%
    }

    #[test]
    fn test_snssai() {
        let s1 = SNssai::new(1, Some(0x010203));
        let s2 = SNssai::from_sst_sd(1, 0x010203);
        assert_eq!(s1, s2);

        let s3 = SNssai::from_sst_sd(1, 0xFFFFFF);
        assert_eq!(s3.sd, None);

        assert_eq!(s1.sd_to_string(), Some("010203".to_string()));
    }

    #[test]
    fn test_ipv6_prefix() {
        let prefix = Ipv6Prefix::from_string("2001:db8::1/64").unwrap();
        assert_eq!(prefix.len, 64);

        let prefix_str = prefix.to_string();
        assert!(prefix_str.contains("/64"));
    }

    #[test]
    fn test_bsf_sess_set_ipv4addr() {
        let mut sess = BsfSess::new(1);
        assert!(sess.set_ipv4addr("192.168.1.1"));
        assert_eq!(sess.ipv4addr_string, Some("192.168.1.1".to_string()));
        assert!(sess.ipv4addr.is_some());
    }

    #[test]
    fn test_bsf_sess_set_ipv6prefix() {
        let mut sess = BsfSess::new(1);
        assert!(sess.set_ipv6prefix("2001:db8::1/128"));
        assert_eq!(sess.ipv6prefix_string, Some("2001:db8::1/128".to_string()));
        assert!(sess.ipv6prefix.is_some());
    }

    #[test]
    fn test_rfc3339_to_epoch() {
        // Reference: 2026-06-12T00:00:00Z = 1781222400
        assert_eq!(rfc3339_to_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_to_epoch("2026-06-12T00:00:00Z"), Some(1781222400));
        // Fractional seconds ignored
        assert_eq!(
            rfc3339_to_epoch("2026-06-12T00:00:00.500Z"),
            Some(1781222400)
        );
        // Positive offset subtracts
        assert_eq!(
            rfc3339_to_epoch("2026-06-12T02:00:00+02:00"),
            Some(1781222400)
        );
        // Negative offset adds
        assert_eq!(
            rfc3339_to_epoch("2026-06-11T22:00:00-02:00"),
            Some(1781222400)
        );
        // Malformed inputs
        assert_eq!(rfc3339_to_epoch("3600"), None);
        assert_eq!(rfc3339_to_epoch("2026-06-12 00:00:00Z"), None);
        assert_eq!(rfc3339_to_epoch("2026-13-12T00:00:00Z"), None);
        assert_eq!(rfc3339_to_epoch("2026-06-12T00:00:00"), None);
        assert_eq!(rfc3339_to_epoch("2026-06-12T00:00:00+0200"), None);
    }

    #[test]
    fn test_normalize_mac() {
        assert_eq!(
            normalize_mac("00:1B:44:11:3A:B7"),
            Some("00-1b-44-11-3a-b7".to_string())
        );
        assert_eq!(
            normalize_mac("00-1b-44-11-3a-b7"),
            Some("00-1b-44-11-3a-b7".to_string())
        );
        assert_eq!(normalize_mac("00:1B:44:11:3A"), None);
        assert_eq!(normalize_mac("00:1B:44:11:3A:ZZ"), None);
        assert_eq!(normalize_mac("not-a-mac"), None);
    }

    #[test]
    fn test_mac_only_binding() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        // MAC-only binding (no UE IP) is valid per TS 29.521 PcfBinding.
        let sess = ctx
            .sess_add_binding(None, None, Some("00:1B:44:11:3A:B7"))
            .unwrap();
        assert!(sess.ipv4addr_string.is_none());
        assert_eq!(sess.mac_addr48, Some("00-1b-44-11-3a-b7".to_string()));

        // Lookup works with either separator/case.
        assert!(ctx.sess_find_by_mac("00-1B-44-11-3A-B7").is_some());
        assert!(ctx.sess_find_by_mac("00:1b:44:11:3a:b7").is_some());
        assert!(ctx.sess_find_by_mac("ff:ff:ff:ff:ff:ff").is_none());

        // Removal cleans the MAC hash.
        ctx.sess_remove(sess.id);
        assert!(ctx.sess_find_by_mac("00-1b-44-11-3a-b7").is_none());

        // No address at all is rejected.
        assert!(ctx.sess_add_binding(None, None, None).is_none());
    }

    #[test]
    fn test_binding_filter_matching() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx
            .sess_add_binding(Some("10.45.0.2"), None, Some("aa:bb:cc:dd:ee:ff"))
            .unwrap();
        let mut sess = sess;
        sess.supi = Some("imsi-001010000000001".to_string());
        sess.dnn = Some("internet".to_string());
        sess.s_nssai = SNssai::new(1, Some(0x010203));
        ctx.sess_update(&sess);

        let now = 1_000_000;
        // SUPI-only is a UE *identifier* but NOT a UE *address* (bsfd-02):
        // such a query is rejected 400 by the discovery handler, though the
        // matcher itself still narrows correctly when combined with a UE address.
        let mut f = BindingFilter {
            supi: Some("imsi-001010000000001".to_string()),
            dnn: Some("INTERNET".to_string()), // case-insensitive DNN
            ..Default::default()
        };
        assert!(f.has_ue_identifier());
        assert!(!f.has_ue_address());
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);

        f.snssai = Some(SNssai::new(1, Some(0x010203)));
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);
        f.snssai = Some(SNssai::new(2, None));
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 0);

        let f = BindingFilter {
            mac_addr48: Some("AA-BB-CC-DD-EE-FF".to_string()),
            ..Default::default()
        };
        assert!(f.has_ue_address());
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);

        // ipv4 alone is a UE address; supi/gpsi alone is not.
        assert!(BindingFilter {
            ipv4addr: Some("10.45.0.2".to_string()),
            ..Default::default()
        }
        .has_ue_address());
        assert!(!BindingFilter {
            gpsi: Some("msisdn-1".to_string()),
            ..Default::default()
        }
        .has_ue_address());

        let f = BindingFilter::default();
        assert!(!f.has_ue_identifier());
        assert!(!f.has_ue_address());
    }

    #[test]
    fn test_ipv6_prefix_contains() {
        let p64 = Ipv6Prefix::from_string("2001:db8::/64").unwrap();
        assert!(p64.contains(&"2001:db8::1".parse().unwrap()));
        assert!(p64.contains(&"2001:db8:0:0:ffff::1".parse().unwrap()));
        assert!(!p64.contains(&"2001:db9::1".parse().unwrap()));

        // Non-byte-aligned prefix length masks the final partial byte. /60
        // fixes the first 60 bits, i.e. group3 in the range 0a00..=0a0f.
        let p60 = Ipv6Prefix::from_string("2001:db8:0:0a00::/60").unwrap();
        assert!(p60.contains(&"2001:db8:0:0a0f::5".parse().unwrap()));
        assert!(!p60.contains(&"2001:db8:0:0a10::5".parse().unwrap()));
        assert!(!p60.contains(&"2001:db8:0:0b00::5".parse().unwrap()));

        // contains_prefix treats a /128 query as a host address.
        let q = Ipv6Prefix::from_string("2001:db8::1/128").unwrap();
        assert!(p64.contains_prefix(&q));
    }

    #[test]
    fn test_binding_filter_ipv6_prefix_match() {
        let mut ctx = BsfContext::new();
        ctx.init(100);
        let _ = ctx
            .sess_add_by_ip_address(None, Some("2001:db8::/64"))
            .unwrap();
        let now = 1_000_000;

        // /128 query inside the stored /64 matches.
        let f = BindingFilter {
            ipv6prefix: Some("2001:db8::1/128".to_string()),
            ..Default::default()
        };
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);

        // Bare-address form also matches.
        let f = BindingFilter {
            ipv6prefix: Some("2001:db8::abcd".to_string()),
            ..Default::default()
        };
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);

        // Out-of-prefix query does not match.
        let f = BindingFilter {
            ipv6prefix: Some("2001:db9::1/128".to_string()),
            ..Default::default()
        };
        assert!(ctx.sess_find_matching(&f, now).is_empty());
    }

    #[test]
    fn test_longest_prefix_selection() {
        let mut ctx = BsfContext::new();
        ctx.init(100);
        // Two nested prefixes covering the same base address: the /64 is the
        // longest match, nested inside the broader /32.
        ctx.sess_add_by_ip_address(None, Some("2001:db8::/32"))
            .unwrap();
        let specific = ctx
            .sess_add_by_ip_address(None, Some("2001:db8::/64"))
            .unwrap();
        let now = 1_000_000;

        // Query inside both prefixes: the longest (/64) wins -> single result.
        let f = BindingFilter {
            ipv6prefix: Some("2001:db8::5/128".to_string()),
            ..Default::default()
        };
        let found = ctx.sess_find_matching(&f, now);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, specific.id);

        // Query inside only the broader /32 (4th hextet != 0): single result.
        let f = BindingFilter {
            ipv6prefix: Some("2001:db8:0:1::5/128".to_string()),
            ..Default::default()
        };
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);
    }

    #[test]
    fn test_framed_route_match() {
        let mut ctx = BsfContext::new();
        ctx.init(100);
        let sess = ctx.sess_add_by_ip_address(Some("10.45.0.2"), None).unwrap();
        let mut sess = sess;
        sess.ipv4_frame_route_list = vec!["10.0.0.0/24".to_string()];
        sess.ipv6_frame_route_list = vec!["2001:dbf::/48".to_string()];
        ctx.sess_update(&sess);
        let now = 1_000_000;

        // IPv4 inside the framed route matches even though it is not the
        // binding's primary UE address.
        let f = BindingFilter {
            ipv4addr: Some("10.0.0.5".to_string()),
            ..Default::default()
        };
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);
        // Outside the route: no match.
        let f = BindingFilter {
            ipv4addr: Some("10.1.0.5".to_string()),
            ..Default::default()
        };
        assert!(ctx.sess_find_matching(&f, now).is_empty());

        // IPv6 inside the framed route matches.
        let f = BindingFilter {
            ipv6prefix: Some("2001:dbf::1234/128".to_string()),
            ..Default::default()
        };
        assert_eq!(ctx.sess_find_matching(&f, now).len(), 1);
    }

    #[test]
    fn test_context_rekey_ipv4() {
        let mut ctx = BsfContext::new();
        ctx.init(100);
        let mut sess = ctx.sess_add_by_ip_address(Some("10.45.1.1"), None).unwrap();
        sess.ip_domain = Some("domain1".to_string());
        ctx.sess_update(&sess);
        assert!(ctx.sess_find_by_ipv4addr("10.45.1.1").is_some());

        // Change A -> B: hash follows.
        assert!(ctx.set_ue_ipv4(&mut sess, Some("10.45.1.2")));
        ctx.sess_update(&sess);
        assert!(ctx.sess_find_by_ipv4addr("10.45.1.1").is_none());
        assert!(ctx.sess_find_by_ipv4addr("10.45.1.2").is_some());

        // Clear: hash key dropped and ipDomain cleared.
        assert!(ctx.set_ue_ipv4(&mut sess, None));
        ctx.sess_update(&sess);
        assert!(ctx.sess_find_by_ipv4addr("10.45.1.2").is_none());
        assert!(sess.ip_domain.is_none());
        assert!(sess.ipv4addr_string.is_none());

        // Invalid address leaves the session unchanged.
        let mut s2 = ctx.sess_add_by_ip_address(Some("10.45.1.3"), None).unwrap();
        assert!(!ctx.set_ue_ipv4(&mut s2, Some("not-an-ip")));
        assert_eq!(s2.ipv4addr_string.as_deref(), Some("10.45.1.3"));
    }

    #[test]
    fn test_context_rekey_ipv6_and_mac() {
        let mut ctx = BsfContext::new();
        ctx.init(100);
        let mut sess = ctx
            .sess_add_binding(None, Some("2001:db8::/64"), Some("aa:bb:cc:dd:ee:01"))
            .unwrap();

        // Re-key IPv6 prefix.
        assert!(ctx.set_ue_ipv6(&mut sess, Some("2001:db8:1::/64")));
        ctx.sess_update(&sess);
        assert!(ctx.sess_find_by_ipv6prefix("2001:db8::/64").is_none());
        assert!(ctx.sess_find_by_ipv6prefix("2001:db8:1::/64").is_some());

        // Clear MAC: mac_hash drops the key.
        assert!(ctx.set_ue_mac(&mut sess, None));
        ctx.sess_update(&sess);
        assert!(ctx.sess_find_by_mac("aa-bb-cc-dd-ee-01").is_none());
        assert!(sess.mac_addr48.is_none());
    }

    #[test]
    fn test_expiry_exclusion_and_sweep() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx.sess_add_binding(Some("10.45.0.3"), None, None).unwrap();
        let mut sess = sess;
        assert!(sess.set_expiry("2026-01-01T00:00:00Z"));
        ctx.sess_update(&sess);

        let live = ctx.sess_add_binding(Some("10.45.0.4"), None, None).unwrap();

        // After expiry: expired binding excluded from discovery.
        let now = rfc3339_to_epoch("2026-02-01T00:00:00Z").unwrap();
        let f = BindingFilter {
            ipv4addr: Some("10.45.0.3".to_string()),
            ..Default::default()
        };
        assert!(ctx.sess_find_matching(&f, now).is_empty());
        // Before expiry it is discoverable.
        let before = rfc3339_to_epoch("2025-12-01T00:00:00Z").unwrap();
        assert_eq!(ctx.sess_find_matching(&f, before).len(), 1);

        // Sweep removes only the expired binding.
        let swept = ctx.sweep_expired(now);
        assert_eq!(swept, vec![sess.binding_id.clone()]);
        assert_eq!(ctx.sess_count(), 1);
        assert!(ctx.sess_find(live.id).is_some());
        // Idempotent.
        assert!(ctx.sweep_expired(now).is_empty());
    }

    #[test]
    fn test_sess_doc_roundtrip_with_pcf_endpoints() {
        let mut sess = BsfSess::new(42);
        sess.binding_id = "42".to_string();
        sess.supi = Some("imsi-001010000000001".to_string());
        sess.gpsi = Some("msisdn-1234".to_string());
        sess.set_ipv4addr("10.45.0.2");
        sess.set_mac_addr48("aa:bb:cc:dd:ee:ff");
        sess.ip_domain = Some("domain1".to_string());
        sess.set_expiry("2026-06-12T10:00:00Z");
        sess.dnn = Some("internet".to_string());
        sess.s_nssai = SNssai::new(1, Some(0x010203));
        sess.pcf_fqdn = Some("pcf.example.com".to_string());
        sess.pcf_ip = vec![
            PcfIpEndpoint {
                addr: Some("10.0.0.10".to_string()),
                addr6: None,
                is_port: true,
                port: 7777,
            },
            PcfIpEndpoint {
                addr: None,
                addr6: Some("2001:db8::10".to_string()),
                is_port: false,
                port: 0,
            },
        ];
        // bsfd-08: new optional PCF identity fields
        sess.pcf_id = Some("pcf-uuid-1234".to_string());
        sess.pcf_set_id = Some("pcfSet-01".to_string());
        sess.bind_level = Some("NF_INSTANCE".to_string());
        sess.recovery_time = Some("2026-06-01T00:00:00Z".to_string());
        sess.pcf_diam_host = Some("pcf.diam.example.com".to_string());
        sess.pcf_diam_realm = Some("example.com".to_string());

        let doc = sess_to_doc(&sess);
        let restored = doc_to_sess(&doc);

        assert_eq!(restored.id, 42);
        assert_eq!(restored.binding_id, "42");
        assert_eq!(restored.supi, sess.supi);
        assert_eq!(restored.gpsi, sess.gpsi);
        assert_eq!(restored.ipv4addr_string, sess.ipv4addr_string);
        assert_eq!(restored.mac_addr48, sess.mac_addr48);
        assert_eq!(restored.ip_domain, sess.ip_domain);
        assert_eq!(restored.expiry, sess.expiry);
        assert_eq!(restored.expiry_epoch, sess.expiry_epoch);
        assert_eq!(restored.dnn, sess.dnn);
        assert_eq!(restored.s_nssai, sess.s_nssai);
        assert_eq!(restored.pcf_fqdn, sess.pcf_fqdn);
        assert_eq!(restored.pcf_ip.len(), 2);
        assert_eq!(restored.pcf_ip[0].addr.as_deref(), Some("10.0.0.10"));
        assert!(restored.pcf_ip[0].is_port);
        assert_eq!(restored.pcf_ip[0].port, 7777);
        assert_eq!(restored.pcf_ip[1].addr6.as_deref(), Some("2001:db8::10"));
        assert!(!restored.pcf_ip[1].is_port);
        // bsfd-08: new fields round-trip through Mongo doc
        assert_eq!(restored.pcf_id.as_deref(), Some("pcf-uuid-1234"));
        assert_eq!(restored.pcf_set_id.as_deref(), Some("pcfSet-01"));
        assert_eq!(restored.bind_level.as_deref(), Some("NF_INSTANCE"));
        assert_eq!(restored.recovery_time.as_deref(), Some("2026-06-01T00:00:00Z"));
        assert_eq!(restored.pcf_diam_host.as_deref(), Some("pcf.diam.example.com"));
        assert_eq!(restored.pcf_diam_realm.as_deref(), Some("example.com"));
    }

    // bsfd-07: sess_find_by_dnn_snssai_supi
    #[test]
    fn test_sess_find_by_dnn_snssai_supi() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let sess = ctx.sess_add_binding(Some("10.45.3.1"), None, None).unwrap();
        let mut sess = sess;
        sess.dnn = Some("internet".to_string());
        sess.s_nssai = SNssai::new(1, Some(0x010203));
        sess.supi = Some("imsi-001010000007001".to_string());
        ctx.sess_update(&sess);

        // Exact match.
        assert!(ctx
            .sess_find_by_dnn_snssai_supi(
                "internet",
                &SNssai::new(1, Some(0x010203)),
                "imsi-001010000007001"
            )
            .is_some());
        // DNN case-insensitive.
        assert!(ctx
            .sess_find_by_dnn_snssai_supi(
                "INTERNET",
                &SNssai::new(1, Some(0x010203)),
                "imsi-001010000007001"
            )
            .is_some());
        // Different SUPI: no match.
        assert!(ctx
            .sess_find_by_dnn_snssai_supi(
                "internet",
                &SNssai::new(1, Some(0x010203)),
                "imsi-999"
            )
            .is_none());
        // Different DNN: no match.
        assert!(ctx
            .sess_find_by_dnn_snssai_supi(
                "ims",
                &SNssai::new(1, Some(0x010203)),
                "imsi-001010000007001"
            )
            .is_none());
    }

    // bsfd-11: pcf-ue-bindings CRUD
    #[test]
    fn test_ue_binding_crud() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let b = PcfUeBinding {
            binding_id: "ue-1".to_string(),
            supi: Some("imsi-001010000008001".to_string()),
            gpsi: None,
            pcf_fqdn: Some("pcf.example.com".to_string()),
            pcf_ip: Vec::new(),
            pcf_id: None,
            pcf_set_id: None,
            bind_level: None,
            recovery_time: None,
            pcf_diam_host: None,
            pcf_diam_realm: None,
            management_features: 0x1,
        };
        ctx.ue_binding_add(b.clone());

        // Find by ID.
        assert!(ctx.ue_binding_find_by_id("ue-1").is_some());
        assert!(ctx.ue_binding_find_by_id("ue-2").is_none());

        // Find by supi.
        let found = ctx.ue_binding_find_matching(Some("imsi-001010000008001"), None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pcf_fqdn.as_deref(), Some("pcf.example.com"));

        // No match on supi filter.
        assert!(ctx.ue_binding_find_matching(Some("imsi-000"), None).is_empty());

        // Update.
        let mut updated = b.clone();
        updated.pcf_fqdn = Some("pcf2.example.com".to_string());
        assert!(ctx.ue_binding_update(&updated));
        assert_eq!(
            ctx.ue_binding_find_by_id("ue-1").unwrap().pcf_fqdn.as_deref(),
            Some("pcf2.example.com")
        );

        // Remove.
        assert!(ctx.ue_binding_remove("ue-1").is_some());
        assert!(ctx.ue_binding_find_by_id("ue-1").is_none());
    }

    // bsfd-12: pcf-mbs-bindings CRUD + duplicate detection
    #[test]
    fn test_mbs_binding_crud() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let b1 = PcfMbsBinding {
            binding_id: "mbs-1".to_string(),
            mbs_session_id: "TMGI-ABC".to_string(),
            pcf_fqdn: Some("pcf.example.com".to_string()),
            pcf_ip: Vec::new(),
            pcf_id: None,
            pcf_set_id: None,
            management_features: 0x1,
        };
        ctx.mbs_binding_add(b1.clone());

        // Find by id.
        assert!(ctx.mbs_binding_find_by_id("mbs-1").is_some());

        // Find by mbs_session_id (single match).
        let found = ctx.mbs_binding_find_by_mbs_session_id("TMGI-ABC");
        assert_eq!(found.len(), 1);

        // Duplicate mbs_session_id: two bindings → caller detects multi-match.
        let b2 = PcfMbsBinding {
            binding_id: "mbs-2".to_string(),
            mbs_session_id: "TMGI-ABC".to_string(),
            pcf_fqdn: Some("pcf2.example.com".to_string()),
            pcf_ip: Vec::new(),
            pcf_id: None,
            pcf_set_id: None,
            management_features: 0x1,
        };
        ctx.mbs_binding_add(b2);
        assert_eq!(ctx.mbs_binding_find_by_mbs_session_id("TMGI-ABC").len(), 2);

        // Remove one; only one left.
        ctx.mbs_binding_remove("mbs-1");
        assert_eq!(ctx.mbs_binding_find_by_mbs_session_id("TMGI-ABC").len(), 1);

        // Different mbs_session_id: no match.
        assert!(ctx.mbs_binding_find_by_mbs_session_id("TMGI-XYZ").is_empty());
    }

    #[test]
    fn test_install_loaded_binding_advances_allocator() {
        let mut ctx = BsfContext::new();
        ctx.init(100);

        let mut sess = BsfSess::new(7);
        sess.binding_id = "7".to_string();
        sess.set_ipv4addr("10.45.0.9");
        sess.set_mac_addr48("aa-aa-aa-aa-aa-01");
        ctx.install_loaded_binding(sess);

        assert!(ctx.sess_find_by_ipv4addr("10.45.0.9").is_some());
        assert!(ctx.sess_find_by_mac("aa-aa-aa-aa-aa-01").is_some());

        // Next allocated id must not collide with the restored one.
        let fresh = ctx
            .sess_add_binding(Some("10.45.0.10"), None, None)
            .unwrap();
        assert!(fresh.id > 7);
    }
}
