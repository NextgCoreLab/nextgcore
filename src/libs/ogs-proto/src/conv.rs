//! Protocol conversion utilities

use crate::types::*;

/// PAA (PDN Address Allocation) structure
#[derive(Debug, Clone, Default)]
pub struct Paa {
    pub session_type: u8,
    pub addr: u32,
    pub addr6: [u8; IPV6_LEN],
    pub prefix_len: u8,
}

impl Paa {
    /// Create IPv4 PAA
    pub fn ipv4(addr: u32) -> Self {
        Self {
            session_type: pdu_session_type::IPV4,
            addr,
            addr6: [0; IPV6_LEN],
            prefix_len: 0,
        }
    }

    /// Create IPv6 PAA
    pub fn ipv6(addr6: [u8; IPV6_LEN], prefix_len: u8) -> Self {
        Self {
            session_type: pdu_session_type::IPV6,
            addr: 0,
            addr6,
            prefix_len,
        }
    }

    /// Create dual-stack PAA
    pub fn ipv4v6(addr: u32, addr6: [u8; IPV6_LEN], prefix_len: u8) -> Self {
        Self {
            session_type: pdu_session_type::IPV4V6,
            addr,
            addr6,
            prefix_len,
        }
    }
}

/// Convert PAA to IP address
pub fn paa_to_ip(paa: &Paa) -> Result<IpAddr, &'static str> {
    let mut ip = IpAddr::default();

    match paa.session_type {
        pdu_session_type::IPV4V6 => {
            ip.ipv4 = true;
            ip.addr = paa.addr;
            ip.ipv6 = true;
            ip.addr6.copy_from_slice(&paa.addr6);
            ip.len = (IPV4_LEN + IPV6_LEN) as u32;
        }
        pdu_session_type::IPV4 => {
            ip.ipv4 = true;
            ip.ipv6 = false;
            ip.addr = paa.addr;
            ip.len = IPV4_LEN as u32;
        }
        pdu_session_type::IPV6 => {
            ip.ipv4 = false;
            ip.ipv6 = true;
            ip.addr6.copy_from_slice(&paa.addr6);
            ip.len = IPV6_LEN as u32;
        }
        _ => {
            return Err("No IPv4 or IPv6");
        }
    }

    Ok(ip)
}

/// Convert IP address to PAA
pub fn ip_to_paa(ip: &IpAddr) -> Result<Paa, &'static str> {
    let mut paa = Paa::default();

    if ip.ipv4 && ip.ipv6 {
        paa.session_type = pdu_session_type::IPV4V6;
        paa.addr = ip.addr;
        paa.addr6.copy_from_slice(&ip.addr6);
    } else if ip.ipv6 {
        paa.session_type = pdu_session_type::IPV6;
        paa.addr6.copy_from_slice(&ip.addr6);
    } else if ip.ipv4 {
        paa.session_type = pdu_session_type::IPV4;
        paa.addr = ip.addr;
    } else {
        return Err("No IPv4 or IPv6");
    }

    Ok(paa)
}

/// Extract digits from a string
/// 
/// Extracts the first contiguous sequence of digits from the string.
pub fn extract_digit_from_string(string: &str) -> String {
    let mut result = String::new();
    let mut extracting = false;

    for (i, c) in string.chars().enumerate() {
        if i >= MAX_IMSI_BCD_LEN {
            break;
        }

        if c.is_ascii_digit() {
            result.push(c);
            extracting = true;
        } else if extracting {
            break;
        }
    }

    result
}

/// Build FQDN from labels
/// 
/// Converts "example.com" to length-prefixed format: "\x07example\x03com"
pub fn fqdn_build(src: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let labels: Vec<&str> = src.split('.').collect();

    for label in labels {
        if !label.is_empty() {
            result.push(label.len() as u8);
            result.extend_from_slice(label.as_bytes());
        }
    }

    result
}

/// Parse FQDN from length-prefixed format
/// 
/// Converts "\x07example\x03com" to "example.com"
pub fn fqdn_parse(data: &[u8]) -> Result<String, &'static str> {
    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let len = data[i] as usize;
        i += 1;

        if len == 0 {
            break;
        }

        if i + len > data.len() {
            return Err("Invalid FQDN encoding");
        }

        if !result.is_empty() {
            result.push('.');
        }

        let label = std::str::from_utf8(&data[i..i + len]).map_err(|_| "Invalid UTF-8 in FQDN")?;
        result.push_str(label);
        i += len;
    }

    Ok(result)
}

/// Generate serving network name from PLMN ID
pub fn serving_network_name_from_plmn_id(plmn_id: &PlmnId) -> String {
    format!(
        "5G:mnc{:03}.mcc{:03}.3gppnetwork.org",
        plmn_id.mnc(),
        plmn_id.mcc()
    )
}

/// Generate home network domain from PLMN ID
pub fn home_network_domain_from_plmn_id(plmn_id: &PlmnId) -> String {
    format!(
        "5gc.mnc{:03}.mcc{:03}.3gppnetwork.org",
        plmn_id.mnc(),
        plmn_id.mcc()
    )
}

/// Generate EPC domain from PLMN ID
pub fn epc_domain_from_plmn_id(plmn_id: &PlmnId) -> String {
    format!(
        "epc.mnc{:03}.mcc{:03}.3gppnetwork.org",
        plmn_id.mnc(),
        plmn_id.mcc()
    )
}

/// Generate NRF FQDN from PLMN ID
pub fn nrf_fqdn_from_plmn_id(plmn_id: &PlmnId) -> String {
    format!(
        "nrf.5gc.mnc{:03}.mcc{:03}.3gppnetwork.org",
        plmn_id.mnc(),
        plmn_id.mcc()
    )
}

/// Generate NSSF FQDN from PLMN ID
pub fn nssf_fqdn_from_plmn_id(plmn_id: &PlmnId) -> String {
    format!(
        "nssf.5gc.mnc{:03}.mcc{:03}.3gppnetwork.org",
        plmn_id.mnc(),
        plmn_id.mcc()
    )
}

/// Generate DNN OI from PLMN ID
pub fn dnn_oi_from_plmn_id(plmn_id: &PlmnId) -> String {
    format!("mnc{:03}.mcc{:03}.gprs", plmn_id.mnc(), plmn_id.mcc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_digit_from_string() {
        assert_eq!(extract_digit_from_string("abc123def"), "123");
        assert_eq!(extract_digit_from_string("123"), "123");
        assert_eq!(extract_digit_from_string("abc"), "");
        assert_eq!(extract_digit_from_string("12abc34"), "12");
    }

    #[test]
    fn test_fqdn_build() {
        let result = fqdn_build("example.com");
        assert_eq!(result.len(), 12); // 1 + 7 + 1 + 3 = 12
        assert_eq!(result[0], 7); // "example" length
        assert_eq!(result[8], 3); // "com" length
    }

    #[test]
    fn test_fqdn_parse() {
        let data = vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm'];
        let result = fqdn_parse(&data).unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_paa_to_ip() {
        let paa = Paa::ipv4(0x0a000001);
        let ip = paa_to_ip(&paa).unwrap();
        assert!(ip.ipv4);
        assert!(!ip.ipv6);
        assert_eq!(ip.addr, 0x0a000001);
    }

    #[test]
    fn test_ip_to_paa() {
        let ip = IpAddr::from_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let paa = ip_to_paa(&ip).unwrap();
        assert_eq!(paa.session_type, pdu_session_type::IPV4);
    }

    #[test]
    fn test_serving_network_name() {
        let plmn = PlmnId::build(310, 410, 3);
        let name = serving_network_name_from_plmn_id(&plmn);
        assert_eq!(name, "5G:mnc410.mcc310.3gppnetwork.org");
    }
}
