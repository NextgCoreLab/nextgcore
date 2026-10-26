//! Where an NF's own SBI host goes in its NFProfile (TS 29.510 §6.1.6.2.2) and in
//! its NFService `ipEndPoints` (§6.1.6.2.3, IpEndPoint §6.1.6.2.6), by its type
//! (#1324).
//!
//! Since #1321/#1323 the advertised host can be an IPv4 literal, an IPv6 literal
//! or an FQDN. The NF profile builders all wrote it to `ipv4Addresses` and
//! `ipEndPoints[].ipv4Address`, so an IPv6 or FQDN advertise host gave the NRF an
//! invalid profile. [`classify_profile_host`] fixes a built profile up:
//! - IPv4: unchanged (`ipv4Addresses`, `ipv4Address`);
//! - IPv6: `ipv6Addresses`, `ipv6Address`, without brackets (Ipv6Addr, TS 29.571);
//! - FQDN: the profile's `fqdn` (unless one is already set), and the endpoints keep
//!   only their port and transport, the address coming from the FQDN.

use crate::context::{NfInstance, NfService};
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The type of a host an NF advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKind {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Fqdn(String),
}

/// Classify `host`: an IPv4 literal, an IPv6 literal (with or without brackets),
/// else an FQDN (lower-cased, without a trailing dot).
pub fn classify_host(host: &str) -> HostKind {
    let host = host.trim();
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(v4) = literal.parse::<Ipv4Addr>() {
        return HostKind::Ipv4(v4);
    }
    if let Ok(v6) = literal.parse::<Ipv6Addr>() {
        return HostKind::Ipv6(v6);
    }
    HostKind::Fqdn(host.trim_end_matches('.').to_ascii_lowercase())
}

/// One IpEndPoint for `host`:`port`. An FQDN host gives a port-only endpoint.
pub fn ip_end_point(host: &str, port: u16) -> Value {
    match classify_host(host) {
        HostKind::Ipv4(a) => serde_json::json!({"ipv4Address": a.to_string(), "port": port}),
        HostKind::Ipv6(a) => serde_json::json!({"ipv6Address": a.to_string(), "port": port}),
        HostKind::Fqdn(_) => serde_json::json!({"port": port}),
    }
}

/// Fix up `profile`, built with `host` in `ipv4Addresses` and in its services'
/// `ipEndPoints[].ipv4Address`, so `host` sits where its type belongs. Entries that
/// carry another address (not `host`) are left alone. Returns the profile.
pub fn classify_profile_host(mut profile: Value, host: &str) -> Value {
    let kind = classify_host(host);
    if matches!(kind, HostKind::Ipv4(_)) {
        return profile;
    }
    let Some(obj) = profile.as_object_mut() else {
        return profile;
    };
    if let Some(Value::Array(v4)) = obj.get_mut("ipv4Addresses") {
        v4.retain(|a| a.as_str() != Some(host));
        if v4.is_empty() {
            obj.remove("ipv4Addresses");
        }
    }
    match &kind {
        HostKind::Ipv6(a) => {
            let v6 = obj
                .entry("ipv6Addresses")
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(list) = v6 {
                let a = Value::String(a.to_string());
                if !list.contains(&a) {
                    list.push(a);
                }
            }
        }
        HostKind::Fqdn(name) => {
            obj.entry("fqdn")
                .or_insert_with(|| Value::String(name.clone()));
        }
        HostKind::Ipv4(_) => {}
    }
    for key in ["nfServices", "nfServiceList"] {
        match obj.get_mut(key) {
            Some(Value::Array(services)) => services
                .iter_mut()
                .for_each(|s| fix_endpoints(s, host, &kind)),
            Some(Value::Object(services)) => services
                .values_mut()
                .for_each(|s| fix_endpoints(s, host, &kind)),
            _ => {}
        }
    }
    profile
}

fn fix_endpoints(service: &mut Value, host: &str, kind: &HostKind) {
    let Some(Value::Array(eps)) = service.get_mut("ipEndPoints") else {
        return;
    };
    for ep in eps.iter_mut().filter_map(Value::as_object_mut) {
        if ep.get("ipv4Address").and_then(Value::as_str) != Some(host) {
            continue;
        }
        ep.remove("ipv4Address");
        if let HostKind::Ipv6(a) = kind {
            ep.insert("ipv6Address".into(), Value::String(a.to_string()));
        }
    }
}

/// Put `host` in the self instance's address of its type (#1324).
pub fn set_instance_host(instance: &mut NfInstance, host: &str) {
    instance.ipv4_addresses.clear();
    instance.ipv6_addresses.clear();
    match classify_host(host) {
        HostKind::Ipv4(a) => instance.ipv4_addresses.push(a.to_string()),
        HostKind::Ipv6(a) => instance.ipv6_addresses.push(a.to_string()),
        HostKind::Fqdn(name) => instance.fqdn = Some(name),
    }
}

/// Put `host` in a self service's address: its IP address, or its FQDN.
pub fn set_service_host(service: &mut NfService, host: &str) {
    service.ip_addresses.clear();
    match classify_host(host) {
        HostKind::Ipv4(a) => service.ip_addresses.push(a.to_string()),
        HostKind::Ipv6(a) => service.ip_addresses.push(a.to_string()),
        HostKind::Fqdn(name) => service.fqdn = Some(name),
    }
}

/// Hosts of each type, for the NF crates' profile tests (#1324).
pub const SAMPLE_HOSTS: [&str; 4] = ["10.0.0.1", "fd00::1", "[fd00::2]", "nf.example.org"];

/// What is wrong with how `profile` carries `host`, for the NF crates' tests
/// (#1324): every `ipv4Address(es)` value must be an IPv4 literal and every
/// `ipv6Address(es)` an unbracketed IPv6 one, and `host` must be in the place its
/// type belongs (`ipv4Addresses`, `ipv6Addresses` or `fqdn`).
pub fn profile_addressing_problems(profile: &Value, host: &str) -> Vec<String> {
    let mut problems = Vec::new();
    scan(profile, "", &mut problems);
    let has = |key: &str, want: &str| {
        profile[key]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(want)))
    };
    match classify_host(host) {
        HostKind::Ipv4(a) if !has("ipv4Addresses", &a.to_string()) => {
            problems.push(format!("ipv4Addresses lacks {a}"))
        }
        HostKind::Ipv6(a) if !has("ipv6Addresses", &a.to_string()) => {
            problems.push(format!("ipv6Addresses lacks {a}"))
        }
        HostKind::Fqdn(_) if profile["fqdn"].as_str().is_none() => {
            problems.push("no fqdn".to_string())
        }
        _ => {}
    }
    problems
}

fn scan(v: &Value, path: &str, problems: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let here = format!("{path}/{k}");
                let check = |s: &str| match k.as_str() {
                    "ipv4Address" | "ipv4Addresses" => s.parse::<Ipv4Addr>().is_ok(),
                    "ipv6Address" | "ipv6Addresses" => s.parse::<Ipv6Addr>().is_ok(),
                    _ => true,
                };
                let bad: Vec<&str> = match child {
                    Value::String(s) => vec![s.as_str()],
                    Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                    _ => Vec::new(),
                }
                .into_iter()
                .filter(|s| !check(s))
                .collect();
                if !bad.is_empty() {
                    problems.push(format!("{here}: {bad:?}"));
                }
                scan(child, &here, problems);
            }
        }
        Value::Array(a) => a.iter().for_each(|c| scan(c, path, problems)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn built(host: &str) -> Value {
        json!({
            "nfInstanceId": "x",
            "nfType": "SMF",
            "ipv4Addresses": [host],
            "nfServices": [{
                "serviceName": "nsmf-pdusession",
                "ipEndPoints": [{"ipv4Address": host, "port": 7777, "transport": "TCP"}]
            }]
        })
    }

    #[test]
    fn the_checker_finds_a_misplaced_host() {
        for host in SAMPLE_HOSTS {
            let fixed = classify_profile_host(built(host), host);
            assert!(
                profile_addressing_problems(&fixed, host).is_empty(),
                "{host}: {fixed}"
            );
        }
        for host in ["fd00::1", "nf.example.org"] {
            assert!(
                !profile_addressing_problems(&built(host), host).is_empty(),
                "{host}"
            );
        }
    }

    #[test]
    fn hosts_are_classified() {
        assert_eq!(
            classify_host("10.0.0.1"),
            HostKind::Ipv4("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            classify_host("fd00::1"),
            HostKind::Ipv6("fd00::1".parse().unwrap())
        );
        assert_eq!(
            classify_host("[fd00::1]"),
            HostKind::Ipv6("fd00::1".parse().unwrap())
        );
        assert_eq!(
            classify_host("SMF.Example.org."),
            HostKind::Fqdn("smf.example.org".into())
        );
    }

    #[test]
    fn an_ipv4_host_leaves_the_profile_as_built() {
        assert_eq!(
            classify_profile_host(built("10.0.0.4"), "10.0.0.4"),
            built("10.0.0.4")
        );
    }

    #[test]
    fn an_ipv6_host_goes_to_ipv6_addresses_and_ipv6_address() {
        let p = classify_profile_host(built("[fd00::4]"), "[fd00::4]");
        assert!(p.get("ipv4Addresses").is_none(), "{p}");
        assert_eq!(p["ipv6Addresses"], json!(["fd00::4"]));
        assert_eq!(
            p["nfServices"][0]["ipEndPoints"][0],
            json!({"ipv6Address": "fd00::4", "port": 7777, "transport": "TCP"})
        );
    }

    #[test]
    fn an_fqdn_host_goes_to_fqdn_and_the_endpoints_keep_their_port() {
        let p = classify_profile_host(built("smf.example.org"), "smf.example.org");
        assert!(p.get("ipv4Addresses").is_none(), "{p}");
        assert!(p.get("ipv6Addresses").is_none(), "{p}");
        assert_eq!(p["fqdn"], json!("smf.example.org"));
        assert_eq!(
            p["nfServices"][0]["ipEndPoints"][0],
            json!({"port": 7777, "transport": "TCP"})
        );
        // A configured fqdn is kept.
        let mut b = built("smf.example.org");
        b["fqdn"] = json!("configured.example");
        assert_eq!(
            classify_profile_host(b, "smf.example.org")["fqdn"],
            json!("configured.example")
        );
    }

    #[test]
    fn a_service_map_and_other_addresses_are_handled() {
        let p = classify_profile_host(
            json!({
                "ipv4Addresses": ["fd00::9", "10.9.9.9"],
                "nfServiceList": {"a": {"ipEndPoints": [
                    {"ipv4Address": "fd00::9", "port": 1},
                    {"ipv4Address": "10.9.9.9", "port": 2}
                ]}}
            }),
            "fd00::9",
        );
        assert_eq!(
            p["ipv4Addresses"],
            json!(["10.9.9.9"]),
            "another address is kept"
        );
        assert_eq!(p["ipv6Addresses"], json!(["fd00::9"]));
        assert_eq!(
            p["nfServiceList"]["a"]["ipEndPoints"],
            json!([{"ipv6Address": "fd00::9", "port": 1}, {"ipv4Address": "10.9.9.9", "port": 2}])
        );
    }

    #[test]
    fn ip_end_points_and_the_self_instance_by_type() {
        assert_eq!(
            ip_end_point("10.0.0.1", 80),
            json!({"ipv4Address": "10.0.0.1", "port": 80})
        );
        assert_eq!(
            ip_end_point("[fd00::1]", 80),
            json!({"ipv6Address": "fd00::1", "port": 80})
        );
        assert_eq!(ip_end_point("nf.example", 80), json!({"port": 80}));
        let mut i = NfInstance::new("x", crate::types::NfType::Smf);
        set_instance_host(&mut i, "fd00::2");
        assert_eq!(
            (i.ipv4_addresses.len(), i.ipv6_addresses.clone()),
            (0, vec!["fd00::2".to_string()])
        );
        set_instance_host(&mut i, "smf.example");
        assert_eq!(i.fqdn.as_deref(), Some("smf.example"));
        assert!(i.ipv4_addresses.is_empty() && i.ipv6_addresses.is_empty());
        let mut s = NfService::new("n", crate::types::SbiServiceType::NsmfPdusession);
        set_service_host(&mut s, "smf.example");
        assert_eq!(
            (s.fqdn.as_deref(), s.ip_addresses.len()),
            (Some("smf.example"), 0)
        );
    }
}
