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

/// The address of one IpEndPoint (TS 29.510 §6.1.6.2.6): its `ipv4Address`, else its
/// `ipv6Address` (unbracketed). `None` for a port-only endpoint.
pub fn endpoint_host(ep: &Value) -> Option<String> {
    ep.get("ipv4Address")
        .and_then(Value::as_str)
        .or_else(|| ep.get("ipv6Address").and_then(Value::as_str))
        .filter(|h| !h.is_empty())
        .map(str::to_string)
}

/// A peer NFProfile's own host (TS 29.510 §6.1.6.2.2): `ipv4Addresses[0]`, else
/// `ipv6Addresses[0]`, else `fqdn`.
pub fn profile_host(profile: &Value) -> Option<String> {
    let first = |key: &str| {
        profile
            .get(key)
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find_map(Value::as_str))
            .filter(|h| !h.is_empty())
            .map(str::to_string)
    };
    first("ipv4Addresses")
        .or_else(|| first("ipv6Addresses"))
        .or_else(|| {
            profile
                .get("fqdn")
                .and_then(Value::as_str)
                .filter(|h| !h.is_empty())
                .map(str::to_string)
        })
}

/// The host to dial for `service` of the peer `profile` (TS 29.510 §6.1.6.2.3:
/// the service's endpoints, then its FQDN, then the NF's): the first `ipEndPoints`
/// entry with an address, else the service `fqdn`, else [`profile_host`].
pub fn service_host(profile: &Value, service: Option<&Value>) -> Option<String> {
    service
        .and_then(|s| s.get("ipEndPoints"))
        .and_then(Value::as_array)
        .and_then(|eps| eps.iter().find_map(endpoint_host))
        .or_else(|| {
            service
                .and_then(|s| s.get("fqdn"))
                .and_then(Value::as_str)
                .filter(|h| !h.is_empty())
                .map(str::to_string)
        })
        .or_else(|| profile_host(profile))
}

/// The port of `service`'s first `ipEndPoints` entry that has one.
pub fn service_port(service: Option<&Value>) -> Option<u16> {
    service
        .and_then(|s| s.get("ipEndPoints"))
        .and_then(Value::as_array)
        .and_then(|eps| {
            eps.iter()
                .find_map(|e| e.get("port").and_then(Value::as_u64))
        })
        .and_then(|p| u16::try_from(p).ok())
}

/// Copy a peer profile's `fqdn`, `ipv4Addresses` and `ipv6Addresses` into `instance`.
pub fn read_instance_addresses(instance: &mut NfInstance, profile: &Value) {
    let list = |key: &str| -> Vec<String> {
        profile
            .get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    instance.ipv4_addresses = list("ipv4Addresses");
    instance.ipv6_addresses = list("ipv6Addresses");
    if let Some(fqdn) = profile.get("fqdn").and_then(Value::as_str) {
        instance.fqdn = Some(fqdn.to_string());
    }
}

/// Copy a peer NFService's first endpoint (its address of either type, and port)
/// and its `fqdn` into `service`.
pub fn read_service_addresses(service: &mut NfService, json: &Value) {
    if let Some(host) = json
        .get("ipEndPoints")
        .and_then(Value::as_array)
        .and_then(|eps| eps.iter().find_map(endpoint_host))
    {
        service.ip_addresses.push(host);
    }
    if let Some(port) = service_port(Some(json)) {
        service.port = port;
    }
    if let Some(fqdn) = json.get("fqdn").and_then(Value::as_str) {
        service.fqdn = Some(fqdn.to_string());
    }
}

/// Put every one of `hosts` in the self instance's address of its type, the
/// lists set once (#1324 review: not one host clearing another).
pub fn set_instance_hosts<'a>(instance: &mut NfInstance, hosts: impl IntoIterator<Item = &'a str>) {
    instance.ipv4_addresses.clear();
    instance.ipv6_addresses.clear();
    for host in hosts {
        match classify_host(host) {
            HostKind::Ipv4(a) => instance.ipv4_addresses.push(a.to_string()),
            HostKind::Ipv6(a) => instance.ipv6_addresses.push(a.to_string()),
            HostKind::Fqdn(name) => {
                instance.fqdn.get_or_insert(name);
            }
        }
    }
}

/// Put every one of `hosts` in a self service's addresses, set once.
pub fn set_service_hosts<'a>(service: &mut NfService, hosts: impl IntoIterator<Item = &'a str>) {
    service.ip_addresses.clear();
    for host in hosts {
        match classify_host(host) {
            HostKind::Ipv4(a) => service.ip_addresses.push(a.to_string()),
            HostKind::Ipv6(a) => service.ip_addresses.push(a.to_string()),
            HostKind::Fqdn(name) => {
                service.fqdn.get_or_insert(name);
            }
        }
    }
}

/// An IpEndPoint (TS 29.510 §6.1.6.2.6) for `host`:`port` over TCP, or `None` for
/// an FQDN host, whose address is not an IP (a consumer reaches it by the FQDN).
pub fn tcp_ip_end_point(host: &str, port: u16) -> Option<Value> {
    let mut ep = ip_end_point(host, port);
    ep.get("ipv4Address").or_else(|| ep.get("ipv6Address"))?;
    ep["transport"] = Value::String("TCP".into());
    Some(ep)
}

/// The InterfaceUpfInfoItem endpoint members (TS 29.510 §6.1.6.2.12) for `addr`:
/// `ipv4EndpointAddresses`, `ipv6EndpointAddresses` (unbracketed) or `endpointFqdn`.
pub fn interface_upf_endpoint(addr: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    match classify_host(addr) {
        HostKind::Ipv4(a) => {
            m.insert(
                "ipv4EndpointAddresses".into(),
                serde_json::json!([a.to_string()]),
            );
        }
        HostKind::Ipv6(a) => {
            m.insert(
                "ipv6EndpointAddresses".into(),
                serde_json::json!([a.to_string()]),
            );
        }
        HostKind::Fqdn(name) => {
            m.insert("endpointFqdn".into(), Value::String(name));
        }
    }
    m
}

/// A sample NRF discovery result (TS 29.510 §6.2.3.2.3.1 SearchResult) holding one
/// `nf_type` instance at `host` with `service_name` on `port`, built the way this
/// codebase's producers build profiles. For the consumers' round-trip tests (#1324).
pub fn sample_search_result(nf_type: &str, service_name: &str, host: &str, port: u16) -> Value {
    serde_json::json!({
        "nfInstances": [classify_profile_host(
            serde_json::json!({
                "nfInstanceId": format!("{}-1324", nf_type.to_ascii_lowercase()),
                "nfType": nf_type,
                "nfStatus": "REGISTERED",
                "ipv4Addresses": [host],
                "nfServices": [{
                    "serviceInstanceId": service_name,
                    "serviceName": service_name,
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{"ipv4Address": host, "port": port}]
                }]
            }),
            host,
        )]
    })
}

/// The host a consumer is expected to dial for `host` once it went through a
/// profile: the literal without brackets, or the FQDN as classified.
pub fn dialled_host(host: &str) -> String {
    match classify_host(host) {
        HostKind::Ipv4(a) => a.to_string(),
        HostKind::Ipv6(a) => a.to_string(),
        HostKind::Fqdn(name) => name,
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
                    "ipv4Address" | "ipv4Addresses" | "ipv4EndpointAddresses" => {
                        s.parse::<Ipv4Addr>().is_ok()
                    }
                    "ipv6Address" | "ipv6Addresses" | "ipv6EndpointAddresses" => {
                        s.parse::<Ipv6Addr>().is_ok()
                    }
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

    /// Producer to consumer: what a profile is built with is what a consumer dials.
    #[test]
    fn a_classified_profile_reads_back_to_its_host() {
        for host in SAMPLE_HOSTS {
            let result = sample_search_result("UDM", "nudm-sdm", host, 7790);
            let p = &result["nfInstances"][0];
            let svc = &p["nfServices"][0];
            let want = dialled_host(host);
            assert_eq!(
                service_host(p, Some(svc)).as_deref(),
                Some(want.as_str()),
                "{host}"
            );
            assert_eq!(service_port(Some(svc)), Some(7790));
            assert_eq!(profile_host(p).as_deref(), Some(want.as_str()), "{host}");
            let mut i = NfInstance::new("x", crate::types::NfType::Udm);
            read_instance_addresses(&mut i, p);
            let mut s = NfService::new("nudm-sdm", crate::types::SbiServiceType::NudmSdm);
            read_service_addresses(&mut s, svc);
            i.add_service(s);
            assert_eq!(
                i.endpoint_for(crate::types::SbiServiceType::NudmSdm),
                Some((want.clone(), 7790)),
                "{host}"
            );
        }
    }

    #[test]
    fn upf_interface_and_tcp_endpoints_by_type() {
        assert_eq!(
            Value::Object(interface_upf_endpoint("10.0.0.6")),
            json!({"ipv4EndpointAddresses": ["10.0.0.6"]})
        );
        assert_eq!(
            Value::Object(interface_upf_endpoint("[fd00::6]")),
            json!({"ipv6EndpointAddresses": ["fd00::6"]})
        );
        assert_eq!(
            Value::Object(interface_upf_endpoint("upf.example")),
            json!({"endpointFqdn": "upf.example"})
        );
        assert_eq!(
            tcp_ip_end_point("fd00::7", 7777),
            Some(json!({"ipv6Address": "fd00::7", "port": 7777, "transport": "TCP"}))
        );
        assert_eq!(tcp_ip_end_point("pcf.example", 7777), None);
        let mut s = NfService::new("n", crate::types::SbiServiceType::NpcfSmpolicycontrol);
        set_service_hosts(&mut s, ["10.0.0.1", "fd00::1"]);
        assert_eq!(s.ip_addresses, vec!["10.0.0.1", "fd00::1"]);
    }

    #[test]
    fn set_instance_hosts_keeps_every_host() {
        let mut i = NfInstance::new("x", crate::types::NfType::Pcf);
        set_instance_hosts(&mut i, ["10.0.0.1", "fd00::1", "10.0.0.2", "pcf.example"]);
        assert_eq!(i.ipv4_addresses, vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(i.ipv6_addresses, vec!["fd00::1"]);
        assert_eq!(i.fqdn.as_deref(), Some("pcf.example"));
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
