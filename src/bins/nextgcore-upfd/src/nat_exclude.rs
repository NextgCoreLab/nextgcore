//! `--nat-exclude`: DN prefixes this UPF does not source-NAT toward (#1455).
//!
//! The UPF masquerades the UE subnet on N6 (`TunDevice::setup_nat`), so a DN server
//! sees the UPF's address and never the UE's. That is right toward the internet,
//! and wrong toward a DN that must identify the UE by its own address: an AF that
//! asks the NEF who `10.45.0.7` is (TS 23.502 §4.15.10) needs the packet to carry
//! `10.45.0.7`. §4.15.10 steps 3-6 exist for a UPF *with* NAT toward that DN; a
//! UPF that does not NAT toward it skips them.
//!
//! Each listed prefix gets one `-j ACCEPT` rule in `nat POSTROUTING`, ahead of the
//! MASQUERADE: ACCEPT ends the nat table's walk for that packet, so no SNAT
//! applies. Unset, the rule list is exactly the single MASQUERADE the UPF has
//! always installed.

use std::net::Ipv4Addr;

/// One IPv4 prefix, held in canonical form (host bits cleared).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl Prefix {
    /// Parse `a.b.c.d/len` or a bare `a.b.c.d` (a /32). Host bits are cleared, so
    /// `10.60.0.7/24` names `10.60.0.0/24`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => {
                let len: u8 = l
                    .parse()
                    .map_err(|_| format!("bad prefix length in '{s}'"))?;
                (a, len)
            }
            None => (s, 32),
        };
        if len > 32 {
            return Err(format!("prefix length {len} > 32 in '{s}'"));
        }
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("'{s}' is not an IPv4 address or prefix"))?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Ok(Self {
            addr: Ipv4Addr::from(u32::from(addr) & mask),
            len,
        })
    }
}

/// The `--nat-exclude` setting: the flag, else `UPF_NAT_EXCLUDE`; comma-separated.
/// Empty is the default (nothing excluded). Any bad entry is an error, so the UPF
/// refuses to start rather than NAT a DN the operator meant to exclude.
pub fn setting(flag: &str, env: Option<String>) -> Result<Vec<Prefix>, String> {
    let list = if flag.trim().is_empty() {
        env.unwrap_or_default()
    } else {
        flag.to_string()
    };
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Prefix::parse)
        .collect()
}

/// The `iptables` argument lists `setup_nat` runs, in order: one ACCEPT per
/// excluded prefix, then the MASQUERADE. With no excludes this is exactly the one
/// command the UPF ran before #1455.
pub fn postrouting_rules(ue_subnet: &str, tun: &str, excludes: &[Prefix]) -> Vec<Vec<String>> {
    let mut rules: Vec<Vec<String>> = excludes
        .iter()
        .map(|p| {
            [
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                ue_subnet,
                "-d",
                &p.to_string(),
                "-j",
                "ACCEPT",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect()
        })
        .collect();
    rules.push(
        [
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            ue_subnet,
            "!",
            "-o",
            tun,
            "-j",
            "MASQUERADE",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    );
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Off: the exact command the UPF has always run, and nothing else.
    #[test]
    fn no_excludes_is_the_single_masquerade_of_before() {
        assert_eq!(
            postrouting_rules("10.45.0.0/16", "ogstun", &[]),
            vec![args(&[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.45.0.0/16",
                "!",
                "-o",
                "ogstun",
                "-j",
                "MASQUERADE"
            ])]
        );
    }

    /// Each excluded prefix is an ACCEPT for the UE subnet toward it, appended
    /// BEFORE the MASQUERADE: nat POSTROUTING stops at the first ACCEPT, so the
    /// order is what makes the exclusion work.
    #[test]
    fn excludes_are_accepts_ahead_of_the_masquerade() {
        let ex = setting("10.60.0.0/24, 172.30.1.9", None).expect("valid");
        let rules = postrouting_rules("10.45.0.0/16", "ogstun", &ex);
        assert_eq!(rules.len(), 3);
        assert_eq!(
            rules[0],
            args(&[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.45.0.0/16",
                "-d",
                "10.60.0.0/24",
                "-j",
                "ACCEPT"
            ])
        );
        assert_eq!(rules[1][7], "172.30.1.9/32");
        assert_eq!(rules[1][9], "ACCEPT");
        assert_eq!(rules[2].last().map(String::as_str), Some("MASQUERADE"));
    }

    #[test]
    fn the_setting_reads_the_flag_then_the_env_and_refuses_bad_entries() {
        assert_eq!(setting("", None), Ok(vec![]));
        assert_eq!(setting(" , ", None), Ok(vec![]));
        assert_eq!(
            setting("", Some("10.60.0.7/24".to_string())),
            Ok(vec![Prefix {
                addr: Ipv4Addr::new(10, 60, 0, 0),
                len: 24
            }]),
            "the env is read without the flag, host bits cleared"
        );
        assert_eq!(
            setting("10.61.0.0/16", Some("10.60.0.0/24".to_string())).unwrap()[0].to_string(),
            "10.61.0.0/16",
            "the flag wins"
        );
        for bad in [
            "10.60.0.0/33",
            "10.60.0/24",
            "eas-local",
            "10.60.0.0/x",
            "::1/128",
        ] {
            assert!(setting(bad, None).is_err(), "{bad} must be refused");
        }
        assert_eq!(
            setting("0.0.0.0/0", None).unwrap()[0].to_string(),
            "0.0.0.0/0"
        );
    }
}
