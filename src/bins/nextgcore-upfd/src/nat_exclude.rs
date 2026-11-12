//! `--nat-exclude`: DN prefixes this UPF does not source-NAT toward (#1455).
//!
//! The UPF masquerades the UE subnet on N6, so a DN server sees the UPF's address
//! and never the UE's. That is right toward the internet, and wrong toward a DN
//! that must identify the UE by its own address: an AF that asks the NEF who
//! `10.45.0.7` is (TS 23.502 §4.15.10) needs the packet to carry `10.45.0.7`.
//! §4.15.10 steps 3-6 exist for a UPF *with* NAT toward that DN; a UPF that does
//! not NAT toward it skips them.
//!
//! # How (#1463 review)
//!
//! The exclusions live in a chain of their own, [`CHAIN`], in the nat table:
//! flushed and refilled at every start (so a restart with another list leaves no
//! stale rule), one `-j ACCEPT` per prefix, and jumped to from the HEAD of
//! POSTROUTING (`-I POSTROUTING 1`, guarded by `-C` so a restart does not add a
//! second jump). ACCEPT ends the nat walk, so no MASQUERADE applies, whichever
//! MASQUERADE it is: this UPF's own, or one a container wrapper installed before
//! the UPF started (the k8s, Helm and EKS manifests do). The UPF's MASQUERADE is
//! appended exactly as before.
//!
//! Unset, the UPF installs the same single MASQUERADE it always has. It only
//! probes for the chain, and flushes a chain an earlier run with exclusions left
//! behind, so nothing it no longer asks for stays excluded.
//!
//! Every exclusion command must succeed, or the UPF refuses to start: running
//! with the DN NATed after the operator excluded it would be the failure this
//! flag exists to prevent. The MASQUERADE stays warn-only, as before.

use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;

/// The nat-table chain holding the exclusions.
pub const CHAIN: &str = "UPF-NAT-EXCLUDE";

/// One IPv4 prefix, held in canonical form (host bits cleared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
/// refuses to start rather than NAT a DN the operator meant to exclude. Duplicates
/// (also after host bits are cleared) are dropped, and the list is ordered.
pub fn setting(flag: &str, env: Option<String>) -> Result<Vec<Prefix>, String> {
    let list = if flag.trim().is_empty() {
        env.unwrap_or_default()
    } else {
        flag.to_string()
    };
    let set: BTreeSet<Prefix> = list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Prefix::parse)
        .collect::<Result<_, _>>()?;
    let prefixes: Vec<Prefix> = set.into_iter().collect();
    if prefixes.iter().any(|p| p.len == 0) {
        log::warn!(
            "--nat-exclude 0.0.0.0/0: NAT is OFF toward every destination; the UE \
             subnet leaves with its own addresses everywhere, the internet included"
        );
    }
    Ok(prefixes)
}

/// The UPF's own MASQUERADE, exactly as it has always been installed.
pub fn masquerade_rule(ue_subnet: &str, tun: &str) -> Vec<String> {
    to_args(&[
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
    ])
}

fn to_args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// What one `iptables` invocation did.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `iptables` with the given arguments. A trait so the plan, and how a
/// failure is handled, can be tested without root.
pub trait Iptables {
    fn run(&mut self, args: &[String]) -> io::Result<Outcome>;
}

/// The real `iptables` (no shell: arguments are passed as they are).
pub struct SystemIptables;

impl Iptables for SystemIptables {
    fn run(&mut self, args: &[String]) -> io::Result<Outcome> {
        let out = std::process::Command::new("iptables").args(args).output()?;
        Ok(Outcome {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

fn must(ipt: &mut impl Iptables, args: Vec<String>) -> io::Result<Outcome> {
    let out = ipt.run(&args)?;
    if out.ok {
        Ok(out)
    } else {
        Err(io::Error::other(format!(
            "iptables {} failed: {}",
            args.join(" "),
            out.stderr.trim()
        )))
    }
}

/// Install the UPF's N6 NAT for `ue_subnet`: the exclusions first (see the module
/// docs), then the MASQUERADE as before.
pub fn install(
    ue_subnet: &str,
    tun: &str,
    excludes: &[Prefix],
    ipt: &mut impl Iptables,
) -> io::Result<()> {
    let list = to_args(&["-t", "nat", "-L", CHAIN, "-n"]);
    if excludes.is_empty() {
        if ipt.run(&list)?.ok {
            must(ipt, to_args(&["-t", "nat", "-F", CHAIN]))?;
            log::info!("NAT: flushed {CHAIN} left by an earlier run; nothing is excluded now");
        }
    } else {
        if !ipt.run(&to_args(&["-t", "nat", "-N", CHAIN]))?.ok {
            // Already there (a restart): fine, provided it really exists.
            must(ipt, list)?;
        }
        must(ipt, to_args(&["-t", "nat", "-F", CHAIN]))?;
        for p in excludes {
            let p = p.to_string();
            must(
                ipt,
                to_args(&[
                    "-t", "nat", "-A", CHAIN, "-s", ue_subnet, "-d", &p, "-j", "ACCEPT",
                ]),
            )?;
        }
        let jump = |op: &str| {
            let mut a = to_args(&["-t", "nat", op, "POSTROUTING"]);
            if op == "-I" {
                a.push("1".to_string());
            }
            a.extend(to_args(&["-j", CHAIN]));
            a
        };
        if !ipt.run(&jump("-C"))?.ok {
            must(ipt, jump("-I"))?;
        }
        // Say what is in effect, not what was asked for: a rule something else
        // inserted at the head after ours would NAT the excluded DNs again.
        let rules = must(ipt, to_args(&["-t", "nat", "-S", "POSTROUTING"]))?.stdout;
        let first = rules.lines().find(|l| l.starts_with("-A ")).unwrap_or("");
        let listed: Vec<String> = excludes.iter().map(Prefix::to_string).collect();
        if first == format!("-A POSTROUTING -j {CHAIN}") {
            log::info!(
                "NAT: {ue_subnet} toward {} keeps the UE source address (--nat-exclude; \
                 {CHAIN} is the first POSTROUTING rule)",
                listed.join(", ")
            );
        } else {
            log::warn!(
                "NAT: {CHAIN} holds {} but is NOT the first POSTROUTING rule (first: \
                 '{first}'); a rule ahead of it may still NAT those destinations",
                listed.join(", ")
            );
        }
    }
    let masq = masquerade_rule(ue_subnet, tun);
    let out = ipt.run(&masq)?;
    if !out.ok {
        log::warn!("iptables NAT setup warning: {}", out.stderr);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted `iptables`: records every call; answers from a model of one
    /// nat table (chains with their rules, POSTROUTING in order), and can be told
    /// to fail a command matching a substring.
    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        chain: Option<Vec<String>>,
        postrouting: Vec<String>,
        fail: Option<&'static str>,
    }

    impl Iptables for Fake {
        fn run(&mut self, args: &[String]) -> io::Result<Outcome> {
            let line = args.join(" ");
            self.calls.push(line.clone());
            if self.fail.is_some_and(|f| line.contains(f)) {
                return Ok(Outcome {
                    ok: false,
                    stderr: "refused".into(),
                    ..Default::default()
                });
            }
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let ok = match &a[2..] {
                ["-L", CHAIN, "-n"] => self.chain.is_some(),
                ["-N", CHAIN] => {
                    let fresh = self.chain.is_none();
                    self.chain.get_or_insert_with(Vec::new);
                    fresh
                }
                ["-F", CHAIN] => self.chain.as_mut().map(Vec::clear).is_some(),
                ["-A", CHAIN, rest @ ..] => self
                    .chain
                    .as_mut()
                    .map(|c| c.push(rest.join(" ")))
                    .is_some(),
                ["-C", "POSTROUTING", "-j", CHAIN] => {
                    self.postrouting.contains(&format!("-j {CHAIN}"))
                }
                ["-I", "POSTROUTING", "1", rest @ ..] => {
                    self.postrouting.insert(0, rest.join(" "));
                    true
                }
                ["-A", "POSTROUTING", rest @ ..] => {
                    self.postrouting.push(rest.join(" "));
                    true
                }
                ["-S", "POSTROUTING"] => {
                    let stdout = std::iter::once("-P POSTROUTING ACCEPT".to_string())
                        .chain(
                            self.postrouting
                                .iter()
                                .map(|r| format!("-A POSTROUTING {r}")),
                        )
                        .collect::<Vec<_>>()
                        .join("\n");
                    return Ok(Outcome {
                        ok: true,
                        stdout,
                        ..Default::default()
                    });
                }
                _ => false,
            };
            Ok(Outcome {
                ok,
                ..Default::default()
            })
        }
    }

    fn prefixes(list: &str) -> Vec<Prefix> {
        setting(list, None).expect("valid")
    }

    /// Off: one probe for a leftover chain, then the exact MASQUERADE of before.
    #[test]
    fn no_excludes_installs_the_single_masquerade_of_before() {
        let mut ipt = Fake::default();
        install("10.45.0.0/16", "ogstun", &[], &mut ipt).expect("ok");
        assert_eq!(
            ipt.calls,
            vec![
                format!("-t nat -L {CHAIN} -n"),
                "-t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE".to_string(),
            ]
        );
        assert_eq!(
            ipt.postrouting,
            vec!["-s 10.45.0.0/16 ! -o ogstun -j MASQUERADE"]
        );
    }

    /// The exclusions go in their own chain, jumped to from the HEAD of
    /// POSTROUTING: ahead of a MASQUERADE that was already there (a container
    /// wrapper's) as well as the UPF's own.
    #[test]
    fn excludes_are_jumped_to_ahead_of_any_masquerade() {
        let mut ipt = Fake {
            postrouting: vec!["-s 10.45.0.0/16 ! -o ogstun -j MASQUERADE".into()],
            ..Default::default()
        };
        install(
            "10.45.0.0/16",
            "ogstun",
            &prefixes("10.60.0.0/24,172.30.1.9"),
            &mut ipt,
        )
        .expect("ok");
        assert_eq!(
            ipt.chain,
            Some(vec![
                "-s 10.45.0.0/16 -d 10.60.0.0/24 -j ACCEPT".to_string(),
                "-s 10.45.0.0/16 -d 172.30.1.9/32 -j ACCEPT".to_string(),
            ])
        );
        assert_eq!(
            ipt.postrouting[0],
            format!("-j {CHAIN}"),
            "the jump is first"
        );
        assert_eq!(
            ipt.postrouting.len(),
            3,
            "jump + wrapper MASQUERADE + the UPF's own"
        );
    }

    /// A restart with another list leaves only the new list, and one jump.
    #[test]
    fn a_restart_replaces_the_list_and_does_not_duplicate_the_jump() {
        let mut ipt = Fake::default();
        install(
            "10.45.0.0/16",
            "ogstun",
            &prefixes("10.60.0.0/24"),
            &mut ipt,
        )
        .expect("ok");
        install(
            "10.45.0.0/16",
            "ogstun",
            &prefixes("10.61.0.0/24"),
            &mut ipt,
        )
        .expect("ok");
        assert_eq!(
            ipt.chain,
            Some(vec!["-s 10.45.0.0/16 -d 10.61.0.0/24 -j ACCEPT".to_string()])
        );
        let jumps = ipt
            .postrouting
            .iter()
            .filter(|r| *r == &format!("-j {CHAIN}"))
            .count();
        assert_eq!(jumps, 1);
        // And a restart with no list at all excludes nothing any more.
        install("10.45.0.0/16", "ogstun", &[], &mut ipt).expect("ok");
        assert_eq!(ipt.chain, Some(vec![]), "the leftover chain is flushed");
    }

    /// Any exclusion command that fails refuses startup; the MASQUERADE is never
    /// reached, so the excluded DN is not silently NATed.
    #[test]
    fn a_failed_exclusion_refuses_to_start() {
        for fail in ["-j ACCEPT", "-I POSTROUTING", "-F UPF-NAT-EXCLUDE"] {
            let mut ipt = Fake {
                fail: Some(fail),
                ..Default::default()
            };
            let err = install(
                "10.45.0.0/16",
                "ogstun",
                &prefixes("10.60.0.0/24"),
                &mut ipt,
            );
            assert!(err.is_err(), "{fail} must refuse");
            assert!(
                !ipt.calls.iter().any(|c| c.contains("MASQUERADE")),
                "{fail}: nothing NATs after a failed exclusion: {:?}",
                ipt.calls
            );
        }
        // The MASQUERADE itself stays warn-only, as before.
        let mut ipt = Fake {
            fail: Some("MASQUERADE"),
            ..Default::default()
        };
        assert!(install("10.45.0.0/16", "ogstun", &[], &mut ipt).is_ok());
    }

    /// The data plane installs ITS OWN `--nat-exclude` list (#1463 review 6: passing
    /// an empty list at the call site left every unit test green).
    #[test]
    fn the_data_plane_installs_its_configured_exclusions() {
        let mut dp = crate::data_plane::DataPlane::new(std::sync::Arc::new(
            std::sync::atomic::AtomicBool::new(false),
        ));
        dp.nat_exclude = prefixes("10.60.0.0/24");
        let mut ipt = Fake::default();
        dp.install_nat("ogstun", Ipv4Addr::new(10, 45, 0, 0), 16, &mut ipt)
            .expect("ok");
        assert_eq!(
            ipt.chain,
            Some(vec!["-s 10.45.0.0/16 -d 10.60.0.0/24 -j ACCEPT".to_string()])
        );
        assert_eq!(
            ipt.postrouting,
            vec![
                format!("-j {CHAIN}"),
                "-s 10.45.0.0/16 ! -o ogstun -j MASQUERADE".to_string()
            ]
        );
    }

    #[test]
    fn the_setting_reads_the_flag_then_the_env_dedupes_and_refuses_bad_entries() {
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
        assert_eq!(
            setting("10.60.0.9/24,10.60.0.0/24, 10.60.0.0/24", None)
                .unwrap()
                .len(),
            1,
            "duplicates, also after host bits are cleared, are one prefix"
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
