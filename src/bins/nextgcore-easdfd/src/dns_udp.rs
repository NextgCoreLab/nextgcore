//! The EASDF's DNS/UDP plane (issue #276): the socket a UE or stub resolver can
//! actually reach.
//!
//! Before this, edge FQDNs resolved only over an SBI shim
//! (`GET /neasdf-dnscontext/v1/dns-queries?fqdn=...`), which no UE, resolver or
//! forwarder speaks. The resolution engine, the per-session handling rules and the
//! baseline patterns all existed and were reachable by nothing that would ask.
//!
//! # Behind the `dns-udp` cargo feature, off by default
//!
//! #276 asks for a cargo feature and gives the reason: unlike the rest of #114's
//! sub-items this one **binds a privileged port and changes the process's network
//! posture**, so leaving it uncompiled by default is the conservative trade. That
//! overrides this project's usual preference for a runtime switch — a preference
//! whose stated reason is that a gated path rots because CI builds default
//! features. Two things answer that here: the wire codec is NOT gated (see
//! [`crate::dns_wire`]), so all the parsing logic is compiled and tested on every
//! run; and CI gained an explicit `--features dns-udp` build+test step for this
//! crate, so the gated half cannot rot silently either.
//!
//! # Port 53 needs a capability
//!
//! Binding 53 requires `CAP_NET_BIND_SERVICE` (or root). The port is configurable
//! (`--dns-udp-port` / `easdf.dns.udp_port`) precisely so a deployment without
//! that capability can run the plane on a high port behind a redirect, and so the
//! tests can bind an ephemeral one.
//!
//! # Source-address scoping
//!
//! A DNS datagram carries no DNS-context id, so the **source address** is the only
//! correlator between a query and a PDU session. That is why the DNS context
//! carries the UE's address ([`crate::context::EasdfDnsContext::ue_addresses`]) and
//! why the SMF now sends it. A query from an unknown source is answered from the
//! static EAS map, baseline patterns and miss behaviour — never from some other
//! session's rules.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::context::{easdf_self, ResolveOutcome};
use crate::dns_wire::{
    self, build_error, build_response, parse_message, qtype, rcode, Question, Record, Response,
    CLASS_IN, MAX_EDNS_PAYLOAD,
};

/// TTL on an EASDF-authored answer, in seconds.
///
/// Deliberately short. An EAS address is a *steering* decision that the SMF may
/// re-take on the next DNS message report (UL-CL / PSA re-selection), so a UE
/// caching it for hours would keep using an EAS the network has moved away from.
/// 30s is the same order as the 5s NRF heartbeat this stack already runs on.
pub const ANSWER_TTL: u32 = 30;

/// How long to wait for an upstream forwarder before giving up.
const FORWARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Largest datagram accepted. A UDP DNS query above this is not a query we can
/// serve; the EDNS ceiling is the practical bound and this leaves headroom.
const RECV_BUF: usize = 4096;

/// What the plane needs from configuration.
#[derive(Debug, Clone)]
pub struct DnsUdpConfig {
    pub bind: SocketAddr,
    /// Where to forward a query the EASDF does not serve. `None` means a miss is
    /// answered `NXDOMAIN` locally.
    ///
    /// Kept separate from the resolution engine's `DnsMissBehavior::Forward`
    /// rather than derived from it: the engine's value is what it *reports* to an
    /// SBI caller (a "you should ask this server" answer), while this is the
    /// address this process dials itself. They come from the same YAML key today,
    /// and conflating the two would make a forward-on-the-wire silently impossible
    /// to configure independently later.
    pub upstream: Option<SocketAddr>,
}

/// Parse an upstream from config: a bare address gets the default DNS port.
pub fn parse_upstream(raw: &str) -> Option<SocketAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr);
    }
    match raw.parse::<IpAddr>() {
        Ok(ip) => Some(SocketAddr::new(ip, 53)),
        Err(_) => {
            log::warn!(
                "dns.upstream '{raw}' is not an IP address or address:port; \
                 UDP forwarding is disabled and a miss will answer NXDOMAIN"
            );
            None
        }
    }
}

/// Bind the socket and serve until the task is dropped.
///
/// Returns the bound address so a caller (and a test) can learn the port when 0
/// was requested.
pub async fn spawn(
    config: DnsUdpConfig,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let socket = Arc::new(UdpSocket::bind(config.bind).await?);
    let local = socket.local_addr()?;
    log::info!(
        "EASDF DNS/UDP listener bound on {local} (upstream: {})",
        config
            .upstream
            .map(|u| u.to_string())
            .unwrap_or_else(|| "none, a miss answers NXDOMAIN".to_string())
    );
    let handle = tokio::spawn(async move { serve(socket, config).await });
    Ok((local, handle))
}

async fn serve(socket: Arc<UdpSocket>, config: DnsUdpConfig) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("EASDF DNS/UDP recv failed: {e}");
                continue;
            }
        };
        let datagram = buf[..len].to_vec();
        let socket = socket.clone();
        let config = config.clone();
        // One task per datagram: a forward waits up to FORWARD_TIMEOUT on an
        // upstream, and doing that inline would stall every other UE's query
        // behind one slow forward.
        tokio::spawn(async move {
            if let Some(reply) = handle_datagram(&datagram, from, &config).await {
                if let Err(e) = socket.send_to(&reply, from).await {
                    log::warn!("EASDF DNS/UDP reply to {from} failed: {e}");
                }
            }
        });
    }
}

/// Turn one received datagram into the bytes to send back, or `None` when there
/// is nothing answerable.
///
/// Separated from the socket loop so every decision below is testable without a
/// network, and so the UDP test asserts the socket wiring rather than re-testing
/// the logic.
pub async fn handle_datagram(
    datagram: &[u8],
    from: SocketAddr,
    config: &DnsUdpConfig,
) -> Option<Vec<u8>> {
    let message = match parse_message(datagram) {
        Ok(m) => m,
        Err(e) => {
            if !e.is_answerable() {
                // No readable ID, so any "response" would be unmatchable noise.
                log::debug!("unanswerable DNS datagram from {from}: {e:?}");
                return None;
            }
            // The ID is at a fixed offset and was readable; echo it with FORMERR
            // so the client fails fast instead of retrying until it times out.
            let id = u16::from_be_bytes([datagram[0], datagram[1]]);
            log::debug!("malformed DNS query from {from}: {e:?}");
            return Some(build_error(id, None, rcode::FORM_ERR, false, false, None));
        }
    };

    // A response arriving on our listening socket is not ours to answer.
    if message.flags.response {
        log::debug!("ignoring a DNS RESPONSE received on the listener from {from}");
        return None;
    }

    let edns = message.edns;
    let recursion_available = config.upstream.is_some();

    // Only standard QUERY, exactly one question, class IN.
    if message.flags.opcode != 0 || message.question_count != 1 {
        return Some(build_error(
            message.id,
            message.question.as_ref(),
            if message.flags.opcode == 0 {
                rcode::FORM_ERR
            } else {
                rcode::NOT_IMP
            },
            message.flags.recursion_desired,
            recursion_available,
            edns,
        ));
    }
    let question = message.question.clone()?;
    if question.qclass != CLASS_IN {
        return Some(build_error(
            message.id,
            Some(&question),
            rcode::NOT_IMP,
            message.flags.recursion_desired,
            recursion_available,
            edns,
        ));
    }

    let ctx = easdf_self();
    let (outcome, report, ctx_id) = {
        match ctx.read() {
            Ok(c) => c.resolve_for_source(from.ip(), &question.name),
            Err(_) => {
                log::error!("EASDF context lock poisoned; answering SERVFAIL");
                return Some(build_error(
                    message.id,
                    Some(&question),
                    rcode::SERV_FAIL,
                    message.flags.recursion_desired,
                    recursion_available,
                    edns,
                ));
            }
        }
    };

    // TS 23.548 §6.2.3.2.2 DNS message reporting, on the UDP plane too: the SMF
    // needs to learn the resolved EAS to drive UL-CL insertion, and it needs to
    // learn it for a query that arrived over DNS just as much as for one that
    // arrived over the shim. Awaited before answering for the same reason the
    // shim awaits it: the SMF should not learn the address after the UE has it.
    if report {
        if let Some(id) = &ctx_id {
            let uri = easdf_self()
                .read()
                .ok()
                .and_then(|c| c.dns_context_notify_uri(id));
            match uri {
                Some(uri) => {
                    crate::send_dns_message_report(&uri, id, &question.name, &outcome).await
                }
                None => log::warn!(
                    "DNS context {id} has a rule requesting a report but no notification URI: \
                     the report for {} cannot be delivered",
                    question.name
                ),
            }
        }
    }

    match outcome {
        ResolveOutcome::Resolved(addresses) => Some(answer_records(
            &message,
            &question,
            &addresses,
            recursion_available,
        )),
        ResolveOutcome::Forward(reported) => {
            // The engine names an upstream; this plane dials the one it was
            // configured with. They are the same value in practice -- both come
            // from `easdf.dns.upstream` -- and when the plane has none, a
            // reported forward becomes a local NXDOMAIN rather than a lie.
            match config.upstream {
                Some(upstream) => match forward(datagram, upstream).await {
                    Some(reply) => Some(reply),
                    None => Some(build_error(
                        message.id,
                        Some(&question),
                        rcode::SERV_FAIL,
                        message.flags.recursion_desired,
                        recursion_available,
                        edns,
                    )),
                },
                None => {
                    log::debug!(
                        "resolution reported a forward to {reported} but no UDP upstream is \
                         configured; answering NXDOMAIN for {}",
                        question.name
                    );
                    Some(build_error(
                        message.id,
                        Some(&question),
                        rcode::NX_DOMAIN,
                        message.flags.recursion_desired,
                        false,
                        edns,
                    ))
                }
            }
        }
        ResolveOutcome::Miss => Some(build_error(
            message.id,
            Some(&question),
            rcode::NX_DOMAIN,
            message.flags.recursion_desired,
            recursion_available,
            edns,
        )),
    }
}

/// Build the answer for a name the EASDF serves.
///
/// A name that resolves but has no address of the QUERIED family answers
/// `NOERROR` with zero records (NODATA), not `NXDOMAIN`: the name demonstrably
/// exists, and telling a dual-stack resolver the name does not exist because we
/// hold no AAAA for it would make it stop asking for the A as well. Same answer
/// for a type we do not serve at all (`MX`, `SVCB`, …) — the name exists, we
/// simply hold no record of that type.
fn answer_records(
    message: &dns_wire::Message,
    question: &Question,
    addresses: &[String],
    recursion_available: bool,
) -> Vec<u8> {
    let records: Vec<Record> = if question.qtype == qtype::A || question.qtype == qtype::AAAA {
        addresses
            .iter()
            .filter_map(|raw| match raw.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => Some(Record::A(v4)),
                Ok(IpAddr::V6(v6)) => Some(Record::Aaaa(v6)),
                Err(_) => {
                    log::warn!(
                        "EAS address '{raw}' for {} is not an IP address; omitted from the answer",
                        question.name
                    );
                    None
                }
            })
            .filter(|r| r.answers(question.qtype))
            .collect()
    } else {
        Vec::new()
    };

    build_response(&Response {
        id: message.id,
        question: Some(question),
        recursion_desired: message.flags.recursion_desired,
        // The EASDF *is* the configured authority for a name its EAS map or a
        // handling rule answers.
        authoritative: true,
        recursion_available,
        rcode: rcode::NO_ERROR,
        records: &records,
        ttl: ANSWER_TTL,
        edns: message.edns,
    })
}

/// Relay a query to the upstream verbatim and return its reply verbatim.
///
/// Verbatim in both directions on purpose: the transaction ID, the question, the
/// EDNS OPT and any option we do not model all survive, which a parse-and-rebuild
/// would quietly drop. This is a forwarder, not a resolver — it does no caching
/// and no validation, and the answer the UE gets is the upstream's own.
async fn forward(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("EASDF DNS forward: cannot bind an ephemeral socket: {e}");
            return None;
        }
    };
    if let Err(e) = socket.send_to(query, upstream).await {
        log::warn!("EASDF DNS forward to {upstream} failed: {e}");
        return None;
    }
    let mut buf = vec![0u8; MAX_EDNS_PAYLOAD as usize];
    match tokio::time::timeout(FORWARD_TIMEOUT, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) => {
            // Only the address we asked answers for us; anything else is either a
            // stray datagram or an off-path spoof attempt.
            if from.ip() != upstream.ip() {
                log::warn!("EASDF DNS forward: reply from {from}, expected {upstream}; dropped");
                return None;
            }
            buf.truncate(len);
            Some(buf)
        }
        Ok(Err(e)) => {
            log::warn!("EASDF DNS forward recv from {upstream} failed: {e}");
            None
        }
        Err(_) => {
            log::warn!("EASDF DNS forward to {upstream} timed out after {FORWARD_TIMEOUT:?}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{
        easdf_context_final, easdf_context_init, DnsHandlingRule, DnsMissBehavior, EasMapEntry,
        EasdfDnsContext,
    };
    use crate::dns_wire::{Flags, HEADER_LEN};

    // The lock is `context::GLOBAL_TEST_LOCK`, shared with `main.rs`'s tests.
    // This module first declared its own `tokio::Mutex` and the result was a HANG,
    // not a failed assertion: a `easdf_context_final()` here wiped a sibling
    // handler test's EAS map mid-flight, its miss became a hit, and the fake
    // upstream it was blocked on never received a forward. See the doc comment on
    // `GLOBAL_TEST_LOCK`.
    use crate::context::lock_globals;

    /// Install a known EASDF configuration: one static EAS entry and the given
    /// miss behaviour.
    fn install_context(miss: DnsMissBehavior) {
        easdf_context_final();
        easdf_context_init(64);
        let ctx = easdf_self();
        let installed = ctx.write().map(|mut c| {
            c.set_dns_config(
                vec![EasMapEntry {
                    fqdn: "*.edge.example.com".to_string(),
                    addresses: vec!["10.60.0.1".to_string(), "2001:db8::60".to_string()],
                }],
                miss,
            );
        });
        assert!(
            installed.is_ok(),
            "the EASDF context lock must not be poisoned"
        );
    }

    /// A DNS context for `ue_ip` whose rule answers `fqdn` with `eas`.
    fn install_ue_context(ue_ip: &str, fqdn: &str, eas: &str) -> String {
        let ctx = easdf_self();
        let mut dns_ctx = EasdfDnsContext::new("imsi-001010000000001", 5, "{}");
        dns_ctx.handling_rules = vec![DnsHandlingRule {
            domain_patterns: vec![fqdn.to_string()],
            eas_addresses: vec![eas.to_string()],
            report: false,
            forward_to: None,
        }];
        dns_ctx.ue_addresses = vec![ue_ip.parse().expect("test address")];
        let id = dns_ctx.id.clone();
        ctx.read()
            .expect("context")
            .dns_context_insert(dns_ctx)
            .expect("insert");
        id
    }

    fn query(id: u16, name: &str, qt: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0u8; 6]);
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qt.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    fn no_upstream(bind: SocketAddr) -> DnsUdpConfig {
        DnsUdpConfig {
            bind,
            upstream: None,
        }
    }

    /// #276 criterion 2: a real UDP DNS query gets an A-record answer for an edge
    /// FQDN.
    ///
    /// Over a real socket in both directions — bind the listener, send from an
    /// ordinary client socket, read the datagram back and decode it with the
    /// production parser. A test that called `handle_datagram` directly would
    /// prove the logic and say nothing about whether anything is listening, which
    /// is the entire defect #276 exists to fix.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_real_udp_query_is_answered_with_an_a_record() {
        let _g = lock_globals();
        install_context(DnsMissBehavior::NxDomain);

        let (bound, listener) = spawn(no_upstream(([127, 0, 0, 1], 0).into()))
            .await
            .expect("bind an ephemeral DNS port");

        let client = UdpSocket::bind::<SocketAddr>(([127, 0, 0, 1], 0).into())
            .await
            .expect("client socket");
        client
            .send_to(&query(0xa1a1, "app.edge.example.com", qtype::A), bound)
            .await
            .expect("send query");

        let mut buf = vec![0u8; 1500];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut buf),
        )
        .await
        .expect("the listener must answer within 5s")
        .expect("recv");
        assert_eq!(from, bound, "the answer must come from the listener");

        let answer = parse_message(&buf[..len]).expect("the answer is a DNS message");
        assert_eq!(answer.id, 0xa1a1, "the transaction ID must be echoed");
        assert!(answer.flags.response);
        assert!(
            answer.flags.authoritative,
            "the EASDF is the authority here"
        );
        assert!(answer.flags.recursion_desired, "RD is echoed");
        assert!(
            !answer.flags.recursion_available,
            "no upstream is configured, so RA must be clear"
        );
        assert_eq!(answer.flags.rcode, rcode::NO_ERROR);
        assert_eq!(
            answer.answers,
            vec![Record::A(std::net::Ipv4Addr::new(10, 60, 0, 1))],
            "the A record from the EAS map, and NOT the AAAA also configured"
        );

        listener.abort();
        easdf_context_final();
    }

    /// The AAAA half of the same map entry, and the NODATA rule.
    ///
    /// An `AAAA` query gets the v6 address; a `MX` query for the same
    /// edge-served name gets `NOERROR` with no records, **not** `NXDOMAIN` — the
    /// name demonstrably exists, and telling a resolver otherwise would make it
    /// stop asking for the A record too.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn family_and_type_selection_answers_nodata_rather_than_nxdomain() {
        let _g = lock_globals();
        install_context(DnsMissBehavior::NxDomain);
        let config = no_upstream(([127, 0, 0, 1], 0).into());
        let from: SocketAddr = ([127, 0, 0, 1], 40000).into();

        let aaaa = handle_datagram(
            &query(1, "app.edge.example.com", qtype::AAAA),
            from,
            &config,
        )
        .await
        .expect("an answer");
        let aaaa = parse_message(&aaaa).expect("parses");
        assert_eq!(
            aaaa.answers,
            vec![Record::Aaaa("2001:db8::60".parse().expect("v6"))]
        );

        const MX: u16 = 15;
        let mx = handle_datagram(&query(2, "app.edge.example.com", MX), from, &config)
            .await
            .expect("an answer");
        let mx = parse_message(&mx).expect("parses");
        assert_eq!(
            mx.flags.rcode,
            rcode::NO_ERROR,
            "an edge-served name with no record of the queried type is NODATA, not NXDOMAIN"
        );
        assert!(mx.answers.is_empty());
        assert_eq!(
            mx.question.as_ref().map(|q| q.qtype),
            Some(MX),
            "the question is echoed with its original QTYPE"
        );

        easdf_context_final();
    }

    /// #276 criterion 3, both halves: a miss forwards to the configured upstream
    /// on the wire, and answers NXDOMAIN when there is none.
    ///
    /// The upstream is a real UDP socket that replies with a recognisable address,
    /// so the assertion is that the UE received the UPSTREAM's answer — not that
    /// the EASDF invented one. Asserting only "an answer arrived" would pass
    /// against a local NXDOMAIN.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_miss_forwards_to_the_upstream_and_nxdomains_without_one() {
        let _g = lock_globals();
        install_context(DnsMissBehavior::Forward("127.0.0.1".to_string()));

        // A fake upstream resolver: answers every query with 203.0.113.9.
        let upstream = UdpSocket::bind::<SocketAddr>(([127, 0, 0, 1], 0).into())
            .await
            .expect("upstream socket");
        let upstream_addr = upstream.local_addr().expect("addr");
        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            let (len, from) = upstream.recv_from(&mut buf).await.expect("recv");
            let request = parse_message(&buf[..len]).expect("the forward is a valid DNS query");
            let question = request.question.clone().expect("question forwarded intact");
            let reply = build_response(&Response {
                id: request.id,
                question: Some(&question),
                recursion_desired: request.flags.recursion_desired,
                authoritative: false,
                recursion_available: true,
                rcode: rcode::NO_ERROR,
                records: &[Record::A(std::net::Ipv4Addr::new(203, 0, 113, 9))],
                ttl: 60,
                edns: request.edns,
            });
            upstream.send_to(&reply, from).await.expect("reply");
            (request.id, question.name)
        });

        let forwarding = DnsUdpConfig {
            bind: ([127, 0, 0, 1], 0).into(),
            upstream: Some(upstream_addr),
        };
        let answer = handle_datagram(
            &query(0xbbbb, "www.elsewhere.example.net", qtype::A),
            ([127, 0, 0, 1], 40001).into(),
            &forwarding,
        )
        .await
        .expect("a forwarded answer");
        // Bounded: if a regression stops the forward from happening, the fake
        // upstream never receives and this await would block forever. A hang is a
        // strictly worse test failure than a failed assertion -- it takes the whole
        // suite with it -- and that is exactly what the lock split produced here.
        let (seen_id, seen_name) =
            tokio::time::timeout(std::time::Duration::from_secs(5), upstream_task)
                .await
                .expect("the upstream must receive the forwarded query within 5s")
                .expect("upstream task");
        assert_eq!(
            seen_id, 0xbbbb,
            "the query is forwarded VERBATIM, ID and all"
        );
        assert_eq!(seen_name, "www.elsewhere.example.net");

        let answer = parse_message(&answer).expect("parses");
        assert_eq!(answer.id, 0xbbbb);
        assert_eq!(
            answer.answers,
            vec![Record::A(std::net::Ipv4Addr::new(203, 0, 113, 9))],
            "the UE must receive the UPSTREAM's answer, not one the EASDF invented"
        );
        assert!(
            !answer.flags.authoritative,
            "a forwarded answer is not ours to claim authority for"
        );

        // Same query, no upstream configured: NXDOMAIN, and RA clear because this
        // EASDF cannot recurse for anyone.
        install_context(DnsMissBehavior::NxDomain);
        let answer = handle_datagram(
            &query(0xcccc, "www.elsewhere.example.net", qtype::A),
            ([127, 0, 0, 1], 40002).into(),
            &no_upstream(([127, 0, 0, 1], 0).into()),
        )
        .await
        .expect("an answer");
        let answer = parse_message(&answer).expect("parses");
        assert_eq!(answer.flags.rcode, rcode::NX_DOMAIN);
        assert!(answer.answers.is_empty());
        assert!(!answer.flags.recursion_available);

        easdf_context_final();
    }

    /// A configured forward with an unreachable upstream must SERVFAIL, not hang
    /// and not silently NXDOMAIN: NXDOMAIN would tell the UE the name does not
    /// exist, which is a different and stickier lie than "I could not find out".
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn an_unreachable_upstream_servfails() {
        let _g = lock_globals();
        install_context(DnsMissBehavior::Forward("127.0.0.1".to_string()));

        // A bound-then-dropped socket's port: nothing is listening there.
        let dead = {
            let s = UdpSocket::bind::<SocketAddr>(([127, 0, 0, 1], 0).into())
                .await
                .expect("socket");
            s.local_addr().expect("addr")
        };

        let answer = handle_datagram(
            &query(0xdddd, "www.elsewhere.example.net", qtype::A),
            ([127, 0, 0, 1], 40003).into(),
            &DnsUdpConfig {
                bind: ([127, 0, 0, 1], 0).into(),
                upstream: Some(dead),
            },
        )
        .await
        .expect("an answer");
        let answer = parse_message(&answer).expect("parses");
        assert_eq!(
            answer.flags.rcode,
            rcode::SERV_FAIL,
            "an upstream we could not reach is SERVFAIL, never NXDOMAIN"
        );

        easdf_context_final();
    }

    /// #276 criterion 4: two UEs with different DNS contexts get DIFFERENT
    /// answers for the SAME FQDN, scoped by the query's source address.
    ///
    /// This is the criterion the whole `ue_addresses` field exists for. Both
    /// queries are byte-identical apart from the transaction ID; the only thing
    /// that differs is where they came from. A third query, from an address no
    /// context claims, must fall through to the static EAS map — not to either
    /// UE's rules, which would leak one subscriber's edge steering into another's
    /// answer.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn two_ues_get_different_answers_for_the_same_fqdn() {
        let _g = lock_globals();
        install_context(DnsMissBehavior::NxDomain);
        install_ue_context("10.45.0.2", "app.edge.example.com", "10.60.0.201");
        install_ue_context("10.45.0.3", "app.edge.example.com", "10.60.0.202");

        let config = no_upstream(([127, 0, 0, 1], 0).into());
        let ask = |source: &str| {
            let config = config.clone();
            let source: SocketAddr = format!("{source}:40000").parse().expect("source");
            async move {
                let bytes =
                    handle_datagram(&query(7, "app.edge.example.com", qtype::A), source, &config)
                        .await
                        .expect("an answer");
                parse_message(&bytes).expect("parses").answers
            }
        };

        assert_eq!(
            ask("10.45.0.2").await,
            vec![Record::A(std::net::Ipv4Addr::new(10, 60, 0, 201))],
            "the first UE must get its OWN context's EAS address"
        );
        assert_eq!(
            ask("10.45.0.3").await,
            vec![Record::A(std::net::Ipv4Addr::new(10, 60, 0, 202))],
            "the second UE must get its own, not the first UE's"
        );
        assert_eq!(
            ask("10.45.0.99").await,
            vec![Record::A(std::net::Ipv4Addr::new(10, 60, 0, 1))],
            "an unknown source falls through to the static EAS map, never to \
             another session's rules"
        );

        easdf_context_final();
    }

    /// Malformed input, in the three shapes that differ in what can be answered.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn malformed_datagrams_are_answered_or_dropped_deliberately() {
        let _g = lock_globals();
        install_context(DnsMissBehavior::NxDomain);
        let config = no_upstream(([127, 0, 0, 1], 0).into());
        let from: SocketAddr = ([127, 0, 0, 1], 40004).into();

        // Too short to hold an ID: nothing to answer, so nothing is sent.
        assert!(
            handle_datagram(&[0u8; 4], from, &config).await.is_none(),
            "a datagram with no readable ID gets no reply"
        );

        // Header present, question missing: FORMERR with the ID echoed.
        let mut stub = Vec::new();
        stub.extend_from_slice(&0xeeeeu16.to_be_bytes());
        stub.extend_from_slice(&0u16.to_be_bytes());
        stub.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT lies
        stub.extend_from_slice(&[0u8; 6]);
        assert_eq!(stub.len(), HEADER_LEN);
        let reply = handle_datagram(&stub, from, &config)
            .await
            .expect("FORMERR is sendable");
        let reply = parse_message(&reply).expect("parses");
        assert_eq!(reply.id, 0xeeee);
        assert_eq!(reply.flags.rcode, rcode::FORM_ERR);

        // A RESPONSE arriving on the listener is not ours to answer; replying
        // would make two EASDFs pointed at each other into a packet loop.
        let mut response = query(0xffff, "app.edge.example.com", qtype::A);
        response[2] |= 0x80; // set QR
        assert!(
            handle_datagram(&response, from, &config).await.is_none(),
            "a DNS response received on the listener is dropped"
        );

        // A non-QUERY opcode (here: STATUS = 2) is NOTIMP, not FORMERR.
        let mut status = query(0x1111, "app.edge.example.com", qtype::A);
        status[2] |= 2 << 3; // OPCODE occupies bits 11..14 of the flags word
        let reply = handle_datagram(&status, from, &config)
            .await
            .expect("an answer");
        let reply = parse_message(&reply).expect("parses");
        assert_eq!(reply.flags.rcode, rcode::NOT_IMP);

        easdf_context_final();
    }

    /// A class other than IN is NOTIMP: this EASDF serves internet-class names
    /// and has no opinion about CHAOS or HESIOD.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_non_internet_class_query_is_notimp() {
        let _g = lock_globals();
        install_context(DnsMissBehavior::NxDomain);

        let mut wire = query(0x2222, "app.edge.example.com", qtype::A);
        let len = wire.len();
        wire[len - 2..].copy_from_slice(&3u16.to_be_bytes()); // CLASS CH

        let reply = handle_datagram(
            &wire,
            ([127, 0, 0, 1], 40005).into(),
            &no_upstream(([127, 0, 0, 1], 0).into()),
        )
        .await
        .expect("an answer");
        assert_eq!(
            parse_message(&reply).expect("parses").flags.rcode,
            rcode::NOT_IMP
        );

        easdf_context_final();
    }

    #[test]
    fn an_upstream_gets_the_default_dns_port_and_a_bad_one_is_refused() {
        assert_eq!(
            parse_upstream("8.8.8.8"),
            Some(([8, 8, 8, 8], 53).into()),
            "a bare address gets port 53"
        );
        assert_eq!(
            parse_upstream("127.0.0.1:5353"),
            Some(([127, 0, 0, 1], 5353).into()),
            "an explicit port is honoured"
        );
        assert_eq!(parse_upstream(""), None);
        assert_eq!(
            parse_upstream("dns.example.com"),
            None,
            "a hostname is refused rather than resolved: the EASDF would have to \
             ask a resolver to find its own resolver"
        );
    }

    /// Flags are read from the right bits. Cheap, and the kind of thing that is
    /// wrong by one shift for a long time before anyone notices.
    #[test]
    fn header_flags_decode_from_their_documented_bits() {
        let mut wire = query(1, "a.example.com", qtype::A);
        // QR=1, OPCODE=0, AA=1, TC=1, RD=1, RA=1, RCODE=3
        wire[2] = 0b1000_0111;
        wire[3] = 0b1000_0011;
        let flags = parse_message(&wire).expect("parses").flags;
        assert_eq!(
            flags,
            Flags {
                response: true,
                opcode: 0,
                authoritative: true,
                truncated: true,
                recursion_desired: true,
                recursion_available: true,
                rcode: rcode::NX_DOMAIN,
            }
        );
    }
}
