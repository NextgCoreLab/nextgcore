//! Transport Delay Reporting (TS 29.244 §5.24.5.3, IE 271), #1450.
//!
//! QoS monitoring of a QoS flow based on GTP-U path monitoring (GTPUPM = 1,
//! TS 23.501 §5.33.3.3): the SMF puts a Transport Delay Reporting IE
//! (Table 7.5.2.2-6) in the UL PDR of the monitored flow, in the PSA and in
//! every intermediate UPF. Each such UPF:
//! - measures the one-way delay of the GTP-U path with the preceding UL GTP-U
//!   peer the IE names (the gNB on N3, or the previous I-UPF on N9) as RTT/2
//!   of its own Echo Requests plus the UPF internal processing time (taken as
//!   0, as #1389 part 1 does for the same measurement);
//! - for a UL G-PDU whose PDU Session Container (TS 38.415 §5.5.2.2) carries the
//!   RAN DL and/or UL Delay Result, adds that delay to the "N3/N9 Delay Result"
//!   field (§5.5.3.21);
//! - an I-UPF sends the resulting value on in the container of the G-PDU it
//!   forwards to the PSA; the PSA uses it, with the RAN part, as the flow's
//!   delay (§5.24.5.4, in `qos_flow_mon`).
//!
//! Off unless `--gtpu-path-qos-monitoring` (GPQM, the feature §5.24.5 belongs
//! to) is set: without it IE 271 is ignored, nothing is probed, and no G-PDU
//! changes.
//!
//! The probes to a peer are sent with the DSCP the IE names (Table 7.5.2.2-6:
//! "the DSCP to use to measure the GTP-U path delay"), one probe series per
//! (peer, DSCP), on the GTP-U socket whose outer marking is set for the probe
//! and put back after it (#2197 review).
//!
//! Limitations, stated honestly:
//! - Until the first Echo Response from the preceding peer, and again once a
//!   probe to it goes unanswered for [`PROBE_TIMEOUT`], the delay is unknown:
//!   an I-UPF then forwards the field unchanged and a PSA takes no sample (a
//!   Measurement Period with none is a measurement failure, §5.24.4.3).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Probe sequence numbers live in 0xC000..=0xFFFF. The §7.2 path table uses
/// 1..=0x7FFF and the GTP-U path QoS probes 0x8000..=0xBFFF, so an Echo
/// Response names the one requester that sent it.
pub const SEQ_BASE: u16 = 0xC000;

/// An Echo Request unanswered after this long is forgotten, and with it the
/// peer's delay: a path that stopped answering has no current delay.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// At most this many probes are outstanding per peer; an older one is forgotten.
const MAX_PENDING: usize = 64;

/// At most this many PDRs carry Transport Delay Reporting UPF-wide; the rest are
/// ignored and logged. Bounded state for what the SMF provisions.
pub const MAX_PDRS: usize = 65_536;

/// What a UL PDR's Transport Delay Reporting IE asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportDelayPdr {
    /// The preceding UL GTP-U peer (M in Table 7.5.2.2-6).
    pub peer: IpAddr,
    /// The DSCP to measure with (O); not applied to the probes (module docs).
    pub dscp: Option<u8>,
}

impl TransportDelayPdr {
    /// From the IE. `None` (logged) when the Remote GTP-U Peer carries no IP
    /// address this UPF can probe.
    pub fn from_ie(ie: &nextgcore_pfcp::qos_monitoring::TransportDelayReporting) -> Option<Self> {
        let p = &ie.preceding_ul_gtpu_peer;
        let peer = p
            .ipv4
            .map(IpAddr::from)
            .or(p.ipv6.map(|a| IpAddr::from(a).to_canonical()));
        let Some(peer) = peer else {
            log::warn!(
                "Transport Delay Reporting names a Preceding UL GTP-U Peer with no IP address: \
                 not acted on"
            );
            return None;
        };
        Some(Self {
            peer,
            dscp: ie.dscp.as_ref().map(|t| t.dscp()),
        })
    }
}

#[derive(Debug, Default)]
struct PeerState {
    /// The most recent one-way delay, ms.
    delay_ms: Option<u32>,
    /// Outstanding probes: sequence number and when it was sent.
    pending: Vec<(u16, Instant)>,
}

/// The PDRs with Transport Delay Reporting, and the delay to each preceding peer.
#[derive(Debug, Default)]
pub struct TransportDelayMonitor {
    pdrs: HashMap<(u64, u16), TransportDelayPdr>,
    /// Per (preceding peer, DSCP): the delay is measured per marking.
    peers: HashMap<(IpAddr, Option<u8>), PeerState>,
    next_seq: u16,
}

impl TransportDelayMonitor {
    pub fn is_active(&self) -> bool {
        !self.pdrs.is_empty()
    }

    /// Provision (`Some`) or remove (`None`) PDR `pdr_id` of session `seid`.
    pub fn set_pdr(&mut self, seid: u64, pdr_id: u16, cfg: Option<TransportDelayPdr>) {
        match cfg {
            Some(c) => {
                if self.pdrs.len() >= MAX_PDRS && !self.pdrs.contains_key(&(seid, pdr_id)) {
                    log::warn!(
                        "SEID {seid:#x} PDR {pdr_id}: Transport Delay Reporting not acted on, \
                         {MAX_PDRS} PDRs already carry it"
                    );
                    return;
                }
                self.pdrs.insert((seid, pdr_id), c);
            }
            None => {
                self.pdrs.remove(&(seid, pdr_id));
            }
        }
        self.sync_peers();
    }

    /// The session is gone.
    pub fn remove_session(&mut self, seid: u64) {
        self.pdrs.retain(|(s, _), _| *s != seid);
        self.sync_peers();
    }

    /// The association is gone.
    pub fn clear(&mut self) {
        self.pdrs.clear();
        self.peers.clear();
    }

    /// Keep peer state for the peers some PDR names, and only those.
    fn sync_peers(&mut self) {
        let wanted: HashSet<(IpAddr, Option<u8>)> =
            self.pdrs.values().map(|c| (c.peer, c.dscp)).collect();
        self.peers.retain(|k, _| wanted.contains(k));
        for k in wanted {
            self.peers.entry(k).or_default();
        }
    }

    /// What PDR `pdr_id` of `seid` asks for, if anything.
    pub fn pdr(&self, seid: u64, pdr_id: u16) -> Option<TransportDelayPdr> {
        self.pdrs.get(&(seid, pdr_id)).copied()
    }

    /// The one-way delay to the preceding peer of PDR `pdr_id` of `seid`, ms:
    /// `None` when the PDR has no Transport Delay Reporting or the delay is not
    /// known (yet, or any more).
    pub fn delay_for(&self, seid: u64, pdr_id: u16) -> Option<u32> {
        let c = self.pdrs.get(&(seid, pdr_id))?;
        self.peers.get(&(c.peer, c.dscp))?.delay_ms
    }

    /// The probes to send at `now`: one Echo Request per preceding peer and
    /// DSCP, each with the DSCP to mark it with and its sequence number. A probe
    /// outstanding past [`PROBE_TIMEOUT`] is forgotten, and the delay with it.
    pub fn probes(&mut self, now: Instant) -> Vec<(SocketAddr, Option<u8>, u16)> {
        let mut peers: Vec<(IpAddr, Option<u8>)> = self.peers.keys().copied().collect();
        peers.sort();
        let mut out = Vec::with_capacity(peers.len());
        for (ip, dscp) in peers {
            let seq = SEQ_BASE | (self.next_seq & 0x3fff);
            self.next_seq = self.next_seq.wrapping_add(1);
            let st = self.peers.get_mut(&(ip, dscp)).expect("listed above");
            let before = st.pending.len();
            st.pending
                .retain(|(_, sent)| now.saturating_duration_since(*sent) < PROBE_TIMEOUT);
            if st.pending.len() < before {
                log::debug!("Transport delay probe to {ip} unanswered: its delay is unknown");
                st.delay_ms = None;
            }
            if st.pending.len() == MAX_PENDING {
                st.pending.remove(0);
            }
            st.pending.push((seq, now));
            out.push((SocketAddr::new(ip, crate::path_qos::GTPU_PORT), dscp, seq));
        }
        out
    }

    /// An Echo Response from `from` with `seq` at `now`. Returns the new delay
    /// when it answers one of these probes.
    pub fn on_echo_response(&mut self, from: SocketAddr, seq: u16, now: Instant) -> Option<u32> {
        let ip = from.ip().to_canonical();
        let st = self
            .peers
            .iter_mut()
            .find(|((p, _), st)| *p == ip && st.pending.iter().any(|(s, _)| *s == seq))?
            .1;
        let i = st.pending.iter().position(|(s, _)| *s == seq)?;
        let (_, sent) = st.pending.remove(i);
        let delay = crate::path_qos::path_delay_ms(now.saturating_duration_since(sent));
        st.delay_ms = Some(delay);
        Some(delay)
    }
}

/// The offset, in a UL PDU SESSION INFORMATION frame (TS 38.415 Figure
/// 5.5.2.2-1, the extension header content after its length octet), of the
/// N3/N9 Delay Result field: after the two fixed octets, the three time stamps
/// (QMP), the DL and UL Delay Results and the UL QFI Sequence Number.
fn n3_n9_offset(content: &[u8]) -> Option<usize> {
    let o0 = *content.first()?;
    if o0 >> 4 != 1 {
        return None;
    }
    let qmp = o0 & 0x08 != 0;
    let dl = o0 & 0x04 != 0;
    let ul = o0 & 0x02 != 0;
    let snp = o0 & 0x01 != 0;
    Some(2 + 24 * qmp as usize + 4 * dl as usize + 4 * ul as usize + 3 * snp as usize)
}

/// The most content octets one extension header carries: its length octet
/// counts 4-octet units (TS 29.281 §5.2.1), so 255 x 4 less the length and
/// next-type octets.
pub const MAX_CONTAINER_CONTENT: usize = 255 * 4 - 2;

/// Add `add_ms` to the N3/N9 Delay Result of a UL PDU SESSION INFORMATION frame
/// (`content`: the PDU Session Container extension header content, padding
/// included) that carries the RAN DL and/or UL Delay Result (TS 29.244
/// §5.24.5.3: only those packets). The field is created when absent (N3/N9
/// Delay Ind set, four octets inserted where Figure 5.5.2.2-1 puts them, so the
/// New IE Flags and whatever follows are kept as they are), else summed,
/// saturating.
///
/// `from_ran`: the preceding UL GTP-U peer is the NG-RAN. The field is then
/// SET to `add_ms`, never summed: TS 38.415 §5.5.3.21 has the N3/N9 Delay
/// Result "reported by the I-UPF", and TS 29.244 §5.24.5.3 NOTE says "The RAN
/// does not report the N3 path delay. The intermediate UPF connected to the
/// RAN adds the N3 delay", so a value present on a packet from the RAN is not
/// one any UPF wrote and is overwritten (#2197 review m2). Behind an I-UPF the
/// field is the upstream UPFs' accumulation and is summed into.
///
/// Returns `None`, changing nothing, for any other frame, and when the
/// inserted field would not fit one extension header
/// ([`MAX_CONTAINER_CONTENT`]): the container then goes on as it came.
pub fn add_n3_n9_delay(content: &[u8], add_ms: u32, from_ran: bool) -> Option<Vec<u8>> {
    let o0 = *content.first()?;
    if o0 & 0x06 == 0 {
        return None;
    }
    let at = n3_n9_offset(content)?;
    let present = content.get(1)? & 0x80 != 0;
    let mut out = content.to_vec();
    if present {
        let old = u32::from_be_bytes(content.get(at..at + 4)?.try_into().ok()?);
        let new = if from_ran {
            add_ms
        } else {
            old.saturating_add(add_ms)
        };
        out[at..at + 4].copy_from_slice(&new.to_be_bytes());
    } else {
        if at > content.len() || content.len() + 4 > MAX_CONTAINER_CONTENT {
            return None;
        }
        out[1] |= 0x80;
        out.splice(at..at, add_ms.to_be_bytes());
    }
    Some(out)
}

/// The N3/N9 Delay Result of a UL PDU SESSION INFORMATION frame, if present.
pub fn n3_n9_delay(content: &[u8]) -> Option<u32> {
    if content.get(1)? & 0x80 == 0 {
        return None;
    }
    let at = n3_n9_offset(content)?;
    Some(u32::from_be_bytes(
        content.get(at..at + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
#[path = "transport_delay_tests.rs"]
mod tests;
