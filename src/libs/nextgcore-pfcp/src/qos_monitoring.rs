//! Typed codecs for the PFCP QoS-monitoring, GTP-U path monitoring and N6
//! delay measurement IEs (TS 29.244 V20.0.0, "29244-k00").
//!
//! - Per QoS flow per UE QoS monitoring (§5.24.4): IEs 242-248.
//! - Per GTP-U path QoS monitoring (§5.24.5): IEs 234-241, and the Transport
//!   Delay Reporting IE 271 an I-UPF gets in its UL Create PDR (§5.24.5.3).
//! - N6 delay measurement (§5.33.8), node-level: IEs 354-358 and the members
//!   of their grouped IEs (375-379).
//!
//! Codec only: nothing in this module is reachable from a message encoder or
//! decoder, so adding it changes no wire output. The PFCP library is shared by
//! smfd, upfd, sgwcd, sgwud and mbsmfd.
//!
//! Conventions:
//! - [`TypedIe::encode_value`] writes the IE value (octet 5 onward) and
//!   [`TypedIe::encode_ie`] the whole TLV.
//! - Every IE here is "Extendable" (§8.1.2), so decoders ignore trailing
//!   octets after the fields they know, and ignore spare bits.
//! - A grouped IE models the members this tree uses as typed fields and keeps
//!   every other member IE (Rel-18+ additions such as Reporting Thresholds or
//!   Protocol Specific Configuration Parameters) byte-exact in `extra`, so a
//!   decode/encode round trip loses nothing. Typed members are emitted in the
//!   spec table's order, then `extra`.
//! - A grouped IE missing a mandatory member fails to decode with
//!   [`PfcpError::MissingMandatoryIe`].

use crate::error::{PfcpError, PfcpResult};
use crate::ie::{IeHeader, IeType, RawIe};
use crate::types::RemoteGtpUPeer;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A PFCP IE with a typed value codec.
pub trait TypedIe: Sized {
    /// The IE type this codec encodes and decodes.
    const IE_TYPE: IeType;

    /// Encode the IE value (octets 5 to n+4).
    fn encode_value(&self, buf: &mut BytesMut);

    /// Decode the IE value (octets 5 to n+4).
    fn decode_value(data: &[u8]) -> PfcpResult<Self>;

    /// Encode the whole IE: Type, Length and value.
    fn encode_ie(&self, buf: &mut BytesMut) {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        IeHeader::new(Self::IE_TYPE as u16, value.len() as u16).encode(buf);
        buf.put_slice(&value);
    }

    /// Decode a whole IE, checking its type.
    fn decode_ie(buf: &mut Bytes) -> PfcpResult<Self> {
        let ie = RawIe::decode(buf)?;
        if ie.ie_type != Self::IE_TYPE as u16 {
            return Err(PfcpError::InvalidIeType(ie.ie_type));
        }
        Self::decode_value(&ie.data)
    }
}

fn need(data: &[u8], at: usize, n: usize) -> PfcpResult<()> {
    if data.len() < at + n {
        return Err(PfcpError::BufferTooShort {
            needed: at + n,
            available: data.len(),
        });
    }
    Ok(())
}

fn u32_at(data: &[u8], at: usize) -> PfcpResult<u32> {
    need(data, at, 4)?;
    Ok(u32::from_be_bytes([
        data[at],
        data[at + 1],
        data[at + 2],
        data[at + 3],
    ]))
}

fn u16_at(data: &[u8], at: usize) -> PfcpResult<u16> {
    need(data, at, 2)?;
    Ok(u16::from_be_bytes([data[at], data[at + 1]]))
}

fn missing(what: &str) -> PfcpError {
    PfcpError::MissingMandatoryIe(what.to_string())
}

fn put_member<T: TypedIe>(buf: &mut BytesMut, ie: &T) {
    ie.encode_ie(buf);
}

fn put_raw_member(buf: &mut BytesMut, ie_type: IeType, value: &[u8]) {
    IeHeader::new(ie_type as u16, value.len() as u16).encode(buf);
    buf.put_slice(value);
}

fn put_u32_member(buf: &mut BytesMut, ie_type: IeType, v: u32) {
    put_raw_member(buf, ie_type, &v.to_be_bytes());
}

fn put_extra(buf: &mut BytesMut, extra: &[RawIe]) {
    for ie in extra {
        ie.encode(buf);
    }
}

fn members(data: &[u8]) -> PfcpResult<Vec<RawIe>> {
    let mut buf = Bytes::copy_from_slice(data);
    let mut out = Vec::new();
    while buf.has_remaining() {
        out.push(RawIe::decode(&mut buf)?);
    }
    Ok(out)
}

fn is(ie: &RawIe, t: IeType) -> bool {
    ie.ie_type == t as u16
}

// ============================================================================
// Shared leaf members (QFI, Transport Level Marking, Timer, timestamps)
// ============================================================================

/// QFI (IE 124, §8.2.89): octet 5 bits 1-6; bits 7-8 spare.
fn decode_qfi(data: &[u8]) -> PfcpResult<u8> {
    need(data, 0, 1)?;
    Ok(data[0] & 0x3f)
}

/// Transport Level Marking (IE 30, §8.2.12): the two-octet ToS/Traffic Class
/// OctetString, the DSCP-bearing value and its mask (0xFC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLevelMarking {
    pub tos_traffic_class: u8,
    pub mask: u8,
}

impl TransportLevelMarking {
    /// The marking for a DSCP codepoint: the ToS octet with the mask 0xFC.
    pub fn from_dscp(dscp: u8) -> Self {
        Self {
            tos_traffic_class: (dscp & 0x3f) << 2,
            mask: 0xfc,
        }
    }

    /// The DSCP codepoint this marking carries.
    pub fn dscp(&self) -> u8 {
        self.tos_traffic_class >> 2
    }
}

impl TypedIe for TransportLevelMarking {
    const IE_TYPE: IeType = IeType::TransportLevelMarking;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.tos_traffic_class);
        buf.put_u8(self.mask);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 2)?;
        Ok(Self {
            tos_traffic_class: data[0],
            mask: data[1],
        })
    }
}

/// Timer (IE 55, §8.2.35): octet 5 is the timer unit (bits 6-8) and the
/// binary-coded timer value (bits 1-5). Used as "Minimum Waiting Time" in the
/// GTP-U path and N6 delay control IEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timer {
    pub unit: u8,
    pub value: u8,
}

impl TypedIe for Timer {
    const IE_TYPE: IeType = IeType::Timer;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(((self.unit & 0x07) << 5) | (self.value & 0x1f));
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        Ok(Self {
            unit: data[0] >> 5,
            value: data[0] & 0x1f,
        })
    }
}

// ============================================================================
// Leaf IEs 234-237, 241 (GTP-U path QoS monitoring)
// ============================================================================

macro_rules! delay_ie {
    ($(#[$doc:meta])* $name:ident, $t:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub u32);

        impl TypedIe for $name {
            const IE_TYPE: IeType = IeType::$t;

            fn encode_value(&self, buf: &mut BytesMut) {
                buf.put_u32(self.0);
            }

            fn decode_value(data: &[u8]) -> PfcpResult<Self> {
                Ok(Self(u32_at(data, 0)?))
            }
        }
    };
}

delay_ie!(
    /// Average Packet Delay (IE 234, §8.2.162): Unsigned32, milliseconds.
    AveragePacketDelay,
    AveragePacketDelay
);
delay_ie!(
    /// Minimum Packet Delay (IE 235, §8.2.163): Unsigned32, milliseconds.
    MinimumPacketDelay,
    MinimumPacketDelay
);
delay_ie!(
    /// Maximum Packet Delay (IE 236, §8.2.164): Unsigned32, milliseconds.
    MaximumPacketDelay,
    MaximumPacketDelay
);
delay_ie!(
    /// Minimum Wait Time (IE 246, §8.2.170): Unsigned32, seconds.
    MinimumWaitTime,
    MinimumWaitTime
);

/// QoS Report Trigger (IE 237, §8.2.165): octet 5 bit 1 PER, bit 2 THR, bit 3 IRE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QosReportTrigger {
    pub per: bool,
    pub thr: bool,
    pub ire: bool,
}

impl TypedIe for QosReportTrigger {
    const IE_TYPE: IeType = IeType::QosReportTrigger;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8((self.per as u8) | ((self.thr as u8) << 1) | ((self.ire as u8) << 2));
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        Ok(Self {
            per: data[0] & 0x01 != 0,
            thr: data[0] & 0x02 != 0,
            ire: data[0] & 0x04 != 0,
        })
    }
}

/// GTP-U Path Interface Type (IE 241, §8.2.166): octet 5 bit 1 N9, bit 2 N3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GtpUPathInterfaceType {
    pub n9: bool,
    pub n3: bool,
}

impl TypedIe for GtpUPathInterfaceType {
    const IE_TYPE: IeType = IeType::GtpUPathInterfaceType;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8((self.n9 as u8) | ((self.n3 as u8) << 1));
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        Ok(Self {
            n9: data[0] & 0x01 != 0,
            n3: data[0] & 0x02 != 0,
        })
    }
}

impl TypedIe for RemoteGtpUPeer {
    const IE_TYPE: IeType = IeType::RemoteGtpUPeer;

    fn encode_value(&self, buf: &mut BytesMut) {
        self.encode(buf);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        RemoteGtpUPeer::decode(data)
    }
}

// ============================================================================
// Grouped IEs 238-240 (GTP-U path QoS monitoring) and 271
// ============================================================================

/// GTP-U Path QoS Control Information (IE 238, Table 7.4.4.1.3-1), in a PFCP
/// Association Setup / Update Request from the SMF.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GtpUPathQosControlInformation {
    /// C: the remote GTP-U peers to report on (NOTE: at least one of these
    /// or the interface type is present).
    pub remote_gtpu_peers: Vec<RemoteGtpUPeer>,
    /// C: the interface type of the GTP-U paths to report on.
    pub gtpu_path_interface_type: Option<GtpUPathInterfaceType>,
    /// M.
    pub qos_report_trigger: QosReportTrigger,
    /// C: the DSCP values to measure the delay with (Transport Level Marking).
    pub dscp: Vec<TransportLevelMarking>,
    /// C: present when the trigger is periodic, seconds (Measurement Period).
    pub measurement_period: Option<u32>,
    /// C: thresholds, milliseconds (Average/Minimum/Maximum Packet Delay).
    pub average_packet_delay_threshold: Option<u32>,
    pub minimum_packet_delay_threshold: Option<u32>,
    pub maximum_packet_delay_threshold: Option<u32>,
    /// C: Minimum Waiting Time (Timer).
    pub minimum_waiting_time: Option<Timer>,
    /// Member IEs not modelled above, kept byte-exact.
    pub extra: Vec<RawIe>,
}

impl TypedIe for GtpUPathQosControlInformation {
    const IE_TYPE: IeType = IeType::GtpUPathQosControlInformation;

    fn encode_value(&self, buf: &mut BytesMut) {
        for peer in &self.remote_gtpu_peers {
            put_member(buf, peer);
        }
        if let Some(t) = &self.gtpu_path_interface_type {
            put_member(buf, t);
        }
        put_member(buf, &self.qos_report_trigger);
        for d in &self.dscp {
            put_member(buf, d);
        }
        if let Some(p) = self.measurement_period {
            put_u32_member(buf, IeType::MeasurementPeriod, p);
        }
        if let Some(v) = self.average_packet_delay_threshold {
            put_member(buf, &AveragePacketDelay(v));
        }
        if let Some(v) = self.minimum_packet_delay_threshold {
            put_member(buf, &MinimumPacketDelay(v));
        }
        if let Some(v) = self.maximum_packet_delay_threshold {
            put_member(buf, &MaximumPacketDelay(v));
        }
        if let Some(t) = &self.minimum_waiting_time {
            put_member(buf, t);
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let mut trigger = None;
        for ie in members(data)? {
            if is(&ie, IeType::RemoteGtpUPeer) {
                out.remote_gtpu_peers
                    .push(RemoteGtpUPeer::decode_value(&ie.data)?);
            } else if is(&ie, IeType::GtpUPathInterfaceType) {
                out.gtpu_path_interface_type = Some(GtpUPathInterfaceType::decode_value(&ie.data)?);
            } else if is(&ie, IeType::QosReportTrigger) {
                trigger = Some(QosReportTrigger::decode_value(&ie.data)?);
            } else if is(&ie, IeType::TransportLevelMarking) {
                out.dscp
                    .push(TransportLevelMarking::decode_value(&ie.data)?);
            } else if is(&ie, IeType::MeasurementPeriod) {
                out.measurement_period = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::AveragePacketDelay) {
                out.average_packet_delay_threshold = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::MinimumPacketDelay) {
                out.minimum_packet_delay_threshold = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::MaximumPacketDelay) {
                out.maximum_packet_delay_threshold = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::Timer) {
                out.minimum_waiting_time = Some(Timer::decode_value(&ie.data)?);
            } else {
                out.extra.push(ie);
            }
        }
        out.qos_report_trigger = trigger
            .ok_or_else(|| missing("GTP-U Path QoS Control Information: QoS Report Trigger"))?;
        // Table 7.4.4.1.3-1 NOTE: at least one Remote GTP-U Peer IE or GTP-U
        // Path Interface Type IE shall be present.
        if out.remote_gtpu_peers.is_empty() && out.gtpu_path_interface_type.is_none() {
            return Err(missing(
                "GTP-U Path QoS Control Information: Remote GTP-U Peer or GTP-U Path Interface Type",
            ));
        }
        Ok(out)
    }
}

/// QoS Information in GTP-U Path QoS Report (IE 240, Table 7.4.5.1.6-1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QosInformationInGtpUPathQosReport {
    /// M, milliseconds.
    pub average_packet_delay: u32,
    /// C, milliseconds.
    pub minimum_packet_delay: Option<u32>,
    pub maximum_packet_delay: Option<u32>,
    /// C: the DSCP used in the Echo messages that measured the delay.
    pub dscp: Option<TransportLevelMarking>,
    pub extra: Vec<RawIe>,
}

impl TypedIe for QosInformationInGtpUPathQosReport {
    const IE_TYPE: IeType = IeType::QosInformationInGtpUPathQosReport;

    fn encode_value(&self, buf: &mut BytesMut) {
        put_member(buf, &AveragePacketDelay(self.average_packet_delay));
        if let Some(v) = self.minimum_packet_delay {
            put_member(buf, &MinimumPacketDelay(v));
        }
        if let Some(v) = self.maximum_packet_delay {
            put_member(buf, &MaximumPacketDelay(v));
        }
        if let Some(d) = &self.dscp {
            put_member(buf, d);
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let mut avg = None;
        for ie in members(data)? {
            if is(&ie, IeType::AveragePacketDelay) {
                avg = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::MinimumPacketDelay) {
                out.minimum_packet_delay = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::MaximumPacketDelay) {
                out.maximum_packet_delay = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::TransportLevelMarking) {
                out.dscp = Some(TransportLevelMarking::decode_value(&ie.data)?);
            } else {
                out.extra.push(ie);
            }
        }
        out.average_packet_delay = avg.ok_or_else(|| {
            missing("QoS Information in GTP-U Path QoS Report: Average Packet Delay")
        })?;
        Ok(out)
    }
}

/// GTP-U Path QoS Report (IE 239, Table 7.4.5.1.5-1), in a PFCP Node Report
/// Request from the UPF.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GtpUPathQosReport {
    /// M.
    pub remote_gtpu_peer: RemoteGtpUPeer,
    /// C.
    pub gtpu_path_interface_type: Option<GtpUPathInterfaceType>,
    /// M.
    pub qos_report_trigger: QosReportTrigger,
    /// M: when this report was generated (Time Stamp, NTP seconds).
    pub time_stamp: u32,
    /// C: when collection started (Start Time, NTP seconds).
    pub start_time: Option<u32>,
    /// M, one or more (e.g. one per DSCP).
    pub qos_information: Vec<QosInformationInGtpUPathQosReport>,
    pub extra: Vec<RawIe>,
}

impl TypedIe for GtpUPathQosReport {
    const IE_TYPE: IeType = IeType::GtpUPathQosReport;

    fn encode_value(&self, buf: &mut BytesMut) {
        put_member(buf, &self.remote_gtpu_peer);
        if let Some(t) = &self.gtpu_path_interface_type {
            put_member(buf, t);
        }
        put_member(buf, &self.qos_report_trigger);
        put_u32_member(buf, IeType::TimeStamp, self.time_stamp);
        if let Some(st) = self.start_time {
            put_u32_member(buf, IeType::StartTime, st);
        }
        for q in &self.qos_information {
            put_member(buf, q);
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let (mut peer, mut trigger, mut ts) = (None, None, None);
        for ie in members(data)? {
            if is(&ie, IeType::RemoteGtpUPeer) {
                peer = Some(RemoteGtpUPeer::decode_value(&ie.data)?);
            } else if is(&ie, IeType::GtpUPathInterfaceType) {
                out.gtpu_path_interface_type = Some(GtpUPathInterfaceType::decode_value(&ie.data)?);
            } else if is(&ie, IeType::QosReportTrigger) {
                trigger = Some(QosReportTrigger::decode_value(&ie.data)?);
            } else if is(&ie, IeType::TimeStamp) {
                ts = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::StartTime) {
                out.start_time = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::QosInformationInGtpUPathQosReport) {
                out.qos_information
                    .push(QosInformationInGtpUPathQosReport::decode_value(&ie.data)?);
            } else {
                out.extra.push(ie);
            }
        }
        out.remote_gtpu_peer =
            peer.ok_or_else(|| missing("GTP-U Path QoS Report: Remote GTP-U Peer"))?;
        out.qos_report_trigger =
            trigger.ok_or_else(|| missing("GTP-U Path QoS Report: QoS Report Trigger"))?;
        out.time_stamp = ts.ok_or_else(|| missing("GTP-U Path QoS Report: Time Stamp"))?;
        if out.qos_information.is_empty() {
            return Err(missing("GTP-U Path QoS Report: QoS Information"));
        }
        Ok(out)
    }
}

/// Transport Delay Reporting (IE 271, Table 7.5.2.2-6), in the UL Create PDR
/// an I-UPF gets when the delay is measured by GTP-U path monitoring
/// (§5.24.5.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransportDelayReporting {
    /// M: the preceding UL GTP-U peer (a Remote GTP-U Peer IE).
    pub preceding_ul_gtpu_peer: RemoteGtpUPeer,
    /// O: the DSCP to measure the GTP-U path delay with.
    pub dscp: Option<TransportLevelMarking>,
    pub extra: Vec<RawIe>,
}

impl TypedIe for TransportDelayReporting {
    const IE_TYPE: IeType = IeType::TransportDelayReporting;

    fn encode_value(&self, buf: &mut BytesMut) {
        put_member(buf, &self.preceding_ul_gtpu_peer);
        if let Some(d) = &self.dscp {
            put_member(buf, d);
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let mut peer = None;
        for ie in members(data)? {
            if is(&ie, IeType::RemoteGtpUPeer) {
                peer = Some(RemoteGtpUPeer::decode_value(&ie.data)?);
            } else if is(&ie, IeType::TransportLevelMarking) {
                out.dscp = Some(TransportLevelMarking::decode_value(&ie.data)?);
            } else {
                out.extra.push(ie);
            }
        }
        out.preceding_ul_gtpu_peer =
            peer.ok_or_else(|| missing("Transport Delay Reporting: Preceding UL GTP-U Peer"))?;
        Ok(out)
    }
}

// ============================================================================
// Per QoS flow QoS monitoring, IEs 242-248
// ============================================================================

/// Requested QoS Monitoring (IE 243, §8.2.167).
///
/// Octet 5: DLPD ULPD RPPD GTPUPM DLCI ULCI DLDR ULDR (bits 1-8); octet 6:
/// DLAB ULAB (bits 1-2). Encoded at its minimal length: octet 6 is only sent
/// when DLAB or ULAB is set, so a Rel-16/17 peer (fixed length 1) gets the
/// one octet it expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RequestedQosMonitoring {
    pub dlpd: bool,
    pub ulpd: bool,
    pub rppd: bool,
    pub gtpupm: bool,
    pub dlci: bool,
    pub ulci: bool,
    pub dldr: bool,
    pub uldr: bool,
    pub dlab: bool,
    pub ulab: bool,
}

impl TypedIe for RequestedQosMonitoring {
    const IE_TYPE: IeType = IeType::RequestedQosMonitoring;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(
            (self.dlpd as u8)
                | ((self.ulpd as u8) << 1)
                | ((self.rppd as u8) << 2)
                | ((self.gtpupm as u8) << 3)
                | ((self.dlci as u8) << 4)
                | ((self.ulci as u8) << 5)
                | ((self.dldr as u8) << 6)
                | ((self.uldr as u8) << 7),
        );
        if self.dlab || self.ulab {
            buf.put_u8((self.dlab as u8) | ((self.ulab as u8) << 1));
        }
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        let b = data[0];
        let b6 = data.get(1).copied().unwrap_or(0);
        Ok(Self {
            dlpd: b & 0x01 != 0,
            ulpd: b & 0x02 != 0,
            rppd: b & 0x04 != 0,
            gtpupm: b & 0x08 != 0,
            dlci: b & 0x10 != 0,
            ulci: b & 0x20 != 0,
            dldr: b & 0x40 != 0,
            uldr: b & 0x80 != 0,
            dlab: b6 & 0x01 != 0,
            ulab: b6 & 0x02 != 0,
        })
    }
}

/// Reporting Frequency (IE 244, §8.2.168): octet 5 bit 1 EVETT, bit 2 PERIO.
/// Bit 3 is Reserved (deprecated SESRL): never set, ignored on receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportingFrequency {
    pub evett: bool,
    pub perio: bool,
}

impl TypedIe for ReportingFrequency {
    const IE_TYPE: IeType = IeType::ReportingFrequency;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8((self.evett as u8) | ((self.perio as u8) << 1));
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        Ok(Self {
            evett: data[0] & 0x01 != 0,
            perio: data[0] & 0x02 != 0,
        })
    }
}

/// Packet Delay Thresholds (IE 245, §8.2.169): octet 5 flags DL (bit 1), UL
/// (bit 2), RP (bit 3), then the flagged Unsigned32 thresholds in DL, UL, RP
/// order, milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketDelayThresholds {
    pub downlink: Option<u32>,
    pub uplink: Option<u32>,
    pub round_trip: Option<u32>,
}

impl TypedIe for PacketDelayThresholds {
    const IE_TYPE: IeType = IeType::PacketDelayThresholds;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(
            (self.downlink.is_some() as u8)
                | ((self.uplink.is_some() as u8) << 1)
                | ((self.round_trip.is_some() as u8) << 2),
        );
        for v in [self.downlink, self.uplink, self.round_trip]
            .into_iter()
            .flatten()
        {
            buf.put_u32(v);
        }
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        let flags = data[0];
        let mut at = 1;
        let mut field = |bit: u8| -> PfcpResult<Option<u32>> {
            if flags & bit == 0 {
                return Ok(None);
            }
            let v = u32_at(data, at)?;
            at += 4;
            Ok(Some(v))
        };
        Ok(Self {
            downlink: field(0x01)?,
            uplink: field(0x02)?,
            round_trip: field(0x04)?,
        })
    }
}

/// The largest value the 5-octet data-rate fields of IE 248 can carry.
pub const MAX_DATA_RATE_KBPS: u64 = 0xff_ffff_ffff;

/// QoS Monitoring Measurement (IE 248, §8.2.171).
///
/// Octet 5 flags: DLPD ULPD RPPD PLMF DLCI ULCI DLDR ULDR (bits 1-8). The
/// flagged fields follow in that order: DL/UL/RP packet delay (Unsigned32,
/// ms), DL/UL congestion information (Unsigned16, 0..=10000 hundredths of a
/// percent), average DL/UL data rate (5 octets, kbps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QosMonitoringMeasurement {
    pub downlink_packet_delay: Option<u32>,
    pub uplink_packet_delay: Option<u32>,
    pub round_trip_packet_delay: Option<u32>,
    /// PLMF: no timestamp arrived in UL for longer than the Measurement Period.
    /// The spec forbids the three delay fields alongside it.
    pub packet_delay_measurement_failure: bool,
    pub downlink_congestion: Option<u16>,
    pub uplink_congestion: Option<u16>,
    /// kbps, at most [`MAX_DATA_RATE_KBPS`]; larger values are saturated.
    pub average_downlink_data_rate: Option<u64>,
    pub average_uplink_data_rate: Option<u64>,
}

impl TypedIe for QosMonitoringMeasurement {
    const IE_TYPE: IeType = IeType::QosMonitoringMeasurement;

    fn encode_value(&self, buf: &mut BytesMut) {
        let flags = (self.downlink_packet_delay.is_some() as u8)
            | ((self.uplink_packet_delay.is_some() as u8) << 1)
            | ((self.round_trip_packet_delay.is_some() as u8) << 2)
            | ((self.packet_delay_measurement_failure as u8) << 3)
            | ((self.downlink_congestion.is_some() as u8) << 4)
            | ((self.uplink_congestion.is_some() as u8) << 5)
            | ((self.average_downlink_data_rate.is_some() as u8) << 6)
            | ((self.average_uplink_data_rate.is_some() as u8) << 7);
        buf.put_u8(flags);
        for v in [
            self.downlink_packet_delay,
            self.uplink_packet_delay,
            self.round_trip_packet_delay,
        ]
        .into_iter()
        .flatten()
        {
            buf.put_u32(v);
        }
        for v in [self.downlink_congestion, self.uplink_congestion]
            .into_iter()
            .flatten()
        {
            buf.put_u16(v);
        }
        for v in [
            self.average_downlink_data_rate,
            self.average_uplink_data_rate,
        ]
        .into_iter()
        .flatten()
        {
            let v = v.min(MAX_DATA_RATE_KBPS);
            buf.put_slice(&v.to_be_bytes()[3..]);
        }
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        let flags = data[0];
        let mut at = 1;
        let mut out = Self {
            packet_delay_measurement_failure: flags & 0x08 != 0,
            ..Default::default()
        };
        for (bit, slot) in [
            (0x01, &mut out.downlink_packet_delay),
            (0x02, &mut out.uplink_packet_delay),
            (0x04, &mut out.round_trip_packet_delay),
        ] {
            if flags & bit != 0 {
                *slot = Some(u32_at(data, at)?);
                at += 4;
            }
        }
        for (bit, slot) in [
            (0x10, &mut out.downlink_congestion),
            (0x20, &mut out.uplink_congestion),
        ] {
            if flags & bit != 0 {
                *slot = Some(u16_at(data, at)?);
                at += 2;
            }
        }
        for (bit, slot) in [
            (0x40, &mut out.average_downlink_data_rate),
            (0x80, &mut out.average_uplink_data_rate),
        ] {
            if flags & bit != 0 {
                need(data, at, 5)?;
                let mut b = [0u8; 8];
                b[3..].copy_from_slice(&data[at..at + 5]);
                *slot = Some(u64::from_be_bytes(b));
                at += 5;
            }
        }
        Ok(out)
    }
}

/// QoS Monitoring per QoS flow Control Information (IE 242, Table 7.5.2.9-3),
/// in a Create/Update SRR.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QosMonitoringPerQosFlowControlInformation {
    /// M, one or more QFIs (6-bit).
    pub qfis: Vec<u8>,
    /// M.
    pub requested_qos_monitoring: RequestedQosMonitoring,
    /// M.
    pub reporting_frequency: ReportingFrequency,
    /// C.
    pub packet_delay_thresholds: Option<PacketDelayThresholds>,
    /// C, seconds.
    pub minimum_wait_time: Option<u32>,
    /// C, seconds (Measurement Period).
    pub measurement_period: Option<u32>,
    /// Reporting Suggestion Info, Measurement Indication, Reporting
    /// Thresholds, Remaining Data Reporting Indication and any later member.
    pub extra: Vec<RawIe>,
}

impl TypedIe for QosMonitoringPerQosFlowControlInformation {
    const IE_TYPE: IeType = IeType::QosMonitoringPerQosFlowControlInformation;

    fn encode_value(&self, buf: &mut BytesMut) {
        for qfi in &self.qfis {
            put_raw_member(buf, IeType::Qfi, &[qfi & 0x3f]);
        }
        put_member(buf, &self.requested_qos_monitoring);
        put_member(buf, &self.reporting_frequency);
        if let Some(t) = &self.packet_delay_thresholds {
            put_member(buf, t);
        }
        if let Some(v) = self.minimum_wait_time {
            put_member(buf, &MinimumWaitTime(v));
        }
        if let Some(p) = self.measurement_period {
            put_u32_member(buf, IeType::MeasurementPeriod, p);
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let (mut req, mut freq) = (None, None);
        for ie in members(data)? {
            if is(&ie, IeType::Qfi) {
                out.qfis.push(decode_qfi(&ie.data)?);
            } else if is(&ie, IeType::RequestedQosMonitoring) {
                req = Some(RequestedQosMonitoring::decode_value(&ie.data)?);
            } else if is(&ie, IeType::ReportingFrequency) {
                freq = Some(ReportingFrequency::decode_value(&ie.data)?);
            } else if is(&ie, IeType::PacketDelayThresholds) {
                out.packet_delay_thresholds = Some(PacketDelayThresholds::decode_value(&ie.data)?);
            } else if is(&ie, IeType::MinimumWaitTime) {
                out.minimum_wait_time = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::MeasurementPeriod) {
                out.measurement_period = Some(u32_at(&ie.data, 0)?);
            } else {
                out.extra.push(ie);
            }
        }
        if out.qfis.is_empty() {
            return Err(missing(
                "QoS Monitoring per QoS flow Control Information: QFI",
            ));
        }
        out.requested_qos_monitoring = req.ok_or_else(|| {
            missing("QoS Monitoring per QoS flow Control Information: Requested QoS Monitoring")
        })?;
        out.reporting_frequency = freq.ok_or_else(|| {
            missing("QoS Monitoring per QoS flow Control Information: Reporting Frequency")
        })?;
        Ok(out)
    }
}

/// QoS Monitoring Report (IE 247, Table 7.5.8.6-3), in a Session Report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QosMonitoringReport {
    /// M.
    pub qfi: u8,
    /// M.
    pub qos_monitoring_measurement: QosMonitoringMeasurement,
    /// M, NTP seconds.
    pub time_stamp: u32,
    /// O, NTP seconds.
    pub start_time: Option<u32>,
    /// Redundant N3/N9 Transmission Information and any later member.
    pub extra: Vec<RawIe>,
}

impl TypedIe for QosMonitoringReport {
    const IE_TYPE: IeType = IeType::QosMonitoringReport;

    fn encode_value(&self, buf: &mut BytesMut) {
        put_raw_member(buf, IeType::Qfi, &[self.qfi & 0x3f]);
        put_member(buf, &self.qos_monitoring_measurement);
        put_u32_member(buf, IeType::TimeStamp, self.time_stamp);
        if let Some(st) = self.start_time {
            put_u32_member(buf, IeType::StartTime, st);
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let (mut qfi, mut meas, mut ts) = (None, None, None);
        for ie in members(data)? {
            if is(&ie, IeType::Qfi) {
                qfi = Some(decode_qfi(&ie.data)?);
            } else if is(&ie, IeType::QosMonitoringMeasurement) {
                meas = Some(QosMonitoringMeasurement::decode_value(&ie.data)?);
            } else if is(&ie, IeType::TimeStamp) {
                ts = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::StartTime) {
                out.start_time = Some(u32_at(&ie.data, 0)?);
            } else {
                out.extra.push(ie);
            }
        }
        out.qfi = qfi.ok_or_else(|| missing("QoS Monitoring Report: QFI"))?;
        out.qos_monitoring_measurement =
            meas.ok_or_else(|| missing("QoS Monitoring Report: QoS Monitoring Measurement"))?;
        out.time_stamp = ts.ok_or_else(|| missing("QoS Monitoring Report: Time Stamp"))?;
        Ok(out)
    }
}

// ============================================================================
// N6 delay measurement, IEs 354-358 and 375-379 (node-level)
// ============================================================================

/// N6 Delay Measurement Protocols (IE 354, §8.2.246): octet 5 bit 1 TWAMP,
/// bit 2 OWAMP, bit 3 STAMP, bit 4 OTHER.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct N6DelayMeasurementProtocols {
    pub twamp: bool,
    pub owamp: bool,
    pub stamp: bool,
    pub other: bool,
}

impl TypedIe for N6DelayMeasurementProtocols {
    const IE_TYPE: IeType = IeType::N6DelayMeasurementProtocols;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(
            (self.twamp as u8)
                | ((self.owamp as u8) << 1)
                | ((self.stamp as u8) << 2)
                | ((self.other as u8) << 3),
        );
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        Ok(Self {
            twamp: data[0] & 0x01 != 0,
            owamp: data[0] & 0x02 != 0,
            stamp: data[0] & 0x04 != 0,
            other: data[0] & 0x08 != 0,
        })
    }
}

/// N6 Delay Measurement Information (IE 357, §8.2.247): octet 5 flags MIND
/// (bit 1) and MAXD (bit 2), then the Average Packet Delay (always present)
/// and the flagged Minimum and Maximum, Unsigned32 milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct N6DelayMeasurementInformation {
    pub average_packet_delay: u32,
    pub minimum_packet_delay: Option<u32>,
    pub maximum_packet_delay: Option<u32>,
}

impl TypedIe for N6DelayMeasurementInformation {
    const IE_TYPE: IeType = IeType::N6DelayMeasurementInformation;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(
            (self.minimum_packet_delay.is_some() as u8)
                | ((self.maximum_packet_delay.is_some() as u8) << 1),
        );
        buf.put_u32(self.average_packet_delay);
        for v in [self.minimum_packet_delay, self.maximum_packet_delay]
            .into_iter()
            .flatten()
        {
            buf.put_u32(v);
        }
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        let flags = data[0];
        let average_packet_delay = u32_at(data, 1)?;
        let mut at = 5;
        let mut field = |bit: u8| -> PfcpResult<Option<u32>> {
            if flags & bit == 0 {
                return Ok(None);
            }
            let v = u32_at(data, at)?;
            at += 4;
            Ok(Some(v))
        };
        Ok(Self {
            average_packet_delay,
            minimum_packet_delay: field(0x01)?,
            maximum_packet_delay: field(0x02)?,
        })
    }
}

/// Measurement Endpoint Address (IE 358, §8.2.248): octet 5 flags V4 (bit 1)
/// and V6 (bit 2), then the IPv4 and/or IPv6 address. Note the bit order is
/// the reverse of the Remote GTP-U Peer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeasurementEndpointAddress {
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
}

impl TypedIe for MeasurementEndpointAddress {
    const IE_TYPE: IeType = IeType::MeasurementEndpointAddress;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8((self.ipv4.is_some() as u8) | ((self.ipv6.is_some() as u8) << 1));
        if let Some(a) = self.ipv4 {
            buf.put_slice(&a);
        }
        if let Some(a) = self.ipv6 {
            buf.put_slice(&a);
        }
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        let flags = data[0];
        let mut at = 1;
        let mut out = Self::default();
        if flags & 0x01 != 0 {
            need(data, at, 4)?;
            let mut a = [0u8; 4];
            a.copy_from_slice(&data[at..at + 4]);
            out.ipv4 = Some(a);
            at += 4;
        }
        if flags & 0x02 != 0 {
            need(data, at, 16)?;
            let mut a = [0u8; 16];
            a.copy_from_slice(&data[at..at + 16]);
            out.ipv6 = Some(a);
        }
        if out.ipv4.is_none() && out.ipv6.is_none() {
            return Err(PfcpError::InvalidFormat(
                "Measurement Endpoint Address: neither V4 nor V6 is set".into(),
            ));
        }
        Ok(out)
    }
}

/// Measurement Reporting Type (IE 375, §8.2.262): octet 5 bit 1 PER, bit 2
/// EVT, bit 3 IRE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeasurementReportingType {
    pub per: bool,
    pub evt: bool,
    pub ire: bool,
}

impl TypedIe for MeasurementReportingType {
    const IE_TYPE: IeType = IeType::MeasurementReportingType;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8((self.per as u8) | ((self.evt as u8) << 1) | ((self.ire as u8) << 2));
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        Ok(Self {
            per: data[0] & 0x01 != 0,
            evt: data[0] & 0x02 != 0,
            ire: data[0] & 0x04 != 0,
        })
    }
}

/// N6 Delay Measurement Failure Information (IE 376, §8.2.263): octet 5 is
/// the failure cause (Table 8.2.263-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct N6DelayMeasurementFailureInformation {
    pub cause: u8,
}

impl N6DelayMeasurementFailureInformation {
    pub const UNSPECIFIED: u8 = 0;
    pub const CONNECTION_ESTABLISHMENT_FAILURE: u8 = 1;
    pub const CONNECTION_LOST: u8 = 2;
    pub const AUTHENTICATION_FAILURE: u8 = 3;

    /// The cause as the receiver must read it: values the spec has not
    /// allocated (4..=255) are "Unspecified" (Table 8.2.263-1 NOTE).
    pub fn effective_cause(&self) -> u8 {
        if self.cause <= Self::AUTHENTICATION_FAILURE {
            self.cause
        } else {
            Self::UNSPECIFIED
        }
    }
}

impl TypedIe for N6DelayMeasurementFailureInformation {
    const IE_TYPE: IeType = IeType::N6DelayMeasurementFailureInformation;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.cause);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        need(data, 0, 1)?;
        Ok(Self { cause: data[0] })
    }
}

/// N6 Delay Measurement Control Information ID (IE 377, §8.2.264): fixed
/// length 2, a binary integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct N6DelayMeasurementControlInformationId(pub u16);

impl TypedIe for N6DelayMeasurementControlInformationId {
    const IE_TYPE: IeType = IeType::N6DelayMeasurementControlInformationId;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.0);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        Ok(Self(u16_at(data, 0)?))
    }
}

/// Measurement Endpoint Port Number (IE 379, §8.2.265): fixed length 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeasurementEndpointPortNumber(pub u16);

impl TypedIe for MeasurementEndpointPortNumber {
    const IE_TYPE: IeType = IeType::MeasurementEndpointPortNumber;

    fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.0);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        Ok(Self(u16_at(data, 0)?))
    }
}

/// N6 Delay Measurement Control Information (IE 355, Table 7.4.4.1.4-1), in a
/// PFCP Association Setup / Update Request from the SMF (§5.33.8.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct N6DelayMeasurementControlInformation {
    /// M.
    pub id: u16,
    /// M, one or more.
    pub measurement_endpoint_addresses: Vec<MeasurementEndpointAddress>,
    /// M: the Network Instance used to reach the endpoints.
    pub network_instance: Vec<u8>,
    /// M, one or more.
    pub measurement_protocols: Vec<N6DelayMeasurementProtocols>,
    /// M.
    pub measurement_reporting_type: MeasurementReportingType,
    /// C: present for periodic reporting, seconds.
    pub measurement_period: Option<u32>,
    /// O: event-triggered thresholds, milliseconds.
    pub average_packet_delay_threshold: Option<u32>,
    pub minimum_packet_delay_threshold: Option<u32>,
    pub maximum_packet_delay_threshold: Option<u32>,
    /// O: Minimum Waiting Time (Timer).
    pub minimum_waiting_time: Option<Timer>,
    /// Protocol Specific Configuration Parameters (378) and any later member.
    pub extra: Vec<RawIe>,
}

impl TypedIe for N6DelayMeasurementControlInformation {
    const IE_TYPE: IeType = IeType::N6DelayMeasurementControlInformation;

    fn encode_value(&self, buf: &mut BytesMut) {
        put_member(buf, &N6DelayMeasurementControlInformationId(self.id));
        for a in &self.measurement_endpoint_addresses {
            put_member(buf, a);
        }
        put_raw_member(buf, IeType::NetworkInstance, &self.network_instance);
        for p in &self.measurement_protocols {
            put_member(buf, p);
        }
        put_member(buf, &self.measurement_reporting_type);
        if let Some(p) = self.measurement_period {
            put_u32_member(buf, IeType::MeasurementPeriod, p);
        }
        if let Some(v) = self.average_packet_delay_threshold {
            put_member(buf, &AveragePacketDelay(v));
        }
        if let Some(v) = self.minimum_packet_delay_threshold {
            put_member(buf, &MinimumPacketDelay(v));
        }
        if let Some(v) = self.maximum_packet_delay_threshold {
            put_member(buf, &MaximumPacketDelay(v));
        }
        if let Some(t) = &self.minimum_waiting_time {
            put_member(buf, t);
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let (mut id, mut ni, mut mrt) = (None, None, None);
        for ie in members(data)? {
            if is(&ie, IeType::N6DelayMeasurementControlInformationId) {
                id = Some(N6DelayMeasurementControlInformationId::decode_value(&ie.data)?.0);
            } else if is(&ie, IeType::MeasurementEndpointAddress) {
                out.measurement_endpoint_addresses
                    .push(MeasurementEndpointAddress::decode_value(&ie.data)?);
            } else if is(&ie, IeType::NetworkInstance) {
                ni = Some(ie.data.to_vec());
            } else if is(&ie, IeType::N6DelayMeasurementProtocols) {
                out.measurement_protocols
                    .push(N6DelayMeasurementProtocols::decode_value(&ie.data)?);
            } else if is(&ie, IeType::MeasurementReportingType) {
                mrt = Some(MeasurementReportingType::decode_value(&ie.data)?);
            } else if is(&ie, IeType::MeasurementPeriod) {
                out.measurement_period = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::AveragePacketDelay) {
                out.average_packet_delay_threshold = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::MinimumPacketDelay) {
                out.minimum_packet_delay_threshold = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::MaximumPacketDelay) {
                out.maximum_packet_delay_threshold = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::Timer) {
                out.minimum_waiting_time = Some(Timer::decode_value(&ie.data)?);
            } else {
                out.extra.push(ie);
            }
        }
        const W: &str = "N6 Delay Measurement Control Information";
        out.id = id
            .ok_or_else(|| missing(&format!("{W}: N6 Delay Measurement Control Information ID")))?;
        if out.measurement_endpoint_addresses.is_empty() {
            return Err(missing(&format!("{W}: Measurement Endpoint Address")));
        }
        out.network_instance = ni.ok_or_else(|| missing(&format!("{W}: Network Instance")))?;
        if out.measurement_protocols.is_empty() {
            return Err(missing(&format!("{W}: Measurement Protocols")));
        }
        out.measurement_reporting_type =
            mrt.ok_or_else(|| missing(&format!("{W}: Measurement Reporting Type")))?;
        Ok(out)
    }
}

/// N6 Delay Measurement Report (IE 356, Table 7.4.5.1.8-1), in a PFCP Node
/// Report Request from the UPF (§5.33.8.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct N6DelayMeasurementReport {
    /// M.
    pub measurement_endpoint_address: MeasurementEndpointAddress,
    /// M.
    pub network_instance: Vec<u8>,
    /// M: why this report was sent.
    pub measurement_reporting_type: MeasurementReportingType,
    /// M, NTP seconds.
    pub time_stamp: u32,
    /// C, NTP seconds.
    pub start_time: Option<u32>,
    /// C: the measurement (NOTE: exactly one of this or the failure).
    pub information: Option<N6DelayMeasurementInformation>,
    /// C: why no measurement could be made.
    pub failure_information: Option<N6DelayMeasurementFailureInformation>,
    /// O.
    pub measurement_endpoint_port_number: Option<u16>,
    pub extra: Vec<RawIe>,
}

impl TypedIe for N6DelayMeasurementReport {
    const IE_TYPE: IeType = IeType::N6DelayMeasurementReport;

    fn encode_value(&self, buf: &mut BytesMut) {
        put_member(buf, &self.measurement_endpoint_address);
        put_raw_member(buf, IeType::NetworkInstance, &self.network_instance);
        put_member(buf, &self.measurement_reporting_type);
        put_u32_member(buf, IeType::TimeStamp, self.time_stamp);
        if let Some(st) = self.start_time {
            put_u32_member(buf, IeType::StartTime, st);
        }
        if let Some(i) = &self.information {
            put_member(buf, i);
        }
        if let Some(f) = &self.failure_information {
            put_member(buf, f);
        }
        if let Some(p) = self.measurement_endpoint_port_number {
            put_member(buf, &MeasurementEndpointPortNumber(p));
        }
        put_extra(buf, &self.extra);
    }

    fn decode_value(data: &[u8]) -> PfcpResult<Self> {
        let mut out = Self::default();
        let (mut addr, mut ni, mut mrt, mut ts) = (None, None, None, None);
        for ie in members(data)? {
            if is(&ie, IeType::MeasurementEndpointAddress) {
                addr = Some(MeasurementEndpointAddress::decode_value(&ie.data)?);
            } else if is(&ie, IeType::NetworkInstance) {
                ni = Some(ie.data.to_vec());
            } else if is(&ie, IeType::MeasurementReportingType) {
                mrt = Some(MeasurementReportingType::decode_value(&ie.data)?);
            } else if is(&ie, IeType::TimeStamp) {
                ts = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::StartTime) {
                out.start_time = Some(u32_at(&ie.data, 0)?);
            } else if is(&ie, IeType::N6DelayMeasurementInformation) {
                out.information = Some(N6DelayMeasurementInformation::decode_value(&ie.data)?);
            } else if is(&ie, IeType::N6DelayMeasurementFailureInformation) {
                out.failure_information = Some(N6DelayMeasurementFailureInformation::decode_value(
                    &ie.data,
                )?);
            } else if is(&ie, IeType::MeasurementEndpointPortNumber) {
                out.measurement_endpoint_port_number =
                    Some(MeasurementEndpointPortNumber::decode_value(&ie.data)?.0);
            } else {
                out.extra.push(ie);
            }
        }
        const W: &str = "N6 Delay Measurement Report";
        out.measurement_endpoint_address =
            addr.ok_or_else(|| missing(&format!("{W}: Measurement Endpoint Address")))?;
        out.network_instance = ni.ok_or_else(|| missing(&format!("{W}: Network Instance")))?;
        out.measurement_reporting_type =
            mrt.ok_or_else(|| missing(&format!("{W}: Measurement Reporting Type")))?;
        out.time_stamp = ts.ok_or_else(|| missing(&format!("{W}: Time Stamp")))?;
        // Table 7.4.5.1.8-1 NOTE: either the Information or the Failure
        // Information IE shall be present.
        if out.information.is_some() == out.failure_information.is_some() {
            return Err(PfcpError::InvalidFormat(format!(
                "{W}: exactly one of N6 Delay Measurement Information and N6 Delay \
                 Measurement Failure Information shall be present"
            )));
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "qos_monitoring_tests.rs"]
mod tests;
