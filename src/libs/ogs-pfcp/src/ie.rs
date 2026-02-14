//! PFCP Information Elements
//!
//! IE types and encoding/decoding for PFCP protocol as specified in 3GPP TS 29.244.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{PfcpError, PfcpResult};

/// PFCP IE Type values (TS 29.244 Section 8.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IeType {
    CreatePdr = 1,
    Pdi = 2,
    CreateFar = 3,
    ForwardingParameters = 4,
    DuplicatingParameters = 5,
    CreateUrr = 6,
    CreateQer = 7,
    CreatedPdr = 8,
    UpdatePdr = 9,
    UpdateFar = 10,
    UpdateForwardingParameters = 11,
    UpdateBar = 12,
    UpdateUrr = 13,
    UpdateQer = 14,
    RemovePdr = 15,
    RemoveFar = 16,
    RemoveUrr = 17,
    RemoveQer = 18,
    Cause = 19,
    SourceInterface = 20,
    FTeid = 21,
    NetworkInstance = 22,
    SdfFilter = 23,
    ApplicationId = 24,
    GateStatus = 25,
    Mbr = 26,
    Gbr = 27,
    QerCorrelationId = 28,
    Precedence = 29,
    TransportLevelMarking = 30,
    VolumeThreshold = 31,
    TimeThreshold = 32,
    MonitoringTime = 33,
    SubsequentVolumeThreshold = 34,
    SubsequentTimeThreshold = 35,
    InactivityDetectionTime = 36,
    ReportingTriggers = 37,
    RedirectInformation = 38,
    ReportType = 39,
    OffendingIe = 40,
    ForwardingPolicy = 41,
    DestinationInterface = 42,
    UpFunctionFeatures = 43,
    ApplyAction = 44,
    DownlinkDataServiceInformation = 45,
    DownlinkDataNotificationDelay = 46,
    DlBufferingDuration = 47,
    DlBufferingSuggestedPacketCount = 48,
    PfcpSmreqFlags = 49,
    PfcpSrrspFlags = 50,
    LoadControlInformation = 51,
    SequenceNumber = 52,
    Metric = 53,
    OverloadControlInformation = 54,
    Timer = 55,
    PdrId = 56,
    FSeid = 57,
    ApplicationIdsPfds = 58,
    PfdContext = 59,
    NodeId = 60,
    PfdContents = 61,
    MeasurementMethod = 62,
    UsageReportTrigger = 63,
    MeasurementPeriod = 64,
    FqCsid = 65,
    VolumeMeasurement = 66,
    DurationMeasurement = 67,
    ApplicationDetectionInformation = 68,
    TimeOfFirstPacket = 69,
    TimeOfLastPacket = 70,
    QuotaHoldingTime = 71,
    DroppedDlTrafficThreshold = 72,
    VolumeQuota = 73,
    TimeQuota = 74,
    StartTime = 75,
    EndTime = 76,
    QueryUrr = 77,
    UsageReportSmr = 78,
    UsageReportSdr = 79,
    UsageReportSrr = 80,
    UrrId = 81,
    LinkedUrrId = 82,
    DownlinkDataReport = 83,
    OuterHeaderCreation = 84,
    CreateBar = 85,
    UpdateBarSmr = 86,
    RemoveBar = 87,
    BarId = 88,
    CpFunctionFeatures = 89,
    UsageInformation = 90,
    ApplicationInstanceId = 91,
    FlowInformation = 92,
    UeIpAddress = 93,
    PacketRate = 94,
    OuterHeaderRemoval = 95,
    RecoveryTimeStamp = 96,
    DlFlowLevelMarking = 97,
    HeaderEnrichment = 98,
    ErrorIndicationReport = 99,
    MeasurementInformation = 100,
    NodeReportType = 101,
    UserPlanePathFailureReport = 102,
    RemoteGtpUPeer = 103,
    UrSeqn = 104,
    UpdateDuplicatingParameters = 105,
    ActivatePredefinedRules = 106,
    DeactivatePredefinedRules = 107,
    FarId = 108,
    QerId = 109,
    OciFlags = 110,
    PfcpAssociationReleaseRequest = 111,
    GracefulReleasePeriod = 112,
    PdnType = 113,
    FailedRuleId = 114,
    TimeQuotaMechanism = 115,
    UserPlaneIpResourceInformation = 116,
    UserPlaneInactivityTimer = 117,
    AggregatedUrrs = 118,
    Multiplier = 119,
    AggregatedUrrId = 120,
    SubsequentVolumeQuota = 121,
    SubsequentTimeQuota = 122,
    Rqi = 123,
    Qfi = 124,
    QueryUrrReference = 125,
    AdditionalUsageReportsInformation = 126,
    CreateTrafficEndpoint = 127,
    CreatedTrafficEndpoint = 128,
    UpdateTrafficEndpoint = 129,
    RemoveTrafficEndpoint = 130,
    TrafficEndpointId = 131,
    EthernetPacketFilter = 132,
    MacAddress = 133,
    CTag = 134,
    STag = 135,
    Ethertype = 136,
    Proxying = 137,
    EthernetFilterId = 138,
    EthernetFilterProperties = 139,
    SuggestedBufferingPacketsCount = 140,
    UserId = 141,
    EthernetPduSessionInformation = 142,
    EthernetTrafficInformation = 143,
    MacAddressesDetected = 144,
    MacAddressesRemoved = 145,
    EthernetInactivityTimer = 146,
    AdditionalMonitoringTime = 147,
    EventQuota = 148,
    EventThreshold = 149,
    SubsequentEventQuota = 150,
    SubsequentEventThreshold = 151,
    TraceInformation = 152,
    FramedRoute = 153,
    FramedRouting = 154,
    FramedIpv6Route = 155,
    TimeStamp = 156,
    AveragingWindow = 157,
    PagingPolicyIndicator = 158,
    ApnDnn = 159,
    ThreeGppInterfaceType = 160,
    PfcpSrreqFlags = 161,
    PfcpAureqFlags = 162,
    ActivationTime = 163,
    DeactivationTime = 164,
    CreateMar = 165,
    ThreeGppAccessForwardingActionInformation = 166,
    Non3gppAccessForwardingActionInformation = 167,
    RemoveMar = 168,
    UpdateMar = 169,
    MarId = 170,
    SteeringFunctionality = 171,
    SteeringMode = 172,
    Weight = 173,
    Priority = 174,
    Update3gppAccessForwardingActionInformation = 175,
    UpdateNon3gppAccessForwardingActionInformation = 176,
    UeIpAddressPoolIdentity = 177,
    AlternativeSmfIpAddress = 178,
    PacketReplicationAndDetectionCarryOnInformation = 179,
    SmfSetId = 180,
    QuotaValidityTime = 181,
    NumberOfReports = 182,
    PfcpSessionRetentionInformation = 183,
    PfcpAsrspFlags = 184,
    CpPfcpEntityIpAddress = 185,
    PfcpSereqFlags = 186,
    UserPlanePathRecoveryReport = 187,
    IpMulticastAddressingInfo = 188,
    JoinIpMulticastInformation = 189,
    LeaveIpMulticastInformation = 190,
    IpMulticastAddress = 191,
    SourceIpAddress = 192,
    PacketRateStatus = 193,
    CreateBridgeInfoForTsc = 194,
    CreatedBridgeInfoForTsc = 195,
    DsTtPortNumber = 196,
    NwTtPortNumber = 197,
    FivegsUserPlaneNode = 198,
    TscManagementInformationSmr = 199,
    TscManagementInformationSmrsp = 200,
    TscManagementInformationSrr = 201,
    PortManagementInformationContainer = 202,
    ClockDriftControlInformation = 203,
    RequestedClockDriftInformation = 204,
    ClockDriftReport = 205,
    TimeDomainNumber = 206,
    TimeOffsetThreshold = 207,
    CumulativeRateratioThreshold = 208,
    TimeOffsetMeasurement = 209,
    CumulativeRateratioMeasurement = 210,
    RemoveSrr = 211,
    CreateSrr = 212,
    UpdateSrr = 213,
    SessionReport = 214,
    SrrId = 215,
    AccessAvailabilityControlInformation = 216,
    RequestedAccessAvailabilityInformation = 217,
    AccessAvailabilityReport = 218,
    AccessAvailabilityInformation = 219,
    ProvideAtsssControlInformation = 220,
    AtsssControlParameters = 221,
    MptcpControlInformation = 222,
    AtsssLlControlInformation = 223,
    PmfControlInformation = 224,
    MptcpParameters = 225,
    AtsssLlParameters = 226,
    PmfParameters = 227,
    MptcpAddressInformation = 228,
    UeLinkSpecificIpAddress = 229,
    PmfAddressInformation = 230,
    AtsssLlInformation = 231,
    DataNetworkAccessIdentifier = 232,
    UeIpAddressPoolInformation = 233,
    AveragePacketDelay = 234,
    MinimumPacketDelay = 235,
    MaximumPacketDelay = 236,
    QosReportTrigger = 237,
    GtpUPathQosControlInformation = 238,
    GtpUPathQosReport = 239,
    QosInformationInGtpUPathQosReport = 240,
    GtpUPathInterfaceType = 241,
    QosMonitoringPerQosFlowControlInformation = 242,
    RequestedQosMonitoring = 243,
    ReportingFrequency = 244,
    PacketDelayThresholds = 245,
    MinimumWaitTime = 246,
    QosMonitoringReport = 247,
    QosMonitoringMeasurement = 248,
    MtEdtControlInformation = 249,
    DlDataPacketsSize = 250,
    QerControlIndications = 251,
    PacketRateStatusReport = 252,
    NfInstanceId = 253,
    EthernetContextInformation = 254,
    RedundantTransmissionParameters = 255,
}

impl TryFrom<u16> for IeType {
    type Error = PfcpError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::CreatePdr),
            2 => Ok(Self::Pdi),
            3 => Ok(Self::CreateFar),
            4 => Ok(Self::ForwardingParameters),
            5 => Ok(Self::DuplicatingParameters),
            6 => Ok(Self::CreateUrr),
            7 => Ok(Self::CreateQer),
            8 => Ok(Self::CreatedPdr),
            9 => Ok(Self::UpdatePdr),
            10 => Ok(Self::UpdateFar),
            11 => Ok(Self::UpdateForwardingParameters),
            12 => Ok(Self::UpdateBar),
            13 => Ok(Self::UpdateUrr),
            14 => Ok(Self::UpdateQer),
            15 => Ok(Self::RemovePdr),
            16 => Ok(Self::RemoveFar),
            17 => Ok(Self::RemoveUrr),
            18 => Ok(Self::RemoveQer),
            19 => Ok(Self::Cause),
            20 => Ok(Self::SourceInterface),
            21 => Ok(Self::FTeid),
            22 => Ok(Self::NetworkInstance),
            23 => Ok(Self::SdfFilter),
            24 => Ok(Self::ApplicationId),
            25 => Ok(Self::GateStatus),
            26 => Ok(Self::Mbr),
            27 => Ok(Self::Gbr),
            28 => Ok(Self::QerCorrelationId),
            29 => Ok(Self::Precedence),
            30 => Ok(Self::TransportLevelMarking),
            31 => Ok(Self::VolumeThreshold),
            32 => Ok(Self::TimeThreshold),
            33 => Ok(Self::MonitoringTime),
            37 => Ok(Self::ReportingTriggers),
            38 => Ok(Self::RedirectInformation),
            39 => Ok(Self::ReportType),
            40 => Ok(Self::OffendingIe),
            41 => Ok(Self::ForwardingPolicy),
            42 => Ok(Self::DestinationInterface),
            43 => Ok(Self::UpFunctionFeatures),
            44 => Ok(Self::ApplyAction),
            45 => Ok(Self::DownlinkDataServiceInformation),
            46 => Ok(Self::DownlinkDataNotificationDelay),
            47 => Ok(Self::DlBufferingDuration),
            48 => Ok(Self::DlBufferingSuggestedPacketCount),
            49 => Ok(Self::PfcpSmreqFlags),
            50 => Ok(Self::PfcpSrrspFlags),
            56 => Ok(Self::PdrId),
            57 => Ok(Self::FSeid),
            60 => Ok(Self::NodeId),
            62 => Ok(Self::MeasurementMethod),
            63 => Ok(Self::UsageReportTrigger),
            64 => Ok(Self::MeasurementPeriod),
            66 => Ok(Self::VolumeMeasurement),
            67 => Ok(Self::DurationMeasurement),
            69 => Ok(Self::TimeOfFirstPacket),
            70 => Ok(Self::TimeOfLastPacket),
            73 => Ok(Self::VolumeQuota),
            74 => Ok(Self::TimeQuota),
            75 => Ok(Self::StartTime),
            76 => Ok(Self::EndTime),
            78 => Ok(Self::UsageReportSmr),
            80 => Ok(Self::UsageReportSrr),
            81 => Ok(Self::UrrId),
            83 => Ok(Self::DownlinkDataReport),
            84 => Ok(Self::OuterHeaderCreation),
            85 => Ok(Self::CreateBar),
            86 => Ok(Self::UpdateBarSmr),
            87 => Ok(Self::RemoveBar),
            88 => Ok(Self::BarId),
            89 => Ok(Self::CpFunctionFeatures),
            93 => Ok(Self::UeIpAddress),
            94 => Ok(Self::PacketRate),
            95 => Ok(Self::OuterHeaderRemoval),
            96 => Ok(Self::RecoveryTimeStamp),
            104 => Ok(Self::UrSeqn),
            108 => Ok(Self::FarId),
            109 => Ok(Self::QerId),
            113 => Ok(Self::PdnType),
            114 => Ok(Self::FailedRuleId),
            116 => Ok(Self::UserPlaneIpResourceInformation),
            124 => Ok(Self::Qfi),
            131 => Ok(Self::TrafficEndpointId),
            140 => Ok(Self::SuggestedBufferingPacketsCount),
            159 => Ok(Self::ApnDnn),
            160 => Ok(Self::ThreeGppInterfaceType),
            161 => Ok(Self::PfcpSrreqFlags),
            253 => Ok(Self::NfInstanceId),
            _ => Err(PfcpError::InvalidIeType(value)),
        }
    }
}


/// PFCP IE Header (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeHeader {
    pub ie_type: u16,
    pub length: u16,
}

impl IeHeader {
    pub const LEN: usize = 4;

    pub fn new(ie_type: u16, length: u16) -> Self {
        Self { ie_type, length }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.ie_type);
        buf.put_u16(self.length);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < Self::LEN {
            return Err(PfcpError::BufferTooShort {
                needed: Self::LEN,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            ie_type: buf.get_u16(),
            length: buf.get_u16(),
        })
    }
}

/// Generic PFCP IE with raw data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIe {
    pub ie_type: u16,
    pub data: Bytes,
}

impl RawIe {
    pub fn new(ie_type: u16, data: Bytes) -> Self {
        Self { ie_type, data }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let header = IeHeader::new(self.ie_type, self.data.len() as u16);
        header.encode(buf);
        buf.put_slice(&self.data);
    }

    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        let header = IeHeader::decode(buf)?;
        if buf.remaining() < header.length as usize {
            return Err(PfcpError::BufferTooShort {
                needed: header.length as usize,
                available: buf.remaining(),
            });
        }
        let data = buf.copy_to_bytes(header.length as usize);
        Ok(Self {
            ie_type: header.ie_type,
            data,
        })
    }
}

/// Helper to encode a u8 IE
pub fn encode_u8_ie(buf: &mut BytesMut, ie_type: IeType, value: u8) {
    let header = IeHeader::new(ie_type as u16, 1);
    header.encode(buf);
    buf.put_u8(value);
}

/// Helper to encode a u16 IE
pub fn encode_u16_ie(buf: &mut BytesMut, ie_type: IeType, value: u16) {
    let header = IeHeader::new(ie_type as u16, 2);
    header.encode(buf);
    buf.put_u16(value);
}

/// Helper to encode a u32 IE
pub fn encode_u32_ie(buf: &mut BytesMut, ie_type: IeType, value: u32) {
    let header = IeHeader::new(ie_type as u16, 4);
    header.encode(buf);
    buf.put_u32(value);
}

/// Helper to encode a u64 IE
pub fn encode_u64_ie(buf: &mut BytesMut, ie_type: IeType, value: u64) {
    let header = IeHeader::new(ie_type as u16, 8);
    header.encode(buf);
    buf.put_u64(value);
}

/// Helper to encode bytes IE
pub fn encode_bytes_ie(buf: &mut BytesMut, ie_type: IeType, data: &[u8]) {
    let header = IeHeader::new(ie_type as u16, data.len() as u16);
    header.encode(buf);
    buf.put_slice(data);
}

// ============================================================================
// Structured PFCP IE Encoders/Decoders
// ============================================================================

/// VolumeMeasurement (IE 66) - Measurement of uplink/downlink/total volume
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeMeasurement {
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
    pub total_packets: Option<u64>,
    pub uplink_packets: Option<u64>,
    pub downlink_packets: Option<u64>,
}

impl VolumeMeasurement {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let mut flags = 0u8;
        if self.total_volume.is_some() { flags |= 0x01; }
        if self.uplink_volume.is_some() { flags |= 0x02; }
        if self.downlink_volume.is_some() { flags |= 0x04; }
        if self.total_packets.is_some() { flags |= 0x08; }
        if self.uplink_packets.is_some() { flags |= 0x10; }
        if self.downlink_packets.is_some() { flags |= 0x20; }

        buf.put_u8(flags);
        if let Some(v) = self.total_volume { buf.put_u64(v); }
        if let Some(v) = self.uplink_volume { buf.put_u64(v); }
        if let Some(v) = self.downlink_volume { buf.put_u64(v); }
        if let Some(v) = self.total_packets { buf.put_u64(v); }
        if let Some(v) = self.uplink_packets { buf.put_u64(v); }
        if let Some(v) = self.downlink_packets { buf.put_u64(v); }

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort { needed: 1, available: 0 });
        }
        let mut buf = Bytes::copy_from_slice(data);
        let flags = buf.get_u8();
        let mut vm = VolumeMeasurement::default();

        if flags & 0x01 != 0 { vm.total_volume = Some(buf.get_u64()); }
        if flags & 0x02 != 0 { vm.uplink_volume = Some(buf.get_u64()); }
        if flags & 0x04 != 0 { vm.downlink_volume = Some(buf.get_u64()); }
        if flags & 0x08 != 0 { vm.total_packets = Some(buf.get_u64()); }
        if flags & 0x10 != 0 { vm.uplink_packets = Some(buf.get_u64()); }
        if flags & 0x20 != 0 { vm.downlink_packets = Some(buf.get_u64()); }

        Ok(vm)
    }
}

/// DurationMeasurement (IE 67) - Duration in seconds
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationMeasurement(pub u32);

impl DurationMeasurement {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.0);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.len() < 4 {
            return Err(PfcpError::BufferTooShort { needed: 4, available: data.len() });
        }
        let mut buf = Bytes::copy_from_slice(data);
        Ok(DurationMeasurement(buf.get_u32()))
    }
}

/// VolumeThreshold (IE 31) - Volume thresholds
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeThreshold {
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
}

impl VolumeThreshold {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let mut flags = 0u8;
        if self.total_volume.is_some() { flags |= 0x01; }
        if self.uplink_volume.is_some() { flags |= 0x02; }
        if self.downlink_volume.is_some() { flags |= 0x04; }

        buf.put_u8(flags);
        if let Some(v) = self.total_volume { buf.put_u64(v); }
        if let Some(v) = self.uplink_volume { buf.put_u64(v); }
        if let Some(v) = self.downlink_volume { buf.put_u64(v); }

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort { needed: 1, available: 0 });
        }
        let mut buf = Bytes::copy_from_slice(data);
        let flags = buf.get_u8();
        let mut vt = VolumeThreshold::default();

        if flags & 0x01 != 0 { vt.total_volume = Some(buf.get_u64()); }
        if flags & 0x02 != 0 { vt.uplink_volume = Some(buf.get_u64()); }
        if flags & 0x04 != 0 { vt.downlink_volume = Some(buf.get_u64()); }

        Ok(vt)
    }
}

/// ReportingTriggers (IE 37) - Bitmap of reporting triggers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportingTriggers {
    pub periodic_reporting: bool,
    pub volume_threshold: bool,
    pub time_threshold: bool,
    pub quota_holding_time: bool,
    pub start_of_traffic: bool,
    pub stop_of_traffic: bool,
    pub dropped_dl_traffic_threshold: bool,
    pub linked_usage_reporting: bool,
}

impl ReportingTriggers {
    pub fn encode(&self) -> Bytes {
        let mut flags = 0u16;
        if self.periodic_reporting { flags |= 0x0001; }
        if self.volume_threshold { flags |= 0x0002; }
        if self.time_threshold { flags |= 0x0004; }
        if self.quota_holding_time { flags |= 0x0008; }
        if self.start_of_traffic { flags |= 0x0010; }
        if self.stop_of_traffic { flags |= 0x0020; }
        if self.dropped_dl_traffic_threshold { flags |= 0x0040; }
        if self.linked_usage_reporting { flags |= 0x0080; }

        let mut buf = BytesMut::new();
        buf.put_u16(flags);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.len() < 2 {
            return Err(PfcpError::BufferTooShort { needed: 2, available: data.len() });
        }
        let mut buf = Bytes::copy_from_slice(data);
        let flags = buf.get_u16();

        Ok(ReportingTriggers {
            periodic_reporting: flags & 0x0001 != 0,
            volume_threshold: flags & 0x0002 != 0,
            time_threshold: flags & 0x0004 != 0,
            quota_holding_time: flags & 0x0008 != 0,
            start_of_traffic: flags & 0x0010 != 0,
            stop_of_traffic: flags & 0x0020 != 0,
            dropped_dl_traffic_threshold: flags & 0x0040 != 0,
            linked_usage_reporting: flags & 0x0080 != 0,
        })
    }
}

/// ReportType (IE 39) - Type of usage report
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportType {
    pub downlink_data_report: bool,
    pub usage_report: bool,
    pub error_indication_report: bool,
}

impl ReportType {
    pub fn encode(&self) -> Bytes {
        let mut flags = 0u8;
        if self.downlink_data_report { flags |= 0x01; }
        if self.usage_report { flags |= 0x02; }
        if self.error_indication_report { flags |= 0x04; }

        Bytes::copy_from_slice(&[flags])
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort { needed: 1, available: 0 });
        }
        let flags = data[0];

        Ok(ReportType {
            downlink_data_report: flags & 0x01 != 0,
            usage_report: flags & 0x02 != 0,
            error_indication_report: flags & 0x04 != 0,
        })
    }
}

/// UsageReportTrigger (IE 63) - Trigger for usage report
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReportTrigger {
    pub immediate_report: bool,
    pub volume_threshold: bool,
    pub time_threshold: bool,
    pub periodic_reporting: bool,
    pub event_threshold: bool,
}

impl UsageReportTrigger {
    pub fn encode(&self) -> Bytes {
        let mut flags = 0u16;
        if self.immediate_report { flags |= 0x0001; }
        if self.volume_threshold { flags |= 0x0002; }
        if self.time_threshold { flags |= 0x0004; }
        if self.periodic_reporting { flags |= 0x0008; }
        if self.event_threshold { flags |= 0x0010; }

        let mut buf = BytesMut::new();
        buf.put_u16(flags);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.len() < 2 {
            return Err(PfcpError::BufferTooShort { needed: 2, available: data.len() });
        }
        let mut buf = Bytes::copy_from_slice(data);
        let flags = buf.get_u16();

        Ok(UsageReportTrigger {
            immediate_report: flags & 0x0001 != 0,
            volume_threshold: flags & 0x0002 != 0,
            time_threshold: flags & 0x0004 != 0,
            periodic_reporting: flags & 0x0008 != 0,
            event_threshold: flags & 0x0010 != 0,
        })
    }
}

/// PacketRate (IE 94) - UL/DL packet rate limits
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketRate {
    pub uplink_time_unit: Option<u8>,
    pub max_uplink_packet_rate: Option<u16>,
    pub downlink_time_unit: Option<u8>,
    pub max_downlink_packet_rate: Option<u16>,
}

impl PacketRate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let mut flags = 0u8;
        if self.uplink_time_unit.is_some() { flags |= 0x01; }
        if self.downlink_time_unit.is_some() { flags |= 0x02; }

        buf.put_u8(flags);
        if let Some(unit) = self.uplink_time_unit {
            buf.put_u8(unit);
            buf.put_u16(self.max_uplink_packet_rate.unwrap_or(0));
        }
        if let Some(unit) = self.downlink_time_unit {
            buf.put_u8(unit);
            buf.put_u16(self.max_downlink_packet_rate.unwrap_or(0));
        }

        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort { needed: 1, available: 0 });
        }
        let mut buf = Bytes::copy_from_slice(data);
        let flags = buf.get_u8();
        let mut pr = PacketRate::default();

        if flags & 0x01 != 0 {
            pr.uplink_time_unit = Some(buf.get_u8());
            pr.max_uplink_packet_rate = Some(buf.get_u16());
        }
        if flags & 0x02 != 0 {
            pr.downlink_time_unit = Some(buf.get_u8());
            pr.max_downlink_packet_rate = Some(buf.get_u16());
        }

        Ok(pr)
    }
}

/// QerControlIndications (IE 251) - QER control indications
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QerControlIndications {
    pub rcsr: bool, // Rate Control Status Reporting
}

impl QerControlIndications {
    pub fn encode(&self) -> Bytes {
        let flags = if self.rcsr { 0x01 } else { 0x00 };
        Bytes::copy_from_slice(&[flags])
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort { needed: 1, available: 0 });
        }
        Ok(QerControlIndications {
            rcsr: data[0] & 0x01 != 0,
        })
    }
}

/// MeasurementMethod (IE 62) - Method used for measurement
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementMethod {
    pub duration: bool,
    pub volume: bool,
    pub event: bool,
}

impl MeasurementMethod {
    pub fn encode(&self) -> Bytes {
        let mut flags = 0u8;
        if self.duration { flags |= 0x01; }
        if self.volume { flags |= 0x02; }
        if self.event { flags |= 0x04; }
        Bytes::copy_from_slice(&[flags])
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort { needed: 1, available: 0 });
        }
        Ok(MeasurementMethod {
            duration: data[0] & 0x01 != 0,
            volume: data[0] & 0x02 != 0,
            event: data[0] & 0x04 != 0,
        })
    }
}

/// MeasurementInformation (IE 100) - Information about measurements
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementInformation {
    pub mbqe: bool,  // Measurement Before QoS Enforcement
    pub inam: bool,  // Inactive Measurement
    pub radi: bool,  // Reduced Application Detection Information
    pub istm: bool,  // Immediate Start Time Metering
}

impl MeasurementInformation {
    pub fn encode(&self) -> Bytes {
        let mut flags = 0u8;
        if self.mbqe { flags |= 0x01; }
        if self.inam { flags |= 0x02; }
        if self.radi { flags |= 0x04; }
        if self.istm { flags |= 0x08; }
        Bytes::copy_from_slice(&[flags])
    }

    pub fn decode(data: &[u8]) -> PfcpResult<Self> {
        if data.is_empty() {
            return Err(PfcpError::BufferTooShort { needed: 1, available: 0 });
        }
        Ok(MeasurementInformation {
            mbqe: data[0] & 0x01 != 0,
            inam: data[0] & 0x02 != 0,
            radi: data[0] & 0x04 != 0,
            istm: data[0] & 0x08 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ie_header_encode_decode() {
        let header = IeHeader::new(IeType::Cause as u16, 1);
        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = IeHeader::decode(&mut bytes).unwrap();

        assert_eq!(decoded.ie_type, IeType::Cause as u16);
        assert_eq!(decoded.length, 1);
    }

    #[test]
    fn test_raw_ie_encode_decode() {
        let ie = RawIe::new(IeType::Cause as u16, Bytes::from_static(&[0x01]));
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = RawIe::decode(&mut bytes).unwrap();

        assert_eq!(decoded.ie_type, IeType::Cause as u16);
        assert_eq!(decoded.data.as_ref(), &[0x01]);
    }

    #[test]
    fn test_volume_measurement_roundtrip() {
        let vm = VolumeMeasurement {
            total_volume: Some(1000),
            uplink_volume: Some(400),
            downlink_volume: Some(600),
            total_packets: None,
            uplink_packets: None,
            downlink_packets: None,
        };
        let encoded = vm.encode();
        let decoded = VolumeMeasurement::decode(&encoded).unwrap();
        assert_eq!(vm, decoded);
    }

    #[test]
    fn test_reporting_triggers_roundtrip() {
        let rt = ReportingTriggers {
            periodic_reporting: true,
            volume_threshold: true,
            time_threshold: false,
            quota_holding_time: false,
            start_of_traffic: true,
            stop_of_traffic: false,
            dropped_dl_traffic_threshold: false,
            linked_usage_reporting: false,
        };
        let encoded = rt.encode();
        let decoded = ReportingTriggers::decode(&encoded).unwrap();
        assert_eq!(rt, decoded);
    }
}
