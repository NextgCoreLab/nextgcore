//! GTPv1 Types
//!
//! Types and constants for GTPv1 protocol as specified in 3GPP TS 29.060.

use crate::error::{GtpError, GtpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// GTPv1 Extension Header Types (TS 29.281 Section 5.2.1, Figure 5.2.1-2 type table)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtensionHeaderType {
    /// No more extension headers
    NoMoreExtensionHeaders = 0x00,
    /// Long PDCP PDU Number (source eNB/gNB, this release)
    LongPdcpPduNumber = 0x03,
    /// PDU Set Information Container (low code point)
    PduSetInformationContainer = 0x04,
    /// Service Class Indicator
    ServiceClassIndicator = 0x20,
    /// UDP Port (provides the UDP source port of the triggering message)
    UdpPort = 0x40,
    /// RAN Container
    RanContainer = 0x81,
    /// Long PDCP PDU Number (legacy code point)
    LongPdcpPduNumberLegacy = 0x82,
    /// Xw RAN Container
    XwRanContainer = 0x83,
    /// NR RAN Container
    NrRanContainer = 0x84,
    /// PDU Session Container
    PduSessionContainer = 0x85,
    /// PDU Set Information Container (high code point)
    PduSetInformationContainerHigh = 0x86,
    /// PDCP PDU Number
    PdcpPduNumber = 0xC0,
}

impl TryFrom<u8> for ExtensionHeaderType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ExtensionHeaderType::NoMoreExtensionHeaders),
            0x03 => Ok(ExtensionHeaderType::LongPdcpPduNumber),
            0x04 => Ok(ExtensionHeaderType::PduSetInformationContainer),
            0x20 => Ok(ExtensionHeaderType::ServiceClassIndicator),
            0x40 => Ok(ExtensionHeaderType::UdpPort),
            0x81 => Ok(ExtensionHeaderType::RanContainer),
            0x82 => Ok(ExtensionHeaderType::LongPdcpPduNumberLegacy),
            0x83 => Ok(ExtensionHeaderType::XwRanContainer),
            0x84 => Ok(ExtensionHeaderType::NrRanContainer),
            0x85 => Ok(ExtensionHeaderType::PduSessionContainer),
            0x86 => Ok(ExtensionHeaderType::PduSetInformationContainerHigh),
            0xC0 => Ok(ExtensionHeaderType::PdcpPduNumber),
            _ => Err(GtpError::InvalidFormat(format!(
                "Unknown extension header type: {value:#x}"
            ))),
        }
    }
}

/// Comprehension class of an extension header, derived from bits 7 and 8 of the
/// Next Extension Header Type field (TS 29.281 Section 5.2.1, Figure 5.2.1-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtHeaderComprehension {
    /// Bits `00`/`01`: comprehension of this extension header is not required.
    NotRequired,
    /// Bits `10`: comprehension required by the Endpoint Receiver only, not by
    /// an Intermediate Node.
    RequiredEndpointOnly,
    /// Bits `11`: comprehension required by the recipient (Endpoint Receiver or
    /// Intermediate Node).
    Required,
}

/// Classify an extension header type by bits 7 and 8 (TS 29.281 Figure 5.2.1-2).
///
/// The two most significant bits of the type octet define how an unknown
/// extension header must be handled: `00`/`01` not required, `10` required by
/// the Endpoint Receiver only, `11` required by the recipient.
pub fn comprehension_of(ext_type: u8) -> ExtHeaderComprehension {
    match (ext_type >> 6) & 0b11 {
        0b00 | 0b01 => ExtHeaderComprehension::NotRequired,
        0b10 => ExtHeaderComprehension::RequiredEndpointOnly,
        _ => ExtHeaderComprehension::Required, // 0b11
    }
}

/// PDU Type for Extension Header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    /// DL PDU Session Information
    DlPduSessionInformation = 0,
    /// UL PDU Session Information
    UlPduSessionInformation = 1,
}

impl TryFrom<u8> for PduType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PduType::DlPduSessionInformation),
            1 => Ok(PduType::UlPduSessionInformation),
            _ => Err(GtpError::InvalidFormat(format!(
                "Unknown PDU type: {value}"
            ))),
        }
    }
}

/// GTPv1-U Extension Header (TS 29.281 Section 5.2.1)
///
/// Wire format: Length (1 octet, in 4-octet units covering the whole header)
/// followed by content (4*length - 2 octets) and a Next Extension Header Type
/// octet. The type of the header itself is carried by the *preceding* header
/// (the GTP header's Next Extension Header Type field or the previous
/// extension header's trailing octet), so it is kept alongside the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp1ExtHeader {
    /// Extension header type (e.g. 0x85 PDU Session Container)
    pub ext_type: u8,
    /// Content octets (length + content + next-type is a multiple of 4)
    pub content: Bytes,
}

impl Gtp1ExtHeader {
    /// Create a new extension header, zero-padding the content so the total
    /// size (length octet + content + next-type octet) is a 4-octet multiple
    pub fn new(ext_type: u8, content: &[u8]) -> Self {
        let mut padded = content.to_vec();
        while !(padded.len() + 2).is_multiple_of(4) {
            padded.push(0);
        }
        Self {
            ext_type,
            content: Bytes::from(padded),
        }
    }

    /// Create a PDU Session Container extension header (type 0x85)
    pub fn pdu_session_container(container: &PduSessionContainer) -> Self {
        Self::new(
            ExtensionHeaderType::PduSessionContainer as u8,
            &container.encode_content(),
        )
    }

    /// Whether the given extension header type is one defined/recognized by
    /// this implementation (TS 29.281 Section 5.2.1 type table). Used by the
    /// comprehension procedure so that defined N3/N9/Xn headers are not
    /// spuriously flagged as unknown.
    pub fn is_known(ext_type: u8) -> bool {
        ExtensionHeaderType::try_from(ext_type).is_ok()
    }

    /// Whether this extension header, if unknown, must be comprehended by the
    /// local role per TS 29.281 Section 5.2.1. Returns false for known types.
    ///
    /// `is_endpoint` is true when the local node is the Endpoint Receiver
    /// (e.g. gNB/UPF terminating the tunnel), false for an Intermediate Node.
    pub fn requires_comprehension(&self, is_endpoint: bool) -> bool {
        if Self::is_known(self.ext_type) {
            return false;
        }
        match comprehension_of(self.ext_type) {
            ExtHeaderComprehension::Required => true,
            ExtHeaderComprehension::RequiredEndpointOnly => is_endpoint,
            ExtHeaderComprehension::NotRequired => false,
        }
    }

    /// Length field value (total header size in 4-octet units)
    pub fn length_units(&self) -> u8 {
        ((self.content.len() + 2) / 4) as u8
    }

    /// Encoded size in bytes
    pub fn encoded_len(&self) -> usize {
        self.content.len() + 2
    }

    /// Encode this extension header followed by the type of the next
    /// extension header in the chain (0 = no more extension headers)
    pub fn encode(&self, buf: &mut BytesMut, next_type: u8) {
        buf.put_u8(self.length_units());
        buf.put_slice(&self.content);
        buf.put_u8(next_type);
    }

    /// Decode one extension header of the given type from the buffer.
    /// Returns the header and the next extension header type in the chain.
    pub fn decode(ext_type: u8, buf: &mut Bytes) -> GtpResult<(Self, u8)> {
        if buf.remaining() < 1 {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        let length_units = buf.get_u8() as usize;
        if length_units == 0 {
            return Err(GtpError::InvalidFormat(
                "Extension header length must be at least 1".to_string(),
            ));
        }
        let content_len = length_units * 4 - 2;
        if buf.remaining() < content_len + 1 {
            return Err(GtpError::BufferTooShort {
                needed: content_len + 1,
                available: buf.remaining(),
            });
        }
        let content = buf.copy_to_bytes(content_len);
        let next_type = buf.get_u8();
        Ok((Self { ext_type, content }, next_type))
    }

    /// Parse the content as a PDU Session Container frame (TS 38.415)
    pub fn as_pdu_session_container(&self) -> GtpResult<PduSessionContainer> {
        if self.ext_type != ExtensionHeaderType::PduSessionContainer as u8 {
            return Err(GtpError::InvalidFormat(format!(
                "Not a PDU Session Container extension header: {:#x}",
                self.ext_type
            )));
        }
        PduSessionContainer::decode_content(&self.content)
    }
}

/// DL PDU SESSION INFORMATION frame (TS 38.415 Section 5.5.2.1, PDU Type 0)
///
/// Conditional fields are derived from their presence flags: PPI presence
/// drives PPP, the DL sending timestamp drives QMP, the DL QFI sequence
/// number drives SNP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DlPduSessionInformation {
    /// QoS Flow Identifier (6 bits)
    pub qfi: u8,
    /// Reflective QoS Indicator
    pub rqi: bool,
    /// Paging Policy Indicator (3 bits, presence sets the PPP flag)
    pub ppi: Option<u8>,
    /// DL Sending Time Stamp (presence sets the QMP flag)
    pub dl_sending_timestamp: Option<u64>,
    /// DL QFI Sequence Number (24 bits, presence sets the SNP flag)
    pub dl_qfi_sequence_number: Option<u32>,
}

/// UL QoS monitoring timestamps (TS 38.415, present when QMP is set)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UlQosMonitoringTimestamps {
    /// DL Sending Time Stamp Repeated
    pub dl_sending_timestamp_repeated: u64,
    /// DL Received Time Stamp
    pub dl_received_timestamp: u64,
    /// UL Sending Time Stamp
    pub ul_sending_timestamp: u64,
}

/// UL PDU SESSION INFORMATION frame (TS 38.415 Section 5.5.2.2, PDU Type 1)
///
/// Conditional fields are derived from their presence flags: the QoS
/// monitoring timestamps drive QMP, the delay results drive the DL/UL/N3-N9
/// delay indicators, the UL QFI sequence number drives SNP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UlPduSessionInformation {
    /// QoS Flow Identifier (6 bits)
    pub qfi: u8,
    /// QoS monitoring timestamps (presence sets the QMP flag)
    pub qos_monitoring: Option<UlQosMonitoringTimestamps>,
    /// DL Delay Result (presence sets the DL Delay Ind flag)
    pub dl_delay_result: Option<u32>,
    /// UL Delay Result (presence sets the UL Delay Ind flag)
    pub ul_delay_result: Option<u32>,
    /// UL QFI Sequence Number (24 bits, presence sets the SNP flag)
    pub ul_qfi_sequence_number: Option<u32>,
    /// N3/N9 Delay Result (presence sets the N3/N9 Delay Ind flag)
    pub n3_n9_delay_result: Option<u32>,
}

/// PDU Session Container frame carried in the 0x85 extension header
/// (TS 38.415 PDU Session user plane protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduSessionContainer {
    /// DL PDU SESSION INFORMATION (PDU Type 0)
    Dl(DlPduSessionInformation),
    /// UL PDU SESSION INFORMATION (PDU Type 1)
    Ul(UlPduSessionInformation),
}

impl PduSessionContainer {
    /// Create a minimal DL PDU SESSION INFORMATION frame with the given QFI
    pub fn dl(qfi: u8) -> Self {
        Self::Dl(DlPduSessionInformation {
            qfi: qfi & 0x3F,
            ..Default::default()
        })
    }

    /// Create a minimal UL PDU SESSION INFORMATION frame with the given QFI
    pub fn ul(qfi: u8) -> Self {
        Self::Ul(UlPduSessionInformation {
            qfi: qfi & 0x3F,
            ..Default::default()
        })
    }

    /// Get the PDU type of this frame
    pub fn pdu_type(&self) -> PduType {
        match self {
            Self::Dl(_) => PduType::DlPduSessionInformation,
            Self::Ul(_) => PduType::UlPduSessionInformation,
        }
    }

    /// Get the QoS Flow Identifier
    pub fn qfi(&self) -> u8 {
        match self {
            Self::Dl(dl) => dl.qfi,
            Self::Ul(ul) => ul.qfi,
        }
    }

    /// Encode the frame to extension header content octets (unpadded)
    pub fn encode_content(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        match self {
            Self::Dl(dl) => {
                // PDU Type (4 bits) | QMP | SNP | spare (2 bits)
                let octet0 = ((PduType::DlPduSessionInformation as u8) << 4)
                    | ((dl.dl_sending_timestamp.is_some() as u8) << 3)
                    | ((dl.dl_qfi_sequence_number.is_some() as u8) << 2);
                buf.put_u8(octet0);
                // PPP | RQI | QFI (6 bits)
                let octet1 =
                    ((dl.ppi.is_some() as u8) << 7) | ((dl.rqi as u8) << 6) | (dl.qfi & 0x3F);
                buf.put_u8(octet1);
                // PPI (3 bits) | spare (5 bits), present if PPP
                if let Some(ppi) = dl.ppi {
                    buf.put_u8((ppi & 0x07) << 5);
                }
                // DL Sending Time Stamp, present if QMP
                if let Some(ts) = dl.dl_sending_timestamp {
                    buf.put_u64(ts);
                }
                // DL QFI Sequence Number (24 bits), present if SNP
                if let Some(sn) = dl.dl_qfi_sequence_number {
                    buf.put_slice(&sn.to_be_bytes()[1..4]);
                }
            }
            Self::Ul(ul) => {
                // PDU Type (4 bits) | QMP | DL Delay Ind | UL Delay Ind | SNP
                let octet0 = ((PduType::UlPduSessionInformation as u8) << 4)
                    | ((ul.qos_monitoring.is_some() as u8) << 3)
                    | ((ul.dl_delay_result.is_some() as u8) << 2)
                    | ((ul.ul_delay_result.is_some() as u8) << 1)
                    | (ul.ul_qfi_sequence_number.is_some() as u8);
                buf.put_u8(octet0);
                // N3/N9 Delay Ind | New IE Flag | QFI (6 bits)
                let octet1 = ((ul.n3_n9_delay_result.is_some() as u8) << 7) | (ul.qfi & 0x3F);
                buf.put_u8(octet1);
                // QoS monitoring timestamps, present if QMP
                if let Some(qm) = ul.qos_monitoring {
                    buf.put_u64(qm.dl_sending_timestamp_repeated);
                    buf.put_u64(qm.dl_received_timestamp);
                    buf.put_u64(qm.ul_sending_timestamp);
                }
                // DL Delay Result, present if DL Delay Ind
                if let Some(delay) = ul.dl_delay_result {
                    buf.put_u32(delay);
                }
                // UL Delay Result, present if UL Delay Ind
                if let Some(delay) = ul.ul_delay_result {
                    buf.put_u32(delay);
                }
                // UL QFI Sequence Number (24 bits), present if SNP
                if let Some(sn) = ul.ul_qfi_sequence_number {
                    buf.put_slice(&sn.to_be_bytes()[1..4]);
                }
                // N3/N9 Delay Result, present if N3/N9 Delay Ind
                if let Some(delay) = ul.n3_n9_delay_result {
                    buf.put_u32(delay);
                }
            }
        }
        buf.to_vec()
    }

    /// Decode a frame from extension header content octets.
    /// Trailing padding octets beyond the decoded fields are ignored.
    pub fn decode_content(content: &[u8]) -> GtpResult<Self> {
        if content.len() < 2 {
            return Err(GtpError::BufferTooShort {
                needed: 2,
                available: content.len(),
            });
        }

        let mut buf = Bytes::copy_from_slice(content);
        let octet0 = buf.get_u8();
        let pdu_type = PduType::try_from((octet0 >> 4) & 0x0F)?;

        match pdu_type {
            PduType::DlPduSessionInformation => {
                let qmp = (octet0 >> 3) & 0x01 != 0;
                let snp = (octet0 >> 2) & 0x01 != 0;
                let octet1 = buf.get_u8();
                let ppp = (octet1 >> 7) & 0x01 != 0;
                let rqi = (octet1 >> 6) & 0x01 != 0;
                let qfi = octet1 & 0x3F;

                let ppi = if ppp {
                    if buf.remaining() < 1 {
                        return Err(GtpError::BufferTooShort {
                            needed: 1,
                            available: buf.remaining(),
                        });
                    }
                    Some((buf.get_u8() >> 5) & 0x07)
                } else {
                    None
                };
                let dl_sending_timestamp = if qmp {
                    if buf.remaining() < 8 {
                        return Err(GtpError::BufferTooShort {
                            needed: 8,
                            available: buf.remaining(),
                        });
                    }
                    Some(buf.get_u64())
                } else {
                    None
                };
                let dl_qfi_sequence_number = if snp {
                    if buf.remaining() < 3 {
                        return Err(GtpError::BufferTooShort {
                            needed: 3,
                            available: buf.remaining(),
                        });
                    }
                    Some(u32::from_be_bytes([
                        0,
                        buf.get_u8(),
                        buf.get_u8(),
                        buf.get_u8(),
                    ]))
                } else {
                    None
                };

                Ok(Self::Dl(DlPduSessionInformation {
                    qfi,
                    rqi,
                    ppi,
                    dl_sending_timestamp,
                    dl_qfi_sequence_number,
                }))
            }
            PduType::UlPduSessionInformation => {
                let qmp = (octet0 >> 3) & 0x01 != 0;
                let dl_delay_ind = (octet0 >> 2) & 0x01 != 0;
                let ul_delay_ind = (octet0 >> 1) & 0x01 != 0;
                let snp = octet0 & 0x01 != 0;
                let octet1 = buf.get_u8();
                let n3_n9_delay_ind = (octet1 >> 7) & 0x01 != 0;
                // New IE Flag (bit 7): any not-comprehended trailing fields
                // are skipped, bounded by the extension header length
                let qfi = octet1 & 0x3F;

                let qos_monitoring = if qmp {
                    if buf.remaining() < 24 {
                        return Err(GtpError::BufferTooShort {
                            needed: 24,
                            available: buf.remaining(),
                        });
                    }
                    Some(UlQosMonitoringTimestamps {
                        dl_sending_timestamp_repeated: buf.get_u64(),
                        dl_received_timestamp: buf.get_u64(),
                        ul_sending_timestamp: buf.get_u64(),
                    })
                } else {
                    None
                };
                let dl_delay_result = if dl_delay_ind {
                    if buf.remaining() < 4 {
                        return Err(GtpError::BufferTooShort {
                            needed: 4,
                            available: buf.remaining(),
                        });
                    }
                    Some(buf.get_u32())
                } else {
                    None
                };
                let ul_delay_result = if ul_delay_ind {
                    if buf.remaining() < 4 {
                        return Err(GtpError::BufferTooShort {
                            needed: 4,
                            available: buf.remaining(),
                        });
                    }
                    Some(buf.get_u32())
                } else {
                    None
                };
                let ul_qfi_sequence_number = if snp {
                    if buf.remaining() < 3 {
                        return Err(GtpError::BufferTooShort {
                            needed: 3,
                            available: buf.remaining(),
                        });
                    }
                    Some(u32::from_be_bytes([
                        0,
                        buf.get_u8(),
                        buf.get_u8(),
                        buf.get_u8(),
                    ]))
                } else {
                    None
                };
                let n3_n9_delay_result = if n3_n9_delay_ind {
                    if buf.remaining() < 4 {
                        return Err(GtpError::BufferTooShort {
                            needed: 4,
                            available: buf.remaining(),
                        });
                    }
                    Some(buf.get_u32())
                } else {
                    None
                };

                Ok(Self::Ul(UlPduSessionInformation {
                    qfi,
                    qos_monitoring,
                    dl_delay_result,
                    ul_delay_result,
                    ul_qfi_sequence_number,
                    n3_n9_delay_result,
                }))
            }
        }
    }

    /// Map QFI to DSCP value per 3GPP TS 23.501 Table 5.7.4-1 (Rel-18).
    ///
    /// Maps QoS Flow Identifier to DiffServ Code Point for transport-level
    /// QoS enforcement in outer IP header of GTP-U tunnel.
    pub fn qfi_to_dscp(qfi: u8) -> u8 {
        match qfi {
            // GBR flows: Conversational voice/video
            1 => 46, // EF (Expedited Forwarding)
            2 => 34, // AF41
            3 => 26, // AF31
            4 => 24, // AF21 (non-conversational video)
            // Non-GBR flows
            5 => 0,  // Best Effort (IMS signaling uses CS0)
            6 => 18, // AF21 (buffered video streaming)
            7 => 10, // AF11 (interactive gaming)
            8 => 10, // AF11 (TCP-based)
            9 => 0,  // BE (default)
            // Rel-18 XR 5QI values mapped to QFI ranges
            82 => 46, // XR cloud rendering DL -> EF
            83 => 46, // XR pose/control UL -> EF
            84 => 34, // XR split rendering DL -> AF41
            85 => 46, // XR haptic feedback -> EF
            _ => 0,   // Unknown -> Best Effort
        }
    }

    /// Map 5QI to QFI→DSCP (convenience for SMF/PCF use).
    pub fn five_qi_to_dscp(five_qi: u8) -> u8 {
        Self::qfi_to_dscp(five_qi)
    }
}

/// GTPv1 Cause Values (TS 29.060 Table 38)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cause {
    // Request causes (0-127)
    RequestImsi = 0,
    RequestImei = 1,
    RequestImsiImei = 2,
    NoIdNeeded = 3,
    MsRefuses = 4,
    MsNotGprsResponding = 5,
    ReactivationRequested = 6,
    PdpAddressInactivityTimerExp = 7,
    NetworkFailure = 8,
    QosParameterMismatch = 9,

    // Acceptance causes (128-191)
    RequestAccepted = 128,
    NewPdpTypeDueToNetworkPreference = 129,
    NewPdpTypeDueToSingleAddressBearerOnly = 130,

    // Rejection causes (192-255)
    NonExistent = 192,
    InvalidMessageFormat = 193,
    ImsiImeiNotKnown = 194,
    MsGprsDetached = 195,
    RejMsNotGprsResponding = 196,
    RejMsRefuses = 197,
    VersionNotSupported = 198,
    NoResourcesAvailable = 199,
    ServiceNotSupported = 200,
    MandatoryIeIncorrect = 201,
    MandatoryIeMissing = 202,
    OptionalIeIncorrect = 203,
    SystemFailure = 204,
    RoamingRestriction = 205,
    PTmsiSignatureMismatch = 206,
    GprsConnSuspended = 207,
    AuthenticationFailure = 208,
    UserAuthenticationFailed = 209,
    ContextNotFound = 210,
    AllDynamicPdpAddrsOccupied = 211,
    NoMemoryAvailable = 212,
    RelocationFailure = 213,
    UnknownMandatoryExtensionHeader = 214,
    SemanticErrTftOperation = 215,
    SyntacticErrTftOperation = 216,
    SemanticErrPktFilter = 217,
    SyntacticErrPktFilter = 218,
    MissingOrUnknownApn = 219,
    UnknownPdpAddrOrType = 220,
    PdpContextWithoutTftActivated = 221,
    ApnAccessDenied = 222,
    ApnIncompatibleWithActivePdpContexts = 223,
    MsMbmsCapInsufficient = 224,
    InvalidCorrelationId = 225,
    MbmsBearerContextSuperseded = 226,
    BearerControlModeViolation = 227,
    CollisionWithNetInitiatedReq = 228,
    ApnCongestion = 229,
    BearerHandlingNotSupported = 230,
    TgtAccRestrictedSubscriber = 231,
    UeTmpNotReachablePowerSaving = 232,
    RelocationFailureNasMsgRedir = 233,
}

impl TryFrom<u8> for Cause {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Cause::RequestImsi),
            1 => Ok(Cause::RequestImei),
            2 => Ok(Cause::RequestImsiImei),
            3 => Ok(Cause::NoIdNeeded),
            4 => Ok(Cause::MsRefuses),
            5 => Ok(Cause::MsNotGprsResponding),
            6 => Ok(Cause::ReactivationRequested),
            7 => Ok(Cause::PdpAddressInactivityTimerExp),
            8 => Ok(Cause::NetworkFailure),
            9 => Ok(Cause::QosParameterMismatch),
            128 => Ok(Cause::RequestAccepted),
            129 => Ok(Cause::NewPdpTypeDueToNetworkPreference),
            130 => Ok(Cause::NewPdpTypeDueToSingleAddressBearerOnly),
            192 => Ok(Cause::NonExistent),
            193 => Ok(Cause::InvalidMessageFormat),
            194 => Ok(Cause::ImsiImeiNotKnown),
            195 => Ok(Cause::MsGprsDetached),
            196 => Ok(Cause::RejMsNotGprsResponding),
            197 => Ok(Cause::RejMsRefuses),
            198 => Ok(Cause::VersionNotSupported),
            199 => Ok(Cause::NoResourcesAvailable),
            200 => Ok(Cause::ServiceNotSupported),
            201 => Ok(Cause::MandatoryIeIncorrect),
            202 => Ok(Cause::MandatoryIeMissing),
            203 => Ok(Cause::OptionalIeIncorrect),
            204 => Ok(Cause::SystemFailure),
            205 => Ok(Cause::RoamingRestriction),
            206 => Ok(Cause::PTmsiSignatureMismatch),
            207 => Ok(Cause::GprsConnSuspended),
            208 => Ok(Cause::AuthenticationFailure),
            209 => Ok(Cause::UserAuthenticationFailed),
            210 => Ok(Cause::ContextNotFound),
            211 => Ok(Cause::AllDynamicPdpAddrsOccupied),
            212 => Ok(Cause::NoMemoryAvailable),
            213 => Ok(Cause::RelocationFailure),
            214 => Ok(Cause::UnknownMandatoryExtensionHeader),
            215 => Ok(Cause::SemanticErrTftOperation),
            216 => Ok(Cause::SyntacticErrTftOperation),
            217 => Ok(Cause::SemanticErrPktFilter),
            218 => Ok(Cause::SyntacticErrPktFilter),
            219 => Ok(Cause::MissingOrUnknownApn),
            220 => Ok(Cause::UnknownPdpAddrOrType),
            221 => Ok(Cause::PdpContextWithoutTftActivated),
            222 => Ok(Cause::ApnAccessDenied),
            223 => Ok(Cause::ApnIncompatibleWithActivePdpContexts),
            224 => Ok(Cause::MsMbmsCapInsufficient),
            225 => Ok(Cause::InvalidCorrelationId),
            226 => Ok(Cause::MbmsBearerContextSuperseded),
            227 => Ok(Cause::BearerControlModeViolation),
            228 => Ok(Cause::CollisionWithNetInitiatedReq),
            229 => Ok(Cause::ApnCongestion),
            230 => Ok(Cause::BearerHandlingNotSupported),
            231 => Ok(Cause::TgtAccRestrictedSubscriber),
            232 => Ok(Cause::UeTmpNotReachablePowerSaving),
            233 => Ok(Cause::RelocationFailureNasMsgRedir),
            _ => Err(GtpError::InvalidCause(value)),
        }
    }
}

impl Cause {
    /// Check if cause indicates acceptance (0x80 bit set, 0xC0 not set)
    pub fn is_accept(&self) -> bool {
        let value = *self as u8;
        (value & 0x80) != 0 && (value & 0xC0) != 0xC0
    }

    /// Check if cause indicates rejection (0xC0 bits set)
    pub fn is_reject(&self) -> bool {
        let value = *self as u8;
        (value & 0xC0) == 0xC0
    }
}

/// GTPv1 Cause IE structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CauseIe {
    /// Cause value
    pub value: u8,
    /// PCE (PDN Connection Error) flag
    pub pce: bool,
    /// BCE (Bearer Context Error) flag
    pub bce: bool,
    /// CS (Cause Source) flag
    pub cs: bool,
}

impl CauseIe {
    /// Create new Cause IE
    pub fn new(value: u8) -> Self {
        Self {
            value,
            pce: false,
            bce: false,
            cs: false,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.value);
        let flags = ((self.pce as u8) << 2) | ((self.bce as u8) << 1) | (self.cs as u8);
        buf.put_u8(flags);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 2 {
            return Err(GtpError::BufferTooShort {
                needed: 2,
                available: buf.remaining(),
            });
        }
        let value = buf.get_u8();
        let flags = buf.get_u8();
        Ok(Self {
            value,
            pce: (flags >> 2) & 0x01 != 0,
            bce: (flags >> 1) & 0x01 != 0,
            cs: flags & 0x01 != 0,
        })
    }
}

/// RAT Type values (TS 29.060 Table 7.7.50.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RatType {
    Reserved = 0,
    Utran = 1,
    Geran = 2,
    Wlan = 3,
    Gan = 4,
    HspaEvolution = 5,
    Eutran = 6,
}

impl TryFrom<u8> for RatType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RatType::Reserved),
            1 => Ok(RatType::Utran),
            2 => Ok(RatType::Geran),
            3 => Ok(RatType::Wlan),
            4 => Ok(RatType::Gan),
            5 => Ok(RatType::HspaEvolution),
            6 => Ok(RatType::Eutran),
            _ => Err(GtpError::InvalidFormat(format!(
                "Unknown RAT type: {value}"
            ))),
        }
    }
}

/// Geographic Location Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GeoLocType {
    Cgi = 0,
    Sai = 1,
    Rai = 2,
}

/// PLMN ID (3 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlmnId {
    pub bytes: [u8; 3],
}

impl PlmnId {
    /// Create from MCC and MNC
    pub fn new(mcc: u16, mnc: u16) -> Self {
        let mut bytes = [0u8; 3];
        // MCC digit 2 | MCC digit 1
        bytes[0] = ((mcc / 10 % 10) << 4) as u8 | (mcc % 10) as u8;
        // MNC digit 3 | MCC digit 3
        let mnc3 = if mnc > 99 { mnc / 100 } else { 0x0F };
        bytes[1] = ((mnc3 as u8) << 4) | ((mcc / 100) as u8);
        // MNC digit 2 | MNC digit 1
        bytes[2] = ((mnc / 10 % 10) << 4) as u8 | (mnc % 10) as u8;
        Self { bytes }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.bytes);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 3 {
            return Err(GtpError::BufferTooShort {
                needed: 3,
                available: buf.remaining(),
            });
        }
        let mut bytes = [0u8; 3];
        buf.copy_to_slice(&mut bytes);
        Ok(Self { bytes })
    }
}

/// User Location Information - CGI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UliCgi {
    pub plmn_id: PlmnId,
    pub lac: u16,
    pub ci: u16,
}

/// User Location Information - SAI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UliSai {
    pub plmn_id: PlmnId,
    pub lac: u16,
    pub sac: u16,
}

/// User Location Information - RAI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UliRai {
    pub plmn_id: PlmnId,
    pub lac: u16,
    pub rac: u16,
}

/// User Location Information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uli {
    Cgi(UliCgi),
    Sai(UliSai),
    Rai(UliRai),
}

impl Uli {
    /// Encode ULI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Uli::Cgi(cgi) => {
                buf.put_u8(GeoLocType::Cgi as u8);
                cgi.plmn_id.encode(buf);
                buf.put_u16(cgi.lac);
                buf.put_u16(cgi.ci);
            }
            Uli::Sai(sai) => {
                buf.put_u8(GeoLocType::Sai as u8);
                sai.plmn_id.encode(buf);
                buf.put_u16(sai.lac);
                buf.put_u16(sai.sac);
            }
            Uli::Rai(rai) => {
                buf.put_u8(GeoLocType::Rai as u8);
                rai.plmn_id.encode(buf);
                buf.put_u16(rai.lac);
                buf.put_u16(rai.rac);
            }
        }
    }

    /// Decode ULI from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 8 {
            return Err(GtpError::BufferTooShort {
                needed: 8,
                available: buf.remaining(),
            });
        }

        let geo_loc_type = buf.get_u8();
        let plmn_id = PlmnId::decode(buf)?;
        let lac = buf.get_u16();
        let value = buf.get_u16();

        match geo_loc_type {
            0 => Ok(Uli::Cgi(UliCgi {
                plmn_id,
                lac,
                ci: value,
            })),
            1 => Ok(Uli::Sai(UliSai {
                plmn_id,
                lac,
                sac: value,
            })),
            2 => Ok(Uli::Rai(UliRai {
                plmn_id,
                lac,
                rac: value,
            })),
            _ => Err(GtpError::InvalidFormat(format!(
                "Unknown geo location type: {geo_loc_type}"
            ))),
        }
    }
}

/// GSN Address (IPv4 or IPv6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GsnAddress {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl GsnAddress {
    /// Encode GSN address to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            GsnAddress::Ipv4(addr) => buf.put_slice(addr),
            GsnAddress::Ipv6(addr) => buf.put_slice(addr),
        }
    }

    /// Decode GSN address from bytes (length determines type)
    pub fn decode(buf: &mut Bytes, len: usize) -> GtpResult<Self> {
        match len {
            4 => {
                if buf.remaining() < 4 {
                    return Err(GtpError::BufferTooShort {
                        needed: 4,
                        available: buf.remaining(),
                    });
                }
                let mut addr = [0u8; 4];
                buf.copy_to_slice(&mut addr);
                Ok(GsnAddress::Ipv4(addr))
            }
            16 => {
                if buf.remaining() < 16 {
                    return Err(GtpError::BufferTooShort {
                        needed: 16,
                        available: buf.remaining(),
                    });
                }
                let mut addr = [0u8; 16];
                buf.copy_to_slice(&mut addr);
                Ok(GsnAddress::Ipv6(addr))
            }
            _ => Err(GtpError::InvalidFormat(format!(
                "Invalid GSN address length: {len}"
            ))),
        }
    }
}

/// APN Restriction values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApnRestriction {
    NoRestriction = 0,
    Public1 = 1,
    Public2 = 2,
    Private1 = 3,
    Private2 = 4,
}

/// Delivery Order values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryOrder {
    Subscribed = 0,
    Yes = 1,
    No = 2,
}

/// Delivery of Erroneous SDUs values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryErrSdu {
    Subscribed = 0,
    NoDetect = 1,
    Yes = 2,
    No = 3,
}

/// QoS Traffic Class values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QosTrafficClass {
    Subscribed = 0,
    Conversational = 1,
    Streaming = 2,
    Interactive = 3,
    Background = 4,
}

/// QoS Source Statistics Descriptor values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QosSrcStatsDesc {
    Unknown = 0,
    Speech = 1,
}

/// Common Flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommonFlags {
    pub dual_address_bearer_flag: bool,
    pub upgrade_qos_supported: bool,
    pub nrsn: bool,
    pub no_qos_negotiation: bool,
    pub mbms_counting_information: bool,
    pub ran_procedures_ready: bool,
    pub mbms_service_type: bool,
    pub prohibit_payload_compression: bool,
}

impl CommonFlags {
    /// Encode to byte
    pub fn encode(&self) -> u8 {
        ((self.dual_address_bearer_flag as u8) << 7)
            | ((self.upgrade_qos_supported as u8) << 6)
            | ((self.nrsn as u8) << 5)
            | ((self.no_qos_negotiation as u8) << 4)
            | ((self.mbms_counting_information as u8) << 3)
            | ((self.ran_procedures_ready as u8) << 2)
            | ((self.mbms_service_type as u8) << 1)
            | (self.prohibit_payload_compression as u8)
    }

    /// Decode from byte
    pub fn decode(byte: u8) -> Self {
        Self {
            dual_address_bearer_flag: (byte >> 7) & 0x01 != 0,
            upgrade_qos_supported: (byte >> 6) & 0x01 != 0,
            nrsn: (byte >> 5) & 0x01 != 0,
            no_qos_negotiation: (byte >> 4) & 0x01 != 0,
            mbms_counting_information: (byte >> 3) & 0x01 != 0,
            ran_procedures_ready: (byte >> 2) & 0x01 != 0,
            mbms_service_type: (byte >> 1) & 0x01 != 0,
            prohibit_payload_compression: byte & 0x01 != 0,
        }
    }
}

/// APN-AMBR (Aggregate Maximum Bit Rate)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApnAmbr {
    pub uplink: u32,
    pub downlink: u32,
}

impl ApnAmbr {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.uplink);
        buf.put_u32(self.downlink);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 8 {
            return Err(GtpError::BufferTooShort {
                needed: 8,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            uplink: buf.get_u32(),
            downlink: buf.get_u32(),
        })
    }
}

/// Tunnel Endpoint Identifier Data II
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TeidII {
    pub nsapi: u8,
    pub teid: u32,
}

impl TeidII {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.nsapi & 0x0F);
        buf.put_u32(self.teid);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 5 {
            return Err(GtpError::BufferTooShort {
                needed: 5,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            nsapi: buf.get_u8() & 0x0F,
            teid: buf.get_u32(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dl_pdu_session_container_minimal_round_trip() {
        let container = PduSessionContainer::dl(9);
        let content = container.encode_content();
        // PDU Type 0, no QMP/SNP; PPP=0, RQI=0, QFI=9
        assert_eq!(content, vec![0x00, 0x09]);

        let decoded = PduSessionContainer::decode_content(&content).unwrap();
        assert_eq!(decoded, container);
        assert_eq!(decoded.qfi(), 9);
        assert_eq!(decoded.pdu_type(), PduType::DlPduSessionInformation);
    }

    #[test]
    fn test_dl_pdu_session_container_all_fields_round_trip() {
        let container = PduSessionContainer::Dl(DlPduSessionInformation {
            qfi: 0x3F,
            rqi: true,
            ppi: Some(5),
            dl_sending_timestamp: Some(0x0123_4567_89AB_CDEF),
            dl_qfi_sequence_number: Some(0x00AB_CDEF),
        });
        let content = container.encode_content();
        let decoded = PduSessionContainer::decode_content(&content).unwrap();
        assert_eq!(decoded, container);
    }

    #[test]
    fn test_ul_pdu_session_container_minimal_round_trip() {
        let container = PduSessionContainer::ul(1);
        let content = container.encode_content();
        // PDU Type 1, all indicators clear; QFI=1
        assert_eq!(content, vec![0x10, 0x01]);

        let decoded = PduSessionContainer::decode_content(&content).unwrap();
        assert_eq!(decoded, container);
        assert_eq!(decoded.pdu_type(), PduType::UlPduSessionInformation);
    }

    #[test]
    fn test_ul_pdu_session_container_all_fields_round_trip() {
        let container = PduSessionContainer::Ul(UlPduSessionInformation {
            qfi: 7,
            qos_monitoring: Some(UlQosMonitoringTimestamps {
                dl_sending_timestamp_repeated: 1,
                dl_received_timestamp: 2,
                ul_sending_timestamp: 3,
            }),
            dl_delay_result: Some(100),
            ul_delay_result: Some(200),
            ul_qfi_sequence_number: Some(0x12_3456),
            n3_n9_delay_result: Some(300),
        });
        let content = container.encode_content();
        let decoded = PduSessionContainer::decode_content(&content).unwrap();
        assert_eq!(decoded, container);
    }

    #[test]
    fn test_pdu_session_container_rejects_invalid_pdu_type() {
        // PDU Type 5 is not defined by TS 38.415
        assert!(PduSessionContainer::decode_content(&[0x50, 0x09]).is_err());
    }

    #[test]
    fn test_pdu_session_container_rejects_truncated_conditional_field() {
        // DL frame with QMP set but no timestamp present
        assert!(PduSessionContainer::decode_content(&[0x08, 0x09]).is_err());
    }

    #[test]
    fn test_ext_header_padding_and_length_units() {
        // 2 content octets fit exactly one 4-octet unit
        let ext = Gtp1ExtHeader::new(
            ExtensionHeaderType::PduSessionContainer as u8,
            &[0x00, 0x09],
        );
        assert_eq!(ext.length_units(), 1);
        assert_eq!(ext.encoded_len(), 4);

        // 3 content octets are padded up to the next 4-octet boundary
        let ext = Gtp1ExtHeader::new(
            ExtensionHeaderType::PduSessionContainer as u8,
            &[0x00, 0x89, 0xA0],
        );
        assert_eq!(ext.content.len(), 6);
        assert_eq!(ext.length_units(), 2);
        assert_eq!(ext.encoded_len(), 8);
    }

    #[test]
    fn test_ext_header_decode_rejects_zero_length() {
        let mut buf = Bytes::from_static(&[0x00, 0x00, 0x09, 0x00]);
        assert!(
            Gtp1ExtHeader::decode(ExtensionHeaderType::PduSessionContainer as u8, &mut buf)
                .is_err()
        );
    }

    #[test]
    fn test_ext_header_decode_rejects_truncated() {
        // Length says 2 units (8 octets total) but only 4 octets present
        let mut buf = Bytes::from_static(&[0x02, 0x00, 0x09, 0x00]);
        assert!(
            Gtp1ExtHeader::decode(ExtensionHeaderType::PduSessionContainer as u8, &mut buf)
                .is_err()
        );
    }

    // gtp-02: comprehension-bit classification (TS 29.281 Figure 5.2.1-2)
    #[test]
    fn test_comprehension_of_bits_7_8() {
        // bits 11 -> required by recipient
        assert_eq!(comprehension_of(0xC4), ExtHeaderComprehension::Required);
        assert_eq!(comprehension_of(0xC2), ExtHeaderComprehension::Required);
        // bits 10 -> required by Endpoint Receiver only
        assert_eq!(
            comprehension_of(0x82),
            ExtHeaderComprehension::RequiredEndpointOnly
        );
        assert_eq!(
            comprehension_of(0x84),
            ExtHeaderComprehension::RequiredEndpointOnly
        );
        // bits 01 and 00 -> comprehension not required
        assert_eq!(comprehension_of(0x44), ExtHeaderComprehension::NotRequired);
        assert_eq!(comprehension_of(0x40), ExtHeaderComprehension::NotRequired);
        assert_eq!(comprehension_of(0x04), ExtHeaderComprehension::NotRequired);
    }

    // gtp-08: all defined user-plane ext header types are recognized
    #[test]
    fn test_known_ext_header_types() {
        for t in [
            0x00u8, 0x03, 0x04, 0x20, 0x40, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0xC0,
        ] {
            assert!(Gtp1ExtHeader::is_known(t), "type {t:#x} should be known");
            assert!(ExtensionHeaderType::try_from(t).is_ok());
        }
        // An unspecified type is unknown
        assert!(!Gtp1ExtHeader::is_known(0xC4));
        assert!(ExtensionHeaderType::try_from(0xC4).is_err());
    }

    // gtp-02: a known type never requires comprehension; an unknown one does
    // per its bits-7/8 class and the local role.
    #[test]
    fn test_requires_comprehension() {
        // Known NR RAN Container (0x84) -> never flagged even though bits=10
        let known = Gtp1ExtHeader::new(0x84, &[0x00, 0x00]);
        assert!(!known.requires_comprehension(true));
        assert!(!known.requires_comprehension(false));

        // Unknown 0xC4 (bits 11) -> required for both endpoint and intermediate
        let req = Gtp1ExtHeader::new(0xC4, &[0x00, 0x00]);
        assert!(req.requires_comprehension(true));
        assert!(req.requires_comprehension(false));

        // Unknown 0x8A (bits 10) -> required by endpoint only
        let ep_only = Gtp1ExtHeader::new(0x8A, &[0x00, 0x00]);
        assert!(ep_only.requires_comprehension(true));
        assert!(!ep_only.requires_comprehension(false));

        // Unknown 0x44 (bits 01) -> never required
        let not_req = Gtp1ExtHeader::new(0x44, &[0x00, 0x00]);
        assert!(!not_req.requires_comprehension(true));
        assert!(!not_req.requires_comprehension(false));
    }
}
