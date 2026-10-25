//! EPS NAS messages
//!
//! Based on 3GPP TS 24.301

use super::header::*;
use super::types::*;
use crate::buf::{
    opaque_tlv, optional_tlv, optional_tlv_e, set_first, skip_unknown_ie, IeLen, NasBuf,
};
use crate::common::types::*;
use crate::error::{NasError, NasResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// EMM message
#[derive(Debug, Clone, PartialEq)]
pub enum EmmMessage {
    AttachRequest(AttachRequest),
    AttachAccept(AttachAccept),
    AttachComplete(AttachComplete),
    AttachReject(AttachReject),
    DetachRequest(DetachRequest),
    DetachAccept,
    TrackingAreaUpdateRequest(TrackingAreaUpdateRequest),
    TrackingAreaUpdateAccept(TrackingAreaUpdateAccept),
    TrackingAreaUpdateReject(TrackingAreaUpdateReject),
    AuthenticationRequest(EpsAuthenticationRequest),
    AuthenticationResponse(EpsAuthenticationResponse),
    AuthenticationReject,
    AuthenticationFailure(EpsAuthenticationFailure),
    SecurityModeCommand(EpsSecurityModeCommand),
    SecurityModeComplete(EpsSecurityModeComplete),
    SecurityModeReject(EpsSecurityModeReject),
    IdentityRequest(EpsIdentityRequest),
    IdentityResponse(EpsIdentityResponse),
    EmmStatus(EmmStatus),
    ServiceRequest(EpsServiceRequest),
    ExtendedServiceRequest(ExtendedServiceRequest),
    ServiceReject(EpsServiceReject),
    GutiReallocationCommand(GutiReallocationCommand),
    GutiReallocationComplete,
    TrackingAreaUpdateComplete,
    EmmInformation(EmmInformation),
    DownlinkNasTransport(EpsDownlinkNasTransport),
    UplinkNasTransport(EpsUplinkNasTransport),
    CsServiceNotification(CsServiceNotification),
}

/// Attach Request message (TS 24.301 Section 8.2.4)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachRequest {
    /// EPS attach type
    pub eps_attach_type: EpsAttachType,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// EPS mobile identity
    pub eps_mobile_identity: EpsMobileIdentity,
    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// ESM message container
    pub esm_message_container: EsmMessageContainer,
    /// Presence mask
    pub presencemask: u64,
    /// Old P-TMSI signature
    pub old_p_tmsi_signature: Option<[u8; 3]>,
    /// Additional GUTI
    pub additional_guti: Option<EpsMobileIdentity>,
    /// Last visited registered TAI
    pub last_visited_tai: Option<EpsTai>,
    /// DRX parameter
    pub drx_parameter: Option<[u8; 2]>,
}

impl AttachRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // EPS attach type + NAS key set identifier (1 byte)
        buf.put_u8((self.nas_key_set_identifier.encode() << 4) | self.eps_attach_type.encode());
        // EPS mobile identity
        self.eps_mobile_identity.encode(buf);
        // UE network capability
        self.ue_network_capability.encode(buf);
        // ESM message container
        self.esm_message_container.encode(buf);
        // Optional IEs (TS 24.301 Table 8.2.4.1)
        if let Some(ref sig) = self.old_p_tmsi_signature {
            buf.put_u8(0x19); // IEI (TV, 3-octet value)
            buf.put_slice(sig);
        }
        if let Some(ref guti) = self.additional_guti {
            buf.put_u8(0x50); // IEI (TLV)
            guti.encode(buf);
        }
        if let Some(ref tai) = self.last_visited_tai {
            buf.put_u8(0x52); // IEI (TV, 5-octet value)
            tai.encode(buf);
        }
        if let Some(ref drx) = self.drx_parameter {
            buf.put_u8(0x5C); // IEI (TV, 2-octet value)
            buf.put_slice(drx);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }

        let first_byte = buf.read_u8()?;
        let eps_attach_type = EpsAttachType::decode(first_byte & 0x0F);
        let nas_key_set_identifier = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let eps_mobile_identity = EpsMobileIdentity::decode(buf)?;
        let ue_network_capability = UeNetworkCapability::decode(buf)?;
        let esm_message_container = EsmMessageContainer::decode(buf)?;

        let mut msg = Self {
            eps_attach_type,
            nas_key_set_identifier,
            eps_mobile_identity,
            ue_network_capability,
            esm_message_container,
            ..Default::default()
        };

        // Decode optional IEs (TS 24.301 Table 8.2.4.1)
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x19 => {
                    buf.skip(1)?;
                    if buf.remaining() >= 3 {
                        let mut sig = [0u8; 3];
                        buf.read_into(&mut sig)?;
                        msg.old_p_tmsi_signature = Some(sig);
                    }
                }
                0x50 => {
                    buf.skip(1)?;
                    set_first(
                        &mut msg.additional_guti,
                        optional_tlv(buf, EpsMobileIdentity::decode)?,
                    );
                }
                0x52 => {
                    buf.skip(1)?;
                    msg.last_visited_tai = Some(EpsTai::decode(buf)?);
                }
                0x5C => {
                    buf.skip(1)?;
                    if buf.remaining() >= 2 {
                        let mut drx = [0u8; 2];
                        buf.read_into(&mut drx)?;
                        msg.drx_parameter = Some(drx);
                    }
                }
                // Old location area identification (TV 6): not modelled. Type 3, so skipped by its fixed
                // length; read as TLV its value octet would be taken as a length (#784).
                0x13 => buf.skip(6)?,
                // Additional information requested (TV 2): not modelled. Type 3, so skipped by its fixed
                // length; read as TLV its value octet would be taken as a length (#784).
                0x17 => buf.skip(2)?,
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

/// Attach Accept message (TS 24.301 Section 8.2.1)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachAccept {
    /// EPS attach result
    pub eps_attach_result: EpsAttachResult,
    /// T3412 value
    pub t3412_value: GprsTimer,
    /// TAI list
    pub tai_list: EpsTaiList,
    /// ESM message container
    pub esm_message_container: EsmMessageContainer,
    /// Presence mask
    pub presencemask: u64,
    /// GUTI
    pub guti: Option<EpsMobileIdentity>,
    /// Location area identification
    pub lai: Option<Vec<u8>>,
    /// MS identity
    pub ms_identity: Option<Vec<u8>>,
    /// EMM cause
    pub emm_cause: Option<u8>,
    /// T3402 value
    pub t3402_value: Option<GprsTimer>,
    /// T3423 value
    pub t3423_value: Option<GprsTimer>,
    /// Equivalent PLMNs
    pub equivalent_plmns: Option<Vec<PlmnId>>,
}

impl AttachAccept {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.eps_attach_result.encode());
        buf.put_u8(self.t3412_value.encode());
        self.tai_list.encode(buf);
        self.esm_message_container.encode(buf);
        // Optional IEs (TS 24.301 Table 8.2.1.1)
        if let Some(ref guti) = self.guti {
            buf.put_u8(0x50); // IEI (TLV)
            guti.encode(buf);
        }
        if let Some(ref lai) = self.lai {
            buf.put_u8(0x13); // IEI (TV, 5-octet value)
            buf.put_slice(lai);
        }
        if let Some(ref ms_id) = self.ms_identity {
            buf.put_u8(0x23); // IEI (TLV)
            buf.put_u8(ms_id.len() as u8);
            buf.put_slice(ms_id);
        }
        if let Some(cause) = self.emm_cause {
            buf.put_u8(0x53); // IEI (TV, 1-octet value)
            buf.put_u8(cause);
        }
        if let Some(t3402) = self.t3402_value {
            buf.put_u8(0x17); // IEI (TV, 1-octet value)
            buf.put_u8(t3402.encode());
        }
        if let Some(t3423) = self.t3423_value {
            buf.put_u8(0x59); // IEI (TV, 1-octet value)
            buf.put_u8(t3423.encode());
        }
        if let Some(ref plmns) = self.equivalent_plmns {
            buf.put_u8(0x4A); // IEI (TLV, 3 octets per PLMN)
            buf.put_u8((plmns.len() * 3) as u8);
            for plmn in plmns {
                plmn.encode(buf);
            }
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort {
                expected: 2,
                actual: buf.remaining(),
            });
        }

        let eps_attach_result = EpsAttachResult::decode(buf.read_u8()?);
        let t3412_value = GprsTimer::decode(buf.read_u8()?);
        let tai_list = EpsTaiList::decode(buf)?;
        let esm_message_container = EsmMessageContainer::decode(buf)?;

        let mut msg = Self {
            eps_attach_result,
            t3412_value,
            tai_list,
            esm_message_container,
            ..Default::default()
        };

        // Decode optional IEs (TS 24.301 Table 8.2.1.1)
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x50 => {
                    buf.skip(1)?;
                    set_first(&mut msg.guti, optional_tlv(buf, EpsMobileIdentity::decode)?);
                }
                0x13 => {
                    buf.skip(1)?;
                    if buf.remaining() >= 5 {
                        msg.lai = Some(buf.read_bytes(5)?.to_vec());
                    }
                }
                0x23 => {
                    buf.skip(1)?;
                    set_first(&mut msg.ms_identity, Some(opaque_tlv(buf)?));
                }
                0x53 => {
                    buf.skip(1)?;
                    if buf.remaining() >= 1 {
                        msg.emm_cause = Some(buf.read_u8()?);
                    }
                }
                0x17 => {
                    buf.skip(1)?;
                    if buf.remaining() >= 1 {
                        msg.t3402_value = Some(GprsTimer::decode(buf.read_u8()?));
                    }
                }
                0x59 => {
                    buf.skip(1)?;
                    if buf.remaining() >= 1 {
                        msg.t3423_value = Some(GprsTimer::decode(buf.read_u8()?));
                    }
                }
                0x4A => {
                    // §9.9.2.8 -> TS 24.008 §10.5.1.13: 5 to 47 octets, so
                    // at least one PLMN. Decoded inside the IE's length, so
                    // a trailing partial PLMN is not read as the next IE (#613).
                    // Optional: a bad one is absent (§7.7.1, #630).
                    buf.skip(1)?;
                    set_first(
                        &mut msg.equivalent_plmns,
                        optional_tlv(buf, |b| {
                            let mut ie = b.read_lv(IeLen::AtLeast(3))?;
                            let mut plmns = Vec::with_capacity(ie.len() / 3);
                            for _ in 0..(ie.len() / 3) {
                                plmns.push(PlmnId::decode(&mut ie)?);
                            }
                            Ok(plmns)
                        })?,
                    );
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

/// Attach Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachComplete {
    /// ESM message container
    pub esm_message_container: EsmMessageContainer,
}

/// Attach Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachReject {
    /// EMM cause
    pub emm_cause: u8,
    /// ESM message container
    pub esm_message_container: Option<EsmMessageContainer>,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
    /// T3402 value
    pub t3402_value: Option<GprsTimer2>,
}

/// Detach Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DetachRequest {
    /// Detach type
    pub detach_type: u8,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// EPS mobile identity
    pub eps_mobile_identity: EpsMobileIdentity,
}

/// Tracking Area Update Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrackingAreaUpdateRequest {
    /// EPS update type
    pub eps_update_type: u8,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// Old GUTI
    pub old_guti: EpsMobileIdentity,
    /// Presence mask
    pub presencemask: u64,
    // Optional IEs (TS 24.301 Table 8.2.29.1, #931). The ones the MME acts on
    // are modelled; the others are skipped by their type (§7.6.1).
    /// Non-current native NAS key set identifier (IEI B-, TV 1): the KSI value.
    pub non_current_native_nas_ksi: Option<u8>,
    /// Old P-TMSI signature (IEI 19, TV 4)
    pub old_p_tmsi_signature: Option<[u8; 3]>,
    /// Additional GUTI (IEI 50, TLV)
    pub additional_guti: Option<EpsMobileIdentity>,
    /// Nonce_UE (IEI 55, TV 5)
    pub nonce_ue: Option<[u8; 4]>,
    /// UE network capability (IEI 58, TLV)
    pub ue_network_capability: Option<UeNetworkCapability>,
    /// Last visited registered TAI (IEI 52, TV 6)
    pub last_visited_tai: Option<EpsTai>,
    /// DRX parameter (IEI 5C, TV 3)
    pub drx_parameter: Option<[u8; 2]>,
    /// UE radio capability information update needed (IEI A-, TV 1): the value.
    pub ue_radio_capability_update_needed: Option<u8>,
    /// EPS bearer context status (IEI 57, TLV 4), bit n for EBI n: octet 3 is
    /// EBI(7)..EBI(0) (§9.9.2.1).
    pub eps_bearer_context_status: Option<u16>,
    /// MS network capability (IEI 31, TLV): the value.
    pub ms_network_capability: Option<Vec<u8>>,
    /// TMSI status (IEI 9-, TV 1): the value.
    pub tmsi_status: Option<u8>,
    /// Additional update type (IEI F-, TV 1): the value.
    pub additional_update_type: Option<u8>,
    /// Voice domain preference and UE's usage setting (IEI 5D, TLV): the value.
    pub voice_domain_preference: Option<Vec<u8>>,
    /// Old GUTI type (IEI E-, TV 1): the value (bit 1: 1 = mapped GUTI).
    pub old_guti_type: Option<u8>,
    /// Device properties (IEI D-, TV 1): the value.
    pub device_properties: Option<u8>,
    /// T3324 value (IEI 6A, TLV): the value.
    pub t3324_value: Option<Vec<u8>>,
    /// T3412 extended value (IEI 5E, TLV): the value.
    pub t3412_extended_value: Option<Vec<u8>>,
    /// Extended DRX parameters (IEI 6E, TLV): the value.
    pub extended_drx_parameters: Option<Vec<u8>>,
    /// UE additional security capability (IEI 6F, TLV): the value.
    pub ue_additional_security_capability: Option<Vec<u8>>,
    /// UE status (IEI 6D, TLV): the value.
    pub ue_status: Option<Vec<u8>>,
}

/// Tracking Area Update Accept message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrackingAreaUpdateAccept {
    /// EPS update result
    pub eps_update_result: u8,
    /// Presence mask
    pub presencemask: u64,
    /// T3412 value
    pub t3412_value: Option<GprsTimer>,
    /// GUTI
    pub guti: Option<EpsMobileIdentity>,
    /// TAI list
    pub tai_list: Option<EpsTaiList>,
}

/// Tracking Area Update Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrackingAreaUpdateReject {
    /// EMM cause
    pub emm_cause: u8,
}

/// EPS Authentication Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsAuthenticationRequest {
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// Authentication parameter RAND
    pub rand: AuthenticationRand,
    /// Authentication parameter AUTN
    pub autn: AuthenticationAutn,
}

/// EPS Authentication Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsAuthenticationResponse {
    /// Authentication response parameter
    pub authentication_response_parameter: AuthenticationResponseParameter,
}

/// EPS Authentication Failure message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsAuthenticationFailure {
    /// EMM cause
    pub emm_cause: u8,
    /// Authentication failure parameter
    pub authentication_failure_parameter: Option<Vec<u8>>,
}

/// EPS Security Mode Command message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsSecurityModeCommand {
    /// Selected NAS security algorithms
    pub selected_nas_security_algorithms: SecurityAlgorithms,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// Replayed UE security capabilities
    pub replayed_ue_security_capabilities: UeNetworkCapability,
    /// IMEISV request
    pub imeisv_request: Option<u8>,
    /// Replayed nonceUE
    pub replayed_nonce_ue: Option<[u8; 4]>,
    /// NonceMME
    pub nonce_mme: Option<[u8; 4]>,
}

/// EPS Security Mode Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsSecurityModeComplete {
    /// IMEISV
    pub imeisv: Option<Vec<u8>>,
}

/// EPS Security Mode Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsSecurityModeReject {
    /// EMM cause
    pub emm_cause: u8,
}

/// EPS Identity Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsIdentityRequest {
    /// Identity type
    pub identity_type: u8,
}

/// EPS Identity Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsIdentityResponse {
    /// Mobile identity
    pub mobile_identity: EpsMobileIdentity,
}

/// EMM Status message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmmStatus {
    /// EMM cause
    pub emm_cause: u8,
}

impl AttachComplete {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.esm_message_container.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let esm_message_container = EsmMessageContainer::decode(buf)?;
        Ok(Self {
            esm_message_container,
        })
    }
}

impl AttachReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
        if let Some(ref esm) = self.esm_message_container {
            buf.put_u8(0x78); // IEI
            esm.encode(buf);
        }
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F); // IEI
            t3346.encode(buf);
        }
        if let Some(ref t3402) = self.t3402_value {
            buf.put_u8(0x16); // IEI
            t3402.encode(buf);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let emm_cause = buf.read_u8()?;
        let mut msg = Self {
            emm_cause,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x78 => {
                    buf.skip(1)?;
                    set_first(
                        &mut msg.esm_message_container,
                        optional_tlv_e(buf, EsmMessageContainer::decode)?,
                    );
                }
                0x5F => {
                    buf.skip(1)?;
                    set_first(&mut msg.t3346_value, optional_tlv(buf, GprsTimer2::decode)?);
                }
                0x16 => {
                    buf.skip(1)?;
                    set_first(&mut msg.t3402_value, optional_tlv(buf, GprsTimer2::decode)?);
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

impl DetachRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.nas_key_set_identifier.encode() << 4) | (self.detach_type & 0x07));
        self.eps_mobile_identity.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let first_byte = buf.read_u8()?;
        let detach_type = first_byte & 0x0F;
        let nas_key_set_identifier = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let eps_mobile_identity = EpsMobileIdentity::decode(buf)?;
        // #931: TS 24.301 Table 8.2.11.1.1 (UE originating detach) defines no
        // optional IE in this release; whatever follows is skipped per §7.6.1,
        // not left unread.
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            skip_unknown_ie(buf, iei)?;
        }
        Ok(Self {
            detach_type,
            nas_key_set_identifier,
            eps_mobile_identity,
        })
    }
}

/// Put a TLV IE `iei` with `value`, if present.
fn put_tlv(buf: &mut BytesMut, iei: u8, value: &Option<Vec<u8>>) {
    if let Some(v) = value {
        buf.put_u8(iei);
        buf.put_u8(v.len() as u8);
        buf.put_slice(v);
    }
}

/// Put a type 1 IE `iei` (high nibble) with the 4-bit `value`, if present.
fn put_type1(buf: &mut BytesMut, iei: u8, value: Option<u8>) {
    if let Some(v) = value {
        buf.put_u8(iei | (v & 0x0F));
    }
}

impl TrackingAreaUpdateRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.nas_key_set_identifier.encode() << 4) | (self.eps_update_type & 0x0F));
        self.old_guti.encode(buf);
        // Optional IEs, in Table 8.2.29.1 order.
        put_type1(buf, 0xB0, self.non_current_native_nas_ksi);
        if let Some(sig) = &self.old_p_tmsi_signature {
            buf.put_u8(0x19);
            buf.put_slice(sig);
        }
        if let Some(guti) = &self.additional_guti {
            buf.put_u8(0x50);
            guti.encode(buf);
        }
        if let Some(nonce) = &self.nonce_ue {
            buf.put_u8(0x55);
            buf.put_slice(nonce);
        }
        if let Some(cap) = &self.ue_network_capability {
            buf.put_u8(0x58);
            cap.encode(buf);
        }
        if let Some(tai) = &self.last_visited_tai {
            buf.put_u8(0x52);
            tai.encode(buf);
        }
        if let Some(drx) = &self.drx_parameter {
            buf.put_u8(0x5C);
            buf.put_slice(drx);
        }
        put_type1(buf, 0xA0, self.ue_radio_capability_update_needed);
        if let Some(status) = self.eps_bearer_context_status {
            buf.put_u8(0x57);
            buf.put_u8(2);
            buf.put_u8((status & 0xFF) as u8);
            buf.put_u8((status >> 8) as u8);
        }
        put_tlv(buf, 0x31, &self.ms_network_capability);
        put_type1(buf, 0x90, self.tmsi_status);
        put_type1(buf, 0xF0, self.additional_update_type);
        put_tlv(buf, 0x5D, &self.voice_domain_preference);
        put_type1(buf, 0xE0, self.old_guti_type);
        put_type1(buf, 0xD0, self.device_properties);
        put_tlv(buf, 0x6A, &self.t3324_value);
        put_tlv(buf, 0x5E, &self.t3412_extended_value);
        put_tlv(buf, 0x6E, &self.extended_drx_parameters);
        put_tlv(buf, 0x6F, &self.ue_additional_security_capability);
        put_tlv(buf, 0x6D, &self.ue_status);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let first_byte = buf.read_u8()?;
        let eps_update_type = first_byte & 0x0F;
        let nas_key_set_identifier = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let old_guti = EpsMobileIdentity::decode(buf)?;
        let mut msg = Self {
            eps_update_type,
            nas_key_set_identifier,
            old_guti,
            ..Default::default()
        };
        // Optional IEs (TS 24.301 Table 8.2.29.1, #931). Type 1 IEs carry their
        // value in the IEI octet; the type 3 (TV) ones have fixed lengths and
        // must be skipped by them, not read as TLV (#784).
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0xB0..=0xBF => msg.non_current_native_nas_ksi = Some(buf.read_u8()? & 0x0F),
                0xA0..=0xAF => msg.ue_radio_capability_update_needed = Some(buf.read_u8()? & 0x0F),
                0x90..=0x9F => msg.tmsi_status = Some(buf.read_u8()? & 0x0F),
                0xF0..=0xFF => msg.additional_update_type = Some(buf.read_u8()? & 0x0F),
                0xE0..=0xEF => msg.old_guti_type = Some(buf.read_u8()? & 0x0F),
                0xD0..=0xDF => msg.device_properties = Some(buf.read_u8()? & 0x0F),
                0x19 => {
                    buf.skip(1)?;
                    let mut sig = [0u8; 3];
                    buf.read_into(&mut sig)?;
                    msg.old_p_tmsi_signature = Some(sig);
                }
                0x50 => {
                    buf.skip(1)?;
                    set_first(
                        &mut msg.additional_guti,
                        optional_tlv(buf, EpsMobileIdentity::decode)?,
                    );
                }
                0x55 => {
                    buf.skip(1)?;
                    let mut nonce = [0u8; 4];
                    buf.read_into(&mut nonce)?;
                    msg.nonce_ue = Some(nonce);
                }
                0x58 => {
                    buf.skip(1)?;
                    set_first(
                        &mut msg.ue_network_capability,
                        optional_tlv(buf, UeNetworkCapability::decode)?,
                    );
                }
                0x52 => {
                    buf.skip(1)?;
                    msg.last_visited_tai = Some(EpsTai::decode(buf)?);
                }
                0x5C => {
                    buf.skip(1)?;
                    let mut drx = [0u8; 2];
                    buf.read_into(&mut drx)?;
                    msg.drx_parameter = Some(drx);
                }
                0x57 => {
                    buf.skip(1)?;
                    let v = opaque_tlv(buf)?;
                    // §9.9.2.1: two contents octets; a shorter one is not legal
                    // and is ignored rather than guessed at.
                    if v.len() >= 2 {
                        msg.eps_bearer_context_status =
                            Some(u16::from(v[0]) | (u16::from(v[1]) << 8));
                    }
                }
                0x31 => {
                    buf.skip(1)?;
                    msg.ms_network_capability = Some(opaque_tlv(buf)?);
                }
                0x5D => {
                    buf.skip(1)?;
                    msg.voice_domain_preference = Some(opaque_tlv(buf)?);
                }
                0x6A => {
                    buf.skip(1)?;
                    msg.t3324_value = Some(opaque_tlv(buf)?);
                }
                0x5E => {
                    buf.skip(1)?;
                    msg.t3412_extended_value = Some(opaque_tlv(buf)?);
                }
                0x6E => {
                    buf.skip(1)?;
                    msg.extended_drx_parameters = Some(opaque_tlv(buf)?);
                }
                0x6F => {
                    buf.skip(1)?;
                    msg.ue_additional_security_capability = Some(opaque_tlv(buf)?);
                }
                0x6D => {
                    buf.skip(1)?;
                    msg.ue_status = Some(opaque_tlv(buf)?);
                }
                // Old location area identification (TV 6) and Additional
                // information requested (TV 2): not modelled, skipped by their
                // fixed lengths.
                0x13 => buf.skip(6)?,
                0x17 => buf.skip(2)?,
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

impl TrackingAreaUpdateAccept {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.eps_update_result & 0x07);
        // Optional IEs
        if let Some(t3412) = self.t3412_value {
            buf.put_u8(0x5A); // IEI
            buf.put_u8(t3412.encode());
        }
        if let Some(ref guti) = self.guti {
            buf.put_u8(0x50); // IEI
            guti.encode(buf);
        }
        if let Some(ref tai_list) = self.tai_list {
            buf.put_u8(0x54); // IEI
            tai_list.encode(buf);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let eps_update_result = buf.read_u8()? & 0x07;
        let mut msg = Self {
            eps_update_result,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x5A => {
                    buf.skip(1)?;
                    if buf.remaining() >= 1 {
                        msg.t3412_value = Some(GprsTimer::decode(buf.read_u8()?));
                    }
                }
                0x50 => {
                    buf.skip(1)?;
                    set_first(&mut msg.guti, optional_tlv(buf, EpsMobileIdentity::decode)?);
                }
                0x54 => {
                    buf.skip(1)?;
                    set_first(&mut msg.tai_list, optional_tlv(buf, EpsTaiList::decode)?);
                }
                // Location area (TV 6): not modelled; type 3, so skipped by its
                // fixed length (TS 24.301 clause 8, #810).
                0x13 => buf.skip(6)?,
                // EMM cause (TV 2): not modelled; type 3, so skipped by its
                // fixed length (TS 24.301 clause 8, #810).
                0x53 => buf.skip(2)?,
                // T3402 value (TV 2): not modelled; type 3, so skipped by its
                // fixed length (TS 24.301 clause 8, #810).
                0x17 => buf.skip(2)?,
                // T3423 value (TV 2): not modelled; type 3, so skipped by its
                // fixed length (TS 24.301 clause 8, #810).
                0x59 => buf.skip(2)?,
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

impl TrackingAreaUpdateReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            emm_cause: buf.read_u8()?,
        })
    }
}

impl EpsAuthenticationRequest {
    /// Encode to bytes
    ///
    /// Per TS 24.301 Table 8.2.7.1, RAND is a mandatory V-format IE (16 octets,
    /// no IEI) and AUTN is a mandatory LV-format IE (length octet + 16 octets,
    /// no IEI). The IEIs 0x21 (RAND) / 0x20 (AUTN) exist only for the optional
    /// IEs of the 5GMM Authentication Request (TS 24.501 Table 8.2.1.1.1).
    pub fn encode(&self, buf: &mut BytesMut) {
        // NAS key set identifier (bits 1-4) + spare half octet (bits 5-8)
        buf.put_u8(self.nas_key_set_identifier.encode());
        // Authentication parameter RAND (V, 16 octets)
        buf.put_slice(&self.rand);
        // Authentication parameter AUTN (LV, length + 16 octets)
        buf.put_u8(16);
        buf.put_slice(&self.autn);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 34 {
            return Err(NasError::BufferTooShort {
                expected: 34,
                actual: buf.remaining(),
            });
        }
        let nas_key_set_identifier = KeySetIdentifier::decode(buf.read_u8()? & 0x0F);
        let mut rand = [0u8; 16];
        buf.read_into(&mut rand)?;
        // AUTN is LV with a fixed 16-octet value (TS 24.301 Section 9.9.3.2)
        let autn_len = buf.read_u8()? as usize;
        if autn_len != 16 {
            return Err(NasError::InvalidIeLength {
                expected: 16,
                actual: autn_len,
            });
        }
        let mut autn = [0u8; 16];
        buf.read_into(&mut autn)?;
        Ok(Self {
            nas_key_set_identifier,
            rand,
            autn,
        })
    }
}

impl EpsAuthenticationResponse {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.authentication_response_parameter.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let authentication_response_parameter = AuthenticationResponseParameter::decode(buf)?;
        Ok(Self {
            authentication_response_parameter,
        })
    }
}

impl EpsAuthenticationFailure {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
        if let Some(ref param) = self.authentication_failure_parameter {
            buf.put_u8(0x30); // IEI
            buf.put_u8(param.len() as u8);
            buf.put_slice(param);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let emm_cause = buf.read_u8()?;
        let mut msg = Self {
            emm_cause,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x30 => {
                    // §9.9.3.1 -> TS 24.008 §10.5.3.2.2: "a length of 16
                    // octets", i.e. the 14-octet AUTS (#613).
                    buf.skip(1)?;
                    set_first(
                        &mut msg.authentication_failure_parameter,
                        optional_tlv(buf, |b| Ok(b.read_lv(IeLen::Exact(14))?.to_vec()))?,
                    );
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

impl EpsSecurityModeCommand {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.selected_nas_security_algorithms.encode());
        buf.put_u8(self.nas_key_set_identifier.encode());
        self.replayed_ue_security_capabilities.encode(buf);
        // Optional IEs
        if let Some(imeisv_req) = self.imeisv_request {
            buf.put_u8(0xC0 | (imeisv_req & 0x0F)); // Type 1 IE
        }
        if let Some(ref nonce) = self.replayed_nonce_ue {
            // TV, 5 (TS 24.301 §8.2.20, §9.9.3.25: no length octet; #629).
            buf.put_u8(0x55); // IEI
            buf.put_slice(nonce);
        }
        if let Some(ref nonce) = self.nonce_mme {
            buf.put_u8(0x56); // IEI (TV, 5)
            buf.put_slice(nonce);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort {
                expected: 3,
                actual: buf.remaining(),
            });
        }
        let selected_nas_security_algorithms = SecurityAlgorithms::decode(buf.read_u8()?);
        let nas_key_set_identifier = KeySetIdentifier::decode(buf.read_u8()? & 0x0F);
        let replayed_ue_security_capabilities = UeNetworkCapability::decode(buf)?;

        let mut msg = Self {
            selected_nas_security_algorithms,
            nas_key_set_identifier,
            replayed_ue_security_capabilities,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0xC0..=0xCF => {
                    msg.imeisv_request = Some(buf.read_u8()? & 0x0F);
                }
                // Replayed nonceUE / NonceMME: TV, 5 (TS 24.301 §8.2.20,
                // §9.9.3.25), the IEI then the 4-octet nonce.
                0x55 => {
                    buf.skip(1)?;
                    let mut nonce = [0u8; 4];
                    buf.read_into(&mut nonce)?;
                    msg.replayed_nonce_ue = Some(nonce);
                }
                0x56 => {
                    buf.skip(1)?;
                    let mut nonce = [0u8; 4];
                    buf.read_into(&mut nonce)?;
                    msg.nonce_mme = Some(nonce);
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

impl EpsSecurityModeComplete {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref imeisv) = self.imeisv {
            buf.put_u8(0x23); // IEI
            buf.put_u8(imeisv.len() as u8);
            buf.put_slice(imeisv);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();

        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x23 => {
                    buf.skip(1)?;
                    set_first(&mut msg.imeisv, Some(opaque_tlv(buf)?));
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

impl EpsSecurityModeReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            emm_cause: buf.read_u8()?,
        })
    }
}

impl EpsIdentityRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.identity_type & 0x07);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            identity_type: buf.read_u8()? & 0x07,
        })
    }
}

impl EpsIdentityResponse {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.mobile_identity.encode(buf);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mobile_identity = EpsMobileIdentity::decode(buf)?;
        Ok(Self { mobile_identity })
    }
}

impl EmmStatus {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            emm_cause: buf.read_u8()?,
        })
    }
}

/// EPS Service Request message (TS 24.301 Section 8.2.15)
/// Note: This is sent with security header type 0x0C (service request)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsServiceRequest {
    /// KSI and sequence number
    pub ksi_and_sequence_number: u8,
    /// Short MAC
    pub short_mac: u16,
}

impl EpsServiceRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ksi_and_sequence_number);
        buf.put_u16(self.short_mac);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort {
                expected: 3,
                actual: buf.remaining(),
            });
        }
        let ksi_and_sequence_number = buf.read_u8()?;
        let short_mac = buf.read_u16()?;
        Ok(Self {
            ksi_and_sequence_number,
            short_mac,
        })
    }
}

/// Extended Service Request message (TS 24.301 Section 8.2.15A)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExtendedServiceRequest {
    /// Service type
    pub service_type: u8,
    /// NAS key set identifier
    pub nas_key_set_identifier: KeySetIdentifier,
    /// M-TMSI
    pub m_tmsi: EpsMobileIdentity,
    /// CSFB response
    pub csfb_response: Option<u8>,
    /// EPS bearer context status: bit n is EBI n (TS 24.301 §9.9.2.1; octet 3
    /// carries EBI(7)..EBI(0), octet 4 EBI(15)..EBI(8)), the convention mmed's
    /// `emm_build::eps_bearer_context_status` uses.
    pub eps_bearer_context_status: Option<u16>,
}

impl ExtendedServiceRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.nas_key_set_identifier.encode() << 4) | (self.service_type & 0x0F));
        self.m_tmsi.encode(buf);
        if let Some(csfb) = self.csfb_response {
            buf.put_u8(0xB0 | (csfb & 0x0F)); // IEI B- (half-byte)
        }
        if let Some(status) = self.eps_bearer_context_status {
            buf.put_u8(0x57); // IEI
            buf.put_u8(2); // Length
                           // §9.9.2.1: octet 3 first, EBI(7)..EBI(0): the low byte (#961).
            buf.put_u8((status & 0xff) as u8);
            buf.put_u8((status >> 8) as u8);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let first_byte = buf.read_u8()?;
        let service_type = first_byte & 0x0F;
        let nas_key_set_identifier = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        // M-TMSI is a TS 24.008 Mobile identity (TS 24.301 §8.2.15), type 4.
        let m_tmsi = EpsMobileIdentity::decode_mobile_identity(buf)?;
        let mut msg = Self {
            service_type,
            nas_key_set_identifier,
            m_tmsi,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0xB0 => {
                    buf.skip(1)?;
                    msg.csfb_response = Some(iei & 0x0F);
                }
                0x57 => {
                    // §9.9.2.1: "4 octets length", two value octets (#613).
                    buf.skip(1)?;
                    set_first(
                        &mut msg.eps_bearer_context_status,
                        optional_tlv(buf, |b| {
                            let mut v = b.read_lv(IeLen::Exact(2))?;
                            let octet3 = v.read_u8()?;
                            let octet4 = v.read_u8()?;
                            Ok(u16::from_le_bytes([octet3, octet4]))
                        })?,
                    );
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// EPS Service Reject message (TS 24.301 Section 8.2.24)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsServiceReject {
    /// EMM cause
    pub emm_cause: u8,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
    /// T3448 value
    pub t3448_value: Option<GprsTimer2>,
}

impl EpsServiceReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.emm_cause);
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F); // IEI
            t3346.encode(buf);
        }
        if let Some(ref t3448) = self.t3448_value {
            buf.put_u8(0x6B); // IEI
            t3448.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let emm_cause = buf.read_u8()?;
        let mut msg = Self {
            emm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x5F => {
                    buf.skip(1)?;
                    set_first(&mut msg.t3346_value, optional_tlv(buf, GprsTimer2::decode)?);
                }
                0x6B => {
                    buf.skip(1)?;
                    set_first(&mut msg.t3448_value, optional_tlv(buf, GprsTimer2::decode)?);
                }
                // T3442 value (TV 2): not modelled; type 3, so skipped by its
                // fixed length (TS 24.301 clause 8, #810).
                0x5B => buf.skip(2)?,
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// GUTI Reallocation Command message (TS 24.301 Section 8.2.16)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GutiReallocationCommand {
    /// GUTI
    pub guti: EpsMobileIdentity,
    /// TAI list
    pub tai_list: Option<EpsTaiList>,
}

impl GutiReallocationCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.guti.encode(buf);
        if let Some(ref tai_list) = self.tai_list {
            buf.put_u8(0x54); // IEI
            tai_list.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let guti = EpsMobileIdentity::decode(buf)?;
        let mut msg = Self {
            guti,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x54 => {
                    buf.skip(1)?;
                    set_first(&mut msg.tai_list, optional_tlv(buf, EpsTaiList::decode)?);
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// EMM Information message (TS 24.301 Section 8.2.13)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmmInformation {
    /// Full name for network
    pub full_name_for_network: Option<Vec<u8>>,
    /// Short name for network
    pub short_name_for_network: Option<Vec<u8>>,
    /// Local time zone
    pub local_time_zone: Option<u8>,
    /// Universal time and local time zone
    pub universal_time_and_local_time_zone: Option<[u8; 7]>,
    /// Network daylight saving time
    pub network_daylight_saving_time: Option<u8>,
}

impl EmmInformation {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref full_name) = self.full_name_for_network {
            buf.put_u8(0x43); // IEI
            buf.put_u8(full_name.len() as u8);
            buf.put_slice(full_name);
        }
        if let Some(ref short_name) = self.short_name_for_network {
            buf.put_u8(0x45); // IEI
            buf.put_u8(short_name.len() as u8);
            buf.put_slice(short_name);
        }
        if let Some(tz) = self.local_time_zone {
            buf.put_u8(0x46); // IEI
            buf.put_u8(tz);
        }
        if let Some(ref utltz) = self.universal_time_and_local_time_zone {
            buf.put_u8(0x47); // IEI
            buf.put_slice(utltz);
        }
        if let Some(dst) = self.network_daylight_saving_time {
            buf.put_u8(0x49); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(dst);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x43 => {
                    buf.skip(1)?;
                    set_first(&mut msg.full_name_for_network, Some(opaque_tlv(buf)?));
                }
                0x45 => {
                    buf.skip(1)?;
                    set_first(&mut msg.short_name_for_network, Some(opaque_tlv(buf)?));
                }
                0x46 => {
                    buf.skip(1)?;
                    if buf.remaining() >= 1 {
                        msg.local_time_zone = Some(buf.read_u8()?);
                    }
                }
                0x47 => {
                    buf.skip(1)?;
                    if buf.remaining() >= 7 {
                        let mut utltz = [0u8; 7];
                        buf.read_into(&mut utltz)?;
                        msg.universal_time_and_local_time_zone = Some(utltz);
                    }
                }
                0x49 => {
                    // §9.9.3.6 -> TS 24.008 §10.5.3.12: "a length of 3
                    // octets", one value octet (#613).
                    buf.skip(1)?;
                    set_first(
                        &mut msg.network_daylight_saving_time,
                        optional_tlv(buf, |b| b.read_lv(IeLen::Exact(1))?.read_u8())?,
                    );
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// EPS Downlink NAS Transport message (TS 24.301 Section 8.2.12)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsDownlinkNasTransport {
    /// NAS message container
    pub nas_message_container: Vec<u8>,
}

impl EpsDownlinkNasTransport {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.nas_message_container.len() as u8);
        buf.put_slice(&self.nas_message_container);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let len = buf.read_u8()? as usize;
        if buf.remaining() < len {
            return Err(NasError::BufferTooShort {
                expected: len,
                actual: buf.remaining(),
            });
        }
        let nas_message_container = buf.read_bytes(len)?.to_vec();
        Ok(Self {
            nas_message_container,
        })
    }
}

/// EPS Uplink NAS Transport message (TS 24.301 Section 8.2.30)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpsUplinkNasTransport {
    /// NAS message container
    pub nas_message_container: Vec<u8>,
}

impl EpsUplinkNasTransport {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.nas_message_container.len() as u8);
        buf.put_slice(&self.nas_message_container);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let len = buf.read_u8()? as usize;
        if buf.remaining() < len {
            return Err(NasError::BufferTooShort {
                expected: len,
                actual: buf.remaining(),
            });
        }
        let nas_message_container = buf.read_bytes(len)?.to_vec();
        Ok(Self {
            nas_message_container,
        })
    }
}

/// CS Service Notification message (TS 24.301 Section 8.2.9)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CsServiceNotification {
    /// Paging identity
    pub paging_identity: u8,
    // Optional IEs (TS 24.301 Table 8.2.9.1, #931)
    /// CLI (IEI 60, TLV): the calling party BCD number contents.
    pub cli: Option<Vec<u8>>,
    /// SS Code (IEI 61, TV 2)
    pub ss_code: Option<u8>,
    /// LCS indicator (IEI 62, TV 2)
    pub lcs_indicator: Option<u8>,
    /// LCS client identity (IEI 63, TLV): the value.
    pub lcs_client_identity: Option<Vec<u8>>,
}

impl CsServiceNotification {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.paging_identity);
        put_tlv(buf, 0x60, &self.cli);
        if let Some(code) = self.ss_code {
            buf.put_u8(0x61);
            buf.put_u8(code);
        }
        if let Some(lcs) = self.lcs_indicator {
            buf.put_u8(0x62);
            buf.put_u8(lcs);
        }
        put_tlv(buf, 0x63, &self.lcs_client_identity);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let mut msg = Self {
            paging_identity: buf.read_u8()?,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x60 => {
                    buf.skip(1)?;
                    msg.cli = Some(opaque_tlv(buf)?);
                }
                // SS Code and LCS indicator are type 3 (TV 2), not TLV.
                0x61 => {
                    buf.skip(1)?;
                    msg.ss_code = Some(buf.read_u8()?);
                }
                0x62 => {
                    buf.skip(1)?;
                    msg.lcs_indicator = Some(buf.read_u8()?);
                }
                0x63 => {
                    buf.skip(1)?;
                    msg.lcs_client_identity = Some(opaque_tlv(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// ESM message
#[derive(Debug, Clone, PartialEq)]
pub enum EsmMessage {
    ActivateDefaultEpsBearerContextRequest(ActivateDefaultEpsBearerContextRequest),
    ActivateDefaultEpsBearerContextAccept,
    ActivateDefaultEpsBearerContextReject(ActivateDefaultEpsBearerContextReject),
    PdnConnectivityRequest(PdnConnectivityRequest),
    PdnConnectivityReject(PdnConnectivityReject),
    PdnDisconnectRequest(PdnDisconnectRequest),
    PdnDisconnectReject(PdnDisconnectReject),
    BearerResourceAllocationRequest(BearerResourceAllocationRequest),
    BearerResourceAllocationReject(BearerResourceAllocationReject),
    BearerResourceModificationRequest(BearerResourceModificationRequest),
    BearerResourceModificationReject(BearerResourceModificationReject),
    ActivateDedicatedEpsBearerContextRequest(ActivateDedicatedEpsBearerContextRequest),
    ActivateDedicatedEpsBearerContextAccept,
    ActivateDedicatedEpsBearerContextReject(ActivateDedicatedEpsBearerContextReject),
    ModifyEpsBearerContextRequest(ModifyEpsBearerContextRequest),
    ModifyEpsBearerContextAccept(ModifyEpsBearerContextAccept),
    ModifyEpsBearerContextReject(ModifyEpsBearerContextReject),
    DeactivateEpsBearerContextRequest(DeactivateEpsBearerContextRequest),
    DeactivateEpsBearerContextAccept,
    EsmInformationRequest,
    EsmInformationResponse(EsmInformationResponse),
    EsmStatus(EsmStatus),
}

/// PDN Connectivity Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnConnectivityRequest {
    /// Request type
    pub request_type: u8,
    /// PDN type
    pub pdn_type: u8,
    /// EPS bearer identity
    pub eps_bearer_identity: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// PDN Connectivity Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnConnectivityReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// PDN Disconnect Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnDisconnectRequest {
    /// Linked EPS bearer identity
    pub linked_eps_bearer_identity: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// PDN Disconnect Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PdnDisconnectReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Activate Default EPS Bearer Context Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActivateDefaultEpsBearerContextRequest {
    /// EPS QoS
    pub eps_qos: Vec<u8>,
    /// Access Point Name
    pub access_point_name: Vec<u8>,
    /// PDN address
    pub pdn_address: Vec<u8>,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Activate Default EPS Bearer Context Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActivateDefaultEpsBearerContextReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Bearer Resource Allocation Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceAllocationRequest {
    /// Linked EPS bearer identity
    pub linked_eps_bearer_identity: u8,
    /// Traffic flow aggregate
    pub traffic_flow_aggregate: Vec<u8>,
    /// Required traffic flow QoS
    pub required_traffic_flow_qos: Vec<u8>,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Bearer Resource Allocation Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceAllocationReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// Bearer Resource Modification Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceModificationRequest {
    /// EPS bearer identity for packet filter
    pub eps_bearer_identity: u8,
    /// Traffic flow aggregate
    pub traffic_flow_aggregate: Vec<u8>,
    /// Procedure transaction identity
    pub pti: u8,
    // Optional IEs (TS 24.301 Table 8.3.10.1, #931)
    /// Required traffic flow QoS (IEI 5B, TLV): the EPS QoS contents.
    pub required_traffic_flow_qos: Option<Vec<u8>>,
    /// ESM cause (IEI 58, TV 2)
    pub esm_cause: Option<u8>,
    /// Protocol configuration options (IEI 27, TLV): the value.
    pub protocol_configuration_options: Option<Vec<u8>>,
    /// Device properties (IEI C-, TV 1): the value.
    pub device_properties: Option<u8>,
    /// NBIFOM container (IEI 33, TLV): the value.
    pub nbifom_container: Option<Vec<u8>>,
    /// Header compression configuration (IEI 66, TLV): the value.
    pub header_compression_configuration: Option<Vec<u8>>,
    /// Extended protocol configuration options (IEI 7B, TLV-E): the value.
    pub extended_protocol_configuration_options: Option<Vec<u8>>,
    /// Extended EPS QoS (IEI 5C, TLV): the value.
    pub extended_eps_qos: Option<Vec<u8>>,
}

/// Bearer Resource Modification Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BearerResourceModificationReject {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

/// ESM Information Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EsmInformationResponse {
    /// Access Point Name
    pub access_point_name: Option<Vec<u8>>,
    /// Protocol configuration options
    pub protocol_configuration_options: Option<Vec<u8>>,
    /// Procedure transaction identity
    pub pti: u8,
}

/// ESM Status message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EsmStatus {
    /// ESM cause
    pub esm_cause: u8,
    /// Procedure transaction identity
    pub pti: u8,
}

impl PdnConnectivityRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.pdn_type << 4) | (self.request_type & 0x0F));
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let byte = buf.read_u8()?;
        Ok(Self {
            request_type: byte & 0x0F,
            pdn_type: (byte >> 4) & 0x0F,
            ..Default::default()
        })
    }
}

impl PdnConnectivityReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
            ..Default::default()
        })
    }
}

impl PdnDisconnectRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.linked_eps_bearer_identity & 0x0F);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            linked_eps_bearer_identity: buf.read_u8()? & 0x0F,
            ..Default::default()
        })
    }
}

impl PdnDisconnectReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
            ..Default::default()
        })
    }
}

impl ActivateDefaultEpsBearerContextRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.eps_qos.len() as u8);
        buf.put_slice(&self.eps_qos);
        buf.put_u8(self.access_point_name.len() as u8);
        buf.put_slice(&self.access_point_name);
        buf.put_u8(self.pdn_address.len() as u8);
        buf.put_slice(&self.pdn_address);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let qos_len = buf.read_u8()? as usize;
        if buf.remaining() < qos_len {
            return Err(NasError::BufferTooShort {
                expected: qos_len,
                actual: buf.remaining(),
            });
        }
        let eps_qos = buf.read_bytes(qos_len)?.to_vec();
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let apn_len = buf.read_u8()? as usize;
        if buf.remaining() < apn_len {
            return Err(NasError::BufferTooShort {
                expected: apn_len,
                actual: buf.remaining(),
            });
        }
        let access_point_name = buf.read_bytes(apn_len)?.to_vec();
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let addr_len = buf.read_u8()? as usize;
        if buf.remaining() < addr_len {
            return Err(NasError::BufferTooShort {
                expected: addr_len,
                actual: buf.remaining(),
            });
        }
        let pdn_address = buf.read_bytes(addr_len)?.to_vec();
        Ok(Self {
            eps_qos,
            access_point_name,
            pdn_address,
            ..Default::default()
        })
    }
}

impl ActivateDefaultEpsBearerContextReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
            ..Default::default()
        })
    }
}

impl BearerResourceAllocationRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.linked_eps_bearer_identity & 0x0F);
        buf.put_u8(self.traffic_flow_aggregate.len() as u8);
        buf.put_slice(&self.traffic_flow_aggregate);
        buf.put_u8(self.required_traffic_flow_qos.len() as u8);
        buf.put_slice(&self.required_traffic_flow_qos);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let linked = buf.read_u8()? & 0x0F;
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let tfa_len = buf.read_u8()? as usize;
        if buf.remaining() < tfa_len {
            return Err(NasError::BufferTooShort {
                expected: tfa_len,
                actual: buf.remaining(),
            });
        }
        let tfa = buf.read_bytes(tfa_len)?.to_vec();
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let qos_len = buf.read_u8()? as usize;
        if buf.remaining() < qos_len {
            return Err(NasError::BufferTooShort {
                expected: qos_len,
                actual: buf.remaining(),
            });
        }
        let qos = buf.read_bytes(qos_len)?.to_vec();
        Ok(Self {
            linked_eps_bearer_identity: linked,
            traffic_flow_aggregate: tfa,
            required_traffic_flow_qos: qos,
            ..Default::default()
        })
    }
}

impl BearerResourceAllocationReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
            ..Default::default()
        })
    }
}

impl BearerResourceModificationRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.eps_bearer_identity & 0x0F);
        buf.put_u8(self.traffic_flow_aggregate.len() as u8);
        buf.put_slice(&self.traffic_flow_aggregate);
        put_tlv(buf, 0x5B, &self.required_traffic_flow_qos);
        if let Some(cause) = self.esm_cause {
            buf.put_u8(0x58);
            buf.put_u8(cause);
        }
        put_tlv(buf, 0x27, &self.protocol_configuration_options);
        put_type1(buf, 0xC0, self.device_properties);
        put_tlv(buf, 0x33, &self.nbifom_container);
        put_tlv(buf, 0x66, &self.header_compression_configuration);
        if let Some(epco) = &self.extended_protocol_configuration_options {
            buf.put_u8(0x7B);
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
        put_tlv(buf, 0x5C, &self.extended_eps_qos);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let ebi = buf.read_u8()? & 0x0F;
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let tfa_len = buf.read_u8()? as usize;
        if buf.remaining() < tfa_len {
            return Err(NasError::BufferTooShort {
                expected: tfa_len,
                actual: buf.remaining(),
            });
        }
        let tfa = buf.read_bytes(tfa_len)?.to_vec();
        let mut msg = Self {
            eps_bearer_identity: ebi,
            traffic_flow_aggregate: tfa,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x5B => {
                    buf.skip(1)?;
                    msg.required_traffic_flow_qos = Some(opaque_tlv(buf)?);
                }
                // ESM cause is type 3 (TV 2), not TLV.
                0x58 => {
                    buf.skip(1)?;
                    msg.esm_cause = Some(buf.read_u8()?);
                }
                0x27 => {
                    buf.skip(1)?;
                    msg.protocol_configuration_options = Some(opaque_tlv(buf)?);
                }
                0xC0..=0xCF => msg.device_properties = Some(buf.read_u8()? & 0x0F),
                0x33 => {
                    buf.skip(1)?;
                    msg.nbifom_container = Some(opaque_tlv(buf)?);
                }
                0x66 => {
                    buf.skip(1)?;
                    msg.header_compression_configuration = Some(opaque_tlv(buf)?);
                }
                0x7B => {
                    buf.skip(1)?;
                    msg.extended_protocol_configuration_options =
                        Some(crate::buf::opaque_tlv_e(buf)?);
                }
                0x5C => {
                    buf.skip(1)?;
                    msg.extended_eps_qos = Some(opaque_tlv(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

impl BearerResourceModificationReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
            ..Default::default()
        })
    }
}

/// Activate Dedicated EPS Bearer Context Request message (TS 24.301 Section 8.3.3)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActivateDedicatedEpsBearerContextRequest {
    /// Linked EPS bearer identity
    pub linked_eps_bearer_identity: u8,
    /// EPS QoS
    pub eps_qos: Vec<u8>,
    /// TFT (Traffic Flow Template)
    pub tft: Vec<u8>,
}

impl ActivateDedicatedEpsBearerContextRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.linked_eps_bearer_identity & 0x0F);
        buf.put_u8(self.eps_qos.len() as u8);
        buf.put_slice(&self.eps_qos);
        buf.put_u8(self.tft.len() as u8);
        buf.put_slice(&self.tft);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let linked = buf.read_u8()? & 0x0F;
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let qos_len = buf.read_u8()? as usize;
        if buf.remaining() < qos_len {
            return Err(NasError::BufferTooShort {
                expected: qos_len,
                actual: buf.remaining(),
            });
        }
        let eps_qos = buf.read_bytes(qos_len)?.to_vec();
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let tft_len = buf.read_u8()? as usize;
        if buf.remaining() < tft_len {
            return Err(NasError::BufferTooShort {
                expected: tft_len,
                actual: buf.remaining(),
            });
        }
        let tft = buf.read_bytes(tft_len)?.to_vec();
        Ok(Self {
            linked_eps_bearer_identity: linked,
            eps_qos,
            tft,
        })
    }
}

/// Activate Dedicated EPS Bearer Context Reject message (TS 24.301 Section 8.3.4)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ActivateDedicatedEpsBearerContextReject {
    /// ESM cause
    pub esm_cause: u8,
}

impl ActivateDedicatedEpsBearerContextReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
        })
    }
}

/// Modify EPS Bearer Context Request message (TS 24.301 Section 8.3.17)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ModifyEpsBearerContextRequest {
    /// New EPS QoS
    pub new_eps_qos: Option<Vec<u8>>,
    /// TFT
    pub tft: Option<Vec<u8>>,
    /// New QoS
    pub new_qos: Option<Vec<u8>>,
}

impl ModifyEpsBearerContextRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref qos) = self.new_eps_qos {
            buf.put_u8(0x5B); // IEI
            buf.put_u8(qos.len() as u8);
            buf.put_slice(qos);
        }
        if let Some(ref tft) = self.tft {
            buf.put_u8(0x36); // IEI
            buf.put_u8(tft.len() as u8);
            buf.put_slice(tft);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x5B => {
                    buf.skip(1)?;
                    set_first(&mut msg.new_eps_qos, Some(opaque_tlv(buf)?));
                }
                0x36 => {
                    buf.skip(1)?;
                    set_first(&mut msg.tft, Some(opaque_tlv(buf)?));
                }
                // Negotiated LLC (TV 2): not modelled; type 3, so skipped by its
                // fixed length (TS 24.301 clause 8, #810).
                0x32 => buf.skip(2)?,
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Modify EPS Bearer Context Accept message (TS 24.301 Section 8.3.18)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ModifyEpsBearerContextAccept {
    /// Protocol configuration options
    pub protocol_configuration_options: Option<Vec<u8>>,
}

impl ModifyEpsBearerContextAccept {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref pco) = self.protocol_configuration_options {
            buf.put_u8(0x27); // IEI
            buf.put_u8(pco.len() as u8);
            buf.put_slice(pco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x27 => {
                    buf.skip(1)?;
                    set_first(
                        &mut msg.protocol_configuration_options,
                        Some(opaque_tlv(buf)?),
                    );
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Modify EPS Bearer Context Reject message (TS 24.301 Section 8.3.19)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ModifyEpsBearerContextReject {
    /// ESM cause
    pub esm_cause: u8,
}

impl ModifyEpsBearerContextReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
        })
    }
}

/// Deactivate EPS Bearer Context Request message (TS 24.301 Section 8.3.12)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeactivateEpsBearerContextRequest {
    /// ESM cause
    pub esm_cause: u8,
}

impl DeactivateEpsBearerContextRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
        })
    }
}

impl EsmInformationResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref apn) = self.access_point_name {
            buf.put_u8(0x28); // IEI
            buf.put_u8(apn.len() as u8);
            buf.put_slice(apn);
        }
        if let Some(ref pco) = self.protocol_configuration_options {
            buf.put_u8(0x27); // IEI
            buf.put_u8(pco.len() as u8);
            buf.put_slice(pco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.peek_u8()?;
            match iei {
                0x28 => {
                    buf.skip(1)?;
                    set_first(&mut msg.access_point_name, Some(opaque_tlv(buf)?));
                }
                0x27 => {
                    buf.skip(1)?;
                    set_first(
                        &mut msg.protocol_configuration_options,
                        Some(opaque_tlv(buf)?),
                    );
                }
                // An unknown IE is ignored, not the end of the message (§7.6.1, #810).
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

impl EsmStatus {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.esm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            esm_cause: buf.read_u8()?,
            ..Default::default()
        })
    }
}

/// Build an ESM message with header
pub fn build_esm_message(eps_bearer_identity: u8, pti: u8, msg: &EsmMessage) -> BytesMut {
    let mut buf = BytesMut::new();

    let message_type = match msg {
        EsmMessage::ActivateDefaultEpsBearerContextRequest(_) => {
            EsmMessageType::ActivateDefaultEpsBearerContextRequest
        }
        EsmMessage::ActivateDefaultEpsBearerContextAccept => {
            EsmMessageType::ActivateDefaultEpsBearerContextAccept
        }
        EsmMessage::ActivateDefaultEpsBearerContextReject(_) => {
            EsmMessageType::ActivateDefaultEpsBearerContextReject
        }
        EsmMessage::ActivateDedicatedEpsBearerContextRequest(_) => {
            EsmMessageType::ActivateDedicatedEpsBearerContextRequest
        }
        EsmMessage::ActivateDedicatedEpsBearerContextAccept => {
            EsmMessageType::ActivateDedicatedEpsBearerContextAccept
        }
        EsmMessage::ActivateDedicatedEpsBearerContextReject(_) => {
            EsmMessageType::ActivateDedicatedEpsBearerContextReject
        }
        EsmMessage::ModifyEpsBearerContextRequest(_) => {
            EsmMessageType::ModifyEpsBearerContextRequest
        }
        EsmMessage::ModifyEpsBearerContextAccept(_) => EsmMessageType::ModifyEpsBearerContextAccept,
        EsmMessage::ModifyEpsBearerContextReject(_) => EsmMessageType::ModifyEpsBearerContextReject,
        EsmMessage::DeactivateEpsBearerContextRequest(_) => {
            EsmMessageType::DeactivateEpsBearerContextRequest
        }
        EsmMessage::DeactivateEpsBearerContextAccept => {
            EsmMessageType::DeactivateEpsBearerContextAccept
        }
        EsmMessage::PdnConnectivityRequest(_) => EsmMessageType::PdnConnectivityRequest,
        EsmMessage::PdnConnectivityReject(_) => EsmMessageType::PdnConnectivityReject,
        EsmMessage::PdnDisconnectRequest(_) => EsmMessageType::PdnDisconnectRequest,
        EsmMessage::PdnDisconnectReject(_) => EsmMessageType::PdnDisconnectReject,
        EsmMessage::BearerResourceAllocationRequest(_) => {
            EsmMessageType::BearerResourceAllocationRequest
        }
        EsmMessage::BearerResourceAllocationReject(_) => {
            EsmMessageType::BearerResourceAllocationReject
        }
        EsmMessage::BearerResourceModificationRequest(_) => {
            EsmMessageType::BearerResourceModificationRequest
        }
        EsmMessage::BearerResourceModificationReject(_) => {
            EsmMessageType::BearerResourceModificationReject
        }
        EsmMessage::EsmInformationRequest => EsmMessageType::EsmInformationRequest,
        EsmMessage::EsmInformationResponse(_) => EsmMessageType::EsmInformationResponse,
        EsmMessage::EsmStatus(_) => EsmMessageType::EsmStatus,
    };

    let header = EpsNasEsmHeader::new(eps_bearer_identity, pti, message_type);
    header.encode(&mut buf);

    match msg {
        EsmMessage::ActivateDefaultEpsBearerContextRequest(m) => m.encode(&mut buf),
        EsmMessage::ActivateDefaultEpsBearerContextAccept => {}
        EsmMessage::ActivateDefaultEpsBearerContextReject(m) => m.encode(&mut buf),
        EsmMessage::ActivateDedicatedEpsBearerContextRequest(m) => m.encode(&mut buf),
        EsmMessage::ActivateDedicatedEpsBearerContextAccept => {}
        EsmMessage::ActivateDedicatedEpsBearerContextReject(m) => m.encode(&mut buf),
        EsmMessage::ModifyEpsBearerContextRequest(m) => m.encode(&mut buf),
        EsmMessage::ModifyEpsBearerContextAccept(m) => m.encode(&mut buf),
        EsmMessage::ModifyEpsBearerContextReject(m) => m.encode(&mut buf),
        EsmMessage::DeactivateEpsBearerContextRequest(m) => m.encode(&mut buf),
        EsmMessage::DeactivateEpsBearerContextAccept => {}
        EsmMessage::PdnConnectivityRequest(m) => m.encode(&mut buf),
        EsmMessage::PdnConnectivityReject(m) => m.encode(&mut buf),
        EsmMessage::PdnDisconnectRequest(m) => m.encode(&mut buf),
        EsmMessage::PdnDisconnectReject(m) => m.encode(&mut buf),
        EsmMessage::BearerResourceAllocationRequest(m) => m.encode(&mut buf),
        EsmMessage::BearerResourceAllocationReject(m) => m.encode(&mut buf),
        EsmMessage::BearerResourceModificationRequest(m) => m.encode(&mut buf),
        EsmMessage::BearerResourceModificationReject(m) => m.encode(&mut buf),
        EsmMessage::EsmInformationRequest => {}
        EsmMessage::EsmInformationResponse(m) => m.encode(&mut buf),
        EsmMessage::EsmStatus(m) => m.encode(&mut buf),
    }

    buf
}

/// Parse an ESM message
pub fn parse_esm_message(buf: &mut Bytes) -> NasResult<(u8, u8, EsmMessage)> {
    let header = EpsNasEsmHeader::decode(buf)?;
    let message_type = EsmMessageType::try_from(header.message_type)?;

    let msg = match message_type {
        EsmMessageType::ActivateDefaultEpsBearerContextRequest => {
            EsmMessage::ActivateDefaultEpsBearerContextRequest(
                ActivateDefaultEpsBearerContextRequest::decode(buf)?,
            )
        }
        EsmMessageType::ActivateDefaultEpsBearerContextAccept => {
            EsmMessage::ActivateDefaultEpsBearerContextAccept
        }
        EsmMessageType::ActivateDefaultEpsBearerContextReject => {
            EsmMessage::ActivateDefaultEpsBearerContextReject(
                ActivateDefaultEpsBearerContextReject::decode(buf)?,
            )
        }
        EsmMessageType::ActivateDedicatedEpsBearerContextRequest => {
            EsmMessage::ActivateDedicatedEpsBearerContextRequest(
                ActivateDedicatedEpsBearerContextRequest::decode(buf)?,
            )
        }
        EsmMessageType::ActivateDedicatedEpsBearerContextAccept => {
            EsmMessage::ActivateDedicatedEpsBearerContextAccept
        }
        EsmMessageType::ActivateDedicatedEpsBearerContextReject => {
            EsmMessage::ActivateDedicatedEpsBearerContextReject(
                ActivateDedicatedEpsBearerContextReject::decode(buf)?,
            )
        }
        EsmMessageType::ModifyEpsBearerContextRequest => {
            EsmMessage::ModifyEpsBearerContextRequest(ModifyEpsBearerContextRequest::decode(buf)?)
        }
        EsmMessageType::ModifyEpsBearerContextAccept => {
            EsmMessage::ModifyEpsBearerContextAccept(ModifyEpsBearerContextAccept::decode(buf)?)
        }
        EsmMessageType::ModifyEpsBearerContextReject => {
            EsmMessage::ModifyEpsBearerContextReject(ModifyEpsBearerContextReject::decode(buf)?)
        }
        EsmMessageType::DeactivateEpsBearerContextRequest => {
            EsmMessage::DeactivateEpsBearerContextRequest(
                DeactivateEpsBearerContextRequest::decode(buf)?,
            )
        }
        EsmMessageType::DeactivateEpsBearerContextAccept => {
            EsmMessage::DeactivateEpsBearerContextAccept
        }
        EsmMessageType::PdnConnectivityRequest => {
            EsmMessage::PdnConnectivityRequest(PdnConnectivityRequest::decode(buf)?)
        }
        EsmMessageType::PdnConnectivityReject => {
            EsmMessage::PdnConnectivityReject(PdnConnectivityReject::decode(buf)?)
        }
        EsmMessageType::PdnDisconnectRequest => {
            EsmMessage::PdnDisconnectRequest(PdnDisconnectRequest::decode(buf)?)
        }
        EsmMessageType::PdnDisconnectReject => {
            EsmMessage::PdnDisconnectReject(PdnDisconnectReject::decode(buf)?)
        }
        EsmMessageType::BearerResourceAllocationRequest => {
            EsmMessage::BearerResourceAllocationRequest(BearerResourceAllocationRequest::decode(
                buf,
            )?)
        }
        EsmMessageType::BearerResourceAllocationReject => {
            EsmMessage::BearerResourceAllocationReject(BearerResourceAllocationReject::decode(buf)?)
        }
        EsmMessageType::BearerResourceModificationRequest => {
            EsmMessage::BearerResourceModificationRequest(
                BearerResourceModificationRequest::decode(buf)?,
            )
        }
        EsmMessageType::BearerResourceModificationReject => {
            EsmMessage::BearerResourceModificationReject(BearerResourceModificationReject::decode(
                buf,
            )?)
        }
        EsmMessageType::EsmInformationRequest => EsmMessage::EsmInformationRequest,
        EsmMessageType::EsmInformationResponse => {
            EsmMessage::EsmInformationResponse(EsmInformationResponse::decode(buf)?)
        }
        EsmMessageType::EsmStatus => EsmMessage::EsmStatus(EsmStatus::decode(buf)?),
    };

    Ok((
        header.eps_bearer_identity,
        header.procedure_transaction_identity,
        msg,
    ))
}

/// Build an EMM message with header
pub fn build_emm_message(msg: &EmmMessage) -> BytesMut {
    let mut buf = BytesMut::new();

    let message_type = match msg {
        EmmMessage::AttachRequest(_) => EmmMessageType::AttachRequest,
        EmmMessage::AttachAccept(_) => EmmMessageType::AttachAccept,
        EmmMessage::AttachComplete(_) => EmmMessageType::AttachComplete,
        EmmMessage::AttachReject(_) => EmmMessageType::AttachReject,
        EmmMessage::DetachRequest(_) => EmmMessageType::DetachRequest,
        EmmMessage::DetachAccept => EmmMessageType::DetachAccept,
        EmmMessage::TrackingAreaUpdateRequest(_) => EmmMessageType::TrackingAreaUpdateRequest,
        EmmMessage::TrackingAreaUpdateAccept(_) => EmmMessageType::TrackingAreaUpdateAccept,
        EmmMessage::TrackingAreaUpdateReject(_) => EmmMessageType::TrackingAreaUpdateReject,
        EmmMessage::AuthenticationRequest(_) => EmmMessageType::AuthenticationRequest,
        EmmMessage::AuthenticationResponse(_) => EmmMessageType::AuthenticationResponse,
        EmmMessage::AuthenticationReject => EmmMessageType::AuthenticationReject,
        EmmMessage::AuthenticationFailure(_) => EmmMessageType::AuthenticationFailure,
        EmmMessage::SecurityModeCommand(_) => EmmMessageType::SecurityModeCommand,
        EmmMessage::SecurityModeComplete(_) => EmmMessageType::SecurityModeComplete,
        EmmMessage::SecurityModeReject(_) => EmmMessageType::SecurityModeReject,
        EmmMessage::IdentityRequest(_) => EmmMessageType::IdentityRequest,
        EmmMessage::IdentityResponse(_) => EmmMessageType::IdentityResponse,
        EmmMessage::EmmStatus(_) => EmmMessageType::EmmStatus,
        EmmMessage::ServiceRequest(_) => EmmMessageType::ExtendedServiceRequest, // Service Request uses security header, map to ExtendedServiceRequest
        EmmMessage::ExtendedServiceRequest(_) => EmmMessageType::ExtendedServiceRequest,
        EmmMessage::ServiceReject(_) => EmmMessageType::ServiceReject,
        EmmMessage::GutiReallocationCommand(_) => EmmMessageType::GutiReallocationCommand,
        EmmMessage::GutiReallocationComplete => EmmMessageType::GutiReallocationComplete,
        EmmMessage::TrackingAreaUpdateComplete => EmmMessageType::TrackingAreaUpdateComplete,
        EmmMessage::EmmInformation(_) => EmmMessageType::EmmInformation,
        EmmMessage::DownlinkNasTransport(_) => EmmMessageType::DownlinkNasTransport,
        EmmMessage::UplinkNasTransport(_) => EmmMessageType::UplinkNasTransport,
        EmmMessage::CsServiceNotification(_) => EmmMessageType::CsServiceNotification,
    };

    // Encode header
    let header = EpsNasEmmHeader::new(message_type);
    header.encode(&mut buf);

    // Encode message body
    match msg {
        EmmMessage::AttachRequest(m) => m.encode(&mut buf),
        EmmMessage::AttachAccept(m) => m.encode(&mut buf),
        EmmMessage::AttachComplete(m) => m.encode(&mut buf),
        EmmMessage::AttachReject(m) => m.encode(&mut buf),
        EmmMessage::DetachRequest(m) => m.encode(&mut buf),
        EmmMessage::DetachAccept => {}
        EmmMessage::TrackingAreaUpdateRequest(m) => m.encode(&mut buf),
        EmmMessage::TrackingAreaUpdateAccept(m) => m.encode(&mut buf),
        EmmMessage::TrackingAreaUpdateReject(m) => m.encode(&mut buf),
        EmmMessage::AuthenticationRequest(m) => m.encode(&mut buf),
        EmmMessage::AuthenticationResponse(m) => m.encode(&mut buf),
        EmmMessage::AuthenticationReject => {}
        EmmMessage::AuthenticationFailure(m) => m.encode(&mut buf),
        EmmMessage::SecurityModeCommand(m) => m.encode(&mut buf),
        EmmMessage::SecurityModeComplete(m) => m.encode(&mut buf),
        EmmMessage::SecurityModeReject(m) => m.encode(&mut buf),
        EmmMessage::IdentityRequest(m) => m.encode(&mut buf),
        EmmMessage::IdentityResponse(m) => m.encode(&mut buf),
        EmmMessage::EmmStatus(m) => m.encode(&mut buf),
        EmmMessage::ServiceRequest(m) => m.encode(&mut buf),
        EmmMessage::ExtendedServiceRequest(m) => m.encode(&mut buf),
        EmmMessage::ServiceReject(m) => m.encode(&mut buf),
        EmmMessage::GutiReallocationCommand(m) => m.encode(&mut buf),
        EmmMessage::GutiReallocationComplete => {}
        EmmMessage::TrackingAreaUpdateComplete => {}
        EmmMessage::EmmInformation(m) => m.encode(&mut buf),
        EmmMessage::DownlinkNasTransport(m) => m.encode(&mut buf),
        EmmMessage::UplinkNasTransport(m) => m.encode(&mut buf),
        EmmMessage::CsServiceNotification(m) => m.encode(&mut buf),
    }

    buf
}

/// Parse an EMM message
pub fn parse_emm_message(buf: &mut Bytes) -> NasResult<EmmMessage> {
    let header = EpsNasEmmHeader::decode(buf)?;
    let message_type = EmmMessageType::try_from(header.message_type)?;

    match message_type {
        EmmMessageType::AttachRequest => Ok(EmmMessage::AttachRequest(AttachRequest::decode(buf)?)),
        EmmMessageType::AttachAccept => Ok(EmmMessage::AttachAccept(AttachAccept::decode(buf)?)),
        EmmMessageType::AttachComplete => {
            Ok(EmmMessage::AttachComplete(AttachComplete::decode(buf)?))
        }
        EmmMessageType::AttachReject => Ok(EmmMessage::AttachReject(AttachReject::decode(buf)?)),
        EmmMessageType::DetachRequest => Ok(EmmMessage::DetachRequest(DetachRequest::decode(buf)?)),
        EmmMessageType::DetachAccept => Ok(EmmMessage::DetachAccept),
        EmmMessageType::TrackingAreaUpdateRequest => Ok(EmmMessage::TrackingAreaUpdateRequest(
            TrackingAreaUpdateRequest::decode(buf)?,
        )),
        EmmMessageType::TrackingAreaUpdateAccept => Ok(EmmMessage::TrackingAreaUpdateAccept(
            TrackingAreaUpdateAccept::decode(buf)?,
        )),
        EmmMessageType::TrackingAreaUpdateReject => Ok(EmmMessage::TrackingAreaUpdateReject(
            TrackingAreaUpdateReject::decode(buf)?,
        )),
        EmmMessageType::AuthenticationRequest => Ok(EmmMessage::AuthenticationRequest(
            EpsAuthenticationRequest::decode(buf)?,
        )),
        EmmMessageType::AuthenticationResponse => Ok(EmmMessage::AuthenticationResponse(
            EpsAuthenticationResponse::decode(buf)?,
        )),
        EmmMessageType::AuthenticationReject => Ok(EmmMessage::AuthenticationReject),
        EmmMessageType::AuthenticationFailure => Ok(EmmMessage::AuthenticationFailure(
            EpsAuthenticationFailure::decode(buf)?,
        )),
        EmmMessageType::SecurityModeCommand => Ok(EmmMessage::SecurityModeCommand(
            EpsSecurityModeCommand::decode(buf)?,
        )),
        EmmMessageType::SecurityModeComplete => Ok(EmmMessage::SecurityModeComplete(
            EpsSecurityModeComplete::decode(buf)?,
        )),
        EmmMessageType::SecurityModeReject => Ok(EmmMessage::SecurityModeReject(
            EpsSecurityModeReject::decode(buf)?,
        )),
        EmmMessageType::IdentityRequest => Ok(EmmMessage::IdentityRequest(
            EpsIdentityRequest::decode(buf)?,
        )),
        EmmMessageType::IdentityResponse => Ok(EmmMessage::IdentityResponse(
            EpsIdentityResponse::decode(buf)?,
        )),
        EmmMessageType::EmmStatus => Ok(EmmMessage::EmmStatus(EmmStatus::decode(buf)?)),
        EmmMessageType::ExtendedServiceRequest => Ok(EmmMessage::ExtendedServiceRequest(
            ExtendedServiceRequest::decode(buf)?,
        )),
        EmmMessageType::ServiceReject => {
            Ok(EmmMessage::ServiceReject(EpsServiceReject::decode(buf)?))
        }
        EmmMessageType::GutiReallocationCommand => Ok(EmmMessage::GutiReallocationCommand(
            GutiReallocationCommand::decode(buf)?,
        )),
        EmmMessageType::GutiReallocationComplete => Ok(EmmMessage::GutiReallocationComplete),
        EmmMessageType::TrackingAreaUpdateComplete => Ok(EmmMessage::TrackingAreaUpdateComplete),
        EmmMessageType::EmmInformation => {
            Ok(EmmMessage::EmmInformation(EmmInformation::decode(buf)?))
        }
        EmmMessageType::DownlinkNasTransport => Ok(EmmMessage::DownlinkNasTransport(
            EpsDownlinkNasTransport::decode(buf)?,
        )),
        EmmMessageType::UplinkNasTransport => Ok(EmmMessage::UplinkNasTransport(
            EpsUplinkNasTransport::decode(buf)?,
        )),
        EmmMessageType::CsServiceNotification => Ok(EmmMessage::CsServiceNotification(
            CsServiceNotification::decode(buf)?,
        )),
    }
}
