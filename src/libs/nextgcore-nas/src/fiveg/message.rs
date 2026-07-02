//! 5GS NAS messages
//!
//! Based on 3GPP TS 24.501

use super::header::*;
use super::ie::*;
use super::types::*;
use crate::common::security::{unprotect_nas_message, NasSecurityContext};
use crate::common::types::*;
use crate::error::{NasError, NasResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Returns true if `iei` denotes a type-6 (TLV-E) IE in the 5GS NAS protocol,
/// i.e. one whose length field is 2 octets rather than 1 (TS 24.007 §11.2.5).
///
/// These are the TLV-E IEIs defined across the TS 24.501 5GMM/5GSM message
/// tables: NAS message container (0x71), Additional GUTI (0x77), EAP message
/// (0x78), LADN information (0x79), Payload container (0x7B), and the other
/// container-style IEs in the 0x70..=0x7F band (SOR transparent container 0x73,
/// operator-defined access category definitions 0x76, extended emergency number
/// list 0x7A, ciphering key data 0x74, CAG information list 0x75, mapped/EPS
/// bearer contexts 0x7A/0x7C, extended PCO 0x7B). Consuming the correct number
/// of length octets keeps the IE loop in sync when such an IE is not modelled.
fn is_tlv_e_iei(iei: u8) -> bool {
    matches!(
        iei,
        0x71 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7A | 0x7B | 0x7C
    )
}

/// Skip an unknown / unhandled optional IE in a default IE-loop arm, per
/// TS 24.501 §7.6.1 (unknown IEs are ignored, not errored) and the TS 24.007
/// IE-format rules. `buf` must be positioned at the IEI octet; `iei` is the
/// peeked IEI (`buf.chunk()[0]`).
///
/// - `iei >= 0x80`: type-1 (TV, half-octet IEI in the high nibble) or type-2
///   (T) — the whole IE is the single IEI octet; consume 1 octet, no length,
///   no value.
/// - `iei <  0x80` and TLV-E (see `is_tlv_e_iei`): consume the IEI octet, a
///   2-octet length, then that many value octets.
/// - other `iei <  0x80`: treated as type-4 (TLV) — consume the IEI octet, a
///   1-octet length, then `len` value octets. NOTE: unknown type-3 (fixed
///   length TV) IEs still cannot be distinguished, but all *known* such IEIs
///   are matched explicitly, so this only affects unknown ones.
fn skip_unknown_ie(buf: &mut Bytes, iei: u8) -> NasResult<()> {
    buf.advance(1); // consume the IEI octet (peeked, not yet advanced by caller)
    if iei >= 0x80 {
        return Ok(());
    }
    if is_tlv_e_iei(iei) {
        if buf.remaining() >= 2 {
            let len = buf.get_u16() as usize;
            let take = len.min(buf.remaining());
            buf.advance(take);
        }
    } else if buf.remaining() > 0 {
        let len = buf.get_u8() as usize;
        let take = len.min(buf.remaining());
        buf.advance(take);
    }
    Ok(())
}

/// 5GMM message
#[derive(Debug, Clone, PartialEq)]
pub enum FiveGmmMessage {
    RegistrationRequest(RegistrationRequest),
    RegistrationAccept(RegistrationAccept),
    RegistrationReject(RegistrationReject),
    RegistrationComplete(RegistrationComplete),
    DeregistrationRequestFromUe(DeregistrationRequestFromUe),
    DeregistrationAcceptFromUe,
    DeregistrationRequestToUe(DeregistrationRequestToUe),
    DeregistrationAcceptToUe,
    ServiceRequest(ServiceRequest),
    ServiceAccept(ServiceAccept),
    ServiceReject(ServiceReject),
    AuthenticationRequest(AuthenticationRequest),
    AuthenticationResponse(AuthenticationResponse),
    AuthenticationReject(AuthenticationReject),
    AuthenticationFailure(AuthenticationFailure),
    AuthenticationResult(AuthenticationResult),
    IdentityRequest(IdentityRequest),
    IdentityResponse(IdentityResponse),
    SecurityModeCommand(SecurityModeCommand),
    SecurityModeComplete(SecurityModeComplete),
    SecurityModeReject(SecurityModeReject),
    FiveGmmStatus(FiveGmmStatus),
    UlNasTransport(UlNasTransport),
    DlNasTransport(DlNasTransport),
    ConfigurationUpdateCommand(ConfigurationUpdateCommand),
    ConfigurationUpdateComplete,
    Notification(Notification),
    NotificationResponse(NotificationResponse),
    ControlPlaneServiceRequest(ControlPlaneServiceRequest),
    NetworkSliceSpecificAuthenticationCommand(NetworkSliceSpecificAuthenticationCommand),
    NetworkSliceSpecificAuthenticationComplete(NetworkSliceSpecificAuthenticationComplete),
    NetworkSliceSpecificAuthenticationResult(NetworkSliceSpecificAuthenticationResult),
}

/// Registration Request message (TS 24.501 Section 8.2.6)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationRequest {
    /// 5GS registration type
    pub registration_type: RegistrationType,
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// 5GS mobile identity
    pub mobile_identity: MobileIdentity,
    /// Presence mask for optional IEs
    pub presencemask: u64,
    /// Non-current native NAS key set identifier
    pub non_current_native_ngksi: Option<KeySetIdentifier>,
    /// 5GMM capability
    pub gmm_capability: Option<FiveGmmCapability>,
    /// UE security capability
    pub ue_security_capability: Option<UeSecurityCapability>,
    /// Requested NSSAI
    pub requested_nssai: Option<Nssai>,
    /// Last visited registered TAI
    pub last_visited_tai: Option<Tai>,
    /// UE status
    pub ue_status: Option<u8>,
    /// Additional GUTI
    pub additional_guti: Option<MobileIdentity>,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// Uplink data status
    pub uplink_data_status: Option<UplinkDataStatus>,
    /// NAS message container (IEI 0x71, TLV-E) — carries the ciphered/cleartext
    /// initial NAS message for the cleartext-IE registration flow (TS 24.501
    /// §4.4.6 / §9.11.3.33).
    pub nas_message_container: Option<NasMessageContainer>,
}

impl RegistrationRequest {
    /// Encode registration request to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // Registration type + ngKSI (1 byte)
        buf.put_u8((self.ngksi.encode() << 4) | self.registration_type.encode());
        // Mobile identity
        self.mobile_identity.encode(buf);
        // Optional IEs (TS 24.501 Table 8.2.6.1.1), emitted in spec order
        if let Some(ref ngksi) = self.non_current_native_ngksi {
            buf.put_u8(0xC0 | ngksi.encode()); // IEI C- (half-byte)
        }
        if let Some(ref cap) = self.gmm_capability {
            buf.put_u8(0x10); // IEI
            cap.encode(buf);
        }
        if let Some(ref sec_cap) = self.ue_security_capability {
            buf.put_u8(0x2E); // IEI
            sec_cap.encode(buf);
        }
        if let Some(ref nssai) = self.requested_nssai {
            buf.put_u8(0x2F); // IEI
            nssai.encode(buf);
        }
        if let Some(ref tai) = self.last_visited_tai {
            buf.put_u8(0x52); // IEI (TV, 6-octet value)
            tai.encode(buf);
        }
        if let Some(ref uds) = self.uplink_data_status {
            buf.put_u8(0x40); // IEI
            uds.encode(buf);
        }
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(status) = self.ue_status {
            buf.put_u8(0x2B); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(status);
        }
        if let Some(ref guti) = self.additional_guti {
            buf.put_u8(0x77); // IEI (TLV-E)
            guti.encode(buf);
        }
        if let Some(ref nmc) = self.nas_message_container {
            buf.put_u8(0x71); // IEI (TLV-E)
            nmc.encode(buf);
        }
    }

    /// Decode registration request from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }

        let first_byte = buf.get_u8();
        let registration_type = RegistrationType::decode(first_byte & 0x0F)?;
        let ngksi = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let mobile_identity = MobileIdentity::decode(buf)?;

        let mut msg = Self {
            registration_type,
            ngksi,
            mobile_identity,
            ..Default::default()
        };

        // Decode optional IEs
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };

            match iei_type {
                0xC0 => {
                    // Non-current native NAS key set identifier (half-byte)
                    buf.advance(1);
                    msg.non_current_native_ngksi = Some(KeySetIdentifier::decode(iei & 0x0F));
                }
                0x10 => {
                    // 5GMM capability
                    buf.advance(1);
                    msg.gmm_capability = Some(FiveGmmCapability::decode(buf)?);
                }
                0x2E => {
                    // UE security capability
                    buf.advance(1);
                    msg.ue_security_capability = Some(UeSecurityCapability::decode(buf)?);
                }
                0x2F => {
                    // Requested NSSAI
                    buf.advance(1);
                    msg.requested_nssai = Some(Nssai::decode(buf)?);
                }
                0x52 => {
                    // Last visited registered TAI
                    buf.advance(1);
                    msg.last_visited_tai = Some(Tai::decode(buf)?);
                }
                0x40 => {
                    // Uplink data status
                    buf.advance(1);
                    msg.uplink_data_status = Some(UplinkDataStatus::decode(buf)?);
                }
                0x50 => {
                    // PDU session status
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x2B => {
                    // UE status
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.ue_status = Some(buf.get_u8());
                    }
                }
                0x77 => {
                    // Additional GUTI
                    buf.advance(1);
                    msg.additional_guti = Some(MobileIdentity::decode(buf)?);
                }
                0x71 => {
                    // NAS message container (TLV-E), cleartext-IE reg (§4.4.6)
                    buf.advance(1);
                    msg.nas_message_container = Some(NasMessageContainer::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

/// Registration Accept message (TS 24.501 Section 8.2.7)
///
/// Supported optional IEs (encoded/decoded in TS 24.501 §8.2.7 IEI order):
/// 5G-GUTI (0x77), Equivalent PLMNs (0x4A), TAI list (0x54), Allowed NSSAI
/// (0x15), Rejected NSSAI (0x11), PDU session status (0x50), T3512 value
/// (0x5E) and T3502 value (0x16). Other optional IEs from the spec table are
/// not modelled and are ignored on decode (see `skip_unknown_ie`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationAccept {
    /// 5GS registration result
    pub registration_result: RegistrationResult,
    /// Presence mask
    pub presencemask: u64,
    /// 5G-GUTI
    pub guti: Option<MobileIdentity>,
    /// Equivalent PLMNs
    pub equivalent_plmns: Option<Vec<PlmnId>>,
    /// TAI list
    pub tai_list: Option<TaiList>,
    /// Allowed NSSAI
    pub allowed_nssai: Option<Nssai>,
    /// Rejected NSSAI
    pub rejected_nssai: Option<Vec<u8>>,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// T3512 value
    pub t3512_value: Option<GprsTimer3>,
    /// T3502 value
    pub t3502_value: Option<GprsTimer2>,
}

impl RegistrationAccept {
    /// Encode registration accept to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.registration_result.encode(buf);
        // Optional IEs
        if let Some(ref guti) = self.guti {
            buf.put_u8(0x77); // IEI
            guti.encode(buf);
        }
        if let Some(ref eplmns) = self.equivalent_plmns {
            // Equivalent PLMNs (TS 24.501 §8.2.7 / §9.11.3.45 "PLMN list"):
            // TLV, IEI 0x4A, length = 3 octets per PLMN.
            buf.put_u8(0x4A); // IEI
            buf.put_u8((eplmns.len() * PlmnId::encoded_len()) as u8);
            for plmn in eplmns {
                plmn.encode(buf);
            }
        }
        if let Some(ref tai_list) = self.tai_list {
            buf.put_u8(0x54); // IEI
            tai_list.encode(buf);
        }
        if let Some(ref allowed_nssai) = self.allowed_nssai {
            buf.put_u8(0x15); // IEI
            allowed_nssai.encode(buf);
        }
        if let Some(ref rejected_nssai) = self.rejected_nssai {
            // Rejected NSSAI (TS 24.501 §8.2.7 / §9.11.3.46): TLV, IEI 0x11.
            buf.put_u8(0x11); // IEI
            buf.put_u8(rejected_nssai.len() as u8);
            buf.put_slice(rejected_nssai);
        }
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(ref t3512) = self.t3512_value {
            buf.put_u8(0x5E); // IEI
            t3512.encode(buf);
        }
        if let Some(ref t3502) = self.t3502_value {
            buf.put_u8(0x16); // IEI
            t3502.encode(buf);
        }
    }

    /// Decode registration accept from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let registration_result = RegistrationResult::decode(buf)?;
        let mut msg = Self {
            registration_result,
            ..Default::default()
        };

        // Decode optional IEs
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x77 => {
                    buf.advance(1);
                    msg.guti = Some(MobileIdentity::decode(buf)?);
                }
                0x4A => {
                    // Equivalent PLMNs (TLV, 3 octets per PLMN).
                    buf.advance(1);
                    if buf.remaining() < 1 {
                        return Err(NasError::BufferTooShort {
                            expected: 1,
                            actual: buf.remaining(),
                        });
                    }
                    let len = buf.get_u8() as usize;
                    if buf.remaining() < len {
                        return Err(NasError::BufferTooShort {
                            expected: len,
                            actual: buf.remaining(),
                        });
                    }
                    let count = len / PlmnId::encoded_len();
                    let mut plmns = Vec::with_capacity(count);
                    for _ in 0..count {
                        plmns.push(PlmnId::decode(buf)?);
                    }
                    // Discard any trailing octets (length not a multiple of 3).
                    let rem = len % PlmnId::encoded_len();
                    if rem > 0 {
                        buf.advance(rem);
                    }
                    msg.equivalent_plmns = Some(plmns);
                }
                0x54 => {
                    buf.advance(1);
                    msg.tai_list = Some(TaiList::decode(buf)?);
                }
                0x15 => {
                    buf.advance(1);
                    msg.allowed_nssai = Some(Nssai::decode(buf)?);
                }
                0x11 => {
                    // Rejected NSSAI (TLV) — stored as opaque octets.
                    buf.advance(1);
                    if buf.remaining() < 1 {
                        return Err(NasError::BufferTooShort {
                            expected: 1,
                            actual: buf.remaining(),
                        });
                    }
                    let len = buf.get_u8() as usize;
                    if buf.remaining() < len {
                        return Err(NasError::BufferTooShort {
                            expected: len,
                            actual: buf.remaining(),
                        });
                    }
                    msg.rejected_nssai = Some(buf.copy_to_bytes(len).to_vec());
                }
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x5E => {
                    buf.advance(1);
                    msg.t3512_value = Some(GprsTimer3::decode(buf)?);
                }
                0x16 => {
                    buf.advance(1);
                    msg.t3502_value = Some(GprsTimer2::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

/// Registration Reject message (TS 24.501 Section 8.2.8)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationReject {
    /// 5GMM cause
    pub gmm_cause: u8,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
    /// T3502 value
    pub t3502_value: Option<GprsTimer2>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl RegistrationReject {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F);
            t3346.encode(buf);
        }
        if let Some(ref t3502) = self.t3502_value {
            buf.put_u8(0x16);
            t3502.encode(buf);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78);
            eap.encode(buf);
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
        let gmm_cause = buf.get_u8();
        let mut msg = Self {
            gmm_cause,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x5F => {
                    buf.advance(1);
                    msg.t3346_value = Some(GprsTimer2::decode(buf)?);
                }
                0x16 => {
                    buf.advance(1);
                    msg.t3502_value = Some(GprsTimer2::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

/// Registration Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistrationComplete {
    /// SOR transparent container
    pub sor_transparent_container: Option<Vec<u8>>,
}

impl RegistrationComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref sor) = self.sor_transparent_container {
            buf.put_u8(0x73); // IEI
            buf.put_u16(sor.len() as u16);
            buf.put_slice(sor);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x73 => {
                    buf.advance(1);
                    if buf.remaining() < 2 {
                        break;
                    }
                    let len = buf.get_u16() as usize;
                    if buf.remaining() >= len {
                        msg.sor_transparent_container = Some(buf.copy_to_bytes(len).to_vec());
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Deregistration Request from UE
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeregistrationRequestFromUe {
    /// De-registration type
    pub de_registration_type: DeRegistrationType,
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// 5GS mobile identity
    pub mobile_identity: MobileIdentity,
}

impl DeregistrationRequestFromUe {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.ngksi.encode() << 4) | self.de_registration_type.encode());
        self.mobile_identity.encode(buf);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let first_byte = buf.get_u8();
        let de_registration_type = DeRegistrationType::decode(first_byte & 0x0F);
        let ngksi = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let mobile_identity = MobileIdentity::decode(buf)?;
        Ok(Self {
            de_registration_type,
            ngksi,
            mobile_identity,
        })
    }
}

/// Deregistration Request to UE
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeregistrationRequestToUe {
    /// De-registration type
    pub de_registration_type: DeRegistrationType,
    /// 5GMM cause
    pub gmm_cause: Option<u8>,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
}

impl DeregistrationRequestToUe {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.de_registration_type.encode());
        if let Some(cause) = self.gmm_cause {
            buf.put_u8(0x58); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F); // IEI
            t3346.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let first_byte = buf.get_u8();
        let de_registration_type = DeRegistrationType::decode(first_byte & 0x0F);
        let mut msg = Self {
            de_registration_type,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x58 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gmm_cause = Some(buf.get_u8());
                    }
                }
                0x5F => {
                    buf.advance(1);
                    msg.t3346_value = Some(GprsTimer2::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Service Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceRequest {
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// Service type
    pub service_type: ServiceType,
    /// 5G-S-TMSI
    pub s_tmsi: MobileIdentity,
    /// Uplink data status
    pub uplink_data_status: Option<UplinkDataStatus>,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// Allowed PDU session status
    pub allowed_pdu_session_status: Option<AllowedPduSessionStatus>,
    /// NAS message container
    pub nas_message_container: Option<NasMessageContainer>,
}

impl ServiceRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.ngksi.encode() << 4) | (self.service_type as u8 & 0x0F));
        self.s_tmsi.encode(buf);
        if let Some(ref uds) = self.uplink_data_status {
            buf.put_u8(0x40); // IEI
            uds.encode(buf);
        }
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(ref apss) = self.allowed_pdu_session_status {
            buf.put_u8(0x25); // IEI
            apss.encode(buf);
        }
        if let Some(ref nmc) = self.nas_message_container {
            buf.put_u8(0x71); // IEI
            nmc.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let first_byte = buf.get_u8();
        let ngksi = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let service_type_val = first_byte & 0x0F;
        let service_type = match service_type_val {
            0 => ServiceType::Signalling,
            1 => ServiceType::Data,
            2 => ServiceType::MobileTerminatedServices,
            3 => ServiceType::EmergencyServices,
            4 => ServiceType::EmergencyServicesFallback,
            5 => ServiceType::HighPriorityAccess,
            6 => ServiceType::ElevatedSignalling,
            _ => ServiceType::UnusedFallback,
        };
        let s_tmsi = MobileIdentity::decode(buf)?;
        let mut msg = Self {
            ngksi,
            service_type,
            s_tmsi,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x40 => {
                    buf.advance(1);
                    msg.uplink_data_status = Some(UplinkDataStatus::decode(buf)?);
                }
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x25 => {
                    buf.advance(1);
                    msg.allowed_pdu_session_status = Some(AllowedPduSessionStatus::decode(buf)?);
                }
                0x71 => {
                    buf.advance(1);
                    msg.nas_message_container = Some(NasMessageContainer::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Service Accept message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceAccept {
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// PDU session reactivation result
    pub pdu_session_reactivation_result: Option<u16>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
    /// T3448 value
    pub t3448_value: Option<GprsTimer2>,
}

impl ServiceAccept {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(result) = self.pdu_session_reactivation_result {
            buf.put_u8(0x26); // IEI
            buf.put_u8(2); // Length
                           // TS 24.501 §9.11.3.42: PSI(0)-PSI(15) bitmap, octet 3 = PSI(0)-PSI(7) => little-endian.
            buf.put_u16_le(result);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
        if let Some(ref t3448) = self.t3448_value {
            buf.put_u8(0x6B); // IEI
            t3448.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x26 => {
                    buf.advance(1);
                    if buf.remaining() >= 3 {
                        let _len = buf.get_u8();
                        msg.pdu_session_reactivation_result = Some(buf.get_u16_le());
                    }
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                0x6B => {
                    buf.advance(1);
                    msg.t3448_value = Some(GprsTimer2::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Service Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceReject {
    /// 5GMM cause
    pub gmm_cause: u8,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// T3346 value
    pub t3346_value: Option<GprsTimer2>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl ServiceReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(ref t3346) = self.t3346_value {
            buf.put_u8(0x5F); // IEI
            t3346.encode(buf);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let gmm_cause = buf.get_u8();
        let mut msg = Self {
            gmm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x5F => {
                    buf.advance(1);
                    msg.t3346_value = Some(GprsTimer2::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Authentication Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationRequest {
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// ABBA
    pub abba: Abba,
    /// Authentication parameter RAND
    pub rand: Option<AuthenticationRand>,
    /// Authentication parameter AUTN
    pub autn: Option<AuthenticationAutn>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl AuthenticationRequest {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ngksi.encode());
        self.abba.encode(buf);
        if let Some(ref rand) = self.rand {
            buf.put_u8(0x21); // IEI
            buf.put_slice(rand);
        }
        if let Some(ref autn) = self.autn {
            buf.put_u8(0x20); // IEI
            buf.put_u8(16); // Length
            buf.put_slice(autn);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
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
        let ngksi = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let abba = Abba::decode(buf)?;

        let mut msg = Self {
            ngksi,
            abba,
            ..Default::default()
        };

        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x21 => {
                    buf.advance(1);
                    let mut rand = [0u8; 16];
                    if buf.remaining() >= 16 {
                        buf.copy_to_slice(&mut rand);
                        msg.rand = Some(rand);
                    }
                }
                0x20 => {
                    buf.advance(1);
                    let len = buf.get_u8();
                    if buf.remaining() >= len as usize && len >= 16 {
                        let mut autn = [0u8; 16];
                        buf.copy_to_slice(&mut autn);
                        msg.autn = Some(autn);
                    }
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }

        Ok(msg)
    }
}

/// Authentication Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationResponse {
    /// Authentication response parameter
    pub authentication_response_parameter: Option<AuthenticationResponseParameter>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl AuthenticationResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref arp) = self.authentication_response_parameter {
            buf.put_u8(0x2D); // IEI
            arp.encode(buf);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x2D => {
                    buf.advance(1);
                    msg.authentication_response_parameter =
                        Some(AuthenticationResponseParameter::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Authentication Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationReject {
    /// EAP message
    pub eap_message: Option<EapMessage>,
}

impl AuthenticationReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Authentication Failure message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationFailure {
    /// 5GMM cause
    pub gmm_cause: u8,
    /// Authentication failure parameter
    pub authentication_failure_parameter: Option<Vec<u8>>,
}

impl AuthenticationFailure {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
        if let Some(ref afp) = self.authentication_failure_parameter {
            buf.put_u8(0x30); // IEI
            buf.put_u8(afp.len() as u8);
            buf.put_slice(afp);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let gmm_cause = buf.get_u8();
        let mut msg = Self {
            gmm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x30 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.authentication_failure_parameter =
                                Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Authentication Result message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuthenticationResult {
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// EAP message
    pub eap_message: EapMessage,
    /// ABBA
    pub abba: Option<Abba>,
}

impl AuthenticationResult {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ngksi.encode());
        self.eap_message.encode(buf);
        if let Some(ref abba) = self.abba {
            buf.put_u8(0x38); // IEI
            abba.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let ngksi = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let eap_message = EapMessage::decode(buf)?;
        let mut msg = Self {
            ngksi,
            eap_message,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x38 => {
                    buf.advance(1);
                    msg.abba = Some(Abba::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Identity Request message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdentityRequest {
    /// 5GS identity type
    pub identity_type: FiveGsIdentityType,
}

impl IdentityRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.identity_type as u8 & 0x07);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let identity_type = FiveGsIdentityType::from(buf.get_u8());
        Ok(Self { identity_type })
    }
}

/// Identity Response message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdentityResponse {
    /// 5GS mobile identity
    pub mobile_identity: MobileIdentity,
}

impl IdentityResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.mobile_identity.encode(buf);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mobile_identity = MobileIdentity::decode(buf)?;
        Ok(Self { mobile_identity })
    }
}

/// Security Mode Command message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityModeCommand {
    /// Selected NAS security algorithms
    pub selected_nas_security_algorithms: SecurityAlgorithms,
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// Replayed UE security capabilities
    pub replayed_ue_security_capabilities: UeSecurityCapability,
    /// IMEISV request
    pub imeisv_request: Option<u8>,
    /// Selected EPS NAS security algorithms
    pub selected_eps_nas_security_algorithms: Option<SecurityAlgorithms>,
    /// Additional 5G security information
    pub additional_5g_security_information: Option<u8>,
    /// EAP message
    pub eap_message: Option<EapMessage>,
    /// ABBA
    pub abba: Option<Abba>,
    /// Replayed S1 UE security capabilities
    pub replayed_s1_ue_security_capabilities: Option<Vec<u8>>,
}

impl SecurityModeCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.selected_nas_security_algorithms.encode());
        buf.put_u8(self.ngksi.encode());
        self.replayed_ue_security_capabilities.encode(buf);
        if let Some(imeisv_req) = self.imeisv_request {
            buf.put_u8(0xE0 | (imeisv_req & 0x0F)); // IEI E- (half-byte)
        }
        if let Some(ref eps_algs) = self.selected_eps_nas_security_algorithms {
            buf.put_u8(0x57); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(eps_algs.encode());
        }
        if let Some(info) = self.additional_5g_security_information {
            buf.put_u8(0x36); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(info);
        }
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
        if let Some(ref abba) = self.abba {
            buf.put_u8(0x38); // IEI
            abba.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort {
                expected: 2,
                actual: buf.remaining(),
            });
        }
        let selected_nas_security_algorithms = SecurityAlgorithms::decode(buf.get_u8());
        let ngksi = KeySetIdentifier::decode(buf.get_u8() & 0x0F);
        let replayed_ue_security_capabilities = UeSecurityCapability::decode(buf)?;
        let mut msg = Self {
            selected_nas_security_algorithms,
            ngksi,
            replayed_ue_security_capabilities,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0xE0 => {
                    buf.advance(1);
                    msg.imeisv_request = Some(iei & 0x0F);
                }
                0x57 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.selected_eps_nas_security_algorithms =
                            Some(SecurityAlgorithms::decode(buf.get_u8()));
                    }
                }
                0x36 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.additional_5g_security_information = Some(buf.get_u8());
                    }
                }
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                0x38 => {
                    buf.advance(1);
                    msg.abba = Some(Abba::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Security Mode Complete message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityModeComplete {
    /// IMEISV
    pub imeisv: Option<MobileIdentity>,
    /// NAS message container
    pub nas_message_container: Option<NasMessageContainer>,
    /// Non-IMEISV PEI
    pub non_imeisv_pei: Option<MobileIdentity>,
}

impl SecurityModeComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref imeisv) = self.imeisv {
            buf.put_u8(0x77); // IEI
            imeisv.encode(buf);
        }
        if let Some(ref nmc) = self.nas_message_container {
            buf.put_u8(0x71); // IEI
            nmc.encode(buf);
        }
        if let Some(ref pei) = self.non_imeisv_pei {
            buf.put_u8(0x78); // IEI
            pei.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x77 => {
                    buf.advance(1);
                    msg.imeisv = Some(MobileIdentity::decode(buf)?);
                }
                0x71 => {
                    buf.advance(1);
                    msg.nas_message_container = Some(NasMessageContainer::decode(buf)?);
                }
                0x78 => {
                    buf.advance(1);
                    msg.non_imeisv_pei = Some(MobileIdentity::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Security Mode Reject message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityModeReject {
    /// 5GMM cause
    pub gmm_cause: u8,
}

impl SecurityModeReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            gmm_cause: buf.get_u8(),
        })
    }
}

/// 5GMM Status message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FiveGmmStatus {
    /// 5GMM cause
    pub gmm_cause: u8,
}

impl FiveGmmStatus {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gmm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            gmm_cause: buf.get_u8(),
        })
    }
}

/// UL NAS Transport message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UlNasTransport {
    /// Payload container type
    pub payload_container_type: PayloadContainerType,
    /// Payload container
    pub payload_container: PayloadContainer,
    /// PDU session ID
    pub pdu_session_id: Option<PduSessionIdentity>,
    /// Old PDU session ID
    pub old_pdu_session_id: Option<PduSessionIdentity>,
    /// Request type
    pub request_type: Option<RequestType>,
    /// S-NSSAI
    pub s_nssai: Option<SNssai>,
    /// DNN
    pub dnn: Option<Dnn>,
}

impl UlNasTransport {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.payload_container_type as u8 & 0x0F);
        self.payload_container.encode(buf);
        if let Some(psi) = self.pdu_session_id {
            buf.put_u8(0x12); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(psi);
        }
        if let Some(old_psi) = self.old_pdu_session_id {
            buf.put_u8(0x59); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(old_psi);
        }
        if let Some(ref rt) = self.request_type {
            buf.put_u8(0x80 | (*rt as u8 & 0x0F)); // IEI 8- (half-byte)
        }
        if let Some(ref snssai) = self.s_nssai {
            buf.put_u8(0x22); // IEI
            snssai.encode(buf);
        }
        if let Some(ref dnn) = self.dnn {
            buf.put_u8(0x25); // IEI
            dnn.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let pct_byte = buf.get_u8();
        let payload_container_type = match pct_byte & 0x0F {
            1 => PayloadContainerType::N1SmInformation,
            2 => PayloadContainerType::SmsContainer,
            3 => PayloadContainerType::LppMessage,
            4 => PayloadContainerType::SorTransparentContainer,
            5 => PayloadContainerType::UeParametersUpdateTransparentContainer,
            6 => PayloadContainerType::UePolicyContainer,
            7 => PayloadContainerType::UeParametersUpdateTransparentContainerForUeInitiated,
            8 => PayloadContainerType::MultiplePayloads,
            9 => PayloadContainerType::EventNotification,
            _ => PayloadContainerType::N1SmInformation,
        };
        let payload_container = PayloadContainer::decode(buf)?;
        let mut msg = Self {
            payload_container_type,
            payload_container,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0x12 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.pdu_session_id = Some(buf.get_u8());
                    }
                }
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.old_pdu_session_id = Some(buf.get_u8());
                    }
                }
                0x80 => {
                    buf.advance(1);
                    let rt = match iei & 0x0F {
                        1 => RequestType::InitialRequest,
                        2 => RequestType::ExistingPduSession,
                        3 => RequestType::InitialEmergencyRequest,
                        4 => RequestType::ExistingEmergencyPduSession,
                        5 => RequestType::ModificationRequest,
                        6 => RequestType::MaPduRequest,
                        _ => RequestType::InitialRequest,
                    };
                    msg.request_type = Some(rt);
                }
                0x22 => {
                    buf.advance(1);
                    msg.s_nssai = Some(SNssai::decode(buf)?);
                }
                0x25 => {
                    buf.advance(1);
                    msg.dnn = Some(Dnn::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// DL NAS Transport message
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DlNasTransport {
    /// Payload container type
    pub payload_container_type: PayloadContainerType,
    /// Payload container
    pub payload_container: PayloadContainer,
    /// PDU session ID
    pub pdu_session_id: Option<PduSessionIdentity>,
    /// Additional information
    pub additional_information: Option<Vec<u8>>,
    /// 5GMM cause
    pub gmm_cause: Option<u8>,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
}

impl DlNasTransport {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.payload_container_type as u8 & 0x0F);
        self.payload_container.encode(buf);
        if let Some(psi) = self.pdu_session_id {
            buf.put_u8(0x12); // IEI
            buf.put_u8(1); // Length
            buf.put_u8(psi);
        }
        if let Some(ref info) = self.additional_information {
            buf.put_u8(0x24); // IEI
            buf.put_u8(info.len() as u8);
            buf.put_slice(info);
        }
        if let Some(cause) = self.gmm_cause {
            buf.put_u8(0x58); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let pct_byte = buf.get_u8();
        let payload_container_type = match pct_byte & 0x0F {
            1 => PayloadContainerType::N1SmInformation,
            2 => PayloadContainerType::SmsContainer,
            3 => PayloadContainerType::LppMessage,
            4 => PayloadContainerType::SorTransparentContainer,
            5 => PayloadContainerType::UeParametersUpdateTransparentContainer,
            6 => PayloadContainerType::UePolicyContainer,
            7 => PayloadContainerType::UeParametersUpdateTransparentContainerForUeInitiated,
            8 => PayloadContainerType::MultiplePayloads,
            9 => PayloadContainerType::EventNotification,
            _ => PayloadContainerType::N1SmInformation,
        };
        let payload_container = PayloadContainer::decode(buf)?;
        let mut msg = Self {
            payload_container_type,
            payload_container,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x12 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.pdu_session_id = Some(buf.get_u8());
                    }
                }
                0x24 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.additional_information = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x58 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gmm_cause = Some(buf.get_u8());
                    }
                }
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Configuration Update Command message (TS 24.501 Section 8.2.18)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConfigurationUpdateCommand {
    /// Configuration update indication
    pub configuration_update_indication: Option<u8>,
    /// 5G-GUTI
    pub guti: Option<MobileIdentity>,
    /// TAI list
    pub tai_list: Option<TaiList>,
    /// Allowed NSSAI
    pub allowed_nssai: Option<Nssai>,
    /// Service area list
    pub service_area_list: Option<Vec<u8>>,
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
    /// LADN information
    pub ladn_information: Option<Vec<u8>>,
    /// Configured NSSAI
    pub configured_nssai: Option<Nssai>,
    /// Rejected NSSAI
    pub rejected_nssai: Option<Vec<u8>>,
}

impl ConfigurationUpdateCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ind) = self.configuration_update_indication {
            buf.put_u8(0xD0 | (ind & 0x0F)); // IEI D- (half-byte)
        }
        if let Some(ref guti) = self.guti {
            buf.put_u8(0x77); // IEI
            guti.encode(buf);
        }
        if let Some(ref tai_list) = self.tai_list {
            buf.put_u8(0x54); // IEI
            tai_list.encode(buf);
        }
        if let Some(ref allowed_nssai) = self.allowed_nssai {
            buf.put_u8(0x15); // IEI
            allowed_nssai.encode(buf);
        }
        if let Some(ref configured_nssai) = self.configured_nssai {
            buf.put_u8(0x31); // IEI
            configured_nssai.encode(buf);
        }
        if let Some(ref rejected_nssai) = self.rejected_nssai {
            buf.put_u8(0x11); // IEI
            buf.put_u8(rejected_nssai.len() as u8);
            buf.put_slice(rejected_nssai);
        }
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
        if let Some(ref ladn) = self.ladn_information {
            buf.put_u8(0x79); // IEI
            buf.put_u16(ladn.len() as u16);
            buf.put_slice(ladn);
        }
        if let Some(ref sal) = self.service_area_list {
            buf.put_u8(0x27); // IEI
            buf.put_u8(sal.len() as u8);
            buf.put_slice(sal);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0xD0 => {
                    buf.advance(1);
                    msg.configuration_update_indication = Some(iei & 0x0F);
                }
                0x77 => {
                    buf.advance(1);
                    msg.guti = Some(MobileIdentity::decode(buf)?);
                }
                0x54 => {
                    buf.advance(1);
                    msg.tai_list = Some(TaiList::decode(buf)?);
                }
                0x15 => {
                    buf.advance(1);
                    msg.allowed_nssai = Some(Nssai::decode(buf)?);
                }
                0x31 => {
                    buf.advance(1);
                    msg.configured_nssai = Some(Nssai::decode(buf)?);
                }
                0x11 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.rejected_nssai = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x43 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.full_name_for_network = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x45 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.short_name_for_network = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x46 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.local_time_zone = Some(buf.get_u8());
                    }
                }
                0x47 => {
                    buf.advance(1);
                    if buf.remaining() >= 7 {
                        let mut utltz = [0u8; 7];
                        buf.copy_to_slice(&mut utltz);
                        msg.universal_time_and_local_time_zone = Some(utltz);
                    }
                }
                0x49 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let _len = buf.get_u8();
                        msg.network_daylight_saving_time = Some(buf.get_u8());
                    }
                }
                0x79 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.ladn_information = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x27 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        let len = buf.get_u8() as usize;
                        if buf.remaining() >= len {
                            msg.service_area_list = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Notification message (TS 24.501 Section 8.2.27)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Notification {
    /// Access type
    pub access_type: u8,
}

impl Notification {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.access_type & 0x03);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            access_type: buf.get_u8() & 0x03,
        })
    }
}

/// Notification Response message (TS 24.501 Section 8.2.28)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NotificationResponse {
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
}

impl NotificationResponse {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Control Plane Service Request message (TS 24.501 Section 8.2.10)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ControlPlaneServiceRequest {
    /// ngKSI
    pub ngksi: KeySetIdentifier,
    /// Control plane service type
    pub control_plane_service_type: u8,
    /// CIoT small data container
    pub ciot_small_data_container: Option<Vec<u8>>,
    /// Payload container type
    pub payload_container_type: Option<u8>,
    /// Payload container
    pub payload_container: Option<PayloadContainer>,
    /// PDU session status
    pub pdu_session_status: Option<PduSessionStatus>,
    /// NAS message container
    pub nas_message_container: Option<NasMessageContainer>,
}

impl ControlPlaneServiceRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.ngksi.encode() << 4) | (self.control_plane_service_type & 0x0F));
        if let Some(ref csdc) = self.ciot_small_data_container {
            buf.put_u8(0x6F); // IEI
            buf.put_u16(csdc.len() as u16);
            buf.put_slice(csdc);
        }
        if let Some(pct) = self.payload_container_type {
            buf.put_u8(0x80 | (pct & 0x0F)); // IEI 8- (half-byte)
        }
        if let Some(ref pc) = self.payload_container {
            buf.put_u8(0x7B); // IEI
            pc.encode(buf);
        }
        if let Some(ref pss) = self.pdu_session_status {
            buf.put_u8(0x50); // IEI
            pss.encode(buf);
        }
        if let Some(ref nmc) = self.nas_message_container {
            buf.put_u8(0x71); // IEI
            nmc.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let first_byte = buf.get_u8();
        let ngksi = KeySetIdentifier::decode((first_byte >> 4) & 0x0F);
        let control_plane_service_type = first_byte & 0x0F;
        let mut msg = Self {
            ngksi,
            control_plane_service_type,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0x6F => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.ciot_small_data_container = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x80 => {
                    buf.advance(1);
                    msg.payload_container_type = Some(iei & 0x0F);
                }
                0x7B => {
                    buf.advance(1);
                    msg.payload_container = Some(PayloadContainer::decode(buf)?);
                }
                0x50 => {
                    buf.advance(1);
                    msg.pdu_session_status = Some(PduSessionStatus::decode(buf)?);
                }
                0x71 => {
                    buf.advance(1);
                    msg.nas_message_container = Some(NasMessageContainer::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Network Slice-Specific Authentication Command (TS 24.501 Section 8.2.29)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkSliceSpecificAuthenticationCommand {
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// EAP message
    pub eap_message: EapMessage,
}

impl NetworkSliceSpecificAuthenticationCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.s_nssai.encode(buf);
        self.eap_message.encode(buf);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let s_nssai = SNssai::decode(buf)?;
        let eap_message = EapMessage::decode(buf)?;
        Ok(Self {
            s_nssai,
            eap_message,
        })
    }
}

/// Network Slice-Specific Authentication Complete (TS 24.501 Section 8.2.30)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkSliceSpecificAuthenticationComplete {
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// EAP message
    pub eap_message: EapMessage,
}

impl NetworkSliceSpecificAuthenticationComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.s_nssai.encode(buf);
        self.eap_message.encode(buf);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let s_nssai = SNssai::decode(buf)?;
        let eap_message = EapMessage::decode(buf)?;
        Ok(Self {
            s_nssai,
            eap_message,
        })
    }
}

/// Network Slice-Specific Authentication Result (TS 24.501 Section 8.2.31)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkSliceSpecificAuthenticationResult {
    /// S-NSSAI
    pub s_nssai: SNssai,
    /// EAP message
    pub eap_message: EapMessage,
}

impl NetworkSliceSpecificAuthenticationResult {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.s_nssai.encode(buf);
        self.eap_message.encode(buf);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let s_nssai = SNssai::decode(buf)?;
        let eap_message = EapMessage::decode(buf)?;
        Ok(Self {
            s_nssai,
            eap_message,
        })
    }
}

/// Build a 5GMM message with header
pub fn build_5gmm_message(msg: &FiveGmmMessage) -> BytesMut {
    let mut buf = BytesMut::new();

    let message_type = match msg {
        FiveGmmMessage::RegistrationRequest(_) => FiveGmmMessageType::RegistrationRequest,
        FiveGmmMessage::RegistrationAccept(_) => FiveGmmMessageType::RegistrationAccept,
        FiveGmmMessage::RegistrationReject(_) => FiveGmmMessageType::RegistrationReject,
        FiveGmmMessage::RegistrationComplete(_) => FiveGmmMessageType::RegistrationComplete,
        FiveGmmMessage::DeregistrationRequestFromUe(_) => {
            FiveGmmMessageType::DeregistrationRequestFromUe
        }
        FiveGmmMessage::DeregistrationAcceptFromUe => {
            FiveGmmMessageType::DeregistrationAcceptFromUe
        }
        FiveGmmMessage::DeregistrationRequestToUe(_) => {
            FiveGmmMessageType::DeregistrationRequestToUe
        }
        FiveGmmMessage::DeregistrationAcceptToUe => FiveGmmMessageType::DeregistrationAcceptToUe,
        FiveGmmMessage::ServiceRequest(_) => FiveGmmMessageType::ServiceRequest,
        FiveGmmMessage::ServiceAccept(_) => FiveGmmMessageType::ServiceAccept,
        FiveGmmMessage::ServiceReject(_) => FiveGmmMessageType::ServiceReject,
        FiveGmmMessage::AuthenticationRequest(_) => FiveGmmMessageType::AuthenticationRequest,
        FiveGmmMessage::AuthenticationResponse(_) => FiveGmmMessageType::AuthenticationResponse,
        FiveGmmMessage::AuthenticationReject(_) => FiveGmmMessageType::AuthenticationReject,
        FiveGmmMessage::AuthenticationFailure(_) => FiveGmmMessageType::AuthenticationFailure,
        FiveGmmMessage::AuthenticationResult(_) => FiveGmmMessageType::AuthenticationResult,
        FiveGmmMessage::IdentityRequest(_) => FiveGmmMessageType::IdentityRequest,
        FiveGmmMessage::IdentityResponse(_) => FiveGmmMessageType::IdentityResponse,
        FiveGmmMessage::SecurityModeCommand(_) => FiveGmmMessageType::SecurityModeCommand,
        FiveGmmMessage::SecurityModeComplete(_) => FiveGmmMessageType::SecurityModeComplete,
        FiveGmmMessage::SecurityModeReject(_) => FiveGmmMessageType::SecurityModeReject,
        FiveGmmMessage::FiveGmmStatus(_) => FiveGmmMessageType::FiveGmmStatus,
        FiveGmmMessage::UlNasTransport(_) => FiveGmmMessageType::UlNasTransport,
        FiveGmmMessage::DlNasTransport(_) => FiveGmmMessageType::DlNasTransport,
        FiveGmmMessage::ConfigurationUpdateCommand(_) => {
            FiveGmmMessageType::ConfigurationUpdateCommand
        }
        FiveGmmMessage::ConfigurationUpdateComplete => {
            FiveGmmMessageType::ConfigurationUpdateComplete
        }
        FiveGmmMessage::Notification(_) => FiveGmmMessageType::Notification,
        FiveGmmMessage::NotificationResponse(_) => FiveGmmMessageType::NotificationResponse,
        FiveGmmMessage::ControlPlaneServiceRequest(_) => {
            FiveGmmMessageType::ControlPlaneServiceRequest
        }
        FiveGmmMessage::NetworkSliceSpecificAuthenticationCommand(_) => {
            FiveGmmMessageType::NetworkSliceSpecificAuthenticationCommand
        }
        FiveGmmMessage::NetworkSliceSpecificAuthenticationComplete(_) => {
            FiveGmmMessageType::NetworkSliceSpecificAuthenticationComplete
        }
        FiveGmmMessage::NetworkSliceSpecificAuthenticationResult(_) => {
            FiveGmmMessageType::NetworkSliceSpecificAuthenticationResult
        }
    };

    // Encode header
    let header = FiveGsNasHeader::new_gmm(message_type);
    header.encode(&mut buf);

    // Encode message body
    match msg {
        FiveGmmMessage::RegistrationRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::RegistrationAccept(m) => m.encode(&mut buf),
        FiveGmmMessage::RegistrationReject(m) => m.encode(&mut buf),
        FiveGmmMessage::RegistrationComplete(m) => m.encode(&mut buf),
        FiveGmmMessage::DeregistrationRequestFromUe(m) => m.encode(&mut buf),
        FiveGmmMessage::DeregistrationAcceptFromUe => {}
        FiveGmmMessage::DeregistrationRequestToUe(m) => m.encode(&mut buf),
        FiveGmmMessage::DeregistrationAcceptToUe => {}
        FiveGmmMessage::ServiceRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::ServiceAccept(m) => m.encode(&mut buf),
        FiveGmmMessage::ServiceReject(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationResponse(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationReject(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationFailure(m) => m.encode(&mut buf),
        FiveGmmMessage::AuthenticationResult(m) => m.encode(&mut buf),
        FiveGmmMessage::IdentityRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::IdentityResponse(m) => m.encode(&mut buf),
        FiveGmmMessage::SecurityModeCommand(m) => m.encode(&mut buf),
        FiveGmmMessage::SecurityModeComplete(m) => m.encode(&mut buf),
        FiveGmmMessage::SecurityModeReject(m) => m.encode(&mut buf),
        FiveGmmMessage::FiveGmmStatus(m) => m.encode(&mut buf),
        FiveGmmMessage::UlNasTransport(m) => m.encode(&mut buf),
        FiveGmmMessage::DlNasTransport(m) => m.encode(&mut buf),
        FiveGmmMessage::ConfigurationUpdateCommand(m) => m.encode(&mut buf),
        FiveGmmMessage::ConfigurationUpdateComplete => {}
        FiveGmmMessage::Notification(m) => m.encode(&mut buf),
        FiveGmmMessage::NotificationResponse(m) => m.encode(&mut buf),
        FiveGmmMessage::ControlPlaneServiceRequest(m) => m.encode(&mut buf),
        FiveGmmMessage::NetworkSliceSpecificAuthenticationCommand(m) => m.encode(&mut buf),
        FiveGmmMessage::NetworkSliceSpecificAuthenticationComplete(m) => m.encode(&mut buf),
        FiveGmmMessage::NetworkSliceSpecificAuthenticationResult(m) => m.encode(&mut buf),
    }

    buf
}

/// Parse a 5GMM message
pub fn parse_5gmm_message(buf: &mut Bytes) -> NasResult<FiveGmmMessage> {
    let header = FiveGsNasHeader::decode(buf)?;
    // TS 24.501 §9.2 — the EPD of a 5GMM message is 0x7E; reject anything else
    // so a foreign / corrupt PDU is not mis-parsed as a 5GMM body.
    if header.extended_protocol_discriminator
        != ProtocolDiscriminator::FiveGsMobilityManagement as u8
    {
        return Err(NasError::InvalidProtocolDiscriminator(
            header.extended_protocol_discriminator,
        ));
    }
    let message_type = FiveGmmMessageType::try_from(header.message_type)?;

    match message_type {
        FiveGmmMessageType::RegistrationRequest => Ok(FiveGmmMessage::RegistrationRequest(
            RegistrationRequest::decode(buf)?,
        )),
        FiveGmmMessageType::RegistrationAccept => Ok(FiveGmmMessage::RegistrationAccept(
            RegistrationAccept::decode(buf)?,
        )),
        FiveGmmMessageType::RegistrationReject => Ok(FiveGmmMessage::RegistrationReject(
            RegistrationReject::decode(buf)?,
        )),
        FiveGmmMessageType::RegistrationComplete => Ok(FiveGmmMessage::RegistrationComplete(
            RegistrationComplete::decode(buf)?,
        )),
        FiveGmmMessageType::DeregistrationRequestFromUe => Ok(
            FiveGmmMessage::DeregistrationRequestFromUe(DeregistrationRequestFromUe::decode(buf)?),
        ),
        FiveGmmMessageType::DeregistrationAcceptFromUe => {
            Ok(FiveGmmMessage::DeregistrationAcceptFromUe)
        }
        FiveGmmMessageType::DeregistrationRequestToUe => Ok(
            FiveGmmMessage::DeregistrationRequestToUe(DeregistrationRequestToUe::decode(buf)?),
        ),
        FiveGmmMessageType::DeregistrationAcceptToUe => {
            Ok(FiveGmmMessage::DeregistrationAcceptToUe)
        }
        FiveGmmMessageType::ServiceRequest => {
            Ok(FiveGmmMessage::ServiceRequest(ServiceRequest::decode(buf)?))
        }
        FiveGmmMessageType::ServiceAccept => {
            Ok(FiveGmmMessage::ServiceAccept(ServiceAccept::decode(buf)?))
        }
        FiveGmmMessageType::ServiceReject => {
            Ok(FiveGmmMessage::ServiceReject(ServiceReject::decode(buf)?))
        }
        FiveGmmMessageType::AuthenticationRequest => Ok(FiveGmmMessage::AuthenticationRequest(
            AuthenticationRequest::decode(buf)?,
        )),
        FiveGmmMessageType::AuthenticationResponse => Ok(FiveGmmMessage::AuthenticationResponse(
            AuthenticationResponse::decode(buf)?,
        )),
        FiveGmmMessageType::AuthenticationReject => Ok(FiveGmmMessage::AuthenticationReject(
            AuthenticationReject::decode(buf)?,
        )),
        FiveGmmMessageType::AuthenticationFailure => Ok(FiveGmmMessage::AuthenticationFailure(
            AuthenticationFailure::decode(buf)?,
        )),
        FiveGmmMessageType::AuthenticationResult => Ok(FiveGmmMessage::AuthenticationResult(
            AuthenticationResult::decode(buf)?,
        )),
        FiveGmmMessageType::IdentityRequest => Ok(FiveGmmMessage::IdentityRequest(
            IdentityRequest::decode(buf)?,
        )),
        FiveGmmMessageType::IdentityResponse => Ok(FiveGmmMessage::IdentityResponse(
            IdentityResponse::decode(buf)?,
        )),
        FiveGmmMessageType::SecurityModeCommand => Ok(FiveGmmMessage::SecurityModeCommand(
            SecurityModeCommand::decode(buf)?,
        )),
        FiveGmmMessageType::SecurityModeComplete => Ok(FiveGmmMessage::SecurityModeComplete(
            SecurityModeComplete::decode(buf)?,
        )),
        FiveGmmMessageType::SecurityModeReject => Ok(FiveGmmMessage::SecurityModeReject(
            SecurityModeReject::decode(buf)?,
        )),
        FiveGmmMessageType::FiveGmmStatus => {
            Ok(FiveGmmMessage::FiveGmmStatus(FiveGmmStatus::decode(buf)?))
        }
        FiveGmmMessageType::UlNasTransport => {
            Ok(FiveGmmMessage::UlNasTransport(UlNasTransport::decode(buf)?))
        }
        FiveGmmMessageType::DlNasTransport => {
            Ok(FiveGmmMessage::DlNasTransport(DlNasTransport::decode(buf)?))
        }
        FiveGmmMessageType::ConfigurationUpdateCommand => Ok(
            FiveGmmMessage::ConfigurationUpdateCommand(ConfigurationUpdateCommand::decode(buf)?),
        ),
        FiveGmmMessageType::ConfigurationUpdateComplete => {
            Ok(FiveGmmMessage::ConfigurationUpdateComplete)
        }
        FiveGmmMessageType::Notification => {
            Ok(FiveGmmMessage::Notification(Notification::decode(buf)?))
        }
        FiveGmmMessageType::NotificationResponse => Ok(FiveGmmMessage::NotificationResponse(
            NotificationResponse::decode(buf)?,
        )),
        FiveGmmMessageType::ControlPlaneServiceRequest => Ok(
            FiveGmmMessage::ControlPlaneServiceRequest(ControlPlaneServiceRequest::decode(buf)?),
        ),
        FiveGmmMessageType::NetworkSliceSpecificAuthenticationCommand => {
            Ok(FiveGmmMessage::NetworkSliceSpecificAuthenticationCommand(
                NetworkSliceSpecificAuthenticationCommand::decode(buf)?,
            ))
        }
        FiveGmmMessageType::NetworkSliceSpecificAuthenticationComplete => {
            Ok(FiveGmmMessage::NetworkSliceSpecificAuthenticationComplete(
                NetworkSliceSpecificAuthenticationComplete::decode(buf)?,
            ))
        }
        FiveGmmMessageType::NetworkSliceSpecificAuthenticationResult => {
            Ok(FiveGmmMessage::NetworkSliceSpecificAuthenticationResult(
                NetworkSliceSpecificAuthenticationResult::decode(buf)?,
            ))
        }
    }
}

/// Parse a 5GMM PDU that may be a SECURITY PROTECTED 5GS NAS MESSAGE
/// (TS 24.501 §9.1.1, Figure 9.1.1.2). This is the AMF receive side.
///
/// - `security_header_type == 0` (plain): the buffer is an unprotected plain
///   5GMM message; delegate verbatim to [`parse_5gmm_message`].
/// - `security_header_type != 0`: the buffer is
///   `EPD(1) | SHT(1) | MAC(4) | SQN(1) | ciphered inner`. Strip the 2-octet
///   EPD+SHT header, verify (and decipher) via [`unprotect_nas_message`], then
///   recurse on the recovered plain inner message.
///
/// `ctx` is mutated: a successful unprotect advances the uplink NAS COUNT.
/// MAC mismatch returns [`NasError::MacVerificationFailed`]; a short buffer
/// returns [`NasError::BufferTooShort`]. Use [`parse_5gmm_message`] directly
/// for an already-plain message.
pub fn parse_5gmm_secured(
    buf: &mut Bytes,
    ctx: &mut NasSecurityContext,
) -> NasResult<FiveGmmMessage> {
    // Need EPD + SHT (2 octets) to read the security header type.
    if buf.remaining() < 2 {
        return Err(NasError::BufferTooShort {
            expected: 2,
            actual: buf.remaining(),
        });
    }

    // Peek the SHT from octet 2's low nibble WITHOUT advancing the cursor; the
    // plain path then re-reads the full EPD+SHT+type header.
    let sht = SecurityHeaderType::try_from(buf[1] & 0x0F)?;

    match sht {
        SecurityHeaderType::PlainNas => parse_5gmm_message(buf),
        _ => {
            // EPD+SHT+MAC+SQN (7) + a >= 3-octet inner plain message.
            if buf.remaining() < FIVEG_NAS_SECURITY_HEADER_LEN {
                return Err(NasError::BufferTooShort {
                    expected: FIVEG_NAS_SECURITY_HEADER_LEN,
                    actual: buf.remaining(),
                });
            }

            // Ciphered iff the SHT selects a ciphered codepoint (2 or 4).
            let ciphered = matches!(
                sht,
                SecurityHeaderType::IntegrityProtectedAndCiphered
                    | SecurityHeaderType::IntegrityProtectedAndCipheredWithNew5gNasSecurityContext
            );

            // AMF receive side => uplink (UE -> network).
            const DIRECTION_UPLINK: u8 = 0;

            // unprotect_nas_message expects its slice to START at the MAC, i.e.
            // wire offset 2 (past EPD+SHT): MAC(4) | SQN(1) | ciphered inner.
            let plain = unprotect_nas_message(ctx, DIRECTION_UPLINK, &buf[2..], ciphered)?;

            // Recurse on the recovered plain inner message
            // (its own EPD | SHT=0 | message type | body).
            let mut inner = Bytes::from(plain);
            parse_5gmm_message(&mut inner)
        }
    }
}

// =========================================================================
// 5GSM (5G Session Management) Messages - TS 24.501 Section 8.3
// =========================================================================

/// 5GSM message
#[derive(Debug, Clone, PartialEq)]
pub enum FiveGsmMessage {
    PduSessionEstablishmentRequest(PduSessionEstablishmentRequest),
    PduSessionEstablishmentAccept(PduSessionEstablishmentAccept),
    PduSessionEstablishmentReject(PduSessionEstablishmentReject),
    PduSessionModificationRequest(PduSessionModificationRequest),
    PduSessionModificationCommand(PduSessionModificationCommand),
    PduSessionModificationComplete,
    PduSessionModificationReject(PduSessionModificationReject),
    PduSessionModificationCommandReject(PduSessionModificationCommandReject),
    PduSessionReleaseRequest(PduSessionReleaseRequest),
    PduSessionReleaseReject(PduSessionReleaseReject),
    PduSessionReleaseCommand(PduSessionReleaseCommand),
    PduSessionReleaseComplete(PduSessionReleaseComplete),
    PduSessionAuthenticationCommand(PduSessionAuthenticationCommand),
    PduSessionAuthenticationComplete(PduSessionAuthenticationComplete),
    PduSessionAuthenticationResult(PduSessionAuthenticationResult),
    FiveGsmStatus(FiveGsmStatus),
    RemoteUeReport(RemoteUeReport),
    RemoteUeReportResponse(RemoteUeReportResponse),
}

/// PDU Session Establishment Request (TS 24.501 Section 8.3.1)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionEstablishmentRequest {
    /// Integrity protection maximum data rate
    pub integrity_protection_max_data_rate: [u8; 2],
    /// PDU session type
    pub pdu_session_type: Option<u8>,
    /// SSC mode
    pub ssc_mode: Option<u8>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
    /// SM PDU DN request container
    pub sm_pdu_dn_request_container: Option<Vec<u8>>,
}

impl PduSessionEstablishmentRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.integrity_protection_max_data_rate);
        if let Some(pst) = self.pdu_session_type {
            buf.put_u8(0x90 | (pst & 0x0F)); // IEI 9- (half-byte)
        }
        if let Some(ssc) = self.ssc_mode {
            buf.put_u8(0xA0 | (ssc & 0x0F)); // IEI A- (half-byte)
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort {
                expected: 2,
                actual: buf.remaining(),
            });
        }
        let mut ipmdr = [0u8; 2];
        buf.copy_to_slice(&mut ipmdr);
        let mut msg = Self {
            integrity_protection_max_data_rate: ipmdr,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            let iei_type = if iei >= 0x80 { iei & 0xF0 } else { iei };
            match iei_type {
                0x90 => {
                    buf.advance(1);
                    msg.pdu_session_type = Some(iei & 0x0F);
                }
                0xA0 => {
                    buf.advance(1);
                    msg.ssc_mode = Some(iei & 0x0F);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Establishment Accept (TS 24.501 Section 8.3.2)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionEstablishmentAccept {
    /// Selected PDU session type
    pub selected_pdu_session_type: u8,
    /// Selected SSC mode
    pub selected_ssc_mode: u8,
    /// Authorized QoS rules
    pub authorized_qos_rules: QosRules,
    /// Session AMBR
    pub session_ambr: SessionAmbr,
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// PDU address
    pub pdu_address: Option<PduAddress>,
    /// Authorized QoS flow descriptions
    pub authorized_qos_flow_descriptions: Option<QosFlowDescriptions>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
    /// DNN
    pub dnn: Option<Dnn>,
}

impl PduSessionEstablishmentAccept {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.selected_ssc_mode << 4) | (self.selected_pdu_session_type & 0x0F));
        self.authorized_qos_rules.encode(buf);
        self.session_ambr.encode(buf);
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref addr) = self.pdu_address {
            buf.put_u8(0x29); // IEI
            addr.encode(buf);
        }
        if let Some(ref qfd) = self.authorized_qos_flow_descriptions {
            buf.put_u8(0x79); // IEI
            qfd.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
        if let Some(ref dnn) = self.dnn {
            buf.put_u8(0x25); // IEI
            dnn.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let type_byte = buf.get_u8();
        let selected_pdu_session_type = type_byte & 0x0F;
        let selected_ssc_mode = (type_byte >> 4) & 0x0F;
        let authorized_qos_rules = QosRules::decode(buf)?;
        let session_ambr = SessionAmbr::decode(buf)?;
        let mut msg = Self {
            selected_pdu_session_type,
            selected_ssc_mode,
            authorized_qos_rules,
            session_ambr,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x29 => {
                    buf.advance(1);
                    msg.pdu_address = Some(PduAddress::decode(buf)?);
                }
                0x79 => {
                    buf.advance(1);
                    msg.authorized_qos_flow_descriptions = Some(QosFlowDescriptions::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x25 => {
                    buf.advance(1);
                    msg.dnn = Some(Dnn::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Establishment Reject (TS 24.501 Section 8.3.3)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionEstablishmentReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionEstablishmentReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self {
            gsm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Request (TS 24.501 Section 8.3.7)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationRequest {
    /// Requested QoS rules
    pub requested_qos_rules: Option<QosRules>,
    /// Requested QoS flow descriptions
    pub requested_qos_flow_descriptions: Option<QosFlowDescriptions>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionModificationRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref qr) = self.requested_qos_rules {
            buf.put_u8(0x7A); // IEI
            qr.encode(buf);
        }
        if let Some(ref qfd) = self.requested_qos_flow_descriptions {
            buf.put_u8(0x79); // IEI
            qfd.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7A => {
                    buf.advance(1);
                    msg.requested_qos_rules = Some(QosRules::decode(buf)?);
                }
                0x79 => {
                    buf.advance(1);
                    msg.requested_qos_flow_descriptions = Some(QosFlowDescriptions::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Command (TS 24.501 Section 8.3.9)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationCommand {
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// Session AMBR
    pub session_ambr: Option<SessionAmbr>,
    /// Authorized QoS rules
    pub authorized_qos_rules: Option<QosRules>,
    /// Authorized QoS flow descriptions
    pub authorized_qos_flow_descriptions: Option<QosFlowDescriptions>,
}

impl PduSessionModificationCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref ambr) = self.session_ambr {
            buf.put_u8(0x2A); // IEI
            ambr.encode(buf);
        }
        if let Some(ref qr) = self.authorized_qos_rules {
            buf.put_u8(0x7A); // IEI
            qr.encode(buf);
        }
        if let Some(ref qfd) = self.authorized_qos_flow_descriptions {
            buf.put_u8(0x79); // IEI
            qfd.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x2A => {
                    buf.advance(1);
                    msg.session_ambr = Some(SessionAmbr::decode(buf)?);
                }
                0x7A => {
                    buf.advance(1);
                    msg.authorized_qos_rules = Some(QosRules::decode(buf)?);
                }
                0x79 => {
                    buf.advance(1);
                    msg.authorized_qos_flow_descriptions = Some(QosFlowDescriptions::decode(buf)?);
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Reject (TS 24.501 Section 8.3.8)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionModificationReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self {
            gsm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Modification Command Reject (TS 24.501 Section 8.3.10)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionModificationCommandReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionModificationCommandReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self {
            gsm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Request (TS 24.501 Section 8.3.12)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseRequest {
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Reject (TS 24.501 Section 8.3.13)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseReject {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseReject {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self {
            gsm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Command (TS 24.501 Section 8.3.14)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseCommand {
    /// 5GSM cause
    pub gsm_cause: u8,
    /// Back-off timer value
    pub back_off_timer_value: Option<GprsTimer3>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
        if let Some(ref timer) = self.back_off_timer_value {
            buf.put_u8(0x37); // IEI
            timer.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let gsm_cause = buf.get_u8();
        let mut msg = Self {
            gsm_cause,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x37 => {
                    buf.advance(1);
                    msg.back_off_timer_value = Some(GprsTimer3::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Release Complete (TS 24.501 Section 8.3.15)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionReleaseComplete {
    /// 5GSM cause
    pub gsm_cause: Option<u8>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionReleaseComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(cause) = self.gsm_cause {
            buf.put_u8(0x59); // IEI
            buf.put_u8(cause);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x59 => {
                    buf.advance(1);
                    if buf.remaining() >= 1 {
                        msg.gsm_cause = Some(buf.get_u8());
                    }
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// 5GSM Status message (TS 24.501 Section 8.3.16)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FiveGsmStatus {
    /// 5GSM cause
    pub gsm_cause: u8,
}

impl FiveGsmStatus {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.gsm_cause);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        Ok(Self {
            gsm_cause: buf.get_u8(),
        })
    }
}

/// PDU Session Authentication Command (TS 24.501 Section 8.3.4)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionAuthenticationCommand {
    /// EAP message
    pub eap_message: EapMessage,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionAuthenticationCommand {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.eap_message.encode(buf);
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let eap_message = EapMessage::decode(buf)?;
        let mut msg = Self {
            eap_message,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Authentication Complete (TS 24.501 Section 8.3.5)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionAuthenticationComplete {
    /// EAP message
    pub eap_message: EapMessage,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionAuthenticationComplete {
    pub fn encode(&self, buf: &mut BytesMut) {
        self.eap_message.encode(buf);
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let eap_message = EapMessage::decode(buf)?;
        let mut msg = Self {
            eap_message,
            ..Default::default()
        };
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// PDU Session Authentication Result (TS 24.501 Section 8.3.6)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PduSessionAuthenticationResult {
    /// EAP message
    pub eap_message: Option<EapMessage>,
    /// Extended protocol configuration options
    pub extended_pco: Option<Vec<u8>>,
}

impl PduSessionAuthenticationResult {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref eap) = self.eap_message {
            buf.put_u8(0x78); // IEI
            eap.encode(buf);
        }
        if let Some(ref epco) = self.extended_pco {
            buf.put_u8(0x7B); // IEI
            buf.put_u16(epco.len() as u16);
            buf.put_slice(epco);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x78 => {
                    buf.advance(1);
                    msg.eap_message = Some(EapMessage::decode(buf)?);
                }
                0x7B => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.extended_pco = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Remote UE Report (TS 24.501 Section 8.3.17)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RemoteUeReport {
    /// Remote UE context connected
    pub remote_ue_context_connected: Option<Vec<u8>>,
    /// Remote UE context disconnected
    pub remote_ue_context_disconnected: Option<Vec<u8>>,
}

impl RemoteUeReport {
    pub fn encode(&self, buf: &mut BytesMut) {
        if let Some(ref connected) = self.remote_ue_context_connected {
            buf.put_u8(0x79); // IEI
            buf.put_u16(connected.len() as u16);
            buf.put_slice(connected);
        }
        if let Some(ref disconnected) = self.remote_ue_context_disconnected {
            buf.put_u8(0x7A); // IEI
            buf.put_u16(disconnected.len() as u16);
            buf.put_slice(disconnected);
        }
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let mut msg = Self::default();
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            match iei {
                0x79 => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.remote_ue_context_connected = Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                0x7A => {
                    buf.advance(1);
                    if buf.remaining() >= 2 {
                        let len = buf.get_u16() as usize;
                        if buf.remaining() >= len {
                            msg.remote_ue_context_disconnected =
                                Some(buf.copy_to_bytes(len).to_vec());
                        }
                    }
                }
                _ => skip_unknown_ie(buf, iei)?,
            }
        }
        Ok(msg)
    }
}

/// Remote UE Report Response (TS 24.501 Section 8.3.18)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RemoteUeReportResponse;

impl RemoteUeReportResponse {
    pub fn encode(&self, _buf: &mut BytesMut) {
        // No mandatory IEs
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        // Skip any optional IEs (type-aware, per TS 24.501 §7.6.1 / TS 24.007).
        while buf.remaining() > 0 {
            let iei = buf.chunk()[0];
            skip_unknown_ie(buf, iei)?;
        }
        Ok(Self)
    }
}

/// Build a 5GSM message with header
pub fn build_5gsm_message(pdu_session_id: u8, pti: u8, msg: &FiveGsmMessage) -> BytesMut {
    let mut buf = BytesMut::new();

    let message_type = match msg {
        FiveGsmMessage::PduSessionEstablishmentRequest(_) => {
            FiveGsmMessageType::PduSessionEstablishmentRequest
        }
        FiveGsmMessage::PduSessionEstablishmentAccept(_) => {
            FiveGsmMessageType::PduSessionEstablishmentAccept
        }
        FiveGsmMessage::PduSessionEstablishmentReject(_) => {
            FiveGsmMessageType::PduSessionEstablishmentReject
        }
        FiveGsmMessage::PduSessionModificationRequest(_) => {
            FiveGsmMessageType::PduSessionModificationRequest
        }
        FiveGsmMessage::PduSessionModificationCommand(_) => {
            FiveGsmMessageType::PduSessionModificationCommand
        }
        FiveGsmMessage::PduSessionModificationComplete => {
            FiveGsmMessageType::PduSessionModificationComplete
        }
        FiveGsmMessage::PduSessionModificationReject(_) => {
            FiveGsmMessageType::PduSessionModificationReject
        }
        FiveGsmMessage::PduSessionModificationCommandReject(_) => {
            FiveGsmMessageType::PduSessionModificationCommandReject
        }
        FiveGsmMessage::PduSessionReleaseRequest(_) => FiveGsmMessageType::PduSessionReleaseRequest,
        FiveGsmMessage::PduSessionReleaseReject(_) => FiveGsmMessageType::PduSessionReleaseReject,
        FiveGsmMessage::PduSessionReleaseCommand(_) => FiveGsmMessageType::PduSessionReleaseCommand,
        FiveGsmMessage::PduSessionReleaseComplete(_) => {
            FiveGsmMessageType::PduSessionReleaseComplete
        }
        FiveGsmMessage::PduSessionAuthenticationCommand(_) => {
            FiveGsmMessageType::PduSessionAuthenticationCommand
        }
        FiveGsmMessage::PduSessionAuthenticationComplete(_) => {
            FiveGsmMessageType::PduSessionAuthenticationComplete
        }
        FiveGsmMessage::PduSessionAuthenticationResult(_) => {
            FiveGsmMessageType::PduSessionAuthenticationResult
        }
        FiveGsmMessage::FiveGsmStatus(_) => FiveGsmMessageType::FiveGsmStatus,
        FiveGsmMessage::RemoteUeReport(_) => FiveGsmMessageType::RemoteUeReport,
        FiveGsmMessage::RemoteUeReportResponse(_) => FiveGsmMessageType::RemoteUeReportResponse,
    };

    let header = FiveGsNasHeader::new_gsm(pdu_session_id, pti, message_type);
    header.encode(&mut buf);

    match msg {
        FiveGsmMessage::PduSessionEstablishmentRequest(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionEstablishmentAccept(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionEstablishmentReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationRequest(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationCommand(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationComplete => {}
        FiveGsmMessage::PduSessionModificationReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionModificationCommandReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseRequest(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseReject(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseCommand(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionReleaseComplete(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionAuthenticationCommand(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionAuthenticationComplete(m) => m.encode(&mut buf),
        FiveGsmMessage::PduSessionAuthenticationResult(m) => m.encode(&mut buf),
        FiveGsmMessage::FiveGsmStatus(m) => m.encode(&mut buf),
        FiveGsmMessage::RemoteUeReport(m) => m.encode(&mut buf),
        FiveGsmMessage::RemoteUeReportResponse(m) => m.encode(&mut buf),
    }

    buf
}

/// Parse a 5GSM message
pub fn parse_5gsm_message(buf: &mut Bytes) -> NasResult<(u8, u8, FiveGsmMessage)> {
    let header = FiveGsNasSmHeader::decode(buf)?;
    // TS 24.501 §9.2 — the EPD of a 5GSM message is 0x2E; reject anything else
    // so a foreign / corrupt PDU is not mis-parsed as a 5GSM body.
    if header.extended_protocol_discriminator
        != ProtocolDiscriminator::FiveGsSessionManagement as u8
    {
        return Err(NasError::InvalidProtocolDiscriminator(
            header.extended_protocol_discriminator,
        ));
    }
    let message_type = FiveGsmMessageType::try_from(header.message_type)?;

    let msg = match message_type {
        FiveGsmMessageType::PduSessionEstablishmentRequest => {
            FiveGsmMessage::PduSessionEstablishmentRequest(PduSessionEstablishmentRequest::decode(
                buf,
            )?)
        }
        FiveGsmMessageType::PduSessionEstablishmentAccept => {
            FiveGsmMessage::PduSessionEstablishmentAccept(PduSessionEstablishmentAccept::decode(
                buf,
            )?)
        }
        FiveGsmMessageType::PduSessionEstablishmentReject => {
            FiveGsmMessage::PduSessionEstablishmentReject(PduSessionEstablishmentReject::decode(
                buf,
            )?)
        }
        FiveGsmMessageType::PduSessionModificationRequest => {
            FiveGsmMessage::PduSessionModificationRequest(PduSessionModificationRequest::decode(
                buf,
            )?)
        }
        FiveGsmMessageType::PduSessionModificationCommand => {
            FiveGsmMessage::PduSessionModificationCommand(PduSessionModificationCommand::decode(
                buf,
            )?)
        }
        FiveGsmMessageType::PduSessionModificationComplete => {
            FiveGsmMessage::PduSessionModificationComplete
        }
        FiveGsmMessageType::PduSessionModificationReject => {
            FiveGsmMessage::PduSessionModificationReject(PduSessionModificationReject::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionModificationCommandReject => {
            FiveGsmMessage::PduSessionModificationCommandReject(
                PduSessionModificationCommandReject::decode(buf)?,
            )
        }
        FiveGsmMessageType::PduSessionReleaseRequest => {
            FiveGsmMessage::PduSessionReleaseRequest(PduSessionReleaseRequest::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionReleaseReject => {
            FiveGsmMessage::PduSessionReleaseReject(PduSessionReleaseReject::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionReleaseCommand => {
            FiveGsmMessage::PduSessionReleaseCommand(PduSessionReleaseCommand::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionReleaseComplete => {
            FiveGsmMessage::PduSessionReleaseComplete(PduSessionReleaseComplete::decode(buf)?)
        }
        FiveGsmMessageType::PduSessionAuthenticationCommand => {
            FiveGsmMessage::PduSessionAuthenticationCommand(
                PduSessionAuthenticationCommand::decode(buf)?,
            )
        }
        FiveGsmMessageType::PduSessionAuthenticationComplete => {
            FiveGsmMessage::PduSessionAuthenticationComplete(
                PduSessionAuthenticationComplete::decode(buf)?,
            )
        }
        FiveGsmMessageType::PduSessionAuthenticationResult => {
            FiveGsmMessage::PduSessionAuthenticationResult(PduSessionAuthenticationResult::decode(
                buf,
            )?)
        }
        FiveGsmMessageType::FiveGsmStatus => {
            FiveGsmMessage::FiveGsmStatus(FiveGsmStatus::decode(buf)?)
        }
        FiveGsmMessageType::RemoteUeReport => {
            FiveGsmMessage::RemoteUeReport(RemoteUeReport::decode(buf)?)
        }
        FiveGsmMessageType::RemoteUeReportResponse => {
            FiveGsmMessage::RemoteUeReportResponse(RemoteUeReportResponse::decode(buf)?)
        }
    };

    Ok((
        header.pdu_session_id,
        header.procedure_transaction_identity,
        msg,
    ))
}

#[cfg(test)]
mod nas05_tests {
    use super::*;

    #[test]
    fn test_skip_unknown_ie_type1_consumes_one_octet() {
        // Type-1/2 (IEI >= 0x80): exactly 1 octet, no length, no value.
        let mut buf = Bytes::from(vec![0xB0, 0x58, 0x2A]);
        skip_unknown_ie(&mut buf, 0xB0).unwrap();
        assert_eq!(buf.remaining(), 2);
        assert_eq!(buf.chunk()[0], 0x58);
    }

    #[test]
    fn test_skip_unknown_ie_type4_tlv() {
        // Type-4 (IEI < 0x80): IEI + 1-octet length + len value octets.
        let mut buf = Bytes::from(vec![0x4A, 0x02, 0xAA, 0xBB, 0x58]);
        skip_unknown_ie(&mut buf, 0x4A).unwrap();
        assert_eq!(buf.remaining(), 1);
        assert_eq!(buf.chunk()[0], 0x58);
    }

    #[test]
    fn test_skip_unknown_ie_truncated_tlv_clamps() {
        // Malformed length > remaining: clamp and terminate, no panic.
        let mut buf = Bytes::from(vec![0x4A, 0x05, 0xAA]);
        skip_unknown_ie(&mut buf, 0x4A).unwrap();
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_unknown_type1_ie_does_not_desync_trailing_tv() {
        // DlNasTransport whose only optional IE is the gmm_cause TV (0x58 + 1).
        let msg = DlNasTransport {
            payload_container_type: PayloadContainerType::N1SmInformation,
            payload_container: PayloadContainer::new(vec![0x01]),
            pdu_session_id: None,
            additional_information: None,
            gmm_cause: Some(0x2A),
            back_off_timer_value: None,
        };
        let encoded = build_5gmm_message(&FiveGmmMessage::DlNasTransport(msg)).freeze();

        // Splice an unknown type-1 IE (0xB0) immediately before the trailing
        // gmm_cause TV. With the old length-assuming skip the parser read 0x58
        // as a length and dropped the cause; the type-aware skip consumes the
        // 0xB0 in one octet so the cause still decodes.
        let mut spliced = encoded.to_vec();
        let cut = spliced.len() - 2; // index of the 0x58 IEI
        assert_eq!(spliced[cut], 0x58, "gmm_cause TV must be the last IE");
        spliced.insert(cut, 0xB0);

        let parsed = parse_5gmm_message(&mut Bytes::from(spliced)).unwrap();
        match parsed {
            FiveGmmMessage::DlNasTransport(m) => assert_eq!(m.gmm_cause, Some(0x2A)),
            other => panic!("expected DlNasTransport, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod nas04_tests {
    use super::*;
    use crate::common::security::protect_nas_message;

    fn ctx() -> NasSecurityContext {
        NasSecurityContext::new(
            SecurityAlgorithms {
                ciphering: SecurityAlgorithms::CIPHERING_NONE,
                integrity: SecurityAlgorithms::INTEGRITY_128_EIA2,
            },
            [0x11; 16],
            [0x22; 16],
        )
    }

    /// Build the wire PDU `EPD | SHT | MAC | SQN | inner` for a plain inner
    /// 5GMM message protected (integrity-only) uplink.
    fn protect_wire(inner: &[u8], sht: u8) -> Vec<u8> {
        let mut tx = ctx();
        let protected = protect_nas_message(&mut tx, 0, inner, false).unwrap();
        let mut wire = BytesMut::new();
        wire.put_u8(0x7e); // EPD = 5GMM
        wire.put_u8(sht);
        wire.put_slice(&protected);
        wire.to_vec()
    }

    #[test]
    fn test_parse_5gmm_secured_roundtrip() {
        let original = FiveGmmMessage::SecurityModeComplete(SecurityModeComplete::default());
        let inner = build_5gmm_message(&original).freeze(); // EPD|SHT0|type|body
        let wire = protect_wire(&inner, 0x01); // SHT = IntegrityProtected
        let mut rx = ctx();
        let recovered = parse_5gmm_secured(&mut Bytes::from(wire), &mut rx).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_parse_5gmm_secured_plain_passthrough() {
        // SHT == 0 behaves exactly like parse_5gmm_message.
        let msg = FiveGmmMessage::SecurityModeComplete(SecurityModeComplete::default());
        let bytes = build_5gmm_message(&msg).freeze();
        let mut rx = ctx();
        let via_secured = parse_5gmm_secured(&mut bytes.clone(), &mut rx).unwrap();
        let via_plain = parse_5gmm_message(&mut bytes.clone()).unwrap();
        assert_eq!(via_secured, via_plain);
        assert_eq!(via_secured, msg);
    }

    #[test]
    fn test_parse_5gmm_secured_mac_tamper_rejected() {
        let original = FiveGmmMessage::SecurityModeComplete(SecurityModeComplete::default());
        let inner = build_5gmm_message(&original).freeze();
        let mut wire = protect_wire(&inner, 0x01);
        wire[2] ^= 0xFF; // tamper the first MAC octet (wire offset 2)
        let mut rx = ctx();
        assert!(matches!(
            parse_5gmm_secured(&mut Bytes::from(wire), &mut rx),
            Err(NasError::MacVerificationFailed)
        ));
    }

    #[test]
    fn test_parse_5gmm_secured_short_buffer() {
        // SHT != 0 but fewer than the 7-octet protected header.
        let bytes = Bytes::from(vec![0x7e, 0x01, 0x00, 0x00]);
        let mut rx = ctx();
        assert!(matches!(
            parse_5gmm_secured(&mut bytes.clone(), &mut rx),
            Err(NasError::BufferTooShort { .. })
        ));
    }
}

#[cfg(test)]
mod nas08_tests {
    //! TS 24.501 §9.2 — the parse entrypoints must reject a NAS PDU whose
    //! Extended Protocol Discriminator is neither 0x7E (5GMM) nor 0x2E (5GSM),
    //! instead of mis-parsing its body.
    use super::*;

    #[test]
    fn test_valid_5gmm_epd_still_parses() {
        // A well-formed 5GMM message (EPD = 0x7E) round-trips unchanged.
        let original = FiveGmmMessage::SecurityModeComplete(SecurityModeComplete::default());
        let bytes = build_5gmm_message(&original).freeze();
        assert_eq!(bytes[0], 0x7e, "5GMM EPD must be 0x7E on the wire");
        let parsed = parse_5gmm_message(&mut bytes.clone()).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_bogus_epd_5gmm_rejected() {
        // Same valid body, but the EPD octet is corrupted to a bogus value:
        // the parser must reject it rather than mis-parse the body.
        let original = FiveGmmMessage::SecurityModeComplete(SecurityModeComplete::default());
        let valid = build_5gmm_message(&original).freeze();

        for bogus in [0x00u8, 0xFF] {
            let mut bytes = valid.to_vec();
            bytes[0] = bogus; // overwrite the EPD octet only
            assert!(
                matches!(
                    parse_5gmm_message(&mut Bytes::from(bytes)),
                    Err(NasError::InvalidProtocolDiscriminator(b)) if b == bogus
                ),
                "EPD 0x{bogus:02x} must be rejected by parse_5gmm_message"
            );
        }
    }

    #[test]
    fn test_valid_5gsm_epd_still_parses_and_bogus_rejected() {
        // 5GSM (EPD = 0x2E) symmetry: valid parses, bogus EPD rejected.
        let msg = FiveGsmMessage::PduSessionReleaseComplete(PduSessionReleaseComplete::default());
        let valid = build_5gsm_message(5, 1, &msg).freeze();
        assert_eq!(valid[0], 0x2e, "5GSM EPD must be 0x2E on the wire");
        let (psi, pti, parsed) = parse_5gsm_message(&mut valid.clone()).unwrap();
        assert_eq!((psi, pti), (5, 1));
        assert_eq!(parsed, msg);

        let mut bytes = valid.to_vec();
        bytes[0] = 0x7e; // a valid-but-wrong EPD (5GMM) for a 5GSM entrypoint
        assert!(matches!(
            parse_5gsm_message(&mut Bytes::from(bytes)),
            Err(NasError::InvalidProtocolDiscriminator(0x7e))
        ));
    }
}

#[cfg(test)]
mod tlv_e_skip_tests {
    //! TS 24.501 §9.11.3.33 / §4.4.6 / TS 24.007 §11.2.5 — TLV-E IEs carry a
    //! 2-octet length; the unknown-IE skipper must consume that correctly, and
    //! REGISTRATION REQUEST must model the NAS message container (IEI 0x71) so
    //! the cleartext-IE initial registration flow round-trips.
    use super::*;

    #[test]
    fn test_registration_request_nas_message_container_roundtrip() {
        let inner = vec![0xAA; 300]; // >255 so a 1-octet length would truncate
        let mut rr = RegistrationRequest {
            mobile_identity: MobileIdentity::default(),
            ..Default::default()
        };
        rr.nas_message_container = Some(NasMessageContainer::new(inner.clone()));

        let mut buf = BytesMut::new();
        rr.encode(&mut buf);
        // IEI 0x71 present with a 2-octet big-endian length (300 = 0x012C).
        let pos = buf
            .windows(3)
            .position(|w| w == [0x71, 0x01, 0x2C])
            .expect("NAS message container must use IEI 0x71 + 2-octet length");
        assert!(pos > 0);

        let mut b = buf.freeze();
        let decoded = RegistrationRequest::decode(&mut b).unwrap();
        assert_eq!(decoded.nas_message_container.map(|c| c.data), Some(inner));
    }

    #[test]
    fn test_skip_unknown_tlv_e_ie_does_not_desync() {
        // Build an RR whose optional-IE area is: an UNKNOWN TLV-E IE (0x74, a
        // TLV-E IEI not modelled here) with a 2-octet length, followed by a
        // known 1-octet UE-status IE (0x2B). If the skipper mis-reads the TLV-E
        // length as 1 octet it desyncs and never sees the UE-status IE.
        let mut buf = BytesMut::new();
        // Registration type/ngKSI + a minimal mobile identity (NO-IDENTITY),
        // encoded LV-E: 2-octet length then the type octet.
        buf.put_u8(0x01);
        buf.put_u16(1); // mobile identity length = 1 (2-octet length field)
        buf.put_u8(0x00); // NO-IDENTITY type octet
                          // Unknown TLV-E IE 0x74, length 0x0003, 3 value octets
        buf.put_u8(0x74);
        buf.put_u16(3);
        buf.put_slice(&[0xDE, 0xAD, 0xBE]);
        // Known UE-status IE (0x2B, len 1, value 1)
        buf.put_u8(0x2B);
        buf.put_u8(1);
        buf.put_u8(0x01);

        let mut b = buf.freeze();
        let decoded = RegistrationRequest::decode(&mut b).unwrap();
        assert_eq!(
            decoded.ue_status,
            Some(0x01),
            "UE-status IE after an unknown TLV-E IE must still be parsed"
        );
    }

    #[test]
    fn test_is_tlv_e_iei_classification() {
        for iei in [0x71u8, 0x77, 0x78, 0x79, 0x7B, 0x7C] {
            assert!(is_tlv_e_iei(iei), "0x{iei:02x} is a TLV-E IEI");
        }
        for iei in [0x40u8, 0x50, 0x2E, 0x2B, 0x80, 0xC0] {
            assert!(!is_tlv_e_iei(iei), "0x{iei:02x} is not TLV-E");
        }
    }
}
