//! EAP-AKA' Authentication Protocol (TS 33.501)
//!
//! Implements the EAP-AKA' (Extensible Authentication Protocol - Authentication
//! and Key Agreement Prime) for 5G networks as specified in:
//! - 3GPP TS 33.501 (5G Security Architecture)
//! - RFC 9048 (EAP-AKA')
//! - RFC 5448 (EAP-AKA' improvements)
//!
//! EAP-AKA' is one of two primary authentication methods in 5G (alongside 5G-AKA).
//! It is derived from EAP-AKA but uses HMAC-SHA-256 for key derivation instead of
//! the original SHA-1 based KDF, providing stronger security guarantees.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// EAP Packet Types
// ============================================================================

/// EAP packet code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

impl EapCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Success),
            4 => Some(Self::Failure),
            _ => None,
        }
    }
}

/// EAP method type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapType {
    Identity = 1,
    Notification = 2,
    Nak = 3,
    AkaPrime = 50,
}

impl EapType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Identity),
            2 => Some(Self::Notification),
            3 => Some(Self::Nak),
            50 => Some(Self::AkaPrime),
            _ => None,
        }
    }
}

/// EAP-AKA' subtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AkaPrimeSubtype {
    Challenge = 1,
    AuthenticationReject = 2,
    SynchronizationFailure = 4,
    Identity = 5,
    Notification = 12,
    ReauthenticationReq = 13,
    ClientError = 14,
}

impl AkaPrimeSubtype {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Challenge),
            2 => Some(Self::AuthenticationReject),
            4 => Some(Self::SynchronizationFailure),
            5 => Some(Self::Identity),
            12 => Some(Self::Notification),
            13 => Some(Self::ReauthenticationReq),
            14 => Some(Self::ClientError),
            _ => None,
        }
    }
}

/// EAP-AKA' attribute type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AkaPrimeAttribute {
    AtRand = 1,
    AtAutn = 2,
    AtRes = 3,
    AtAuts = 4,
    AtMac = 11,
    AtNotification = 12,
    AtIdentity = 14,
    AtKdfInput = 23,
    AtKdf = 24,
    AtCheckcode = 134,
    AtResultInd = 135,
}

impl AkaPrimeAttribute {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::AtRand),
            2 => Some(Self::AtAutn),
            3 => Some(Self::AtRes),
            4 => Some(Self::AtAuts),
            11 => Some(Self::AtMac),
            12 => Some(Self::AtNotification),
            14 => Some(Self::AtIdentity),
            23 => Some(Self::AtKdfInput),
            24 => Some(Self::AtKdf),
            134 => Some(Self::AtCheckcode),
            135 => Some(Self::AtResultInd),
            _ => None,
        }
    }
}

// ============================================================================
// EAP-AKA' Message Encoding/Decoding
// ============================================================================

/// An EAP packet (RFC 3748).
#[derive(Debug, Clone)]
pub struct EapPacket {
    /// Code (Request/Response/Success/Failure)
    pub code: EapCode,
    /// Identifier (used to match request/response)
    pub identifier: u8,
    /// EAP method type (only for Request/Response)
    pub eap_type: Option<EapType>,
    /// AKA' subtype (only for AKA' method)
    pub subtype: Option<AkaPrimeSubtype>,
    /// AKA' attributes
    pub attributes: Vec<(u8, Vec<u8>)>,
}

impl EapPacket {
    /// Create a new EAP-AKA' Challenge request.
    pub fn new_aka_challenge(
        identifier: u8,
        rand: &[u8; 16],
        autn: &[u8; 16],
        kdf_input: &str,
        mac: &[u8; 16],
    ) -> Self {
        let mut attrs = Vec::new();

        // AT_RAND (type=1, length=5 words, 2 reserved + 16 bytes RAND)
        let mut rand_attr = vec![0u8; 18]; // 2 reserved + 16 RAND
        rand_attr[2..18].copy_from_slice(rand);
        attrs.push((AkaPrimeAttribute::AtRand as u8, rand_attr));

        // AT_AUTN (type=2, length=5 words, 2 reserved + 16 bytes AUTN)
        let mut autn_attr = vec![0u8; 18];
        autn_attr[2..18].copy_from_slice(autn);
        attrs.push((AkaPrimeAttribute::AtAutn as u8, autn_attr));

        // AT_KDF_INPUT (type=23, serving network name)
        let kdf_bytes = kdf_input.as_bytes();
        let mut kdf_attr = Vec::with_capacity(2 + kdf_bytes.len());
        let kdf_len = kdf_bytes.len() as u16;
        kdf_attr.extend_from_slice(&kdf_len.to_be_bytes());
        kdf_attr.extend_from_slice(kdf_bytes);
        // Pad to 4-byte boundary
        while kdf_attr.len() % 4 != 2 {
            kdf_attr.push(0);
        }
        attrs.push((AkaPrimeAttribute::AtKdfInput as u8, kdf_attr));

        // AT_KDF (type=24, KDF identifier = 1 for HMAC-SHA-256)
        attrs.push((AkaPrimeAttribute::AtKdf as u8, vec![0, 1]));

        // AT_MAC (type=11, length=5 words, 2 reserved + 16 bytes MAC)
        let mut mac_attr = vec![0u8; 18];
        mac_attr[2..18].copy_from_slice(mac);
        attrs.push((AkaPrimeAttribute::AtMac as u8, mac_attr));

        Self {
            code: EapCode::Request,
            identifier,
            eap_type: Some(EapType::AkaPrime),
            subtype: Some(AkaPrimeSubtype::Challenge),
            attributes: attrs,
        }
    }

    /// Create an EAP-Success packet.
    pub fn new_success(identifier: u8) -> Self {
        Self {
            code: EapCode::Success,
            identifier,
            eap_type: None,
            subtype: None,
            attributes: Vec::new(),
        }
    }

    /// Create an EAP-Failure packet.
    pub fn new_failure(identifier: u8) -> Self {
        Self {
            code: EapCode::Failure,
            identifier,
            eap_type: None,
            subtype: None,
            attributes: Vec::new(),
        }
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self.code {
            EapCode::Success | EapCode::Failure => {
                // Success/Failure: Code(1) + Identifier(1) + Length(2) = 4 bytes
                let mut buf = Vec::with_capacity(4);
                buf.push(self.code as u8);
                buf.push(self.identifier);
                buf.extend_from_slice(&4u16.to_be_bytes());
                buf
            }
            _ => {
                // Request/Response with AKA' data
                // EAP header: Code(1) + ID(1) + Length(2) + Type(1) + Subtype(1) + Reserved(2)
                let mut data = Vec::new();

                // Encode attributes
                for (attr_type, attr_data) in &self.attributes {
                    let attr_len = (attr_data.len() + 2).div_ceil(4) as u8; // in 4-byte words
                    data.push(*attr_type);
                    data.push(attr_len);
                    data.extend_from_slice(attr_data);
                    // Pad to 4-byte boundary
                    while data.len() % 4 != 0 {
                        data.push(0);
                    }
                }

                let total_len = 8 + data.len(); // 4 (EAP header) + 1 (type) + 1 (subtype) + 2 (reserved) + data
                let mut buf = Vec::with_capacity(total_len);
                buf.push(self.code as u8);
                buf.push(self.identifier);
                buf.extend_from_slice(&(total_len as u16).to_be_bytes());
                buf.push(self.eap_type.unwrap_or(EapType::AkaPrime) as u8);
                buf.push(self.subtype.unwrap_or(AkaPrimeSubtype::Challenge) as u8);
                buf.extend_from_slice(&[0u8; 2]); // Reserved
                buf.extend_from_slice(&data);
                buf
            }
        }
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let code = EapCode::from_u8(data[0])?;
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < length {
            return None;
        }

        match code {
            EapCode::Success | EapCode::Failure => Some(Self {
                code,
                identifier,
                eap_type: None,
                subtype: None,
                attributes: Vec::new(),
            }),
            _ => {
                if length < 8 {
                    return None;
                }
                let eap_type = EapType::from_u8(data[4])?;
                let subtype = AkaPrimeSubtype::from_u8(data[5])?;

                // Parse attributes
                let mut attributes = Vec::new();
                let mut offset = 8;
                while offset + 2 <= length {
                    let attr_type = data[offset];
                    let attr_len_words = data[offset + 1] as usize;
                    let attr_len_bytes = attr_len_words * 4;
                    if offset + attr_len_bytes > length {
                        break;
                    }
                    let attr_data = data[offset + 2..offset + attr_len_bytes].to_vec();
                    attributes.push((attr_type, attr_data));
                    offset += attr_len_bytes;
                }

                Some(Self {
                    code,
                    identifier,
                    eap_type: Some(eap_type),
                    subtype: Some(subtype),
                    attributes,
                })
            }
        }
    }

    /// Find an attribute by type.
    pub fn find_attribute(&self, attr_type: AkaPrimeAttribute) -> Option<&[u8]> {
        let type_val = attr_type as u8;
        self.attributes
            .iter()
            .find(|(t, _)| *t == type_val)
            .map(|(_, data)| data.as_slice())
    }
}

// ============================================================================
// EAP-AKA' Key Derivation (CK', IK')
// ============================================================================

/// Derive CK' and IK' from CK, IK, and serving network name per TS 33.501 Annex A.
///
/// Uses HMAC-SHA-256 based KDF as specified in RFC 5448 Section 3.3.
/// Key = CK || IK
/// S = FC || SN_name || len(SN_name) || SQN xor AK || len(SQN xor AK)
/// where FC = 0x20 for EAP-AKA'
///
/// Returns (CK', IK') each 16 bytes.
pub fn derive_ck_ik_prime(
    ck: &[u8; 16],
    ik: &[u8; 16],
    serving_network_name: &str,
    sqn_xor_ak: &[u8; 6],
) -> ([u8; 16], [u8; 16]) {
    // Key = CK || IK
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);

    // Build S parameter: FC(1) || SN_name || len(SN_name)(2) || SQN_xor_AK || len(SQN_xor_AK)(2)
    let sn_bytes = serving_network_name.as_bytes();
    let sn_len = sn_bytes.len() as u16;

    let mut s = Vec::with_capacity(1 + sn_bytes.len() + 2 + 6 + 2);
    s.push(0x20); // FC for EAP-AKA' CK'/IK' derivation
    s.extend_from_slice(sn_bytes);
    s.extend_from_slice(&sn_len.to_be_bytes());
    s.extend_from_slice(sqn_xor_ak);
    s.extend_from_slice(&6u16.to_be_bytes());

    // HMAC-SHA-256
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(&s);
    let result = mac.finalize().into_bytes();

    // CK' = first 16 bytes, IK' = last 16 bytes
    let mut ck_prime = [0u8; 16];
    let mut ik_prime = [0u8; 16];
    ck_prime.copy_from_slice(&result[..16]);
    ik_prime.copy_from_slice(&result[16..]);

    (ck_prime, ik_prime)
}

/// Derive KAUSF from CK' and IK' for EAP-AKA' per TS 33.501 Annex A.2.
///
/// For EAP-AKA': KAUSF = KDF(CK'||IK', FC=0x6A, SN name, SQN xor AK)
pub fn derive_kausf_eap(
    ck_prime: &[u8; 16],
    ik_prime: &[u8; 16],
    serving_network_name: &str,
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    ogs_crypt::kdf::ogs_kdf_kausf(ck_prime, ik_prime, serving_network_name, sqn_xor_ak)
}

/// Compute AT_MAC for EAP-AKA' message using K_aut.
///
/// K_aut is derived from the master session key (MSK) during EAP-AKA' key generation.
/// MAC = HMAC-SHA-256-128(K_aut, EAP_packet)
/// (Truncated to 16 bytes)
pub fn compute_mac(k_aut: &[u8; 32], eap_data: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(k_aut).expect("HMAC can take key of any size");
    mac.update(eap_data);
    let result = mac.finalize().into_bytes();

    let mut mac_value = [0u8; 16];
    mac_value.copy_from_slice(&result[..16]);
    mac_value
}

/// Verify AT_MAC in received EAP-AKA' message.
pub fn verify_mac(k_aut: &[u8; 32], eap_data: &[u8], expected_mac: &[u8; 16]) -> bool {
    let computed = compute_mac(k_aut, eap_data);
    computed == *expected_mac
}

// ============================================================================
// EAP-AKA' Session State
// ============================================================================

/// EAP-AKA' authentication state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapAkaState {
    /// Waiting for EAP-Response/Identity
    Identity,
    /// Challenge sent, waiting for response
    Challenge,
    /// Authentication succeeded
    Success,
    /// Authentication failed
    Failure,
}

/// EAP-AKA' session context held at the AUSF.
#[derive(Debug, Clone)]
pub struct EapAkaSession {
    /// Session state
    pub state: EapAkaState,
    /// Current EAP identifier
    pub identifier: u8,
    /// RAND value (16 bytes)
    pub rand: [u8; 16],
    /// AUTN value (16 bytes)
    pub autn: [u8; 16],
    /// XRES value for verification
    pub xres: Vec<u8>,
    /// CK' (derived from CK, IK via EAP-AKA' KDF)
    pub ck_prime: [u8; 16],
    /// IK' (derived from CK, IK via EAP-AKA' KDF)
    pub ik_prime: [u8; 16],
    /// KAUSF (derived from CK', IK')
    pub kausf: [u8; 32],
    /// K_aut for MAC computation (from EAP-AKA' key hierarchy)
    pub k_aut: [u8; 32],
    /// Serving network name
    pub serving_network_name: String,
}

impl EapAkaSession {
    /// Create a new EAP-AKA' session.
    pub fn new(serving_network_name: &str) -> Self {
        Self {
            state: EapAkaState::Identity,
            identifier: 0,
            rand: [0u8; 16],
            autn: [0u8; 16],
            xres: Vec::new(),
            ck_prime: [0u8; 16],
            ik_prime: [0u8; 16],
            kausf: [0u8; 32],
            k_aut: [0u8; 32],
            serving_network_name: serving_network_name.to_string(),
        }
    }

    /// Initialize session with authentication vector from UDM.
    ///
    /// Derives CK', IK' from CK, IK per EAP-AKA' specification,
    /// then derives KAUSF from CK', IK'.
    pub fn init_from_av(
        &mut self,
        rand: &[u8; 16],
        autn: &[u8; 16],
        xres: &[u8],
        ck: &[u8; 16],
        ik: &[u8; 16],
    ) {
        self.rand = *rand;
        self.autn = *autn;
        self.xres = xres.to_vec();

        // Extract SQN xor AK from AUTN[0..6]
        let mut sqn_xor_ak = [0u8; 6];
        sqn_xor_ak.copy_from_slice(&autn[..6]);

        // Derive CK', IK' per RFC 5448
        let (ck_prime, ik_prime) =
            derive_ck_ik_prime(ck, ik, &self.serving_network_name, &sqn_xor_ak);
        self.ck_prime = ck_prime;
        self.ik_prime = ik_prime;

        // Derive KAUSF from CK', IK'
        self.kausf = derive_kausf_eap(&ck_prime, &ik_prime, &self.serving_network_name, &sqn_xor_ak);

        // For K_aut, in a full implementation this would come from PRF' expansion.
        // Simplified: use HMAC-SHA-256(CK'||IK', "EAP-AKA'K_aut")
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&ck_prime);
        key[16..].copy_from_slice(&ik_prime);
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
        mac.update(b"EAP-AKA'K_aut");
        let result = mac.finalize().into_bytes();
        self.k_aut.copy_from_slice(&result);

        self.state = EapAkaState::Challenge;
        self.identifier = self.identifier.wrapping_add(1);
    }

    /// Generate EAP-Request/AKA'-Challenge message.
    pub fn generate_challenge(&self) -> EapPacket {
        let mac = compute_mac(&self.k_aut, &self.rand);
        EapPacket::new_aka_challenge(
            self.identifier,
            &self.rand,
            &self.autn,
            &self.serving_network_name,
            &mac,
        )
    }

    /// Process EAP-Response/AKA'-Challenge from UE.
    ///
    /// Verifies the RES value from the UE against XRES.
    /// Returns true if authentication succeeds.
    pub fn process_challenge_response(&mut self, response: &EapPacket) -> bool {
        if response.code != EapCode::Response {
            log::error!("EAP-AKA': Expected Response, got {:?}", response.code);
            self.state = EapAkaState::Failure;
            return false;
        }

        if response.subtype != Some(AkaPrimeSubtype::Challenge) {
            // Check for Authentication-Reject or Synchronization-Failure
            if response.subtype == Some(AkaPrimeSubtype::AuthenticationReject) {
                log::warn!("EAP-AKA': UE rejected authentication");
                self.state = EapAkaState::Failure;
                return false;
            }
            if response.subtype == Some(AkaPrimeSubtype::SynchronizationFailure) {
                log::warn!("EAP-AKA': Synchronization failure from UE");
                self.state = EapAkaState::Failure;
                return false;
            }
            self.state = EapAkaState::Failure;
            return false;
        }

        // Extract AT_RES from response
        let res_data = match response.find_attribute(AkaPrimeAttribute::AtRes) {
            Some(data) => data,
            None => {
                log::error!("EAP-AKA': No AT_RES in response");
                self.state = EapAkaState::Failure;
                return false;
            }
        };

        // AT_RES format: 2 bytes RES length in bits, then RES value
        if res_data.len() < 2 {
            self.state = EapAkaState::Failure;
            return false;
        }
        let res_bits = u16::from_be_bytes([res_data[0], res_data[1]]);
        let res_bytes = (res_bits as usize).div_ceil(8);

        if res_data.len() < 2 + res_bytes {
            self.state = EapAkaState::Failure;
            return false;
        }

        let res = &res_data[2..2 + res_bytes];

        // Compare RES with XRES
        if res.len() != self.xres.len() || res != self.xres.as_slice() {
            log::warn!("EAP-AKA': RES mismatch (authentication failed)");
            self.state = EapAkaState::Failure;
            return false;
        }

        log::info!("EAP-AKA': Authentication succeeded");
        self.state = EapAkaState::Success;
        true
    }

    /// Generate final EAP-Success or EAP-Failure message.
    pub fn generate_result(&self) -> EapPacket {
        match self.state {
            EapAkaState::Success => EapPacket::new_success(self.identifier),
            _ => EapPacket::new_failure(self.identifier),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eap_code_from_u8() {
        assert_eq!(EapCode::from_u8(1), Some(EapCode::Request));
        assert_eq!(EapCode::from_u8(2), Some(EapCode::Response));
        assert_eq!(EapCode::from_u8(3), Some(EapCode::Success));
        assert_eq!(EapCode::from_u8(4), Some(EapCode::Failure));
        assert_eq!(EapCode::from_u8(5), None);
    }

    #[test]
    fn test_eap_type_from_u8() {
        assert_eq!(EapType::from_u8(50), Some(EapType::AkaPrime));
        assert_eq!(EapType::from_u8(1), Some(EapType::Identity));
        assert_eq!(EapType::from_u8(99), None);
    }

    #[test]
    fn test_aka_prime_subtype() {
        assert_eq!(
            AkaPrimeSubtype::from_u8(1),
            Some(AkaPrimeSubtype::Challenge)
        );
        assert_eq!(
            AkaPrimeSubtype::from_u8(2),
            Some(AkaPrimeSubtype::AuthenticationReject)
        );
        assert_eq!(
            AkaPrimeSubtype::from_u8(4),
            Some(AkaPrimeSubtype::SynchronizationFailure)
        );
    }

    #[test]
    fn test_eap_success_failure_encode_decode() {
        let success = EapPacket::new_success(42);
        let encoded = success.encode();
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0], 3); // Success
        assert_eq!(encoded[1], 42); // Identifier

        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.code, EapCode::Success);
        assert_eq!(decoded.identifier, 42);

        let failure = EapPacket::new_failure(7);
        let encoded = failure.encode();
        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.code, EapCode::Failure);
        assert_eq!(decoded.identifier, 7);
    }

    #[test]
    fn test_eap_aka_challenge_encode_decode() {
        let rand = [1u8; 16];
        let autn = [2u8; 16];
        let mac = [3u8; 16];

        let challenge = EapPacket::new_aka_challenge(
            10,
            &rand,
            &autn,
            "5G:mnc001.mcc001.3gppnetwork.org",
            &mac,
        );

        let encoded = challenge.encode();
        assert!(encoded.len() > 8);
        assert_eq!(encoded[0], 1); // Request
        assert_eq!(encoded[1], 10); // Identifier
        assert_eq!(encoded[4], 50); // AKA'
        assert_eq!(encoded[5], 1); // Challenge

        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.code, EapCode::Request);
        assert_eq!(decoded.identifier, 10);
        assert_eq!(decoded.eap_type, Some(EapType::AkaPrime));
        assert_eq!(decoded.subtype, Some(AkaPrimeSubtype::Challenge));

        // Verify AT_RAND
        let at_rand = decoded.find_attribute(AkaPrimeAttribute::AtRand).unwrap();
        assert_eq!(&at_rand[2..18], &rand);

        // Verify AT_AUTN
        let at_autn = decoded.find_attribute(AkaPrimeAttribute::AtAutn).unwrap();
        assert_eq!(&at_autn[2..18], &autn);
    }

    #[test]
    fn test_derive_ck_ik_prime() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_xor_ak = [0x33u8; 6];

        let (ck_prime, ik_prime) =
            derive_ck_ik_prime(&ck, &ik, "5G:mnc001.mcc001.3gppnetwork.org", &sqn_xor_ak);

        // Verify they're not zero and not equal to original
        assert_ne!(ck_prime, [0u8; 16]);
        assert_ne!(ik_prime, [0u8; 16]);
        assert_ne!(ck_prime, ck);
        assert_ne!(ik_prime, ik);

        // Verify deterministic
        let (ck_prime2, ik_prime2) =
            derive_ck_ik_prime(&ck, &ik, "5G:mnc001.mcc001.3gppnetwork.org", &sqn_xor_ak);
        assert_eq!(ck_prime, ck_prime2);
        assert_eq!(ik_prime, ik_prime2);

        // Different serving network should give different keys
        let (ck_prime3, ik_prime3) =
            derive_ck_ik_prime(&ck, &ik, "5G:mnc002.mcc002.3gppnetwork.org", &sqn_xor_ak);
        assert_ne!(ck_prime, ck_prime3);
        assert_ne!(ik_prime, ik_prime3);
    }

    #[test]
    fn test_compute_verify_mac() {
        let k_aut = [0xAAu8; 32];
        let data = b"test EAP message data";

        let mac = compute_mac(&k_aut, data);
        assert_ne!(mac, [0u8; 16]);

        assert!(verify_mac(&k_aut, data, &mac));

        // Tampered data should fail
        assert!(!verify_mac(&k_aut, b"tampered data", &mac));

        // Tampered MAC should fail
        let mut bad_mac = mac;
        bad_mac[0] ^= 0xFF;
        assert!(!verify_mac(&k_aut, data, &bad_mac));
    }

    #[test]
    fn test_eap_aka_session_flow() {
        let sn_name = "5G:mnc001.mcc001.3gppnetwork.org";
        let mut session = EapAkaSession::new(sn_name);
        assert_eq!(session.state, EapAkaState::Identity);

        // Simulate AV from UDM
        let rand = [0x10u8; 16];
        let autn = [0x20u8; 16];
        let xres = vec![0x30u8; 8];
        let ck = [0x40u8; 16];
        let ik = [0x50u8; 16];

        session.init_from_av(&rand, &autn, &xres, &ck, &ik);
        assert_eq!(session.state, EapAkaState::Challenge);
        assert_ne!(session.ck_prime, [0u8; 16]);
        assert_ne!(session.ik_prime, [0u8; 16]);
        assert_ne!(session.kausf, [0u8; 32]);

        // Generate challenge
        let challenge = session.generate_challenge();
        assert_eq!(challenge.code, EapCode::Request);
        assert_eq!(challenge.subtype, Some(AkaPrimeSubtype::Challenge));

        // Simulate correct UE response
        let mut response = EapPacket {
            code: EapCode::Response,
            identifier: session.identifier,
            eap_type: Some(EapType::AkaPrime),
            subtype: Some(AkaPrimeSubtype::Challenge),
            attributes: Vec::new(),
        };
        // AT_RES: 2 bytes length in bits + RES value
        let res_bits = (xres.len() * 8) as u16;
        let mut res_attr = Vec::new();
        res_attr.extend_from_slice(&res_bits.to_be_bytes());
        res_attr.extend_from_slice(&xres);
        response
            .attributes
            .push((AkaPrimeAttribute::AtRes as u8, res_attr));

        let result = session.process_challenge_response(&response);
        assert!(result);
        assert_eq!(session.state, EapAkaState::Success);

        let eap_result = session.generate_result();
        assert_eq!(eap_result.code, EapCode::Success);
    }

    #[test]
    fn test_eap_aka_session_wrong_res() {
        let sn_name = "5G:mnc001.mcc001.3gppnetwork.org";
        let mut session = EapAkaSession::new(sn_name);

        let rand = [0x10u8; 16];
        let autn = [0x20u8; 16];
        let xres = vec![0x30u8; 8];
        let ck = [0x40u8; 16];
        let ik = [0x50u8; 16];

        session.init_from_av(&rand, &autn, &xres, &ck, &ik);

        // Wrong RES
        let wrong_res = vec![0xFFu8; 8];
        let mut response = EapPacket {
            code: EapCode::Response,
            identifier: session.identifier,
            eap_type: Some(EapType::AkaPrime),
            subtype: Some(AkaPrimeSubtype::Challenge),
            attributes: Vec::new(),
        };
        let res_bits = (wrong_res.len() * 8) as u16;
        let mut res_attr = Vec::new();
        res_attr.extend_from_slice(&res_bits.to_be_bytes());
        res_attr.extend_from_slice(&wrong_res);
        response
            .attributes
            .push((AkaPrimeAttribute::AtRes as u8, res_attr));

        let result = session.process_challenge_response(&response);
        assert!(!result);
        assert_eq!(session.state, EapAkaState::Failure);

        let eap_result = session.generate_result();
        assert_eq!(eap_result.code, EapCode::Failure);
    }

    #[test]
    fn test_eap_aka_session_auth_reject() {
        let sn_name = "5G:mnc001.mcc001.3gppnetwork.org";
        let mut session = EapAkaSession::new(sn_name);

        session.init_from_av(
            &[0x10u8; 16],
            &[0x20u8; 16],
            &[0x30u8; 8],
            &[0x40u8; 16],
            &[0x50u8; 16],
        );

        let response = EapPacket {
            code: EapCode::Response,
            identifier: session.identifier,
            eap_type: Some(EapType::AkaPrime),
            subtype: Some(AkaPrimeSubtype::AuthenticationReject),
            attributes: Vec::new(),
        };

        let result = session.process_challenge_response(&response);
        assert!(!result);
        assert_eq!(session.state, EapAkaState::Failure);
    }
}
