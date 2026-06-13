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

    /// Replace the value of the AT_MAC attribute (bytes 2..18 of the attribute
    /// data: 2 reserved bytes followed by the 16-byte MAC).
    pub fn set_mac(&mut self, mac: &[u8; 16]) {
        let mac_type = AkaPrimeAttribute::AtMac as u8;
        for (t, data) in self.attributes.iter_mut() {
            if *t == mac_type && data.len() >= 18 {
                data[2..18].copy_from_slice(mac);
            }
        }
    }
}

/// Zero out the AT_MAC value inside a raw encoded EAP-AKA' packet.
///
/// Per RFC 4187 §10.15 / RFC 5448 §3.3, AT_MAC is computed over the entire
/// EAP packet with the MAC value field set to zero. Returns a copy of the
/// packet with the MAC field zeroed, or `None` if no AT_MAC is present.
pub fn zero_at_mac(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 8 {
        return None;
    }
    let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if raw.len() < length {
        return None;
    }
    let mut out = raw.to_vec();
    let mut offset = 8;
    while offset + 2 <= length {
        let attr_type = raw[offset];
        let attr_len = (raw[offset + 1] as usize) * 4;
        if attr_len == 0 || offset + attr_len > length {
            return None;
        }
        if attr_type == AkaPrimeAttribute::AtMac as u8 && attr_len >= 20 {
            // type(1) len(1) reserved(2) mac(16)
            for b in out[offset + 4..offset + 20].iter_mut() {
                *b = 0;
            }
            return Some(out);
        }
        offset += attr_len;
    }
    None
}

// ============================================================================
// EAP-AKA' Key Derivation (CK', IK')
// ============================================================================

/// Derive CK' and IK' from CK, IK, and serving network name per TS 33.501
/// Annex A.3 (FC = 0x20). Delegates to [`ogs_crypt::kdf::ogs_kdf_ck_ik_prime`].
///
/// Returns (CK', IK') each 16 bytes.
pub fn derive_ck_ik_prime(
    ck: &[u8; 16],
    ik: &[u8; 16],
    serving_network_name: &str,
    sqn_xor_ak: &[u8; 6],
) -> ([u8; 16], [u8; 16]) {
    ogs_crypt::kdf::ogs_kdf_ck_ik_prime(ck, ik, serving_network_name, sqn_xor_ak)
}

/// PRF' as specified in RFC 5448 §3.4.1 (also RFC 9048 §3.4.1).
///
/// `PRF'(K, S) = T1 | T2 | T3 | ...` where
/// `T1 = HMAC-SHA-256(K, S | 0x01)` and
/// `Tn = HMAC-SHA-256(K, Tn-1 | S | n)`.
pub fn prf_prime(key: &[u8], s: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len.div_ceil(32) * 32);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut mac = HmacSha256::new_from_slice(key).expect("value expected");
        mac.update(&prev);
        mac.update(s);
        mac.update(&[counter]);
        prev = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&prev);
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

/// EAP-AKA' key material derived from the master key (RFC 5448 §3.3).
#[derive(Debug, Clone)]
pub struct EapAkaPrimeKeys {
    /// Encryption key for AT_ENCR_DATA (16 bytes)
    pub k_encr: [u8; 16],
    /// Authentication key for AT_MAC (32 bytes)
    pub k_aut: [u8; 32],
    /// Re-authentication key (32 bytes)
    pub k_re: [u8; 32],
    /// Master Session Key (64 bytes)
    pub msk: [u8; 64],
    /// Extended Master Session Key (64 bytes)
    pub emsk: [u8; 64],
}

/// Derive the full EAP-AKA' key hierarchy per RFC 5448 §3.3:
///
/// `MK = PRF'(IK' | CK', "EAP-AKA'" | Identity)` and
/// `K_encr(16) | K_aut(32) | K_re(32) | MSK(64) | EMSK(64) = MK` (208 bytes).
///
/// In 5G the peer identity used for key derivation is the SUPI
/// (TS 33.501 Annex F).
pub fn derive_keys_aka_prime(
    ck_prime: &[u8; 16],
    ik_prime: &[u8; 16],
    identity: &str,
) -> EapAkaPrimeKeys {
    // Key = IK' | CK' (note the order per RFC 5448 §3.3)
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ik_prime);
    key[16..].copy_from_slice(ck_prime);

    let mut s = Vec::with_capacity(8 + identity.len());
    s.extend_from_slice(b"EAP-AKA'");
    s.extend_from_slice(identity.as_bytes());

    let mk = prf_prime(&key, &s, 208);

    let mut keys = EapAkaPrimeKeys {
        k_encr: [0u8; 16],
        k_aut: [0u8; 32],
        k_re: [0u8; 32],
        msk: [0u8; 64],
        emsk: [0u8; 64],
    };
    keys.k_encr.copy_from_slice(&mk[0..16]);
    keys.k_aut.copy_from_slice(&mk[16..48]);
    keys.k_re.copy_from_slice(&mk[48..80]);
    keys.msk.copy_from_slice(&mk[80..144]);
    keys.emsk.copy_from_slice(&mk[144..208]);
    keys
}

/// Derive KAUSF for EAP-AKA' per TS 33.501 §6.1.3.1 / Annex F:
/// KAUSF is the most significant 256 bits of the EMSK.
pub fn kausf_from_emsk(emsk: &[u8; 64]) -> [u8; 32] {
    let mut kausf = [0u8; 32];
    kausf.copy_from_slice(&emsk[..32]);
    kausf
}

/// Compute AT_MAC for EAP-AKA' message using K_aut.
///
/// K_aut is derived from the master session key (MSK) during EAP-AKA' key generation.
/// MAC = HMAC-SHA-256-128(K_aut, EAP_packet)
/// (Truncated to 16 bytes)
pub fn compute_mac(k_aut: &[u8; 32], eap_data: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(k_aut).expect("value expected");
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
    /// CK' (from the UDM transformed AV)
    pub ck_prime: [u8; 16],
    /// IK' (from the UDM transformed AV)
    pub ik_prime: [u8; 16],
    /// KAUSF (MSB 256 bits of EMSK per TS 33.501 Annex F)
    pub kausf: [u8; 32],
    /// K_aut for AT_MAC computation (RFC 5448 key hierarchy)
    pub k_aut: [u8; 32],
    /// Peer identity used in the RFC 5448 key derivation (the SUPI in 5G)
    pub identity: String,
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
            identity: String::new(),
            serving_network_name: serving_network_name.to_string(),
        }
    }

    /// Initialize session with the EAP-AKA' transformed authentication vector
    /// received from the UDM (TS 33.501 §6.1.3.1: RAND, AUTN, XRES, CK', IK').
    ///
    /// Derives the RFC 5448 key hierarchy from CK'/IK' and the peer identity
    /// (the SUPI), sets K_aut for AT_MAC and KAUSF = MSB256(EMSK).
    pub fn init_from_transformed_av(
        &mut self,
        rand: &[u8; 16],
        autn: &[u8; 16],
        xres: &[u8],
        ck_prime: &[u8; 16],
        ik_prime: &[u8; 16],
        identity: &str,
    ) {
        self.rand = *rand;
        self.autn = *autn;
        self.xres = xres.to_vec();
        self.ck_prime = *ck_prime;
        self.ik_prime = *ik_prime;
        self.identity = identity.to_string();

        let keys = derive_keys_aka_prime(ck_prime, ik_prime, identity);
        self.k_aut = keys.k_aut;
        self.kausf = kausf_from_emsk(&keys.emsk);

        self.state = EapAkaState::Challenge;
        self.identifier = self.identifier.wrapping_add(1);
    }

    /// Initialize session with a non-transformed authentication vector
    /// (CK/IK). Derives CK'/IK' per TS 33.501 Annex A.3 first, then proceeds
    /// as [`Self::init_from_transformed_av`].
    pub fn init_from_av(
        &mut self,
        rand: &[u8; 16],
        autn: &[u8; 16],
        xres: &[u8],
        ck: &[u8; 16],
        ik: &[u8; 16],
    ) {
        // Extract SQN xor AK from AUTN[0..6]
        let mut sqn_xor_ak = [0u8; 6];
        sqn_xor_ak.copy_from_slice(&autn[..6]);

        let snn = self.serving_network_name.clone();
        let identity = self.identity.clone();
        let (ck_prime, ik_prime) = derive_ck_ik_prime(ck, ik, &snn, &sqn_xor_ak);
        self.init_from_transformed_av(rand, autn, xres, &ck_prime, &ik_prime, &identity);
    }

    /// Generate EAP-Request/AKA'-Challenge message.
    ///
    /// AT_MAC is computed with K_aut over the entire encoded EAP packet with
    /// the MAC field zeroed (RFC 4187 §10.15 / RFC 5448 §3.3).
    pub fn generate_challenge(&self) -> EapPacket {
        let mut packet = EapPacket::new_aka_challenge(
            self.identifier,
            &self.rand,
            &self.autn,
            &self.serving_network_name,
            &[0u8; 16],
        );
        let encoded = packet.encode();
        let mac = compute_mac(&self.k_aut, &encoded);
        packet.set_mac(&mac);
        packet
    }

    /// Process a raw EAP-Response/AKA'-Challenge: verifies AT_MAC over the
    /// packet (with the MAC field zeroed) and then the RES against XRES.
    ///
    /// Returns true if authentication succeeds.
    pub fn process_challenge_response_bytes(&mut self, raw: &[u8]) -> bool {
        let packet = match EapPacket::decode(raw) {
            Some(p) => p,
            None => {
                log::error!("EAP-AKA': failed to decode response packet");
                self.state = EapAkaState::Failure;
                return false;
            }
        };

        // AT_MAC is mandatory in AKA'-Challenge responses (RFC 4187 §9.4)
        if packet.code == EapCode::Response && packet.subtype == Some(AkaPrimeSubtype::Challenge) {
            let zeroed = match zero_at_mac(raw) {
                Some(z) => z,
                None => {
                    log::error!("EAP-AKA': response has no AT_MAC");
                    self.state = EapAkaState::Failure;
                    return false;
                }
            };
            let received_mac = match packet.find_attribute(AkaPrimeAttribute::AtMac) {
                Some(data) if data.len() >= 18 => {
                    let mut mac = [0u8; 16];
                    mac.copy_from_slice(&data[2..18]);
                    mac
                }
                _ => {
                    log::error!("EAP-AKA': malformed AT_MAC");
                    self.state = EapAkaState::Failure;
                    return false;
                }
            };
            if !verify_mac(&self.k_aut, &zeroed, &received_mac) {
                log::warn!("EAP-AKA': AT_MAC verification failed");
                self.state = EapAkaState::Failure;
                return false;
            }
        }

        self.process_challenge_response(&packet)
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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5448 test vector 1: full PRF' key schedule from CK'/IK'.
    ///
    /// Identity "0555444333222111"; CK'/IK' as derived for network name "WLAN"
    /// (the CK'/IK' derivation itself is vector-tested in ogs-crypt kdf).
    #[test]
    fn test_rfc5448_key_schedule_vector1() {
        let ck_prime_v = unhex("0093962d0dd84aa5684b045c9edffa04");
        let ik_prime_v = unhex("ccfc230ca74fcc96c0a5d61164f5a76c");
        let mut ck_prime = [0u8; 16];
        ck_prime.copy_from_slice(&ck_prime_v);
        let mut ik_prime = [0u8; 16];
        ik_prime.copy_from_slice(&ik_prime_v);

        let keys = derive_keys_aka_prime(&ck_prime, &ik_prime, "0555444333222111");

        assert_eq!(
            &keys.k_encr[..],
            &unhex("766fa0a6c317174b812d52fbcd11a179")[..],
            "K_encr"
        );
        assert_eq!(
            &keys.k_aut[..],
            &unhex("0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea")[..],
            "K_aut"
        );
        assert_eq!(
            &keys.k_re[..],
            &unhex("cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a")[..],
            "K_re"
        );
        assert_eq!(
            &keys.msk[..],
            &unhex(
                "67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544\
                 e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a"
            )[..],
            "MSK"
        );
        assert_eq!(
            &keys.emsk[..],
            &unhex(
                "f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c\
                 313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb"
            )[..],
            "EMSK"
        );

        // KAUSF = MSB 256 bits of EMSK (TS 33.501 Annex F)
        let kausf = kausf_from_emsk(&keys.emsk);
        assert_eq!(&kausf[..], &keys.emsk[..32]);
    }

    /// Challenge AT_MAC is computed over the full packet with a zeroed MAC
    /// field and verifies via zero_at_mac + verify_mac.
    #[test]
    fn test_challenge_at_mac_over_packet() {
        let mut session = EapAkaSession::new("5G:mnc001.mcc001.3gppnetwork.org");
        session.init_from_transformed_av(
            &[0x10u8; 16],
            &[0x20u8; 16],
            &[0x30u8; 8],
            &[0x40u8; 16],
            &[0x50u8; 16],
            "imsi-001010000000001",
        );

        let challenge = session.generate_challenge();
        let encoded = challenge.encode();

        // Extract AT_MAC from encoded packet and verify over zeroed packet
        let decoded = EapPacket::decode(&encoded).unwrap();
        let at_mac = decoded.find_attribute(AkaPrimeAttribute::AtMac).unwrap();
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&at_mac[2..18]);
        assert_ne!(mac, [0u8; 16]);

        let zeroed = zero_at_mac(&encoded).unwrap();
        assert!(verify_mac(&session.k_aut, &zeroed, &mac));
        // MAC over the un-zeroed packet must NOT match
        assert!(!verify_mac(&session.k_aut, &encoded, &mac));
    }

    /// Full response processing from raw bytes: correct AT_MAC + RES succeeds;
    /// tampered MAC or missing MAC fails.
    #[test]
    fn test_process_challenge_response_bytes() {
        let xres = vec![0x30u8; 8];
        let mut session = EapAkaSession::new("5G:mnc001.mcc001.3gppnetwork.org");
        session.init_from_transformed_av(
            &[0x10u8; 16],
            &[0x20u8; 16],
            &xres,
            &[0x40u8; 16],
            &[0x50u8; 16],
            "imsi-001010000000001",
        );

        // Build a UE response: AT_RES + AT_MAC (computed like a real peer)
        let build_response = |xres: &[u8], k_aut: &[u8; 32], identifier: u8| -> Vec<u8> {
            let mut response = EapPacket {
                code: EapCode::Response,
                identifier,
                eap_type: Some(EapType::AkaPrime),
                subtype: Some(AkaPrimeSubtype::Challenge),
                attributes: Vec::new(),
            };
            let res_bits = (xres.len() * 8) as u16;
            let mut res_attr = Vec::new();
            res_attr.extend_from_slice(&res_bits.to_be_bytes());
            res_attr.extend_from_slice(xres);
            response
                .attributes
                .push((AkaPrimeAttribute::AtRes as u8, res_attr));
            response
                .attributes
                .push((AkaPrimeAttribute::AtMac as u8, vec![0u8; 18]));
            let encoded = response.encode();
            let mac = compute_mac(k_aut, &encoded);
            response.set_mac(&mac);
            response.encode()
        };

        // Correct response
        let raw = build_response(&xres, &session.k_aut, session.identifier);
        let mut s1 = session.clone();
        assert!(s1.process_challenge_response_bytes(&raw));
        assert_eq!(s1.state, EapAkaState::Success);

        // Tampered MAC
        let mut tampered = raw.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0xFF;
        let mut s2 = session.clone();
        assert!(!s2.process_challenge_response_bytes(&tampered));
        assert_eq!(s2.state, EapAkaState::Failure);

        // Wrong RES (recompute MAC so only RES check fails)
        let raw_wrong_res = build_response(&[0xFFu8; 8], &session.k_aut, session.identifier);
        let mut s3 = session.clone();
        assert!(!s3.process_challenge_response_bytes(&raw_wrong_res));
        assert_eq!(s3.state, EapAkaState::Failure);
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
