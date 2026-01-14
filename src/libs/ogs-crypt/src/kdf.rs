//! Key Derivation Functions
//!
//! Exact port of lib/crypt/ogs-kdf.c
//!
//! Implements key derivation functions as defined in:
//! - 3GPP TS 33.501 (5G Security)
//! - 3GPP TS 33.401 (EPS Security)
//! - 3GPP TS 33.220 (Generic Bootstrapping Architecture)
//! - 3GPP TS 33.102 (3G Security)

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::sha::{sha256, SHA256_DIGEST_SIZE};
use crate::milenage;

// Length constants
pub const OGS_KEY_LEN: usize = 16;
pub const OGS_IVEC_LEN: usize = 16;
pub const OGS_RAND_LEN: usize = 16;
pub const OGS_SQN_XOR_AK_LEN: usize = 6;
pub const OGS_PLMN_ID_LEN: usize = 3;
pub const OGS_HASH_MME_LEN: usize = 8;
pub const ECC_BYTES: usize = 32; // secp256r1

// FC (Function Code) values for KDF
const FC_FOR_5GS_ALGORITHM_KEY_DERIVATION: u8 = 0x69;
const FC_FOR_KAUSF_DERIVATION: u8 = 0x6A;
const FC_FOR_RES_STAR_XRES_STAR_DERIVATION: u8 = 0x6B;
const FC_FOR_KSEAF_DERIVATION: u8 = 0x6C;
const FC_FOR_KAMF_DERIVATION: u8 = 0x6D;
const FC_FOR_KGNB_KN3IWF_DERIVATION: u8 = 0x6E;
const FC_FOR_NH_GNB_DERIVATION: u8 = 0x6F;

const FC_FOR_KASME: u8 = 0x10;
const FC_FOR_KENB_DERIVATION: u8 = 0x11;
const FC_FOR_NH_ENB_DERIVATION: u8 = 0x12;
const FC_FOR_EPS_ALGORITHM_KEY_DERIVATION: u8 = 0x15;
const FC_FOR_CK_IK_DERIVATION_HANDOVER: u8 = 0x16;
const FC_FOR_NAS_TOKEN_DERIVATION: u8 = 0x17;
const FC_FOR_KASME_DERIVATION_IDLE_MOBILITY: u8 = 0x19;
const FC_FOR_CK_IK_DERIVATION_IDLE_MOBILITY: u8 = 0x1B;

// Algorithm Type Distinguishers
pub const OGS_KDF_NAS_ENC_ALG: u8 = 0x01;
pub const OGS_KDF_NAS_INT_ALG: u8 = 0x02;

type HmacSha256 = Hmac<Sha256>;

/// KDF parameter structure
struct KdfParam {
    buf: Option<Vec<u8>>,
    len: u16,
}

impl Default for KdfParam {
    fn default() -> Self {
        KdfParam { buf: None, len: 0 }
    }
}

/// Common KDF function as defined in TS 33.220 clause B.2.0
///
/// This is the core key derivation function used by all other KDF functions.
fn ogs_kdf_common(key: &[u8], fc: u8, params: &[KdfParam]) -> [u8; SHA256_DIGEST_SIZE] {
    // Calculate buffer length
    let mut total_len = 1; // FC value
    for param in params.iter() {
        if let Some(ref buf) = param.buf {
            if param.len > 0 {
                total_len += buf.len() + 2; // data + 2 bytes for length
            }
        }
    }

    // Build the S parameter
    let mut s = Vec::with_capacity(total_len);
    s.push(fc);

    for param in params.iter() {
        if let Some(ref buf) = param.buf {
            if param.len > 0 {
                s.extend_from_slice(buf);
                let len_be = (param.len).to_be_bytes();
                s.extend_from_slice(&len_be);
            }
        }
    }

    // Compute HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(&s);
    let result = mac.finalize();
    
    let mut output = [0u8; SHA256_DIGEST_SIZE];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// TS33.501 Annex A.2: Kausf derivation function
///
/// Derives Kausf from CK, IK, serving network name, and AUTN.
pub fn ogs_kdf_kausf(
    ck: &[u8; OGS_KEY_LEN],
    ik: &[u8; OGS_KEY_LEN],
    serving_network_name: &str,
    autn: &[u8],
) -> [u8; SHA256_DIGEST_SIZE] {
    // Key = CK || IK
    let mut key = [0u8; OGS_KEY_LEN * 2];
    key[..OGS_KEY_LEN].copy_from_slice(ck);
    key[OGS_KEY_LEN..].copy_from_slice(ik);

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(serving_network_name.as_bytes().to_vec());
    params[0].len = serving_network_name.len() as u16;
    params[1].buf = Some(autn[..OGS_SQN_XOR_AK_LEN].to_vec());
    params[1].len = OGS_SQN_XOR_AK_LEN as u16;

    ogs_kdf_common(&key, FC_FOR_KAUSF_DERIVATION, &params)
}

/// TS33.501 Annex A.4: RES* and XRES* derivation function
///
/// Derives XRES* from CK, IK, serving network name, RAND, and XRES.
/// Returns the 16-byte XRES* (lower 16 bytes of the 32-byte output).
pub fn ogs_kdf_xres_star(
    ck: &[u8; OGS_KEY_LEN],
    ik: &[u8; OGS_KEY_LEN],
    serving_network_name: &str,
    rand: &[u8; OGS_RAND_LEN],
    xres: &[u8],
) -> [u8; OGS_KEY_LEN] {
    // Key = CK || IK
    let mut key = [0u8; OGS_KEY_LEN * 2];
    key[..OGS_KEY_LEN].copy_from_slice(ck);
    key[OGS_KEY_LEN..].copy_from_slice(ik);

    let mut params = [KdfParam::default(), KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(serving_network_name.as_bytes().to_vec());
    params[0].len = serving_network_name.len() as u16;
    params[1].buf = Some(rand.to_vec());
    params[1].len = OGS_RAND_LEN as u16;
    params[2].buf = Some(xres.to_vec());
    params[2].len = xres.len() as u16;

    let output = ogs_kdf_common(&key, FC_FOR_RES_STAR_XRES_STAR_DERIVATION, &params);

    // Return lower 16 bytes
    let mut xres_star = [0u8; OGS_KEY_LEN];
    xres_star.copy_from_slice(&output[OGS_KEY_LEN..]);
    xres_star
}

/// TS33.501 Annex A.5: HRES* and HXRES* derivation function
///
/// Derives HXRES* from RAND and XRES*.
/// Returns the 16-byte HXRES* (lower 16 bytes of SHA-256 hash).
pub fn ogs_kdf_hxres_star(
    rand: &[u8; OGS_RAND_LEN],
    xres_star: &[u8; OGS_KEY_LEN],
) -> [u8; OGS_KEY_LEN] {
    // message = RAND || XRES*
    let mut message = [0u8; OGS_RAND_LEN + OGS_KEY_LEN];
    message[..OGS_RAND_LEN].copy_from_slice(rand);
    message[OGS_RAND_LEN..].copy_from_slice(xres_star);

    let output = sha256(&message);

    // Return lower 16 bytes
    let mut hxres_star = [0u8; OGS_KEY_LEN];
    hxres_star.copy_from_slice(&output[OGS_KEY_LEN..]);
    hxres_star
}

/// TS33.501 Annex A.6: Kseaf derivation function
///
/// Derives Kseaf from serving network name and Kausf.
pub fn ogs_kdf_kseaf(
    serving_network_name: &str,
    kausf: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut params = [KdfParam::default()];
    params[0].buf = Some(serving_network_name.as_bytes().to_vec());
    params[0].len = serving_network_name.len() as u16;

    ogs_kdf_common(kausf, FC_FOR_KSEAF_DERIVATION, &params)
}

/// TS33.501 Annex A.7: Kamf derivation function
///
/// Derives Kamf from SUPI, ABBA, and Kseaf.
pub fn ogs_kdf_kamf(
    supi: &str,
    abba: &[u8],
    kseaf: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    // Extract the value part from SUPI (e.g., "imsi-123456789" -> "123456789")
    let val = ogs_id_get_value(supi);

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(val.as_bytes().to_vec());
    params[0].len = val.len() as u16;
    params[1].buf = Some(abba.to_vec());
    params[1].len = abba.len() as u16;

    ogs_kdf_common(kseaf, FC_FOR_KAMF_DERIVATION, &params)
}

/// TS33.501 Annex A.8: Algorithm key derivation functions (5GS)
///
/// Derives NAS keys from Kamf.
/// Returns the 16-byte key (lower 16 bytes of the 32-byte output).
pub fn ogs_kdf_nas_5gs(
    algorithm_type_distinguishers: u8,
    algorithm_identity: u8,
    kamf: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; OGS_KEY_LEN] {
    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(vec![algorithm_type_distinguishers]);
    params[0].len = 1;
    params[1].buf = Some(vec![algorithm_identity]);
    params[1].len = 1;

    let output = ogs_kdf_common(kamf, FC_FOR_5GS_ALGORITHM_KEY_DERIVATION, &params);

    // Return lower 16 bytes
    let mut knas = [0u8; OGS_KEY_LEN];
    knas.copy_from_slice(&output[16..]);
    knas
}

/// TS33.501 Annex A.9: KgNB and Kn3iwf derivation function
///
/// Derives KgNB from Kamf, uplink NAS COUNT, and access type distinguisher.
pub fn ogs_kdf_kgnb_and_kn3iwf(
    kamf: &[u8; SHA256_DIGEST_SIZE],
    ul_count: u32,
    access_type_distinguisher: u8,
) -> [u8; SHA256_DIGEST_SIZE] {
    let ul_count_be = ul_count.to_be_bytes();

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(ul_count_be.to_vec());
    params[0].len = 4;
    params[1].buf = Some(vec![access_type_distinguisher]);
    params[1].len = 1;

    ogs_kdf_common(kamf, FC_FOR_KGNB_KN3IWF_DERIVATION, &params)
}

/// TS33.501 Annex A.10: NH derivation function (5G)
///
/// Derives NH from Kamf and sync input.
pub fn ogs_kdf_nh_gnb(
    kamf: &[u8; SHA256_DIGEST_SIZE],
    sync_input: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut params = [KdfParam::default()];
    params[0].buf = Some(sync_input.to_vec());
    params[0].len = SHA256_DIGEST_SIZE as u16;

    ogs_kdf_common(kamf, FC_FOR_NH_GNB_DERIVATION, &params)
}

/// TS33.501 Annex C.3.4.1 Profile A / C.3.4.2 Profile B: ANSI-X9.63-KDF
///
/// Key derivation function for ECIES (Elliptic Curve Integrated Encryption Scheme).
/// Returns (encryption_key, initial_counter_block, mac_key).
pub fn ogs_kdf_ansi_x963(
    z: &[u8],
    info: &[u8],
) -> ([u8; OGS_KEY_LEN], [u8; OGS_IVEC_LEN], [u8; SHA256_DIGEST_SIZE]) {
    let counter_len = 4;

    // First iteration: counter = 1
    let mut input1 = Vec::with_capacity(z.len() + counter_len + info.len());
    input1.extend_from_slice(z);
    input1.extend_from_slice(&1u32.to_be_bytes());
    input1.extend_from_slice(info);

    let output1 = sha256(&input1);

    let mut ek = [0u8; OGS_KEY_LEN];
    let mut icb = [0u8; OGS_IVEC_LEN];
    ek.copy_from_slice(&output1[..OGS_KEY_LEN]);
    icb.copy_from_slice(&output1[OGS_KEY_LEN..OGS_KEY_LEN + OGS_IVEC_LEN]);

    // Second iteration: counter = 2
    let mut input2 = Vec::with_capacity(z.len() + counter_len + info.len());
    input2.extend_from_slice(z);
    input2.extend_from_slice(&2u32.to_be_bytes());
    input2.extend_from_slice(info);

    let mk = sha256(&input2);

    (ek, icb, mk)
}

/// TS33.401 Annex A.2: KASME derivation function
///
/// Derives KASME from CK, IK, PLMN ID, SQN, and AK.
pub fn ogs_auc_kasme(
    ck: &[u8; OGS_KEY_LEN],
    ik: &[u8; OGS_KEY_LEN],
    plmn_id: &[u8; OGS_PLMN_ID_LEN],
    sqn: &[u8; 6],
    ak: &[u8; 6],
) -> [u8; SHA256_DIGEST_SIZE] {
    // Key = CK || IK
    let mut key = [0u8; OGS_KEY_LEN * 2];
    key[..OGS_KEY_LEN].copy_from_slice(ck);
    key[OGS_KEY_LEN..].copy_from_slice(ik);

    // SQN XOR AK
    let mut sqn_xor_ak = [0u8; OGS_SQN_XOR_AK_LEN];
    for i in 0..6 {
        sqn_xor_ak[i] = sqn[i] ^ ak[i];
    }

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(plmn_id.to_vec());
    params[0].len = OGS_PLMN_ID_LEN as u16;
    params[1].buf = Some(sqn_xor_ak.to_vec());
    params[1].len = OGS_SQN_XOR_AK_LEN as u16;

    ogs_kdf_common(&key, FC_FOR_KASME, &params)
}

/// TS33.401 Annex A.3: KeNB derivation function
///
/// Derives KeNB from KASME and uplink NAS COUNT.
pub fn ogs_kdf_kenb(
    kasme: &[u8; SHA256_DIGEST_SIZE],
    ul_count: u32,
) -> [u8; SHA256_DIGEST_SIZE] {
    let ul_count_be = ul_count.to_be_bytes();

    let mut params = [KdfParam::default()];
    params[0].buf = Some(ul_count_be.to_vec());
    params[0].len = 4;

    ogs_kdf_common(kasme, FC_FOR_KENB_DERIVATION, &params)
}

/// TS33.401 Annex A.4: NH derivation function (EPS)
///
/// Derives NH from KASME and sync input.
pub fn ogs_kdf_nh_enb(
    kasme: &[u8; SHA256_DIGEST_SIZE],
    sync_input: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut params = [KdfParam::default()];
    params[0].buf = Some(sync_input.to_vec());
    params[0].len = SHA256_DIGEST_SIZE as u16;

    ogs_kdf_common(kasme, FC_FOR_NH_ENB_DERIVATION, &params)
}

/// TS33.401 Annex A.7: Algorithm key derivation functions (EPS)
///
/// Derives NAS keys from KASME.
/// Returns the 16-byte key (lower 16 bytes of the 32-byte output).
pub fn ogs_kdf_nas_eps(
    algorithm_type_distinguishers: u8,
    algorithm_identity: u8,
    kasme: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; OGS_KEY_LEN] {
    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(vec![algorithm_type_distinguishers]);
    params[0].len = 1;
    params[1].buf = Some(vec![algorithm_identity]);
    params[1].len = 1;

    let output = ogs_kdf_common(kasme, FC_FOR_EPS_ALGORITHM_KEY_DERIVATION, &params);

    // Return lower 16 bytes
    let mut knas = [0u8; OGS_KEY_LEN];
    knas.copy_from_slice(&output[16..]);
    knas
}

/// TS33.401 Annex A.8: KASME to CK', IK' derivation at handover
///
/// Derives CK' and IK' from KASME and downlink NAS COUNT.
pub fn ogs_kdf_ck_ik_handover(
    dl_count: u32,
    kasme: &[u8; SHA256_DIGEST_SIZE],
) -> ([u8; OGS_KEY_LEN], [u8; OGS_KEY_LEN]) {
    let dl_count_bytes = dl_count.to_ne_bytes(); // Note: C code uses native byte order here

    let mut params = [KdfParam::default()];
    params[0].buf = Some(dl_count_bytes.to_vec());
    params[0].len = 4;

    let output = ogs_kdf_common(kasme, FC_FOR_CK_IK_DERIVATION_HANDOVER, &params);

    let mut ck = [0u8; OGS_KEY_LEN];
    let mut ik = [0u8; OGS_KEY_LEN];
    ck.copy_from_slice(&output[..16]);
    ik.copy_from_slice(&output[16..]);

    (ck, ik)
}

/// TS33.401 Annex A.9: NAS token derivation for inter-RAT mobility
///
/// Derives NAS token from KASME and uplink NAS COUNT.
/// Returns the 2-byte NAS token.
pub fn ogs_kdf_nas_token(
    ul_count: u32,
    kasme: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; 2] {
    let ul_count_bytes = ul_count.to_ne_bytes(); // Note: C code uses native byte order here

    let mut params = [KdfParam::default()];
    params[0].buf = Some(ul_count_bytes.to_vec());
    params[0].len = 4;

    let output = ogs_kdf_common(kasme, FC_FOR_NAS_TOKEN_DERIVATION, &params);

    let mut nas_token = [0u8; 2];
    nas_token.copy_from_slice(&output[..2]);
    nas_token
}

/// TS33.401 Annex A.11: K'ASME from CK, IK derivation during idle mode mobility
///
/// Derives K'ASME from CK, IK, nonce_ue, and nonce_mme.
pub fn ogs_kdf_kasme_idle_mobility(
    ck: &[u8; OGS_KEY_LEN],
    ik: &[u8; OGS_KEY_LEN],
    nonce_ue: u32,
    nonce_mme: u32,
) -> [u8; SHA256_DIGEST_SIZE] {
    // Key = CK || IK
    let mut key = [0u8; OGS_KEY_LEN * 2];
    key[..OGS_KEY_LEN].copy_from_slice(ck);
    key[OGS_KEY_LEN..].copy_from_slice(ik);

    // Note: C code uses native byte order for nonces
    let nonce_ue_bytes = nonce_ue.to_ne_bytes();
    let nonce_mme_bytes = nonce_mme.to_ne_bytes();

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(nonce_ue_bytes.to_vec());
    params[0].len = 4;
    params[1].buf = Some(nonce_mme_bytes.to_vec());
    params[1].len = 4;

    ogs_kdf_common(&key, FC_FOR_KASME_DERIVATION_IDLE_MOBILITY, &params)
}

/// TS33.401 Annex A.13: KASME to CK', IK' derivation at idle mobility
///
/// Derives CK' and IK' from KASME and uplink NAS COUNT.
pub fn ogs_kdf_ck_ik_idle_mobility(
    ul_count: u32,
    kasme: &[u8; SHA256_DIGEST_SIZE],
) -> ([u8; OGS_KEY_LEN], [u8; OGS_KEY_LEN]) {
    let ul_count_bytes = ul_count.to_ne_bytes(); // Note: C code uses native byte order here

    let mut params = [KdfParam::default()];
    params[0].buf = Some(ul_count_bytes.to_vec());
    params[0].len = 4;

    let output = ogs_kdf_common(kasme, FC_FOR_CK_IK_DERIVATION_IDLE_MOBILITY, &params);

    let mut ck = [0u8; OGS_KEY_LEN];
    let mut ik = [0u8; OGS_KEY_LEN];
    ck.copy_from_slice(&output[..16]);
    ik.copy_from_slice(&output[16..]);

    (ck, ik)
}

/// TS33.401 Annex I: Hash Functions (Hash-MME)
///
/// Computes Hash-MME using HMAC-SHA256 with zero key.
/// Returns the 8-byte hash (last 8 bytes of the 32-byte output).
pub fn ogs_kdf_hash_mme(message: &[u8]) -> [u8; OGS_HASH_MME_LEN] {
    let key = [0u8; 32];

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    let output = result.into_bytes();

    let mut hash_mme = [0u8; OGS_HASH_MME_LEN];
    hash_mme.copy_from_slice(&output[24..]);
    hash_mme
}

/// TS33.102 6.3.3: Authentication and key agreement - SQN extraction
///
/// Extracts SQN from AUTS for re-synchronization.
/// Returns (sqn_ms, mac_s).
pub fn ogs_auc_sqn(
    opc: &[u8; 16],
    k: &[u8; 16],
    rand: &[u8; 16],
    conc_sqn_ms: &[u8; 6],
) -> Result<([u8; 6], [u8; 8]), milenage::MilenageError> {
    // AMF = 0x0000 for re-sync (TS 33.102 v7.0.0, 6.3.3)
    let amf = [0x00u8, 0x00];

    // Get AK* using f5*
    let (_res, _ck, _ik, _ak, akstar) = milenage::milenage_f2345(opc, k, rand)?;

    // SQN_MS = CONC_SQN_MS XOR AK*
    let mut sqn_ms = [0u8; 6];
    for i in 0..6 {
        sqn_ms[i] = akstar[i] ^ conc_sqn_ms[i];
    }

    // Compute MAC-S using f1*
    let (_mac_a, mac_s) = milenage::milenage_f1(opc, k, rand, &sqn_ms, &amf)?;

    Ok((sqn_ms, mac_s))
}

/// Helper function to extract value from ID string (e.g., "imsi-123456789" -> "123456789")
///
/// This is a port of ogs_id_get_value from lib/proto/types.c
fn ogs_id_get_value(id: &str) -> String {
    // Split by '-' and get the second part
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        id.to_string()
    }
}
