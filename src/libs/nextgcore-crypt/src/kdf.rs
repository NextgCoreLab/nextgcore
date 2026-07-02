//! Key Derivation Functions
//!
//! Exact port of lib/crypt/nextgcore-kdf.c
//!
//! Implements key derivation functions as defined in:
//! - 3GPP TS 33.501 (5G Security)
//! - 3GPP TS 33.401 (EPS Security)
//! - 3GPP TS 33.220 (Generic Bootstrapping Architecture)
//! - 3GPP TS 33.102 (3G Security)

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::milenage;
use crate::sha::{sha256, SHA256_DIGEST_SIZE};

// Length constants
pub const NEXTGCORE_KEY_LEN: usize = 16;
pub const NEXTGCORE_IVEC_LEN: usize = 16;
pub const NEXTGCORE_RAND_LEN: usize = 16;
pub const NEXTGCORE_SQN_XOR_AK_LEN: usize = 6;
pub const NEXTGCORE_PLMN_ID_LEN: usize = 3;
pub const NEXTGCORE_HASH_MME_LEN: usize = 8;
pub const ECC_BYTES: usize = 32; // secp256r1

// FC (Function Code) values for KDF
const FC_FOR_CK_PRIME_IK_PRIME_DERIVATION: u8 = 0x20;
const FC_FOR_5GS_ALGORITHM_KEY_DERIVATION: u8 = 0x69;
const FC_FOR_KAUSF_DERIVATION: u8 = 0x6A;
const FC_FOR_RES_STAR_XRES_STAR_DERIVATION: u8 = 0x6B;
const FC_FOR_KSEAF_DERIVATION: u8 = 0x6C;
const FC_FOR_KAMF_DERIVATION: u8 = 0x6D;
const FC_FOR_KGNB_KN3IWF_DERIVATION: u8 = 0x6E;
const FC_FOR_NH_GNB_DERIVATION: u8 = 0x6F;
const FC_FOR_SOR_MAC_IAUSF_DERIVATION: u8 = 0x77;
const FC_FOR_SOR_MAC_IUE_DERIVATION: u8 = 0x78;
const FC_FOR_UPU_MAC_IAUSF_DERIVATION: u8 = 0x7B;
const FC_FOR_UPU_MAC_IUE_DERIVATION: u8 = 0x7C;

const FC_FOR_KASME: u8 = 0x10;
const FC_FOR_KENB_DERIVATION: u8 = 0x11;
const FC_FOR_NH_ENB_DERIVATION: u8 = 0x12;
const FC_FOR_EPS_ALGORITHM_KEY_DERIVATION: u8 = 0x15;
const FC_FOR_CK_IK_DERIVATION_HANDOVER: u8 = 0x16;
const FC_FOR_NAS_TOKEN_DERIVATION: u8 = 0x17;
const FC_FOR_KASME_DERIVATION_IDLE_MOBILITY: u8 = 0x19;
const FC_FOR_CK_IK_DERIVATION_IDLE_MOBILITY: u8 = 0x1B;

// Algorithm Type Distinguishers
pub const NEXTGCORE_KDF_NAS_ENC_ALG: u8 = 0x01;
pub const NEXTGCORE_KDF_NAS_INT_ALG: u8 = 0x02;

type HmacSha256 = Hmac<Sha256>;

/// KDF parameter structure
#[derive(Default)]
struct KdfParam {
    buf: Option<Vec<u8>>,
    len: u16,
}

/// Common KDF function as defined in TS 33.220 clause B.2.0
///
/// This is the core key derivation function used by all other KDF functions.
fn nextgcore_kdf_common(key: &[u8], fc: u8, params: &[KdfParam]) -> [u8; SHA256_DIGEST_SIZE] {
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
    let mut mac = HmacSha256::new_from_slice(key).expect("value expected");
    mac.update(&s);
    let result = mac.finalize();

    let mut output = [0u8; SHA256_DIGEST_SIZE];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// TS33.501 Annex A.2: Kausf derivation function
///
/// Derives Kausf from CK, IK, serving network name, and AUTN.
pub fn nextgcore_kdf_kausf(
    ck: &[u8; NEXTGCORE_KEY_LEN],
    ik: &[u8; NEXTGCORE_KEY_LEN],
    serving_network_name: &str,
    autn: &[u8],
) -> [u8; SHA256_DIGEST_SIZE] {
    // Key = CK || IK
    let mut key = [0u8; NEXTGCORE_KEY_LEN * 2];
    key[..NEXTGCORE_KEY_LEN].copy_from_slice(ck);
    key[NEXTGCORE_KEY_LEN..].copy_from_slice(ik);

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(serving_network_name.as_bytes().to_vec());
    params[0].len = serving_network_name.len() as u16;
    params[1].buf = Some(autn[..NEXTGCORE_SQN_XOR_AK_LEN].to_vec());
    params[1].len = NEXTGCORE_SQN_XOR_AK_LEN as u16;

    nextgcore_kdf_common(&key, FC_FOR_KAUSF_DERIVATION, &params)
}

/// TS 33.501 Annex A.3: CK' and IK' derivation function (EAP-AKA', RFC 5448 §3.3)
///
/// Derives CK' and IK' from CK, IK, the serving network name and SQN xor AK:
/// `CK' || IK' = KDF(CK || IK, FC=0x20, SN name, SQN xor AK)`.
///
/// Used by the UDM/ARPF when producing an EAP-AKA' transformed authentication
/// vector (TS 33.501 §6.1.3.1) and by the AUSF for verification.
pub fn nextgcore_kdf_ck_ik_prime(
    ck: &[u8; NEXTGCORE_KEY_LEN],
    ik: &[u8; NEXTGCORE_KEY_LEN],
    serving_network_name: &str,
    sqn_xor_ak: &[u8; NEXTGCORE_SQN_XOR_AK_LEN],
) -> ([u8; NEXTGCORE_KEY_LEN], [u8; NEXTGCORE_KEY_LEN]) {
    // Key = CK || IK
    let mut key = [0u8; NEXTGCORE_KEY_LEN * 2];
    key[..NEXTGCORE_KEY_LEN].copy_from_slice(ck);
    key[NEXTGCORE_KEY_LEN..].copy_from_slice(ik);

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(serving_network_name.as_bytes().to_vec());
    params[0].len = serving_network_name.len() as u16;
    params[1].buf = Some(sqn_xor_ak.to_vec());
    params[1].len = NEXTGCORE_SQN_XOR_AK_LEN as u16;

    let output = nextgcore_kdf_common(&key, FC_FOR_CK_PRIME_IK_PRIME_DERIVATION, &params);

    let mut ck_prime = [0u8; NEXTGCORE_KEY_LEN];
    let mut ik_prime = [0u8; NEXTGCORE_KEY_LEN];
    ck_prime.copy_from_slice(&output[..NEXTGCORE_KEY_LEN]);
    ik_prime.copy_from_slice(&output[NEXTGCORE_KEY_LEN..]);
    (ck_prime, ik_prime)
}

/// TS33.501 Annex A.4: RES* and XRES* derivation function
///
/// Derives XRES* from CK, IK, serving network name, RAND, and XRES.
/// Returns the 16-byte XRES* (lower 16 bytes of the 32-byte output).
pub fn nextgcore_kdf_xres_star(
    ck: &[u8; NEXTGCORE_KEY_LEN],
    ik: &[u8; NEXTGCORE_KEY_LEN],
    serving_network_name: &str,
    rand: &[u8; NEXTGCORE_RAND_LEN],
    xres: &[u8],
) -> [u8; NEXTGCORE_KEY_LEN] {
    // Key = CK || IK
    let mut key = [0u8; NEXTGCORE_KEY_LEN * 2];
    key[..NEXTGCORE_KEY_LEN].copy_from_slice(ck);
    key[NEXTGCORE_KEY_LEN..].copy_from_slice(ik);

    let mut params = [
        KdfParam::default(),
        KdfParam::default(),
        KdfParam::default(),
    ];
    params[0].buf = Some(serving_network_name.as_bytes().to_vec());
    params[0].len = serving_network_name.len() as u16;
    params[1].buf = Some(rand.to_vec());
    params[1].len = NEXTGCORE_RAND_LEN as u16;
    params[2].buf = Some(xres.to_vec());
    params[2].len = xres.len() as u16;

    let output = nextgcore_kdf_common(&key, FC_FOR_RES_STAR_XRES_STAR_DERIVATION, &params);

    // Return lower 16 bytes
    let mut xres_star = [0u8; NEXTGCORE_KEY_LEN];
    xres_star.copy_from_slice(&output[NEXTGCORE_KEY_LEN..]);
    xres_star
}

/// TS33.501 Annex A.5: HRES* and HXRES* derivation function
///
/// Derives HXRES* from RAND and XRES*.
/// Returns the 16-byte HXRES* (lower 16 bytes of SHA-256 hash).
pub fn nextgcore_kdf_hxres_star(
    rand: &[u8; NEXTGCORE_RAND_LEN],
    xres_star: &[u8; NEXTGCORE_KEY_LEN],
) -> [u8; NEXTGCORE_KEY_LEN] {
    // message = RAND || XRES*
    let mut message = [0u8; NEXTGCORE_RAND_LEN + NEXTGCORE_KEY_LEN];
    message[..NEXTGCORE_RAND_LEN].copy_from_slice(rand);
    message[NEXTGCORE_RAND_LEN..].copy_from_slice(xres_star);

    let output = sha256(&message);

    // Return lower 16 bytes
    let mut hxres_star = [0u8; NEXTGCORE_KEY_LEN];
    hxres_star.copy_from_slice(&output[NEXTGCORE_KEY_LEN..]);
    hxres_star
}

/// TS33.501 Annex A.6: Kseaf derivation function
///
/// Derives Kseaf from serving network name and Kausf.
pub fn nextgcore_kdf_kseaf(
    serving_network_name: &str,
    kausf: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut params = [KdfParam::default()];
    params[0].buf = Some(serving_network_name.as_bytes().to_vec());
    params[0].len = serving_network_name.len() as u16;

    nextgcore_kdf_common(kausf, FC_FOR_KSEAF_DERIVATION, &params)
}

/// TS33.501 Annex A.7: Kamf derivation function
///
/// Derives Kamf from SUPI, ABBA, and Kseaf.
pub fn nextgcore_kdf_kamf(
    supi: &str,
    abba: &[u8],
    kseaf: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    // Extract the value part from SUPI (e.g., "imsi-123456789" -> "123456789")
    let val = nextgcore_id_get_value(supi);

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(val.as_bytes().to_vec());
    params[0].len = val.len() as u16;
    params[1].buf = Some(abba.to_vec());
    params[1].len = abba.len() as u16;

    nextgcore_kdf_common(kseaf, FC_FOR_KAMF_DERIVATION, &params)
}

/// TS33.501 Annex A.8: Algorithm key derivation functions (5GS)
///
/// Derives NAS keys from Kamf.
/// Returns the 16-byte key (lower 16 bytes of the 32-byte output).
pub fn nextgcore_kdf_nas_5gs(
    algorithm_type_distinguishers: u8,
    algorithm_identity: u8,
    kamf: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; NEXTGCORE_KEY_LEN] {
    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(vec![algorithm_type_distinguishers]);
    params[0].len = 1;
    params[1].buf = Some(vec![algorithm_identity]);
    params[1].len = 1;

    let output = nextgcore_kdf_common(kamf, FC_FOR_5GS_ALGORITHM_KEY_DERIVATION, &params);

    // Return lower 16 bytes
    let mut knas = [0u8; NEXTGCORE_KEY_LEN];
    knas.copy_from_slice(&output[16..]);
    knas
}

/// TS33.501 Annex A.9: KgNB and Kn3iwf derivation function
///
/// Derives KgNB from Kamf, uplink NAS COUNT, and access type distinguisher.
pub fn nextgcore_kdf_kgnb_and_kn3iwf(
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

    nextgcore_kdf_common(kamf, FC_FOR_KGNB_KN3IWF_DERIVATION, &params)
}

/// TS33.501 Annex A.10: NH derivation function (5G)
///
/// Derives NH from Kamf and sync input.
pub fn nextgcore_kdf_nh_gnb(
    kamf: &[u8; SHA256_DIGEST_SIZE],
    sync_input: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut params = [KdfParam::default()];
    params[0].buf = Some(sync_input.to_vec());
    params[0].len = SHA256_DIGEST_SIZE as u16;

    nextgcore_kdf_common(kamf, FC_FOR_NH_GNB_DERIVATION, &params)
}

/// TS 33.501 Annex A.17: SoR-MAC-I_AUSF generation function
///
/// `S = FC(0x77) || P0(SoR header) || L0 || P1(Counter_SoR, 2 bytes BE) || L1(0x0002)
///      [ || P2(steering-list octets) || L2 ]`
///
/// * `sor_header` — the SOR header received from the requester NF (e.g. UDM) or
///   constructed by the AUSF per TS 24.501 §9.11.3.51.
/// * `steering_list` — the octets included in the SOR transparent container
///   beyond (and not including) octet 22 (TS 24.501 §9.11.3.51). When `None`
///   (no list / no secured packet in the Nausf_SoRProtection invocation),
///   **P2 and L2 are not included at all** (A.17: "P2 and L2 are not included
///   for SoR-MAC-I_AUSF generation") — omission, not an empty P2 with L2=0.
///   An empty `Some(&[])` is normalised to the same omission.
///
/// Returns the 128 **least** significant bits (the LAST 16 bytes) of the
/// TS 33.220 B.2.0 HMAC-SHA-256 output.
///
/// Counter policy (TS 33.501 §6.14.2.3): `counter_sor` 0x0000 shall never be
/// used; callers must obtain counters from the per-SUPI anchor store.
pub fn nextgcore_kdf_sor_mac_iausf(
    kausf: &[u8; SHA256_DIGEST_SIZE],
    sor_header: &[u8],
    counter_sor: u16,
    steering_list: Option<&[u8]>,
) -> [u8; NEXTGCORE_KEY_LEN] {
    debug_assert!(counter_sor != 0, "Counter_SoR 0x0000 is forbidden (TS 33.501 §6.14.2.3)");

    let mut params = [
        KdfParam::default(),
        KdfParam::default(),
        KdfParam::default(),
    ];
    params[0].buf = Some(sor_header.to_vec());
    params[0].len = sor_header.len() as u16;
    params[1].buf = Some(counter_sor.to_be_bytes().to_vec());
    params[1].len = 2;
    if let Some(list) = steering_list {
        // Zero-length P2 is skipped by nextgcore_kdf_common (len == 0), which
        // realises the A.17 omission rule for an absent steering list.
        params[2].buf = Some(list.to_vec());
        params[2].len = list.len() as u16;
    }

    let output = nextgcore_kdf_common(kausf, FC_FOR_SOR_MAC_IAUSF_DERIVATION, &params);

    // 128 least significant bits = last 16 bytes of the 32-byte output.
    let mut mac = [0u8; NEXTGCORE_KEY_LEN];
    mac.copy_from_slice(&output[NEXTGCORE_KEY_LEN..]);
    mac
}

/// TS 33.501 Annex A.18: SoR-MAC-I_UE / SoR-XMAC-I_UE generation function
///
/// `S = FC(0x78) || P0(0x01 SoR acknowledgement) || L0(0x0001)
///      || P1(Counter_SoR, 2 bytes BE) || L1(0x0002)`
///
/// P0 is the fixed SoR Acknowledgement value 0x01 ("Verified the Steering of
/// Roaming Information successfully"). Returns the 128 least significant bits
/// (last 16 bytes) of the HMAC-SHA-256 output.
pub fn nextgcore_kdf_sor_mac_iue(
    kausf: &[u8; SHA256_DIGEST_SIZE],
    counter_sor: u16,
) -> [u8; NEXTGCORE_KEY_LEN] {
    debug_assert!(counter_sor != 0, "Counter_SoR 0x0000 is forbidden (TS 33.501 §6.14.2.3)");

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(vec![0x01]);
    params[0].len = 1;
    params[1].buf = Some(counter_sor.to_be_bytes().to_vec());
    params[1].len = 2;

    let output = nextgcore_kdf_common(kausf, FC_FOR_SOR_MAC_IUE_DERIVATION, &params);

    let mut mac = [0u8; NEXTGCORE_KEY_LEN];
    mac.copy_from_slice(&output[NEXTGCORE_KEY_LEN..]);
    mac
}

/// TS 33.501 Annex A.19: UPU-MAC-I_AUSF generation function
///
/// `S = FC(0x7B) || P0(UE Parameters Update Data) || L0
///      || P1(Counter_UPU, 2 bytes BE) || L1(0x0002)`
///
/// `upu_data` — the UE parameters update list per TS 24.501 §9.11.3.53A
/// starting from octet 23. Returns the 128 least significant bits (last 16
/// bytes) of the HMAC-SHA-256 output.
///
/// Counter policy (TS 33.501 §6.15.2.2): `counter_upu` 0x0000 shall never be
/// used; callers must obtain counters from the per-SUPI anchor store.
pub fn nextgcore_kdf_upu_mac_iausf(
    kausf: &[u8; SHA256_DIGEST_SIZE],
    upu_data: &[u8],
    counter_upu: u16,
) -> [u8; NEXTGCORE_KEY_LEN] {
    debug_assert!(counter_upu != 0, "Counter_UPU 0x0000 is forbidden (TS 33.501 §6.15.2.2)");

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(upu_data.to_vec());
    params[0].len = upu_data.len() as u16;
    params[1].buf = Some(counter_upu.to_be_bytes().to_vec());
    params[1].len = 2;

    let output = nextgcore_kdf_common(kausf, FC_FOR_UPU_MAC_IAUSF_DERIVATION, &params);

    let mut mac = [0u8; NEXTGCORE_KEY_LEN];
    mac.copy_from_slice(&output[NEXTGCORE_KEY_LEN..]);
    mac
}

/// TS 33.501 Annex A.20: UPU-MAC-I_UE / UPU-XMAC-I_UE generation function
///
/// `S = FC(0x7C) || P0(0x01 UPU acknowledgement) || L0(0x0001)
///      || P1(Counter_UPU, 2 bytes BE) || L1(0x0002)`
///
/// P0 is the fixed UPU Acknowledgement value 0x01 ("Verified the UE Parameters
/// Update Data successfully"). Returns the 128 least significant bits (last 16
/// bytes) of the HMAC-SHA-256 output.
pub fn nextgcore_kdf_upu_mac_iue(
    kausf: &[u8; SHA256_DIGEST_SIZE],
    counter_upu: u16,
) -> [u8; NEXTGCORE_KEY_LEN] {
    debug_assert!(counter_upu != 0, "Counter_UPU 0x0000 is forbidden (TS 33.501 §6.15.2.2)");

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(vec![0x01]);
    params[0].len = 1;
    params[1].buf = Some(counter_upu.to_be_bytes().to_vec());
    params[1].len = 2;

    let output = nextgcore_kdf_common(kausf, FC_FOR_UPU_MAC_IUE_DERIVATION, &params);

    let mut mac = [0u8; NEXTGCORE_KEY_LEN];
    mac.copy_from_slice(&output[NEXTGCORE_KEY_LEN..]);
    mac
}

/// TS33.501 Annex C.3.4.1 Profile A / C.3.4.2 Profile B: ANSI-X9.63-KDF
///
/// Key derivation function for ECIES (Elliptic Curve Integrated Encryption Scheme).
/// Returns (encryption_key, initial_counter_block, mac_key).
pub fn nextgcore_kdf_ansi_x963(
    z: &[u8],
    info: &[u8],
) -> (
    [u8; NEXTGCORE_KEY_LEN],
    [u8; NEXTGCORE_IVEC_LEN],
    [u8; SHA256_DIGEST_SIZE],
) {
    let counter_len = 4;

    // First iteration: counter = 1
    let mut input1 = Vec::with_capacity(z.len() + counter_len + info.len());
    input1.extend_from_slice(z);
    input1.extend_from_slice(&1u32.to_be_bytes());
    input1.extend_from_slice(info);

    let output1 = sha256(&input1);

    let mut ek = [0u8; NEXTGCORE_KEY_LEN];
    let mut icb = [0u8; NEXTGCORE_IVEC_LEN];
    ek.copy_from_slice(&output1[..NEXTGCORE_KEY_LEN]);
    icb.copy_from_slice(&output1[NEXTGCORE_KEY_LEN..NEXTGCORE_KEY_LEN + NEXTGCORE_IVEC_LEN]);

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
pub fn nextgcore_auc_kasme(
    ck: &[u8; NEXTGCORE_KEY_LEN],
    ik: &[u8; NEXTGCORE_KEY_LEN],
    plmn_id: &[u8; NEXTGCORE_PLMN_ID_LEN],
    sqn: &[u8; 6],
    ak: &[u8; 6],
) -> [u8; SHA256_DIGEST_SIZE] {
    // Key = CK || IK
    let mut key = [0u8; NEXTGCORE_KEY_LEN * 2];
    key[..NEXTGCORE_KEY_LEN].copy_from_slice(ck);
    key[NEXTGCORE_KEY_LEN..].copy_from_slice(ik);

    // SQN XOR AK
    let mut sqn_xor_ak = [0u8; NEXTGCORE_SQN_XOR_AK_LEN];
    for i in 0..6 {
        sqn_xor_ak[i] = sqn[i] ^ ak[i];
    }

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(plmn_id.to_vec());
    params[0].len = NEXTGCORE_PLMN_ID_LEN as u16;
    params[1].buf = Some(sqn_xor_ak.to_vec());
    params[1].len = NEXTGCORE_SQN_XOR_AK_LEN as u16;

    nextgcore_kdf_common(&key, FC_FOR_KASME, &params)
}

/// TS33.401 Annex A.3: KeNB derivation function
///
/// Derives KeNB from KASME and uplink NAS COUNT.
pub fn nextgcore_kdf_kenb(
    kasme: &[u8; SHA256_DIGEST_SIZE],
    ul_count: u32,
) -> [u8; SHA256_DIGEST_SIZE] {
    let ul_count_be = ul_count.to_be_bytes();

    let mut params = [KdfParam::default()];
    params[0].buf = Some(ul_count_be.to_vec());
    params[0].len = 4;

    nextgcore_kdf_common(kasme, FC_FOR_KENB_DERIVATION, &params)
}

/// TS33.401 Annex A.4: NH derivation function (EPS)
///
/// Derives NH from KASME and sync input.
pub fn nextgcore_kdf_nh_enb(
    kasme: &[u8; SHA256_DIGEST_SIZE],
    sync_input: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut params = [KdfParam::default()];
    params[0].buf = Some(sync_input.to_vec());
    params[0].len = SHA256_DIGEST_SIZE as u16;

    nextgcore_kdf_common(kasme, FC_FOR_NH_ENB_DERIVATION, &params)
}

/// TS33.401 Annex A.7: Algorithm key derivation functions (EPS)
///
/// Derives NAS keys from KASME.
/// Returns the 16-byte key (lower 16 bytes of the 32-byte output).
pub fn nextgcore_kdf_nas_eps(
    algorithm_type_distinguishers: u8,
    algorithm_identity: u8,
    kasme: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; NEXTGCORE_KEY_LEN] {
    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(vec![algorithm_type_distinguishers]);
    params[0].len = 1;
    params[1].buf = Some(vec![algorithm_identity]);
    params[1].len = 1;

    let output = nextgcore_kdf_common(kasme, FC_FOR_EPS_ALGORITHM_KEY_DERIVATION, &params);

    // Return lower 16 bytes
    let mut knas = [0u8; NEXTGCORE_KEY_LEN];
    knas.copy_from_slice(&output[16..]);
    knas
}

/// TS33.401 Annex A.8: KASME to CK', IK' derivation at handover
///
/// Derives CK' and IK' from KASME and downlink NAS COUNT.
pub fn nextgcore_kdf_ck_ik_handover(
    dl_count: u32,
    kasme: &[u8; SHA256_DIGEST_SIZE],
) -> ([u8; NEXTGCORE_KEY_LEN], [u8; NEXTGCORE_KEY_LEN]) {
    let dl_count_bytes = dl_count.to_ne_bytes(); // Note: C code uses native byte order here

    let mut params = [KdfParam::default()];
    params[0].buf = Some(dl_count_bytes.to_vec());
    params[0].len = 4;

    let output = nextgcore_kdf_common(kasme, FC_FOR_CK_IK_DERIVATION_HANDOVER, &params);

    let mut ck = [0u8; NEXTGCORE_KEY_LEN];
    let mut ik = [0u8; NEXTGCORE_KEY_LEN];
    ck.copy_from_slice(&output[..16]);
    ik.copy_from_slice(&output[16..]);

    (ck, ik)
}

/// TS33.401 Annex A.9: NAS token derivation for inter-RAT mobility
///
/// Derives NAS token from KASME and uplink NAS COUNT.
/// Returns the 2-byte NAS token.
pub fn nextgcore_kdf_nas_token(ul_count: u32, kasme: &[u8; SHA256_DIGEST_SIZE]) -> [u8; 2] {
    let ul_count_bytes = ul_count.to_ne_bytes(); // Note: C code uses native byte order here

    let mut params = [KdfParam::default()];
    params[0].buf = Some(ul_count_bytes.to_vec());
    params[0].len = 4;

    let output = nextgcore_kdf_common(kasme, FC_FOR_NAS_TOKEN_DERIVATION, &params);

    let mut nas_token = [0u8; 2];
    nas_token.copy_from_slice(&output[..2]);
    nas_token
}

/// TS33.401 Annex A.11: K'ASME from CK, IK derivation during idle mode mobility
///
/// Derives K'ASME from CK, IK, nonce_ue, and nonce_mme.
pub fn nextgcore_kdf_kasme_idle_mobility(
    ck: &[u8; NEXTGCORE_KEY_LEN],
    ik: &[u8; NEXTGCORE_KEY_LEN],
    nonce_ue: u32,
    nonce_mme: u32,
) -> [u8; SHA256_DIGEST_SIZE] {
    // Key = CK || IK
    let mut key = [0u8; NEXTGCORE_KEY_LEN * 2];
    key[..NEXTGCORE_KEY_LEN].copy_from_slice(ck);
    key[NEXTGCORE_KEY_LEN..].copy_from_slice(ik);

    // Note: C code uses native byte order for nonces
    let nonce_ue_bytes = nonce_ue.to_ne_bytes();
    let nonce_mme_bytes = nonce_mme.to_ne_bytes();

    let mut params = [KdfParam::default(), KdfParam::default()];
    params[0].buf = Some(nonce_ue_bytes.to_vec());
    params[0].len = 4;
    params[1].buf = Some(nonce_mme_bytes.to_vec());
    params[1].len = 4;

    nextgcore_kdf_common(&key, FC_FOR_KASME_DERIVATION_IDLE_MOBILITY, &params)
}

/// TS33.401 Annex A.13: KASME to CK', IK' derivation at idle mobility
///
/// Derives CK' and IK' from KASME and uplink NAS COUNT.
pub fn nextgcore_kdf_ck_ik_idle_mobility(
    ul_count: u32,
    kasme: &[u8; SHA256_DIGEST_SIZE],
) -> ([u8; NEXTGCORE_KEY_LEN], [u8; NEXTGCORE_KEY_LEN]) {
    let ul_count_bytes = ul_count.to_ne_bytes(); // Note: C code uses native byte order here

    let mut params = [KdfParam::default()];
    params[0].buf = Some(ul_count_bytes.to_vec());
    params[0].len = 4;

    let output = nextgcore_kdf_common(kasme, FC_FOR_CK_IK_DERIVATION_IDLE_MOBILITY, &params);

    let mut ck = [0u8; NEXTGCORE_KEY_LEN];
    let mut ik = [0u8; NEXTGCORE_KEY_LEN];
    ck.copy_from_slice(&output[..16]);
    ik.copy_from_slice(&output[16..]);

    (ck, ik)
}

/// TS33.401 Annex I: Hash Functions (Hash-MME)
///
/// Computes Hash-MME using HMAC-SHA256 with zero key.
/// Returns the 8-byte hash (last 8 bytes of the 32-byte output).
pub fn nextgcore_kdf_hash_mme(message: &[u8]) -> [u8; NEXTGCORE_HASH_MME_LEN] {
    let key = [0u8; 32];

    let mut mac = HmacSha256::new_from_slice(&key).expect("value expected");
    mac.update(message);
    let result = mac.finalize();
    let output = result.into_bytes();

    let mut hash_mme = [0u8; NEXTGCORE_HASH_MME_LEN];
    hash_mme.copy_from_slice(&output[24..]);
    hash_mme
}

/// TS33.102 6.3.3: Authentication and key agreement - SQN extraction
///
/// Extracts SQN from AUTS for re-synchronization.
/// Returns (sqn_ms, mac_s).
pub fn nextgcore_auc_sqn(
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
/// This is a port of nextgcore_id_get_value from lib/proto/types.c
fn nextgcore_id_get_value(id: &str) -> String {
    // Split by '-' and get the second part
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5448 (EAP-AKA') test vector 1: CK'/IK' derivation.
    ///
    /// Network name "WLAN"; SQN xor AK = AUTN[0..6].
    #[test]
    fn test_ck_ik_prime_rfc5448_vector1() {
        let ck_v = unhex("5349fbe098649f948f5d2e973a81c00f");
        let ik_v = unhex("9744871ad32bf9bbd1dd5ce54e3e2e5a");
        let autn = unhex("bb52e91c747ac3ab2a5c23d15ee351d5");

        let mut ck = [0u8; 16];
        ck.copy_from_slice(&ck_v);
        let mut ik = [0u8; 16];
        ik.copy_from_slice(&ik_v);
        let mut sqn_xor_ak = [0u8; 6];
        sqn_xor_ak.copy_from_slice(&autn[..6]);

        let (ck_prime, ik_prime) = nextgcore_kdf_ck_ik_prime(&ck, &ik, "WLAN", &sqn_xor_ak);

        assert_eq!(
            &ck_prime[..],
            &unhex("0093962d0dd84aa5684b045c9edffa04")[..]
        );
        assert_eq!(
            &ik_prime[..],
            &unhex("ccfc230ca74fcc96c0a5d61164f5a76c")[..]
        );
    }

    // ========================================================================
    // TS 33.501 Annex A.17–A.20 SoR/UPU MAC KATs (F-01).
    //
    // TS 33.501 contains NO official test vectors for these MACs (A.17–A.20
    // define construction only), so the expected MACs below are SELF-DERIVED
    // golden vectors: each test hand-assembles the S byte string per the annex
    // and computes HMAC-SHA-256 with the raw `Hmac<Sha256>` primitive —
    // deliberately NOT via `nextgcore_kdf_common`, to avoid self-confirmation —
    // then locks the resulting hex constants. The same constants were
    // cross-derived with an independent Python `hmac`/`hashlib` recompute.
    //
    // Shared inputs (documented so a reviewer can reproduce every MAC):
    //   KAUSF_1  = 000102...1e1f                     (bytes 0x00..=0x1f)
    //   KAUSF_2  = ffeeddccbbaa99887766554433221100 x2
    //   SOR_HDR_ACK    = 0x0a (example SOR header octet, ack requested)
    //   SOR_HDR_NO_ACK = 0x02 (example SOR header octet, no ack)
    //   STEERING = 00f110800032f4024000  (two PLMN+access-tech entries,
    //              container octets beyond octet 22, TS 24.501 §9.11.3.51)
    //   UPU_DATA_1 = a0a1a2a3a4a5, UPU_DATA_2 = b0b1b2b3
    //              (UPU list octets from octet 23, TS 24.501 §9.11.3.53A)
    //   MAC = 128 LEAST significant bits (LAST 16 bytes) of the HMAC output.
    // ========================================================================

    const KAUSF_1_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const KAUSF_2_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    const STEERING_HEX: &str = "00f110800032f4024000";
    const UPU_DATA_1_HEX: &str = "a0a1a2a3a4a5";
    const UPU_DATA_2_HEX: &str = "b0b1b2b3";

    fn kausf_1() -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&unhex(KAUSF_1_HEX));
        k
    }

    fn kausf_2() -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&unhex(KAUSF_2_HEX));
        k
    }

    /// Independent reference: raw HMAC-SHA-256 over a hand-assembled S string,
    /// returning the 128 least significant bits (last 16 bytes). This is the
    /// oracle for the golden vectors — it never calls `nextgcore_kdf_common`.
    fn raw_hmac_last16(key: &[u8], s: &[u8]) -> [u8; 16] {
        let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
        mac.update(s);
        let out = mac.finalize().into_bytes();
        let mut last16 = [0u8; 16];
        last16.copy_from_slice(&out[16..]);
        last16
    }

    /// A.17 golden vectors: SoR-MAC-I_AUSF with P2 present, counter freshness
    /// and key sensitivity.
    #[test]
    fn sor_mac_iausf_golden() {
        let steering = unhex(STEERING_HEX);

        // Vector 1: KAUSF_1, header 0x0a (ack), counter 0x0001, P2 = STEERING.
        // S = 77 || 0a || 0001 || 0001 || 0002 || STEERING || 000a
        let mut s1 = vec![0x77u8, 0x0a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02];
        s1.extend_from_slice(&steering);
        s1.extend_from_slice(&[0x00, 0x0a]);
        assert_eq!(s1, unhex("770a00010001000200f110800032f4024000000a"));
        let expected1 = unhex("ce848061a1d075a400526c79a601089e"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s1)[..], &expected1[..]);
        assert_eq!(
            &nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x0a], 0x0001, Some(&steering))[..],
            &expected1[..]
        );

        // Vector 2: same inputs, counter 0x0002 → different MAC (freshness).
        let mut s2 = vec![0x77u8, 0x0a, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02];
        s2.extend_from_slice(&steering);
        s2.extend_from_slice(&[0x00, 0x0a]);
        let expected2 = unhex("a804047820d952431cd93cd8fb388623"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s2)[..], &expected2[..]);
        assert_eq!(
            &nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x0a], 0x0002, Some(&steering))[..],
            &expected2[..]
        );
        assert_ne!(expected1, expected2, "counter must be freshness input");

        // Vector 3: KAUSF_2, header 0x0a, counter 0x0001, P2 = STEERING.
        let expected3 = unhex("675bbf06b48e9b3d5ca97ad83939dd3d"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_2(), &s1)[..], &expected3[..]);
        assert_eq!(
            &nextgcore_kdf_sor_mac_iausf(&kausf_2(), &[0x0a], 0x0001, Some(&steering))[..],
            &expected3[..]
        );
    }

    /// A.17: when no steering list is supplied, P2 AND L2 are omitted entirely
    /// (S is exactly 8 bytes: FC ‖ P0(1) ‖ L0(2) ‖ P1(2) ‖ L1(2)) — NOT encoded
    /// as an empty P2 with L2 = 0x0000 (which would make S 10 bytes).
    #[test]
    fn sor_mac_no_p2_omits_l2() {
        // Hand-assembled S for KAUSF_1, header 0x02 (no ack), counter 0x0001.
        let s = unhex("7702000100010002");
        assert_eq!(
            s.len(),
            1 + 1 + 2 + 2 + 2,
            "S with P2 omitted must carry no L2 length field"
        );
        let expected = unhex("f2dac4d1463c5cac640430a1f447db93"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s)[..], &expected[..]);
        assert_eq!(
            &nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x02], 0x0001, None)[..],
            &expected[..]
        );

        // Some(&[]) normalises to the same omission (A.17 "not included").
        assert_eq!(
            nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x02], 0x0001, Some(&[])),
            nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x02], 0x0001, None),
        );

        // And an L2=0x0000 encoding would NOT verify against the locked MAC.
        let s_wrong = unhex("77020001000100020000");
        assert_ne!(&raw_hmac_last16(&kausf_1(), &s_wrong)[..], &expected[..]);
    }

    /// A.18 golden vectors: SoR-MAC-I_UE (P0 fixed 0x01, L0 0x0001).
    #[test]
    fn sor_mac_iue_golden() {
        // S = 78 || 01 || 0001 || counter || 0002
        let s1 = unhex("7801000100010002");
        let expected1 = unhex("4a67dd7f904e7c8f668238aa702c4a9f"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s1)[..], &expected1[..]);
        assert_eq!(
            &nextgcore_kdf_sor_mac_iue(&kausf_1(), 0x0001)[..],
            &expected1[..]
        );

        let s2 = unhex("7801000100020002");
        let expected2 = unhex("49f6998ef6bbb0c8e0b02f758c4f61bf"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s2)[..], &expected2[..]);
        assert_eq!(
            &nextgcore_kdf_sor_mac_iue(&kausf_1(), 0x0002)[..],
            &expected2[..]
        );

        let expected3 = unhex("076862e7dbfb2a598d13613ab6ad97ea"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_2(), &s1)[..], &expected3[..]);
        assert_eq!(
            &nextgcore_kdf_sor_mac_iue(&kausf_2(), 0x0001)[..],
            &expected3[..]
        );
    }

    /// A.19 golden vectors: UPU-MAC-I_AUSF over UPU data + counter.
    #[test]
    fn upu_mac_iausf_golden() {
        let upu1 = unhex(UPU_DATA_1_HEX);
        let upu2 = unhex(UPU_DATA_2_HEX);

        // S = 7b || UPU_DATA_1 || 0006 || 0001 || 0002
        let s1 = unhex("7ba0a1a2a3a4a5000600010002");
        let expected1 = unhex("80c0b44903002328f3c307ae2b1e5ac6"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s1)[..], &expected1[..]);
        assert_eq!(
            &nextgcore_kdf_upu_mac_iausf(&kausf_1(), &upu1, 0x0001)[..],
            &expected1[..]
        );

        let s2 = unhex("7ba0a1a2a3a4a5000600020002");
        let expected2 = unhex("8161f20f89478cd3a8f2abd1a54baef8"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s2)[..], &expected2[..]);
        assert_eq!(
            &nextgcore_kdf_upu_mac_iausf(&kausf_1(), &upu1, 0x0002)[..],
            &expected2[..]
        );

        // Different UPU data (4 bytes) → different S length and MAC.
        let s3 = unhex("7bb0b1b2b3000400010002");
        let expected3 = unhex("d53be64e793db605c2867983a98cee82"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s3)[..], &expected3[..]);
        assert_eq!(
            &nextgcore_kdf_upu_mac_iausf(&kausf_1(), &upu2, 0x0001)[..],
            &expected3[..]
        );

        let expected4 = unhex("78146881485e45dc3d042f4790b5b1cb"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_2(), &s1)[..], &expected4[..]);
        assert_eq!(
            &nextgcore_kdf_upu_mac_iausf(&kausf_2(), &upu1, 0x0001)[..],
            &expected4[..]
        );
    }

    /// A.20 golden vectors: UPU-MAC-I_UE (P0 fixed 0x01, L0 0x0001).
    #[test]
    fn upu_mac_iue_golden() {
        // S = 7c || 01 || 0001 || counter || 0002
        let s1 = unhex("7c01000100010002");
        let expected1 = unhex("c954bbe60cbf81b3be14051c2b21116c"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s1)[..], &expected1[..]);
        assert_eq!(
            &nextgcore_kdf_upu_mac_iue(&kausf_1(), 0x0001)[..],
            &expected1[..]
        );

        let s2 = unhex("7c01000100020002");
        let expected2 = unhex("f20f43b13f188d1a588f43d0a4f32636"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_1(), &s2)[..], &expected2[..]);
        assert_eq!(
            &nextgcore_kdf_upu_mac_iue(&kausf_1(), 0x0002)[..],
            &expected2[..]
        );

        let expected3 = unhex("34a3861428e32627b9511e9cbe796b78"); // locked golden
        assert_eq!(&raw_hmac_last16(&kausf_2(), &s1)[..], &expected3[..]);
        assert_eq!(
            &nextgcore_kdf_upu_mac_iue(&kausf_2(), 0x0001)[..],
            &expected3[..]
        );
    }

    /// Adversarial non-malleability sanity: flipping one steering-list byte,
    /// one header bit, one counter bit, one UPU-data byte or one key bit must
    /// change the MAC.
    #[test]
    fn sor_upu_mac_bitflip_sensitivity() {
        let steering = unhex(STEERING_HEX);
        let base =
            nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x0a], 0x0001, Some(&steering));

        // Flip one steering-list byte.
        let mut steering_flipped = steering.clone();
        steering_flipped[3] ^= 0x01;
        assert_ne!(
            base,
            nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x0a], 0x0001, Some(&steering_flipped))
        );

        // Flip one header bit.
        assert_ne!(
            base,
            nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x0b], 0x0001, Some(&steering))
        );

        // Flip one counter bit.
        assert_ne!(
            base,
            nextgcore_kdf_sor_mac_iausf(&kausf_1(), &[0x0a], 0x0001 ^ 0x0100, Some(&steering))
        );

        // Flip one key bit.
        let mut k = kausf_1();
        k[0] ^= 0x80;
        assert_ne!(
            base,
            nextgcore_kdf_sor_mac_iausf(&k, &[0x0a], 0x0001, Some(&steering))
        );

        // UPU: one data byte flip and one counter bit flip.
        let upu = unhex(UPU_DATA_1_HEX);
        let upu_base = nextgcore_kdf_upu_mac_iausf(&kausf_1(), &upu, 0x0001);
        let mut upu_flipped = upu.clone();
        upu_flipped[0] ^= 0x01;
        assert_ne!(
            upu_base,
            nextgcore_kdf_upu_mac_iausf(&kausf_1(), &upu_flipped, 0x0001)
        );
        assert_ne!(
            upu_base,
            nextgcore_kdf_upu_mac_iausf(&kausf_1(), &upu, 0x8001)
        );

        // IUE variants: counter sensitivity.
        assert_ne!(
            nextgcore_kdf_sor_mac_iue(&kausf_1(), 0x0001),
            nextgcore_kdf_sor_mac_iue(&kausf_1(), 0x0002)
        );
        assert_ne!(
            nextgcore_kdf_upu_mac_iue(&kausf_1(), 0x0001),
            nextgcore_kdf_upu_mac_iue(&kausf_1(), 0x0002)
        );
    }

    /// Determinism + sensitivity checks for CK'/IK'.
    #[test]
    fn test_ck_ik_prime_properties() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_xor_ak = [0x33u8; 6];

        let (c1, i1) =
            nextgcore_kdf_ck_ik_prime(&ck, &ik, "5G:mnc001.mcc001.3gppnetwork.org", &sqn_xor_ak);
        let (c2, i2) =
            nextgcore_kdf_ck_ik_prime(&ck, &ik, "5G:mnc001.mcc001.3gppnetwork.org", &sqn_xor_ak);
        assert_eq!(c1, c2);
        assert_eq!(i1, i2);

        let (c3, _) =
            nextgcore_kdf_ck_ik_prime(&ck, &ik, "5G:mnc002.mcc002.3gppnetwork.org", &sqn_xor_ak);
        assert_ne!(c1, c3);
    }
}
