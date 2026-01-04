//! 3GPP Milenage Algorithm
//!
//! Exact port of lib/crypt/milenage.c
//!
//! Implements the Milenage algorithm as defined in 3GPP TS 35.205, .206, .207, .208
//! for UMTS/LTE/5G authentication.

use crate::aes::AesEncContext;

// Length constants
pub const OGS_RAND_LEN: usize = 16;
pub const OGS_AUTN_LEN: usize = 16;
pub const OGS_AUTS_LEN: usize = 14;
pub const OGS_MAX_RES_LEN: usize = 16;
pub const OGS_AK_LEN: usize = 6;
pub const OGS_SQN_LEN: usize = 6;
pub const OGS_AMF_LEN: usize = 2;
pub const OGS_MAC_LEN: usize = 8;

/// Error type for Milenage operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MilenageError {
    /// AES encryption failed
    AesError,
    /// MAC verification failed
    MacMismatch,
    /// Synchronization failure (SQN out of range)
    SyncFailure,
    /// Invalid buffer length
    InvalidLength,
}

/// AES-128 block encryption helper
fn aes_128_encrypt_block(key: &[u8; 16], input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), MilenageError> {
    let ctx = AesEncContext::new(key, 128).map_err(|_| MilenageError::AesError)?;
    ctx.encrypt_block(input, output);
    Ok(())
}

/// Shift bits helper function for rotation operations
fn shift_bits(r: u8, rijndael_input: &mut [u8; 16], temp: &[u8; 16], opc: &[u8; 16]) {
    let deltlen = 16 - (r as usize / 8);
    let leftout = r as usize % 8;

    if leftout == 0 {
        // Simple byte rotation
        for i in 0..16 {
            rijndael_input[(i + deltlen) % 16] = temp[i] ^ opc[i];
        }
    } else {
        // Bit-level rotation
        let mut temp1 = [0u8; 16];
        for i in 0..16 {
            temp1[(i + deltlen) % 16] = temp[i] ^ opc[i];
        }
        
        let move_bits = 8 - leftout;
        rijndael_input[15] = 0;
        
        // Shift bits left by move_bits
        for i in 0..15 {
            rijndael_input[i] = (temp1[i] << move_bits) | (temp1[i + 1] >> leftout);
        }
        
        // Handle wrap-around
        let temp2 = temp1[0] >> leftout;
        rijndael_input[15] |= temp2;
    }
}

/// Milenage f1 and f1* algorithms
///
/// # Arguments
/// * `opc` - OPc = 128-bit value derived from OP and K
/// * `k` - K = 128-bit subscriber key
/// * `rand` - RAND = 128-bit random challenge
/// * `sqn` - SQN = 48-bit sequence number
/// * `amf` - AMF = 16-bit authentication management field
///
/// # Returns
/// * `Ok((mac_a, mac_s))` - MAC-A (f1) and MAC-S (f1*)
pub fn milenage_f1(
    opc: &[u8; 16],
    k: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> Result<([u8; 8], [u8; 8]), MilenageError> {
    let r1: u8 = 64;
    
    // tmp1 = RAND XOR OPc
    let mut tmp1 = [0u8; 16];
    for i in 0..16 {
        tmp1[i] = rand[i] ^ opc[i];
    }
    
    // tmp1 = E_K(tmp1)
    let mut encrypted = [0u8; 16];
    aes_128_encrypt_block(k, &tmp1, &mut encrypted)?;
    tmp1 = encrypted;
    
    // tmp2 = IN1 = SQN || AMF || SQN || AMF
    let mut tmp2 = [0u8; 16];
    tmp2[..6].copy_from_slice(sqn);
    tmp2[6..8].copy_from_slice(amf);
    tmp2[8..14].copy_from_slice(sqn);
    tmp2[14..16].copy_from_slice(amf);
    
    // OUT1 = E_K(TEMP XOR rot(IN1 XOR OP_C, r1) XOR c1) XOR OP_C
    // rotate (tmp2 XOR OP_C) by r1 (= 64 bits = 8 bytes)
    let mut tmp3 = [0u8; 16];
    shift_bits(r1, &mut tmp3, &tmp2, opc);
    
    // XOR with TEMP = E_K(RAND XOR OP_C)
    for i in 0..16 {
        tmp3[i] ^= tmp1[i];
    }
    // XOR with c1 (= ..00, i.e., NOP)
    
    // f1 || f1* = E_K(tmp3) XOR OP_c
    aes_128_encrypt_block(k, &tmp3, &mut tmp1)?;
    for i in 0..16 {
        tmp1[i] ^= opc[i];
    }
    
    let mut mac_a = [0u8; 8];
    let mut mac_s = [0u8; 8];
    mac_a.copy_from_slice(&tmp1[..8]);  // f1
    mac_s.copy_from_slice(&tmp1[8..]);  // f1*
    
    Ok((mac_a, mac_s))
}


/// Milenage f2, f3, f4, f5, f5* algorithms
///
/// # Arguments
/// * `opc` - OPc = 128-bit value derived from OP and K
/// * `k` - K = 128-bit subscriber key
/// * `rand` - RAND = 128-bit random challenge
///
/// # Returns
/// * `Ok((res, ck, ik, ak, akstar))` - RES (f2), CK (f3), IK (f4), AK (f5), AK* (f5*)
pub fn milenage_f2345(
    opc: &[u8; 16],
    k: &[u8; 16],
    rand: &[u8; 16],
) -> Result<([u8; 8], [u8; 16], [u8; 16], [u8; 6], [u8; 6]), MilenageError> {
    let r2: u8 = 0;
    let r3: u8 = 32;
    let r4: u8 = 64;
    let r5: u8 = 96;
    
    // tmp1 = RAND XOR OPc
    let mut tmp1 = [0u8; 16];
    for i in 0..16 {
        tmp1[i] = rand[i] ^ opc[i];
    }
    
    // tmp2 = TEMP = E_K(RAND XOR OP_C)
    let mut tmp2 = [0u8; 16];
    aes_128_encrypt_block(k, &tmp1, &mut tmp2)?;
    
    // f2 and f5
    // rotate by r2 (= 0, i.e., NOP)
    shift_bits(r2, &mut tmp1, &tmp2, opc);
    tmp1[15] ^= 1; // XOR c2 (= ..01)
    
    // f5 || f2 = E_K(tmp1) XOR OP_c
    let mut tmp3 = [0u8; 16];
    aes_128_encrypt_block(k, &tmp1, &mut tmp3)?;
    for i in 0..16 {
        tmp3[i] ^= opc[i];
    }
    
    let mut res = [0u8; 8];
    let mut ak = [0u8; 6];
    res.copy_from_slice(&tmp3[8..]);  // f2
    ak.copy_from_slice(&tmp3[..6]);   // f5
    
    // f3 (CK)
    // rotate by r3 = 32 bits = 4 bytes
    let mut ck = [0u8; 16];
    shift_bits(r3, &mut tmp1, &tmp2, opc);
    tmp1[15] ^= 2; // XOR c3 (= ..02)
    aes_128_encrypt_block(k, &tmp1, &mut ck)?;
    for i in 0..16 {
        ck[i] ^= opc[i];
    }
    
    // f4 (IK)
    // rotate by r4 = 64 bits = 8 bytes
    let mut ik = [0u8; 16];
    shift_bits(r4, &mut tmp1, &tmp2, opc);
    tmp1[15] ^= 4; // XOR c4 (= ..04)
    aes_128_encrypt_block(k, &tmp1, &mut ik)?;
    for i in 0..16 {
        ik[i] ^= opc[i];
    }
    
    // f5* (AK*)
    // rotate by r5 = 96 bits = 12 bytes
    let mut akstar = [0u8; 6];
    shift_bits(r5, &mut tmp1, &tmp2, opc);
    tmp1[15] ^= 8; // XOR c5 (= ..08)
    let mut tmp_out = [0u8; 16];
    aes_128_encrypt_block(k, &tmp1, &mut tmp_out)?;
    for i in 0..6 {
        akstar[i] = tmp_out[i] ^ opc[i];
    }
    
    Ok((res, ck, ik, ak, akstar))
}

/// Generate OPc from K and OP
///
/// # Arguments
/// * `k` - K = 128-bit subscriber key
/// * `op` - OP = 128-bit operator variant algorithm configuration field
///
/// # Returns
/// * OPc = 128-bit encrypted operator variant
pub fn milenage_opc(k: &[u8; 16], op: &[u8; 16]) -> Result<[u8; 16], MilenageError> {
    let mut opc = [0u8; 16];
    aes_128_encrypt_block(k, op, &mut opc)?;
    
    for i in 0..16 {
        opc[i] ^= op[i];
    }
    
    Ok(opc)
}

/// Generate AKA authentication vectors (AUTN, IK, CK, RES)
///
/// # Arguments
/// * `opc` - OPc = 128-bit operator variant algorithm configuration field (encrypted)
/// * `amf` - AMF = 16-bit authentication management field
/// * `k` - K = 128-bit subscriber key
/// * `sqn` - SQN = 48-bit sequence number
/// * `rand` - RAND = 128-bit random challenge
///
/// # Returns
/// * `Ok((autn, ik, ck, ak, res))` - Authentication vectors
pub fn milenage_generate(
    opc: &[u8; 16],
    amf: &[u8; 2],
    k: &[u8; 16],
    sqn: &[u8; 6],
    rand: &[u8; 16],
) -> Result<([u8; 16], [u8; 16], [u8; 16], [u8; 6], [u8; 8]), MilenageError> {
    let (mac_a, _mac_s) = milenage_f1(opc, k, rand, sqn, amf)?;
    let (res, ck, ik, ak, _akstar) = milenage_f2345(opc, k, rand)?;
    
    // AUTN = (SQN ^ AK) || AMF || MAC
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn[i] ^ ak[i];
    }
    autn[6..8].copy_from_slice(amf);
    autn[8..16].copy_from_slice(&mac_a);
    
    Ok((autn, ik, ck, ak, res))
}

/// Validate AUTS and extract SQN
///
/// # Arguments
/// * `opc` - OPc = 128-bit operator variant algorithm configuration field (encrypted)
/// * `k` - K = 128-bit subscriber key
/// * `rand` - RAND = 128-bit random challenge
/// * `auts` - AUTS = 112-bit authentication token from client
///
/// # Returns
/// * `Ok(sqn)` - Extracted SQN on success
/// * `Err(MilenageError)` - On failure
pub fn milenage_auts(
    opc: &[u8; 16],
    k: &[u8; 16],
    rand: &[u8; 16],
    auts: &[u8; 14],
) -> Result<[u8; 6], MilenageError> {
    let amf = [0x00u8, 0x00]; // TS 33.102 v7.0.0, 6.3.3
    
    let (_res, _ck, _ik, _ak, akstar) = milenage_f2345(opc, k, rand)?;
    
    let mut sqn = [0u8; 6];
    for i in 0..6 {
        sqn[i] = auts[i] ^ akstar[i];
    }
    
    let (_mac_a, mac_s) = milenage_f1(opc, k, rand, &sqn, &amf)?;
    
    // Verify MAC-S
    if mac_s != auts[6..14] {
        return Err(MilenageError::MacMismatch);
    }
    
    Ok(sqn)
}

/// Generate GSM-Milenage authentication triplet (3GPP TS 55.205)
///
/// # Arguments
/// * `opc` - OPc = 128-bit operator variant algorithm configuration field (encrypted)
/// * `k` - K = 128-bit subscriber key
/// * `rand` - RAND = 128-bit random challenge
///
/// # Returns
/// * `Ok((sres, kc))` - SRES (32-bit) and Kc (64-bit)
pub fn gsm_milenage(
    opc: &[u8; 16],
    k: &[u8; 16],
    rand: &[u8; 16],
) -> Result<([u8; 4], [u8; 8]), MilenageError> {
    let (res, ck, ik, _ak, _akstar) = milenage_f2345(opc, k, rand)?;
    
    // Kc = CK[0..7] XOR CK[8..15] XOR IK[0..7] XOR IK[8..15]
    let mut kc = [0u8; 8];
    for i in 0..8 {
        kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];
    }
    
    // SRES = RES[0..3] XOR RES[4..7]
    let mut sres = [0u8; 4];
    for i in 0..4 {
        sres[i] = res[i] ^ res[i + 4];
    }
    
    Ok((sres, kc))
}

/// Check AKA authentication (UE side)
///
/// # Arguments
/// * `opc` - OPc = 128-bit operator variant algorithm configuration field (encrypted)
/// * `k` - K = 128-bit subscriber key
/// * `sqn` - SQN = 48-bit expected sequence number
/// * `rand` - RAND = 128-bit random challenge
/// * `autn` - AUTN = 128-bit authentication token
///
/// # Returns
/// * `Ok((ik, ck, res))` - On success
/// * `Err(MilenageError::SyncFailure)` with AUTS - On synchronization failure
/// * `Err(MilenageError::MacMismatch)` - On MAC verification failure
pub fn milenage_check(
    opc: &[u8; 16],
    k: &[u8; 16],
    sqn: &[u8; 6],
    rand: &[u8; 16],
    autn: &[u8; 16],
) -> Result<([u8; 16], [u8; 16], [u8; 8], Option<[u8; 14]>), MilenageError> {
    let (res, ck, ik, ak, _akstar) = milenage_f2345(opc, k, rand)?;
    
    // Extract SQN from AUTN: SQN = (AUTN[0..5] ^ AK)
    let mut rx_sqn = [0u8; 6];
    for i in 0..6 {
        rx_sqn[i] = autn[i] ^ ak[i];
    }
    
    // Check if received SQN is acceptable
    // In the C code, this is: os_memcmp(rx_sqn, sqn, 6) <= 0
    // which means rx_sqn <= sqn (sync failure if received SQN is not greater than expected)
    let sqn_ok = rx_sqn.as_slice() > sqn.as_slice();
    
    if !sqn_ok {
        // Synchronization failure - generate AUTS
        let auts_amf = [0x00u8, 0x00]; // TS 33.102 v7.0.0, 6.3.3
        let (_res2, _ck2, _ik2, _ak2, akstar) = milenage_f2345(opc, k, rand)?;
        
        let mut auts = [0u8; 14];
        for i in 0..6 {
            auts[i] = sqn[i] ^ akstar[i];
        }
        
        let (_mac_a, mac_s) = milenage_f1(opc, k, rand, sqn, &auts_amf)?;
        auts[6..14].copy_from_slice(&mac_s);
        
        return Ok((ik, ck, res, Some(auts)));
    }
    
    // Verify MAC-A
    let amf: [u8; 2] = [autn[6], autn[7]];
    let (mac_a, _mac_s) = milenage_f1(opc, k, rand, &rx_sqn, &amf)?;
    
    if mac_a != autn[8..16] {
        return Err(MilenageError::MacMismatch);
    }
    
    Ok((ik, ck, res, None))
}


#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from 3GPP TS 35.207
    
    // Test Set 1
    const K1: [u8; 16] = [
        0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
        0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
    ];
    const RAND1: [u8; 16] = [
        0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d,
        0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35,
    ];
    const SQN1: [u8; 6] = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
    const AMF1: [u8; 2] = [0xb9, 0xb9];
    const OP1: [u8; 16] = [
        0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6,
        0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18,
    ];
    const OPC1: [u8; 16] = [
        0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
        0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
    ];
    
    // Expected outputs for Test Set 1
    const F1_1: [u8; 8] = [0x4a, 0x9f, 0xfa, 0xc3, 0x54, 0xdf, 0xaf, 0xb3];
    const F1STAR_1: [u8; 8] = [0x01, 0xcf, 0xaf, 0x9e, 0xc4, 0xe8, 0x71, 0xe9];
    const F2_1: [u8; 8] = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];
    const F3_1: [u8; 16] = [
        0xb4, 0x0b, 0xa9, 0xa3, 0xc5, 0x8b, 0x2a, 0x05,
        0xbb, 0xf0, 0xd9, 0x87, 0xb2, 0x1b, 0xf8, 0xcb,
    ];
    const F4_1: [u8; 16] = [
        0xf7, 0x69, 0xbc, 0xd7, 0x51, 0x04, 0x46, 0x04,
        0x12, 0x76, 0x72, 0x71, 0x1c, 0x6d, 0x34, 0x41,
    ];
    const F5_1: [u8; 6] = [0xaa, 0x68, 0x9c, 0x64, 0x83, 0x70];
    const F5STAR_1: [u8; 6] = [0x45, 0x1e, 0x8b, 0xec, 0xa4, 0x3b];

    #[test]
    fn test_milenage_opc() {
        let opc = milenage_opc(&K1, &OP1).unwrap();
        assert_eq!(opc, OPC1);
    }

    #[test]
    fn test_milenage_f1() {
        let (mac_a, mac_s) = milenage_f1(&OPC1, &K1, &RAND1, &SQN1, &AMF1).unwrap();
        assert_eq!(mac_a, F1_1);
        assert_eq!(mac_s, F1STAR_1);
    }

    #[test]
    fn test_milenage_f2345() {
        let (res, ck, ik, ak, akstar) = milenage_f2345(&OPC1, &K1, &RAND1).unwrap();
        assert_eq!(res, F2_1);
        assert_eq!(ck, F3_1);
        assert_eq!(ik, F4_1);
        assert_eq!(ak, F5_1);
        assert_eq!(akstar, F5STAR_1);
    }

    #[test]
    fn test_milenage_generate() {
        let (autn, ik, ck, ak, res) = milenage_generate(&OPC1, &AMF1, &K1, &SQN1, &RAND1).unwrap();
        
        // Verify individual components
        assert_eq!(res, F2_1);
        assert_eq!(ck, F3_1);
        assert_eq!(ik, F4_1);
        assert_eq!(ak, F5_1);
        
        // Verify AUTN structure: (SQN ^ AK) || AMF || MAC-A
        let mut expected_autn = [0u8; 16];
        for i in 0..6 {
            expected_autn[i] = SQN1[i] ^ F5_1[i];
        }
        expected_autn[6..8].copy_from_slice(&AMF1);
        expected_autn[8..16].copy_from_slice(&F1_1);
        
        assert_eq!(autn, expected_autn);
    }

    #[test]
    fn test_gsm_milenage() {
        let (sres, kc) = gsm_milenage(&OPC1, &K1, &RAND1).unwrap();
        
        // SRES = RES[0..3] XOR RES[4..7]
        let mut expected_sres = [0u8; 4];
        for i in 0..4 {
            expected_sres[i] = F2_1[i] ^ F2_1[i + 4];
        }
        assert_eq!(sres, expected_sres);
        
        // Kc = CK[0..7] XOR CK[8..15] XOR IK[0..7] XOR IK[8..15]
        let mut expected_kc = [0u8; 8];
        for i in 0..8 {
            expected_kc[i] = F3_1[i] ^ F3_1[i + 8] ^ F4_1[i] ^ F4_1[i + 8];
        }
        assert_eq!(kc, expected_kc);
    }

    // Test Set 2 from 3GPP TS 35.207
    const K2: [u8; 16] = [
        0x03, 0x96, 0xeb, 0x31, 0x7b, 0x6d, 0x1c, 0x36,
        0xf1, 0x9c, 0x1c, 0x84, 0xcd, 0x6f, 0xfd, 0x16,
    ];
    const RAND2: [u8; 16] = [
        0xc0, 0x0d, 0x60, 0x31, 0x03, 0xdc, 0xee, 0x52,
        0xc4, 0x47, 0x81, 0x19, 0x49, 0x42, 0x02, 0xe8,
    ];
    const SQN2: [u8; 6] = [0xfd, 0x8e, 0xef, 0x40, 0xdf, 0x7d];
    const AMF2: [u8; 2] = [0xaf, 0x17];
    const OP2: [u8; 16] = [
        0xff, 0x53, 0xba, 0xde, 0x17, 0xdf, 0x5d, 0x4e,
        0x79, 0x30, 0x73, 0xce, 0x9d, 0x75, 0x79, 0xfa,
    ];
    const OPC2: [u8; 16] = [
        0x53, 0xc1, 0x56, 0x71, 0xc6, 0x0a, 0x4b, 0x73,
        0x1c, 0x55, 0xb4, 0xa4, 0x41, 0xc0, 0xbd, 0xe2,
    ];
    
    const F1_2: [u8; 8] = [0x5d, 0xf5, 0xb3, 0x18, 0x07, 0xe2, 0x58, 0xb0];
    const F2_2: [u8; 8] = [0xd3, 0xa6, 0x28, 0xed, 0x98, 0x86, 0x20, 0xf0];
    const F3_2: [u8; 16] = [
        0x58, 0xc4, 0x33, 0xff, 0x7a, 0x70, 0x82, 0xac,
        0xd4, 0x24, 0x22, 0x0f, 0x2b, 0x67, 0xc5, 0x56,
    ];
    const F4_2: [u8; 16] = [
        0x21, 0xa8, 0xc1, 0xf9, 0x29, 0x70, 0x2a, 0xdb,
        0x3e, 0x73, 0x84, 0x88, 0xb9, 0xf5, 0xc5, 0xda,
    ];
    const F5_2: [u8; 6] = [0xc4, 0x77, 0x83, 0x99, 0x5f, 0x72];

    #[test]
    fn test_milenage_opc_set2() {
        let opc = milenage_opc(&K2, &OP2).unwrap();
        assert_eq!(opc, OPC2);
    }

    #[test]
    fn test_milenage_f1_set2() {
        let (mac_a, _mac_s) = milenage_f1(&OPC2, &K2, &RAND2, &SQN2, &AMF2).unwrap();
        assert_eq!(mac_a, F1_2);
    }

    #[test]
    fn test_milenage_f2345_set2() {
        let (res, ck, ik, ak, _akstar) = milenage_f2345(&OPC2, &K2, &RAND2).unwrap();
        assert_eq!(res, F2_2);
        assert_eq!(ck, F3_2);
        assert_eq!(ik, F4_2);
        assert_eq!(ak, F5_2);
    }
}
