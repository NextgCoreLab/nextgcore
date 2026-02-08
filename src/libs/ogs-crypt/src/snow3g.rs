//! SNOW 3G Stream Cipher
//!
//! Exact port of lib/crypt/snow-3g.c
//!
//! Implements the SNOW 3G stream cipher as used in 3GPP UEA2 (confidentiality)
//! and UIA2 (integrity) algorithms.

/// Rijndael S-box SR
const SR: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

/// S-box SQ
const SQ: [u8; 256] = [
    0x25, 0x24, 0x73, 0x67, 0xD7, 0xAE, 0x5C, 0x30, 0xA4, 0xEE, 0x6E, 0xCB, 0x7D, 0xB5, 0x82, 0xDB,
    0xE4, 0x8E, 0x48, 0x49, 0x4F, 0x5D, 0x6A, 0x78, 0x70, 0x88, 0xE8, 0x5F, 0x5E, 0x84, 0x65, 0xE2,
    0xD8, 0xE9, 0xCC, 0xED, 0x40, 0x2F, 0x11, 0x28, 0x57, 0xD2, 0xAC, 0xE3, 0x4A, 0x15, 0x1B, 0xB9,
    0xB2, 0x80, 0x85, 0xA6, 0x2E, 0x02, 0x47, 0x29, 0x07, 0x4B, 0x0E, 0xC1, 0x51, 0xAA, 0x89, 0xD4,
    0xCA, 0x01, 0x46, 0xB3, 0xEF, 0xDD, 0x44, 0x7B, 0xC2, 0x7F, 0xBE, 0xC3, 0x9F, 0x20, 0x4C, 0x64,
    0x83, 0xA2, 0x68, 0x42, 0x13, 0xB4, 0x41, 0xCD, 0xBA, 0xC6, 0xBB, 0x6D, 0x4D, 0x71, 0x21, 0xF4,
    0x8D, 0xB0, 0xE5, 0x93, 0xFE, 0x8F, 0xE6, 0xCF, 0x43, 0x45, 0x31, 0x22, 0x37, 0x36, 0x96, 0xFA,
    0xBC, 0x0F, 0x08, 0x52, 0x1D, 0x55, 0x1A, 0xC5, 0x4E, 0x23, 0x69, 0x7A, 0x92, 0xFF, 0x5B, 0x5A,
    0xEB, 0x9A, 0x1C, 0xA9, 0xD1, 0x7E, 0x0D, 0xFC, 0x50, 0x8A, 0xB6, 0x62, 0xF5, 0x0A, 0xF8, 0xDC,
    0x03, 0x3C, 0x0C, 0x39, 0xF1, 0xB8, 0xF3, 0x3D, 0xF2, 0xD5, 0x97, 0x66, 0x81, 0x32, 0xA0, 0x00,
    0x06, 0xCE, 0xF6, 0xEA, 0xB7, 0x17, 0xF7, 0x8C, 0x79, 0xD6, 0xA7, 0xBF, 0x8B, 0x3F, 0x1F, 0x53,
    0x63, 0x75, 0x35, 0x2C, 0x60, 0xFD, 0x27, 0xD3, 0x94, 0xA5, 0x7C, 0xA1, 0x05, 0x58, 0x2D, 0xBD,
    0xD9, 0xC7, 0xAF, 0x6B, 0x54, 0x0B, 0xE0, 0x38, 0x04, 0xC8, 0x9D, 0xE7, 0x14, 0xB1, 0x87, 0x9C,
    0xDF, 0x6F, 0xF9, 0xDA, 0x2A, 0xC4, 0x59, 0x16, 0x74, 0x91, 0xAB, 0x26, 0x61, 0x76, 0x34, 0x2B,
    0xAD, 0x99, 0xFB, 0x72, 0xEC, 0x33, 0x12, 0xDE, 0x98, 0x3B, 0xC0, 0x9B, 0x3E, 0x18, 0x10, 0x3A,
    0x56, 0xE1, 0x77, 0xC9, 0x1E, 0x9E, 0x95, 0xA3, 0x90, 0x19, 0xA8, 0x6C, 0x09, 0xD0, 0xF0, 0x86,
];

/// SNOW 3G cipher state
/// Contains the LFSR (Linear Feedback Shift Register) and FSM (Finite State Machine) state
pub struct Snow3gState {
    /// LFSR registers S0 to S15
    lfsr: [u32; 16],
    /// FSM registers R1, R2, R3
    fsm_r1: u32,
    fsm_r2: u32,
    fsm_r3: u32,
}

impl Snow3gState {
    /// Create a new uninitialized SNOW 3G state
    pub fn new() -> Self {
        Self {
            lfsr: [0; 16],
            fsm_r1: 0,
            fsm_r2: 0,
            fsm_r3: 0,
        }
    }
}

impl Default for Snow3gState {
    fn default() -> Self {
        Self::new()
    }
}

/// MULx function
/// Input V: an 8-bit input.
/// Input c: an 8-bit input.
/// Output: an 8-bit output.
/// See section 3.1.1 for details.
#[inline]
fn mul_x(v: u8, c: u8) -> u8 {
    if v & 0x80 != 0 {
        (v << 1) ^ c
    } else {
        v << 1
    }
}

/// MULxPOW function
/// Input V: an 8-bit input.
/// Input i: a positive integer.
/// Input c: an 8-bit input.
/// Output: an 8-bit output.
/// See section 3.1.2 for details.
fn mul_x_pow(v: u8, i: u8, c: u8) -> u8 {
    if i == 0 {
        v
    } else {
        mul_x(mul_x_pow(v, i - 1, c), c)
    }
}

/// The function MUL alpha.
/// Input c: 8-bit input.
/// Output: 32-bit output.
/// See section 3.4.2 for details.
#[inline]
fn mul_alpha(c: u8) -> u32 {
    ((mul_x_pow(c, 23, 0xa9) as u32) << 24)
        | ((mul_x_pow(c, 245, 0xa9) as u32) << 16)
        | ((mul_x_pow(c, 48, 0xa9) as u32) << 8)
        | (mul_x_pow(c, 239, 0xa9) as u32)
}

/// The function DIV alpha.
/// Input c: 8-bit input.
/// Output: 32-bit output.
/// See section 3.4.3 for details.
#[inline]
fn div_alpha(c: u8) -> u32 {
    ((mul_x_pow(c, 16, 0xa9) as u32) << 24)
        | ((mul_x_pow(c, 39, 0xa9) as u32) << 16)
        | ((mul_x_pow(c, 6, 0xa9) as u32) << 8)
        | (mul_x_pow(c, 64, 0xa9) as u32)
}

/// The 32x32-bit S-Box S1
/// Input: a 32-bit input.
/// Output: a 32-bit output of S1 box.
/// See section 3.3.1.
#[inline]
fn s1(w: u32) -> u32 {
    let srw0 = SR[((w >> 24) & 0xff) as usize];
    let srw1 = SR[((w >> 16) & 0xff) as usize];
    let srw2 = SR[((w >> 8) & 0xff) as usize];
    let srw3 = SR[(w & 0xff) as usize];

    let r0 = mul_x(srw0, 0x1b) ^ srw1 ^ srw2 ^ (mul_x(srw3, 0x1b) ^ srw3);
    let r1 = (mul_x(srw0, 0x1b) ^ srw0) ^ mul_x(srw1, 0x1b) ^ srw2 ^ srw3;
    let r2 = srw0 ^ (mul_x(srw1, 0x1b) ^ srw1) ^ mul_x(srw2, 0x1b) ^ srw3;
    let r3 = srw0 ^ srw1 ^ (mul_x(srw2, 0x1b) ^ srw2) ^ mul_x(srw3, 0x1b);

    ((r0 as u32) << 24) | ((r1 as u32) << 16) | ((r2 as u32) << 8) | (r3 as u32)
}

/// The 32x32-bit S-Box S2
/// Input: a 32-bit input.
/// Output: a 32-bit output of S2 box.
/// See section 3.3.2.
#[inline]
fn s2(w: u32) -> u32 {
    let sqw0 = SQ[((w >> 24) & 0xff) as usize];
    let sqw1 = SQ[((w >> 16) & 0xff) as usize];
    let sqw2 = SQ[((w >> 8) & 0xff) as usize];
    let sqw3 = SQ[(w & 0xff) as usize];

    let r0 = mul_x(sqw0, 0x69) ^ sqw1 ^ sqw2 ^ (mul_x(sqw3, 0x69) ^ sqw3);
    let r1 = (mul_x(sqw0, 0x69) ^ sqw0) ^ mul_x(sqw1, 0x69) ^ sqw2 ^ sqw3;
    let r2 = sqw0 ^ (mul_x(sqw1, 0x69) ^ sqw1) ^ mul_x(sqw2, 0x69) ^ sqw3;
    let r3 = sqw0 ^ sqw1 ^ (mul_x(sqw2, 0x69) ^ sqw2) ^ mul_x(sqw3, 0x69);

    ((r0 as u32) << 24) | ((r1 as u32) << 16) | ((r2 as u32) << 8) | (r3 as u32)
}

impl Snow3gState {
    /// Clocking LFSR in initialization mode.
    /// LFSR Registers S0 to S15 are updated as the LFSR receives a single clock.
    /// Input F: a 32-bit word comes from output of FSM.
    /// See section 3.4.4.
    fn clock_lfsr_initialization_mode(&mut self, f: u32) {
        let v = ((self.lfsr[0] << 8) & 0xffffff00)
            ^ mul_alpha(((self.lfsr[0] >> 24) & 0xff) as u8)
            ^ self.lfsr[2]
            ^ ((self.lfsr[11] >> 8) & 0x00ffffff)
            ^ div_alpha((self.lfsr[11] & 0xff) as u8)
            ^ f;

        // Shift LFSR
        for i in 0..15 {
            self.lfsr[i] = self.lfsr[i + 1];
        }
        self.lfsr[15] = v;
    }

    /// Clocking LFSR in keystream mode.
    /// LFSR Registers S0 to S15 are updated as the LFSR receives a single clock.
    /// See section 3.4.5.
    fn clock_lfsr_keystream_mode(&mut self) {
        let v = ((self.lfsr[0] << 8) & 0xffffff00)
            ^ mul_alpha(((self.lfsr[0] >> 24) & 0xff) as u8)
            ^ self.lfsr[2]
            ^ ((self.lfsr[11] >> 8) & 0x00ffffff)
            ^ div_alpha((self.lfsr[11] & 0xff) as u8);

        // Shift LFSR
        for i in 0..15 {
            self.lfsr[i] = self.lfsr[i + 1];
        }
        self.lfsr[15] = v;
    }

    /// Clocking FSM.
    /// Produces a 32-bit word F.
    /// Updates FSM registers R1, R2, R3.
    /// See Section 3.4.6.
    fn clock_fsm(&mut self) -> u32 {
        let f = self.lfsr[15].wrapping_add(self.fsm_r1) ^ self.fsm_r2;
        let r = self.fsm_r2.wrapping_add(self.fsm_r3 ^ self.lfsr[5]);
        self.fsm_r3 = s2(self.fsm_r2);
        self.fsm_r2 = s1(self.fsm_r1);
        self.fsm_r1 = r;
        f
    }

    /// Initialization.
    /// Input k[4]: Four 32-bit words making up 128-bit key.
    /// Input IV[4]: Four 32-bit words making 128-bit initialization variable.
    /// Output: All the LFSRs and FSM are initialized for key generation.
    /// See Section 4.1.
    pub fn initialize(&mut self, k: &[u32; 4], iv: &[u32; 4]) {
        self.lfsr[15] = k[3] ^ iv[0];
        self.lfsr[14] = k[2];
        self.lfsr[13] = k[1];
        self.lfsr[12] = k[0] ^ iv[1];
        self.lfsr[11] = k[3] ^ 0xffffffff;
        self.lfsr[10] = k[2] ^ 0xffffffff ^ iv[2];
        self.lfsr[9] = k[1] ^ 0xffffffff ^ iv[3];
        self.lfsr[8] = k[0] ^ 0xffffffff;
        self.lfsr[7] = k[3];
        self.lfsr[6] = k[2];
        self.lfsr[5] = k[1];
        self.lfsr[4] = k[0];
        self.lfsr[3] = k[3] ^ 0xffffffff;
        self.lfsr[2] = k[2] ^ 0xffffffff;
        self.lfsr[1] = k[1] ^ 0xffffffff;
        self.lfsr[0] = k[0] ^ 0xffffffff;

        self.fsm_r1 = 0;
        self.fsm_r2 = 0;
        self.fsm_r3 = 0;

        for _ in 0..32 {
            let f = self.clock_fsm();
            self.clock_lfsr_initialization_mode(f);
        }
    }

    /// Generation of Keystream.
    /// input n: number of 32-bit words of keystream.
    /// output: generated keystream which is filled in ks
    /// See section 4.2.
    pub fn generate_keystream(&mut self, ks: &mut [u32]) {
        // Clock FSM once. Discard the output.
        self.clock_fsm();
        // Clock LFSR in keystream mode once.
        self.clock_lfsr_keystream_mode();

        for t in 0..ks.len() {
            let f = self.clock_fsm(); // STEP 1
            ks[t] = f ^ self.lfsr[0]; // STEP 2
            // Note that ks[t] corresponds to z_{t+1} in section 4.2
            self.clock_lfsr_keystream_mode(); // STEP 3
        }
    }
}

/// SNOW 3G f8 - 3GPP Confidentiality Algorithm (UEA2)
///
/// # Arguments
/// * `key` - 128-bit Confidentiality Key
/// * `count` - 32-bit Count, Frame dependent input
/// * `bearer` - 5-bit Bearer identity (in the LSB side)
/// * `dir` - 1-bit direction of transmission
/// * `data` - Data to encrypt/decrypt (modified in place)
/// * `length` - Length in bits
///
/// Encrypts/decrypts blocks of data between 1 and 2^32 bits in length.
pub fn snow_3g_f8(key: &[u8; 16], count: u32, bearer: u32, dir: u32, data: &mut [u8], length: u32) {
    if length == 0 {
        return;
    }

    let n = length.div_ceil(32) as usize;
    let lastbits = (8 - (length % 8)) % 8;

    // Load the confidentiality key for SNOW 3G initialization as in section 3.4
    let mut k = [0u32; 4];
    for i in 0..4 {
        k[3 - i] = ((key[4 * i] as u32) << 24)
            ^ ((key[4 * i + 1] as u32) << 16)
            ^ ((key[4 * i + 2] as u32) << 8)
            ^ (key[4 * i + 3] as u32);
    }

    // Prepare the initialization vector (IV) for SNOW 3G initialization as in section 3.4
    let mut iv = [0u32; 4];
    iv[3] = count;
    iv[2] = (bearer << 27) | ((dir & 0x1) << 26);
    iv[1] = iv[3];
    iv[0] = iv[2];

    // Run SNOW 3G algorithm to generate sequence of key stream bits KS
    let mut state = Snow3gState::new();
    state.initialize(&k, &iv);

    let mut ks = vec![0u32; n];
    state.generate_keystream(&mut ks);

    // Exclusive-OR the input data with keystream to generate the output bit stream
    for i in 0..n {
        let base = 4 * i;
        if base < data.len() {
            data[base] ^= ((ks[i] >> 24) & 0xff) as u8;
        }
        if base + 1 < data.len() {
            data[base + 1] ^= ((ks[i] >> 16) & 0xff) as u8;
        }
        if base + 2 < data.len() {
            data[base + 2] ^= ((ks[i] >> 8) & 0xff) as u8;
        }
        if base + 3 < data.len() {
            data[base + 3] ^= (ks[i] & 0xff) as u8;
        }
    }

    // Zero last bits of data in case its length is not byte-aligned
    if lastbits > 0 {
        let byte_idx = (length / 8) as usize;
        if byte_idx < data.len() {
            data[byte_idx] &= 0xFF_u8.wrapping_shl(lastbits);
        }
    }
}

/// MUL64x function for f9
/// Input V: a 64-bit input.
/// Input c: a 64-bit input.
/// Output: a 64-bit output.
/// See section 4.3.2 for details.
#[inline]
fn mul64x(v: u64, c: u64) -> u64 {
    if v & 0x8000000000000000 != 0 {
        (v << 1) ^ c
    } else {
        v << 1
    }
}

/// MUL64xPOW function for f9
/// Input V: a 64-bit input.
/// Input i: a positive integer.
/// Input c: a 64-bit input.
/// Output: a 64-bit output.
/// See section 4.3.3 for details.
fn mul64x_pow(v: u64, i: u8, c: u64) -> u64 {
    if i == 0 {
        v
    } else {
        mul64x(mul64x_pow(v, i - 1, c), c)
    }
}

/// MUL64 function for f9
/// Input V: a 64-bit input.
/// Input P: a 64-bit input.
/// Input c: a 64-bit input.
/// Output: a 64-bit output.
/// See section 4.3.4 for details.
fn mul64(v: u64, p: u64, c: u64) -> u64 {
    let mut result: u64 = 0;
    for i in 0u8..64 {
        if (p >> i) & 0x1 != 0 {
            result ^= mul64x_pow(v, i, c);
        }
    }
    result
}

/// mask8bit function for f9
/// Input n: an integer in 1-7.
/// Output: an 8 bit mask.
/// Prepares an 8 bit mask with required number of 1 bits on the MSB side.
#[inline]
fn mask8bit(n: i32) -> u8 {
    0xFF ^ ((1u8 << (8 - n)) - 1)
}

/// SNOW 3G f9 - 3GPP Integrity Algorithm (UIA2)
///
/// # Arguments
/// * `key` - 128-bit Integrity Key
/// * `count` - 32-bit Count, Frame dependent input
/// * `fresh` - 32-bit Random number
/// * `dir` - 1-bit direction of transmission (in the LSB)
/// * `data` - Data to authenticate
/// * `length` - Length in bits
///
/// # Returns
/// * 32-bit MAC
pub fn snow_3g_f9(
    key: &[u8; 16],
    count: u32,
    fresh: u32,
    dir: u32,
    data: &[u8],
    length: u64,
) -> [u8; 4] {
    // Load the Integrity Key for SNOW3G initialization as in section 4.4
    let mut k = [0u32; 4];
    for i in 0..4 {
        k[3 - i] = ((key[4 * i] as u32) << 24)
            ^ ((key[4 * i + 1] as u32) << 16)
            ^ ((key[4 * i + 2] as u32) << 8)
            ^ (key[4 * i + 3] as u32);
    }

    // Prepare the Initialization Vector (IV) for SNOW3G initialization as in section 4.4
    let mut iv = [0u32; 4];
    iv[3] = count;
    iv[2] = fresh;
    iv[1] = count ^ (dir << 31);
    iv[0] = fresh ^ (dir << 15);

    // Run SNOW 3G to produce 5 keystream words z_1, z_2, z_3, z_4 and z_5
    let mut state = Snow3gState::new();
    state.initialize(&k, &iv);

    let mut z = [0u32; 5];
    state.generate_keystream(&mut z);

    let p: u64 = ((z[0] as u64) << 32) | (z[1] as u64);
    let q: u64 = ((z[2] as u64) << 32) | (z[3] as u64);

    // Calculation
    let d: u32 = if (length % 64) == 0 {
        (length >> 6) as u32 + 1
    } else {
        (length >> 6) as u32 + 2
    };

    let mut eval: u64 = 0;
    let c: u64 = 0x1b;

    // for 0 <= i <= D-3
    for i in 0..(d as usize).saturating_sub(2) {
        let base = 8 * i;
        let v = eval
            ^ ((data.get(base).copied().unwrap_or(0) as u64) << 56)
            ^ ((data.get(base + 1).copied().unwrap_or(0) as u64) << 48)
            ^ ((data.get(base + 2).copied().unwrap_or(0) as u64) << 40)
            ^ ((data.get(base + 3).copied().unwrap_or(0) as u64) << 32)
            ^ ((data.get(base + 4).copied().unwrap_or(0) as u64) << 24)
            ^ ((data.get(base + 5).copied().unwrap_or(0) as u64) << 16)
            ^ ((data.get(base + 6).copied().unwrap_or(0) as u64) << 8)
            ^ (data.get(base + 7).copied().unwrap_or(0) as u64);
        eval = mul64(v, p, c);
    }

    // for D-2
    let mut rem_bits = (length % 64) as i32;
    if rem_bits == 0 {
        rem_bits = 64;
    }

    let mut m_d_2: u64 = 0;
    let mut i: u32 = 0;
    let base = 8 * (d - 2);
    while rem_bits > 7 {
        m_d_2 |= (data.get((base + i) as usize).copied().unwrap_or(0) as u64) << (8 * (7 - i));
        rem_bits -= 8;
        i += 1;
    }
    if rem_bits > 0 {
        m_d_2 |= ((data.get((base + i) as usize).copied().unwrap_or(0) & mask8bit(rem_bits)) as u64)
            << (8 * (7 - i));
    }

    let v = eval ^ m_d_2;
    eval = mul64(v, p, c);

    // for D-1
    eval ^= length;

    // Multiply by Q
    eval = mul64(eval, q, c);

    // XOR with z_5
    let mut out = [0u8; 4];
    for i in 0..4u32 {
        out[i as usize] = ((eval >> (56 - (i * 8))) ^ ((z[4] >> (24 - (i * 8))) as u64)) as u8;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snow3g_state_initialization() {
        let mut state = Snow3gState::new();
        let k = [0x12345678u32, 0x9ABCDEF0, 0x12345678, 0x9ABCDEF0];
        let iv = [0x11111111u32, 0x22222222, 0x33333333, 0x44444444];

        state.initialize(&k, &iv);

        // After initialization, state should be non-zero
        assert!(state.lfsr.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_snow3g_keystream_generation() {
        let mut state = Snow3gState::new();
        let k = [0x12345678u32, 0x9ABCDEF0, 0x12345678, 0x9ABCDEF0];
        let iv = [0x11111111u32, 0x22222222, 0x33333333, 0x44444444];

        state.initialize(&k, &iv);

        let mut ks = [0u32; 4];
        state.generate_keystream(&mut ks);

        // Keystream should be non-zero
        assert!(ks.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_snow3g_f8_roundtrip() {
        // Test that f8 encryption followed by f8 decryption returns original
        let key: [u8; 16] = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
        ];
        let count: u32 = 0x72A4F20F;
        let bearer: u32 = 0x0C;
        let dir: u32 = 1;

        let original: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut data = original;
        let length: u32 = 64;

        // Encrypt
        snow_3g_f8(&key, count, bearer, dir, &mut data, length);

        // Verify data was modified
        assert_ne!(data, original);

        // Decrypt (f8 is symmetric)
        snow_3g_f8(&key, count, bearer, dir, &mut data, length);

        // Should return to original
        assert_eq!(data, original);
    }

    #[test]
    fn test_snow3g_f9_produces_mac() {
        // Test that f9 produces a non-zero MAC
        let key: [u8; 16] = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
        ];
        let count: u32 = 0x38A6F056;
        let fresh: u32 = 0x05D2EC49;
        let dir: u32 = 0;
        let data: [u8; 8] = [
            0x6B, 0x22, 0x77, 0x37, 0x29, 0x6F, 0x39, 0x3C,
        ];
        let length: u64 = 64;

        let mac = snow_3g_f9(&key, count, fresh, dir, &data, length);

        // Verify MAC is non-zero
        assert_ne!(mac, [0, 0, 0, 0]);
    }

    #[test]
    fn test_snow3g_f9_deterministic() {
        // Test that f9 produces the same MAC for same inputs
        let key: [u8; 16] = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
        ];
        let count: u32 = 0x38A6F056;
        let fresh: u32 = 0x05D2EC49;
        let dir: u32 = 0;
        let data: [u8; 8] = [
            0x6B, 0x22, 0x77, 0x37, 0x29, 0x6F, 0x39, 0x3C,
        ];
        let length: u64 = 64;

        let mac1 = snow_3g_f9(&key, count, fresh, dir, &data, length);
        let mac2 = snow_3g_f9(&key, count, fresh, dir, &data, length);

        assert_eq!(mac1, mac2);
    }

    // 3GPP Test Set 1 for UEA2 (f8)
    // From 3GPP TS 35.207
    #[test]
    fn test_snow3g_f8_3gpp_test_set_1() {
        let key: [u8; 16] = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
        ];
        let count: u32 = 0x72A4F20F;
        let bearer: u32 = 0x0C;
        let dir: u32 = 1;
        let length: u32 = 798;

        let plaintext: [u8; 100] = [
            0x7E, 0xC6, 0x12, 0x72, 0x74, 0x3B, 0xF1, 0x61,
            0x47, 0x26, 0x44, 0x6A, 0x6C, 0x38, 0xCE, 0xD1,
            0x66, 0xF6, 0xCA, 0x76, 0xEB, 0x54, 0x30, 0x04,
            0x42, 0x86, 0x34, 0x6C, 0xEF, 0x13, 0x0F, 0x92,
            0x92, 0x2B, 0x03, 0x45, 0x0D, 0x3A, 0x99, 0x75,
            0xE5, 0xBD, 0x2E, 0xA0, 0xEB, 0x55, 0xAD, 0x8E,
            0x1B, 0x19, 0x9E, 0x3E, 0xC4, 0x31, 0x60, 0x20,
            0xE9, 0xA1, 0xB2, 0x85, 0xE7, 0x62, 0x79, 0x53,
            0x59, 0xB7, 0xBD, 0xFD, 0x39, 0xBE, 0xF4, 0xB2,
            0x48, 0x45, 0x83, 0xD5, 0xAF, 0xE0, 0x82, 0xAE,
            0xE6, 0x38, 0xBF, 0x5F, 0xD5, 0xA6, 0x06, 0x19,
            0x39, 0x01, 0xA0, 0x8F, 0x4A, 0xB4, 0x1A, 0xAB,
            0x9B, 0x13, 0x48, 0x80,
        ];

        let expected_ciphertext: [u8; 100] = [
            0x8C, 0xEB, 0xA6, 0x29, 0x43, 0xDC, 0xED, 0x3A,
            0x09, 0x90, 0xB0, 0x6E, 0xA1, 0xB0, 0xA2, 0xC4,
            0xFB, 0x3C, 0xED, 0xC7, 0x1B, 0x36, 0x9F, 0x42,
            0xBA, 0x64, 0xC1, 0xEB, 0x66, 0x65, 0xE7, 0x2A,
            0xA1, 0xC9, 0xBB, 0x0D, 0xEA, 0xA2, 0x0F, 0xE8,
            0x60, 0x58, 0xB8, 0xBA, 0xEE, 0x2C, 0x2E, 0x7F,
            0x0B, 0xEC, 0xCE, 0x48, 0xB5, 0x29, 0x32, 0xA5,
            0x3C, 0x9D, 0x5F, 0x93, 0x1A, 0x3A, 0x7C, 0x53,
            0x22, 0x59, 0xAF, 0x43, 0x25, 0xE2, 0xA6, 0x5E,
            0x30, 0x84, 0xAD, 0x5F, 0x6A, 0x51, 0x3B, 0x7B,
            0xDD, 0xC1, 0xB6, 0x5F, 0x0A, 0xA0, 0xD9, 0x7A,
            0x05, 0x3D, 0xB5, 0x5A, 0x88, 0xC4, 0xC4, 0xF9,
            0x60, 0x5E, 0x41, 0x40,
        ];

        let mut data = plaintext;
        snow_3g_f8(&key, count, bearer, dir, &mut data, length);

        assert_eq!(data, expected_ciphertext);
    }

    // 3GPP Test Set 1 for UIA2 (f9)
    // From tests/unit/security-test.c (security_test4)
    #[test]
    fn test_snow3g_f9_3gpp_test_set_1() {
        let key: [u8; 16] = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
        ];
        let count: u32 = 0x38A6F056;
        let fresh: u32 = 0x1F << 27; // 0xF8000000
        let dir: u32 = 0;
        let length: u64 = 88;

        // "33323462 63393861 37347900 00000000"
        let message: [u8; 11] = [
            0x33, 0x32, 0x34, 0x62, 0x63, 0x39, 0x38, 0x61,
            0x37, 0x34, 0x79,
        ];

        // Expected MAC: "731f1165"
        let expected_mac: [u8; 4] = [0x73, 0x1F, 0x11, 0x65];

        let mac = snow_3g_f9(&key, count, fresh, dir, &message, length);

        assert_eq!(mac, expected_mac);
    }
    #[test]
    fn test_snow3g_f8_empty_data() {
        let key: [u8; 16] = [0; 16];
        let mut data: [u8; 0] = [];
        
        // Should not panic on empty data
        snow_3g_f8(&key, 0, 0, 0, &mut data, 0);
    }

    #[test]
    fn test_snow3g_f8_non_byte_aligned() {
        // Test with non-byte-aligned length
        let key: [u8; 16] = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
        ];
        let count: u32 = 0x72A4F20F;
        let bearer: u32 = 0x0C;
        let dir: u32 = 1;

        let original: [u8; 2] = [0xFF, 0xFF];
        let mut data = original;
        let length: u32 = 13; // 13 bits = 1 byte + 5 bits

        snow_3g_f8(&key, count, bearer, dir, &mut data, length);

        // Last 3 bits of second byte should be zeroed
        assert_eq!(data[1] & 0x07, 0);
    }
}
