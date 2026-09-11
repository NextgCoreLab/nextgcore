//! TUAK authentication and key generation functions (3GPP TS 35.231)
//!
//! The second standardised algorithm set for the 3GPP f1, f1*, f2, f3, f4, f5 and f5*
//! functions, alongside MILENAGE ([`crate::milenage`]). Where MILENAGE is built on AES,
//! TUAK is built on the Keccak-f[1600] permutation.
//!
//! # Why this exists (#115)
//!
//! Authentication-vector generation in this tree was MILENAGE-only, with no algorithm
//! branch and no per-subscriber algorithm identifier — so a TUAK-provisioned subscriber
//! could not be authenticated at all, and an operator could not choose per subscriber.
//!
//! # Bit ordering, which is the whole difficulty
//!
//! TS 35.231 specifies the permutation input as a bit string with reversed indices,
//! e.g. §6.2 `IN[0] .. IN[255] = TOPC[255] .. TOPC[0]`. Read literally that is a full
//! bit reversal of the 32-byte value. It is not, in practice, because §5.2 says inputs
//! are mapped "in such a way that bits of input and output should not need to be
//! reversed within bytes": the `IN` bit string is indexed LSB-first within each byte
//! while the 3GPP parameters are numbered MSB-first, and the two reversals cancel.
//!
//! What survives is a **byte reversal**, and nothing else. Confirmed against
//! TS 35.232 §6.3's intermediate values rather than reasoned about: for
//! `TOPc = bd04…40cccbff`, that document shows `IN` beginning `ff cb cc 40 …`, and
//! `ALGONAME` = "TUAK1.0" appearing as `30 2e 31 4b 41 55 54` — "0.1KAUT". Every
//! placement and extraction below therefore reverses bytes, and
//! [`tests::keccak_permutation_matches_ts_35_233_test_set_1`] plus the f1/f2345 vector
//! tests pin the result.
//!
//! The `INSTANCE` octet is the one place a genuine bit reversal remains, because
//! `IN[256] .. IN[263] = INSTANCE[7] .. INSTANCE[0]` reverses an 8-bit string inside a
//! single byte, so there is no second reversal to cancel it. See [`Instance::to_byte`].

/// What can go wrong in TUAK.
///
/// Its own type rather than a reuse of [`crate::milenage::MilenageError`]: that enum's
/// variants are `AesError`, `MacMismatch`, `SyncFailure` and `InvalidLength`, and the
/// first cannot occur in a Keccak-based algorithm. Only the parameter lengths are
/// checkable here — the permutation itself cannot fail — so there is exactly one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuakError {
    /// A key or output length TS 35.231 does not define.
    ///
    /// Carries what was asked for and what is allowed, because "invalid length" alone
    /// leaves the caller to rediscover which of its four length parameters was wrong.
    InvalidLength {
        /// The parameter that was rejected.
        parameter: &'static str,
        /// The length, in bytes, that was supplied.
        got: usize,
    },
}

impl std::fmt::Display for TuakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { parameter, got } => write!(
                f,
                "TUAK {parameter} length {got} bytes is not one TS 35.231 defines"
            ),
        }
    }
}

impl std::error::Error for TuakError {}

/// Keccak state size in bytes (1600 bits).
const STATE_BYTES: usize = 200;

/// Keccak-f[1600] has 24 rounds (12 + 2·log2(1600/25) = 12 + 2·6).
const KECCAK_ROUNDS: usize = 24;

/// `ALGONAME`, the ASCII of "TUAK1.0" (TS 35.231 §5.3).
const ALGONAME: &[u8; 7] = b"TUAK1.0";

/// Iota round constants for Keccak-f[1600].
const RC: [u64; KECCAK_ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rho rotation offsets, indexed by lane `x + 5y`.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// The Keccak-f[1600] permutation, in place over a 200-byte state.
///
/// Lanes are read from and written back to the byte string little-endian, which is the
/// standard Keccak convention and the one TS 35.231 Annex C's reference code uses.
fn keccak_f1600(state: &mut [u8; STATE_BYTES]) {
    let mut a = [0u64; 25];
    for (i, lane) in a.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&state[i * 8..i * 8 + 8]);
        *lane = u64::from_le_bytes(bytes);
    }

    for round in 0..KECCAK_ROUNDS {
        // Theta
        let mut c = [0u64; 5];
        for (x, c_x) in c.iter_mut().enumerate() {
            *c_x = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }

        // Rho and pi combined: B[y][2x+3y] = rot(A[x][y], r[x][y])
        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }

        // Chi
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // Iota
        a[0] ^= RC[round];
    }

    for (i, lane) in a.iter().enumerate() {
        state[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
}

/// The `INSTANCE` octet (TS 35.231 §5.3), before the reversal into `IN`.
///
/// Fields are named as the spec numbers them, `INSTANCE[0]` first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Instance {
    /// `INSTANCE[0] .. INSTANCE[1]`: which function.
    function: [u8; 2],
    /// `INSTANCE[2] .. INSTANCE[4]`: MAC/RES output length, or all zero for TOPc.
    length: [u8; 3],
    /// `INSTANCE[5]`: CK is 256-bit.
    ck_256: bool,
    /// `INSTANCE[6]`: IK is 256-bit.
    ik_256: bool,
    /// `INSTANCE[7]`: K is 256-bit.
    k_256: bool,
}

impl Instance {
    /// Pack into the byte that occupies `IN[256] .. IN[263]`.
    ///
    /// `IN[256] .. IN[263] = INSTANCE[7] .. INSTANCE[0]`, and `IN` is indexed LSB-first
    /// within a byte — so bit `k` of the result is `INSTANCE[7 - k]`. This is a real
    /// bit reversal, unlike every multi-byte field in the message, because it happens
    /// entirely inside one byte and so has no byte reversal to cancel against.
    ///
    /// Pinned by the vectors: TS 35.232 §6.3's f1 `IN` has `0x08` here (MAC-A 64 bits ⇒
    /// `INSTANCE[4] = 1` ⇒ bit 3), and its f1* `IN` has `0x88` (additionally
    /// `INSTANCE[0] = 1` ⇒ bit 7).
    fn to_byte(self) -> u8 {
        let bits = [
            self.function[0],
            self.function[1],
            self.length[0],
            self.length[1],
            self.length[2],
            u8::from(self.ck_256),
            u8::from(self.ik_256),
            u8::from(self.k_256),
        ];
        let mut out = 0u8;
        for (i, bit) in bits.iter().enumerate() {
            if *bit != 0 {
                out |= 1 << (7 - i);
            }
        }
        out
    }

    /// `INSTANCE[2] .. INSTANCE[4]` for a MAC-A/MAC-S length in bytes
    /// (TS 35.231 §6.2: 64 ⇒ 0,0,1; 128 ⇒ 0,1,0; 256 ⇒ 1,0,0).
    fn mac_length_bits(mac_len: usize) -> Result<[u8; 3], TuakError> {
        match mac_len {
            8 => Ok([0, 0, 1]),
            16 => Ok([0, 1, 0]),
            32 => Ok([1, 0, 0]),
            got => Err(TuakError::InvalidLength {
                parameter: "MAC",
                got,
            }),
        }
    }

    /// `INSTANCE[2] .. INSTANCE[4]` for a RES length in bytes
    /// (§6.4: 32 ⇒ 0,0,0; 64 ⇒ 0,0,1; 128 ⇒ 0,1,0; 256 ⇒ 1,0,0).
    fn res_length_bits(res_len: usize) -> Result<[u8; 3], TuakError> {
        match res_len {
            4 => Ok([0, 0, 0]),
            8 => Ok([0, 0, 1]),
            16 => Ok([0, 1, 0]),
            32 => Ok([1, 0, 0]),
            got => Err(TuakError::InvalidLength {
                parameter: "RES",
                got,
            }),
        }
    }
}

/// Copy `value` into `dst` in reversed byte order.
///
/// This is the single mapping rule the whole module rests on — see the module docs.
fn put_reversed(dst: &mut [u8], value: &[u8]) {
    for (i, byte) in value.iter().rev().enumerate() {
        dst[i] = *byte;
    }
}

/// Read `len` bytes from `src` in reversed byte order.
fn take_reversed(src: &[u8], len: usize) -> Vec<u8> {
    src[..len].iter().rev().copied().collect()
}

/// Build the 1600-bit `IN` common to every TUAK function.
///
/// `top_or_topc` occupies bytes 0..32, `INSTANCE` byte 32, `ALGONAME` bytes 33..40,
/// then per-function material in bytes 40..64, `K` from byte 64, and the Keccak padding.
fn build_in(
    top_or_topc: &[u8; 32],
    instance: Instance,
    rand: Option<&[u8; 16]>,
    amf: Option<&[u8; 2]>,
    sqn: Option<&[u8; 6]>,
    k: &[u8],
) -> [u8; STATE_BYTES] {
    let mut input = [0u8; STATE_BYTES];

    // IN[0..255] = TOP/TOPC reversed.
    put_reversed(&mut input[0..32], top_or_topc);
    // IN[256..263] = INSTANCE[7]..INSTANCE[0].
    input[32] = instance.to_byte();
    // IN[264..319] = ALGONAME[55]..ALGONAME[0].
    put_reversed(&mut input[33..40], ALGONAME);
    // IN[320..447] = RAND, IN[448..463] = AMF, IN[464..511] = SQN. All absent (and so
    // zero) for the TOPc derivation and for f2-f5, which carry only RAND.
    if let Some(rand) = rand {
        put_reversed(&mut input[40..56], rand);
    }
    if let Some(amf) = amf {
        put_reversed(&mut input[56..58], amf);
    }
    if let Some(sqn) = sqn {
        put_reversed(&mut input[58..64], sqn);
    }
    // IN[512..767] = K reversed; a 128-bit K leaves bytes 80..96 zero.
    put_reversed(&mut input[64..64 + k.len()], k);

    // Keccak padding, §5.2: "1111" for Sakura domain separation immediately followed by
    // the "1 0* 1" pad, giving five 1 bits at IN[768..772] and a final 1 at IN[1087].
    // In LSB-first byte terms that is 0x1f at byte 96 and 0x80 at byte 135 — the values
    // TS 35.232 §6.3's intermediate `IN` shows.
    input[96] = 0x1f;
    input[135] = 0x80;

    input
}

/// Run the permutation `iterations` times (TS 35.231 §7.2 allows more than one for
/// additional customisation; every 3GPP test vector uses 1).
fn permute(mut state: [u8; STATE_BYTES], iterations: u8) -> [u8; STATE_BYTES] {
    for _ in 0..iterations.max(1) {
        keccak_f1600(&mut state);
    }
    state
}

/// Validate a subscriber key length: TUAK takes a 128-bit or 256-bit K.
fn check_k(k: &[u8]) -> Result<bool, TuakError> {
    match k.len() {
        16 => Ok(false),
        32 => Ok(true),
        got => Err(TuakError::InvalidLength {
            parameter: "K",
            got,
        }),
    }
}

/// Derive TOPC from TOP and K (TS 35.231 §6.1).
///
/// TOPC is to TUAK what OPC is to MILENAGE: the operator-variant field bound to the
/// subscriber key, so it can be provisioned instead of TOP and TOP need never leave the
/// operator's control (§7.1).
pub fn tuak_topc(top: &[u8; 32], k: &[u8], iterations: u8) -> Result<[u8; 32], TuakError> {
    let k_256 = check_k(k)?;
    let instance = Instance {
        // §6.1: INSTANCE[0]..INSTANCE[6] are all zero when deriving TOPC — including
        // the length field, which is what distinguishes this from f2-f5 with a 32-bit
        // RES (also all-zero there) via INSTANCE[0..1].
        function: [0, 0],
        length: [0, 0, 0],
        ck_256: false,
        ik_256: false,
        k_256,
    };
    let out = permute(build_in(top, instance, None, None, None, k), iterations);
    let mut topc = [0u8; 32];
    topc.copy_from_slice(&take_reversed(&out, 32));
    Ok(topc)
}

/// f1: the network authentication function, producing MAC-A (TS 35.231 §6.2).
///
/// `mac_len` is 8, 16 or 32 bytes; 8 is what a 3GPP AUTN carries.
pub fn tuak_f1(
    topc: &[u8; 32],
    k: &[u8],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    mac_len: usize,
    iterations: u8,
) -> Result<Vec<u8>, TuakError> {
    let k_256 = check_k(k)?;
    let instance = Instance {
        function: [0, 0],
        length: Instance::mac_length_bits(mac_len)?,
        ck_256: false,
        ik_256: false,
        k_256,
    };
    let out = permute(
        build_in(topc, instance, Some(rand), Some(amf), Some(sqn), k),
        iterations,
    );
    Ok(take_reversed(&out, mac_len))
}

/// f1*: the re-synchronisation authentication function, producing MAC-S
/// (TS 35.231 §6.3). Identical to f1 except `INSTANCE[0]` is 1.
pub fn tuak_f1star(
    topc: &[u8; 32],
    k: &[u8],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    mac_len: usize,
    iterations: u8,
) -> Result<Vec<u8>, TuakError> {
    let k_256 = check_k(k)?;
    let instance = Instance {
        function: [1, 0],
        length: Instance::mac_length_bits(mac_len)?,
        ck_256: false,
        ik_256: false,
        k_256,
    };
    let out = permute(
        build_in(topc, instance, Some(rand), Some(amf), Some(sqn), k),
        iterations,
    );
    Ok(take_reversed(&out, mac_len))
}

/// The outputs of one f2/f3/f4/f5 evaluation (TS 35.231 §6.4).
///
/// All four come out of a SINGLE permutation, from different ranges of `OUT` — which is
/// why they are returned together rather than as four functions that would each redo the
/// same work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuakF2345 {
    /// f2 output: RES (4, 8, 16 or 32 bytes).
    pub res: Vec<u8>,
    /// f3 output: CK (16 or 32 bytes).
    pub ck: Vec<u8>,
    /// f4 output: IK (16 or 32 bytes).
    pub ik: Vec<u8>,
    /// f5 output: AK (always 48 bits).
    pub ak: [u8; 6],
}

/// f2, f3, f4 and f5 in one evaluation (TS 35.231 §6.4).
pub fn tuak_f2345(
    topc: &[u8; 32],
    k: &[u8],
    rand: &[u8; 16],
    res_len: usize,
    ck_len: usize,
    ik_len: usize,
    iterations: u8,
) -> Result<TuakF2345, TuakError> {
    let k_256 = check_k(k)?;
    if !matches!(ck_len, 16 | 32) {
        return Err(TuakError::InvalidLength {
            parameter: "CK",
            got: ck_len,
        });
    }
    if !matches!(ik_len, 16 | 32) {
        return Err(TuakError::InvalidLength {
            parameter: "IK",
            got: ik_len,
        });
    }
    let instance = Instance {
        function: [0, 1],
        length: Instance::res_length_bits(res_len)?,
        ck_256: ck_len == 32,
        ik_256: ik_len == 32,
        k_256,
    };
    let out = permute(
        build_in(topc, instance, Some(rand), None, None, k),
        iterations,
    );

    // §6.4's extraction ranges, in bytes: RES from OUT[0..], CK from OUT[256..],
    // IK from OUT[512..], AK from OUT[768..]. Each is byte-reversed like every other
    // field. Note CK and IK start at fixed offsets regardless of their length, so a
    // 128-bit CK is the FIRST 16 bytes of its 32-byte window in `OUT` order — which,
    // reversed, is `OUT[383]..OUT[256]` as the spec writes it.
    Ok(TuakF2345 {
        res: take_reversed(&out[0..], res_len),
        ck: take_reversed(&out[32..], ck_len),
        ik: take_reversed(&out[64..], ik_len),
        ak: {
            let mut ak = [0u8; 6];
            ak.copy_from_slice(&take_reversed(&out[96..], 6));
            ak
        },
    })
}

/// f5*: the anonymity key for re-synchronisation (TS 35.231 §6.5).
///
/// Same `IN` as f2-f5 but with `INSTANCE[0..1] = 1,1` and the length field zeroed.
pub fn tuak_f5star(
    topc: &[u8; 32],
    k: &[u8],
    rand: &[u8; 16],
    iterations: u8,
) -> Result<[u8; 6], TuakError> {
    let k_256 = check_k(k)?;
    let instance = Instance {
        function: [1, 1],
        length: [0, 0, 0],
        ck_256: false,
        ik_256: false,
        k_256,
    };
    let out = permute(
        build_in(topc, instance, Some(rand), None, None, k),
        iterations,
    );
    let mut ak = [0u8; 6];
    ak.copy_from_slice(&take_reversed(&out[96..], 6));
    Ok(ak)
}

/// Generate a 3GPP authentication vector with TUAK.
///
/// Returns `(autn, ik, ck, ak, res)` — the same tuple, in the same order, as
/// [`crate::milenage::milenage_generate`], so the two are interchangeable at a call
/// site that branches on the subscriber's algorithm.
///
/// Fixed at the 3GPP AV shape: a 64-bit MAC-A, a 64-bit RES and 128-bit CK/IK, because
/// that is what AUTN and the Nudm authentication-vector schema carry. TUAK's longer
/// variants are reachable through the individual functions above.
pub fn tuak_generate(
    topc: &[u8; 32],
    amf: &[u8; 2],
    k: &[u8],
    sqn: &[u8; 6],
    rand: &[u8; 16],
    iterations: u8,
) -> Result<([u8; 16], [u8; 16], [u8; 16], [u8; 6], [u8; 8]), TuakError> {
    let mac_a = tuak_f1(topc, k, rand, sqn, amf, 8, iterations)?;
    let f2345 = tuak_f2345(topc, k, rand, 8, 16, 16, iterations)?;

    // AUTN = (SQN xor AK) || AMF || MAC-A, exactly as TS 33.102 §6.3.2 defines it for
    // MILENAGE — the AV shape is the authentication framework's, not the algorithm's.
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn[i] ^ f2345.ak[i];
    }
    autn[6..8].copy_from_slice(amf);
    autn[8..16].copy_from_slice(&mac_a);

    let mut ck = [0u8; 16];
    ck.copy_from_slice(&f2345.ck);
    let mut ik = [0u8; 16];
    ik.copy_from_slice(&f2345.ik);
    let mut res = [0u8; 8];
    res.copy_from_slice(&f2345.res);

    Ok((autn, ik, ck, f2345.ak, res))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the whitespace-separated hex the 3GPP test-data documents print.
    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..cleaned.len() / 2)
            .map(|i| u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// TS 35.233 / TS 35.232 §5.4 Test set 2: the permutation alone, on the state whose
    /// only set bit is the most significant of byte 0.
    ///
    /// This pins Keccak-f[1600] independently of every TUAK-specific mapping. If the
    /// permutation is wrong, all the vector tests below fail together and none of them
    /// says why; this one does.
    #[test]
    fn keccak_permutation_matches_ts_35_233_test_set_2() {
        let mut state = [0u8; STATE_BYTES];
        state[0] = 0x80;
        keccak_f1600(&mut state);

        let expected = hex(
            "44 e0 e5 8c a9 68 97 5c 4c 25 92 a1 57 f5 3f 21 24 51 9b 01 0b 89 e1 5e
             30 1e f5 8f 76 50 1d b5 9c de 06 7f 1f de 09 c0 a4 b5 c2 10 a6 a1 9f 06
             ba 4c 8f 0c 6f c8 68 f0 fc 80 a6 3b 25 53 79 1e 41 c8 22 78 ad 11 5e fc
             70 f7 1d 64 1f f0 77 4a a5 d5 47 b6 d9 91 49 14 02 2c 51 4c 45 fc ec a6
             1c b6 6b 0f 03 13 e3 49 88 ae 0d 36 73 7e 2c 05 29 90 7f e6 53 fc 4e 18
             5d 07 f3 96 1f 82 6b b8 80 31 af 84 4d 9e 7d 98 76 17 03 63 fd e7 67 86
             c5 8c cb cf 5c 3a 01 bb 91 4c 1b 02 08 a2 7c 7b e3 bb bb bb 99 76 e0 40
             31 7a fc 2a fb fa dc 7b a7 fc 23 72 35 c6 55 51 aa 31 39 64 1f a8 db 2e
             64 83 f2 87 40 b3 1b 61",
        );
        assert_eq!(
            state.to_vec(),
            expected,
            "Keccak-f[1600] must be byte-exact"
        );
    }

    /// The same permutation against TS 35.232 §5.3 Test set 1, a full pseudo-random
    /// state — so the check is not satisfied by a state that is mostly zero.
    #[test]
    fn keccak_permutation_matches_ts_35_233_test_set_1() {
        let input = hex(
            "24 76 d2 da c5 9e 2e 93 49 df 32 55 a9 da b1 b6 9e b5 c2 08 f1 51 c7 30
             9e 8c 8f 17 db 45 6d 0b 5e b0 af b6 c7 3e 37 ce 8c cc cf 20 b7 9d 8a 67
             29 41 49 17 48 09 e4 29 70 93 30 c4 ad 23 1d 3e 52 11 ae 0b d8 05 20 c4
             3a d4 b4 36 62 57 92 a7 6c 52 08 9d 0f 73 92 71 15 1a 37 59 4d f6 6d e4
             42 9f 3c 97 0a 34 56 b6 ce 2c 78 cd 11 28 71 7f 4b db 73 1a 4c 97 db e5
             eb 73 53 fe 81 e3 7c 33 ac 60 b8 21 22 ea c6 11 a9 8e 0e 74 42 b9 99 64
             75 22 93 e4 f9 c6 96 ba 05 f0 7a 21 45 1f 90 73 0c 96 78 c6 45 ad 4b e4
             4c 4d 2d 98 1a 34 12 08 1c 9c 6b 05 c9 93 ff 1c 56 1a 0d 24 2b 47 06 d5
             01 c3 47 65 b3 7a 0b 50",
        );
        let expected = hex(
            "2f dc 58 d4 d9 4a 88 4c 1c b0 3a 8e 63 ac ab 83 75 e8 56 b5 61 ba 3a 06
             25 e8 30 ac db 55 73 42 86 64 6f 87 18 9b 43 54 25 b5 d6 65 4e 22 82 28
             b6 97 b8 1c be ad 65 5b 71 aa cc c2 5e 3d 7e 51 b5 cb 5a c2 27 f6 7f 2a
             d8 a0 62 97 67 82 b0 8a 7e c3 f1 b5 38 d6 00 8c 0b ab ef 83 da 64 36 6b
             62 a5 3f 88 a3 dc 06 29 bd ed 79 5f 32 20 f3 c6 5c 76 bd d0 12 43 e8 8f
             63 d6 91 2e 5f b5 cd a1 67 b7 1f 9b aa a7 42 dc 19 3f f7 8c 17 67 a3 8a
             1c 96 40 8c ce 16 92 39 b0 77 f2 90 3a 07 b8 c4 6a 04 8d 66 31 8e 59 5e
             a4 bb 92 99 2c 7c 2d 3d cd 38 19 75 b6 e0 5f 85 ba 18 15 20 96 cc 30 ed
             22 14 0f f3 b6 71 1e a7",
        );
        let mut state = [0u8; STATE_BYTES];
        state.copy_from_slice(&input);
        keccak_f1600(&mut state);
        assert_eq!(state.to_vec(), expected);
    }

    /// TS 35.232 §6.3 Test set 1, the whole of it: TOPc, f1 and f1*.
    ///
    /// K = 128 bits, MAC = 64 bits, KeccakIterations = 1.
    #[test]
    fn tuak_test_set_1_topc_f1_and_f1star() {
        let k = hex("abababababababababababababababab");
        let rand: [u8; 16] = hex("42424242424242424242424242424242").try_into().unwrap();
        let sqn: [u8; 6] = hex("111111111111").try_into().unwrap();
        let amf: [u8; 2] = hex("ffff").try_into().unwrap();
        let top: [u8; 32] = hex("5555555555555555555555555555555555555555555555555555555555555555")
            .try_into()
            .unwrap();

        let topc = tuak_topc(&top, &k, 1).unwrap();
        assert_eq!(
            topc.to_vec(),
            hex("bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff"),
            "TOPc must match TS 35.232 §6.3"
        );

        assert_eq!(
            tuak_f1(&topc, &k, &rand, &sqn, &amf, 8, 1).unwrap(),
            hex("f9a54e6aeaa8618d"),
            "f1 (MAC-A) must match TS 35.232 §6.3"
        );
        assert_eq!(
            tuak_f1star(&topc, &k, &rand, &sqn, &amf, 8, 1).unwrap(),
            hex("e94b4dc6c7297df3"),
            "f1* (MAC-S) must match TS 35.232 §6.3"
        );
    }

    /// TS 35.232 §7.3 Test set 1: f2, f3, f4, f5 and f5*.
    ///
    /// K = 128, CK = 128, IK = 128, RES = 32 bits, KeccakIterations = 1. Note RES is 32
    /// bits here, which is `INSTANCE[2..4] = 0,0,0` — the same length field as the TOPc
    /// derivation uses, so this vector also proves the two are distinguished by
    /// `INSTANCE[0..1]` and not by the length bits.
    #[test]
    fn tuak_test_set_1_f2_f3_f4_f5_and_f5star() {
        let k = hex("abababababababababababababababab");
        let rand: [u8; 16] = hex("42424242424242424242424242424242").try_into().unwrap();
        let topc: [u8; 32] =
            hex("bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff")
                .try_into()
                .unwrap();

        let out = tuak_f2345(&topc, &k, &rand, 4, 16, 16, 1).unwrap();
        assert_eq!(out.res, hex("657acd64"), "f2 (RES)");
        assert_eq!(out.ck, hex("d71a1e5c6caffe986a26f783e5c78be1"), "f3 (CK)");
        assert_eq!(out.ik, hex("be849fa2564f869aecee6f62d4337e72"), "f4 (IK)");
        assert_eq!(out.ak.to_vec(), hex("719f1e9b9054"), "f5 (AK)");

        assert_eq!(
            tuak_f5star(&topc, &k, &rand, 1).unwrap().to_vec(),
            hex("e7af6b3d0e38"),
            "f5* (AK for re-synchronisation)"
        );
    }

    /// The f2-f5 `IN` must match TS 35.232 §7.3's intermediate value too — the same
    /// localisation argument as for TOPc, and it additionally pins that AMF and SQN are
    /// ABSENT here (bytes 56..64 zero) where f1 carries them.
    #[test]
    fn the_f2345_input_matches_the_documented_intermediate_value() {
        let k = hex("abababababababababababababababab");
        let rand: [u8; 16] = hex("42424242424242424242424242424242").try_into().unwrap();
        let topc: [u8; 32] =
            hex("bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff")
                .try_into()
                .unwrap();
        let instance = Instance {
            function: [0, 1],
            length: Instance::res_length_bits(4).unwrap(),
            ck_256: false,
            ik_256: false,
            k_256: false,
        };
        assert_eq!(instance.to_byte(), 0x40, "TS 35.232 §7.3 f2-f5 IN[32]");

        let input = build_in(&topc, instance, Some(&rand), None, None, &k);
        let expected = hex(
            "ff cb cc 40 1f 5d b4 3e a7 05 53 11 0c 33 e2 a8 23 46 95 ad c2 7a 83 5d
             3c 51 87 0e 53 d9 04 bd 40 30 2e 31 4b 41 55 54 42 42 42 42 42 42 42 42
             42 42 42 42 42 42 42 42 00 00 00 00 00 00 00 00 ab ab ab ab ab ab ab ab
             ab ab ab ab ab ab ab ab 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             1f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00",
        );
        assert_eq!(input.to_vec(), expected);
        assert!(
            input[56..64].iter().all(|b| *b == 0),
            "f2-f5 carry no AMF or SQN (§6.4: IN[448..511] = 0), unlike f1"
        );
    }

    /// The `INSTANCE` octet is the one field with a real intra-byte bit reversal, so it
    /// gets its own assertion against the two values TS 35.232 §6.3 prints.
    #[test]
    fn instance_byte_matches_the_documented_intermediate_values() {
        // f1 with a 64-bit MAC and a 128-bit K: INSTANCE[4] = 1 alone ⇒ bit 3 ⇒ 0x08.
        let f1 = Instance {
            function: [0, 0],
            length: Instance::mac_length_bits(8).unwrap(),
            ck_256: false,
            ik_256: false,
            k_256: false,
        };
        assert_eq!(f1.to_byte(), 0x08, "TS 35.232 §6.3 f1 IN[32]");

        // f1* adds INSTANCE[0] = 1 ⇒ bit 7 ⇒ 0x88.
        let f1star = Instance {
            function: [1, 0],
            ..f1
        };
        assert_eq!(f1star.to_byte(), 0x88, "TS 35.232 §6.3 f1* IN[32]");

        // TOPc derivation with a 128-bit K: every bit zero.
        let topc = Instance {
            function: [0, 0],
            length: [0, 0, 0],
            ck_256: false,
            ik_256: false,
            k_256: false,
        };
        assert_eq!(topc.to_byte(), 0x00, "TS 35.232 §6.3 TOPc IN[32]");
    }

    /// The `IN` this module builds must be byte-identical to the intermediate value
    /// TS 35.232 §6.3 prints for the TOPc derivation.
    ///
    /// Asserting the INPUT and not only the output is what localises a mapping error:
    /// a wrong byte order in `IN` and a wrong extraction from `OUT` can otherwise
    /// cancel in a round trip, and the permutation in between would hide both.
    #[test]
    fn the_topc_input_matches_the_documented_intermediate_value() {
        let k = hex("abababababababababababababababab");
        let top: [u8; 32] = hex("5555555555555555555555555555555555555555555555555555555555555555")
            .try_into()
            .unwrap();
        let instance = Instance {
            function: [0, 0],
            length: [0, 0, 0],
            ck_256: false,
            ik_256: false,
            k_256: false,
        };
        let input = build_in(&top, instance, None, None, None, &k);

        let expected = hex(
            "55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55
             55 55 55 55 55 55 55 55 00 30 2e 31 4b 41 55 54 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ab ab ab ab ab ab ab ab
             ab ab ab ab ab ab ab ab 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             1f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00",
        );
        assert_eq!(input.to_vec(), expected);
        // And the ALGONAME really is reversed, which is the least obvious part.
        assert_eq!(&input[33..40], b"0.1KAUT");
    }

    /// A 256-bit K must set `INSTANCE[7]` and fill all 32 K bytes of `IN`.
    #[test]
    fn a_256_bit_key_sets_the_k_length_bit_and_fills_the_key_field() {
        let k = vec![0xa5u8; 32];
        let top = [0x55u8; 32];
        let instance = Instance {
            function: [0, 0],
            length: [0, 0, 0],
            ck_256: false,
            ik_256: false,
            k_256: true,
        };
        assert_eq!(instance.to_byte(), 0x01, "INSTANCE[7] is IN bit 0");
        let input = build_in(&top, instance, None, None, None, &k);
        assert!(
            input[64..96].iter().all(|b| *b == 0xa5),
            "a 256-bit K occupies IN[512..767] in full; a 128-bit one leaves the upper \
             half zero"
        );
        // And the derivation accepts it.
        assert!(tuak_topc(&top, &k, 1).is_ok());
    }

    #[test]
    fn an_unsupported_key_length_is_refused() {
        let top = [0x55u8; 32];
        assert!(tuak_topc(&top, &[0u8; 24], 1).is_err());
        assert!(tuak_topc(&top, &[], 1).is_err());
    }

    #[test]
    fn an_unsupported_output_length_is_refused() {
        let topc = [0u8; 32];
        let k = [0xabu8; 16];
        let rand = [0x42u8; 16];
        let sqn = [0x11u8; 6];
        let amf = [0xffu8; 2];
        // MAC-A of 96 bits is not one of §6.2's three lengths.
        assert!(tuak_f1(&topc, &k, &rand, &sqn, &amf, 12, 1).is_err());
        // RES of 96 bits is not one of §6.4's four.
        assert!(tuak_f2345(&topc, &k, &rand, 12, 16, 16, 1).is_err());
        // CK must be 128 or 256 bits.
        assert!(tuak_f2345(&topc, &k, &rand, 8, 24, 16, 1).is_err());
    }

    /// `tuak_generate` assembles AUTN the way TS 33.102 §6.3.2 defines it, so the AV is
    /// interchangeable with MILENAGE's at a call site that branches on the algorithm.
    #[test]
    fn tuak_generate_assembles_the_autn_from_its_own_f1_and_f5() {
        let k = hex("abababababababababababababababab");
        let rand: [u8; 16] = hex("42424242424242424242424242424242").try_into().unwrap();
        let sqn: [u8; 6] = hex("111111111111").try_into().unwrap();
        let amf: [u8; 2] = hex("ffff").try_into().unwrap();
        let top: [u8; 32] = hex("5555555555555555555555555555555555555555555555555555555555555555")
            .try_into()
            .unwrap();
        let topc = tuak_topc(&top, &k, 1).unwrap();

        let (autn, ik, ck, ak, res) = tuak_generate(&topc, &amf, &k, &sqn, &rand, 1).unwrap();
        let f2345 = tuak_f2345(&topc, &k, &rand, 8, 16, 16, 1).unwrap();
        let mac_a = tuak_f1(&topc, &k, &rand, &sqn, &amf, 8, 1).unwrap();

        for i in 0..6 {
            assert_eq!(autn[i], sqn[i] ^ ak[i], "AUTN[0..6] = SQN xor AK");
        }
        assert_eq!(&autn[6..8], &amf, "AUTN[6..8] = AMF");
        assert_eq!(&autn[8..16], mac_a.as_slice(), "AUTN[8..16] = MAC-A");
        assert_eq!(res.to_vec(), f2345.res);
        assert_eq!(ck.to_vec(), f2345.ck);
        assert_eq!(ik.to_vec(), f2345.ik);
        assert_eq!(ak.to_vec(), f2345.ak.to_vec());
    }

    /// TUAK and MILENAGE must not agree: they are different algorithms, and a call site
    /// that branched the wrong way would otherwise be undetectable.
    #[test]
    fn tuak_and_milenage_produce_different_vectors_for_the_same_inputs() {
        let k = [0xabu8; 16];
        let rand = [0x42u8; 16];
        let sqn = [0x11u8; 6];
        let amf = [0xffu8; 2];
        let topc = tuak_topc(&[0x55u8; 32], &k, 1).unwrap();
        let opc = [0x55u8; 16];

        let (tuak_autn, ..) = tuak_generate(&topc, &amf, &k, &sqn, &rand, 1).unwrap();
        let (mil_autn, ..) =
            crate::milenage::milenage_generate(&opc, &amf, &k, &sqn, &rand).expect("milenage");
        assert_ne!(
            tuak_autn, mil_autn,
            "a TUAK AV must differ from a MILENAGE AV for the same subscriber inputs"
        );
    }

    /// More than one Keccak iteration changes the answer (§7.2's customisation knob),
    /// so the parameter is not silently ignored.
    #[test]
    fn keccak_iterations_change_the_result() {
        let k = [0xabu8; 16];
        let top = [0x55u8; 32];
        assert_ne!(
            tuak_topc(&top, &k, 1).unwrap(),
            tuak_topc(&top, &k, 2).unwrap()
        );
        // 0 is treated as 1 rather than "no permutation at all", which would return the
        // input and leak K straight into TOPc.
        assert_eq!(
            tuak_topc(&top, &k, 0).unwrap(),
            tuak_topc(&top, &k, 1).unwrap()
        );
    }
}
