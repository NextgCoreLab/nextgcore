//! KASUMI Block Cipher
//!
//! Exact port of lib/crypt/kasumi.c
//!
//! Implements the KASUMI block cipher as used in 3GPP f8 (confidentiality)
//! and f9 (integrity) algorithms.

/// 16-bit rotate left
#[inline]
fn rol16(a: u16, b: u32) -> u16 {
    (a << b) | (a >> (16 - b))
}

/// S7 substitution box
const S7: [u16; 128] = [
    54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33,
    55, 113, 39, 114, 21, 67, 65, 12, 47, 73, 46, 27, 25, 111, 124, 81,
    53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40, 120, 104, 70, 71, 43,
    20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
    117, 116, 76, 11, 89, 106, 0, 125, 118, 99, 86, 69, 30, 57, 126, 87,
    112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35, 103, 32, 97, 28, 66,
    102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29, 115, 44,
    64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3,
];

/// S9 substitution box
const S9: [u16; 512] = [
    167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
    183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
    175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
    95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
    165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
    501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421, 350, 163,
    232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
    344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,
    487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
    475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
    363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
    439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
    465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61, 244, 282,
    173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330,
    280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
    132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,
    35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
    50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
    72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
    185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
    1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
    336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
    47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
    414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
    266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
    311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
    485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
    312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
    284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
    97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
    438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
    43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461,
];

/// Key schedule constants
const C: [u16; 8] = [0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210];

/// KASUMI key schedule
pub struct KasumiKeySchedule {
    kli1: [u16; 8],
    kli2: [u16; 8],
    koi1: [u16; 8],
    koi2: [u16; 8],
    koi3: [u16; 8],
    kii1: [u16; 8],
    kii2: [u16; 8],
    kii3: [u16; 8],
}

impl KasumiKeySchedule {
    /// Build the key schedule from a 128-bit key
    pub fn new(key: &[u8; 16]) -> Self {
        let mut ks = Self {
            kli1: [0; 8],
            kli2: [0; 8],
            koi1: [0; 8],
            koi2: [0; 8],
            koi3: [0; 8],
            kii1: [0; 8],
            kii2: [0; 8],
            kii3: [0; 8],
        };

        // Convert key bytes to 16-bit words (big-endian)
        let mut k = [0u16; 8];
        for n in 0..8 {
            k[n] = ((key[n * 2] as u16) << 8) | (key[n * 2 + 1] as u16);
        }

        // Build K' keys
        let mut kprime = [0u16; 8];
        for n in 0..8 {
            kprime[n] = k[n] ^ C[n];
        }

        // Construct the various sub keys
        for n in 0..8 {
            ks.kli1[n] = rol16(k[n], 1);
            ks.kli2[n] = kprime[(n + 2) & 0x7];
            ks.koi1[n] = rol16(k[(n + 1) & 0x7], 5);
            ks.koi2[n] = rol16(k[(n + 5) & 0x7], 8);
            ks.koi3[n] = rol16(k[(n + 6) & 0x7], 13);
            ks.kii1[n] = kprime[(n + 4) & 0x7];
            ks.kii2[n] = kprime[(n + 3) & 0x7];
            ks.kii3[n] = kprime[(n + 7) & 0x7];
        }

        ks
    }
}


/// FI function - transforms a 16-bit value
fn fi(input: u16, subkey: u16) -> u16 {
    let mut nine = input >> 7;
    let mut seven = input & 0x7F;

    // First round
    nine = S9[nine as usize] ^ seven;
    seven = S7[seven as usize] ^ (nine & 0x7F);

    // XOR with subkey
    seven ^= subkey >> 9;
    nine ^= subkey & 0x1FF;

    // Second round
    nine = S9[nine as usize] ^ seven;
    seven = S7[seven as usize] ^ (nine & 0x7F);

    (seven << 9) | nine
}

/// FO function - transforms a 32-bit value
fn fo(input: u32, ks: &KasumiKeySchedule, index: usize) -> u32 {
    let mut left = (input >> 16) as u16;
    let mut right = input as u16;

    // Three rounds
    left ^= ks.koi1[index];
    left = fi(left, ks.kii1[index]);
    left ^= right;

    right ^= ks.koi2[index];
    right = fi(right, ks.kii2[index]);
    right ^= left;

    left ^= ks.koi3[index];
    left = fi(left, ks.kii3[index]);
    left ^= right;

    ((right as u32) << 16) | (left as u32)
}

/// FL function - transforms a 32-bit value
fn fl(input: u32, ks: &KasumiKeySchedule, index: usize) -> u32 {
    let mut l = (input >> 16) as u16;
    let mut r = input as u16;

    let a = l & ks.kli1[index];
    r ^= rol16(a, 1);

    let b = r | ks.kli2[index];
    l ^= rol16(b, 1);

    ((l as u32) << 16) | (r as u32)
}

/// KASUMI block cipher - encrypts a 64-bit block in place
pub fn kasumi(data: &mut [u8; 8], ks: &KasumiKeySchedule) {
    // Get data into two 32-bit words (big-endian)
    let mut left = ((data[0] as u32) << 24)
        | ((data[1] as u32) << 16)
        | ((data[2] as u32) << 8)
        | (data[3] as u32);
    let mut right = ((data[4] as u32) << 24)
        | ((data[5] as u32) << 16)
        | ((data[6] as u32) << 8)
        | (data[7] as u32);

    // 8 rounds
    let mut n = 0;
    while n <= 7 {
        let temp = fl(left, ks, n);
        let temp = fo(temp, ks, n);
        n += 1;
        right ^= temp;

        let temp = fo(right, ks, n);
        let temp = fl(temp, ks, n);
        n += 1;
        left ^= temp;
    }

    // Return the correct endian result
    data[0] = (left >> 24) as u8;
    data[1] = (left >> 16) as u8;
    data[2] = (left >> 8) as u8;
    data[3] = left as u8;
    data[4] = (right >> 24) as u8;
    data[5] = (right >> 16) as u8;
    data[6] = (right >> 8) as u8;
    data[7] = right as u8;
}

/// KASUMI f8 - 3GPP Confidentiality Algorithm
///
/// # Arguments
/// * `key` - 128-bit key
/// * `count` - 32-bit counter
/// * `bearer` - 5-bit bearer identity
/// * `dir` - 1-bit direction
/// * `data` - Data to encrypt/decrypt (modified in place)
/// * `length` - Length in bits
pub fn kasumi_f8(key: &[u8; 16], count: u32, bearer: u32, dir: u32, data: &mut [u8], length: usize) {
    if length == 0 {
        return;
    }

    // Build modifier A
    let mut a = [0u8; 8];
    a[0] = (count >> 24) as u8;
    a[1] = (count >> 16) as u8;
    a[2] = (count >> 8) as u8;
    a[3] = count as u8;
    a[4] = ((bearer << 3) | (dir << 2)) as u8;

    // Construct modified key (XOR with 0x55)
    let mut mod_key = [0u8; 16];
    for n in 0..16 {
        mod_key[n] = key[n] ^ 0x55;
    }

    // First encryption to create modifier
    let mod_ks = KasumiKeySchedule::new(&mod_key);
    kasumi(&mut a, &mod_ks);

    // Initialize block cipher with original key
    let ks = KasumiKeySchedule::new(key);

    let mut temp = [0u8; 8];
    let mut blkcnt: u16 = 0;
    let mut remaining = length as i32;
    let mut pos = 0;

    while remaining > 0 {
        // XOR in A and BLKCNT
        for i in 0..8 {
            temp[i] ^= a[i];
        }
        temp[7] ^= blkcnt as u8;
        temp[6] ^= (blkcnt >> 8) as u8;

        // KASUMI to produce keystream
        kasumi(&mut temp, &ks);

        // Number of bytes to process
        let n = if remaining >= 64 { 8 } else { ((remaining + 7) / 8) as usize };

        // XOR keystream with data
        for i in 0..n {
            if pos + i < data.len() {
                data[pos + i] ^= temp[i];
            }
        }

        pos += n;
        remaining -= 64;
        blkcnt = blkcnt.wrapping_add(1);
    }

    // Zero last bits if length is not byte-aligned
    let lastbits = (8 - (length % 8)) % 8;
    if lastbits > 0 && pos > 0 {
        data[pos - 1] &= 0xFF << lastbits;
    }
}

/// KASUMI f9 - 3GPP Integrity Algorithm
///
/// # Arguments
/// * `key` - 128-bit key
/// * `count` - 32-bit counter
/// * `fresh` - 32-bit random value
/// * `dir` - 1-bit direction
/// * `data` - Data to authenticate
/// * `length` - Length in bits
///
/// # Returns
/// * 32-bit MAC
pub fn kasumi_f9(key: &[u8; 16], count: u32, fresh: u32, dir: u32, data: &[u8], length: usize) -> [u8; 4] {
    let final_bit: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 8, 4, 2, 1];

    // Initialize key schedule
    let ks = KasumiKeySchedule::new(key);

    // Initialize MAC chain
    let mut a = [0u8; 8];
    for n in 0..4 {
        a[n] = (count >> (24 - (n * 8))) as u8;
        a[n + 4] = (fresh >> (24 - (n * 8))) as u8;
    }
    kasumi(&mut a, &ks);

    let mut b = a;
    let mut remaining = length as i32;
    let mut pos = 0;

    // Process full 64-bit blocks
    while remaining >= 64 {
        for n in 0..8 {
            a[n] ^= data[pos + n];
        }
        kasumi(&mut a, &ks);
        remaining -= 64;
        pos += 8;

        for n in 0..8 {
            b[n] ^= a[n];
        }
    }

    // Process remaining whole bytes
    let mut n = 0;
    while remaining >= 8 {
        a[n] ^= data[pos];
        pos += 1;
        n += 1;
        remaining -= 8;
    }

    // Add direction bit
    let i = if remaining > 0 {
        let mut val = data[pos];
        if dir != 0 {
            val |= final_bit[remaining as usize];
        }
        val
    } else {
        if dir != 0 { 0x80 } else { 0 }
    };
    a[n] ^= i;
    n += 1;

    // Handle final '1' bit
    if remaining == 7 && n == 8 {
        kasumi(&mut a, &ks);
        for j in 0..8 {
            b[j] ^= a[j];
        }
        a[0] ^= 0x80;
        // n = 1; // Not used after this point
    } else if remaining == 7 {
        a[n] ^= 0x80;
    } else {
        a[n - 1] ^= final_bit[(remaining + 1) as usize];
    }

    kasumi(&mut a, &ks);
    for j in 0..8 {
        b[j] ^= a[j];
    }

    // Final KASUMI with modified key (XOR with 0xAA)
    let mut mod_key = [0u8; 16];
    for j in 0..16 {
        mod_key[j] = key[j] ^ 0xAA;
    }
    let mod_ks = KasumiKeySchedule::new(&mod_key);
    kasumi(&mut b, &mod_ks);

    // Return left-most 32 bits
    [b[0], b[1], b[2], b[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kasumi_block_cipher() {
        // Basic KASUMI block cipher test
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let mut data: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        let ks = KasumiKeySchedule::new(&key);
        kasumi(&mut data, &ks);
        
        // Verify encryption changed the data
        assert_ne!(data, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_kasumi_f8_roundtrip() {
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
        let length: usize = 64;

        // Encrypt
        kasumi_f8(&key, count, bearer, dir, &mut data, length);
        
        // Verify data was modified
        assert_ne!(data, original);
        
        // Decrypt (f8 is symmetric)
        kasumi_f8(&key, count, bearer, dir, &mut data, length);
        
        // Should return to original
        assert_eq!(data, original);
    }

    #[test]
    fn test_kasumi_f9_produces_mac() {
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
        let length: usize = 64;

        let mac = kasumi_f9(&key, count, fresh, dir, &data, length);

        // Verify MAC is non-zero
        assert_ne!(mac, [0, 0, 0, 0]);
    }

    #[test]
    fn test_kasumi_f9_deterministic() {
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
        let length: usize = 64;

        let mac1 = kasumi_f9(&key, count, fresh, dir, &data, length);
        let mac2 = kasumi_f9(&key, count, fresh, dir, &data, length);

        assert_eq!(mac1, mac2);
    }
}
