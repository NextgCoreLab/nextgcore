//! FFI bindings for ogs-crypt library
//!
//! These bindings allow comparison testing between Rust and C implementations.
//! When `OGS_FFI_GENERATE_BINDINGS=1` is set, actual bindings are generated
//! from the C headers using bindgen.

use libc::c_int;

// ============================================================================
// Milenage algorithm bindings (3GPP TS 35.206)
// ============================================================================

extern "C" {
    /// Milenage f1 function - Network authentication
    /// Computes MAC-A from K, RAND, SQN, AMF
    pub fn milenage_f1(
        opc: *const u8,  // 16 bytes
        k: *const u8,    // 16 bytes
        rand: *const u8, // 16 bytes
        sqn: *const u8,  // 6 bytes
        amf: *const u8,  // 2 bytes
        mac_a: *mut u8,  // 8 bytes output
        mac_s: *mut u8,  // 8 bytes output (can be NULL)
    ) -> c_int;

    /// Milenage f2345 function - Derives RES, CK, IK, AK
    pub fn milenage_f2345(
        opc: *const u8,  // 16 bytes
        k: *const u8,    // 16 bytes
        rand: *const u8, // 16 bytes
        res: *mut u8,    // 8 bytes output
        ck: *mut u8,     // 16 bytes output
        ik: *mut u8,     // 16 bytes output
        ak: *mut u8,     // 6 bytes output
    ) -> c_int;

    /// Milenage f5star function - Derives AK for re-sync
    pub fn milenage_f5star(
        opc: *const u8,  // 16 bytes
        k: *const u8,    // 16 bytes
        rand: *const u8, // 16 bytes
        ak: *mut u8,     // 6 bytes output
    ) -> c_int;

    /// Generate OPc from OP and K
    pub fn milenage_opc(
        op: *const u8,  // 16 bytes
        k: *const u8,   // 16 bytes
        opc: *mut u8,   // 16 bytes output
    ) -> c_int;
}

// ============================================================================
// KASUMI cipher bindings (3GPP TS 35.202)
// ============================================================================

extern "C" {
    /// KASUMI f8 confidentiality function
    pub fn kasumi_f8(
        key: *const u8,    // 16 bytes
        count: u32,
        bearer: u8,
        direction: u8,
        data: *mut u8,
        length: c_int,     // in bits
    );

    /// KASUMI f9 integrity function
    pub fn kasumi_f9(
        key: *const u8,    // 16 bytes
        count: u32,
        fresh: u32,
        direction: u8,
        data: *const u8,
        length: c_int,     // in bits
        mac: *mut u8,      // 4 bytes output
    );
}

// ============================================================================
// SNOW-3G cipher bindings (3GPP TS 35.201)
// ============================================================================

extern "C" {
    /// SNOW-3G f8 confidentiality function (UEA2)
    pub fn snow_3g_f8(
        key: *const u8,    // 16 bytes
        count: u32,
        bearer: u8,
        direction: u8,
        data: *mut u8,
        length: u32,       // in bits
    );

    /// SNOW-3G f9 integrity function (UIA2)
    pub fn snow_3g_f9(
        key: *const u8,    // 16 bytes
        count: u32,
        fresh: u32,
        direction: u8,
        data: *const u8,
        length: u64,       // in bits
        mac: *mut u8,      // 4 bytes output
    );
}

// ============================================================================
// ZUC cipher bindings (3GPP TS 35.221)
// ============================================================================

extern "C" {
    /// ZUC-128 EEA3 confidentiality function
    pub fn zuc_eea3(
        key: *const u8,    // 16 bytes
        count: u32,
        bearer: u8,
        direction: u8,
        length: u32,       // in bits
        input: *const u32,
        output: *mut u32,
    );

    /// ZUC-128 EIA3 integrity function
    pub fn zuc_eia3(
        key: *const u8,    // 16 bytes
        count: u32,
        bearer: u8,
        direction: u8,
        length: u32,       // in bits
        data: *const u32,
        mac: *mut u32,     // 4 bytes output
    );
}

// ============================================================================
// AES bindings
// ============================================================================

extern "C" {
    /// AES-128 encrypt
    pub fn ogs_aes_encrypt(
        key: *const u8,    // 16 bytes
        input: *const u8,  // 16 bytes
        output: *mut u8,   // 16 bytes
    ) -> c_int;

    /// AES-128 decrypt
    pub fn ogs_aes_decrypt(
        key: *const u8,    // 16 bytes
        input: *const u8,  // 16 bytes
        output: *mut u8,   // 16 bytes
    ) -> c_int;

    /// AES-CMAC
    pub fn ogs_aes_cmac_calculate(
        cmac: *mut u8,     // 16 bytes output
        key: *const u8,    // 16 bytes
        msg: *const u8,
        len: c_int,
    ) -> c_int;
}

// ============================================================================
// SHA bindings
// ============================================================================

extern "C" {
    /// SHA-1 hash
    pub fn ogs_sha1(
        input: *const u8,
        len: usize,
        output: *mut u8,   // 20 bytes
    );

    /// SHA-256 hash
    pub fn ogs_sha256(
        input: *const u8,
        len: usize,
        output: *mut u8,   // 32 bytes
    );

    /// SHA-384 hash
    pub fn ogs_sha384(
        input: *const u8,
        len: usize,
        output: *mut u8,   // 48 bytes
    );

    /// SHA-512 hash
    pub fn ogs_sha512(
        input: *const u8,
        len: usize,
        output: *mut u8,   // 64 bytes
    );

    /// HMAC-SHA-256
    pub fn ogs_hmac_sha256(
        key: *const u8,
        key_len: usize,
        input: *const u8,
        input_len: usize,
        output: *mut u8,   // 32 bytes
        output_len: *mut usize,
    );
}

// ============================================================================
// KDF (Key Derivation Function) bindings
// ============================================================================

extern "C" {
    /// 5G KDF for deriving keys (3GPP TS 33.501)
    pub fn ogs_kdf_common(
        key: *const u8,
        key_len: usize,
        fc: u8,
        param: *const u8,
        param_len: usize,
        output: *mut u8,
    );

    /// Derive KAUSF from CK, IK
    pub fn ogs_kdf_kausf(
        ck: *const u8,     // 16 bytes
        ik: *const u8,     // 16 bytes
        serving_network_name: *const u8,
        serving_network_name_len: usize,
        sqn_xor_ak: *const u8, // 6 bytes
        kausf: *mut u8,    // 32 bytes output
    );

    /// Derive KSEAF from KAUSF
    pub fn ogs_kdf_kseaf(
        kausf: *const u8,  // 32 bytes
        serving_network_name: *const u8,
        serving_network_name_len: usize,
        kseaf: *mut u8,    // 32 bytes output
    );

    /// Derive KAMF from KSEAF
    pub fn ogs_kdf_kamf(
        kseaf: *const u8,  // 32 bytes
        supi: *const u8,
        supi_len: usize,
        abba: *const u8,
        abba_len: usize,
        kamf: *mut u8,     // 32 bytes output
    );

    /// Derive KNASint from KAMF
    pub fn ogs_kdf_nas_int(
        kamf: *const u8,   // 32 bytes
        algorithm_type: u8,
        algorithm_id: u8,
        knas_int: *mut u8, // 32 bytes output
    );

    /// Derive KNASenc from KAMF
    pub fn ogs_kdf_nas_enc(
        kamf: *const u8,   // 32 bytes
        algorithm_type: u8,
        algorithm_id: u8,
        knas_enc: *mut u8, // 32 bytes output
    );

    /// Derive KgNB from KAMF
    pub fn ogs_kdf_kgnb(
        kamf: *const u8,   // 32 bytes
        ul_count: u32,
        access_type: u8,
        kgnb: *mut u8,     // 32 bytes output
    );
}

// ============================================================================
// Base64 bindings
// ============================================================================

extern "C" {
    /// Base64 encode
    pub fn ogs_base64_encode(
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_len: *mut usize,
    ) -> c_int;

    /// Base64 decode
    pub fn ogs_base64_decode(
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        output_len: *mut usize,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ffi_crypt_module_loads() {
        // Basic test to ensure module compiles
        assert!(true);
    }
}
