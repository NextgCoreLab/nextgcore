//! Property-Based Tests for Cryptographic Algorithms
//!
//! Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
//!
//! These tests verify that cryptographic algorithms produce consistent, deterministic
//! outputs and satisfy key mathematical properties.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    // ========================================================================
    // Milenage Property Tests
    // ========================================================================

    mod milenage_props {
        use super::*;
        use crate::milenage::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: OPc generation is deterministic - same K and OP always produce same OPc
        //
        // Determinism alone cannot pin the ARGUMENT ORDER: this test previously
        // called `milenage_opc(&op, &k)` against a `(k, op)` signature and still
        // passed, because two identical transposed calls agree with each other.
        // `prop_opc_matches_3gpp_test_set_1` below pins the order to the spec
        // vector, so a future transposition fails a test instead of hiding.
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_opc_deterministic(
                k in prop::array::uniform16(any::<u8>()),
                op in prop::array::uniform16(any::<u8>()),
            ) {
                let opc1 = milenage_opc(&k, &op);
                let opc2 = milenage_opc(&k, &op);
                prop_assert_eq!(opc1, opc2, "OPc generation must be deterministic");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: f2345 outputs are deterministic
            #[test]
            fn prop_f2345_deterministic(
                k in prop::array::uniform16(any::<u8>()),
                opc in prop::array::uniform16(any::<u8>()),
                rand in prop::array::uniform16(any::<u8>()),
            ) {
                let result1 = milenage_f2345(&opc, &k, &rand);
                let result2 = milenage_f2345(&opc, &k, &rand);

                prop_assert!(result1.is_ok() == result2.is_ok());
                if let (Ok(r1), Ok(r2)) = (result1, result2) {
                    prop_assert_eq!(r1, r2, "f2345 must be deterministic");
                }
            }
        }

        /// Pins `milenage_opc`'s argument order to 3GPP TS 35.208 Test Set 1.
        ///
        /// OPc = E_K(OP) XOR OP, which is NOT symmetric in its two arguments, so
        /// a transposed call yields a different OPc and fails here. That is the
        /// point: the neighbouring determinism property is blind to argument
        /// order, so this vector is what actually holds the contract.
        #[test]
        fn prop_opc_matches_3gpp_test_set_1() {
            const K: [u8; 16] = [
                0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38,
                0xa6, 0xbc,
            ];
            const OP: [u8; 16] = [
                0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c,
                0xb3, 0x18,
            ];
            const OPC: [u8; 16] = [
                0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0,
                0x2b, 0xaf,
            ];

            assert_eq!(
                milenage_opc(&K, &OP).expect("OPc derivation must succeed"),
                OPC,
                "milenage_opc(k, op) must match TS 35.208 Test Set 1"
            );

            // Guard the guard: if the function were symmetric the assertion above
            // could not detect a transposition at all.
            assert_ne!(
                milenage_opc(&OP, &K).expect("transposed call still computes"),
                OPC,
                "OPc must depend on argument order, else this test proves nothing"
            );
        }
    }

    // ========================================================================
    // KASUMI Property Tests
    // ========================================================================

    mod kasumi_props {
        use super::*;
        use crate::kasumi::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: f8 encryption/decryption round-trip (symmetric cipher)
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_f8_round_trip(
                key in prop::array::uniform16(any::<u8>()),
                count in any::<u32>(),
                bearer in 0u32..32,
                direction in 0u32..2,
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let bit_length = data.len() * 8;

                // Encrypt
                let mut encrypted = data.clone();
                kasumi_f8(&key, count, bearer, direction, &mut encrypted, bit_length);

                // Decrypt (same operation for stream cipher)
                let mut decrypted = encrypted.clone();
                kasumi_f8(&key, count, bearer, direction, &mut decrypted, bit_length);

                prop_assert_eq!(data, decrypted, "f8 encrypt/decrypt round-trip must recover original");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: f9 MAC is deterministic
            #[test]
            fn prop_f9_deterministic(
                key in prop::array::uniform16(any::<u8>()),
                count in any::<u32>(),
                fresh in any::<u32>(),
                direction in 0u32..2,
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let bit_length = data.len() * 8;

                let mac1 = kasumi_f9(&key, count, fresh, direction, &data, bit_length);
                let mac2 = kasumi_f9(&key, count, fresh, direction, &data, bit_length);

                prop_assert_eq!(mac1, mac2, "f9 MAC must be deterministic");
            }
        }
    }

    // ========================================================================
    // SNOW 3G Property Tests
    // ========================================================================

    mod snow3g_props {
        use super::*;
        use crate::snow3g::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: f8 encryption/decryption round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_snow3g_f8_round_trip(
                key in prop::array::uniform16(any::<u8>()),
                count in any::<u32>(),
                bearer in 0u32..32,
                direction in 0u32..2,
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let bit_length = (data.len() * 8) as u32;

                // Encrypt
                let mut encrypted = data.clone();
                snow_3g_f8(&key, count, bearer, direction, &mut encrypted, bit_length);

                // Decrypt (same operation for stream cipher)
                let mut decrypted = encrypted.clone();
                snow_3g_f8(&key, count, bearer, direction, &mut decrypted, bit_length);

                prop_assert_eq!(data, decrypted, "SNOW 3G f8 round-trip must recover original");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: f9 MAC is deterministic
            #[test]
            fn prop_snow3g_f9_deterministic(
                key in prop::array::uniform16(any::<u8>()),
                count in any::<u32>(),
                fresh in any::<u32>(),
                direction in 0u32..2,
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let bit_length = (data.len() * 8) as u64;

                let mac1 = snow_3g_f9(&key, count, fresh, direction, &data, bit_length);
                let mac2 = snow_3g_f9(&key, count, fresh, direction, &data, bit_length);

                prop_assert_eq!(mac1, mac2, "SNOW 3G f9 MAC must be deterministic");
            }
        }
    }

    // ========================================================================
    // ZUC Property Tests
    // ========================================================================

    mod zuc_props {
        use super::*;
        use crate::zuc::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: EEA3 encryption/decryption round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_zuc_eea3_round_trip(
                key in prop::array::uniform16(any::<u8>()),
                count in any::<u32>(),
                bearer in 0u32..32,
                direction in 0u32..2,
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let bit_length = (data.len() * 8) as u32;

                // Encrypt
                let mut encrypted = vec![0u8; data.len()];
                zuc_eea3(&key, count, bearer, direction, bit_length, &data, &mut encrypted);

                // Decrypt (same operation for stream cipher)
                let mut decrypted = vec![0u8; encrypted.len()];
                zuc_eea3(&key, count, bearer, direction, bit_length, &encrypted, &mut decrypted);

                prop_assert_eq!(data, decrypted, "ZUC EEA3 round-trip must recover original");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: EIA3 MAC is deterministic
            #[test]
            fn prop_zuc_eia3_deterministic(
                key in prop::array::uniform16(any::<u8>()),
                count in any::<u32>(),
                bearer in 0u32..32,
                direction in 0u32..2,
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let bit_length = (data.len() * 8) as u32;

                let mac1 = zuc_eia3(&key, count, bearer, direction, bit_length, &data);
                let mac2 = zuc_eia3(&key, count, bearer, direction, bit_length, &data);

                prop_assert_eq!(mac1, mac2, "ZUC EIA3 MAC must be deterministic");
            }
        }
    }

    // ========================================================================
    // AES Property Tests
    // ========================================================================

    mod aes_props {
        use super::*;
        use crate::aes::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: AES block encrypt/decrypt round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_aes_block_round_trip(
                key in prop::array::uniform16(any::<u8>()),
                plaintext in prop::array::uniform16(any::<u8>()),
            ) {
                let enc_ctx = AesEncContext::new(&key, 128).unwrap();
                let dec_ctx = AesDecContext::new(&key, 128).unwrap();

                let mut ciphertext = [0u8; 16];
                enc_ctx.encrypt_block(&plaintext, &mut ciphertext);

                let mut decrypted = [0u8; 16];
                dec_ctx.decrypt_block(&ciphertext, &mut decrypted);

                prop_assert_eq!(plaintext, decrypted, "AES ECB round-trip must recover original");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: AES-CBC round-trip
            #[test]
            fn prop_aes_cbc_round_trip(
                key in prop::array::uniform16(any::<u8>()),
                iv in prop::array::uniform16(any::<u8>()),
                // CBC requires block-aligned data
                blocks in 1usize..16,
            ) {
                let plaintext: Vec<u8> = (0..(blocks * 16)).map(|i| i as u8).collect();

                let mut enc_iv = iv;
                let mut ciphertext = vec![0u8; plaintext.len()];
                aes_cbc_encrypt(&key, 128, &mut enc_iv, &plaintext, &mut ciphertext).unwrap();

                let mut dec_iv = iv;
                let mut decrypted = vec![0u8; ciphertext.len()];
                aes_cbc_decrypt(&key, 128, &mut dec_iv, &ciphertext, &mut decrypted).unwrap();

                prop_assert_eq!(plaintext, decrypted, "AES CBC round-trip must recover original");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: AES-CTR round-trip
            #[test]
            fn prop_aes_ctr_round_trip(
                key in prop::array::uniform16(any::<u8>()),
                iv in prop::array::uniform16(any::<u8>()),
                data in prop::collection::vec(any::<u8>(), 1..256),
            ) {
                let mut enc_iv = iv;
                let mut encrypted = vec![0u8; data.len()];
                aes_ctr128_encrypt(&key, &mut enc_iv, &data, &mut encrypted).unwrap();

                let mut dec_iv = iv;
                let mut decrypted = vec![0u8; encrypted.len()];
                aes_ctr128_encrypt(&key, &mut dec_iv, &encrypted, &mut decrypted).unwrap();

                prop_assert_eq!(data, decrypted, "AES CTR round-trip must recover original");
            }
        }
    }

    // ========================================================================
    // AES-CMAC Property Tests
    // ========================================================================

    mod aes_cmac_props {
        use super::*;
        use crate::aes_cmac::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: AES-CMAC is deterministic
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_aes_cmac_deterministic(
                key in prop::array::uniform16(any::<u8>()),
                data in prop::collection::vec(any::<u8>(), 0..256),
            ) {
                let mac1 = aes_cmac_calculate(&key, &data);
                let mac2 = aes_cmac_calculate(&key, &data);

                prop_assert_eq!(mac1, mac2, "AES-CMAC must be deterministic");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: Different inputs produce different MACs (with high probability)
            #[test]
            fn prop_aes_cmac_different_inputs(
                key in prop::array::uniform16(any::<u8>()),
                data1 in prop::collection::vec(any::<u8>(), 1..128),
                data2 in prop::collection::vec(any::<u8>(), 1..128),
            ) {
                prop_assume!(data1 != data2);

                let mac1 = aes_cmac_calculate(&key, &data1);
                let mac2 = aes_cmac_calculate(&key, &data2);

                // Different inputs should produce different MACs
                prop_assert_ne!(mac1, mac2, "Different inputs should produce different MACs");
            }
        }
    }

    // ========================================================================
    // SHA Property Tests
    // ========================================================================

    mod sha_props {
        use super::*;
        use crate::sha::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: SHA functions are deterministic
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_sha256_deterministic(
                data in prop::collection::vec(any::<u8>(), 0..512),
            ) {
                let hash1 = sha256(&data);
                let hash2 = sha256(&data);

                prop_assert_eq!(hash1, hash2, "SHA-256 must be deterministic");
            }

            #[test]
            fn prop_sha1_deterministic(
                data in prop::collection::vec(any::<u8>(), 0..512),
            ) {
                let hash1 = sha1(&data);
                let hash2 = sha1(&data);

                prop_assert_eq!(hash1, hash2, "SHA-1 must be deterministic");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: Incremental hashing produces same result as one-shot
            #[test]
            fn prop_sha256_incremental_equivalence(
                part1 in prop::collection::vec(any::<u8>(), 0..128),
                part2 in prop::collection::vec(any::<u8>(), 0..128),
            ) {
                // One-shot hash
                let mut combined = part1.clone();
                combined.extend(&part2);
                let oneshot = sha256(&combined);

                // Incremental hash
                let mut ctx = Sha256Context::new();
                ctx.update(&part1);
                ctx.update(&part2);
                let mut incremental = [0u8; SHA256_DIGEST_SIZE];
                ctx.finalize(&mut incremental);

                prop_assert_eq!(oneshot, incremental, "Incremental SHA-256 must match one-shot");
            }
        }
    }

    // ========================================================================
    // KDF Property Tests
    // ========================================================================

    mod kdf_props {
        use super::*;
        use crate::kdf::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: KDF functions are deterministic
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_kdf_kseaf_deterministic(
                serving_network in "[a-zA-Z0-9]{1,32}",
                kausf in prop::array::uniform32(any::<u8>()),
            ) {
                let kseaf1 = nextgcore_kdf_kseaf(&serving_network, &kausf);
                let kseaf2 = nextgcore_kdf_kseaf(&serving_network, &kausf);

                prop_assert_eq!(kseaf1, kseaf2, "Kseaf derivation must be deterministic");
            }

            #[test]
            fn prop_kdf_kenb_deterministic(
                kasme in prop::array::uniform32(any::<u8>()),
                ul_count in any::<u32>(),
            ) {
                let kenb1 = nextgcore_kdf_kenb(&kasme, ul_count);
                let kenb2 = nextgcore_kdf_kenb(&kasme, ul_count);

                prop_assert_eq!(kenb1, kenb2, "KeNB derivation must be deterministic");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: ANSI X9.63 KDF is deterministic
            #[test]
            fn prop_kdf_ansi_x963_deterministic(
                z in prop::collection::vec(any::<u8>(), 16..64),
                info in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                let (ek1, icb1, mk1) = nextgcore_kdf_ansi_x963(&z, &info);
                let (ek2, icb2, mk2) = nextgcore_kdf_ansi_x963(&z, &info);

                prop_assert_eq!(ek1, ek2, "ANSI X9.63 encryption key must be deterministic");
                prop_assert_eq!(icb1, icb2, "ANSI X9.63 ICB must be deterministic");
                prop_assert_eq!(mk1, mk2, "ANSI X9.63 MAC key must be deterministic");
            }
        }
    }

    // ========================================================================
    // ECC Property Tests
    // ========================================================================

    mod ecc_props {
        use super::*;
        use crate::ecc::*;

        // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
        // Test: ECDH shared secret is symmetric
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_ecdh_symmetric(_seed in any::<u64>()) {
                // Generate two key pairs
                let mut pub1 = [0u8; ECC_PUBLIC_KEY_SIZE];
                let mut priv1 = [0u8; ECC_BYTES];
                ecc_make_key(&mut pub1, &mut priv1).unwrap();

                let mut pub2 = [0u8; ECC_PUBLIC_KEY_SIZE];
                let mut priv2 = [0u8; ECC_BYTES];
                ecc_make_key(&mut pub2, &mut priv2).unwrap();

                // Compute shared secrets both ways
                let mut secret1 = [0u8; ECC_BYTES];
                let mut secret2 = [0u8; ECC_BYTES];

                ecdh_shared_secret(&pub2, &priv1, &mut secret1).unwrap();
                ecdh_shared_secret(&pub1, &priv2, &mut secret2).unwrap();

                prop_assert_eq!(secret1, secret2, "ECDH shared secret must be symmetric");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: ECDSA sign/verify round-trip
            #[test]
            fn prop_ecdsa_sign_verify(
                hash in prop::array::uniform32(any::<u8>()),
            ) {
                let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
                let mut private_key = [0u8; ECC_BYTES];
                ecc_make_key(&mut public_key, &mut private_key).unwrap();

                let mut signature = [0u8; ECC_SIGNATURE_SIZE];
                ecdsa_sign(&private_key, &hash, &mut signature).unwrap();

                let valid = ecdsa_verify(&public_key, &hash, &signature).unwrap();
                prop_assert!(valid, "ECDSA signature must verify with correct key");
            }

            // Feature: nextgcore-rust-conversion, Property 8: Cryptographic Algorithm Bit-Identical Output
            // Test: ECDSA signature fails with wrong hash
            #[test]
            fn prop_ecdsa_wrong_hash_fails(
                hash1 in prop::array::uniform32(any::<u8>()),
                hash2 in prop::array::uniform32(any::<u8>()),
            ) {
                prop_assume!(hash1 != hash2);

                let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
                let mut private_key = [0u8; ECC_BYTES];
                ecc_make_key(&mut public_key, &mut private_key).unwrap();

                let mut signature = [0u8; ECC_SIGNATURE_SIZE];
                ecdsa_sign(&private_key, &hash1, &mut signature).unwrap();

                let valid = ecdsa_verify(&public_key, &hash2, &signature).unwrap();
                prop_assert!(!valid, "ECDSA signature must fail with wrong hash");
            }
        }
    }
}
