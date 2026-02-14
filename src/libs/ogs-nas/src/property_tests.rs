//! Property-Based Tests for NAS Protocol Messages
//!
//! Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
//!
//! These tests verify that 5GS NAS protocol messages can be encoded
//! and decoded correctly, producing equivalent message structures.
//!
//! Validates: Requirements 4.5

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use bytes::BytesMut;

    // ========================================================================
    // 5GMM Message Property Tests
    // ========================================================================

    mod fivegmm_props {
        use super::*;
        use crate::fiveg::types::*;
        use crate::fiveg::header::*;
        use crate::common::types::*;

        // Strategy for generating valid PLMN IDs
        fn arb_plmn_id() -> impl Strategy<Value = PlmnId> {
            (
                prop::array::uniform3(0u8..10),
                prop::array::uniform3(0u8..10),
                2u8..4,
            ).prop_map(|(mcc, mnc, mnc_len)| PlmnId::new(mcc, mnc, mnc_len))
        }

        // Strategy for generating valid 5G-GUTI
        fn arb_five_g_guti() -> impl Strategy<Value = FiveGGuti> {
            (
                arb_plmn_id(),
                any::<u8>(),
                0u16..1024,
                0u8..64,
                any::<u32>(),
            ).prop_map(|(plmn_id, amf_region_id, amf_set_id, amf_pointer, tmsi)| {
                FiveGGuti {
                    plmn_id,
                    amf_region_id,
                    amf_set_id,
                    amf_pointer,
                    tmsi,
                }
            })
        }

        // Strategy for generating valid 5G-S-TMSI
        fn arb_five_g_s_tmsi() -> impl Strategy<Value = FiveGSTmsi> {
            (
                0u16..1024,
                0u8..64,
                any::<u32>(),
            ).prop_map(|(amf_set_id, amf_pointer, tmsi)| {
                FiveGSTmsi { amf_set_id, amf_pointer, tmsi }
            })
        }

        // Strategy for generating valid registration type
        fn arb_registration_type() -> impl Strategy<Value = RegistrationType> {
            (
                prop::bool::ANY,
                prop::sample::select(vec![
                    RegistrationTypeValue::InitialRegistration,
                    RegistrationTypeValue::MobilityRegistrationUpdating,
                    RegistrationTypeValue::PeriodicRegistrationUpdating,
                    RegistrationTypeValue::EmergencyRegistration,
                ]),
            ).prop_map(|(follow_on_request, value)| {
                RegistrationType { follow_on_request, value }
            })
        }

        // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
        // Test: 5G-GUTI mobile identity round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_five_g_guti_round_trip(guti in arb_five_g_guti()) {
                let identity = MobileIdentity::FiveGGuti(guti.clone());
                
                let mut buf = BytesMut::new();
                identity.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = MobileIdentity::decode(&mut bytes).unwrap();
                
                if let MobileIdentity::FiveGGuti(decoded_guti) = decoded {
                    // PLMN ID comparison: MCC must match exactly
                    prop_assert_eq!(decoded_guti.plmn_id.mcc, guti.plmn_id.mcc);
                    // MNC comparison depends on mnc_len - only compare significant digits
                    prop_assert_eq!(decoded_guti.plmn_id.mnc[0], guti.plmn_id.mnc[0]);
                    prop_assert_eq!(decoded_guti.plmn_id.mnc[1], guti.plmn_id.mnc[1]);
                    if guti.plmn_id.mnc_len == 3 {
                        prop_assert_eq!(decoded_guti.plmn_id.mnc[2], guti.plmn_id.mnc[2]);
                    }
                    prop_assert_eq!(decoded_guti.amf_region_id, guti.amf_region_id);
                    prop_assert_eq!(decoded_guti.amf_set_id, guti.amf_set_id);
                    prop_assert_eq!(decoded_guti.amf_pointer, guti.amf_pointer);
                    prop_assert_eq!(decoded_guti.tmsi, guti.tmsi);
                } else {
                    prop_assert!(false, "Wrong mobile identity type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: 5G-S-TMSI mobile identity round-trip
            #[test]
            fn prop_five_g_s_tmsi_round_trip(tmsi in arb_five_g_s_tmsi()) {
                let identity = MobileIdentity::FiveGSTmsi(tmsi.clone());
                
                let mut buf = BytesMut::new();
                identity.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = MobileIdentity::decode(&mut bytes).unwrap();
                
                if let MobileIdentity::FiveGSTmsi(decoded_tmsi) = decoded {
                    prop_assert_eq!(decoded_tmsi.amf_set_id, tmsi.amf_set_id);
                    prop_assert_eq!(decoded_tmsi.amf_pointer, tmsi.amf_pointer);
                    prop_assert_eq!(decoded_tmsi.tmsi, tmsi.tmsi);
                } else {
                    prop_assert!(false, "Wrong mobile identity type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: IMEI mobile identity round-trip
            #[test]
            fn prop_imei_round_trip(digits in prop::array::uniform15(0u8..10)) {
                let imei = Imei { digits };
                let identity = MobileIdentity::Imei(imei.clone());
                
                let mut buf = BytesMut::new();
                identity.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = MobileIdentity::decode(&mut bytes).unwrap();
                
                if let MobileIdentity::Imei(decoded_imei) = decoded {
                    prop_assert_eq!(decoded_imei.digits, imei.digits);
                } else {
                    prop_assert!(false, "Wrong mobile identity type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: IMEISV mobile identity round-trip
            #[test]
            fn prop_imeisv_round_trip(digits in prop::array::uniform16(0u8..10)) {
                let imeisv = Imeisv { digits };
                let identity = MobileIdentity::Imeisv(imeisv.clone());
                
                let mut buf = BytesMut::new();
                identity.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = MobileIdentity::decode(&mut bytes).unwrap();
                
                if let MobileIdentity::Imeisv(decoded_imeisv) = decoded {
                    prop_assert_eq!(decoded_imeisv.digits, imeisv.digits);
                } else {
                    prop_assert!(false, "Wrong mobile identity type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: Registration type encode/decode round-trip
            #[test]
            fn prop_registration_type_round_trip(reg_type in arb_registration_type()) {
                let encoded = reg_type.encode();
                let decoded = RegistrationType::decode(encoded).unwrap();
                
                prop_assert_eq!(decoded.follow_on_request, reg_type.follow_on_request);
                prop_assert_eq!(decoded.value, reg_type.value);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: Registration result encode/decode round-trip
            #[test]
            fn prop_registration_result_round_trip(
                sms_allowed in prop::bool::ANY,
                value in prop::sample::select(vec![
                    RegistrationResultValue::ThreeGppAccess,
                    RegistrationResultValue::Non3gppAccess,
                    RegistrationResultValue::ThreeGppAndNon3gppAccess,
                ]),
            ) {
                let result = RegistrationResult { sms_allowed, value };
                
                let mut buf = BytesMut::new();
                result.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = RegistrationResult::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.sms_allowed, result.sms_allowed);
                prop_assert_eq!(decoded.value, result.value);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: De-registration type encode/decode round-trip
            #[test]
            fn prop_deregistration_type_round_trip(
                switch_off in prop::bool::ANY,
                re_registration_required in prop::bool::ANY,
                access_type in prop::sample::select(vec![
                    AccessType::ThreeGppAccess,
                    AccessType::Non3gppAccess,
                    AccessType::ThreeGppAndNon3gppAccess,
                ]),
            ) {
                let dereg_type = DeRegistrationType {
                    switch_off,
                    re_registration_required,
                    access_type,
                };
                
                let encoded = dereg_type.encode();
                let decoded = DeRegistrationType::decode(encoded);
                
                prop_assert_eq!(decoded.switch_off, dereg_type.switch_off);
                prop_assert_eq!(decoded.re_registration_required, dereg_type.re_registration_required);
                prop_assert_eq!(decoded.access_type, dereg_type.access_type);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: 5GS NAS header encode/decode round-trip
            #[test]
            fn prop_fivegs_nas_header_round_trip(
                message_type in prop::sample::select(vec![
                    FiveGmmMessageType::RegistrationRequest as u8,
                    FiveGmmMessageType::RegistrationAccept as u8,
                    FiveGmmMessageType::RegistrationReject as u8,
                    FiveGmmMessageType::AuthenticationRequest as u8,
                    FiveGmmMessageType::AuthenticationResponse as u8,
                ]),
            ) {
                let header = FiveGsNasHeader {
                    extended_protocol_discriminator: ProtocolDiscriminator::FiveGsMobilityManagement as u8,
                    security_header_type: SecurityHeaderType::PlainNas,
                    message_type,
                };
                
                let mut buf = BytesMut::new();
                header.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = FiveGsNasHeader::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.extended_protocol_discriminator, header.extended_protocol_discriminator);
                prop_assert_eq!(decoded.security_header_type, header.security_header_type);
                prop_assert_eq!(decoded.message_type, header.message_type);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: Mobile identity encoding is deterministic
            #[test]
            fn prop_mobile_identity_deterministic(guti in arb_five_g_guti()) {
                let identity = MobileIdentity::FiveGGuti(guti);
                
                // Encode twice
                let mut buf1 = BytesMut::new();
                let mut buf2 = BytesMut::new();
                identity.encode(&mut buf1);
                identity.encode(&mut buf2);
                
                prop_assert_eq!(buf1, buf2, "Mobile identity encoding must be deterministic");
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: SUCI mobile identity round-trip
            #[test]
            fn prop_suci_round_trip(
                plmn_id in arb_plmn_id(),
                routing_indicator in prop::array::uniform2(any::<u8>()),
                protection_scheme_id in 0u8..5,
                home_network_pki in any::<u8>(),
                scheme_output in prop::collection::vec(any::<u8>(), 1..32),
            ) {
                let suci = Suci {
                    supi_format: 0, // IMSI format
                    plmn_id,
                    routing_indicator,
                    protection_scheme_id,
                    home_network_pki,
                    scheme_output: scheme_output.clone(),
                };
                let identity = MobileIdentity::Suci(suci);
                
                let mut buf = BytesMut::new();
                identity.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = MobileIdentity::decode(&mut bytes).unwrap();
                
                if let MobileIdentity::Suci(decoded_suci) = decoded {
                    prop_assert_eq!(decoded_suci.supi_format, 0);
                    // PLMN ID comparison: MCC must match exactly
                    prop_assert_eq!(decoded_suci.plmn_id.mcc, plmn_id.mcc);
                    // MNC comparison depends on mnc_len - only compare significant digits
                    prop_assert_eq!(decoded_suci.plmn_id.mnc[0], plmn_id.mnc[0]);
                    prop_assert_eq!(decoded_suci.plmn_id.mnc[1], plmn_id.mnc[1]);
                    if plmn_id.mnc_len == 3 {
                        prop_assert_eq!(decoded_suci.plmn_id.mnc[2], plmn_id.mnc[2]);
                    }
                    prop_assert_eq!(decoded_suci.routing_indicator, routing_indicator);
                    prop_assert_eq!(decoded_suci.protection_scheme_id, protection_scheme_id);
                    prop_assert_eq!(decoded_suci.home_network_pki, home_network_pki);
                    prop_assert_eq!(decoded_suci.scheme_output, scheme_output);
                } else {
                    prop_assert!(false, "Wrong mobile identity type decoded");
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: No identity mobile identity round-trip
            #[test]
            fn prop_no_identity_round_trip(_dummy in Just(())) {
                let identity = MobileIdentity::NoIdentity;
                
                let mut buf = BytesMut::new();
                identity.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = MobileIdentity::decode(&mut bytes).unwrap();
                
                prop_assert!(matches!(decoded, MobileIdentity::NoIdentity));
            }
        }
    }

    // ========================================================================
    // Common NAS Types Property Tests
    // ========================================================================

    mod common_props {
        use super::*;
        use crate::common::types::*;

        // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
        // Test: PLMN ID encode/decode round-trip
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            #[test]
            fn prop_plmn_id_round_trip(
                mcc in prop::array::uniform3(0u8..10),
                mnc in prop::array::uniform3(0u8..10),
                mnc_len in 2u8..4,
            ) {
                let plmn_id = PlmnId::new(mcc, mnc, mnc_len);
                
                let mut buf = BytesMut::new();
                plmn_id.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = PlmnId::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.mcc, plmn_id.mcc);
                // MNC comparison depends on mnc_len
                if mnc_len == 2 {
                    prop_assert_eq!(decoded.mnc[0], plmn_id.mnc[0]);
                    prop_assert_eq!(decoded.mnc[1], plmn_id.mnc[1]);
                } else {
                    prop_assert_eq!(decoded.mnc, plmn_id.mnc);
                }
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: TAI encode/decode round-trip
            #[test]
            fn prop_tai_round_trip(
                mcc in prop::array::uniform3(0u8..10),
                mnc in prop::array::uniform3(0u8..10),
                mnc_len in 2u8..4,
                tac in prop::array::uniform3(any::<u8>()),
            ) {
                let plmn_id = PlmnId::new(mcc, mnc, mnc_len);
                let tai = Tai { plmn_id, tac };
                
                let mut buf = BytesMut::new();
                tai.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = Tai::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.tac, tai.tac);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: S-NSSAI encode/decode round-trip
            #[test]
            fn prop_s_nssai_round_trip(
                sst in any::<u8>(),
                sd in prop::option::of(prop::array::uniform3(any::<u8>())),
            ) {
                let s_nssai = if let Some(sd_val) = sd {
                    SNssai::with_sd(sst, sd_val)
                } else {
                    SNssai::new(sst)
                };
                
                let mut buf = BytesMut::new();
                s_nssai.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = SNssai::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.sst, s_nssai.sst);
                prop_assert_eq!(decoded.sd, s_nssai.sd);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: Key set identifier encode/decode round-trip
            #[test]
            fn prop_key_set_identifier_round_trip(
                tsc in 0u8..2,
                value in 0u8..8,
            ) {
                let ksi = KeySetIdentifier::new(tsc, value);
                
                let encoded = ksi.encode();
                let decoded = KeySetIdentifier::decode(encoded);
                
                prop_assert_eq!(decoded.tsc, ksi.tsc);
                prop_assert_eq!(decoded.value, ksi.value);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GPRS Timer 2 encode/decode round-trip
            #[test]
            fn prop_gprs_timer2_round_trip(
                value in any::<u8>(),
            ) {
                let timer = GprsTimer2::new(value);
                
                let mut buf = BytesMut::new();
                timer.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = GprsTimer2::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.length, timer.length);
                prop_assert_eq!(decoded.value, timer.value);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: GPRS Timer 3 encode/decode round-trip
            #[test]
            fn prop_gprs_timer3_round_trip(
                unit in 0u8..8,
                value in 0u8..32,
            ) {
                let timer = GprsTimer3::new(unit, value);
                
                let mut buf = BytesMut::new();
                timer.encode(&mut buf);
                
                let mut bytes = buf.freeze();
                let decoded = GprsTimer3::decode(&mut bytes).unwrap();
                
                prop_assert_eq!(decoded.unit, timer.unit);
                prop_assert_eq!(decoded.value, timer.value);
            }

            // Feature: nextgcore-rust-conversion, Property 11: Protocol Message Round-Trip
            // Test: Security algorithms encode/decode round-trip
            #[test]
            fn prop_security_algorithms_round_trip(
                ciphering in 0u8..8,
                integrity in 0u8..8,
            ) {
                let algs = SecurityAlgorithms { ciphering, integrity };
                
                let encoded = algs.encode();
                let decoded = SecurityAlgorithms::decode(encoded);
                
                prop_assert_eq!(decoded.ciphering, algs.ciphering);
                prop_assert_eq!(decoded.integrity, algs.integrity);
            }
        }
    }
}
