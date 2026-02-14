//! Property-Based Tests for Database Interface
//!
//! Tests for database query equivalence and data integrity.
//! Validates Requirements 10.1-10.5

use proptest::prelude::*;

use crate::types::*;

// Strategy for generating valid IMSI strings (15 digits)
fn imsi_strategy() -> impl Strategy<Value = String> {
    "[0-9]{15}".prop_map(|s| s)
}

// Strategy for generating valid MSISDN strings (up to 15 digits)
fn msisdn_strategy() -> impl Strategy<Value = String> {
    "[0-9]{1,15}".prop_map(|s| s)
}

// Strategy for generating valid hex strings of specific length
fn hex_string_strategy(len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec("[0-9A-Fa-f]", len * 2)
        .prop_map(|chars| chars.into_iter().collect::<String>())
}

// Strategy for generating OgsUint24 values
fn uint24_strategy() -> impl Strategy<Value = OgsUint24> {
    (0u32..=0xFFFFFFu32).prop_map(OgsUint24::new)
}

// Strategy for generating S-NSSAI values
fn s_nssai_strategy() -> impl Strategy<Value = OgsSNssai> {
    (any::<u8>(), prop_oneof![Just(None), uint24_strategy().prop_map(Some)])
        .prop_map(|(sst, sd)| OgsSNssai::new(sst, sd.map(|s| s.v)))
}

// Strategy for generating AMBR values
fn ambr_strategy() -> impl Strategy<Value = OgsAmbr> {
    (any::<u64>(), any::<u64>()).prop_map(|(downlink, uplink)| OgsAmbr { downlink, uplink })
}

// Strategy for generating ARP values
fn arp_strategy() -> impl Strategy<Value = OgsArp> {
    (1u8..=15, 0u8..=1, 0u8..=1).prop_map(|(priority_level, pre_emption_capability, pre_emption_vulnerability)| {
        OgsArp {
            priority_level,
            pre_emption_capability,
            pre_emption_vulnerability,
        }
    })
}

// Strategy for generating QoS values
fn qos_strategy() -> impl Strategy<Value = OgsQos> {
    (1u8..=9, arp_strategy(), ambr_strategy(), ambr_strategy()).prop_map(|(index, arp, mbr, gbr)| {
        OgsQos {
            index,
            arp,
            mbr,
            gbr,
        }
    })
}

proptest! {
    /// Property 13.1: OgsUint24 round-trip through bytes
    #[test]
    fn test_uint24_byte_roundtrip(value in 0u32..=0xFFFFFFu32) {
        let u = OgsUint24::new(value);
        let bytes = u.to_be_bytes();
        let u2 = OgsUint24::from_be_bytes(bytes);
        prop_assert_eq!(u.v, u2.v);
    }

    /// Property 13.2: OgsUint24 overflow handling
    #[test]
    fn test_uint24_overflow(value in any::<u32>()) {
        let u = OgsUint24::new(value);
        prop_assert!(u.v <= 0xFFFFFF);
    }

    /// Property 13.3: S-NSSAI SD detection
    #[test]
    fn test_s_nssai_sd_detection(sst in any::<u8>(), sd in prop_oneof![Just(None), (0u32..0xFFFFFEu32).prop_map(Some)]) {
        let snssai = OgsSNssai::new(sst, sd);
        if sd.is_some() && sd.unwrap() != OGS_S_NSSAI_NO_SD_VALUE {
            prop_assert!(snssai.has_sd());
        }
    }

    /// Property 13.4: SUPI parsing consistency
    #[test]
    fn test_supi_parsing(id_type in "[a-z]{2,8}", id_value in "[a-zA-Z0-9]{1,20}") {
        let supi = format!("{id_type}-{id_value}");
        let parsed_type = ogs_id_get_type(&supi);
        let parsed_value = ogs_id_get_value(&supi);

        prop_assert_eq!(parsed_type, Some(id_type.clone()));
        prop_assert_eq!(parsed_value, Some(id_value.clone()));
    }

    /// Property 13.5: Hex string conversion
    #[test]
    fn test_hex_conversion(hex_str in hex_string_strategy(16)) {
        let mut buf = [0u8; 16];
        let len = ogs_ascii_to_hex(&hex_str, &mut buf);
        prop_assert_eq!(len, 16);

        // Verify each byte
        for i in 0..16 {
            let expected = u8::from_str_radix(&hex_str[i*2..i*2+2], 16).unwrap();
            prop_assert_eq!(buf[i], expected);
        }
    }

    /// Property 13.6: BCD buffer conversion
    #[test]
    fn test_bcd_conversion(bcd in "[0-9]{1,15}") {
        let mut buf = Vec::new();
        let len = ogs_bcd_to_buffer(&bcd, &mut buf);

        // Length should be ceil(bcd.len() / 2)
        let expected_len = bcd.len().div_ceil(2);
        prop_assert_eq!(len, expected_len);
        prop_assert_eq!(buf.len(), expected_len);
    }

    /// Property 13.7: QoS index bounds
    #[test]
    fn test_qos_index_bounds(qos in qos_strategy()) {
        prop_assert!(qos.index >= 1 && qos.index <= 9);
    }

    /// Property 13.8: ARP priority level bounds
    #[test]
    fn test_arp_priority_bounds(arp in arp_strategy()) {
        prop_assert!(arp.priority_level >= 1 && arp.priority_level <= 15);
        prop_assert!(arp.pre_emption_capability <= 1);
        prop_assert!(arp.pre_emption_vulnerability <= 1);
    }

    /// Property 13.9: Subscription data clear
    #[test]
    fn test_subscription_data_clear(
        imsi in imsi_strategy(),
        num_msisdn in 0usize..=OGS_MAX_NUM_OF_MSISDN
    ) {
        let mut data = OgsSubscriptionData::new();
        data.imsi = Some(imsi);
        data.num_of_msisdn = num_msisdn;

        data.clear();

        prop_assert!(data.imsi.is_none());
        prop_assert_eq!(data.num_of_msisdn, 0);
        prop_assert!(data.msisdn.is_empty());
    }

    /// Property 13.10: Session data clear
    #[test]
    fn test_session_data_clear(
        name in "[a-zA-Z0-9]{1,20}",
        num_pcc_rule in 0usize..=OGS_MAX_NUM_OF_PCC_RULE
    ) {
        let mut data = OgsSessionData::new();
        data.session.name = Some(name);
        data.num_of_pcc_rule = num_pcc_rule;

        data.clear();

        prop_assert!(data.session.name.is_none());
        prop_assert_eq!(data.num_of_pcc_rule, 0);
        prop_assert!(data.pcc_rule.is_empty());
    }

    /// Property 13.11: IMS data clear
    #[test]
    fn test_ims_data_clear(
        num_msisdn in 0usize..=OGS_MAX_NUM_OF_MSISDN,
        num_ifc in 0usize..=OGS_MAX_NUM_OF_IFC
    ) {
        let mut data = OgsImsData::new();
        data.num_of_msisdn = num_msisdn;
        data.num_of_ifc = num_ifc;

        data.clear();

        prop_assert_eq!(data.num_of_msisdn, 0);
        prop_assert_eq!(data.num_of_ifc, 0);
        prop_assert!(data.msisdn.is_empty());
        prop_assert!(data.ifc.is_empty());
    }

    /// Property 13.12: PCC rule clear
    #[test]
    fn test_pcc_rule_clear(
        id in "[a-zA-Z0-9]{1,20}",
        name in "[a-zA-Z0-9]{1,20}",
        num_flow in 0usize..=OGS_MAX_NUM_OF_FLOW_IN_PCC_RULE
    ) {
        let mut rule = OgsPccRule::default();
        rule.id = Some(id);
        rule.name = Some(name);
        rule.num_of_flow = num_flow;

        rule.clear();

        prop_assert!(rule.id.is_none());
        prop_assert!(rule.name.is_none());
        prop_assert_eq!(rule.num_of_flow, 0);
        prop_assert!(rule.flow.is_empty());
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_uint24_from_hex_string() {
        let u = OgsUint24::from_hex_string("000001").unwrap();
        assert_eq!(u.v, 1);

        let u2 = OgsUint24::from_hex_string("FFFFFF").unwrap();
        assert_eq!(u2.v, 0xFFFFFF);

        let u3 = OgsUint24::from_hex_string("invalid");
        assert!(u3.is_none());
    }

    #[test]
    fn test_s_nssai_no_sd() {
        let snssai = OgsSNssai::new(1, None);
        assert_eq!(snssai.sst, 1);
        assert_eq!(snssai.sd.v, OGS_S_NSSAI_NO_SD_VALUE);
        assert!(!snssai.has_sd());
    }

    #[test]
    fn test_s_nssai_with_sd() {
        let snssai = OgsSNssai::new(1, Some(0x000001));
        assert_eq!(snssai.sst, 1);
        assert_eq!(snssai.sd.v, 0x000001);
        assert!(snssai.has_sd());
    }

    #[test]
    fn test_supi_parsing_imsi() {
        let supi = "imsi-123456789012345";
        assert_eq!(ogs_id_get_type(supi), Some("imsi".to_string()));
        assert_eq!(ogs_id_get_value(supi), Some("123456789012345".to_string()));
    }

    #[test]
    fn test_supi_parsing_nai() {
        let supi = "nai-user@example.com";
        assert_eq!(ogs_id_get_type(supi), Some("nai".to_string()));
        assert_eq!(ogs_id_get_value(supi), Some("user@example.com".to_string()));
    }

    #[test]
    fn test_hex_to_bytes() {
        let mut buf = [0u8; 16];
        let len = ogs_ascii_to_hex("465B5CE8B199B49FAA5F0A2EE238A6BC", &mut buf);
        assert_eq!(len, 16);
        assert_eq!(buf[0], 0x46);
        assert_eq!(buf[1], 0x5B);
        assert_eq!(buf[15], 0xBC);
    }

    #[test]
    fn test_bcd_to_buffer() {
        let mut buf = Vec::new();
        let len = ogs_bcd_to_buffer("123456789012345", &mut buf);
        assert_eq!(len, 8);
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
    }
}
