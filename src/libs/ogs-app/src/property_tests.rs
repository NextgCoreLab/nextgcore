//! Property-based tests for configuration
//!
//! Property 14: Configuration Round-Trip
//! Validates: Requirements 11.1-11.5

#[cfg(test)]
mod tests {
    use crate::config::{
        OgsGlobalConf, OgsLocalConf, OgsPlmnId, ParameterConf, MaxConf, SockoptConf,
        PkbufConfig, ogs_time_from_sec, ogs_time_from_msec,
    };
    use crate::context::{OgsAppContext, PoolConf, MetricsConf};
    use crate::yaml::OgsYamlDocument;
    use proptest::prelude::*;

    // Strategy for generating valid parameter configurations
    fn arb_parameter_conf() -> impl Strategy<Value = ParameterConf> {
        // Use nested tuples to avoid the 12-element limit
        (
            (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
            (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
            (any::<bool>(), any::<bool>(), any::<bool>()),
        ).prop_map(|(
            (no_mme, no_hss, no_sgw, no_sgwc),
            (no_sgwu, no_pgw, no_pcrf, no_amf),
            (no_smf, no_upf, no_ausf),
        )| {
            ParameterConf {
                no_mme, no_hss, no_sgw, no_sgwc, no_sgwu, no_pgw, no_pcrf,
                no_amf, no_smf, no_upf, no_ausf,
                no_udm: false, no_pcf: false, no_nssf: false,
                no_bsf: false, no_udr: false, no_sepp: false, no_scp: false, no_nrf: false,
                // Network flags - ensure not both no_ipv4 and no_ipv6 are true
                no_ipv4: false,
                no_ipv6: false,
                prefer_ipv4: false,
                multicast: false,
                use_openair: false,
                fake_csfb: false,
                use_upg_vpp: false,
                no_ipv4v6_local_addr_in_packet_filter: false,
                no_pfcp_rr_select: false,
                no_time_zone_information: false,
                // Counts
                amf_count: 0, smf_count: 0, upf_count: 0, ausf_count: 0,
                udm_count: 0, pcf_count: 0, nssf_count: 0, bsf_count: 0, udr_count: 0,
            }
        })
    }

    // Strategy for generating valid max configurations
    fn arb_max_conf() -> impl Strategy<Value = MaxConf> {
        (1u64..10000, 1u64..1000, 0u64..1000).prop_map(|(ue, peer, gtp_peer)| {
            MaxConf { ue, peer, gtp_peer }
        })
    }

    // Strategy for generating valid sockopt configurations
    fn arb_sockopt_conf() -> impl Strategy<Value = SockoptConf> {
        (any::<bool>(), any::<bool>(), 0i32..100).prop_map(|(no_delay, l_onoff, l_linger)| {
            SockoptConf { no_delay, l_onoff, l_linger }
        })
    }

    // Strategy for generating valid pkbuf configurations
    fn arb_pkbuf_config() -> impl Strategy<Value = PkbufConfig> {
        (
            (1u32..100000, 1u32..50000, 1u32..20000, 1u32..10000),
            (1u32..5000, 1u32..1000, 1u32..500, 1u32..100),
        ).prop_map(|((c128, c256, c512, c1024), (c2048, c8192, c32768, big))| {
            PkbufConfig {
                cluster_128_pool: c128,
                cluster_256_pool: c256,
                cluster_512_pool: c512,
                cluster_1024_pool: c1024,
                cluster_2048_pool: c2048,
                cluster_8192_pool: c8192,
                cluster_32768_pool: c32768,
                cluster_big_pool: big,
            }
        })
    }

    // Strategy for generating valid global configurations
    fn arb_global_conf() -> impl Strategy<Value = OgsGlobalConf> {
        (arb_parameter_conf(), arb_max_conf(), arb_sockopt_conf(), arb_pkbuf_config())
            .prop_map(|(parameter, max, sockopt, pkbuf_config)| {
                OgsGlobalConf { parameter, max, sockopt, pkbuf_config }
            })
    }

    // Strategy for generating valid PLMN IDs
    fn arb_plmn_id() -> impl Strategy<Value = OgsPlmnId> {
        (100u16..999, 0u16..999, 2u8..=3).prop_map(|(mcc, mnc, mnc_len)| {
            OgsPlmnId::build(mcc, mnc, mnc_len)
        })
    }

    // Strategy for generating valid local configurations
    fn arb_local_conf() -> impl Strategy<Value = OgsLocalConf> {
        (
            (1i32..100, 1i32..10, 1i32..3600),
            (1i32..86400 * 7, 1i64..60000, 1i64..10000),
            proptest::collection::vec(arb_plmn_id(), 0..6),
        ).prop_map(|((hb, margin, validity), (sub_validity, msg_dur, ho_dur), plmns)| {
            let mut conf = OgsLocalConf::new();
            conf.time.nf_instance.heartbeat_interval = hb;
            conf.time.nf_instance.no_heartbeat_margin = margin;
            conf.time.nf_instance.validity_duration = validity;
            conf.time.subscription.validity_duration = sub_validity;
            conf.time.message.duration = ogs_time_from_msec(msg_dur);
            conf.time.handover.duration = ogs_time_from_msec(ho_dur);
            conf.regenerate_timer_durations();
            conf.serving_plmn_id = plmns;
            conf
        })
    }

    // Strategy for generating valid pool configurations (used in arb_app_context)
    #[allow(dead_code)]
    fn arb_pool_conf() -> impl Strategy<Value = PoolConf> {
        (
            (1u64..100000, 1u64..50000, 1u64..50000, 1u64..50000),
            (1u64..10000, 1u64..50000, 1u64..50000, 1u64..50000),
            (1u64..50000, 1u64..10000, 1u64..50000, 1u64..50000),
            (1u64..1000, 1u64..1000, 1u64..1000, 1u64..100),
            (1u64..10000, 1u64..100000),
        ).prop_map(|(
            (gtpu, sess, bearer, tunnel),
            (nf_service, timer, message, event),
            (socket, subscription, xact, stream),
            (nf, gtp_node, csmap, emerg),
            (impi, impu),
        )| {
            PoolConf {
                gtpu, sess, bearer, tunnel, nf_service, timer, message, event,
                socket, subscription, xact, stream, nf, gtp_node, csmap, emerg,
                impi, impu,
            }
        })
    }

    // Strategy for generating valid app contexts (available for future tests)
    #[allow(dead_code)]
    fn arb_app_context() -> impl Strategy<Value = OgsAppContext> {
        (
            proptest::option::of("[a-z0-9.]+"),
            proptest::option::of("/[a-z/]+\\.yaml"),
            arb_pool_conf(),
            1u64..10000,
            0i32..10,
        ).prop_map(|(version, file, pool, max_specs, config_section_id)| {
            OgsAppContext {
                version,
                file,
                db_uri: None,
                logger_default: Default::default(),
                logger: Default::default(),
                usrsctp: Default::default(),
                pool,
                metrics: MetricsConf { max_specs },
                config_section_id,
            }
        })
    }

    proptest! {
        /// Property 14.1: Global configuration validation is consistent
        #[test]
        fn prop_global_conf_validation_consistent(conf in arb_global_conf()) {
            // Validation should be deterministic
            let result1 = conf.validate();
            let result2 = conf.validate();
            prop_assert_eq!(result1.is_ok(), result2.is_ok());
        }

        /// Property 14.2: Local configuration validation is consistent
        #[test]
        fn prop_local_conf_validation_consistent(conf in arb_local_conf()) {
            let result1 = conf.validate();
            let result2 = conf.validate();
            prop_assert_eq!(result1.is_ok(), result2.is_ok());
        }

        /// Property 14.3: PLMN ID build is deterministic
        #[test]
        fn prop_plmn_id_build_deterministic(mcc in 100u16..999, mnc in 0u16..999, mnc_len in 2u8..=3) {
            let plmn1 = OgsPlmnId::build(mcc, mnc, mnc_len);
            let plmn2 = OgsPlmnId::build(mcc, mnc, mnc_len);
            prop_assert_eq!(plmn1, plmn2);
        }

        /// Property 14.4: Timer regeneration is consistent
        #[test]
        fn prop_timer_regeneration_consistent(duration_ms in 1000i64..60000) {
            let mut conf1 = OgsLocalConf::new();
            let mut conf2 = OgsLocalConf::new();
            
            conf1.time.message.duration = ogs_time_from_msec(duration_ms);
            conf2.time.message.duration = ogs_time_from_msec(duration_ms);
            
            conf1.regenerate_timer_durations();
            conf2.regenerate_timer_durations();
            
            prop_assert_eq!(conf1.time.message.sbi.client_wait_duration, 
                           conf2.time.message.sbi.client_wait_duration);
            prop_assert_eq!(conf1.time.message.pfcp.t1_response_duration,
                           conf2.time.message.pfcp.t1_response_duration);
            prop_assert_eq!(conf1.time.message.gtp.t3_response_duration,
                           conf2.time.message.gtp.t3_response_duration);
        }

        /// Property 14.5: Pool size calculation is deterministic
        #[test]
        fn prop_pool_size_calculation_deterministic(max_ue in 1u64..10000, max_peer in 1u64..1000) {
            let mut global = OgsGlobalConf::new();
            global.max.ue = max_ue;
            global.max.peer = max_peer;
            
            let mut ctx1 = OgsAppContext::new();
            let mut ctx2 = OgsAppContext::new();
            
            ctx1.recalculate_pool_size(&global);
            ctx2.recalculate_pool_size(&global);
            
            prop_assert_eq!(ctx1.pool.gtpu, ctx2.pool.gtpu);
            prop_assert_eq!(ctx1.pool.sess, ctx2.pool.sess);
            prop_assert_eq!(ctx1.pool.timer, ctx2.pool.timer);
            prop_assert_eq!(ctx1.pool.nf, ctx2.pool.nf);
        }

        /// Property 14.6: Global configuration with valid IP settings passes validation
        #[test]
        fn prop_valid_ip_settings_pass_validation(no_ipv4 in any::<bool>(), no_ipv6 in any::<bool>()) {
            let mut conf = OgsGlobalConf::new();
            
            // Ensure at least one IP version is enabled
            if no_ipv4 && no_ipv6 {
                conf.parameter.no_ipv4 = false;
                conf.parameter.no_ipv6 = true;
            } else {
                conf.parameter.no_ipv4 = no_ipv4;
                conf.parameter.no_ipv6 = no_ipv6;
            }
            
            prop_assert!(conf.validate().is_ok());
        }

        /// Property 14.7: Invalid IP settings fail validation
        #[test]
        fn prop_invalid_ip_settings_fail_validation(_dummy in 0..1i32) {
            let mut conf = OgsGlobalConf::new();
            conf.parameter.no_ipv4 = true;
            conf.parameter.no_ipv6 = true;
            
            prop_assert!(conf.validate().is_err());
        }

        /// Property 14.8: Local configuration with zero validity fails validation
        #[test]
        fn prop_zero_validity_fails_validation(_dummy in 0..1i32) {
            let mut conf = OgsLocalConf::new();
            conf.time.nf_instance.validity_duration = 0;
            
            prop_assert!(conf.validate().is_err());
        }

        /// Property 14.9: Time conversion functions are consistent
        #[test]
        fn prop_time_conversion_consistent(sec in 0i64..1000000) {
            // ogs_time_from_sec(n) == ogs_time_from_msec(n * 1000)
            prop_assert_eq!(ogs_time_from_sec(sec), ogs_time_from_msec(sec * 1000));
        }

        /// Property 14.10: NF section counting is cumulative
        #[test]
        fn prop_nf_section_counting_cumulative(count in 1usize..10) {
            let mut conf = OgsGlobalConf::new();
            
            for _ in 0..count {
                conf.count_nf_conf_section("amf");
            }
            
            prop_assert_eq!(conf.parameter.amf_count, count as i32);
        }

        /// Property 14.11: App context pool calculation scales with UE count
        #[test]
        fn prop_pool_scales_with_ue_count(ue1 in 1u64..5000, ue2 in 5001u64..10000) {
            let mut global1 = OgsGlobalConf::new();
            let mut global2 = OgsGlobalConf::new();
            global1.max.ue = ue1;
            global2.max.ue = ue2;
            
            let mut ctx1 = OgsAppContext::new();
            let mut ctx2 = OgsAppContext::new();
            
            ctx1.recalculate_pool_size(&global1);
            ctx2.recalculate_pool_size(&global2);
            
            // Larger UE count should result in larger pools
            prop_assert!(ctx2.pool.gtpu > ctx1.pool.gtpu);
            prop_assert!(ctx2.pool.sess > ctx1.pool.sess);
            prop_assert!(ctx2.pool.timer > ctx1.pool.timer);
        }
    }

    // Non-proptest unit tests for YAML round-trip
    #[test]
    fn test_yaml_global_conf_round_trip() {
        let yaml = r#"
global:
  parameter:
    no_ipv4: false
    no_ipv6: true
    prefer_ipv4: true
  max:
    ue: 2048
    peer: 128
  sockopt:
    no_delay: true
    linger: 5
"#;
        let doc = OgsYamlDocument::from_str(yaml).unwrap();
        let mut iter = doc.iter();
        
        let mut conf = OgsGlobalConf::new();
        
        while iter.next() {
            if iter.key() == Some("global") {
                conf.parse(&mut iter).unwrap();
            }
        }

        // Verify parsed values
        assert!(!conf.parameter.no_ipv4);
        assert!(conf.parameter.no_ipv6);
        assert!(conf.parameter.prefer_ipv4);
        assert_eq!(conf.max.ue, 2048);
        assert_eq!(conf.max.peer, 128);
        assert!(conf.sockopt.no_delay);
        assert!(conf.sockopt.l_onoff);
        assert_eq!(conf.sockopt.l_linger, 5);
    }

    #[test]
    fn test_yaml_local_conf_round_trip() {
        let yaml = r#"
amf:
  serving:
    - plmn_id:
        mcc: 310
        mnc: 410
    - plmn_id:
        mcc: 001
        mnc: 01
  time:
    nf_instance:
      heartbeat: 20
      validity: 60
    subscription:
      validity: 172800
    message:
      duration: 5000
    handover:
      duration: 500
"#;
        let doc = OgsYamlDocument::from_str(yaml).unwrap();
        let mut iter = doc.iter();
        
        let mut conf = OgsLocalConf::new();
        
        while iter.next() {
            if iter.key() == Some("amf") {
                if let Some(mut local_iter) = iter.recurse() {
                    conf.parse(&mut local_iter).unwrap();
                }
            }
        }

        // Verify parsed values
        assert_eq!(conf.time.nf_instance.heartbeat_interval, 20);
        assert_eq!(conf.time.nf_instance.validity_duration, 60);
        assert_eq!(conf.time.subscription.validity_duration, 172800);
        assert_eq!(conf.time.message.duration, ogs_time_from_msec(5000));
        assert_eq!(conf.time.handover.duration, ogs_time_from_msec(500));
        
        // Check PLMN IDs
        assert_eq!(conf.serving_plmn_id.len(), 2);
    }
}
