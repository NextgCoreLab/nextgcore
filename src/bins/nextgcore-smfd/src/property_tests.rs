//! Property-Based Tests for SMF State Machines
//!
//! This module contains property-based tests that verify the correctness
//! of SMF state machine implementations using the proptest framework.
//!
//! Property 12: Network Function State Machine Equivalence (SMF)

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crate::smf_sm::{SmfFsm, SmfState, SmfFsmResult};
    use crate::gsm_sm::{GsmFsm, GsmState, GsmFsmResult};
    use crate::pfcp_sm::{PfcpFsm, PfcpState, PfcpFsmResult};
    use crate::event::{SmfEvent, SmfEventId, SmfTimerId, SbiRequest};

    // ========================================================================
    // Strategies for generating test data
    // ========================================================================

    /// Strategy for generating SMF event IDs
    fn arb_smf_event_id() -> impl Strategy<Value = SmfEventId> {
        prop_oneof![
            Just(SmfEventId::FsmEntry),
            Just(SmfEventId::FsmExit),
            Just(SmfEventId::S5cMessage),
            Just(SmfEventId::GnMessage),
            Just(SmfEventId::GxMessage),
            Just(SmfEventId::GyMessage),
            Just(SmfEventId::S6bMessage),
            Just(SmfEventId::N4Message),
            Just(SmfEventId::N4Timer),
            Just(SmfEventId::N4NoHeartbeat),
            Just(SmfEventId::SbiServer),
            Just(SmfEventId::SbiClient),
            Just(SmfEventId::SbiTimer),
            Just(SmfEventId::GsmMessage),
            Just(SmfEventId::GsmTimer),
            Just(SmfEventId::NgapMessage),
            Just(SmfEventId::NgapTimer),
            Just(SmfEventId::SessionRelease),
        ]
    }

    /// Strategy for generating SMF timer IDs
    fn arb_smf_timer_id() -> impl Strategy<Value = SmfTimerId> {
        prop_oneof![
            Just(SmfTimerId::NfInstanceRegistrationInterval),
            Just(SmfTimerId::NfInstanceHeartbeatInterval),
            Just(SmfTimerId::NfInstanceNoHeartbeat),
            Just(SmfTimerId::NfInstanceValidity),
            Just(SmfTimerId::SubscriptionValidity),
            Just(SmfTimerId::SubscriptionPatch),
            Just(SmfTimerId::SbiClientWait),
            Just(SmfTimerId::PfcpAssociation),
            Just(SmfTimerId::PfcpNoHeartbeat),
            Just(SmfTimerId::PfcpNoEstablishmentResponse),
            Just(SmfTimerId::PfcpNoDeletionResponse),
        ]
    }

    /// Strategy for generating PFCP timer IDs
    fn arb_pfcp_timer_id() -> impl Strategy<Value = SmfTimerId> {
        prop_oneof![
            Just(SmfTimerId::PfcpAssociation),
            Just(SmfTimerId::PfcpNoHeartbeat),
            Just(SmfTimerId::PfcpNoEstablishmentResponse),
            Just(SmfTimerId::PfcpNoDeletionResponse),
        ]
    }

    /// Strategy for generating GSM states
    fn arb_gsm_state() -> impl Strategy<Value = GsmState> {
        prop_oneof![
            Just(GsmState::Initial),
            Just(GsmState::WaitEpcAuthInitial),
            Just(GsmState::Wait5gcSmPolicyAssociation),
            Just(GsmState::WaitPfcpEstablishment),
            Just(GsmState::Operational),
            Just(GsmState::WaitPfcpDeletion),
            Just(GsmState::WaitEpcAuthRelease),
            Just(GsmState::Wait5gcN1N2Release),
            Just(GsmState::N1N2Reject5gc),
            Just(GsmState::SessionWillDeregister5gc),
            Just(GsmState::SessionWillRelease),
            Just(GsmState::Exception),
            Just(GsmState::Final),
        ]
    }

    /// Strategy for generating PFCP states
    fn arb_pfcp_state() -> impl Strategy<Value = PfcpState> {
        prop_oneof![
            Just(PfcpState::Initial),
            Just(PfcpState::WillAssociate),
            Just(PfcpState::Associated),
            Just(PfcpState::Exception),
            Just(PfcpState::Final),
        ]
    }

    // ========================================================================
    // SMF FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.1: SMF FSM initialization always transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - SMF state machine initialization
        #[test]
        fn prop_smf_fsm_init_transitions_to_operational(_seed in any::<u64>()) {
            let mut fsm = SmfFsm::new();
            prop_assert_eq!(fsm.state, SmfState::Initial);
            
            fsm.init();
            prop_assert_eq!(fsm.state, SmfState::Operational);
        }

        /// Property 12.2: SMF FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - SMF state machine finalization
        #[test]
        fn prop_smf_fsm_fini_transitions_to_final(_seed in any::<u64>()) {
            let mut fsm = SmfFsm::new();
            fsm.init();
            prop_assert_eq!(fsm.state, SmfState::Operational);
            
            fsm.fini();
            prop_assert_eq!(fsm.state, SmfState::Final);
        }

        /// Property 12.3: SMF FSM entry event in Initial state transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - SMF state machine entry handling
        #[test]
        fn prop_smf_fsm_entry_event_transitions(_seed in any::<u64>()) {
            let mut fsm = SmfFsm::new();
            let event = SmfEvent::entry();
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, SmfFsmResult::Transition(SmfState::Operational));
            prop_assert_eq!(fsm.state, SmfState::Operational);
        }

        /// Property 12.4: SMF FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - SMF state machine final state behavior
        #[test]
        fn prop_smf_fsm_final_ignores_events(event_id in arb_smf_event_id()) {
            let mut fsm = SmfFsm::new();
            fsm.init();
            fsm.fini();
            prop_assert_eq!(fsm.state, SmfState::Final);
            
            let event = SmfEvent::new(event_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, SmfFsmResult::Ignored);
            prop_assert_eq!(fsm.state, SmfState::Final);
        }

        /// Property 12.5: SMF FSM in Operational state handles SBI events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.7 - SMF SBI handling
        #[test]
        fn prop_smf_fsm_operational_handles_sbi(_seed in any::<u64>()) {
            let mut fsm = SmfFsm::new();
            fsm.init();
            
            let request = SbiRequest {
                method: "POST".to_string(),
                uri: "/nsmf-pdusession/v1/sm-contexts".to_string(),
                body: None,
            };
            let event = SmfEvent::sbi_server(123, request);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, SmfFsmResult::Handled);
        }

        /// Property 12.6: SMF FSM in Operational state handles N4 events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - SMF N4/PFCP handling
        #[test]
        fn prop_smf_fsm_operational_handles_n4(pfcp_node_id in 1u64..1000) {
            let mut fsm = SmfFsm::new();
            fsm.init();
            
            let event = SmfEvent::n4_message(pfcp_node_id, 789, vec![1, 2, 3]);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, SmfFsmResult::Delegated);
        }
    }

    // ========================================================================
    // GSM FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.7: GSM FSM creation preserves session ID
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM state machine initialization
        #[test]
        fn prop_gsm_fsm_new_preserves_sess_id(sess_id in 1u64..10000) {
            let fsm = GsmFsm::new(sess_id);
            prop_assert_eq!(fsm.state, GsmState::Initial);
            prop_assert_eq!(fsm.sess_id, sess_id);
        }

        /// Property 12.8: GSM FSM initialization resets SM data
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM state machine initialization
        #[test]
        fn prop_gsm_fsm_init_resets_sm_data(sess_id in 1u64..10000) {
            let mut fsm = GsmFsm::new(sess_id);
            
            // Set some flags
            fsm.set_s6b_aar_in_flight(true);
            fsm.set_gx_ccr_init_in_flight(true);
            
            // Init should reset
            fsm.init();
            prop_assert!(!fsm.sm_data.s6b_aar_in_flight);
            prop_assert!(!fsm.sm_data.gx_ccr_init_in_flight);
        }

        /// Property 12.9: GSM FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM state machine finalization
        #[test]
        fn prop_gsm_fsm_fini_transitions_to_final(sess_id in 1u64..10000) {
            let mut fsm = GsmFsm::new(sess_id);
            fsm.init();
            
            fsm.fini();
            prop_assert_eq!(fsm.state, GsmState::Final);
        }

        /// Property 12.10: GSM FSM entry event in Initial state is handled
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM state machine entry handling
        #[test]
        fn prop_gsm_fsm_entry_event_handled(sess_id in 1u64..10000) {
            let mut fsm = GsmFsm::new(sess_id);
            let event = SmfEvent::entry();
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, GsmFsmResult::Handled);
        }

        /// Property 12.11: GSM FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM state machine final state behavior
        #[test]
        fn prop_gsm_fsm_final_ignores_events(
            sess_id in 1u64..10000,
            event_id in arb_smf_event_id()
        ) {
            let mut fsm = GsmFsm::new(sess_id);
            fsm.init();
            fsm.fini();
            prop_assert_eq!(fsm.state, GsmState::Final);
            
            let event = SmfEvent::new(event_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, GsmFsmResult::Ignored);
            prop_assert_eq!(fsm.state, GsmState::Final);
        }

        /// Property 12.12: GSM FSM state transitions are deterministic
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM state machine determinism
        #[test]
        fn prop_gsm_fsm_state_transitions_deterministic(sess_id in 1u64..10000) {
            let mut fsm = GsmFsm::new(sess_id);
            fsm.init();
            prop_assert!(fsm.is_initial());
            
            // Transition through session establishment flow
            fsm.transition_to(GsmState::WaitEpcAuthInitial);
            prop_assert_eq!(fsm.state, GsmState::WaitEpcAuthInitial);
            
            fsm.transition_to(GsmState::WaitPfcpEstablishment);
            prop_assert_eq!(fsm.state, GsmState::WaitPfcpEstablishment);
            
            fsm.transition_to(GsmState::Operational);
            prop_assert!(fsm.is_operational());
        }

        /// Property 12.13: GSM FSM state helper methods work correctly
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.3 - GSM state helper methods
        #[test]
        fn prop_gsm_fsm_state_helpers(sess_id in 1u64..10000) {
            let mut fsm = GsmFsm::new(sess_id);
            
            // Test is_initial
            prop_assert!(fsm.is_initial());
            prop_assert!(!fsm.is_operational());
            
            // Transition to operational
            fsm.transition_to(GsmState::Operational);
            prop_assert!(!fsm.is_initial());
            prop_assert!(fsm.is_operational());
            
            // Test is_state
            prop_assert!(fsm.is_state(GsmState::Operational));
            prop_assert!(!fsm.is_state(GsmState::Initial));
            
            // Test current_state
            prop_assert_eq!(fsm.current_state(), GsmState::Operational);
        }

        /// Property 12.14: GSM FSM state names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM state naming
        #[test]
        fn prop_gsm_state_names_consistent(state in arb_gsm_state()) {
            let name = state.name();
            prop_assert!(name.starts_with("GSM_STATE_"));
            prop_assert!(!name.is_empty());
        }

        /// Property 12.15: GSM FSM in-flight flag setters work correctly
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.3 - GSM in-flight tracking
        #[test]
        fn prop_gsm_fsm_in_flight_flags(sess_id in 1u64..10000) {
            let mut fsm = GsmFsm::new(sess_id);
            
            fsm.set_s6b_aar_in_flight(true);
            prop_assert!(fsm.sm_data.s6b_aar_in_flight);
            fsm.set_s6b_aar_in_flight(false);
            prop_assert!(!fsm.sm_data.s6b_aar_in_flight);
            
            fsm.set_gx_ccr_init_in_flight(true);
            prop_assert!(fsm.sm_data.gx_ccr_init_in_flight);
            
            fsm.set_gy_ccr_init_in_flight(true);
            prop_assert!(fsm.sm_data.gy_ccr_init_in_flight);
            
            fsm.set_gx_ccr_term_in_flight(true);
            prop_assert!(fsm.sm_data.gx_ccr_term_in_flight);
            
            fsm.set_gy_ccr_term_in_flight(true);
            prop_assert!(fsm.sm_data.gy_ccr_term_in_flight);
            
            fsm.set_s6b_str_in_flight(true);
            prop_assert!(fsm.sm_data.s6b_str_in_flight);
        }
    }

    // ========================================================================
    // PFCP FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.16: PFCP FSM creation preserves node ID
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP state machine initialization
        #[test]
        fn prop_pfcp_fsm_new_preserves_node_id(pfcp_node_id in 1u64..10000) {
            let fsm = PfcpFsm::new(pfcp_node_id);
            prop_assert_eq!(fsm.state, PfcpState::Initial);
            prop_assert_eq!(fsm.pfcp_node_id, pfcp_node_id);
            prop_assert!(!fsm.restoration_required);
        }

        /// Property 12.17: PFCP FSM initialization transitions to WillAssociate
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP state machine initialization
        #[test]
        fn prop_pfcp_fsm_init_transitions_to_will_associate(pfcp_node_id in 1u64..10000) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            prop_assert_eq!(fsm.state, PfcpState::Initial);
            
            fsm.init();
            prop_assert_eq!(fsm.state, PfcpState::WillAssociate);
        }

        /// Property 12.18: PFCP FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP state machine finalization
        #[test]
        fn prop_pfcp_fsm_fini_transitions_to_final(pfcp_node_id in 1u64..10000) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            fsm.init();
            
            fsm.fini();
            prop_assert_eq!(fsm.state, PfcpState::Final);
        }

        /// Property 12.19: PFCP FSM entry event in Initial state transitions to WillAssociate
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP state machine entry handling
        #[test]
        fn prop_pfcp_fsm_entry_event_transitions(pfcp_node_id in 1u64..10000) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            let event = SmfEvent::entry();
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, PfcpFsmResult::Transition(PfcpState::WillAssociate));
            prop_assert_eq!(fsm.state, PfcpState::WillAssociate);
        }

        /// Property 12.20: PFCP FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP state machine final state behavior
        #[test]
        fn prop_pfcp_fsm_final_ignores_events(
            pfcp_node_id in 1u64..10000,
            event_id in arb_smf_event_id()
        ) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            fsm.init();
            fsm.fini();
            prop_assert_eq!(fsm.state, PfcpState::Final);
            
            let event = SmfEvent::new(event_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, PfcpFsmResult::Ignored);
            prop_assert_eq!(fsm.state, PfcpState::Final);
        }

        /// Property 12.21: PFCP FSM state transitions are deterministic
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP state transitions
        #[test]
        fn prop_pfcp_fsm_state_transitions_deterministic(pfcp_node_id in 1u64..10000) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            fsm.init();
            prop_assert_eq!(fsm.state, PfcpState::WillAssociate);

            fsm.transition_to(PfcpState::Associated);
            prop_assert!(fsm.is_associated());

            fsm.transition_to(PfcpState::WillAssociate);
            prop_assert!(!fsm.is_associated());
        }

        /// Property 12.22: PFCP FSM no heartbeat in Associated state triggers reassociation
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.5 - PFCP heartbeat handling
        #[test]
        fn prop_pfcp_fsm_no_heartbeat_triggers_reassociation(pfcp_node_id in 1u64..10000) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            fsm.init();
            fsm.transition_to(PfcpState::Associated);
            prop_assert!(fsm.is_associated());

            let event = SmfEvent::n4_no_heartbeat(pfcp_node_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, PfcpFsmResult::Transition(PfcpState::WillAssociate));
            prop_assert_eq!(fsm.state, PfcpState::WillAssociate);
        }

        /// Property 12.23: PFCP FSM restoration required flag works correctly
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP restoration handling
        #[test]
        fn prop_pfcp_fsm_restoration_required(pfcp_node_id in 1u64..10000) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            prop_assert!(!fsm.restoration_required);

            fsm.set_restoration_required(true);
            prop_assert!(fsm.restoration_required);

            fsm.set_restoration_required(false);
            prop_assert!(!fsm.restoration_required);
        }

        /// Property 12.24: PFCP FSM state names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP state naming
        #[test]
        fn prop_pfcp_state_names_consistent(state in arb_pfcp_state()) {
            let name = state.name();
            prop_assert!(name.starts_with("PFCP_STATE_"));
            prop_assert!(!name.is_empty());
        }
    }

    // ========================================================================
    // Cross-FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property 12.25: Timer ID classification is consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.9 - Timer classification
        #[test]
        fn prop_timer_classification_consistent(timer_id in arb_smf_timer_id()) {
            let is_pfcp = timer_id.is_pfcp_timer();
            
            // PFCP timers should be correctly identified
            let expected_pfcp = matches!(
                timer_id,
                SmfTimerId::PfcpAssociation
                    | SmfTimerId::PfcpNoHeartbeat
                    | SmfTimerId::PfcpNoEstablishmentResponse
                    | SmfTimerId::PfcpNoDeletionResponse
            );
            prop_assert_eq!(is_pfcp, expected_pfcp);
            
            // Timer name should be non-empty
            prop_assert!(!timer_id.name().is_empty());
        }

        /// Property 12.26: Event ID names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - Event naming
        #[test]
        fn prop_event_id_names_consistent(event_id in arb_smf_event_id()) {
            let name = event_id.name();
            prop_assert!(!name.is_empty());
            // SMF events should have recognizable prefixes
            prop_assert!(
                name.contains("FSM") || 
                name.contains("SMF") || 
                name.contains("SBI") ||
                name.contains("EVENT")
            );
        }

        /// Property 12.27: Multiple FSMs can coexist independently
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.8 - SMF context isolation
        #[test]
        fn prop_multiple_fsms_independent(
            sess_id1 in 1u64..5000,
            sess_id2 in 5001u64..10000,
            pfcp_node_id in 1u64..10000
        ) {
            let mut smf_fsm = SmfFsm::new();
            let mut gsm_fsm1 = GsmFsm::new(sess_id1);
            let mut gsm_fsm2 = GsmFsm::new(sess_id2);
            let mut pfcp_fsm = PfcpFsm::new(pfcp_node_id);
            
            // Initialize all FSMs
            smf_fsm.init();
            gsm_fsm1.init();
            gsm_fsm2.init();
            pfcp_fsm.init();
            
            // Verify independent states
            prop_assert_eq!(smf_fsm.state, SmfState::Operational);
            prop_assert_eq!(gsm_fsm1.state, GsmState::Initial);
            prop_assert_eq!(gsm_fsm2.state, GsmState::Initial);
            prop_assert_eq!(pfcp_fsm.state, PfcpState::WillAssociate);
            
            // Transition one GSM FSM
            gsm_fsm1.transition_to(GsmState::Operational);
            
            // Verify other FSMs are unaffected
            prop_assert_eq!(gsm_fsm1.state, GsmState::Operational);
            prop_assert_eq!(gsm_fsm2.state, GsmState::Initial);
            prop_assert_eq!(smf_fsm.state, SmfState::Operational);
            prop_assert_eq!(pfcp_fsm.state, PfcpState::WillAssociate);
        }

        /// Property 12.28: GSM FSM session lifecycle is consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GSM session lifecycle
        #[test]
        fn prop_gsm_session_lifecycle(sess_id in 1u64..10000) {
            let mut fsm = GsmFsm::new(sess_id);
            
            // Initial state
            prop_assert!(fsm.is_initial());
            prop_assert!(!fsm.is_operational());
            
            // Transition to operational
            fsm.transition_to(GsmState::Operational);
            prop_assert!(fsm.is_operational());
            prop_assert!(!fsm.is_initial());
            
            // Transition to deletion
            fsm.transition_to(GsmState::WaitPfcpDeletion);
            prop_assert!(!fsm.is_operational());
            
            // Transition to release
            fsm.transition_to(GsmState::SessionWillRelease);
            prop_assert!(!fsm.is_operational());
        }

        /// Property 12.29: PFCP FSM association lifecycle is consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - PFCP association lifecycle
        #[test]
        fn prop_pfcp_association_lifecycle(pfcp_node_id in 1u64..10000) {
            let mut fsm = PfcpFsm::new(pfcp_node_id);
            
            // Initial state
            prop_assert!(!fsm.is_associated());
            
            // Initialize - should go to WillAssociate
            fsm.init();
            prop_assert!(!fsm.is_associated());
            prop_assert_eq!(fsm.state, PfcpState::WillAssociate);
            
            // Transition to Associated
            fsm.transition_to(PfcpState::Associated);
            prop_assert!(fsm.is_associated());
            
            // Transition back to WillAssociate (e.g., after heartbeat failure)
            fsm.transition_to(PfcpState::WillAssociate);
            prop_assert!(!fsm.is_associated());
        }
    }
}
