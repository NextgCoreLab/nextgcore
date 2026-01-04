//! Property-Based Tests for AMF State Machines
//!
//! Feature: nextgcore-rust-conversion
//! Property 12: Network Function State Machine Equivalence (AMF)
//! Validates: Requirements 5.1-5.10

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crate::amf_sm::{AmfFsm, AmfState, AmfFsmResult};
    use crate::gmm_sm::{GmmFsm, GmmState, GmmFsmResult};
    use crate::ngap_sm::{NgapFsm, NgapState, NgapFsmResult};
    use crate::event::{AmfEvent, AmfEventId, AmfTimerId};

    // ========================================================================
    // Strategies for generating test data
    // ========================================================================

    /// Strategy for generating AMF event IDs
    fn arb_amf_event_id() -> impl Strategy<Value = AmfEventId> {
        prop_oneof![
            Just(AmfEventId::FsmEntry),
            Just(AmfEventId::FsmExit),
            Just(AmfEventId::SbiServer),
            Just(AmfEventId::SbiClient),
            Just(AmfEventId::SbiTimer),
            Just(AmfEventId::NgapMessage),
            Just(AmfEventId::NgapTimer),
            Just(AmfEventId::GmmTimer),
        ]
    }

    /// Strategy for generating AMF timer IDs
    fn arb_amf_timer_id() -> impl Strategy<Value = AmfTimerId> {
        prop_oneof![
            Just(AmfTimerId::NfInstanceRegistrationInterval),
            Just(AmfTimerId::NfInstanceHeartbeatInterval),
            Just(AmfTimerId::NfInstanceNoHeartbeat),
            Just(AmfTimerId::NfInstanceValidity),
            Just(AmfTimerId::SubscriptionValidity),
            Just(AmfTimerId::SubscriptionPatch),
            Just(AmfTimerId::SbiClientWait),
            Just(AmfTimerId::NgDelayedSend),
            Just(AmfTimerId::NgHolding),
            Just(AmfTimerId::T3513),
            Just(AmfTimerId::T3522),
            Just(AmfTimerId::T3550),
            Just(AmfTimerId::T3555),
            Just(AmfTimerId::T3560),
            Just(AmfTimerId::T3570),
            Just(AmfTimerId::MobileReachable),
            Just(AmfTimerId::ImplicitDeregistration),
        ]
    }

    /// Strategy for generating GMM timer IDs
    fn arb_gmm_timer_id() -> impl Strategy<Value = AmfTimerId> {
        prop_oneof![
            Just(AmfTimerId::T3513),
            Just(AmfTimerId::T3522),
            Just(AmfTimerId::T3550),
            Just(AmfTimerId::T3555),
            Just(AmfTimerId::T3560),
            Just(AmfTimerId::T3570),
            Just(AmfTimerId::MobileReachable),
            Just(AmfTimerId::ImplicitDeregistration),
        ]
    }

    /// Strategy for generating NGAP timer IDs
    fn arb_ngap_timer_id() -> impl Strategy<Value = AmfTimerId> {
        prop_oneof![
            Just(AmfTimerId::NgDelayedSend),
            Just(AmfTimerId::NgHolding),
        ]
    }

    /// Strategy for generating GMM states
    fn arb_gmm_state() -> impl Strategy<Value = GmmState> {
        prop_oneof![
            Just(GmmState::Initial),
            Just(GmmState::DeRegistered),
            Just(GmmState::Authentication),
            Just(GmmState::SecurityMode),
            Just(GmmState::InitialContextSetup),
            Just(GmmState::Registered),
            Just(GmmState::UeContextWillRemove),
            Just(GmmState::Exception),
            Just(GmmState::Final),
        ]
    }

    // ========================================================================
    // AMF FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.1: AMF FSM initialization always transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - AMF state machine initialization
        #[test]
        fn prop_amf_fsm_init_transitions_to_operational(_seed in any::<u64>()) {
            let mut fsm = AmfFsm::new();
            prop_assert_eq!(fsm.state, AmfState::Initial);
            
            fsm.init();
            prop_assert_eq!(fsm.state, AmfState::Operational);
        }

        /// Property 12.2: AMF FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - AMF state machine finalization
        #[test]
        fn prop_amf_fsm_fini_transitions_to_final(_seed in any::<u64>()) {
            let mut fsm = AmfFsm::new();
            fsm.init();
            prop_assert_eq!(fsm.state, AmfState::Operational);
            
            fsm.fini();
            prop_assert_eq!(fsm.state, AmfState::Final);
        }

        /// Property 12.3: AMF FSM entry event in Initial state transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - AMF state machine entry handling
        #[test]
        fn prop_amf_fsm_entry_event_transitions(_seed in any::<u64>()) {
            let mut fsm = AmfFsm::new();
            let event = AmfEvent::entry();
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, AmfFsmResult::Transition(AmfState::Operational));
            prop_assert_eq!(fsm.state, AmfState::Operational);
        }

        /// Property 12.4: AMF FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - AMF state machine final state behavior
        #[test]
        fn prop_amf_fsm_final_ignores_events(event_id in arb_amf_event_id()) {
            let mut fsm = AmfFsm::new();
            fsm.init();
            fsm.fini();
            prop_assert_eq!(fsm.state, AmfState::Final);
            
            let event = AmfEvent::new(event_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, AmfFsmResult::Ignored);
            prop_assert_eq!(fsm.state, AmfState::Final);
        }

        /// Property 12.5: AMF FSM in Operational state handles SBI events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.7 - AMF SBI handling
        #[test]
        fn prop_amf_fsm_operational_handles_sbi(_seed in any::<u64>()) {
            let mut fsm = AmfFsm::new();
            fsm.init();
            
            let request = crate::event::SbiRequest {
                method: "POST".to_string(),
                uri: "/namf-comm/v1/ue-contexts".to_string(),
                body: None,
            };
            let event = AmfEvent::sbi_server(123, request);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, AmfFsmResult::Handled);
        }

        /// Property 12.6: AMF FSM in Operational state handles NGAP events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - AMF NGAP handling
        #[test]
        fn prop_amf_fsm_operational_handles_ngap(gnb_id in 1u64..1000) {
            let mut fsm = AmfFsm::new();
            fsm.init();
            
            let event = AmfEvent::ngap_message(gnb_id, vec![1, 2, 3]);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, AmfFsmResult::Handled);
        }
    }

    // ========================================================================
    // GMM FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.7: GMM FSM initialization always transitions to DeRegistered
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GMM state machine initialization
        #[test]
        fn prop_gmm_fsm_init_transitions_to_deregistered(amf_ue_id in 1u64..10000) {
            let mut fsm = GmmFsm::new(amf_ue_id);
            prop_assert_eq!(fsm.state, GmmState::Initial);
            prop_assert_eq!(fsm.amf_ue_id, amf_ue_id);
            
            fsm.init();
            prop_assert_eq!(fsm.state, GmmState::DeRegistered);
            prop_assert!(fsm.is_de_registered());
        }

        /// Property 12.8: GMM FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GMM state machine finalization
        #[test]
        fn prop_gmm_fsm_fini_transitions_to_final(amf_ue_id in 1u64..10000) {
            let mut fsm = GmmFsm::new(amf_ue_id);
            fsm.init();
            
            fsm.fini();
            prop_assert_eq!(fsm.state, GmmState::Final);
        }

        /// Property 12.9: GMM FSM entry event in Initial state transitions to DeRegistered
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GMM state machine entry handling
        #[test]
        fn prop_gmm_fsm_entry_event_transitions(amf_ue_id in 1u64..10000) {
            let mut fsm = GmmFsm::new(amf_ue_id);
            let event = AmfEvent::entry();
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, GmmFsmResult::Transition(GmmState::DeRegistered));
            prop_assert_eq!(fsm.state, GmmState::DeRegistered);
        }

        /// Property 12.10: GMM FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GMM state machine final state behavior
        #[test]
        fn prop_gmm_fsm_final_ignores_events(
            amf_ue_id in 1u64..10000,
            event_id in arb_amf_event_id()
        ) {
            let mut fsm = GmmFsm::new(amf_ue_id);
            fsm.init();
            fsm.fini();
            prop_assert_eq!(fsm.state, GmmState::Final);
            
            let event = AmfEvent::new(event_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, GmmFsmResult::Ignored);
            prop_assert_eq!(fsm.state, GmmState::Final);
        }

        /// Property 12.11: GMM FSM state transitions are deterministic
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GMM state machine determinism
        #[test]
        fn prop_gmm_fsm_state_transitions_deterministic(amf_ue_id in 1u64..10000) {
            let mut fsm = GmmFsm::new(amf_ue_id);
            fsm.init();
            prop_assert!(fsm.is_de_registered());
            
            // Transition through registration flow
            fsm.transition_to_authentication();
            prop_assert_eq!(fsm.state, GmmState::Authentication);
            
            fsm.transition_to_security_mode();
            prop_assert_eq!(fsm.state, GmmState::SecurityMode);
            
            fsm.transition_to_initial_context_setup();
            prop_assert_eq!(fsm.state, GmmState::InitialContextSetup);
            
            fsm.transition_to_registered();
            prop_assert!(fsm.is_registered());
        }

        /// Property 12.12: GMM FSM implicit deregistration timer causes deregistration
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.3 - GMM timer handling
        #[test]
        fn prop_gmm_fsm_implicit_dereg_timer(amf_ue_id in 1u64..10000) {
            let mut fsm = GmmFsm::new(amf_ue_id);
            fsm.init();
            fsm.transition_to_registered();
            prop_assert!(fsm.is_registered());
            
            let event = AmfEvent::gmm_timer(AmfTimerId::ImplicitDeregistration, amf_ue_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, GmmFsmResult::Transition(GmmState::DeRegistered));
            prop_assert!(fsm.is_de_registered());
        }

        /// Property 12.13: GMM FSM T3522 timer in registered state causes exception
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.3 - GMM timer handling
        #[test]
        fn prop_gmm_fsm_t3522_timer_exception(amf_ue_id in 1u64..10000) {
            let mut fsm = GmmFsm::new(amf_ue_id);
            fsm.init();
            fsm.transition_to_registered();
            
            let event = AmfEvent::gmm_timer(AmfTimerId::T3522, amf_ue_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, GmmFsmResult::Transition(GmmState::Exception));
            prop_assert_eq!(fsm.state, GmmState::Exception);
        }

        /// Property 12.14: GMM FSM state names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.2 - GMM state naming
        #[test]
        fn prop_gmm_state_names_consistent(state in arb_gmm_state()) {
            let name = state.name();
            prop_assert!(name.starts_with("GMM_STATE_"));
            prop_assert!(!name.is_empty());
        }
    }

    // ========================================================================
    // NGAP FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.15: NGAP FSM initialization always transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - NGAP state machine initialization
        #[test]
        fn prop_ngap_fsm_init_transitions_to_operational(gnb_id in 1u64..10000) {
            let mut fsm = NgapFsm::new(gnb_id);
            prop_assert_eq!(fsm.state, NgapState::Initial);
            prop_assert_eq!(fsm.gnb_id, gnb_id);
            
            fsm.init();
            prop_assert_eq!(fsm.state, NgapState::Operational);
            prop_assert!(fsm.is_operational());
        }

        /// Property 12.16: NGAP FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - NGAP state machine finalization
        #[test]
        fn prop_ngap_fsm_fini_transitions_to_final(gnb_id in 1u64..10000) {
            let mut fsm = NgapFsm::new(gnb_id);
            fsm.init();
            
            fsm.fini();
            prop_assert_eq!(fsm.state, NgapState::Final);
        }

        /// Property 12.17: NGAP FSM entry event in Initial state transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - NGAP state machine entry handling
        #[test]
        fn prop_ngap_fsm_entry_event_transitions(gnb_id in 1u64..10000) {
            let mut fsm = NgapFsm::new(gnb_id);
            let event = AmfEvent::entry();
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, NgapFsmResult::Transition(NgapState::Operational));
            prop_assert_eq!(fsm.state, NgapState::Operational);
        }

        /// Property 12.18: NGAP FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - NGAP state machine final state behavior
        #[test]
        fn prop_ngap_fsm_final_ignores_events(
            gnb_id in 1u64..10000,
            event_id in arb_amf_event_id()
        ) {
            let mut fsm = NgapFsm::new(gnb_id);
            fsm.init();
            fsm.fini();
            prop_assert_eq!(fsm.state, NgapState::Final);
            
            let event = AmfEvent::new(event_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, NgapFsmResult::Ignored);
            prop_assert_eq!(fsm.state, NgapState::Final);
        }

        /// Property 12.19: NGAP FSM in Operational state handles NGAP messages
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - NGAP message handling
        #[test]
        fn prop_ngap_fsm_operational_handles_messages(gnb_id in 1u64..10000) {
            let mut fsm = NgapFsm::new(gnb_id);
            fsm.init();
            
            let event = AmfEvent::ngap_message(gnb_id, vec![1, 2, 3]);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, NgapFsmResult::Handled);
        }

        /// Property 12.20: NGAP FSM in Operational state handles NGAP timers
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.5 - NGAP timer handling
        #[test]
        fn prop_ngap_fsm_operational_handles_timers(
            gnb_id in 1u64..10000,
            timer_id in arb_ngap_timer_id()
        ) {
            let mut fsm = NgapFsm::new(gnb_id);
            fsm.init();
            
            let event = AmfEvent::ngap_timer(timer_id, gnb_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, NgapFsmResult::Handled);
        }

        /// Property 12.21: NGAP FSM exception state can still receive messages
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - NGAP exception handling
        #[test]
        fn prop_ngap_fsm_exception_handles_messages(gnb_id in 1u64..10000) {
            let mut fsm = NgapFsm::new(gnb_id);
            fsm.init();
            fsm.transition_to_exception();
            prop_assert!(fsm.is_exception());
            
            let event = AmfEvent::ngap_message(gnb_id, vec![1, 2, 3]);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, NgapFsmResult::Handled);
        }

        /// Property 12.22: NGAP FSM state transitions are reversible
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.4 - NGAP state transitions
        #[test]
        fn prop_ngap_fsm_state_transitions_reversible(gnb_id in 1u64..10000) {
            let mut fsm = NgapFsm::new(gnb_id);
            fsm.init();
            prop_assert!(fsm.is_operational());
            
            fsm.transition_to_exception();
            prop_assert!(fsm.is_exception());
            
            fsm.transition_to_operational();
            prop_assert!(fsm.is_operational());
        }
    }

    // ========================================================================
    // Cross-FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property 12.23: Timer ID classification is consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.9 - Timer classification
        #[test]
        fn prop_timer_classification_consistent(timer_id in arb_amf_timer_id()) {
            let is_gmm = timer_id.is_gmm_timer();
            let is_ngap = timer_id.is_ngap_timer();
            
            // A timer cannot be both GMM and NGAP
            prop_assert!(!(is_gmm && is_ngap));
            
            // Timer name should be non-empty
            prop_assert!(!timer_id.name().is_empty());
        }

        /// Property 12.24: Event ID names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.1 - Event naming
        #[test]
        fn prop_event_id_names_consistent(event_id in arb_amf_event_id()) {
            let name = event_id.name();
            prop_assert!(!name.is_empty());
            prop_assert!(name.contains("FSM") || name.contains("EVENT"));
        }

        /// Property 12.25: Multiple FSMs can coexist independently
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 5.8 - AMF context isolation
        #[test]
        fn prop_multiple_fsms_independent(
            amf_ue_id1 in 1u64..5000,
            amf_ue_id2 in 5001u64..10000,
            gnb_id in 1u64..10000
        ) {
            let mut amf_fsm = AmfFsm::new();
            let mut gmm_fsm1 = GmmFsm::new(amf_ue_id1);
            let mut gmm_fsm2 = GmmFsm::new(amf_ue_id2);
            let mut ngap_fsm = NgapFsm::new(gnb_id);
            
            // Initialize all FSMs
            amf_fsm.init();
            gmm_fsm1.init();
            gmm_fsm2.init();
            ngap_fsm.init();
            
            // Verify independent states
            prop_assert_eq!(amf_fsm.state, AmfState::Operational);
            prop_assert_eq!(gmm_fsm1.state, GmmState::DeRegistered);
            prop_assert_eq!(gmm_fsm2.state, GmmState::DeRegistered);
            prop_assert_eq!(ngap_fsm.state, NgapState::Operational);
            
            // Transition one GMM FSM
            gmm_fsm1.transition_to_registered();
            
            // Verify other FSMs are unaffected
            prop_assert_eq!(gmm_fsm1.state, GmmState::Registered);
            prop_assert_eq!(gmm_fsm2.state, GmmState::DeRegistered);
            prop_assert_eq!(amf_fsm.state, AmfState::Operational);
            prop_assert_eq!(ngap_fsm.state, NgapState::Operational);
        }
    }
}
