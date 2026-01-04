//! Property-Based Tests for MME State Machines
//!
//! Feature: nextgcore-rust-conversion
//! Property 12: Network Function State Machine Equivalence (MME)
//! Validates: Requirements 8.1-8.10

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crate::sm::{
        MmeFsm, MmeState, Fsm,
        EmmFsm, EmmState,
        EsmFsm, EsmState,
        S1apFsm, S1apState,
        SgsapFsm, SgsapState,
        MmeEvent, MmeEventId, MmeTimerId,
    };

    // ========================================================================
    // Strategies for generating test data
    // ========================================================================

    /// Strategy for generating MME event IDs
    fn arb_mme_event_id() -> impl Strategy<Value = MmeEventId> {
        prop_oneof![
            Just(MmeEventId::S1apMessage),
            Just(MmeEventId::S1apTimer),
            Just(MmeEventId::EmmMessage),
            Just(MmeEventId::EmmTimer),
            Just(MmeEventId::EsmMessage),
            Just(MmeEventId::EsmTimer),
            Just(MmeEventId::S11Message),
            Just(MmeEventId::S11Timer),
            Just(MmeEventId::S6aMessage),
            Just(MmeEventId::S6aTimer),
            Just(MmeEventId::SgsapMessage),
            Just(MmeEventId::SgsapTimer),
        ]
    }

    /// Strategy for generating MME timer IDs
    fn arb_mme_timer_id() -> impl Strategy<Value = MmeTimerId> {
        prop_oneof![
            Just(MmeTimerId::T3413),
            Just(MmeTimerId::T3422),
            Just(MmeTimerId::T3450),
            Just(MmeTimerId::T3460),
            Just(MmeTimerId::T3470),
            Just(MmeTimerId::T3489),
            Just(MmeTimerId::MobileReachable),
            Just(MmeTimerId::ImplicitDetach),
            Just(MmeTimerId::S1Holding),
            Just(MmeTimerId::S1DelayedSend),
        ]
    }


    /// Strategy for generating EMM states
    fn arb_emm_state() -> impl Strategy<Value = EmmState> {
        prop_oneof![
            Just(EmmState::Initial),
            Just(EmmState::DeRegistered),
            Just(EmmState::Authentication),
            Just(EmmState::SecurityMode),
            Just(EmmState::InitialContextSetup),
            Just(EmmState::Registered),
            Just(EmmState::Exception),
            Just(EmmState::Final),
        ]
    }

    /// Strategy for generating ESM states
    fn arb_esm_state() -> impl Strategy<Value = EsmState> {
        prop_oneof![
            Just(EsmState::Initial),
            Just(EsmState::Inactive),
            Just(EsmState::Active),
            Just(EsmState::PdnWillDisconnect),
            Just(EsmState::PdnDidDisconnect),
            Just(EsmState::BearerDeactivated),
            Just(EsmState::Exception),
            Just(EsmState::Final),
        ]
    }

    // ========================================================================
    // MME FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.1: MME FSM initialization always transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.1 - MME state machine initialization
        #[test]
        fn prop_mme_fsm_init_transitions_to_operational(_seed in any::<u64>()) {
            let mut fsm = MmeFsm::new();
            prop_assert_eq!(fsm.state(), MmeState::Initial);
            
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), MmeState::Operational);
        }

        /// Property 12.2: MME FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.1 - MME state machine finalization
        #[test]
        fn prop_mme_fsm_fini_transitions_to_final(_seed in any::<u64>()) {
            let mut fsm = MmeFsm::new();
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), MmeState::Operational);
            
            Fsm::fini(&mut fsm);
            prop_assert_eq!(fsm.state(), MmeState::Final);
        }

        /// Property 12.3: MME FSM in Operational state handles events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.1 - MME state machine event handling
        #[test]
        fn prop_mme_fsm_operational_handles_events(event_id in arb_mme_event_id()) {
            let mut fsm = MmeFsm::new();
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), MmeState::Operational);
            
            let event = MmeEvent::new(event_id);
            Fsm::dispatch(&mut fsm, &event);
            // Should remain in Operational state
            prop_assert_eq!(fsm.state(), MmeState::Operational);
        }

        /// Property 12.4: MME FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.1 - MME state machine final state behavior
        #[test]
        fn prop_mme_fsm_final_ignores_events(event_id in arb_mme_event_id()) {
            let mut fsm = MmeFsm::new();
            Fsm::init(&mut fsm);
            Fsm::fini(&mut fsm);
            prop_assert_eq!(fsm.state(), MmeState::Final);
            
            let event = MmeEvent::new(event_id);
            Fsm::dispatch(&mut fsm, &event);
            // Should remain in Final state
            prop_assert_eq!(fsm.state(), MmeState::Final);
        }
    }


    // ========================================================================
    // EMM FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.5: EMM FSM initialization always transitions to DeRegistered
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.2 - EMM state machine initialization
        #[test]
        fn prop_emm_fsm_init_transitions_to_deregistered(mme_ue_id in 1u64..10000) {
            let mut fsm = EmmFsm::new(mme_ue_id);
            prop_assert_eq!(fsm.state(), EmmState::Initial);
            
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), EmmState::DeRegistered);
        }

        /// Property 12.6: EMM FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.2 - EMM state machine finalization
        #[test]
        fn prop_emm_fsm_fini_transitions_to_final(mme_ue_id in 1u64..10000) {
            let mut fsm = EmmFsm::new(mme_ue_id);
            Fsm::init(&mut fsm);
            
            Fsm::fini(&mut fsm);
            prop_assert_eq!(fsm.state(), EmmState::Final);
        }

        /// Property 12.7: EMM FSM state transitions are deterministic
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.2 - EMM state machine determinism
        #[test]
        fn prop_emm_fsm_state_transitions_deterministic(mme_ue_id in 1u64..10000) {
            let mut fsm = EmmFsm::new(mme_ue_id);
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), EmmState::DeRegistered);
            
            // Transition through attach flow
            fsm.transition(EmmState::Authentication);
            prop_assert_eq!(fsm.state(), EmmState::Authentication);
            
            fsm.transition(EmmState::SecurityMode);
            prop_assert_eq!(fsm.state(), EmmState::SecurityMode);
            
            fsm.transition(EmmState::InitialContextSetup);
            prop_assert_eq!(fsm.state(), EmmState::InitialContextSetup);
            
            fsm.transition(EmmState::Registered);
            prop_assert_eq!(fsm.state(), EmmState::Registered);
        }

        /// Property 12.8: EMM FSM state names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.2 - EMM state naming
        #[test]
        fn prop_emm_state_names_consistent(state in arb_emm_state()) {
            let name = state.to_string();
            prop_assert!(!name.is_empty());
        }

        /// Property 12.9: EMM FSM can transition to any valid state
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.2 - EMM state transitions
        #[test]
        fn prop_emm_fsm_can_transition_to_any_state(
            mme_ue_id in 1u64..10000,
            target_state in arb_emm_state()
        ) {
            let mut fsm = EmmFsm::new(mme_ue_id);
            Fsm::init(&mut fsm);
            
            fsm.transition(target_state);
            prop_assert_eq!(fsm.state(), target_state);
        }
    }


    // ========================================================================
    // ESM FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.10: ESM FSM initialization always transitions to Inactive
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.4 - ESM state machine initialization
        #[test]
        fn prop_esm_fsm_init_transitions_to_inactive(bearer_id in 1u64..16) {
            let mut fsm = EsmFsm::new(bearer_id);
            prop_assert_eq!(fsm.state(), EsmState::Initial);
            
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), EsmState::Inactive);
        }

        /// Property 12.11: ESM FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.4 - ESM state machine finalization
        #[test]
        fn prop_esm_fsm_fini_transitions_to_final(bearer_id in 1u64..16) {
            let mut fsm = EsmFsm::new(bearer_id);
            Fsm::init(&mut fsm);
            
            Fsm::fini(&mut fsm);
            prop_assert_eq!(fsm.state(), EsmState::Final);
        }

        /// Property 12.12: ESM FSM state transitions follow bearer lifecycle
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.4 - ESM state machine lifecycle
        #[test]
        fn prop_esm_fsm_bearer_lifecycle(bearer_id in 1u64..16) {
            let mut fsm = EsmFsm::new(bearer_id);
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), EsmState::Inactive);
            
            // Activate bearer
            fsm.transition(EsmState::Active);
            prop_assert_eq!(fsm.state(), EsmState::Active);
            
            // Deactivate bearer
            fsm.transition(EsmState::PdnWillDisconnect);
            prop_assert_eq!(fsm.state(), EsmState::PdnWillDisconnect);
            
            fsm.transition(EsmState::Inactive);
            prop_assert_eq!(fsm.state(), EsmState::Inactive);
        }

        /// Property 12.13: ESM FSM state names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.4 - ESM state naming
        #[test]
        fn prop_esm_state_names_consistent(state in arb_esm_state()) {
            let name = state.to_string();
            prop_assert!(!name.is_empty());
        }
    }


    // ========================================================================
    // S1AP FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.14: S1AP FSM initialization always transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.6 - S1AP state machine initialization
        #[test]
        fn prop_s1ap_fsm_init_transitions_to_operational(enb_id in 1u64..10000) {
            let mut fsm = S1apFsm::new(enb_id);
            prop_assert_eq!(fsm.state(), S1apState::Initial);
            
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), S1apState::Operational);
        }

        /// Property 12.15: S1AP FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.6 - S1AP state machine finalization
        #[test]
        fn prop_s1ap_fsm_fini_transitions_to_final(enb_id in 1u64..10000) {
            let mut fsm = S1apFsm::new(enb_id);
            Fsm::init(&mut fsm);
            
            Fsm::fini(&mut fsm);
            prop_assert_eq!(fsm.state(), S1apState::Final);
        }

        /// Property 12.16: S1AP FSM in Operational state handles S1AP messages
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.6 - S1AP message handling
        #[test]
        fn prop_s1ap_fsm_operational_handles_messages(enb_id in 1u64..10000) {
            let mut fsm = S1apFsm::new(enb_id);
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), S1apState::Operational);
            
            let event = MmeEvent::new(MmeEventId::S1apMessage);
            Fsm::dispatch(&mut fsm, &event);
            // Should remain in Operational state
            prop_assert_eq!(fsm.state(), S1apState::Operational);
        }

        /// Property 12.17: S1AP FSM can transition to exception state
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.6 - S1AP exception handling
        #[test]
        fn prop_s1ap_fsm_can_transition_to_exception(enb_id in 1u64..10000) {
            let mut fsm = S1apFsm::new(enb_id);
            Fsm::init(&mut fsm);
            
            fsm.transition(S1apState::Exception);
            prop_assert_eq!(fsm.state(), S1apState::Exception);
        }
    }


    // ========================================================================
    // SGsAP FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.18: SGsAP FSM initialization always transitions to WillConnect
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.10 - SGsAP state machine initialization
        #[test]
        fn prop_sgsap_fsm_init_transitions_to_will_connect(vlr_id in 1u64..10000) {
            let mut fsm = SgsapFsm::new(vlr_id);
            prop_assert_eq!(fsm.state(), SgsapState::Initial);
            
            Fsm::init(&mut fsm);
            prop_assert_eq!(fsm.state(), SgsapState::WillConnect);
        }

        /// Property 12.19: SGsAP FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.10 - SGsAP state machine finalization
        #[test]
        fn prop_sgsap_fsm_fini_transitions_to_final(vlr_id in 1u64..10000) {
            let mut fsm = SgsapFsm::new(vlr_id);
            Fsm::init(&mut fsm);
            
            Fsm::fini(&mut fsm);
            prop_assert_eq!(fsm.state(), SgsapState::Final);
        }

        /// Property 12.20: SGsAP FSM can transition to Connected state
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.10 - SGsAP connection handling
        #[test]
        fn prop_sgsap_fsm_can_transition_to_connected(vlr_id in 1u64..10000) {
            let mut fsm = SgsapFsm::new(vlr_id);
            Fsm::init(&mut fsm);
            
            fsm.transition(SgsapState::Connected);
            prop_assert_eq!(fsm.state(), SgsapState::Connected);
        }
    }


    // ========================================================================
    // Cross-FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property 12.21: Timer ID names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.9 - Timer naming
        #[test]
        fn prop_timer_names_consistent(timer_id in arb_mme_timer_id()) {
            let name = timer_id.to_string();
            prop_assert!(!name.is_empty());
        }

        /// Property 12.22: Event ID names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.1 - Event naming
        #[test]
        fn prop_event_id_names_consistent(event_id in arb_mme_event_id()) {
            let event = MmeEvent::new(event_id);
            let name = event.name();
            prop_assert!(!name.is_empty());
        }

        /// Property 12.23: Multiple FSMs can coexist independently
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.9 - MME context isolation
        #[test]
        fn prop_multiple_fsms_independent(
            mme_ue_id1 in 1u64..5000,
            mme_ue_id2 in 5001u64..10000,
            enb_id in 1u64..10000,
            bearer_id in 1u64..16
        ) {
            let mut mme_fsm = MmeFsm::new();
            let mut emm_fsm1 = EmmFsm::new(mme_ue_id1);
            let mut emm_fsm2 = EmmFsm::new(mme_ue_id2);
            let mut s1ap_fsm = S1apFsm::new(enb_id);
            let mut esm_fsm = EsmFsm::new(bearer_id);
            
            // Initialize all FSMs
            Fsm::init(&mut mme_fsm);
            Fsm::init(&mut emm_fsm1);
            Fsm::init(&mut emm_fsm2);
            Fsm::init(&mut s1ap_fsm);
            Fsm::init(&mut esm_fsm);
            
            // Verify independent states
            prop_assert_eq!(mme_fsm.state(), MmeState::Operational);
            prop_assert_eq!(emm_fsm1.state(), EmmState::DeRegistered);
            prop_assert_eq!(emm_fsm2.state(), EmmState::DeRegistered);
            prop_assert_eq!(s1ap_fsm.state(), S1apState::Operational);
            prop_assert_eq!(esm_fsm.state(), EsmState::Inactive);
            
            // Transition one EMM FSM
            emm_fsm1.transition(EmmState::Registered);
            
            // Verify other FSMs are unaffected
            prop_assert_eq!(emm_fsm1.state(), EmmState::Registered);
            prop_assert_eq!(emm_fsm2.state(), EmmState::DeRegistered);
            prop_assert_eq!(mme_fsm.state(), MmeState::Operational);
            prop_assert_eq!(s1ap_fsm.state(), S1apState::Operational);
            prop_assert_eq!(esm_fsm.state(), EsmState::Inactive);
        }

        /// Property 12.24: EMM and ESM FSMs can be associated
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.5 - EMM/ESM coordination
        #[test]
        fn prop_emm_esm_association(
            mme_ue_id in 1u64..10000,
            bearer_id in 5u64..16
        ) {
            let mut emm_fsm = EmmFsm::new(mme_ue_id);
            let mut esm_fsm = EsmFsm::new(bearer_id);
            
            Fsm::init(&mut emm_fsm);
            Fsm::init(&mut esm_fsm);
            
            // EMM attach flow
            emm_fsm.transition(EmmState::Authentication);
            emm_fsm.transition(EmmState::SecurityMode);
            emm_fsm.transition(EmmState::InitialContextSetup);
            
            // ESM bearer activation during attach
            esm_fsm.transition(EsmState::Active);
            
            // Complete EMM attach
            emm_fsm.transition(EmmState::Registered);
            
            // Verify both FSMs are in expected states
            prop_assert_eq!(emm_fsm.state(), EmmState::Registered);
            prop_assert_eq!(esm_fsm.state(), EsmState::Active);
        }

        /// Property 12.25: FSM lifecycle is consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 8.1 - FSM lifecycle
        #[test]
        fn prop_fsm_lifecycle_consistent(mme_ue_id in 1u64..10000) {
            let mut emm_fsm = EmmFsm::new(mme_ue_id);
            
            // Initial state
            prop_assert_eq!(emm_fsm.state(), EmmState::Initial);
            
            // After init
            Fsm::init(&mut emm_fsm);
            prop_assert_eq!(emm_fsm.state(), EmmState::DeRegistered);
            
            // After fini
            Fsm::fini(&mut emm_fsm);
            prop_assert_eq!(emm_fsm.state(), EmmState::Final);
        }
    }
}
