//! Property-Based Tests for UPF State Machines
//!
//! This module contains property-based tests that verify the correctness
//! of UPF state machine implementations using the proptest framework.
//!
//! Property 12: Network Function State Machine Equivalence (UPF)

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crate::upf_sm::{UpfSmContext, UpfState, UpfSmResult};
    use crate::pfcp_sm::{PfcpSmContext, PfcpState, PfcpSmResult, pfcp_msg_type};
    use crate::event::{UpfEvent, UpfEventId, UpfTimerId, PfcpEventData};

    // ========================================================================
    // Strategies for generating test data
    // ========================================================================

    /// Strategy for generating UPF event IDs
    fn arb_upf_event_id() -> impl Strategy<Value = UpfEventId> {
        prop_oneof![
            Just(UpfEventId::FsmEntry),
            Just(UpfEventId::FsmExit),
            Just(UpfEventId::N4Message),
            Just(UpfEventId::N4Timer),
            Just(UpfEventId::N4NoHeartbeat),
        ]
    }

    /// Strategy for generating UPF timer IDs
    fn arb_upf_timer_id() -> impl Strategy<Value = UpfTimerId> {
        prop_oneof![
            Just(UpfTimerId::Association),
            Just(UpfTimerId::NoHeartbeat),
        ]
    }

    /// Strategy for generating UPF states
    fn arb_upf_state() -> impl Strategy<Value = UpfState> {
        prop_oneof![
            Just(UpfState::Initial),
            Just(UpfState::Operational),
            Just(UpfState::Final),
            Just(UpfState::Exception),
        ]
    }

    /// Strategy for generating PFCP states
    fn arb_pfcp_state() -> impl Strategy<Value = PfcpState> {
        prop_oneof![
            Just(PfcpState::Initial),
            Just(PfcpState::WillAssociate),
            Just(PfcpState::Associated),
            Just(PfcpState::Final),
            Just(PfcpState::Exception),
        ]
    }


    // ========================================================================
    // UPF FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.1: UPF FSM initialization always starts in Initial state
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.1 - UPF state machine initialization
        #[test]
        fn prop_upf_fsm_init_starts_in_initial(_seed in any::<u64>()) {
            let mut fsm = UpfSmContext::new();
            prop_assert_eq!(fsm.state, UpfState::Initial);
            
            fsm.init();
            prop_assert_eq!(fsm.state, UpfState::Initial);
        }

        /// Property 12.2: UPF FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.1 - UPF state machine finalization
        #[test]
        fn prop_upf_fsm_fini_transitions_to_final(_seed in any::<u64>()) {
            let mut fsm = UpfSmContext::new();
            
            // Transition to operational first
            let entry = UpfEvent::entry();
            fsm.dispatch(&entry);
            prop_assert_eq!(fsm.state, UpfState::Operational);
            
            fsm.fini();
            prop_assert_eq!(fsm.state, UpfState::Final);
            prop_assert!(fsm.is_final());
        }

        /// Property 12.3: UPF FSM entry event in Initial state transitions to Operational
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.1 - UPF state machine entry handling
        #[test]
        fn prop_upf_fsm_entry_event_transitions(_seed in any::<u64>()) {
            let mut fsm = UpfSmContext::new();
            let event = UpfEvent::entry();
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, UpfSmResult::Transition(UpfState::Operational));
            prop_assert_eq!(fsm.state, UpfState::Operational);
            prop_assert!(fsm.is_operational());
        }

        /// Property 12.4: UPF FSM in Final state ignores all events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.1 - UPF state machine final state behavior
        #[test]
        fn prop_upf_fsm_final_ignores_events(event_id in arb_upf_event_id()) {
            let mut fsm = UpfSmContext::new();
            fsm.fini();
            prop_assert_eq!(fsm.state, UpfState::Final);
            
            let event = UpfEvent::new(event_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, UpfSmResult::Ok);
            prop_assert_eq!(fsm.state, UpfState::Final);
        }

        /// Property 12.5: UPF FSM in Operational state handles N4 message events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.2 - UPF N4/PFCP handling
        #[test]
        fn prop_upf_fsm_operational_handles_n4_message(
            pfcp_node_id in 1u64..1000,
            pfcp_xact_id in 1u64..1000
        ) {
            let mut fsm = UpfSmContext::new();
            let entry = UpfEvent::entry();
            fsm.dispatch(&entry);
            prop_assert!(fsm.is_operational());
            
            let event = UpfEvent::n4_message(pfcp_node_id, pfcp_xact_id, vec![1, 2, 3]);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, UpfSmResult::DispatchToPfcp);
        }

        /// Property 12.6: UPF FSM in Operational state handles N4 timer events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.2 - UPF N4 timer handling
        #[test]
        fn prop_upf_fsm_operational_handles_n4_timer(
            timer_id in arb_upf_timer_id(),
            pfcp_node_id in 1u64..1000
        ) {
            let mut fsm = UpfSmContext::new();
            let entry = UpfEvent::entry();
            fsm.dispatch(&entry);
            prop_assert!(fsm.is_operational());
            
            let event = UpfEvent::n4_timer(timer_id, Some(pfcp_node_id));
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, UpfSmResult::DispatchToPfcp);
        }

        /// Property 12.7: UPF FSM in Operational state handles N4 no heartbeat events
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.2 - UPF N4 heartbeat handling
        #[test]
        fn prop_upf_fsm_operational_handles_n4_no_heartbeat(pfcp_node_id in 1u64..1000) {
            let mut fsm = UpfSmContext::new();
            let entry = UpfEvent::entry();
            fsm.dispatch(&entry);
            prop_assert!(fsm.is_operational());
            
            let event = UpfEvent::n4_no_heartbeat(pfcp_node_id);
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, UpfSmResult::DispatchToPfcp);
        }
    }


    // ========================================================================
    // PFCP FSM Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.8: PFCP FSM creation preserves node ID
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.3 - PFCP state machine initialization
        #[test]
        fn prop_pfcp_fsm_new_preserves_node_id(node_id in 1u64..10000) {
            let fsm = PfcpSmContext::new(node_id);
            prop_assert_eq!(fsm.state, PfcpState::Initial);
            prop_assert_eq!(fsm.node_id, node_id);
            prop_assert!(!fsm.restoration_required);
        }

        /// Property 12.9: PFCP FSM initialization transitions to WillAssociate
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.3 - PFCP state machine initialization
        #[test]
        fn prop_pfcp_fsm_entry_transitions_to_will_associate(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            prop_assert_eq!(fsm.state, PfcpState::Initial);
            
            let event = UpfEvent::entry();
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, PfcpSmResult::Transition(PfcpState::WillAssociate));
            prop_assert_eq!(fsm.state, PfcpState::WillAssociate);
        }

        /// Property 12.10: PFCP FSM finalization always transitions to Final
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.3 - PFCP state machine finalization
        #[test]
        fn prop_pfcp_fsm_fini_transitions_to_final(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            let entry = UpfEvent::entry();
            fsm.dispatch(&entry);
            
            fsm.fini();
            prop_assert_eq!(fsm.state, PfcpState::Final);
            prop_assert!(fsm.is_final());
            prop_assert!(!fsm.no_heartbeat_timer_active);
        }

        /// Property 12.11: PFCP FSM entry event in WillAssociate with timer sends association request
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.4 - PFCP association handling
        #[test]
        fn prop_pfcp_fsm_will_associate_entry_with_timer(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            fsm.state = PfcpState::WillAssociate;
            fsm.has_association_timer = true;
            
            let event = UpfEvent::entry();
            let result = fsm.dispatch(&event);
            
            prop_assert_eq!(result, PfcpSmResult::SendAssociationSetupRequest);
            prop_assert!(fsm.association_timer_active);
        }

        /// Property 12.12: PFCP FSM no heartbeat in Associated state triggers reassociation
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.5 - PFCP heartbeat handling
        #[test]
        fn prop_pfcp_fsm_no_heartbeat_triggers_reassociation(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            fsm.state = PfcpState::Associated;
            prop_assert!(fsm.is_associated());
            
            let event = UpfEvent::n4_no_heartbeat(node_id);
            let result = fsm.dispatch(&event);
            
            prop_assert_eq!(result, PfcpSmResult::Transition(PfcpState::WillAssociate));
            prop_assert_eq!(fsm.state, PfcpState::WillAssociate);
            prop_assert!(!fsm.is_associated());
        }

        /// Property 12.13: PFCP FSM restoration required flag works correctly
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.6 - PFCP restoration handling
        #[test]
        fn prop_pfcp_fsm_restoration_required(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            prop_assert!(!fsm.restoration_required);
            
            fsm.set_restoration_required(true);
            prop_assert!(fsm.restoration_required);
            
            fsm.set_restoration_required(false);
            prop_assert!(!fsm.restoration_required);
        }

        /// Property 12.14: PFCP FSM Associated state entry sends heartbeat request
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.5 - PFCP heartbeat handling
        #[test]
        fn prop_pfcp_fsm_associated_entry_sends_heartbeat(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            fsm.state = PfcpState::Associated;
            fsm.restoration_required = false;
            
            let event = UpfEvent::entry();
            let result = fsm.dispatch(&event);
            
            prop_assert_eq!(result, PfcpSmResult::SendHeartbeatRequest);
            prop_assert!(fsm.no_heartbeat_timer_active);
        }

        /// Property 12.15: PFCP FSM Associated state with restoration required performs restoration
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.6 - PFCP restoration handling
        #[test]
        fn prop_pfcp_fsm_associated_restoration(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            fsm.state = PfcpState::Associated;
            fsm.restoration_required = true;
            
            let event = UpfEvent::entry();
            let result = fsm.dispatch(&event);
            
            prop_assert_eq!(result, PfcpSmResult::PerformRestoration);
            prop_assert!(!fsm.restoration_required);
        }
    }


    // ========================================================================
    // Cross-FSM and Consistency Property Tests
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 12.16: UPF state names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.1 - UPF state naming
        #[test]
        fn prop_upf_state_names_consistent(state in arb_upf_state()) {
            let name = format!("{state:?}");
            prop_assert!(!name.is_empty());
            // UPF states should have recognizable names
            prop_assert!(
                name == "Initial" ||
                name == "Operational" ||
                name == "Final" ||
                name == "Exception"
            );
        }

        /// Property 12.17: PFCP state names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.3 - PFCP state naming
        #[test]
        fn prop_pfcp_state_names_consistent(state in arb_pfcp_state()) {
            let name = format!("{state:?}");
            prop_assert!(!name.is_empty());
            // PFCP states should have recognizable names
            prop_assert!(
                name == "Initial" ||
                name == "WillAssociate" ||
                name == "Associated" ||
                name == "Final" ||
                name == "Exception"
            );
        }

        /// Property 12.18: Multiple FSMs can coexist independently
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.7 - UPF context isolation
        #[test]
        fn prop_multiple_fsms_independent(
            node_id1 in 1u64..5000,
            node_id2 in 5001u64..10000
        ) {
            let mut upf_fsm = UpfSmContext::new();
            let mut pfcp_fsm1 = PfcpSmContext::new(node_id1);
            let mut pfcp_fsm2 = PfcpSmContext::new(node_id2);
            
            // Initialize UPF FSM
            let entry = UpfEvent::entry();
            upf_fsm.dispatch(&entry);
            
            // Initialize PFCP FSMs
            pfcp_fsm1.dispatch(&entry);
            pfcp_fsm2.dispatch(&entry);
            
            // Verify independent states
            prop_assert_eq!(upf_fsm.state, UpfState::Operational);
            prop_assert_eq!(pfcp_fsm1.state, PfcpState::WillAssociate);
            prop_assert_eq!(pfcp_fsm2.state, PfcpState::WillAssociate);
            
            // Transition one PFCP FSM to Associated
            pfcp_fsm1.state = PfcpState::Associated;
            
            // Verify other FSMs are unaffected
            prop_assert_eq!(upf_fsm.state, UpfState::Operational);
            prop_assert!(pfcp_fsm1.is_associated());
            prop_assert!(!pfcp_fsm2.is_associated());
        }

        /// Property 12.19: Timer ID classification is consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.8 - Timer classification
        #[test]
        fn prop_timer_classification_consistent(timer_id in arb_upf_timer_id()) {
            let name = timer_id.name();
            prop_assert!(!name.is_empty());
            prop_assert!(name.starts_with("UPF_TIMER_"));
        }

        /// Property 12.20: Event ID names are consistent
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.1 - Event naming
        #[test]
        fn prop_event_id_names_consistent(event_id in arb_upf_event_id()) {
            let name = event_id.name();
            prop_assert!(!name.is_empty());
            // UPF events should have recognizable prefixes
            prop_assert!(
                name.contains("FSM") ||
                name.contains("UPF") ||
                name.contains("N4")
            );
        }

        /// Property 12.21: PFCP FSM handles session messages in Associated state
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.4 - PFCP session handling
        #[test]
        fn prop_pfcp_fsm_handles_session_establishment(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            fsm.state = PfcpState::Associated;
            
            let mut event = UpfEvent::new(UpfEventId::N4Message);
            event.pfcp = Some(PfcpEventData {
                pfcp_node_id: Some(node_id),
                pfcp_xact_id: Some(1),
                pkbuf: Some(vec![pfcp_msg_type::SESSION_ESTABLISHMENT_REQUEST]),
            });
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, PfcpSmResult::HandleSessionEstablishmentRequest);
        }

        /// Property 12.22: PFCP FSM handles session modification in Associated state
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.4 - PFCP session handling
        #[test]
        fn prop_pfcp_fsm_handles_session_modification(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            fsm.state = PfcpState::Associated;
            
            let mut event = UpfEvent::new(UpfEventId::N4Message);
            event.pfcp = Some(PfcpEventData {
                pfcp_node_id: Some(node_id),
                pfcp_xact_id: Some(1),
                pkbuf: Some(vec![pfcp_msg_type::SESSION_MODIFICATION_REQUEST]),
            });
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, PfcpSmResult::HandleSessionModificationRequest);
        }

        /// Property 12.23: PFCP FSM handles session deletion in Associated state
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.4 - PFCP session handling
        #[test]
        fn prop_pfcp_fsm_handles_session_deletion(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            fsm.state = PfcpState::Associated;
            
            let mut event = UpfEvent::new(UpfEventId::N4Message);
            event.pfcp = Some(PfcpEventData {
                pfcp_node_id: Some(node_id),
                pfcp_xact_id: Some(1),
                pkbuf: Some(vec![pfcp_msg_type::SESSION_DELETION_REQUEST]),
            });
            
            let result = fsm.dispatch(&event);
            prop_assert_eq!(result, PfcpSmResult::HandleSessionDeletionRequest);
        }

        /// Property 12.24: UPF FSM state helper methods work correctly
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.1 - UPF state helper methods
        #[test]
        fn prop_upf_fsm_state_helpers(_seed in any::<u64>()) {
            let mut fsm = UpfSmContext::new();
            
            // Initial state
            prop_assert!(!fsm.is_operational());
            prop_assert!(!fsm.is_final());
            prop_assert!(!fsm.is_exception());
            
            // Transition to operational
            let entry = UpfEvent::entry();
            fsm.dispatch(&entry);
            prop_assert!(fsm.is_operational());
            prop_assert!(!fsm.is_final());
            prop_assert!(!fsm.is_exception());
            
            // Transition to final
            fsm.fini();
            prop_assert!(!fsm.is_operational());
            prop_assert!(fsm.is_final());
            prop_assert!(!fsm.is_exception());
            
            // Set to exception
            fsm.state = UpfState::Exception;
            prop_assert!(!fsm.is_operational());
            prop_assert!(!fsm.is_final());
            prop_assert!(fsm.is_exception());
        }

        /// Property 12.25: PFCP FSM state helper methods work correctly
        /// Feature: nextgcore-rust-conversion
        /// Validates: Requirement 7.3 - PFCP state helper methods
        #[test]
        fn prop_pfcp_fsm_state_helpers(node_id in 1u64..10000) {
            let mut fsm = PfcpSmContext::new(node_id);
            
            // Initial state
            prop_assert!(!fsm.is_associated());
            prop_assert!(!fsm.is_final());
            prop_assert!(!fsm.is_exception());
            
            // Transition to associated
            fsm.state = PfcpState::Associated;
            prop_assert!(fsm.is_associated());
            prop_assert!(!fsm.is_final());
            prop_assert!(!fsm.is_exception());
            
            // Transition to final
            fsm.fini();
            prop_assert!(!fsm.is_associated());
            prop_assert!(fsm.is_final());
            prop_assert!(!fsm.is_exception());
            
            // Set to exception
            fsm.state = PfcpState::Exception;
            prop_assert!(!fsm.is_associated());
            prop_assert!(!fsm.is_final());
            prop_assert!(fsm.is_exception());
        }
    }
}
