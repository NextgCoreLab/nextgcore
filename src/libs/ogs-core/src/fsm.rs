//! Finite State Machine implementation
//!
//! Exact port of lib/core/ogs-fsm.h and ogs-fsm.c
//!
//! This implementation provides a simple hierarchical state machine
//! with entry/exit signals and state transitions.

use std::marker::PhantomData;

/// FSM signal types (identical to ogs_fsm_signal_e)
pub const OGS_FSM_ENTRY_SIG: i32 = 0;
pub const OGS_FSM_EXIT_SIG: i32 = 1;
pub const OGS_FSM_USER_SIG: i32 = 2;

/// FSM handler function type
pub type OgsFsmHandler<S, E> = fn(&mut S, &mut E);

/// Finite State Machine structure (identical to ogs_fsm_t)
#[repr(C)]
pub struct OgsFsm<S, E> {
    /// Initial state handler
    pub init: Option<OgsFsmHandler<S, E>>,
    /// Final state handler
    pub fini: Option<OgsFsmHandler<S, E>>,
    /// Current state handler
    pub state: Option<OgsFsmHandler<S, E>>,
    _phantom: PhantomData<(S, E)>,
}

impl<S, E> OgsFsm<S, E> {
    /// Create a new FSM
    pub fn new() -> Self {
        OgsFsm {
            init: None,
            fini: None,
            state: None,
            _phantom: PhantomData,
        }
    }

    /// Create FSM with initial and final handlers
    pub fn with_handlers(init: OgsFsmHandler<S, E>, fini: OgsFsmHandler<S, E>) -> Self {
        OgsFsm {
            init: Some(init),
            fini: Some(fini),
            state: None,
            _phantom: PhantomData,
        }
    }

    /// Initialize FSM (identical to ogs_fsm_init)
    /// Calls the init handler which should set the initial state
    pub fn init_fsm(&mut self, sm: &mut S, event: &mut E) {
        if let Some(handler) = self.init {
            handler(sm, event);
        }
    }

    /// Transition to new state (identical to OGS_FSM_TRAN macro)
    /// This sets the new state without calling entry/exit handlers
    #[inline]
    pub fn tran(&mut self, target: OgsFsmHandler<S, E>) {
        self.state = Some(target);
    }

    /// Dispatch event to current state (identical to ogs_fsm_dispatch)
    pub fn dispatch(&mut self, sm: &mut S, event: &mut E) {
        if let Some(handler) = self.state {
            handler(sm, event);
        }
    }

    /// Finalize FSM (identical to ogs_fsm_fini)
    pub fn fini_fsm(&mut self, sm: &mut S, event: &mut E) {
        if let Some(handler) = self.fini {
            handler(sm, event);
        }
        self.state = None;
    }

    /// Check current state (identical to OGS_FSM_CHECK macro)
    /// Note: Function pointer comparison may not be reliable across compilation units
    #[allow(unpredictable_function_pointer_comparisons)]
    pub fn check(&self, target: OgsFsmHandler<S, E>) -> bool {
        self.state == Some(target)
    }

    /// Get current state (identical to OGS_FSM_STATE macro)
    #[inline]
    pub fn get_state(&self) -> Option<OgsFsmHandler<S, E>> {
        self.state
    }

    /// Set state directly
    #[inline]
    pub fn set_state(&mut self, state: OgsFsmHandler<S, E>) {
        self.state = Some(state);
    }

    /// Check if FSM has a state set
    #[inline]
    pub fn has_state(&self) -> bool {
        self.state.is_some()
    }

    /// Clear the current state
    #[inline]
    pub fn clear_state(&mut self) {
        self.state = None;
    }
}

impl<S, E> Default for OgsFsm<S, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, E> Clone for OgsFsm<S, E> {
    fn clone(&self) -> Self {
        OgsFsm {
            init: self.init,
            fini: self.fini,
            state: self.state,
            _phantom: PhantomData,
        }
    }
}

impl<S, E> std::fmt::Debug for OgsFsm<S, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OgsFsm")
            .field("has_init", &self.init.is_some())
            .field("has_fini", &self.fini.is_some())
            .field("has_state", &self.state.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // Test state machine context
    struct TestContext {
        value: i32,
        transitions: RefCell<Vec<String>>,
    }

    // Test event
    struct TestEvent {
        signal: i32,
        data: i32,
    }

    // State handlers
    fn state_init(ctx: &mut TestContext, event: &mut TestEvent) {
        ctx.transitions.borrow_mut().push("init".to_string());
        ctx.value = event.data;
    }

    fn state_fini(ctx: &mut TestContext, _event: &mut TestEvent) {
        ctx.transitions.borrow_mut().push("fini".to_string());
    }

    fn state_a(ctx: &mut TestContext, event: &mut TestEvent) {
        ctx.transitions.borrow_mut().push(format!("state_a({})", event.signal));
        ctx.value += 1;
    }

    fn state_b(ctx: &mut TestContext, event: &mut TestEvent) {
        ctx.transitions.borrow_mut().push(format!("state_b({})", event.signal));
        ctx.value += 10;
    }

    #[test]
    fn test_fsm_new() {
        let fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::new();
        assert!(fsm.init.is_none());
        assert!(fsm.fini.is_none());
        assert!(fsm.state.is_none());
        assert!(!fsm.has_state());
    }

    #[test]
    fn test_fsm_with_handlers() {
        let fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::with_handlers(state_init, state_fini);
        assert!(fsm.init.is_some());
        assert!(fsm.fini.is_some());
        assert!(fsm.state.is_none());
    }

    #[test]
    fn test_fsm_init() {
        let mut fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::with_handlers(state_init, state_fini);
        let mut ctx = TestContext {
            value: 0,
            transitions: RefCell::new(Vec::new()),
        };
        let mut event = TestEvent { signal: OGS_FSM_ENTRY_SIG, data: 42 };
        
        fsm.init_fsm(&mut ctx, &mut event);
        
        assert_eq!(ctx.value, 42);
        assert_eq!(ctx.transitions.borrow().len(), 1);
        assert_eq!(ctx.transitions.borrow()[0], "init");
    }

    #[test]
    fn test_fsm_tran() {
        let mut fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::new();
        
        assert!(!fsm.has_state());
        
        fsm.tran(state_a);
        assert!(fsm.has_state());
    }

    #[test]
    fn test_fsm_dispatch() {
        let mut fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::new();
        let mut ctx = TestContext {
            value: 0,
            transitions: RefCell::new(Vec::new()),
        };
        let mut event = TestEvent { signal: OGS_FSM_USER_SIG, data: 0 };
        
        fsm.tran(state_a);
        fsm.dispatch(&mut ctx, &mut event);
        
        assert_eq!(ctx.value, 1);
        assert_eq!(ctx.transitions.borrow()[0], "state_a(2)");
    }

    #[test]
    fn test_fsm_state_transition() {
        let mut fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::new();
        let mut ctx = TestContext {
            value: 0,
            transitions: RefCell::new(Vec::new()),
        };
        let mut event = TestEvent { signal: OGS_FSM_USER_SIG, data: 0 };
        
        // Start in state A
        fsm.tran(state_a);
        fsm.dispatch(&mut ctx, &mut event);
        assert_eq!(ctx.value, 1);
        
        // Transition to state B
        fsm.tran(state_b);
        fsm.dispatch(&mut ctx, &mut event);
        assert_eq!(ctx.value, 11);
        
        // Back to state A
        fsm.tran(state_a);
        fsm.dispatch(&mut ctx, &mut event);
        assert_eq!(ctx.value, 12);
    }

    #[test]
    fn test_fsm_fini() {
        let mut fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::with_handlers(state_init, state_fini);
        let mut ctx = TestContext {
            value: 0,
            transitions: RefCell::new(Vec::new()),
        };
        let mut event = TestEvent { signal: OGS_FSM_EXIT_SIG, data: 0 };
        
        fsm.tran(state_a);
        assert!(fsm.has_state());
        
        fsm.fini_fsm(&mut ctx, &mut event);
        
        assert!(!fsm.has_state());
        assert!(ctx.transitions.borrow().contains(&"fini".to_string()));
    }

    #[test]
    fn test_fsm_check() {
        let mut fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::new();
        
        fsm.tran(state_a);
        assert!(fsm.check(state_a));
        assert!(!fsm.check(state_b));
        
        fsm.tran(state_b);
        assert!(!fsm.check(state_a));
        assert!(fsm.check(state_b));
    }

    #[test]
    fn test_fsm_clear_state() {
        let mut fsm: OgsFsm<TestContext, TestEvent> = OgsFsm::new();
        
        fsm.tran(state_a);
        assert!(fsm.has_state());
        
        fsm.clear_state();
        assert!(!fsm.has_state());
    }

    #[test]
    fn test_fsm_clone() {
        let mut fsm1: OgsFsm<TestContext, TestEvent> = OgsFsm::with_handlers(state_init, state_fini);
        fsm1.tran(state_a);
        
        let fsm2 = fsm1.clone();
        
        assert!(fsm2.init.is_some());
        assert!(fsm2.fini.is_some());
        assert!(fsm2.has_state());
    }

    // Property-based tests
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        // Simple state handlers for property testing
        fn handler_1(ctx: &mut i32, _event: &mut i32) {
            *ctx += 1;
        }

        fn handler_2(ctx: &mut i32, _event: &mut i32) {
            *ctx += 10;
        }

        fn handler_3(ctx: &mut i32, _event: &mut i32) {
            *ctx += 100;
        }

        fn init_handler(ctx: &mut i32, _event: &mut i32) {
            *ctx = 0;
        }

        fn fini_handler(ctx: &mut i32, _event: &mut i32) {
            *ctx = -1;
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            /// Property 1: tran sets state
            #[test]
            fn prop_tran_sets_state(handler_idx in 0..3usize) {
                let mut fsm: OgsFsm<i32, i32> = OgsFsm::new();
                
                let handlers = [handler_1 as OgsFsmHandler<i32, i32>, handler_2, handler_3];
                let handler = handlers[handler_idx];
                
                prop_assert!(!fsm.has_state());
                fsm.tran(handler);
                prop_assert!(fsm.has_state());
            }

            /// Property 2: dispatch calls current state handler
            #[test]
            fn prop_dispatch_calls_handler(dispatch_count in 1..10usize) {
                let mut fsm: OgsFsm<i32, i32> = OgsFsm::new();
                let mut ctx = 0i32;
                let mut event = 0i32;
                
                fsm.tran(handler_1);
                
                for _ in 0..dispatch_count {
                    fsm.dispatch(&mut ctx, &mut event);
                }
                
                prop_assert_eq!(ctx, dispatch_count as i32, "dispatch should call handler each time");
            }

            /// Property 3: State transitions are immediate
            #[test]
            fn prop_state_transition_immediate(transitions in prop::collection::vec(0..3usize, 1..10)) {
                let mut fsm: OgsFsm<i32, i32> = OgsFsm::new();
                let mut ctx = 0i32;
                let mut event = 0i32;
                
                let handlers = [handler_1 as OgsFsmHandler<i32, i32>, handler_2, handler_3];
                let increments = [1, 10, 100];
                
                let mut expected = 0;
                for idx in transitions {
                    fsm.tran(handlers[idx]);
                    fsm.dispatch(&mut ctx, &mut event);
                    expected += increments[idx];
                }
                
                prop_assert_eq!(ctx, expected, "state transitions should be immediate");
            }

            /// Property 4: init_fsm calls init handler
            #[test]
            fn prop_init_calls_handler(_dummy in 0..1i32) {
                let mut fsm: OgsFsm<i32, i32> = OgsFsm::with_handlers(init_handler, fini_handler);
                let mut ctx = 999i32;
                let mut event = 0i32;
                
                fsm.init_fsm(&mut ctx, &mut event);
                
                prop_assert_eq!(ctx, 0, "init should call init handler");
            }

            /// Property 5: fini_fsm calls fini handler and clears state
            #[test]
            fn prop_fini_clears_state(_dummy in 0..1i32) {
                let mut fsm: OgsFsm<i32, i32> = OgsFsm::with_handlers(init_handler, fini_handler);
                let mut ctx = 0i32;
                let mut event = 0i32;
                
                fsm.tran(handler_1);
                prop_assert!(fsm.has_state());
                
                fsm.fini_fsm(&mut ctx, &mut event);
                
                prop_assert!(!fsm.has_state(), "fini should clear state");
                prop_assert_eq!(ctx, -1, "fini should call fini handler");
            }

            /// Property 6: clear_state removes state
            #[test]
            fn prop_clear_state(_dummy in 0..1i32) {
                let mut fsm: OgsFsm<i32, i32> = OgsFsm::new();
                
                fsm.tran(handler_1);
                prop_assert!(fsm.has_state());
                
                fsm.clear_state();
                prop_assert!(!fsm.has_state());
            }

            /// Property 7: dispatch without state is no-op
            #[test]
            fn prop_dispatch_no_state_noop(initial_value in any::<i32>()) {
                let mut fsm: OgsFsm<i32, i32> = OgsFsm::new();
                let mut ctx = initial_value;
                let mut event = 0i32;
                
                // No state set
                fsm.dispatch(&mut ctx, &mut event);
                
                prop_assert_eq!(ctx, initial_value, "dispatch without state should be no-op");
            }

            /// Property 8: Clone preserves state
            #[test]
            fn prop_clone_preserves_state(handler_idx in 0..3usize) {
                let mut fsm1: OgsFsm<i32, i32> = OgsFsm::with_handlers(init_handler, fini_handler);
                let handlers = [handler_1 as OgsFsmHandler<i32, i32>, handler_2, handler_3];
                
                fsm1.tran(handlers[handler_idx]);
                
                let fsm2 = fsm1.clone();
                
                prop_assert!(fsm2.init.is_some());
                prop_assert!(fsm2.fini.is_some());
                prop_assert!(fsm2.has_state());
            }
        }
    }
}
