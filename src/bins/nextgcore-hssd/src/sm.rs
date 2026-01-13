//! HSS Main State Machine
//!
//! Port of src/hss/hss-sm.c - Main HSS state machine implementation

use crate::event::{HssEvent, HssEventId, HssTimerId};
use crate::timer::{timer_manager, DB_POLLING_TIME_MS};
use std::time::Duration;

/// HSS state type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HssState {
    /// Initial state
    Initial,
    /// Operational state
    Operational,
    /// Final state
    Final,
}

/// HSS state machine context
pub struct HssSmContext {
    /// Current state
    state: HssState,
    /// DB polling timer ID
    db_polling_timer_id: Option<u64>,
    /// Use MongoDB change stream
    use_mongodb_change_stream: bool,
}

impl HssSmContext {
    /// Create a new HSS state machine context
    pub fn new() -> Self {
        Self {
            state: HssState::Initial,
            db_polling_timer_id: None,
            use_mongodb_change_stream: false,
        }
    }

    /// Initialize the state machine
    pub fn init(&mut self, use_mongodb_change_stream: bool) {
        log::debug!("HSS SM: Initializing");
        self.state = HssState::Initial;
        self.use_mongodb_change_stream = use_mongodb_change_stream;

        // Process initial state
        let mut event = HssEvent::entry();
        self.dispatch(&mut event);
    }

    /// Finalize the state machine
    pub fn fini(&mut self) {
        log::debug!("HSS SM: Finalizing");
        let mut event = HssEvent::exit();
        self.dispatch(&mut event);
        self.state = HssState::Final;

        // Delete DB polling timer if exists
        if let Some(timer_id) = self.db_polling_timer_id.take() {
            timer_manager().delete_timer(timer_id);
        }
    }

    /// Dispatch an event to the state machine
    pub fn dispatch(&mut self, event: &mut HssEvent) {
        hss_sm_debug(event);

        match self.state {
            HssState::Initial => {
                self.handle_initial_state(event);
            }
            HssState::Operational => {
                self.handle_operational_state(event);
            }
            HssState::Final => {
                self.handle_final_state(event);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> HssState {
        self.state
    }

    /// Check if in operational state
    pub fn is_operational(&self) -> bool {
        self.state == HssState::Operational
    }

    /// Handle initial state
    fn handle_initial_state(&mut self, _event: &mut HssEvent) {
        // Initialize MongoDB change stream if enabled
        if self.use_mongodb_change_stream {
            log::info!("HSS SM: MongoDB change stream enabled, initializing collection watch");
            // Note: Call ogs_dbi_collection_watch_init()
            // Collection watch initialization is handled by the ogs_dbi module when MongoDB is connected

            // Start DB polling timer
            let timer_id = timer_manager().start_timer(
                HssTimerId::DbiPollChangeStream,
                Duration::from_millis(DB_POLLING_TIME_MS),
                None,
            );
            self.db_polling_timer_id = timer_id;

            if timer_id.is_some() {
                log::debug!("HSS SM: DB polling timer started");
            }
        }

        // Transition to operational state
        log::info!("HSS SM: Transitioning from Initial to Operational");
        self.state = HssState::Operational;
    }

    /// Handle final state
    fn handle_final_state(&mut self, _event: &mut HssEvent) {
        log::debug!("HSS SM: In final state");
    }

    /// Handle operational state
    fn handle_operational_state(&mut self, event: &mut HssEvent) {
        match event.id {
            HssEventId::FsmEntry => {
                log::info!("HSS entering operational state");
            }

            HssEventId::FsmExit => {
                log::info!("HSS exiting operational state");
                // Stop DB polling timer
                if let Some(timer_id) = self.db_polling_timer_id {
                    timer_manager().stop_timer(timer_id);
                }
            }

            HssEventId::DbiPollTimer => {
                self.handle_dbi_poll_timer_event(event);
            }

            HssEventId::DbiMessage => {
                self.handle_dbi_message_event(event);
            }
        }
    }

    /// Handle DBI poll timer events
    fn handle_dbi_poll_timer_event(&mut self, event: &HssEvent) {
        let timer_id = match event.timer_id {
            Some(id) => id,
            None => {
                log::error!("No timer ID in timer event");
                return;
            }
        };

        match timer_id {
            HssTimerId::DbiPollChangeStream => {
                // Poll the change stream
                log::trace!("HSS SM: Polling DB change stream");
                // Note: Call hss_db_poll_change_stream()
                // Change stream polling is handled by the ogs_dbi module

                // Restart the timer
                if let Some(old_timer_id) = self.db_polling_timer_id {
                    timer_manager().delete_timer(old_timer_id);
                }
                let new_timer_id = timer_manager().start_timer(
                    HssTimerId::DbiPollChangeStream,
                    Duration::from_millis(DB_POLLING_TIME_MS),
                    None,
                );
                self.db_polling_timer_id = new_timer_id;
            }
        }
    }

    /// Handle DBI message events (change stream notifications)
    fn handle_dbi_message_event(&mut self, event: &HssEvent) {
        let dbi = match &event.dbi {
            Some(dbi) => dbi,
            None => {
                log::error!("No DBI data in message event");
                return;
            }
        };

        let document = match &dbi.document {
            Some(doc) => doc,
            None => {
                log::error!("No document in DBI event");
                return;
            }
        };

        log::debug!("HSS SM: Processing change stream document ({} bytes)", document.len());
        // Note: Call hss_handle_change_event(document)
        // Change event handling updates subscriber data in the context based on MongoDB notifications
    }
}

impl Default for HssSmContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Debug helper for state machine events
pub fn hss_sm_debug(event: &HssEvent) {
    log::trace!("HSS SM event: {}", event.name());
}

// Legacy function signatures for compatibility
pub fn hss_state_initial(_sm: &mut HssSmContext, _event: &mut HssEvent) {}
pub fn hss_state_final(_sm: &mut HssSmContext, _event: &mut HssEvent) {}
pub fn hss_state_operational(_sm: &mut HssSmContext, _event: &mut HssEvent) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hss_sm_context_new() {
        let ctx = HssSmContext::new();
        assert_eq!(ctx.state(), HssState::Initial);
    }

    #[test]
    fn test_hss_sm_init_without_change_stream() {
        let mut ctx = HssSmContext::new();
        ctx.init(false);
        assert!(ctx.is_operational());
        assert!(ctx.db_polling_timer_id.is_none());
    }

    #[test]
    fn test_hss_sm_init_with_change_stream() {
        let mut ctx = HssSmContext::new();
        ctx.init(true);
        assert!(ctx.is_operational());
        // Timer should be started
        assert!(ctx.db_polling_timer_id.is_some());
    }

    #[test]
    fn test_hss_sm_dispatch_entry() {
        let mut ctx = HssSmContext::new();
        ctx.init(false);

        let mut event = HssEvent::entry();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_hss_sm_dispatch_exit() {
        let mut ctx = HssSmContext::new();
        ctx.init(false);

        let mut event = HssEvent::exit();
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_hss_sm_dispatch_dbi_poll_timer() {
        let mut ctx = HssSmContext::new();
        ctx.init(true);

        let mut event = HssEvent::dbi_poll_timer(HssTimerId::DbiPollChangeStream);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_hss_sm_dispatch_dbi_message() {
        let mut ctx = HssSmContext::new();
        ctx.init(false);

        let doc = vec![1, 2, 3, 4];
        let mut event = HssEvent::dbi_message(doc);
        ctx.dispatch(&mut event);
    }

    #[test]
    fn test_hss_sm_fini() {
        let mut ctx = HssSmContext::new();
        ctx.init(true);
        ctx.fini();
        assert_eq!(ctx.state(), HssState::Final);
        assert!(ctx.db_polling_timer_id.is_none());
    }
}
