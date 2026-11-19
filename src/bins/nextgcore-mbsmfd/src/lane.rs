//! #1854: Namf_MBSBroadcast ContextCreate and ContextDelete run one at a time per
//! (AMF, TMGI).
//!
//! The AMF's ContextCreate is idempotent on the TMGI (TS 29.518 §5.6; amfd hands
//! a repeat from the same MB-SMF the context it already holds). A session B created
//! on the TMGI of a session A being released could therefore be handed A's
//! context, which A's in-flight ContextDelete then removes, leaving B recorded
//! against a context the AMF no longer holds. In the lane, either A's delete is
//! done first (and B's create gets a fresh context), or B's create and record are
//! done first (and A's delete sees B holding the context and is dropped, R24).
//!
//! A lane lives while someone holds or waits for it, so the map holds only the
//! keys in use. Tests that count lanes hold no lock: each uses its own AMF port.

use crate::context::Tmgi;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Key = (String, u16, Option<Tmgi>);

fn lanes() -> &'static Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>> {
    static LANES: std::sync::OnceLock<Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>> =
        std::sync::OnceLock::new();
    LANES.get_or_init(Default::default)
}

/// A turn in one (AMF, TMGI) lane, held until dropped. Dropping the last holder
/// (or waiter) removes the lane, also when its task is cancelled mid-turn.
pub struct LaneGuard {
    key: Key,
    lane: Arc<tokio::sync::Mutex<()>>,
    turn: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for LaneGuard {
    fn drop(&mut self) {
        self.turn.take();
        let mut map = lanes().lock().unwrap_or_else(|e| e.into_inner());
        // The map's reference and this one: nobody else holds or waits.
        if map
            .get(&self.key)
            .is_some_and(|l| Arc::ptr_eq(l, &self.lane))
            && Arc::strong_count(&self.lane) == 2
        {
            map.remove(&self.key);
        }
    }
}

/// Wait for, then take, the turn of the lane for `tmgi` at the AMF `host`:`port`.
/// An unknown TMGI (`None`) is a lane of its own per AMF.
pub async fn enter(host: &str, port: u16, tmgi: Option<&Tmgi>) -> LaneGuard {
    let key: Key = (host.to_string(), port, tmgi.cloned());
    let lane = {
        let mut map = lanes().lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(map.entry(key.clone()).or_default())
    };
    let mut guard = LaneGuard {
        key,
        lane: Arc::clone(&lane),
        turn: None,
    };
    guard.turn = Some(lane.lock_owned().await);
    guard
}

/// How many lanes exist for the AMF at `port` (tests).
#[cfg(test)]
pub fn count_for_port(port: u16) -> usize {
    lanes()
        .lock()
        .map(|m| m.keys().filter(|k| k.1 == port).count())
        .unwrap_or(0)
}
