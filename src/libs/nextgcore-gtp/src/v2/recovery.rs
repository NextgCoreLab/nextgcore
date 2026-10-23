//! GTP-C Restart counter comparison (TS 23.007 §18).
//!
//! The Recovery IE carries a peer's 8-bit Restart counter. A receiver compares
//! it with the value it stored for that peer:
//! - nothing stored: store it;
//! - stored smaller than received, "taking the integer roll-over into
//!   account": the peer restarted; store the new value;
//! - stored larger than received, again with roll-over: "a possible race
//!   condition (newer message arriving before the older one). The received new
//!   Restart counter value shall be discarded".
//!
//! "Smaller ... taking the integer roll-over into account" is serial-number
//! arithmetic over the 8-bit space (RFC 1982 §3.2): `received` is ahead of
//! `stored` when `(received - stored) mod 256` is in 1..=127. So 255 -> 0 is a
//! restart, and 4 -> 3 is a stale datagram from the old incarnation.

/// How a received Restart counter relates to the stored one (TS 23.007 §18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOrder {
    /// The received value is ahead of the stored one: the peer restarted. The
    /// received value replaces the stored one.
    Restarted,
    /// The same value: nothing happened.
    Unchanged,
    /// The received value is behind the stored one: a reordered datagram from
    /// an older incarnation. It is discarded and the stored value is kept.
    ///
    /// A distance of exactly 128 has no defined order (RFC 1982 §3.2); it is
    /// classed here too, because acting on it would tear down every live
    /// context on a guess.
    Stale,
}

/// Classify `received` against `stored` (TS 23.007 §18, with roll-over).
pub fn restart_counter_order(stored: u8, received: u8) -> RestartOrder {
    match received.wrapping_sub(stored) {
        0 => RestartOrder::Unchanged,
        1..=127 => RestartOrder::Restarted,
        _ => RestartOrder::Stale,
    }
}

/// Apply TS 23.007 §18 to a stored counter: returns the classification, and
/// updates `stored` only when there was none (`None` -> `Unchanged`, recorded)
/// or the peer restarted. A stale value never overwrites the stored one, so the
/// next message of the current incarnation is not mistaken for a restart.
pub fn note_restart_counter(stored: &mut Option<u8>, received: u8) -> RestartOrder {
    match *stored {
        None => {
            *stored = Some(received);
            RestartOrder::Unchanged
        }
        Some(previous) => {
            let order = restart_counter_order(previous, received);
            if order == RestartOrder::Restarted {
                *stored = Some(received);
            }
            order
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_takes_the_roll_over_into_account() {
        assert_eq!(restart_counter_order(5, 6), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(5, 132), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(5, 5), RestartOrder::Unchanged);
        assert_eq!(restart_counter_order(5, 4), RestartOrder::Stale);
        assert_eq!(restart_counter_order(200, 5), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(5, 200), RestartOrder::Stale);
        // Roll-over: 255 -> 0 is the next incarnation, 0 -> 255 a stale one.
        assert_eq!(restart_counter_order(255, 0), RestartOrder::Restarted);
        assert_eq!(restart_counter_order(0, 255), RestartOrder::Stale);
        // Half-way has no order: not acted on.
        assert_eq!(restart_counter_order(0, 128), RestartOrder::Stale);
    }

    /// #728: 3 -> 4 -> 3 -> 4 is ONE restart; the stale 3 is discarded and does
    /// not overwrite the stored 4.
    #[test]
    fn a_reordered_old_incarnation_counter_is_one_restart_not_three() {
        let mut stored = None;
        let seq: Vec<_> = [3u8, 4, 3, 4, 4]
            .iter()
            .map(|c| note_restart_counter(&mut stored, *c))
            .collect();
        assert_eq!(
            seq,
            [
                RestartOrder::Unchanged,
                RestartOrder::Restarted,
                RestartOrder::Stale,
                RestartOrder::Unchanged,
                RestartOrder::Unchanged,
            ]
        );
        assert_eq!(stored, Some(4));
    }
}
