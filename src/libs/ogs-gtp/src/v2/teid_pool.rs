//! TEID Pool for GTPv2-C
//!
//! Manages allocation and release of Tunnel Endpoint Identifiers (TEIDs).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use crate::error::{GtpError, GtpResult};

/// TEID Pool for allocating unique TEIDs
#[derive(Debug, Clone)]
pub struct TeidPool {
    /// Atomic counter for TEID allocation
    counter: Arc<AtomicU32>,
    /// Starting TEID value
    base: u32,
    /// Maximum TEID value
    max: u32,
}

impl TeidPool {
    /// Create a new TEID pool with default range (1..0xFFFFFFFF)
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicU32::new(1)),
            base: 1,
            max: 0xFFFFFFFF,
        }
    }

    /// Create a new TEID pool with custom range
    pub fn with_range(base: u32, max: u32) -> GtpResult<Self> {
        if base == 0 {
            return Err(GtpError::InvalidFormat(
                "TEID base must be greater than 0".to_string(),
            ));
        }
        if base >= max {
            return Err(GtpError::InvalidFormat(
                "TEID base must be less than max".to_string(),
            ));
        }
        Ok(Self {
            counter: Arc::new(AtomicU32::new(base)),
            base,
            max,
        })
    }

    /// Allocate a new TEID
    pub fn allocate(&self) -> GtpResult<u32> {
        let teid = self.counter.fetch_add(1, Ordering::SeqCst);
        if teid >= self.max {
            // Wrap around
            self.counter.store(self.base, Ordering::SeqCst);
            // Try one more time
            let teid = self.counter.fetch_add(1, Ordering::SeqCst);
            if teid >= self.max {
                return Err(GtpError::ResourceExhausted(
                    "TEID pool exhausted".to_string(),
                ));
            }
            Ok(teid)
        } else {
            Ok(teid)
        }
    }

    /// Release a TEID (currently a no-op, but kept for API consistency)
    pub fn release(&self, _teid: u32) {
        // In a more sophisticated implementation, this would track released TEIDs
        // and reuse them. For now, we just keep incrementing.
    }

    /// Get the next TEID that will be allocated (without allocating it)
    pub fn peek_next(&self) -> u32 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Reset the TEID pool to the base value
    pub fn reset(&self) {
        self.counter.store(self.base, Ordering::SeqCst);
    }
}

impl Default for TeidPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_teid_pool_allocation() {
        let pool = TeidPool::new();
        let teid1 = pool.allocate().unwrap();
        let teid2 = pool.allocate().unwrap();
        let teid3 = pool.allocate().unwrap();

        assert_eq!(teid1, 1);
        assert_eq!(teid2, 2);
        assert_eq!(teid3, 3);
    }

    #[test]
    fn test_teid_pool_custom_range() {
        let pool = TeidPool::with_range(1000, 2000).unwrap();
        let teid1 = pool.allocate().unwrap();
        assert_eq!(teid1, 1000);

        let teid2 = pool.allocate().unwrap();
        assert_eq!(teid2, 1001);
    }

    #[test]
    fn test_teid_pool_wrap_around() {
        let pool = TeidPool::with_range(1, 5).unwrap();
        let t1 = pool.allocate().unwrap();
        let t2 = pool.allocate().unwrap();
        let t3 = pool.allocate().unwrap();
        let t4 = pool.allocate().unwrap();

        assert_eq!(t1, 1);
        assert_eq!(t2, 2);
        assert_eq!(t3, 3);
        assert_eq!(t4, 4);

        // Next allocation should wrap around to base
        let t5 = pool.allocate().unwrap();
        assert_eq!(t5, 1);
    }

    #[test]
    fn test_teid_pool_peek() {
        let pool = TeidPool::new();
        assert_eq!(pool.peek_next(), 1);

        pool.allocate().unwrap();
        assert_eq!(pool.peek_next(), 2);

        pool.allocate().unwrap();
        assert_eq!(pool.peek_next(), 3);
    }

    #[test]
    fn test_teid_pool_reset() {
        let pool = TeidPool::with_range(100, 200).unwrap();
        pool.allocate().unwrap();
        pool.allocate().unwrap();
        assert_eq!(pool.peek_next(), 102);

        pool.reset();
        assert_eq!(pool.peek_next(), 100);

        let teid = pool.allocate().unwrap();
        assert_eq!(teid, 100);
    }

    #[test]
    fn test_teid_pool_invalid_range() {
        let result = TeidPool::with_range(0, 100);
        assert!(result.is_err());

        let result = TeidPool::with_range(100, 50);
        assert!(result.is_err());
    }
}
