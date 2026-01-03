//! PCRF FreeDiameter Path
//!
//! Port of src/pcrf/pcrf-fd-path.c - FreeDiameter initialization and statistics

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Gx interface statistics
#[derive(Debug, Default)]
pub struct PcrfDiamStatsGx {
    /// CCR received count
    pub rx_ccr: AtomicU64,
    /// CCR error count
    pub rx_ccr_error: AtomicU64,
    /// CCA transmitted count
    pub tx_cca: AtomicU64,
    /// RAR transmitted count
    pub tx_rar: AtomicU64,
    /// RAR error count
    pub tx_rar_error: AtomicU64,
    /// RAA received count
    pub rx_raa: AtomicU64,
    /// Unknown message received count
    pub rx_unknown: AtomicU64,
}

impl PcrfDiamStatsGx {
    /// Create new Gx stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.rx_ccr.store(0, Ordering::SeqCst);
        self.rx_ccr_error.store(0, Ordering::SeqCst);
        self.tx_cca.store(0, Ordering::SeqCst);
        self.tx_rar.store(0, Ordering::SeqCst);
        self.tx_rar_error.store(0, Ordering::SeqCst);
        self.rx_raa.store(0, Ordering::SeqCst);
        self.rx_unknown.store(0, Ordering::SeqCst);
    }

    /// Increment CCR received
    pub fn inc_rx_ccr(&self) {
        self.rx_ccr.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment CCR error
    pub fn inc_rx_ccr_error(&self) {
        self.rx_ccr_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment CCA transmitted
    pub fn inc_tx_cca(&self) {
        self.tx_cca.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment RAR transmitted
    pub fn inc_tx_rar(&self) {
        self.tx_rar.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment RAR error
    pub fn inc_tx_rar_error(&self) {
        self.tx_rar_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment RAA received
    pub fn inc_rx_raa(&self) {
        self.rx_raa.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment unknown received
    pub fn inc_rx_unknown(&self) {
        self.rx_unknown.fetch_add(1, Ordering::SeqCst);
    }
}

/// Rx interface statistics
#[derive(Debug, Default)]
pub struct PcrfDiamStatsRx {
    /// AAR received count
    pub rx_aar: AtomicU64,
    /// AAR error count
    pub rx_aar_error: AtomicU64,
    /// AAA transmitted count
    pub tx_aaa: AtomicU64,
    /// STR received count
    pub rx_str: AtomicU64,
    /// STR error count
    pub rx_str_error: AtomicU64,
    /// STA transmitted count
    pub tx_sta: AtomicU64,
    /// ASR transmitted count (Abort-Session-Request)
    pub tx_asr: AtomicU64,
    /// ASA received count (Abort-Session-Answer)
    pub rx_asa: AtomicU64,
    /// Unknown message received count
    pub rx_unknown: AtomicU64,
}

impl PcrfDiamStatsRx {
    /// Create new Rx stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.rx_aar.store(0, Ordering::SeqCst);
        self.rx_aar_error.store(0, Ordering::SeqCst);
        self.tx_aaa.store(0, Ordering::SeqCst);
        self.rx_str.store(0, Ordering::SeqCst);
        self.rx_str_error.store(0, Ordering::SeqCst);
        self.tx_sta.store(0, Ordering::SeqCst);
        self.tx_asr.store(0, Ordering::SeqCst);
        self.rx_asa.store(0, Ordering::SeqCst);
        self.rx_unknown.store(0, Ordering::SeqCst);
    }

    /// Increment AAR received
    pub fn inc_rx_aar(&self) {
        self.rx_aar.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment AAR error
    pub fn inc_rx_aar_error(&self) {
        self.rx_aar_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment AAA transmitted
    pub fn inc_tx_aaa(&self) {
        self.tx_aaa.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment STR received
    pub fn inc_rx_str(&self) {
        self.rx_str.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment STR error
    pub fn inc_rx_str_error(&self) {
        self.rx_str_error.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment STA transmitted
    pub fn inc_tx_sta(&self) {
        self.tx_sta.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment ASR transmitted
    pub fn inc_tx_asr(&self) {
        self.tx_asr.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment ASA received
    pub fn inc_rx_asa(&self) {
        self.rx_asa.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment unknown received
    pub fn inc_rx_unknown(&self) {
        self.rx_unknown.fetch_add(1, Ordering::SeqCst);
    }
}

/// PCRF Diameter statistics
#[derive(Debug, Default)]
pub struct PcrfDiamStats {
    /// Gx interface stats
    pub gx: PcrfDiamStatsGx,
    /// Rx interface stats
    pub rx: PcrfDiamStatsRx,
}

impl PcrfDiamStats {
    /// Create new PCRF Diameter stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.gx.reset();
        self.rx.reset();
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        format!(
            "Gx: CCR={}/{} CCA={} RAR={}/{} RAA={} | Rx: AAR={}/{} AAA={} STR={}/{} STA={} ASR={} ASA={}",
            self.gx.rx_ccr.load(Ordering::SeqCst),
            self.gx.rx_ccr_error.load(Ordering::SeqCst),
            self.gx.tx_cca.load(Ordering::SeqCst),
            self.gx.tx_rar.load(Ordering::SeqCst),
            self.gx.tx_rar_error.load(Ordering::SeqCst),
            self.gx.rx_raa.load(Ordering::SeqCst),
            self.rx.rx_aar.load(Ordering::SeqCst),
            self.rx.rx_aar_error.load(Ordering::SeqCst),
            self.rx.tx_aaa.load(Ordering::SeqCst),
            self.rx.rx_str.load(Ordering::SeqCst),
            self.rx.rx_str_error.load(Ordering::SeqCst),
            self.rx.tx_sta.load(Ordering::SeqCst),
            self.rx.tx_asr.load(Ordering::SeqCst),
            self.rx.rx_asa.load(Ordering::SeqCst),
        )
    }
}

/// Global PCRF Diameter statistics
static GLOBAL_PCRF_DIAM_STATS: std::sync::OnceLock<Arc<PcrfDiamStats>> = std::sync::OnceLock::new();

/// Get global PCRF Diameter statistics
pub fn pcrf_diam_stats() -> Arc<PcrfDiamStats> {
    GLOBAL_PCRF_DIAM_STATS
        .get_or_init(|| Arc::new(PcrfDiamStats::new()))
        .clone()
}

/// Initialize FreeDiameter for PCRF
pub fn pcrf_fd_init() -> Result<(), String> {
    log::info!("Initializing PCRF FreeDiameter");

    // Reset statistics
    pcrf_diam_stats().reset();

    // TODO: Initialize FreeDiameter library
    // - Load configuration
    // - Initialize dictionary
    // - Start FreeDiameter core

    log::info!("PCRF FreeDiameter initialized");
    Ok(())
}

/// Finalize FreeDiameter for PCRF
pub fn pcrf_fd_final() {
    log::info!("Finalizing PCRF FreeDiameter");

    // Log final statistics
    log::info!("PCRF Diameter stats: {}", pcrf_diam_stats().summary());

    // TODO: Shutdown FreeDiameter library
    // - Stop FreeDiameter core
    // - Cleanup resources

    log::info!("PCRF FreeDiameter finalized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gx_stats_new() {
        let stats = PcrfDiamStatsGx::new();
        assert_eq!(stats.rx_ccr.load(Ordering::SeqCst), 0);
        assert_eq!(stats.tx_cca.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_gx_stats_increment() {
        let stats = PcrfDiamStatsGx::new();

        stats.inc_rx_ccr();
        assert_eq!(stats.rx_ccr.load(Ordering::SeqCst), 1);

        stats.inc_tx_cca();
        assert_eq!(stats.tx_cca.load(Ordering::SeqCst), 1);

        stats.inc_tx_rar();
        stats.inc_rx_raa();
        assert_eq!(stats.tx_rar.load(Ordering::SeqCst), 1);
        assert_eq!(stats.rx_raa.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_gx_stats_reset() {
        let stats = PcrfDiamStatsGx::new();

        stats.inc_rx_ccr();
        stats.inc_tx_cca();
        stats.reset();

        assert_eq!(stats.rx_ccr.load(Ordering::SeqCst), 0);
        assert_eq!(stats.tx_cca.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_rx_stats_new() {
        let stats = PcrfDiamStatsRx::new();
        assert_eq!(stats.rx_aar.load(Ordering::SeqCst), 0);
        assert_eq!(stats.tx_aaa.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_rx_stats_increment() {
        let stats = PcrfDiamStatsRx::new();

        stats.inc_rx_aar();
        assert_eq!(stats.rx_aar.load(Ordering::SeqCst), 1);

        stats.inc_tx_aaa();
        assert_eq!(stats.tx_aaa.load(Ordering::SeqCst), 1);

        stats.inc_rx_str();
        stats.inc_tx_sta();
        assert_eq!(stats.rx_str.load(Ordering::SeqCst), 1);
        assert_eq!(stats.tx_sta.load(Ordering::SeqCst), 1);

        stats.inc_tx_asr();
        stats.inc_rx_asa();
        assert_eq!(stats.tx_asr.load(Ordering::SeqCst), 1);
        assert_eq!(stats.rx_asa.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_pcrf_diam_stats() {
        let stats = PcrfDiamStats::new();

        stats.gx.inc_rx_ccr();
        stats.gx.inc_tx_cca();
        stats.rx.inc_rx_aar();
        stats.rx.inc_tx_aaa();

        let summary = stats.summary();
        assert!(summary.contains("CCR=1"));
        assert!(summary.contains("CCA=1"));
        assert!(summary.contains("AAR=1"));
        assert!(summary.contains("AAA=1"));
    }

    #[test]
    fn test_pcrf_fd_init_final() {
        // Test initialization
        let result = pcrf_fd_init();
        assert!(result.is_ok());

        // Test finalization
        pcrf_fd_final();
    }
}
