//! HSS FreeDiameter Path
//!
//! Port of src/hss/hss-fd-path.c - FreeDiameter initialization and stats tracking

use crate::s6a_path;
use crate::cx_path;
use crate::swx_path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Cx interface Diameter statistics
#[derive(Debug, Default)]
pub struct HssDiamStatsCx {
    pub rx_unknown: AtomicU64,
    pub rx_mar: AtomicU64,
    pub rx_mar_error: AtomicU64,
    pub rx_sar: AtomicU64,
    pub rx_sar_error: AtomicU64,
    pub rx_uar: AtomicU64,
    pub rx_uar_error: AtomicU64,
    pub rx_lir: AtomicU64,
    pub rx_lir_error: AtomicU64,
    pub tx_maa: AtomicU64,
    pub tx_saa: AtomicU64,
    pub tx_uaa: AtomicU64,
    pub tx_lia: AtomicU64,
}

impl HssDiamStatsCx {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_rx_unknown(&self) {
        self.rx_unknown.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_mar(&self) {
        self.rx_mar.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_mar_error(&self) {
        self.rx_mar_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_sar(&self) {
        self.rx_sar.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_sar_error(&self) {
        self.rx_sar_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_uar(&self) {
        self.rx_uar.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_uar_error(&self) {
        self.rx_uar_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_lir(&self) {
        self.rx_lir.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_lir_error(&self) {
        self.rx_lir_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_maa(&self) {
        self.tx_maa.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_saa(&self) {
        self.tx_saa.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_uaa(&self) {
        self.tx_uaa.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_lia(&self) {
        self.tx_lia.fetch_add(1, Ordering::Relaxed);
    }
}

/// S6a interface Diameter statistics
#[derive(Debug, Default)]
pub struct HssDiamStatsS6a {
    pub rx_unknown: AtomicU64,
    pub rx_air: AtomicU64,
    pub rx_air_error: AtomicU64,
    pub rx_cla: AtomicU64,
    pub rx_cla_error: AtomicU64,
    pub rx_ida: AtomicU64,
    pub rx_ida_error: AtomicU64,
    pub rx_pur: AtomicU64,
    pub rx_pur_error: AtomicU64,
    pub rx_ulr: AtomicU64,
    pub rx_ulr_error: AtomicU64,
    pub tx_aia: AtomicU64,
    pub tx_clr: AtomicU64,
    pub tx_idr: AtomicU64,
    pub tx_pua: AtomicU64,
    pub tx_ula: AtomicU64,
}

impl HssDiamStatsS6a {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_rx_unknown(&self) {
        self.rx_unknown.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_air(&self) {
        self.rx_air.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_air_error(&self) {
        self.rx_air_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_cla(&self) {
        self.rx_cla.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_cla_error(&self) {
        self.rx_cla_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_ida(&self) {
        self.rx_ida.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_ida_error(&self) {
        self.rx_ida_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_pur(&self) {
        self.rx_pur.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_pur_error(&self) {
        self.rx_pur_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_ulr(&self) {
        self.rx_ulr.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_ulr_error(&self) {
        self.rx_ulr_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_aia(&self) {
        self.tx_aia.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_clr(&self) {
        self.tx_clr.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_idr(&self) {
        self.tx_idr.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_pua(&self) {
        self.tx_pua.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_ula(&self) {
        self.tx_ula.fetch_add(1, Ordering::Relaxed);
    }
}

/// SWx interface Diameter statistics
#[derive(Debug, Default)]
pub struct HssDiamStatsSwx {
    pub rx_unknown: AtomicU64,
    pub rx_mar: AtomicU64,
    pub rx_mar_error: AtomicU64,
    pub rx_sar: AtomicU64,
    pub rx_sar_error: AtomicU64,
    pub tx_maa: AtomicU64,
    pub tx_saa: AtomicU64,
}

impl HssDiamStatsSwx {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_rx_unknown(&self) {
        self.rx_unknown.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_mar(&self) {
        self.rx_mar.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_mar_error(&self) {
        self.rx_mar_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_sar(&self) {
        self.rx_sar.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rx_sar_error(&self) {
        self.rx_sar_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_maa(&self) {
        self.tx_maa.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tx_saa(&self) {
        self.tx_saa.fetch_add(1, Ordering::Relaxed);
    }
}

/// Combined HSS Diameter statistics
#[derive(Debug, Default)]
pub struct HssDiamStats {
    pub cx: HssDiamStatsCx,
    pub s6a: HssDiamStatsS6a,
    pub swx: HssDiamStatsSwx,
}

impl HssDiamStats {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Global Diameter statistics
static GLOBAL_DIAM_STATS: std::sync::OnceLock<Arc<HssDiamStats>> = std::sync::OnceLock::new();

/// Get the global Diameter statistics
pub fn diam_stats() -> Arc<HssDiamStats> {
    GLOBAL_DIAM_STATS
        .get_or_init(|| Arc::new(HssDiamStats::new()))
        .clone()
}

/// Initialize HSS FreeDiameter
pub fn hss_fd_init() -> Result<(), String> {
    log::info!("Initializing HSS FreeDiameter");

    // Initialize S6a interface
    s6a_path::hss_s6a_init()?;

    // Initialize Cx interface
    cx_path::hss_cx_init()?;

    // Initialize SWx interface
    swx_path::hss_swx_init().map_err(|e| e.to_string())?;

    log::info!("HSS FreeDiameter initialized");
    Ok(())
}

/// Finalize HSS FreeDiameter
pub fn hss_fd_final() {
    log::info!("Finalizing HSS FreeDiameter");

    // Finalize S6a interface
    s6a_path::hss_s6a_final();

    // Finalize Cx interface
    cx_path::hss_cx_final();

    // Finalize SWx interface
    swx_path::hss_swx_final();

    log::info!("HSS FreeDiameter finalized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diam_stats_cx() {
        let stats = HssDiamStatsCx::new();
        stats.inc_rx_mar();
        stats.inc_tx_maa();
        assert_eq!(stats.rx_mar.load(Ordering::Relaxed), 1);
        assert_eq!(stats.tx_maa.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_diam_stats_s6a() {
        let stats = HssDiamStatsS6a::new();
        stats.inc_rx_air();
        stats.inc_tx_aia();
        assert_eq!(stats.rx_air.load(Ordering::Relaxed), 1);
        assert_eq!(stats.tx_aia.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_diam_stats_swx() {
        let stats = HssDiamStatsSwx::new();
        stats.inc_rx_mar();
        stats.inc_tx_maa();
        assert_eq!(stats.rx_mar.load(Ordering::Relaxed), 1);
        assert_eq!(stats.tx_maa.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_global_diam_stats() {
        let stats = diam_stats();
        stats.s6a.inc_rx_air();
        assert_eq!(stats.s6a.rx_air.load(Ordering::Relaxed), 1);
    }
}
