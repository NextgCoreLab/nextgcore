//! Ambient IoT Energy Harvesting Simulation (Item #212)
//!
//! Models energy harvesting for zero-energy ambient IoT devices per:
//! - TS 22.369: Communication requirements for Ambient IoT
//! - TR 38.848: Ambient IoT study
//!
//! Supports RF energy harvesting, solar, and piezoelectric models.

use std::collections::HashMap;

// ============================================================================
// Energy Harvesting Models
// ============================================================================

/// Energy harvesting source type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarvestSource {
    /// RF energy from base station signals
    RfHarvest,
    /// Solar/ambient light energy
    Solar,
    /// Piezoelectric (vibration)
    Piezoelectric,
    /// Thermal gradient
    Thermoelectric,
}

/// RF energy harvesting parameters
#[derive(Debug, Clone, Copy)]
pub struct RfHarvestParams {
    /// Receive antenna gain (dBi)
    pub rx_gain_dbi: f64,
    /// RF-to-DC conversion efficiency (0.0-1.0)
    pub conversion_efficiency: f64,
    /// Minimum input power for harvesting (dBm)
    pub sensitivity_dbm: f64,
    /// Operating frequency (MHz)
    pub frequency_mhz: f64,
}

impl Default for RfHarvestParams {
    fn default() -> Self {
        Self {
            rx_gain_dbi: 0.0,
            conversion_efficiency: 0.25,
            sensitivity_dbm: -20.0,
            frequency_mhz: 900.0,
        }
    }
}

/// Solar harvesting parameters
#[derive(Debug, Clone, Copy)]
pub struct SolarParams {
    /// Panel area (cm²)
    pub area_cm2: f64,
    /// Solar cell efficiency (0.0-1.0)
    pub efficiency: f64,
}

impl Default for SolarParams {
    fn default() -> Self {
        Self { area_cm2: 1.0, efficiency: 0.15 }
    }
}

/// Energy harvester model
#[derive(Debug, Clone)]
pub struct EnergyHarvester {
    /// Harvesting source
    pub source: HarvestSource,
    /// Stored energy (microjoules)
    pub stored_energy_uj: f64,
    /// Maximum storage capacity (microjoules)
    pub capacity_uj: f64,
    /// Current harvesting rate (microwatts)
    pub harvest_rate_uw: f64,
    /// Total harvested energy (microjoules)
    pub total_harvested_uj: f64,
    /// RF parameters
    rf_params: RfHarvestParams,
    /// Solar parameters
    solar_params: SolarParams,
}

impl EnergyHarvester {
    /// Creates an RF energy harvester
    pub fn rf_harvester(params: RfHarvestParams, capacity_uj: f64) -> Self {
        Self {
            source: HarvestSource::RfHarvest,
            stored_energy_uj: 0.0,
            capacity_uj,
            harvest_rate_uw: 0.0,
            total_harvested_uj: 0.0,
            rf_params: params,
            solar_params: SolarParams::default(),
        }
    }

    /// Creates a solar energy harvester
    pub fn solar_harvester(params: SolarParams, capacity_uj: f64) -> Self {
        Self {
            source: HarvestSource::Solar,
            stored_energy_uj: 0.0,
            capacity_uj,
            harvest_rate_uw: 0.0,
            total_harvested_uj: 0.0,
            rf_params: RfHarvestParams::default(),
            solar_params: params,
        }
    }

    /// Computes RF harvested power (microwatts) from received power (dBm)
    pub fn compute_rf_harvest_uw(&self, rx_power_dbm: f64) -> f64 {
        if rx_power_dbm < self.rf_params.sensitivity_dbm {
            return 0.0;
        }
        // Convert dBm to milliwatts: P_mW = 10^(P_dBm/10)
        let rx_power_mw = 10.0_f64.powf(rx_power_dbm / 10.0);
        let harvested_mw = rx_power_mw * self.rf_params.conversion_efficiency;
        harvested_mw * 1000.0 // Convert mW to µW
    }

    /// Computes solar harvested power (microwatts) from irradiance (mW/cm²)
    pub fn compute_solar_harvest_uw(&self, irradiance_mw_cm2: f64) -> f64 {
        let power_mw = irradiance_mw_cm2 * self.solar_params.area_cm2 * self.solar_params.efficiency;
        power_mw * 1000.0 // mW to µW
    }

    /// Advances simulation by duration_ms, harvesting energy
    pub fn tick(&mut self, duration_ms: u64, ambient_power_dbm: f64) {
        let harvest_uw = match self.source {
            HarvestSource::RfHarvest => self.compute_rf_harvest_uw(ambient_power_dbm),
            HarvestSource::Solar => {
                // Approximate: map dBm to irradiance roughly
                let irradiance = 10.0_f64.powf(ambient_power_dbm / 10.0).max(0.0);
                self.compute_solar_harvest_uw(irradiance)
            }
            HarvestSource::Piezoelectric => 5.0, // Fixed 5 µW typical
            HarvestSource::Thermoelectric => 2.0, // Fixed 2 µW typical
        };

        self.harvest_rate_uw = harvest_uw;
        let harvested_uj = harvest_uw * (duration_ms as f64) / 1000.0;
        self.stored_energy_uj = (self.stored_energy_uj + harvested_uj).min(self.capacity_uj);
        self.total_harvested_uj += harvested_uj;
    }

    /// Consumes energy for a transmission (returns true if enough energy)
    pub fn consume(&mut self, energy_uj: f64) -> bool {
        if self.stored_energy_uj >= energy_uj {
            self.stored_energy_uj -= energy_uj;
            true
        } else {
            false
        }
    }

    /// Returns charge level as fraction (0.0-1.0)
    pub fn charge_level(&self) -> f64 {
        if self.capacity_uj == 0.0 { return 0.0; }
        self.stored_energy_uj / self.capacity_uj
    }

    /// Whether the device has enough energy for minimal operation
    pub fn is_operational(&self) -> bool {
        self.stored_energy_uj > 1.0 // At least 1 µJ
    }
}

// ============================================================================
// Ambient IoT Device Model
// ============================================================================

/// Ambient IoT device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbientIotState {
    /// Harvesting energy (not operational)
    Harvesting,
    /// Ready to receive/transmit
    Ready,
    /// Performing backscatter communication
    Backscatter,
    /// Deep sleep (insufficient energy)
    DeepSleep,
}

/// Ambient IoT device
pub struct AmbientIotDevice {
    /// Device identifier
    pub device_id: String,
    /// Energy harvester
    pub harvester: EnergyHarvester,
    /// Current state
    pub state: AmbientIotState,
    /// Energy required for one backscatter transmission (µJ)
    pub tx_energy_uj: f64,
    /// Energy required for one receive operation (µJ)
    pub rx_energy_uj: f64,
    /// Transmission count
    pub tx_count: u64,
}

impl AmbientIotDevice {
    /// Creates a new backscatter-type ambient IoT device
    pub fn new_backscatter(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            harvester: EnergyHarvester::rf_harvester(RfHarvestParams::default(), 100.0),
            state: AmbientIotState::DeepSleep,
            tx_energy_uj: 0.5,  // 0.5 µJ per backscatter transmission
            rx_energy_uj: 0.1,  // 0.1 µJ per receive
            tx_count: 0,
        }
    }

    /// Simulation tick
    pub fn tick(&mut self, duration_ms: u64, ambient_power_dbm: f64) {
        self.harvester.tick(duration_ms, ambient_power_dbm);

        self.state = if !self.harvester.is_operational() {
            AmbientIotState::DeepSleep
        } else if self.harvester.stored_energy_uj >= self.tx_energy_uj {
            AmbientIotState::Ready
        } else {
            AmbientIotState::Harvesting
        };
    }

    /// Attempts a backscatter transmission
    pub fn transmit(&mut self) -> bool {
        if self.state == AmbientIotState::Ready && self.harvester.consume(self.tx_energy_uj) {
            self.state = AmbientIotState::Backscatter;
            self.tx_count += 1;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Ambient IoT Fleet Manager
// ============================================================================

/// Manages a fleet of ambient IoT devices
pub struct AmbientIotFleet {
    devices: HashMap<String, AmbientIotDevice>,
}

impl Default for AmbientIotFleet {
    fn default() -> Self {
        Self::new()
    }
}

impl AmbientIotFleet {
    pub fn new() -> Self {
        Self { devices: HashMap::new() }
    }

    pub fn add_device(&mut self, device: AmbientIotDevice) {
        self.devices.insert(device.device_id.clone(), device);
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn operational_count(&self) -> usize {
        self.devices.values().filter(|d| d.harvester.is_operational()).count()
    }

    /// Tick all devices
    pub fn tick_all(&mut self, duration_ms: u64, ambient_power_dbm: f64) {
        for device in self.devices.values_mut() {
            device.tick(duration_ms, ambient_power_dbm);
        }
    }

    pub fn get_device(&self, id: &str) -> Option<&AmbientIotDevice> {
        self.devices.get(id)
    }

    pub fn get_device_mut(&mut self, id: &str) -> Option<&mut AmbientIotDevice> {
        self.devices.get_mut(id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rf_harvest_power() {
        let h = EnergyHarvester::rf_harvester(RfHarvestParams::default(), 100.0);
        let power = h.compute_rf_harvest_uw(-10.0); // -10 dBm = 0.1 mW
        assert!(power > 0.0);
        // 0.1 mW * 0.25 efficiency = 0.025 mW = 25 µW
        assert!((power - 25.0).abs() < 1.0, "Got {power}µW");
    }

    #[test]
    fn test_rf_harvest_below_sensitivity() {
        let h = EnergyHarvester::rf_harvester(RfHarvestParams::default(), 100.0);
        let power = h.compute_rf_harvest_uw(-25.0); // Below -20 dBm sensitivity
        assert_eq!(power, 0.0);
    }

    #[test]
    fn test_solar_harvest() {
        let h = EnergyHarvester::solar_harvester(SolarParams { area_cm2: 2.0, efficiency: 0.2 }, 1000.0);
        let power = h.compute_solar_harvest_uw(10.0); // 10 mW/cm² (bright indoor)
        // 10 * 2.0 * 0.2 = 4 mW = 4000 µW
        assert!((power - 4000.0).abs() < 1.0);
    }

    #[test]
    fn test_energy_harvesting_tick() {
        let mut h = EnergyHarvester::rf_harvester(RfHarvestParams::default(), 100.0);
        assert_eq!(h.stored_energy_uj, 0.0);

        h.tick(1000, -10.0); // 1 second at -10 dBm
        assert!(h.stored_energy_uj > 0.0);
        assert!(h.total_harvested_uj > 0.0);
    }

    #[test]
    fn test_energy_consume() {
        let mut h = EnergyHarvester::rf_harvester(RfHarvestParams::default(), 100.0);
        h.stored_energy_uj = 50.0;

        assert!(h.consume(10.0));
        assert!((h.stored_energy_uj - 40.0).abs() < 0.001);

        assert!(!h.consume(100.0)); // Not enough
    }

    #[test]
    fn test_capacity_limit() {
        let mut h = EnergyHarvester::rf_harvester(RfHarvestParams::default(), 100.0);
        // Harvest a lot
        for _ in 0..1000 {
            h.tick(1000, -5.0);
        }
        assert!(h.stored_energy_uj <= 100.0);
    }

    #[test]
    fn test_ambient_iot_device_lifecycle() {
        let mut device = AmbientIotDevice::new_backscatter("dev-001");
        assert_eq!(device.state, AmbientIotState::DeepSleep);

        // Harvest energy
        for _ in 0..100 {
            device.tick(100, -10.0);
        }
        assert_ne!(device.state, AmbientIotState::DeepSleep);

        // Try to transmit
        if device.state == AmbientIotState::Ready {
            assert!(device.transmit());
            assert_eq!(device.tx_count, 1);
        }
    }

    #[test]
    fn test_fleet_management() {
        let mut fleet = AmbientIotFleet::new();
        fleet.add_device(AmbientIotDevice::new_backscatter("dev-001"));
        fleet.add_device(AmbientIotDevice::new_backscatter("dev-002"));

        assert_eq!(fleet.device_count(), 2);
        assert_eq!(fleet.operational_count(), 0); // No energy yet

        fleet.tick_all(10000, -5.0); // 10 seconds of strong signal
        assert!(fleet.operational_count() > 0);
    }

    #[test]
    fn test_charge_level() {
        let mut h = EnergyHarvester::rf_harvester(RfHarvestParams::default(), 100.0);
        assert_eq!(h.charge_level(), 0.0);
        h.stored_energy_uj = 50.0;
        assert!((h.charge_level() - 0.5).abs() < 0.001);
    }
}
