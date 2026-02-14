//! PIN Context Management
//!
//! Personal IoT Network Manager context (TS 23.542)
//! PEGC (PIN Element Gateway Controller) functionality

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// PIN Element type (TS 23.542 5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinElementType {
    /// PIN Element with Gateway capability (PEGC)
    Gateway,
    /// PIN Element (sensor, actuator, etc.)
    Element,
    /// PIN Management Entity
    ManagementEntity,
}

/// PIN Element status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinElementStatus {
    #[default]
    Registered,
    Active,
    Inactive,
    Deregistered,
}

/// PIN Element registration
#[derive(Debug, Clone)]
pub struct PinElement {
    /// Unique PIN Element ID
    pub element_id: String,
    /// Element type
    pub element_type: PinElementType,
    /// Element status
    pub status: PinElementStatus,
    /// PIN ID this element belongs to
    pub pin_id: String,
    /// Element capabilities
    pub capabilities: Vec<String>,
    /// SUPI of the UE hosting this PIN element (if UE-based)
    pub host_supi: Option<String>,
    /// Gateway element ID (for non-gateway elements)
    pub gateway_id: Option<String>,
    /// Relay path (element IDs forming the relay chain)
    pub relay_path: Vec<String>,
}

/// Personal IoT Network
#[derive(Debug, Clone)]
pub struct PersonalIotNetwork {
    /// Unique PIN ID
    pub pin_id: String,
    /// PIN name
    pub name: String,
    /// Owner SUPI
    pub owner_supi: String,
    /// PIN Gateway element ID (PEGC)
    pub gateway_id: Option<String>,
    /// Member element IDs
    pub member_ids: Vec<String>,
    /// PIN status
    pub active: bool,
}

/// PIN Context
pub struct PinContext {
    /// PIN networks
    pin_networks: RwLock<HashMap<String, PersonalIotNetwork>>,
    /// PIN Elements (element_id -> element)
    elements: RwLock<HashMap<String, PinElement>>,
    /// SUPI -> list of owned PIN IDs
    owner_index: RwLock<HashMap<String, Vec<String>>>,
    /// Next ID generator
    next_id: AtomicUsize,
    /// Maximum PINs
    max_pins: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl PinContext {
    pub fn new() -> Self {
        Self {
            pin_networks: RwLock::new(HashMap::new()),
            elements: RwLock::new(HashMap::new()),
            owner_index: RwLock::new(HashMap::new()),
            next_id: AtomicUsize::new(1),
            max_pins: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_pins: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_pins = max_pins;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("PIN context initialized with max {max_pins} PINs");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut pins) = self.pin_networks.write() { pins.clear(); }
        if let Ok(mut elements) = self.elements.write() { elements.clear(); }
        if let Ok(mut owners) = self.owner_index.write() { owners.clear(); }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("PIN context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    fn alloc_id(&self, prefix: &str) -> String {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        format!("{prefix}-{id}")
    }

    /// Create a new Personal IoT Network
    pub fn pin_create(&self, name: &str, owner_supi: &str) -> Option<PersonalIotNetwork> {
        let mut pins = self.pin_networks.write().ok()?;
        let mut owners = self.owner_index.write().ok()?;

        if pins.len() >= self.max_pins {
            log::error!("Maximum PINs [{}] reached", self.max_pins);
            return None;
        }

        let pin_id = self.alloc_id("pin");
        let pin = PersonalIotNetwork {
            pin_id: pin_id.clone(),
            name: name.to_string(),
            owner_supi: owner_supi.to_string(),
            gateway_id: None,
            member_ids: Vec::new(),
            active: true,
        };

        owners.entry(owner_supi.to_string())
            .or_default()
            .push(pin_id.clone());
        pins.insert(pin_id, pin.clone());

        log::info!("PIN created: {} (owner={})", pin.pin_id, owner_supi);
        Some(pin)
    }

    /// Delete a PIN
    pub fn pin_delete(&self, pin_id: &str) -> Option<PersonalIotNetwork> {
        let mut pins = self.pin_networks.write().ok()?;
        let mut owners = self.owner_index.write().ok()?;
        let mut elements = self.elements.write().ok()?;

        if let Some(pin) = pins.remove(pin_id) {
            // Remove from owner index
            if let Some(owned) = owners.get_mut(&pin.owner_supi) {
                owned.retain(|id| id != pin_id);
            }
            // Remove all member elements
            for elem_id in &pin.member_ids {
                elements.remove(elem_id);
            }
            log::info!("PIN deleted: {pin_id}");
            return Some(pin);
        }
        None
    }

    /// Get a PIN by ID
    pub fn pin_find(&self, pin_id: &str) -> Option<PersonalIotNetwork> {
        self.pin_networks.read().ok()?.get(pin_id).cloned()
    }

    /// List PINs owned by a SUPI
    pub fn pins_by_owner(&self, supi: &str) -> Vec<PersonalIotNetwork> {
        let owners = self.owner_index.read().unwrap();
        let pins = self.pin_networks.read().unwrap();

        owners.get(supi)
            .map(|ids| ids.iter().filter_map(|id| pins.get(id).cloned()).collect())
            .unwrap_or_default()
    }

    /// List all PINs
    pub fn pin_list(&self) -> Vec<PersonalIotNetwork> {
        self.pin_networks.read()
            .map(|p| p.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn pin_count(&self) -> usize {
        self.pin_networks.read().map(|p| p.len()).unwrap_or(0)
    }

    /// Register a PIN Element (TS 23.542 6.2)
    pub fn element_register(
        &self,
        pin_id: &str,
        element_type: PinElementType,
        capabilities: Vec<String>,
        host_supi: Option<String>,
    ) -> Option<PinElement> {
        let mut pins = self.pin_networks.write().ok()?;
        let mut elements = self.elements.write().ok()?;

        let pin = pins.get_mut(pin_id)?;
        let element_id = self.alloc_id("pe");

        let element = PinElement {
            element_id: element_id.clone(),
            element_type,
            status: PinElementStatus::Registered,
            pin_id: pin_id.to_string(),
            capabilities,
            host_supi,
            gateway_id: pin.gateway_id.clone(),
            relay_path: Vec::new(),
        };

        // If this is a gateway element, set it as the PIN gateway
        if element_type == PinElementType::Gateway && pin.gateway_id.is_none() {
            pin.gateway_id = Some(element_id.clone());
        }

        pin.member_ids.push(element_id.clone());
        elements.insert(element_id, element.clone());

        log::info!("PIN Element registered: {} (type={:?}, pin={})", element.element_id, element_type, pin_id);
        Some(element)
    }

    /// Deregister a PIN Element
    pub fn element_deregister(&self, element_id: &str) -> Option<PinElement> {
        let mut pins = self.pin_networks.write().ok()?;
        let mut elements = self.elements.write().ok()?;

        if let Some(element) = elements.remove(element_id) {
            if let Some(pin) = pins.get_mut(&element.pin_id) {
                pin.member_ids.retain(|id| id != element_id);
                if pin.gateway_id.as_deref() == Some(element_id) {
                    pin.gateway_id = None;
                }
            }
            log::info!("PIN Element deregistered: {element_id}");
            return Some(element);
        }
        None
    }

    /// Get a PIN element by ID
    pub fn element_find(&self, element_id: &str) -> Option<PinElement> {
        self.elements.read().ok()?.get(element_id).cloned()
    }

    /// Discover elements in a PIN by capability
    pub fn element_discover(&self, pin_id: &str, capability: Option<&str>) -> Vec<PinElement> {
        let elements = self.elements.read().unwrap();
        let pins = self.pin_networks.read().unwrap();

        let pin = match pins.get(pin_id) {
            Some(p) => p,
            None => return vec![],
        };

        pin.member_ids.iter()
            .filter_map(|id| elements.get(id))
            .filter(|e| {
                match capability {
                    Some(cap) => e.capabilities.iter().any(|c| c == cap),
                    None => true,
                }
            })
            .cloned()
            .collect()
    }

    /// Set up communication relay path between elements
    pub fn element_set_relay(&self, element_id: &str, relay_path: Vec<String>) -> bool {
        if let Ok(mut elements) = self.elements.write() {
            if let Some(element) = elements.get_mut(element_id) {
                element.relay_path = relay_path;
                return true;
            }
        }
        false
    }

    pub fn element_count(&self) -> usize {
        self.elements.read().map(|e| e.len()).unwrap_or(0)
    }
}

impl Default for PinContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global PIN context
static GLOBAL_PIN_CONTEXT: std::sync::OnceLock<Arc<RwLock<PinContext>>> = std::sync::OnceLock::new();

pub fn pin_self() -> Arc<RwLock<PinContext>> {
    GLOBAL_PIN_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(PinContext::new())))
        .clone()
}

pub fn pin_context_init(max_pins: usize) {
    let ctx = pin_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_pins);
    };
}

pub fn pin_context_final() {
    let ctx = pin_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_context_new() {
        let ctx = PinContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.pin_count(), 0);
    }

    #[test]
    fn test_pin_create_delete() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("My Smart Home", "imsi-001010000000001").unwrap();
        assert!(pin.active);
        assert_eq!(ctx.pin_count(), 1);

        let found = ctx.pin_find(&pin.pin_id);
        assert!(found.is_some());

        ctx.pin_delete(&pin.pin_id);
        assert_eq!(ctx.pin_count(), 0);
    }

    #[test]
    fn test_pins_by_owner() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        ctx.pin_create("Home PIN", "imsi-001010000000001");
        ctx.pin_create("Office PIN", "imsi-001010000000001");
        ctx.pin_create("Other PIN", "imsi-001010000000002");

        let owned = ctx.pins_by_owner("imsi-001010000000001");
        assert_eq!(owned.len(), 2);
    }

    #[test]
    fn test_element_register_gateway() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();

        let gw = ctx.element_register(
            &pin.pin_id,
            PinElementType::Gateway,
            vec!["relay".to_string(), "routing".to_string()],
            Some("imsi-001010000000001".to_string()),
        ).unwrap();

        assert_eq!(gw.element_type, PinElementType::Gateway);
        assert_eq!(ctx.element_count(), 1);

        // Gateway should be set on PIN
        let pin = ctx.pin_find(&pin.pin_id).unwrap();
        assert_eq!(pin.gateway_id, Some(gw.element_id.clone()));
    }

    #[test]
    fn test_element_discover() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();

        ctx.element_register(
            &pin.pin_id, PinElementType::Element,
            vec!["temperature".to_string(), "humidity".to_string()],
            None,
        );
        ctx.element_register(
            &pin.pin_id, PinElementType::Element,
            vec!["camera".to_string()],
            None,
        );

        let all = ctx.element_discover(&pin.pin_id, None);
        assert_eq!(all.len(), 2);

        let sensors = ctx.element_discover(&pin.pin_id, Some("temperature"));
        assert_eq!(sensors.len(), 1);

        let cameras = ctx.element_discover(&pin.pin_id, Some("camera"));
        assert_eq!(cameras.len(), 1);
    }

    #[test]
    fn test_element_relay_path() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();
        let elem = ctx.element_register(
            &pin.pin_id, PinElementType::Element,
            vec!["sensor".to_string()], None,
        ).unwrap();

        assert!(ctx.element_set_relay(&elem.element_id, vec!["pe-gw".to_string()]));
        let found = ctx.element_find(&elem.element_id).unwrap();
        assert_eq!(found.relay_path, vec!["pe-gw".to_string()]);
    }
}
