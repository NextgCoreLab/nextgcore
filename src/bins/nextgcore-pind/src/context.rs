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

/// PIN Element role (TS 23.542 §5.2)
///
/// Mapping from `PinElementType`:
///   - `Gateway`          → `Pegc`   (carries relay/routing capability)
///   - `ManagementEntity` → `Pemc`   (carries management capability)
///   - `Element`          → `Regular` (plain sensor/actuator, no special privilege)
///
/// A separate enum is kept (rather than just using `PinElementType`) so that
/// future spec revisions can introduce new types without silently expanding
/// role semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinElementRole {
    /// PIN Element with Management Capability — may perform PIN management ops.
    Pemc,
    /// PIN Element with Gateway Capability — may have relay semantics.
    Pegc,
    /// Plain element — no elevated privilege.
    Regular,
}

impl PinElementRole {
    /// Derive the role from the element type.
    pub fn from_type(element_type: PinElementType) -> Self {
        match element_type {
            PinElementType::ManagementEntity => PinElementRole::Pemc,
            PinElementType::Gateway => PinElementRole::Pegc,
            PinElementType::Element => PinElementRole::Regular,
        }
    }
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
    /// Element role (derived from type at registration time)
    pub role: PinElementRole,
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

/// Default PIN lifetime (24h) used when no CLI/config override is supplied.
pub const DEFAULT_PIN_LIFETIME_SECS: u64 = 86_400;
/// Default per-PIN heartbeat timer (seconds) used when no override is supplied.
pub const DEFAULT_HEARTBEAT_SECS: u64 = 30;

/// Current wall-clock time in seconds since the Unix epoch.
///
/// Falls back to `0` on the (practically impossible) pre-epoch clock so this
/// never panics on a request-serving path.
fn now_epoch_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    /// Expiration time (epoch seconds). Mandatory PIN-create response IE per
    /// TS 23.542 §8.5.2.3.3 Table 8.5.2.3.3-1.
    pub expiration_time: u64,
    /// Heartbeat timer (seconds). Mandatory PIN-create response IE per
    /// TS 23.542 §8.5.2.3.3 Table 8.5.2.3.3-1. (Liveness reaping that consumes
    /// this timer is tracked under PIND-09, deferred.)
    pub heartbeat_timer: u64,
}

/// Error type for authorization-gated context operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinContextError {
    /// The caller is not the PIN owner and has no PEMC privilege.
    /// Cause: `PEMC_REQUIRES_OWNER`
    PemcRequiresOwner,
    /// The target element exists but is not a PEGC.
    /// Cause: `RELAY_ONLY_FOR_PEGC`
    RelayOnlyForPegc,
    /// The requested resource (PIN or element) was not found.
    NotFound,
}

impl PinContextError {
    /// A machine-readable cause string for ProblemDetails.
    pub fn cause(&self) -> &'static str {
        match self {
            PinContextError::PemcRequiresOwner => "PEMC_REQUIRES_OWNER",
            PinContextError::RelayOnlyForPegc => "RELAY_ONLY_FOR_PEGC",
            PinContextError::NotFound => "NOT_FOUND",
        }
    }

    /// A human-readable detail string.
    pub fn detail(&self) -> &'static str {
        match self {
            PinContextError::PemcRequiresOwner => {
                "Registering a PEMC (management) element requires the caller \
                 to be the PIN owner or an already-registered PEMC of this PIN"
            }
            PinContextError::RelayOnlyForPegc => {
                "A relay path may only be set on a PEGC (gateway) element"
            }
            PinContextError::NotFound => "The requested resource was not found",
        }
    }
}

/// Authorization predicate shared by the management-gated operations
/// (PEMC registration, PIN delete, element deregister).
///
/// A caller is authorized for a PIN when it is either the PIN owner, or a
/// SUPI that hosts an already-registered PEMC (management) element of that
/// PIN. Mirrors TS 23.542 §8.5.3.2.1 / §8.5.8.2.3 (owner-or-PEMC).
fn caller_is_owner_or_pemc(
    pin: &PersonalIotNetwork,
    caller: &str,
    elements: &HashMap<String, PinElement>,
) -> bool {
    if !caller.is_empty() && caller == pin.owner_supi {
        return true;
    }
    if caller.is_empty() {
        return false;
    }
    pin.member_ids.iter().any(|id| {
        elements
            .get(id)
            .map(|e| {
                e.role == PinElementRole::Pemc && e.host_supi.as_deref() == Some(caller)
            })
            .unwrap_or(false)
    })
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
    /// Default PIN lifetime (seconds) applied at create (PIND-03).
    default_pin_lifetime_secs: u64,
    /// Default per-PIN heartbeat timer (seconds) applied at create (PIND-03).
    default_heartbeat_secs: u64,
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
            default_pin_lifetime_secs: DEFAULT_PIN_LIFETIME_SECS,
            default_heartbeat_secs: DEFAULT_HEARTBEAT_SECS,
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

    /// Configure the lifecycle defaults assigned to a PIN at create time
    /// (PIND-03). Threaded from the `--default-pin-lifetime-secs` /
    /// `--default-heartbeat-secs` CLI flags.
    pub fn set_lifecycle_defaults(&mut self, lifetime_secs: u64, heartbeat_secs: u64) {
        self.default_pin_lifetime_secs = lifetime_secs;
        self.default_heartbeat_secs = heartbeat_secs;
    }

    /// Default PIN lifetime (seconds) assigned at create.
    pub fn default_pin_lifetime_secs(&self) -> u64 {
        self.default_pin_lifetime_secs
    }

    /// Default per-PIN heartbeat timer (seconds) assigned at create.
    pub fn default_heartbeat_secs(&self) -> u64 {
        self.default_heartbeat_secs
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut pins) = self.pin_networks.write() {
            pins.clear();
        }
        if let Ok(mut elements) = self.elements.write() {
            elements.clear();
        }
        if let Ok(mut owners) = self.owner_index.write() {
            owners.clear();
        }
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
            // PIND-03: mandatory Expiration time + Heartbeat Timer assigned at
            // create from the configured lifecycle defaults.
            expiration_time: now_epoch_secs().saturating_add(self.default_pin_lifetime_secs),
            heartbeat_timer: self.default_heartbeat_secs,
        };

        owners
            .entry(owner_supi.to_string())
            .or_default()
            .push(pin_id.clone());
        pins.insert(pin_id, pin.clone());

        log::info!("PIN created: {} (owner={})", pin.pin_id, owner_supi);
        Some(pin)
    }

    /// Delete a PIN (PIND-04: authorized — caller must be the PIN owner or a
    /// registered PEMC of that PIN, per TS 23.542 §8.5.3.2.1).
    ///
    /// Returns:
    ///   - `Ok(pin)` on authorized delete (cascade-removes member elements).
    ///   - `Err(PinContextError::NotFound)` when `pin_id` does not exist.
    ///   - `Err(PinContextError::PemcRequiresOwner)` on authorization failure.
    pub fn pin_delete(
        &self,
        pin_id: &str,
        caller_supi: Option<&str>,
    ) -> Result<PersonalIotNetwork, PinContextError> {
        let mut pins = self.pin_networks.write().map_err(|_| PinContextError::NotFound)?;
        let mut owners = self.owner_index.write().map_err(|_| PinContextError::NotFound)?;
        let mut elements = self.elements.write().map_err(|_| PinContextError::NotFound)?;

        // Authorize against the current state (immutable borrow), then mutate.
        {
            let pin = pins.get(pin_id).ok_or(PinContextError::NotFound)?;
            if !caller_is_owner_or_pemc(pin, caller_supi.unwrap_or(""), &elements) {
                log::warn!(
                    "PIN delete denied: caller={:?} is not owner/PEMC of PIN {} (owner={})",
                    caller_supi,
                    pin_id,
                    pin.owner_supi
                );
                return Err(PinContextError::PemcRequiresOwner);
            }
        }

        let pin = pins.remove(pin_id).ok_or(PinContextError::NotFound)?;
        // Remove from owner index
        if let Some(owned) = owners.get_mut(&pin.owner_supi) {
            owned.retain(|id| id != pin_id);
        }
        // Remove all member elements
        for elem_id in &pin.member_ids {
            elements.remove(elem_id);
        }
        log::info!("PIN deleted: {pin_id}");
        Ok(pin)
    }

    /// Get a PIN by ID
    pub fn pin_find(&self, pin_id: &str) -> Option<PersonalIotNetwork> {
        self.pin_networks.read().ok()?.get(pin_id).cloned()
    }

    /// List PINs owned by a SUPI.
    ///
    /// PIND-00: never panics on a request-serving path — an absent owner
    /// yields an empty `Vec`, and a poisoned lock is logged and treated as
    /// empty rather than unwinding the handler.
    pub fn pins_by_owner(&self, supi: &str) -> Vec<PersonalIotNetwork> {
        let owners = match self.owner_index.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("pins_by_owner: owner_index lock poisoned; returning empty");
                return Vec::new();
            }
        };
        let pins = match self.pin_networks.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("pins_by_owner: pin_networks lock poisoned; returning empty");
                return Vec::new();
            }
        };

        owners
            .get(supi)
            .map(|ids| ids.iter().filter_map(|id| pins.get(id).cloned()).collect())
            .unwrap_or_default()
    }

    /// List all PINs.
    ///
    /// PIND-00: a poisoned lock returns an empty `Vec` instead of panicking.
    pub fn pin_list(&self) -> Vec<PersonalIotNetwork> {
        self.pin_networks
            .read()
            .map(|p| p.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn pin_count(&self) -> usize {
        self.pin_networks.read().map(|p| p.len()).unwrap_or(0)
    }

    /// Register a PIN Element (TS 23.542 6.2).
    ///
    /// Authorization rule: registering a PEMC (`ManagementEntity`) element
    /// requires `caller_supi` to be either the PIN owner or an already-
    /// registered PEMC member of the same PIN.  All other element types are
    /// unrestricted.
    ///
    /// Returns `Err(PinContextError::NotFound)` when `pin_id` does not exist.
    /// Returns `Err(PinContextError::PemcRequiresOwner)` on role violation.
    pub fn element_register(
        &self,
        pin_id: &str,
        element_type: PinElementType,
        capabilities: Vec<String>,
        host_supi: Option<String>,
        caller_supi: Option<&str>,
    ) -> Result<PinElement, PinContextError> {
        let mut pins = self.pin_networks.write().map_err(|_| PinContextError::NotFound)?;
        let mut elements = self.elements.write().map_err(|_| PinContextError::NotFound)?;

        let pin = pins.get_mut(pin_id).ok_or(PinContextError::NotFound)?;

        // Authorization: only the PIN owner or an existing PEMC may register
        // a new PEMC (management) element.
        if element_type == PinElementType::ManagementEntity
            && !caller_is_owner_or_pemc(pin, caller_supi.unwrap_or(""), &elements)
        {
            log::warn!(
                "PEMC registration denied: caller={:?} is not owner of PIN {} (owner={})",
                caller_supi,
                pin_id,
                pin.owner_supi
            );
            return Err(PinContextError::PemcRequiresOwner);
        }

        let element_id = self.alloc_id("pe");
        let role = PinElementRole::from_type(element_type);

        let element = PinElement {
            element_id: element_id.clone(),
            element_type,
            role,
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

        log::info!(
            "PIN Element registered: {} (type={:?}, role={:?}, pin={})",
            element.element_id,
            element_type,
            role,
            pin_id
        );
        Ok(element)
    }

    /// Deregister a PIN Element (PIND-04: authorized — caller must be the
    /// owner or a registered PEMC of the element's PIN, per TS 23.542
    /// §8.5.8.2.3).
    ///
    /// Returns:
    ///   - `Ok(element)` on authorized deregister.
    ///   - `Err(PinContextError::NotFound)` when the element does not exist.
    ///   - `Err(PinContextError::PemcRequiresOwner)` on authorization failure.
    pub fn element_deregister(
        &self,
        element_id: &str,
        caller_supi: Option<&str>,
    ) -> Result<PinElement, PinContextError> {
        let mut pins = self.pin_networks.write().map_err(|_| PinContextError::NotFound)?;
        let mut elements = self.elements.write().map_err(|_| PinContextError::NotFound)?;

        // Resolve the element's owning PIN, then authorize against it.
        let pin_id = match elements.get(element_id) {
            Some(e) => e.pin_id.clone(),
            None => return Err(PinContextError::NotFound),
        };
        {
            // A dangling element whose PIN no longer exists: treat as not found.
            let pin = pins.get(&pin_id).ok_or(PinContextError::NotFound)?;
            if !caller_is_owner_or_pemc(pin, caller_supi.unwrap_or(""), &elements) {
                log::warn!(
                    "Element deregister denied: caller={:?} is not owner/PEMC of PIN {} (element={})",
                    caller_supi,
                    pin_id,
                    element_id
                );
                return Err(PinContextError::PemcRequiresOwner);
            }
        }

        let element = elements.remove(element_id).ok_or(PinContextError::NotFound)?;
        if let Some(pin) = pins.get_mut(&element.pin_id) {
            pin.member_ids.retain(|id| id != element_id);
            if pin.gateway_id.as_deref() == Some(element_id) {
                pin.gateway_id = None;
            }
        }
        log::info!("PIN Element deregistered: {element_id}");
        Ok(element)
    }

    /// Get a PIN element by ID
    pub fn element_find(&self, element_id: &str) -> Option<PinElement> {
        self.elements.read().ok()?.get(element_id).cloned()
    }

    /// Discover elements in a PIN by capability.
    ///
    /// PIND-00: a poisoned lock returns an empty `Vec` instead of panicking.
    pub fn element_discover(&self, pin_id: &str, capability: Option<&str>) -> Vec<PinElement> {
        let elements = match self.elements.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("element_discover: elements lock poisoned; returning empty");
                return Vec::new();
            }
        };
        let pins = match self.pin_networks.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("element_discover: pin_networks lock poisoned; returning empty");
                return Vec::new();
            }
        };

        let pin = match pins.get(pin_id) {
            Some(p) => p,
            None => return vec![],
        };

        pin.member_ids
            .iter()
            .filter_map(|id| elements.get(id))
            .filter(|e| match capability {
                Some(cap) => e.capabilities.iter().any(|c| c == cap),
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Set up communication relay path between elements (TS 23.542 §6).
    ///
    /// Authorization rule: relay semantics may only be assigned to a PEGC
    /// (gateway) element.
    ///
    /// Returns:
    ///   - `Ok(())` on success.
    ///   - `Err(PinContextError::NotFound)` when the element does not exist.
    ///   - `Err(PinContextError::RelayOnlyForPegc)` when the element is not a PEGC.
    pub fn element_set_relay(
        &self,
        element_id: &str,
        relay_path: Vec<String>,
    ) -> Result<(), PinContextError> {
        if let Ok(mut elements) = self.elements.write() {
            match elements.get_mut(element_id) {
                None => Err(PinContextError::NotFound),
                Some(element) => {
                    if element.role != PinElementRole::Pegc {
                        log::warn!(
                            "Relay path denied on element {} (role={:?}): only PEGC allowed",
                            element_id,
                            element.role
                        );
                        return Err(PinContextError::RelayOnlyForPegc);
                    }
                    element.relay_path = relay_path;
                    Ok(())
                }
            }
        } else {
            Err(PinContextError::NotFound)
        }
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
static GLOBAL_PIN_CONTEXT: std::sync::OnceLock<Arc<RwLock<PinContext>>> =
    std::sync::OnceLock::new();

pub fn pin_self() -> Arc<RwLock<PinContext>> {
    GLOBAL_PIN_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(PinContext::new())))
        .clone()
}

pub fn pin_context_init(max_pins: usize, lifetime_secs: u64, heartbeat_secs: u64) {
    let ctx = pin_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_pins);
        context.set_lifecycle_defaults(lifetime_secs, heartbeat_secs);
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

        let pin = ctx
            .pin_create("My Smart Home", "imsi-001010000000001")
            .unwrap();
        assert!(pin.active);
        assert_eq!(ctx.pin_count(), 1);

        let found = ctx.pin_find(&pin.pin_id);
        assert!(found.is_some());

        // PIND-04: delete now requires an authorized caller (the owner).
        ctx.pin_delete(&pin.pin_id, Some("imsi-001010000000001"))
            .unwrap();
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

        let pin = ctx
            .pin_create("Smart Home", "imsi-001010000000001")
            .unwrap();

        let gw = ctx
            .element_register(
                &pin.pin_id,
                PinElementType::Gateway,
                vec!["relay".to_string(), "routing".to_string()],
                Some("imsi-001010000000001".to_string()),
                Some("imsi-001010000000001"),
            )
            .unwrap();

        assert_eq!(gw.element_type, PinElementType::Gateway);
        assert_eq!(gw.role, PinElementRole::Pegc);
        assert_eq!(ctx.element_count(), 1);

        // Gateway should be set on PIN
        let pin = ctx.pin_find(&pin.pin_id).unwrap();
        assert_eq!(pin.gateway_id, Some(gw.element_id.clone()));
    }

    #[test]
    fn test_element_discover() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx
            .pin_create("Smart Home", "imsi-001010000000001")
            .unwrap();

        ctx.element_register(
            &pin.pin_id,
            PinElementType::Element,
            vec!["temperature".to_string(), "humidity".to_string()],
            None,
            None,
        )
        .ok();
        ctx.element_register(
            &pin.pin_id,
            PinElementType::Element,
            vec!["camera".to_string()],
            None,
            None,
        )
        .ok();

        let all = ctx.element_discover(&pin.pin_id, None);
        assert_eq!(all.len(), 2);

        let sensors = ctx.element_discover(&pin.pin_id, Some("temperature"));
        assert_eq!(sensors.len(), 1);

        let cameras = ctx.element_discover(&pin.pin_id, Some("camera"));
        assert_eq!(cameras.len(), 1);
    }

    // T4.4-a: PEMC registration — owner and non-owner paths
    #[test]
    fn test_pemc_registration_owner_allowed() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx
            .pin_create("Home", "imsi-owner-001")
            .unwrap();

        // Owner registers a PEMC → ok
        let result = ctx.element_register(
            &pin.pin_id,
            PinElementType::ManagementEntity,
            vec![],
            Some("imsi-owner-001".to_string()),
            Some("imsi-owner-001"),
        );
        assert!(result.is_ok(), "owner should be allowed to register PEMC");
        let elem = result.unwrap();
        assert_eq!(elem.role, PinElementRole::Pemc);
    }

    #[test]
    fn test_pemc_registration_non_owner_denied() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx
            .pin_create("Home", "imsi-owner-001")
            .unwrap();

        // Non-owner tries to register a PEMC → role error
        let result = ctx.element_register(
            &pin.pin_id,
            PinElementType::ManagementEntity,
            vec![],
            Some("imsi-attacker-999".to_string()),
            Some("imsi-attacker-999"),
        );
        assert_eq!(
            result.unwrap_err(),
            PinContextError::PemcRequiresOwner,
            "non-owner must be denied PEMC registration"
        );
    }

    #[test]
    fn test_pemc_registration_absent_caller_denied() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        // No caller identity → denied
        let result = ctx.element_register(
            &pin.pin_id,
            PinElementType::ManagementEntity,
            vec![],
            None,
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            PinContextError::PemcRequiresOwner,
            "absent caller must be denied PEMC registration"
        );
    }

    // T4.4-b: relay path — PEGC allowed, plain element denied
    #[test]
    fn test_relay_set_on_pegc_allowed() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();
        let gw = ctx
            .element_register(
                &pin.pin_id,
                PinElementType::Gateway,
                vec!["relay".to_string()],
                None,
                Some("imsi-001010000000001"),
            )
            .unwrap();

        let result = ctx.element_set_relay(&gw.element_id, vec!["pe-upstream".to_string()]);
        assert!(result.is_ok(), "relay on PEGC should succeed");

        let found = ctx.element_find(&gw.element_id).unwrap();
        assert_eq!(found.relay_path, vec!["pe-upstream".to_string()]);
    }

    #[test]
    fn test_relay_set_on_plain_element_denied() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();
        let elem = ctx
            .element_register(
                &pin.pin_id,
                PinElementType::Element,
                vec!["sensor".to_string()],
                None,
                None,
            )
            .unwrap();

        let result = ctx.element_set_relay(&elem.element_id, vec!["pe-gw".to_string()]);
        assert_eq!(
            result.unwrap_err(),
            PinContextError::RelayOnlyForPegc,
            "relay on plain element must be denied"
        );
    }

    #[test]
    fn test_relay_set_on_nonexistent_element() {
        let ctx = PinContext::new();
        let result = ctx.element_set_relay("nonexistent-id", vec![]);
        assert_eq!(result.unwrap_err(), PinContextError::NotFound);
    }

    // T4.4-c: PIN create records owner (verified via PEMC registration)
    #[test]
    fn test_pin_owner_recorded_and_enforced() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Home", "imsi-real-owner").unwrap();
        // PIN's owner_supi is stored correctly
        assert_eq!(pin.owner_supi, "imsi-real-owner");

        // Owner can register PEMC
        assert!(ctx
            .element_register(
                &pin.pin_id,
                PinElementType::ManagementEntity,
                vec![],
                Some("imsi-real-owner".to_string()),
                Some("imsi-real-owner"),
            )
            .is_ok());

        // A different caller cannot
        assert_eq!(
            ctx.element_register(
                &pin.pin_id,
                PinElementType::ManagementEntity,
                vec![],
                Some("imsi-impostor".to_string()),
                Some("imsi-impostor"),
            )
            .unwrap_err(),
            PinContextError::PemcRequiresOwner
        );
    }

    // Legacy relay test updated for new signature
    #[test]
    fn test_element_relay_path() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx
            .pin_create("Smart Home", "imsi-001010000000001")
            .unwrap();
        // Use Gateway type so relay is permitted
        let elem = ctx
            .element_register(
                &pin.pin_id,
                PinElementType::Gateway,
                vec!["sensor".to_string()],
                None,
                Some("imsi-001010000000001"),
            )
            .unwrap();

        assert!(ctx
            .element_set_relay(&elem.element_id, vec!["pe-gw".to_string()])
            .is_ok());
        let found = ctx.element_find(&elem.element_id).unwrap();
        assert_eq!(found.relay_path, vec!["pe-gw".to_string()]);
    }

    // ── PIND-00: serving paths never panic ──────────────────────────────────
    #[test]
    fn pins_by_owner_absent_owner_returns_empty() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        ctx.pin_create("Home", "imsi-known-owner");

        // An unknown SUPI must yield an empty Vec, never panic.
        let owned = ctx.pins_by_owner("imsi-totally-unknown-999");
        assert!(owned.is_empty(), "unknown owner must return empty, no panic");
    }

    #[test]
    fn element_discover_unknown_pin_returns_empty() {
        let ctx = PinContext::new();
        // No init, no PINs: discovery on an unknown PIN must not panic.
        let found = ctx.element_discover("pin-does-not-exist", Some("temperature"));
        assert!(found.is_empty());
    }

    #[test]
    fn pin_list_empty_when_no_pins() {
        let ctx = PinContext::new();
        assert!(ctx.pin_list().is_empty());
    }

    // ── PIND-03: create assigns mandatory expiry + heartbeat ────────────────
    #[test]
    fn pin_create_assigns_expiry_and_heartbeat() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        ctx.set_lifecycle_defaults(3600, 45);

        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        // Expiration is in the future; heartbeat equals the configured default.
        assert!(
            pin.expiration_time > now_epoch_secs(),
            "expiration_time must be in the future"
        );
        assert_eq!(pin.heartbeat_timer, 45);
    }

    // ── PIND-04: PIN delete authorization ───────────────────────────────────
    #[test]
    fn pin_delete_owner_allowed() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let removed = ctx.pin_delete(&pin.pin_id, Some("imsi-owner-001"));
        assert!(removed.is_ok(), "owner must be allowed to delete");
        assert_eq!(ctx.pin_count(), 0);
    }

    #[test]
    fn pin_delete_non_owner_denied() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let err = ctx.pin_delete(&pin.pin_id, Some("imsi-attacker-999"));
        assert_eq!(err.unwrap_err(), PinContextError::PemcRequiresOwner);
        // PIN must still exist after a denied delete.
        assert_eq!(ctx.pin_count(), 1);
    }

    #[test]
    fn pin_delete_absent_caller_denied() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let err = ctx.pin_delete(&pin.pin_id, None);
        assert_eq!(err.unwrap_err(), PinContextError::PemcRequiresOwner);
        assert_eq!(ctx.pin_count(), 1);
    }

    #[test]
    fn pin_delete_not_found() {
        let ctx = PinContext::new();
        let err = ctx.pin_delete("pin-nope", Some("imsi-owner-001"));
        assert_eq!(err.unwrap_err(), PinContextError::NotFound);
    }

    #[test]
    fn pin_delete_registered_pemc_allowed() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        // Owner registers a PEMC hosted on a different SUPI.
        ctx.element_register(
            &pin.pin_id,
            PinElementType::ManagementEntity,
            vec![],
            Some("imsi-pemc-host".to_string()),
            Some("imsi-owner-001"),
        )
        .unwrap();

        // The PEMC host (not the owner) may delete the PIN.
        let removed = ctx.pin_delete(&pin.pin_id, Some("imsi-pemc-host"));
        assert!(removed.is_ok(), "a registered PEMC must be allowed to delete");
    }

    // ── PIND-04: element deregister authorization ───────────────────────────
    #[test]
    fn element_deregister_owner_allowed() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        let elem = ctx
            .element_register(
                &pin.pin_id,
                PinElementType::Element,
                vec!["sensor".to_string()],
                None,
                None,
            )
            .unwrap();

        let removed = ctx.element_deregister(&elem.element_id, Some("imsi-owner-001"));
        assert!(removed.is_ok(), "owner may deregister an element");
        assert_eq!(ctx.element_count(), 0);
    }

    #[test]
    fn element_deregister_non_owner_denied() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        let elem = ctx
            .element_register(
                &pin.pin_id,
                PinElementType::Element,
                vec!["sensor".to_string()],
                None,
                None,
            )
            .unwrap();

        let err = ctx.element_deregister(&elem.element_id, Some("imsi-attacker-999"));
        assert_eq!(err.unwrap_err(), PinContextError::PemcRequiresOwner);
        // Element must survive a denied deregister.
        assert_eq!(ctx.element_count(), 1);
    }

    #[test]
    fn element_deregister_not_found() {
        let ctx = PinContext::new();
        let err = ctx.element_deregister("pe-nope", Some("imsi-owner-001"));
        assert_eq!(err.unwrap_err(), PinContextError::NotFound);
    }
}
