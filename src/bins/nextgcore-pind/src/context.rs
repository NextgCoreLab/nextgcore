//! PIN Context Management
//!
//! Personal IoT Network Manager context (TS 23.542)
//! PEGC (PIN Element Gateway Controller) functionality

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// PIN Element type (TS 23.542 5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinElementType {
    /// PIN Element with Gateway capability (PEGC)
    Gateway,
    /// PIN Element (sensor, actuator, etc.)
    #[default]
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
    /// Derive the *requested* role from the element type. PIND-06: this is no
    /// longer the *granted* role — a requested PEMC/PEGC role is granted only
    /// after an authorization/subscription check in [`PinContext::element_register`];
    /// an unauthorized caller is downgraded to `Regular`.
    pub fn from_type(element_type: PinElementType) -> Self {
        match element_type {
            PinElementType::ManagementEntity => PinElementRole::Pemc,
            PinElementType::Gateway => PinElementRole::Pegc,
            PinElementType::Element => PinElementRole::Regular,
        }
    }
}

/// PEMC cardinality rank within a PIN (TS 23.542 §6.5.2): exactly one primary
/// PEMC, all others secondary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemcRank {
    /// The single primary PEMC of the PIN.
    Primary,
    /// A secondary PEMC, eligible for take-over (§8.5.10).
    Secondary,
}

/// PEGC cardinality rank within a PIN (TS 23.542 §6.5.3): exactly one default
/// PEGC, all others backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PegcRank {
    /// The single default PEGC of the PIN.
    Default,
    /// A backup PEGC, eligible for take-over (§8.5.10).
    Backup,
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
    /// Unique PIN Element ID (bespoke `pe-N` resource handle).
    pub element_id: String,
    /// PIN client ID (TS 23.542 §7.2.4) — newly assigned at registration and
    /// returned to the PINE (mandatory response IE, Table 8.4.2.3.3-1). PIND-06.
    pub pin_client_id: String,
    /// Element type
    pub element_type: PinElementType,
    /// *Granted* element role (after the PIND-06 authorization gate).
    pub role: PinElementRole,
    /// Element status
    pub status: PinElementStatus,
    /// PIN ID this element belongs to
    pub pin_id: String,
    /// Element capabilities
    pub capabilities: Vec<String>,
    /// SUPI of the UE hosting this PIN element (if UE-based)
    pub host_supi: Option<String>,
    /// Gateway element ID serving this element (the PIN default PEGC at
    /// registration time, for non-gateway elements).
    pub gateway_id: Option<String>,
    /// Relay path (element IDs forming the relay chain)
    pub relay_path: Vec<String>,
    /// PINE Address — IP address of the PINE (mandatory register IE,
    /// TS 23.542 Table 8.4.2.3.2-1). PIND-05.
    pub pine_address: Option<String>,
    /// Port used by the PINE to expose a service (mandatory register IE). PIND-05.
    pub port: Option<u16>,
    /// MAC address (optional register IE). PIND-05.
    pub mac_address: Option<String>,
    /// Vendor name (optional register IE). PIND-05.
    pub vendor_name: Option<String>,
    /// Device description (optional register IE). PIND-05.
    pub device_description: Option<String>,
    /// PEMC cardinality rank (Primary/Secondary), set only for granted PEMCs.
    /// PIND-07.
    pub pemc_rank: Option<PemcRank>,
    /// PEGC cardinality rank (Default/Backup), set only for granted PEGCs.
    /// PIND-07.
    pub pegc_rank: Option<PegcRank>,
    /// Per-element heartbeat timer (seconds) — the maximum gap allowed between
    /// keep-alives before the element is reaped. PIND-09.
    pub heartbeat_timer: u64,
    /// Last keep-alive timestamp (epoch seconds). PIND-09.
    pub last_heartbeat: u64,
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

/// Extract the numeric sequence from a `prefix-N` id for "lowest-id" ordering
/// (PIND-07 take-over picks the lowest-id backup). A non-numeric / malformed id
/// sorts last (`u64::MAX`) so it never silently wins a take-over.
fn id_seq(id: &str) -> u64 {
    id.rsplit('-')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
}

/// PINE registration input (TS 23.542 Table 8.4.2.3.2-1). Mandatory presence of
/// PINE Address / Port / UE Identifier / Security credentials is validated at
/// the HTTP handler; the context layer stores whatever it is given. PIND-05.
#[derive(Debug, Clone)]
pub struct PinElementRegistration {
    /// Requested element type (self-asserted; the granted role is gated). PIND-06.
    pub element_type: PinElementType,
    /// Advertised capabilities.
    pub capabilities: Vec<String>,
    /// Hosting UE SUPI, if any.
    pub host_supi: Option<String>,
    /// PINE Address (mandatory IE). PIND-05.
    pub pine_address: String,
    /// Port (mandatory IE). PIND-05.
    pub port: u16,
    /// MAC address (optional IE). PIND-05.
    pub mac_address: Option<String>,
    /// Vendor name (optional IE). PIND-05.
    pub vendor_name: Option<String>,
    /// Device description (optional IE). PIND-05.
    pub device_description: Option<String>,
}

impl PinElementRegistration {
    /// Construct with the mandatory PINE Address + Port and a requested type.
    pub fn new(element_type: PinElementType, pine_address: impl Into<String>, port: u16) -> Self {
        Self {
            element_type,
            capabilities: Vec::new(),
            host_supi: None,
            pine_address: pine_address.into(),
            port,
            mac_address: None,
            vendor_name: None,
            device_description: None,
        }
    }

    /// Builder: set advertised capabilities.
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Builder: set the hosting UE SUPI.
    pub fn with_host_supi(mut self, host_supi: Option<String>) -> Self {
        self.host_supi = host_supi;
        self
    }
}

/// Statistics returned by a single liveness reaper pass (PIND-09).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReapStats {
    /// Elements deregistered for missing their heartbeat timer.
    pub reaped_elements: usize,
    /// PINs deleted for passing their expiration time.
    pub deleted_pins: usize,
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
    /// Primary PEMC element ID (TS 23.542 §6.5.2 — exactly one). PIND-07.
    pub primary_pemc_id: Option<String>,
    /// Default PEGC element ID (TS 23.542 §6.5.3 — exactly one). Replaces the
    /// former single `gateway_id`. PIND-07.
    pub default_pegc_id: Option<String>,
    /// Member element IDs
    pub member_ids: Vec<String>,
    /// PIN status
    pub active: bool,
    /// Expiration time (epoch seconds). Mandatory PIN-create response IE per
    /// TS 23.542 §8.5.2.3.3 Table 8.5.2.3.3-1. Consumed by the PIND-09 reaper.
    pub expiration_time: u64,
    /// Heartbeat timer (seconds). Mandatory PIN-create response IE per
    /// TS 23.542 §8.5.2.3.3 Table 8.5.2.3.3-1. Seeds each element's heartbeat.
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
    /// PIN creation failed: no PEGC candidate is available among the owner's
    /// registered elements (TS 23.542 §8.5.2.2). Cause: `NO_PEGC_AVAILABLE`
    NoPegcAvailable,
    /// The maximum number of PINs has been reached. Cause: `MAX_PINS_REACHED`
    MaxPinsReached,
    /// The requested resource (PIN or element) was not found.
    NotFound,
}

impl PinContextError {
    /// A machine-readable cause string for ProblemDetails.
    pub fn cause(&self) -> &'static str {
        match self {
            PinContextError::PemcRequiresOwner => "PEMC_REQUIRES_OWNER",
            PinContextError::RelayOnlyForPegc => "RELAY_ONLY_FOR_PEGC",
            PinContextError::NoPegcAvailable => "NO_PEGC_AVAILABLE",
            PinContextError::MaxPinsReached => "MAX_PINS_REACHED",
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
            PinContextError::NoPegcAvailable => {
                "PIN creation requires an available PEGC; no gateway-capable \
                 (or PEMC-as-PEGC) element is registered for the owner"
            }
            PinContextError::MaxPinsReached => "The maximum number of PINs has been reached",
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
            .map(|e| e.role == PinElementRole::Pemc && e.host_supi.as_deref() == Some(caller))
            .unwrap_or(false)
    })
}

/// Pick the lowest-id member of `pin` whose granted role equals `role`,
/// excluding `exclude_id`. Used by the PIND-07 take-over to promote the
/// lowest-id secondary/backup.
fn lowest_id_member_with_role(
    pin: &PersonalIotNetwork,
    elements: &HashMap<String, PinElement>,
    role: PinElementRole,
    exclude_id: &str,
) -> Option<String> {
    pin.member_ids
        .iter()
        .filter(|id| id.as_str() != exclude_id)
        .filter_map(|id| elements.get(id))
        .filter(|e| e.role == role)
        .map(|e| e.element_id.clone())
        .min_by_key(|id| id_seq(id))
}

/// PIN Context
///
/// **PIND-11 — persistence DEFERRED + FLAGGED.** All PIN profiles and element
/// registrations are held in-memory only (the `RwLock<HashMap<..>>` fields
/// below) and are lost on restart; `fini` clears everything. pind has **no**
/// `mongodb` / `ogs-dbi` dependency in its own `Cargo.toml` today, and the
/// remediation rule for this batch forbids touching any `libs/` crate. A
/// write-through persistence backend (TS 23.542 §6.5.4 PIN-profile storage)
/// therefore cannot be added without either a new direct `mongodb` dependency
/// on this binary or a shared-lib change, so it is intentionally left
/// unimplemented here. The data model (`PersonalIotNetwork` / `PinElement`) is
/// already plain, owned, `Clone`-able state that serializes cleanly, so a
/// future PIND-11 pass can add a backend additively without reshaping it.
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
    /// PIND-08: when true, PIN creation fails with `NoPegcAvailable` unless a
    /// PEGC candidate (gateway-capable, or PEMC-as-PEGC fallback) is available
    /// among the owner's registered elements. Default false so a fresh owner
    /// can bootstrap their first PIN.
    require_pegc_at_create: bool,
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
            require_pegc_at_create: false,
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

    /// PIND-08: require an available PEGC at PIN create (otherwise creation
    /// fails with `NoPegcAvailable`).
    pub fn set_require_pegc_at_create(&mut self, require: bool) {
        self.require_pegc_at_create = require;
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

    /// Select a PEGC candidate among the owner's registered elements
    /// (TS 23.542 §8.5.2.2). Prefers a gateway-capable element (PEGC), falling
    /// back to a PEMC ("PEMC may itself be PEGC"). Returns the lowest-id match.
    /// PIND-08.
    fn select_pegc_candidate(
        &self,
        owner_supi: &str,
        pins: &HashMap<String, PersonalIotNetwork>,
        elements: &HashMap<String, PinElement>,
    ) -> Option<String> {
        let owner_owns = |pin_id: &str| {
            pins.get(pin_id)
                .map(|p| p.owner_supi == owner_supi)
                .unwrap_or(false)
        };
        // Primary: gateway-capable elements (granted PEGC role) owned by the caller.
        let gateway = elements
            .values()
            .filter(|e| e.role == PinElementRole::Pegc && owner_owns(&e.pin_id))
            .map(|e| e.element_id.clone())
            .min_by_key(|id| id_seq(id));
        if gateway.is_some() {
            return gateway;
        }
        // Fallback: a PEMC may itself act as PEGC.
        elements
            .values()
            .filter(|e| e.role == PinElementRole::Pemc && owner_owns(&e.pin_id))
            .map(|e| e.element_id.clone())
            .min_by_key(|id| id_seq(id))
    }

    /// Create a new Personal IoT Network.
    ///
    /// PIND-08: at create, a PEGC candidate is selected among the owner's
    /// registered elements and recorded as the PIN's default PEGC. When
    /// `require_pegc_at_create` is set and no candidate qualifies, creation
    /// fails with `NoPegcAvailable`.
    pub fn pin_create(
        &self,
        name: &str,
        owner_supi: &str,
    ) -> Result<PersonalIotNetwork, PinContextError> {
        let mut pins = self
            .pin_networks
            .write()
            .map_err(|_| PinContextError::NotFound)?;
        let mut owners = self
            .owner_index
            .write()
            .map_err(|_| PinContextError::NotFound)?;
        let elements = self.elements.read().map_err(|_| PinContextError::NotFound)?;

        if pins.len() >= self.max_pins {
            log::error!("Maximum PINs [{}] reached", self.max_pins);
            return Err(PinContextError::MaxPinsReached);
        }

        // PIND-08: PEGC candidate selection over the owner's existing elements.
        let default_pegc_id = self.select_pegc_candidate(owner_supi, &pins, &elements);
        if self.require_pegc_at_create && default_pegc_id.is_none() {
            log::warn!("PIN create denied for owner={owner_supi}: no PEGC available");
            return Err(PinContextError::NoPegcAvailable);
        }

        let pin_id = self.alloc_id("pin");
        let pin = PersonalIotNetwork {
            pin_id: pin_id.clone(),
            name: name.to_string(),
            owner_supi: owner_supi.to_string(),
            primary_pemc_id: None,
            default_pegc_id,
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

        log::info!(
            "PIN created: {} (owner={}, default_pegc={:?})",
            pin.pin_id,
            owner_supi,
            pin.default_pegc_id
        );
        Ok(pin)
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
        let mut pins = self
            .pin_networks
            .write()
            .map_err(|_| PinContextError::NotFound)?;
        let mut owners = self
            .owner_index
            .write()
            .map_err(|_| PinContextError::NotFound)?;
        let mut elements = self
            .elements
            .write()
            .map_err(|_| PinContextError::NotFound)?;

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
        // Acquire pins before owners to match the canonical lock order
        // (pins → owners → elements) used by the mutating paths, avoiding a
        // lock-order inversion with `pin_create`/`pin_delete`.
        let pins = match self.pin_networks.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("pins_by_owner: pin_networks lock poisoned; returning empty");
                return Vec::new();
            }
        };
        let owners = match self.owner_index.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("pins_by_owner: owner_index lock poisoned; returning empty");
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

    /// Register a PIN Element (TS 23.542 §8.4.2).
    ///
    /// PIND-05: stores the mandatory PINE Address + Port and optional metadata.
    /// PIND-06: assigns a PIN client ID and gates the requested PEMC/PEGC role
    /// behind an authorization check — an unauthorized caller is *downgraded*
    /// to `Regular` rather than rejected (the registration still succeeds and
    /// returns a PIN client ID, per Table 8.4.2.3.3-1).
    /// PIND-07: assigns Primary/Secondary (PEMC) and Default/Backup (PEGC)
    /// cardinality ranks.
    /// PIND-09: seeds the per-element heartbeat timer and last-seen timestamp.
    ///
    /// Returns `Err(PinContextError::NotFound)` when `pin_id` does not exist.
    pub fn element_register(
        &self,
        pin_id: &str,
        reg: PinElementRegistration,
        caller_supi: Option<&str>,
    ) -> Result<PinElement, PinContextError> {
        let mut pins = self
            .pin_networks
            .write()
            .map_err(|_| PinContextError::NotFound)?;
        let mut elements = self
            .elements
            .write()
            .map_err(|_| PinContextError::NotFound)?;

        let pin = pins.get_mut(pin_id).ok_or(PinContextError::NotFound)?;

        // PIND-06: gate the requested PEMC/PEGC role behind authorization.
        // Only the PIN owner or an existing PEMC may be granted an elevated
        // role; everyone else is downgraded to Regular.
        let authorized = caller_is_owner_or_pemc(pin, caller_supi.unwrap_or(""), &elements);
        let granted_role = match reg.element_type {
            PinElementType::ManagementEntity if authorized => PinElementRole::Pemc,
            PinElementType::Gateway if authorized => PinElementRole::Pegc,
            PinElementType::ManagementEntity | PinElementType::Gateway => {
                log::info!(
                    "PINE role downgraded to Regular: caller={caller_supi:?} not authorized for \
                     {:?} on PIN {pin_id}",
                    reg.element_type
                );
                PinElementRole::Regular
            }
            PinElementType::Element => PinElementRole::Regular,
        };

        let element_id = self.alloc_id("pe");
        let pin_client_id = self.alloc_id("pinc");

        // PIND-07: assign cardinality rank and maintain the PIN's primary/default.
        let mut pemc_rank = None;
        let mut pegc_rank = None;
        match granted_role {
            PinElementRole::Pemc => {
                if pin.primary_pemc_id.is_none() {
                    pemc_rank = Some(PemcRank::Primary);
                    pin.primary_pemc_id = Some(element_id.clone());
                } else {
                    pemc_rank = Some(PemcRank::Secondary);
                }
            }
            PinElementRole::Pegc => {
                if pin.default_pegc_id.is_none() {
                    pegc_rank = Some(PegcRank::Default);
                    pin.default_pegc_id = Some(element_id.clone());
                } else {
                    pegc_rank = Some(PegcRank::Backup);
                }
            }
            PinElementRole::Regular => {}
        }

        let now = now_epoch_secs();
        let element = PinElement {
            element_id: element_id.clone(),
            pin_client_id,
            element_type: reg.element_type,
            role: granted_role,
            status: PinElementStatus::Registered,
            pin_id: pin_id.to_string(),
            capabilities: reg.capabilities,
            host_supi: reg.host_supi,
            gateway_id: pin.default_pegc_id.clone(),
            relay_path: Vec::new(),
            pine_address: Some(reg.pine_address),
            port: Some(reg.port),
            mac_address: reg.mac_address,
            vendor_name: reg.vendor_name,
            device_description: reg.device_description,
            pemc_rank,
            pegc_rank,
            heartbeat_timer: pin.heartbeat_timer,
            last_heartbeat: now,
        };

        pin.member_ids.push(element_id.clone());
        elements.insert(element_id, element.clone());

        log::info!(
            "PIN Element registered: {} (type={:?}, role={:?}, pemc_rank={:?}, pegc_rank={:?}, pin={})",
            element.element_id,
            element.element_type,
            granted_role,
            pemc_rank,
            pegc_rank,
            pin_id
        );
        Ok(element)
    }

    /// Deregister a PIN Element (PIND-04: authorized — caller must be the
    /// owner or a registered PEMC of the element's PIN, per TS 23.542
    /// §8.5.8.2.3).
    ///
    /// PIND-07: if the removed element was the primary PEMC or default PEGC,
    /// the lowest-id secondary/backup is promoted (role take-over, §8.5.10).
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
        let mut pins = self
            .pin_networks
            .write()
            .map_err(|_| PinContextError::NotFound)?;
        let mut elements = self
            .elements
            .write()
            .map_err(|_| PinContextError::NotFound)?;

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

        let element = remove_element_locked(&mut pins, &mut elements, element_id)
            .ok_or(PinContextError::NotFound)?;
        log::info!("PIN Element deregistered: {element_id}");
        Ok(element)
    }

    /// Reset an element's keep-alive timestamp (PIND-09). Accepts a heartbeat
    /// from the PINE/PEMC/PEGC and slides its liveness deadline forward.
    pub fn element_heartbeat(&self, element_id: &str) -> Result<(), PinContextError> {
        let mut elements = self
            .elements
            .write()
            .map_err(|_| PinContextError::NotFound)?;
        match elements.get_mut(element_id) {
            Some(e) => {
                e.last_heartbeat = now_epoch_secs();
                e.status = PinElementStatus::Active;
                log::debug!("PIN Element heartbeat: {element_id}");
                Ok(())
            }
            None => Err(PinContextError::NotFound),
        }
    }

    /// Run one liveness reaper pass at wall-clock `now` (PIND-09).
    ///
    /// 1. Deregisters every element whose last heartbeat is older than its
    ///    heartbeat timer (firing PIND-07 take-over on primary/default loss).
    /// 2. Deletes every PIN past its expiration time (cascade-removing members).
    fn reap(&self, now: u64) -> ReapStats {
        let mut stats = ReapStats::default();

        // ── 1. Reap elements that missed their heartbeat ────────────────────
        if let (Ok(mut pins), Ok(mut elements)) =
            (self.pin_networks.write(), self.elements.write())
        {
            let stale: Vec<String> = elements
                .values()
                .filter(|e| {
                    e.heartbeat_timer > 0
                        && now.saturating_sub(e.last_heartbeat) > e.heartbeat_timer
                })
                .map(|e| e.element_id.clone())
                .collect();
            for id in stale {
                if remove_element_locked(&mut pins, &mut elements, &id).is_some() {
                    stats.reaped_elements += 1;
                    log::info!("PIN Element reaped (heartbeat expired): {id}");
                }
            }
        }

        // ── 2. Delete PINs past expiration ──────────────────────────────────
        if let (Ok(mut pins), Ok(mut owners), Ok(mut elements)) = (
            self.pin_networks.write(),
            self.owner_index.write(),
            self.elements.write(),
        ) {
            let expired: Vec<String> = pins
                .values()
                .filter(|p| p.expiration_time > 0 && now > p.expiration_time)
                .map(|p| p.pin_id.clone())
                .collect();
            for pin_id in expired {
                if let Some(pin) = pins.remove(&pin_id) {
                    if let Some(owned) = owners.get_mut(&pin.owner_supi) {
                        owned.retain(|id| id != &pin_id);
                    }
                    for elem_id in &pin.member_ids {
                        elements.remove(elem_id);
                    }
                    stats.deleted_pins += 1;
                    log::info!("PIN deleted (expired): {pin_id}");
                }
            }
        }

        stats
    }

    /// Run one reaper pass at the current wall-clock time (PIND-09). Invoked by
    /// the background reaper task.
    pub fn reap_now(&self) -> ReapStats {
        self.reap(now_epoch_secs())
    }

    /// Get a PIN element by ID
    pub fn element_find(&self, element_id: &str) -> Option<PinElement> {
        self.elements.read().ok()?.get(element_id).cloned()
    }

    /// Discover elements in a PIN by capability.
    ///
    /// PIND-00: a poisoned lock returns an empty `Vec` instead of panicking.
    pub fn element_discover(&self, pin_id: &str, capability: Option<&str>) -> Vec<PinElement> {
        // Acquire pin_networks before elements to match the canonical lock order
        // (pins -> owners -> elements) used by pin_create/reap; taking elements
        // first would be an AB-BA deadlock vs those mutating paths.
        let pins = match self.pin_networks.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("element_discover: pin_networks lock poisoned; returning empty");
                return Vec::new();
            }
        };
        let elements = match self.elements.read() {
            Ok(g) => g,
            Err(_) => {
                log::error!("element_discover: elements lock poisoned; returning empty");
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

/// Remove an element from the elements map and its owning PIN's member list,
/// then run the PIND-07 role take-over (§8.5.10): if the removed element was
/// the primary PEMC or default PEGC, promote the lowest-id secondary/backup.
///
/// Shared by both authorized deregister and the liveness reaper so take-over
/// fires identically on manual removal and expiry. Returns the removed element,
/// or `None` if it did not exist.
fn remove_element_locked(
    pins: &mut HashMap<String, PersonalIotNetwork>,
    elements: &mut HashMap<String, PinElement>,
    element_id: &str,
) -> Option<PinElement> {
    let element = elements.remove(element_id)?;
    if let Some(pin) = pins.get_mut(&element.pin_id) {
        pin.member_ids.retain(|id| id != element_id);

        // PIND-07 take-over: promote the lowest-id secondary PEMC to primary.
        if pin.primary_pemc_id.as_deref() == Some(element_id) {
            pin.primary_pemc_id =
                lowest_id_member_with_role(pin, elements, PinElementRole::Pemc, element_id);
            if let Some(new_id) = pin.primary_pemc_id.clone() {
                if let Some(e) = elements.get_mut(&new_id) {
                    e.pemc_rank = Some(PemcRank::Primary);
                }
                log::info!("PEMC take-over: {new_id} promoted to Primary (was {element_id})");
            }
        }
        // PIND-07 take-over: promote the lowest-id backup PEGC to default.
        if pin.default_pegc_id.as_deref() == Some(element_id) {
            pin.default_pegc_id =
                lowest_id_member_with_role(pin, elements, PinElementRole::Pegc, element_id);
            if let Some(new_id) = pin.default_pegc_id.clone() {
                if let Some(e) = elements.get_mut(&new_id) {
                    e.pegc_rank = Some(PegcRank::Default);
                }
                log::info!("PEGC take-over: {new_id} promoted to Default (was {element_id})");
            }
        }
    }
    Some(element)
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

    /// Build a registration with the mandatory PINE Address + Port supplied
    /// (the context layer does not re-validate mandatory presence — that is the
    /// HTTP handler's job, PIND-05).
    fn reg(
        t: PinElementType,
        caps: Vec<String>,
        host: Option<String>,
    ) -> PinElementRegistration {
        PinElementRegistration::new(t, "10.0.0.9", 9000)
            .with_capabilities(caps)
            .with_host_supi(host)
    }

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

        ctx.pin_create("Home PIN", "imsi-001010000000001").ok();
        ctx.pin_create("Office PIN", "imsi-001010000000001").ok();
        ctx.pin_create("Other PIN", "imsi-001010000000002").ok();

        let owned = ctx.pins_by_owner("imsi-001010000000001");
        assert_eq!(owned.len(), 2);
    }

    #[test]
    fn test_element_register_gateway() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();

        let gw = ctx
            .element_register(
                &pin.pin_id,
                reg(
                    PinElementType::Gateway,
                    vec!["relay".to_string(), "routing".to_string()],
                    Some("imsi-001010000000001".to_string()),
                ),
                Some("imsi-001010000000001"),
            )
            .unwrap();

        assert_eq!(gw.element_type, PinElementType::Gateway);
        assert_eq!(gw.role, PinElementRole::Pegc);
        assert_eq!(gw.pegc_rank, Some(PegcRank::Default));
        assert_eq!(ctx.element_count(), 1);

        // The gateway should be the PIN default PEGC (PIND-07).
        let pin = ctx.pin_find(&pin.pin_id).unwrap();
        assert_eq!(pin.default_pegc_id, Some(gw.element_id.clone()));
    }

    #[test]
    fn test_element_discover() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();

        ctx.element_register(
            &pin.pin_id,
            reg(
                PinElementType::Element,
                vec!["temperature".to_string(), "humidity".to_string()],
                None,
            ),
            None,
        )
        .ok();
        ctx.element_register(
            &pin.pin_id,
            reg(PinElementType::Element, vec!["camera".to_string()], None),
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

    // ── PIND-05: mandatory PINE address/port are stored and surfaced ─────────
    #[test]
    fn element_register_stores_address_and_port() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let elem = ctx
            .element_register(
                &pin.pin_id,
                PinElementRegistration::new(PinElementType::Element, "192.0.2.7", 5683)
                    .with_capabilities(vec!["coap".to_string()]),
                None,
            )
            .unwrap();

        let found = ctx.element_find(&elem.element_id).unwrap();
        assert_eq!(found.pine_address.as_deref(), Some("192.0.2.7"));
        assert_eq!(found.port, Some(5683));
        // PIND-06: a PIN client ID is assigned and distinct from the resource id.
        assert!(found.pin_client_id.starts_with("pinc-"));
        assert_ne!(found.pin_client_id, found.element_id);
    }

    // ── PIND-06: PIN client ID assignment + role gating ─────────────────────
    #[test]
    fn test_pemc_registration_owner_allowed() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        // Owner registers a PEMC → granted, role Pemc, Primary rank.
        let elem = ctx
            .element_register(
                &pin.pin_id,
                reg(
                    PinElementType::ManagementEntity,
                    vec![],
                    Some("imsi-owner-001".to_string()),
                ),
                Some("imsi-owner-001"),
            )
            .unwrap();
        assert_eq!(elem.role, PinElementRole::Pemc);
        assert_eq!(elem.pemc_rank, Some(PemcRank::Primary));
    }

    #[test]
    fn test_pemc_registration_non_owner_downgraded_to_regular() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        // PIND-06: a non-owner requesting PEMC is downgraded to Regular, NOT
        // rejected — registration still succeeds and yields a PIN client ID.
        let elem = ctx
            .element_register(
                &pin.pin_id,
                reg(
                    PinElementType::ManagementEntity,
                    vec![],
                    Some("imsi-attacker-999".to_string()),
                ),
                Some("imsi-attacker-999"),
            )
            .unwrap();
        assert_eq!(elem.role, PinElementRole::Regular);
        assert!(elem.pemc_rank.is_none());
        assert!(!elem.pin_client_id.is_empty());
    }

    #[test]
    fn test_pemc_registration_absent_caller_downgraded() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        // No caller identity → downgraded to Regular (PIND-06).
        let elem = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::ManagementEntity, vec![], None),
                None,
            )
            .unwrap();
        assert_eq!(elem.role, PinElementRole::Regular);
    }

    #[test]
    fn unauthorized_role_is_not_promotable_to_pemc_privilege() {
        // A downgraded (Regular) caller must NOT gain PEMC delete privilege.
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        ctx.element_register(
            &pin.pin_id,
            reg(
                PinElementType::ManagementEntity,
                vec![],
                Some("imsi-attacker-999".to_string()),
            ),
            Some("imsi-attacker-999"),
        )
        .unwrap();
        // The attacker holds only a Regular element → cannot delete the PIN.
        assert_eq!(
            ctx.pin_delete(&pin.pin_id, Some("imsi-attacker-999"))
                .unwrap_err(),
            PinContextError::PemcRequiresOwner
        );
    }

    // ── PIND-07: PEMC primary/secondary + PEGC default/backup + take-over ────
    #[test]
    fn two_pemcs_yield_primary_then_secondary() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let first = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::ManagementEntity, vec![], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();
        let second = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::ManagementEntity, vec![], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();

        assert_eq!(first.pemc_rank, Some(PemcRank::Primary));
        assert_eq!(second.pemc_rank, Some(PemcRank::Secondary));
        let pin = ctx.pin_find(&pin.pin_id).unwrap();
        assert_eq!(pin.primary_pemc_id.as_deref(), Some(first.element_id.as_str()));
    }

    #[test]
    fn pemc_takeover_promotes_secondary_on_primary_deregister() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let primary = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::ManagementEntity, vec![], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();
        let secondary = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::ManagementEntity, vec![], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();

        // Deregister the primary → the secondary takes over (§8.5.10).
        ctx.element_deregister(&primary.element_id, Some("imsi-owner-001"))
            .unwrap();

        let pin = ctx.pin_find(&pin.pin_id).unwrap();
        assert_eq!(pin.primary_pemc_id.as_deref(), Some(secondary.element_id.as_str()));
        let promoted = ctx.element_find(&secondary.element_id).unwrap();
        assert_eq!(promoted.pemc_rank, Some(PemcRank::Primary));
    }

    #[test]
    fn pegc_default_backup_and_takeover() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let default_gw = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Gateway, vec!["relay".to_string()], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();
        let backup_gw = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Gateway, vec!["relay".to_string()], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();

        assert_eq!(default_gw.pegc_rank, Some(PegcRank::Default));
        assert_eq!(backup_gw.pegc_rank, Some(PegcRank::Backup));
        // Multiple PEGCs coexist.
        assert_eq!(ctx.element_count(), 2);

        // Deregister the default → the backup is promoted to default.
        ctx.element_deregister(&default_gw.element_id, Some("imsi-owner-001"))
            .unwrap();
        let pin = ctx.pin_find(&pin.pin_id).unwrap();
        assert_eq!(pin.default_pegc_id.as_deref(), Some(backup_gw.element_id.as_str()));
        let promoted = ctx.element_find(&backup_gw.element_id).unwrap();
        assert_eq!(promoted.pegc_rank, Some(PegcRank::Default));
    }

    // ── PIND-08: PEGC candidate selection at PIN create ─────────────────────
    #[test]
    fn pin_create_selects_registered_gateway_as_default_pegc() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        // Bootstrap PIN with an in-PIN gateway element for the owner.
        let pin1 = ctx.pin_create("First", "imsi-owner-gw").unwrap();
        let gw = ctx
            .element_register(
                &pin1.pin_id,
                reg(PinElementType::Gateway, vec!["relay".to_string()], Some("imsi-owner-gw".to_string())),
                Some("imsi-owner-gw"),
            )
            .unwrap();

        // A new PIN for the same owner selects that gateway as default PEGC.
        let pin2 = ctx.pin_create("Second", "imsi-owner-gw").unwrap();
        assert_eq!(pin2.default_pegc_id.as_deref(), Some(gw.element_id.as_str()));
    }

    #[test]
    fn pin_create_pemc_as_pegc_fallback() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin1 = ctx.pin_create("First", "imsi-owner-pemc").unwrap();
        let pemc = ctx
            .element_register(
                &pin1.pin_id,
                reg(PinElementType::ManagementEntity, vec![], Some("imsi-owner-pemc".to_string())),
                Some("imsi-owner-pemc"),
            )
            .unwrap();

        // No gateway exists → PEMC-as-PEGC fallback selects the PEMC.
        let pin2 = ctx.pin_create("Second", "imsi-owner-pemc").unwrap();
        assert_eq!(pin2.default_pegc_id.as_deref(), Some(pemc.element_id.as_str()));
    }

    #[test]
    fn pin_create_no_pegc_available_when_required() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        ctx.set_require_pegc_at_create(true);

        // A fresh owner with no registered elements cannot get a PEGC.
        let err = ctx.pin_create("Home", "imsi-fresh-owner").unwrap_err();
        assert_eq!(err, PinContextError::NoPegcAvailable);
        assert_eq!(ctx.pin_count(), 0);
    }

    #[test]
    fn pin_create_succeeds_without_pegc_when_not_required() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        // Default: require_pegc_at_create = false → a fresh owner can bootstrap.
        let pin = ctx.pin_create("Home", "imsi-fresh-owner").unwrap();
        assert!(pin.default_pegc_id.is_none());
    }

    // ── PIND-09: heartbeat reset + reaper expiry ────────────────────────────
    #[test]
    fn element_heartbeat_resets_last_seen() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        let elem = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Element, vec![], None),
                None,
            )
            .unwrap();

        // Force the element stale, then heartbeat to refresh last_heartbeat.
        {
            let mut elements = ctx.elements.write().unwrap();
            elements.get_mut(&elem.element_id).unwrap().last_heartbeat = 0;
        }
        ctx.element_heartbeat(&elem.element_id).unwrap();
        let refreshed = ctx.element_find(&elem.element_id).unwrap();
        assert!(refreshed.last_heartbeat > 0, "heartbeat must refresh last_seen");
    }

    #[test]
    fn reaper_deregisters_element_past_heartbeat() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        ctx.set_lifecycle_defaults(86_400, 30); // 30s element heartbeat
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        let elem = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Element, vec![], None),
                None,
            )
            .unwrap();

        // last_heartbeat = now; reap far in the future → element is reaped.
        let future = now_epoch_secs() + 10_000;
        let stats = ctx.reap(future);
        assert_eq!(stats.reaped_elements, 1);
        assert!(ctx.element_find(&elem.element_id).is_none());
    }

    #[test]
    fn reaper_keeps_freshly_heartbeated_element() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        ctx.set_lifecycle_defaults(86_400, 30);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();
        let elem = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Element, vec![], None),
                None,
            )
            .unwrap();

        // Reap at "now": within the 30s timer → element survives.
        let stats = ctx.reap(now_epoch_secs());
        assert_eq!(stats.reaped_elements, 0);
        assert!(ctx.element_find(&elem.element_id).is_some());
    }

    #[test]
    fn reaper_deletes_expired_pin() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        ctx.set_lifecycle_defaults(3600, 30);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let future = now_epoch_secs() + 7200; // past the 1h lifetime
        let stats = ctx.reap(future);
        assert_eq!(stats.deleted_pins, 1);
        assert!(ctx.pin_find(&pin.pin_id).is_none());
    }

    #[test]
    fn reaper_fires_takeover_on_default_pegc_expiry() {
        let mut ctx = PinContext::new();
        ctx.init(64);
        ctx.set_lifecycle_defaults(86_400, 30);
        let pin = ctx.pin_create("Home", "imsi-owner-001").unwrap();

        let default_gw = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Gateway, vec!["relay".to_string()], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();
        let backup_gw = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Gateway, vec!["relay".to_string()], Some("imsi-owner-001".to_string())),
                Some("imsi-owner-001"),
            )
            .unwrap();

        // Only the default's heartbeat is stale; the backup stays fresh.
        // Anchor both to a fixed base so the reap time is past the default's
        // deadline (gap > 30s) but within the backup's (gap == 30s, not > 30).
        let base = now_epoch_secs();
        {
            let mut elements = ctx.elements.write().unwrap();
            elements.get_mut(&default_gw.element_id).unwrap().last_heartbeat = 0;
            elements.get_mut(&backup_gw.element_id).unwrap().last_heartbeat = base;
        }
        let stats = ctx.reap(base + 30);
        assert_eq!(stats.reaped_elements, 1);

        let pin = ctx.pin_find(&pin.pin_id).unwrap();
        assert_eq!(pin.default_pegc_id.as_deref(), Some(backup_gw.element_id.as_str()));
    }

    // ── Relay authorization (carried forward) ───────────────────────────────
    #[test]
    fn test_relay_set_on_pegc_allowed() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();
        let gw = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Gateway, vec!["relay".to_string()], None)
                    .with_host_supi(None),
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
                reg(PinElementType::Element, vec!["sensor".to_string()], None),
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

    // ── PIN owner recorded and enforced (carried forward, PIND-06 semantics) ─
    #[test]
    fn test_pin_owner_recorded_and_enforced() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Home", "imsi-real-owner").unwrap();
        // PIN's owner_supi is stored correctly.
        assert_eq!(pin.owner_supi, "imsi-real-owner");

        // Owner is granted the PEMC role.
        let owner_elem = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::ManagementEntity, vec![], Some("imsi-real-owner".to_string())),
                Some("imsi-real-owner"),
            )
            .unwrap();
        assert_eq!(owner_elem.role, PinElementRole::Pemc);

        // A different caller requesting PEMC is downgraded to Regular (PIND-06).
        let other_elem = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::ManagementEntity, vec![], Some("imsi-impostor".to_string())),
                Some("imsi-impostor"),
            )
            .unwrap();
        assert_eq!(other_elem.role, PinElementRole::Regular);
    }

    #[test]
    fn test_element_relay_path() {
        let mut ctx = PinContext::new();
        ctx.init(64);

        let pin = ctx.pin_create("Smart Home", "imsi-001010000000001").unwrap();
        // Use Gateway type so relay is permitted (owner is authorized → PEGC).
        let elem = ctx
            .element_register(
                &pin.pin_id,
                reg(PinElementType::Gateway, vec!["sensor".to_string()], None),
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
        ctx.pin_create("Home", "imsi-known-owner").ok();

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
            reg(PinElementType::ManagementEntity, vec![], Some("imsi-pemc-host".to_string())),
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
                reg(PinElementType::Element, vec!["sensor".to_string()], None),
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
                reg(PinElementType::Element, vec!["sensor".to_string()], None),
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
