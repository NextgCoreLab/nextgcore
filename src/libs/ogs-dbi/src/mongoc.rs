//! MongoDB Interface
//!
//! Provides MongoDB connection management and database operations.
//! Ported from lib/dbi/ogs-mongoc.c in the C implementation.

use mongodb::{
    bson::{doc, Document},
    options::ClientOptions,
    sync::{Client, Collection, Database},
};
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;

/// Database interface error types
#[derive(Error, Debug)]
pub enum DbiError {
    #[error("MongoDB error: {0}")]
    MongoDb(#[from] mongodb::error::Error),
    #[error("BSON error: {0}")]
    Bson(#[from] mongodb::bson::de::Error),
    #[error("No database URI provided")]
    NoDbUri,
    #[error("Database not initialized")]
    NotInitialized,
    #[error("Invalid SUPI format: {0}")]
    InvalidSupi(String),
    #[error("Subscriber not found: {0}")]
    SubscriberNotFound(String),
    #[error("Field not found: {0}")]
    FieldNotFound(String),
    #[error("Session not found for S-NSSAI/DNN")]
    SessionNotFound,
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Retry needed")]
    Retry,
}

/// Result type for database operations
pub type DbiResult<T> = Result<T, DbiError>;

/// MongoDB connection state
#[derive(Debug)]
#[derive(Default)]
pub struct OgsMongoc {
    pub initialized: bool,
    pub name: String,
    pub client: Option<Client>,
    pub database: Option<Database>,
    pub masked_db_uri: Option<String>,
}


/// Database interface with subscriber collection
#[derive(Debug)]
#[derive(Default)]
pub struct OgsDbi {
    pub mongoc: OgsMongoc,
    pub subscriber_collection: Option<Collection<Document>>,
}


/// Global singleton for database interface
static OGS_DBI: OnceLock<Arc<Mutex<OgsDbi>>> = OnceLock::new();

/// Get the global database interface instance
pub fn ogs_mongoc() -> Arc<Mutex<OgsDbi>> {
    OGS_DBI
        .get_or_init(|| Arc::new(Mutex::new(OgsDbi::default())))
        .clone()
}

/// Mask credentials in database URI for logging
fn masked_db_uri(db_uri: &str) -> String {
    // Split on '@' to separate credentials from host
    if let Some(at_pos) = db_uri.find('@') {
        let host_part = &db_uri[at_pos + 1..];
        format!("mongodb://*****:*****@{host_part}")
    } else {
        db_uri.to_string()
    }
}

/// Initialize MongoDB connection
///
/// # Arguments
/// * `db_uri` - MongoDB connection URI
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(DbiError::NoDbUri)` if URI is empty
/// * `Err(DbiError::Retry)` if connection failed but can be retried
pub fn ogs_mongoc_init(db_uri: &str) -> DbiResult<()> {
    if db_uri.is_empty() {
        log::error!("No DB_URI");
        return Err(DbiError::NoDbUri);
    }

    let dbi = ogs_mongoc();
    let mut dbi_guard = dbi.lock().unwrap();

    dbi_guard.mongoc.masked_db_uri = Some(masked_db_uri(db_uri));

    // Parse client options (sync version)
    let client_options = ClientOptions::parse(db_uri)?;

    // Get database name from URI or use default
    let db_name = client_options
        .default_database
        .clone()
        .unwrap_or_else(|| "nextgcore".to_string());

    // Create client
    let client = Client::with_options(client_options)?;

    // Get database reference
    let database = client.database(&db_name);

    // Test connection with ping command
    match database.run_command(doc! { "ping": 1 }, None) {
        Ok(_) => {
            log::info!(
                "MongoDB URI: '{}'",
                dbi_guard.mongoc.masked_db_uri.as_deref().unwrap_or("")
            );
        }
        Err(e) => {
            log::warn!(
                "Failed to connect to server [{}]: {}",
                dbi_guard.mongoc.masked_db_uri.as_deref().unwrap_or(""),
                e
            );
            return Err(DbiError::Retry);
        }
    }

    dbi_guard.mongoc.initialized = true;
    dbi_guard.mongoc.name = db_name;
    dbi_guard.mongoc.client = Some(client);
    dbi_guard.mongoc.database = Some(database);

    Ok(())
}

/// Cleanup MongoDB connection
pub fn ogs_mongoc_final() {
    let dbi = ogs_mongoc();
    let mut dbi_guard = dbi.lock().unwrap();

    dbi_guard.mongoc.database = None;
    dbi_guard.mongoc.client = None;
    dbi_guard.mongoc.masked_db_uri = None;
    dbi_guard.mongoc.initialized = false;
}

/// Initialize database interface with subscriber collection
///
/// # Arguments
/// * `db_uri` - MongoDB connection URI
pub fn ogs_dbi_init(db_uri: &str) -> DbiResult<()> {
    ogs_mongoc_init(db_uri)?;

    let dbi = ogs_mongoc();
    let mut dbi_guard = dbi.lock().unwrap();

    if let Some(ref client) = dbi_guard.mongoc.client {
        let collection = client
            .database(&dbi_guard.mongoc.name)
            .collection::<Document>("subscribers");
        dbi_guard.subscriber_collection = Some(collection);
    }

    Ok(())
}

/// Cleanup database interface
pub fn ogs_dbi_final() {
    let dbi = ogs_mongoc();
    {
        let mut dbi_guard = dbi.lock().unwrap();
        dbi_guard.subscriber_collection = None;
    }
    ogs_mongoc_final();
}

/// Get subscriber collection reference
pub fn get_subscriber_collection() -> DbiResult<Collection<Document>> {
    let dbi = ogs_mongoc();
    let dbi_guard = dbi.lock().unwrap();

    dbi_guard
        .subscriber_collection
        .clone()
        .ok_or(DbiError::NotInitialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masked_db_uri() {
        let uri = "mongodb://user:password@localhost:27017/nextgcore";
        let masked = masked_db_uri(uri);
        assert_eq!(masked, "mongodb://*****:*****@localhost:27017/nextgcore");

        let uri_no_auth = "mongodb://localhost:27017/nextgcore";
        let masked_no_auth = masked_db_uri(uri_no_auth);
        assert_eq!(masked_no_auth, "mongodb://localhost:27017/nextgcore");
    }
}

//
// B4.6: Distributed Database Support (6G Feature)
//


/// Database replication modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationMode {
    /// Primary-secondary replication
    PrimarySecondary,
    /// Multi-primary (active-active)
    MultiPrimary,
    /// Sharded cluster
    Sharded,
}

/// Database node role
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    /// Primary node (read/write)
    Primary,
    /// Secondary node (read-only replica)
    Secondary,
    /// Arbiter (voting only, no data)
    Arbiter,
}

/// Database node information
#[derive(Debug, Clone)]
pub struct DbNode {
    /// Node host
    pub host: String,
    /// Node port
    pub port: u16,
    /// Node role
    pub role: NodeRole,
    /// Node health status
    pub healthy: bool,
    /// Replication lag (seconds)
    pub replication_lag_sec: Option<f64>,
}

impl DbNode {
    /// Create a new database node
    pub fn new(host: impl Into<String>, port: u16, role: NodeRole) -> Self {
        DbNode {
            host: host.into(),
            port,
            role,
            healthy: true,
            replication_lag_sec: None,
        }
    }

    /// Get connection string for this node
    pub fn connection_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Distributed database coordinator
pub struct DistributedDbCoordinator {
    /// Replication mode
    mode: ReplicationMode,
    /// Database nodes
    nodes: Vec<DbNode>,
    /// Active read preference
    read_preference: ReadPreference,
    /// Write concern level
    write_concern: WriteConcern,
}

/// Read preference for distributed queries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadPreference {
    /// Read from primary only
    Primary,
    /// Read from primary, fall back to secondary if primary unavailable
    PrimaryPreferred,
    /// Read from secondary only
    Secondary,
    /// Read from secondary, fall back to primary if no secondary available
    SecondaryPreferred,
    /// Read from nearest node (lowest latency)
    Nearest,
}

/// Write concern for distributed writes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteConcern {
    /// Write to primary only (no replication confirmation)
    Unacknowledged,
    /// Write to primary, wait for acknowledgment
    Acknowledged,
    /// Write to majority of nodes
    Majority,
    /// Write to all nodes
    All,
}

impl DistributedDbCoordinator {
    /// Create a new distributed database coordinator
    pub fn new(mode: ReplicationMode) -> Self {
        DistributedDbCoordinator {
            mode,
            nodes: Vec::new(),
            read_preference: ReadPreference::PrimaryPreferred,
            write_concern: WriteConcern::Majority,
        }
    }

    /// Add a database node
    pub fn add_node(&mut self, node: DbNode) {
        self.nodes.push(node);
    }

    /// Remove a database node
    pub fn remove_node(&mut self, host: &str, port: u16) {
        self.nodes.retain(|node| !(node.host == host && node.port == port));
    }

    /// Get all nodes
    pub fn nodes(&self) -> &[DbNode] {
        &self.nodes
    }

    /// Get primary nodes
    pub fn primary_nodes(&self) -> Vec<&DbNode> {
        self.nodes
            .iter()
            .filter(|node| node.role == NodeRole::Primary)
            .collect()
    }

    /// Get secondary nodes
    pub fn secondary_nodes(&self) -> Vec<&DbNode> {
        self.nodes
            .iter()
            .filter(|node| node.role == NodeRole::Secondary)
            .collect()
    }

    /// Get healthy nodes
    pub fn healthy_nodes(&self) -> Vec<&DbNode> {
        self.nodes
            .iter()
            .filter(|node| node.healthy)
            .collect()
    }

    /// Set read preference
    pub fn set_read_preference(&mut self, preference: ReadPreference) {
        self.read_preference = preference;
    }

    /// Get read preference
    pub fn read_preference(&self) -> ReadPreference {
        self.read_preference
    }

    /// Set write concern
    pub fn set_write_concern(&mut self, concern: WriteConcern) {
        self.write_concern = concern;
    }

    /// Get write concern
    pub fn write_concern(&self) -> WriteConcern {
        self.write_concern
    }

    /// Get replication mode
    pub fn mode(&self) -> ReplicationMode {
        self.mode
    }

    /// Select nodes for read operation based on preference
    pub fn select_read_nodes(&self) -> Vec<&DbNode> {
        match self.read_preference {
            ReadPreference::Primary => self.primary_nodes()
                .into_iter()
                .filter(|n| n.healthy)
                .collect(),
            ReadPreference::PrimaryPreferred => {
                let primary = self.primary_nodes()
                    .into_iter()
                    .filter(|n| n.healthy)
                    .collect::<Vec<_>>();
                if !primary.is_empty() {
                    primary
                } else {
                    self.secondary_nodes()
                        .into_iter()
                        .filter(|n| n.healthy)
                        .collect()
                }
            }
            ReadPreference::Secondary => self.secondary_nodes()
                .into_iter()
                .filter(|n| n.healthy)
                .collect(),
            ReadPreference::SecondaryPreferred => {
                let secondary = self.secondary_nodes()
                    .into_iter()
                    .filter(|n| n.healthy)
                    .collect::<Vec<_>>();
                if !secondary.is_empty() {
                    secondary
                } else {
                    self.primary_nodes()
                        .into_iter()
                        .filter(|n| n.healthy)
                        .collect()
                }
            }
            ReadPreference::Nearest => self.healthy_nodes(),
        }
    }

    /// Select nodes for write operation based on write concern
    pub fn select_write_nodes(&self) -> Vec<&DbNode> {
        match self.write_concern {
            WriteConcern::Unacknowledged | WriteConcern::Acknowledged => {
                self.primary_nodes()
                    .into_iter()
                    .filter(|n| n.healthy)
                    .take(1)
                    .collect()
            }
            WriteConcern::Majority => {
                let all_nodes = self.healthy_nodes();
                let majority_count = (all_nodes.len() / 2) + 1;
                all_nodes.into_iter().take(majority_count).collect()
            }
            WriteConcern::All => self.healthy_nodes(),
        }
    }

    /// Check if cluster has quorum
    pub fn has_quorum(&self) -> bool {
        let healthy_count = self.healthy_nodes().len();
        let total_count = self.nodes.len();
        healthy_count > total_count / 2
    }

    /// Get replica set status
    pub fn get_status(&self) -> ReplicaSetStatus {
        let primary_count = self.primary_nodes().len();
        let secondary_count = self.secondary_nodes().len();
        let healthy_count = self.healthy_nodes().len();
        let unhealthy_count = self.nodes.len() - healthy_count;

        ReplicaSetStatus {
            mode: self.mode,
            total_nodes: self.nodes.len(),
            primary_nodes: primary_count,
            secondary_nodes: secondary_count,
            healthy_nodes: healthy_count,
            unhealthy_nodes: unhealthy_count,
            has_quorum: self.has_quorum(),
        }
    }

    /// Mark node as healthy/unhealthy
    pub fn set_node_health(&mut self, host: &str, port: u16, healthy: bool) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.host == host && n.port == port) {
            node.healthy = healthy;
        }
    }

    /// Update replication lag for a node
    pub fn set_replication_lag(&mut self, host: &str, port: u16, lag_sec: f64) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.host == host && n.port == port) {
            node.replication_lag_sec = Some(lag_sec);
        }
    }
}

/// Replica set status information
#[derive(Debug, Clone)]
pub struct ReplicaSetStatus {
    /// Replication mode
    pub mode: ReplicationMode,
    /// Total number of nodes
    pub total_nodes: usize,
    /// Number of primary nodes
    pub primary_nodes: usize,
    /// Number of secondary nodes
    pub secondary_nodes: usize,
    /// Number of healthy nodes
    pub healthy_nodes: usize,
    /// Number of unhealthy nodes
    pub unhealthy_nodes: usize,
    /// Whether cluster has quorum
    pub has_quorum: bool,
}

#[cfg(test)]
mod distributed_tests {
    use super::*;

    #[test]
    fn test_db_node_creation() {
        let node = DbNode::new("localhost", 27017, NodeRole::Primary);
        assert_eq!(node.host, "localhost");
        assert_eq!(node.port, 27017);
        assert_eq!(node.role, NodeRole::Primary);
        assert!(node.healthy);
    }

    #[test]
    fn test_coordinator_add_nodes() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        coordinator.add_node(DbNode::new("host1", 27017, NodeRole::Primary));
        coordinator.add_node(DbNode::new("host2", 27017, NodeRole::Secondary));
        coordinator.add_node(DbNode::new("host3", 27017, NodeRole::Secondary));

        assert_eq!(coordinator.nodes().len(), 3);
        assert_eq!(coordinator.primary_nodes().len(), 1);
        assert_eq!(coordinator.secondary_nodes().len(), 2);
    }

    #[test]
    fn test_read_preference_primary() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        coordinator.add_node(DbNode::new("host1", 27017, NodeRole::Primary));
        coordinator.add_node(DbNode::new("host2", 27017, NodeRole::Secondary));

        coordinator.set_read_preference(ReadPreference::Primary);
        let read_nodes = coordinator.select_read_nodes();

        assert_eq!(read_nodes.len(), 1);
        assert_eq!(read_nodes[0].role, NodeRole::Primary);
    }

    #[test]
    fn test_read_preference_primary_preferred_fallback() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        let mut primary = DbNode::new("host1", 27017, NodeRole::Primary);
        primary.healthy = false; // Primary unhealthy
        coordinator.add_node(primary);
        coordinator.add_node(DbNode::new("host2", 27017, NodeRole::Secondary));

        coordinator.set_read_preference(ReadPreference::PrimaryPreferred);
        let read_nodes = coordinator.select_read_nodes();

        // Should fall back to secondary
        assert_eq!(read_nodes.len(), 1);
        assert_eq!(read_nodes[0].role, NodeRole::Secondary);
    }

    #[test]
    fn test_write_concern_majority() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        coordinator.add_node(DbNode::new("host1", 27017, NodeRole::Primary));
        coordinator.add_node(DbNode::new("host2", 27017, NodeRole::Secondary));
        coordinator.add_node(DbNode::new("host3", 27017, NodeRole::Secondary));

        coordinator.set_write_concern(WriteConcern::Majority);
        let write_nodes = coordinator.select_write_nodes();

        // Majority of 3 is 2
        assert_eq!(write_nodes.len(), 2);
    }

    #[test]
    fn test_quorum() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        coordinator.add_node(DbNode::new("host1", 27017, NodeRole::Primary));
        coordinator.add_node(DbNode::new("host2", 27017, NodeRole::Secondary));
        coordinator.add_node(DbNode::new("host3", 27017, NodeRole::Secondary));

        // All healthy - has quorum
        assert!(coordinator.has_quorum());

        // Mark two as unhealthy - no quorum
        coordinator.set_node_health("host2", 27017, false);
        coordinator.set_node_health("host3", 27017, false);
        assert!(!coordinator.has_quorum());
    }

    #[test]
    fn test_replica_set_status() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        coordinator.add_node(DbNode::new("host1", 27017, NodeRole::Primary));
        coordinator.add_node(DbNode::new("host2", 27017, NodeRole::Secondary));
        coordinator.add_node(DbNode::new("host3", 27017, NodeRole::Secondary));

        let status = coordinator.get_status();

        assert_eq!(status.total_nodes, 3);
        assert_eq!(status.primary_nodes, 1);
        assert_eq!(status.secondary_nodes, 2);
        assert_eq!(status.healthy_nodes, 3);
        assert_eq!(status.unhealthy_nodes, 0);
        assert!(status.has_quorum);
    }

    #[test]
    fn test_replication_lag() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        coordinator.add_node(DbNode::new("host1", 27017, NodeRole::Secondary));

        coordinator.set_replication_lag("host1", 27017, 2.5);

        let node = &coordinator.nodes()[0];
        assert_eq!(node.replication_lag_sec, Some(2.5));
    }

    #[test]
    fn test_remove_node() {
        let mut coordinator = DistributedDbCoordinator::new(ReplicationMode::PrimarySecondary);

        coordinator.add_node(DbNode::new("host1", 27017, NodeRole::Primary));
        coordinator.add_node(DbNode::new("host2", 27017, NodeRole::Secondary));

        assert_eq!(coordinator.nodes().len(), 2);

        coordinator.remove_node("host2", 27017);
        assert_eq!(coordinator.nodes().len(), 1);
    }
}
