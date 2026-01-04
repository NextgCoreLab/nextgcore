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
pub struct OgsMongoc {
    pub initialized: bool,
    pub name: String,
    pub client: Option<Client>,
    pub database: Option<Database>,
    pub masked_db_uri: Option<String>,
}

impl Default for OgsMongoc {
    fn default() -> Self {
        Self {
            initialized: false,
            name: String::new(),
            client: None,
            database: None,
            masked_db_uri: None,
        }
    }
}

/// Database interface with subscriber collection
#[derive(Debug)]
pub struct OgsDbi {
    pub mongoc: OgsMongoc,
    pub subscriber_collection: Option<Collection<Document>>,
}

impl Default for OgsDbi {
    fn default() -> Self {
        Self {
            mongoc: OgsMongoc::default(),
            subscriber_collection: None,
        }
    }
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
        format!("mongodb://*****:*****@{}", host_part)
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
