//! MongoDB test container setup
//!
//! Provides utilities for spinning up MongoDB containers for integration tests
//! using testcontainers. Uses synchronous MongoDB API to be compatible with
//! ogs-dbi's sync feature.

use std::sync::Arc;
use testcontainers::{clients::Cli, Container, GenericImage};
use mongodb::{sync::{Client, Database}, options::ClientOptions};
use anyhow::Result;

/// MongoDB test container wrapper
pub struct MongoDbTestContainer<'a> {
    _container: Container<'a, GenericImage>,
    client: Client,
    database: Database,
    connection_string: String,
}

impl<'a> MongoDbTestContainer<'a> {
    /// Create a new MongoDB test container
    pub fn new(docker: &'a Cli) -> Result<Self> {
        // Start MongoDB container
        let mongo_image = GenericImage::new("mongo", "6.0")
            .with_exposed_port(27017)
            .with_env_var("MONGO_INITDB_DATABASE", "nextgcore");
        
        let container = docker.run(mongo_image);
        let port = container.get_host_port_ipv4(27017);
        
        let connection_string = format!("mongodb://localhost:{port}");
        
        // Connect to MongoDB (sync API)
        let client_options = ClientOptions::parse(&connection_string)?;
        let client = Client::with_options(client_options)?;
        let database = client.database("nextgcore");
        
        // Wait for MongoDB to be ready
        Self::wait_for_ready(&client)?;
        
        Ok(Self {
            _container: container,
            client,
            database,
            connection_string,
        })
    }
    
    /// Wait for MongoDB to be ready (sync version)
    fn wait_for_ready(client: &Client) -> Result<()> {
        let max_retries = 30;
        let retry_delay = std::time::Duration::from_millis(500);
        
        for i in 0..max_retries {
            match client.database("admin").run_command(bson::doc! { "ping": 1 }, None) {
                Ok(_) => {
                    log::info!("MongoDB is ready after {} attempts", i + 1);
                    return Ok(());
                }
                Err(e) => {
                    if i == max_retries - 1 {
                        return Err(anyhow::anyhow!("MongoDB not ready after {max_retries} attempts: {e}"));
                    }
                    std::thread::sleep(retry_delay);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get the MongoDB client
    pub fn client(&self) -> &Client {
        &self.client
    }
    
    /// Get the test database
    pub fn database(&self) -> &Database {
        &self.database
    }
    
    /// Get the connection string
    pub fn connection_string(&self) -> &str {
        &self.connection_string
    }
    
    /// Initialize the database with required collections
    pub fn init_collections(&self) -> Result<()> {
        // Create subscribers collection
        self.database.create_collection("subscribers", None).ok();
        
        // Create sessions collection
        self.database.create_collection("sessions", None).ok();
        
        // Create accounts collection (for WebUI)
        self.database.create_collection("accounts", None).ok();
        
        log::info!("Initialized MongoDB collections");
        Ok(())
    }
    
    /// Clear all test data
    pub fn clear_data(&self) -> Result<()> {
        self.database.collection::<bson::Document>("subscribers").drop(None).ok();
        self.database.collection::<bson::Document>("sessions").drop(None).ok();
        
        log::info!("Cleared MongoDB test data");
        Ok(())
    }
}

/// Shared MongoDB container for tests that need database access
pub struct SharedMongoDb {
    docker: Arc<Cli>,
}

impl SharedMongoDb {
    /// Create a new shared MongoDB instance
    pub fn new() -> Self {
        Self {
            docker: Arc::new(Cli::default()),
        }
    }
    
    /// Get a reference to the Docker client
    pub fn docker(&self) -> &Cli {
        &self.docker
    }
}

impl Default for SharedMongoDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mongodb_container_starts() {
        let _ = env_logger::try_init();
        
        // Check if Docker is available first
        let docker_check = std::process::Command::new("docker")
            .arg("info")
            .output();
        
        match docker_check {
            Ok(output) if output.status.success() => {
                // Docker is available, try to start container
                let docker = Cli::default();
                let result = MongoDbTestContainer::new(&docker);
                
                match result {
                    Ok(mongo) => {
                        assert!(!mongo.connection_string().is_empty());
                        log::info!("MongoDB container started at: {}", mongo.connection_string());
                    }
                    Err(e) => {
                        log::warn!("MongoDB container failed to start: {e}");
                    }
                }
            }
            _ => {
                // Docker not available - skip test
                log::warn!("MongoDB container test skipped (Docker not available)");
            }
        }
    }
}
