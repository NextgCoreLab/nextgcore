//! Graph Database Support (6G Feature - B4.4)
//!
//! This module provides Neo4j-compatible graph database operations for modeling
//! complex network relationships, service dependencies, and AI/ML feature graphs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Graph database errors
#[derive(Error, Debug)]
pub enum GraphDbError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Query error: {0}")]
    QueryError(String),
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    #[error("Relationship not found: {0}")]
    RelationshipNotFound(String),
    #[error("Invalid query: {0}")]
    InvalidQuery(String),
}

/// Result type for graph database operations
pub type GraphDbResult<T> = Result<T, GraphDbError>;

/// Graph node representing network entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    /// Node ID
    pub id: String,
    /// Node labels (e.g., "UE", "AMF", "SMF", "Slice")
    pub labels: Vec<String>,
    /// Node properties
    pub properties: HashMap<String, PropertyValue>,
}

/// Graph relationship representing connections between entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRelationship {
    /// Relationship ID
    pub id: String,
    /// Relationship type (e.g., "CONNECTED_TO", "REGISTERED_WITH", "PART_OF")
    pub rel_type: String,
    /// Source node ID
    pub from_node: String,
    /// Target node ID
    pub to_node: String,
    /// Relationship properties
    pub properties: HashMap<String, PropertyValue>,
}

/// Property value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PropertyValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    List(Vec<PropertyValue>),
    Map(HashMap<String, PropertyValue>),
}

impl PropertyValue {
    /// Get as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PropertyValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as integer
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            PropertyValue::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Get as float
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            PropertyValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Get as boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PropertyValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Cypher-like query for graph operations
#[derive(Debug, Clone)]
pub struct CypherQuery {
    /// Query string
    pub query: String,
    /// Query parameters
    pub params: HashMap<String, PropertyValue>,
}

impl CypherQuery {
    /// Create a new query
    pub fn new(query: impl Into<String>) -> Self {
        CypherQuery {
            query: query.into(),
            params: HashMap::new(),
        }
    }

    /// Add parameter
    pub fn with_param(mut self, key: impl Into<String>, value: PropertyValue) -> Self {
        self.params.insert(key.into(), value);
        self
    }
}

/// Graph database client interface (Neo4j-compatible)
pub struct GraphDbClient {
    /// Connection endpoint
    _endpoint: String,
    /// Database name
    _database: String,
    /// In-memory graph storage (for testing/simulation)
    nodes: HashMap<String, GraphNode>,
    relationships: HashMap<String, GraphRelationship>,
    next_id: u64,
}

impl GraphDbClient {
    /// Create a new graph database client
    pub fn new(endpoint: impl Into<String>, database: impl Into<String>) -> Self {
        GraphDbClient {
            _endpoint: endpoint.into(),
            _database: database.into(),
            nodes: HashMap::new(),
            relationships: HashMap::new(),
            next_id: 1,
        }
    }

    /// Create an in-memory client (for testing)
    pub fn in_memory() -> Self {
        GraphDbClient::new("memory://localhost", "graph")
    }

    /// Create a node
    pub fn create_node(
        &mut self,
        labels: Vec<String>,
        properties: HashMap<String, PropertyValue>,
    ) -> GraphDbResult<GraphNode> {
        let id = format!("n{}", self.next_id);
        self.next_id += 1;

        let node = GraphNode {
            id: id.clone(),
            labels,
            properties,
        };

        self.nodes.insert(id.clone(), node.clone());
        Ok(node)
    }

    /// Get node by ID
    pub fn get_node(&self, id: &str) -> GraphDbResult<&GraphNode> {
        self.nodes
            .get(id)
            .ok_or_else(|| GraphDbError::NodeNotFound(id.to_string()))
    }

    /// Update node properties
    pub fn update_node(
        &mut self,
        id: &str,
        properties: HashMap<String, PropertyValue>,
    ) -> GraphDbResult<()> {
        let node = self.nodes
            .get_mut(id)
            .ok_or_else(|| GraphDbError::NodeNotFound(id.to_string()))?;

        for (key, value) in properties {
            node.properties.insert(key, value);
        }

        Ok(())
    }

    /// Delete node
    pub fn delete_node(&mut self, id: &str) -> GraphDbResult<()> {
        self.nodes.remove(id)
            .ok_or_else(|| GraphDbError::NodeNotFound(id.to_string()))?;

        // Remove relationships involving this node
        self.relationships.retain(|_, rel| {
            rel.from_node != id && rel.to_node != id
        });

        Ok(())
    }

    /// Create a relationship
    pub fn create_relationship(
        &mut self,
        from_node: &str,
        to_node: &str,
        rel_type: impl Into<String>,
        properties: HashMap<String, PropertyValue>,
    ) -> GraphDbResult<GraphRelationship> {
        // Verify nodes exist
        self.get_node(from_node)?;
        self.get_node(to_node)?;

        let id = format!("r{}", self.next_id);
        self.next_id += 1;

        let relationship = GraphRelationship {
            id: id.clone(),
            rel_type: rel_type.into(),
            from_node: from_node.to_string(),
            to_node: to_node.to_string(),
            properties,
        };

        self.relationships.insert(id.clone(), relationship.clone());
        Ok(relationship)
    }

    /// Get relationship by ID
    pub fn get_relationship(&self, id: &str) -> GraphDbResult<&GraphRelationship> {
        self.relationships
            .get(id)
            .ok_or_else(|| GraphDbError::RelationshipNotFound(id.to_string()))
    }

    /// Delete relationship
    pub fn delete_relationship(&mut self, id: &str) -> GraphDbResult<()> {
        self.relationships.remove(id)
            .ok_or_else(|| GraphDbError::RelationshipNotFound(id.to_string()))?;
        Ok(())
    }

    /// Find nodes by label
    pub fn find_nodes_by_label(&self, label: &str) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|node| node.labels.contains(&label.to_string()))
            .collect()
    }

    /// Find nodes by property
    pub fn find_nodes_by_property(&self, key: &str, value: &PropertyValue) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|node| {
                if let Some(prop) = node.properties.get(key) {
                    // Simple equality check (could be enhanced)
                    match (prop, value) {
                        (PropertyValue::String(a), PropertyValue::String(b)) => a == b,
                        (PropertyValue::Int(a), PropertyValue::Int(b)) => a == b,
                        (PropertyValue::Bool(a), PropertyValue::Bool(b)) => a == b,
                        _ => false,
                    }
                } else {
                    false
                }
            })
            .collect()
    }

    /// Get relationships from a node
    pub fn get_outgoing_relationships(&self, node_id: &str) -> Vec<&GraphRelationship> {
        self.relationships
            .values()
            .filter(|rel| rel.from_node == node_id)
            .collect()
    }

    /// Get relationships to a node
    pub fn get_incoming_relationships(&self, node_id: &str) -> Vec<&GraphRelationship> {
        self.relationships
            .values()
            .filter(|rel| rel.to_node == node_id)
            .collect()
    }

    /// Get all relationships for a node
    pub fn get_all_relationships(&self, node_id: &str) -> Vec<&GraphRelationship> {
        self.relationships
            .values()
            .filter(|rel| rel.from_node == node_id || rel.to_node == node_id)
            .collect()
    }

    /// Execute a Cypher-like query (simplified)
    pub fn execute_query(&self, query: &CypherQuery) -> GraphDbResult<Vec<GraphNode>> {
        // Simplified query execution (proof of concept)
        // In production, this would connect to actual Neo4j
        let query_lower = query.query.to_lowercase();

        if query_lower.contains("match") && query_lower.contains("return") {
            // Simple MATCH query
            if let Some(label_start) = query_lower.find("(n:") {
                if let Some(label_end) = query_lower[label_start..].find(")") {
                    let label = &query.query[label_start + 3..label_start + label_end];
                    let nodes: Vec<GraphNode> = self.find_nodes_by_label(label)
                        .into_iter()
                        .cloned()
                        .collect();
                    return Ok(nodes);
                }
            }
        }

        Err(GraphDbError::InvalidQuery("Unsupported query format".to_string()))
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get relationship count
    pub fn relationship_count(&self) -> usize {
        self.relationships.len()
    }

    /// Clear all data
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.relationships.clear();
        self.next_id = 1;
    }
}

/// Network topology graph helper
pub struct NetworkTopology {
    client: GraphDbClient,
}

impl NetworkTopology {
    /// Create a new network topology helper
    pub fn new(client: GraphDbClient) -> Self {
        NetworkTopology { client }
    }

    /// Add UE node
    pub fn add_ue(&mut self, supi: &str, imsi: &str) -> GraphDbResult<GraphNode> {
        let mut props = HashMap::new();
        props.insert("supi".to_string(), PropertyValue::String(supi.to_string()));
        props.insert("imsi".to_string(), PropertyValue::String(imsi.to_string()));

        self.client.create_node(vec!["UE".to_string()], props)
    }

    /// Add NF node
    pub fn add_nf(&mut self, nf_type: &str, nf_instance_id: &str) -> GraphDbResult<GraphNode> {
        let mut props = HashMap::new();
        props.insert("nf_instance_id".to_string(), PropertyValue::String(nf_instance_id.to_string()));

        self.client.create_node(vec!["NF".to_string(), nf_type.to_string()], props)
    }

    /// Add slice node
    pub fn add_slice(&mut self, sst: i64, sd: &str) -> GraphDbResult<GraphNode> {
        let mut props = HashMap::new();
        props.insert("sst".to_string(), PropertyValue::Int(sst));
        props.insert("sd".to_string(), PropertyValue::String(sd.to_string()));

        self.client.create_node(vec!["Slice".to_string()], props)
    }

    /// Register UE with NF
    pub fn register_ue_with_nf(
        &mut self,
        ue_id: &str,
        nf_id: &str,
    ) -> GraphDbResult<GraphRelationship> {
        self.client.create_relationship(
            ue_id,
            nf_id,
            "REGISTERED_WITH",
            HashMap::new(),
        )
    }

    /// Associate UE with slice
    pub fn associate_ue_with_slice(
        &mut self,
        ue_id: &str,
        slice_id: &str,
    ) -> GraphDbResult<GraphRelationship> {
        self.client.create_relationship(
            ue_id,
            slice_id,
            "USES_SLICE",
            HashMap::new(),
        )
    }

    /// Get UEs for a slice
    pub fn get_slice_ues(&self, slice_id: &str) -> Vec<&GraphNode> {
        let rels = self.client.get_incoming_relationships(slice_id);
        rels.iter()
            .filter(|rel| rel.rel_type == "USES_SLICE")
            .filter_map(|rel| self.client.get_node(&rel.from_node).ok())
            .collect()
    }

    /// Get reference to client
    pub fn client(&self) -> &GraphDbClient {
        &self.client
    }

    /// Get mutable reference to client
    pub fn client_mut(&mut self) -> &mut GraphDbClient {
        &mut self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_node() {
        let mut client = GraphDbClient::in_memory();
        let mut props = HashMap::new();
        props.insert("name".to_string(), PropertyValue::String("test".to_string()));

        let node = client.create_node(vec!["TestNode".to_string()], props).unwrap();
        assert_eq!(node.labels, vec!["TestNode".to_string()]);
        assert!(node.properties.contains_key("name"));
    }

    #[test]
    fn test_get_node() {
        let mut client = GraphDbClient::in_memory();
        let node = client.create_node(vec!["Test".to_string()], HashMap::new()).unwrap();

        let retrieved = client.get_node(&node.id).unwrap();
        assert_eq!(retrieved.id, node.id);
    }

    #[test]
    fn test_create_relationship() {
        let mut client = GraphDbClient::in_memory();
        let node1 = client.create_node(vec!["Node1".to_string()], HashMap::new()).unwrap();
        let node2 = client.create_node(vec!["Node2".to_string()], HashMap::new()).unwrap();

        let rel = client.create_relationship(
            &node1.id,
            &node2.id,
            "CONNECTS_TO",
            HashMap::new(),
        ).unwrap();

        assert_eq!(rel.from_node, node1.id);
        assert_eq!(rel.to_node, node2.id);
        assert_eq!(rel.rel_type, "CONNECTS_TO");
    }

    #[test]
    fn test_find_nodes_by_label() {
        let mut client = GraphDbClient::in_memory();
        client.create_node(vec!["UE".to_string()], HashMap::new()).unwrap();
        client.create_node(vec!["UE".to_string()], HashMap::new()).unwrap();
        client.create_node(vec!["AMF".to_string()], HashMap::new()).unwrap();

        let ues = client.find_nodes_by_label("UE");
        assert_eq!(ues.len(), 2);
    }

    #[test]
    fn test_find_nodes_by_property() {
        let mut client = GraphDbClient::in_memory();

        let mut props1 = HashMap::new();
        props1.insert("status".to_string(), PropertyValue::String("active".to_string()));
        client.create_node(vec!["UE".to_string()], props1).unwrap();

        let mut props2 = HashMap::new();
        props2.insert("status".to_string(), PropertyValue::String("inactive".to_string()));
        client.create_node(vec!["UE".to_string()], props2).unwrap();

        let active_nodes = client.find_nodes_by_property(
            "status",
            &PropertyValue::String("active".to_string()),
        );
        assert_eq!(active_nodes.len(), 1);
    }

    #[test]
    fn test_network_topology() {
        let mut topo = NetworkTopology::new(GraphDbClient::in_memory());

        let ue = topo.add_ue("supi-001", "imsi-001").unwrap();
        let amf = topo.add_nf("AMF", "amf-1").unwrap();
        let slice = topo.add_slice(1, "000001").unwrap();

        topo.register_ue_with_nf(&ue.id, &amf.id).unwrap();
        topo.associate_ue_with_slice(&ue.id, &slice.id).unwrap();

        let slice_ues = topo.get_slice_ues(&slice.id);
        assert_eq!(slice_ues.len(), 1);
    }

    #[test]
    fn test_get_relationships() {
        let mut client = GraphDbClient::in_memory();
        let node1 = client.create_node(vec!["N1".to_string()], HashMap::new()).unwrap();
        let node2 = client.create_node(vec!["N2".to_string()], HashMap::new()).unwrap();
        let node3 = client.create_node(vec!["N3".to_string()], HashMap::new()).unwrap();

        client.create_relationship(&node1.id, &node2.id, "REL1", HashMap::new()).unwrap();
        client.create_relationship(&node2.id, &node3.id, "REL2", HashMap::new()).unwrap();

        let outgoing = client.get_outgoing_relationships(&node1.id);
        assert_eq!(outgoing.len(), 1);

        let incoming = client.get_incoming_relationships(&node2.id);
        assert_eq!(incoming.len(), 1);

        let all = client.get_all_relationships(&node2.id);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_delete_node() {
        let mut client = GraphDbClient::in_memory();
        let node = client.create_node(vec!["Test".to_string()], HashMap::new()).unwrap();

        let node_id = node.id.clone();
        assert!(client.get_node(&node_id).is_ok());

        client.delete_node(&node_id).unwrap();
        assert!(client.get_node(&node_id).is_err());
    }

    #[test]
    fn test_property_value_accessors() {
        let str_val = PropertyValue::String("test".to_string());
        assert_eq!(str_val.as_str(), Some("test"));
        assert_eq!(str_val.as_i64(), None);

        let int_val = PropertyValue::Int(42);
        assert_eq!(int_val.as_i64(), Some(42));
        assert_eq!(int_val.as_str(), None);

        let bool_val = PropertyValue::Bool(true);
        assert_eq!(bool_val.as_bool(), Some(true));
    }
}
