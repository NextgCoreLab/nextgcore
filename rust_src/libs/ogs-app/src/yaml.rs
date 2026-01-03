//! YAML Configuration Parser
//!
//! This module provides YAML configuration parsing functionality,
//! ported from lib/app/ogs-yaml.c.

use serde_yaml::Value;
use thiserror::Error;

/// YAML parsing errors
#[derive(Error, Debug)]
pub enum YamlError {
    #[error("YAML parse error: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid node type")]
    InvalidNodeType,
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Value not found")]
    ValueNotFound,
    #[error("Invalid value type")]
    InvalidValueType,
}

/// YAML node type (mirrors yaml_node_type_t)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamlNodeType {
    /// No node
    NoNode,
    /// Scalar node (string value)
    Scalar,
    /// Sequence node (array)
    Sequence,
    /// Mapping node (object/dictionary)
    Mapping,
}

/// YAML iterator for traversing YAML documents
/// Mirrors ogs_yaml_iter_t from the C implementation
#[derive(Debug, Clone)]
pub struct OgsYamlIter {
    /// The root value being iterated
    root: Value,
    /// Current position in mapping (key index)
    mapping_index: Option<usize>,
    /// Current position in sequence (item index)
    sequence_index: Option<usize>,
    /// Keys for mapping iteration (cached)
    mapping_keys: Vec<String>,
    /// Current key (for mapping)
    current_key: Option<String>,
}

impl OgsYamlIter {
    /// Initialize iterator from a YAML document root
    /// Mirrors ogs_yaml_iter_init()
    pub fn new(root: Value) -> Self {
        let mapping_keys = if let Value::Mapping(ref map) = root {
            map.keys()
                .filter_map(|k| k.as_str().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        };

        OgsYamlIter {
            root,
            mapping_index: None,
            sequence_index: None,
            mapping_keys,
            current_key: None,
        }
    }

    /// Initialize iterator from a YAML string
    pub fn from_str(yaml_str: &str) -> Result<Self, YamlError> {
        let value: Value = serde_yaml::from_str(yaml_str)
            .map_err(|e| YamlError::ParseError(e.to_string()))?;
        Ok(Self::new(value))
    }

    /// Initialize iterator from a file
    pub fn from_file(path: &str) -> Result<Self, YamlError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Move to next element
    /// Mirrors ogs_yaml_iter_next()
    pub fn next(&mut self) -> bool {
        match &self.root {
            Value::Mapping(_) => {
                let next_idx = self.mapping_index.map(|i| i + 1).unwrap_or(0);
                if next_idx < self.mapping_keys.len() {
                    self.mapping_index = Some(next_idx);
                    self.current_key = Some(self.mapping_keys[next_idx].clone());
                    true
                } else {
                    false
                }
            }
            Value::Sequence(seq) => {
                let next_idx = self.sequence_index.map(|i| i + 1).unwrap_or(0);
                if next_idx < seq.len() {
                    self.sequence_index = Some(next_idx);
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Create a child iterator for the current value
    /// Mirrors ogs_yaml_iter_recurse()
    pub fn recurse(&self) -> Option<OgsYamlIter> {
        match &self.root {
            Value::Mapping(map) => {
                if let Some(ref key) = self.current_key {
                    let yaml_key = Value::String(key.clone());
                    if let Some(value) = map.get(&yaml_key) {
                        return Some(OgsYamlIter::new(value.clone()));
                    }
                }
                None
            }
            Value::Sequence(seq) => {
                if let Some(idx) = self.sequence_index {
                    if idx < seq.len() {
                        return Some(OgsYamlIter::new(seq[idx].clone()));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Get the type of the current node
    /// Mirrors ogs_yaml_iter_type()
    pub fn node_type(&self) -> YamlNodeType {
        match &self.root {
            Value::Null => YamlNodeType::NoNode,
            Value::Bool(_) | Value::Number(_) | Value::String(_) => YamlNodeType::Scalar,
            Value::Sequence(_) => YamlNodeType::Sequence,
            Value::Mapping(_) => YamlNodeType::Mapping,
            Value::Tagged(tagged) => {
                // Handle tagged values by checking inner value
                match &tagged.value {
                    Value::Null => YamlNodeType::NoNode,
                    Value::Bool(_) | Value::Number(_) | Value::String(_) => YamlNodeType::Scalar,
                    Value::Sequence(_) => YamlNodeType::Sequence,
                    Value::Mapping(_) => YamlNodeType::Mapping,
                    _ => YamlNodeType::NoNode,
                }
            }
        }
    }

    /// Get the current key (for mapping iteration)
    /// Mirrors ogs_yaml_iter_key()
    pub fn key(&self) -> Option<&str> {
        match &self.root {
            Value::Mapping(_) => self.current_key.as_deref(),
            Value::Sequence(seq) => {
                // For sequences, return the scalar value if it's a scalar
                if let Some(idx) = self.sequence_index {
                    if idx < seq.len() {
                        if let Value::String(s) = &seq[idx] {
                            return Some(s.as_str());
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Get the current value as a string
    /// Mirrors ogs_yaml_iter_value()
    pub fn value(&self) -> Option<&str> {
        match &self.root {
            Value::String(s) => Some(s.as_str()),
            Value::Bool(b) => {
                // Return static strings for booleans
                if *b { Some("true") } else { Some("false") }
            }
            Value::Number(_n) => None, // Numbers need special handling
            Value::Mapping(map) => {
                if let Some(ref key) = self.current_key {
                    let yaml_key = Value::String(key.clone());
                    if let Some(Value::String(s)) = map.get(&yaml_key) {
                        return Some(s.as_str());
                    }
                }
                None
            }
            Value::Sequence(seq) => {
                if let Some(idx) = self.sequence_index {
                    if idx < seq.len() {
                        if let Value::String(s) = &seq[idx] {
                            return Some(s.as_str());
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Get the current value as a string (owned version for numbers)
    pub fn value_string(&self) -> Option<String> {
        match &self.root {
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) => Some(n.to_string()),
            Value::Mapping(map) => {
                if let Some(ref key) = self.current_key {
                    let yaml_key = Value::String(key.clone());
                    if let Some(value) = map.get(&yaml_key) {
                        return match value {
                            Value::String(s) => Some(s.clone()),
                            Value::Bool(b) => Some(b.to_string()),
                            Value::Number(n) => Some(n.to_string()),
                            _ => None,
                        };
                    }
                }
                None
            }
            Value::Sequence(seq) => {
                if let Some(idx) = self.sequence_index {
                    if idx < seq.len() {
                        return match &seq[idx] {
                            Value::String(s) => Some(s.clone()),
                            Value::Bool(b) => Some(b.to_string()),
                            Value::Number(n) => Some(n.to_string()),
                            _ => None,
                        };
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Check if current position has a scalar value
    /// Mirrors ogs_yaml_iter_has_value()
    pub fn has_value(&self) -> bool {
        match &self.root {
            Value::String(_) | Value::Bool(_) | Value::Number(_) => true,
            Value::Mapping(map) => {
                if let Some(ref key) = self.current_key {
                    let yaml_key = Value::String(key.clone());
                    if let Some(value) = map.get(&yaml_key) {
                        return matches!(value, Value::String(_) | Value::Bool(_) | Value::Number(_));
                    }
                }
                false
            }
            Value::Sequence(seq) => {
                if let Some(idx) = self.sequence_index {
                    if idx < seq.len() {
                        return matches!(&seq[idx], Value::String(_) | Value::Bool(_) | Value::Number(_));
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Get the current value as a boolean
    /// Mirrors ogs_yaml_iter_bool()
    pub fn bool_value(&self) -> bool {
        if let Some(v) = self.value_string() {
            let v_lower = v.to_lowercase();
            if v_lower == "true" || v_lower == "yes" {
                return true;
            }
            if let Ok(n) = v.parse::<i64>() {
                return n != 0;
            }
        }
        false
    }

    /// Get the current value as an integer
    pub fn int_value(&self) -> Option<i64> {
        self.value_string().and_then(|v| v.parse().ok())
    }

    /// Get the current value as an unsigned integer
    pub fn uint_value(&self) -> Option<u64> {
        self.value_string().and_then(|v| v.parse().ok())
    }

    /// Get the current value as a float
    pub fn float_value(&self) -> Option<f64> {
        self.value_string().and_then(|v| v.parse().ok())
    }

    /// Get the underlying Value
    pub fn get_value(&self) -> &Value {
        &self.root
    }

    /// Check if this is a mapping node
    pub fn is_mapping(&self) -> bool {
        matches!(self.root, Value::Mapping(_))
    }

    /// Check if this is a sequence node
    pub fn is_sequence(&self) -> bool {
        matches!(self.root, Value::Sequence(_))
    }

    /// Check if this is a scalar node
    pub fn is_scalar(&self) -> bool {
        matches!(self.root, Value::String(_) | Value::Bool(_) | Value::Number(_))
    }
}

/// YAML document wrapper
/// Provides high-level access to YAML configuration files
#[derive(Debug, Clone)]
pub struct OgsYamlDocument {
    root: Value,
}

impl OgsYamlDocument {
    /// Parse YAML from a string
    pub fn from_str(yaml_str: &str) -> Result<Self, YamlError> {
        let root: Value = serde_yaml::from_str(yaml_str)
            .map_err(|e| YamlError::ParseError(e.to_string()))?;
        Ok(OgsYamlDocument { root })
    }

    /// Parse YAML from a file
    pub fn from_file(path: &str) -> Result<Self, YamlError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Get an iterator for the root node
    pub fn iter(&self) -> OgsYamlIter {
        OgsYamlIter::new(self.root.clone())
    }

    /// Get the root value
    pub fn root(&self) -> &Value {
        &self.root
    }

    /// Get a value by key path (e.g., "global.parameter.no_ipv4")
    pub fn get(&self, path: &str) -> Option<&Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = &self.root;
        
        for part in parts {
            match current {
                Value::Mapping(map) => {
                    let key = Value::String(part.to_string());
                    current = map.get(&key)?;
                }
                _ => return None,
            }
        }
        
        Some(current)
    }

    /// Get a string value by key path
    pub fn get_str(&self, path: &str) -> Option<&str> {
        self.get(path).and_then(|v| v.as_str())
    }

    /// Get a boolean value by key path
    pub fn get_bool(&self, path: &str) -> Option<bool> {
        self.get(path).and_then(|v| {
            match v {
                Value::Bool(b) => Some(*b),
                Value::String(s) => {
                    let s_lower = s.to_lowercase();
                    if s_lower == "true" || s_lower == "yes" {
                        Some(true)
                    } else if s_lower == "false" || s_lower == "no" {
                        Some(false)
                    } else {
                        s.parse::<i64>().ok().map(|n| n != 0)
                    }
                }
                Value::Number(n) => n.as_i64().map(|n| n != 0),
                _ => None,
            }
        })
    }

    /// Get an integer value by key path
    pub fn get_i64(&self, path: &str) -> Option<i64> {
        self.get(path).and_then(|v| {
            match v {
                Value::Number(n) => n.as_i64(),
                Value::String(s) => s.parse().ok(),
                _ => None,
            }
        })
    }

    /// Get an unsigned integer value by key path
    pub fn get_u64(&self, path: &str) -> Option<u64> {
        self.get(path).and_then(|v| {
            match v {
                Value::Number(n) => n.as_u64(),
                Value::String(s) => s.parse().ok(),
                _ => None,
            }
        })
    }

    /// Serialize the document back to YAML string
    pub fn to_string(&self) -> Result<String, YamlError> {
        serde_yaml::to_string(&self.root)
            .map_err(|e| YamlError::ParseError(e.to_string()))
    }
}

/// Macro for iterating over YAML arrays (mirrors OGS_YAML_ARRAY_RECURSE)
#[macro_export]
macro_rules! yaml_array_recurse {
    ($array:expr, $iter:expr) => {
        match $array.node_type() {
            YamlNodeType::Mapping => {
                *$iter = $array.clone();
            }
            YamlNodeType::Sequence => {
                if let Some(child) = $array.recurse() {
                    *$iter = child;
                }
            }
            YamlNodeType::Scalar => {
                break;
            }
            _ => {
                panic!("Unexpected node type in yaml_array_recurse");
            }
        }
    };
}

/// Macro for iterating to next array element (mirrors OGS_YAML_ARRAY_NEXT)
#[macro_export]
macro_rules! yaml_array_next {
    ($array:expr, $iter:expr) => {
        if $array.node_type() == YamlNodeType::Sequence && !$array.next() {
            break;
        }
        yaml_array_recurse!($array, $iter);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_document_from_str() {
        let yaml = r#"
global:
  parameter:
    no_ipv4: false
    no_ipv6: true
  max:
    ue: 1024
    peer: 64
logger:
  file: /var/log/nextgcore/amf.log
  level: info
"#;
        let doc = OgsYamlDocument::from_str(yaml).unwrap();
        
        assert_eq!(doc.get_bool("global.parameter.no_ipv4"), Some(false));
        assert_eq!(doc.get_bool("global.parameter.no_ipv6"), Some(true));
        assert_eq!(doc.get_i64("global.max.ue"), Some(1024));
        assert_eq!(doc.get_i64("global.max.peer"), Some(64));
        assert_eq!(doc.get_str("logger.file"), Some("/var/log/nextgcore/amf.log"));
        assert_eq!(doc.get_str("logger.level"), Some("info"));
    }

    #[test]
    fn test_yaml_iter_mapping() {
        let yaml = r#"
key1: value1
key2: value2
key3: value3
"#;
        let mut iter = OgsYamlIter::from_str(yaml).unwrap();
        
        let mut keys = Vec::new();
        while iter.next() {
            if let Some(key) = iter.key() {
                keys.push(key.to_string());
            }
        }
        
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));
    }

    #[test]
    fn test_yaml_iter_sequence() {
        let yaml = r#"
- item1
- item2
- item3
"#;
        let mut iter = OgsYamlIter::from_str(yaml).unwrap();
        
        let mut items = Vec::new();
        while iter.next() {
            if let Some(value) = iter.value() {
                items.push(value.to_string());
            }
        }
        
        assert_eq!(items, vec!["item1", "item2", "item3"]);
    }

    #[test]
    fn test_yaml_iter_recurse() {
        let yaml = r#"
parent:
  child1: value1
  child2: value2
"#;
        let mut iter = OgsYamlIter::from_str(yaml).unwrap();
        
        assert!(iter.next());
        assert_eq!(iter.key(), Some("parent"));
        
        let mut child_iter = iter.recurse().unwrap();
        
        let mut children = Vec::new();
        while child_iter.next() {
            if let Some(key) = child_iter.key() {
                children.push(key.to_string());
            }
        }
        
        assert!(children.contains(&"child1".to_string()));
        assert!(children.contains(&"child2".to_string()));
    }

    #[test]
    fn test_yaml_iter_bool() {
        let yaml = r#"
bool_true: true
bool_false: false
bool_yes: yes
bool_no: no
bool_1: 1
bool_0: 0
"#;
        let mut iter = OgsYamlIter::from_str(yaml).unwrap();
        
        while iter.next() {
            let key = iter.key().unwrap();
            let child = iter.recurse().unwrap();
            
            match key {
                "bool_true" | "bool_yes" | "bool_1" => {
                    assert!(child.bool_value(), "Expected true for {}", key);
                }
                "bool_false" | "bool_no" | "bool_0" => {
                    assert!(!child.bool_value(), "Expected false for {}", key);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_yaml_node_type() {
        let yaml = r#"
mapping:
  key: value
sequence:
  - item1
  - item2
scalar: value
"#;
        let mut iter = OgsYamlIter::from_str(yaml).unwrap();
        assert_eq!(iter.node_type(), YamlNodeType::Mapping);
        
        while iter.next() {
            let key = iter.key().unwrap();
            let child = iter.recurse().unwrap();
            
            match key {
                "mapping" => assert_eq!(child.node_type(), YamlNodeType::Mapping),
                "sequence" => assert_eq!(child.node_type(), YamlNodeType::Sequence),
                "scalar" => assert_eq!(child.node_type(), YamlNodeType::Scalar),
                _ => {}
            }
        }
    }

    #[test]
    fn test_yaml_round_trip() {
        let yaml = r#"global:
  parameter:
    no_ipv4: false
    no_ipv6: true
  max:
    ue: 1024
"#;
        let doc = OgsYamlDocument::from_str(yaml).unwrap();
        let output = doc.to_string().unwrap();
        
        // Parse the output again and verify values
        let doc2 = OgsYamlDocument::from_str(&output).unwrap();
        assert_eq!(doc2.get_bool("global.parameter.no_ipv4"), Some(false));
        assert_eq!(doc2.get_bool("global.parameter.no_ipv6"), Some(true));
        assert_eq!(doc2.get_i64("global.max.ue"), Some(1024));
    }
}
