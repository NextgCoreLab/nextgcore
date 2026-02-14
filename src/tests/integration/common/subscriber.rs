//! Subscriber provisioning utilities
//!
//! Provides utilities for creating and managing test subscribers in MongoDB.

use serde::{Deserialize, Serialize};
use mongodb::Database;
use anyhow::Result;

/// Test subscriber data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSubscriber {
    /// IMSI (International Mobile Subscriber Identity)
    pub imsi: String,
    
    /// MSISDN (Mobile Station International Subscriber Directory Number)
    pub msisdn: Option<String>,
    
    /// Security context
    pub security: SubscriberSecurity,
    
    /// Access and Mobility Subscription Data
    pub am_data: Option<AmData>,
    
    /// Session Management Subscription Data
    pub sm_data: Option<Vec<SmData>>,
    
    /// Slice information
    pub slice: Option<Vec<SliceData>>,
}

/// Subscriber security data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberSecurity {
    /// Authentication key (K)
    pub k: String,
    
    /// Operator variant algorithm configuration field (OPc)
    pub opc: String,
    
    /// Authentication Management Field (AMF)
    pub amf: String,
    
    /// Sequence number
    pub sqn: u64,
}

impl Default for SubscriberSecurity {
    fn default() -> Self {
        Self {
            // Default test values from 3GPP TS 35.207
            k: "465B5CE8B199B49FAA5F0A2EE238A6BC".to_string(),
            opc: "E8ED289DEBA952E4283B54E88E6183CA".to_string(),
            amf: "8000".to_string(),
            sqn: 0,
        }
    }
}

/// Access and Mobility subscription data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmData {
    /// GPSI (Generic Public Subscription Identifier)
    pub gpsi: Option<String>,
    
    /// Subscribed UE-AMBR (Aggregate Maximum Bit Rate)
    pub subscribed_ue_ambr: Option<Ambr>,
    
    /// NSSAI (Network Slice Selection Assistance Information)
    pub nssai: Option<Vec<Snssai>>,
}

/// Session Management subscription data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmData {
    /// S-NSSAI
    pub snssai: Snssai,
    
    /// DNN (Data Network Name)
    pub dnn: String,
    
    /// Session type
    pub session_type: String,
    
    /// Session AMBR
    pub session_ambr: Option<Ambr>,
    
    /// QoS profile
    pub qos: Option<QosProfile>,
}

/// Slice data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceData {
    /// S-NSSAI
    pub snssai: Snssai,
    
    /// Default indicator
    pub default_indicator: bool,
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snssai {
    /// Slice/Service Type (SST)
    pub sst: u8,
    
    /// Slice Differentiator (SD) - optional
    pub sd: Option<String>,
}

impl Default for Snssai {
    fn default() -> Self {
        Self {
            sst: 1,
            sd: None,
        }
    }
}

/// Aggregate Maximum Bit Rate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ambr {
    /// Downlink (e.g., "1 Gbps")
    pub downlink: String,
    
    /// Uplink (e.g., "500 Mbps")
    pub uplink: String,
}

impl Default for Ambr {
    fn default() -> Self {
        Self {
            downlink: "1 Gbps".to_string(),
            uplink: "500 Mbps".to_string(),
        }
    }
}

/// QoS Profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosProfile {
    /// 5QI (5G QoS Identifier)
    pub qos_5qi: u8,
    
    /// ARP (Allocation and Retention Priority)
    pub arp: Option<Arp>,
}

impl Default for QosProfile {
    fn default() -> Self {
        Self {
            qos_5qi: 9, // Default 5QI for internet
            arp: Some(Arp::default()),
        }
    }
}

/// Allocation and Retention Priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Arp {
    /// Priority level (1-15)
    pub priority_level: u8,
    
    /// Pre-emption capability
    pub pre_emption_capability: String,
    
    /// Pre-emption vulnerability
    pub pre_emption_vulnerability: String,
}

impl Default for Arp {
    fn default() -> Self {
        Self {
            priority_level: 8,
            pre_emption_capability: "NOT_PREEMPT".to_string(),
            pre_emption_vulnerability: "NOT_PREEMPTABLE".to_string(),
        }
    }
}

impl TestSubscriber {
    /// Create a new test subscriber with default values
    pub fn new(imsi: &str) -> Self {
        Self {
            imsi: imsi.to_string(),
            msisdn: None,
            security: SubscriberSecurity::default(),
            am_data: Some(AmData {
                gpsi: None,
                subscribed_ue_ambr: Some(Ambr::default()),
                nssai: Some(vec![Snssai::default()]),
            }),
            sm_data: Some(vec![SmData {
                snssai: Snssai::default(),
                dnn: "internet".to_string(),
                session_type: "IPv4".to_string(),
                session_ambr: Some(Ambr::default()),
                qos: Some(QosProfile::default()),
            }]),
            slice: Some(vec![SliceData {
                snssai: Snssai::default(),
                default_indicator: true,
            }]),
        }
    }
    
    /// Create a subscriber with custom security parameters
    pub fn with_security(mut self, k: &str, opc: &str) -> Self {
        self.security.k = k.to_string();
        self.security.opc = opc.to_string();
        self
    }
    
    /// Set MSISDN
    pub fn with_msisdn(mut self, msisdn: &str) -> Self {
        self.msisdn = Some(msisdn.to_string());
        self
    }
    
    /// Add a DNN configuration
    pub fn with_dnn(mut self, dnn: &str, session_type: &str) -> Self {
        if let Some(ref mut sm_data) = self.sm_data {
            sm_data.push(SmData {
                snssai: Snssai::default(),
                dnn: dnn.to_string(),
                session_type: session_type.to_string(),
                session_ambr: Some(Ambr::default()),
                qos: Some(QosProfile::default()),
            });
        }
        self
    }
    
    /// Provision this subscriber to MongoDB
    pub async fn provision(&self, db: &Database) -> Result<()> {
        let collection = db.collection::<bson::Document>("subscribers");
        
        // Convert to BSON document
        let doc = bson::to_document(self)?;
        
        // Insert or update
        let filter = bson::doc! { "imsi": &self.imsi };
        let options = mongodb::options::ReplaceOptions::builder()
            .upsert(true)
            .build();
        
        collection.replace_one(filter, doc, options).await?;
        
        log::info!("Provisioned subscriber: {}", self.imsi);
        Ok(())
    }
    
    /// Delete this subscriber from MongoDB
    pub async fn delete(&self, db: &Database) -> Result<()> {
        let collection = db.collection::<bson::Document>("subscribers");
        let filter = bson::doc! { "imsi": &self.imsi };
        collection.delete_one(filter, None).await?;
        
        log::info!("Deleted subscriber: {}", self.imsi);
        Ok(())
    }
}

/// Subscriber builder for creating test subscribers
pub struct SubscriberBuilder {
    imsi_prefix: String,
    count: u32,
    base_msisdn: Option<u64>,
}

impl SubscriberBuilder {
    /// Create a new subscriber builder
    pub fn new(imsi_prefix: &str) -> Self {
        Self {
            imsi_prefix: imsi_prefix.to_string(),
            count: 1,
            base_msisdn: None,
        }
    }
    
    /// Set the number of subscribers to create
    pub fn count(mut self, count: u32) -> Self {
        self.count = count;
        self
    }
    
    /// Set the base MSISDN (will be incremented for each subscriber)
    pub fn base_msisdn(mut self, msisdn: u64) -> Self {
        self.base_msisdn = Some(msisdn);
        self
    }
    
    /// Build the subscribers
    pub fn build(&self) -> Vec<TestSubscriber> {
        (0..self.count)
            .map(|i| {
                let imsi = format!("{}{:010}", self.imsi_prefix, i);
                let mut sub = TestSubscriber::new(&imsi);
                
                if let Some(base) = self.base_msisdn {
                    sub.msisdn = Some(format!("{}", base + i as u64));
                }
                
                sub
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_subscriber_creation() {
        let sub = TestSubscriber::new("001010000000001");
        assert_eq!(sub.imsi, "001010000000001");
        assert!(!sub.security.k.is_empty());
    }
    
    #[test]
    fn test_subscriber_builder() {
        let subs = SubscriberBuilder::new("00101")
            .count(5)
            .base_msisdn(1234567890)
            .build();
        
        assert_eq!(subs.len(), 5);
        assert_eq!(subs[0].imsi, "001010000000000");
        assert_eq!(subs[0].msisdn, Some("1234567890".to_string()));
        assert_eq!(subs[4].imsi, "001010000000004");
        assert_eq!(subs[4].msisdn, Some("1234567894".to_string()));
    }
    
    #[test]
    fn test_subscriber_with_dnn() {
        let sub = TestSubscriber::new("001010000000001")
            .with_dnn("ims", "IPv4v6")
            .with_dnn("mms", "IPv4");
        
        assert_eq!(sub.sm_data.as_ref().unwrap().len(), 3); // default + 2 added
    }
    
    #[test]
    fn test_default_snssai() {
        let snssai = Snssai::default();
        assert_eq!(snssai.sst, 1);
        assert!(snssai.sd.is_none());
    }
}
