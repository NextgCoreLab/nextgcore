//! NWDAF Federation and DCCF/MFAF Integration (TS 23.288 §6.1A, Rel-17)
//!
//! Implements federated analytics:
//! - DCCF (Data Collection Co-ordination Function) consumer interface
//! - MFAF (Messaging Framework Adaptor Function) forwarding
//! - Cross-PLMN analytics federation for roaming scenarios
//! - Model federated learning aggregation stubs

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::context::AnalyticsId;

/// Federation peer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationPeerType {
    /// Another NWDAF in the same PLMN
    LocalNwdaf,
    /// NWDAF in a roaming PLMN
    RemoteNwdaf,
    /// DCCF (Data Collection Coordination Function)
    Dccf,
    /// MFAF (Messaging Framework Adaptor Function)
    Mfaf,
    /// ADRF (Analytics Data Repository Function, Rel-17)
    Adrf,
}

/// Federation peer descriptor
#[derive(Debug, Clone)]
pub struct FederationPeer {
    /// NF instance ID of the peer
    pub instance_id: String,
    /// SBI base URI
    pub sbi_uri: String,
    /// PLMN ID of the peer (for cross-PLMN)
    pub plmn_id: Option<String>,
    /// Peer type
    pub peer_type: FederationPeerType,
    /// Supported analytics IDs
    pub supported_analytics: Vec<AnalyticsId>,
    /// Last heartbeat timestamp (UNIX seconds)
    pub last_heartbeat: u64,
    /// Whether this peer is currently reachable
    pub reachable: bool,
}

impl FederationPeer {
    pub fn new(
        instance_id: String,
        sbi_uri: String,
        peer_type: FederationPeerType,
        supported_analytics: Vec<AnalyticsId>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            instance_id,
            sbi_uri,
            plmn_id: None,
            peer_type,
            supported_analytics,
            last_heartbeat: now,
            reachable: true,
        }
    }

    /// Returns true if this peer supports the given analytics type
    pub fn supports(&self, analytics_id: AnalyticsId) -> bool {
        self.supported_analytics.contains(&analytics_id)
    }
}

/// Federated analytics request: forward analytics query to a peer
#[derive(Debug, Clone)]
pub struct FederatedRequest {
    /// Local subscription or query ID
    pub local_ref: String,
    /// Target peer instance ID
    pub peer_instance_id: String,
    /// Analytics IDs requested
    pub analytics_ids: Vec<AnalyticsId>,
    /// Request timestamp
    pub sent_at: u64,
    /// Whether a response has been received
    pub completed: bool,
}

/// FL (Federated Learning) aggregation round
///
/// NWDAF acts as aggregator for distributed model updates from UPFs/gNBs.
#[derive(Debug, Clone)]
pub struct FlAggregationRound {
    /// Round ID
    pub round_id: u32,
    /// Analytics ID this round trains for
    pub analytics_id: AnalyticsId,
    /// Expected number of participant updates
    pub expected_participants: u32,
    /// Received gradient updates (participant ID → update vector hash)
    pub received_updates: HashMap<String, Vec<f64>>,
    /// Aggregated global model update (FedAvg result)
    pub aggregated_update: Option<Vec<f64>>,
}

impl FlAggregationRound {
    pub fn new(round_id: u32, analytics_id: AnalyticsId, expected: u32) -> Self {
        Self {
            round_id,
            analytics_id,
            expected_participants: expected,
            received_updates: HashMap::new(),
            aggregated_update: None,
        }
    }

    /// Registers a model update from a participant
    pub fn add_update(&mut self, participant_id: String, update: Vec<f64>) {
        self.received_updates.insert(participant_id, update);
    }

    /// Returns true if all expected updates have been received
    pub fn is_ready_to_aggregate(&self) -> bool {
        self.received_updates.len() >= self.expected_participants as usize
    }

    /// Performs FedAvg aggregation (element-wise mean of all updates)
    pub fn aggregate(&mut self) -> Option<&Vec<f64>> {
        if !self.is_ready_to_aggregate() || self.received_updates.is_empty() {
            return None;
        }
        let n = self.received_updates.len();
        let dim = self.received_updates.values().next()?.len();
        let mut avg = vec![0.0f64; dim];
        for update in self.received_updates.values() {
            for (i, &v) in update.iter().enumerate() {
                if i < dim {
                    avg[i] += v / n as f64;
                }
            }
        }
        self.aggregated_update = Some(avg);
        self.aggregated_update.as_ref()
    }
}

/// NWDAF federation manager
#[derive(Debug, Default)]
pub struct FederationManager {
    /// Known federation peers
    peers: HashMap<String, FederationPeer>,
    /// Active federated requests
    requests: HashMap<String, FederatedRequest>,
    /// Active FL rounds
    fl_rounds: HashMap<u32, FlAggregationRound>,
}

impl FederationManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a federation peer
    pub fn register_peer(&mut self, peer: FederationPeer) {
        self.peers.insert(peer.instance_id.clone(), peer);
    }

    /// Finds peers that can serve a given analytics ID
    pub fn find_peers_for(&self, analytics_id: AnalyticsId) -> Vec<&FederationPeer> {
        self.peers.values()
            .filter(|p| p.reachable && p.supports(analytics_id))
            .collect()
    }

    /// Updates peer reachability
    pub fn update_reachability(&mut self, instance_id: &str, reachable: bool) {
        if let Some(p) = self.peers.get_mut(instance_id) {
            p.reachable = reachable;
            if reachable {
                p.last_heartbeat = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs();
            }
        }
    }

    /// Creates a new FL aggregation round
    pub fn start_fl_round(&mut self, round: FlAggregationRound) -> u32 {
        let id = round.round_id;
        self.fl_rounds.insert(id, round);
        id
    }

    /// Adds a participant update to an FL round
    pub fn add_fl_update(
        &mut self,
        round_id: u32,
        participant_id: String,
        update: Vec<f64>,
    ) -> bool {
        if let Some(round) = self.fl_rounds.get_mut(&round_id) {
            round.add_update(participant_id, update);
            true
        } else {
            false
        }
    }

    /// Runs aggregation for a round, returns aggregated update
    pub fn aggregate_fl_round(&mut self, round_id: u32) -> Option<Vec<f64>> {
        self.fl_rounds.get_mut(&round_id)?.aggregate().cloned()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_registration_and_discovery() {
        let mut mgr = FederationManager::new();
        let peer = FederationPeer::new(
            "nwdaf-02".into(),
            "http://nwdaf-02:7815".into(),
            FederationPeerType::LocalNwdaf,
            vec![AnalyticsId::NfLoad, AnalyticsId::UeMobility],
        );
        mgr.register_peer(peer);
        assert_eq!(mgr.peer_count(), 1);
        let found = mgr.find_peers_for(AnalyticsId::NfLoad);
        assert_eq!(found.len(), 1);
        let not_found = mgr.find_peers_for(AnalyticsId::SliceLoad);
        assert!(not_found.is_empty());
    }

    #[test]
    fn test_fl_aggregation_fedavg() {
        let mut mgr = FederationManager::new();
        let round = FlAggregationRound::new(1, AnalyticsId::NfLoad, 2);
        mgr.start_fl_round(round);
        mgr.add_fl_update(1, "p1".into(), vec![1.0, 2.0, 3.0]);
        mgr.add_fl_update(1, "p2".into(), vec![3.0, 4.0, 5.0]);
        let agg = mgr.aggregate_fl_round(1).unwrap();
        // FedAvg: mean of [1,2,3] and [3,4,5] = [2,3,4]
        assert!((agg[0] - 2.0).abs() < 1e-9);
        assert!((agg[1] - 3.0).abs() < 1e-9);
        assert!((agg[2] - 4.0).abs() < 1e-9);
    }

    #[test]
    fn test_fl_not_ready_without_all_updates() {
        let mut round = FlAggregationRound::new(1, AnalyticsId::NfLoad, 3);
        round.add_update("p1".into(), vec![1.0]);
        assert!(!round.is_ready_to_aggregate());
        assert!(round.aggregate().is_none());
    }

    #[test]
    fn test_peer_unreachable_excluded() {
        let mut mgr = FederationManager::new();
        let peer = FederationPeer::new(
            "nwdaf-down".into(),
            "http://nwdaf-down:7815".into(),
            FederationPeerType::RemoteNwdaf,
            vec![AnalyticsId::NfLoad],
        );
        mgr.register_peer(peer);
        mgr.update_reachability("nwdaf-down", false);
        assert!(mgr.find_peers_for(AnalyticsId::NfLoad).is_empty());
    }
}
