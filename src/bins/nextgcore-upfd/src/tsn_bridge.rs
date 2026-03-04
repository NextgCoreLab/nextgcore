//! TSN (Time-Sensitive Networking) Bridge for UPF (Rel-17, TS 23.501 §5.28)
//!
//! Provides 5G-TSN bridge integration: IEEE 802.1Q VLAN/PCP tagging,
//! per-flow bridge port management, and CNC/PSFP configuration stubs.

use std::collections::HashMap;

/// 802.1Q PCP (Priority Code Point) value (3 bits, 0-7)
pub type Pcp = u8;

/// VLAN ID (12 bits, 1-4094)
pub type VlanId = u16;

/// TSN bridge port state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsnPortState {
    /// Port is open and forwarding
    Forwarding,
    /// Port is blocked (STP/MSTP)
    Blocking,
    /// Port is in learning state
    Learning,
    /// Port is disabled
    Disabled,
}

/// TSN flow entry: maps a 5QI/QFI to a TSN PCP and VLAN
#[derive(Debug, Clone)]
pub struct TsnFlowEntry {
    /// PDR ID this flow corresponds to
    pub pdr_id: u32,
    /// QFI from GTP-U extension header
    pub qfi: u8,
    /// 5QI mapped from QFI
    pub qi5: u8,
    /// Target VLAN ID for 802.1Q tagging
    pub vlan_id: VlanId,
    /// PCP value (0=BE … 7=NC per IEEE 802.1Q Table 8-5)
    pub pcp: Pcp,
}

/// TSN bridge configuration per UPF session
#[derive(Debug, Clone, Default)]
pub struct TsnBridgeConfig {
    /// VLAN ID to use for TSN traffic (0 = no tagging)
    pub default_vlan: VlanId,
    /// Map from QFI to PCP for QoS marking
    pub qfi_to_pcp: HashMap<u8, Pcp>,
    /// Whether to strip VLAN on egress to UE
    pub strip_vlan_on_dl: bool,
}

impl TsnBridgeConfig {
    /// Creates a default bridge config with no VLAN
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps a QFI to a PCP value per TS 23.501 Table 5.7.4-1 recommendations.
    ///
    /// 5QI 1 (GBR voice)   → PCP 6
    /// 5QI 2 (GBR video)   → PCP 5
    /// 5QI 65 (MCPTT)      → PCP 7
    /// 5QI 9 (default BE)  → PCP 0
    pub fn default_5qi_pcp_mapping() -> HashMap<u8, Pcp> {
        let mut m = HashMap::new();
        // Non-GBR conversational
        m.insert(1, 6u8);  // GBR conversational voice
        m.insert(2, 5u8);  // GBR conversational video
        m.insert(3, 4u8);  // GBR real-time gaming
        m.insert(4, 4u8);  // GBR non-conv video
        m.insert(65, 7u8); // Mission critical push-to-talk
        m.insert(66, 6u8); // Non-mission critical push-to-talk
        m.insert(7, 3u8);  // Non-GBR voice video, interactive gaming
        m.insert(8, 2u8);  // Non-GBR video, TCP-based
        m.insert(9, 0u8);  // Non-GBR (default bearer / best effort)
        m
    }

    /// Returns the PCP for a QFI, falling back to 0 (best effort)
    pub fn pcp_for_qfi(&self, qfi: u8) -> Pcp {
        *self.qfi_to_pcp.get(&qfi).unwrap_or(&0)
    }
}

/// Inserts an IEEE 802.1Q tag into a raw Ethernet frame.
///
/// Input:  [DST(6)] [SRC(6)] [EtherType(2)] [Payload...]
/// Output: [DST(6)] [SRC(6)] [0x8100(2)] [TCI(2)] [Original EtherType(2)] [Payload...]
pub fn insert_vlan_tag(frame: &[u8], vlan_id: VlanId, pcp: Pcp) -> Option<Vec<u8>> {
    if frame.len() < 14 {
        return None; // Not enough bytes for Ethernet header
    }
    let original_ether_type = &frame[12..14];
    let tci = ((pcp as u16 & 0x07) << 13) | (vlan_id & 0x0FFF);

    let mut tagged = Vec::with_capacity(frame.len() + 4);
    tagged.extend_from_slice(&frame[..12]);    // DST + SRC
    tagged.extend_from_slice(&[0x81, 0x00]);  // 802.1Q EtherType
    tagged.extend_from_slice(&tci.to_be_bytes()); // TCI
    tagged.extend_from_slice(original_ether_type);
    tagged.extend_from_slice(&frame[14..]);
    Some(tagged)
}

/// Strips an 802.1Q VLAN tag from a frame if present.
///
/// Returns the stripped frame or a copy of the original if not tagged.
pub fn strip_vlan_tag(frame: &[u8]) -> Vec<u8> {
    if frame.len() >= 16 && frame[12] == 0x81 && frame[13] == 0x00 {
        let mut stripped = Vec::with_capacity(frame.len() - 4);
        stripped.extend_from_slice(&frame[..12]);
        stripped.extend_from_slice(&frame[16..]); // skip 4-byte 802.1Q tag
        stripped
    } else {
        frame.to_vec()
    }
}

/// Active TSN bridge state per UPF
pub struct TsnBridge {
    config: TsnBridgeConfig,
    /// Flow entries keyed by PDR ID
    flows: HashMap<u32, TsnFlowEntry>,
}

impl TsnBridge {
    pub fn new(config: TsnBridgeConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
        }
    }

    /// Registers a PDR→TSN flow entry
    pub fn add_flow(&mut self, entry: TsnFlowEntry) {
        self.flows.insert(entry.pdr_id, entry);
    }

    /// Removes a flow entry by PDR ID
    pub fn remove_flow(&mut self, pdr_id: u32) {
        self.flows.remove(&pdr_id);
    }

    /// Returns the VLAN tag parameters for a given QFI, or None if no tagging needed
    pub fn tagging_params(&self, qfi: u8) -> Option<(VlanId, Pcp)> {
        if self.config.default_vlan == 0 {
            return None;
        }
        let pcp = self.config.pcp_for_qfi(qfi);
        Some((self.config.default_vlan, pcp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_vlan_tag_basic() {
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08; frame[13] = 0x00; // IPv4 EtherType
        let tagged = insert_vlan_tag(&frame, 100, 5).unwrap();
        assert_eq!(tagged.len(), 18);
        assert_eq!(&tagged[12..14], &[0x81, 0x00]);
        // TCI: pcp=5 (3 bits) | DEI=0 | VID=100 (12 bits) = 0b101_0_000001100100 = 0xA064
        let tci = u16::from_be_bytes([tagged[14], tagged[15]]);
        assert_eq!(tci >> 13, 5); // PCP
        assert_eq!(tci & 0x0FFF, 100); // VID
        assert_eq!(&tagged[16..18], &[0x08, 0x00]); // original EtherType preserved
    }

    #[test]
    fn test_strip_vlan_tag() {
        let mut frame = vec![0u8; 18];
        frame[12] = 0x81; frame[13] = 0x00; // 802.1Q
        frame[14] = 0xA0; frame[15] = 0x64; // TCI
        frame[16] = 0x08; frame[17] = 0x00; // IPv4
        let stripped = strip_vlan_tag(&frame);
        assert_eq!(stripped.len(), 14);
        assert_eq!(&stripped[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn test_strip_untagged_frame_unchanged() {
        let frame = vec![0u8; 60];
        let result = strip_vlan_tag(&frame);
        assert_eq!(result.len(), 60);
    }

    #[test]
    fn test_default_pcp_for_qfi_voice() {
        let config = TsnBridgeConfig {
            default_vlan: 10,
            qfi_to_pcp: TsnBridgeConfig::default_5qi_pcp_mapping(),
            strip_vlan_on_dl: false,
        };
        assert_eq!(config.pcp_for_qfi(1), 6); // GBR voice → PCP 6
        assert_eq!(config.pcp_for_qfi(9), 0); // Best effort → PCP 0
        assert_eq!(config.pcp_for_qfi(65), 7); // MCPTT → PCP 7
    }

    #[test]
    fn test_bridge_no_tagging_when_vlan_zero() {
        let bridge = TsnBridge::new(TsnBridgeConfig::new());
        assert!(bridge.tagging_params(1).is_none());
    }

    #[test]
    fn test_bridge_returns_params_when_vlan_set() {
        let bridge = TsnBridge::new(TsnBridgeConfig {
            default_vlan: 200,
            qfi_to_pcp: TsnBridgeConfig::default_5qi_pcp_mapping(),
            strip_vlan_on_dl: false,
        });
        let (vid, pcp) = bridge.tagging_params(9).unwrap();
        assert_eq!(vid, 200);
        assert_eq!(pcp, 0);
    }
}
