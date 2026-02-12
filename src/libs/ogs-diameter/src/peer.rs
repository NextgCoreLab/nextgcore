//! Diameter peer state machine per RFC 6733 Section 5.6
//!
//! Implements connection management for Diameter peers including:
//! - Capabilities Exchange (CER/CEA) for initial handshake
//! - Device Watchdog (DWR/DWA) for liveness detection
//! - Disconnect Peer (DPR/DPA) for graceful shutdown
//!
//! Simplified state machine:
//!   Closed -> WaitCEA (initiator sends CER)
//!   Closed -> WaitCER (responder waits for CER)
//!   WaitCEA -> Open (received CEA with success)
//!   WaitCER -> Open (received CER, sent CEA)
//!   Open -> Closing (sent DPR)
//!   Open -> Closed (received DPR, sent DPA)
//!   Closing -> Closed (received DPA)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::config::DiameterConfig;
use crate::error::{DiameterError, DiameterResult};
use crate::message::{base_cmd, DiameterMessage, BASE_APPLICATION_ID};
use crate::transport::DiameterTransport;

/// Peer connection state per RFC 6733
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// No connection
    Closed,
    /// Initiator: CER sent, waiting for CEA
    WaitCEA,
    /// Responder: waiting for incoming CER
    WaitCER,
    /// Capabilities exchanged, connection is operational
    Open,
    /// DPR sent, waiting for DPA before closing
    Closing,
}

/// Disconnect cause values for DPR (RFC 6733 Section 5.4.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DisconnectCause {
    Rebooting = 0,
    Busy = 1,
    DoNotWantToTalkToYou = 2,
}

/// Result of processing an incoming message in the peer state machine
#[derive(Debug)]
pub enum PeerEvent {
    /// Peer is now open and ready for application messages
    Established {
        origin_host: String,
        origin_realm: String,
    },
    /// Received an application-level message (not a base protocol message)
    Message(DiameterMessage),
    /// Peer disconnected (received DPR or connection lost)
    Disconnected,
    /// Watchdog response received
    WatchdogAck,
}

/// Diameter peer representing a single connection to a remote node
pub struct DiameterPeer {
    transport: DiameterTransport,
    state: PeerState,
    local_host: String,
    local_realm: String,
    remote_host: Option<String>,
    remote_realm: Option<String>,
    hop_by_hop_seq: u32,
    end_to_end_seq: u32,
    watchdog_interval: Duration,
}

impl DiameterPeer {
    /// Create a new peer from an established transport (responder side)
    pub fn new_responder(
        transport: DiameterTransport,
        config: &DiameterConfig,
    ) -> Self {
        Self {
            transport,
            state: PeerState::WaitCER,
            local_host: config.diameter_id.clone(),
            local_realm: config.diameter_realm.clone(),
            remote_host: None,
            remote_realm: None,
            hop_by_hop_seq: rand_u32(),
            end_to_end_seq: rand_u32(),
            watchdog_interval: Duration::from_secs(config.timer_tc as u64),
        }
    }

    /// Create a new peer and initiate connection (initiator side)
    pub fn new_initiator(
        transport: DiameterTransport,
        config: &DiameterConfig,
    ) -> Self {
        Self {
            transport,
            state: PeerState::Closed,
            local_host: config.diameter_id.clone(),
            local_realm: config.diameter_realm.clone(),
            remote_host: None,
            remote_realm: None,
            hop_by_hop_seq: rand_u32(),
            end_to_end_seq: rand_u32(),
            watchdog_interval: Duration::from_secs(config.timer_tc as u64),
        }
    }

    /// Get the current peer state
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Get the remote peer's Origin-Host (available after CER/CEA exchange)
    pub fn remote_host(&self) -> Option<&str> {
        self.remote_host.as_deref()
    }

    /// Get the remote peer's Origin-Realm (available after CER/CEA exchange)
    pub fn remote_realm(&self) -> Option<&str> {
        self.remote_realm.as_deref()
    }

    /// Get the next hop-by-hop identifier
    fn next_hop_by_hop(&mut self) -> u32 {
        self.hop_by_hop_seq = self.hop_by_hop_seq.wrapping_add(1);
        self.hop_by_hop_seq
    }

    /// Get the next end-to-end identifier
    fn next_end_to_end(&mut self) -> u32 {
        self.end_to_end_seq = self.end_to_end_seq.wrapping_add(1);
        self.end_to_end_seq
    }

    /// Initiate the capabilities exchange by sending CER
    pub async fn start(&mut self) -> DiameterResult<()> {
        match self.state {
            PeerState::Closed => {
                self.send_cer().await?;
                self.state = PeerState::WaitCEA;
                Ok(())
            }
            PeerState::WaitCER => {
                // Responder side: just wait for incoming CER
                Ok(())
            }
            _ => Err(DiameterError::Protocol(format!(
                "cannot start peer in state {:?}",
                self.state
            ))),
        }
    }

    /// Process the next event from this peer
    ///
    /// This handles all base protocol messages (CER/CEA, DWR/DWA, DPR/DPA)
    /// internally and returns application-level events to the caller.
    pub async fn next_event(&mut self) -> DiameterResult<PeerEvent> {
        let msg = self.transport.recv().await?;
        self.process_message(msg).await
    }

    /// Process a received message through the state machine
    async fn process_message(&mut self, msg: DiameterMessage) -> DiameterResult<PeerEvent> {
        let cmd = msg.header.command_code;
        let is_request = msg.header.is_request();

        match (self.state, cmd, is_request) {
            // Responder: received CER while waiting
            (PeerState::WaitCER, base_cmd::CAPABILITIES_EXCHANGE, true) => {
                self.handle_cer(msg).await
            }
            // Initiator: received CEA after sending CER
            (PeerState::WaitCEA, base_cmd::CAPABILITIES_EXCHANGE, false) => {
                self.handle_cea(msg).await
            }
            // Open: received DWR (watchdog request)
            (PeerState::Open, base_cmd::DEVICE_WATCHDOG, true) => {
                self.handle_dwr(msg).await
            }
            // Open: received DWA (watchdog answer)
            (PeerState::Open, base_cmd::DEVICE_WATCHDOG, false) => {
                Ok(PeerEvent::WatchdogAck)
            }
            // Open: received DPR (disconnect request)
            (PeerState::Open, base_cmd::DISCONNECT_PEER, true) => {
                self.handle_dpr(msg).await
            }
            // Closing: received DPA (disconnect answer)
            (PeerState::Closing, base_cmd::DISCONNECT_PEER, false) => {
                self.state = PeerState::Closed;
                self.transport.shutdown().await?;
                Ok(PeerEvent::Disconnected)
            }
            // Open: application message
            (PeerState::Open, _, _) => {
                Ok(PeerEvent::Message(msg))
            }
            // Unexpected message for current state
            _ => Err(DiameterError::Protocol(format!(
                "unexpected command {} (request={}) in state {:?}",
                cmd, is_request, self.state
            ))),
        }
    }

    /// Send a Diameter message through this peer
    pub async fn send_message(&mut self, msg: &DiameterMessage) -> DiameterResult<()> {
        if self.state != PeerState::Open {
            return Err(DiameterError::Protocol(format!(
                "cannot send message in state {:?}",
                self.state
            )));
        }
        self.transport.send(msg).await
    }

    /// Build and send Capabilities-Exchange-Request
    async fn send_cer(&mut self) -> DiameterResult<()> {
        let mut msg = DiameterMessage::new_request(
            base_cmd::CAPABILITIES_EXCHANGE,
            BASE_APPLICATION_ID,
        );
        msg.header.hop_by_hop_id = self.next_hop_by_hop();
        msg.header.end_to_end_id = self.next_end_to_end();

        // Origin-Host (mandatory)
        msg.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(self.local_host.clone()),
        ));
        // Origin-Realm (mandatory)
        msg.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(self.local_realm.clone()),
        ));
        // Origin-State-Id
        msg.add_avp(Avp::mandatory(
            avp_code::ORIGIN_STATE_ID,
            AvpData::Unsigned32(origin_state_id()),
        ));

        self.transport.send(&msg).await
    }

    /// Handle incoming CER: validate and respond with CEA
    async fn handle_cer(&mut self, cer: DiameterMessage) -> DiameterResult<PeerEvent> {
        let origin_host = cer
            .origin_host()
            .ok_or_else(|| DiameterError::MissingAvp("Origin-Host".into()))?
            .to_string();
        let origin_realm = cer
            .origin_realm()
            .ok_or_else(|| DiameterError::MissingAvp("Origin-Realm".into()))?
            .to_string();

        // Build CEA
        let mut cea = DiameterMessage::new_answer(&cer);
        // Result-Code: Success
        cea.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(crate::error::ResultCode::Success as u32),
        ));
        // Origin-Host
        cea.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(self.local_host.clone()),
        ));
        // Origin-Realm
        cea.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(self.local_realm.clone()),
        ));
        // Origin-State-Id
        cea.add_avp(Avp::mandatory(
            avp_code::ORIGIN_STATE_ID,
            AvpData::Unsigned32(origin_state_id()),
        ));

        self.transport.send(&cea).await?;
        self.remote_host = Some(origin_host.clone());
        self.remote_realm = Some(origin_realm.clone());
        self.state = PeerState::Open;

        Ok(PeerEvent::Established {
            origin_host,
            origin_realm,
        })
    }

    /// Handle incoming CEA: validate result code and transition to Open
    async fn handle_cea(&mut self, cea: DiameterMessage) -> DiameterResult<PeerEvent> {
        let result_code = cea
            .result_code()
            .ok_or_else(|| DiameterError::MissingAvp("Result-Code".into()))?;

        let rc: crate::error::ResultCode = result_code.into();
        if !rc.is_success() {
            self.state = PeerState::Closed;
            return Err(DiameterError::Protocol(format!(
                "CEA returned non-success result code: {result_code}"
            )));
        }

        let origin_host = cea
            .origin_host()
            .ok_or_else(|| DiameterError::MissingAvp("Origin-Host".into()))?
            .to_string();
        let origin_realm = cea
            .origin_realm()
            .ok_or_else(|| DiameterError::MissingAvp("Origin-Realm".into()))?
            .to_string();

        self.remote_host = Some(origin_host.clone());
        self.remote_realm = Some(origin_realm.clone());
        self.state = PeerState::Open;

        Ok(PeerEvent::Established {
            origin_host,
            origin_realm,
        })
    }

    /// Handle incoming DWR: respond with DWA
    async fn handle_dwr(&mut self, dwr: DiameterMessage) -> DiameterResult<PeerEvent> {
        let mut dwa = DiameterMessage::new_answer(&dwr);
        dwa.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(crate::error::ResultCode::Success as u32),
        ));
        dwa.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(self.local_host.clone()),
        ));
        dwa.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(self.local_realm.clone()),
        ));
        dwa.add_avp(Avp::mandatory(
            avp_code::ORIGIN_STATE_ID,
            AvpData::Unsigned32(origin_state_id()),
        ));

        self.transport.send(&dwa).await?;
        Ok(PeerEvent::WatchdogAck)
    }

    /// Send a DWR (Device-Watchdog-Request) to the peer
    pub async fn send_watchdog(&mut self) -> DiameterResult<()> {
        if self.state != PeerState::Open {
            return Err(DiameterError::Protocol(format!(
                "cannot send watchdog in state {:?}",
                self.state
            )));
        }

        let mut dwr = DiameterMessage::new_request(
            base_cmd::DEVICE_WATCHDOG,
            BASE_APPLICATION_ID,
        );
        dwr.header.hop_by_hop_id = self.next_hop_by_hop();
        dwr.header.end_to_end_id = self.next_end_to_end();
        dwr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(self.local_host.clone()),
        ));
        dwr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(self.local_realm.clone()),
        ));
        dwr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_STATE_ID,
            AvpData::Unsigned32(origin_state_id()),
        ));

        self.transport.send(&dwr).await
    }

    /// Handle incoming DPR: respond with DPA and close
    async fn handle_dpr(&mut self, dpr: DiameterMessage) -> DiameterResult<PeerEvent> {
        let mut dpa = DiameterMessage::new_answer(&dpr);
        dpa.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(crate::error::ResultCode::Success as u32),
        ));
        dpa.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(self.local_host.clone()),
        ));
        dpa.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(self.local_realm.clone()),
        ));

        self.transport.send(&dpa).await?;
        self.state = PeerState::Closed;
        self.transport.shutdown().await?;
        Ok(PeerEvent::Disconnected)
    }

    /// Initiate graceful disconnect by sending DPR
    pub async fn disconnect(&mut self, cause: DisconnectCause) -> DiameterResult<()> {
        if self.state != PeerState::Open {
            return Err(DiameterError::Protocol(format!(
                "cannot disconnect in state {:?}",
                self.state
            )));
        }

        let mut dpr = DiameterMessage::new_request(
            base_cmd::DISCONNECT_PEER,
            BASE_APPLICATION_ID,
        );
        dpr.header.hop_by_hop_id = self.next_hop_by_hop();
        dpr.header.end_to_end_id = self.next_end_to_end();
        dpr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(self.local_host.clone()),
        ));
        dpr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(self.local_realm.clone()),
        ));
        // Disconnect-Cause AVP (code 273)
        dpr.add_avp(Avp::mandatory(273, AvpData::Enumerated(cause as i32)));

        self.transport.send(&dpr).await?;
        self.state = PeerState::Closing;
        Ok(())
    }

    /// Get the watchdog interval for this peer
    pub fn watchdog_interval(&self) -> Duration {
        self.watchdog_interval
    }
}

/// Run a Diameter peer with automatic watchdog keepalive.
///
/// This spawns a loop that:
/// 1. Sends DWR at the configured `watchdog_interval`
/// 2. Processes incoming events and forwards application messages to the channel
/// 3. Detects missed watchdog responses and closes the connection
///
/// Returns when the peer is disconnected or an error occurs.
pub async fn run_peer_with_keepalive(
    mut peer: DiameterPeer,
    app_tx: tokio::sync::mpsc::Sender<DiameterMessage>,
) -> DiameterResult<()> {
    let interval = peer.watchdog_interval();
    let mut watchdog_timer = tokio::time::interval(interval);
    let mut missed_watchdogs: u32 = 0;
    const MAX_MISSED_WATCHDOGS: u32 = 3;

    loop {
        tokio::select! {
            _ = watchdog_timer.tick() => {
                if peer.state() == PeerState::Open {
                    if missed_watchdogs >= MAX_MISSED_WATCHDOGS {
                        log::warn!(
                            "Peer {:?} missed {} watchdogs, disconnecting",
                            peer.remote_host(),
                            missed_watchdogs
                        );
                        let _ = peer.disconnect(DisconnectCause::Rebooting).await;
                        return Err(DiameterError::Protocol(
                            "watchdog timeout".into(),
                        ));
                    }
                    match peer.send_watchdog().await {
                        Ok(()) => {
                            missed_watchdogs += 1;
                        }
                        Err(e) => {
                            log::warn!("Failed to send watchdog: {e}");
                            return Err(e);
                        }
                    }
                }
            }
            event_result = peer.next_event() => {
                match event_result? {
                    PeerEvent::Established { origin_host, origin_realm } => {
                        log::info!(
                            "Peer established: host={origin_host}, realm={origin_realm}"
                        );
                        missed_watchdogs = 0;
                    }
                    PeerEvent::Message(msg) => {
                        if app_tx.send(msg).await.is_err() {
                            log::warn!("Application channel closed");
                            return Ok(());
                        }
                    }
                    PeerEvent::WatchdogAck => {
                        missed_watchdogs = 0;
                    }
                    PeerEvent::Disconnected => {
                        log::info!("Peer disconnected");
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Peer table managing multiple Diameter peer connections
pub struct PeerTable {
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
}

/// Information about a peer in the peer table
struct PeerInfo {
    state: PeerState,
    addr: SocketAddr,
    #[allow(dead_code)]
    realm: String,
}

impl PeerTable {
    /// Create an empty peer table
    pub fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a peer that has completed capabilities exchange
    pub async fn register(
        &self,
        origin_host: String,
        realm: String,
        addr: SocketAddr,
        state: PeerState,
    ) {
        let mut peers = self.peers.lock().await;
        peers.insert(origin_host, PeerInfo { state, addr, realm });
    }

    /// Remove a peer from the table
    pub async fn remove(&self, origin_host: &str) {
        let mut peers = self.peers.lock().await;
        peers.remove(origin_host);
    }

    /// Update a peer's state
    pub async fn update_state(&self, origin_host: &str, state: PeerState) {
        let mut peers = self.peers.lock().await;
        if let Some(info) = peers.get_mut(origin_host) {
            info.state = state;
        }
    }

    /// Check if a peer is known and in Open state
    pub async fn is_peer_open(&self, origin_host: &str) -> bool {
        let peers = self.peers.lock().await;
        peers
            .get(origin_host)
            .map(|info| info.state == PeerState::Open)
            .unwrap_or(false)
    }

    /// Get the address of a peer by origin host
    pub async fn peer_addr(&self, origin_host: &str) -> Option<SocketAddr> {
        let peers = self.peers.lock().await;
        peers.get(origin_host).map(|info| info.addr)
    }

    /// Get the list of all connected peer origin hosts
    pub async fn connected_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().await;
        peers
            .iter()
            .filter(|(_, info)| info.state == PeerState::Open)
            .map(|(host, _)| host.clone())
            .collect()
    }

    /// Get the count of connected peers
    pub async fn connected_count(&self) -> usize {
        let peers = self.peers.lock().await;
        peers
            .values()
            .filter(|info| info.state == PeerState::Open)
            .count()
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate an Origin-State-Id (seconds since process start, simplified)
fn origin_state_id() -> u32 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Generate a pseudo-random u32 for sequence initialization
fn rand_u32() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Mix bits for better distribution
    nanos.wrapping_mul(2654435761)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DiameterConfig;
    use crate::transport::{DiameterListener, DiameterTransport};

    fn test_config(host: &str, realm: &str) -> DiameterConfig {
        DiameterConfig {
            diameter_id: host.to_string(),
            diameter_realm: realm.to_string(),
            timer_tc: 30,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_cer_cea_exchange() {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_cfg = test_config("hss.epc.mnc001.mcc001.3gppnetwork.org", "epc.mnc001.mcc001.3gppnetwork.org");
        let client_cfg = test_config("mme.epc.mnc001.mcc001.3gppnetwork.org", "epc.mnc001.mcc001.3gppnetwork.org");

        // Spawn server (responder)
        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            let event = peer.next_event().await.unwrap();
            match event {
                PeerEvent::Established { origin_host, origin_realm } => {
                    assert_eq!(origin_host, "mme.epc.mnc001.mcc001.3gppnetwork.org");
                    assert_eq!(origin_realm, "epc.mnc001.mcc001.3gppnetwork.org");
                }
                _ => panic!("expected Established event"),
            }
            assert_eq!(peer.state(), PeerState::Open);
            peer
        });

        // Client (initiator)
        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();
        assert_eq!(client.state(), PeerState::WaitCEA);

        let event = client.next_event().await.unwrap();
        match event {
            PeerEvent::Established { origin_host, origin_realm } => {
                assert_eq!(origin_host, "hss.epc.mnc001.mcc001.3gppnetwork.org");
                assert_eq!(origin_realm, "epc.mnc001.mcc001.3gppnetwork.org");
            }
            _ => panic!("expected Established event"),
        }
        assert_eq!(client.state(), PeerState::Open);

        let _server_peer = handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_watchdog_exchange() {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_cfg = test_config("hss.example.com", "example.com");
        let client_cfg = test_config("mme.example.com", "example.com");

        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            // Handle CER
            let _event = peer.next_event().await.unwrap();
            // Handle DWR -> send DWA
            let event = peer.next_event().await.unwrap();
            assert!(matches!(event, PeerEvent::WatchdogAck));
            peer
        });

        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();
        let _event = client.next_event().await.unwrap();

        // Send DWR
        client.send_watchdog().await.unwrap();
        // Receive DWA
        let event = client.next_event().await.unwrap();
        assert!(matches!(event, PeerEvent::WatchdogAck));

        let _server_peer = handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_disconnect_exchange() {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_cfg = test_config("hss.example.com", "example.com");
        let client_cfg = test_config("mme.example.com", "example.com");

        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            // Handle CER
            let _event = peer.next_event().await.unwrap();
            // Handle DPR -> send DPA, transition to Closed
            let event = peer.next_event().await.unwrap();
            assert!(matches!(event, PeerEvent::Disconnected));
            assert_eq!(peer.state(), PeerState::Closed);
        });

        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();
        let _event = client.next_event().await.unwrap();
        assert_eq!(client.state(), PeerState::Open);

        // Send DPR
        client.disconnect(DisconnectCause::Rebooting).await.unwrap();
        assert_eq!(client.state(), PeerState::Closing);

        // Receive DPA
        let event = client.next_event().await.unwrap();
        assert!(matches!(event, PeerEvent::Disconnected));
        assert_eq!(client.state(), PeerState::Closed);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_peer_table() {
        let table = PeerTable::new();
        let addr: std::net::SocketAddr = ([10, 0, 0, 1], 3868).into();

        table
            .register("hss.example.com".into(), "example.com".into(), addr, PeerState::Open)
            .await;

        assert!(table.is_peer_open("hss.example.com").await);
        assert!(!table.is_peer_open("unknown.example.com").await);
        assert_eq!(table.connected_count().await, 1);
        assert_eq!(table.connected_peers().await, vec!["hss.example.com".to_string()]);

        table.update_state("hss.example.com", PeerState::Closing).await;
        assert!(!table.is_peer_open("hss.example.com").await);
        assert_eq!(table.connected_count().await, 0);

        table.remove("hss.example.com").await;
        assert_eq!(table.peer_addr("hss.example.com").await, None);
    }

    #[tokio::test]
    async fn test_application_message_passthrough() {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_cfg = test_config("hss.example.com", "example.com");
        let client_cfg = test_config("mme.example.com", "example.com");

        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            // CER/CEA
            let _event = peer.next_event().await.unwrap();
            // Receive application message (S6a AIR, command code 318)
            let event = peer.next_event().await.unwrap();
            match event {
                PeerEvent::Message(msg) => {
                    assert_eq!(msg.header.command_code, 318);
                    assert!(msg.header.is_request());
                    // Send answer
                    let answer = DiameterMessage::new_answer(&msg);
                    peer.send_message(&answer).await.unwrap();
                }
                _ => panic!("expected Message event"),
            }
        });

        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();
        let _event = client.next_event().await.unwrap();

        // Send an S6a AIR
        let mut air = DiameterMessage::new_request(318, 16777251);
        air.header.hop_by_hop_id = 42;
        air.header.end_to_end_id = 42;
        client.send_message(&air).await.unwrap();

        // Receive answer
        let event = client.next_event().await.unwrap();
        match event {
            PeerEvent::Message(msg) => {
                assert_eq!(msg.header.command_code, 318);
                assert!(msg.header.is_answer());
            }
            _ => panic!("expected Message event"),
        }

        handle.await.unwrap();
    }
}
