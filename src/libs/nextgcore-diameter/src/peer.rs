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
pub struct DiameterPeer<T = DiameterTransport> {
    transport: T,
    state: PeerState,
    local_host: String,
    local_realm: String,
    remote_host: Option<String>,
    remote_realm: Option<String>,
    hop_by_hop_seq: u32,
    end_to_end_seq: u32,
    watchdog_interval: Duration,
    /// Applications advertised in CER/CEA and used to reject a peer with none in
    /// common (RFC 6733 §5.3). Empty means "do not negotiate".
    applications: crate::applications::ApplicationRegistry,
    /// Addresses advertised as `Host-IP-Address`. Derived from
    /// `DiameterConfig::address`; empty when unset, in which case the AVP is
    /// omitted -- the RFC makes it mandatory, but inventing an address would
    /// advertise something unroutable, which is worse than omitting it.
    host_addresses: Vec<std::net::IpAddr>,
}

/// Parse `DiameterConfig::address` into advertisable Host-IP-Addresses.
///
/// A comma-separated list is accepted so a multi-homed node can advertise every
/// address, as `1* { Host-IP-Address }` allows. Unparseable entries are warned
/// about and skipped rather than failing peer construction: a bad address in
/// config should degrade the advertisement, not stop the node from starting.
fn parse_host_addresses(config: &DiameterConfig) -> Vec<std::net::IpAddr> {
    let Some(raw) = config.address.as_deref() else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                log::warn!("ignoring unparseable Diameter address '{s}' for Host-IP-Address");
                None
            }
        })
        .collect()
}

impl<T: crate::transport::DiameterTransportIo> DiameterPeer<T> {
    /// Create a new peer from an established transport (responder side)
    pub fn new_responder(transport: T, config: &DiameterConfig) -> Self {
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
            applications: config.applications.clone(),
            host_addresses: parse_host_addresses(config),
        }
    }

    /// Create a new peer and initiate connection (initiator side)
    pub fn new_initiator(transport: T, config: &DiameterConfig) -> Self {
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
            applications: config.applications.clone(),
            host_addresses: parse_host_addresses(config),
        }
    }

    /// Alias for [`Self::new_responder`], named to make a non-TCP transport
    /// explicit at the call site.
    ///
    /// The plain constructors are generic now, so these add no capability; they
    /// exist so a reader of a test or a daemon can see that the peer is not on
    /// the default TCP transport without inspecting the argument's type.
    pub fn new_responder_generic(transport: T, config: &DiameterConfig) -> Self {
        Self::new_responder(transport, config)
    }

    /// Alias for [`Self::new_initiator`]. See [`Self::new_responder_generic`].
    pub fn new_initiator_generic(transport: T, config: &DiameterConfig) -> Self {
        Self::new_initiator(transport, config)
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
    ///
    /// # Cancel safety
    ///
    /// This method is **not** cancel-safe and must not be used as a `select!`
    /// branch: [`Self::handle_message`] can await a write (a DWA answering a
    /// watchdog, a DPA answering a disconnect), so dropping the future mid-write
    /// would leave a partial message on the wire and desynchronise framing for
    /// every subsequent message. Use [`Self::recv_raw`] plus
    /// [`Self::handle_message`] when the read has to race another branch — see
    /// [`crate::session`], which does exactly that.
    pub async fn next_event(&mut self) -> DiameterResult<PeerEvent> {
        let msg = self.recv_raw().await?;
        self.handle_message(msg).await
    }

    /// Read the next message off the wire without interpreting it.
    ///
    /// # Cancel safety
    ///
    /// This **is** cancel-safe, which is the reason it is split out. The only
    /// await is the transport's own read into a buffer it owns: if the future is
    /// dropped, no bytes are consumed from the socket and any partial message
    /// already buffered stays buffered, so a later call resumes exactly where
    /// this one left off. That makes it sound as a `select!` branch, unlike
    /// [`Self::next_event`].
    ///
    /// The cancel-safety guarantee is a property of each
    /// [`crate::transport::DiameterTransportIo`] implementation, not of this
    /// wrapper: TCP buffers into `read_buf` and SCTP reads one whole message, so
    /// both hold. A future transport must preserve it.
    pub async fn recv_raw(&mut self) -> DiameterResult<DiameterMessage> {
        self.transport.recv_message().await
    }

    /// Advance the state machine for a message obtained from [`Self::recv_raw`].
    ///
    /// Handles the base protocol (CER/CEA, DWR/DWA, DPR/DPA) internally,
    /// answering where the RFC requires it, and returns application-level events
    /// to the caller. Not cancel-safe: see [`Self::next_event`].
    pub async fn handle_message(&mut self, msg: DiameterMessage) -> DiameterResult<PeerEvent> {
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
            (PeerState::Open, base_cmd::DEVICE_WATCHDOG, true) => self.handle_dwr(msg).await,
            // Open: received DWA (watchdog answer)
            (PeerState::Open, base_cmd::DEVICE_WATCHDOG, false) => Ok(PeerEvent::WatchdogAck),
            // Open: received DPR (disconnect request)
            (PeerState::Open, base_cmd::DISCONNECT_PEER, true) => self.handle_dpr(msg).await,
            // Closing: received DPA (disconnect answer)
            (PeerState::Closing, base_cmd::DISCONNECT_PEER, false) => {
                self.state = PeerState::Closed;
                self.transport.close().await?;
                Ok(PeerEvent::Disconnected)
            }
            // Open: application message
            (PeerState::Open, _, _) => Ok(PeerEvent::Message(msg)),
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
        self.transport.send_message(msg).await
    }

    /// Build and send Capabilities-Exchange-Request
    async fn send_cer(&mut self) -> DiameterResult<()> {
        let mut msg =
            DiameterMessage::new_request(base_cmd::CAPABILITIES_EXCHANGE, BASE_APPLICATION_ID);
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

        // Host-IP-Address, Vendor-Id, Product-Name (all mandatory per RFC 6733
        // §5.3.1 and all previously absent), plus one advertisement per declared
        // application. With an empty registry this still adds the mandatory AVPs
        // and advertises nothing, which is what the old code did minus the
        // conformance violation.
        self.applications
            .append_capabilities(&mut msg, &self.host_addresses);

        self.transport.send_message(&msg).await
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

        // Capability negotiation (RFC 6733 §5.3). `negotiate` returns None only
        // when both sides advertised applications and none matched; an empty
        // registry on either side is accepted for backward compatibility, with
        // the reasoning on `ApplicationRegistry::negotiate`.
        let peer_apps = crate::applications::advertised_applications(&cer);
        let negotiated = self.applications.negotiate(&peer_apps);

        let result_code = match &negotiated {
            Some(common) => {
                if !common.is_empty() {
                    log::info!(
                        "CER from {origin_host}: {} common application(s): {}",
                        common.len(),
                        common
                            .iter()
                            .map(|a| a.id.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                crate::error::ResultCode::Success as u32
            }
            None => {
                log::warn!(
                    "CER from {origin_host} rejected: no common application (local {:?}, peer {:?})",
                    self.applications
                        .applications()
                        .map(|a| a.id)
                        .collect::<Vec<_>>(),
                    peer_apps.iter().map(|a| a.id).collect::<Vec<_>>()
                );
                crate::error::ResultCode::NoCommonApplication as u32
            }
        };

        // Build CEA
        let mut cea = DiameterMessage::new_answer(&cer);
        cea.add_avp(Avp::mandatory(
            avp_code::RESULT_CODE,
            AvpData::Unsigned32(result_code),
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
        // The CEA advertises our own capabilities too: §5.3.2 gives it the same
        // mandatory AVPs as the CER, and the initiator has no other way to learn
        // what we support.
        self.applications
            .append_capabilities(&mut cea, &self.host_addresses);

        self.transport.send_message(&cea).await?;

        // Only reach Open on success. On 5010 the RFC closes the connection, so
        // the peer is reported as Disconnected rather than Established and stays
        // out of PeerState::Open -- which is what makes `send_message` refuse to
        // carry application traffic over it.
        if negotiated.is_none() {
            self.state = PeerState::Closed;
            self.transport.close().await?;
            return Ok(PeerEvent::Disconnected);
        }

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

        self.transport.send_message(&dwa).await?;
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

        let mut dwr = DiameterMessage::new_request(base_cmd::DEVICE_WATCHDOG, BASE_APPLICATION_ID);
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

        self.transport.send_message(&dwr).await
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

        self.transport.send_message(&dpa).await?;
        self.state = PeerState::Closed;
        self.transport.close().await?;
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

        let mut dpr = DiameterMessage::new_request(base_cmd::DISCONNECT_PEER, BASE_APPLICATION_ID);
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

        self.transport.send_message(&dpr).await?;
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

/// This node's Origin-State-Id: constant for the lifetime of the process,
/// advancing only across a restart (RFC 6733 §8.16).
///
/// # Why this is latched rather than computed per call
///
/// This used to return `SystemTime::now().as_secs()` on every call, so the
/// advertised value increased once per second. Origin-State-Id is how a peer
/// detects that a node has RESTARTED and its session state is therefore gone:
/// a value that keeps climbing tells every peer this node is perpetually
/// rebooting. A conformant HSS/PCRF/DRA is entitled to discard the sessions it
/// holds for us each time it sees a higher value, so the bug is not cosmetic --
/// it invites peers to drop live state, and it does so more often the longer the
/// connection lives (CER, CEA, DWR and DWA all carry the value, and the watchdog
/// re-sends it periodically).
///
/// Seeding from the wall clock at first use is deliberate and matches the RFC's
/// suggestion: it must increase monotonically ACROSS restarts, so it cannot be a
/// fixed constant or a counter that starts at zero. A restart within the same
/// second reuses the value, which is acceptable -- the RFC only requires that it
/// not decrease, and one second of ambiguity after a crash-restart is a far
/// smaller problem than announcing a reboot every second.
/// # What consumes a RECEIVED Origin-State-Id in this tree: nothing
///
/// Enumerated for #280 across the whole workspace: the only readers of AVP 278
/// are the four senders below. `handle_cea` validates Result-Code, Origin-Host
/// and Origin-Realm and never looks at the peer's Origin-State-Id; `handle_cer`,
/// `handle_dwr` and `handle_dwa` likewise. No NF (`hssd`, `pcrfd`, `mmed`)
/// references the AVP at all.
///
/// So this fix has **no receive-side behaviour change to declare**: making our
/// own value stable cannot perturb an in-tree peer, because no in-tree peer acts
/// on the value it receives. The corollary is a real gap rather than a
/// reassurance -- Diameter peer-restart detection (TS 23.007 restoration) does
/// not exist here in either direction, and closing it needs a per-NF decision
/// about what to discard on a detected restart. Tracked separately; #280 asks
/// for this enumeration, not for the receive side.
static ORIGIN_STATE_ID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// This node's Origin-State-Id (RFC 6733 §8.16). Stable for the process
/// lifetime; see [`ORIGIN_STATE_ID`].
fn origin_state_id() -> u32 {
    *ORIGIN_STATE_ID.get_or_init(|| derive_origin_state_id(std::time::SystemTime::now()))
}

/// Derive an Origin-State-Id from a process-start instant.
///
/// Split out of the latch so the property §8.16 actually requires -- that a
/// LATER process start yields a GREATER value -- is testable. Inside the latch
/// it was not: a single process observes exactly one value, so a test can only
/// ever confirm stability, which is the weaker half of the requirement.
///
/// A clock reading before the epoch yields `0`. That is the floor rather than a
/// wrap-around, so a node with a badly wrong clock advertises "oldest possible
/// state" instead of a value a peer would read as newer than one from a healthy
/// node.
fn derive_origin_state_id(start: std::time::SystemTime) -> u32 {
    start
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
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
    use crate::transport::{DiameterListener, DiameterTransport, DiameterTransportIo};

    fn test_config(host: &str, realm: &str) -> DiameterConfig {
        DiameterConfig {
            diameter_id: host.to_string(),
            diameter_realm: realm.to_string(),
            timer_tc: 30,
            ..Default::default()
        }
    }

    /// Origin-State-Id must be CONSTANT while the process runs (RFC 6733 §8.16):
    /// it is how a peer detects a genuine restart. It previously returned
    /// `SystemTime::now().as_secs()` per call, so it advanced every second and
    /// told every peer this node was perpetually rebooting -- inviting a
    /// conformant peer to discard our live session state repeatedly.
    ///
    /// Sleeping past a second boundary is what makes this a real regression
    /// test: the old implementation returned a different value here, the latched
    /// one cannot.
    #[test]
    fn origin_state_id_is_stable_across_a_second_boundary() {
        let first = origin_state_id();
        assert_ne!(first, 0, "a zero state id would mean the clock read failed");

        // Comfortably longer than one second, since the old code changed value
        // on each wall-clock second tick.
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        assert_eq!(
            origin_state_id(),
            first,
            "Origin-State-Id changed while the process kept running"
        );
    }

    /// Every call site (CER, CEA, DWR, DWA) must see the same value; a peer that
    /// compares the CER's id against a later DWR's would otherwise conclude the
    /// node restarted mid-connection.
    #[test]
    fn origin_state_id_is_identical_across_repeated_reads() {
        let baseline = origin_state_id();
        for _ in 0..1000 {
            assert_eq!(origin_state_id(), baseline);
        }
    }

    /// §8.16's requirement has TWO halves, and stability is only the first: the
    /// value must also be *greater* after a restart, because that ordering is
    /// what tells a peer which of two states is the newer one. A latched value
    /// cannot be tested for that from inside one process -- one process observes
    /// exactly one value -- which is why the derivation is a separate function.
    ///
    /// The three cases are the three a real deployment produces: an ordinary
    /// restart minutes later, a restart inside the same second (§8.16 requires
    /// non-decreasing, not strictly increasing, so equality is conformant), and
    /// a clock that reads before the epoch.
    #[test]
    fn a_later_process_start_derives_a_greater_origin_state_id() {
        use std::time::{Duration, SystemTime};

        let first_boot = SystemTime::UNIX_EPOCH + Duration::from_secs(1_757_000_000);
        let after_restart = first_boot + Duration::from_secs(600);

        assert!(
            derive_origin_state_id(after_restart) > derive_origin_state_id(first_boot),
            "a process that started later must advertise a greater Origin-State-Id"
        );

        // Same second: non-decreasing is what §8.16 asks for, so equal is right.
        assert_eq!(
            derive_origin_state_id(first_boot + Duration::from_millis(400)),
            derive_origin_state_id(first_boot),
            "a restart inside one second reuses the value rather than decreasing"
        );

        // Pre-epoch clock: floored at 0 rather than wrapped, so a node with a
        // broken clock claims the OLDEST state instead of the newest.
        assert_eq!(
            derive_origin_state_id(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
            0,
            "a pre-epoch clock must floor at 0, not wrap to u32::MAX"
        );
    }

    /// Build a CER by hand for the raw side of the capture tests below. Only the
    /// AVPs `handle_cer` actually reads (Origin-Host, Origin-Realm) plus an
    /// Origin-State-Id of our own, so the responder answers 2001 and reaches
    /// Open.
    fn hand_built_cer(host: &str, realm: &str) -> DiameterMessage {
        let mut cer =
            DiameterMessage::new_request(base_cmd::CAPABILITIES_EXCHANGE, BASE_APPLICATION_ID);
        cer.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity(host.to_string()),
        ));
        cer.add_avp(Avp::mandatory(
            avp_code::ORIGIN_REALM,
            AvpData::DiameterIdentity(realm.to_string()),
        ));
        cer
    }

    fn received_origin_state_id(msg: &DiameterMessage, what: &str) -> u32 {
        msg.find_avp(avp_code::ORIGIN_STATE_ID)
            .unwrap_or_else(|| panic!("{what} carried no Origin-State-Id"))
            .as_u32()
            .unwrap_or_else(|| panic!("{what}'s Origin-State-Id was not a Unsigned32"))
    }

    /// #280 criterion 3: every message-building path must carry the LATCHED
    /// value, not just the latch itself being stable. Four paths emit AVP 278 --
    /// `send_cer`, `handle_cer`'s CEA, `send_watchdog`'s DWR and `handle_dwr`'s
    /// DWA -- and each calls `origin_state_id()` on its own, so a fifth path
    /// added later could reintroduce a per-call read without disturbing the
    /// latch's own tests.
    ///
    /// **The 1.1s sleep is the whole test.** The defect was
    /// `now().as_secs()` recomputed per call, which returns the SAME value for
    /// every message sent inside one wall-clock second -- so a handshake and a
    /// watchdog run back to back agree with each other even with the bug
    /// present, and the assertion would prove nothing. Crossing a second
    /// boundary between the handshake and the watchdog is the only arrangement
    /// in which the old code fails this test.
    ///
    /// Both directions are captured, because the request paths and the answer
    /// paths are different functions: this node is the raw side twice, once
    /// facing a real responder (capturing its CEA and DWA) and once facing a
    /// real initiator (capturing its CER and DWR).
    #[tokio::test]
    async fn every_message_path_carries_the_latched_origin_state_id() {
        let latched = origin_state_id();

        // ---- Direction 1: capture a real RESPONDER's CEA and DWA. ----
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let responder_addr = listener.local_addr().unwrap();
        let responder_cfg = test_config("hss.example.org", "epc.example.org");

        let responder = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &responder_cfg);
            peer.start().await.unwrap();
            // CER -> CEA
            assert!(matches!(
                peer.next_event().await.unwrap(),
                PeerEvent::Established { .. }
            ));
            // DWR -> DWA
            assert!(matches!(
                peer.next_event().await.unwrap(),
                PeerEvent::WatchdogAck
            ));
        });

        let mut raw = DiameterTransport::connect(responder_addr).await.unwrap();
        raw.send_message(&hand_built_cer("mme.example.org", "epc.example.org"))
            .await
            .unwrap();
        let cea = raw.recv_message().await.unwrap();
        let cea_osi = received_origin_state_id(&cea, "CEA");

        // Cross a second boundary before the second exchange.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

        let mut dwr = DiameterMessage::new_request(base_cmd::DEVICE_WATCHDOG, BASE_APPLICATION_ID);
        dwr.add_avp(Avp::mandatory(
            avp_code::ORIGIN_HOST,
            AvpData::DiameterIdentity("mme.example.org".to_string()),
        ));
        raw.send_message(&dwr).await.unwrap();
        let dwa = raw.recv_message().await.unwrap();
        let dwa_osi = received_origin_state_id(&dwa, "DWA");

        responder.await.unwrap();

        assert_eq!(
            cea_osi, dwa_osi,
            "handle_cer's CEA and handle_dwr's DWA disagreed across a second boundary"
        );
        assert_eq!(cea_osi, latched, "the CEA did not carry the latched value");

        // ---- Direction 2: capture a real INITIATOR's CER and DWR. ----
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let raw_addr = listener.local_addr().unwrap();

        let raw_side = tokio::spawn(async move {
            let mut raw = listener.accept().await.unwrap();
            let cer = raw.recv_message().await.unwrap();
            let cer_osi = received_origin_state_id(&cer, "CER");

            // Answer a minimal successful CEA so the initiator reaches Open;
            // `send_watchdog` refuses to build a DWR in any other state.
            let mut cea = DiameterMessage::new_answer(&cer);
            cea.add_avp(Avp::mandatory(
                avp_code::RESULT_CODE,
                AvpData::Unsigned32(crate::error::ResultCode::Success as u32),
            ));
            cea.add_avp(Avp::mandatory(
                avp_code::ORIGIN_HOST,
                AvpData::DiameterIdentity("hss.example.org".to_string()),
            ));
            cea.add_avp(Avp::mandatory(
                avp_code::ORIGIN_REALM,
                AvpData::DiameterIdentity("epc.example.org".to_string()),
            ));
            raw.send_message(&cea).await.unwrap();

            let dwr = raw.recv_message().await.unwrap();
            (cer_osi, received_origin_state_id(&dwr, "DWR"))
        });

        let transport = DiameterTransport::connect(raw_addr).await.unwrap();
        let initiator_cfg = test_config("mme.example.org", "epc.example.org");
        let mut initiator = DiameterPeer::new_initiator(transport, &initiator_cfg);
        initiator.start().await.unwrap();
        assert!(matches!(
            initiator.next_event().await.unwrap(),
            PeerEvent::Established { .. }
        ));

        // Same second boundary, this time between the CER and the DWR.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        initiator.send_watchdog().await.unwrap();

        let (cer_osi, dwr_osi) = raw_side.await.unwrap();

        assert_eq!(
            cer_osi, dwr_osi,
            "send_cer and send_watchdog disagreed across a second boundary"
        );
        assert_eq!(cer_osi, latched, "the CER did not carry the latched value");
    }

    #[tokio::test]
    async fn test_cer_cea_exchange() {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_cfg = test_config(
            "hss.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
        );
        let client_cfg = test_config(
            "mme.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
        );

        // Spawn server (responder)
        let handle = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            let event = peer.next_event().await.unwrap();
            match event {
                PeerEvent::Established {
                    origin_host,
                    origin_realm,
                } => {
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
            PeerEvent::Established {
                origin_host,
                origin_realm,
            } => {
                assert_eq!(origin_host, "hss.epc.mnc001.mcc001.3gppnetwork.org");
                assert_eq!(origin_realm, "epc.mnc001.mcc001.3gppnetwork.org");
            }
            _ => panic!("expected Established event"),
        }
        assert_eq!(client.state(), PeerState::Open);

        let _server_peer = handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // CER/CEA application negotiation (RFC 6733 §5.3), issue #55
    // -----------------------------------------------------------------------

    fn config_with_apps(host: &str, apps: &[crate::applications::ApplicationId]) -> DiameterConfig {
        let mut registry = crate::applications::ApplicationRegistry::new("NextGCore test");
        for app in apps {
            registry = registry.with_application(*app);
        }
        DiameterConfig {
            diameter_id: host.to_string(),
            diameter_realm: "epc.example.org".to_string(),
            address: Some("127.0.0.1".to_string()),
            applications: registry,
            ..Default::default()
        }
    }

    /// An MME advertising only S6a meeting a PCRF that speaks only Gx/Rx must be
    /// refused with 5010 and must NOT reach Open — the case RFC 6733 §5.3
    /// describes and that `handle_cer` previously could not express, because it
    /// answered 2001 unconditionally.
    #[tokio::test]
    async fn cer_with_no_common_application_is_rejected_with_5010() {
        use crate::applications::well_known;

        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        // Responder speaks Gx and Rx only.
        let server_cfg = config_with_apps("pcrf.example.org", &[well_known::GX, well_known::RX]);
        let server = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            let event = peer.next_event().await.unwrap();
            // The responder reports a disconnect, not an establishment.
            assert!(
                matches!(event, PeerEvent::Disconnected),
                "expected Disconnected on no-common-application"
            );
            assert_ne!(
                peer.state(),
                PeerState::Open,
                "a refused peer must never reach Open"
            );
        });

        // Initiator speaks S6a only.
        let client_cfg = config_with_apps("mme.example.org", &[well_known::S6A]);
        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();

        // The initiator sees the 5010 CEA as an error (is_success is 2000..3000).
        let result = client.next_event().await;
        assert!(
            result.is_err(),
            "a 5010 CEA must not be treated as a successful handshake"
        );
        assert_ne!(client.state(), PeerState::Open);

        server.await.unwrap();
    }

    /// One application in common is enough: an MME (S6a) and an HSS
    /// (S6a + Cx + SWx) must both reach Open.
    #[tokio::test]
    async fn cer_with_one_common_application_succeeds() {
        use crate::applications::well_known;

        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_cfg = config_with_apps(
            "hss.example.org",
            &[well_known::S6A, well_known::CX, well_known::SWX],
        );
        let server = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            let event = peer.next_event().await.unwrap();
            assert!(matches!(event, PeerEvent::Established { .. }));
            assert_eq!(peer.state(), PeerState::Open);
        });

        let client_cfg = config_with_apps("mme.example.org", &[well_known::S6A]);
        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();
        let event = client.next_event().await.unwrap();
        assert!(matches!(event, PeerEvent::Established { .. }));
        assert_eq!(client.state(), PeerState::Open);

        server.await.unwrap();
    }

    /// A CER must now carry the three AVPs the ABNF makes mandatory and that
    /// were entirely absent, plus the advertised application. Asserted by
    /// inspecting the CER the responder actually receives, not by re-reading the
    /// builder, so the check covers encode/decode too.
    #[tokio::test]
    async fn cer_carries_mandatory_avps_and_advertises_applications() {
        use crate::applications::well_known;

        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut transport = listener.accept().await.unwrap();
            transport.recv().await.unwrap()
        });

        let client_cfg = config_with_apps("mme.example.org", &[well_known::S6A]);
        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();

        let cer = server.await.unwrap();
        assert_eq!(cer.header.command_code, base_cmd::CAPABILITIES_EXCHANGE);
        assert!(
            cer.find_avp(avp_code::HOST_IP_ADDRESS).is_some(),
            "Host-IP-Address (RFC 6733 §5.3.1) was missing entirely before this change"
        );
        assert!(cer.find_avp(avp_code::VENDOR_ID).is_some(), "Vendor-Id");
        assert!(
            cer.find_avp(avp_code::PRODUCT_NAME).is_some(),
            "Product-Name"
        );

        let advertised = crate::applications::advertised_applications(&cer);
        assert_eq!(
            advertised.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![well_known::S6A.id],
            "the CER must advertise the declared application"
        );
    }

    /// Backward compatibility: peers whose config declares no applications (every
    /// existing caller, including the other tests in this file) must still
    /// complete the handshake. Negotiation is opt-in.
    #[tokio::test]
    async fn peers_without_declared_applications_still_handshake() {
        let listener = DiameterListener::bind(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server_cfg = test_config("hss.example.org", "epc.example.org");
        let server = tokio::spawn(async move {
            let transport = listener.accept().await.unwrap();
            let mut peer = DiameterPeer::new_responder(transport, &server_cfg);
            peer.start().await.unwrap();
            let event = peer.next_event().await.unwrap();
            assert!(matches!(event, PeerEvent::Established { .. }));
            assert_eq!(peer.state(), PeerState::Open);
        });

        let client_cfg = test_config("mme.example.org", "epc.example.org");
        let transport = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut client = DiameterPeer::new_initiator(transport, &client_cfg);
        client.start().await.unwrap();
        assert!(matches!(
            client.next_event().await.unwrap(),
            PeerEvent::Established { .. }
        ));
        server.await.unwrap();
    }

    /// An unparseable configured address degrades the advertisement rather than
    /// preventing the node from starting: the CER simply omits Host-IP-Address.
    #[test]
    fn unparseable_configured_address_is_skipped_not_fatal() {
        let cfg = DiameterConfig {
            address: Some("not-an-ip, 10.0.0.7".to_string()),
            ..Default::default()
        };
        let addrs = parse_host_addresses(&cfg);
        assert_eq!(addrs.len(), 1, "the good half is kept");
        assert_eq!(addrs[0].to_string(), "10.0.0.7");
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
            .register(
                "hss.example.com".into(),
                "example.com".into(),
                addr,
                PeerState::Open,
            )
            .await;

        assert!(table.is_peer_open("hss.example.com").await);
        assert!(!table.is_peer_open("unknown.example.com").await);
        assert_eq!(table.connected_count().await, 1);
        assert_eq!(
            table.connected_peers().await,
            vec!["hss.example.com".to_string()]
        );

        table
            .update_state("hss.example.com", PeerState::Closing)
            .await;
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
