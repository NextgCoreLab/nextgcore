//! Diameter transport layer (TCP)
//!
//! Provides TCP-based transport for Diameter messages per RFC 6733 Section 2.1.
//! Diameter uses a 4-byte length prefix in the message header for framing.
//! The first byte is the version, and the next 3 bytes are the message length.

use bytes::BytesMut;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::error::{DiameterError, DiameterResult};
use crate::message::{DiameterMessage, DIAMETER_HEADER_SIZE};
use crate::DIAMETER_PORT;

/// Maximum Diameter message size (default 64KB, RFC allows up to 16MB)
const MAX_MESSAGE_SIZE: usize = 65536;

/// Diameter transport connection wrapping a TCP stream
pub struct DiameterTransport {
    stream: TcpStream,
    read_buf: BytesMut,
    peer_addr: SocketAddr,
}

impl DiameterTransport {
    /// Wrap an existing TCP stream as a Diameter transport
    pub fn new(stream: TcpStream) -> DiameterResult<Self> {
        let peer_addr = stream.peer_addr()?;
        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            peer_addr,
        })
    }

    /// Connect to a remote Diameter peer
    pub async fn connect(addr: SocketAddr) -> DiameterResult<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::new(stream)
    }

    /// Get the remote peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Send a Diameter message
    pub async fn send(&mut self, msg: &DiameterMessage) -> DiameterResult<()> {
        let encoded = msg.encode();
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive a Diameter message
    ///
    /// Reads from the TCP stream, performing message framing based on the
    /// 3-byte length field in the Diameter header (bytes 1-3).
    pub async fn recv(&mut self) -> DiameterResult<DiameterMessage> {
        loop {
            // Try to parse a complete message from the buffer
            if let Some(msg) = self.try_parse_message()? {
                return Ok(msg);
            }

            // Read more data from the stream
            let n = self.stream.read_buf(&mut self.read_buf).await?;
            if n == 0 {
                return Err(DiameterError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed by peer",
                )));
            }
        }
    }

    /// Try to parse a complete Diameter message from the read buffer
    fn try_parse_message(&mut self) -> DiameterResult<Option<DiameterMessage>> {
        if self.read_buf.len() < DIAMETER_HEADER_SIZE {
            return Ok(None);
        }

        // Read message length from header bytes 1-3 (3-byte big-endian)
        let len_high = self.read_buf[1] as usize;
        let len_mid = self.read_buf[2] as usize;
        let len_low = self.read_buf[3] as usize;
        let msg_len = (len_high << 16) | (len_mid << 8) | len_low;

        if msg_len < DIAMETER_HEADER_SIZE {
            return Err(DiameterError::InvalidMessage(format!(
                "message length {msg_len} is less than header size"
            )));
        }

        if msg_len > MAX_MESSAGE_SIZE {
            return Err(DiameterError::InvalidMessage(format!(
                "message length {msg_len} exceeds maximum {MAX_MESSAGE_SIZE}"
            )));
        }

        // Check if we have the full message
        if self.read_buf.len() < msg_len {
            return Ok(None);
        }

        // Extract the message bytes and decode
        let msg_bytes = self.read_buf.split_to(msg_len);
        let mut bytes = msg_bytes.freeze();
        let msg = DiameterMessage::decode(&mut bytes)?;
        Ok(Some(msg))
    }

    /// Shutdown the transport connection
    pub async fn shutdown(&mut self) -> DiameterResult<()> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

/// Diameter TCP listener that accepts incoming connections
pub struct DiameterListener {
    listener: TcpListener,
}

impl DiameterListener {
    /// Bind to the given address
    pub async fn bind(addr: SocketAddr) -> DiameterResult<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    /// Bind to the default Diameter port on all interfaces
    pub async fn bind_default() -> DiameterResult<Self> {
        let addr: SocketAddr = ([0, 0, 0, 0], DIAMETER_PORT).into();
        Self::bind(addr).await
    }

    /// Accept a new incoming connection
    pub async fn accept(&self) -> DiameterResult<DiameterTransport> {
        let (stream, _addr) = self.listener.accept().await?;
        DiameterTransport::new(stream)
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> DiameterResult<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Run the listener, sending accepted transports to a channel
    pub async fn run(
        self,
        tx: mpsc::Sender<DiameterTransport>,
    ) -> DiameterResult<()> {
        loop {
            match self.accept().await {
                Ok(transport) => {
                    if tx.send(transport).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("Failed to accept Diameter connection: {e}");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avp::{Avp, AvpData};
    use crate::message::DiameterMessage;

    #[tokio::test]
    async fn test_transport_send_recv() {
        // Bind listener on a random port
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        // Spawn a task to accept and echo
        let handle = tokio::spawn(async move {
            let mut server = listener.accept().await.unwrap();
            let msg = server.recv().await.unwrap();
            // Echo back as answer
            let answer = DiameterMessage::new_answer(&msg);
            server.send(&answer).await.unwrap();
            server.shutdown().await.unwrap();
        });

        // Connect and send a request
        let mut client = DiameterTransport::connect(listen_addr).await.unwrap();
        let mut req = DiameterMessage::new_request(257, 0);
        req.add_avp(Avp::mandatory(264, AvpData::DiameterIdentity(
            "client.example.com".to_string(),
        )));
        req.header.hop_by_hop_id = 1;
        req.header.end_to_end_id = 1;
        client.send(&req).await.unwrap();

        // Receive the answer
        let answer = client.recv().await.unwrap();
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, 257);
        assert_eq!(answer.header.hop_by_hop_id, 1);

        client.shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_transport_multiple_messages() {
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = DiameterListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut server = listener.accept().await.unwrap();
            for _ in 0..3 {
                let msg = server.recv().await.unwrap();
                let answer = DiameterMessage::new_answer(&msg);
                server.send(&answer).await.unwrap();
            }
            server.shutdown().await.unwrap();
        });

        let mut client = DiameterTransport::connect(listen_addr).await.unwrap();
        for i in 0..3u32 {
            let mut req = DiameterMessage::new_request(257, 0);
            req.header.hop_by_hop_id = i;
            req.header.end_to_end_id = i;
            client.send(&req).await.unwrap();

            let answer = client.recv().await.unwrap();
            assert!(answer.header.is_answer());
            assert_eq!(answer.header.hop_by_hop_id, i);
        }

        client.shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_connection_refused() {
        // Try connecting to a port that should not be listening
        let addr: SocketAddr = ([127, 0, 0, 1], 19999).into();
        let result = DiameterTransport::connect(addr).await;
        assert!(result.is_err());
    }
}
