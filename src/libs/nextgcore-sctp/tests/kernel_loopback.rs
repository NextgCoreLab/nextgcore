//! Runtime validation for the native kernel-SCTP NGAP transport (T0.2b).
//!
//! Exercises the real syscall path end-to-end over a loopback **kernel** SCTP
//! association — our [`KernelSctpServer`] (accept/read loop on tokio `AsyncFd`)
//! against our [`KernelSctpSocket`] client — with NO third-party stack
//! (no Open5GS, no UERANSIM). Validates the parts that cannot be checked by
//! `cargo check` on a non-Linux host:
//!   * `sctp_sendmsg`/`sctp_recvmsg` actually link + carry payloads,
//!   * the NGAP PPID (60) survives the wire (network-order round-trip both ways),
//!   * the accept loop registers an association and emits `NewAssociation`,
//!   * inbound data surfaces as `DataReceived` with the right PPID/bytes,
//!   * the server `send` path reaches the client,
//!   * client close surfaces as `AssociationClosed`.
//!
//! Linux + libsctp only; compiles to nothing elsewhere.
#![cfg(all(feature = "kernel", target_os = "linux"))]

use std::sync::Arc;
use std::time::Duration;

use nextgcore_sctp::{
    KernelSctpServer, KernelSctpSocket, ServerEvent, SctpServerConfig, MSG_NOTIFICATION, NGAP_PPID,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn next_event(rx: &mut mpsc::UnboundedReceiver<ServerEvent>) -> ServerEvent {
    timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for a server event")
        .expect("server event channel closed unexpectedly")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kernel_sctp_loopback_ngap_roundtrip() {
    let bind = "127.0.0.1:0".parse().unwrap();
    let mut server = KernelSctpServer::bind(bind, SctpServerConfig::default())
        .await
        .expect("kernel SCTP server bind");
    let server_addr = server.local_addr();

    let (tx, mut rx) = mpsc::unbounded_channel();
    server.set_event_sender(tx);

    // Native kernel-SCTP client (blocking libc connect -> off the runtime).
    let client = tokio::task::spawn_blocking(move || {
        KernelSctpSocket::client(server_addr, None).expect("kernel SCTP client connect")
    })
    .await
    .unwrap();
    let client = Arc::new(client);

    // (1) association established
    let assoc_id = match next_event(&mut rx).await {
        ServerEvent::NewAssociation { association_id, .. } => association_id,
        other => panic!("expected NewAssociation, got {other:?}"),
    };

    // (2) client -> server with the NGAP PPID
    let uplink = b"\x00\x15\x00\x10ngap-uplink-pdu".to_vec();
    {
        let c = Arc::clone(&client);
        let payload = uplink.clone();
        tokio::task::spawn_blocking(move || c.send(&payload, NGAP_PPID, 0).expect("client send"))
            .await
            .unwrap();
    }
    match next_event(&mut rx).await {
        ServerEvent::DataReceived {
            association_id,
            message,
        } => {
            assert_eq!(association_id, assoc_id);
            assert_eq!(
                message.ppid, NGAP_PPID,
                "PPID must survive the wire (network-order round-trip)"
            );
            assert_eq!(&message.data[..], &uplink[..], "uplink payload mismatch");
        }
        other => panic!("expected DataReceived, got {other:?}"),
    }

    // (3) server -> client
    let downlink = b"\x20\x15\x00\x08ngap-dl".to_vec();
    server
        .send(assoc_id, 0, &downlink)
        .await
        .expect("server send");
    let (n, ppid, recv_buf) = {
        let c = Arc::clone(&client);
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 4096];
            // The client socket also surfaces SCTP event notifications (e.g. the
            // COMM_UP queued at association setup); skip them to reach the data.
            loop {
                let (n, info, flags) = c.recv_msg(&mut buf).expect("client recv");
                if flags & MSG_NOTIFICATION == 0 {
                    break (n, info.ppid, buf);
                }
            }
        })
        .await
        .unwrap()
    };
    assert_eq!(&recv_buf[..n], &downlink[..], "downlink payload mismatch");
    assert_eq!(ppid, NGAP_PPID, "downlink PPID must be 60");

    // (4) client close -> server observes the association going down
    drop(client);
    match next_event(&mut rx).await {
        ServerEvent::AssociationClosed { association_id, .. } => {
            assert_eq!(association_id, assoc_id);
        }
        other => panic!("expected AssociationClosed, got {other:?}"),
    }
}
