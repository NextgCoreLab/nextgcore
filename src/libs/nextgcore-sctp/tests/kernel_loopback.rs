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
//! Linux + libsctp only; compiles to nothing elsewhere. Needs `sctp-proto` as
//! well as `kernel`, because `KernelSctpServer` reuses the userspace server's
//! event types and is gated on both (lib.rs).
#![cfg(all(feature = "kernel", feature = "sctp-proto", target_os = "linux"))]

use std::sync::Arc;
use std::time::Duration;

use nextgcore_sctp::{
    KernelSctpServer, KernelSctpSocket, SctpServerConfig, ServerEvent, MSG_NOTIFICATION, NGAP_PPID,
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

/// #510: a message larger than the server's receive buffer arrives from the
/// kernel in pieces, MSG_EOR set only on the last (RFC 6458 §8.1.20). The read
/// loop must deliver it as ONE message, under the first piece's stream and PPID
/// -- not as three "messages" a codec then fails on.
///
/// The read buffer is `max(max_message_size, NEXTGCORE_MAX_SDU_LEN)`; with
/// `max_message_size` 1024 that is 8192 octets, so a 20000-octet message comes up
/// as at least three partial deliveries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_larger_than_the_receive_buffer_is_reassembled() {
    let bind = "127.0.0.1:0".parse().unwrap();
    let config = SctpServerConfig {
        max_message_size: 1024,
        ..SctpServerConfig::default()
    };
    let mut server = KernelSctpServer::bind(bind, config)
        .await
        .expect("kernel SCTP server bind");
    let server_addr = server.local_addr();
    let (tx, mut rx) = mpsc::unbounded_channel();
    server.set_event_sender(tx);

    let client = tokio::task::spawn_blocking(move || {
        KernelSctpSocket::client(server_addr, None).expect("kernel SCTP client connect")
    })
    .await
    .unwrap();
    let client = Arc::new(client);
    let assoc_id = match next_event(&mut rx).await {
        ServerEvent::NewAssociation { association_id, .. } => association_id,
        other => panic!("expected NewAssociation, got {other:?}"),
    };

    // Distinct octets at every position, so a reordering or a dropped piece shows.
    let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    {
        let c = Arc::clone(&client);
        let payload = big.clone();
        tokio::task::spawn_blocking(move || c.send(&payload, NGAP_PPID, 0).expect("client send"))
            .await
            .unwrap();
    }
    // A second, small message right behind it must stay a separate message.
    {
        let c = Arc::clone(&client);
        tokio::task::spawn_blocking(move || c.send(b"tail", NGAP_PPID, 0).expect("client send"))
            .await
            .unwrap();
    }
    match next_event(&mut rx).await {
        ServerEvent::DataReceived {
            association_id,
            message,
        } => {
            assert_eq!(association_id, assoc_id);
            assert_eq!(message.data.len(), big.len(), "delivered as one message");
            assert_eq!(&message.data[..], &big[..], "reassembled in order");
            assert_eq!(message.ppid, NGAP_PPID, "the first piece's PPID");
        }
        other => panic!("expected DataReceived, got {other:?}"),
    }
    match next_event(&mut rx).await {
        ServerEvent::DataReceived { message, .. } => {
            assert_eq!(
                &message.data[..],
                b"tail",
                "the next message is not merged in"
            );
        }
        other => panic!("expected DataReceived, got {other:?}"),
    }
}

/// #1297: a peer's ABORT reaches the server first as an `SCTP_ASSOC_CHANGE` /
/// `SCTP_COMM_LOST` notification. The notification types are
/// `SCTP_SN_TYPE_BASE + n` in `<linux/sctp.h>` (`SCTP_ASSOC_CHANGE` is 0x8001), so
/// the association is reported closed by that notification ("SCTP association
/// down"), not only later through the read error that follows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_abort_is_recognised_by_its_notification() {
    let bind = "127.0.0.1:0".parse().unwrap();
    let mut server = KernelSctpServer::bind(bind, SctpServerConfig::default())
        .await
        .expect("kernel SCTP server bind");
    let server_addr = server.local_addr();
    let (tx, mut rx) = mpsc::unbounded_channel();
    server.set_event_sender(tx);
    let client = tokio::task::spawn_blocking(move || {
        KernelSctpSocket::client(server_addr, None).expect("kernel SCTP client connect")
    })
    .await
    .unwrap();
    assert!(matches!(
        next_event(&mut rx).await,
        ServerEvent::NewAssociation { .. }
    ));
    // Close with SO_LINGER 0: an SCTP ABORT (RFC 6458 §8.1.4).
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let rc = unsafe {
        libc::setsockopt(
            client.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0);
    drop(client);
    match next_event(&mut rx).await {
        ServerEvent::AssociationClosed { reason, .. } => {
            assert_eq!(
                reason, "SCTP association down",
                "closed by the COMM_LOST notification"
            )
        }
        other => panic!("expected AssociationClosed, got {other:?}"),
    }
}

/// #1297: the notification constants are `<linux/sctp.h>`'s.
#[test]
fn the_notification_types_are_the_kernels() {
    use nextgcore_sctp::kernel::{SCTP_ASSOC_CHANGE, SCTP_PEER_ADDR_CHANGE, SCTP_SHUTDOWN_EVENT};
    assert_eq!(SCTP_ASSOC_CHANGE, 0x8001);
    assert_eq!(SCTP_PEER_ADDR_CHANGE, 0x8002);
    assert_eq!(SCTP_SHUTDOWN_EVENT, 0x8005);
}
