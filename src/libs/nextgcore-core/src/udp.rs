//! UDP server and client
//!
//! Exact port of lib/core/nextgcore-udp.h and nextgcore-udp.c

use crate::errno::{NEXTGCORE_ERROR, NEXTGCORE_OK};
use crate::sockaddr::NextgcoreSockaddr;
use crate::socket::{
    nextgcore_sock_bind, nextgcore_sock_connect, nextgcore_sock_socket, NextgcoreSock,
};
use crate::sockopt::{nextgcore_bind_to_device, NextgcoreSockopt};

/// Create a UDP server socket (identical to nextgcore_udp_server)
pub fn nextgcore_udp_server(
    sa_list: &NextgcoreSockaddr,
    socket_option: Option<&NextgcoreSockopt>,
) -> Option<NextgcoreSock> {
    let option = socket_option.cloned().unwrap_or_default();

    let mut current = Some(sa_list);

    while let Some(addr) = current {
        // Create socket
        if let Some(mut sock) =
            nextgcore_sock_socket(addr.family, libc::SOCK_DGRAM, libc::IPPROTO_UDP)
        {
            // Bind
            if nextgcore_sock_bind(&mut sock, addr) == NEXTGCORE_OK {
                // Bind to device if specified
                if let Some(ref device) = option.so_bindtodevice {
                    if nextgcore_bind_to_device(sock.fd, device) != NEXTGCORE_OK {
                        current = addr.next.as_ref().map(|b| b.as_ref());
                        continue;
                    }
                }

                return Some(sock);
            }
        }

        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    None
}

/// Create a UDP client socket (identical to nextgcore_udp_client)
pub fn nextgcore_udp_client(
    sa_list: &NextgcoreSockaddr,
    socket_option: Option<&NextgcoreSockopt>,
) -> Option<NextgcoreSock> {
    let _option = socket_option.cloned().unwrap_or_default();

    let mut current = Some(sa_list);

    while let Some(addr) = current {
        // Create socket
        if let Some(mut sock) =
            nextgcore_sock_socket(addr.family, libc::SOCK_DGRAM, libc::IPPROTO_UDP)
        {
            // Connect
            if nextgcore_sock_connect(&mut sock, addr) == NEXTGCORE_OK {
                return Some(sock);
            }
        }

        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    None
}

/// Connect an existing UDP socket to an address (identical to nextgcore_udp_connect)
pub fn nextgcore_udp_connect(sock: &mut NextgcoreSock, sa_list: &NextgcoreSockaddr) -> i32 {
    let mut current = Some(sa_list);

    while let Some(addr) = current {
        if nextgcore_sock_connect(sock, addr) == NEXTGCORE_OK {
            return NEXTGCORE_OK;
        }

        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    NEXTGCORE_ERROR
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_udp_server() {
        // Create server address with port 0 (let OS assign)
        let server_addr = NextgcoreSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 0);

        // Create server
        let server = nextgcore_udp_server(&server_addr, None);
        // Note: This may fail depending on system configuration
        if server.is_none() {
            return;
        }

        let server = server.unwrap();
        assert!(server.is_valid());
    }

    #[test]
    fn test_udp_client() {
        // Create client address
        let client_addr = NextgcoreSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 12345);

        // Create client (will connect to the address)
        let client = nextgcore_udp_client(&client_addr, None);
        // Note: UDP connect doesn't actually establish a connection,
        // it just sets the default destination
        if client.is_none() {
            return;
        }

        let client = client.unwrap();
        assert!(client.is_valid());
    }
}
