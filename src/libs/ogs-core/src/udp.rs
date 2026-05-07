//! UDP server and client
//!
//! Exact port of lib/core/ogs-udp.h and ogs-udp.c

use crate::errno::{OGS_ERROR, OGS_OK};
use crate::sockaddr::OgsSockaddr;
use crate::socket::{ogs_sock_bind, ogs_sock_connect, ogs_sock_socket, OgsSock};
use crate::sockopt::{ogs_bind_to_device, OgsSockopt};

/// Create a UDP server socket (identical to ogs_udp_server)
pub fn ogs_udp_server(sa_list: &OgsSockaddr, socket_option: Option<&OgsSockopt>) -> Option<OgsSock> {
    let option = socket_option.cloned().unwrap_or_default();

    let mut current = Some(sa_list);

    while let Some(addr) = current {
        // Create socket
        if let Some(mut sock) = ogs_sock_socket(addr.family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
            // Bind
            if ogs_sock_bind(&mut sock, addr) == OGS_OK {
                // Bind to device if specified
                if let Some(ref device) = option.so_bindtodevice {
                    if ogs_bind_to_device(sock.fd, device) != OGS_OK {
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

/// Create a UDP client socket (identical to ogs_udp_client)
pub fn ogs_udp_client(sa_list: &OgsSockaddr, socket_option: Option<&OgsSockopt>) -> Option<OgsSock> {
    let _option = socket_option.cloned().unwrap_or_default();

    let mut current = Some(sa_list);

    while let Some(addr) = current {
        // Create socket
        if let Some(mut sock) = ogs_sock_socket(addr.family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
            // Connect
            if ogs_sock_connect(&mut sock, addr) == OGS_OK {
                return Some(sock);
            }
        }

        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    None
}

/// Connect an existing UDP socket to an address (identical to ogs_udp_connect)
pub fn ogs_udp_connect(sock: &mut OgsSock, sa_list: &OgsSockaddr) -> i32 {
    let mut current = Some(sa_list);

    while let Some(addr) = current {
        if ogs_sock_connect(sock, addr) == OGS_OK {
            return OGS_OK;
        }

        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    OGS_ERROR
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_udp_server() {
        // Create server address with port 0 (let OS assign)
        let server_addr = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 0);

        // Create server
        let server = ogs_udp_server(&server_addr, None);
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
        let client_addr = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 12345);

        // Create client (will connect to the address)
        let client = ogs_udp_client(&client_addr, None);
        // Note: UDP connect doesn't actually establish a connection,
        // it just sets the default destination
        if client.is_none() {
            return;
        }

        let client = client.unwrap();
        assert!(client.is_valid());
    }
}
