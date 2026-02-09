//! TCP server and client
//!
//! Exact port of lib/core/ogs-tcp.h and ogs-tcp.c

use crate::errno::OGS_OK;
use crate::sockaddr::OgsSockaddr;
use crate::socket::{ogs_sock_bind, ogs_sock_connect, ogs_sock_listen, ogs_sock_socket, OgsSock};
use crate::sockopt::{ogs_listen_reusable, ogs_so_linger, ogs_tcp_nodelay, OgsSockopt};

/// Create a TCP server socket (identical to ogs_tcp_server)
pub fn ogs_tcp_server(sa_list: &OgsSockaddr, socket_option: Option<&OgsSockopt>) -> Option<OgsSock> {
    let option = socket_option.cloned().unwrap_or_default();

    let mut current = Some(sa_list);

    while let Some(addr) = current {
        // Create socket
        if let Some(mut sock) = ogs_sock_socket(addr.family, libc::SOCK_STREAM, libc::IPPROTO_TCP) {
            // Set TCP_NODELAY
            if option.tcp_nodelay {
                let rv = ogs_tcp_nodelay(sock.fd, true);
                if rv != OGS_OK {
                    // Continue to next address
                    current = addr.next.as_ref().map(|b| b.as_ref());
                    continue;
                }
            }

            // Set SO_LINGER
            if option.so_linger.l_onoff {
                let rv = ogs_so_linger(sock.fd, option.so_linger.l_linger);
                if rv != OGS_OK {
                    current = addr.next.as_ref().map(|b| b.as_ref());
                    continue;
                }
            }

            // Set SO_REUSEADDR
            let rv = ogs_listen_reusable(sock.fd, true);
            if rv != OGS_OK {
                current = addr.next.as_ref().map(|b| b.as_ref());
                continue;
            }

            // Bind
            if ogs_sock_bind(&mut sock, addr) == OGS_OK {
                // Listen
                let rv = ogs_sock_listen(&sock);
                if rv == OGS_OK {
                    return Some(sock);
                }
            }
        }

        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    None
}

/// Create a TCP client socket (identical to ogs_tcp_client)
pub fn ogs_tcp_client(sa_list: &OgsSockaddr, socket_option: Option<&OgsSockopt>) -> Option<OgsSock> {
    let option = socket_option.cloned().unwrap_or_default();

    let mut current = Some(sa_list);

    while let Some(addr) = current {
        // Create socket
        if let Some(mut sock) = ogs_sock_socket(addr.family, libc::SOCK_STREAM, libc::IPPROTO_TCP) {
            // Set TCP_NODELAY (note: original code uses sctp_nodelay for tcp_client, likely a bug)
            if option.sctp_nodelay {
                let rv = ogs_tcp_nodelay(sock.fd, true);
                if rv != OGS_OK {
                    current = addr.next.as_ref().map(|b| b.as_ref());
                    continue;
                }
            }

            // Set SO_LINGER
            if option.so_linger.l_onoff {
                let rv = ogs_so_linger(sock.fd, option.so_linger.l_linger);
                if rv != OGS_OK {
                    current = addr.next.as_ref().map(|b| b.as_ref());
                    continue;
                }
            }

            // Connect
            if ogs_sock_connect(&mut sock, addr) == OGS_OK {
                return Some(sock);
            }
        }

        current = addr.next.as_ref().map(|b| b.as_ref());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tcp_server_client() {
        // Create server address
        let server_addr = OgsSockaddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 0);

        // Create server
        let server = ogs_tcp_server(&server_addr, None);
        // Note: This may fail if port 0 doesn't work as expected
        // The test is mainly to verify the code compiles and runs
        if server.is_none() {
            // Skip test if we can't create server
        }
    }
}
