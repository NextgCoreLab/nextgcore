//! HTTP/3 (QUIC) SBI Transport Prototype (issue #15)
//!
//! 3GPP TS 29.500 mandates HTTP/2 as the SBI transport; 6G "SBA 2.0"
//! discussions raise HTTP/3/QUIC as a candidate successor. **There is no
//! frozen 3GPP Rel-20/6G Stage-3 specification for any alternate SBI
//! transport**, so this module is explicitly non-normative research, out of
//! scope for the TS 29.500 conformance work — like [`crate::grpc`], but
//! unlike that type-only stub this module performs real wire I/O
//! (RFC 9114 HTTP/3 over RFC 9000 QUIC via `h3` + `quinn`).
//!
//! # Status
//!
//! **Loopback research prototype.** No NF binary uses this transport; it is
//! feature-gated (`http3`), off by default, and served only by
//! [`Http3LoopbackServer`] for benchmarks and tests. The transport seam is
//! the existing message layer: the server drives the same
//! [`SbiRequestHandler`] the HTTP/2 [`crate::server::SbiServer`] drives, and
//! [`Http3Client`] returns the same [`SbiResponse`] shape the HTTP/2
//! [`crate::client::SbiClient`] returns, so a handler's response body is
//! byte-identical across both transports (see the round-trip parity test).
//!
//! Unlike TCP/TLS, QUIC has no plaintext mode — every connection runs
//! TLS 1.3 with ALPN `h3`. Callers supply a DER certificate/key pair
//! (tests and benches generate one with `rcgen`); compare against the
//! HTTP/2-over-TLS path, not h2c, for a like-for-like benchmark.
//!
//! # Known parity limitations (deliberate spike scope)
//!
//! Relative to the HTTP/2 server's message conversion, this prototype does
//! not encode/decode `multipart/related` N1/N2 binary containers
//! (`http.parts` is ignored in both directions) and does not stamp
//! `application/problem+json` on untyped 4xx/5xx bodies. Handlers using
//! plain JSON bodies — the benchmarked and parity-tested surface — behave
//! identically across transports.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};

use crate::error::{SbiError, SbiResult};
use crate::message::{SbiRequest, SbiResponse};
use crate::server::SbiRequestHandler;

/// ALPN protocol identifier for HTTP/3 (RFC 9114 §3.1).
const ALPN_H3: &[u8] = b"h3";

/// TLS material and bind address for the loopback HTTP/3 server.
///
/// Certificates are DER blobs rather than file paths (the HTTP/2
/// `SbiServerConfig` takes paths) so tests and benches can feed `rcgen`
/// output directly without touching the filesystem.
pub struct Http3ServerConfig {
    /// Bind address; use port 0 and read back [`Http3LoopbackServer::local_addr`].
    pub addr: SocketAddr,
    /// DER-encoded server certificate.
    pub cert_der: Vec<u8>,
    /// DER-encoded private key (PKCS#8 or SEC1).
    pub key_der: Vec<u8>,
}

/// Loopback HTTP/3 server driving an [`SbiRequestHandler`].
///
/// Accepts QUIC connections, resolves HTTP/3 request streams, converts each
/// request into an [`SbiRequest`] (lowercased headers, buffered UTF-8 body —
/// mirroring the HTTP/2 server's message conversion), and writes the
/// handler's [`SbiResponse`] back on the stream.
pub struct Http3LoopbackServer {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
}

impl Http3LoopbackServer {
    /// Bind a QUIC endpoint and start serving `handler`.
    ///
    /// Returns once the endpoint is bound; connections are accepted on a
    /// spawned task until [`stop`](Self::stop) closes the endpoint.
    pub async fn start<H: SbiRequestHandler>(
        config: Http3ServerConfig,
        handler: H,
    ) -> SbiResult<Self> {
        let cert = rustls::pki_types::CertificateDer::from(config.cert_der);
        let key = rustls::pki_types::PrivateKeyDer::try_from(config.key_der)
            .map_err(|e| SbiError::TlsError(format!("invalid private key DER: {e}")))?;

        // QUIC negotiates TLS 1.3 only (RFC 9001), so build a TLS 1.3-only
        // config rather than reusing tls::build_server_config (TLS 1.2+1.3).
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| SbiError::TlsError(format!("TLS 1.3 config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| SbiError::TlsError(format!("server cert: {e}")))?;
        tls.alpn_protocols = vec![ALPN_H3.to_vec()];

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| SbiError::TlsError(format!("QUIC TLS config: {e}")))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let endpoint = quinn::Endpoint::server(server_config, config.addr)?;
        let local_addr = endpoint.local_addr()?;

        let handler = Arc::new(handler);
        let accept_endpoint = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    if let Ok(connection) = incoming.await {
                        serve_connection(connection, handler).await;
                    }
                });
            }
        });

        Ok(Self {
            endpoint,
            local_addr,
        })
    }

    /// The bound address (real port when started on port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close the endpoint and stop accepting connections.
    pub async fn stop(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
    }
}

/// Serve one QUIC connection: resolve HTTP/3 request streams and dispatch
/// each to the handler on its own task (streams multiplex like HTTP/2).
async fn serve_connection<H: SbiRequestHandler>(connection: quinn::Connection, handler: Arc<H>) {
    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await
    {
        Ok(conn) => conn,
        Err(_) => return,
    };
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    if let Ok((request, stream)) = resolver.resolve_request().await {
                        let _ = serve_request(request, stream, handler).await;
                    }
                });
            }
            // Peer closed the connection or a connection-level error occurred.
            Ok(None) | Err(_) => return,
        }
    }
}

/// Convert one HTTP/3 request to an [`SbiRequest`], run the handler, and
/// write the [`SbiResponse`] back — mirroring the HTTP/2 server's
/// buffered-body, lowercased-header message conversion.
async fn serve_request<H, S>(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    handler: Arc<H>,
) -> SbiResult<()>
where
    H: SbiRequestHandler,
    S: h3::quic::BidiStream<Bytes>,
{
    let (parts, ()) = request.into_parts();

    // Mirror the HTTP/2 server's convert_request: headers into the message
    // map, correlation-ID extraction, query string split into params (and
    // stripped from the URI), then TS 29.501 URI decomposition.
    let mut http = crate::message::SbiHttpMessage::new();
    for (name, value) in &parts.headers {
        if let Ok(value) = value.to_str() {
            http.set_header(name.as_str().to_string(), value.to_string());
        }
    }
    let correlation_id = crate::server::extract_or_generate_correlation_id(&http);
    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                http.set_param(key.to_string(), value.to_string());
            }
        }
    }

    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| SbiError::ConnectionError(format!("h3 recv_data: {e}")))?
    {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        body.extend_from_slice(&bytes);
        if body.len() > crate::server::DEFAULT_MAX_REQUEST_BODY_SIZE {
            // Same cap the HTTP/2 server enforces via Limited.
            let response = http::Response::builder()
                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .map_err(|e| SbiError::ServerError(format!("h3 413 build: {e}")))?;
            stream
                .send_response(response)
                .await
                .map_err(|e| SbiError::ConnectionError(format!("h3 send_response: {e}")))?;
            stream
                .finish()
                .await
                .map_err(|e| SbiError::ConnectionError(format!("h3 finish: {e}")))?;
            return Ok(());
        }
    }
    if !body.is_empty() {
        // Same lossy UTF-8 conversion as the HTTP/2 server/client message
        // layer; SBI payloads are JSON, so this is byte-faithful in practice.
        http.content = Some(String::from_utf8_lossy(&body).to_string());
    }

    let mut header = crate::message::SbiHeader::with_method_uri(
        parts.method.as_str().to_string(),
        parts.uri.path().to_string(),
    );
    header.decompose_uri();
    let sbi_request = SbiRequest {
        header,
        http,
        correlation_id,
        // The N32 RFC 5705 exporter is not wired for QUIC-TLS (see the
        // evaluation doc); rustls exposes one, but SEPP-over-HTTP/3 has no
        // spec basis yet.
        tls_exporter_secret: None,
    };

    let sbi_response = handler.handle(sbi_request).await;

    let mut response = http::Response::builder().status(
        http::StatusCode::from_u16(sbi_response.status)
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
    );
    for (key, value) in &sbi_response.http.headers {
        response = response.header(key.as_str(), value.as_str());
    }
    let response = response
        .body(())
        .map_err(|e| SbiError::ServerError(format!("h3 response build: {e}")))?;

    stream
        .send_response(response)
        .await
        .map_err(|e| SbiError::ConnectionError(format!("h3 send_response: {e}")))?;
    if let Some(content) = sbi_response.http.content {
        stream
            .send_data(Bytes::from(content))
            .await
            .map_err(|e| SbiError::ConnectionError(format!("h3 send_data: {e}")))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| SbiError::ConnectionError(format!("h3 finish: {e}")))?;
    Ok(())
}

/// Minimal HTTP/3 client for the loopback prototype.
///
/// Holds one QUIC connection and multiplexes each request onto its own
/// HTTP/3 stream — the semantic equivalent of the HTTP/2 client reusing one
/// pooled connection.
pub struct Http3Client {
    endpoint: quinn::Endpoint,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    authority: String,
}

impl Http3Client {
    /// Connect to `server_addr`, trusting exactly the given DER certificate
    /// (the self-signed-leaf-as-root pattern the TLS tests use). The server
    /// certificate must cover the name `localhost`.
    pub async fn connect(server_addr: SocketAddr, server_cert_der: &[u8]) -> SbiResult<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                server_cert_der.to_vec(),
            ))
            .map_err(|e| SbiError::TlsError(format!("trust anchor: {e}")))?;

        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| SbiError::TlsError(format!("TLS 1.3 config: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN_H3.to_vec()];

        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| SbiError::TlsError(format!("QUIC TLS config: {e}")))?;
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_tls)));

        let connection = endpoint
            .connect(server_addr, "localhost")
            .map_err(|e| SbiError::ConnectionError(format!("QUIC connect: {e}")))?
            .await
            .map_err(|e| SbiError::ConnectionError(format!("QUIC handshake: {e}")))?;

        let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| SbiError::ConnectionError(format!("h3 handshake: {e}")))?;
        // The driver owns connection-level I/O; park it until shutdown.
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        Ok(Self {
            endpoint,
            send_request,
            authority: format!("localhost:{}", server_addr.port()),
        })
    }

    /// Issue a GET and return the raw response: status, lowercased headers,
    /// and the exact body bytes (the byte-parity surface for tests).
    ///
    /// Takes `&self` like the HTTP/2 client: each call clones the h3
    /// `SendRequest` handle and opens its own request stream on the shared
    /// QUIC connection.
    pub async fn get_raw(&self, path: &str) -> SbiResult<(u16, HashMap<String, String>, Bytes)> {
        let uri = format!("https://{}{}", self.authority, path);
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(&uri)
            .body(())
            .map_err(|e| SbiError::InvalidUri(format!("{uri}: {e}")))?;

        let mut stream = self
            .send_request
            .clone()
            .send_request(request)
            .await
            .map_err(|e| SbiError::ConnectionError(format!("h3 send_request: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| SbiError::ConnectionError(format!("h3 finish: {e}")))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| SbiError::ConnectionError(format!("h3 recv_response: {e}")))?;
        let status = response.status().as_u16();
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), value.to_string());
            }
        }

        let mut body = BytesMut::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|e| SbiError::ConnectionError(format!("h3 recv_data: {e}")))?
        {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            body.extend_from_slice(&bytes);
        }
        Ok((status, headers, body.freeze()))
    }

    /// Issue a GET and return an [`SbiResponse`] with the same conversion
    /// semantics as the HTTP/2 [`crate::client::SbiClient`] (headers into a
    /// lowercased map, body via lossy UTF-8 into `http.content`).
    pub async fn get(&self, path: &str) -> SbiResult<SbiResponse> {
        let (status, headers, body) = self.get_raw(path).await?;
        let mut response = SbiResponse::with_status(status);
        response.http.headers = headers;
        if !body.is_empty() {
            response.http.content = Some(String::from_utf8_lossy(&body).to_string());
        }
        Ok(response)
    }

    /// Close the QUIC endpoint.
    pub async fn close(self) {
        self.endpoint.close(0u32.into(), b"done");
        self.endpoint.wait_idle().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::SbiResponse;
    use crate::server::{SbiServer, SbiServerConfig};
    use crate::SbiClient;

    const BODY: &str = r#"{"transport":"parity","payload":"0123456789abcdef"}"#;

    fn fixed_json_handler(
        request: SbiRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SbiResponse> + Send>> {
        Box::pin(async move {
            assert_eq!(request.header.method, "GET");
            // Conversion parity with the HTTP/2 server: query split into
            // params (and stripped from the URI), correlation-ID populated.
            assert_eq!(
                request.http.get_param("target-nf-type").map(String::as_str),
                Some("AMF")
            );
            assert!(!request.header.uri.contains('?'));
            assert!(!request.correlation_id.is_empty());
            SbiResponse::ok()
                .with_body(BODY, "application/json")
                .with_header("x-transport-parity", "1")
        })
    }

    const REQ_PATH: &str = "/nbench/v1/fixed?target-nf-type=AMF";

    fn self_signed() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        (cert.cert.der().to_vec(), cert.key_pair.serialize_der())
    }

    async fn start_http3(
        handler: fn(
            SbiRequest,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = SbiResponse> + Send>>,
    ) -> (Http3LoopbackServer, Vec<u8>) {
        let (cert_der, key_der) = self_signed();
        let server = Http3LoopbackServer::start(
            Http3ServerConfig {
                addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                cert_der: cert_der.clone(),
                key_der,
            },
            handler,
        )
        .await
        .expect("http3 server");
        (server, cert_der)
    }

    #[tokio::test]
    async fn http3_get_roundtrip() {
        let (server, cert_der) = start_http3(fixed_json_handler).await;

        let client = Http3Client::connect(server.local_addr(), &cert_der)
            .await
            .expect("http3 client");
        let response = client.get(REQ_PATH).await.expect("h3 GET");

        assert_eq!(response.status, 200);
        assert_eq!(
            response.http.get_header("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(response.http.content.as_deref(), Some(BODY));

        client.close().await;
        server.stop().await;
    }

    /// Acceptance criterion for issue #15: the same request against the same
    /// handler returns a body byte-identical to the HTTP/2 path.
    #[tokio::test]
    async fn http3_body_is_byte_identical_to_http2() {
        // HTTP/2 (h2c) side — probe-bind-drop to pick a free port (the
        // server binds only its configured address), retrying if a parallel
        // test steals the port in the probe→bind window.
        let (h2_server, port) = {
            let mut started = None;
            for _ in 0..5 {
                let port = crate::test_support::free_port();
                let server = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
                    [127, 0, 0, 1],
                    port,
                ))));
                if server.start(fixed_json_handler).await.is_ok() {
                    started = Some((server, port));
                    break;
                }
            }
            started.expect("h2 server after 5 attempts")
        };
        let h2_client = SbiClient::with_host_port("127.0.0.1", port);
        let h2_response = h2_client.get(REQ_PATH).await.expect("h2 GET");
        assert_eq!(h2_response.status, 200);
        let h2_body = h2_response.http.content.expect("h2 body");

        // HTTP/3 side — same handler, same path.
        let (h3_server, cert_der) = start_http3(fixed_json_handler).await;
        let h3_client = Http3Client::connect(h3_server.local_addr(), &cert_der)
            .await
            .expect("http3 client");
        let (h3_status, h3_headers, h3_body) = h3_client.get_raw(REQ_PATH).await.expect("h3 GET");

        assert_eq!(h3_status, h2_response.status);
        assert_eq!(h3_body.as_ref(), h2_body.as_bytes(), "body bytes differ");
        assert_eq!(
            h3_headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            h3_headers.get("x-transport-parity").map(String::as_str),
            Some("1")
        );

        h3_client.close().await;
        h3_server.stop().await;
        h2_server.stop().await.expect("h2 stop");
    }
}
