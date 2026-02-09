//! SBI HTTP/2 Client
//!
//! HTTP/2 client implementation using hyper for SBI communication.
//! Matches the interface in lib/sbi/client.h

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::error::{SbiError, SbiResult};
use crate::message::{SbiRequest, SbiResponse};
use crate::tls;
use crate::types::UriScheme;

/// Default connection timeout in seconds
const DEFAULT_CONNECT_TIMEOUT: u64 = 5;
/// Default request timeout in seconds
const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// SBI Client configuration
#[derive(Debug, Clone)]
pub struct SbiClientConfig {
    /// URI scheme (http or https)
    pub scheme: UriScheme,
    /// Target host (FQDN or IP)
    pub host: String,
    /// Target port
    pub port: u16,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Skip TLS verification (for testing)
    pub insecure_skip_verify: bool,
    /// CA certificate path
    pub ca_cert: Option<String>,
    /// Client certificate path
    pub client_cert: Option<String>,
    /// Client private key path
    pub client_key: Option<String>,
}

impl Default for SbiClientConfig {
    fn default() -> Self {
        Self {
            scheme: UriScheme::Http,
            host: "localhost".to_string(),
            port: 80,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT),
            insecure_skip_verify: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
        }
    }
}

impl SbiClientConfig {
    /// Create a new client configuration
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Set the URI scheme
    pub fn with_scheme(mut self, scheme: UriScheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// Set HTTPS scheme
    pub fn with_https(mut self) -> Self {
        self.scheme = UriScheme::Https;
        self
    }

    /// Set connection timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Build the base URI
    pub fn base_uri(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Connection state for HTTP/2
struct ConnectionState {
    sender: SendRequest<Full<Bytes>>,
}

/// SBI Client - HTTP/2 client for SBI communication
/// Matches ogs_sbi_client_t
pub struct SbiClient {
    /// Client configuration
    config: SbiClientConfig,
    /// Connection state (lazily initialized)
    connection: Arc<Mutex<Option<ConnectionState>>>,
}

impl SbiClient {
    /// Create a new SBI client
    pub fn new(config: SbiClientConfig) -> Self {
        Self {
            config,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a client with host and port
    pub fn with_host_port(host: impl Into<String>, port: u16) -> Self {
        Self::new(SbiClientConfig::new(host, port))
    }

    /// Get the client configuration
    pub fn config(&self) -> &SbiClientConfig {
        &self.config
    }

    /// Build a TLS connector from the client config
    fn build_tls_connector(&self) -> SbiResult<TlsConnector> {
        let client_config = if let (Some(cert_path), Some(key_path)) =
            (&self.config.client_cert, &self.config.client_key)
        {
            // mTLS: client certificate authentication
            let certs = tls::load_certs(cert_path)?;
            let key = tls::load_private_key(key_path)?;
            tls::build_client_config_mtls(
                certs,
                key,
                self.config.ca_cert.as_deref(),
                self.config.insecure_skip_verify,
            )?
        } else {
            tls::build_client_config(
                self.config.ca_cert.as_deref(),
                self.config.insecure_skip_verify,
            )?
        };

        Ok(TlsConnector::from(Arc::new(client_config)))
    }

    /// Connect to the server
    async fn connect(&self) -> SbiResult<SendRequest<Full<Bytes>>> {
        let addr = format!("{}:{}", self.config.host, self.config.port);

        let stream = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| SbiError::Timeout)?
        .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

        if self.config.scheme == UriScheme::Https {
            let connector = self.build_tls_connector()?;
            let server_name = ServerName::try_from(self.config.host.clone())
                .map_err(|e| SbiError::TlsError(format!("Invalid server name: {e}")))?;

            let tls_stream = tokio::time::timeout(
                self.config.connect_timeout,
                connector.connect(server_name, stream),
            )
            .await
            .map_err(|_| SbiError::Timeout)?
            .map_err(|e| SbiError::TlsError(format!("TLS handshake failed: {e}")))?;

            let io = TokioIo::new(tls_stream);

            let (sender, conn) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                io,
            )
            .await
            .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    eprintln!("HTTP/2 TLS connection error: {e}");
                }
            });

            Ok(sender)
        } else {
            let io = TokioIo::new(stream);

            let (sender, conn) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                io,
            )
            .await
            .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    eprintln!("HTTP/2 connection error: {e}");
                }
            });

            Ok(sender)
        }
    }

    /// Get or create a connection
    async fn get_connection(&self) -> SbiResult<SendRequest<Full<Bytes>>> {
        let mut conn_guard = self.connection.lock().await;
        
        if let Some(ref state) = *conn_guard {
            if state.sender.is_ready() {
                return Ok(state.sender.clone());
            }
        }

        // Create new connection
        let sender = self.connect().await?;
        *conn_guard = Some(ConnectionState { sender: sender.clone() });
        Ok(sender)
    }

    /// Send an SBI request and receive a response
    pub async fn send_request(&self, request: SbiRequest) -> SbiResult<SbiResponse> {
        let mut sender = self.get_connection().await?;

        // Build the URI
        let uri_str = if request.header.uri.starts_with("http") {
            request.header.uri.clone()
        } else {
            format!("{}{}", self.config.base_uri(), request.header.uri)
        };

        // Add query parameters
        let uri_with_params = if request.http.params.is_empty() {
            uri_str
        } else {
            let params: Vec<String> = request
                .http
                .params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            format!("{}?{}", uri_str, params.join("&"))
        };

        let uri: Uri = uri_with_params
            .parse()
            .map_err(|e| SbiError::InvalidUri(format!("{uri_with_params}: {e}")))?;

        // Build the HTTP method
        let method = match request.header.method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "OPTIONS" => Method::OPTIONS,
            other => return Err(SbiError::InvalidMethod(other.to_string())),
        };

        // Build the request body
        let body = request
            .http
            .content
            .map(|c| Full::new(Bytes::from(c)))
            .unwrap_or_else(|| Full::new(Bytes::new()));

        // Build the HTTP request
        let mut req_builder = Request::builder()
            .method(method)
            .uri(uri);

        // Add headers
        for (key, value) in &request.http.headers {
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }

        let http_request = req_builder
            .body(body)
            .map_err(|e| SbiError::ClientError(e.to_string()))?;

        // Send the request with timeout
        let response = tokio::time::timeout(
            self.config.request_timeout,
            sender.send_request(http_request),
        )
        .await
        .map_err(|_| SbiError::Timeout)?
        .map_err(|e| SbiError::HyperError(e.to_string()))?;

        // Convert to SbiResponse
        self.convert_response(response).await
    }

    /// Convert hyper response to SbiResponse
    async fn convert_response(
        &self,
        response: hyper::Response<Incoming>,
    ) -> SbiResult<SbiResponse> {
        let status = response.status().as_u16();
        
        // Extract headers
        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.to_string(), v.to_string());
            }
        }

        // Read body
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| SbiError::InvalidResponse(e.to_string()))?
            .to_bytes();

        let content = if body_bytes.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&body_bytes).to_string())
        };

        let mut sbi_response = SbiResponse::with_status(status);
        sbi_response.http.headers = headers;
        sbi_response.http.content = content;

        Ok(sbi_response)
    }

    /// Send a GET request
    pub async fn get(&self, path: &str) -> SbiResult<SbiResponse> {
        self.send_request(SbiRequest::get(path)).await
    }

    /// Send a POST request with JSON body
    pub async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> SbiResult<SbiResponse> {
        let request = SbiRequest::post(path)
            .with_json_body(body)?;
        self.send_request(request).await
    }

    /// Send a PUT request with JSON body
    pub async fn put_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> SbiResult<SbiResponse> {
        let request = SbiRequest::put(path)
            .with_json_body(body)?;
        self.send_request(request).await
    }

    /// Send a DELETE request
    pub async fn delete(&self, path: &str) -> SbiResult<SbiResponse> {
        self.send_request(SbiRequest::delete(path)).await
    }

    /// Send a PATCH request with JSON body
    pub async fn patch_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> SbiResult<SbiResponse> {
        let request = SbiRequest::patch(path)
            .with_json_body(body)?;
        self.send_request(request).await
    }

    /// Close the connection
    pub async fn close(&self) {
        let mut conn_guard = self.connection.lock().await;
        *conn_guard = None;
    }
}

/// Client callback type for async responses
pub type ClientCallback = Box<dyn Fn(SbiResult<SbiResponse>) + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config() {
        let config = SbiClientConfig::new("localhost", 8080)
            .with_https()
            .with_connect_timeout(Duration::from_secs(10));

        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 8080);
        assert_eq!(config.scheme, UriScheme::Https);
        assert_eq!(config.base_uri(), "https://localhost:8080");
    }

    #[test]
    fn test_client_creation() {
        let client = SbiClient::with_host_port("127.0.0.1", 7777);
        assert_eq!(client.config().host, "127.0.0.1");
        assert_eq!(client.config().port, 7777);
    }
}
