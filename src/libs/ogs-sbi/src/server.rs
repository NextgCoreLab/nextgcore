//! SBI HTTP/2 Server
//!
//! HTTP/2 server implementation using hyper for SBI communication.
//! Matches the interface in lib/sbi/server.h

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

use crate::error::{SbiError, SbiResult};
use crate::message::{SbiHttpMessage, SbiRequest, SbiResponse};
use crate::types::UriScheme;

/// Server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    /// Bind address
    pub addr: SocketAddr,
    /// URI scheme
    pub scheme: UriScheme,
    /// Interface name (optional)
    pub interface: Option<String>,
    /// TLS private key path
    pub private_key: Option<String>,
    /// TLS certificate path
    pub cert: Option<String>,
    /// Verify client certificates
    pub verify_client: bool,
    /// CA certificate for client verification
    pub verify_client_cacert: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], 7777)),
            scheme: UriScheme::Http,
            interface: None,
            private_key: None,
            cert: None,
            verify_client: false,
            verify_client_cacert: None,
        }
    }
}

impl SbiServerConfig {
    /// Create a new server configuration
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            ..Default::default()
        }
    }

    /// Create configuration with host and port
    pub fn with_host_port(host: impl AsRef<str>, port: u16) -> SbiResult<Self> {
        let addr: SocketAddr = format!("{}:{}", host.as_ref(), port)
            .parse()
            .map_err(|e| SbiError::InvalidUri(format!("Invalid address: {}", e)))?;
        Ok(Self::new(addr))
    }

    /// Set the interface name
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Enable HTTPS with certificates
    pub fn with_tls(mut self, private_key: impl Into<String>, cert: impl Into<String>) -> Self {
        self.scheme = UriScheme::Https;
        self.private_key = Some(private_key.into());
        self.cert = Some(cert.into());
        self
    }
}

/// Request handler trait
pub trait SbiRequestHandler: Send + Sync + 'static {
    /// Handle an incoming SBI request
    fn handle(&self, request: SbiRequest) -> Pin<Box<dyn Future<Output = SbiResponse> + Send>>;
}

/// Function-based request handler
impl<F, Fut> SbiRequestHandler for F
where
    F: Fn(SbiRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = SbiResponse> + Send + 'static,
{
    fn handle(&self, request: SbiRequest) -> Pin<Box<dyn Future<Output = SbiResponse> + Send>> {
        Box::pin(self(request))
    }
}

/// Hyper service wrapper
struct SbiService<H: SbiRequestHandler> {
    handler: Arc<H>,
}

impl<H: SbiRequestHandler> Clone for SbiService<H> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
        }
    }
}

impl<H: SbiRequestHandler> Service<Request<Incoming>> for SbiService<H> {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let handler = self.handler.clone();
        
        Box::pin(async move {
            // Convert hyper request to SbiRequest
            let sbi_request = convert_request(req).await;
            
            // Call the handler
            let sbi_response = handler.handle(sbi_request).await;
            
            // Convert SbiResponse to hyper response
            let response = convert_response(sbi_response);
            
            Ok(response)
        })
    }
}

/// Convert hyper request to SbiRequest
async fn convert_request(req: Request<Incoming>) -> SbiRequest {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    
    // Extract headers
    let mut http = SbiHttpMessage::new();
    for (key, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            http.set_header(key.to_string(), v.to_string());
        }
    }
    
    // Extract query parameters
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                http.set_param(key.to_string(), value.to_string());
            }
        }
    }
    
    // Read body
    if let Ok(body) = req.into_body().collect().await {
        let bytes = body.to_bytes();
        if !bytes.is_empty() {
            http.set_content(String::from_utf8_lossy(&bytes).to_string());
        }
    }
    
    SbiRequest {
        header: crate::message::SbiHeader::with_method_uri(method, uri),
        http,
    }
}

/// Convert SbiResponse to hyper response
fn convert_response(sbi_response: SbiResponse) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(sbi_response.status);
    
    // Add headers
    for (key, value) in &sbi_response.http.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    
    // Build body
    let body = sbi_response
        .http
        .content
        .map(|c| Full::new(Bytes::from(c)))
        .unwrap_or_else(|| Full::new(Bytes::new()));
    
    builder.body(body).unwrap_or_else(|_| {
        Response::builder()
            .status(500)
            .body(Full::new(Bytes::from("Internal Server Error")))
            .unwrap()
    })
}

/// Server state
enum ServerState {
    Stopped,
    Running(oneshot::Sender<()>),
}

/// SBI Server - HTTP/2 server for SBI communication
/// Matches ogs_sbi_server_t
pub struct SbiServer {
    /// Server configuration
    config: SbiServerConfig,
    /// Server state
    state: Arc<Mutex<ServerState>>,
}

impl SbiServer {
    /// Create a new SBI server
    pub fn new(config: SbiServerConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ServerState::Stopped)),
        }
    }

    /// Create a server with address
    pub fn with_addr(addr: SocketAddr) -> Self {
        Self::new(SbiServerConfig::new(addr))
    }

    /// Get the server configuration
    pub fn config(&self) -> &SbiServerConfig {
        &self.config
    }

    /// Start the server with a request handler
    pub async fn start<H: SbiRequestHandler>(&self, handler: H) -> SbiResult<()> {
        let mut state = self.state.lock().await;
        
        if matches!(*state, ServerState::Running(_)) {
            return Err(SbiError::ServerError("Server already running".to_string()));
        }

        let listener = TcpListener::bind(self.config.addr)
            .await
            .map_err(|e| SbiError::ServerError(format!("Failed to bind: {}", e)))?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        *state = ServerState::Running(shutdown_tx);
        drop(state);

        let handler = Arc::new(handler);
        let _addr = self.config.addr;

        // Spawn the server task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let io = TokioIo::new(stream);
                                let service = SbiService {
                                    handler: handler.clone(),
                                };

                                tokio::spawn(async move {
                                    if let Err(e) = http2::Builder::new(
                                        hyper_util::rt::TokioExecutor::new()
                                    )
                                    .serve_connection(io, service)
                                    .await
                                    {
                                        eprintln!("HTTP/2 connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the server
    pub async fn stop(&self) -> SbiResult<()> {
        let mut state = self.state.lock().await;
        
        if let ServerState::Running(shutdown_tx) = std::mem::replace(&mut *state, ServerState::Stopped) {
            let _ = shutdown_tx.send(());
        }
        
        Ok(())
    }

    /// Check if the server is running
    pub async fn is_running(&self) -> bool {
        let state = self.state.lock().await;
        matches!(*state, ServerState::Running(_))
    }
}

/// Stream identifier for tracking requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Helper function to send an error response
pub fn send_error(
    status: u16,
    title: &str,
    detail: &str,
    cause: Option<&str>,
) -> SbiResponse {
    use crate::message::ProblemDetails;

    let problem = ProblemDetails::with_status(status as i32)
        .with_title(title)
        .with_detail(detail);

    let problem = if let Some(c) = cause {
        problem.with_cause(c)
    } else {
        problem
    };

    SbiResponse::with_status(status)
        .with_json_body(&problem)
        .unwrap_or_else(|_| SbiResponse::with_status(status))
}

/// Send a 400 Bad Request error response
pub fn send_bad_request(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(400, "Bad Request", detail, cause)
}

/// Send a 401 Unauthorized error response
pub fn send_unauthorized(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(401, "Unauthorized", detail, cause)
}

/// Send a 403 Forbidden error response
pub fn send_forbidden(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(403, "Forbidden", detail, cause)
}

/// Send a 404 Not Found error response
pub fn send_not_found(detail: &str, cause: Option<&str>) -> SbiResponse {
    send_error(404, "Not Found", detail, cause)
}

/// Send a 405 Method Not Allowed error response
pub fn send_method_not_allowed(method: &str, resource: &str) -> SbiResponse {
    send_error(
        405,
        "Method Not Allowed",
        &format!("Method {} not allowed for resource {}", method, resource),
        Some("METHOD_NOT_ALLOWED"),
    )
}

/// Send a 500 Internal Server Error response
pub fn send_internal_error(detail: &str) -> SbiResponse {
    send_error(500, "Internal Server Error", detail, Some("INTERNAL_ERROR"))
}

/// Send a 503 Service Unavailable error response
pub fn send_service_unavailable(detail: &str) -> SbiResponse {
    send_error(503, "Service Unavailable", detail, Some("SERVICE_UNAVAILABLE"))
}

/// Send a 504 Gateway Timeout error response
pub fn send_gateway_timeout(detail: &str) -> SbiResponse {
    send_error(504, "Gateway Timeout", detail, Some("GATEWAY_TIMEOUT"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config() {
        let config = SbiServerConfig::new(SocketAddr::from(([0, 0, 0, 0], 8080)))
            .with_interface("sbi");
        
        assert_eq!(config.addr.port(), 8080);
        assert_eq!(config.interface, Some("sbi".to_string()));
    }

    #[test]
    fn test_stream_id() {
        let id = StreamId::new(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn test_send_error() {
        let response = send_error(404, "Not Found", "Resource not found", None);
        assert_eq!(response.status, 404);
    }
}
