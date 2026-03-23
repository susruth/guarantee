//! RA-TLS server startup.
//!
//! Provides `serve_ra_tls` which starts an HTTPS server with an RA-TLS
//! certificate and an optional HTTP server for health checks.

use crate::errors::SdkError;
use crate::ra_tls::cert;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

/// Start an RA-TLS server with dual ports: HTTPS (RA-TLS) + HTTP (health/dev).
///
/// The HTTPS server uses a self-signed certificate with an embedded SGX quote
/// (in enclave mode) or a plain self-signed cert (in dev mode).
///
/// The HTTP server runs on a separate port for health checks and local
/// development. Both servers share the same `Router`.
///
/// # Arguments
///
/// * `app` - The axum Router to serve
/// * `service_name` - Service name used in the certificate CN
/// * `https_addr` - Address for the HTTPS server (e.g., "0.0.0.0:8443")
/// * `http_addr` - Address for the HTTP server (e.g., "0.0.0.0:8080")
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use guarantee::serve_ra_tls;
///
/// let app = Router::new();
/// serve_ra_tls(app, "my-service", "0.0.0.0:8443", "0.0.0.0:8080").await?;
/// ```
pub async fn serve_ra_tls(
    app: Router,
    service_name: &str,
    https_addr: &str,
    http_addr: &str,
) -> Result<(), SdkError> {
    let ra_cert = cert::generate_ra_tls_cert(service_name)?;

    let tls_config = RustlsConfig::from_pem(
        ra_cert.cert_pem.into_bytes(),
        ra_cert.key_pem.into_bytes(),
    )
    .await
    .map_err(|e| SdkError::TlsError(format!("RustlsConfig from PEM: {e}")))?;

    let https_socket: SocketAddr = https_addr
        .parse()
        .map_err(|e| SdkError::TlsError(format!("Invalid HTTPS address '{https_addr}': {e}")))?;

    let http_socket: SocketAddr = http_addr
        .parse()
        .map_err(|e| SdkError::TlsError(format!("Invalid HTTP address '{http_addr}': {e}")))?;

    let https_app = app.clone();
    let http_app = app;

    tracing::info!(
        https = %https_socket,
        http = %http_socket,
        service = service_name,
        "Starting RA-TLS server (HTTPS + HTTP)"
    );

    let tls_handle = tokio::spawn(async move {
        axum_server::bind_rustls(https_socket, tls_config)
            .serve(https_app.into_make_service())
            .await
            .map_err(|e| SdkError::TlsError(format!("HTTPS server error: {e}")))
    });

    let http_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(http_socket)
            .await
            .map_err(|e| SdkError::TlsError(format!("HTTP bind error: {e}")))?;
        axum::serve(listener, http_app)
            .await
            .map_err(|e| SdkError::TlsError(format!("HTTP server error: {e}")))
    });

    // Wait for either server to finish (or fail)
    tokio::select! {
        result = tls_handle => {
            result
                .map_err(|e| SdkError::TlsError(format!("HTTPS task join error: {e}")))?
        }
        result = http_handle => {
            result
                .map_err(|e| SdkError::TlsError(format!("HTTP task join error: {e}")))?
        }
    }
}
