//! WebSocket support over RA-TLS.
//!
//! WebSocket connections run over the RA-TLS HTTPS server, so the TLS
//! handshake already verifies the enclave attestation. No per-message
//! signing is needed — the entire connection is attested at the transport layer.
//!
//! This module provides re-exports of axum's WebSocket types and a marker
//! trait for documentation purposes.
//!
//! # Example
//!
//! ```rust,ignore
//! use guarantee::ra_tls::websocket::{WsMessage, WsSocket, WsUpgrade};
//! use axum::response::IntoResponse;
//!
//! async fn ws_handler(ws: WsUpgrade) -> impl IntoResponse {
//!     ws.on_upgrade(handle_socket)
//! }
//!
//! async fn handle_socket(mut socket: WsSocket) {
//!     while let Some(Ok(msg)) = socket.recv().await {
//!         // Process message — connection is attested via RA-TLS
//!         if let axum::extract::ws::Message::Text(text) = msg {
//!             socket.send(axum::extract::ws::Message::Text(format!("echo: {text}"))).await.ok();
//!         }
//!     }
//! }
//! ```
//!
//! The attestation happens at the TLS level during the handshake.
//! Once connected, all messages are encrypted in transit and authenticated
//! to the attested enclave. No additional per-message signatures are needed.

// Re-export axum WebSocket types for convenience.
pub use axum::extract::ws::Message as WsMessage;
pub use axum::extract::ws::WebSocket as WsSocket;
pub use axum::extract::ws::WebSocketUpgrade as WsUpgrade;

/// Marker trait indicating a WebSocket connection is RA-TLS attested.
///
/// This is compile-time documentation — the actual attestation happens
/// in the TLS layer. Any `WebSocket` served via `guarantee::ra_tls::server::serve_ra_tls`
/// is automatically attested.
pub trait AttestedWebSocket {}

impl AttestedWebSocket for axum::extract::ws::WebSocket {}
