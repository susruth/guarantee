//! # guarantee
//!
//! TEE attestation SDK for Rust. Cryptographic proof that your code runs inside
//! a Trusted Execution Environment (TEE) — every HTTP response carries a
//! verifiable signature chain from the enclave's SGX startup quote down to the
//! individual response body.
//!
//! ## How it works
//!
//! 1. At startup, [`EnclaveAttestor::initialize`] generates an ephemeral Ed25519
//!    signing keypair and, when running inside an Intel SGX enclave, obtains a
//!    DCAP attestation quote binding the public key to the enclave measurement
//!    (MRENCLAVE + MRSIGNER). In dev mode it produces a mock quote so you can
//!    develop without SGX hardware.
//! 2. The `#[attest]` macro wraps axum handlers so that every HTTP response
//!    automatically includes an `X-TEE-Attestation` header containing an
//!    Ed25519 signature over `SHA-256(body || timestamp_ms || request_id)`.
//! 3. Callers can independently verify: the startup quote proves the enclave is
//!    genuine, and the per-response signature proves the response came from that
//!    exact enclave binary.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use axum::{extract::Extension, response::Json, routing::get, Router};
//! use guarantee::{attest, state, EnclaveAttestor};
//! use serde::Serialize;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[derive(Serialize, Default, Clone, serde::Deserialize)]
//! struct AppData {
//!     request_count: u64,
//! }
//!
//! // Declare MRENCLAVE-bound state (resets on every redeploy).
//! state! {
//!     #[mrenclave]
//!     AppData,
//! }
//!
//! // Every response from this handler will include X-TEE-Attestation.
//! #[attest]
//! async fn hello() -> Json<serde_json::Value> {
//!     Json(serde_json::json!({ "message": "hello from TEE" }))
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let state = TeeState::initialize(std::path::Path::new("./sealed"))
//!         .expect("Failed to initialize TeeState");
//!
//!     let app = Router::new()
//!         .route("/hello", get(hello))
//!         .layer(Extension(Arc::new(RwLock::new(state))));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
//!         .await
//!         .expect("Failed to bind");
//!     axum::serve(listener, app).await.expect("Server failed");
//! }
//! ```
//!
//! ## Feature Flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `ra-tls` | RA-TLS server and inter-enclave client with SGX attestation embedded in X.509 certificates |
//!
//! Enable `ra-tls` in `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! guarantee = { version = "0.1", features = ["ra-tls"] }
//! ```
//!
//! ## Environment Variables
//!
//! | Variable | Values | Description |
//! |----------|--------|-------------|
//! | `GUARANTEE_ENCLAVE` | `1` | Activates real SGX `/dev/attestation` calls. Unset for dev mode. |
//! | `GUARANTEE_ATTEST_MODE` | `startup-only` | Only produce the startup quote; skip per-response signatures. |
//!
//! ## Key capabilities
//!
//! - **`state!` macro** — Declares TEE state with MRENCLAVE / MRSIGNER / external tiers,
//!   generates `TeeState` with `initialize`, `seal`, `backup`, `restore`, and schema migration.
//! - **`#[attest]`** — Wraps axum handlers for automatic per-response Ed25519 signing.
//! - **`#[derive(Encrypted)]` + `#[encrypt]`** — Field-level AES-256-GCM encryption for external databases.
//! - **Key rotation** — `check_rotation()` / `rotate_master_key()` with retired key fallback.
//! - **Backup/restore** — `state.backup(seal_dir, backup_dir)` / `TeeState::restore(backup_dir, seal_dir)`.
//! - **RA-TLS** *(feature flag)* — `serve_ra_tls` for HTTPS with embedded attestation,
//!   `connect()` for inter-enclave calls with MRENCLAVE pinning, and WebSocket over RA-TLS.
//!
//! ## Modules
//!
//! - [`attestation`] — [`EnclaveAttestor`] and [`AttestationMode`]
//! - [`crypto`] — AES-256-GCM field-level encryption and HKDF key derivation
//! - [`errors`] — [`SdkError`] error type
//! - [`gramine`] — Raw `/dev/attestation` interface
//! - [`response`] — [`AttestationHeader`] and [`AttestedResponse`]
//! - [`seal`] — SGX sealing / unsealing for persistent TEE state
//! - [`types`] — Core TEE types: [`MrEnclave`], [`MrSigner`], [`StartupQuote`]
//! - [`ra_tls`] — RA-TLS server, inter-enclave client, and WebSocket *(feature-gated)*

pub mod attestation;
pub mod crypto;
pub mod errors;
pub mod gramine;
pub mod macros;
pub mod response;
pub mod seal;
pub mod types;

#[cfg(feature = "ra-tls")]
pub mod ra_tls;

pub use attestation::{AttestationMode, EnclaveAttestor};
pub use crypto::{Encryptable, RetiredKeyEntry};
pub use errors::SdkError;
pub use macros::attest;
pub use response::{AttestationHeader, AttestedResponse};
pub use types::{MrEnclave, MrSigner, StartupQuote};

#[cfg(feature = "ra-tls")]
pub use ra_tls::client::EnclaveConnectionBuilder;
#[cfg(feature = "ra-tls")]
pub use ra_tls::server::serve_ra_tls;

/// Create a builder for connecting to another enclave with RA-TLS verification.
///
/// Returns an [`EnclaveConnectionBuilder`] that configures a `reqwest::Client`
/// with a custom `rustls` verifier. The verifier checks the server's X.509
/// certificate for an embedded SGX attestation quote and, if
/// [`EnclaveConnectionBuilder::with_mrenclave`] is called, verifies that the
/// quote's MRENCLAVE matches the expected value.
///
/// # Example
///
/// ```rust,ignore
/// let conn = guarantee::connect("https://oracle.internal:8443")
///     .with_mrenclave(expected_measurement)
///     .build()?;
/// let resp = conn.get("/price/BTC").await?;
/// ```
#[cfg(feature = "ra-tls")]
pub fn connect(url: &str) -> ra_tls::client::EnclaveConnectionBuilder {
    ra_tls::client::EnclaveConnectionBuilder::new(url)
}

// Re-export proc macros from guarantee-macros crate.
// All three macro types (attribute, derive, function-like) are re-exported
// so users only need `use guarantee::{attest, state, Encrypted}`.
pub use guarantee_macros::Encrypted;

/// Declare TEE state with automatic key management and sealing.
///
/// The macro generates a `TeeState` struct that wraps your data types and
/// handles key derivation, sealing, and attestation automatically. Each
/// annotated type maps to a different sealing scope:
///
/// - `#[mrenclave]` — sealed with the enclave's MRENCLAVE. Only the exact same
///   compiled binary can unseal this state. Resets on every redeploy.
/// - `#[mrsigner]` — sealed with MRSIGNER. Any binary from the same signing
///   key can unseal, so state persists across redeployments and upgrades.
/// - `#[external]` — encrypted for storage in external databases or caches
///   (e.g., PostgreSQL, Redis). Use `state.encrypt_<type>()` /
///   `state.decrypt_<type>()` when reading and writing to external storage.
///
/// # Example
///
/// ```rust,ignore
/// guarantee::state! {
///     #[mrenclave]
///     SessionState,
///
///     #[mrsigner]
///     UserSecrets,
///
///     #[external]
///     UserRecord,
/// }
/// ```
pub use guarantee_macros::state;
