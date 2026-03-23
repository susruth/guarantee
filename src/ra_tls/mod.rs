//! RA-TLS (Remote Attestation TLS) support.
//!
//! Generates self-signed X.509 certificates with SGX attestation quotes
//! embedded as extensions, and provides both server and client-side
//! verification of these certificates.
//!
//! This module is only available with the `ra-tls` feature flag.

pub mod cert;
pub mod client;
pub mod server;
pub mod verifier;
pub mod websocket;
