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
