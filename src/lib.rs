pub mod attestation;
pub mod crypto;
pub mod errors;
pub mod gramine;
pub mod macros;
pub mod response;
pub mod seal;
pub mod types;

pub use attestation::{AttestationMode, EnclaveAttestor};
pub use crypto::Encryptable;
pub use errors::SdkError;
pub use macros::attest;
pub use response::{AttestationHeader, AttestedResponse};
pub use types::{MrEnclave, MrSigner, StartupQuote};

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
