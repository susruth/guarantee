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
// `attest` (proc_macro_attribute) is re-exported via src/macros.rs.
// `state` (proc_macro) and `Encrypted` (proc_macro_derive) use the
// extern crate re-export pattern since pub use doesn't work for these.
#[doc(hidden)]
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
#[macro_export]
macro_rules! state {
    ($($tt:tt)*) => {
        ::guarantee_macros::state!($($tt)*);
    };
}
