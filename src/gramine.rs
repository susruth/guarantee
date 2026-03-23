//! Raw interface to Gramine's `/dev/attestation` pseudo-filesystem.
//!
//! Inside a Gramine SGX enclave, the Gramine runtime exposes a pseudo-filesystem
//! at `/dev/attestation` that enables the enclave to generate DCAP attestation
//! quotes. The workflow is:
//!
//! 1. Write exactly 64 bytes of user-controlled data to
//!    `/dev/attestation/user_report_data`. These bytes are embedded verbatim in
//!    the generated quote's `report_data` field and bind arbitrary data (such as
//!    a public key hash) to the enclave identity.
//! 2. Read the generated DCAP quote from `/dev/attestation/quote`.
//!
//! The Gramine manifest **must** include the following mount:
//!
//! ```toml
//! fs.mounts = [
//!   { path = "/dev/attestation", type = "pseudo" },
//! ]
//! ```
//!
//! Without this mount, both functions will return an error.
//!
//! In dev mode (`GUARANTEE_ENCLAVE` not set), these functions are never called;
//! [`EnclaveAttestor`](crate::EnclaveAttestor) substitutes a mock quote instead.

use crate::errors::SdkError;
use std::fs;

const USER_REPORT_DATA_PATH: &str = "/dev/attestation/user_report_data";
const QUOTE_PATH: &str = "/dev/attestation/quote";

/// Write exactly 64 bytes to `/dev/attestation/user_report_data`.
///
/// The data is embedded in the DCAP quote's `report_data` field, which is
/// included in the signed quote body. This binds the arbitrary `data` bytes
/// to the enclave's identity.
///
/// In GuaranTEE, the first 32 bytes are set to
/// `SHA-256(attested_public_key)`, cryptographically linking the enclave's
/// ephemeral Ed25519 public key to the quote.
///
/// # Errors
///
/// Returns [`SdkError::AttestationUnavailable`] if the write fails. This
/// typically means the Gramine manifest does not include the
/// `/dev/attestation` pseudo-filesystem mount.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::gramine::write_user_report_data;
/// use sha2::{Digest, Sha256};
///
/// let mut user_data = [0u8; 64];
/// let hash = Sha256::digest(public_key.as_bytes());
/// user_data[..32].copy_from_slice(&hash);
///
/// write_user_report_data(&user_data)?;
/// ```
pub fn write_user_report_data(data: &[u8; 64]) -> Result<(), SdkError> {
    tracing::debug!(path = USER_REPORT_DATA_PATH, "Writing user report data to attestation device");
    fs::write(USER_REPORT_DATA_PATH, data).map_err(|e| {
        SdkError::AttestationUnavailable(format!("Failed to write user_report_data: {}", e))
    })
}

/// Read the full DCAP quote from `/dev/attestation/quote`.
///
/// Must be called after [`write_user_report_data`]. The Gramine runtime reads
/// the previously written user report data and asks the SGX quoting enclave to
/// produce a DCAP attestation quote that includes it.
///
/// The returned bytes are a raw DCAP quote in the format defined by Intel's
/// [DCAP specification]. They can be passed to an attestation verification
/// service (e.g., Intel DCAP or a third-party verifier) to obtain a verified
/// measurement.
///
/// [DCAP specification]: https://download.01.org/intel-sgx/sgx-dcap/1.20/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
///
/// # Errors
///
/// Returns [`SdkError::QuoteReadFailed`] if the read fails. Common causes:
/// - `write_user_report_data` was not called first.
/// - The Gramine manifest does not include the `/dev/attestation` mount.
/// - The node does not have SGX DCAP support enabled.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::gramine::{write_user_report_data, read_quote};
///
/// let user_data = [0u8; 64]; // fill with your data
/// write_user_report_data(&user_data)?;
/// let raw_quote: Vec<u8> = read_quote()?;
/// ```
pub fn read_quote() -> Result<Vec<u8>, SdkError> {
    tracing::debug!(path = QUOTE_PATH, "Reading DCAP quote from attestation device");
    fs::read(QUOTE_PATH)
        .map_err(|e| SdkError::QuoteReadFailed(format!("Failed to read quote: {}", e)))
}
