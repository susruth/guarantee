//! Error types for the guarantee SDK.
//!
//! All fallible operations in this crate return [`SdkError`]. The variants
//! map onto the major subsystems: attestation, cryptography, sealing, and
//! transport (RA-TLS).

use thiserror::Error;

/// The top-level error type for the guarantee SDK.
///
/// Returned by every fallible function in the crate. Use pattern matching or
/// the [`thiserror`]-generated `Display` impl to produce human-readable
/// diagnostics.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::{EnclaveAttestor, SdkError};
///
/// match EnclaveAttestor::initialize().await {
///     Ok(attestor) => { /* use attestor */ }
///     Err(SdkError::AttestationUnavailable(msg)) => {
///         eprintln!("SGX attestation not available: {msg}");
///     }
///     Err(e) => eprintln!("Unexpected error: {e}"),
/// }
/// ```
#[derive(Debug, Error)]
pub enum SdkError {
    /// The SGX attestation interface (`/dev/attestation`) is not available.
    ///
    /// This occurs when the binary runs outside a Gramine enclave and
    /// `GUARANTEE_ENCLAVE=1` is set, or when the Gramine manifest does not
    /// include the `/dev/attestation` pseudo-filesystem mount.
    #[error("Attestation unavailable: {0}")]
    AttestationUnavailable(String),

    /// Reading the DCAP quote from `/dev/attestation/quote` failed.
    ///
    /// This can happen if user report data was not written first, or if the
    /// Gramine process does not have SGX quoting support enabled.
    #[error("Failed to read quote: {0}")]
    QuoteReadFailed(String),

    /// Generating the ephemeral Ed25519 signing keypair failed.
    ///
    /// This is extremely unlikely under normal conditions since key generation
    /// only requires operating-system randomness (`OsRng`).
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// An Ed25519 signing operation failed.
    ///
    /// Also returned when parsing an `X-TEE-Attestation` header that contains
    /// invalid fields (e.g., a non-integer version or timestamp).
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// A low-level I/O error, propagated from [`std::io::Error`].
    ///
    /// This is automatically produced by the `#[from]` conversion.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// The [`EnclaveAttestor`](crate::attestation::EnclaveAttestor) was used
    /// before it was initialized.
    ///
    /// Always call [`EnclaveAttestor::initialize`](crate::attestation::EnclaveAttestor::initialize)
    /// at startup and store the resulting `Arc<EnclaveAttestor>` before
    /// accepting requests.
    #[error("Attestor not initialized")]
    NotInitialized,

    /// A sealing or unsealing operation failed.
    ///
    /// In dev mode this covers file I/O errors and seal-mode mismatches.
    /// In enclave mode it covers Gramine Protected Files errors.
    #[error("Seal error: {0}")]
    SealError(String),

    /// An AES-256-GCM encryption or decryption error, or an HKDF derivation
    /// error.
    ///
    /// Common causes: wrong key, corrupted ciphertext, key version not found
    /// in the retired key list, or a malformed `enc:v1:...` payload.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// An RA-TLS connection or verification error.
    ///
    /// Returned by [`EnclaveConnectionBuilder::build`](crate::ra_tls::client::EnclaveConnectionBuilder::build)
    /// and by HTTP methods on [`EnclaveConnection`](crate::ra_tls::client::EnclaveConnection).
    /// Also returned when MRENCLAVE verification fails during the TLS handshake.
    #[error("RA-TLS error: {0}")]
    RaTlsError(String),

    /// An X.509 certificate generation error.
    ///
    /// Returned by [`generate_ra_tls_cert`](crate::ra_tls::cert::generate_ra_tls_cert)
    /// when `rcgen` fails to generate the keypair or self-sign the certificate.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// A TLS configuration or server startup error.
    ///
    /// Returned by [`serve_ra_tls`](crate::ra_tls::server::serve_ra_tls) when
    /// `rustls` fails to load the certificate, or when the HTTPS or HTTP
    /// server encounters a fatal error.
    #[error("TLS error: {0}")]
    TlsError(String),
}
