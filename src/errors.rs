use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Attestation unavailable: {0}")]
    AttestationUnavailable(String),

    #[error("Failed to read quote: {0}")]
    QuoteReadFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Attestor not initialized")]
    NotInitialized,

    #[error("Seal error: {0}")]
    SealError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("RA-TLS error: {0}")]
    RaTlsError(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("TLS error: {0}")]
    TlsError(String),
}
