//! RA-TLS client-side certificate verification.
//!
//! Provides `RaTlsVerifier`, a custom `rustls` `ServerCertVerifier` that
//! verifies SGX attestation quotes embedded in X.509 certificates.

use crate::errors::SdkError;
use crate::types::MrEnclave;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use x509_parser::prelude::*;

/// OID for the SGX quote extension: 1.2.840.113741.1337.6
const SGX_QUOTE_OID_BYTES: &[u64] = &[1, 2, 840, 113741, 1337, 6];

/// Offset of MRENCLAVE in the SGX quote report body (bytes 112..144 within
/// the report body, which starts at byte 48 of the quote).
const MRENCLAVE_OFFSET: usize = 48 + 112;
const MRENCLAVE_LEN: usize = 32;

/// Offset of report_data in the SGX quote (bytes 368..432 within the quote).
const REPORT_DATA_OFFSET: usize = 48 + 320;
const REPORT_DATA_LEN: usize = 64;

/// Custom `rustls` `ServerCertVerifier` that verifies SGX quotes in RA-TLS certificates.
///
/// Verification steps:
/// 1. Parse the X.509 certificate
/// 2. Look for the SGX quote extension (OID 1.2.840.113741.1337.6)
/// 3. If found: parse quote, verify `report_data == SHA-256(TLS public key)`
/// 4. If `expected_mrenclave` is set: verify it matches the quote's MRENCLAVE
/// 5. If no extension and `allow_dev_mode`: accept with warning
/// 6. If no extension and `!allow_dev_mode`: reject
#[derive(Debug)]
pub struct RaTlsVerifier {
    /// Optional: pin verification to a specific enclave measurement.
    pub expected_mrenclave: Option<MrEnclave>,
    /// Whether to accept certificates without an SGX quote extension (dev mode).
    pub allow_dev_mode: bool,
    /// The crypto provider for signature verification.
    crypto_provider: Arc<CryptoProvider>,
}

impl RaTlsVerifier {
    /// Create a new RA-TLS verifier.
    ///
    /// # Arguments
    ///
    /// * `expected_mrenclave` - If set, the quote's MRENCLAVE must match
    /// * `allow_dev_mode` - If true, accept certs without SGX quote extension
    pub fn new(expected_mrenclave: Option<MrEnclave>, allow_dev_mode: bool) -> Self {
        Self {
            expected_mrenclave,
            allow_dev_mode,
            crypto_provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }

    /// Extract and verify the SGX quote from a certificate's extensions.
    fn verify_sgx_extension(
        &self,
        cert: &X509Certificate<'_>,
        cert_der: &[u8],
    ) -> Result<(), rustls::Error> {
        let sgx_oid = x509_parser::oid_registry::Oid::from(SGX_QUOTE_OID_BYTES)
            .expect("Static OID is always valid");

        let sgx_ext = cert.extensions().iter().find(|ext| ext.oid == sgx_oid);

        match sgx_ext {
            Some(ext) => {
                let quote_bytes = ext.value;
                self.verify_quote_binding(quote_bytes, cert_der)?;
                self.verify_mrenclave(quote_bytes)?;
                tracing::info!("RA-TLS certificate verified: SGX quote present and valid");
                Ok(())
            }
            None => {
                if self.allow_dev_mode {
                    tracing::warn!(
                        "RA-TLS certificate has no SGX quote extension — accepting in dev mode"
                    );
                    Ok(())
                } else {
                    Err(rustls::Error::General(
                        "RA-TLS certificate missing SGX quote extension and dev mode not allowed"
                            .into(),
                    ))
                }
            }
        }
    }

    /// Verify that the quote's report_data binds to the TLS public key.
    ///
    /// The first 32 bytes of report_data must equal SHA-256(SubjectPublicKeyInfo DER).
    fn verify_quote_binding(
        &self,
        quote_bytes: &[u8],
        cert_der: &[u8],
    ) -> Result<(), rustls::Error> {
        if quote_bytes.len() < REPORT_DATA_OFFSET + REPORT_DATA_LEN {
            return Err(rustls::Error::General(
                "SGX quote too short to contain report_data".into(),
            ));
        }

        let report_data =
            &quote_bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN];

        // Extract the SubjectPublicKeyInfo from the certificate
        let (_, parsed_cert) = X509Certificate::from_der(cert_der).map_err(|_| {
            rustls::Error::General("Failed to parse certificate DER for key extraction".into())
        })?;

        let spki_der = parsed_cert.public_key().raw;
        let key_hash = Sha256::digest(spki_der);

        if report_data[..32] != key_hash[..] {
            return Err(rustls::Error::General(
                "SGX quote report_data does not match SHA-256(TLS public key)".into(),
            ));
        }

        tracing::debug!("RA-TLS key binding verified: report_data matches TLS public key hash");
        Ok(())
    }

    /// Verify that the quote's MRENCLAVE matches the expected value (if set).
    fn verify_mrenclave(&self, quote_bytes: &[u8]) -> Result<(), rustls::Error> {
        if let Some(ref expected) = self.expected_mrenclave {
            if quote_bytes.len() < MRENCLAVE_OFFSET + MRENCLAVE_LEN {
                return Err(rustls::Error::General(
                    "SGX quote too short to contain MRENCLAVE".into(),
                ));
            }

            let mut mrenclave_bytes = [0u8; 32];
            mrenclave_bytes
                .copy_from_slice(&quote_bytes[MRENCLAVE_OFFSET..MRENCLAVE_OFFSET + MRENCLAVE_LEN]);
            let actual = MrEnclave::new(mrenclave_bytes);

            if actual != *expected {
                return Err(rustls::Error::General(format!(
                    "MRENCLAVE mismatch: expected {expected}, got {actual}"
                )));
            }

            tracing::debug!(%expected, "MRENCLAVE verification passed");
        }
        Ok(())
    }
}

impl ServerCertVerifier for RaTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert_der = end_entity.as_ref();
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| rustls::Error::General(format!("Failed to parse X.509: {e}")))?;

        self.verify_sgx_extension(&cert, cert_der)?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create a `reqwest::Client` configured with RA-TLS verification.
///
/// The client uses a custom `rustls` `ServerCertVerifier` that checks for
/// SGX attestation quotes in the server's TLS certificate.
///
/// # Arguments
///
/// * `expected_mrenclave` - If set, the server's MRENCLAVE must match
/// * `allow_dev_mode` - If true, accept certs without SGX quote extension
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::ra_tls::verifier::ra_tls_client;
///
/// let client = ra_tls_client(None, true)?;
/// let resp = client.get("https://my-service:8443/api").send().await?;
/// ```
pub fn ra_tls_client(
    expected_mrenclave: Option<MrEnclave>,
    allow_dev_mode: bool,
) -> Result<reqwest::Client, SdkError> {
    let verifier = Arc::new(RaTlsVerifier::new(expected_mrenclave, allow_dev_mode));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SdkError::TlsError(format!("TLS protocol version error: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(|e| SdkError::TlsError(format!("Failed to build reqwest client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_new_sets_fields() {
        let mrenclave = MrEnclave::new([0xAB; 32]);
        let v = RaTlsVerifier::new(Some(mrenclave), false);
        assert_eq!(v.expected_mrenclave, Some(mrenclave));
        assert!(!v.allow_dev_mode);
    }

    #[test]
    fn verifier_accepts_dev_cert_when_allowed() {
        let v = RaTlsVerifier::new(None, true);
        let cert = crate::ra_tls::cert::generate_ra_tls_cert("test").expect("cert");
        let cert_der = CertificateDer::from(cert.cert_der.clone());

        let result = v.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("test.guarantee.run").expect("valid name"),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok(), "Should accept dev cert when allow_dev_mode=true");
    }

    #[test]
    fn verifier_rejects_dev_cert_when_not_allowed() {
        let v = RaTlsVerifier::new(None, false);
        let cert = crate::ra_tls::cert::generate_ra_tls_cert("test").expect("cert");
        let cert_der = CertificateDer::from(cert.cert_der.clone());

        let result = v.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("test.guarantee.run").expect("valid name"),
            &[],
            UnixTime::now(),
        );

        assert!(
            result.is_err(),
            "Should reject dev cert when allow_dev_mode=false"
        );
    }

    #[test]
    fn ra_tls_client_builds_successfully() {
        let client = ra_tls_client(None, true);
        assert!(client.is_ok(), "Should build reqwest client with RA-TLS verifier");
    }
}
