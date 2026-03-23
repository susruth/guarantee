//! RA-TLS certificate generation.
//!
//! Generates a self-signed X.509 certificate with an SGX attestation quote
//! embedded as an extension. In dev mode, generates a plain self-signed cert
//! without the quote extension.

use crate::errors::SdkError;
use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair};
use sha2::{Digest, Sha256};

/// OID for the SGX quote extension in RA-TLS certificates.
/// OID: 1.2.840.113741.1337.6
const SGX_QUOTE_EXTENSION_OID: &[u64] = &[1, 2, 840, 113741, 1337, 6];

/// An RA-TLS certificate with its private key.
pub struct RaTlsCert {
    /// DER-encoded X.509 certificate.
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key (ECDSA P-256).
    pub private_key_der: Vec<u8>,
    /// PEM-encoded X.509 certificate.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

/// Generate an RA-TLS certificate.
///
/// In enclave mode (`GUARANTEE_ENCLAVE=1`): generates an ECDSA P-256 keypair,
/// obtains an SGX quote with `SHA-256(public_key)` as user report data, and
/// embeds the quote in an X.509 extension (OID 1.2.840.113741.1337.6).
///
/// In dev mode: generates a normal self-signed cert without the quote extension.
pub fn generate_ra_tls_cert(service_name: &str) -> Result<RaTlsCert, SdkError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| SdkError::CertificateError(format!("Key generation failed: {e}")))?;

    let mut params = CertificateParams::new(vec![
        format!("{service_name}.guarantee.run"),
        "localhost".to_string(),
    ])
    .map_err(|e| SdkError::CertificateError(format!("Certificate params: {e}")))?;

    params
        .distinguished_name
        .push(DnType::CommonName, format!("{service_name}.guarantee.run"));
    params
        .distinguished_name
        .push(DnType::OrganizationName, "GuaranTEE");

    // Set validity period: 1 year from now
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365);

    if is_enclave_mode() {
        let quote = get_sgx_quote_for_key(&key_pair)?;
        let ext = CustomExtension::from_oid_content(SGX_QUOTE_EXTENSION_OID, quote);
        params.custom_extensions.push(ext);
        tracing::info!(
            service = service_name,
            "Generated RA-TLS certificate with SGX quote extension"
        );
    } else {
        tracing::info!(
            service = service_name,
            "Generated RA-TLS certificate in dev mode (no SGX quote extension)"
        );
    }

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| SdkError::CertificateError(format!("Self-sign failed: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_der = cert.der().to_vec();
    let private_key_der = key_pair.serialized_der().to_vec();

    Ok(RaTlsCert {
        cert_der,
        private_key_der,
        cert_pem,
        key_pem,
    })
}

/// Check if we are running inside a Gramine SGX enclave.
fn is_enclave_mode() -> bool {
    std::env::var("GUARANTEE_ENCLAVE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Get an SGX quote binding the TLS public key to the enclave identity.
///
/// Writes SHA-256(public_key_der) to `/dev/attestation/user_report_data`,
/// then reads the generated quote from `/dev/attestation/quote`.
fn get_sgx_quote_for_key(key_pair: &KeyPair) -> Result<Vec<u8>, SdkError> {
    let pub_key_der = key_pair.public_key_der();
    let hash = Sha256::digest(pub_key_der);

    let mut user_data = [0u8; 64];
    user_data[..32].copy_from_slice(&hash);

    crate::gramine::write_user_report_data(&user_data)?;
    let quote = crate::gramine::read_quote()?;

    tracing::debug!(
        pub_key_hash = %hex::encode(&hash),
        quote_len = quote.len(),
        "Obtained SGX quote for TLS key"
    );

    Ok(quote)
}

/// Helper: hex encode bytes (avoids external dep for internal use).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_mode_generates_valid_cert() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let cert = generate_ra_tls_cert("test-service").expect("should generate cert");
        assert!(!cert.cert_der.is_empty());
        assert!(!cert.private_key_der.is_empty());
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn dev_mode_cert_has_no_quote_extension() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let cert = generate_ra_tls_cert("test-service").expect("should generate cert");

        // Parse the certificate and check for the SGX extension
        let (_, parsed) = x509_parser::parse_x509_certificate(&cert.cert_der)
            .expect("should parse X.509");

        // OID 1.2.840.113741.1337.6
        let sgx_oid = x509_parser::oid_registry::Oid::from(SGX_QUOTE_EXTENSION_OID)
            .expect("valid OID");
        let has_sgx_ext = parsed
            .extensions()
            .iter()
            .any(|ext| ext.oid == sgx_oid);

        assert!(!has_sgx_ext, "Dev mode cert should not have SGX quote extension");
    }

    #[test]
    fn dev_mode_cert_has_correct_cn() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let cert = generate_ra_tls_cert("my-oracle").expect("should generate cert");

        let (_, parsed) = x509_parser::parse_x509_certificate(&cert.cert_der)
            .expect("should parse X.509");

        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .expect("should have CN");
        assert_eq!(
            cn.as_str().expect("valid UTF-8"),
            "my-oracle.guarantee.run"
        );
    }

    #[test]
    fn multiple_certs_have_different_keys() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let cert1 = generate_ra_tls_cert("svc1").expect("cert1");
        let cert2 = generate_ra_tls_cert("svc2").expect("cert2");
        assert_ne!(cert1.private_key_der, cert2.private_key_der);
    }
}
