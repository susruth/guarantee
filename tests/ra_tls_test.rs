//! Integration tests for RA-TLS certificate generation, server, and verifier.
//!
//! Run with: `cargo test --features ra-tls`

#![cfg(feature = "ra-tls")]

use guarantee::ra_tls::cert::generate_ra_tls_cert;
use guarantee::ra_tls::verifier::{ra_tls_client, RaTlsVerifier};
use guarantee::ra_tls::websocket::{AttestedWebSocket, WsMessage, WsSocket, WsUpgrade};
use guarantee::types::MrEnclave;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

#[test]
fn dev_mode_cert_generation_produces_valid_x509() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let cert = generate_ra_tls_cert("test-service").expect("should generate cert");

    // Parse as X.509 to confirm validity
    let (_, parsed) =
        x509_parser::parse_x509_certificate(&cert.cert_der).expect("should parse X.509");

    // Verify subject CN
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .expect("should have CN");
    assert_eq!(
        cn.as_str().expect("valid UTF-8"),
        "test-service.guarantee.run"
    );

    // Verify it has a public key
    assert!(!parsed.public_key().raw.is_empty());
}

#[test]
fn dev_mode_cert_has_no_sgx_quote_extension() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let cert = generate_ra_tls_cert("test-service").expect("should generate cert");

    let (_, parsed) =
        x509_parser::parse_x509_certificate(&cert.cert_der).expect("should parse X.509");

    // OID 1.2.840.113741.1337.6
    let sgx_oid = x509_parser::oid_registry::Oid::from(&[1, 2, 840, 113741, 1337, 6])
        .expect("valid OID");
    let has_sgx_ext = parsed.extensions().iter().any(|ext| ext.oid == sgx_oid);

    assert!(
        !has_sgx_ext,
        "Dev mode cert should not have SGX quote extension"
    );
}

#[test]
fn verifier_accepts_dev_mode_cert_when_allow_dev_mode_true() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let verifier = RaTlsVerifier::new(None, true);
    let cert = generate_ra_tls_cert("test").expect("cert");
    let cert_der = CertificateDer::from(cert.cert_der);

    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.guarantee.run").expect("valid name"),
        &[],
        UnixTime::now(),
    );

    assert!(
        result.is_ok(),
        "Should accept dev mode cert when allow_dev_mode is true"
    );
}

#[test]
fn verifier_rejects_dev_mode_cert_when_allow_dev_mode_false() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let verifier = RaTlsVerifier::new(None, false);
    let cert = generate_ra_tls_cert("test").expect("cert");
    let cert_der = CertificateDer::from(cert.cert_der);

    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.guarantee.run").expect("valid name"),
        &[],
        UnixTime::now(),
    );

    assert!(
        result.is_err(),
        "Should reject dev mode cert when allow_dev_mode is false"
    );
}

#[test]
fn verifier_with_mrenclave_rejects_dev_cert() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let mrenclave = MrEnclave::new([0xAA; 32]);
    let verifier = RaTlsVerifier::new(Some(mrenclave), false);
    let cert = generate_ra_tls_cert("test").expect("cert");
    let cert_der = CertificateDer::from(cert.cert_der);

    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.guarantee.run").expect("valid name"),
        &[],
        UnixTime::now(),
    );

    assert!(
        result.is_err(),
        "Should reject dev cert when MRENCLAVE is expected"
    );
}

#[test]
fn ra_tls_client_builds_with_dev_mode() {
    let client = ra_tls_client(None, true);
    assert!(
        client.is_ok(),
        "Should build reqwest client with dev mode allowed"
    );
}

#[test]
fn ra_tls_client_builds_with_mrenclave() {
    let mrenclave = MrEnclave::new([0xBB; 32]);
    let client = ra_tls_client(Some(mrenclave), false);
    assert!(
        client.is_ok(),
        "Should build reqwest client with MRENCLAVE pinning"
    );
}

#[test]
fn websocket_types_available() {
    // Verify that WsMessage, WsSocket, and WsUpgrade are importable and usable.
    // We cannot construct a WsSocket or WsUpgrade without a real connection,
    // but we can verify the re-exported types exist by using WsMessage.
    let msg = WsMessage::Text("hello".to_string());
    match msg {
        WsMessage::Text(t) => assert_eq!(t, "hello"),
        _ => panic!("Expected Text message"),
    }
}

#[test]
fn websocket_attested_trait_exists() {
    // Verify AttestedWebSocket trait is defined and WsSocket implements it.
    // This is a compile-time check — if this compiles, the trait and impl exist.
    fn assert_attested<T: AttestedWebSocket>() {}
    assert_attested::<WsSocket>();
}
