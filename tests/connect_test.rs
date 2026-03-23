//! Integration tests for inter-enclave communication.
//!
//! Run with: `cargo test --features ra-tls`

#![cfg(feature = "ra-tls")]

use guarantee::connect;
use guarantee::ra_tls::client::{EnclaveConnection, EnclaveConnectionBuilder};
use guarantee::types::MrEnclave;

#[test]
fn connection_builder_sets_url() {
    let builder = EnclaveConnectionBuilder::new("https://oracle:8443");
    let conn = builder.build().expect("should build");
    assert_eq!(conn.url(), "https://oracle:8443");
}

#[test]
fn connection_builder_with_mrenclave() {
    let mr = MrEnclave::new([0xAA; 32]);
    let conn = EnclaveConnectionBuilder::new("https://oracle:8443")
        .with_mrenclave(mr)
        .build()
        .expect("should build");
    assert_eq!(conn.expected_mrenclave(), Some(&mr));
}

#[test]
fn connection_builder_dev_mode_default() {
    // In test environment, GUARANTEE_ENCLAVE is not set
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let conn = EnclaveConnectionBuilder::new("https://oracle:8443")
        .build();
    assert!(conn.is_ok(), "Should build with dev mode auto-detected");
}

#[test]
fn connect_convenience_function_works() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let conn = connect("https://oracle:8443").build();
    assert!(conn.is_ok(), "Convenience function should build connection");
    assert_eq!(conn.expect("should build").url(), "https://oracle:8443");
}

#[test]
fn connect_with_mrenclave_pinning() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let mr = MrEnclave::new([0xBB; 32]);
    let conn = connect("https://oracle:8443")
        .with_mrenclave(mr)
        .build()
        .expect("should build");
    assert_eq!(conn.expected_mrenclave(), Some(&mr));
}

#[test]
fn enclave_connection_builder_method() {
    std::env::remove_var("GUARANTEE_ENCLAVE");
    let conn = EnclaveConnection::builder("https://oracle:8443")
        .build()
        .expect("should build");
    assert_eq!(conn.url(), "https://oracle:8443");
}
