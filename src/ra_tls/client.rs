//! Inter-enclave communication via RA-TLS.
//!
//! Provides `EnclaveConnection` and its builder for making HTTP requests
//! to other enclaves with mutual attestation verification.

use crate::errors::SdkError;
use crate::types::MrEnclave;

/// Configuration for connecting to another enclave.
///
/// Wraps a `reqwest::Client` configured with RA-TLS verification so that
/// every request verifies the target enclave's SGX attestation quote
/// during the TLS handshake.
pub struct EnclaveConnection {
    /// URL of the target enclave (https://...).
    url: String,
    /// Expected MRENCLAVE of the target (if set, rejects mismatches).
    expected_mrenclave: Option<MrEnclave>,
    /// The reqwest client with RA-TLS verification.
    client: reqwest::Client,
}

impl EnclaveConnection {
    /// Create a builder for connecting to another enclave at the given URL.
    pub fn builder(url: &str) -> EnclaveConnectionBuilder {
        EnclaveConnectionBuilder::new(url)
    }

    /// GET request to the connected enclave.
    pub async fn get(&self, path: &str) -> Result<reqwest::Response, SdkError> {
        let url = format!("{}{}", self.url, path);
        self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| SdkError::RaTlsError(format!("Request failed: {e}")))
    }

    /// POST request with JSON body.
    pub async fn post<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, SdkError> {
        let url = format!("{}{}", self.url, path);
        self.client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| SdkError::RaTlsError(format!("Request failed: {e}")))
    }

    /// The target URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The expected MRENCLAVE (if set).
    pub fn expected_mrenclave(&self) -> Option<&MrEnclave> {
        self.expected_mrenclave.as_ref()
    }
}

/// Builder for `EnclaveConnection`.
///
/// # Example
///
/// ```rust,ignore
/// let conn = guarantee::connect("https://oracle.internal:8443")
///     .with_mrenclave(expected_measurement)
///     .build()?;
/// let price: PriceResponse = conn.get("/price/BTC").await?.json().await?;
/// ```
pub struct EnclaveConnectionBuilder {
    url: String,
    expected_mrenclave: Option<MrEnclave>,
    allow_dev_mode: bool,
}

impl EnclaveConnectionBuilder {
    /// Create a new builder targeting the given URL.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            expected_mrenclave: None,
            allow_dev_mode: !is_enclave_mode(),
        }
    }

    /// Pin the connection to a specific MRENCLAVE measurement.
    /// The TLS handshake will fail if the target enclave's measurement
    /// does not match.
    pub fn with_mrenclave(mut self, mr: MrEnclave) -> Self {
        self.expected_mrenclave = Some(mr);
        self
    }

    /// Whether to allow connections to non-enclave (dev mode) targets.
    /// Defaults to `true` when not running inside an enclave.
    pub fn allow_dev_mode(mut self, allow: bool) -> Self {
        self.allow_dev_mode = allow;
        self
    }

    /// Build the `EnclaveConnection`.
    ///
    /// Creates a `reqwest::Client` with RA-TLS verification configured
    /// according to the builder settings.
    pub fn build(self) -> Result<EnclaveConnection, SdkError> {
        let client = super::verifier::ra_tls_client(
            self.expected_mrenclave.clone(),
            self.allow_dev_mode,
        )?;

        Ok(EnclaveConnection {
            url: self.url,
            expected_mrenclave: self.expected_mrenclave,
            client,
        })
    }
}

/// Check whether we are running inside a TEE enclave.
fn is_enclave_mode() -> bool {
    std::env::var("GUARANTEE_ENCLAVE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_builder_sets_url() {
        let builder = EnclaveConnectionBuilder::new("https://oracle:8443");
        assert_eq!(builder.url, "https://oracle:8443");
    }

    #[test]
    fn connection_builder_with_mrenclave() {
        let mr = MrEnclave::new([0xAA; 32]);
        let builder = EnclaveConnectionBuilder::new("https://oracle:8443").with_mrenclave(mr);
        assert_eq!(builder.expected_mrenclave, Some(mr));
    }

    #[test]
    fn connection_builder_dev_mode_default() {
        // In test env, GUARANTEE_ENCLAVE is not set, so dev mode should be allowed
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let builder = EnclaveConnectionBuilder::new("https://oracle:8443");
        assert!(builder.allow_dev_mode);
    }

    #[test]
    fn connection_builder_allow_dev_mode_override() {
        let builder = EnclaveConnectionBuilder::new("https://oracle:8443").allow_dev_mode(false);
        assert!(!builder.allow_dev_mode);
    }

    #[test]
    fn connection_builds_successfully() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let conn = EnclaveConnectionBuilder::new("https://oracle:8443")
            .build();
        assert!(conn.is_ok());
    }

    #[test]
    fn connection_url_accessor() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let conn = EnclaveConnectionBuilder::new("https://oracle:8443")
            .build()
            .expect("should build");
        assert_eq!(conn.url(), "https://oracle:8443");
    }

    #[test]
    fn connection_mrenclave_accessor() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let mr = MrEnclave::new([0xCC; 32]);
        let conn = EnclaveConnectionBuilder::new("https://oracle:8443")
            .with_mrenclave(mr)
            .build()
            .expect("should build");
        assert_eq!(conn.expected_mrenclave(), Some(&mr));
    }

    #[test]
    fn connection_no_mrenclave_returns_none() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let conn = EnclaveConnectionBuilder::new("https://oracle:8443")
            .build()
            .expect("should build");
        assert!(conn.expected_mrenclave().is_none());
    }
}
