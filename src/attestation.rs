//! Enclave attestation: startup quote generation and per-response signing.
//!
//! [`EnclaveAttestor`] is the central type for attestation. Initialize it once
//! at startup and inject it into your axum router as an [`Extension`](axum::extract::Extension).
//! The `#[attest]` macro retrieves it from the extension layer and calls
//! [`sign_response`](EnclaveAttestor::sign_response) automatically.

use std::sync::{Arc, RwLock};

use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::types::{MrEnclave, MrSigner, StartupQuote};

use crate::errors::SdkError;
use crate::gramine;
use crate::response::{hex_encode, AttestationHeader};

/// Controls whether per-response attestation signatures are produced.
///
/// Set via the `GUARANTEE_ATTEST_MODE` environment variable:
///
/// | Value | Mode |
/// |-------|------|
/// | *(unset or other)* | `EveryResponse` |
/// | `startup-only` | `StartupOnly` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    /// Every HTTP response is signed with the enclave's ephemeral Ed25519 key.
    ///
    /// The resulting `X-TEE-Attestation` header allows callers to verify that
    /// each response was produced by the attested enclave instance.
    EveryResponse,

    /// Only the startup quote is produced; per-response signatures are skipped.
    ///
    /// The `X-TEE-Attestation` header is still present but `sig` and `hash`
    /// will be empty strings. Use this mode when per-response overhead matters
    /// and callers only need startup-level assurance.
    StartupOnly,
}

/// The core attestation engine.
///
/// `EnclaveAttestor` holds an ephemeral Ed25519 signing keypair and the startup
/// attestation quote. It is created once at startup via [`initialize`] and then
/// shared across request handlers as an `Arc<EnclaveAttestor>`.
///
/// In enclave mode (`GUARANTEE_ENCLAVE=1`), initialization writes the public
/// key hash to `/dev/attestation/user_report_data` and reads a real DCAP quote.
/// In dev mode the quote is a mock struct with `0xDE` fill bytes.
///
/// # Example
///
/// ```rust,ignore
/// use axum::{extract::Extension, routing::get, Router};
/// use guarantee::{attest, EnclaveAttestor};
///
/// #[attest]
/// async fn handler() -> axum::response::Json<serde_json::Value> {
///     axum::response::Json(serde_json::json!({ "ok": true }))
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let attestor = EnclaveAttestor::initialize().await.unwrap();
///
///     let app = Router::new()
///         .route("/api", get(handler))
///         .layer(Extension(attestor));
///
///     // every /api response will carry X-TEE-Attestation
/// }
/// ```
///
/// [`initialize`]: EnclaveAttestor::initialize
pub struct EnclaveAttestor {
    signing_key: SigningKey,
    /// The Ed25519 public key corresponding to the private signing key.
    /// Clients use this to verify per-response signatures.
    pub public_key: VerifyingKey,
    /// The startup attestation quote, populated during [`initialize`].
    /// Served at `GET /.well-known/tee-attestation`.
    ///
    /// [`initialize`]: EnclaveAttestor::initialize
    pub startup_quote: Arc<RwLock<Option<StartupQuote>>>,
    /// Whether to produce per-response signatures.
    pub mode: AttestationMode,
}

impl EnclaveAttestor {
    /// Initialize the attestor using the attestation mode from the environment.
    ///
    /// Reads `GUARANTEE_ATTEST_MODE` to determine [`AttestationMode`] and then
    /// delegates to [`initialize_with_mode`](Self::initialize_with_mode).
    ///
    /// In enclave mode, this call blocks briefly while the SGX quoting enclave
    /// generates the DCAP quote. In dev mode it returns immediately.
    pub async fn initialize() -> Result<Arc<Self>, SdkError> {
        let mode = Self::detect_attestation_mode();
        Self::initialize_with_mode(mode).await
    }

    /// Initialize the attestor with an explicit [`AttestationMode`].
    ///
    /// Useful in tests or when the attestation mode must be chosen
    /// programmatically rather than via the environment.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use guarantee::{EnclaveAttestor, AttestationMode};
    ///
    /// let attestor = EnclaveAttestor::initialize_with_mode(AttestationMode::StartupOnly)
    ///     .await?;
    /// ```
    pub async fn initialize_with_mode(mode: AttestationMode) -> Result<Arc<Self>, SdkError> {
        tracing::info!(
            mode = if Self::is_enclave_mode() { "enclave" } else { "dev" },
            attestation_mode = ?mode,
            "Initializing EnclaveAttestor"
        );
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let quote = Self::get_startup_quote(&signing_key, &public_key)?;

        tracing::info!("EnclaveAttestor initialized successfully");
        Ok(Arc::new(Self {
            signing_key,
            public_key,
            startup_quote: Arc::new(RwLock::new(Some(quote))),
            mode,
        }))
    }

    /// Detect attestation mode from the `GUARANTEE_ATTEST_MODE` env var.
    /// Defaults to `EveryResponse` if not set or unrecognised.
    fn detect_attestation_mode() -> AttestationMode {
        match std::env::var("GUARANTEE_ATTEST_MODE").as_deref() {
            Ok("startup-only") => AttestationMode::StartupOnly,
            _ => AttestationMode::EveryResponse,
        }
    }

    fn is_enclave_mode() -> bool {
        std::env::var("GUARANTEE_ENCLAVE")
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    fn get_startup_quote(
        signing_key: &SigningKey,
        pub_key: &VerifyingKey,
    ) -> Result<StartupQuote, SdkError> {
        if Self::is_enclave_mode() {
            Self::get_real_quote(signing_key, pub_key)
        } else {
            Ok(Self::get_dev_quote(pub_key))
        }
    }

    fn get_real_quote(
        _signing_key: &SigningKey,
        pub_key: &VerifyingKey,
    ) -> Result<StartupQuote, SdkError> {
        // Write public key hash as user report data
        let mut user_data = [0u8; 64];
        let hash = Sha256::digest(pub_key.as_bytes());
        user_data[..32].copy_from_slice(&hash);

        gramine::write_user_report_data(&user_data)?;
        let raw_quote = gramine::read_quote()?;

        // In production, parse the quote to extract MrEnclave/MrSigner.
        // For now, return with placeholder values -- the infrastructure
        // verifier will do the real parsing.
        Ok(StartupQuote {
            raw_quote,
            mr_enclave: MrEnclave::new([0u8; 32]),
            mr_signer: MrSigner::new([0u8; 32]),
            attested_public_key: *pub_key,
            produced_at: Utc::now(),
        })
    }

    fn get_dev_quote(pub_key: &VerifyingKey) -> StartupQuote {
        StartupQuote {
            raw_quote: b"DEV_MODE_QUOTE".to_vec(),
            mr_enclave: MrEnclave::new([0xDE_u8; 32]),
            mr_signer: MrSigner::new([0xDE_u8; 32]),
            attested_public_key: *pub_key,
            produced_at: Utc::now(),
        }
    }

    /// Sign a response body and produce an [`AttestationHeader`].
    ///
    /// Called automatically by handlers wrapped with `#[attest]`. The payload
    /// hash is computed as:
    ///
    /// ```text
    /// SHA-256(body || timestamp_ms_big_endian || request_id_utf8)
    /// ```
    ///
    /// When [`AttestationMode::StartupOnly`] is active, the returned header has
    /// empty `signature_b64` and `payload_hash_hex` fields but still includes
    /// the public key hex so callers can identify the enclave instance.
    pub fn sign_response(&self, body: &[u8], request_id: &str) -> AttestationHeader {
        tracing::debug!(%request_id, body_len = body.len(), "Signing response");
        if self.mode == AttestationMode::StartupOnly {
            return AttestationHeader {
                version: 1,
                signature_b64: String::new(),
                payload_hash_hex: String::new(),
                timestamp_ms: Utc::now().timestamp_millis() as u64,
                public_key_hex: hex_encode(self.public_key.as_bytes()),
            };
        }

        let timestamp_ms = Utc::now().timestamp_millis() as u64;

        let mut hasher = Sha256::new();
        hasher.update(body);
        hasher.update(timestamp_ms.to_be_bytes());
        hasher.update(request_id.as_bytes());
        let payload_hash: [u8; 32] = hasher.finalize().into();

        let signature = self.signing_key.sign(&payload_hash);

        AttestationHeader {
            version: 1,
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            payload_hash_hex: hex_encode(&payload_hash),
            timestamp_ms,
            public_key_hex: hex_encode(self.public_key.as_bytes()),
        }
    }

    /// Produce the JSON body for `GET /.well-known/tee-attestation`.
    ///
    /// Returns a [`serde_json::Value`] with the following fields:
    ///
    /// | Field | Type | Description |
    /// |-------|------|-------------|
    /// | `public_key` | hex string | The enclave's ephemeral Ed25519 public key |
    /// | `quote` | base64 string or null | Raw DCAP quote bytes |
    /// | `mr_enclave` | hex string or null | Enclave code measurement |
    /// | `mr_signer` | hex string or null | Signing key measurement |
    /// | `tee_type` | string | `"intel-sgx"` or `"dev-mode"` |
    /// | `produced_at` | RFC 3339 string or null | Quote generation timestamp |
    ///
    /// Returns [`SdkError::NotInitialized`] if called before [`initialize`].
    ///
    /// [`initialize`]: EnclaveAttestor::initialize
    pub fn startup_attestation_json(&self) -> Result<serde_json::Value, SdkError> {
        let quote_guard = self
            .startup_quote
            .read()
            .map_err(|_| SdkError::NotInitialized)?;
        let quote = quote_guard.as_ref();

        Ok(serde_json::json!({
            "public_key": hex_encode(self.public_key.as_bytes()),
            "quote": quote.map(|q| base64::engine::general_purpose::STANDARD.encode(&q.raw_quote)),
            "mr_enclave": quote.map(|q| q.mr_enclave.to_string()),
            "mr_signer": quote.map(|q| q.mr_signer.to_string()),
            "tee_type": if Self::is_enclave_mode() { "intel-sgx" } else { "dev-mode" },
            "produced_at": quote.map(|q| q.produced_at.to_rfc3339()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn initialize_succeeds_in_dev_mode() {
        // GUARANTEE_ENCLAVE should NOT be set in test env
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let attestor = EnclaveAttestor::initialize()
            .await
            .expect("should init in dev mode");
        assert!(attestor.startup_quote.read().expect("lock").is_some());
    }

    #[tokio::test]
    async fn sign_response_produces_valid_header() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let attestor = EnclaveAttestor::initialize().await.expect("should init");
        let header = attestor.sign_response(b"hello world", "req-123");
        assert_eq!(header.version, 1);
        assert!(!header.signature_b64.is_empty());
        assert!(!header.payload_hash_hex.is_empty());
    }

    #[tokio::test]
    async fn sign_response_signature_verifies() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let attestor = EnclaveAttestor::initialize().await.expect("should init");
        let body = b"test body";
        let header = attestor.sign_response(body, "req-456");

        // Decode and verify
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&header.signature_b64)
            .expect("valid base64");
        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().expect("64 bytes"),
        );

        let hash_bytes = hex_decode(&header.payload_hash_hex);
        use ed25519_dalek::Verifier;
        assert!(attestor.public_key.verify(&hash_bytes, &signature).is_ok());
    }

    #[tokio::test]
    async fn startup_attestation_json_has_required_fields() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let attestor = EnclaveAttestor::initialize().await.expect("should init");
        let json = attestor
            .startup_attestation_json()
            .expect("should produce json");
        assert!(json.get("public_key").is_some());
        assert!(json.get("quote").is_some());
        assert!(json.get("mr_enclave").is_some());
        assert!(json.get("tee_type").is_some());
    }

    #[tokio::test]
    async fn startup_only_mode_returns_empty_signature() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let attestor = EnclaveAttestor::initialize_with_mode(AttestationMode::StartupOnly)
            .await
            .expect("should init");
        assert_eq!(attestor.mode, AttestationMode::StartupOnly);

        let header = attestor.sign_response(b"hello world", "req-789");
        assert_eq!(header.version, 1);
        assert!(header.signature_b64.is_empty());
        assert!(header.payload_hash_hex.is_empty());
        // Public key should still be present
        assert!(!header.public_key_hex.is_empty());
    }

    #[tokio::test]
    async fn every_response_mode_signs_responses() {
        std::env::remove_var("GUARANTEE_ENCLAVE");
        let attestor = EnclaveAttestor::initialize_with_mode(AttestationMode::EveryResponse)
            .await
            .expect("should init");
        assert_eq!(attestor.mode, AttestationMode::EveryResponse);

        let header = attestor.sign_response(b"hello world", "req-abc");
        assert!(!header.signature_b64.is_empty());
        assert!(!header.payload_hash_hex.is_empty());
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
