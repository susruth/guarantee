//! Attestation response types.
//!
//! [`AttestationHeader`] represents the parsed form of the `X-TEE-Attestation`
//! HTTP response header that the `#[attest]` macro injects into every response.
//! [`AttestedResponse`] bundles a response body with its attestation header for
//! use in verification workflows.

use crate::errors::SdkError;

/// Encode a byte slice as a lowercase hex string.
///
/// Used internally to encode signatures, public keys, and payload hashes
/// in the `X-TEE-Attestation` header.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parsed representation of the `X-TEE-Attestation` HTTP response header.
///
/// The header format is:
///
/// ```text
/// X-TEE-Attestation: v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>
/// ```
///
/// Where:
/// - `v` — header version (currently always `1`)
/// - `sig` — base64-encoded Ed25519 signature over the payload hash
/// - `hash` — hex-encoded SHA-256 of `body || timestamp_ms_be || request_id`
/// - `ts` — Unix timestamp in milliseconds at the time of signing
/// - `key` — hex-encoded Ed25519 public key of the enclave's ephemeral keypair
///
/// Clients verify by:
/// 1. Fetching the startup quote from `GET /.well-known/tee-attestation` and
///    recording the `public_key` field.
/// 2. Recomputing the payload hash from the response body, `ts`, and the known
///    `request_id`.
/// 3. Verifying the `sig` against the payload hash with the `public_key`.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::AttestationHeader;
///
/// let raw = "v=1; sig=abc=; hash=deadbeef; ts=1700000000000; key=0102";
/// let header = AttestationHeader::from_header_value(raw)?;
/// println!("Signed at: {}ms", header.timestamp_ms);
/// ```
#[derive(Debug, Clone)]
pub struct AttestationHeader {
    /// Header schema version. Currently always `1`.
    pub version: u32,
    /// Base64-encoded Ed25519 signature over the payload hash.
    pub signature_b64: String,
    /// Hex-encoded SHA-256 payload hash: `SHA-256(body || ts_be || request_id)`.
    pub payload_hash_hex: String,
    /// Unix timestamp in milliseconds when the response was signed.
    pub timestamp_ms: u64,
    /// Hex-encoded Ed25519 public key matching the enclave's startup quote.
    pub public_key_hex: String,
}

impl AttestationHeader {
    /// Serialize to the `X-TEE-Attestation` header value string.
    ///
    /// Format: `v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>`
    pub fn to_header_value(&self) -> String {
        format!(
            "v={}; sig={}; hash={}; ts={}; key={}",
            self.version,
            self.signature_b64,
            self.payload_hash_hex,
            self.timestamp_ms,
            self.public_key_hex,
        )
    }

    /// Parse an `X-TEE-Attestation` header value string.
    ///
    /// Returns [`SdkError::SigningFailed`] if the `v` or `ts` fields cannot
    /// be parsed as integers. Unknown fields are silently ignored.
    pub fn from_header_value(value: &str) -> Result<Self, SdkError> {
        let mut version = 0u32;
        let mut sig = String::new();
        let mut hash = String::new();
        let mut ts = 0u64;
        let mut key = String::new();

        for part in value.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                match k.trim() {
                    "v" => {
                        version = v
                            .trim()
                            .parse()
                            .map_err(|_| SdkError::SigningFailed("Invalid version".into()))?;
                    }
                    "sig" => sig = v.trim().to_string(),
                    "hash" => hash = v.trim().to_string(),
                    "ts" => {
                        ts = v
                            .trim()
                            .parse()
                            .map_err(|_| SdkError::SigningFailed("Invalid timestamp".into()))?;
                    }
                    "key" => key = v.trim().to_string(),
                    _ => {}
                }
            }
        }

        Ok(Self {
            version,
            signature_b64: sig,
            payload_hash_hex: hash,
            timestamp_ms: ts,
            public_key_hex: key,
        })
    }
}

/// A response body paired with its TEE attestation header.
///
/// Used in client-side verification workflows where the raw body bytes and the
/// attestation metadata must be kept together.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::response::{AttestedResponse, AttestationHeader};
///
/// let resp = AttestedResponse {
///     body: response_bytes,
///     attestation: header,
/// };
///
/// // Verify the signature using the public key from the startup quote
/// ```
#[derive(Debug)]
pub struct AttestedResponse {
    /// The raw HTTP response body bytes.
    pub body: Vec<u8>,
    /// The parsed attestation header from `X-TEE-Attestation`.
    pub attestation: AttestationHeader,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_header_format() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = signing_key.verifying_key();

        let header = AttestationHeader {
            version: 1,
            signature_b64: "dGVzdA==".to_string(),
            payload_hash_hex: "ab".repeat(32),
            timestamp_ms: 1234567890,
            public_key_hex: hex_encode(public_key.as_bytes()),
        };

        let value = header.to_header_value();
        assert!(value.starts_with("v=1;"));
        assert!(value.contains("sig=dGVzdA=="));
        assert!(value.contains("ts=1234567890"));
    }

    #[test]
    fn attestation_header_parse_roundtrip() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = signing_key.verifying_key();

        let header = AttestationHeader {
            version: 1,
            signature_b64: "dGVzdA==".to_string(),
            payload_hash_hex: "ab".repeat(32),
            timestamp_ms: 1234567890,
            public_key_hex: hex_encode(public_key.as_bytes()),
        };

        let value = header.to_header_value();
        let parsed = AttestationHeader::from_header_value(&value).expect("should parse");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.signature_b64, "dGVzdA==");
        assert_eq!(parsed.timestamp_ms, 1234567890);
    }
}
