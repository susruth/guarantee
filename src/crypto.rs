//! Field-level encryption for external storage.
//!
//! Provides AES-256-GCM encryption for individual fields and HKDF-SHA256
//! key derivation for purpose-specific keys. Encrypted fields use the
//! versioned format `enc:v1:<nonce_hex>:<ciphertext_hex>`.

use crate::errors::SdkError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const ENC_PREFIX: &str = "enc:v1:";

/// Trait for types that support field-level encryption.
///
/// Implemented by the `#[derive(Encrypted)]` macro. Fields annotated with
/// `#[encrypt]` are encrypted with AES-256-GCM; other fields are copied as-is.
pub trait Encryptable: Sized {
    /// The encrypted form of this type.
    type Encrypted;

    /// Encrypt all `#[encrypt]`-annotated fields using the given 256-bit key.
    fn encrypt(&self, key: &[u8; 32]) -> Result<Self::Encrypted, SdkError>;

    /// Decrypt all `#[encrypt]`-annotated fields and reconstruct the original type.
    fn decrypt_from(encrypted: &Self::Encrypted, key: &[u8; 32]) -> Result<Self, SdkError>;

    /// Encrypt with versioned key tagging and per-type key derivation.
    /// The `purpose` is used to derive a per-type key via HKDF.
    fn encrypt_versioned(
        &self,
        key: &[u8; 32],
        version: u32,
        purpose: &[u8],
    ) -> Result<Self::Encrypted, SdkError>;

    /// Decrypt with key version fallback. Handles both old and new encryption formats.
    fn decrypt_versioned(
        encrypted: &Self::Encrypted,
        current_key: &[u8; 32],
        current_version: u32,
        retired_keys: &[RetiredKeyEntry],
        purpose: &[u8],
    ) -> Result<Self, SdkError>;
}

/// A retired encryption key entry, kept for backward decryption after key rotation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RetiredKeyEntry {
    /// The key version number.
    pub version: u32,
    /// The 256-bit key material.
    pub key: [u8; 32],
    /// RFC3339 timestamp of when the key was retired.
    pub retired_at: String,
    /// Optional RFC3339 timestamp of when the retired key expires (after which it is purged).
    pub expires_at: Option<String>,
}

/// Encrypt a string field using AES-256-GCM.
///
/// Returns `"enc:v1:<nonce_hex>:<ciphertext_hex>"`.
/// Each call generates a unique 12-byte random nonce.
pub fn encrypt_field(plaintext: &str, key: &[u8; 32]) -> Result<String, SdkError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::CryptoError(format!("AES init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| SdkError::CryptoError(format!("Encrypt: {e}")))?;

    let nonce_hex = hex_encode(&nonce_bytes);
    let ct_hex = hex_encode(&ciphertext);

    Ok(format!("{ENC_PREFIX}{nonce_hex}:{ct_hex}"))
}

/// Decrypt a field. Input must be `"enc:v1:<nonce_hex>:<ciphertext_hex>"`.
pub fn decrypt_field(encrypted: &str, key: &[u8; 32]) -> Result<String, SdkError> {
    let stripped = encrypted
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| SdkError::CryptoError("Not an encrypted field".into()))?;

    let (nonce_hex, ct_hex) = stripped
        .split_once(':')
        .ok_or_else(|| SdkError::CryptoError("Invalid encrypted format".into()))?;

    let nonce_bytes = hex_decode(nonce_hex)?;
    let ciphertext = hex_decode(ct_hex)?;

    if nonce_bytes.len() != 12 {
        return Err(SdkError::CryptoError(format!(
            "Invalid nonce length: expected 12, got {}",
            nonce_bytes.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::CryptoError(format!("AES init: {e}")))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| SdkError::CryptoError(format!("Decrypt: {e}")))?;

    String::from_utf8(plaintext).map_err(|e| SdkError::CryptoError(format!("UTF-8: {e}")))
}

/// Derive a purpose-specific 256-bit key from a master key using HKDF-SHA256.
///
/// The same `(master_key, purpose)` pair always produces the same derived key.
/// Different purposes produce different keys.
pub fn derive_key(master_key: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut output = [0u8; 32];
    // HKDF expand with 32 bytes output is mathematically guaranteed to succeed
    // (output length <= 255 * hash length = 255 * 32 = 8160 bytes)
    hk.expand(purpose, &mut output)
        .expect("HKDF expand with 32 bytes should never fail");
    output
}

/// Encrypt a string field using AES-256-GCM with a versioned key tag.
///
/// Returns `"enc:v1:k<version>:<nonce_hex>:<ciphertext_hex>"`.
/// The key is first derived via `derive_key(master_key, purpose)` before encryption.
pub fn encrypt_field_versioned(
    plaintext: &str,
    key: &[u8; 32],
    version: u32,
    purpose: &[u8],
) -> Result<String, SdkError> {
    let derived = derive_key(key, purpose);

    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| SdkError::CryptoError(format!("AES init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| SdkError::CryptoError(format!("Encrypt: {e}")))?;

    let nonce_hex = hex_encode(&nonce_bytes);
    let ct_hex = hex_encode(&ciphertext);

    Ok(format!("{ENC_PREFIX}k{version}:{nonce_hex}:{ct_hex}"))
}

/// Decrypt a field with key version fallback. Handles both formats:
/// - Old: `"enc:v1:<nonce_hex>:<ciphertext_hex>"` (treated as version 0, uses key directly)
/// - New: `"enc:v1:k<N>:<nonce_hex>:<ciphertext_hex>"` (derives key from purpose)
///
/// For the old unversioned format, `current_key` is used directly (no derivation),
/// preserving backward compatibility with data encrypted by `encrypt_field`.
///
/// For the versioned format, the appropriate master key is located (current or retired),
/// then derived via `derive_key(master, purpose)` before decryption.
pub fn decrypt_field_versioned(
    encrypted: &str,
    current_key: &[u8; 32],
    current_version: u32,
    retired_keys: &[RetiredKeyEntry],
    purpose: &[u8],
) -> Result<String, SdkError> {
    let stripped = encrypted
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| SdkError::CryptoError("Not an encrypted field".into()))?;

    // Detect format: new versioned format starts with 'k' followed by digits.
    // Hex nonces contain only [0-9a-f], so 'k' is unambiguous.
    if stripped.starts_with('k') {
        // Versioned format: "k<N>:<nonce_hex>:<ciphertext_hex>"
        let after_k = &stripped[1..];
        let (version_str, remainder) = after_k
            .split_once(':')
            .ok_or_else(|| SdkError::CryptoError("Invalid versioned format".into()))?;
        let key_version: u32 = version_str
            .parse()
            .map_err(|_| SdkError::CryptoError("Invalid key version number".into()))?;

        // Select the right master key for this version
        let master = if key_version == current_version {
            current_key
        } else {
            &retired_keys
                .iter()
                .find(|k| k.version == key_version)
                .ok_or_else(|| {
                    SdkError::CryptoError(format!(
                        "Key version {key_version} not found (current is {current_version})"
                    ))
                })?
                .key
        };

        // Derive per-type key and decrypt
        let derived = derive_key(master, purpose);
        let (nonce_hex, ct_hex) = remainder
            .split_once(':')
            .ok_or_else(|| SdkError::CryptoError("Invalid encrypted format".into()))?;
        decrypt_raw(&derived, nonce_hex, ct_hex)
    } else {
        // Old unversioned format: "<nonce_hex>:<ciphertext_hex>" (version 0)
        // Use the key directly — old format did not use per-type derivation via this path.
        // The old encrypt_field used the already-derived key directly.
        let (nonce_hex, ct_hex) = stripped
            .split_once(':')
            .ok_or_else(|| SdkError::CryptoError("Invalid encrypted format".into()))?;

        // Try current key first (for version 0 compatibility)
        match decrypt_raw(current_key, nonce_hex, ct_hex) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => {
                // Try retired keys (version 0)
                for retired in retired_keys {
                    if let Ok(plaintext) = decrypt_raw(&retired.key, nonce_hex, ct_hex) {
                        return Ok(plaintext);
                    }
                }
                Err(SdkError::CryptoError(
                    "Decryption failed: no matching key for unversioned format".into(),
                ))
            }
        }
    }
}

/// Raw AES-256-GCM decryption from hex-encoded nonce and ciphertext.
fn decrypt_raw(key: &[u8; 32], nonce_hex: &str, ct_hex: &str) -> Result<String, SdkError> {
    let nonce_bytes = hex_decode(nonce_hex)?;
    let ciphertext = hex_decode(ct_hex)?;

    if nonce_bytes.len() != 12 {
        return Err(SdkError::CryptoError(format!(
            "Invalid nonce length: expected 12, got {}",
            nonce_bytes.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::CryptoError(format!("AES init: {e}")))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| SdkError::CryptoError(format!("Decrypt: {e}")))?;

    String::from_utf8(plaintext).map_err(|e| SdkError::CryptoError(format!("UTF-8: {e}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, SdkError> {
    if hex.len() % 2 != 0 {
        return Err(SdkError::CryptoError(
            "Hex decode: odd-length string".into(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| SdkError::CryptoError(format!("Hex decode: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_field_roundtrip() {
        let key = [42u8; 32];
        let plaintext = "hello world";
        let encrypted = encrypt_field(plaintext, &key).expect("encrypt");
        assert!(encrypted.starts_with("enc:v1:"));
        let decrypted = decrypt_field(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces_produce_different_ciphertexts() {
        let key = [42u8; 32];
        let e1 = encrypt_field("same", &key).expect("encrypt 1");
        let e2 = encrypt_field("same", &key).expect("encrypt 2");
        assert_ne!(e1, e2);
    }

    #[test]
    fn wrong_key_fails() {
        let encrypted = encrypt_field("secret", &[1u8; 32]).expect("encrypt");
        assert!(decrypt_field(&encrypted, &[2u8; 32]).is_err());
    }

    #[test]
    fn derive_key_deterministic() {
        let master = [99u8; 32];
        let k1 = derive_key(&master, b"purpose-a");
        let k2 = derive_key(&master, b"purpose-a");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_purposes() {
        let master = [99u8; 32];
        let k1 = derive_key(&master, b"a");
        let k2 = derive_key(&master, b"b");
        assert_ne!(k1, k2);
    }

    #[test]
    fn decrypt_invalid_prefix_fails() {
        assert!(decrypt_field("not-encrypted", &[0u8; 32]).is_err());
    }

    #[test]
    fn decrypt_invalid_format_fails() {
        assert!(decrypt_field("enc:v1:no-colon-here", &[0u8; 32]).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = [7u8; 32];
        let encrypted = encrypt_field("", &key).expect("encrypt");
        let decrypted = decrypt_field(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, "");
    }

    // ── Versioned encryption tests ───────────────────────────────────────

    #[test]
    fn encrypt_versioned_includes_key_version() {
        let key = [42u8; 32];
        let encrypted = encrypt_field_versioned("hello", &key, 3, b"test").expect("encrypt");
        assert!(encrypted.starts_with("enc:v1:k3:"));
    }

    #[test]
    fn decrypt_versioned_roundtrip() {
        let key = [42u8; 32];
        let encrypted =
            encrypt_field_versioned("secret", &key, 1, b"purpose").expect("encrypt");
        let decrypted =
            decrypt_field_versioned(&encrypted, &key, 1, &[], b"purpose").expect("decrypt");
        assert_eq!(decrypted, "secret");
    }

    #[test]
    fn decrypt_versioned_falls_back_to_retired_key() {
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];
        let encrypted =
            encrypt_field_versioned("secret", &old_key, 1, b"purpose").expect("encrypt");

        let retired = vec![RetiredKeyEntry {
            version: 1,
            key: old_key,
            retired_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
        }];

        let decrypted =
            decrypt_field_versioned(&encrypted, &new_key, 2, &retired, b"purpose")
                .expect("decrypt");
        assert_eq!(decrypted, "secret");
    }

    #[test]
    fn decrypt_old_unversioned_format_as_version_0() {
        let key = [42u8; 32];
        let old_encrypted = encrypt_field("hello", &key).expect("encrypt");

        // Should parse as version 0 (old format) and decrypt with the key directly
        let decrypted =
            decrypt_field_versioned(&old_encrypted, &key, 0, &[], b"").expect("decrypt");
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn wrong_version_key_fails() {
        let key = [42u8; 32];
        let encrypted =
            encrypt_field_versioned("secret", &key, 5, b"purpose").expect("encrypt");
        let result =
            decrypt_field_versioned(&encrypted, &[99u8; 32], 6, &[], b"purpose");
        assert!(result.is_err());
    }

    #[test]
    fn versioned_different_purposes_not_interchangeable() {
        let key = [42u8; 32];
        let encrypted =
            encrypt_field_versioned("secret", &key, 1, b"purpose-a").expect("encrypt");
        let result =
            decrypt_field_versioned(&encrypted, &key, 1, &[], b"purpose-b");
        assert!(result.is_err());
    }

    #[test]
    fn versioned_empty_plaintext_roundtrip() {
        let key = [7u8; 32];
        let encrypted =
            encrypt_field_versioned("", &key, 1, b"test").expect("encrypt");
        let decrypted =
            decrypt_field_versioned(&encrypted, &key, 1, &[], b"test").expect("decrypt");
        assert_eq!(decrypted, "");
    }
}
