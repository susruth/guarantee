//! Field-level encryption for external storage.
//!
//! Provides AES-256-GCM encryption for individual struct fields and
//! HKDF-SHA256 key derivation for purpose-specific sub-keys. Use this module
//! when you need to store sensitive data in an external database or cache
//! (PostgreSQL, Redis, etc.) and want the plaintext to never leave the enclave
//! unencrypted.
//!
//! ## Encrypted field format
//!
//! Unversioned (legacy):
//! ```text
//! enc:v1:<nonce_hex>:<ciphertext_hex>
//! ```
//!
//! Versioned (recommended):
//! ```text
//! enc:v1:k<version>:<nonce_hex>:<ciphertext_hex>
//! ```
//!
//! Each call to [`encrypt_field`] or [`encrypt_field_versioned`] generates a
//! fresh 12-byte random nonce, so encrypting the same plaintext twice always
//! produces different ciphertexts.
//!
//! ## Usage with `#[derive(Encrypted)]`
//!
//! The easiest way to encrypt structs is via the `Encrypted` derive macro
//! provided by the `guarantee-macros` crate:
//!
//! ```rust,ignore
//! use guarantee::Encrypted;
//!
//! #[derive(Encrypted, serde::Serialize, serde::Deserialize)]
//! struct UserRecord {
//!     pub id: String,
//!     #[encrypt]
//!     pub email: String,
//!     #[encrypt]
//!     pub api_key: String,
//! }
//! ```
//!
//! The macro generates a `UserRecordEncrypted` type and implements
//! [`Encryptable`] for `UserRecord`.

use crate::errors::SdkError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const ENC_PREFIX: &str = "enc:v1:";

/// Implemented by types that support field-level AES-256-GCM encryption.
///
/// Typically derived automatically with `#[derive(Encrypted)]`. Fields
/// annotated with `#[encrypt]` are encrypted; all other fields are copied
/// as-is into the generated `*Encrypted` type.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::{Encryptable, Encrypted};
///
/// #[derive(Encrypted, serde::Serialize, serde::Deserialize)]
/// struct Secret {
///     pub id: u64,
///     #[encrypt]
///     pub token: String,
/// }
///
/// let secret = Secret { id: 1, token: "super-secret".into() };
/// let key = [0u8; 32]; // use a real key in production
///
/// let encrypted = secret.encrypt(&key)?;
/// let recovered = Secret::decrypt_from(&encrypted, &key)?;
/// assert_eq!(recovered.token, "super-secret");
/// ```
pub trait Encryptable: Sized {
    /// The generated encrypted form of this type (e.g., `SecretEncrypted`).
    type Encrypted;

    /// Encrypt all `#[encrypt]`-annotated fields using the given 256-bit key.
    ///
    /// Non-annotated fields are copied verbatim into the `Encrypted` variant.
    fn encrypt(&self, key: &[u8; 32]) -> Result<Self::Encrypted, SdkError>;

    /// Decrypt all `#[encrypt]`-annotated fields and reconstruct the original type.
    ///
    /// Returns an error if any field cannot be decrypted (wrong key, corrupted
    /// ciphertext, or malformed `enc:v1:...` payload).
    fn decrypt_from(encrypted: &Self::Encrypted, key: &[u8; 32]) -> Result<Self, SdkError>;

    /// Encrypt with versioned key tagging and per-type key derivation.
    ///
    /// The `purpose` byte slice is used to derive a per-type sub-key via
    /// [`derive_key`]. Using a different `purpose` per struct type ensures
    /// that a key leaked for one type cannot be used to decrypt another.
    /// The `version` is embedded in the ciphertext tag so that
    /// [`decrypt_versioned`](Self::decrypt_versioned) can select the correct
    /// retired key after rotation.
    fn encrypt_versioned(
        &self,
        key: &[u8; 32],
        version: u32,
        purpose: &[u8],
    ) -> Result<Self::Encrypted, SdkError>;

    /// Decrypt with key version fallback.
    ///
    /// Handles both the old unversioned format (`enc:v1:<nonce>:<ct>`) and the
    /// new versioned format (`enc:v1:k<N>:<nonce>:<ct>`). For the versioned
    /// format, looks up the master key by version in `current_key` (if version
    /// matches `current_version`) or `retired_keys`, then derives the per-type
    /// sub-key with [`derive_key`] before decrypting.
    fn decrypt_versioned(
        encrypted: &Self::Encrypted,
        current_key: &[u8; 32],
        current_version: u32,
        retired_keys: &[RetiredKeyEntry],
        purpose: &[u8],
    ) -> Result<Self, SdkError>;
}

/// A retired encryption key entry, kept for backward decryption after key rotation.
///
/// When a master key is rotated, the old key is moved into the retired keys list
/// so that data encrypted with the old key can still be decrypted. The
/// `expires_at` field controls when the retired key is purged; after expiry,
/// data encrypted with that key can no longer be decrypted.
///
/// Retired key entries are stored in sealed storage (MRSIGNER scope) so they
/// are available across enclave redeployments but never leave the enclave
/// unencrypted.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::RetiredKeyEntry;
///
/// let entry = RetiredKeyEntry {
///     version: 1,
///     key: old_master_key,
///     retired_at: "2026-01-01T00:00:00Z".to_string(),
///     expires_at: Some("2027-01-01T00:00:00Z".to_string()),
/// };
/// ```
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RetiredKeyEntry {
    /// The key version number that was active when this key was in use.
    pub version: u32,
    /// The 256-bit AES master key material.
    pub key: [u8; 32],
    /// RFC 3339 timestamp of when this key was retired.
    pub retired_at: String,
    /// Optional RFC 3339 timestamp after which this retired key may be purged.
    ///
    /// Once a key expires, any data that was encrypted with it becomes
    /// permanently unreadable. Set this to enforce data-deletion policies.
    pub expires_at: Option<String>,
}

/// Encrypt a string field using AES-256-GCM.
///
/// Returns a string in the format `"enc:v1:<nonce_hex>:<ciphertext_hex>"`.
/// A fresh 12-byte random nonce is generated on every call, so encrypting the
/// same plaintext twice produces different ciphertexts.
///
/// This function uses the key directly without any additional derivation. For
/// new code, prefer [`encrypt_field_versioned`] which adds key version tracking
/// and per-type derivation.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::crypto::{encrypt_field, decrypt_field};
///
/// let key = [42u8; 32];
/// let encrypted = encrypt_field("my secret", &key)?;
/// assert!(encrypted.starts_with("enc:v1:"));
///
/// let plaintext = decrypt_field(&encrypted, &key)?;
/// assert_eq!(plaintext, "my secret");
/// ```
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

/// Decrypt a field that was encrypted with [`encrypt_field`].
///
/// The input must be in the format `"enc:v1:<nonce_hex>:<ciphertext_hex>"`.
/// Returns [`SdkError::CryptoError`] if the prefix is missing, the format is
/// invalid, the key is wrong, or the ciphertext is corrupted.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::crypto::{encrypt_field, decrypt_field};
///
/// let key = [42u8; 32];
/// let enc = encrypt_field("hello", &key)?;
/// let dec = decrypt_field(&enc, &key)?;
/// assert_eq!(dec, "hello");
/// ```
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
/// Different `purpose` values produce cryptographically independent keys, so a
/// compromise of one derived key does not expose others.
///
/// Use a stable, human-readable byte string as the purpose — typically the
/// struct or field name:
///
/// ```rust,ignore
/// use guarantee::crypto::derive_key;
///
/// let master = [0u8; 32]; // loaded from sealed storage
/// let email_key = derive_key(&master, b"UserRecord::email");
/// let token_key = derive_key(&master, b"UserRecord::token");
/// // email_key != token_key
/// ```
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
/// Returns a string in the format `"enc:v1:k<version>:<nonce_hex>:<ciphertext_hex>"`.
/// The key is first derived via [`derive_key`]`(master_key, purpose)` before
/// encryption, providing per-type key isolation.
///
/// The embedded `k<version>` tag allows [`decrypt_field_versioned`] to
/// locate the correct key after a rotation event.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::crypto::{encrypt_field_versioned, decrypt_field_versioned};
///
/// let master = [42u8; 32];
/// let enc = encrypt_field_versioned("secret", &master, 1, b"UserRecord::email")?;
/// assert!(enc.starts_with("enc:v1:k1:"));
///
/// let plain = decrypt_field_versioned(&enc, &master, 1, &[], b"UserRecord::email")?;
/// assert_eq!(plain, "secret");
/// ```
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

/// Decrypt a field with key version fallback.
///
/// Handles both encryption formats produced by this crate:
///
/// - **Old unversioned** (`"enc:v1:<nonce>:<ct>"`): treated as version 0.
///   `current_key` is tried first, then each entry in `retired_keys`.
///   No key derivation is applied (the key was already derived before being
///   passed to the old `encrypt_field`).
///
/// - **New versioned** (`"enc:v1:k<N>:<nonce>:<ct>"`): the version `N` is
///   extracted, the matching master key is located (from `current_key` if
///   `N == current_version`, otherwise from `retired_keys`), and the per-type
///   sub-key is derived via [`derive_key`]`(master, purpose)` before decrypting.
///
/// Returns [`SdkError::CryptoError`] if:
/// - The ciphertext format is invalid
/// - The key version `N` is not found in `current_version` or `retired_keys`
/// - Decryption fails (wrong key, corrupted ciphertext)
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::crypto::{encrypt_field_versioned, decrypt_field_versioned, RetiredKeyEntry};
///
/// let old_key = [1u8; 32];
/// let new_key = [2u8; 32];
///
/// // Data was encrypted with the old key at version 1
/// let enc = encrypt_field_versioned("hello", &old_key, 1, b"purpose")?;
///
/// // After rotation, old_key is now a retired key
/// let retired = vec![RetiredKeyEntry {
///     version: 1,
///     key: old_key,
///     retired_at: "2026-01-01T00:00:00Z".to_string(),
///     expires_at: None,
/// }];
///
/// // Decryption succeeds by falling back to the retired key
/// let plain = decrypt_field_versioned(&enc, &new_key, 2, &retired, b"purpose")?;
/// assert_eq!(plain, "hello");
/// ```
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
