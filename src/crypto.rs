//! Field-level encryption for external storage.
//!
//! Provides AES-256-GCM encryption for individual fields and HKDF-SHA256
//! key derivation for purpose-specific keys. Encrypted fields use the
//! versioned format `enc:v1:<nonce_hex>:<ciphertext_hex>`.

use crate::errors::SdkError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

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
}
