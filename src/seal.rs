//! Sealing and unsealing of TEE state for persistent storage.
//!
//! SGX "sealing" encrypts data so that only a specific enclave (or family of
//! enclaves) can decrypt it. This module abstracts over two backends:
//!
//! - **Enclave mode** (`GUARANTEE_ENCLAVE=1`): writes and reads raw bytes.
//!   Gramine's [Protected Files] feature intercepts the I/O at the OS layer and
//!   applies SGX sealing transparently. The file at `path` must be listed under
//!   `sgx.protected_files` (MRENCLAVE) or `sgx.protected_mrsigner_files`
//!   (MRSIGNER) in the Gramine manifest.
//!
//! - **Dev mode** (default): writes a header-prefixed plain file. The header
//!   records which [`SealMode`] was used so that mode mismatches are detected
//!   on read. **Not cryptographically secure** — for development and CI only.
//!
//! [Protected Files]: https://gramine.readthedocs.io/en/stable/manifest-syntax.html#protected-files

use crate::errors::SdkError;
use std::path::Path;

/// Determines which SGX measurement is used as the sealing key.
///
/// SGX supports two distinct sealing policies. Choose based on whether you need
/// state to survive a redeploy (MRSIGNER) or to be wiped on every new binary
/// (MRENCLAVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealMode {
    /// Sealed with MRENCLAVE.
    ///
    /// Only the exact same compiled binary can unseal this data. Any change to
    /// the enclave source code, compiler flags, or dependencies produces a
    /// different MRENCLAVE and renders this data permanently inaccessible.
    ///
    /// Use this for ephemeral per-deployment secrets such as session keys.
    MrEnclave,

    /// Sealed with MRSIGNER.
    ///
    /// Any binary signed by the same enclave signing key can unseal this data,
    /// regardless of the binary's content. State persists across redeployments
    /// and upgrades as long as the signing key is unchanged.
    ///
    /// Use this for long-lived secrets such as master encryption keys or user
    /// data that must survive rolling deployments.
    MrSigner,
}

/// Seal `data` to a file at `path` using the given [`SealMode`].
///
/// In enclave mode (`GUARANTEE_ENCLAVE=1`), writes `data` as raw bytes.
/// Gramine Protected Files supply the encryption transparently — the file must
/// be declared in the Gramine manifest under the appropriate protected-files key.
///
/// In dev mode, writes a human-readable header followed by the raw bytes. The
/// file is **not encrypted** and should not be used to protect real secrets.
///
/// Parent directories are created automatically if they do not exist.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::seal::{seal_to_file, unseal_from_file, SealMode};
/// use std::path::Path;
///
/// let data = serde_json::to_vec(&my_state)?;
/// seal_to_file(&data, Path::new("./sealed/state.bin"), SealMode::MrEnclave)?;
/// ```
pub fn seal_to_file(data: &[u8], path: &Path, mode: SealMode) -> Result<(), SdkError> {
    if is_enclave_mode() {
        seal_sgx(data, path, mode)
    } else {
        seal_dev(data, path, mode)
    }
}

/// Unseal data from a file previously written by [`seal_to_file`].
///
/// In enclave mode, reads the raw bytes directly; Gramine Protected Files
/// handle decryption at the OS layer.
///
/// In dev mode, strips the mode header and returns the remaining bytes. Returns
/// [`SdkError::SealError`] if the stored mode header does not match `mode` (for
/// example, trying to unseal an MRENCLAVE-sealed file with `SealMode::MrSigner`).
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::seal::{unseal_from_file, SealMode};
/// use std::path::Path;
///
/// let raw = unseal_from_file(Path::new("./sealed/state.bin"), SealMode::MrEnclave)?;
/// let my_state: MyState = serde_json::from_slice(&raw)?;
/// ```
pub fn unseal_from_file(path: &Path, mode: SealMode) -> Result<Vec<u8>, SdkError> {
    if is_enclave_mode() {
        unseal_sgx(path, mode)
    } else {
        unseal_dev(path, mode)
    }
}

fn is_enclave_mode() -> bool {
    std::env::var("GUARANTEE_ENCLAVE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

// Dev mode: simple file I/O with a header indicating seal mode.
// NOT cryptographically secure -- for development and testing only.
fn seal_dev(data: &[u8], path: &Path, mode: SealMode) -> Result<(), SdkError> {
    let header: &[u8] = match mode {
        SealMode::MrEnclave => b"SEAL_MRENCLAVE_DEV\n",
        SealMode::MrSigner => b"SEAL_MRSIGNER_DEV\n",
    };
    let mut sealed = header.to_vec();
    sealed.extend_from_slice(data);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SdkError::SealError(format!("Create dir: {e}")))?;
    }
    std::fs::write(path, &sealed)
        .map_err(|e| SdkError::SealError(format!("Write sealed: {e}")))?;
    tracing::debug!(path = %path.display(), ?mode, "Sealed data (dev mode)");
    Ok(())
}

fn unseal_dev(path: &Path, mode: SealMode) -> Result<Vec<u8>, SdkError> {
    let sealed = std::fs::read(path)
        .map_err(|e| SdkError::SealError(format!("Read sealed: {e}")))?;

    let expected_header: &[u8] = match mode {
        SealMode::MrEnclave => b"SEAL_MRENCLAVE_DEV\n",
        SealMode::MrSigner => b"SEAL_MRSIGNER_DEV\n",
    };

    if !sealed.starts_with(expected_header) {
        return Err(SdkError::SealError(format!(
            "Seal mode mismatch: expected {:?}",
            mode
        )));
    }

    let data = sealed[expected_header.len()..].to_vec();
    tracing::debug!(path = %path.display(), ?mode, "Unsealed data (dev mode)");
    Ok(data)
}

// SGX mode: write/read raw bytes — Gramine Protected Files handle encryption transparently.
// The file at `path` must be listed under `sgx.protected_files` or `sgx.protected_mrsigner_files`
// in the Gramine manifest so that Gramine intercepts the I/O and applies SGX sealing.
fn seal_sgx(data: &[u8], path: &Path, _mode: SealMode) -> Result<(), SdkError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SdkError::SealError(format!("Create dir: {e}")))?;
    }
    std::fs::write(path, data)
        .map_err(|e| SdkError::SealError(format!("Write sealed: {e}")))?;
    tracing::debug!(path = %path.display(), "Sealed data (enclave mode — Gramine PF)");
    Ok(())
}

fn unseal_sgx(path: &Path, _mode: SealMode) -> Result<Vec<u8>, SdkError> {
    let data = std::fs::read(path)
        .map_err(|e| SdkError::SealError(format!("Read sealed: {e}")))?;
    tracing::debug!(path = %path.display(), "Unsealed data (enclave mode — Gramine PF)");
    Ok(data)
}

/// Sign a response body using the enclave's ephemeral signing key.
///
/// Called internally by [`TeeState::sign_response`] — the signing key itself
/// is never exposed to user code. The payload hash is computed as:
///
/// ```text
/// SHA-256(body || timestamp_ms_big_endian || request_id_utf8)
/// ```
///
/// The resulting [`AttestationHeader`](crate::AttestationHeader) is attached to
/// the HTTP response as the `X-TEE-Attestation` header by the `#[attest]` macro.
pub fn sign_with_enclave_key(
    signing_key: &ed25519_dalek::SigningKey,
    body: &[u8],
    request_id: &str,
) -> crate::AttestationHeader {
    use base64::Engine;
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use crate::response::hex_encode;

    let timestamp_ms = chrono::Utc::now().timestamp_millis() as u64;

    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.update(timestamp_ms.to_be_bytes());
    hasher.update(request_id.as_bytes());
    let payload_hash: [u8; 32] = hasher.finalize().into();

    let signature = signing_key.sign(&payload_hash);

    crate::AttestationHeader {
        version: 1,
        signature_b64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        payload_hash_hex: hex_encode(&payload_hash),
        timestamp_ms,
        public_key_hex: hex_encode(signing_key.verifying_key().as_bytes()),
    }
}

/// Serde helper for serializing and deserializing `ed25519_dalek::SigningKey` as raw bytes.
///
/// `SigningKey` does not implement `serde::Serialize`/`Deserialize` by default.
/// Use this module with `#[serde(with = "signing_key_serde")]` to persist
/// signing keys in sealed storage.
///
/// # Example
///
/// ```rust,ignore
/// use guarantee::seal::signing_key_serde;
///
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct SealedKeys {
///     #[serde(with = "signing_key_serde")]
///     pub master_signing_key: ed25519_dalek::SigningKey,
/// }
/// ```
pub mod signing_key_serde {
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a `SigningKey` as its 32-byte little-endian representation.
    pub fn serialize<S: Serializer>(key: &SigningKey, s: S) -> Result<S::Ok, S::Error> {
        key.to_bytes().serialize(s)
    }

    /// Deserialize a `SigningKey` from its 32-byte little-endian representation.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SigningKey, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip_mrenclave() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let data = b"hello enclave";

        seal_to_file(data, &path, SealMode::MrEnclave).expect("seal");
        let recovered = unseal_from_file(&path, SealMode::MrEnclave).expect("unseal");
        assert_eq!(recovered, data);
    }

    #[test]
    fn seal_unseal_roundtrip_mrsigner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let data = b"hello signer";

        seal_to_file(data, &path, SealMode::MrSigner).expect("seal");
        let recovered = unseal_from_file(&path, SealMode::MrSigner).expect("unseal");
        assert_eq!(recovered, data);
    }

    #[test]
    fn unseal_wrong_mode_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let data = b"secret";

        seal_to_file(data, &path, SealMode::MrEnclave).expect("seal");
        let result = unseal_from_file(&path, SealMode::MrSigner);
        assert!(result.is_err());
    }

    #[test]
    fn unseal_missing_file_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent.sealed");
        let result = unseal_from_file(&path, SealMode::MrEnclave);
        assert!(result.is_err());
    }

    #[test]
    fn signing_key_serde_roundtrip() {
        use rand::rngs::OsRng;

        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let serialized = serde_json::to_vec(&SigningKeyWrapper { key: key.clone() })
            .expect("serialize");
        let deserialized: SigningKeyWrapper =
            serde_json::from_slice(&serialized).expect("deserialize");
        assert_eq!(key.to_bytes(), deserialized.key.to_bytes());
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct SigningKeyWrapper {
        #[serde(with = "super::signing_key_serde")]
        key: ed25519_dalek::SigningKey,
    }

    // ── SGX mode unit tests ───────────────────────────────────────────────────
    // These call seal_sgx / unseal_sgx directly (bypassing the enclave-mode env
    // var) so they run in normal CI without SGX hardware.  The invariant being
    // tested is that the raw byte representation is stored with no header prefix;
    // Gramine Protected Files supply the encryption transparently at the OS layer.

    #[test]
    fn seal_sgx_writes_raw_data_no_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let data = b"test data";

        seal_sgx(data, &path, SealMode::MrEnclave).expect("seal_sgx");

        let read_back = std::fs::read(&path).expect("read back");
        // Enclave mode must write raw bytes — no header prefix.
        assert_eq!(read_back, data);
    }

    #[test]
    fn unseal_sgx_reads_raw_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.sealed");
        let raw = b"raw json data";
        std::fs::write(&path, raw).expect("write");

        let recovered = unseal_sgx(&path, SealMode::MrEnclave).expect("unseal_sgx");
        assert_eq!(recovered, raw);
    }

    #[test]
    fn seal_unseal_sgx_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("roundtrip.sealed");
        let data = b"enclave state payload";

        seal_sgx(data, &path, SealMode::MrEnclave).expect("seal_sgx");
        let recovered = unseal_sgx(&path, SealMode::MrEnclave).expect("unseal_sgx");
        assert_eq!(recovered, data);
    }

    #[test]
    fn seal_sgx_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("deep").join("test.sealed");
        let data = b"nested payload";

        seal_sgx(data, &path, SealMode::MrSigner).expect("seal_sgx with nested path");
        assert!(path.exists());
        let read_back = std::fs::read(&path).expect("read back");
        assert_eq!(read_back, data);
    }
}
