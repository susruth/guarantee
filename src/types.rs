//! Core TEE types used by the SDK.
//! These are self-contained — the SDK has no dependency on the internal domain crate.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use std::fmt;

/// 32-byte SHA-256 measurement of the enclave contents (MRENCLAVE).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MrEnclave([u8; 32]);

impl MrEnclave {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MrEnclave {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MrEnclave({})", self)
    }
}

impl fmt::Display for MrEnclave {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// 32-byte hash of the enclave signing key (MRSIGNER).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MrSigner([u8; 32]);

impl MrSigner {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MrSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MrSigner({})", self)
    }
}

impl fmt::Display for MrSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// The SGX quote produced at enclave startup, binding measurements to the
/// enclave's ephemeral attestation public key.
#[derive(Clone, Debug)]
pub struct StartupQuote {
    pub raw_quote: Vec<u8>,
    pub mr_enclave: MrEnclave,
    pub mr_signer: MrSigner,
    pub attested_public_key: VerifyingKey,
    pub produced_at: DateTime<Utc>,
}
