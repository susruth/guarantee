use crate::errors::SdkError;

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Debug, Clone)]
pub struct AttestationHeader {
    pub version: u32,
    pub signature_b64: String,
    pub payload_hash_hex: String,
    pub timestamp_ms: u64,
    pub public_key_hex: String,
}

impl AttestationHeader {
    /// Format: v=1; sig=<base64>; hash=<hex>; ts=<unix_ms>; key=<hex>
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

#[derive(Debug)]
pub struct AttestedResponse {
    pub body: Vec<u8>,
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
