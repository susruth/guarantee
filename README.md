# guarantee

TEE attestation SDK for Rust. Cryptographic proof that your code runs in a Trusted Execution Environment.

## Quick Start

```toml
[dependencies]
guarantee = "0.1.1"
```

```rust
use guarantee::{attest, EnclaveAttestor};

#[attest]
async fn my_handler() -> Json<MyResponse> {
    // Your business logic — attestation is automatic
}

#[tokio::main]
async fn main() {
    let attestor = EnclaveAttestor::initialize().await.unwrap();

    let app = Router::new()
        .route("/api", get(my_handler))
        .layer(Extension(attestor));

    // Every response includes X-TEE-Attestation header
}
```

## How it works

1. At startup, generates an ephemeral Ed25519 keypair
2. In SGX enclaves: gets an attestation quote binding the key to the enclave measurement
3. Every response is signed with `X-TEE-Attestation: v=1; sig=<ed25519>; hash=<sha256>; key=<pubkey>`
4. Callers verify the signature chain: startup quote -> public key -> response signature

Works in dev mode without SGX hardware (`GUARANTEE_ENCLAVE` not set).

## License

MIT
