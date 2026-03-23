# guarantee

TEE attestation SDK for Rust. Cryptographic proof that your code runs inside a
Trusted Execution Environment — every HTTP response carries a verifiable
signature chain from the enclave's SGX startup quote down to the response body.

## Installation

```toml
[dependencies]
guarantee = "0.1"
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

For RA-TLS support (HTTPS with embedded attestation):

```toml
[dependencies]
guarantee = { version = "0.1", features = ["ra-tls"] }
```

## Quick Start

```rust
use axum::{extract::Extension, response::Json, routing::get, Router};
use guarantee::{attest, state};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct AppData {
    request_count: u64,
}

// Declare MRENCLAVE-bound state (resets on redeploy)
state! {
    #[mrenclave]
    AppData,
}

// Every response from this handler includes X-TEE-Attestation
#[attest]
async fn hello() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "hello from TEE" }))
}

async fn attestation_info(
    Extension(state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let s = state.read().await;
    Json(s.attestation_json())
}

#[tokio::main]
async fn main() {
    let state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");

    let app = Router::new()
        .route("/hello", get(hello))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(Arc::new(RwLock::new(state))));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}
```

```bash
curl http://localhost:8080/hello
# {"message":"hello from TEE"}
# X-TEE-Attestation: v=1; sig=<base64(ed25519)>; hash=<sha256>; ts=<ms>; key=<pubkey>
```

## How It Works

1. At startup, generates an ephemeral Ed25519 keypair.
2. In SGX enclaves: writes `SHA-256(public_key)` to `/dev/attestation/user_report_data`
   and reads a DCAP quote that cryptographically binds the key to MRENCLAVE + MRSIGNER.
3. Every response signed with `#[attest]` carries:
   `X-TEE-Attestation: v=1; sig=<ed25519>; hash=<sha256(body||ts||id)>; key=<pubkey>`
4. Callers verify: startup quote (hardware) → public key → response signature.

Works without SGX hardware in dev mode (`GUARANTEE_ENCLAVE` not set).

## Features

| Feature | Description |
|---------|-------------|
| `state!` | Declare TEE state with MRENCLAVE / MRSIGNER / external tiers |
| `#[attest]` | Automatic per-response Ed25519 signing via axum handler macro |
| `#[derive(Encrypted)]` + `#[encrypt]` | AES-256-GCM field-level encryption for external databases |
| Key rotation | Automatic 90-day master key rotation with retired key fallback |
| Backup / restore | `state.backup(seal_dir, backup_dir)` / `TeeState::restore(backup_dir, seal_dir)` |
| Schema migration | Automatic schema versioning — old sealed state is migrated on load |
| RA-TLS *(feature flag)* | HTTPS with SGX quote embedded in TLS certificate |
| Inter-enclave `connect()` *(feature flag)* | RA-TLS client for calling other enclaves with MRENCLAVE pinning |
| WebSocket *(feature flag)* | Attested WebSocket connections over RA-TLS |

## Feature Flags

| Flag | Description |
|------|-------------|
| `ra-tls` | Enables `serve_ra_tls`, `guarantee::connect`, and the `ra_tls` module |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GUARANTEE_ENCLAVE=1` | Enable real SGX `/dev/attestation` calls (enclave mode) |
| `GUARANTEE_ATTEST_MODE=startup-only` | Skip per-response signatures; only produce startup quote |

## Key Hierarchy

```
OsRng
 ├─→ signing_key  (Ed25519, MRENCLAVE-scoped)
 │     └─→ X-TEE-Attestation per-response signatures
 └─→ master_key  (256-bit AES, MRSIGNER-scoped)
       └─→ derive_key(master, b"TypeName") → AES-256-GCM encryption keys
             └─→ enc:v1:k<N>:<nonce>:<ciphertext>  (stored externally)
```

Neither key is ever written to disk in plaintext. In enclave mode, sealed files
are protected by Gramine's SGX Protected Files.

## Guides

- [Getting Started](docs/pages/getting-started.mdx)
- [Architecture](docs/pages/architecture.mdx)
- [Field-Level Encryption](docs/pages/encryption.mdx)
- [Key Rotation](docs/pages/key-rotation.mdx)
- [RA-TLS](docs/pages/sdk/ra-tls.mdx)

## License

MIT
