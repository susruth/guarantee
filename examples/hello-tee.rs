// Service configuration (heap_size, max_threads, allowed_hosts, attest_mode)
// is managed via the GuaranTEE API or dashboard — no guarantee.toml needed.
// Users only need the #[attest] macro on their handlers.

use axum::{extract::Extension, response::Json, routing::get, Router};
use guarantee::{attest, EnclaveAttestor};
use std::sync::Arc;

#[attest]
async fn hello() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "hello from TEE" }))
}

async fn attestation_info(
    Extension(attestor): Extension<Arc<EnclaveAttestor>>,
) -> Json<serde_json::Value> {
    match attestor.startup_attestation_json() {
        Ok(json) => Json(json),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let attestor = EnclaveAttestor::initialize()
        .await
        .expect("Failed to initialize EnclaveAttestor");

    println!("Starting hello-tee on port {port}");

    let app = Router::new()
        .route("/hello", get(hello))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(attestor));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
