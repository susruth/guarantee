//! Re-exports the `#[attest]` proc macro from `guarantee-macros`.
//!
//! The `#[attest]` attribute macro wraps an axum handler function so that
//! every HTTP response automatically includes the `X-TEE-Attestation` header.
//!
//! See the crate-level documentation for a full usage example.

/// Automatically sign every HTTP response with the enclave's attestation key.
///
/// Apply this attribute to any axum handler that returns `impl IntoResponse`.
/// The macro:
///
/// 1. Injects `Extension(state): Extension<Arc<RwLock<TeeState>>>` as an extractor
/// 2. Runs the original handler body
/// 3. Serializes the response body
/// 4. Calls the enclave's signing key to produce an [`AttestationHeader`](crate::AttestationHeader)
/// 5. Inserts `X-TEE-Attestation: v=1; sig=...; hash=...; ts=...; key=...` into the response
///
/// The `TeeState` must be registered as an axum [`Extension`](axum::extract::Extension) layer.
///
/// # Example
///
/// ```rust,ignore
/// use axum::response::Json;
/// use guarantee::attest;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct PriceResponse { price: f64 }
///
/// #[attest]
/// async fn get_price() -> Json<PriceResponse> {
///     Json(PriceResponse { price: 42_000.0 })
/// }
/// // Every response to GET /price will include X-TEE-Attestation.
/// ```
pub use guarantee_macros::attest;
