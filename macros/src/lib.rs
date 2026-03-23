use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Transforms an axum handler to automatically sign responses with TEE attestation.
///
/// The macro:
/// 1. Extracts `Arc<EnclaveAttestor>` from axum Extension
/// 2. Generates a request ID
/// 3. Runs the original handler
/// 4. Signs the response body
/// 5. Attaches X-TEE-Attestation and X-TEE-Verified headers
#[proc_macro_attribute]
pub fn attest(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_vis = &input_fn.vis;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_body = &input_fn.block;
    let fn_attrs = &input_fn.attrs;

    let expanded = quote! {
        #(#fn_attrs)*
        #fn_vis async fn #fn_name(
            ::axum::extract::Extension(attestor): ::axum::extract::Extension<::std::sync::Arc<::guarantee::EnclaveAttestor>>,
            #fn_inputs
        ) -> impl ::axum::response::IntoResponse {
            use ::axum::response::IntoResponse;
            use ::axum::http::header::HeaderValue;

            // Generate request ID
            let request_id = ::uuid::Uuid::new_v4().to_string();

            // Execute original handler
            let inner_response = {
                #fn_body
            };

            // Convert to axum response
            let response = inner_response.into_response();
            let (mut parts, body) = response.into_parts();

            // Read body bytes — return 500 if body cannot be read
            let body_bytes = match ::axum::body::to_bytes(body, usize::MAX).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    let error_response = ::axum::response::Response::builder()
                        .status(::axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(::axum::body::Body::from(
                            r#"{"error":{"code":"body_read_failed","message":"Failed to read response body for attestation"}}"#
                        ))
                        .expect("failed to build error response");
                    return error_response.into_response();
                }
            };

            // Sign the response
            let header = attestor.sign_response(&body_bytes, &request_id);

            // Insert attestation headers
            if let Ok(val) = HeaderValue::from_str(&header.to_header_value()) {
                parts.headers.insert("X-TEE-Attestation", val);
            }
            if let Ok(val) = HeaderValue::from_str("true") {
                parts.headers.insert("X-TEE-Verified", val);
            }
            if let Ok(val) = HeaderValue::from_str(&request_id) {
                parts.headers.insert("X-TEE-Request-Id", val);
            }

            ::axum::response::Response::from_parts(parts, ::axum::body::Body::from(body_bytes))
        }
    };

    TokenStream::from(expanded)
}
