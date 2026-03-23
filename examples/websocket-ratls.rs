//! # WebSocket Over RA-TLS
//!
//! A real-time attested data stream using WebSocket over RA-TLS.
//! The TLS handshake verifies the SGX attestation quote — by the time
//! the WebSocket connection is established, the client has cryptographic
//! proof they're talking to a genuine enclave.
//!
//! No per-message signing overhead. The entire channel is attested.
//!
//! ## Run the server
//!
//! ```bash
//! cargo run --example websocket-ratls --features ra-tls
//! ```
//!
//! ## Connect with wscat (dev mode — self-signed cert)
//!
//! ```bash
//! # HTTP WebSocket (dev mode, no TLS)
//! wscat -c ws://localhost:8080/ws
//!
//! # Send a message
//! > {"type": "subscribe", "channel": "prices"}
//! ```
//!
//! ## Connect with a Rust client (RA-TLS verified)
//!
//! ```rust,ignore
//! let conn = guarantee::connect("https://localhost:8443")
//!     .allow_dev_mode(true)
//!     .build()?;
//! // Use tokio-tungstenite with the RA-TLS verified connection
//! ```

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::Extension,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use guarantee::{attest, state};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Tracks connected clients and stream statistics.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct StreamStats {
    total_connections: u64,
    total_messages_sent: u64,
    active_subscriptions: u64,
}

/// Persistent stream configuration.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct StreamConfig {
    max_clients: u32,
    price_update_interval_ms: u64,
}

state! {
    #[mrenclave]
    StreamStats,

    #[mrsigner]
    StreamConfig,
}

// ---------------------------------------------------------------------------
// Price data
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
struct PriceUpdate {
    symbol: String,
    price: f64,
    timestamp: String,
    source: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "subscribe")]
    Subscribe { channel: String },
    #[serde(rename = "unsubscribe")]
    Unsubscribe { channel: String },
    #[serde(rename = "ping")]
    Ping,
}

#[derive(Serialize)]
struct ServerMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

// ---------------------------------------------------------------------------
// WebSocket handler
// ---------------------------------------------------------------------------

/// GET /ws — WebSocket upgrade.
/// Over RA-TLS, the connection is attested at the TLS layer.
async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(tee_state): Extension<Arc<RwLock<TeeState>>>,
    Extension(price_tx): Extension<broadcast::Sender<PriceUpdate>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, tee_state, price_tx))
}

async fn handle_socket(
    mut socket: WebSocket,
    tee_state: Arc<RwLock<TeeState>>,
    price_tx: broadcast::Sender<PriceUpdate>,
) {
    // Track connection
    {
        let mut state = tee_state.write().await;
        state.enclave_mut().stream_stats.total_connections += 1;
    }

    // Send welcome message
    let welcome = ServerMessage {
        msg_type: "connected".into(),
        channel: None,
        data: None,
        message: Some("Connected to attested WebSocket stream. Send {\"type\":\"subscribe\",\"channel\":\"prices\"} to start.".into()),
    };
    if let Ok(json) = serde_json::to_string(&welcome) {
        let _ = socket.send(Message::Text(json.into())).await;
    }

    let mut subscriptions: HashMap<String, bool> = HashMap::new();
    let mut price_rx = price_tx.subscribe();

    loop {
        tokio::select! {
            // Handle incoming client messages
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMessage>(&text) {
                            Ok(ClientMessage::Subscribe { channel }) => {
                                subscriptions.insert(channel.clone(), true);
                                {
                                    let mut state = tee_state.write().await;
                                    state.enclave_mut().stream_stats.active_subscriptions += 1;
                                }
                                let resp = ServerMessage {
                                    msg_type: "subscribed".into(),
                                    channel: Some(channel),
                                    data: None,
                                    message: None,
                                };
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = socket.send(Message::Text(json.into())).await;
                                }
                            }
                            Ok(ClientMessage::Unsubscribe { channel }) => {
                                subscriptions.remove(&channel);
                                let resp = ServerMessage {
                                    msg_type: "unsubscribed".into(),
                                    channel: Some(channel),
                                    data: None,
                                    message: None,
                                };
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = socket.send(Message::Text(json.into())).await;
                                }
                            }
                            Ok(ClientMessage::Ping) => {
                                let resp = ServerMessage {
                                    msg_type: "pong".into(),
                                    channel: None,
                                    data: None,
                                    message: None,
                                };
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = socket.send(Message::Text(json.into())).await;
                                }
                            }
                            Err(_) => {
                                let resp = ServerMessage {
                                    msg_type: "error".into(),
                                    channel: None,
                                    data: None,
                                    message: Some("Invalid message format. Expected JSON with \"type\" field.".into()),
                                };
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = socket.send(Message::Text(json.into())).await;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            // Forward price updates to subscribed clients
            update = price_rx.recv() => {
                if let Ok(price) = update {
                    if subscriptions.contains_key(&"prices".to_string()) {
                        let msg = ServerMessage {
                            msg_type: "price_update".into(),
                            channel: Some("prices".into()),
                            data: Some(serde_json::json!({
                                "symbol": price.symbol,
                                "price": price.price,
                                "timestamp": price.timestamp,
                                "source": price.source,
                            })),
                            message: None,
                        };
                        if let Ok(json) = serde_json::to_string(&msg) {
                            {
                                let mut state = tee_state.write().await;
                                state.enclave_mut().stream_stats.total_messages_sent += 1;
                            }
                            if socket.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Client disconnected
    let sub_count = subscriptions.len() as u64;
    let mut state = tee_state.write().await;
    state.enclave_mut().stream_stats.active_subscriptions =
        state.enclave().stream_stats().active_subscriptions.saturating_sub(sub_count);
}

// ---------------------------------------------------------------------------
// REST endpoints (also attested)
// ---------------------------------------------------------------------------

/// GET /stats — stream statistics (attested response).
/// GET /stats — stream statistics (attested response).
/// The #[attest] macro injects `tee_state: Arc<RwLock<TeeState>>` automatically.
/// We access it directly inside the handler body — no extra parameter needed.
#[attest]
async fn get_stats() -> Json<serde_json::Value> {
    let state = tee_state.read().await;
    let stats = state.enclave().stream_stats();
    Json(serde_json::json!({
        "total_connections": stats.total_connections,
        "total_messages_sent": stats.total_messages_sent,
        "active_subscriptions": stats.active_subscriptions,
        "attested": true,
    }))
}

/// GET /health — health check.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn attestation_info(
    Extension(tee_state): Extension<Arc<RwLock<TeeState>>>,
) -> Json<serde_json::Value> {
    let state = tee_state.read().await;
    Json(state.attestation_json())
}

// ---------------------------------------------------------------------------
// Background price publisher
// ---------------------------------------------------------------------------

async fn publish_prices(tx: broadcast::Sender<PriceUpdate>) {
    let mut btc_price: f64 = 67_000.0;
    let mut eth_price: f64 = 3_500.0;
    let mut tick: u64 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        tick += 1;

        // Simulate price movement
        let btc_delta = (tick as f64 * 0.7).sin() * 150.0;
        let eth_delta = (tick as f64 * 1.1).cos() * 25.0;
        btc_price += btc_delta;
        eth_price += eth_delta;

        let now = chrono::Utc::now().to_rfc3339();

        let _ = tx.send(PriceUpdate {
            symbol: "BTC".into(),
            price: (btc_price * 100.0).round() / 100.0,
            timestamp: now.clone(),
            source: "tee-oracle".into(),
        });

        let _ = tx.send(PriceUpdate {
            symbol: "ETH".into(),
            price: (eth_price * 100.0).round() / 100.0,
            timestamp: now,
            source: "tee-oracle".into(),
        });
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let tee_state = TeeState::initialize(std::path::Path::new("./sealed"))
        .expect("Failed to initialize TeeState");
    let tee_state = Arc::new(RwLock::new(tee_state));

    // Broadcast channel for price updates
    let (price_tx, _) = broadcast::channel::<PriceUpdate>(256);

    // Start background price publisher
    tokio::spawn(publish_prices(price_tx.clone()));

    let app = Router::new()
        // WebSocket endpoint — attested at TLS layer
        .route("/ws", get(ws_handler))
        // REST endpoints — attested per-response
        .route("/stats", get(get_stats))
        .route("/health", get(health))
        .route("/.well-known/tee-attestation", get(attestation_info))
        .layer(Extension(tee_state))
        .layer(Extension(price_tx));

    let http_port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let https_port = std::env::var("HTTPS_PORT").unwrap_or_else(|_| "8443".to_string());

    println!("Attested WebSocket Stream Server");
    println!("================================");
    println!();
    println!("  WebSocket:  ws://localhost:{http_port}/ws");
    println!("  Stats:      http://localhost:{http_port}/stats");
    println!("  Attestation: http://localhost:{http_port}/.well-known/tee-attestation");
    println!();
    println!("  With RA-TLS: wss://localhost:{https_port}/ws");
    println!();
    println!("  Connect: wscat -c ws://localhost:{http_port}/ws");
    println!("  Subscribe: {{\"type\":\"subscribe\",\"channel\":\"prices\"}}");
    println!();

    // In dev mode, just run HTTP. With ra-tls feature, run dual port.
    #[cfg(feature = "ra-tls")]
    {
        if std::env::var("GUARANTEE_ENCLAVE").map(|v| v == "1").unwrap_or(false)
            || std::env::var("USE_RATLS").map(|v| v == "1").unwrap_or(false)
        {
            println!("  Starting with RA-TLS (HTTPS + HTTP)...");
            guarantee::serve_ra_tls(
                app,
                "websocket-ratls",
                &format!("0.0.0.0:{https_port}"),
                &format!("0.0.0.0:{http_port}"),
            )
            .await
            .expect("Server failed");
            return;
        }
    }

    // Fallback: plain HTTP
    println!("  Starting HTTP-only (dev mode)...");
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{http_port}"))
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server failed");
}
