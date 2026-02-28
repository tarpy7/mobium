//! HTTP routing configuration

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::websocket::ServerState;

/// Create the application router
pub fn create_router(state: Arc<ServerState>) -> Router {
    let cors = build_cors_layer(&state.config.cors_origins);

    let mut router = Router::new()
        .route("/ws", get(crate::websocket::handle_websocket))
        .route("/health", get(health_check))
        .route("/info", get(server_info));

    // Only mount admin endpoint if a token is configured
    if state.config.admin_token.is_some() {
        router = router.route("/admin/stats", get(admin_stats));
    }

    router
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

/// Build CORS layer from config. Permissive when no origins are configured.
fn build_cors_layer(origins: &Option<String>) -> CorsLayer {
    match origins {
        Some(list) if !list.is_empty() => {
            let parsed: Vec<_> = list
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            CorsLayer::new().allow_origin(AllowOrigin::list(parsed))
        }
        _ => CorsLayer::permissive(),
    }
}

/// Health check — no sensitive data
async fn health_check() -> &'static str {
    "OK"
}

/// Server info — only protocol version (no version/feature leakage)
async fn server_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "Mobium Server",
        "protocol_version": 1,
    }))
}

/// Admin stats — protected by bearer token
async fn admin_stats(
    headers: HeaderMap,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let expected = state.config.admin_token.as_deref().ok_or(StatusCode::NOT_FOUND)?;

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    if expected.as_bytes().ct_eq(provided.as_bytes()).into() {
        Ok(Json(serde_json::json!({
            "connected_users": state.connections.len(),
            "voice_channels_active": state.voice_channels.len(),
            "max_connections": state.config.max_connections,
        })))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
