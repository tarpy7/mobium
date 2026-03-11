//! WebSocket handler for real-time messaging

use axum::{
    extract::{ws::{WebSocket, Message}, WebSocketUpgrade, State, ConnectInfo},
    response::IntoResponse,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;
use tracing::{info, debug, warn, error};
use futures::{sink::SinkExt, stream::StreamExt};

use sha2::Digest;
use crate::config::ServerConfig;
use crate::database;
use crate::auth::verify_challenge;
use sqlx::{Pool, Sqlite};

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Simple token-bucket rate limiter (not shared across threads)
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: std::time::Instant,
}

impl RateLimiter {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Try to consume one token. Returns false if rate limit exceeded.
    fn try_consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

struct Connection {
    pubkey: Option<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    auth_challenge: Vec<u8>,
    /// General message rate limiter (30 burst, 10/s refill)
    rate_limiter: RateLimiter,
    /// Separate rate limiter for real-time media (voice + screen data).
    /// 150 burst, 80/s refill — accommodates 50fps voice + 10fps screen simultaneously.
    voice_rate_limiter: RateLimiter,
    /// Chat message rate limiter: 1 message per 0.3 seconds (burst 3, refill 3.33/s)
    chat_rate_limiter: RateLimiter,
}

/// Maximum participants in a voice channel.
const MAX_VOICE_PARTICIPANTS: usize = 40;

/// Threshold for P2P mesh voice (at or below this, clients use mesh WebRTC).
const P2P_VOICE_THRESHOLD: usize = 4;

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

/// Server state shared across connections
pub struct ServerState {
    pub db_pool: Pool<Sqlite>,
    pub config: ServerConfig,
    /// Map of public key → sender channel
    pub connections: dashmap::DashMap<Vec<u8>, mpsc::Sender<Vec<u8>>>,
    /// Voice channel participants: channel_id → set of participant pubkeys
    pub voice_channels: dashmap::DashMap<Vec<u8>, std::collections::HashSet<Vec<u8>>>,
    /// Current total connection count (for enforcing max_connections)
    connection_count: AtomicUsize,
    /// Per-IP connection counts (for enforcing max_connections_per_ip)
    ip_connections: dashmap::DashMap<std::net::IpAddr, AtomicUsize>,
}

impl ServerState {
    pub fn new(db_pool: Pool<Sqlite>, config: ServerConfig) -> Self {
        Self {
            db_pool,
            config,
            connections: dashmap::DashMap::new(),
            voice_channels: dashmap::DashMap::new(),
            connection_count: AtomicUsize::new(0),
            ip_connections: dashmap::DashMap::new(),
        }
    }

    /// Try to acquire a connection slot. Returns false if limits are exceeded.
    fn try_acquire_connection(&self, ip: std::net::IpAddr) -> bool {
        let max_global = self.config.max_connections;
        let max_per_ip = self.config.max_connections_per_ip;

        // Check global limit (0 = unlimited)
        if max_global > 0 && self.connection_count.load(Ordering::Relaxed) >= max_global {
            return false;
        }

        // Check per-IP limit (0 = unlimited)
        if max_per_ip > 0 {
            let entry = self.ip_connections.entry(ip).or_insert_with(|| AtomicUsize::new(0));
            if entry.value().load(Ordering::Relaxed) >= max_per_ip {
                return false;
            }
            entry.value().fetch_add(1, Ordering::Relaxed);
        }

        self.connection_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Release a connection slot.
    fn release_connection(&self, ip: std::net::IpAddr) {
        self.connection_count.fetch_sub(1, Ordering::Relaxed);
        if let Some(entry) = self.ip_connections.get(&ip) {
            let prev = entry.value().fetch_sub(1, Ordering::Relaxed);
            if prev <= 1 {
                drop(entry);
                self.ip_connections.remove(&ip);
            }
        }
    }

    /// Remove a user from all voice channels (called on disconnect).
    fn remove_from_voice_channels(&self, pubkey: &[u8]) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
        let mut notifications = Vec::new();
        let mut empty_channels = Vec::new();
        for mut entry in self.voice_channels.iter_mut() {
            let channel_id = entry.key().clone();
            let participants = entry.value_mut();
            if participants.remove(pubkey) {
                let remaining: Vec<Vec<u8>> = participants.iter().cloned().collect();
                notifications.push((channel_id.clone(), remaining));
                if participants.is_empty() {
                    empty_channels.push(channel_id);
                }
            }
        }
        for ch in empty_channels {
            self.voice_channels.remove(&ch);
        }
        notifications
    }

    /// Route a message to a connected user or store offline
    pub async fn route_message(
        &self,
        recipient: &[u8],
        sender: &[u8],
        payload: &[u8],
    ) -> anyhow::Result<()> {
        if let Some(entry) = self.connections.get(recipient) {
            let tx = entry.value();
            let msg = rmp_serde::to_vec_named(&serde_json::json!({
                "type": "message",
                "sender": sender,
                "payload": payload,
            }))?;
            if tx.send(msg).await.is_err() {
                drop(entry);
            } else {
                return Ok(());
            }
        }

        // Enforce per-user offline queue limit
        let current_count = database::count_offline_messages(&self.db_pool, recipient)
            .await.unwrap_or(0);

        if current_count >= self.config.max_offline_messages as i64 {
            warn!(
                "Offline queue full for recipient {} ({}/{}), dropping message",
                hex::encode(&recipient[..8.min(recipient.len())]),
                current_count,
                self.config.max_offline_messages
            );
            return Ok(());
        }

        database::store_offline_message(&self.db_pool, recipient, sender, payload).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebSocket upgrade handler
// ---------------------------------------------------------------------------

/// Handle WebSocket upgrade — enforces connection limits before accepting
pub async fn handle_websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip();

    if !state.try_acquire_connection(ip) {
        warn!("Connection rejected for {}: limit exceeded", ip);
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state, addr))
        .into_response()
}

// ---------------------------------------------------------------------------
// Socket lifecycle
// ---------------------------------------------------------------------------

async fn handle_socket(socket: WebSocket, state: Arc<ServerState>, addr: SocketAddr) {
    let ip = addr.ip();
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(50); // B8: bounded buffer

    // Generate auth challenge
    let auth_challenge: Vec<u8> = {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut nonce = vec![0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    };

    let mut conn = Connection {
        pubkey: None,
        tx: tx.clone(),
        auth_challenge: auth_challenge.clone(),
        rate_limiter: RateLimiter::new(30.0, 10.0),
        voice_rate_limiter: RateLimiter::new(150.0, 80.0),
        chat_rate_limiter: RateLimiter::new(3.0, 3.33), // 1 per 0.3s, burst 3
    };

    info!("New WebSocket connection from {}", addr);

    // Send auth challenge
    {
        let challenge_msg = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "auth_challenge",
            "nonce": &auth_challenge,
        })).unwrap_or_default();
        if ws_sender.send(Message::Binary(challenge_msg)).await.is_err() {
            error!("Failed to send auth challenge to {}", addr);
            state.release_connection(ip);
            return;
        }
    }

    // B4: Spawn task to forward outbound messages + send periodic pings
    let ping_interval_secs = state.config.ws_ping_interval;
    let forward_task = tokio::spawn(async move {
        let mut ping_ticker = tokio::time::interval(
            std::time::Duration::from_secs(ping_interval_secs),
        );
        ping_ticker.tick().await; // skip first immediate tick

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(data) => {
                            if ws_sender.send(Message::Binary(data)).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = ping_ticker.tick() => {
                    if ws_sender.send(Message::Ping(vec![])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // B2: Auth timeout — if not authenticated within N seconds, drop
    let auth_timeout = std::time::Duration::from_secs(state.config.auth_timeout_seconds);
    let auth_deadline = tokio::time::Instant::now() + auth_timeout;

    // Main receive loop
    loop {
        // If not yet authenticated, enforce the auth deadline
        let next_msg = if conn.pubkey.is_none() {
            match tokio::time::timeout_at(auth_deadline, ws_receiver.next()).await {
                Ok(msg) => msg,
                Err(_) => {
                    warn!("Auth timeout for {} — dropping connection", addr);
                    break;
                }
            }
        } else {
            ws_receiver.next().await
        };

        match next_msg {
            Some(Ok(msg)) => match msg {
                Message::Binary(data) => {
                    if let Err(e) = handle_binary_message(&data, &mut conn, &state).await {
                        // Log the full error for server-side debugging but send
                        // a generic message to the client to avoid leaking
                        // internal details (stack traces, SQL errors, etc.).
                        error!("Error handling message from {}: {}", addr, e);
                        let _ = tx.send(rmp_serde::to_vec_named(&serde_json::json!({
                            "type": "error",
                            "code": 400,
                            "message": "Request failed",
                        })).unwrap_or_default()).await;
                    }
                }
                Message::Text(_) => { /* ignore text frames */ }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => { /* axum auto-responds to pings */ }
            },
            Some(Err(e)) => {
                debug!("WebSocket error from {}: {}", addr, e);
                break;
            }
            None => break,
        }
    }

    // Cleanup
    if let Some(ref pubkey) = conn.pubkey {
        // Notify voice channel peers
        let voice_notifications = state.remove_from_voice_channels(pubkey);
        for (channel_id, remaining) in voice_notifications {
            let leave_msg = rmp_serde::to_vec_named(&serde_json::json!({
                "type": "voice_left",
                "channel_id": &channel_id,
                "pubkey": pubkey,
            })).unwrap_or_default();
            for participant in &remaining {
                if let Some(entry) = state.connections.get(participant) {
                    let _ = entry.value().try_send(leave_msg.clone());
                }
            }
        }
        state.connections.remove(pubkey);
        info!("User {} disconnected ({})", hex::encode(&pubkey[..8.min(pubkey.len())]), addr);
    }

    state.release_connection(ip);
    forward_task.abort();
}

// ---------------------------------------------------------------------------
// Binary helpers
// ---------------------------------------------------------------------------

/// Extract bytes from serde_json::Value (supports byte arrays and hex strings)
fn extract_bytes(value: Option<&serde_json::Value>) -> Option<Vec<u8>> {
    let v = value?;
    if let Some(arr) = v.as_array() {
        return arr.iter().map(|v| v.as_u64().map(|n| n as u8)).collect();
    }
    if let Some(s) = v.as_str() {
        return hex::decode(s).ok();
    }
    None
}

// ---------------------------------------------------------------------------
// Protocol handler
// ---------------------------------------------------------------------------

async fn handle_binary_message(
    data: &[u8],
    conn: &mut Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let msg: serde_json::Value = rmp_serde::from_slice(data)?;
    let msg_type = msg.get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing message type"))?;

    // Rate limit: exempt ping/pong, auth, voice_data, and screen_data
    if !matches!(msg_type, "ping" | "pong" | "auth" | "voice_data" | "screen_data") {
        if !conn.rate_limiter.try_consume() {
            anyhow::bail!("Rate limit exceeded — slow down");
        }
    }

    // Stricter chat message rate limit: 1 per 0.3s (burst 3)
    if matches!(msg_type, "message" | "channel_message") {
        if !conn.chat_rate_limiter.try_consume() {
            let err = rmp_serde::to_vec_named(&serde_json::json!({
                "type": "error",
                "code": "RATE_LIMITED",
                "message": "You're sending messages too fast. Limit: 1 per 0.3 seconds.",
            }))?;
            conn.tx.send(err).await?;
            return Ok(());
        }
    }

    match msg_type {
        "auth" => handle_auth(&msg, conn, state).await,
        "message" => handle_dm(&msg, conn, state).await,
        "channel_message" => handle_channel_message(&msg, conn, state).await,
        "get_history" => handle_get_history(&msg, conn, state).await,
        "create_channel" => handle_create_channel(&msg, conn, state).await,
        "join_channel" => handle_join_channel(&msg, conn, state).await,
        "leave_channel" => handle_leave_channel_text(&msg, conn, state).await,
        "sender_key_distribution" => handle_sender_key_dist(&msg, conn, state).await,
        "get_members" => handle_get_members(&msg, conn, state).await,
        "publish_prekeys" => handle_publish_prekeys(&msg, conn, state).await,
        "get_prekey_bundle" => handle_get_prekey_bundle(&msg, conn, state).await,
        "get_prekey_count" => handle_get_prekey_count(conn, state).await,
        "voice_signal" => handle_voice_signal(&msg, conn, state).await,
        "join_voice" => handle_join_voice(&msg, conn, state).await,
        "leave_voice" => handle_leave_voice(&msg, conn, state).await,
        "voice_data" => handle_voice_data_raw(data, &msg, conn, state).await,
        "screen_data" => handle_screen_data_raw(data, &msg, conn, state).await,
        "get_ice_config" => handle_get_ice_config(conn, state).await,
        "set_channel_access" => handle_set_channel_access(&msg, conn, state).await,
        "create_invite" => handle_create_invite(&msg, conn, state).await,
        "set_username" => handle_set_username(&msg, conn, state).await,
        "search_users" => handle_search_users(&msg, conn, state).await,
        "get_username" => handle_get_username(&msg, conn, state).await,
        // Roles & moderation
        "set_role" => handle_set_role(&msg, conn, state).await,
        "ban_user" => handle_ban_user(&msg, conn, state).await,
        "unban_user" => handle_unban_user(&msg, conn, state).await,
        "get_bans" => handle_get_bans(&msg, conn, state).await,
        // Sub-channels
        "create_sub_channel" => handle_create_sub_channel(&msg, conn, state).await,
        "delete_sub_channel" => handle_delete_sub_channel(&msg, conn, state).await,
        "get_sub_channels" => handle_get_sub_channels(&msg, conn, state).await,
        "sub_channel_message" => handle_sub_channel_message(&msg, conn, state).await,
        "get_sub_history" => handle_get_sub_history(&msg, conn, state).await,
        // Channel password
        "set_channel_password" => handle_set_channel_password(&msg, conn, state).await,
        // Channel info
        "get_channel_info" => handle_get_channel_info(&msg, conn, state).await,
        "update_channel_info" => handle_update_channel_info(&msg, conn, state).await,
        "ping" => {
            let pong = rmp_serde::to_vec_named(&serde_json::json!({"type": "pong"}))?;
            conn.tx.send(pong).await?;
            Ok(())
        }
        _ => anyhow::bail!("Unknown message type: {}", msg_type),
    }
}

/// Require the connection to be authenticated, returning the pubkey.
fn require_auth(conn: &Connection) -> anyhow::Result<&Vec<u8>> {
    conn.pubkey.as_ref().ok_or_else(|| anyhow::anyhow!("Not authenticated"))
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async fn handle_auth(
    msg: &serde_json::Value,
    conn: &mut Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let pubkey = msg.get("pubkey")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Missing pubkey"))?
        .iter().map(|v| v.as_u64().map(|n| n as u8)).collect::<Option<Vec<u8>>>()
        .ok_or_else(|| anyhow::anyhow!("Invalid pubkey format"))?;

    let signature = msg.get("signature")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Missing signature"))?
        .iter().map(|v| v.as_u64().map(|n| n as u8)).collect::<Option<Vec<u8>>>()
        .ok_or_else(|| anyhow::anyhow!("Invalid signature format"))?;

    let mut challenge_data = b"Mobium-auth-v1".to_vec();
    challenge_data.extend_from_slice(&conn.auth_challenge);
    if !verify_challenge(&pubkey, &signature, &challenge_data) {
        anyhow::bail!("Invalid authentication signature");
    }

    let x25519_pub = extract_bytes(msg.get("x25519_pub"));
    conn.pubkey = Some(pubkey.clone());
    state.connections.insert(pubkey.clone(), conn.tx.clone());
    database::store_user(&state.db_pool, &pubkey, x25519_pub.as_deref(), None).await?;

    // Deliver offline messages
    let messages = database::get_offline_messages(
        &state.db_pool, &pubkey, state.config.max_offline_messages as i64,
    ).await?;

    let mut ids_to_delete = Vec::new();
    for (id, sender, payload, timestamp) in messages {
        let m = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "message", "sender": sender, "payload": payload,
            "offline": true, "timestamp": timestamp,
        }))?;
        if conn.tx.send(m).await.is_ok() {
            ids_to_delete.push(id);
        }
    }
    if !ids_to_delete.is_empty() {
        database::delete_offline_messages(&state.db_pool, &ids_to_delete).await?;
    }

    info!("User {} authenticated", hex::encode(&pubkey[..8.min(pubkey.len())]));
    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "auth_success", "offline_count": ids_to_delete.len(),
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// DM
// ---------------------------------------------------------------------------

async fn handle_dm(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?;
    let recipient = extract_bytes(msg.get("recipient"))
        .ok_or_else(|| anyhow::anyhow!("Missing recipient"))?;
    let payload = extract_bytes(msg.get("payload"))
        .ok_or_else(|| anyhow::anyhow!("Missing payload"))?;

    if payload.len() > state.config.max_message_size {
        anyhow::bail!("Message too large");
    }

    state.route_message(&recipient, sender, &payload).await?;
    let ack = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "ack", "recipient": recipient,
    }))?;
    conn.tx.send(ack).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel message
// ---------------------------------------------------------------------------

async fn handle_channel_message(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let payload = extract_bytes(msg.get("payload"))
        .ok_or_else(|| anyhow::anyhow!("Missing payload"))?;
    let bucket_size = msg.get("bucket_size").and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow::anyhow!("Missing bucket_size"))?;

    if payload.len() > state.config.max_message_size {
        anyhow::bail!("Message too large");
    }
    if !database::is_channel_member(&state.db_pool, &channel_id, sender).await? {
        anyhow::bail!("Not a member of this channel");
    }

    database::store_channel_message(&state.db_pool, &channel_id, sender, &payload, bucket_size).await?;

    // Pre-serialize once, forward to online members
    let fwd = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "channel_message",
        "channel_id": &channel_id,
        "sender": sender,
        "payload": &payload,
    }))?;
    let members = database::get_channel_members(&state.db_pool, &channel_id).await?;
    for member in &members {
        if member != sender {
            if let Some(entry) = state.connections.get(member) {
                let _ = entry.value().send(fwd.clone()).await;
            }
        }
    }

    let ack = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "ack", "channel_id": channel_id,
    }))?;
    conn.tx.send(ack).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

async fn handle_get_history(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user_pubkey = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let after_timestamp = msg.get("after_timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
    let limit = msg.get("limit").and_then(|v| v.as_i64()).unwrap_or(100).min(1000);

    let messages = database::get_channel_history(
        &state.db_pool, &channel_id, user_pubkey, after_timestamp, limit,
    ).await?;

    let history: Vec<_> = messages.into_iter().map(|(id, sender, payload, ts, bucket)| {
        serde_json::json!({"id": id, "sender": sender, "payload": payload, "timestamp": ts, "bucket_size": bucket})
    }).collect();

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "history_response", "channel_id": channel_id,
        "messages": history, "count": history.len(),
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel lifecycle
// ---------------------------------------------------------------------------

async fn handle_create_channel(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let creator = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let encrypted_metadata = extract_bytes(msg.get("encrypted_metadata"))
        .ok_or_else(|| anyhow::anyhow!("Missing encrypted_metadata"))?;

    database::create_channel(&state.db_pool, &channel_id, &encrypted_metadata, creator).await?;
    // Set creator as owner
    database::set_member_role(&state.db_pool, &channel_id, creator, "owner").await?;

    info!("Channel {} created by {}",
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        hex::encode(&creator[..8.min(creator.len())]));

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "channel_created", "channel_id": channel_id,
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

async fn handle_join_channel(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?.clone();
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let invite_token = extract_bytes(msg.get("invite_token"));

    // Check if channel exists
    let channel_access = database::get_channel_access(&state.db_pool, &channel_id).await?;

    if let Some((access_mode, _creator)) = &channel_access {
        // Check ban first
        if database::is_banned(&state.db_pool, &channel_id, &user).await? {
            let err = rmp_serde::to_vec_named(&serde_json::json!({
                "type": "error", "code": "banned", "message": "You are banned from this channel",
            }))?;
            conn.tx.send(err).await?;
            return Ok(());
        }

        // Check channel password if set (client sends pre-hashed SHA-256)
        let pw_hash = database::get_channel_password_hash(&state.db_pool, &channel_id).await?;
        if let Some(ref stored_hash) = pw_hash {
            let provided = msg.get("password").and_then(|v| v.as_str()).unwrap_or("");
            if provided != stored_hash.as_str() {
                let err = rmp_serde::to_vec_named(&serde_json::json!({
                    "type": "error", "code": "password_required", "message": "Incorrect or missing channel password",
                }))?;
                conn.tx.send(err).await?;
                return Ok(());
            }
        }

        // Channel exists — check access
        if access_mode == "private" {
            // Already a member? Allow rejoin silently
            let is_member = database::is_channel_member(&state.db_pool, &channel_id, &user).await?;
            if !is_member {
                // Need a valid invite token
                if let Some(token) = &invite_token {
                    let valid = database::consume_invite(&state.db_pool, token).await?;
                    match valid {
                        Some(ref invite_channel) if *invite_channel == channel_id => {
                            // Valid invite — proceed
                        }
                        _ => {
                            let err = rmp_serde::to_vec_named(&serde_json::json!({
                                "type": "error", "message": "Invalid or expired invite token",
                            }))?;
                            conn.tx.send(err).await?;
                            return Ok(());
                        }
                    }
                } else {
                    let err = rmp_serde::to_vec_named(&serde_json::json!({
                        "type": "error", "message": "This channel is private. An invite token is required.",
                    }))?;
                    conn.tx.send(err).await?;
                    return Ok(());
                }
            }
        }
    } else {
        // Channel doesn't exist — auto-create as public
        info!("Channel {} does not exist — auto-creating for joiner {}",
            hex::encode(&channel_id[..8.min(channel_id.len())]),
            hex::encode(&user[..8.min(user.len())]));
        let placeholder_metadata = vec![0u8; 32];
        let _ = database::create_channel(&state.db_pool, &channel_id, &placeholder_metadata, &user).await;
    }

    let existing_members = database::get_channel_members(&state.db_pool, &channel_id).await?;
    database::add_channel_member(&state.db_pool, &channel_id, &user).await?;

    info!("User {} joined channel {}",
        hex::encode(&user[..8.min(user.len())]),
        hex::encode(&channel_id[..8.min(channel_id.len())]));

    // Notify existing members so they re-distribute sender keys
    let join_notification = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "member_joined", "channel_id": &channel_id, "member": &user,
    }))?;
    for member in &existing_members {
        if *member != user {
            if let Some(entry) = state.connections.get(member) {
                let _ = entry.value().send(join_notification.clone()).await;
            }
        }
    }

    // Deliver stored sender key distributions to the joiner
    let stored_keys = database::get_sender_keys_for_recipient(
        &state.db_pool, &channel_id, &user,
    ).await.unwrap_or_default();
    for (sender_pubkey, sender_x25519_pub, encrypted_dist) in &stored_keys {
        let fwd = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "sender_key_distribution",
            "channel_id": &channel_id,
            "sender_ed25519_pub": sender_pubkey,
            "sender_x25519_pub": sender_x25519_pub,
            "encrypted_distribution": encrypted_dist,
        }))?;
        let _ = conn.tx.send(fwd).await;
    }

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "channel_joined", "channel_id": channel_id,
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

/// Leave a text channel — remove from DB and notify remaining members.
///
/// Remaining members receive `member_left` and are expected to rotate their
/// sender keys so the departed member cannot decrypt future messages (forward
/// secrecy for group channels).
async fn handle_leave_channel_text(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?.clone();
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    // Remove from DB
    database::remove_channel_member(&state.db_pool, &channel_id, &user).await?;

    // Get remaining members to notify
    let remaining = database::get_channel_members(&state.db_pool, &channel_id).await?;

    info!("User {} left channel {} ({} remaining)",
        hex::encode(&user[..8.min(user.len())]),
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        remaining.len());

    // Notify remaining members so they rotate sender keys
    if !remaining.is_empty() {
        let leave_msg = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "member_left",
            "channel_id": &channel_id,
            "member": &user,
        }))?;
        for member in &remaining {
            if let Some(entry) = state.connections.get(member) {
                let _ = entry.value().send(leave_msg.clone()).await;
            }
        }
    }

    let ack = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "channel_left",
        "channel_id": channel_id,
    }))?;
    conn.tx.send(ack).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sender key distribution
// ---------------------------------------------------------------------------

async fn handle_sender_key_dist(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    if !database::is_channel_member(&state.db_pool, &channel_id, sender).await? {
        anyhow::bail!("Not a member of this channel");
    }

    let distributions = msg.get("distributions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Missing distributions array"))?;

    let sender_x25519_pub = extract_bytes(msg.get("sender_x25519_pub"))
        .ok_or_else(|| anyhow::anyhow!("Missing sender_x25519_pub"))?;

    for dist_entry in distributions {
        let recipient_pubkey = extract_bytes(dist_entry.get("recipient"))
            .ok_or_else(|| anyhow::anyhow!("Missing recipient in distribution"))?;
        let encrypted_dist = extract_bytes(dist_entry.get("encrypted_dist"))
            .ok_or_else(|| anyhow::anyhow!("Missing encrypted_dist in distribution"))?;

        // Persist for redelivery to future joiners/reconnectors
        if let Err(e) = database::store_sender_key_distribution(
            &state.db_pool, &channel_id, sender, &recipient_pubkey,
            &sender_x25519_pub, &encrypted_dist,
        ).await {
            error!("Failed to persist sender key distribution: {}", e);
        }

        // Forward to online recipient
        if let Some(entry) = state.connections.get(&recipient_pubkey) {
            let fwd = rmp_serde::to_vec_named(&serde_json::json!({
                "type": "sender_key_distribution",
                "channel_id": &channel_id,
                "sender_ed25519_pub": sender,
                "sender_x25519_pub": &sender_x25519_pub,
                "encrypted_distribution": &encrypted_dist,
            }))?;
            let _ = entry.value().send(fwd).await;
        }
    }

    let ack = rmp_serde::to_vec_named(&serde_json::json!({"type": "ack"}))?;
    conn.tx.send(ack).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Get members
// ---------------------------------------------------------------------------

async fn handle_get_members(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user_pubkey = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    if !database::is_channel_member(&state.db_pool, &channel_id, user_pubkey).await? {
        anyhow::bail!("Not a member of this channel");
    }

    let members_with_keys = database::get_channel_members_with_keys(&state.db_pool, &channel_id).await?;
    // Build members with role info
    let mut members_data: Vec<serde_json::Value> = Vec::with_capacity(members_with_keys.len());
    let mut members_flat: Vec<Vec<u8>> = Vec::with_capacity(members_with_keys.len());
    for (ed, x) in &members_with_keys {
        let role = database::get_member_role(&state.db_pool, &channel_id, ed).await?
            .unwrap_or_else(|| "member".to_string());
        members_data.push(serde_json::json!({"ed25519": ed, "x25519": x, "role": role}));
        members_flat.push(ed.clone());
    }

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "members_response", "channel_id": channel_id,
        "members": members_flat, "members_with_keys": members_data,
    }))?;
    conn.tx.send(response).await?;

    // Also deliver stored sender keys for this user in this channel
    let stored_keys = database::get_sender_keys_for_recipient(
        &state.db_pool, &channel_id, user_pubkey,
    ).await.unwrap_or_default();
    for (sender_pubkey, sender_x25519_pub, encrypted_dist) in &stored_keys {
        let fwd = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "sender_key_distribution",
            "channel_id": &channel_id,
            "sender_ed25519_pub": sender_pubkey,
            "sender_x25519_pub": sender_x25519_pub,
            "encrypted_distribution": encrypted_dist,
        }))?;
        let _ = conn.tx.send(fwd).await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pre-keys (X3DH)
// ---------------------------------------------------------------------------

async fn handle_publish_prekeys(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user_pubkey = require_auth(conn)?;
    let identity_x25519_pub = extract_bytes(msg.get("identity_x25519_pub"))
        .ok_or_else(|| anyhow::anyhow!("Missing identity_x25519_pub"))?;
    let signed_prekey = extract_bytes(msg.get("signed_prekey"))
        .ok_or_else(|| anyhow::anyhow!("Missing signed_prekey"))?;
    let signed_prekey_sig = extract_bytes(msg.get("signed_prekey_sig"))
        .ok_or_else(|| anyhow::anyhow!("Missing signed_prekey_sig"))?;
    let one_time_prekeys = extract_bytes(msg.get("one_time_prekeys")).unwrap_or_default();

    database::store_prekey_bundle(
        &state.db_pool, user_pubkey, &identity_x25519_pub,
        &signed_prekey, &signed_prekey_sig, &one_time_prekeys,
    ).await?;

    info!("Stored pre-key bundle for user {}", hex::encode(&user_pubkey[..8.min(user_pubkey.len())]));
    let ack = rmp_serde::to_vec_named(&serde_json::json!({"type": "prekeys_stored"}))?;
    conn.tx.send(ack).await?;
    Ok(())
}

async fn handle_get_prekey_bundle(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let _requester = require_auth(conn)?;
    let target_pubkey = extract_bytes(msg.get("target_pubkey"))
        .ok_or_else(|| anyhow::anyhow!("Missing target_pubkey"))?;

    let bundle = database::get_and_consume_prekey_bundle(&state.db_pool, &target_pubkey).await?;
    let response = match bundle {
        Some((identity_x25519_pub, signed_prekey, signed_prekey_sig, one_time_prekey, _)) => {
            rmp_serde::to_vec_named(&serde_json::json!({
                "type": "prekey_bundle_response", "target_pubkey": target_pubkey,
                "identity_x25519_pub": identity_x25519_pub,
                "signed_prekey": signed_prekey,
                "signed_prekey_sig": signed_prekey_sig,
                "one_time_prekey": one_time_prekey,
            }))?
        }
        None => {
            rmp_serde::to_vec_named(&serde_json::json!({
                "type": "prekey_bundle_response", "target_pubkey": target_pubkey,
                "error": "No pre-key bundle found for this user",
            }))?
        }
    };
    conn.tx.send(response).await?;
    Ok(())
}

/// Return how many one-time pre-keys the server still has for this user.
/// The client uses this to decide whether to generate and upload more.
async fn handle_get_prekey_count(
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user_pubkey = require_auth(conn)?;
    let count = database::count_one_time_prekeys(&state.db_pool, &user_pubkey).await?;
    let resp = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "prekey_count_response",
        "count": count,
    }))?;
    conn.tx.send(resp).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel access control
// ---------------------------------------------------------------------------

async fn handle_set_channel_access(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let access_mode = msg.get("access_mode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing access_mode"))?;

    if access_mode != "public" && access_mode != "private" {
        anyhow::bail!("access_mode must be 'public' or 'private'");
    }

    // Only the channel creator can change access mode
    let access = database::get_channel_access(&state.db_pool, &channel_id).await?;
    match access {
        Some((_mode, Some(ref creator))) if creator == user => {}
        _ => {
            let err = rmp_serde::to_vec_named(&serde_json::json!({
                "type": "error", "message": "Only the channel creator can change access mode",
            }))?;
            conn.tx.send(err).await?;
            return Ok(());
        }
    }

    database::set_channel_access_mode(&state.db_pool, &channel_id, access_mode).await?;

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "channel_access_updated",
        "channel_id": channel_id,
        "access_mode": access_mode,
    }))?;
    conn.tx.send(response).await?;

    info!("Channel {} access mode set to '{}' by {}",
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        access_mode,
        hex::encode(&user[..8.min(user.len())]));
    Ok(())
}

async fn handle_create_invite(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let max_uses = msg.get("max_uses").and_then(|v| v.as_i64()).unwrap_or(1);
    let ttl_seconds = msg.get("ttl_seconds").and_then(|v| v.as_i64());

    // Only channel members can create invites
    let is_member = database::is_channel_member(&state.db_pool, &channel_id, user).await?;
    if !is_member {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "You must be a channel member to create invites",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    // Generate a random 32-byte invite token
    let mut token = [0u8; 32];
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut token);

    let expires_at = ttl_seconds.map(|ttl| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64 + ttl
    });

    database::create_invite(&state.db_pool, &token, &channel_id, user, max_uses, expires_at).await?;

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "invite_created",
        "channel_id": channel_id,
        "invite_token": hex::encode(token),
        "max_uses": max_uses,
        "expires_at": expires_at,
    }))?;
    conn.tx.send(response).await?;

    info!("Invite created for channel {} by {} (uses: {}, expires: {:?})",
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        hex::encode(&user[..8.min(user.len())]),
        max_uses, expires_at);
    Ok(())
}

// ---------------------------------------------------------------------------
// Username & friends
// ---------------------------------------------------------------------------

async fn handle_set_username(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?;
    let username = msg.get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing username"))?;

    // Validate: 3-24 chars, alphanumeric + underscores, must start with letter
    let username = username.trim();
    if username.len() < 3 || username.len() > 24 {
        anyhow::bail!("Username must be 3-24 characters");
    }
    if !username.chars().next().map_or(false, |c| c.is_ascii_alphabetic()) {
        anyhow::bail!("Username must start with a letter");
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("Username can only contain letters, numbers, and underscores");
    }

    database::set_username(&state.db_pool, sender, username).await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let resp = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "username_set", "username": username,
    }))?;
    conn.tx.send(resp).await?;
    info!("User {} set username to '{}'", hex::encode(&sender[..8.min(sender.len())]), username);
    Ok(())
}

async fn handle_get_username(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let _ = require_auth(conn)?;
    let target_pubkey = extract_bytes(msg.get("pubkey"))
        .ok_or_else(|| anyhow::anyhow!("Missing pubkey"))?;

    let username = database::get_username(&state.db_pool, &target_pubkey).await?;
    let resp = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "username_result", "pubkey": target_pubkey, "username": username,
    }))?;
    conn.tx.send(resp).await?;
    Ok(())
}

async fn handle_search_users(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let _ = require_auth(conn)?;
    let query = msg.get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing query"))?;

    if query.len() < 2 {
        anyhow::bail!("Search query must be at least 2 characters");
    }

    let results = database::search_users(&state.db_pool, query).await?;
    let users: Vec<serde_json::Value> = results.into_iter().map(|(pubkey, username)| {
        serde_json::json!({ "pubkey": pubkey, "username": username })
    }).collect();

    let resp = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "search_results", "users": users,
    }))?;
    conn.tx.send(resp).await?;
    Ok(())
}


// ---------------------------------------------------------------------------
// ICE configuration (server-provided STUN/TURN)
// ---------------------------------------------------------------------------

async fn handle_get_ice_config(
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let pubkey = conn.pubkey.as_ref().ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;
    let config = &state.config;

    let mut ice_servers = Vec::new();

    // Add STUN server if configured
    if let Some(ref stun_url) = config.ice_stun_url {
        ice_servers.push(serde_json::json!({
            "urls": [stun_url],
        }));
    }

    // Add TURN server with HMAC credentials if configured
    if let Some(ref turn_url) = config.ice_turn_url {
        if let Some(ref secret) = config.ice_turn_secret {
            // Generate time-limited HMAC-SHA1 credentials (coturn use-auth-secret format)
            let ttl = config.ice_ttl;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() + ttl;
            let username = format!("{}:{}", timestamp, hex::encode(pubkey));

            // HMAC-SHA1(secret, username) -> base64 = password
            use hmac::{Hmac, Mac};
            use sha1::Sha1;
            type HmacSha1 = Hmac<Sha1>;
            let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
                .map_err(|_| anyhow::anyhow!("HMAC key error"))?;
            mac.update(username.as_bytes());
            let credential = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                mac.finalize().into_bytes(),
            );

            ice_servers.push(serde_json::json!({
                "urls": [turn_url],
                "username": username,
                "credential": credential,
                "ttl": ttl,
            }));
        } else {
            // TURN without auth (not recommended, but supported)
            ice_servers.push(serde_json::json!({
                "urls": [turn_url],
            }));
        }
    }

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "ice_config",
        "ice_servers": ice_servers,
    }))?;

    conn.tx.send(response).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Voice signaling (DM — WebRTC relay)
// ---------------------------------------------------------------------------

async fn handle_voice_signal(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?;
    let recipient = extract_bytes(msg.get("recipient"))
        .ok_or_else(|| anyhow::anyhow!("Missing recipient"))?;
    let payload = extract_bytes(msg.get("payload"))
        .ok_or_else(|| anyhow::anyhow!("Missing payload"))?;
    let signal_type = msg.get("signal_type").and_then(|v| v.as_str()).unwrap_or("unknown");

    if payload.len() > state.config.max_message_size {
        anyhow::bail!("Voice signal too large");
    }

    if let Some(entry) = state.connections.get(&recipient) {
        let fwd = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "voice_signal", "sender": sender,
            "signal_type": signal_type, "payload": payload,
        }))?;
        let _ = entry.value().send(fwd).await;
        debug!("Forwarded voice signal '{}' {} → {}",
            signal_type,
            hex::encode(&sender[..8.min(sender.len())]),
            hex::encode(&recipient[..8.min(recipient.len())]));
    } else {
        let unavail = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "voice_signal", "sender": recipient,
            "signal_type": "peer_unavailable", "payload": [],
        }))?;
        conn.tx.send(unavail).await?;
    }

    let ack = rmp_serde::to_vec_named(&serde_json::json!({"type": "ack"}))?;
    conn.tx.send(ack).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel voice
// ---------------------------------------------------------------------------

async fn handle_join_voice(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    let mut participants = state.voice_channels
        .entry(channel_id.clone())
        .or_insert_with(std::collections::HashSet::new);

    // Enforce voice channel capacity
    if participants.len() >= MAX_VOICE_PARTICIPANTS && !participants.contains(sender) {
        drop(participants);
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "voice_full",
            "channel_id": &channel_id,
            "message": format!("Voice channel is full ({}/{} participants)", MAX_VOICE_PARTICIPANTS, MAX_VOICE_PARTICIPANTS),
            "max_participants": MAX_VOICE_PARTICIPANTS,
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    participants.insert(sender.clone());
    let all_participants: Vec<Vec<u8>> = participants.iter().cloned().collect();
    let count = all_participants.len();
    drop(participants);

    // Determine voice mode: P2P mesh for ≤4 participants, server relay for 5+
    let voice_mode = if count <= P2P_VOICE_THRESHOLD { "p2p" } else { "relay" };

    // Send full voice state to the joiner
    let voice_state = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "voice_state", "channel_id": &channel_id,
        "participants": &all_participants,
        "voice_mode": voice_mode,
        "max_participants": MAX_VOICE_PARTICIPANTS,
    }))?;
    conn.tx.send(voice_state).await?;

    // Notify others of join + voice mode (so they can switch P2P ↔ relay)
    let join_msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "voice_joined", "channel_id": &channel_id, "pubkey": sender,
        "voice_mode": voice_mode,
        "participant_count": count,
    }))?;
    for p in &all_participants {
        if p != sender {
            if let Some(entry) = state.connections.get(p) {
                let _ = entry.value().try_send(join_msg.clone());
            }
        }
    }

    info!("User {} joined voice channel {} ({} participants)",
        hex::encode(&sender[..8.min(sender.len())]),
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        all_participants.len());
    Ok(())
}

async fn handle_leave_voice(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    let mut remaining = Vec::new();
    if let Some(mut entry) = state.voice_channels.get_mut(&channel_id) {
        entry.value_mut().remove(sender);
        remaining = entry.value().iter().cloned().collect();
        if entry.value().is_empty() {
            drop(entry);
            state.voice_channels.remove(&channel_id);
        }
    }

    if !remaining.is_empty() {
        let rem_count = remaining.len();
        let voice_mode = if rem_count <= P2P_VOICE_THRESHOLD { "p2p" } else { "relay" };
        let leave_msg = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "voice_left", "channel_id": &channel_id, "pubkey": sender,
            "voice_mode": voice_mode,
            "participant_count": rem_count,
        }))?;
        for p in &remaining {
            if let Some(entry) = state.connections.get(p) {
                let _ = entry.value().try_send(leave_msg.clone());
            }
        }
    }

    info!("User {} left voice channel {} ({} remaining)",
        hex::encode(&sender[..8.min(sender.len())]),
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        remaining.len());
    Ok(())
}

/// Hot path: relay encrypted audio frames as opaque bytes.
///
/// The caller already parsed the msgpack into `serde_json::Value` for
/// dispatch. We reuse that Value, inject the authenticated `sender` pubkey,
/// re-serialize once, and broadcast the same bytes to all recipients.
///
/// We must inject `sender` server-side (not trust the client) because the
/// recipient's `voice_decrypt` needs the sender pubkey to find the correct
/// chain key.  One serialization per incoming frame, reused for N recipients.
async fn handle_voice_data_raw(
    _raw_data: &[u8],
    msg: &serde_json::Value,
    conn: &mut Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    // B5: Voice-specific rate limit (silently drop, don't error)
    if !conn.voice_rate_limiter.try_consume() {
        return Ok(());
    }

    let sender = conn.pubkey.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

    // Reuse the already-parsed msg — only extract channel_id for routing
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    if let Some(entry) = state.voice_channels.get(&channel_id) {
        if !entry.value().contains(sender) {
            anyhow::bail!("Not in this voice channel");
        }

        // Rebuild the message with the authenticated sender pubkey injected.
        // The original message from the client does NOT include "sender"
        // (clients can't be trusted to identify themselves). We serialize
        // once and reuse the bytes for all recipients.
        let mut fwd_msg = msg.clone();
        fwd_msg.as_object_mut().unwrap().insert(
            "sender".to_string(),
            serde_json::json!(sender),
        );
        let fwd = rmp_serde::to_vec_named(&fwd_msg)?;

        for p in entry.value().iter() {
            if p != sender {
                if let Some(conn_entry) = state.connections.get(p) {
                    let _ = conn_entry.value().try_send(fwd.clone());
                }
            }
        }
    }
    Ok(()) // No ack for voice_data — fire and forget
}

/// Hot path: relay encrypted screen share frames as opaque bytes.
///
/// Same optimization as voice_data: reuse the already-parsed message for
/// channel_id routing, then forward the original raw bytes to recipients.
/// Screen share uses the same voice rate limiter since both are real-time
/// media streams (screen frames are larger but sent less frequently).
async fn handle_screen_data_raw(
    _raw_data: &[u8],
    msg: &serde_json::Value,
    conn: &mut Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    // Reuse voice rate limiter (silently drop if exceeded)
    if !conn.voice_rate_limiter.try_consume() {
        return Ok(());
    }

    let sender = conn.pubkey.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    if let Some(entry) = state.voice_channels.get(&channel_id) {
        if !entry.value().contains(sender) {
            anyhow::bail!("Not in this voice channel");
        }

        // Rebuild with authenticated sender pubkey (same pattern as voice_data).
        let mut fwd_msg = msg.clone();
        fwd_msg.as_object_mut().unwrap().insert(
            "sender".to_string(),
            serde_json::json!(sender),
        );
        let fwd = rmp_serde::to_vec_named(&fwd_msg)?;

        for p in entry.value().iter() {
            if p != sender {
                if let Some(conn_entry) = state.connections.get(p) {
                    let _ = conn_entry.value().try_send(fwd.clone());
                }
            }
        }
    }
    Ok(()) // No ack for screen_data — fire and forget
}

// ── Helper: check if user is owner or moderator ──────────────────────

async fn require_mod_or_owner(
    state: &Arc<ServerState>,
    channel_id: &[u8],
    user: &[u8],
) -> anyhow::Result<String> {
    let role = database::get_member_role(&state.db_pool, channel_id, user).await?
        .unwrap_or_default();
    if role != "owner" && role != "moderator" {
        anyhow::bail!("Requires owner or moderator role");
    }
    Ok(role)
}

async fn require_owner(
    state: &Arc<ServerState>,
    channel_id: &[u8],
    user: &[u8],
) -> anyhow::Result<()> {
    let role = database::get_member_role(&state.db_pool, channel_id, user).await?
        .unwrap_or_default();
    if role != "owner" {
        anyhow::bail!("Requires owner role");
    }
    Ok(())
}

// ── Set Role (owner only) ────────────────────────────────────────────

async fn handle_set_role(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let target = extract_bytes(msg.get("target_pubkey"))
        .ok_or_else(|| anyhow::anyhow!("Missing target_pubkey"))?;
    let role = msg.get("role").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing role"))?;

    if role != "moderator" && role != "member" {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Role must be 'moderator' or 'member'",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    // Only owner can set roles
    if let Err(_) = require_owner(state, &channel_id, user).await {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Only the channel owner can set roles",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    // Can't change own role
    if target == *user {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Cannot change your own role",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    database::set_member_role(&state.db_pool, &channel_id, &target, role).await?;

    // Notify the target if online
    if let Some(target_conn) = state.connections.get(&target) {
        let notif = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "role_updated", "channel_id": channel_id, "role": role,
        }))?;
        let _ = target_conn.value().try_send(notif);
    }

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "role_set", "channel_id": channel_id, "target_pubkey": target, "role": role,
    }))?;
    conn.tx.send(response).await?;

    info!("Role set: {} -> {} in channel {}",
        hex::encode(&target[..8.min(target.len())]),
        role,
        hex::encode(&channel_id[..8.min(channel_id.len())]));
    Ok(())
}

// ── Ban User (owner or moderator) ────────────────────────────────────

async fn handle_ban_user(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let target = extract_bytes(msg.get("target_pubkey"))
        .ok_or_else(|| anyhow::anyhow!("Missing target_pubkey"))?;
    let reason = msg.get("reason").and_then(|v| v.as_str());

    let user_role = match require_mod_or_owner(state, &channel_id, user).await {
        Ok(r) => r,
        Err(_) => {
            let err = rmp_serde::to_vec_named(&serde_json::json!({
                "type": "error", "message": "Only owner or moderator can ban users",
            }))?;
            conn.tx.send(err).await?;
            return Ok(());
        }
    };

    // Check target's role — mods can't ban owners or other mods
    let target_role = database::get_member_role(&state.db_pool, &channel_id, &target).await?
        .unwrap_or_default();
    if target_role == "owner" {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Cannot ban the channel owner",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }
    if target_role == "moderator" && user_role != "owner" {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Only the owner can ban moderators",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    // Can't ban self
    if target == *user {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Cannot ban yourself",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    database::ban_user(&state.db_pool, &channel_id, &target, user, reason).await?;

    // Notify target if online
    if let Some(target_conn) = state.connections.get(&target) {
        let notif = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "banned", "channel_id": channel_id, "reason": reason.unwrap_or(""),
        }))?;
        let _ = target_conn.value().try_send(notif);
    }

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "user_banned", "channel_id": channel_id, "target_pubkey": target,
    }))?;
    conn.tx.send(response).await?;

    info!("Banned {} from channel {} by {}",
        hex::encode(&target[..8.min(target.len())]),
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        hex::encode(&user[..8.min(user.len())]));
    Ok(())
}

// ── Unban User (owner or moderator) ──────────────────────────────────

async fn handle_unban_user(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let target = extract_bytes(msg.get("target_pubkey"))
        .ok_or_else(|| anyhow::anyhow!("Missing target_pubkey"))?;

    if let Err(_) = require_mod_or_owner(state, &channel_id, user).await {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Only owner or moderator can unban users",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    database::unban_user(&state.db_pool, &channel_id, &target).await?;

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "user_unbanned", "channel_id": channel_id, "target_pubkey": target,
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

// ── Get Bans (owner or moderator) ────────────────────────────────────

async fn handle_get_bans(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    if let Err(_) = require_mod_or_owner(state, &channel_id, user).await {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Only owner or moderator can view bans",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    let bans = database::get_bans(&state.db_pool, &channel_id).await?;
    let ban_list: Vec<serde_json::Value> = bans.into_iter().map(|(pk, reason)| {
        serde_json::json!({ "pubkey": pk, "reason": reason })
    }).collect();

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "bans_list", "channel_id": channel_id, "bans": ban_list,
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

// ── Create Sub-Channel (owner or moderator) ──────────────────────────

async fn handle_create_sub_channel(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let name = msg.get("name").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing name"))?;
    let kind = msg.get("kind").and_then(|v| v.as_str()).unwrap_or("text");
    let category = msg.get("category").and_then(|v| v.as_str()).unwrap_or("");
    let position = msg.get("position").and_then(|v| v.as_i64()).unwrap_or(0);

    if kind != "text" && kind != "voice" {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Sub-channel kind must be 'text' or 'voice'",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    if name.len() > 64 || name.is_empty() {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Sub-channel name must be 1-64 characters",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    if let Err(_) = require_mod_or_owner(state, &channel_id, user).await {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Only owner or moderator can create sub-channels",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    // Generate random ID
    let mut id = [0u8; 16];
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut id);

    database::create_sub_channel(&state.db_pool, &id, &channel_id, name, kind, category, position).await?;

    // Notify all channel members
    let members = database::get_channel_members(&state.db_pool, &channel_id).await?;
    let notif = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "sub_channel_created",
        "channel_id": channel_id,
        "sub_channel_id": id.to_vec(),
        "name": name,
        "kind": kind,
        "category": category,
        "position": position,
    }))?;
    for member_pk in &members {
        if let Some(c) = state.connections.get(member_pk) {
            let _ = c.value().try_send(notif.clone());
        }
    }

    info!("Sub-channel '{}' ({}) created in channel {}",
        name, kind, hex::encode(&channel_id[..8.min(channel_id.len())]));
    Ok(())
}

// ── Delete Sub-Channel (owner or moderator) ──────────────────────────

async fn handle_delete_sub_channel(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let sub_channel_id = extract_bytes(msg.get("sub_channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing sub_channel_id"))?;

    if let Err(_) = require_mod_or_owner(state, &channel_id, user).await {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Only owner or moderator can delete sub-channels",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    database::delete_sub_channel(&state.db_pool, &sub_channel_id).await?;

    // Notify all channel members
    let members = database::get_channel_members(&state.db_pool, &channel_id).await?;
    let notif = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "sub_channel_deleted",
        "channel_id": channel_id,
        "sub_channel_id": sub_channel_id,
    }))?;
    for member_pk in &members {
        if let Some(c) = state.connections.get(member_pk) {
            let _ = c.value().try_send(notif.clone());
        }
    }
    Ok(())
}

// ── Get Sub-Channels ─────────────────────────────────────────────────

async fn handle_get_sub_channels(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let _user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    let subs = database::get_sub_channels(&state.db_pool, &channel_id).await?;
    let list: Vec<serde_json::Value> = subs.into_iter().map(|(id, name, kind, category, pos)| {
        serde_json::json!({ "id": id, "name": name, "kind": kind, "category": category, "position": pos })
    }).collect();

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "sub_channels_list", "channel_id": channel_id, "sub_channels": list,
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

// ── Sub-Channel Message ──────────────────────────────────────────────

async fn handle_sub_channel_message(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let sender = require_auth(conn)?.clone();
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let sub_channel_id = extract_bytes(msg.get("sub_channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing sub_channel_id"))?;
    let payload = extract_bytes(msg.get("encrypted_payload"))
        .ok_or_else(|| anyhow::anyhow!("Missing encrypted_payload"))?;
    let bucket_size = msg.get("bucket_size").and_then(|v| v.as_i64()).unwrap_or(0);

    // Must be a channel member
    if !database::is_channel_member(&state.db_pool, &channel_id, &sender).await? {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Not a member of this channel",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    database::store_sub_channel_message(&state.db_pool, &sub_channel_id, &payload, bucket_size, &sender).await?;

    // Fan out to channel members
    let members = database::get_channel_members(&state.db_pool, &channel_id).await?;
    let fwd = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "sub_channel_message",
        "channel_id": channel_id,
        "sub_channel_id": sub_channel_id,
        "encrypted_payload": payload,
        "bucket_size": bucket_size,
        "sender": sender,
    }))?;
    for member_pk in &members {
        if *member_pk != sender {
            if let Some(c) = state.connections.get(member_pk) {
                let _ = c.value().try_send(fwd.clone());
            }
        }
    }
    Ok(())
}

// ── Get Sub-Channel History ──────────────────────────────────────────

async fn handle_get_sub_history(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let sub_channel_id = extract_bytes(msg.get("sub_channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing sub_channel_id"))?;
    let limit = msg.get("limit").and_then(|v| v.as_i64()).unwrap_or(50).min(200);
    let before_id = msg.get("before_id").and_then(|v| v.as_i64());

    if !database::is_channel_member(&state.db_pool, &channel_id, user).await? {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Not a member of this channel",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    let messages = database::get_sub_channel_history(&state.db_pool, &sub_channel_id, limit, before_id).await?;
    let list: Vec<serde_json::Value> = messages.into_iter().map(|(id, payload, bs, sender, ts)| {
        serde_json::json!({
            "id": id, "encrypted_payload": payload, "bucket_size": bs,
            "sender": sender, "timestamp": ts,
        })
    }).collect();

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "sub_channel_history",
        "sub_channel_id": sub_channel_id,
        "messages": list,
    }))?;
    conn.tx.send(response).await?;
    Ok(())
}

// ── Set Channel Password (owner only) ────────────────────────────────

async fn handle_set_channel_password(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;

    if let Err(_) = require_owner(state, &channel_id, user).await {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "error", "message": "Only the channel owner can set the password",
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    // Client sends pre-hashed SHA-256 — store directly (empty = clear)
    let password = msg.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let hash = if password.is_empty() {
        None
    } else {
        Some(password.to_string())
    };

    database::set_channel_password(&state.db_pool, &channel_id, hash.as_deref()).await?;

    let response = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "channel_password_set",
        "channel_id": channel_id,
        "has_password": hash.is_some(),
    }))?;
    conn.tx.send(response).await?;

    info!("Channel {} password {}",
        hex::encode(&channel_id[..8.min(channel_id.len())]),
        if hash.is_some() { "set" } else { "cleared" });
    Ok(())
}

// ── Channel info (get/update metadata) ──────────────────────────────

async fn handle_get_channel_info(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let _user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let info = database::get_channel_info(&state.db_pool, &channel_id).await?;
    let resp = if let Some((desc, rules, topic, access_mode, creator)) = info {
        serde_json::json!({
            "type": "channel_info",
            "channel_id": hex::encode(&channel_id),
            "description": desc,
            "rules": rules,
            "topic": topic,
            "access_mode": access_mode,
            "creator_pubkey": creator.map(|c| hex::encode(&c)),
        })
    } else {
        serde_json::json!({
            "type": "server_error",
            "code": "channel_not_found",
            "message": "Channel not found"
        })
    };
    let data = rmp_serde::to_vec_named(&resp)?;
    conn.tx.send(data).await?;
    Ok(())
}

async fn handle_update_channel_info(
    msg: &serde_json::Value,
    conn: &Connection,
    state: &Arc<ServerState>,
) -> anyhow::Result<()> {
    let user = require_auth(conn)?;
    let channel_id = extract_bytes(msg.get("channel_id"))
        .ok_or_else(|| anyhow::anyhow!("Missing channel_id"))?;
    let description = msg.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let rules = msg.get("rules").and_then(|v| v.as_str()).unwrap_or("");
    let topic = msg.get("topic").and_then(|v| v.as_str()).unwrap_or("");

    // Only owner can update
    if let Err(_) = require_owner(state, &channel_id, user).await {
        let err = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "server_error",
            "code": "not_owner",
            "message": "Only the channel owner can update channel info"
        }))?;
        conn.tx.send(err).await?;
        return Ok(());
    }

    database::update_channel_info(&state.db_pool, &channel_id, description, rules, topic).await?;

    // Broadcast to all channel members
    let resp = serde_json::json!({
        "type": "channel_info_updated",
        "channel_id": hex::encode(&channel_id),
        "description": description,
        "rules": rules,
        "topic": topic,
    });
    let data = rmp_serde::to_vec_named(&resp)?;
    let members = database::get_channel_members(&state.db_pool, &channel_id).await?;
    for pk in &members {
        if let Some(tx) = state.connections.get(pk) {
            let _ = tx.send(data.clone()).await;
        }
    }

    info!("Channel {} info updated by owner", hex::encode(&channel_id[..8.min(channel_id.len())]));
    Ok(())
}
