//! WebSocket client connection

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{info, error, debug, warn};
use tauri::{AppHandle, Emitter, Manager, State};
use crate::state::AppState;
use crate::db;
use std::sync::Arc;
use serde::Serialize;
use mobium_shared::ratchet::{DoubleRatchet, MessageHeader};
use mobium_shared::sender_keys::SenderKeyDistribution;
use mobium_shared::x3dh;
use x25519_dalek;


/// Events emitted to the frontend
#[derive(Clone, Serialize)]
pub struct AuthSuccessEvent {
    pub offline_count: u64,
}

#[derive(Clone, Serialize)]
pub struct ChannelMessageEvent {
    pub channel_id: String,
    pub sender: String,
    pub content: String,
    pub timestamp: i64,
}

#[derive(Clone, Serialize)]
pub struct DirectMessageEvent {
    pub sender: String,
    pub content: String,
    pub timestamp: i64,
}

#[derive(Clone, Serialize)]
pub struct ChannelCreatedEvent {
    pub channel_id: String,
}

#[derive(Clone, Serialize)]
pub struct ChannelJoinedEvent {
    pub channel_id: String,
}

#[derive(Clone, Serialize)]
pub struct ServerErrorEvent {
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct VoiceSignalEvent {
    pub sender: String,
    pub signal_type: String,
    pub payload: Vec<u8>,
}

/// WebSocket connection handle
pub struct Connection {
    /// Sender for outgoing messages
    tx: mpsc::Sender<Vec<u8>>,
    /// Oneshot channel for receiving pre-key bundle responses.
    /// Wrapped in a Mutex so we can take it from a shared reference.
    prekey_response_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<serde_json::Value>>>,
    #[allow(dead_code)]
    prekey_response_rx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<serde_json::Value>>>,
    /// Oneshot channel for receiving ICE config responses.
    ice_config_response_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<serde_json::Value>>>,
}

impl Connection {
    /// Send a message through the WebSocket
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.tx.send(data).await
            .map_err(|_| anyhow::anyhow!("WebSocket send failed"))?;
        Ok(())
    }

    /// Prepare a oneshot channel for receiving a pre-key bundle response,
    /// then return the receiver half. The sender half is stored internally
    /// for the WS message handler to fill.
    pub async fn take_prekey_response(&self) -> Option<tokio::sync::oneshot::Receiver<serde_json::Value>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.prekey_response_tx.lock().await = Some(tx);
        Some(rx)
    }

    /// Called by the WS handler when a prekey_bundle_response arrives.
    async fn deliver_prekey_response(&self, value: serde_json::Value) {
        if let Some(tx) = self.prekey_response_tx.lock().await.take() {
            let _ = tx.send(value);
        }
    }

    /// Prepare a oneshot channel for receiving an ICE config response.
    pub async fn take_ice_config_response(&self) -> Option<tokio::sync::oneshot::Receiver<serde_json::Value>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.ice_config_response_tx.lock().await = Some(tx);
        Some(rx)
    }

    /// Called by the WS handler when an ice_config response arrives.
    async fn deliver_ice_config_response(&self, value: serde_json::Value) {
        if let Some(tx) = self.ice_config_response_tx.lock().await.take() {
            let _ = tx.send(value);
        }
    }
}

/// Run a WebSocket session over any transport that implements AsyncRead + AsyncWrite.
/// This is the core session logic shared between direct and Tor connections.
async fn run_ws_session<S>(
    ws_stream: WebSocketStream<S>,
    server_url: String,
    identity: Arc<mobium_shared::IdentityKey>,
    state: State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut write, mut read) = ws_stream.split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

    // Wait for the server's auth challenge (random nonce)
    let auth_nonce = {
        let challenge_msg = read.next().await
            .ok_or_else(|| anyhow::anyhow!("Server closed connection before sending auth challenge"))?
            .map_err(|e| anyhow::anyhow!("WebSocket error waiting for auth challenge: {}", e))?;

        match challenge_msg {
            Message::Binary(data) => {
                let msg: serde_json::Value = rmp_serde::from_slice(&data)
                    .map_err(|e| anyhow::anyhow!("Failed to parse auth challenge: {}", e))?;
                let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if msg_type != "auth_challenge" {
                    return Err(anyhow::anyhow!("Expected auth_challenge, got: {}", msg_type));
                }
                msg.get("nonce")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<u8>>())
                    .ok_or_else(|| anyhow::anyhow!("Missing nonce in auth_challenge"))?
            }
            _ => return Err(anyhow::anyhow!("Expected binary auth challenge message")),
        }
    };

    // Sign "Mobium-auth-v1" || nonce
    let pubkey = identity.public_signing_key().as_bytes().to_vec();
    let x25519_pub = identity.public_encryption_key().as_bytes().to_vec();
    let mut challenge_data = b"Mobium-auth-v1".to_vec();
    challenge_data.extend_from_slice(&auth_nonce);
    let signature = identity.sign(&challenge_data).to_bytes().to_vec();

    let auth_msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "auth",
        "pubkey": pubkey,
        "x25519_pub": x25519_pub,
        "signature": signature,
    }))?;

    write.send(Message::Binary(auth_msg)).await
        .map_err(|e| anyhow::anyhow!("Failed to send auth: {}", e))?;

    // Spawn write task
    let _write_task = tauri::async_runtime::spawn(async move {
        info!("WebSocket write task started");
        while let Some(data) = rx.recv().await {
            let len = data.len();
            match write.send(Message::Binary(data)).await {
                Ok(_) => {
                    info!("Write task: sent {} bytes to WebSocket", len);
                }
                Err(e) => {
                    error!("Write task: WebSocket send error: {}", e);
                    break;
                }
            }
        }
        info!("WebSocket write task ended");
    });

    // Spawn read task
    let app = app_handle.clone();
    let _read_task = tauri::async_runtime::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if let Err(e) = handle_server_message(&data, &app).await {
                        error!("Error handling server message: {}", e);
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("Server closed connection");
                    let _ = app.emit("connection_lost", ());
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    let _ = app.emit("connection_lost", ());
                    break;
                }
                _ => {}
            }
        }
    });

    // Store connection
    let connection = Arc::new(Connection {
        tx,
        prekey_response_tx: tokio::sync::Mutex::new(None),
        prekey_response_rx: tokio::sync::Mutex::new(None),
        ice_config_response_tx: tokio::sync::Mutex::new(None),
    });
    let mut conn_guard = state.connection.write().await;
    *conn_guard = Some(connection);

    // Persist the server URL for auto-reconnect
    {
        let mut url_guard = state.last_server_url.write().await;
        *url_guard = Some(server_url.clone());
    }
    let _ = crate::db::set_setting(&state, "last_server_url", &server_url).await;

    info!("WebSocket connection established and authenticated");
    Ok(())
}

/// Connect to the server
pub async fn connect(server_url: String, app_handle: AppHandle, state: State<'_, AppState>) -> Result<()> {
    // Drop any existing connection first so the old write/read tasks shut
    // down cleanly before we create a new WebSocket.
    {
        let mut conn_guard = state.connection.write().await;
        if conn_guard.is_some() {
            info!("Closing existing connection before reconnecting");
            *conn_guard = None;
        }
    }
    // Small yield so the old write task has a chance to observe the
    // dropped sender and exit before we open a new socket.
    tokio::task::yield_now().await;

    // Ensure we have an identity
    let identity = {
        let identity_guard = state.identity.read().await;
        if let Some(ref id) = *identity_guard {
            id.clone()
        } else {
            return Err(anyhow::anyhow!("No identity found. Please create or import an identity first."));
        }
    };
    
    // Parse URL and add WebSocket protocol
    let ws_url = if server_url.starts_with("wss://") || server_url.starts_with("ws://") {
        server_url.clone()
    } else if server_url.starts_with("https://") {
        server_url.replace("https://", "wss://")
    } else if server_url.starts_with("http://") {
        server_url.replace("http://", "ws://")
    } else if server_url.starts_with("localhost") || server_url.starts_with("127.0.0.1") {
        // Default to plain ws:// for localhost (no TLS in dev)
        format!("ws://{}", server_url)
    } else {
        format!("wss://{}", server_url)
    };
    
    let ws_url = if ws_url.ends_with("/ws") { ws_url } else { format!("{}/ws", ws_url) };
    
    info!("Connecting to {}", ws_url);
    
    // Check if Tor mode is enabled
    #[allow(unused_mut)]
    let mut use_tor = false;
    {
        let tor_state = state.tor_state.read().await;
        if let Some(ref ts) = *tor_state {
            use_tor = ts.is_enabled().await;
        }
    }

    // Connect — either through Tor or directly.
    // We connect via Tor in a separate early-return branch to keep types simple.
    #[cfg(feature = "tor")]
    if use_tor {
        info!("Routing connection through Tor...");
        let tor_state_guard = state.tor_state.read().await;
        let tor_state_ref = tor_state_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Tor state not initialized"))?;

        let parsed = url::Url::parse(&ws_url)
            .map_err(|e| anyhow::anyhow!("Invalid URL: {}", e))?;
        let host = parsed.host_str()
            .ok_or_else(|| anyhow::anyhow!("No host in URL"))?.to_string();
        let port = parsed.port_or_known_default()
            .unwrap_or(if parsed.scheme() == "wss" { 443 } else { 80 });

        let tor_stream = tor_state_ref.connect_tcp(&host, port).await?;
        // Drop the read lock before the long-lived session
        drop(tor_state_guard);
        info!("Tor circuit established, upgrading to WebSocket...");

        let (ws_stream, _) = tokio_tungstenite::client_async(&ws_url, tor_stream).await
            .map_err(|e| anyhow::anyhow!("WebSocket upgrade over Tor failed: {}", e))?;

        info!("WebSocket connected (via Tor)");
        return run_ws_session(ws_stream, server_url, identity, state, app_handle).await;
    }

    // Direct (non-Tor) connection
    let (ws_stream, _) = connect_async(&ws_url).await
        .map_err(|e| anyhow::anyhow!("WebSocket connection failed: {}", e))?;

    info!("WebSocket connected");
    run_ws_session(ws_stream, server_url, identity, state, app_handle).await
}

/// Handle messages from the server and emit Tauri events to frontend
async fn handle_server_message(data: &[u8], app: &AppHandle) -> Result<()> {
    let app_state = app.state::<AppState>();
    let msg: serde_json::Value = rmp_serde::from_slice(data)?;
    let msg_type = msg.get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing message type"))?;
    
    match msg_type {
        "auth_success" => {
            let offline_count = msg.get("offline_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            info!("Authentication successful ({} offline messages)", offline_count);
            let _ = app.emit("auth_success", AuthSuccessEvent { offline_count });
            
            // Auto-publish pre-keys if we haven't yet
            let should_publish = {
                let published = app_state.prekeys_published.read().await;
                !*published
            };
            if should_publish {
                info!("Auto-publishing pre-keys after auth_success");
                // Generate and publish pre-keys in the background
                let app_clone = app.clone();
                tauri::async_runtime::spawn(async move {
                    let app_state2 = app_clone.state::<AppState>();
                    // Small delay to ensure connection is fully stored
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    
                    let identity = {
                        let guard = app_state2.identity.read().await;
                        match guard.as_ref() {
                            Some(id) => id.clone(),
                            None => {
                                error!("auto-publish prekeys: no identity loaded");
                                return;
                            }
                        }
                    };
                    
                    let conn = {
                        let guard = app_state2.connection.read().await;
                        match guard.as_ref() {
                            Some(c) => c.clone(),
                            None => {
                                error!("auto-publish prekeys: no connection");
                                return;
                            }
                        }
                    };
                    
                    // Try to load existing pre-key material from DB first
                    let loaded = db::load_prekey_material(&app_state2).await.unwrap_or(None);
                    
                    let (bundle, _spk_bytes, _otpk_bytes_list) = if let Some((spk_bytes, otpk_bytes_list)) = loaded {
                        // Reconstruct the bundle from existing material
                        let spk = x25519_dalek::StaticSecret::from(spk_bytes);
                        let spk_pub = x25519_dalek::PublicKey::from(&spk);
                        let sig = identity.sign(spk_pub.as_bytes());
                        let otpks_pub: Vec<x25519_dalek::PublicKey> = otpk_bytes_list.iter()
                            .filter(|b| b.len() == 32)
                            .map(|b| {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(b);
                                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(arr))
                            })
                            .collect();
                        let otpks_secret: Vec<x25519_dalek::StaticSecret> = otpk_bytes_list.iter()
                            .filter(|b| b.len() == 32)
                            .map(|b| {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(b);
                                x25519_dalek::StaticSecret::from(arr)
                            })
                            .collect();
                        
                        let bundle = x3dh::PreKeyBundle {
                            identity_key: identity.public_signing_key(),
                            identity_encryption_key: identity.public_encryption_key(),
                            signed_pre_key: spk_pub,
                            signed_pre_key_signature: sig,
                            one_time_pre_keys: otpks_pub,
                        };
                        
                        // Restore private pre-keys into state
                        let private_keys = x3dh::PrivatePreKeys {
                            signed_pre_key: spk,
                            one_time_pre_keys: otpks_secret,
                        };
                        {
                            let mut guard = app_state2.our_prekeys.write().await;
                            *guard = Some(private_keys);
                        }
                        {
                            let mut guard = app_state2.our_spk_bytes.write().await;
                            *guard = Some(spk_bytes);
                        }
                        
                        (bundle, spk_bytes, otpk_bytes_list)
                    } else {
                        // Generate fresh pre-keys
                        let num_otpks = 10;
                        let (bundle, private_keys) = x3dh::generate_pre_key_bundle(&identity, num_otpks);
                        let spk_bytes = private_keys.signed_pre_key.to_bytes();
                        let otpk_bytes_list: Vec<Vec<u8>> = private_keys.one_time_pre_keys.iter()
                            .map(|sk| sk.to_bytes().to_vec())
                            .collect();
                        
                        // Save to DB
                        if let Err(e) = db::save_prekey_material(&app_state2, &spk_bytes, &otpk_bytes_list).await {
                            error!("auto-publish prekeys: failed to save material: {}", e);
                        }
                        
                        {
                            let mut guard = app_state2.our_prekeys.write().await;
                            *guard = Some(private_keys);
                        }
                        {
                            let mut guard = app_state2.our_spk_bytes.write().await;
                            *guard = Some(spk_bytes);
                        }
                        
                        (bundle, spk_bytes, otpk_bytes_list)
                    };
                    
                    // Serialize OTPKs for the server
                    let otpk_pub_list: Vec<Vec<u8>> = bundle.one_time_pre_keys.iter()
                        .map(|pk| pk.as_bytes().to_vec())
                        .collect();
                    let otpk_pub_blob = match rmp_serde::to_vec(&otpk_pub_list) {
                        Ok(b) => b,
                        Err(e) => {
                            error!("auto-publish prekeys: serialization error: {}", e);
                            return;
                        }
                    };
                    
                    let msg = rmp_serde::to_vec_named(&serde_json::json!({
                        "type": "publish_prekeys",
                        "identity_x25519_pub": bundle.identity_encryption_key.as_bytes().to_vec(),
                        "signed_prekey": bundle.signed_pre_key.as_bytes().to_vec(),
                        "signed_prekey_sig": bundle.signed_pre_key_signature.to_bytes().to_vec(),
                        "one_time_prekeys": otpk_pub_blob,
                    }));
                    
                    match msg {
                        Ok(data) => {
                            match conn.send(data).await {
                                Ok(_) => {
                                    info!("auto-publish prekeys: published successfully");
                                    let mut published = app_state2.prekeys_published.write().await;
                                    *published = true;
                                }
                                Err(e) => error!("auto-publish prekeys: send failed: {}", e),
                            }
                        }
                        Err(e) => error!("auto-publish prekeys: serialization error: {}", e),
                    }
                    
                    // Ask the server how many OTPKs it still has for us.
                    // The `prekey_count_response` handler will auto-replenish
                    // if the count drops below the threshold (5).
                    let count_msg = rmp_serde::to_vec_named(&serde_json::json!({
                        "type": "get_prekey_count",
                    }));
                    if let Ok(data) = count_msg {
                        let _ = conn.send(data).await;
                    }

                    // Also restore any existing ratchet sessions from DB
                    match db::load_all_ratchet_sessions(&app_state2).await {
                        Ok(sessions) => {
                            if !sessions.is_empty() {
                                info!("Restoring {} ratchet sessions from DB", sessions.len());
                                for (peer, ratchet_bytes, ad) in sessions {
                                    match DoubleRatchet::load(&ratchet_bytes) {
                                        Ok(ratchet) => {
                                            let mut s = app_state2.ratchet_sessions.write().await;
                                            s.insert(peer.clone(), ratchet);
                                            let mut a = app_state2.ratchet_ad.write().await;
                                            a.insert(peer, ad);
                                        }
                                        Err(e) => {
                                            // Session is corrupt (likely saved with the old
                                            // broken save() that wrote [0u8;32] as the DH
                                            // private key). Delete it so a fresh X3DH
                                            // handshake will be performed on next DM.
                                            warn!("Discarding corrupt ratchet session for {}: {} — will re-establish on next DM",
                                                &peer[..16.min(peer.len())], e);
                                            let _ = db::delete_ratchet_session(&app_state2, &peer).await;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => warn!("Failed to load ratchet sessions from DB: {}", e),
                    }

                    // ── Auto-rejoin channels on reconnect ────────────────
                    // Re-join all previously joined channels so the server
                    // knows we're a member again and will relay messages.
                    // Also triggers sender key re-distribution via the
                    // members_response handler.
                    match db::get_joined_channels(&app_state2).await {
                        Ok(channels) => {
                            if !channels.is_empty() {
                                info!("Auto-rejoining {} channels after reconnect", channels.len());
                                for channel_hex in &channels {
                                    if let Ok(channel_bytes) = hex::decode(channel_hex) {
                                        let join_msg = rmp_serde::to_vec_named(&serde_json::json!({
                                            "type": "join_channel",
                                            "channel_id": channel_bytes,
                                        }));
                                        if let Ok(data) = join_msg {
                                            if let Err(e) = conn.send(data).await {
                                                warn!("auto-rejoin: failed to rejoin channel {}: {}", &channel_hex[..16.min(channel_hex.len())], e);
                                            }
                                        }
                                        // Request members to trigger sender key re-distribution
                                        let members_msg = rmp_serde::to_vec_named(&serde_json::json!({
                                            "type": "get_members",
                                            "channel_id": channel_bytes,
                                        }));
                                        if let Ok(data) = members_msg {
                                            let _ = conn.send(data).await;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => warn!("auto-rejoin: failed to load joined channels: {}", e),
                    }
                });
            }
        }
        
        "message" => {
            // Incoming direct message (encrypted with X3DH + Double Ratchet)
            let sender = extract_byte_array(&msg, "sender");
            let payload = extract_byte_array(&msg, "payload");
            
            if let (Some(sender), Some(payload)) = (sender, payload) {
                let sender_hex = hex::encode(&sender);
                // Use server-provided timestamp for offline messages, otherwise use current time
                let timestamp = msg.get("timestamp")
                    .and_then(|v| v.as_i64())
                    .map(|t| t * 1000) // server stores seconds, frontend uses millis
                    .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
                
                info!("Received DM from {} ({} bytes)", &sender_hex[..16.min(sender_hex.len())], payload.len());
                
                // Try to parse the DM payload (MessagePack)
                let dm_msg: serde_json::Value = match rmp_serde::from_slice(&payload) {
                    Ok(v) => v,
                    Err(_) => {
                        // Legacy plaintext fallback (for backward compatibility)
                        let content = String::from_utf8_lossy(&payload).to_string();
                        if let Err(e) = db::store_message(&app_state, &sender_hex, &sender, payload.as_slice(), false).await {
                            error!("Failed to persist incoming DM: {}", e);
                        }
                        let _ = app.emit("direct_message", DirectMessageEvent {
                            sender: sender_hex,
                            content,
                            timestamp,
                        });
                        return Ok(());
                    }
                };
                
                let dm_type = dm_msg.get("dm_type").and_then(|v| v.as_str()).unwrap_or("unknown");
                
                let content = match dm_type {
                    "x3dh_init" => {
                        // Initial X3DH message — perform responder side
                        info!("Processing X3DH init message from {}", &sender_hex[..16.min(sender_hex.len())]);
                        
                        let ephemeral_pub_bytes = dm_msg.get("ephemeral_pub")
                            .and_then(|v| extract_byte_array_from_value(Some(v)))
                            .ok_or_else(|| anyhow::anyhow!("Missing ephemeral_pub in X3DH init"))?;
                        let header_bytes = dm_msg.get("header")
                            .and_then(|v| extract_byte_array_from_value(Some(v)))
                            .ok_or_else(|| anyhow::anyhow!("Missing header in X3DH init"))?;
                        let ciphertext = dm_msg.get("ciphertext")
                            .and_then(|v| extract_byte_array_from_value(Some(v)))
                            .ok_or_else(|| anyhow::anyhow!("Missing ciphertext in X3DH init"))?;
                        let one_time_key_used = dm_msg.get("one_time_key_used")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        
                        // Get our identity and pre-keys
                        let identity = {
                            let guard = app_state.identity.read().await;
                            guard.as_ref().ok_or_else(|| anyhow::anyhow!("No identity loaded"))?.clone()
                        };
                        let prekeys = {
                            let guard = app_state.our_prekeys.read().await;
                            if guard.is_none() {
                                // Try to load from DB
                                drop(guard);
                                if let Ok(Some((spk_bytes, otpk_bytes_list))) = db::load_prekey_material(&app_state).await {
                                    let spk = x25519_dalek::StaticSecret::from(spk_bytes);
                                    let otpks: Vec<x25519_dalek::StaticSecret> = otpk_bytes_list.iter()
                                        .filter(|b| b.len() == 32)
                                        .map(|b| {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(b);
                                            x25519_dalek::StaticSecret::from(arr)
                                        })
                                        .collect();
                                    let private_prekeys = x3dh::PrivatePreKeys {
                                        signed_pre_key: spk,
                                        one_time_pre_keys: otpks,
                                    };
                                    let mut guard2 = app_state.our_prekeys.write().await;
                                    *guard2 = Some(private_prekeys);
                                    let mut spk_guard = app_state.our_spk_bytes.write().await;
                                    *spk_guard = Some(spk_bytes);
                                }
                                app_state.our_prekeys.read().await
                            } else {
                                guard
                            }
                        };
                        let our_prekeys = prekeys.as_ref()
                            .ok_or_else(|| anyhow::anyhow!("No pre-key material available — cannot perform X3DH responder"))?;
                        
                        // Build sender's identity info
                        let their_identity_key = ed25519_dalek::VerifyingKey::from_bytes(
                            &<[u8; 32]>::try_from(sender.as_slice())
                                .map_err(|_| anyhow::anyhow!("Invalid sender pubkey length"))?
                        ).map_err(|_| anyhow::anyhow!("Invalid sender Ed25519 key"))?;
                        
                        // Get the sender's X25519 identity key.
                        // Prefer the key embedded in the x3dh_init payload (always
                        // available regardless of channel membership), then fall back
                        // to the members_with_keys cache.
                        let their_x25519_bytes = match dm_msg.get("sender_x25519_pub")
                            .and_then(|v| extract_byte_array_from_value(Some(v)))
                        {
                            Some(bytes) => Some(bytes),
                            None => {
                                let x25519_guard = app_state.x25519_keys.read().await;
                                x25519_guard.get(&sender).cloned()
                            }
                        };
                        let their_identity_x25519 = match their_x25519_bytes {
                            Some(bytes) if bytes.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                x25519_dalek::PublicKey::from(arr)
                            }
                            _ => {
                                return Err(anyhow::anyhow!("No X25519 key for sender {} — cannot complete X3DH", &sender_hex[..16.min(sender_hex.len())]));
                            }
                        };
                        
                        // Cache the sender's X25519 key for future use
                        {
                            let mut x25519_guard = app_state.x25519_keys.write().await;
                            x25519_guard.insert(sender.clone(), their_identity_x25519.as_bytes().to_vec());
                        }
                        
                        let ephemeral_pub = x25519_dalek::PublicKey::from(
                            <[u8; 32]>::try_from(ephemeral_pub_bytes.as_slice())
                                .map_err(|_| anyhow::anyhow!("Invalid ephemeral key length"))?
                        );
                        
                        let otpk_index = if one_time_key_used { Some(0usize) } else { None };
                        
                        // Perform X3DH responder
                        let handshake = x3dh::X3DHHandshake::responder(
                            &identity,
                            our_prekeys,
                            &their_identity_key,
                            &their_identity_x25519,
                            &ephemeral_pub,
                            otpk_index,
                        ).map_err(|e| anyhow::anyhow!("X3DH responder failed: {}", e))?;
                        
                        let shared_secret = handshake.shared_secret();
                        let ad = handshake.associated_data().to_vec();
                        
                        // Get our signed pre-key secret for Double Ratchet init
                        let spk_bytes = {
                            let guard = app_state.our_spk_bytes.read().await;
                            guard.ok_or_else(|| anyhow::anyhow!("No SPK bytes available"))?
                        };
                        let bob_spk = x25519_dalek::StaticSecret::from(spk_bytes);
                        
                        // Initialise Double Ratchet as Bob (responder)
                        let mut ratchet = DoubleRatchet::init_bob(shared_secret, &bob_spk)
                            .map_err(|e| anyhow::anyhow!("Ratchet init_bob failed: {}", e))?;
                        
                        // Parse the message header and decrypt
                        let header = MessageHeader::from_bytes(&header_bytes)
                            .map_err(|e| anyhow::anyhow!("Invalid message header: {}", e))?;
                        let plaintext = ratchet.decrypt(&header, &ciphertext, &ad)
                            .map_err(|e| anyhow::anyhow!("Ratchet decrypt failed: {}", e))?;
                        
                        let content = String::from_utf8_lossy(&plaintext).to_string();
                        
                        // Store the ratchet session
                        {
                            let mut sessions = app_state.ratchet_sessions.write().await;
                            sessions.insert(sender_hex.clone(), ratchet);
                        }
                        {
                            let mut ad_map = app_state.ratchet_ad.write().await;
                            ad_map.insert(sender_hex.clone(), ad);
                        }
                        
                        // Persist ratchet to DB
                        persist_ratchet_session_ws(&app_state, &sender_hex).await;
                        
                        info!("X3DH handshake completed with {} — session established", &sender_hex[..16.min(sender_hex.len())]);

                        // An OTPK was consumed by the server when the initiator
                        // fetched our prekey bundle. Query our remaining count
                        // so the `prekey_count_response` handler can replenish
                        // if we're running low.
                        if one_time_key_used {
                            let conn_guard = app_state.connection.read().await;
                            if let Some(conn) = conn_guard.as_ref() {
                                let count_msg = rmp_serde::to_vec_named(&serde_json::json!({
                                    "type": "get_prekey_count",
                                }));
                                if let Ok(data) = count_msg {
                                    let _ = conn.send(data).await;
                                }
                            }
                        }
                        
                        // Drain any buffered DMs that arrived before the session was established
                        let buffered = {
                            let mut buf = app_state.buffered_dms.write().await;
                            buf.remove(&sender_hex).unwrap_or_default()
                        };
                        if !buffered.is_empty() {
                            info!("Draining {} buffered DM(s) from {}", buffered.len(), &sender_hex[..16.min(sender_hex.len())]);
                            for buf_payload in buffered {
                                if let Ok(buf_msg) = rmp_serde::from_slice::<serde_json::Value>(&buf_payload) {
                                    let buf_header_bytes = buf_msg.get("header")
                                        .and_then(|v| extract_byte_array_from_value(Some(v)));
                                    let buf_ciphertext = buf_msg.get("ciphertext")
                                        .and_then(|v| extract_byte_array_from_value(Some(v)));
                                    if let (Some(bh), Some(bc)) = (buf_header_bytes, buf_ciphertext) {
                                        if let Ok(buf_header) = MessageHeader::from_bytes(&bh) {
                                            let decrypt_result = {
                                                let mut sessions = app_state.ratchet_sessions.write().await;
                                                let ad_map = app_state.ratchet_ad.read().await;
                                                if let (Some(r), Some(a)) = (sessions.get_mut(&sender_hex), ad_map.get(&sender_hex)) {
                                                    r.decrypt(&buf_header, &bc, a).ok()
                                                } else {
                                                    None
                                                }
                                            };
                                            if let Some(buf_plaintext) = decrypt_result {
                                                let buf_content = String::from_utf8_lossy(&buf_plaintext).to_string();
                                                let buf_ts = chrono::Utc::now().timestamp_millis();
                                                // Persist
                                                let _ = db::store_message(&app_state, &sender_hex, &sender, buf_content.as_bytes(), false).await;
                                                let display_name = &sender_hex[..16.min(sender_hex.len())];
                                                let _ = db::store_conversation(&app_state, &sender_hex, display_name, "dm").await;
                                                let _ = app.emit("direct_message", DirectMessageEvent {
                                                    sender: sender_hex.clone(),
                                                    content: buf_content,
                                                    timestamp: buf_ts,
                                                });
                                            } else {
                                                warn!("Failed to decrypt buffered DM from {}", &sender_hex[..16.min(sender_hex.len())]);
                                            }
                                        }
                                    }
                                }
                            }
                            // Persist ratchet state after processing buffered messages
                            persist_ratchet_session_ws(&app_state, &sender_hex).await;
                        }
                        
                        content
                    }
                    "ratchet" => {
                        // Subsequent ratchet message — decrypt with existing session
                        let header_bytes = dm_msg.get("header")
                            .and_then(|v| extract_byte_array_from_value(Some(v)))
                            .ok_or_else(|| anyhow::anyhow!("Missing header in ratchet message"))?;
                        let ciphertext = dm_msg.get("ciphertext")
                            .and_then(|v| extract_byte_array_from_value(Some(v)))
                            .ok_or_else(|| anyhow::anyhow!("Missing ciphertext in ratchet message"))?;
                        
                        let header = MessageHeader::from_bytes(&header_bytes)
                            .map_err(|e| anyhow::anyhow!("Invalid message header: {}", e))?;
                        
                        let has_session = {
                            let sessions = app_state.ratchet_sessions.read().await;
                            sessions.contains_key(&sender_hex)
                        };
                        
                        if !has_session {
                            // Try loading from DB
                            if let Ok(Some((ratchet_bytes, ad))) = db::load_ratchet_session(&app_state, &sender_hex).await {
                                match DoubleRatchet::load(&ratchet_bytes) {
                                    Ok(ratchet) => {
                                        let mut sessions = app_state.ratchet_sessions.write().await;
                                        sessions.insert(sender_hex.clone(), ratchet);
                                        let mut ad_map = app_state.ratchet_ad.write().await;
                                        ad_map.insert(sender_hex.clone(), ad);
                                    }
                                    Err(e) => {
                                        // Corrupt session — delete from DB so a fresh
                                        // X3DH handshake will be triggered.
                                        warn!("Discarding corrupt ratchet session for {}: {}", &sender_hex[..16.min(sender_hex.len())], e);
                                        let _ = db::delete_ratchet_session(&app_state, &sender_hex).await;
                                    }
                                }
                            }
                        }
                        
                        let content = {
                            let mut sessions = app_state.ratchet_sessions.write().await;
                            let ad_map = app_state.ratchet_ad.read().await;
                            if let (Some(ratchet), Some(ad)) = (sessions.get_mut(&sender_hex), ad_map.get(&sender_hex)) {
                                let plaintext = ratchet.decrypt(&header, &ciphertext, ad)
                                    .map_err(|e| anyhow::anyhow!("Ratchet decrypt failed: {}", e))?;
                                String::from_utf8_lossy(&plaintext).to_string()
                            } else {
                                // Buffer the message for later.
                                // Cap at 100 per peer to prevent memory exhaustion.
                                let mut buf = app_state.buffered_dms.write().await;
                                let entry = buf.entry(sender_hex.clone()).or_default();
                                if entry.len() < 100 {
                                    entry.push(payload.clone());
                                    info!("Buffered encrypted DM from {} (no ratchet session, {} buffered)", &sender_hex[..16.min(sender_hex.len())], entry.len());
                                } else {
                                    warn!("DM buffer full for {} — dropping message", &sender_hex[..16.min(sender_hex.len())]);
                                }
                                return Ok(());
                            }
                        };
                        
                        // Persist updated ratchet state
                        persist_ratchet_session_ws(&app_state, &sender_hex).await;
                        
                        content
                    }
                    _ => {
                        // Unknown DM type — try plaintext fallback
                        warn!("Unknown dm_type '{}' — treating as plaintext", dm_type);
                        String::from_utf8_lossy(&payload).to_string()
                    }
                };
                
                // Persist to client DB
                let content_bytes = content.as_bytes();
                if let Err(e) = db::store_message(&app_state, &sender_hex, &sender, content_bytes, false).await {
                    error!("Failed to persist incoming DM: {}", e);
                }
                
                // Ensure DM conversation exists
                let display_name = &sender_hex[..16.min(sender_hex.len())];
                let _ = db::store_conversation(&app_state, &sender_hex, display_name, "dm").await;
                
                let _ = app.emit("direct_message", DirectMessageEvent {
                    sender: sender_hex,
                    content,
                    timestamp,
                });
            }
        }
        
        "channel_message" => {
            // Incoming channel message (encrypted with Sender Keys)
            let channel_id = extract_byte_array(&msg, "channel_id");
            let sender = extract_byte_array(&msg, "sender");
            let payload = extract_byte_array(&msg, "payload");
            
            if let (Some(channel_id), Some(sender), Some(payload)) = (channel_id, sender, payload) {
                let channel_hex = hex::encode(&channel_id);
                let sender_hex = hex::encode(&sender);
                let timestamp = chrono::Utc::now().timestamp_millis();
                
                info!("Received channel message in {} from {} ({} bytes)", 
                    &channel_hex[..16.min(channel_hex.len())],
                    &sender_hex[..16.min(sender_hex.len())],
                    payload.len());
                
                // Try to decrypt with Sender Keys
                let decrypt_result = {
                    let mut sessions = app_state.group_sessions.write().await;
                    if let Some(session) = sessions.get_mut(&channel_hex) {
                        let ad = channel_hex.as_bytes();
                        match session.decrypt(&sender, &payload, ad) {
                            Ok(plaintext) => {
                                info!("Decrypted channel message successfully");
                                Ok(String::from_utf8_lossy(&plaintext).to_string())
                            }
                            Err(e) => {
                                error!("Failed to decrypt channel message: {} — buffering for later", e);
                                Err(e.to_string())
                            }
                        }
                    } else {
                        debug!("No group session for channel {} — buffering message", &channel_hex[..16.min(channel_hex.len())]);
                        Err("No group session".to_string())
                    }
                };
                
                match decrypt_result {
                    Ok(content) => {
                        // Persist decrypted content to client DB
                        let content_bytes = content.as_bytes();
                        if let Err(e) = db::store_message(&app_state, &channel_hex, &sender, content_bytes, false).await {
                            error!("Failed to persist incoming channel message: {}", e);
                        }
                        
                        let event = ChannelMessageEvent {
                            channel_id: channel_hex.clone(),
                            sender: sender_hex.clone(),
                            content: content.clone(),
                            timestamp,
                        };
                        info!("Emitting channel_message (channel={}, sender={}, content_len={})",
                            &channel_hex[..16.min(channel_hex.len())], &sender_hex[..16.min(sender_hex.len())], content.len());
                        let _ = app.emit("channel_message", event);
                    }
                    Err(_) => {
                        // Buffer the encrypted message for later retry when we receive the sender key.
                        // Cap at 1000 per channel to prevent memory exhaustion.
                        let mut buf = app_state.buffered_messages.write().await;
                        let entry = buf.entry(channel_hex.clone()).or_insert_with(Vec::new);
                        if entry.len() < 1000 {
                            entry.push((sender.clone(), payload.clone(), timestamp));
                            info!("Buffered encrypted message for channel {} ({} total buffered)", 
                                &channel_hex[..16.min(channel_hex.len())], entry.len());
                        } else {
                            warn!("Buffer full for channel {} — dropping message", &channel_hex[..16.min(channel_hex.len())]);
                        }
                    }
                }
            }
        }
        
        "history_response" => {
            // History messages are server-stored ciphertext.  Because Sender
            // Keys use a forward-ratchet, we CANNOT re-decrypt them — doing so
            // would either fail ("iteration already consumed") or corrupt the
            // chain state and break future real-time decryption.
            //
            // Instead, history is used only at the DB level:  real-time
            // messages are already persisted by the channel_message handler
            // above, and the frontend loads them via get_messages.  We simply
            // tell the frontend to reload from DB.
            let channel_id = extract_byte_array(&msg, "channel_id");
            if let Some(channel_id) = channel_id {
                let channel_hex = hex::encode(&channel_id);
                let count = msg.get("messages").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                info!("Received history_response for channel {} ({} messages) — skipping ratchet decrypt, notifying frontend to reload from DB",
                    &channel_hex[..16.min(channel_hex.len())], count);
                
                let _ = app.emit("history_loaded", serde_json::json!({
                    "channel_id": channel_hex,
                }));
            }
        }
        
        "sender_key_distribution" => {
            // A peer is distributing their sender key for a channel (encrypted for us)
            let channel_id = extract_byte_array(&msg, "channel_id");
            let encrypted_dist = extract_byte_array(&msg, "encrypted_distribution");
            let sender_x25519_pub = extract_byte_array(&msg, "sender_x25519_pub");
            
            if let (Some(channel_id), Some(encrypted_dist), Some(sender_x25519_pub)) = 
                (channel_id, encrypted_dist, sender_x25519_pub) 
            {
                let channel_hex = hex::encode(&channel_id);
                
                // Decrypt the distribution using our X25519 key
                let identity_guard = app_state.identity.read().await;
                let decrypted = if let Some(identity) = identity_guard.as_ref() {
                    let sender_x25519: [u8; 32] = match sender_x25519_pub.as_slice().try_into() {
                        Ok(arr) => arr,
                        Err(_) => {
                            error!("Invalid sender X25519 pubkey length");
                            return Ok(());
                        }
                    };
                    let sender_x25519 = x25519_dalek::PublicKey::from(sender_x25519);
                    match mobium_shared::decrypt_from_sender(
                        &identity.encryption,
                        &sender_x25519,
                        &encrypted_dist,
                        &channel_id,
                    ) {
                        Ok(plaintext) => Some(plaintext),
                        Err(e) => {
                            error!("Failed to decrypt sender key distribution: {}", e);
                            None
                        }
                    }
                } else {
                    error!("No identity loaded — cannot decrypt sender key distribution");
                    None
                };
                drop(identity_guard);
                
                if let Some(dist_bytes) = decrypted {
                    match serde_json::from_slice::<SenderKeyDistribution>(&dist_bytes) {
                        Ok(dist) => {
                            let sender_hex = hex::encode(&dist.sender_pubkey);
                            info!("Received + decrypted sender key distribution for channel {} from {}",
                                &channel_hex[..16.min(channel_hex.len())],
                                &sender_hex[..16.min(sender_hex.len())]);
                            
                            // Process into group session — create one if it doesn't exist yet
                            let mut sessions = app_state.group_sessions.write().await;
                            let session = if let Some(s) = sessions.get_mut(&channel_hex) {
                                s
                            } else {
                                // We received a sender key before creating our own session for this channel.
                                // This happens when another member distributes their key after we joined.
                                // Create a session now so we can process their key.
                                info!("Creating group session for channel {} on-the-fly (triggered by incoming distribution)",
                                    &channel_hex[..16.min(channel_hex.len())]);
                                
                                let identity_guard2 = app_state.identity.read().await;
                                if let Some(identity) = identity_guard2.as_ref() {
                                    let my_pubkey = identity.public_signing_key().as_bytes().to_vec();
                                    drop(identity_guard2);
                                    let channel_id_bytes2 = hex::decode(&channel_hex).unwrap_or_default();
                                    let (new_session, my_dist) = mobium_shared::sender_keys::GroupSession::new(&channel_id_bytes2, &my_pubkey);
                                    
                                    // Persist our chain to DB
                                    let (chain_key, key_id, iteration) = new_session.my_chain_state();
                                    let my_pubkey_hex2 = hex::encode(&my_pubkey);
                                    let _ = db::save_sender_key(
                                        &app_state, &channel_hex, &my_pubkey_hex2,
                                        key_id, chain_key, iteration, true,
                                    ).await;
                                    
                                    // Store our distribution as pending so it gets sent when we know members
                                    {
                                        let mut pending = app_state.pending_distributions.write().await;
                                        pending.insert(channel_hex.clone(), my_dist);
                                    }
                                    
                                    sessions.insert(channel_hex.clone(), new_session);
                                    sessions.get_mut(&channel_hex).unwrap()
                                } else {
                                    drop(identity_guard2);
                                    error!("No identity loaded — cannot create group session");
                                    return Ok(());
                                }
                            };
                            
                            if let Err(e) = session.process_distribution(&dist) {
                                error!("Failed to process sender key distribution: {}", e);
                            } else {
                                // Persist peer chain to DB
                                let _ = db::save_sender_key(
                                    &app_state, &channel_hex, &sender_hex,
                                    dist.key_id, &dist.chain_key, dist.iteration, false,
                                ).await;
                                
                                // Retry any buffered messages for this channel
                                let buffered = {
                                    let mut buf = app_state.buffered_messages.write().await;
                                    buf.remove(&channel_hex).unwrap_or_default()
                                };
                                if !buffered.is_empty() {
                                    info!("Retrying {} buffered messages for channel {}", 
                                        buffered.len(), &channel_hex[..16.min(channel_hex.len())]);
                                    // Need to drop sessions lock, re-acquire for each retry
                                    drop(sessions);
                                    for (buf_sender, buf_payload, buf_timestamp) in buffered {
                                        let buf_sender_hex = hex::encode(&buf_sender);
                                        let content = {
                                            let mut sessions2 = app_state.group_sessions.write().await;
                                            if let Some(session2) = sessions2.get_mut(&channel_hex) {
                                                let ad = channel_hex.as_bytes();
                                                match session2.decrypt(&buf_sender, &buf_payload, ad) {
                                                    Ok(plaintext) => {
                                                        info!("Successfully decrypted buffered message from {}", &buf_sender_hex[..16.min(buf_sender_hex.len())]);
                                                        String::from_utf8_lossy(&plaintext).to_string()
                                                    }
                                                    Err(e) => {
                                                        error!("Failed to decrypt buffered message: {}", e);
                                                        continue;
                                                    }
                                                }
                                            } else {
                                                continue;
                                            }
                                        };
                                        
                                        // Persist and emit
                                        let content_bytes = content.as_bytes();
                                        if let Err(e) = db::store_message(&app_state, &channel_hex, &buf_sender, content_bytes, false).await {
                                            error!("Failed to persist buffered message: {}", e);
                                        }
                                        let buf_event = ChannelMessageEvent {
                                            channel_id: channel_hex.clone(),
                                            sender: buf_sender_hex,
                                            content,
                                            timestamp: buf_timestamp,
                                        };
                                        let _ = app.emit("channel_message", buf_event);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to deserialize sender key distribution: {}", e);
                        }
                    }
                }
            }
        }
        
        "members_response" => {
            // Server returned the member list for a channel
            let channel_id = extract_byte_array(&msg, "channel_id");
            let members = msg.get("members").and_then(|v| v.as_array());
            
            if let (Some(channel_id), Some(members)) = (channel_id, members) {
                let channel_hex = hex::encode(&channel_id);
                
                let member_pubkeys: Vec<Vec<u8>> = members.iter()
                    .filter_map(|m| {
                        m.as_array().map(|arr| {
                            arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect()
                        })
                    })
                    .collect();
                
                info!("Received member list for channel {} ({} members)",
                    &channel_hex[..16.min(channel_hex.len())], member_pubkeys.len());
                
                // Parse and cache X25519 public keys from members_with_keys
                if let Some(members_with_keys) = msg.get("members_with_keys").and_then(|v| v.as_array()) {
                    let mut x25519_guard = app_state.x25519_keys.write().await;
                    for entry in members_with_keys {
                        if let (Some(ed25519), Some(x25519)) = (
                            extract_byte_array_from_value(entry.get("ed25519")),
                            extract_byte_array_from_value(entry.get("x25519")),
                        ) {
                            if !x25519.is_empty() {
                                x25519_guard.insert(ed25519, x25519);
                            }
                        }
                    }
                }
                
                // Cache member list
                {
                    let mut members_guard = app_state.channel_members.write().await;
                    members_guard.insert(channel_hex.clone(), member_pubkeys.clone());
                }
                
                // Consume any explicit pending distribution first
                let pending_dist = {
                    let mut pending = app_state.pending_distributions.write().await;
                    pending.remove(&channel_hex)
                };
                
                // Determine the distribution to send.  If we had a pending one,
                // use it.  Otherwise, if we already have a group session (common
                // when fetch_channel_history triggers a members_response after
                // the session was created), generate the distribution on the fly.
                let dist_to_send = if let Some(d) = pending_dist {
                    info!("members_response: found pending distribution for channel {}", 
                        &channel_hex[..16.min(channel_hex.len())]);
                    Some(d)
                } else {
                    let sessions = app_state.group_sessions.read().await;
                    sessions.get(&channel_hex).map(|session| {
                        info!("members_response: no pending dist, but session exists — distributing key for channel {}",
                            &channel_hex[..16.min(channel_hex.len())]);
                        session.my_distribution(&channel_id)
                    })
                };
                
                if let Some(dist) = dist_to_send {
                    // Get connection to send the encrypted distribution
                    let conn_guard = app_state.connection.read().await;
                    if let Some(conn) = conn_guard.as_ref() {
                        let identity_guard = app_state.identity.read().await;
                        if let Some(identity) = identity_guard.as_ref() {
                            let my_pubkey = identity.public_signing_key().as_bytes().to_vec();
                            let my_x25519_pub = identity.public_encryption_key();
                            let encryption_key = &identity.encryption;
                            
                            let dist_bytes = match serde_json::to_vec(&dist) {
                                Ok(b) => b,
                                Err(e) => {
                                    error!("Failed to serialize distribution: {}", e);
                                    return Ok(());
                                }
                            };
                            
                            // Use cached X25519 public keys for encryption
                            let x25519_guard = app_state.x25519_keys.read().await;
                            let mut distributions = Vec::new();
                            for member_pk in &member_pubkeys {
                                if *member_pk == my_pubkey { continue; }
                                
                                let recipient_x25519 = match x25519_guard.get(member_pk) {
                                    Some(bytes) if bytes.len() == 32 => {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(bytes);
                                        x25519_dalek::PublicKey::from(arr)
                                    }
                                    _ => {
                                        tracing::warn!("members_response: no X25519 key for member {} — skipping",
                                            hex::encode(&member_pk[..8.min(member_pk.len())]));
                                        continue;
                                    }
                                };
                                
                                let encrypted = match mobium_shared::encrypt_for_recipient(
                                    encryption_key,
                                    &recipient_x25519,
                                    &dist_bytes,
                                    &channel_id,
                                ) {
                                    Ok(enc) => enc,
                                    Err(e) => {
                                        error!("Failed to encrypt dist for recipient: {}", e);
                                        continue;
                                    }
                                };
                                
                                distributions.push(serde_json::json!({
                                    "recipient": member_pk,
                                    "encrypted_dist": encrypted,
                                }));
                            }
                            drop(x25519_guard);
                            drop(identity_guard);
                            
                            if !distributions.is_empty() {
                                let msg = rmp_serde::to_vec_named(&serde_json::json!({
                                    "type": "sender_key_distribution",
                                    "channel_id": &channel_id,
                                    "sender_x25519_pub": my_x25519_pub.as_bytes().to_vec(),
                                    "distributions": distributions,
                                }));
                                if let Ok(data) = msg {
                                    let _ = conn.send(data).await;
                                    info!("Sent encrypted sender key distributions to {} members for channel {}", 
                                        distributions.len(), &channel_hex[..16.min(channel_hex.len())]);
                                }
                            } else {
                                info!("members_response: no recipients with X25519 keys for channel {}", 
                                    &channel_hex[..16.min(channel_hex.len())]);
                            }
                        }
                    }
                } else {
                    debug!("members_response: no session yet for channel {} — nothing to distribute",
                        &channel_hex[..16.min(channel_hex.len())]);
                }
            }
        }
        
        "member_joined" => {
            // A new member joined a channel we're in — re-distribute our sender key to them
            let channel_id = extract_byte_array(&msg, "channel_id");
            let new_member = extract_byte_array(&msg, "member");
            
            if let (Some(channel_id), Some(new_member)) = (channel_id, new_member) {
                let channel_hex = hex::encode(&channel_id);
                let member_hex = hex::encode(&new_member[..8.min(new_member.len())]);
                info!("New member {} joined channel {} — re-distributing our sender key",
                    member_hex, &channel_hex[..16.min(channel_hex.len())]);
                
                // Update cached member list
                {
                    let mut members_guard = app_state.channel_members.write().await;
                    let members = members_guard.entry(channel_hex.clone()).or_insert_with(Vec::new);
                    if !members.contains(&new_member) {
                        members.push(new_member.clone());
                    }
                }
                
                // Get our current sender key distribution for this channel
                let dist = {
                    let sessions = app_state.group_sessions.read().await;
                    sessions.get(&channel_hex).map(|session| {
                        session.my_distribution(&channel_id)
                    })
                };
                
                if let Some(dist) = dist {
                    info!("member_joined: have session, distributing key (key_id={}, iteration={}) to {}",
                        dist.key_id, dist.iteration, member_hex);
                    
                    // Look up the new member's X25519 public key
                    let recipient_x25519_bytes = {
                        let x25519_guard = app_state.x25519_keys.read().await;
                        x25519_guard.get(&new_member).cloned()
                    };
                    
                    let recipient_x25519 = match recipient_x25519_bytes {
                        Some(bytes) if bytes.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            x25519_dalek::PublicKey::from(arr)
                        }
                        _ => {
                            // Don't have X25519 key yet — request members to get it,
                            // then the members_response will trigger distribution via pending
                            info!("member_joined: no X25519 key for new member {} — requesting member list",
                                member_hex);
                            let conn_guard = app_state.connection.read().await;
                            if let Some(conn) = conn_guard.as_ref() {
                                // Store dist as pending, request members
                                {
                                    let mut pending = app_state.pending_distributions.write().await;
                                    pending.insert(channel_hex.clone(), dist);
                                }
                                let channel_id_bytes = hex::decode(&channel_hex).unwrap_or_default();
                                let msg = rmp_serde::to_vec_named(&serde_json::json!({
                                    "type": "get_members",
                                    "channel_id": channel_id_bytes,
                                }));
                                if let Ok(data) = msg {
                                    let _ = conn.send(data).await;
                                }
                            }
                            return Ok(());
                        }
                    };
                    
                    // Encrypt and send our sender key to just the new member
                    let conn_guard = app_state.connection.read().await;
                    if let Some(conn) = conn_guard.as_ref() {
                        let identity_guard = app_state.identity.read().await;
                        if let Some(identity) = identity_guard.as_ref() {
                            let my_x25519_pub = identity.public_encryption_key();
                            let encryption_key = &identity.encryption;
                            
                            let dist_bytes = match serde_json::to_vec(&dist) {
                                Ok(b) => b,
                                Err(e) => {
                                    error!("member_joined: failed to serialize distribution: {}", e);
                                    return Ok(());
                                }
                            };
                            
                            let encrypted = match mobium_shared::encrypt_for_recipient(
                                encryption_key,
                                &recipient_x25519,
                                &dist_bytes,
                                &channel_id,
                            ) {
                                Ok(enc) => enc,
                                Err(e) => {
                                    error!("member_joined: failed to encrypt dist for new member: {}", e);
                                    return Ok(());
                                }
                            };
                            
                            let x25519_bytes = my_x25519_pub.as_bytes().to_vec();
                            drop(identity_guard);
                            
                            let msg = rmp_serde::to_vec_named(&serde_json::json!({
                                "type": "sender_key_distribution",
                                "channel_id": channel_id,
                                "sender_x25519_pub": x25519_bytes,
                                "distributions": [
                                    {
                                        "recipient": new_member,
                                        "encrypted_dist": encrypted,
                                    }
                                ],
                            }));
                            match msg {
                                Ok(data) => {
                                    match conn.send(data).await {
                                        Ok(_) => info!("member_joined: re-distributed sender key to new member {}", member_hex),
                                        Err(e) => error!("member_joined: failed to send distribution: {}", e),
                                    }
                                }
                                Err(e) => {
                                    error!("member_joined: failed to serialize distribution message: {}", e);
                                }
                            }
                        } else {
                            error!("member_joined: no identity loaded");
                        }
                    } else {
                        error!("member_joined: no connection available");
                    }
                } else {
                    // No group session exists yet — create one now and distribute
                    info!("member_joined: no group session for channel {} — creating one and distributing",
                        &channel_hex[..16.min(channel_hex.len())]);
                    
                    let identity_guard = app_state.identity.read().await;
                    if let Some(identity) = identity_guard.as_ref() {
                        let my_pubkey = identity.public_signing_key().as_bytes().to_vec();
                        let my_x25519_pub = identity.public_encryption_key().as_bytes().to_vec();
                        let encryption_key = identity.encryption.clone();
                        let my_pubkey_hex = hex::encode(&my_pubkey);
                        drop(identity_guard);
                        
                        let channel_id_bytes = channel_id.clone();
                        let (new_session, my_dist) = mobium_shared::sender_keys::GroupSession::new(&channel_id_bytes, &my_pubkey);
                        
                        // Persist our chain to DB
                        let (chain_key, key_id, iteration) = new_session.my_chain_state();
                        let _ = db::save_sender_key(
                            &app_state, &channel_hex, &my_pubkey_hex,
                            key_id, chain_key, iteration, true,
                        ).await;
                        
                        // Store session
                        {
                            let mut sessions = app_state.group_sessions.write().await;
                            sessions.insert(channel_hex.clone(), new_session);
                        }
                        
                        // Now distribute to the new member
                        let dist_bytes = match serde_json::to_vec(&my_dist) {
                            Ok(b) => b,
                            Err(e) => {
                                error!("member_joined: failed to serialize new distribution: {}", e);
                                return Ok(());
                            }
                        };
                        
                        // Look up the new member's actual X25519 public key
                        let recipient_x25519 = {
                            let x25519_guard = app_state.x25519_keys.read().await;
                            match x25519_guard.get(&new_member) {
                                Some(bytes) if bytes.len() == 32 => {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(bytes);
                                    x25519_dalek::PublicKey::from(arr)
                                }
                                _ => {
                                    info!("member_joined: no X25519 key for new member — storing dist as pending and requesting members");
                                    let mut pending = app_state.pending_distributions.write().await;
                                    pending.insert(channel_hex.clone(), my_dist);
                                    let conn_guard2 = app_state.connection.read().await;
                                    if let Some(conn2) = conn_guard2.as_ref() {
                                        let msg = rmp_serde::to_vec_named(&serde_json::json!({
                                            "type": "get_members",
                                            "channel_id": channel_id.clone(),
                                        }));
                                        if let Ok(data) = msg {
                                            let _ = conn2.send(data).await;
                                        }
                                    }
                                    return Ok(());
                                }
                            }
                        };
                        
                        let encrypted = match mobium_shared::encrypt_for_recipient(
                            &encryption_key,
                            &recipient_x25519,
                            &dist_bytes,
                            &channel_id_bytes,
                        ) {
                            Ok(enc) => enc,
                            Err(e) => {
                                error!("member_joined: failed to encrypt dist: {}", e);
                                return Ok(());
                            }
                        };
                        
                        let x25519_bytes = my_x25519_pub.clone();
                        let conn_guard = app_state.connection.read().await;
                        if let Some(conn) = conn_guard.as_ref() {
                            let msg = rmp_serde::to_vec_named(&serde_json::json!({
                                "type": "sender_key_distribution",
                                "channel_id": channel_id_bytes,
                                "sender_x25519_pub": x25519_bytes,
                                "distributions": [
                                    {
                                        "recipient": new_member,
                                        "encrypted_dist": encrypted,
                                    }
                                ],
                            }));
                            match msg {
                                Ok(data) => {
                                    match conn.send(data).await {
                                        Ok(_) => info!("member_joined: created session and distributed key to new member {}", member_hex),
                                        Err(e) => error!("member_joined: failed to send distribution: {}", e),
                                    }
                                }
                                Err(e) => {
                                    error!("member_joined: failed to serialize distribution message: {}", e);
                                }
                            }
                        } else {
                            error!("member_joined: no connection available");
                        }
                    } else {
                        error!("member_joined: no identity loaded");
                    }
                }
            }
        }
        
        "member_left" => {
            // A member left a channel — rotate our sender key for forward secrecy.
            // The departed member must NOT be able to decrypt future messages.
            let channel_id = extract_byte_array(&msg, "channel_id");
            let departed = extract_byte_array(&msg, "member");
            
            if let (Some(channel_id), Some(departed)) = (channel_id, departed) {
                let channel_hex = hex::encode(&channel_id);
                let departed_hex = hex::encode(&departed[..8.min(departed.len())]);
                info!("Member {} left channel {} — rotating sender keys for forward secrecy",
                    departed_hex, &channel_hex[..16.min(channel_hex.len())]);
                
                // Remove departed from cached member list
                {
                    let mut members_guard = app_state.channel_members.write().await;
                    if let Some(members) = members_guard.get_mut(&channel_hex) {
                        members.retain(|pk| *pk != departed);
                    }
                }
                
                // Destroy the old group session (invalidates departed member's sender key)
                {
                    let mut sessions = app_state.group_sessions.write().await;
                    sessions.remove(&channel_hex);
                }
                
                // Delete old sender keys from DB
                let _ = db::delete_sender_keys_for_channel(&app_state, &channel_hex).await;
                
                // Create a brand new group session with fresh sender keys
                let identity_guard = app_state.identity.read().await;
                if let Some(identity) = identity_guard.as_ref() {
                    let my_pubkey = identity.public_signing_key().as_bytes().to_vec();
                    let my_pubkey_hex = hex::encode(&my_pubkey);
                    drop(identity_guard);
                    
                    let (new_session, new_dist) = mobium_shared::sender_keys::GroupSession::new(&channel_id, &my_pubkey);
                    
                    // Persist new chain
                    let (chain_key, key_id, iteration) = new_session.my_chain_state();
                    let _ = db::save_sender_key(
                        &app_state, &channel_hex, &my_pubkey_hex,
                        key_id, chain_key, iteration, true,
                    ).await;
                    
                    {
                        let mut sessions = app_state.group_sessions.write().await;
                        sessions.insert(channel_hex.clone(), new_session);
                    }
                    
                    // Distribute new sender key to remaining members
                    let members = {
                        let members_guard = app_state.channel_members.read().await;
                        members_guard.get(&channel_hex).cloned().unwrap_or_default()
                    };
                    
                    if !members.is_empty() {
                        let conn_guard = app_state.connection.read().await;
                        if let Some(conn) = conn_guard.as_ref() {
                            // Use send_encrypted_distribution pattern inline
                            let identity_guard2 = app_state.identity.read().await;
                            if let Some(identity2) = identity_guard2.as_ref() {
                                let my_x25519_pub = identity2.public_encryption_key();
                                let encryption_key = &identity2.encryption;
                                let dist_bytes = match serde_json::to_vec(&new_dist) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        error!("member_left: failed to serialize distribution: {}", e);
                                        return Ok(());
                                    }
                                };
                                
                                let x25519_guard = app_state.x25519_keys.read().await;
                                let mut distributions = Vec::new();
                                for member_pk in &members {
                                    if *member_pk == my_pubkey { continue; }
                                    let recipient_x25519 = match x25519_guard.get(member_pk) {
                                        Some(bytes) if bytes.len() == 32 => {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(bytes);
                                            x25519_dalek::PublicKey::from(arr)
                                        }
                                        _ => continue,
                                    };
                                    let encrypted = match mobium_shared::encrypt_for_recipient(
                                        encryption_key, &recipient_x25519, &dist_bytes, &channel_id,
                                    ) {
                                        Ok(enc) => enc,
                                        Err(_) => continue,
                                    };
                                    distributions.push(serde_json::json!({
                                        "recipient": member_pk,
                                        "encrypted_dist": encrypted,
                                    }));
                                }
                                drop(x25519_guard);
                                drop(identity_guard2);
                                
                                if !distributions.is_empty() {
                                    let msg = rmp_serde::to_vec_named(&serde_json::json!({
                                        "type": "sender_key_distribution",
                                        "channel_id": &channel_id,
                                        "sender_x25519_pub": my_x25519_pub.as_bytes().to_vec(),
                                        "distributions": distributions,
                                    }));
                                    if let Ok(data) = msg {
                                        let _ = conn.send(data).await;
                                        info!("member_left: rotated and distributed new sender key to {} members",
                                            distributions.len());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        "channel_left" => {
            // Confirmation that we left a channel
            let channel_id = extract_byte_array(&msg, "channel_id");
            if let Some(channel_id) = channel_id {
                let channel_hex = hex::encode(&channel_id);
                info!("Confirmed: left channel {}", &channel_hex[..16.min(channel_hex.len())]);
            }
        }
        
        "voice_signal" => {
            // Voice signaling: WebRTC SDP/ICE relayed through the server.
            // The payload is opaque to the server (E2E encrypted by the caller).
            let sender = extract_byte_array(&msg, "sender");
            let signal_type = msg.get("signal_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let payload = extract_byte_array(&msg, "payload")
                .unwrap_or_default();
            
            if let Some(sender) = sender {
                let sender_hex = hex::encode(&sender);
                info!("Received voice signal '{}' from {}", 
                    signal_type, &sender_hex[..16.min(sender_hex.len())]);
                
                // Buffer for frontend polling (Tauri 2 event bus is unreliable
                // for events emitted from spawned async tasks).
                {
                    let mut pending = app_state.pending_voice_signals.write().await;
                    pending.push((sender_hex.clone(), signal_type.clone(), payload.clone()));
                }
                
                // Also emit Tauri event as a best-effort fast path
                let _ = app.emit("voice_signal", VoiceSignalEvent {
                    sender: sender_hex,
                    signal_type,
                    payload,
                });
            }
        }
        
        "voice_data" => {
            // Incoming encrypted audio frame from a voice channel participant.
            // Decrypt with Sender Key, then buffer for frontend polling at 20ms intervals.
            let channel_id = extract_byte_array(&msg, "channel_id");
            let sender = extract_byte_array(&msg, "sender");
            let encrypted_audio = extract_byte_array(&msg, "audio");
            let seq = msg.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
            
            if let (Some(channel_id), Some(sender), Some(encrypted)) = (channel_id, sender, encrypted_audio) {
                let channel_hex = hex::encode(&channel_id);
                let sender_hex = hex::encode(&sender);
                
                // Decrypt with the channel's stable voice key (does NOT advance text ratchet)
                let decrypted = {
                    let sessions = app_state.group_sessions.read().await;
                    if let Some(session) = sessions.get(&channel_hex) {
                        match session.voice_decrypt(&sender, &encrypted, channel_hex.as_bytes()) {
                            Ok(audio) => Some(audio),
                            Err(e) => {
                                // Non-fatal: log and skip this frame (common during key exchange)
                                debug!("Voice decrypt failed from {}: {}", &sender_hex[..16.min(sender_hex.len())], e);
                                None
                            }
                        }
                    } else {
                        debug!("No group session for voice channel {} — dropping audio frame", &channel_hex[..16.min(channel_hex.len())]);
                        None
                    }
                };
                
                if let Some(audio) = decrypted {
                    let mut pending = app_state.pending_voice_data.write().await;
                    // Cap at 50 frames (~1s at 50fps) to prevent memory buildup
                    // if the frontend stops polling. Oldest frames are dropped.
                    if pending.len() >= 50 {
                        pending.drain(..10); // drop oldest 10 frames
                    }
                    pending.push((sender_hex, audio, seq));
                }
            }
        }
        
        "screen_data" => {
            // Incoming encrypted screen share chunk from a voice channel participant.
            // Decrypt with Sender Key, then buffer for frontend polling.
            let channel_id = extract_byte_array(&msg, "channel_id");
            let sender = extract_byte_array(&msg, "sender");
            let encrypted_chunk = extract_byte_array(&msg, "chunk");
            let seq = msg.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
            
            if let (Some(channel_id), Some(sender), Some(encrypted)) = (channel_id, sender, encrypted_chunk) {
                let channel_hex = hex::encode(&channel_id);
                let sender_hex = hex::encode(&sender);
                
                // Decrypt with the channel's stable voice key (same key as audio)
                let decrypted = {
                    let sessions = app_state.group_sessions.read().await;
                    if let Some(session) = sessions.get(&channel_hex) {
                        match session.voice_decrypt(&sender, &encrypted, channel_hex.as_bytes()) {
                            Ok(chunk) => Some(chunk),
                            Err(e) => {
                                debug!("Screen decrypt failed from {}: {}", &sender_hex[..16.min(sender_hex.len())], e);
                                None
                            }
                        }
                    } else {
                        debug!("No group session for screen channel {} — dropping chunk", &channel_hex[..16.min(channel_hex.len())]);
                        None
                    }
                };
                
                if let Some(chunk) = decrypted {
                    // Track who is sharing
                    {
                        let mut sharer = app_state.screen_sharer.write().await;
                        *sharer = Some(sender_hex.clone());
                    }
                    
                    let mut pending = app_state.pending_screen_data.write().await;
                    // Cap at 200 chunks. Higher quality presets produce fewer but
                    // larger chunks (500ms-1s timeslice), so we need room for
                    // ~30-60s of buffered data to prevent losing the WebM init
                    // segment that medium/high quality streams need.
                    if pending.len() >= 200 {
                        pending.drain(..50); // drop oldest 50 chunks
                    }
                    pending.push((sender_hex, chunk, seq));
                }
            }
        }
        
        "voice_joined" => {
            // A user joined a voice channel we're in
            let channel_id = extract_byte_array(&msg, "channel_id");
            let pubkey = extract_byte_array(&msg, "pubkey");
            
            if let (Some(channel_id), Some(pubkey)) = (channel_id, pubkey) {
                let channel_hex = hex::encode(&channel_id);
                let pubkey_hex = hex::encode(&pubkey);
                info!("Voice: {} joined channel {}", &pubkey_hex[..16.min(pubkey_hex.len())], &channel_hex[..16.min(channel_hex.len())]);
                
                let event = serde_json::json!({
                    "type": "voice_joined",
                    "channel_id": channel_hex,
                    "pubkey": pubkey_hex,
                }).to_string();
                let mut pending = app_state.pending_voice_events.write().await;
                pending.push(event);
            }
        }
        
        "voice_left" => {
            // A user left a voice channel we're in
            let channel_id = extract_byte_array(&msg, "channel_id");
            let pubkey = extract_byte_array(&msg, "pubkey");
            
            if let (Some(channel_id), Some(pubkey)) = (channel_id, pubkey) {
                let channel_hex = hex::encode(&channel_id);
                let pubkey_hex = hex::encode(&pubkey);
                info!("Voice: {} left channel {}", &pubkey_hex[..16.min(pubkey_hex.len())], &channel_hex[..16.min(channel_hex.len())]);
                
                let event = serde_json::json!({
                    "type": "voice_left",
                    "channel_id": channel_hex,
                    "pubkey": pubkey_hex,
                }).to_string();
                let mut pending = app_state.pending_voice_events.write().await;
                pending.push(event);
            }
        }
        
        "voice_state" => {
            // Full participant list for a voice channel (sent on join)
            let channel_id = extract_byte_array(&msg, "channel_id");
            let participants = msg.get("participants").and_then(|v| v.as_array());
            
            if let (Some(channel_id), Some(participants)) = (channel_id, participants) {
                let channel_hex = hex::encode(&channel_id);
                let participant_hexes: Vec<String> = participants.iter()
                    .filter_map(|p| {
                        p.as_array().map(|arr| {
                            hex::encode(arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<u8>>())
                        })
                    })
                    .collect();
                
                info!("Voice state for channel {}: {} participants", 
                    &channel_hex[..16.min(channel_hex.len())], participant_hexes.len());
                
                let event = serde_json::json!({
                    "type": "voice_state",
                    "channel_id": channel_hex,
                    "participants": participant_hexes,
                }).to_string();
                let mut pending = app_state.pending_voice_events.write().await;
                pending.push(event);
            }
        }
        
        "prekey_bundle_response" => {
            // Server returned a pre-key bundle for a user we requested.
            // Deliver it to the waiting oneshot channel in Connection.
            info!("Received prekey_bundle_response");
            let conn_guard = app_state.connection.read().await;
            if let Some(conn) = conn_guard.as_ref() {
                conn.deliver_prekey_response(msg.clone()).await;
            }
        }
        
        "ice_config" => {
            info!("Received ICE config from server");
            let conn_guard = app_state.connection.read().await;
            if let Some(conn) = conn_guard.as_ref() {
                conn.deliver_ice_config_response(msg.clone()).await;
            }
        }

        "prekeys_stored" => {
            info!("Server confirmed pre-keys stored");
        }

        "prekey_count_response" => {
            // Server reports how many OTPKs it still has for us.
            // If below the replenishment threshold, generate and upload more.
            const REPLENISH_THRESHOLD: usize = 5;
            const REPLENISH_BATCH: usize = 10;

            let count = msg.get("count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            info!("Server has {} OTPKs remaining for us", count);

            if count < REPLENISH_THRESHOLD {
                info!("OTPK count {} < {}, replenishing with {} new keys",
                    count, REPLENISH_THRESHOLD, REPLENISH_BATCH);

                let app_clone = app.clone();
                tauri::async_runtime::spawn(async move {
                    let st = app_clone.state::<AppState>();

                    // We need our identity to sign and our connection to send
                    let identity = {
                        let g = st.identity.read().await;
                        match g.as_ref() { Some(id) => id.clone(), None => return }
                    };
                    let conn = {
                        let g = st.connection.read().await;
                        match g.as_ref() { Some(c) => c.clone(), None => return }
                    };

                    // Generate fresh OTPKs
                    let mut new_otpk_secrets = Vec::with_capacity(REPLENISH_BATCH);
                    let mut new_otpk_pubs = Vec::with_capacity(REPLENISH_BATCH);
                    for _ in 0..REPLENISH_BATCH {
                        let sk = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
                        let pk = x25519_dalek::PublicKey::from(&sk);
                        new_otpk_pubs.push(pk);
                        new_otpk_secrets.push(sk);
                    }

                    // Append to our in-memory pre-key store
                    {
                        let mut guard = st.our_prekeys.write().await;
                        if let Some(ref mut pks) = *guard {
                            pks.one_time_pre_keys.extend(new_otpk_secrets.iter().map(|sk| {
                                let bytes = sk.to_bytes();
                                x25519_dalek::StaticSecret::from(bytes)
                            }));
                        }
                    }

                    // Persist the full updated material to local DB
                    let spk_bytes = {
                        let g = st.our_spk_bytes.read().await;
                        match *g { Some(b) => b, None => return }
                    };
                    let all_otpk_bytes: Vec<Vec<u8>> = {
                        let g = st.our_prekeys.read().await;
                        match g.as_ref() {
                            Some(pks) => pks.one_time_pre_keys.iter()
                                .map(|sk| sk.to_bytes().to_vec())
                                .collect(),
                            None => return,
                        }
                    };
                    if let Err(e) = db::save_prekey_material(&st, &spk_bytes, &all_otpk_bytes).await {
                        error!("replenish prekeys: failed to save material: {}", e);
                    }

                    // Build the full bundle to re-publish (server replaces
                    // the entire set, not appends)
                    let signed_prekey_pub = {
                        let g = st.our_prekeys.read().await;
                        match g.as_ref() {
                            Some(pks) => x25519_dalek::PublicKey::from(&pks.signed_pre_key),
                            None => return,
                        }
                    };
                    let sig = identity.sign(signed_prekey_pub.as_bytes());
                    let all_otpk_pub: Vec<Vec<u8>> = {
                        let g = st.our_prekeys.read().await;
                        match g.as_ref() {
                            Some(pks) => pks.one_time_pre_keys.iter()
                                .map(|sk| x25519_dalek::PublicKey::from(sk).as_bytes().to_vec())
                                .collect(),
                            None => return,
                        }
                    };
                    let otpk_blob = match rmp_serde::to_vec(&all_otpk_pub) {
                        Ok(b) => b,
                        Err(e) => { error!("replenish prekeys: serialize error: {}", e); return; }
                    };

                    let msg = rmp_serde::to_vec_named(&serde_json::json!({
                        "type": "publish_prekeys",
                        "identity_x25519_pub": identity.public_encryption_key().as_bytes().to_vec(),
                        "signed_prekey": signed_prekey_pub.as_bytes().to_vec(),
                        "signed_prekey_sig": sig.to_bytes().to_vec(),
                        "one_time_prekeys": otpk_blob,
                    }));
                    match msg {
                        Ok(data) => {
                            match conn.send(data).await {
                                Ok(_) => info!("replenish prekeys: published {} new OTPKs (total {})",
                                    REPLENISH_BATCH, all_otpk_pub.len()),
                                Err(e) => error!("replenish prekeys: send failed: {}", e),
                            }
                        }
                        Err(e) => error!("replenish prekeys: serialization error: {}", e),
                    }
                });
            }
        }
        
        "channel_created" => {
            let channel_id = extract_byte_array(&msg, "channel_id");
            if let Some(channel_id) = channel_id {
                let channel_hex = hex::encode(&channel_id);
                info!("Channel created: {}", &channel_hex[..16.min(channel_hex.len())]);
                let _ = app.emit("channel_created", ChannelCreatedEvent { channel_id: channel_hex });
            }
        }
        
        "channel_joined" => {
            let channel_id = extract_byte_array(&msg, "channel_id");
            if let Some(channel_id) = channel_id {
                let channel_hex = hex::encode(&channel_id);
                info!("Joined channel: {}", &channel_hex[..16.min(channel_hex.len())]);
                let _ = app.emit("channel_joined", ChannelJoinedEvent { channel_id: channel_hex });
            }
        }
        
        "ack" => {
            debug!("Message acknowledged by server");
        }
        
        "error" => {
            let error_msg = msg.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            error!("Server error: {}", error_msg);
            let _ = app.emit("server_error", ServerErrorEvent { message: error_msg.to_string() });
        }
        
        _ => {
            debug!("Unknown message type: {}", msg_type);
        }
    }
    
    Ok(())
}

/// Helper: persist a ratchet session to the DB (called from the websocket handler context).
async fn persist_ratchet_session_ws(state: &AppState, peer_pubkey: &str) {
    let sessions = state.ratchet_sessions.read().await;
    let ad_map = state.ratchet_ad.read().await;
    if let (Some(ratchet), Some(ad)) = (sessions.get(peer_pubkey), ad_map.get(peer_pubkey)) {
        match ratchet.save() {
            Ok(ratchet_bytes) => {
                if let Err(e) = db::save_ratchet_session(state, peer_pubkey, &ratchet_bytes, ad).await {
                    error!("Failed to persist ratchet session for {}: {}", &peer_pubkey[..16.min(peer_pubkey.len())], e);
                }
            }
            Err(e) => {
                error!("Failed to serialize ratchet for {}: {}", &peer_pubkey[..16.min(peer_pubkey.len())], e);
            }
        }
    }
}

/// Helper: extract a byte array from a MessagePack-decoded JSON value
fn extract_byte_array(msg: &serde_json::Value, field: &str) -> Option<Vec<u8>> {
    extract_byte_array_from_value(msg.get(field))
}

/// Helper: extract a byte array from an optional JSON value
fn extract_byte_array_from_value(value: Option<&serde_json::Value>) -> Option<Vec<u8>> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<u8>>())
}
