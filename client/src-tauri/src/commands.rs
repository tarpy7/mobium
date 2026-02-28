//! Tauri command handlers

use tauri::State;
use serde::Serialize;
use crate::state::AppState;
use crate::crypto::SecureStorage;
use crate::db;
use crate::db_crypto;
use mobium_shared::ratchet::DoubleRatchet;
use mobium_shared::sender_keys::{GroupSession, SenderKeyDistribution};
use mobium_shared::x3dh;
use x25519_dalek;


/// Get a SecureStorage pointing at the active profile directory.
async fn storage_for_profile(state: &AppState) -> anyhow::Result<SecureStorage> {
    let dir = crate::mobium_profile_dir(state).await?;
    Ok(SecureStorage::with_dir(dir))
}

// ─── Profile Management ─────────────────────────────────────────────────────

/// List available profiles (subdirectories of the data directory that contain
/// an identity.enc file, plus any empty subdirectories created by create_profile).
#[tauri::command]
pub async fn list_profiles() -> Result<Vec<String>, String> {
    let base = crate::mobium_data_dir().map_err(|e| e.to_string())?;
    
    let mut profiles = Vec::new();
    
    // Check for legacy profile (identity.enc directly in base dir)
    if base.join("identity.enc").exists() {
        profiles.push("Default".to_string());
    }
    
    // Scan subdirectories
    if let Ok(mut entries) = tokio::fs::read_dir(&base).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(ft) = entry.file_type().await {
                if ft.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        profiles.push(name.to_string());
                    }
                }
            }
        }
    }
    
    Ok(profiles)
}

/// Select (activate) a profile. This sets the active profile name in AppState.
/// All subsequent operations (has_identity, unlock, generate, etc.) will use
/// this profile's data directory.
#[tauri::command]
pub async fn select_profile(profile_name: String, state: State<'_, AppState>) -> Result<(), String> {
    let base = crate::mobium_data_dir().map_err(|e| e.to_string())?;
    
    // "Default" is the legacy profile in the base directory
    if profile_name == "Default" {
        let mut guard = state.active_profile.write().await;
        *guard = None; // None = use base dir (legacy)
        return Ok(());
    }
    
    // Ensure the profile directory exists
    let profile_dir = base.join(&profile_name);
    tokio::fs::create_dir_all(&profile_dir).await.map_err(|e| e.to_string())?;
    
    let mut guard = state.active_profile.write().await;
    *guard = Some(profile_name);
    Ok(())
}

/// Create a new profile directory.
#[tauri::command]
pub async fn create_profile(profile_name: String, state: State<'_, AppState>) -> Result<(), String> {
    if profile_name.is_empty() || profile_name == "Default" {
        return Err("Invalid profile name".to_string());
    }
    
    // Sanitize: only allow alphanumeric, spaces, dashes, underscores
    if !profile_name.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_') {
        return Err("Profile name may only contain letters, numbers, spaces, dashes, and underscores".to_string());
    }
    
    let base = crate::mobium_data_dir().map_err(|e| e.to_string())?;
    let profile_dir = base.join(&profile_name);
    
    if profile_dir.exists() {
        return Err("Profile already exists".to_string());
    }
    
    tokio::fs::create_dir_all(&profile_dir).await.map_err(|e| e.to_string())?;
    
    // Auto-select the new profile
    let mut guard = state.active_profile.write().await;
    *guard = Some(profile_name);
    
    Ok(())
}

/// Get the currently active profile name.
#[tauri::command]
pub async fn get_active_profile(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let guard = state.active_profile.read().await;
    match guard.as_ref() {
        Some(name) => Ok(Some(name.clone())),
        None => Ok(None), // Legacy/Default
    }
}

// ─── Identity Management ────────────────────────────────────────────────────

/// Generate a new identity
#[tauri::command]
pub async fn generate_identity(password: String, state: State<'_, AppState>) -> Result<String, String> {
    match _generate_identity(password, state).await {
        Ok(mnemonic) => Ok(mnemonic),
        Err(e) => Err(e.to_string()),
    }
}

async fn _generate_identity(password: String, state: State<'_, AppState>) -> anyhow::Result<String> {
    // Generate identity key
    let identity = mobium_shared::generate_identity();
    
    // Generate mnemonic
    let mnemonic = mobium_shared::recovery::generate_mnemonic()
        .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {}", e))?;
    
    // Derive seed from mnemonic
    let _seed = mobium_shared::recovery::mnemonic_to_seed(&mnemonic, None)
        .map_err(|e| anyhow::anyhow!("Failed to derive seed: {}", e))?;
    
    // Store identity securely
    let storage = storage_for_profile(&state).await?;
    storage.store_identity(&identity, &password).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    
    // Store mnemonic hash for verification
    storage.store_mnemonic_hash(&mnemonic).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    
    // Update state
    let mut identity_guard = state.identity.write().await;
    *identity_guard = Some(std::sync::Arc::new(identity));
    drop(identity_guard);
    
    // Derive and store DB encryption key
    let db_key = db_crypto::derive_db_key(&password);
    let mut key_guard = state.db_key.write().await;
    *key_guard = Some(db_key);
    drop(key_guard);
    
    // Initialize database
    let profile_dir = crate::mobium_profile_dir(&state).await?;
    let db_pool = db::init(&profile_dir).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut db_guard = state.db.write().await;
    *db_guard = Some(db_pool);
    
    Ok(mnemonic)
}

/// Export the mnemonic phrase for backup
#[tauri::command]
pub async fn export_mnemonic(state: State<'_, AppState>) -> Result<String, String> {
    match _export_mnemonic(state).await {
        Ok(mnemonic) => Ok(mnemonic),
        Err(e) => Err(e.to_string()),
    }
}

async fn _export_mnemonic(state: State<'_, AppState>) -> anyhow::Result<String> {
    // Check if identity exists
    let identity_guard = state.identity.read().await;
    if identity_guard.is_none() {
        return Err(anyhow::anyhow!("No identity found"));
    }
    drop(identity_guard);
    
    // Retrieve mnemonic from secure storage
    let storage = storage_for_profile(&state).await?;
    storage.get_mnemonic().await.map_err(|e| anyhow::anyhow!("{}", e))
}

/// Import identity from mnemonic
#[tauri::command]
pub async fn import_mnemonic(
    mnemonic: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    match _import_mnemonic(mnemonic, password, state).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

async fn _import_mnemonic(
    mnemonic: String,
    password: String,
    state: State<'_, AppState>,
) -> anyhow::Result<()> {
    // Validate mnemonic
    mobium_shared::recovery::validate_mnemonic(&mnemonic)
        .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;
    
    // Derive seed from mnemonic
    let bip39_seed = mobium_shared::recovery::mnemonic_to_seed(&mnemonic, None)
        .map_err(|e| anyhow::anyhow!("Failed to derive seed: {}", e))?;
    
    // Derive 32-byte identity seed from the 64-byte BIP39 seed
    let identity_seed = mobium_shared::recovery::derive_identity_seed(&bip39_seed)
        .map_err(|e| anyhow::anyhow!("Failed to derive identity seed: {}", e))?;
    
    // Generate identity deterministically from seed
    let identity = mobium_shared::identity_from_seed(&identity_seed);
    
    // Store identity
    let storage = storage_for_profile(&state).await?;
    storage.store_identity(&identity, &password).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    storage.store_mnemonic_hash(&mnemonic).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    
    // Update state
    let mut identity_guard = state.identity.write().await;
    *identity_guard = Some(std::sync::Arc::new(identity));
    drop(identity_guard);
    
    // Derive and store DB encryption key
    let db_key = db_crypto::derive_db_key(&password);
    let mut key_guard = state.db_key.write().await;
    *key_guard = Some(db_key);
    drop(key_guard);
    
    // Initialize database
    let profile_dir = crate::mobium_profile_dir(&state).await?;
    let db_pool = db::init(&profile_dir).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut db_guard = state.db.write().await;
    *db_guard = Some(db_pool);
    
    Ok(())
}

/// Check if identity exists
#[tauri::command]
pub async fn has_identity(state: State<'_, AppState>) -> Result<bool, String> {
    let storage = match storage_for_profile(&state).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("has_identity: storage_for_profile failed: {}", e);
            return Ok(false);
        }
    };
    
    match storage.has_identity().await {
        Ok(has) => {
            tracing::info!("has_identity: returning {}", has);
            Ok(has)
        }
        Err(e) => {
            tracing::error!("has_identity: check failed: {}", e);
            Ok(false)
        }
    }
}

/// Unlock an existing identity with a password
///
/// Decrypts the stored identity from OS keychain or file,
/// loads it into AppState, and initializes the client database.
#[tauri::command]
pub async fn unlock_identity(password: String, state: State<'_, AppState>) -> Result<(), String> {
    match _unlock_identity(password, state).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

async fn _unlock_identity(password: String, state: State<'_, AppState>) -> anyhow::Result<()> {
    let storage = storage_for_profile(&state).await?;
    
    // Decrypt identity from storage
    let identity = storage.load_identity(&password).await
        .map_err(|e| anyhow::anyhow!("Failed to unlock identity: {}", e))?;
    
    // Store in app state
    let mut identity_guard = state.identity.write().await;
    *identity_guard = Some(std::sync::Arc::new(identity));
    drop(identity_guard);
    
    // Derive and store DB encryption key
    let db_key = db_crypto::derive_db_key(&password);
    let mut key_guard = state.db_key.write().await;
    *key_guard = Some(db_key);
    drop(key_guard);
    
    // Initialize database
    let profile_dir = crate::mobium_profile_dir(&state).await?;
    let db_pool = db::init(&profile_dir).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut db_guard = state.db.write().await;
    *db_guard = Some(db_pool);
    
    Ok(())
}

/// Get the current user's public key (hex-encoded)
#[tauri::command]
pub async fn get_pubkey(state: State<'_, AppState>) -> Result<String, String> {
    let identity_guard = state.identity.read().await;
    match identity_guard.as_ref() {
        Some(identity) => Ok(hex::encode(identity.public_signing_key().as_bytes())),
        None => Err("No identity loaded".to_string()),
    }
}

/// Connect to server
#[tauri::command]
pub async fn connect_server(
    server_url: String,
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    match crate::websocket::connect(server_url, app_handle, state).await {
        Ok(_) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Disconnect from server
#[tauri::command]
pub async fn disconnect_server(state: State<'_, AppState>) -> Result<(), String> {
    let mut conn_guard = state.connection.write().await;
    *conn_guard = None;
    Ok(())
}

/// Get connection status
#[tauri::command]
pub async fn get_connection_status(state: State<'_, AppState>) -> Result<bool, String> {
    let conn_guard = state.connection.read().await;
    Ok(conn_guard.is_some())
}

/// Send a direct message (DM) to a peer using X3DH + Double Ratchet.
///
/// The `recipient` is the peer's Ed25519 public key (hex).
/// If no ratchet session exists, we fetch the recipient's pre-key bundle
/// from the server, perform X3DH, initialise a Double Ratchet, and send
/// the first message with the X3DH handshake data included.
#[tauri::command]
pub async fn send_message(
    recipient: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    tracing::info!("send_message (DM) called: recipient={}, content_len={}", &recipient[..16.min(recipient.len())], content.len());

    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let recipient_bytes = hex::decode(&recipient)
        .map_err(|_| "Invalid recipient pubkey hex".to_string())?;

    // Check if we have an existing ratchet session
    let has_session = {
        let sessions = state.ratchet_sessions.read().await;
        sessions.contains_key(&recipient)
    };

    if has_session {
        // Encrypt with existing ratchet session
        let (header, ciphertext) = {
            let mut sessions = state.ratchet_sessions.write().await;
            let ratchet = sessions.get_mut(&recipient)
                .ok_or_else(|| "Session disappeared".to_string())?;
            let ad_guard = state.ratchet_ad.read().await;
            let ad = ad_guard.get(&recipient)
                .ok_or_else(|| "Missing associated data for ratchet session".to_string())?;
            ratchet.encrypt(content.as_bytes(), ad)
                .map_err(|e| format!("Ratchet encrypt failed: {}", e))?
        };

        // Build subsequent-message DM payload
        let dm_payload = rmp_serde::to_vec_named(&serde_json::json!({
            "dm_type": "ratchet",
            "header": header.to_bytes().to_vec(),
            "ciphertext": ciphertext,
        })).map_err(|e| format!("Serialization error: {}", e))?;

        // Send via server
        let msg = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "message",
            "recipient": recipient_bytes,
            "payload": dm_payload,
        })).map_err(|e| format!("Serialization error: {}", e))?;
        conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

        // Persist ratchet state
        persist_ratchet_session(&state, &recipient).await;
    } else {
        // No session — need to perform X3DH first.
        // Request the recipient's pre-key bundle from the server (synchronous-ish via oneshot).
        // Since our WS handler is async, we'll fetch the bundle via a direct request-response.
        let bundle_response = request_prekey_bundle(&conn, &recipient_bytes).await?;

        // Parse the bundle response
        let identity_x25519_bytes: Vec<u8> = bundle_response.get("identity_x25519_pub")
            .and_then(|v| extract_byte_array_from_json(v))
            .ok_or_else(|| "Missing identity_x25519_pub in bundle response".to_string())?;
        let signed_prekey_bytes: Vec<u8> = bundle_response.get("signed_prekey")
            .and_then(|v| extract_byte_array_from_json(v))
            .ok_or_else(|| "Missing signed_prekey in bundle response".to_string())?;
        let signed_prekey_sig_bytes: Vec<u8> = bundle_response.get("signed_prekey_sig")
            .and_then(|v| extract_byte_array_from_json(v))
            .ok_or_else(|| "Missing signed_prekey_sig in bundle response".to_string())?;
        let one_time_prekey_bytes: Option<Vec<u8>> = bundle_response.get("one_time_prekey")
            .and_then(|v| {
                if v.is_null() { None } else { extract_byte_array_from_json(v) }
            });

        // Construct the PreKeyBundle
        let their_identity_key = ed25519_dalek::VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(recipient_bytes.as_slice())
                .map_err(|_| "Invalid recipient pubkey length")?
        ).map_err(|_| "Invalid recipient Ed25519 key")?;

        let their_identity_x25519 = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(identity_x25519_bytes.as_slice())
                .map_err(|_| "Invalid X25519 key length")?
        );

        let their_signed_prekey = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(signed_prekey_bytes.as_slice())
                .map_err(|_| "Invalid signed prekey length")?
        );

        let their_sig = ed25519_dalek::Signature::from_bytes(
            &<[u8; 64]>::try_from(signed_prekey_sig_bytes.as_slice())
                .map_err(|_| "Invalid signature length")?
        );

        let mut one_time_prekeys = Vec::new();
        let otpk_index = if let Some(ref otpk_bytes) = one_time_prekey_bytes {
            one_time_prekeys.push(x25519_dalek::PublicKey::from(
                <[u8; 32]>::try_from(otpk_bytes.as_slice())
                    .map_err(|_| "Invalid OPK length")?
            ));
            Some(0usize)
        } else {
            None
        };

        let their_bundle = x3dh::PreKeyBundle {
            identity_key: their_identity_key,
            identity_encryption_key: their_identity_x25519,
            signed_pre_key: their_signed_prekey,
            signed_pre_key_signature: their_sig,
            one_time_pre_keys: one_time_prekeys,
        };

        // Get our identity
        let identity = {
            let guard = state.identity.read().await;
            guard.as_ref().ok_or_else(|| "No identity loaded".to_string())?.clone()
        };

        // Perform X3DH initiator
        let (handshake, ephemeral_pub) = x3dh::X3DHHandshake::initiator(
            &identity,
            &their_bundle,
            otpk_index,
        ).map_err(|e| format!("X3DH failed: {}", e))?;

        let shared_secret = handshake.shared_secret();
        let ad = handshake.associated_data().to_vec();

        // Initialise Double Ratchet as Alice (initiator)
        let mut ratchet = DoubleRatchet::init_alice(shared_secret, &their_signed_prekey)
            .map_err(|e| format!("Ratchet init failed: {}", e))?;

        // Encrypt the first message
        let (header, ciphertext) = ratchet.encrypt(content.as_bytes(), &ad)
            .map_err(|e| format!("Ratchet encrypt failed: {}", e))?;

        // Build X3DH initial DM payload
        // Include our X25519 identity key so the receiver can complete X3DH
        // without depending on the channel members_with_keys cache.
        let our_x25519_pub = identity.public_encryption_key();
        let dm_payload = rmp_serde::to_vec_named(&serde_json::json!({
            "dm_type": "x3dh_init",
            "ephemeral_pub": ephemeral_pub.as_bytes().to_vec(),
            "sender_x25519_pub": our_x25519_pub.as_bytes().to_vec(),
            "one_time_key_used": one_time_prekey_bytes.is_some(),
            "header": header.to_bytes().to_vec(),
            "ciphertext": ciphertext,
        })).map_err(|e| format!("Serialization error: {}", e))?;

        // Send via server
        let msg = rmp_serde::to_vec_named(&serde_json::json!({
            "type": "message",
            "recipient": recipient_bytes,
            "payload": dm_payload,
        })).map_err(|e| format!("Serialization error: {}", e))?;
        conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

        // Store the ratchet session
        {
            let mut sessions = state.ratchet_sessions.write().await;
            sessions.insert(recipient.clone(), ratchet);
        }
        {
            let mut ad_map = state.ratchet_ad.write().await;
            ad_map.insert(recipient.clone(), ad);
        }

        // Persist to DB
        persist_ratchet_session(&state, &recipient).await;
    }

    // Store the DM conversation locally
    let display_name = &recipient[..16.min(recipient.len())];
    let _ = db::store_conversation(&state, &recipient, display_name, "dm").await;

    // Store outgoing message in local DB
    let content_bytes = content.into_bytes();
    if let Err(e) = db::store_message(&state, &recipient, b"self", &content_bytes, true).await {
        tracing::warn!("send_message: failed to persist message locally: {}", e);
    }

    tracing::info!("send_message (DM): sent successfully to {}", &recipient[..16.min(recipient.len())]);
    Ok("sent".to_string())
}

/// Helper: persist a ratchet session to the DB.
async fn persist_ratchet_session(state: &AppState, peer_pubkey: &str) {
    let sessions = state.ratchet_sessions.read().await;
    let ad_map = state.ratchet_ad.read().await;
    if let (Some(ratchet), Some(ad)) = (sessions.get(peer_pubkey), ad_map.get(peer_pubkey)) {
        match ratchet.save() {
            Ok(ratchet_bytes) => {
                if let Err(e) = db::save_ratchet_session(state, peer_pubkey, &ratchet_bytes, ad).await {
                    tracing::warn!("Failed to persist ratchet session for {}: {}", &peer_pubkey[..16.min(peer_pubkey.len())], e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize ratchet for {}: {}", &peer_pubkey[..16.min(peer_pubkey.len())], e);
            }
        }
    }
}

/// Helper: request a pre-key bundle from the server and wait for response.
///
/// We send the request and then poll a oneshot receiver that the WebSocket
/// handler fills when it gets a `prekey_bundle_response`.
async fn request_prekey_bundle(
    conn: &crate::websocket::Connection,
    target_pubkey: &[u8],
) -> Result<serde_json::Value, String> {
    // Send request
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "get_prekey_bundle",
        "target_pubkey": target_pubkey,
    })).map_err(|e| format!("Serialization error: {}", e))?;
    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

    // Wait for the response via the connection's prekey response channel
    let rx = conn.take_prekey_response().await
        .ok_or_else(|| "No prekey response channel available".to_string())?;

    match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
        Ok(Ok(response)) => {
            if response.get("error").is_some() {
                let err_msg = response["error"].as_str().unwrap_or("Unknown error");
                Err(format!("Server error: {}", err_msg))
            } else {
                Ok(response)
            }
        }
        Ok(Err(_)) => Err("Prekey bundle response channel dropped".to_string()),
        Err(_) => Err("Timed out waiting for prekey bundle from server".to_string()),
    }
}

/// Helper: extract a byte array from a serde_json::Value (array of numbers or null).
fn extract_byte_array_from_json(value: &serde_json::Value) -> Option<Vec<u8>> {
    if let Some(arr) = value.as_array() {
        return arr.iter()
            .map(|v| v.as_u64().map(|n| n as u8))
            .collect::<Option<Vec<u8>>>();
    }
    None
}

/// Get conversations
#[tauri::command]
pub async fn get_conversations(state: State<'_, AppState>) -> Result<Vec<db::Conversation>, String> {
    match db::get_conversations(&state).await {
        Ok(conversations) => Ok(conversations),
        Err(e) => Err(e.to_string()),
    }
}

/// A message in a format the frontend can consume directly
#[derive(Serialize)]
pub struct FrontendMessage {
    pub id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "senderPubkey")]
    pub sender_pubkey: String,
    pub content: String,
    pub timestamp: i64,
    #[serde(rename = "isOutgoing")]
    pub is_outgoing: bool,
    pub status: String,
}

/// Get messages for a conversation
#[tauri::command]
pub async fn get_messages(
    conversation_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<FrontendMessage>, String> {
    let db_messages = db::get_messages(&state, &conversation_id).await
        .map_err(|e| e.to_string())?;
    
    let messages: Vec<FrontendMessage> = db_messages.into_iter().map(|m| {
        let sender_pubkey = if m.is_outgoing {
            "self".to_string()
        } else {
            hex::encode(&m.sender_pubkey)
        };
        // Content is stored as bytes; decode as UTF-8
        let content = String::from_utf8_lossy(&m.encrypted_content).to_string();
        FrontendMessage {
            id: m.id,
            conversation_id: m.conversation_id,
            sender_pubkey,
            content,
            // DB stores seconds; frontend uses milliseconds
            timestamp: m.timestamp * 1000,
            is_outgoing: m.is_outgoing,
            status: "delivered".to_string(),
        }
    }).collect();
    
    Ok(messages)
}

/// Reset (delete) the local identity and all associated data.
///
/// This removes the encrypted identity file, the mnemonic hash, and the
/// local client database so the user can start fresh.
#[tauri::command]
pub async fn reset_identity(state: State<'_, AppState>) -> Result<(), String> {
    match _reset_identity(state).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

async fn _reset_identity(state: State<'_, AppState>) -> anyhow::Result<()> {
    let data_dir = crate::mobium_profile_dir(&state).await?;
    
    // Close DB if open
    {
        let mut db_guard = state.db.write().await;
        *db_guard = None;
    }
    
    // Clear in-memory state
    {
        let mut identity_guard = state.identity.write().await;
        *identity_guard = None;
    }
    {
        let mut key_guard = state.db_key.write().await;
        *key_guard = None;
    }
    {
        let mut sessions_guard = state.group_sessions.write().await;
        sessions_guard.clear();
    }
    
    // Delete files
    let files_to_remove = ["identity.enc", "mnemonic.hash", "client.db", "client.db-shm", "client.db-wal"];
    for filename in &files_to_remove {
        let path = data_dir.join(filename);
        if path.exists() {
            tokio::fs::remove_file(&path).await
                .map_err(|e| anyhow::anyhow!("Failed to delete {}: {}", filename, e))?;
            tracing::info!("Deleted {}", path.display());
        }
    }
    
    tracing::info!("Identity reset complete");
    Ok(())
}

/// Fetch ICE (STUN/TURN) configuration from the connected server.
///
/// The server generates time-limited HMAC credentials for TURN if configured.
/// Falls back to empty config if not connected.
#[tauri::command]
pub async fn get_ice_config(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Ok(serde_json::json!({ "ice_servers": [] })),
        }
    };

    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "get_ice_config",
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

    // Wait for response via the connection's ICE config channel
    let rx = conn.take_ice_config_response().await
        .ok_or_else(|| "No ICE config response channel available".to_string())?;

    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => Ok(serde_json::json!({ "ice_servers": [] })),
        Err(_) => Ok(serde_json::json!({ "ice_servers": [] })),
    }
}

/// Lock the current profile — wipes all cryptographic material from memory.
///
/// After locking, the user must re-enter their password to unlock.
/// This disconnects the WebSocket and clears all in-memory secrets.
#[tauri::command]
pub async fn lock_profile(state: State<'_, AppState>) -> Result<(), String> {
    // Disconnect WebSocket first
    {
        let mut conn_guard = state.connection.write().await;
        *conn_guard = None;
    }

    // Close DB pool
    {
        let mut db_guard = state.db.write().await;
        if let Some(pool) = db_guard.take() {
            pool.close().await;
        }
    }

    // Zeroize all cryptographic material
    state.lock_profile().await;

    tracing::info!("Profile locked via Tauri command");
    Ok(())
}

/// Setup social recovery
#[tauri::command]
pub async fn setup_social_recovery(
    _total_shares: u8,
    _threshold: u8,
    _recipient_pubkeys: Vec<String>,
) -> Result<Vec<String>, String> {
    Err("Not yet implemented".to_string())
}

/// Reconstruct from shards
#[tauri::command]
pub async fn reconstruct_from_shards(
    _shards: Vec<String>,
) -> Result<String, String> {
    Err("Not yet implemented".to_string())
}

/// Publish pre-key bundle to the server for X3DH key agreement.
///
/// Generates a signed pre-key + one-time pre-keys, stores private material
/// locally (encrypted), and sends the public bundle to the server.
#[tauri::command]
pub async fn publish_prekeys(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let identity = {
        let guard = state.identity.read().await;
        guard.as_ref().ok_or_else(|| "No identity loaded".to_string())?.clone()
    };

    // Generate pre-key bundle: signed pre-key + 10 one-time pre-keys
    let num_otpks = 10;
    let (bundle, private_keys) = x3dh::generate_pre_key_bundle(&identity, num_otpks);

    // Extract raw bytes for the signed pre-key secret so we can persist it.
    // StaticSecret::to_bytes() gives us the raw 32 bytes.
    let spk_bytes = private_keys.signed_pre_key.to_bytes();

    // Collect OTP private key bytes
    let otpk_bytes_list: Vec<Vec<u8>> = private_keys.one_time_pre_keys.iter()
        .map(|sk| sk.to_bytes().to_vec())
        .collect();

    // Store private pre-key material locally (encrypted)
    db::save_prekey_material(&state, &spk_bytes, &otpk_bytes_list).await
        .map_err(|e| format!("Failed to save prekey material: {}", e))?;

    // Store in memory
    {
        let mut prekeys_guard = state.our_prekeys.write().await;
        *prekeys_guard = Some(private_keys);
    }
    {
        let mut spk_guard = state.our_spk_bytes.write().await;
        *spk_guard = Some(spk_bytes);
    }

    // Serialize one-time pre-key public keys as MessagePack (Vec<Vec<u8>>)
    let otpk_pub_list: Vec<Vec<u8>> = bundle.one_time_pre_keys.iter()
        .map(|pk| pk.as_bytes().to_vec())
        .collect();
    let otpk_pub_blob = rmp_serde::to_vec(&otpk_pub_list)
        .map_err(|e| format!("Serialization error: {}", e))?;

    // Send to server
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "publish_prekeys",
        "identity_x25519_pub": bundle.identity_encryption_key.as_bytes().to_vec(),
        "signed_prekey": bundle.signed_pre_key.as_bytes().to_vec(),
        "signed_prekey_sig": bundle.signed_pre_key_signature.to_bytes().to_vec(),
        "one_time_prekeys": otpk_pub_blob,
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

    {
        let mut published = state.prekeys_published.write().await;
        *published = true;
    }

    tracing::info!("Published pre-key bundle ({} OTPKs) to server", num_otpks);
    Ok(())
}

/// Check if we have a DM ratchet session with a peer
#[tauri::command]
pub async fn has_dm_session(
    peer_pubkey: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let sessions = state.ratchet_sessions.read().await;
    Ok(sessions.contains_key(&peer_pubkey))
}

/// Send encrypted sender key distributions to all channel members.
///
/// Encrypts the distribution individually for each member using X25519 ECDH,
/// so the server never sees the plaintext chain key.
async fn send_encrypted_distribution(
    state: &AppState,
    conn: &crate::websocket::Connection,
    channel_id: &str,
    dist: &SenderKeyDistribution,
    member_pubkeys: &[Vec<u8>],
) -> std::result::Result<(), String> {
    let identity_guard = state.identity.read().await;
    let identity = identity_guard.as_ref()
        .ok_or_else(|| "No identity loaded".to_string())?;
    let my_pubkey = identity.public_signing_key().as_bytes().to_vec();
    let my_x25519_pub = identity.public_encryption_key();
    let encryption_key = &identity.encryption;

    let dist_bytes = serde_json::to_vec(dist)
        .map_err(|e| format!("Serialization error: {}", e))?;

    let channel_id_bytes = hex::decode(channel_id)
        .map_err(|_| "Invalid channel ID".to_string())?;

    // Look up cached X25519 public keys for recipients
    let x25519_keys = state.x25519_keys.read().await;

    let mut distributions = Vec::new();
    for member_pk_bytes in member_pubkeys {
        // Skip self
        if *member_pk_bytes == my_pubkey {
            continue;
        }

        // Use the cached X25519 public key (registered by the recipient on auth)
        let recipient_x25519 = if let Some(x25519_bytes) = x25519_keys.get(member_pk_bytes) {
            if x25519_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(x25519_bytes);
                x25519_dalek::PublicKey::from(arr)
            } else {
                tracing::warn!("Invalid X25519 key length for member {}", hex::encode(&member_pk_bytes[..8.min(member_pk_bytes.len())]));
                continue;
            }
        } else {
            tracing::warn!("No X25519 key cached for member {} — skipping distribution", hex::encode(&member_pk_bytes[..8.min(member_pk_bytes.len())]));
            continue;
        };

        // Encrypt distribution for this recipient
        let context = channel_id_bytes.as_slice();
        let encrypted = mobium_shared::encrypt_for_recipient(
            encryption_key,
            &recipient_x25519,
            &dist_bytes,
            context,
        ).map_err(|e| format!("Encryption for recipient failed: {}", e))?;

        distributions.push(serde_json::json!({
            "recipient": member_pk_bytes,
            "encrypted_dist": encrypted,
        }));
    }
    drop(x25519_keys);
    drop(identity_guard);

    if distributions.is_empty() {
        return Ok(());
    }

    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "sender_key_distribution",
        "channel_id": channel_id_bytes,
        "sender_x25519_pub": my_x25519_pub.as_bytes().to_vec(),
        "distributions": distributions,
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;
    tracing::info!("Sent encrypted sender key distributions to {} recipients", distributions.len());
    Ok(())
}

/// Request channel member list from the server.
///
/// This is a fire-and-forget request; the response comes async via
/// `members_response` in the WebSocket handler.
async fn request_channel_members(
    conn: &crate::websocket::Connection,
    channel_id: &str,
) -> std::result::Result<(), String> {
    let channel_id_bytes = hex::decode(channel_id)
        .map_err(|_| "Invalid channel ID".to_string())?;
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "get_members",
        "channel_id": channel_id_bytes,
    })).map_err(|e| format!("Serialization error: {}", e))?;
    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;
    Ok(())
}

/// Ensure a GroupSession exists for a channel, creating one if needed.
/// Returns the SenderKeyDistribution that should be sent to peers (if newly created).
async fn ensure_group_session(
    state: &AppState,
    channel_id: &str,
) -> std::result::Result<Option<SenderKeyDistribution>, String> {
    let mut sessions = state.group_sessions.write().await;
    if sessions.contains_key(channel_id) {
        return Ok(None);
    }
    
    // Get our pubkey
    let identity_guard = state.identity.read().await;
    let identity = identity_guard.as_ref()
        .ok_or_else(|| "No identity loaded".to_string())?;
    let my_pubkey = identity.public_signing_key().as_bytes().to_vec();
    drop(identity_guard);
    
    let channel_id_bytes = hex::decode(channel_id)
        .map_err(|_| "Invalid channel ID".to_string())?;
    
    // Try to load from DB
    let db_rows = db::load_sender_keys(state, channel_id).await
        .map_err(|e| format!("DB error: {}", e))?;
    
    let my_pubkey_hex = hex::encode(&my_pubkey);
    
    if let Some(my_row) = db_rows.iter().find(|r| r.is_self) {
        // Restore existing session
        if my_row.chain_key.len() != 32 {
            return Err("Corrupted sender key in DB".to_string());
        }
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&my_row.chain_key);
        let mut session = GroupSession::from_existing(
            &my_pubkey,
            ck,
            my_row.key_id as u32,
            my_row.iteration as u32,
        );
        
        // Load peer chains
        for row in &db_rows {
            if !row.is_self && row.chain_key.len() == 32 {
                let dist = SenderKeyDistribution {
                    channel_id: channel_id_bytes.clone(),
                    sender_pubkey: hex::decode(&row.sender_pubkey).unwrap_or_default(),
                    key_id: row.key_id as u32,
                    chain_key: row.chain_key.clone(),
                    iteration: row.iteration as u32,
                    voice_key: None, // Will be derived from chain_key in process_distribution
                };
                let _ = session.process_distribution(&dist);
            }
        }
        
        sessions.insert(channel_id.to_string(), session);
        Ok(None)
    } else {
        // Create brand new session
        let (session, dist) = GroupSession::new(&channel_id_bytes, &my_pubkey);
        
        // Persist our chain to DB
        let (chain_key, key_id, iteration) = session.my_chain_state();
        let _ = db::save_sender_key(
            state, channel_id, &my_pubkey_hex,
            key_id, chain_key, iteration, true,
        ).await;
        
        sessions.insert(channel_id.to_string(), session);
        Ok(Some(dist))
    }
}

/// Send a message to a channel
/// 
/// The message is encrypted with Sender Keys, padded to a bucket size,
/// and sent to all channel members.
#[tauri::command]
pub async fn send_channel_message(
    channel_id: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    tracing::info!("send_channel_message called: channel={}, content_len={}", &channel_id[..16.min(channel_id.len())], content.len());
    
    // Clone the Arc and drop the lock before any .await
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => {
                tracing::error!("send_channel_message: not connected");
                return Err("Not connected to server".to_string());
            }
        }
    };
    
    // Ensure we have a group session; if newly created, we need to distribute our sender key
    let maybe_dist = ensure_group_session(&state, &channel_id).await?;
    
    // If we just created a session, distribute our sender key (encrypted per-recipient)
    if let Some(dist) = maybe_dist {
        // Check if we have the member list cached
        let members = {
            let members_guard = state.channel_members.read().await;
            members_guard.get(&channel_id).cloned()
        };
        
        if let Some(member_pubkeys) = members {
            // We know the members — encrypt and send immediately
            send_encrypted_distribution(&state, &conn, &channel_id, &dist, &member_pubkeys).await?;
        } else {
            // We don't know members yet — store as pending, request member list
            {
                let mut pending: tokio::sync::RwLockWriteGuard<'_, std::collections::HashMap<String, SenderKeyDistribution>> = state.pending_distributions.write().await;
                pending.insert(channel_id.clone(), dist);
            }
            request_channel_members(&conn, &channel_id).await?;
            tracing::info!("send_channel_message: requested member list for pending distribution");
        }
    }
    
    // Encrypt with Sender Keys
    let plaintext = content.as_bytes();
    let associated_data = channel_id.as_bytes(); // channel ID as AAD
    
    let encrypted_payload = {
        let mut sessions = state.group_sessions.write().await;
        let session = sessions.get_mut(&channel_id)
            .ok_or_else(|| "No group session".to_string())?;
        
        session.encrypt(plaintext, associated_data)
            .map_err(|e| format!("Encryption failed: {}", e))?
    };
    
    // Persist our updated chain state
    {
        let sessions = state.group_sessions.read().await;
        if let Some(session) = sessions.get(&channel_id) {
            let (chain_key, key_id, iteration) = session.my_chain_state();
            let identity_guard = state.identity.read().await;
            if let Some(identity) = identity_guard.as_ref() {
                let my_pubkey_hex = hex::encode(identity.public_signing_key().as_bytes());
                let _ = db::save_sender_key(
                    &state, &channel_id, &my_pubkey_hex,
                    key_id, chain_key, iteration, true,
                ).await;
            }
        }
    }
    
    // The encrypted_payload already includes padding (done by GroupSession::encrypt),
    // so bucket_index is derived from the ciphertext size
    let bucket_index = match mobium_shared::get_bucket_index(content.len()) {
        Ok(idx) => idx as i64,
        Err(e) => {
            tracing::error!("send_channel_message: message too large: {}", e);
            return Err(format!("Message too large: {}", e));
        }
    };
    
    // Decode channel_id from hex
    let channel_id_bytes = match hex::decode(&channel_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::error!("send_channel_message: invalid channel ID hex");
            return Err("Invalid channel ID".to_string());
        }
    };
    
    // Send to server
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "channel_message",
        "channel_id": channel_id_bytes,
        "payload": encrypted_payload,
        "bucket_size": bucket_index,
    })).map_err(|e| {
        tracing::error!("send_channel_message: serialization error: {}", e);
        format!("Serialization error: {}", e)
    })?;
    
    tracing::info!("send_channel_message: sending {} encrypted bytes to WebSocket", msg.len());
    conn.send(msg).await.map_err(|e| {
        tracing::error!("send_channel_message: send failed: {}", e);
        format!("Failed to send: {}", e)
    })?;
    tracing::info!("send_channel_message: sent successfully");
    
    // Persist outgoing message to client DB (store plaintext locally for display)
    let content_bytes = content.into_bytes();
    if let Err(e) = db::store_message(&state, &channel_id, b"self", &content_bytes, true).await {
        tracing::warn!("send_channel_message: failed to persist message locally: {}", e);
    }
    
    Ok("sent".to_string())
}

/// Create a new channel
#[tauri::command]
pub async fn create_channel(
    channel_name: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };
    
    // Generate a random channel ID (32 bytes)
    let mut channel_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut channel_id);
    let channel_hex = hex::encode(&channel_id);
    
    // Encrypt metadata (channel name) with the DB key for local storage,
    // and send only a hash to the server (server doesn't need the channel name)
    let encrypted_metadata = {
        let db_key_guard = state.db_key.read().await;
        if let Some(ref db_key) = *db_key_guard {
            // Send HMAC of channel name to server as opaque metadata
            // The server only needs a unique identifier, not the actual name
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(db_key)
                .expect("HMAC accepts any key length");
            mac.update(channel_name.as_bytes());
            mac.finalize().into_bytes().to_vec()
        } else {
            // Fallback: opaque random bytes (don't leak channel name)
            let random_metadata: [u8; 32] = rand::random();
            random_metadata.to_vec()
        }
    };
    
    // Send to server
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "create_channel",
        "channel_id": channel_id.to_vec(),
        "encrypted_metadata": encrypted_metadata,
    })).map_err(|e| format!("Serialization error: {}", e))?;
    
    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;
    
    // Initialize group session for this channel
    let _ = ensure_group_session(&state, &channel_hex).await;
    
    // Create conversation locally with encrypted name
    if let Err(e) = db::store_conversation(&state, &channel_hex, &channel_name, "group").await {
        tracing::warn!("Failed to store conversation: {}", e);
    }
    
    // Record for auto-rejoin on reconnect
    let _ = db::add_joined_channel(&state, &channel_hex, &channel_name).await;
    
    Ok(channel_hex)
}

/// Join an existing channel
#[tauri::command]
pub async fn join_channel(
    channel_id: String,
    channel_name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };
    
    let channel_id_bytes = hex::decode(&channel_id)
        .map_err(|_| "Invalid channel ID".to_string())?;
    
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "join_channel",
        "channel_id": channel_id_bytes,
    })).map_err(|e| format!("Serialization error: {}", e))?;
    
    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;
    
    // Initialize group session and distribute our sender key (encrypted)
    if let Ok(Some(dist)) = ensure_group_session(&state, &channel_id).await {
        // Store as pending and request member list
        {
            let mut pending: tokio::sync::RwLockWriteGuard<'_, std::collections::HashMap<String, SenderKeyDistribution>> = state.pending_distributions.write().await;
            pending.insert(channel_id.clone(), dist);
        }
        request_channel_members(&conn, &channel_id).await?;
        tracing::info!("join_channel: requested member list for sender key distribution");
    }
    
    // Create conversation locally with encrypted name
    if let Err(e) = db::store_conversation(&state, &channel_id, &channel_name, "group").await {
        tracing::warn!("Failed to store conversation: {}", e);
    }
    
    // Record for auto-rejoin on reconnect
    let _ = db::add_joined_channel(&state, &channel_id, &channel_name).await;
    
    Ok(())
}

/// Leave a channel — destroys our sender key so we can no longer decrypt.
///
/// Notifies the server (which removes us from the member list and broadcasts
/// `member_left` to remaining members), then deletes our local group session
/// and sender key material for this channel.
///
/// On receiving `member_left`, other clients rotate their own sender keys
/// (forward secrecy: the departed member cannot decrypt future messages).
#[tauri::command]
pub async fn leave_channel(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let channel_id_bytes = hex::decode(&channel_id)
        .map_err(|_| "Invalid channel ID".to_string())?;

    // Tell the server to remove us from the channel
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "leave_channel",
        "channel_id": channel_id_bytes,
    })).map_err(|e| format!("Serialization error: {}", e))?;
    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

    // Destroy local group session — we can no longer encrypt/decrypt for this channel
    {
        let mut sessions = state.group_sessions.write().await;
        sessions.remove(&channel_id);
    }
    // Remove cached members
    {
        let mut members = state.channel_members.write().await;
        members.remove(&channel_id);
    }
    // Remove pending distributions
    {
        let mut pending = state.pending_distributions.write().await;
        pending.remove(&channel_id);
    }
    // Remove buffered messages
    {
        let mut buf = state.buffered_messages.write().await;
        buf.remove(&channel_id);
    }

    // Delete sender keys from DB
    let _ = db::delete_sender_keys_for_channel(&state, &channel_id).await;
    // Remove from auto-rejoin list
    let _ = db::remove_joined_channel(&state, &channel_id).await;

    tracing::info!("Left channel {}", &channel_id[..16.min(channel_id.len())]);
    Ok(())
}

/// Channel member info for the frontend
#[derive(Serialize)]
pub struct ChannelMember {
    pub pubkey: String,
    pub nickname: Option<String>,
    #[serde(rename = "isSelf")]
    pub is_self: bool,
}

/// Get the member list for a channel, including nicknames
#[tauri::command]
pub async fn get_channel_members(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ChannelMember>, String> {
    // Get our own pubkey
    let my_pubkey = {
        let identity_guard = state.identity.read().await;
        match identity_guard.as_ref() {
            Some(identity) => hex::encode(identity.public_signing_key().as_bytes()),
            None => return Err("No identity loaded".to_string()),
        }
    };

    // Get cached member list
    let member_pubkeys = {
        let members_guard = state.channel_members.read().await;
        members_guard.get(&channel_id).cloned().unwrap_or_default()
    };

    if member_pubkeys.is_empty() {
        // Try requesting members from server
        let conn_guard = state.connection.read().await;
        if let Some(conn) = conn_guard.as_ref() {
            let _ = request_channel_members(conn, &channel_id).await;
        }
        return Ok(vec![]);
    }

    // Get all nicknames
    let nicknames = db::get_all_nicknames(&state).await
        .map_err(|e| e.to_string())?;
    let nick_map: std::collections::HashMap<String, String> = nicknames.into_iter().collect();

    // Build member list
    let mut members: Vec<ChannelMember> = member_pubkeys.iter().map(|pk| {
        let pubkey_hex = hex::encode(pk);
        let is_self = pubkey_hex == my_pubkey;
        let nickname = nick_map.get(&pubkey_hex).cloned();
        ChannelMember {
            pubkey: pubkey_hex,
            nickname,
            is_self,
        }
    }).collect();

    // Sort: self first, then by nickname/pubkey
    members.sort_by(|a, b| {
        if a.is_self && !b.is_self { return std::cmp::Ordering::Less; }
        if !a.is_self && b.is_self { return std::cmp::Ordering::Greater; }
        let a_name = a.nickname.as_deref().unwrap_or(&a.pubkey);
        let b_name = b.nickname.as_deref().unwrap_or(&b.pubkey);
        a_name.cmp(b_name)
    });

    Ok(members)
}

/// Get all known users across all joined channels (deduplicated)
#[tauri::command]
pub async fn get_all_known_users(
    state: State<'_, AppState>,
) -> Result<Vec<ChannelMember>, String> {
    // Get our own pubkey
    let my_pubkey = {
        let identity_guard = state.identity.read().await;
        match identity_guard.as_ref() {
            Some(identity) => hex::encode(identity.public_signing_key().as_bytes()),
            None => return Err("No identity loaded".to_string()),
        }
    };

    // Collect all unique pubkeys from all channel member caches
    let mut all_pubkeys = std::collections::HashSet::<Vec<u8>>::new();
    {
        let members_guard = state.channel_members.read().await;
        for member_list in members_guard.values() {
            for pk in member_list {
                all_pubkeys.insert(pk.clone());
            }
        }
    }

    if all_pubkeys.is_empty() {
        return Ok(vec![]);
    }

    // Get all nicknames
    let nicknames = db::get_all_nicknames(&state).await
        .map_err(|e| e.to_string())?;
    let nick_map: std::collections::HashMap<String, String> = nicknames.into_iter().collect();

    // Build user list, excluding self
    let mut users: Vec<ChannelMember> = all_pubkeys.iter().filter_map(|pk| {
        let pubkey_hex = hex::encode(pk);
        if pubkey_hex == my_pubkey {
            return None; // Exclude self
        }
        let nickname = nick_map.get(&pubkey_hex).cloned();
        Some(ChannelMember {
            pubkey: pubkey_hex,
            nickname,
            is_self: false,
        })
    }).collect();

    // Sort by nickname/pubkey
    users.sort_by(|a, b| {
        let a_name = a.nickname.as_deref().unwrap_or(&a.pubkey);
        let b_name = b.nickname.as_deref().unwrap_or(&b.pubkey);
        a_name.to_lowercase().cmp(&b_name.to_lowercase())
    });

    Ok(users)
}

/// Set a nickname for a pubkey
#[tauri::command]
pub async fn set_nickname(
    pubkey: String,
    nickname: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    db::set_nickname(&state, &pubkey, &nickname).await
        .map_err(|e| e.to_string())
}

/// Get all nicknames
#[tauri::command]
pub async fn get_nicknames(state: State<'_, AppState>) -> Result<Vec<(String, String)>, String> {
    db::get_all_nicknames(&state).await
        .map_err(|e| e.to_string())
}

// ─── Voice Calling ──────────────────────────────────────────────────────────

/// Send a voice signaling message (WebRTC SDP offer/answer or ICE candidate)
/// to a specific peer, relayed through the server.
///
/// `signal_type` is one of: "offer", "answer", "ice_candidate", "hangup", "reject"
/// `payload` is the serialised SDP/ICE data (opaque bytes to the server).
#[tauri::command]
pub async fn send_voice_signal(
    recipient: String,
    signal_type: String,
    payload: Vec<u8>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let recipient_bytes = hex::decode(&recipient)
        .map_err(|_| "Invalid recipient pubkey hex".to_string())?;

    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "voice_signal",
        "recipient": recipient_bytes,
        "signal_type": signal_type,
        "payload": payload,
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

    tracing::info!("Sent voice signal '{}' to {}", signal_type, &recipient[..16.min(recipient.len())]);
    Ok(())
}

/// Poll for incoming voice signals buffered by the websocket handler.
///
/// Returns and drains all pending signals. Each entry is
/// (sender_hex, signal_type, payload_bytes).  The frontend calls this on a
/// short interval to work around Tauri 2's unreliable event bus for events
/// emitted from spawned async tasks.
#[tauri::command]
pub async fn poll_voice_signals(
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, Vec<u8>)>, String> {
    let mut pending = state.pending_voice_signals.write().await;
    Ok(std::mem::take(&mut *pending))
}

/// Clear all pending voice signals without returning them.
///
/// Called by the frontend when a call ends (endCall / rejectCall) to prevent
/// stale signals (e.g. a lingering reject/hangup from a previous attempt)
/// from contaminating the next call.
#[tauri::command]
pub async fn clear_voice_signals(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut pending = state.pending_voice_signals.write().await;
    pending.clear();
    Ok(())
}

// ─── Channel Voice Chat ─────────────────────────────────────────────────────

/// Join a voice channel. Sends `join_voice` to the server and tracks the
/// channel locally so the frontend knows we're in a voice session.
#[tauri::command]
pub async fn join_voice_channel(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let channel_id_bytes = hex::decode(&channel_id)
        .map_err(|_| "Invalid channel ID hex".to_string())?;

    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "join_voice",
        "channel_id": channel_id_bytes,
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

    // Track locally
    {
        let mut guard = state.current_voice_channel.write().await;
        *guard = Some(channel_id.clone());
    }

    tracing::info!("Joined voice channel {}", &channel_id[..16.min(channel_id.len())]);
    Ok(())
}

/// Leave the current voice channel.
#[tauri::command]
pub async fn leave_voice_channel(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let channel_id = {
        let guard = state.current_voice_channel.read().await;
        match guard.as_ref() {
            Some(id) => id.clone(),
            None => return Ok(()), // Not in any voice channel
        }
    };

    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let channel_id_bytes = hex::decode(&channel_id)
        .map_err(|_| "Invalid channel ID hex".to_string())?;

    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "leave_voice",
        "channel_id": channel_id_bytes,
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;

    // Clear local state
    {
        let mut guard = state.current_voice_channel.write().await;
        *guard = None;
    }
    // Drain any remaining voice data/events/screen data
    {
        let mut data = state.pending_voice_data.write().await;
        data.clear();
    }
    {
        let mut events = state.pending_voice_events.write().await;
        events.clear();
    }
    {
        let mut screen = state.pending_screen_data.write().await;
        screen.clear();
    }
    {
        let mut sharer = state.screen_sharer.write().await;
        *sharer = None;
    }

    tracing::info!("Left voice channel {}", &channel_id[..16.min(channel_id.len())]);
    Ok(())
}

/// Send an audio frame to the current voice channel.
///
/// The audio data is encrypted with the channel's Sender Key (AES-256-GCM)
/// before being sent to the server. The server only sees opaque ciphertext.
#[tauri::command]
pub async fn send_voice_data(
    audio: Vec<u8>,
    seq: u64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let channel_id = {
        let guard = state.current_voice_channel.read().await;
        match guard.as_ref() {
            Some(id) => id.clone(),
            None => return Err("Not in a voice channel".to_string()),
        }
    };

    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let channel_id_bytes = hex::decode(&channel_id)
        .map_err(|_| "Invalid channel ID hex".to_string())?;

    // Encrypt the audio frame with the channel's stable voice key.
    // This uses a fixed key derived from the initial chain seed (never advances
    // the text ratchet), so voice traffic cannot desync text decryption.
    let encrypted = {
        let sessions = state.group_sessions.read().await;
        match sessions.get(&channel_id) {
            Some(session) => {
                session.voice_encrypt(&audio, seq, channel_id.as_bytes())
                    .map_err(|e| format!("Voice encrypt failed: {}", e))?
            }
            None => return Err("No group session for voice channel — send a text message first to establish keys".to_string()),
        }
    };

    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "voice_data",
        "channel_id": channel_id_bytes,
        "audio": encrypted,
        "seq": seq,
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;
    Ok(())
}

/// Poll for incoming voice audio data buffered by the websocket handler.
/// Returns and drains all pending audio frames.
/// Each entry: (sender_hex, audio_bytes, sequence_number).
#[tauri::command]
pub async fn poll_voice_data(
    state: State<'_, AppState>,
) -> Result<Vec<(String, Vec<u8>, u64)>, String> {
    let mut pending = state.pending_voice_data.write().await;
    Ok(std::mem::take(&mut *pending))
}

/// Poll for voice channel events (joins, leaves, state updates).
/// Returns and drains all pending events as JSON strings.
#[tauri::command]
pub async fn poll_voice_events(
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let mut pending = state.pending_voice_events.write().await;
    Ok(std::mem::take(&mut *pending))
}

/// Send a screen share chunk to the current voice channel.
///
/// The video chunk is encrypted with the channel's Sender Key (AES-256-GCM)
/// before being sent to the server. The server only sees opaque ciphertext.
#[tauri::command]
pub async fn send_screen_data(
    chunk: Vec<u8>,
    seq: u64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let channel_id = {
        let guard = state.current_voice_channel.read().await;
        match guard.as_ref() {
            Some(id) => id.clone(),
            None => return Err("Not in a voice channel".to_string()),
        }
    };

    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };

    let channel_id_bytes = hex::decode(&channel_id)
        .map_err(|_| "Invalid channel ID hex".to_string())?;

    // Encrypt the video chunk with the channel's stable voice key.
    // Same key as voice audio — never advances the text ratchet.
    let encrypted = {
        let sessions = state.group_sessions.read().await;
        match sessions.get(&channel_id) {
            Some(session) => {
                session.voice_encrypt(&chunk, seq, channel_id.as_bytes())
                    .map_err(|e| format!("Screen encrypt failed: {}", e))?
            }
            None => return Err("No group session for voice channel — send a text message first to establish keys".to_string()),
        }
    };

    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "screen_data",
        "channel_id": channel_id_bytes,
        "chunk": encrypted,
        "seq": seq,
    })).map_err(|e| format!("Serialization error: {}", e))?;

    conn.send(msg).await.map_err(|e| format!("Failed to send: {}", e))?;
    Ok(())
}

/// Poll for incoming screen share data buffered by the websocket handler.
/// Returns and drains all pending screen chunks.
/// Each entry: (sender_hex, chunk_bytes, sequence_number).
#[tauri::command]
pub async fn poll_screen_data(
    state: State<'_, AppState>,
) -> Result<Vec<(String, Vec<u8>, u64)>, String> {
    let mut pending = state.pending_screen_data.write().await;
    Ok(std::mem::take(&mut *pending))
}

/// Get the current voice channel ID (if in one).
#[tauri::command]
pub async fn get_current_voice_channel(
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let guard = state.current_voice_channel.read().await;
    Ok(guard.clone())
}

/// Get the last connected server URL
#[tauri::command]
pub async fn get_last_server(state: State<'_, AppState>) -> Result<Option<String>, String> {
    db::get_setting(&state, "last_server_url").await
        .map_err(|e| e.to_string())
}

/// Fetch channel message history
/// 
/// Retrieves messages sent after the user joined the channel.
#[tauri::command]
pub async fn fetch_channel_history(
    channel_id: String,
    after_timestamp: i64,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    let conn = {
        let conn_guard = state.connection.read().await;
        match conn_guard.as_ref() {
            Some(c) => c.clone(),
            None => return Err("Not connected to server".to_string()),
        }
    };
    
    // Decode channel_id from hex
    let channel_id_bytes = match hex::decode(&channel_id) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid channel ID".to_string()),
    };
    
    // Re-join the channel to ensure the server knows we're a member.
    // This is idempotent (ON CONFLICT DO NOTHING) and handles the case
    // where the server DB was reset or the client reconnects after a long time.
    let rejoin_msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "join_channel",
        "channel_id": &channel_id_bytes,
    })).map_err(|e| format!("Serialization error: {}", e))?;
    let _ = conn.send(rejoin_msg).await;
    
    // Ensure we have a group session, and request sender keys from the server.
    // This triggers server-side delivery of stored sender key distributions.
    let _ = ensure_group_session(&state, &channel_id).await;
    request_channel_members(&conn, &channel_id).await
        .map_err(|e| format!("Failed to request members: {}", e))?;
    
    // Request history from server
    let msg = rmp_serde::to_vec_named(&serde_json::json!({
        "type": "get_history",
        "channel_id": &channel_id_bytes,
        "after_timestamp": after_timestamp,
        "limit": 100,
    }));
    
    match msg {
        Ok(data) => {
            match conn.send(data).await {
                Ok(_) => Ok(0), // Server will respond async
                Err(e) => Err(format!("Failed to request history: {}", e)),
            }
        }
        Err(e) => Err(format!("Serialization error: {}", e)),
    }
}