//! Client-side database operations
//!
//! All sensitive data (message content, conversation names, sender chain keys)
//! is encrypted with AES-256-GCM before being written to the local SQLite DB.
//! The encryption key is derived from the user's password and held in memory
//! only while the app is unlocked.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use crate::state::AppState;
use crate::db_crypto;

/// Conversation record
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Conversation {
    pub id: String,
    pub name: String,
    pub conversation_type: String,
    pub created_at: i64,
    pub last_message_at: Option<i64>,
}

/// Message record
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    pub sender_pubkey: Vec<u8>,
    pub encrypted_content: Vec<u8>,
    pub timestamp: i64,
    pub is_outgoing: bool,
}

/// Initialize client database in the given profile directory.
pub async fn init(data_dir: &std::path::Path) -> Result<Pool<Sqlite>> {
    tokio::fs::create_dir_all(&data_dir).await?;
    
    let db_path = data_dir.join("client.db");
    
    // Use SqliteConnectOptions with create_if_missing to handle Windows paths correctly
    let connect_options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true);
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;
    
    // Run migrations
    run_migrations(&pool).await?;
    
    Ok(pool)
}

/// Current schema version. Increment when adding new migrations.
const SCHEMA_VERSION: i64 = 3;

async fn run_migrations(pool: &Pool<Sqlite>) -> Result<()> {
    // Create the version table first (always idempotent)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL DEFAULT 0)"
    )
    .execute(pool)
    .await?;

    // Ensure exactly one row exists
    let row_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_version")
        .fetch_one(pool)
        .await?;
    if row_count == 0 {
        sqlx::query("INSERT INTO schema_version (version) VALUES (0)")
            .execute(pool)
            .await?;
    }

    let current: i64 = sqlx::query_scalar("SELECT version FROM schema_version LIMIT 1")
        .fetch_one(pool)
        .await?;

    tracing::info!("DB schema version: {} (target: {})", current, SCHEMA_VERSION);

    // Run migrations sequentially
    if current < 1 {
        migrate_v1(pool).await?;
    }
    if current < 2 {
        migrate_v2(pool).await?;
    }
    if current < 3 {
        migrate_v3(pool).await?;
    }

    // Stamp the version
    if current < SCHEMA_VERSION {
        sqlx::query("UPDATE schema_version SET version = ?1")
            .bind(SCHEMA_VERSION)
            .execute(pool)
            .await?;
        tracing::info!("DB schema upgraded to version {}", SCHEMA_VERSION);
    }

    Ok(())
}

/// V1: initial schema (all original tables)
async fn migrate_v1(pool: &Pool<Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            conversation_type TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            last_message_at INTEGER
        )
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_pubkey BLOB NOT NULL,
            encrypted_content BLOB NOT NULL,
            content_hash TEXT,
            timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            is_outgoing BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id)
        )
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_messages_conversation 
        ON messages(conversation_id, timestamp DESC)
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_messages_content_hash
        ON messages(content_hash)
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS contacts (
            pubkey BLOB PRIMARY KEY,
            nickname TEXT,
            prekeys BLOB,
            added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS nicknames (
            pubkey TEXT PRIMARY KEY,
            nickname TEXT NOT NULL
        )
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ratchet_sessions (
            peer_pubkey TEXT PRIMARY KEY,
            encrypted_state BLOB NOT NULL,
            associated_data BLOB NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS prekey_material (
            key TEXT PRIMARY KEY DEFAULT 'current',
            signed_prekey_bytes BLOB NOT NULL,
            one_time_prekey_bytes BLOB NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sender_key_sessions (
            channel_id TEXT NOT NULL,
            sender_pubkey TEXT NOT NULL,
            key_id INTEGER NOT NULL,
            chain_key BLOB NOT NULL,
            iteration INTEGER NOT NULL DEFAULT 0,
            is_self BOOLEAN NOT NULL DEFAULT 0,
            PRIMARY KEY (channel_id, sender_pubkey, key_id)
        )
        "#
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// V2: add joined_channels table for auto-rejoin on reconnect.
/// Stores channel_id + encrypted display name so we know which channels to
/// rejoin and re-distribute sender keys for without leaking channel names.
async fn migrate_v2(pool: &Pool<Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS joined_channels (
            channel_id TEXT PRIMARY KEY,
            encrypted_name TEXT NOT NULL,
            joined_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )
        "#
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// V3: clear ratchet sessions saved with the old broken `DoubleRatchet::save()`
/// that wrote `[0u8; 32]` as a placeholder for the DH private key. Those sessions
/// cannot perform DH ratchet steps correctly and would cause decryption failures.
/// Users will need to re-establish DM sessions after this migration, but this is
/// safer than silently corrupting conversations.
async fn migrate_v3(pool: &Pool<Sqlite>) -> Result<()> {
    let deleted = sqlx::query("DELETE FROM ratchet_sessions")
        .execute(pool)
        .await?
        .rows_affected();
    if deleted > 0 {
        tracing::warn!(
            "V3 migration: cleared {} ratchet session(s) with potentially broken DH keys. \
             DM sessions will be re-established on next message.",
            deleted
        );
    }
    Ok(())
}

/// Store a conversation with an encrypted name.
pub async fn store_conversation(
    state: &AppState,
    id: &str,
    name: &str,
    conversation_type: &str,
) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    // Encrypt the conversation name and hex-encode for TEXT column storage
    let encrypted_name = db_crypto::encrypt_for_db(state, name.as_bytes()).await?;
    let name_b64 = hex::encode(&encrypted_name);
    
    sqlx::query(
        "INSERT OR IGNORE INTO conversations (id, name, conversation_type) VALUES (?1, ?2, ?3)"
    )
    .bind(id)
    .bind(&name_b64)
    .bind(conversation_type)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Get all conversations, decrypting names.
pub async fn get_conversations(state: &AppState) -> Result<Vec<Conversation>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let rows = sqlx::query_as::<_, Conversation>(
        r#"
        SELECT * FROM conversations
        ORDER BY last_message_at DESC, created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;
    
    // Decrypt conversation names
    let mut conversations = Vec::with_capacity(rows.len());
    for mut conv in rows {
        // Try to hex-decode and decrypt — if it fails, the name is a legacy plaintext entry
        if let Ok(encrypted_bytes) = hex::decode(&conv.name) {
            if let Ok(plaintext) = db_crypto::decrypt_for_db(state, &encrypted_bytes).await {
                conv.name = String::from_utf8_lossy(&plaintext).to_string();
            }
            // else: leave the name as-is (legacy unencrypted or wrong key)
        }
        // else: not valid hex, definitely a legacy plaintext name — leave as-is
        conversations.push(conv);
    }
    
    Ok(conversations)
}

/// Get messages for a conversation, decrypting content from at-rest encryption.
pub async fn get_messages(state: &AppState, conversation_id: &str) -> Result<Vec<Message>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let rows = sqlx::query_as::<_, Message>(
        r#"
        SELECT id, conversation_id, sender_pubkey, encrypted_content, timestamp, is_outgoing
        FROM messages
        WHERE conversation_id = ?1
        ORDER BY timestamp ASC
        "#
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await?;
    
    // Decrypt each message's content
    let mut messages = Vec::with_capacity(rows.len());
    for mut msg in rows {
        match db_crypto::decrypt_for_db(state, &msg.encrypted_content).await {
            Ok(plaintext) => {
                msg.encrypted_content = plaintext;
                messages.push(msg);
            }
            Err(e) => {
                tracing::warn!("Failed to decrypt message {}: {} — skipping", msg.id, e);
                // Skip messages we can't decrypt (e.g. from before encryption was enabled)
            }
        }
    }
    
    Ok(messages)
}

/// Store a message with at-rest encryption.
///
/// `content` is the **plaintext** message body.  It is encrypted with the DB
/// key before being written to the `encrypted_content` column.
///
/// Dedup: we compute a HMAC-SHA256 of the plaintext (keyed by the DB key) and
/// store it in a separate `content_hash` column with a unique index, so
/// identical messages from the same sender in the same conversation are
/// deduplicated without ever comparing plaintext in the DB.
pub async fn store_message(
    state: &AppState,
    conversation_id: &str,
    sender_pubkey: &[u8],
    content: &[u8],
    is_outgoing: bool,
) -> Result<()> {
    let pool = {
        let db_guard = state.db.read().await;
        db_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?
            .clone()
    };
    let pool = &pool;
    
    // Encrypt content for at-rest storage
    let encrypted = db_crypto::encrypt_for_db(state, content).await?;
    
    // Compute content hash for dedup.
    //
    // We include a coarse timestamp (floored to 10-second windows) so that
    // duplicate messages arriving within the same window are caught, but an
    // attacker with DB access cannot verify whether a specific message was
    // ever sent (they'd need to guess the 10s window too).
    //
    // We also truncate to 16 bytes (128 bits) to reduce information leaked.
    let content_hash = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type H = Hmac<Sha256>;
        let key_guard = state.db_key.read().await;
        let db_key = key_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("DB key not available"))?;
        let mut mac = <H as hmac::Mac>::new_from_slice(db_key)
            .map_err(|e| anyhow::anyhow!("HMAC init: {}", e))?;
        // 10-second dedup window
        let time_window = chrono::Utc::now().timestamp() / 10;
        mac.update(&time_window.to_le_bytes());
        mac.update(conversation_id.as_bytes());
        mac.update(sender_pubkey);
        mac.update(content);
        let full_hash = mac.finalize().into_bytes();
        // Truncate to 128 bits (16 bytes = 32 hex chars)
        hex::encode(&full_hash[..16])
    };
    
    // Dedup check using content hash
    let existing: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT id FROM messages
        WHERE content_hash = ?1
        LIMIT 1
        "#
    )
    .bind(&content_hash)
    .fetch_optional(pool)
    .await?;
    
    if existing.is_some() {
        return Ok(());
    }
    
    let id = uuid::Uuid::new_v4().to_string();
    
    sqlx::query(
        r#"
        INSERT INTO messages (id, conversation_id, sender_pubkey, encrypted_content, content_hash, is_outgoing)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#
    )
    .bind(&id)
    .bind(conversation_id)
    .bind(sender_pubkey)
    .bind(&encrypted)
    .bind(&content_hash)
    .bind(is_outgoing)
    .execute(pool)
    .await?;
    
    // Update conversation last_message_at
    sqlx::query(
        r#"
        UPDATE conversations SET last_message_at = strftime('%s', 'now')
        WHERE id = ?1
        "#
    )
    .bind(conversation_id)
    .execute(pool)
    .await?;
    
    // Prune old messages to enforce the local cache limit
    let _ = prune_old_messages(state, conversation_id).await;
    
    Ok(())
}

/// Maximum number of messages to keep per conversation.
/// Older messages are pruned automatically after each insert.
const MAX_MESSAGES_PER_CONVERSATION: i64 = 500;

/// Prune old messages from a conversation, keeping only the most recent N.
pub async fn prune_old_messages(state: &AppState, conversation_id: &str) -> Result<u64> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let result = sqlx::query(
        r#"
        DELETE FROM messages
        WHERE conversation_id = ?1
          AND id NOT IN (
            SELECT id FROM messages
            WHERE conversation_id = ?1
            ORDER BY timestamp DESC
            LIMIT ?2
          )
        "#
    )
    .bind(conversation_id)
    .bind(MAX_MESSAGES_PER_CONVERSATION)
    .execute(pool)
    .await?;
    
    let deleted = result.rows_affected();
    if deleted > 0 {
        tracing::info!("Pruned {} old messages from conversation {}", deleted, &conversation_id[..16.min(conversation_id.len())]);
    }
    Ok(deleted)
}

// ─── Sender Key Persistence ─────────────────────────────────────────────────

/// Sender key row from the DB
#[derive(Debug, sqlx::FromRow)]
pub struct SenderKeyRow {
    pub channel_id: String,
    pub sender_pubkey: String,
    pub key_id: i64,
    pub chain_key: Vec<u8>,
    pub iteration: i64,
    pub is_self: bool,
}

/// Save (upsert) a sender key chain to the DB, encrypting the chain key at rest.
pub async fn save_sender_key(
    state: &AppState,
    channel_id: &str,
    sender_pubkey: &str,
    key_id: u32,
    chain_key: &[u8],
    iteration: u32,
    is_self: bool,
) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    // Encrypt the chain key before storing
    let encrypted_chain_key = db_crypto::encrypt_for_db(state, chain_key).await?;
    
    sqlx::query(
        r#"
        INSERT INTO sender_key_sessions (channel_id, sender_pubkey, key_id, chain_key, iteration, is_self)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(channel_id, sender_pubkey, key_id) DO UPDATE SET
            chain_key = excluded.chain_key,
            iteration = excluded.iteration
        "#
    )
    .bind(channel_id)
    .bind(sender_pubkey)
    .bind(key_id as i64)
    .bind(&encrypted_chain_key)
    .bind(iteration as i64)
    .bind(is_self)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Load all sender key chains for a channel, decrypting chain keys from at-rest encryption.
pub async fn load_sender_keys(state: &AppState, channel_id: &str) -> Result<Vec<SenderKeyRow>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let rows = sqlx::query_as::<_, SenderKeyRow>(
        r#"
        SELECT * FROM sender_key_sessions WHERE channel_id = ?1
        "#
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    
    // Decrypt chain keys
    let mut decrypted_rows = Vec::with_capacity(rows.len());
    for mut row in rows {
        match db_crypto::decrypt_for_db(state, &row.chain_key).await {
            Ok(plaintext_key) => {
                row.chain_key = plaintext_key;
                decrypted_rows.push(row);
            }
            Err(e) => {
                tracing::warn!("Failed to decrypt sender key for {}: {} — skipping", row.sender_pubkey, e);
            }
        }
    }
    
    Ok(decrypted_rows)
}

// ─── Nicknames ──────────────────────────────────────────────────────────────

/// Set a nickname for a pubkey (hex-encoded).
///
/// Both the pubkey and nickname are encrypted at rest. The pubkey is stored
/// as HMAC-SHA256(db_key, pubkey) for indexing, and the actual pubkey + nickname
/// are encrypted together in the nickname column.
pub async fn set_nickname(state: &AppState, pubkey: &str, nickname: &str) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    // Hash the pubkey for indexing (so we can upsert without exposing it)
    let pubkey_hash = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type H = Hmac<Sha256>;
        let key_guard = state.db_key.read().await;
        let db_key = key_guard.as_ref()
            .ok_or_else(|| anyhow::anyhow!("DB key not available"))?;
        let mut mac = <H as hmac::Mac>::new_from_slice(db_key)
            .map_err(|e| anyhow::anyhow!("HMAC init: {}", e))?;
        mac.update(b"nickname-key:");
        mac.update(pubkey.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    
    // Encrypt pubkey + nickname together: "pubkey\0nickname"
    let mut payload = pubkey.as_bytes().to_vec();
    payload.push(0); // separator
    payload.extend_from_slice(nickname.as_bytes());
    let encrypted = db_crypto::encrypt_for_db(state, &payload).await?;
    let encrypted_hex = hex::encode(&encrypted);
    
    sqlx::query(
        r#"
        INSERT INTO nicknames (pubkey, nickname) VALUES (?1, ?2)
        ON CONFLICT(pubkey) DO UPDATE SET nickname = excluded.nickname
        "#
    )
    .bind(&pubkey_hash)
    .bind(&encrypted_hex)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Get all nicknames as (pubkey, nickname) pairs, decrypting from at-rest encryption.
pub async fn get_all_nicknames(state: &AppState) -> Result<Vec<(String, String)>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT pubkey, nickname FROM nicknames"
    )
    .fetch_all(pool)
    .await?;
    
    // Decrypt each row: the "nickname" column contains hex-encoded encrypted "pubkey\0nickname"
    let mut result = Vec::with_capacity(rows.len());
    for (_pubkey_hash, encrypted_hex) in rows {
        if let Ok(encrypted_bytes) = hex::decode(&encrypted_hex) {
            if let Ok(plaintext) = db_crypto::decrypt_for_db(state, &encrypted_bytes).await {
                // Split on null byte separator
                if let Some(sep_pos) = plaintext.iter().position(|&b| b == 0) {
                    let pubkey = String::from_utf8_lossy(&plaintext[..sep_pos]).to_string();
                    let nickname = String::from_utf8_lossy(&plaintext[sep_pos + 1..]).to_string();
                    result.push((pubkey, nickname));
                }
            }
        }
        // Skip rows we can't decrypt (legacy unencrypted entries)
    }
    
    Ok(result)
}

// ─── App Settings ───────────────────────────────────────────────────────────

/// Get a setting value by key, decrypting from at-rest encryption.
pub async fn get_setting(state: &AppState, key: &str) -> Result<Option<String>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    // Hash the key for indexing
    let key_hash = hash_setting_key(state, key).await?;
    
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM app_settings WHERE key = ?1"
    )
    .bind(&key_hash)
    .fetch_optional(pool)
    .await?;
    
    // Decrypt the value
    match row {
        Some((encrypted_hex,)) => {
            if let Ok(encrypted_bytes) = hex::decode(&encrypted_hex) {
                if let Ok(plaintext) = db_crypto::decrypt_for_db(state, &encrypted_bytes).await {
                    return Ok(Some(String::from_utf8_lossy(&plaintext).to_string()));
                }
            }
            // Fallback for legacy unencrypted values
            Ok(Some(encrypted_hex))
        }
        None => Ok(None),
    }
}

/// Set a setting value, encrypting at rest.
pub async fn set_setting(state: &AppState, key: &str, value: &str) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    // Hash the key for indexing
    let key_hash = hash_setting_key(state, key).await?;
    
    // Encrypt the value
    let encrypted = db_crypto::encrypt_for_db(state, value.as_bytes()).await?;
    let encrypted_hex = hex::encode(&encrypted);
    
    sqlx::query(
        r#"
        INSERT INTO app_settings (key, value) VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        "#
    )
    .bind(&key_hash)
    .bind(&encrypted_hex)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Hash a setting key for deterministic DB indexing.
async fn hash_setting_key(state: &AppState, key: &str) -> Result<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type H = Hmac<Sha256>;
    
    let key_guard = state.db_key.read().await;
    let db_key = key_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("DB key not available"))?;
    let mut mac = <H as hmac::Mac>::new_from_slice(db_key)
        .map_err(|e| anyhow::anyhow!("HMAC init: {}", e))?;
    mac.update(b"setting-key:");
    mac.update(key.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

// ─── Double Ratchet Session Persistence ─────────────────────────────────────

/// Save a Double Ratchet session state for a peer, encrypted at rest.
///
/// `peer_pubkey` is the peer's Ed25519 public key (hex).
/// `ratchet_bytes` is the serialized ratchet state (from `DoubleRatchet::save()`).
/// `associated_data` is the X3DH AD (IK_A || IK_B) needed for encrypt/decrypt.
pub async fn save_ratchet_session(
    state: &AppState,
    peer_pubkey: &str,
    ratchet_bytes: &[u8],
    associated_data: &[u8],
) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let encrypted_state = db_crypto::encrypt_for_db(state, ratchet_bytes).await?;
    let encrypted_ad = db_crypto::encrypt_for_db(state, associated_data).await?;
    
    sqlx::query(
        r#"
        INSERT INTO ratchet_sessions (peer_pubkey, encrypted_state, associated_data)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(peer_pubkey) DO UPDATE SET
            encrypted_state = excluded.encrypted_state,
            associated_data = excluded.associated_data,
            updated_at = strftime('%s', 'now')
        "#
    )
    .bind(peer_pubkey)
    .bind(&encrypted_state)
    .bind(&encrypted_ad)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Load a Double Ratchet session state for a peer, decrypting from at-rest storage.
///
/// Returns `(ratchet_state_bytes, associated_data)` or None if no session exists.
pub async fn load_ratchet_session(
    state: &AppState,
    peer_pubkey: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT encrypted_state, associated_data FROM ratchet_sessions WHERE peer_pubkey = ?1"
    )
    .bind(peer_pubkey)
    .fetch_optional(pool)
    .await?;
    
    match row {
        Some((encrypted_state, encrypted_ad)) => {
            let ratchet_bytes = db_crypto::decrypt_for_db(state, &encrypted_state).await?;
            let ad = db_crypto::decrypt_for_db(state, &encrypted_ad).await?;
            Ok(Some((ratchet_bytes, ad)))
        }
        None => Ok(None),
    }
}

/// Delete a ratchet session from the DB (e.g., when it's detected as corrupt).
pub async fn delete_ratchet_session(
    state: &AppState,
    peer_pubkey: &str,
) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

    sqlx::query("DELETE FROM ratchet_sessions WHERE peer_pubkey = ?1")
        .bind(peer_pubkey)
        .execute(pool)
        .await?;

    Ok(())
}

/// Load all ratchet sessions from the DB (for restoring on app unlock).
pub async fn load_all_ratchet_sessions(
    state: &AppState,
) -> Result<Vec<(String, Vec<u8>, Vec<u8>)>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT peer_pubkey, encrypted_state, associated_data FROM ratchet_sessions"
    )
    .fetch_all(pool)
    .await?;
    
    let mut result = Vec::with_capacity(rows.len());
    for (peer, encrypted_state, encrypted_ad) in rows {
        match (
            db_crypto::decrypt_for_db(state, &encrypted_state).await,
            db_crypto::decrypt_for_db(state, &encrypted_ad).await,
        ) {
            (Ok(ratchet_bytes), Ok(ad)) => {
                result.push((peer, ratchet_bytes, ad));
            }
            _ => {
                tracing::warn!("Failed to decrypt ratchet session for peer {} — skipping", &peer[..16.min(peer.len())]);
            }
        }
    }
    
    Ok(result)
}

// ─── Pre-Key Material Persistence ───────────────────────────────────────────

/// Save our private pre-key material (encrypted at rest).
///
/// `spk_bytes` is the 32-byte raw signed pre-key secret.
/// `otpk_bytes_list` is a list of 32-byte one-time pre-key secrets.
pub async fn save_prekey_material(
    state: &AppState,
    spk_bytes: &[u8; 32],
    otpk_bytes_list: &[Vec<u8>],
) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let encrypted_spk = db_crypto::encrypt_for_db(state, spk_bytes).await?;
    
    // Serialize the OTPKs as MessagePack
    let otpk_blob = rmp_serde::to_vec(otpk_bytes_list)
        .map_err(|e| anyhow::anyhow!("Failed to serialize OTPKs: {}", e))?;
    let encrypted_otpk = db_crypto::encrypt_for_db(state, &otpk_blob).await?;
    
    sqlx::query(
        r#"
        INSERT INTO prekey_material (key, signed_prekey_bytes, one_time_prekey_bytes)
        VALUES ('current', ?1, ?2)
        ON CONFLICT(key) DO UPDATE SET
            signed_prekey_bytes = excluded.signed_prekey_bytes,
            one_time_prekey_bytes = excluded.one_time_prekey_bytes,
            updated_at = strftime('%s', 'now')
        "#
    )
    .bind(&encrypted_spk)
    .bind(&encrypted_otpk)
    .execute(pool)
    .await?;
    
    Ok(())
}

// ─── Joined Channels (for auto-rejoin on reconnect) ─────────────────────────

/// Record that we joined a channel (encrypted name stored at rest).
pub async fn add_joined_channel(state: &AppState, channel_id: &str, name: &str) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

    let encrypted_name = db_crypto::encrypt_for_db(state, name.as_bytes()).await?;
    let name_hex = hex::encode(&encrypted_name);

    sqlx::query(
        r#"
        INSERT INTO joined_channels (channel_id, encrypted_name) VALUES (?1, ?2)
        ON CONFLICT(channel_id) DO UPDATE SET encrypted_name = excluded.encrypted_name
        "#
    )
    .bind(channel_id)
    .bind(&name_hex)
    .execute(pool)
    .await?;

    Ok(())
}

/// Remove a channel from the joined list (on explicit leave).
pub async fn remove_joined_channel(state: &AppState, channel_id: &str) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

    sqlx::query("DELETE FROM joined_channels WHERE channel_id = ?1")
        .bind(channel_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all joined channel IDs (for auto-rejoin on reconnect).
pub async fn get_joined_channels(state: &AppState) -> Result<Vec<String>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT channel_id FROM joined_channels"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Delete all sender key sessions for a channel (on rotation after member leave).
pub async fn delete_sender_keys_for_channel(state: &AppState, channel_id: &str) -> Result<()> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

    sqlx::query("DELETE FROM sender_key_sessions WHERE channel_id = ?1")
        .bind(channel_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Load our private pre-key material (decrypted from at-rest storage).
///
/// Returns `(spk_bytes_32, vec_of_otpk_bytes)` or None.
pub async fn load_prekey_material(
    state: &AppState,
) -> Result<Option<([u8; 32], Vec<Vec<u8>>)>> {
    let db_guard = state.db.read().await;
    let pool = db_guard.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;
    
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT signed_prekey_bytes, one_time_prekey_bytes FROM prekey_material WHERE key = 'current'"
    )
    .fetch_optional(pool)
    .await?;
    
    match row {
        Some((encrypted_spk, encrypted_otpk)) => {
            let spk_bytes = db_crypto::decrypt_for_db(state, &encrypted_spk).await?;
            if spk_bytes.len() != 32 {
                return Err(anyhow::anyhow!("Invalid SPK length: {}", spk_bytes.len()));
            }
            let mut spk_arr = [0u8; 32];
            spk_arr.copy_from_slice(&spk_bytes);
            
            let otpk_blob = db_crypto::decrypt_for_db(state, &encrypted_otpk).await?;
            let otpk_list: Vec<Vec<u8>> = rmp_serde::from_slice(&otpk_blob).unwrap_or_default();
            
            Ok(Some((spk_arr, otpk_list)))
        }
        None => Ok(None),
    }
}