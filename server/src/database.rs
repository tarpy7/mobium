//! Database operations

use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, migrate::MigrateDatabase};
use anyhow::Result;
use tracing::info;

/// Initialize the database connection pool
pub async fn init(database_url: &str) -> Result<Pool<Sqlite>> {
    // Create database file if it doesn't exist
    if !sqlx::Sqlite::database_exists(database_url).await.unwrap_or(false) {
        info!("Creating database at {}", database_url);
        sqlx::Sqlite::create_database(database_url).await?;
    }

    // Create connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    // Run migrations
    run_migrations(&pool).await?;

    Ok(pool)
}

/// Run database migrations
pub async fn run_migrations(pool: &Pool<Sqlite>) -> Result<()> {
    info!("Running database migrations");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            pubkey BLOB PRIMARY KEY,
            x25519_pub BLOB,
            last_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            encrypted_prekeys BLOB,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS offline_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_pubkey BLOB NOT NULL,
            sender_pubkey BLOB NOT NULL,
            encrypted_payload BLOB NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (recipient_pubkey) REFERENCES users(pubkey)
        );
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_offline_messages_recipient 
        ON offline_messages(recipient_pubkey);
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS channels (
            id BLOB PRIMARY KEY,
            encrypted_metadata BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        "#
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS channel_members (
            channel_id BLOB NOT NULL,
            user_pubkey BLOB NOT NULL,
            joined_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (channel_id, user_pubkey),
            FOREIGN KEY (channel_id) REFERENCES channels(id),
            FOREIGN KEY (user_pubkey) REFERENCES users(pubkey)
        );
        "#
    )
    .execute(pool)
    .await?;

    // Channel messages table - stores one copy per message with bucket size for size masking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS channel_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id BLOB NOT NULL,
            encrypted_payload BLOB NOT NULL,
            bucket_size INTEGER NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            sender_pubkey BLOB NOT NULL
        );
        "#
    )
    .execute(pool)
    .await?;

    // Index for efficient channel history queries
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_channel_messages_channel_time 
        ON channel_messages(channel_id, timestamp);
        "#
    )
    .execute(pool)
    .await?;

    // Index for bucket size analysis
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_channel_messages_bucket 
        ON channel_messages(bucket_size);
        "#
    )
    .execute(pool)
    .await?;

    // Stored sender key distributions — the server holds encrypted blobs
    // so that new joiners or reconnecting clients can retrieve keys reliably.
    // Each entry is encrypted for a specific recipient (zero-knowledge: server
    // sees only opaque ciphertext).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sender_key_store (
            channel_id BLOB NOT NULL,
            sender_pubkey BLOB NOT NULL,
            recipient_pubkey BLOB NOT NULL,
            sender_x25519_pub BLOB NOT NULL,
            encrypted_distribution BLOB NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (channel_id, sender_pubkey, recipient_pubkey)
        );
        "#
    )
    .execute(pool)
    .await?;

    // Pre-key bundles for X3DH key agreement (DMs).
    // Each user publishes their signed pre-key + one-time pre-keys.
    // The server stores these as public key material (not encrypted secrets).
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS prekey_bundles (
            user_pubkey BLOB PRIMARY KEY,
            identity_x25519_pub BLOB NOT NULL,
            signed_prekey BLOB NOT NULL,
            signed_prekey_sig BLOB NOT NULL,
            one_time_prekeys BLOB NOT NULL DEFAULT X'',
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (user_pubkey) REFERENCES users(pubkey)
        );
        "#
    )
    .execute(pool)
    .await?;

    // Channel access control: add access_mode and creator columns if missing
    // access_mode: 'public' (default, anyone can join), 'private' (invite only)
    // creator_pubkey: who created the channel (can generate invites)
    sqlx::query("ALTER TABLE channels ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'public'")
        .execute(pool).await.ok(); // ignore if column exists
    sqlx::query("ALTER TABLE channels ADD COLUMN creator_pubkey BLOB")
        .execute(pool).await.ok();

    // Invite tokens for private channels
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS channel_invites (
            token BLOB PRIMARY KEY,
            channel_id BLOB NOT NULL,
            created_by BLOB NOT NULL,
            uses_remaining INTEGER NOT NULL DEFAULT 1,
            expires_at INTEGER,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (channel_id) REFERENCES channels(id)
        );
        "#
    )
    .execute(pool)
    .await?;

    info!("Migrations completed successfully");
    Ok(())
}

/// Store (or update) a user's pre-key bundle for X3DH key agreement.
///
/// `one_time_prekeys` is a MessagePack-encoded list of 32-byte X25519 public keys.
pub async fn store_prekey_bundle(
    pool: &Pool<Sqlite>,
    user_pubkey: &[u8],
    identity_x25519_pub: &[u8],
    signed_prekey: &[u8],
    signed_prekey_sig: &[u8],
    one_time_prekeys: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO prekey_bundles (user_pubkey, identity_x25519_pub, signed_prekey, signed_prekey_sig, one_time_prekeys)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(user_pubkey) DO UPDATE SET
            identity_x25519_pub = excluded.identity_x25519_pub,
            signed_prekey = excluded.signed_prekey,
            signed_prekey_sig = excluded.signed_prekey_sig,
            one_time_prekeys = excluded.one_time_prekeys,
            updated_at = strftime('%s', 'now')
        "#
    )
    .bind(user_pubkey)
    .bind(identity_x25519_pub)
    .bind(signed_prekey)
    .bind(signed_prekey_sig)
    .bind(one_time_prekeys)
    .execute(pool)
    .await?;

    Ok(())
}

/// Retrieve a user's pre-key bundle and consume one one-time pre-key.
///
/// Returns `(identity_x25519_pub, signed_prekey, signed_prekey_sig, one_time_prekey_or_none, otpk_index_or_none)`.
/// If one-time pre-keys are available, the first one is consumed (removed from the list).
pub async fn get_and_consume_prekey_bundle(
    pool: &Pool<Sqlite>,
    user_pubkey: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<usize>)>> {
    // Fetch the bundle
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT identity_x25519_pub, signed_prekey, signed_prekey_sig, one_time_prekeys
        FROM prekey_bundles
        WHERE user_pubkey = ?1
        "#
    )
    .bind(user_pubkey)
    .fetch_optional(pool)
    .await?;

    let (identity_x25519_pub, signed_prekey, signed_prekey_sig, otpk_blob) = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    // Decode one-time pre-keys from MessagePack: Vec<Vec<u8>> (list of 32-byte keys)
    let mut otpks: Vec<Vec<u8>> = if otpk_blob.is_empty() {
        Vec::new()
    } else {
        rmp_serde::from_slice(&otpk_blob).unwrap_or_default()
    };

    let (consumed_otpk, otpk_index) = if !otpks.is_empty() {
        let key = otpks.remove(0);
        let idx = 0usize; // always consume the first available
        // Update the DB with the remaining keys
        let remaining_blob = rmp_serde::to_vec(&otpks)?;
        sqlx::query(
            r#"
            UPDATE prekey_bundles SET one_time_prekeys = ?1, updated_at = strftime('%s', 'now')
            WHERE user_pubkey = ?2
            "#
        )
        .bind(&remaining_blob)
        .bind(user_pubkey)
        .execute(pool)
        .await?;
        (Some(key), Some(idx))
    } else {
        (None, None)
    };

    Ok(Some((identity_x25519_pub, signed_prekey, signed_prekey_sig, consumed_otpk, otpk_index)))
}

/// Get the count of remaining one-time pre-keys for a user.
pub async fn count_one_time_prekeys(
    pool: &Pool<Sqlite>,
    user_pubkey: &[u8],
) -> Result<usize> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT one_time_prekeys FROM prekey_bundles WHERE user_pubkey = ?1"
    )
    .bind(user_pubkey)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((blob,)) if !blob.is_empty() => {
            let otpks: Vec<Vec<u8>> = rmp_serde::from_slice(&blob).unwrap_or_default();
            Ok(otpks.len())
        }
        _ => Ok(0),
    }
}

/// Store (or update) an encrypted sender key distribution for a specific recipient.
pub async fn store_sender_key_distribution(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    sender_pubkey: &[u8],
    recipient_pubkey: &[u8],
    sender_x25519_pub: &[u8],
    encrypted_distribution: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO sender_key_store (channel_id, sender_pubkey, recipient_pubkey, sender_x25519_pub, encrypted_distribution)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(channel_id, sender_pubkey, recipient_pubkey) DO UPDATE SET
            sender_x25519_pub = excluded.sender_x25519_pub,
            encrypted_distribution = excluded.encrypted_distribution,
            updated_at = strftime('%s', 'now')
        "#
    )
    .bind(channel_id)
    .bind(sender_pubkey)
    .bind(recipient_pubkey)
    .bind(sender_x25519_pub)
    .bind(encrypted_distribution)
    .execute(pool)
    .await?;

    Ok(())
}

/// Retrieve all stored sender key distributions for a recipient in a channel.
/// Returns (sender_pubkey, sender_x25519_pub, encrypted_distribution) tuples.
pub async fn get_sender_keys_for_recipient(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    recipient_pubkey: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT sender_pubkey, sender_x25519_pub, encrypted_distribution
        FROM sender_key_store
        WHERE channel_id = ?1 AND recipient_pubkey = ?2
        "#
    )
    .bind(channel_id)
    .bind(recipient_pubkey)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Store a user
pub async fn store_user(
    pool: &Pool<Sqlite>,
    pubkey: &[u8],
    x25519_pub: Option<&[u8]>,
    encrypted_prekeys: Option<&[u8]>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO users (pubkey, x25519_pub, encrypted_prekeys)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(pubkey) DO UPDATE SET
            x25519_pub = COALESCE(excluded.x25519_pub, users.x25519_pub),
            encrypted_prekeys = excluded.encrypted_prekeys,
            last_seen = strftime('%s', 'now')
        "#
    )
    .bind(pubkey)
    .bind(x25519_pub)
    .bind(encrypted_prekeys)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update user last seen
#[allow(dead_code)]
pub async fn update_last_seen(pool: &Pool<Sqlite>, pubkey: &[u8]) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE users SET last_seen = strftime('%s', 'now') WHERE pubkey = ?1
        "#
    )
    .bind(pubkey)
    .execute(pool)
    .await?;

    Ok(())
}

/// Store an offline message
pub async fn store_offline_message(
    pool: &Pool<Sqlite>,
    recipient_pubkey: &[u8],
    sender_pubkey: &[u8],
    encrypted_payload: &[u8],
) -> Result<i64> {
    let result = sqlx::query(
        r#"
        INSERT INTO offline_messages (recipient_pubkey, sender_pubkey, encrypted_payload)
        VALUES (?1, ?2, ?3)
        "#
    )
    .bind(recipient_pubkey)
    .bind(sender_pubkey)
    .bind(encrypted_payload)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get offline messages for a user
pub async fn get_offline_messages(
    pool: &Pool<Sqlite>,
    recipient_pubkey: &[u8],
    limit: i64,
) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64)>> {
    let rows = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>, i64)>(
        r#"
        SELECT id, sender_pubkey, encrypted_payload, CAST(timestamp AS INTEGER)
        FROM offline_messages
        WHERE recipient_pubkey = ?1
        ORDER BY timestamp ASC
        LIMIT ?2
        "#
    )
    .bind(recipient_pubkey)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete offline messages by IDs (batched for efficiency)
pub async fn delete_offline_messages(pool: &Pool<Sqlite>, ids: &[i64]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    
    // Build a single DELETE with parameterised IN clause.
    // SQLite supports up to 999 parameters; batch if needed.
    for chunk in ids.chunks(500) {
        let placeholders: String = chunk.iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM offline_messages WHERE id IN ({})", placeholders);
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(id);
        }
        query.execute(pool).await?;
    }

    Ok(())
}

/// Count offline messages for a user
pub async fn count_offline_messages(pool: &Pool<Sqlite>, recipient_pubkey: &[u8]) -> Result<i64> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM offline_messages WHERE recipient_pubkey = ?1
        "#
    )
    .bind(recipient_pubkey)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Store a channel message (one copy for all members)
/// 
/// The server stores the encrypted payload but cannot decrypt it.
/// bucket_size is 0-13 corresponding to SIZE_BUCKETS for traffic analysis resistance.
pub async fn store_channel_message(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    sender_pubkey: &[u8],
    encrypted_payload: &[u8],
    bucket_size: i64,
) -> Result<i64> {
    let result = sqlx::query(
        r#"
        INSERT INTO channel_messages (channel_id, sender_pubkey, encrypted_payload, bucket_size)
        VALUES (?1, ?2, ?3, ?4)
        "#
    )
    .bind(channel_id)
    .bind(sender_pubkey)
    .bind(encrypted_payload)
    .bind(bucket_size)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get channel history for a user
/// 
/// Returns messages where:
/// - Message timestamp >= user's joined_at time
/// - Message timestamp > after_timestamp (for pagination)
/// 
/// User must be a member of the channel to receive history.
pub async fn get_channel_history(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    user_pubkey: &[u8],
    after_timestamp: i64,
    limit: i64,
) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64, i64)>> {
    // First verify user is a member and get their join time
    let join_time: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT joined_at FROM channel_members 
        WHERE channel_id = ?1 AND user_pubkey = ?2
        "#
    )
    .bind(channel_id)
    .bind(user_pubkey)
    .fetch_optional(pool)
    .await?;

    // If user is not a member, return empty (don't reveal channel exists)
    let joined_at = match join_time {
        Some(time) => time,
        None => return Ok(vec![]),
    };

    // Calculate effective start time (max of joined_at and after_timestamp)
    let start_time = std::cmp::max(joined_at, after_timestamp);

    // Fetch messages
    let rows = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>, i64, i64)>(
        r#"
        SELECT id, sender_pubkey, encrypted_payload, timestamp, bucket_size
        FROM channel_messages
        WHERE channel_id = ?1 AND timestamp > ?2
        ORDER BY timestamp ASC
        LIMIT ?3
        "#
    )
    .bind(channel_id)
    .bind(start_time)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Check if a channel exists
#[allow(dead_code)]
pub async fn channel_exists(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
) -> Result<bool> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE id = ?1")
        .bind(channel_id)
        .fetch_one(pool)
        .await?;
    Ok(count > 0)
}

/// Create a new channel
pub async fn create_channel(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    encrypted_metadata: &[u8],
    creator_pubkey: &[u8],
) -> Result<()> {
    // Insert channel with creator and default public access
    sqlx::query(
        r#"
        INSERT INTO channels (id, encrypted_metadata, creator_pubkey, access_mode)
        VALUES (?1, ?2, ?3, 'public')
        "#
    )
    .bind(channel_id)
    .bind(encrypted_metadata)
    .bind(creator_pubkey)
    .execute(pool)
    .await?;

    // Add creator as first member
    sqlx::query(
        r#"
        INSERT INTO channel_members (channel_id, user_pubkey)
        VALUES (?1, ?2)
        "#
    )
    .bind(channel_id)
    .bind(creator_pubkey)
    .execute(pool)
    .await?;

    Ok(())
}

/// Add a member to a channel
pub async fn add_channel_member(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    user_pubkey: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO channel_members (channel_id, user_pubkey)
        VALUES (?1, ?2)
        ON CONFLICT(channel_id, user_pubkey) DO NOTHING
        "#
    )
    .bind(channel_id)
    .bind(user_pubkey)
    .execute(pool)
    .await?;

    Ok(())
}

/// Remove a member from a channel
pub async fn remove_channel_member(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    user_pubkey: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM channel_members 
        WHERE channel_id = ?1 AND user_pubkey = ?2
        "#
    )
    .bind(channel_id)
    .bind(user_pubkey)
    .execute(pool)
    .await?;

    Ok(())
}

/// Check if user is a channel member
pub async fn is_channel_member(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    user_pubkey: &[u8],
) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM channel_members 
        WHERE channel_id = ?1 AND user_pubkey = ?2
        "#
    )
    .bind(channel_id)
    .bind(user_pubkey)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

/// Delete channel messages older than the given TTL (in seconds).
///
/// Returns the number of deleted rows.
pub async fn purge_expired_messages(pool: &Pool<Sqlite>, ttl_seconds: i64) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM channel_messages
        WHERE timestamp < (strftime('%s', 'now') - ?1)
        "#
    )
    .bind(ttl_seconds)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Delete offline messages older than the given TTL (in seconds).
///
/// Returns the number of deleted rows.
pub async fn purge_expired_offline_messages(pool: &Pool<Sqlite>, ttl_seconds: i64) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM offline_messages
        WHERE timestamp < (strftime('%s', 'now') - ?1)
        "#
    )
    .bind(ttl_seconds)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Get channel member list (returns pubkeys only)
pub async fn get_channel_members(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        r#"
        SELECT user_pubkey FROM channel_members 
        WHERE channel_id = ?1
        "#
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Get channel members with their X25519 public keys.
/// Returns (ed25519_pubkey, x25519_pubkey_or_empty) tuples.
pub async fn get_channel_members_with_keys(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rows: Vec<(Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        r#"
        SELECT cm.user_pubkey, u.x25519_pub
        FROM channel_members cm
        LEFT JOIN users u ON cm.user_pubkey = u.pubkey
        WHERE cm.channel_id = ?1
        "#
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(pk, x)| (pk, x.unwrap_or_default())).collect())
}
/// Get channel access mode and creator
pub async fn get_channel_access(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
) -> Result<Option<(String, Option<Vec<u8>>)>> {
    let row: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT access_mode, creator_pubkey FROM channels WHERE id = ?1"
    )
    .bind(channel_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Set channel access mode (only creator can do this)
pub async fn set_channel_access_mode(
    pool: &Pool<Sqlite>,
    channel_id: &[u8],
    access_mode: &str,
) -> Result<()> {
    sqlx::query("UPDATE channels SET access_mode = ?1 WHERE id = ?2")
        .bind(access_mode)
        .bind(channel_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Create an invite token for a private channel
pub async fn create_invite(
    pool: &Pool<Sqlite>,
    token: &[u8],
    channel_id: &[u8],
    created_by: &[u8],
    uses: i64,
    expires_at: Option<i64>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO channel_invites (token, channel_id, created_by, uses_remaining, expires_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#
    )
    .bind(token)
    .bind(channel_id)
    .bind(created_by)
    .bind(uses)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Consume an invite token. Returns the channel_id if valid.
pub async fn consume_invite(
    pool: &Pool<Sqlite>,
    token: &[u8],
) -> Result<Option<Vec<u8>>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let row: Option<(Vec<u8>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT channel_id, uses_remaining, expires_at FROM channel_invites WHERE token = ?1"
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((channel_id, uses, expires)) => {
            if uses <= 0 {
                return Ok(None); // exhausted
            }
            if let Some(exp) = expires {
                if now > exp {
                    return Ok(None); // expired
                }
            }
            // Decrement uses
            sqlx::query("UPDATE channel_invites SET uses_remaining = uses_remaining - 1 WHERE token = ?1")
                .bind(token)
                .execute(pool)
                .await?;
            Ok(Some(channel_id))
        }
        None => Ok(None),
    }
}
