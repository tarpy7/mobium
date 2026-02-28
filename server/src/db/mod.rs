//! Database abstraction layer
//!
//! Defines the `DatabaseBackend` trait that abstracts all database operations.
//! Community servers use SQLite, managed servers use PostgreSQL.

pub mod sqlite;

use anyhow::Result;
use async_trait::async_trait;

/// Abstraction over database operations for both SQLite and PostgreSQL backends.
#[async_trait]
pub trait DatabaseBackend: Send + Sync + 'static {
    // ── Initialization ───────────────────────────────────────────────────
    async fn run_migrations(&self) -> Result<()>;

    // ── Users ────────────────────────────────────────────────────────────
    async fn store_user(
        &self, pubkey: &[u8], x25519_pub: Option<&[u8]>,
        encrypted_prekeys: Option<&[u8]>,
    ) -> Result<()>;

    async fn update_last_seen(&self, pubkey: &[u8]) -> Result<()>;

    // ── Pre-keys (X3DH) ─────────────────────────────────────────────────
    async fn store_prekey_bundle(
        &self, user_pubkey: &[u8], identity_x25519_pub: &[u8],
        signed_prekey: &[u8], signed_prekey_sig: &[u8],
        one_time_prekeys: &[u8],
    ) -> Result<()>;

    async fn get_and_consume_prekey_bundle(
        &self, user_pubkey: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<usize>)>>;

    async fn count_one_time_prekeys(&self, user_pubkey: &[u8]) -> Result<usize>;

    // ── Offline messages ─────────────────────────────────────────────────
    async fn store_offline_message(
        &self, recipient: &[u8], sender: &[u8], payload: &[u8],
    ) -> Result<i64>;

    async fn get_offline_messages(
        &self, recipient: &[u8], limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64)>>;

    async fn delete_offline_messages(&self, ids: &[i64]) -> Result<()>;
    async fn count_offline_messages(&self, recipient: &[u8]) -> Result<i64>;

    // ── Channels ─────────────────────────────────────────────────────────
    async fn create_channel(
        &self, channel_id: &[u8], encrypted_metadata: &[u8],
        creator_pubkey: &[u8],
    ) -> Result<()>;

    async fn channel_exists(&self, channel_id: &[u8]) -> Result<bool>;
    async fn add_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<()>;
    async fn remove_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<()>;
    async fn is_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<bool>;
    async fn get_channel_members(&self, channel_id: &[u8]) -> Result<Vec<Vec<u8>>>;
    async fn get_channel_members_with_keys(
        &self, channel_id: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    // ── Channel access control ───────────────────────────────────────────
    async fn get_channel_access(
        &self, channel_id: &[u8],
    ) -> Result<Option<(String, Option<Vec<u8>>)>>;
    async fn set_channel_access_mode(
        &self, channel_id: &[u8], access_mode: &str,
    ) -> Result<()>;

    // ── Invites ──────────────────────────────────────────────────────────
    async fn create_invite(
        &self, token: &[u8], channel_id: &[u8], created_by: &[u8],
        uses: i64, expires_at: Option<i64>,
    ) -> Result<()>;
    async fn consume_invite(&self, token: &[u8]) -> Result<Option<Vec<u8>>>;

    // ── Channel messages ─────────────────────────────────────────────────
    async fn store_channel_message(
        &self, channel_id: &[u8], sender: &[u8],
        payload: &[u8], bucket_size: i64,
    ) -> Result<i64>;

    async fn get_channel_history(
        &self, channel_id: &[u8], user_pubkey: &[u8],
        after_timestamp: i64, limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64, i64)>>;

    // ── Sender keys ──────────────────────────────────────────────────────
    async fn store_sender_key_distribution(
        &self, channel_id: &[u8], sender: &[u8], recipient: &[u8],
        sender_x25519_pub: &[u8], encrypted_dist: &[u8],
    ) -> Result<()>;

    async fn get_sender_keys_for_recipient(
        &self, channel_id: &[u8], recipient: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>;

    // ── TTL cleanup ──────────────────────────────────────────────────────
    async fn purge_expired_messages(&self, ttl_seconds: i64) -> Result<u64>;
    async fn purge_expired_offline_messages(&self, ttl_seconds: i64) -> Result<u64>;
}
