//! SQLite implementation of DatabaseBackend
//!
//! This wraps the existing database.rs functions to implement the trait.
//! The community server uses this backend.

use super::DatabaseBackend;
use anyhow::Result;
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use crate::database;

pub struct SqliteBackend {
    pool: Pool<Sqlite>,
}

impl SqliteBackend {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }
}

#[async_trait]
impl DatabaseBackend for SqliteBackend {
    async fn run_migrations(&self) -> Result<()> {
        database::run_migrations(&self.pool).await
    }

    async fn store_user(&self, pubkey: &[u8], x25519_pub: Option<&[u8]>, encrypted_prekeys: Option<&[u8]>) -> Result<()> {
        database::store_user(&self.pool, pubkey, x25519_pub, encrypted_prekeys).await
    }

    async fn update_last_seen(&self, pubkey: &[u8]) -> Result<()> {
        database::update_last_seen(&self.pool, pubkey).await
    }

    async fn store_prekey_bundle(
        &self, user_pubkey: &[u8], identity_x25519_pub: &[u8],
        signed_prekey: &[u8], signed_prekey_sig: &[u8],
        one_time_prekeys: &[u8],
    ) -> Result<()> {
        database::store_prekey_bundle(
            &self.pool, user_pubkey, identity_x25519_pub,
            signed_prekey, signed_prekey_sig, one_time_prekeys,
        ).await
    }

    async fn get_and_consume_prekey_bundle(
        &self, user_pubkey: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<usize>)>> {
        database::get_and_consume_prekey_bundle(&self.pool, user_pubkey).await
    }

    async fn count_one_time_prekeys(&self, user_pubkey: &[u8]) -> Result<usize> {
        database::count_one_time_prekeys(&self.pool, user_pubkey).await
    }

    async fn store_offline_message(
        &self, recipient: &[u8], sender: &[u8], payload: &[u8],
    ) -> Result<i64> {
        database::store_offline_message(&self.pool, recipient, sender, payload).await
    }

    async fn get_offline_messages(
        &self, recipient: &[u8], limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64)>> {
        database::get_offline_messages(&self.pool, recipient, limit).await
    }

    async fn delete_offline_messages(&self, ids: &[i64]) -> Result<()> {
        database::delete_offline_messages(&self.pool, ids).await
    }

    async fn count_offline_messages(&self, recipient: &[u8]) -> Result<i64> {
        database::count_offline_messages(&self.pool, recipient).await
    }

    async fn create_channel(
        &self, channel_id: &[u8], encrypted_metadata: &[u8],
        creator_pubkey: &[u8],
    ) -> Result<()> {
        database::create_channel(&self.pool, channel_id, encrypted_metadata, creator_pubkey).await
    }

    async fn channel_exists(&self, channel_id: &[u8]) -> Result<bool> {
        database::channel_exists(&self.pool, channel_id).await
    }

    async fn add_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<()> {
        database::add_channel_member(&self.pool, channel_id, user_pubkey).await
    }

    async fn remove_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<()> {
        database::remove_channel_member(&self.pool, channel_id, user_pubkey).await
    }

    async fn is_channel_member(&self, channel_id: &[u8], user_pubkey: &[u8]) -> Result<bool> {
        database::is_channel_member(&self.pool, channel_id, user_pubkey).await
    }

    async fn get_channel_members(&self, channel_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        database::get_channel_members(&self.pool, channel_id).await
    }

    async fn get_channel_members_with_keys(
        &self, channel_id: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        database::get_channel_members_with_keys(&self.pool, channel_id).await
    }

    async fn get_channel_access(
        &self, channel_id: &[u8],
    ) -> Result<Option<(String, Option<Vec<u8>>)>> {
        database::get_channel_access(&self.pool, channel_id).await
    }

    async fn set_channel_access_mode(
        &self, channel_id: &[u8], access_mode: &str,
    ) -> Result<()> {
        database::set_channel_access_mode(&self.pool, channel_id, access_mode).await
    }

    async fn create_invite(
        &self, token: &[u8], channel_id: &[u8], created_by: &[u8],
        uses: i64, expires_at: Option<i64>,
    ) -> Result<()> {
        database::create_invite(&self.pool, token, channel_id, created_by, uses, expires_at).await
    }

    async fn consume_invite(&self, token: &[u8]) -> Result<Option<Vec<u8>>> {
        database::consume_invite(&self.pool, token).await
    }

    async fn store_channel_message(
        &self, channel_id: &[u8], sender: &[u8],
        payload: &[u8], bucket_size: i64,
    ) -> Result<i64> {
        database::store_channel_message(&self.pool, channel_id, sender, payload, bucket_size).await
    }

    async fn get_channel_history(
        &self, channel_id: &[u8], user_pubkey: &[u8],
        after_timestamp: i64, limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>, Vec<u8>, i64, i64)>> {
        database::get_channel_history(&self.pool, channel_id, user_pubkey, after_timestamp, limit).await
    }

    async fn store_sender_key_distribution(
        &self, channel_id: &[u8], sender: &[u8], recipient: &[u8],
        sender_x25519_pub: &[u8], encrypted_dist: &[u8],
    ) -> Result<()> {
        database::store_sender_key_distribution(
            &self.pool, channel_id, sender, recipient,
            sender_x25519_pub, encrypted_dist,
        ).await
    }

    async fn get_sender_keys_for_recipient(
        &self, channel_id: &[u8], recipient: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
        database::get_sender_keys_for_recipient(&self.pool, channel_id, recipient).await
    }

    async fn purge_expired_messages(&self, ttl_seconds: i64) -> Result<u64> {
        database::purge_expired_messages(&self.pool, ttl_seconds).await
    }

    async fn purge_expired_offline_messages(&self, ttl_seconds: i64) -> Result<u64> {
        database::purge_expired_offline_messages(&self.pool, ttl_seconds).await
    }
}
