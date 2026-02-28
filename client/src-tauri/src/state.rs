//! Application state

use mobium_shared::ratchet::DoubleRatchet;
use mobium_shared::sender_keys::{GroupSession, SenderKeyDistribution};
use mobium_shared::x3dh::PrivatePreKeys;
use mobium_shared::IdentityKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

/// Global application state
#[derive(Default)]
pub struct AppState {
    /// Currently active profile name (None until a profile is selected).
    /// Each profile is a subdirectory under the base data directory.
    pub active_profile: RwLock<Option<String>>,
    /// Current user identity (None if not initialized)
    pub identity: RwLock<Option<Arc<IdentityKey>>>,
    /// WebSocket connection state
    pub connection: RwLock<Option<Arc<crate::websocket::Connection>>>,
    /// Database connection pool
    pub db: RwLock<Option<sqlx::SqlitePool>>,
    /// Group sessions keyed by channel_id (hex)
    pub group_sessions: RwLock<HashMap<String, GroupSession>>,
    /// AES-256-GCM key for encrypting data at rest in the local DB.
    /// Derived from the user's password; only present while the app is unlocked.
    pub db_key: RwLock<Option<[u8; 32]>>,
    /// Last successfully connected server URL (persisted for auto-reconnect)
    pub last_server_url: RwLock<Option<String>>,
    /// Cached channel member pubkeys, keyed by channel_id (hex).
    /// Populated from server `members_response` messages.
    pub channel_members: RwLock<HashMap<String, Vec<Vec<u8>>>>,
    /// Cached Ed25519 → X25519 public key mapping.
    /// Populated from `members_with_keys` in the server's members_response.
    pub x25519_keys: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    /// Pending sender key distributions waiting for member list.
    /// Key: channel_id (hex), Value: SenderKeyDistribution to send once we know members.
    pub pending_distributions: RwLock<HashMap<String, SenderKeyDistribution>>,
    /// Buffered channel messages that could not be decrypted yet (missing sender key).
    /// Key: channel_id (hex), Value: vec of (sender_pubkey_bytes, payload_bytes, timestamp).
    /// Retried after receiving a sender_key_distribution for that channel.
    pub buffered_messages: RwLock<HashMap<String, Vec<(Vec<u8>, Vec<u8>, i64)>>>,

    // ─── DM / X3DH / Double Ratchet state ──────────────────────────────
    /// Active Double Ratchet sessions for DMs, keyed by peer Ed25519 pubkey (hex).
    pub ratchet_sessions: RwLock<HashMap<String, DoubleRatchet>>,
    /// X3DH associated data per peer session: IK_A || IK_B (64 bytes).
    /// Keyed by peer Ed25519 pubkey (hex).
    pub ratchet_ad: RwLock<HashMap<String, Vec<u8>>>,
    /// Our own private pre-key material for responding to incoming X3DH handshakes.
    pub our_prekeys: RwLock<Option<PrivatePreKeys>>,
    /// Raw bytes of the signed pre-key secret (needed for save/load of ratchet state).
    pub our_spk_bytes: RwLock<Option<[u8; 32]>>,
    /// Whether we have published pre-keys to the server for this session.
    pub prekeys_published: RwLock<bool>,
    /// Buffered DM messages that arrived before we had a ratchet session.
    /// Key: sender pubkey hex, Value: vec of raw DM payloads (MessagePack blobs).
    pub buffered_dms: RwLock<HashMap<String, Vec<Vec<u8>>>>,

    // ─── Voice signaling ────────────────────────────────────────────────
    /// Incoming voice signals buffered for frontend polling.
    /// The Tauri 2 event bus is unreliable for events emitted from spawned
    /// async tasks, so the frontend polls this queue instead.
    /// Each entry: (sender_hex, signal_type, payload_bytes).
    pub pending_voice_signals: RwLock<Vec<(String, String, Vec<u8>)>>,

    // ─── Channel voice chat ─────────────────────────────────────────────
    /// The channel_id (hex) we are currently in for voice chat (None if not in any).
    pub current_voice_channel: RwLock<Option<String>>,
    /// Incoming audio frames buffered for frontend polling (20ms interval).
    /// Each entry: (sender_hex, audio_bytes, sequence_number).
    pub pending_voice_data: RwLock<Vec<(String, Vec<u8>, u64)>>,
    /// Voice channel participant events buffered for frontend polling.
    /// Each entry: JSON-serialised event string (voice_joined, voice_left, voice_state).
    pub pending_voice_events: RwLock<Vec<String>>,

    // ─── Channel screen share ────────────────────────────────────────────
    /// Incoming encrypted screen share chunks buffered for frontend polling.
    /// Each entry: (sender_hex, chunk_bytes, sequence_number).
    pub pending_screen_data: RwLock<Vec<(String, Vec<u8>, u64)>>,
    /// Who is currently sharing their screen in the voice channel (pubkey hex, or None).
    pub screen_sharer: RwLock<Option<String>>,
}

impl AppState {
    /// Securely wipe all sensitive cryptographic material from memory.
    ///
    /// Call this when the user logs out, locks the app, or before the app
    /// exits. Takes write locks on every field that holds key material and
    /// either zeroizes it in-place or replaces it with an empty/`None` value
    /// so the previous allocation is dropped (triggering `ZeroizeOnDrop`
    /// where implemented).
    ///
    /// Fields cleared:
    /// - `db_key`        — AES-256-GCM database encryption key
    /// - `identity`      — Ed25519 + X25519 identity key pair
    /// - `our_prekeys`   — X3DH private pre-key material (SPK + OTPKs)
    /// - `our_spk_bytes` — Raw signed pre-key secret bytes
    /// - `ratchet_sessions` — All active Double Ratchet sessions (contain chain keys)
    /// - `ratchet_ad`    — X3DH associated data (identity key concatenation)
    /// - `group_sessions`— Sender Key group sessions (contain chain keys)
    /// - `buffered_dms`  — Potentially undecrypted DM payloads
    pub async fn lock_profile(&self) {
        // Zero the 32-byte DB encryption key in place
        {
            let mut guard = self.db_key.write().await;
            if let Some(ref mut key) = *guard {
                key.zeroize();
            }
            *guard = None;
        }

        // Drop identity (IdentityKey fields implement ZeroizeOnDrop)
        {
            let mut guard = self.identity.write().await;
            *guard = None;
        }

        // Drop pre-key material (PrivatePreKeys implements ZeroizeOnDrop)
        {
            let mut guard = self.our_prekeys.write().await;
            *guard = None;
        }

        // Zero the signed pre-key raw bytes
        {
            let mut guard = self.our_spk_bytes.write().await;
            if let Some(ref mut bytes) = *guard {
                bytes.zeroize();
            }
            *guard = None;
        }

        // Drop all Double Ratchet sessions (contain chain keys, skipped keys).
        // DoubleRatchet's Drop impl zeroizes internal key material.
        {
            let mut guard = self.ratchet_sessions.write().await;
            guard.clear();
        }

        // Clear X3DH associated data
        {
            let mut guard = self.ratchet_ad.write().await;
            for (_peer, mut ad) in guard.drain() {
                ad.zeroize();
            }
        }

        // Drop all group sessions (contain sender key chain state)
        {
            let mut guard = self.group_sessions.write().await;
            guard.clear();
        }

        // Clear buffered DMs (may contain ciphertext)
        {
            let mut guard = self.buffered_dms.write().await;
            guard.clear();
        }

        // Reset prekey-published flag
        {
            let mut guard = self.prekeys_published.write().await;
            *guard = false;
        }

        tracing::info!("lock_profile: all sensitive material zeroized");
    }
}
