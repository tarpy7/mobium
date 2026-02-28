//! Sender Keys for Group Messaging
//!
//! Each group member maintains their own symmetric ratchet chain.
//! When sending to a group, you advance YOUR chain and encrypt with the derived message key.
//! All other members hold a copy of your chain key so they can derive the same message keys.
//!
//! Properties:
//! - Forward secrecy: compromising a chain key only reveals future messages from that sender
//! - Efficient: O(1) encryption per message (vs O(N) for pairwise ratchets)
//! - Key rotation: when a member leaves, all remaining members rotate their sender keys
//!
//! Wire format for encrypted messages:
//! ```text
//! [4 bytes: sender_key_id (u32 BE)]  — identifies which sender chain to use
//! [4 bytes: iteration (u32 BE)]       — chain step number for this message
//! [12 bytes: nonce]                   — AES-GCM nonce
//! [N bytes: ciphertext + 16-byte tag] — AES-256-GCM encrypted (padded plaintext)
//! ```

use crate::error::{CryptoError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

/// Header size in the wire format: sender_key_id(4) + iteration(4) + nonce(12)
const HEADER_SIZE: usize = 4 + 4 + 12;

// ─── Sender Chain (one per member) ───────────────────────────────────────────

/// The state of a single sender's ratchet chain.
///
/// The *sender* advances `iteration` on every message they send.
/// Each *receiver* keeps a copy and advances it when decrypting.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SenderChainState {
    /// Current chain key (32 bytes).  Ratcheted forward on each message.
    chain_key: [u8; 32],
    /// Which step we are on (monotonically increasing).
    #[zeroize(skip)]
    iteration: u32,
    /// Unique id for this chain (stays constant across ratchet steps).
    #[zeroize(skip)]
    key_id: u32,
}

impl SenderChainState {
    /// Create a brand-new chain from a random 32-byte seed.
    pub fn new(seed: [u8; 32], key_id: u32) -> Self {
        Self {
            chain_key: seed,
            iteration: 0,
            key_id,
        }
    }

    /// Current iteration counter.
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    /// The key_id for this chain.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Derive the message key for the *current* iteration, then advance the chain.
    ///
    /// Returns `(message_key_32, nonce_12)`.
    fn ratchet(&mut self) -> Result<([u8; 32], [u8; 12])> {
        // message_key = HMAC-SHA256(chain_key, 0x01 || iteration_be)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key).map_err(
            |e: hmac::digest::InvalidLength| CryptoError::KeyDerivationError(e.to_string()),
        )?;
        mac.update(&[0x01]);
        mac.update(&self.iteration.to_be_bytes());
        let mk_full = mac.finalize().into_bytes();

        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&mk_full);

        // nonce = HMAC-SHA256(chain_key, 0x02 || iteration_be) truncated to 12 bytes
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key).map_err(
            |e: hmac::digest::InvalidLength| CryptoError::KeyDerivationError(e.to_string()),
        )?;
        mac.update(&[0x02]);
        mac.update(&self.iteration.to_be_bytes());
        let nonce_full = mac.finalize().into_bytes();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);

        // Advance chain: chain_key' = HMAC-SHA256(chain_key, 0x03)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key).map_err(
            |e: hmac::digest::InvalidLength| CryptoError::KeyDerivationError(e.to_string()),
        )?;
        mac.update(&[0x03]);
        let next = mac.finalize().into_bytes();
        self.chain_key.copy_from_slice(&next);

        self.iteration += 1;
        Ok((message_key, nonce))
    }

    /// Advance the chain to a target iteration, skipping intermediate keys.
    ///
    /// Returns the skipped `(iteration, message_key, nonce)` tuples.
    fn advance_to(&mut self, target: u32, max_skip: u32) -> Result<Vec<(u32, [u8; 32], [u8; 12])>> {
        if target < self.iteration {
            return Err(CryptoError::RatchetError(format!(
                "Cannot rewind chain: at {} but requested {}",
                self.iteration, target
            )));
        }
        let gap = target - self.iteration;
        if gap > max_skip {
            return Err(CryptoError::RatchetError(format!(
                "Too many skipped messages: {} (max {})",
                gap, max_skip
            )));
        }

        let mut skipped = Vec::with_capacity(gap as usize);
        while self.iteration < target {
            let iter = self.iteration;
            let (mk, nonce) = self.ratchet()?;
            skipped.push((iter, mk, nonce));
        }
        Ok(skipped)
    }
}

// ─── Sender Key Distribution message ────────────────────────────────────────

/// A message that distributes a sender's chain key to group members.
///
/// When you join (or rotate), you send one of these to every other member
/// (encrypted pairwise, e.g. via X3DH + Double Ratchet or an existing session).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SenderKeyDistribution {
    /// Channel / group id (hex or raw — up to transport layer)
    pub channel_id: Vec<u8>,
    /// The sender's public key (identifies who this chain belongs to)
    pub sender_pubkey: Vec<u8>,
    /// Unique id for this chain generation
    pub key_id: u32,
    /// The initial chain key seed (32 bytes) — **sensitive**
    pub chain_key: Vec<u8>,
    /// Starting iteration (normally 0, but could be non-zero on rotation)
    pub iteration: u32,
    /// Stable voice encryption key (32 bytes), derived once from the initial
    /// seed. Unlike the text chain key, this does NOT advance per-message,
    /// so voice frames never desync the text ratchet.
    /// Optional for backwards compatibility with distributions that predate voice.
    #[serde(default)]
    pub voice_key: Option<Vec<u8>>,
}

/// Derive a stable voice encryption key from an initial chain seed and key_id.
///
/// This key is used for AES-256-GCM encryption of voice frames and never
/// changes during the lifetime of a sender chain (unlike the text chain key
/// which advances on every message).
fn derive_voice_key(initial_seed: &[u8; 32], key_id: u32) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(initial_seed).expect("HMAC accepts any key length");
    mac.update(b"Mobium-voice-v1");
    mac.update(&key_id.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Header size for voice frames: key_id(4) + seq(8) = 12 bytes
const VOICE_HEADER_SIZE: usize = 4 + 8;

// ─── Group Session ──────────────────────────────────────────────────────────

/// A group session that manages sender chains for all members of a channel.
pub struct GroupSession {
    /// Our own sender chain (we are the only one who advances it when encrypting)
    my_chain: SenderChainState,
    /// Our public key (to tag outgoing messages)
    my_pubkey: Vec<u8>,
    /// Other members' sender chains, keyed by `(sender_pubkey_hex, key_id)`
    peer_chains: std::collections::HashMap<(String, u32), SenderChainState>,
    /// Skipped message keys for out-of-order decryption
    /// Key: (sender_pubkey_hex, key_id, iteration) → (message_key, nonce)
    skipped_keys: std::collections::HashMap<(String, u32, u32), ([u8; 32], [u8; 12])>,
    /// Maximum number of messages we allow to be skipped
    max_skip: u32,
    /// Stable voice encryption key derived from our initial chain seed.
    /// Unlike the text chain key, this NEVER advances per-message.
    my_voice_key: [u8; 32],
    /// Peers' stable voice encryption keys, keyed by `(sender_pubkey_hex, key_id)`.
    peer_voice_keys: std::collections::HashMap<(String, u32), [u8; 32]>,
}

impl GroupSession {
    /// Create a new group session.
    ///
    /// `my_pubkey` — our identity public key (raw bytes, will be hex-encoded internally).
    /// Returns `(session, distribution)` — the distribution message should be sent to all
    /// current group members.
    pub fn new(channel_id: &[u8], my_pubkey: &[u8]) -> (Self, SenderKeyDistribution) {
        let seed: [u8; 32] = rand::random();
        let key_id: u32 = rand::random();
        let chain = SenderChainState::new(seed, key_id);
        let voice_key = derive_voice_key(&seed, key_id);

        let dist = SenderKeyDistribution {
            channel_id: channel_id.to_vec(),
            sender_pubkey: my_pubkey.to_vec(),
            key_id,
            chain_key: seed.to_vec(),
            iteration: 0,
            voice_key: Some(voice_key.to_vec()),
        };

        let session = Self {
            my_chain: chain,
            my_pubkey: my_pubkey.to_vec(),
            peer_chains: std::collections::HashMap::new(),
            skipped_keys: std::collections::HashMap::new(),
            max_skip: 256,
            my_voice_key: voice_key,
            peer_voice_keys: std::collections::HashMap::new(),
        };

        (session, dist)
    }

    /// Restore a session with an existing sender chain (e.g. loaded from DB).
    ///
    /// If `voice_key` is `None`, the voice key is derived from the chain_key.
    /// This works correctly when the chain_key is the *initial* seed (iteration 0).
    /// For sessions restored at a later iteration, the chain_key will have
    /// advanced past the initial seed, so voice will not work until the next
    /// key rotation triggers a fresh distribution.  Pass `Some(key)` to provide
    /// the correct voice key when it is persisted alongside the chain state.
    pub fn from_existing(
        my_pubkey: &[u8],
        chain_key: [u8; 32],
        key_id: u32,
        iteration: u32,
    ) -> Self {
        let mut chain = SenderChainState::new(chain_key, key_id);
        chain.iteration = iteration;

        // Best-effort: derive voice key from whatever chain_key we have.
        // This is only perfectly correct when iteration == 0 (initial seed).
        let voice_key = derive_voice_key(&chain_key, key_id);

        Self {
            my_chain: chain,
            my_pubkey: my_pubkey.to_vec(),
            peer_chains: std::collections::HashMap::new(),
            skipped_keys: std::collections::HashMap::new(),
            max_skip: 256,
            my_voice_key: voice_key,
            peer_voice_keys: std::collections::HashMap::new(),
        }
    }

    /// Our current sender key distribution (for sending to a new joiner).
    pub fn my_distribution(&self, channel_id: &[u8]) -> SenderKeyDistribution {
        SenderKeyDistribution {
            channel_id: channel_id.to_vec(),
            sender_pubkey: self.my_pubkey.clone(),
            key_id: self.my_chain.key_id,
            chain_key: self.my_chain.chain_key.to_vec(),
            iteration: self.my_chain.iteration,
            voice_key: Some(self.my_voice_key.to_vec()),
        }
    }

    /// Process a sender key distribution from another member.
    pub fn process_distribution(&mut self, dist: &SenderKeyDistribution) -> Result<()> {
        if dist.chain_key.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "Chain key must be 32 bytes".to_string(),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&dist.chain_key);

        let mut chain = SenderChainState::new(seed, dist.key_id);
        chain.iteration = dist.iteration;

        let sender_hex = hex::encode(&dist.sender_pubkey);
        self.peer_chains
            .insert((sender_hex.clone(), dist.key_id), chain);

        // Extract or derive the peer's stable voice key
        let peer_vk = if let Some(ref vk_bytes) = dist.voice_key {
            if vk_bytes.len() == 32 {
                let mut vk = [0u8; 32];
                vk.copy_from_slice(vk_bytes);
                vk
            } else {
                // Malformed voice key — fall back to derivation
                derive_voice_key(&seed, dist.key_id)
            }
        } else {
            // Old distribution without voice_key field — derive from
            // chain_key (correct when iteration == 0, best-effort otherwise)
            derive_voice_key(&seed, dist.key_id)
        };
        self.peer_voice_keys
            .insert((sender_hex, dist.key_id), peer_vk);

        Ok(())
    }

    /// Encrypt a message to the group.
    ///
    /// Returns the encrypted wire-format bytes (header + ciphertext).
    /// The plaintext is padded to a bucket before encryption.
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        // Pad plaintext to bucket for size masking
        let padded = crate::padding::pad_to_bucket(plaintext)?;

        // Derive message key and nonce, advance our chain
        let iteration = self.my_chain.iteration;
        let key_id = self.my_chain.key_id;
        let (message_key, nonce) = self.my_chain.ratchet()?;

        // AES-256-GCM encrypt
        let aes_key = Key::<Aes256Gcm>::from_slice(&message_key);
        let cipher = Aes256Gcm::new(aes_key);
        let aes_nonce = Nonce::from_slice(&nonce);

        let payload = Payload {
            msg: &padded,
            aad: associated_data,
        };
        let ciphertext = cipher
            .encrypt(aes_nonce, payload)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        // Build wire format: key_id(4) + iteration(4) + nonce(12) + ciphertext
        let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(&key_id.to_be_bytes());
        out.extend_from_slice(&iteration.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    /// Decrypt a message from a group member.
    ///
    /// `sender_pubkey` — the raw public key of the sender (provided by the transport layer).
    pub fn decrypt(
        &mut self,
        sender_pubkey: &[u8],
        encrypted: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if encrypted.len() < HEADER_SIZE + 16 {
            // 16 = minimum AES-GCM tag
            return Err(CryptoError::EncryptionError(
                "Ciphertext too short".to_string(),
            ));
        }

        // Parse header
        let key_id = u32::from_be_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]);
        let iteration =
            u32::from_be_bytes([encrypted[4], encrypted[5], encrypted[6], encrypted[7]]);
        let nonce: [u8; 12] = encrypted[8..20].try_into().unwrap();
        let ciphertext = &encrypted[20..];

        let sender_hex = hex::encode(sender_pubkey);

        // 1) Check skipped keys first
        let sk_key = (sender_hex.clone(), key_id, iteration);
        if let Some((mk, _nonce)) = self.skipped_keys.remove(&sk_key) {
            return self.decrypt_with_key(&mk, &nonce, ciphertext, associated_data);
        }

        // 2) Look up or fail
        let chain = self
            .peer_chains
            .get_mut(&(sender_hex.clone(), key_id))
            .ok_or_else(|| {
                CryptoError::RatchetError(format!(
                    "No sender chain for {} key_id={}",
                    &sender_hex[..16.min(sender_hex.len())],
                    key_id
                ))
            })?;

        // 3) Advance chain, stash skipped keys
        if iteration >= chain.iteration {
            let skipped = chain.advance_to(iteration, self.max_skip)?;
            for (sk_iter, sk_mk, sk_nonce) in skipped {
                self.skipped_keys
                    .insert((sender_hex.clone(), key_id, sk_iter), (sk_mk, sk_nonce));
            }
            // Now chain.iteration == target; derive the message key
            let (mk, _derived_nonce) = chain.ratchet()?;
            self.decrypt_with_key(&mk, &nonce, ciphertext, associated_data)
        } else {
            Err(CryptoError::RatchetError(format!(
                "Message iteration {} already consumed (chain at {})",
                iteration, chain.iteration
            )))
        }
    }

    /// Rotate our sender key (e.g. after a member leaves the group).
    ///
    /// Returns a new `SenderKeyDistribution` that must be sent to all remaining members.
    pub fn rotate(&mut self, channel_id: &[u8]) -> SenderKeyDistribution {
        let seed: [u8; 32] = rand::random();
        let key_id: u32 = rand::random();
        self.my_chain = SenderChainState::new(seed, key_id);
        self.my_voice_key = derive_voice_key(&seed, key_id);

        SenderKeyDistribution {
            channel_id: channel_id.to_vec(),
            sender_pubkey: self.my_pubkey.clone(),
            key_id,
            chain_key: seed.to_vec(),
            iteration: 0,
            voice_key: Some(self.my_voice_key.to_vec()),
        }
    }

    /// Get our chain state for persistence.
    pub fn my_chain_state(&self) -> (&[u8; 32], u32, u32) {
        (
            &self.my_chain.chain_key,
            self.my_chain.key_id,
            self.my_chain.iteration,
        )
    }

    // ── Voice encrypt/decrypt (stable key, no chain advancement) ──────
    //
    // Voice frames use a *stable* AES-256-GCM key derived once from the
    // initial chain seed.  Unlike the text chain, this key NEVER advances
    // per-frame, so voice traffic cannot desynchronise the text ratchet.
    //
    // Wire format: `key_id(4 BE) + seq(8 BE) + AES-256-GCM(ciphertext + 16-byte tag)`
    // Nonce: `key_id(4) || seq(8)` = 12 bytes (globally unique per sender + frame).
    // Overhead: 12 bytes header + 16 bytes AES-GCM tag = 28 bytes.

    /// Encrypt a voice frame with the stable voice key.
    ///
    /// `seq` must be a monotonically increasing sequence number (typically
    /// the frame counter).  Reusing a `(key_id, seq)` pair is a nonce reuse
    /// and will break AES-GCM security.
    pub fn voice_encrypt(
        &self,
        plaintext: &[u8],
        seq: u64,
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let key_id = self.my_chain.key_id;

        // Build 12-byte nonce: key_id(4 BE) || seq(8 BE)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&key_id.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());

        let aes_key = Key::<Aes256Gcm>::from_slice(&self.my_voice_key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        // Wire format: key_id(4) + seq(8) + ciphertext+tag
        let mut out = Vec::with_capacity(VOICE_HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(&key_id.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    /// Decrypt a voice frame from a peer using their stable voice key.
    pub fn voice_decrypt(
        &self,
        sender_pubkey: &[u8],
        encrypted: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if encrypted.len() < VOICE_HEADER_SIZE + 16 {
            return Err(CryptoError::EncryptionError(
                "Voice ciphertext too short".to_string(),
            ));
        }

        // Parse header
        let key_id = u32::from_be_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]);
        let seq = u64::from_be_bytes([
            encrypted[4],
            encrypted[5],
            encrypted[6],
            encrypted[7],
            encrypted[8],
            encrypted[9],
            encrypted[10],
            encrypted[11],
        ]);
        let ciphertext = &encrypted[VOICE_HEADER_SIZE..];

        let sender_hex = hex::encode(sender_pubkey);

        // Look up peer's stable voice key
        let peer_vk = self
            .peer_voice_keys
            .get(&(sender_hex.clone(), key_id))
            .ok_or_else(|| {
                CryptoError::RatchetError(format!(
                    "No voice key for {} key_id={}",
                    &sender_hex[..16.min(sender_hex.len())],
                    key_id
                ))
            })?;

        // Reconstruct nonce: key_id(4) || seq(8)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&key_id.to_be_bytes());
        nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());

        let aes_key = Key::<Aes256Gcm>::from_slice(peer_vk);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };
        cipher.decrypt(nonce, payload).map_err(|_| {
            CryptoError::EncryptionError("Voice AES-GCM decryption failed".to_string())
        })
    }

    // ── Raw encrypt/decrypt (no padding) ──────────────────────────────
    //
    // For real-time voice frames where every frame is the same known size.
    // Padding is unnecessary (all frames are identical length) and would
    // waste bandwidth at 50 frames/sec.
    //
    // **DEPRECATED**: These methods advance the text chain ratchet on every
    // call, which breaks text decryption for peers not in voice.  Use
    // `voice_encrypt`/`voice_decrypt` instead for voice traffic.

    /// Encrypt raw bytes without bucket-padding.
    ///
    /// Same wire format as `encrypt()`: `key_id(4) + iteration(4) + nonce(12) + ciphertext+tag`.
    /// Overhead: 20 bytes header + 16 bytes AES-GCM tag = 36 bytes.
    pub fn encrypt_raw(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let iteration = self.my_chain.iteration;
        let key_id = self.my_chain.key_id;
        let (message_key, nonce) = self.my_chain.ratchet()?;

        let aes_key = Key::<Aes256Gcm>::from_slice(&message_key);
        let cipher = Aes256Gcm::new(aes_key);
        let aes_nonce = Nonce::from_slice(&nonce);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };
        let ciphertext = cipher
            .encrypt(aes_nonce, payload)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(&key_id.to_be_bytes());
        out.extend_from_slice(&iteration.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    /// Decrypt raw bytes without bucket-unpadding.
    ///
    /// Same wire format and ratchet logic as `decrypt()`, but returns the
    /// raw plaintext without attempting to remove bucket padding.
    pub fn decrypt_raw(
        &mut self,
        sender_pubkey: &[u8],
        encrypted: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if encrypted.len() < HEADER_SIZE + 16 {
            return Err(CryptoError::EncryptionError(
                "Ciphertext too short".to_string(),
            ));
        }

        let key_id = u32::from_be_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]);
        let iteration =
            u32::from_be_bytes([encrypted[4], encrypted[5], encrypted[6], encrypted[7]]);
        let nonce: [u8; 12] = encrypted[8..20].try_into().unwrap();
        let ciphertext = &encrypted[20..];

        let sender_hex = hex::encode(sender_pubkey);

        // 1) Check skipped keys
        let sk_key = (sender_hex.clone(), key_id, iteration);
        if let Some((mk, _nonce)) = self.skipped_keys.remove(&sk_key) {
            return self.decrypt_raw_with_key(&mk, &nonce, ciphertext, associated_data);
        }

        // 2) Look up peer chain
        let chain = self
            .peer_chains
            .get_mut(&(sender_hex.clone(), key_id))
            .ok_or_else(|| {
                CryptoError::RatchetError(format!(
                    "No sender chain for {} key_id={}",
                    &sender_hex[..16.min(sender_hex.len())],
                    key_id
                ))
            })?;

        // 3) Advance chain, stash skipped keys
        if iteration >= chain.iteration {
            let skipped = chain.advance_to(iteration, self.max_skip)?;
            for (sk_iter, sk_mk, sk_nonce) in skipped {
                self.skipped_keys
                    .insert((sender_hex.clone(), key_id, sk_iter), (sk_mk, sk_nonce));
            }
            let (mk, _derived_nonce) = chain.ratchet()?;
            self.decrypt_raw_with_key(&mk, &nonce, ciphertext, associated_data)
        } else {
            Err(CryptoError::RatchetError(format!(
                "Message iteration {} already consumed (chain at {})",
                iteration, chain.iteration
            )))
        }
    }

    // ── private helpers ──

    fn decrypt_with_key(
        &self,
        message_key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let aes_key = Key::<Aes256Gcm>::from_slice(message_key);
        let cipher = Aes256Gcm::new(aes_key);
        let aes_nonce = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };
        let padded = cipher
            .decrypt(aes_nonce, payload)
            .map_err(|_| CryptoError::EncryptionError("AES-GCM decryption failed".to_string()))?;

        // Remove bucket padding
        crate::padding::unpad_from_bucket(&padded)
    }

    fn decrypt_raw_with_key(
        &self,
        message_key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let aes_key = Key::<Aes256Gcm>::from_slice(message_key);
        let cipher = Aes256Gcm::new(aes_key);
        let aes_nonce = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };
        cipher
            .decrypt(aes_nonce, payload)
            .map_err(|_| CryptoError::EncryptionError("AES-GCM decryption failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_chain_ratchet() {
        let seed = [0x42u8; 32];
        let mut chain = SenderChainState::new(seed, 1);

        assert_eq!(chain.iteration(), 0);
        let (mk1, n1) = chain.ratchet().unwrap();
        assert_eq!(chain.iteration(), 1);
        let (mk2, n2) = chain.ratchet().unwrap();
        assert_eq!(chain.iteration(), 2);

        // Keys should differ
        assert_ne!(mk1, mk2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_sender_chain_deterministic() {
        let seed = [0xAB; 32];
        let mut c1 = SenderChainState::new(seed, 1);
        let mut c2 = SenderChainState::new(seed, 1);

        let (mk1, n1) = c1.ratchet().unwrap();
        let (mk2, n2) = c2.ratchet().unwrap();
        assert_eq!(mk1, mk2);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_group_encrypt_decrypt() {
        let channel_id = b"test-channel";
        let alice_pk = b"alice-pubkey-32-bytes-0000000000";
        let bob_pk = b"bob---pubkey-32-bytes-0000000000";

        // Alice creates session
        let (mut alice, alice_dist) = GroupSession::new(channel_id, alice_pk);

        // Bob creates session
        let (mut bob, bob_dist) = GroupSession::new(channel_id, bob_pk);

        // Exchange distributions
        alice.process_distribution(&bob_dist).unwrap();
        bob.process_distribution(&alice_dist).unwrap();

        // Alice encrypts
        let plaintext = b"Hello group!";
        let ad = b"channel-ad";
        let encrypted = alice.encrypt(plaintext, ad).unwrap();

        // Bob decrypts
        let decrypted = bob.decrypt(alice_pk, &encrypted, ad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Bob sends back
        let reply = b"Hey Alice!";
        let encrypted2 = bob.encrypt(reply, ad).unwrap();
        let decrypted2 = alice.decrypt(bob_pk, &encrypted2, ad).unwrap();
        assert_eq!(decrypted2, reply);
    }

    #[test]
    fn test_multiple_messages() {
        let channel_id = b"multi-msg";
        let alice_pk = b"alice-pubkey-32-bytes-0000000000";
        let bob_pk = b"bob---pubkey-32-bytes-0000000000";

        let (mut alice, alice_dist) = GroupSession::new(channel_id, alice_pk);
        let (mut bob, bob_dist) = GroupSession::new(channel_id, bob_pk);
        alice.process_distribution(&bob_dist).unwrap();
        bob.process_distribution(&alice_dist).unwrap();

        let ad = b"";
        for i in 0..10 {
            let msg = format!("Message {}", i);
            let enc = alice.encrypt(msg.as_bytes(), ad).unwrap();
            let dec = bob.decrypt(alice_pk, &enc, ad).unwrap();
            assert_eq!(dec, msg.as_bytes());
        }
    }

    #[test]
    fn test_out_of_order() {
        let channel_id = b"ooo-test";
        let alice_pk = b"alice-pubkey-32-bytes-0000000000";
        let bob_pk = b"bob---pubkey-32-bytes-0000000000";

        let (mut alice, alice_dist) = GroupSession::new(channel_id, alice_pk);
        let (mut bob, _bob_dist) = GroupSession::new(channel_id, bob_pk);
        bob.process_distribution(&alice_dist).unwrap();

        let ad = b"";
        let enc0 = alice.encrypt(b"msg0", ad).unwrap();
        let enc1 = alice.encrypt(b"msg1", ad).unwrap();
        let enc2 = alice.encrypt(b"msg2", ad).unwrap();

        // Decrypt out of order: 2, 0, 1
        let dec2 = bob.decrypt(alice_pk, &enc2, ad).unwrap();
        assert_eq!(dec2, b"msg2");

        let dec0 = bob.decrypt(alice_pk, &enc0, ad).unwrap();
        assert_eq!(dec0, b"msg0");

        let dec1 = bob.decrypt(alice_pk, &enc1, ad).unwrap();
        assert_eq!(dec1, b"msg1");
    }

    #[test]
    fn test_voice_encrypt_decrypt() {
        let channel_id = b"voice-test";
        let alice_pk = b"alice-pubkey-32-bytes-0000000000";
        let bob_pk = b"bob---pubkey-32-bytes-0000000000";

        let (alice, alice_dist) = GroupSession::new(channel_id, alice_pk);
        let (mut bob, _bob_dist) = GroupSession::new(channel_id, bob_pk);
        bob.process_distribution(&alice_dist).unwrap();

        let ad = b"channel-ad";
        // Encrypt several frames
        for seq in 0..100u64 {
            let frame = vec![0xAB; 160]; // simulated audio frame
            let encrypted = alice.voice_encrypt(&frame, seq, ad).unwrap();
            let decrypted = bob.voice_decrypt(alice_pk, &encrypted, ad).unwrap();
            assert_eq!(decrypted, frame);
        }
    }

    #[test]
    fn test_voice_does_not_advance_text_chain() {
        let channel_id = b"voice-text-isolation";
        let alice_pk = b"alice-pubkey-32-bytes-0000000000";
        let bob_pk = b"bob---pubkey-32-bytes-0000000000";

        let (mut alice, alice_dist) = GroupSession::new(channel_id, alice_pk);
        let (mut bob, bob_dist) = GroupSession::new(channel_id, bob_pk);
        alice.process_distribution(&bob_dist).unwrap();
        bob.process_distribution(&alice_dist).unwrap();

        let ad = b"";

        // Send a text message
        let enc1 = alice.encrypt(b"before voice", ad).unwrap();
        let dec1 = bob.decrypt(alice_pk, &enc1, ad).unwrap();
        assert_eq!(dec1, b"before voice");

        // Send 1000 voice frames (should NOT advance the text chain)
        for seq in 0..1000u64 {
            let frame = vec![0xCD; 80];
            let encrypted = alice.voice_encrypt(&frame, seq, ad).unwrap();
            let decrypted = bob.voice_decrypt(alice_pk, &encrypted, ad).unwrap();
            assert_eq!(decrypted, frame);
        }

        // Send another text message — should still work (no skipped-message gap)
        let enc2 = alice.encrypt(b"after voice", ad).unwrap();
        let dec2 = bob.decrypt(alice_pk, &enc2, ad).unwrap();
        assert_eq!(dec2, b"after voice");
    }

    #[test]
    fn test_rotation() {
        let channel_id = b"rotate-test";
        let alice_pk = b"alice-pubkey-32-bytes-0000000000";
        let bob_pk = b"bob---pubkey-32-bytes-0000000000";

        let (mut alice, alice_dist) = GroupSession::new(channel_id, alice_pk);
        let (mut bob, bob_dist) = GroupSession::new(channel_id, bob_pk);
        alice.process_distribution(&bob_dist).unwrap();
        bob.process_distribution(&alice_dist).unwrap();

        let ad = b"";

        // Send a message before rotation
        let enc1 = alice.encrypt(b"before rotation", ad).unwrap();
        let dec1 = bob.decrypt(alice_pk, &enc1, ad).unwrap();
        assert_eq!(dec1, b"before rotation");

        // Alice rotates her key
        let new_dist = alice.rotate(channel_id);
        bob.process_distribution(&new_dist).unwrap();

        // Send a message after rotation
        let enc2 = alice.encrypt(b"after rotation", ad).unwrap();
        let dec2 = bob.decrypt(alice_pk, &enc2, ad).unwrap();
        assert_eq!(dec2, b"after rotation");

        // Voice should also work after rotation
        let voice_enc = alice.voice_encrypt(b"voice-frame", 0, ad).unwrap();
        let voice_dec = bob.voice_decrypt(alice_pk, &voice_enc, ad).unwrap();
        assert_eq!(voice_dec, b"voice-frame");
    }
}
