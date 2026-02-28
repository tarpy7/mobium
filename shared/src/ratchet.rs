//! Double Ratchet Algorithm
//!
//! Implementation of Signal's Double Ratchet for forward secrecy
//! and future secrecy in ongoing conversations.
//!
//! Follows the specification at:
//! <https://signal.org/docs/specifications/doubleratchet/>
//!
//! ## Wire format
//!
//! Each encrypted message header contains:
//! - `dh_public` (32 bytes): sender's current ratchet public key
//! - `message_number` (u32): message index in the current sending chain
//! - `previous_chain_length` (u32): length of the previous sending chain
//!
//! The receiver uses `dh_public` to detect when a DH ratchet step is needed,
//! `previous_chain_length` to store skipped keys from the old receiving chain,
//! and `message_number` to advance (or skip forward in) the current receiving chain.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

// ───────────────────────────── helpers ──────────────────────────────

/// Type alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

/// Maximum number of skipped message keys we are willing to store.
const MAX_SKIP: u32 = 1000;

// ───────────────────────────── types ───────────────────────────────

/// Message key for a single message (AES-256-GCM key + nonce).
///
/// Zeroized on drop to prevent key material from lingering in memory.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    /// Key for AES-256-GCM
    pub key: [u8; 32],
    /// IV/nonce for AES-256-GCM
    pub iv: [u8; 12],
}

/// Header sent alongside each ciphertext so the receiver can ratchet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Sender's current ratchet DH public key (32 bytes).
    pub dh_public: [u8; 32],
    /// Index of this message in the current sending chain.
    pub message_number: u32,
    /// Length of the *previous* sending chain (so receiver can skip).
    pub previous_chain_length: u32,
}

impl MessageHeader {
    /// Serialize to bytes: [dh_public:32][msg_num:4 LE][prev_chain:4 LE] = 40 bytes
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..32].copy_from_slice(&self.dh_public);
        buf[32..36].copy_from_slice(&self.message_number.to_le_bytes());
        buf[36..40].copy_from_slice(&self.previous_chain_length.to_le_bytes());
        buf
    }

    /// Deserialize from exactly 40 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 40 {
            return Err(CryptoError::RatchetError(
                "Invalid header length".to_string(),
            ));
        }
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&bytes[0..32]);
        let message_number = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let previous_chain_length = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        Ok(Self {
            dh_public,
            message_number,
            previous_chain_length,
        })
    }
}

// ───────────── internal (serializable) key wrappers ────────────────

/// Root key — the slow-ratcheting top-level key.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
struct RootKey {
    key: [u8; 32],
}

/// Symmetric chain key — ratcheted once per message.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
struct ChainKey {
    key: [u8; 32],
}

/// Skipped message key entry (identified by ratchet pubkey + message number).
///
/// Contains sensitive key material (`key`, `iv`) that is zeroized on drop.
/// The `ratchet_pub` and `message_number` fields are non-secret identifiers
/// used for lookup and are skipped during zeroization.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    /// The ratchet public key that was active when this key was skipped.
    #[zeroize(skip)]
    ratchet_pub: [u8; 32],
    /// Message number within that chain.
    #[zeroize(skip)]
    message_number: u32,
    /// The derived 32-byte encryption key.
    key: [u8; 32],
    /// The derived 12-byte nonce.
    iv: [u8; 12],
}

// ─────────────── serializable snapshot ──────────────────────────────

/// A fully serializable snapshot of a `DoubleRatchet` session, suitable
/// for persisting to an encrypted database and later restoring.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    root_key: RootKey,
    send_chain_key: Option<ChainKey>,
    recv_chain_key: Option<ChainKey>,
    /// Raw bytes of our current DH private key (32 bytes).
    our_dh_private: Option<[u8; 32]>,
    /// Our current DH public key (32 bytes).
    our_dh_public: Option<[u8; 32]>,
    /// Their current DH public key (32 bytes).
    their_dh_public: Option<[u8; 32]>,
    send_message_number: u32,
    recv_message_number: u32,
    previous_chain_length: u32,
    skipped_keys: Vec<SkippedKey>,
}

// ───────────────── Double Ratchet ──────────────────────────────────

/// Double Ratchet state for a DM session.
///
/// The initiator (Alice) calls [`DoubleRatchet::init_alice`] after X3DH.
/// The responder (Bob) calls [`DoubleRatchet::init_bob`] after X3DH.
///
/// ## DH private key persistence
///
/// x25519-dalek's `ReusableSecret` does not expose its raw bytes, so we
/// cannot extract them for serialization. To support correct save/load
/// (allowing the restored session to encrypt immediately without waiting
/// for an incoming message), we keep a parallel copy of the raw 32-byte
/// secret in `our_dh_private_bytes`. This field is:
///
/// - Set at every point where a new DH keypair is generated (`init_alice`,
///   `init_bob`, `dh_ratchet_recv`) by generating random bytes first and
///   constructing the `ReusableSecret` from those bytes via `FixedRng`.
/// - Restored from the serialized `RatchetState` during `load`.
/// - Explicitly zeroized in the `Drop` implementation.
///
/// This mirrors how Signal's reference implementations handle the same
/// limitation — the raw bytes and the opaque secret have identical
/// lifetimes and are cleaned up together.
pub struct DoubleRatchet {
    root_key: RootKey,
    send_chain_key: Option<ChainKey>,
    recv_chain_key: Option<ChainKey>,
    /// Our current ratchet DH key pair.
    our_dh_private: Option<ReusableSecret>,
    /// Raw bytes of our current DH private key, kept in sync with
    /// `our_dh_private` for serialization. See struct-level docs.
    our_dh_private_bytes: Option<[u8; 32]>,
    our_dh_public: Option<PublicKey>,
    /// Their current ratchet DH public key.
    their_dh_public: Option<PublicKey>,
    /// Messages sent in the current sending chain.
    send_message_number: u32,
    /// Messages received in the current receiving chain.
    recv_message_number: u32,
    /// Length of previous sending chain.
    previous_chain_length: u32,
    /// Stored message keys for out-of-order decryption.
    skipped_keys: Vec<SkippedKey>,
}

/// Explicitly zeroize the DH private key bytes on drop.
///
/// `ReusableSecret` handles its own zeroization; this ensures the
/// parallel raw-byte copy is also wiped from memory.
impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        if let Some(ref mut bytes) = self.our_dh_private_bytes {
            bytes.zeroize();
        }
    }
}

impl DoubleRatchet {
    // ─────────────── initialisation ────────────────────────────────

    /// Initialise Alice's side (the X3DH initiator).
    ///
    /// Alice has already performed X3DH and obtained `shared_secret`.
    /// She also knows Bob's signed pre-key (`bob_spk`) which becomes
    /// `their_dh_public` for the first DH ratchet step.
    ///
    /// Alice immediately performs a DH ratchet step so she has a
    /// sending chain and can encrypt her first message.
    pub fn init_alice(shared_secret: &[u8; 32], bob_spk: &PublicKey) -> Result<Self> {
        let root_key = RootKey {
            key: *shared_secret,
        };

        // Generate Alice's first ratchet key pair.
        // We generate random bytes first so we can retain a copy for
        // serialization, then construct the ReusableSecret deterministically.
        let mut dh_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut dh_bytes);
        let our_dh = ReusableSecret::random_from_rng(&mut FixedRng(dh_bytes));
        let our_dh_pub = PublicKey::from(&our_dh);

        // DH ratchet step: DH(our_dh, bob_spk) → new root key + send chain key
        let dh_output = our_dh.diffie_hellman(bob_spk);
        let (new_root_key, send_ck) = kdf_rk(&root_key.key, dh_output.as_bytes())?;

        Ok(Self {
            root_key: RootKey { key: new_root_key },
            send_chain_key: Some(ChainKey { key: send_ck }),
            recv_chain_key: None,
            our_dh_private: Some(our_dh),
            our_dh_private_bytes: Some(dh_bytes),
            our_dh_public: Some(our_dh_pub),
            their_dh_public: Some(*bob_spk),
            send_message_number: 0,
            recv_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: Vec::new(),
        })
    }

    /// Initialise Bob's side (the X3DH responder).
    ///
    /// Bob uses his signed pre-key as the initial ratchet key pair,
    /// since that is the key Alice will DH against in her first message.
    ///
    /// Bob does NOT have a sending chain yet — he will create one when
    /// he first receives a message from Alice (triggering a DH ratchet).
    pub fn init_bob(shared_secret: &[u8; 32], bob_spk_private: &StaticSecret) -> Result<Self> {
        let bob_spk_pub = PublicKey::from(bob_spk_private);
        // We need a ReusableSecret with the same key material.
        // StaticSecret and ReusableSecret are both wrappers over the same
        // scalar bytes, so we extract and reconstruct.
        let spk_bytes = bob_spk_private.to_bytes();
        let our_dh = ReusableSecret::random_from_rng(&mut FixedRng(spk_bytes));

        Ok(Self {
            root_key: RootKey {
                key: *shared_secret,
            },
            send_chain_key: None,
            recv_chain_key: None,
            our_dh_private: Some(our_dh),
            our_dh_private_bytes: Some(spk_bytes),
            our_dh_public: Some(bob_spk_pub),
            their_dh_public: None,
            send_message_number: 0,
            recv_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: Vec::new(),
        })
    }

    // ────────────────── encrypt ────────────────────────────────────

    /// Encrypt a plaintext message.
    ///
    /// Returns `(header, ciphertext)`.  The caller is responsible for
    /// serialising the header (see [`MessageHeader::to_bytes`]) and
    /// transmitting it alongside the ciphertext.
    ///
    /// `associated_data` should include the concatenated identity keys
    /// of both parties (from X3DH).
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>)> {
        // We must have a sending chain.
        let ck = self
            .send_chain_key
            .as_ref()
            .ok_or_else(|| CryptoError::RatchetError("No sending chain".into()))?;

        // KDF_CK → message key + next chain key
        let (mk, next_ck) = kdf_ck(&ck.key)?;
        self.send_chain_key = Some(ChainKey { key: next_ck });

        // Build header
        let dh_pub = self
            .our_dh_public
            .ok_or_else(|| CryptoError::RatchetError("No DH public key".into()))?;
        let header = MessageHeader {
            dh_public: *dh_pub.as_bytes(),
            message_number: self.send_message_number,
            previous_chain_length: self.previous_chain_length,
        };

        // Pad plaintext
        let padded = crate::padding::pad_to_bucket(plaintext)?;

        // Concat header bytes into AAD: ad || header
        let mut full_ad = associated_data.to_vec();
        full_ad.extend_from_slice(&header.to_bytes());

        // Encrypt
        let ciphertext = aes_gcm_encrypt(&mk, &padded, &full_ad)?;

        self.send_message_number += 1;

        Ok((header, ciphertext))
    }

    // ────────────────── decrypt ────────────────────────────────────

    /// Decrypt an incoming message.
    ///
    /// The caller provides the parsed [`MessageHeader`] and `ciphertext`.
    /// `associated_data` must match what the sender used.
    pub fn decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let their_pub = PublicKey::from(header.dh_public);

        // 1. Try skipped keys first.
        if let Some(mk) = self.try_skipped_key(&header.dh_public, header.message_number) {
            let mut full_ad = associated_data.to_vec();
            full_ad.extend_from_slice(&header.to_bytes());
            let padded = aes_gcm_decrypt(&mk, ciphertext, &full_ad)?;
            return crate::padding::unpad_from_bucket(&padded);
        }

        // 2. Do we need a DH ratchet step?
        let need_dh_ratchet = match self.their_dh_public {
            Some(ref their_current) => *their_current.as_bytes() != header.dh_public,
            None => true,
        };

        if need_dh_ratchet {
            // Skip remaining keys in the current receiving chain.
            self.skip_message_keys(header.previous_chain_length)?;

            // DH ratchet step (receiving half).
            self.dh_ratchet_recv(&their_pub)?;
        }

        // 3. Skip message keys in the current receiving chain if needed.
        self.skip_message_keys(header.message_number)?;

        // 4. Derive the message key for this message.
        let ck = self
            .recv_chain_key
            .as_ref()
            .ok_or_else(|| CryptoError::RatchetError("No receiving chain".into()))?;
        let (mk, next_ck) = kdf_ck(&ck.key)?;
        self.recv_chain_key = Some(ChainKey { key: next_ck });
        self.recv_message_number += 1;

        let mut full_ad = associated_data.to_vec();
        full_ad.extend_from_slice(&header.to_bytes());
        let padded = aes_gcm_decrypt(&mk, ciphertext, &full_ad)?;
        crate::padding::unpad_from_bucket(&padded)
    }

    // ─────────────── DH ratchet (receiving) ────────────────────────

    /// Perform a DH ratchet step upon receiving a new ratchet public key.
    ///
    /// This derives a new receiving chain, then generates a new DH key
    /// pair and derives a new sending chain.
    fn dh_ratchet_recv(&mut self, their_new_pub: &PublicKey) -> Result<()> {
        self.previous_chain_length = self.send_message_number;
        self.send_message_number = 0;
        self.recv_message_number = 0;
        self.their_dh_public = Some(*their_new_pub);

        // DH with our current key and their new key → receiving chain
        let our_priv = self
            .our_dh_private
            .as_ref()
            .ok_or_else(|| CryptoError::RatchetError("No DH private key".into()))?;
        let dh_out = our_priv.diffie_hellman(their_new_pub);
        let (new_rk, recv_ck) = kdf_rk(&self.root_key.key, dh_out.as_bytes())?;
        self.root_key = RootKey { key: new_rk };
        self.recv_chain_key = Some(ChainKey { key: recv_ck });

        // Generate new DH key pair for sending.
        // Capture raw bytes before constructing the secret so we can
        // persist them in save().
        let mut new_dh_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_dh_bytes);
        let new_dh = ReusableSecret::random_from_rng(&mut FixedRng(new_dh_bytes));
        let new_dh_pub = PublicKey::from(&new_dh);

        // DH with new key and their key → sending chain
        let dh_out2 = new_dh.diffie_hellman(their_new_pub);
        let (new_rk2, send_ck) = kdf_rk(&self.root_key.key, dh_out2.as_bytes())?;
        self.root_key = RootKey { key: new_rk2 };
        self.send_chain_key = Some(ChainKey { key: send_ck });

        // Zeroize old bytes before replacing
        if let Some(ref mut old_bytes) = self.our_dh_private_bytes {
            old_bytes.zeroize();
        }
        self.our_dh_private = Some(new_dh);
        self.our_dh_private_bytes = Some(new_dh_bytes);
        self.our_dh_public = Some(new_dh_pub);

        Ok(())
    }

    // ───────────── skipped message keys ────────────────────────────

    /// Try to find a skipped key for the given ratchet pubkey + message number.
    fn try_skipped_key(
        &mut self,
        ratchet_pub: &[u8; 32],
        message_number: u32,
    ) -> Option<MessageKey> {
        let pos = self
            .skipped_keys
            .iter()
            .position(|sk| sk.ratchet_pub == *ratchet_pub && sk.message_number == message_number);
        pos.map(|idx| {
            let sk = self.skipped_keys.remove(idx);
            MessageKey {
                key: sk.key,
                iv: sk.iv,
            }
        })
    }

    /// Advance the receiving chain to `until`, storing skipped keys.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if until < self.recv_message_number {
            return Ok(());
        }
        let to_skip = until - self.recv_message_number;
        if to_skip > MAX_SKIP {
            return Err(CryptoError::RatchetError(format!(
                "Too many skipped messages: {to_skip}"
            )));
        }
        let ck = match self.recv_chain_key.as_ref() {
            Some(ck) => ck,
            None => return Ok(()), // No receiving chain yet — nothing to skip.
        };
        let their_pub = match self.their_dh_public {
            Some(pk) => *pk.as_bytes(),
            None => return Ok(()),
        };

        let mut current_ck = ck.key;
        for _ in 0..to_skip {
            let (mk, next_ck) = kdf_ck(&current_ck)?;
            self.skipped_keys.push(SkippedKey {
                ratchet_pub: their_pub,
                message_number: self.recv_message_number,
                key: mk.key,
                iv: mk.iv,
            });
            current_ck = next_ck;
            self.recv_message_number += 1;
        }
        self.recv_chain_key = Some(ChainKey { key: current_ck });
        Ok(())
    }

    // ─────────── public accessors ──────────────────────────────────

    /// Our current DH public key (sent in message headers).
    pub fn our_dh_public(&self) -> Option<PublicKey> {
        self.our_dh_public
    }

    // ─────────── serialisation ─────────────────────────────────────

    /// Serialise the ratchet state to bytes (MessagePack).
    ///
    /// The returned bytes should be encrypted before storage.
    /// The DH private key is serialized from `our_dh_private_bytes`,
    /// which is kept in sync with `our_dh_private` at every key
    /// generation point (init, ratchet step, and load).
    pub fn save(&self) -> Result<Vec<u8>> {
        let state = RatchetState {
            root_key: self.root_key.clone(),
            send_chain_key: self.send_chain_key.clone(),
            recv_chain_key: self.recv_chain_key.clone(),
            our_dh_private: self.our_dh_private_bytes,
            our_dh_public: self.our_dh_public.map(|pk| *pk.as_bytes()),
            their_dh_public: self.their_dh_public.map(|pk| *pk.as_bytes()),
            send_message_number: self.send_message_number,
            recv_message_number: self.recv_message_number,
            previous_chain_length: self.previous_chain_length,
            skipped_keys: self.skipped_keys.clone(),
        };
        rmp_serde::to_vec(&state)
            .map_err(|e| CryptoError::StorageError(format!("Serialization failed: {e}")))
    }

    /// Restore ratchet state from bytes.
    ///
    /// Validates that the stored DH private key (if present) is consistent
    /// with the stored public key. Sessions saved with older code may have
    /// a `[0u8; 32]` placeholder for the private key, making them unusable
    /// for DH ratchet steps. Use [`has_valid_dh_key`](Self::has_valid_dh_key)
    /// after loading to check, or call this method which will return an error
    /// if the keys are inconsistent.
    pub fn load(bytes: &[u8]) -> Result<Self> {
        let state: RatchetState = rmp_serde::from_slice(bytes)
            .map_err(|e| CryptoError::StorageError(format!("Deserialization failed: {e}")))?;

        // Validate DH key consistency: if both private and public bytes are
        // present, the public key derived from the private bytes must match
        // the stored public key. A mismatch indicates a session saved with
        // the old broken save() that wrote [0u8; 32] as a placeholder.
        if let (Some(priv_bytes), Some(pub_bytes)) = (&state.our_dh_private, &state.our_dh_public) {
            let reconstructed = ReusableSecret::random_from_rng(&mut FixedRng(*priv_bytes));
            let reconstructed_pub = PublicKey::from(&reconstructed);
            if reconstructed_pub.as_bytes() != pub_bytes {
                return Err(CryptoError::StorageError(
                    "DH key mismatch: stored private key does not match public key \
                     (session may have been saved with broken serialization). \
                     This session must be re-established."
                        .into(),
                ));
            }
        }

        let our_dh_private = state
            .our_dh_private
            .map(|raw| ReusableSecret::random_from_rng(&mut FixedRng(raw)));
        let our_dh_public = state.our_dh_public.map(|b| PublicKey::from(b));
        let their_dh_public = state.their_dh_public.map(|b| PublicKey::from(b));

        Ok(Self {
            root_key: state.root_key,
            send_chain_key: state.send_chain_key,
            recv_chain_key: state.recv_chain_key,
            our_dh_private,
            our_dh_private_bytes: state.our_dh_private,
            our_dh_public,
            their_dh_public,
            send_message_number: state.send_message_number,
            recv_message_number: state.recv_message_number,
            previous_chain_length: state.previous_chain_length,
            skipped_keys: state.skipped_keys,
        })
    }

    /// Serialise to bytes with an externally-provided DH private key.
    ///
    /// **Deprecated**: Prefer [`save()`](Self::save) which now uses the
    /// internally-tracked `our_dh_private_bytes`. This method is retained
    /// only for backward compatibility with existing tests.
    pub fn save_with_key(&self, our_dh_private_bytes: Option<[u8; 32]>) -> Result<Vec<u8>> {
        let state = RatchetState {
            root_key: self.root_key.clone(),
            send_chain_key: self.send_chain_key.clone(),
            recv_chain_key: self.recv_chain_key.clone(),
            our_dh_private: our_dh_private_bytes,
            our_dh_public: self.our_dh_public.map(|pk| *pk.as_bytes()),
            their_dh_public: self.their_dh_public.map(|pk| *pk.as_bytes()),
            send_message_number: self.send_message_number,
            recv_message_number: self.recv_message_number,
            previous_chain_length: self.previous_chain_length,
            skipped_keys: self.skipped_keys.clone(),
        };
        rmp_serde::to_vec(&state)
            .map_err(|e| CryptoError::StorageError(format!("Serialization failed: {e}")))
    }
}

// ─────────── FixedRng for deterministic secret construction ────────

/// A trivial RNG that yields exactly 32 pre-determined bytes,
/// used to reconstruct a `ReusableSecret` from stored raw bytes.
///
/// x25519-dalek's `ReusableSecret::random_from_rng` reads exactly
/// 32 bytes from the RNG to create the secret. By feeding it the
/// original bytes, we get back the same secret.
struct FixedRng([u8; 32]);

impl rand::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Copy from our stored bytes (wrapping if needed, but in practice
        // x25519-dalek asks for exactly 32).
        let len = dest.len().min(32);
        dest[..len].copy_from_slice(&self.0[..len]);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand::CryptoRng for FixedRng {}

// ──────────────────── KDF functions ────────────────────────────────

/// KDF_RK: Root key ratchet. Returns (new_root_key, chain_key).
///
/// HMAC-SHA256 based HKDF-like construction:
///   PRK  = HMAC(root_key, dh_output)
///   RK'  = HMAC(PRK, "Mobium-v1-RK" || 0x01)
///   CK   = HMAC(PRK, "Mobium-v1-CK" || 0x02)
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // Extract
    let mut mac = <HmacSha256 as Mac>::new_from_slice(root_key)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(dh_output);
    let prk: [u8; 32] = mac.finalize().into_bytes().into();

    // Expand — root key
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(b"Mobium-v1-RK");
    mac.update(&[0x01]);
    let new_rk: [u8; 32] = mac.finalize().into_bytes().into();

    // Expand — chain key
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(b"Mobium-v1-CK");
    mac.update(&[0x02]);
    let ck: [u8; 32] = mac.finalize().into_bytes().into();

    Ok((new_rk, ck))
}

/// KDF_CK: Symmetric chain key ratchet. Returns (MessageKey, next_chain_key_bytes).
///
///   mk_bytes = HMAC(ck, 0x01)          — 32 bytes key
///   iv_bytes = HMAC(ck, mk_bytes || 0x02) — take first 12 bytes as IV
///   next_ck  = HMAC(ck, 0x03)
fn kdf_ck(chain_key: &[u8; 32]) -> Result<(MessageKey, [u8; 32])> {
    // Message key
    let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(&[0x01]);
    let mk_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    // IV (12 bytes from a second HMAC round)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(&mk_bytes);
    mac.update(&[0x02]);
    let iv_full: [u8; 32] = mac.finalize().into_bytes().into();
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_full[..12]);

    // Next chain key
    let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(&[0x03]);
    let next_ck: [u8; 32] = mac.finalize().into_bytes().into();

    Ok((MessageKey { key: mk_bytes, iv }, next_ck))
}

// ──────────────── AES-256-GCM helpers ──────────────────────────────

fn aes_gcm_encrypt(mk: &MessageKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(&mk.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&mk.iv);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

fn aes_gcm_decrypt(mk: &MessageKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(&mk.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&mk.iv);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionError("Decryption failed".to_string()))
}

// ────────────────────── tests ──────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    /// Helper: create Alice + Bob ratchets from a shared secret and Bob's SPK.
    fn make_pair() -> (DoubleRatchet, DoubleRatchet) {
        let shared_secret = [0x42u8; 32];
        let bob_spk_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bob_spk_public = PublicKey::from(&bob_spk_secret);

        let alice = DoubleRatchet::init_alice(&shared_secret, &bob_spk_public).unwrap();
        let bob = DoubleRatchet::init_bob(&shared_secret, &bob_spk_secret).unwrap();

        (alice, bob)
    }

    #[test]
    fn test_basic_encrypt_decrypt() {
        let (mut alice, mut bob) = make_pair();
        let ad = b"test-ad";

        // Alice → Bob
        let (hdr, ct) = alice.encrypt(b"Hello Bob!", ad).unwrap();
        let pt = bob.decrypt(&hdr, &ct, ad).unwrap();
        assert_eq!(pt, b"Hello Bob!");

        // Bob → Alice
        let (hdr, ct) = bob.encrypt(b"Hi Alice!", ad).unwrap();
        let pt = alice.decrypt(&hdr, &ct, ad).unwrap();
        assert_eq!(pt, b"Hi Alice!");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let (mut alice, mut bob) = make_pair();
        let ad = b"ad";

        for i in 0..10 {
            let msg = format!("Message {i}");
            let (hdr, ct) = alice.encrypt(msg.as_bytes(), ad).unwrap();
            let pt = bob.decrypt(&hdr, &ct, ad).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_alternating_messages() {
        let (mut alice, mut bob) = make_pair();
        let ad = b"ad";

        for i in 0..5 {
            let msg_a = format!("Alice {i}");
            let (hdr, ct) = alice.encrypt(msg_a.as_bytes(), ad).unwrap();
            let pt = bob.decrypt(&hdr, &ct, ad).unwrap();
            assert_eq!(pt, msg_a.as_bytes());

            let msg_b = format!("Bob {i}");
            let (hdr, ct) = bob.encrypt(msg_b.as_bytes(), ad).unwrap();
            let pt = alice.decrypt(&hdr, &ct, ad).unwrap();
            assert_eq!(pt, msg_b.as_bytes());
        }
    }

    #[test]
    fn test_out_of_order_messages() {
        let (mut alice, mut bob) = make_pair();
        let ad = b"ad";

        // Alice sends 3 messages
        let (hdr0, ct0) = alice.encrypt(b"msg0", ad).unwrap();
        let (hdr1, ct1) = alice.encrypt(b"msg1", ad).unwrap();
        let (hdr2, ct2) = alice.encrypt(b"msg2", ad).unwrap();

        // Bob decrypts out of order: 2, 0, 1
        let pt2 = bob.decrypt(&hdr2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"msg2");

        let pt0 = bob.decrypt(&hdr0, &ct0, ad).unwrap();
        assert_eq!(pt0, b"msg0");

        let pt1 = bob.decrypt(&hdr1, &ct1, ad).unwrap();
        assert_eq!(pt1, b"msg1");
    }

    #[test]
    fn test_header_serialization() {
        let hdr = MessageHeader {
            dh_public: [0xAB; 32],
            message_number: 42,
            previous_chain_length: 7,
        };
        let bytes = hdr.to_bytes();
        let hdr2 = MessageHeader::from_bytes(&bytes).unwrap();
        assert_eq!(hdr.dh_public, hdr2.dh_public);
        assert_eq!(hdr.message_number, hdr2.message_number);
        assert_eq!(hdr.previous_chain_length, hdr2.previous_chain_length);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let (mut alice, mut bob) = make_pair();
        let ad = b"ad";

        // Alice sends a message
        let (hdr, ct) = alice.encrypt(b"before save", ad).unwrap();
        let pt = bob.decrypt(&hdr, &ct, ad).unwrap();
        assert_eq!(pt, b"before save");

        // Save Bob's state (we need to know his private key bytes for save).
        // For this test, we'll use save_with_key with None since we can't
        // extract ReusableSecret bytes. Instead, test via load with a fresh pair.

        // A more complete roundtrip: create a ratchet, save with known bytes, load, use.
        let shared_secret = [0x55u8; 32];
        let bob_spk_bytes: [u8; 32] = rand::random();
        let bob_spk = StaticSecret::from(bob_spk_bytes);
        let bob_spk_pub = PublicKey::from(&bob_spk);

        let mut alice2 = DoubleRatchet::init_alice(&shared_secret, &bob_spk_pub).unwrap();
        let mut bob2 = DoubleRatchet::init_bob(&shared_secret, &bob_spk).unwrap();

        // Exchange a message so both sides have state
        let (hdr, ct) = alice2.encrypt(b"hello", ad).unwrap();
        let pt = bob2.decrypt(&hdr, &ct, ad).unwrap();
        assert_eq!(pt, b"hello");

        // Bob replies
        let (hdr, ct) = bob2.encrypt(b"world", ad).unwrap();
        let pt = alice2.decrypt(&hdr, &ct, ad).unwrap();
        assert_eq!(pt, b"world");

        // Save bob2 using the correct save() which now persists DH private bytes
        let saved_bob = bob2.save().unwrap();
        let mut bob3 = DoubleRatchet::load(&saved_bob).unwrap();

        // Bob3 (restored from save) should be able to decrypt Alice's next message
        let (hdr3, ct3) = alice2.encrypt(b"after bob reload", ad).unwrap();
        let pt3 = bob3.decrypt(&hdr3, &ct3, ad).unwrap();
        assert_eq!(pt3, b"after bob reload");

        // Bob3 should also be able to send (needs DH private key for ratchet)
        let (hdr4, ct4) = bob3.encrypt(b"bob3 reply", ad).unwrap();
        let pt4 = alice2.decrypt(&hdr4, &ct4, ad).unwrap();
        assert_eq!(pt4, b"bob3 reply");

        // Save and restore Alice too
        let saved_alice = alice2.save().unwrap();
        let mut alice3 = DoubleRatchet::load(&saved_alice).unwrap();

        // Continue conversation with both sides restored
        let (hdr5, ct5) = alice3.encrypt(b"alice3 msg", ad).unwrap();
        let pt5 = bob3.decrypt(&hdr5, &ct5, ad).unwrap();
        assert_eq!(pt5, b"alice3 msg");

        // Multiple messages after restore
        for i in 0..5 {
            let msg = format!("round {i}");
            let (h, c) = alice3.encrypt(msg.as_bytes(), ad).unwrap();
            let p = bob3.decrypt(&h, &c, ad).unwrap();
            assert_eq!(p, msg.as_bytes());
        }
    }

    /// Verify that the FixedRng-based key generation in init_alice produces
    /// a consistent keypair (public key matches private key).
    #[test]
    fn test_init_alice_keypair_consistency() {
        let shared_secret = [0x42u8; 32];
        let bob_spk_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let bob_spk_pub = PublicKey::from(&bob_spk_secret);

        let alice = DoubleRatchet::init_alice(&shared_secret, &bob_spk_pub).unwrap();

        // The public key derived from the stored private bytes should match
        // the public key stored in the ratchet.
        let priv_bytes = alice.our_dh_private_bytes.unwrap();
        let reconstructed_secret = ReusableSecret::random_from_rng(&mut FixedRng(priv_bytes));
        let reconstructed_pub = PublicKey::from(&reconstructed_secret);

        assert_eq!(
            alice.our_dh_public.unwrap().as_bytes(),
            reconstructed_pub.as_bytes(),
            "Public key from stored bytes must match ratchet's public key"
        );
    }

    /// Verify that save→load produces a ratchet that can immediately send
    /// (the DH private key is correctly persisted and restored).
    #[test]
    fn test_save_load_can_send_immediately() {
        let shared_secret = [0x77u8; 32];
        let bob_spk_bytes: [u8; 32] = rand::random();
        let bob_spk = StaticSecret::from(bob_spk_bytes);
        let bob_spk_pub = PublicKey::from(&bob_spk);
        let ad = b"test-ad";

        let mut alice = DoubleRatchet::init_alice(&shared_secret, &bob_spk_pub).unwrap();
        let mut bob = DoubleRatchet::init_bob(&shared_secret, &bob_spk).unwrap();

        // Alice sends first message
        let (hdr1, ct1) = alice.encrypt(b"msg1", ad).unwrap();
        let pt1 = bob.decrypt(&hdr1, &ct1, ad).unwrap();
        assert_eq!(pt1, b"msg1");

        // Save and restore Alice
        let saved = alice.save().unwrap();
        let mut alice2 = DoubleRatchet::load(&saved).unwrap();

        // Alice2 should be able to send immediately (no incoming message needed)
        let (hdr2, ct2) = alice2.encrypt(b"msg2 from restored", ad).unwrap();
        let pt2 = bob.decrypt(&hdr2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"msg2 from restored");

        // And Bob can reply
        let (hdr3, ct3) = bob.encrypt(b"bob reply", ad).unwrap();
        let pt3 = alice2.decrypt(&hdr3, &ct3, ad).unwrap();
        assert_eq!(pt3, b"bob reply");

        // Save and restore Bob too
        let saved_bob = bob.save().unwrap();
        let mut bob2 = DoubleRatchet::load(&saved_bob).unwrap();

        // Both restored — continue conversation
        let (hdr4, ct4) = alice2.encrypt(b"continue", ad).unwrap();
        let pt4 = bob2.decrypt(&hdr4, &ct4, ad).unwrap();
        assert_eq!(pt4, b"continue");
    }

    #[test]
    fn test_wrong_associated_data_fails() {
        let (mut alice, mut bob) = make_pair();

        let (hdr, ct) = alice.encrypt(b"secret", b"correct-ad").unwrap();
        let result = bob.decrypt(&hdr, &ct, b"wrong-ad");
        assert!(result.is_err());
    }
}
