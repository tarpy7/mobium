//! Application-layer encryption for data stored in the local SQLite DB.
//!
//! All sensitive data (message content, sender chain keys, conversation names)
//! is encrypted with AES-256-GCM before being written to disk, using a key
//! derived from the user's password.
//!
//! Wire format per encrypted blob:
//! ```text
//! [12 bytes: nonce] [N bytes: ciphertext + 16-byte GCM tag]
//! ```

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use anyhow::Result;

use crate::state::AppState;

/// Nonce size for AES-256-GCM
const NONCE_LEN: usize = 12;
/// Minimum ciphertext size: nonce + GCM tag
const MIN_CT_LEN: usize = NONCE_LEN + 16;

/// Derive a 32-byte database encryption key from the user's password.
///
/// Uses Argon2id with a deterministic salt derived from the password so that
/// the same password always produces the same DB key, while remaining
/// computationally expensive to brute-force.
///
/// The salt is `HMAC-SHA256("Discable-db-salt-v2", password)` — this is NOT
/// used for security of the salt itself (the salt is deterministic by design),
/// but to domain-separate the DB key from the identity encryption key which
/// uses Argon2id with a random salt.
///
/// Argon2id parameters: 64 MiB memory, 3 iterations, 1 lane.
/// This makes brute-force attacks require ~64 MiB per guess, roughly 10⁴×
/// slower than the previous HMAC-SHA256 approach.
pub fn derive_db_key(password: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use argon2::{Argon2, Algorithm, Version, Params};

    type HmacSha256 = Hmac<Sha256>;

    // Deterministic salt: HMAC-SHA256("Discable-db-salt-v2", password)
    // This ensures the same password always yields the same DB key.
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(b"Discable-db-salt-v2")
        .expect("HMAC accepts any key length");
    mac.update(password.as_bytes());
    let salt = mac.finalize().into_bytes();

    // Argon2id: 64 MiB, 3 iterations, 1 lane
    let params = Params::new(
        64 * 1024, // 64 MiB memory cost
        3,         // 3 iterations
        1,         // 1 lane (parallelism)
        Some(32),  // 32-byte output
    ).expect("valid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .expect("Argon2id hashing should not fail with valid params");
    key
}

/// Encrypt arbitrary bytes with the DB key.
///
/// Returns `nonce || ciphertext` (12 + N+16 bytes).
pub fn encrypt_blob(db_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(db_key);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("DB encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `encrypt_blob`.
pub fn decrypt_blob(db_key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < MIN_CT_LEN {
        return Err(anyhow::anyhow!("Encrypted blob too short ({} bytes)", encrypted.len()));
    }

    let key = Key::<Aes256Gcm>::from_slice(db_key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted[..NONCE_LEN]);
    let ciphertext = &encrypted[NONCE_LEN..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("DB decryption failed — wrong password or corrupted data"))?;

    Ok(plaintext)
}

// ─── Convenience wrappers that pull the key from AppState ────────────────────

/// Encrypt with the DB key from AppState. Returns an error if no key is loaded.
pub async fn encrypt_for_db(state: &AppState, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_guard = state.db_key.read().await;
    let db_key = key_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("DB encryption key not available (not unlocked)"))?;
    encrypt_blob(db_key, plaintext)
}

/// Decrypt with the DB key from AppState. Returns an error if no key is loaded.
pub async fn decrypt_for_db(state: &AppState, encrypted: &[u8]) -> Result<Vec<u8>> {
    let key_guard = state.db_key.read().await;
    let db_key = key_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("DB encryption key not available (not unlocked)"))?;
    decrypt_blob(db_key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_db_key("test-password-123");
        let plaintext = b"Hello, this is a secret message!";

        let encrypted = encrypt_blob(&key, plaintext).unwrap();
        assert!(encrypted.len() > plaintext.len()); // nonce + tag overhead

        let decrypted = decrypt_blob(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = derive_db_key("password-1");
        let key2 = derive_db_key("password-2");
        let plaintext = b"secret";

        let encrypted = encrypt_blob(&key1, plaintext).unwrap();
        let result = decrypt_blob(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = derive_db_key("pw");
        let encrypted = encrypt_blob(&key, b"").unwrap();
        let decrypted = decrypt_blob(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_deterministic_key_derivation() {
        let k1 = derive_db_key("same-password");
        let k2 = derive_db_key("same-password");
        assert_eq!(k1, k2);

        let k3 = derive_db_key("different-password");
        assert_ne!(k1, k3);
    }
}
