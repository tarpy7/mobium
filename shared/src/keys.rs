//! Identity key generation and secure storage

use crate::error::{CryptoError, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonRng, SaltString},
    Argon2, PasswordHasher,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Identity key pair containing both signing and encryption keys
///
/// This is the root of trust for a user's identity in SecureComm.
/// The signing key (Ed25519) is used for authentication and signatures.
/// The encryption key (X25519) is used for X3DH key agreement.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKey {
    /// Ed25519 signing key for authentication
    #[zeroize(skip)]
    pub signing: SigningKey,
    /// X25519 static key for encryption
    pub encryption: StaticSecret,
}

impl IdentityKey {
    /// Get the public signing key
    pub fn public_signing_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Get the public encryption key
    pub fn public_encryption_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.encryption)
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.signing
            .verifying_key()
            .verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// Generate a new identity key pair
///
/// Uses cryptographically secure random number generation from the OS.
pub fn generate_identity() -> IdentityKey {
    let mut csprng = OsRng;

    let signing = SigningKey::generate(&mut csprng);
    let encryption = StaticSecret::random_from_rng(&mut csprng);

    IdentityKey {
        signing,
        encryption,
    }
}

/// Generate an identity key pair deterministically from a 32-byte seed
///
/// This is used for recovering identity from a BIP39 mnemonic.
/// The same seed will always produce the same key pair.
///
/// Uses HKDF-SHA256 to derive two independent 32-byte keys from the seed:
/// - Signing key: HKDF(seed, info="Discable-ed25519-signing-v1")
/// - Encryption key: HKDF(seed, info="Discable-x25519-encryption-v1")
///
/// This prevents cross-protocol key reuse between Ed25519 and X25519.
pub fn identity_from_seed(seed: &[u8; 32]) -> IdentityKey {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // HKDF-expand is overkill for a single 32-byte output from a 32-byte
    // uniformly random seed — HMAC with distinct info strings suffices and
    // is equivalent to a single HKDF-Expand step.
    let mut signing_mac =
        <HmacSha256 as Mac>::new_from_slice(seed).expect("HMAC accepts any key length");
    signing_mac.update(b"Discable-ed25519-signing-v1");
    let signing_bytes: [u8; 32] = signing_mac.finalize().into_bytes().into();

    let mut encryption_mac =
        <HmacSha256 as Mac>::new_from_slice(seed).expect("HMAC accepts any key length");
    encryption_mac.update(b"Discable-x25519-encryption-v1");
    let encryption_bytes: [u8; 32] = encryption_mac.finalize().into_bytes().into();

    let signing = SigningKey::from_bytes(&signing_bytes);
    let encryption = StaticSecret::from(encryption_bytes);

    IdentityKey {
        signing,
        encryption,
    }
}

/// Securely store an identity key encrypted with a password
///
/// Uses Argon2id for key derivation and AES-256-GCM for encryption.
/// The format includes a salt and nonce for secure storage.
pub fn secure_store(key: &IdentityKey, password: &str) -> Result<Vec<u8>> {
    // Serialize the keys
    let signing_bytes = key.signing.to_bytes();
    let encryption_bytes = key.encryption.to_bytes();

    let mut plaintext = Vec::with_capacity(64);
    plaintext.extend_from_slice(&signing_bytes);
    plaintext.extend_from_slice(&encryption_bytes);

    // Generate salt for Argon2
    let salt = SaltString::generate(&mut ArgonRng);

    // Derive encryption key using Argon2id
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    let key_material = password_hash
        .hash
        .ok_or_else(|| CryptoError::KeyDerivationError("No hash generated".to_string()))?;

    // Use first 32 bytes as AES key
    let aes_key = Key::<Aes256Gcm>::from_slice(&key_material.as_bytes()[..32]);
    let cipher = Aes256Gcm::new(aes_key);

    // Generate random nonce
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    // Format: [salt (22 bytes)] [nonce (12 bytes)] [ciphertext]
    let mut result = Vec::new();
    result.extend_from_slice(salt.as_str().as_bytes());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    // Clear sensitive data
    plaintext.zeroize();

    Ok(result)
}

/// Load an identity key from encrypted storage
///
/// Decrypts using the provided password and reconstructs the key pair.
pub fn secure_load(encrypted: &[u8], password: &str) -> Result<IdentityKey> {
    if encrypted.len() < 34 {
        return Err(CryptoError::InvalidKey(
            "Encrypted data too short".to_string(),
        ));
    }

    // Parse format: [salt (22 bytes)] [nonce (12 bytes)] [ciphertext]
    let salt_str = std::str::from_utf8(&encrypted[..22])
        .map_err(|_| CryptoError::InvalidKey("Invalid salt encoding".to_string()))?;
    let salt = SaltString::from_b64(salt_str)
        .map_err(|_| CryptoError::InvalidKey("Invalid salt format".to_string()))?;

    let nonce = Nonce::from_slice(&encrypted[22..34]);
    let ciphertext = &encrypted[34..];

    // Derive key using Argon2id
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    let key_material = password_hash
        .hash
        .ok_or_else(|| CryptoError::KeyDerivationError("No hash generated".to_string()))?;

    let aes_key = Key::<Aes256Gcm>::from_slice(&key_material.as_bytes()[..32]);
    let cipher = Aes256Gcm::new(aes_key);

    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        CryptoError::EncryptionError("Decryption failed - wrong password?".to_string())
    })?;

    if plaintext.len() != 64 {
        return Err(CryptoError::InvalidKey(
            "Decrypted key has wrong length".to_string(),
        ));
    }

    // Reconstruct keys
    let mut signing_bytes = [0u8; 32];
    let mut encryption_bytes = [0u8; 32];
    signing_bytes.copy_from_slice(&plaintext[..32]);
    encryption_bytes.copy_from_slice(&plaintext[32..]);

    let signing = SigningKey::from_bytes(&signing_bytes);
    let encryption = StaticSecret::from(encryption_bytes);

    // Clear sensitive data
    signing_bytes.zeroize();
    encryption_bytes.zeroize();

    Ok(IdentityKey {
        signing,
        encryption,
    })
}

/// Convert an Ed25519 verifying (public) key to an X25519 public key.
///
/// This uses the standard birational map from the Ed25519 curve (twisted Edwards)
/// to Curve25519 (Montgomery form), which is the same conversion that libsodium's
/// `crypto_sign_ed25519_pk_to_curve25519` performs.
///
/// This allows encrypting data for a recipient whose public key you only know
/// in Ed25519 form (e.g., from their authentication identity).
pub fn ed25519_pk_to_x25519(ed_pk: &VerifyingKey) -> Result<X25519PublicKey> {
    let ed_point = curve25519_dalek::edwards::CompressedEdwardsY(ed_pk.to_bytes());
    let ed_point = ed_point
        .decompress()
        .ok_or_else(|| CryptoError::InvalidKey("Failed to decompress Ed25519 public key".into()))?;
    let mont_point = ed_point.to_montgomery();
    Ok(X25519PublicKey::from(mont_point.to_bytes()))
}

/// Encrypt a payload for a specific recipient using ECDH + AES-256-GCM.
///
/// Performs X25519 DH between `our_secret` and `their_public`, derives an
/// AES-256-GCM key via HKDF-SHA256, and encrypts `plaintext`.
///
/// Returns `nonce (12 bytes) || ciphertext+tag`.
pub fn encrypt_for_recipient(
    our_secret: &StaticSecret,
    their_public: &X25519PublicKey,
    plaintext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let shared_secret = our_secret.diffie_hellman(their_public);

    // Derive AES key: HMAC-SHA256(shared_secret, "Discable-dist-enc-v1" || context)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(shared_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(b"Discable-dist-enc-v1");
    mac.update(context);
    let aes_key_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a payload encrypted by `encrypt_for_recipient`.
///
/// Performs X25519 DH between `our_secret` and `their_public` (the sender's
/// X25519 public key), derives the same AES key, and decrypts.
pub fn decrypt_from_sender(
    our_secret: &StaticSecret,
    their_public: &X25519PublicKey,
    encrypted: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    if encrypted.len() < 28 {
        return Err(CryptoError::EncryptionError(
            "Encrypted data too short".into(),
        ));
    }

    let shared_secret = our_secret.diffie_hellman(their_public);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(shared_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(b"Discable-dist-enc-v1");
    mac.update(context);
    let aes_key_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::EncryptionError(format!("Decryption failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let key = generate_identity();
        assert!(key.public_signing_key().as_bytes().len() == 32);
    }

    #[test]
    fn test_sign_verify() {
        let key = generate_identity();
        let message = b"test message";
        let signature = key.sign(message);
        assert!(key.verify(message, &signature).is_ok());

        // Wrong message should fail
        let wrong_message = b"wrong message";
        assert!(key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_secure_store_load() {
        let key = generate_identity();
        let password = "super_secure_password_123";

        // Store
        let encrypted = secure_store(&key, password).unwrap();
        assert!(!encrypted.is_empty());

        // Load
        let loaded = secure_load(&encrypted, password).unwrap();

        // Verify keys match
        assert_eq!(
            key.public_signing_key().as_bytes(),
            loaded.public_signing_key().as_bytes()
        );
        assert_eq!(
            key.public_encryption_key().as_bytes(),
            loaded.public_encryption_key().as_bytes()
        );

        // Wrong password should fail
        assert!(secure_load(&encrypted, "wrong_password").is_err());
    }
}
