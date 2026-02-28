//! Error types for cryptographic operations

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// Invalid key format or length
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Encryption/decryption failure
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Key derivation failure
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid pre-key bundle
    #[error("Invalid pre-key bundle: {0}")]
    InvalidPreKeyBundle(String),

    /// Ratchet desynchronization
    #[error("Ratchet error: {0}")]
    RatchetError(String),

    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Shamir secret sharing error
    #[error("Secret sharing error: {0}")]
    SecretSharingError(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Result type alias for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;
