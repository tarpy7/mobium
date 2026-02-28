//! Cryptographic operations and secure storage

use anyhow::Result;
use securecomm_shared::IdentityKey;
use sha2::{Sha256, Digest};
use tracing::info;

/// Secure storage using encrypted files in the app data directory.
///
/// Identity keys are encrypted with Argon2id + AES-256-GCM before
/// being written to disk, so they are safe at rest.
pub struct SecureStorage {
    data_dir: std::path::PathBuf,
}

impl SecureStorage {
    /// Create a new SecureStorage pointing at the given directory.
    pub fn with_dir(data_dir: std::path::PathBuf) -> Self {
        info!("SecureStorage: data_dir={}", data_dir.display());
        Self { data_dir }
    }

    /// Store identity key encrypted with password
    pub async fn store_identity(&self, identity: &IdentityKey, password: &str) -> Result<()> {
        let encrypted = securecomm_shared::secure_store(identity, password)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt identity: {}", e))?;

        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("identity.enc");
        tokio::fs::write(&path, &encrypted).await?;
        info!("Identity stored at {} ({} bytes)", path.display(), encrypted.len());
        Ok(())
    }

    /// Load identity key
    pub async fn load_identity(&self, password: &str) -> Result<IdentityKey> {
        let path = self.data_dir.join("identity.enc");
        info!("Loading identity from {}", path.display());
        let encrypted = tokio::fs::read(&path).await
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;

        let identity = securecomm_shared::secure_load(&encrypted, password)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt identity: {}", e))?;

        info!("Identity loaded and decrypted successfully");
        Ok(identity)
    }

    /// Check if identity exists
    pub async fn has_identity(&self) -> Result<bool> {
        let path = self.data_dir.join("identity.enc");
        let exists = path.exists();
        info!("has_identity: {} -> {}", path.display(), exists);
        Ok(exists)
    }

    /// Store mnemonic hash for verification
    pub async fn store_mnemonic_hash(&self, mnemonic: &str) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(mnemonic.as_bytes());
        let hash = hex::encode(hasher.finalize());

        tokio::fs::create_dir_all(&self.data_dir).await?;
        tokio::fs::write(self.data_dir.join("mnemonic.hash"), hash).await?;
        Ok(())
    }

    /// Get stored mnemonic (not available -- user must keep their own backup)
    pub async fn get_mnemonic(&self) -> Result<String> {
        Err(anyhow::anyhow!("Mnemonic can only be exported during creation. Please check your backup."))
    }
}
