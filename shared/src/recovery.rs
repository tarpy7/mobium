//! BIP39 Mnemonic-based key recovery
//!
//! Implements BIP39 for generating 24-word mnemonic phrases
//! that can be used to recover identity keys.

use crate::error::{CryptoError, Result};
use bip39::{Language, Mnemonic};
use zerocopy::IntoBytes;

/// Generate a new 24-word BIP39 mnemonic
///
/// Uses the English wordlist with 256 bits of entropy.
pub fn generate_mnemonic() -> Result<String> {
    let mut rng = rand::rngs::OsRng;
    let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 24)
        .map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;

    Ok(mnemonic.to_string())
}

/// Convert a mnemonic phrase to a seed
///
/// Uses PBKDF2 with HMAC-SHA512 (as per BIP39).
/// Returns a 64-byte seed.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: Option<&str>) -> Result<[u8; 64]> {
    let mnemonic =
        Mnemonic::parse(mnemonic).map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;

    let passphrase = passphrase.unwrap_or("");
    let seed = mnemonic.to_seed(passphrase);

    let mut result = [0u8; 64];
    result.copy_from_slice(seed.as_bytes());
    Ok(result)
}

/// Validate a mnemonic phrase
///
/// Checks that the words are valid and the checksum is correct.
pub fn validate_mnemonic(mnemonic: &str) -> Result<()> {
    Mnemonic::parse(mnemonic).map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;
    Ok(())
}

/// Derive identity key seed from BIP39 seed
///
/// Uses HKDF-like derivation to get a 32-byte key.
pub fn derive_identity_seed(bip39_seed: &[u8; 64]) -> Result<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(b"Mobium-Identity-Derivation")
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
    mac.update(bip39_seed);
    let result = mac.finalize().into_bytes();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let mnemonic = generate_mnemonic().unwrap();

        // Convert to seed
        let seed = mnemonic_to_seed(&mnemonic, None).unwrap();
        assert_eq!(seed.len(), 64);

        // Validate
        assert!(validate_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn test_invalid_mnemonic() {
        assert!(validate_mnemonic("invalid mnemonic phrase here").is_err());
        assert!(validate_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());
        // Too short
    }

    #[test]
    fn test_seed_derivation() {
        let mnemonic = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&mnemonic, None).unwrap();
        let identity_seed = derive_identity_seed(&seed).unwrap();
        assert_eq!(identity_seed.len(), 32);
    }
}
