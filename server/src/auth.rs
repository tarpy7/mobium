//! Authentication utilities

use ed25519_dalek::{VerifyingKey, Signature, Verifier};

/// Verify a challenge signature
/// 
/// Used for WebSocket authentication. The client must sign
/// a server-provided challenge with their Ed25519 identity key.
pub fn verify_challenge(pubkey_bytes: &[u8], signature_bytes: &[u8], challenge: &[u8]) -> bool {
    // Parse public key
    let pubkey_array: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    
    let pubkey = match VerifyingKey::from_bytes(&pubkey_array) {
        Ok(key) => key,
        Err(_) => return false,
    };
    
    // Parse signature
    let sig_array: [u8; 64] = match signature_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    
    let signature = Signature::from_bytes(&sig_array);
    
    // Verify
    pubkey.verify_strict(challenge, &signature).is_ok()
}