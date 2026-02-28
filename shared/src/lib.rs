//! Mobium Cryptographic Primitives
//!
//! This crate provides the cryptographic foundation for Mobium,
//! implementing Signal Protocol primitives, X3DH handshake, and Double Ratchet.

#![warn(missing_docs)]
#![warn(unsafe_code)]

pub mod error;
pub mod keys;
pub mod padding;
pub mod ratchet;
pub mod recovery;
pub mod sender_keys;
pub mod sss;
pub mod x3dh;

pub use error::CryptoError;
pub use keys::{
    decrypt_from_sender, ed25519_pk_to_x25519, encrypt_for_recipient, generate_identity,
    identity_from_seed, secure_load, secure_store, IdentityKey,
};
pub use padding::{
    get_bucket_index, get_bucket_size, pad_to_bucket, unpad_from_bucket, SIZE_BUCKETS,
};
pub use ratchet::{DoubleRatchet, MessageHeader, MessageKey};
pub use recovery::{generate_mnemonic, mnemonic_to_seed, validate_mnemonic};
pub use sender_keys::{GroupSession, SenderKeyDistribution};
pub use sss::{create_shards, reconstruct_secret};
pub use x3dh::{PreKeyBundle, X3DHHandshake};

use subtle::ConstantTimeEq;

/// Version of the crypto protocol
pub const PROTOCOL_VERSION: u8 = 1;

/// Constant-time comparison of byte arrays
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
