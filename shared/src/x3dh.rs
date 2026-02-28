//! X3DH (Extended Triple Diffie-Hellman) Key Agreement
//!
//! Implementation of the X3DH protocol for initial key exchange.
//! Provides mutual authentication and forward secrecy.
//!
//! <https://signal.org/docs/specifications/x3dh/>
//!
//! ## Flow
//!
//! 1. Bob publishes a [`PreKeyBundle`] (identity key, signed pre-key, one-time pre-keys).
//! 2. Alice fetches the bundle and calls [`X3DHHandshake::initiator`], which returns
//!    the handshake **and** her ephemeral public key.
//! 3. Alice sends the ephemeral public key (+ which one-time key she used) with her
//!    first Double Ratchet message.
//! 4. Bob calls [`X3DHHandshake::responder`] using Alice's ephemeral public key to
//!    derive the same shared secret.

use crate::error::{CryptoError, Result};
use crate::keys::IdentityKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Type alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

/// Pre-key bundle published by a user to the server.
///
/// This is the public information needed by another user to initiate
/// an X3DH handshake.
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    /// User's identity public key (Ed25519) — for signature verification & AD.
    pub identity_key: VerifyingKey,
    /// User's X25519 identity public key — for DH calculations.
    ///
    /// This is `PublicKey::from(&identity.encryption)`, i.e. the independently
    /// generated X25519 key, **not** an Ed25519→X25519 conversion.
    pub identity_encryption_key: PublicKey,
    /// User's signed pre-key (X25519)
    pub signed_pre_key: PublicKey,
    /// Signature of the signed pre-key by the identity key
    pub signed_pre_key_signature: Signature,
    /// One-time pre-keys (X25519) — optional
    pub one_time_pre_keys: Vec<PublicKey>,
}

/// Private pre-key material stored by the user.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivatePreKeys {
    /// Signed pre-key secret
    pub signed_pre_key: StaticSecret,
    /// One-time pre-key secrets.
    /// x25519-dalek v2 `StaticSecret` implements `Zeroize`, so these are
    /// properly zeroized when the `PrivatePreKeys` struct is dropped.
    pub one_time_pre_keys: Vec<StaticSecret>,
}

/// Result of an X3DH handshake.
pub struct X3DHHandshake {
    /// The shared secret derived from the handshake
    shared_secret: [u8; 32],
    /// Associated data for the session (concatenation of identity keys)
    associated_data: Vec<u8>,
}

impl X3DHHandshake {
    /// Perform X3DH as the **initiator** (Alice).
    ///
    /// Returns `(handshake, ephemeral_public_key)`.
    /// The caller MUST transmit `ephemeral_public_key` with the first message
    /// so that the responder can derive the same shared secret.
    ///
    /// # Arguments
    /// * `our_identity` — Our long-term identity key
    /// * `their_bundle` — The recipient's pre-key bundle
    /// * `one_time_key_index` — Index of the one-time pre-key to use (if any)
    pub fn initiator(
        our_identity: &IdentityKey,
        their_bundle: &PreKeyBundle,
        one_time_key_index: Option<usize>,
    ) -> Result<(Self, PublicKey)> {
        // 1. Verify signed pre-key signature
        their_bundle
            .identity_key
            .verify(
                their_bundle.signed_pre_key.as_bytes(),
                &their_bundle.signed_pre_key_signature,
            )
            .map_err(|_| CryptoError::InvalidSignature)?;

        // 2. Generate ephemeral key pair
        let ephemeral_secret = ReusableSecret::random_from_rng(&mut rand::rngs::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // 3. DH calculations using the X25519 identity keys directly
        // DH1 = DH(IK_A, SPK_B)  — our identity encryption key × their signed pre-key
        let dh1 = our_identity
            .encryption
            .diffie_hellman(&their_bundle.signed_pre_key);

        // DH2 = DH(EK_A, IK_B)   — our ephemeral × their X25519 identity key
        let dh2 = ephemeral_secret.diffie_hellman(&their_bundle.identity_encryption_key);

        // DH3 = DH(EK_A, SPK_B)  — our ephemeral × their signed pre-key
        let dh3 = ephemeral_secret.diffie_hellman(&their_bundle.signed_pre_key);

        // DH4 = DH(EK_A, OPK_B)  — our ephemeral × their one-time pre-key (optional)
        let dh4 = if let Some(idx) = one_time_key_index {
            if idx >= their_bundle.one_time_pre_keys.len() {
                return Err(CryptoError::InvalidPreKeyBundle(
                    "One-time key index out of bounds".to_string(),
                ));
            }
            Some(ephemeral_secret.diffie_hellman(&their_bundle.one_time_pre_keys[idx]))
        } else {
            None
        };

        // 5. Concatenate DH outputs
        let mut dh_bytes = Vec::with_capacity(128);
        dh_bytes.extend_from_slice(dh1.as_bytes());
        dh_bytes.extend_from_slice(dh2.as_bytes());
        dh_bytes.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4_val) = dh4 {
            dh_bytes.extend_from_slice(dh4_val.as_bytes());
        }

        // 6. Associated data = IK_A || IK_B  (Ed25519 public keys)
        let mut associated_data = Vec::with_capacity(64);
        associated_data.extend_from_slice(our_identity.public_signing_key().as_bytes());
        associated_data.extend_from_slice(their_bundle.identity_key.as_bytes());

        // 7. KDF
        let shared_secret = Self::kdf_x3dh(&dh_bytes, &associated_data)?;

        Ok((
            Self {
                shared_secret,
                associated_data,
            },
            ephemeral_public,
        ))
    }

    /// Perform X3DH as the **responder** (Bob).
    ///
    /// # Arguments
    /// * `our_identity` — Our long-term identity key
    /// * `our_pre_keys` — Our private pre-key material
    /// * `their_identity_key` — Initiator's Ed25519 identity public key (for AD)
    /// * `their_identity_encryption_key` — Initiator's X25519 identity public key (for DH)
    /// * `their_ephemeral_key` — Initiator's ephemeral X25519 public key (from the first message)
    /// * `one_time_key_index` — Index of the one-time pre-key that was used (if any)
    pub fn responder(
        our_identity: &IdentityKey,
        our_pre_keys: &PrivatePreKeys,
        their_identity_key: &VerifyingKey,
        their_identity_encryption_key: &PublicKey,
        their_ephemeral_key: &PublicKey,
        one_time_key_index: Option<usize>,
    ) -> Result<Self> {
        // DH calculations (mirror of initiator) using X25519 identity keys
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = our_pre_keys
            .signed_pre_key
            .diffie_hellman(their_identity_encryption_key);

        // DH2 = DH(IK_B, EK_A)
        let dh2 = our_identity.encryption.diffie_hellman(their_ephemeral_key);

        // DH3 = DH(SPK_B, EK_A)
        let dh3 = our_pre_keys
            .signed_pre_key
            .diffie_hellman(their_ephemeral_key);

        // DH4 = DH(OPK_B, EK_A) — optional
        let dh4 = if let Some(idx) = one_time_key_index {
            if idx >= our_pre_keys.one_time_pre_keys.len() {
                return Err(CryptoError::InvalidPreKeyBundle(
                    "One-time key index out of bounds".to_string(),
                ));
            }
            Some(our_pre_keys.one_time_pre_keys[idx].diffie_hellman(their_ephemeral_key))
        } else {
            None
        };

        // Concatenate DH outputs (same order as initiator)
        let mut dh_bytes = Vec::with_capacity(128);
        dh_bytes.extend_from_slice(dh1.as_bytes());
        dh_bytes.extend_from_slice(dh2.as_bytes());
        dh_bytes.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4_val) = dh4 {
            dh_bytes.extend_from_slice(dh4_val.as_bytes());
        }

        // Associated data: IK_Alice || IK_Bob  (same order as initiator)
        let mut associated_data = Vec::with_capacity(64);
        associated_data.extend_from_slice(their_identity_key.as_bytes());
        associated_data.extend_from_slice(our_identity.public_signing_key().as_bytes());

        // KDF
        let shared_secret = Self::kdf_x3dh(&dh_bytes, &associated_data)?;

        Ok(Self {
            shared_secret,
            associated_data,
        })
    }

    /// Get the shared secret.
    pub fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Get the associated data.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    /// KDF for X3DH (HKDF-like: extract then expand).
    fn kdf_x3dh(dh_bytes: &[u8], associated_data: &[u8]) -> Result<[u8; 32]> {
        // Extract: PRK = HMAC(salt=0, IKM=dh_bytes)
        let mut mac = HmacSha256::new_from_slice(&[0u8; 32])
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
        mac.update(dh_bytes);
        let prk = mac.finalize().into_bytes();

        // Expand: HMAC(PRK, info || 0x01)
        let mut mac = HmacSha256::new_from_slice(&prk)
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;
        mac.update(associated_data);
        mac.update(&[1u8]);
        let result = mac.finalize().into_bytes();

        let mut output = [0u8; 32];
        output.copy_from_slice(&result[..32]);
        Ok(output)
    }
}

/// Generate a pre-key bundle for publishing.
pub fn generate_pre_key_bundle(
    identity: &IdentityKey,
    num_one_time_keys: usize,
) -> (PreKeyBundle, PrivatePreKeys) {
    // Generate signed pre-key
    let signed_pre_key_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let signed_pre_key_public = PublicKey::from(&signed_pre_key_secret);

    // Sign the pre-key with Ed25519 identity key
    let signature = identity.sign(signed_pre_key_public.as_bytes());

    // Generate one-time pre-keys
    let mut one_time_public = Vec::with_capacity(num_one_time_keys);
    let mut one_time_private = Vec::with_capacity(num_one_time_keys);

    for _ in 0..num_one_time_keys {
        let secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        one_time_public.push(public);
        one_time_private.push(secret);
    }

    let bundle = PreKeyBundle {
        identity_key: identity.public_signing_key(),
        identity_encryption_key: identity.public_encryption_key(),
        signed_pre_key: signed_pre_key_public,
        signed_pre_key_signature: signature,
        one_time_pre_keys: one_time_public,
    };

    let private_keys = PrivatePreKeys {
        signed_pre_key: signed_pre_key_secret,
        one_time_pre_keys: one_time_private,
    };

    (bundle, private_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_identity;

    #[test]
    fn test_pre_key_bundle_generation() {
        let identity = generate_identity();
        let (bundle, private_keys) = generate_pre_key_bundle(&identity, 5);

        assert_eq!(bundle.one_time_pre_keys.len(), 5);
        assert_eq!(private_keys.one_time_pre_keys.len(), 5);

        // Verify signature
        assert!(identity
            .verify(
                bundle.signed_pre_key.as_bytes(),
                &bundle.signed_pre_key_signature
            )
            .is_ok());
    }

    #[test]
    fn test_x3dh_handshake() {
        let alice_identity = generate_identity();
        let bob_identity = generate_identity();

        // Bob publishes pre-key bundle
        let (bob_bundle, bob_private) = generate_pre_key_bundle(&bob_identity, 1);

        // Alice initiates — returns (handshake, ephemeral_public)
        let (alice_handshake, alice_ephemeral) =
            X3DHHandshake::initiator(&alice_identity, &bob_bundle, Some(0)).unwrap();

        // Bob responds using Alice's ACTUAL ephemeral public key
        let bob_handshake = X3DHHandshake::responder(
            &bob_identity,
            &bob_private,
            &alice_identity.public_signing_key(),
            &alice_identity.public_encryption_key(),
            &alice_ephemeral,
            Some(0),
        )
        .unwrap();

        // Shared secrets MUST match
        assert_eq!(
            alice_handshake.shared_secret(),
            bob_handshake.shared_secret(),
            "X3DH shared secrets do not match!"
        );

        // Associated data must match
        assert_eq!(
            alice_handshake.associated_data(),
            bob_handshake.associated_data(),
        );
    }

    #[test]
    fn test_x3dh_without_one_time_key() {
        let alice_identity = generate_identity();
        let bob_identity = generate_identity();

        let (bob_bundle, bob_private) = generate_pre_key_bundle(&bob_identity, 0);

        let (alice_hs, alice_eph) =
            X3DHHandshake::initiator(&alice_identity, &bob_bundle, None).unwrap();

        let bob_hs = X3DHHandshake::responder(
            &bob_identity,
            &bob_private,
            &alice_identity.public_signing_key(),
            &alice_identity.public_encryption_key(),
            &alice_eph,
            None,
        )
        .unwrap();

        assert_eq!(alice_hs.shared_secret(), bob_hs.shared_secret());
    }

    #[test]
    fn test_x3dh_into_double_ratchet() {
        use crate::ratchet::DoubleRatchet;

        let alice_identity = generate_identity();
        let bob_identity = generate_identity();

        let (bob_bundle, bob_private) = generate_pre_key_bundle(&bob_identity, 1);

        // X3DH
        let (alice_hs, alice_eph) =
            X3DHHandshake::initiator(&alice_identity, &bob_bundle, Some(0)).unwrap();

        let bob_hs = X3DHHandshake::responder(
            &bob_identity,
            &bob_private,
            &alice_identity.public_signing_key(),
            &alice_identity.public_encryption_key(),
            &alice_eph,
            Some(0),
        )
        .unwrap();

        assert_eq!(alice_hs.shared_secret(), bob_hs.shared_secret());

        // Transition into Double Ratchet
        let ad = alice_hs.associated_data();
        let mut alice_dr =
            DoubleRatchet::init_alice(alice_hs.shared_secret(), &bob_bundle.signed_pre_key)
                .unwrap();
        let mut bob_dr =
            DoubleRatchet::init_bob(bob_hs.shared_secret(), &bob_private.signed_pre_key).unwrap();

        // Alice → Bob
        let (hdr, ct) = alice_dr.encrypt(b"Hello from X3DH!", ad).unwrap();
        let pt = bob_dr.decrypt(&hdr, &ct, ad).unwrap();
        assert_eq!(pt, b"Hello from X3DH!");

        // Bob → Alice
        let (hdr, ct) = bob_dr.encrypt(b"Got it!", ad).unwrap();
        let pt = alice_dr.decrypt(&hdr, &ct, ad).unwrap();
        assert_eq!(pt, b"Got it!");
    }
}
