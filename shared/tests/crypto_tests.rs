//! Comprehensive tests for cryptographic primitives
//!
//! These tests verify correctness and security properties of:
//! - Identity key generation and storage
//! - X3DH handshake
//! - Double Ratchet
//! - Size masking padding
//! - BIP39 recovery
//! - Shamir's Secret Sharing

use mobium_shared::*;

// ============================================================================
// Identity Key Tests
// ============================================================================

#[test]
fn test_identity_key_generation() {
    let identity = generate_identity();

    // Verify keys are non-zero
    assert_ne!(identity.public_signing_key().as_bytes(), &[0u8; 32]);
    assert_ne!(identity.public_encryption_key().as_bytes(), &[0u8; 32]);

    // Verify signing key works
    let message = b"test message";
    let signature = identity.sign(message);
    assert!(identity.verify(message, &signature).is_ok());
}

#[test]
fn test_identity_key_storage_roundtrip() {
    let identity = generate_identity();
    let password = "super_secure_password_123!";

    // Store
    let encrypted = secure_store(&identity, password).unwrap();
    assert!(!encrypted.is_empty());

    // Load
    let loaded = secure_load(&encrypted, password).unwrap();

    // Verify keys match
    assert_eq!(
        identity.public_signing_key().as_bytes(),
        loaded.public_signing_key().as_bytes()
    );
    assert_eq!(
        identity.public_encryption_key().as_bytes(),
        loaded.public_encryption_key().as_bytes()
    );
}

#[test]
fn test_identity_storage_wrong_password() {
    let identity = generate_identity();
    let encrypted = secure_store(&identity, "correct_password").unwrap();

    // Wrong password should fail
    let result = secure_load(&encrypted, "wrong_password");
    assert!(result.is_err());
}

#[test]
fn test_identity_signature_verification() {
    let identity = generate_identity();
    let message = b"hello world";

    // Sign
    let signature = identity.sign(message);

    // Verify
    assert!(identity.verify(message, &signature).is_ok());

    // Wrong message should fail
    let wrong_message = b"different message";
    assert!(identity.verify(wrong_message, &signature).is_err());

    // Tampered signature should fail
    let mut tampered_sig = signature.to_bytes();
    tampered_sig[0] ^= 0xFF;
    let tampered = ed25519_dalek::Signature::from_bytes(&tampered_sig);
    assert!(identity.verify(message, &tampered).is_err());
}

// ============================================================================
// X3DH Handshake Tests
// ============================================================================

#[test]
fn test_x3dh_prekey_bundle_generation() {
    let identity = generate_identity();
    let (bundle, private_keys) = x3dh::generate_pre_key_bundle(&identity, 5);

    // Verify bundle components
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
fn test_x3dh_handshake_full() {
    // Alice and Bob setup
    let alice_identity = generate_identity();
    let bob_identity = generate_identity();

    // Bob generates and publishes pre-key bundle
    let (bob_bundle, bob_private) = x3dh::generate_pre_key_bundle(&bob_identity, 1);

    // Alice initiates handshake (using one-time pre-key)
    // Returns (handshake, ephemeral_public_key)
    let (alice_handshake, alice_ephemeral) =
        x3dh::X3DHHandshake::initiator(&alice_identity, &bob_bundle, Some(0)).unwrap();

    // Bob responds using Alice's actual ephemeral public key
    let bob_handshake = x3dh::X3DHHandshake::responder(
        &bob_identity,
        &bob_private,
        &alice_identity.public_signing_key(),
        &alice_identity.public_encryption_key(),
        &alice_ephemeral,
        Some(0),
    )
    .unwrap();

    // Shared secrets must now match since we use the real ephemeral key
    assert_eq!(
        alice_handshake.shared_secret(),
        bob_handshake.shared_secret()
    );
}

#[test]
fn test_x3dh_invalid_signature() {
    let alice_identity = generate_identity();
    let bob_identity = generate_identity();

    let (mut bob_bundle, _) = x3dh::generate_pre_key_bundle(&bob_identity, 1);

    // Corrupt the signature
    let corrupted_sig = ed25519_dalek::Signature::from_bytes(&[0u8; 64]);
    bob_bundle.signed_pre_key_signature = corrupted_sig;

    // Should fail signature verification
    let result = x3dh::X3DHHandshake::initiator(&alice_identity, &bob_bundle, None);
    assert!(result.is_err());
}

// ============================================================================
// Double Ratchet Tests
// ============================================================================

#[test]
fn test_double_ratchet_encryption_decryption() {
    use x25519_dalek::StaticSecret;

    let shared_secret = [0x42u8; 32];
    let ad = b"test session";

    // Bob's signed pre-key
    let bob_spk = StaticSecret::random_from_rng(&mut rand::thread_rng());
    let bob_spk_pub = x25519_dalek::PublicKey::from(&bob_spk);

    // Alice (initiator) and Bob (responder)
    let mut alice = ratchet::DoubleRatchet::init_alice(&shared_secret, &bob_spk_pub).unwrap();
    let mut bob = ratchet::DoubleRatchet::init_bob(&shared_secret, &bob_spk).unwrap();

    // Alice sends first message
    let plaintext = b"Hello, Bob!";
    let (header, ciphertext) = alice.encrypt(plaintext, ad).unwrap();

    // Bob decrypts
    let decrypted = bob.decrypt(&header, &ciphertext, ad).unwrap();
    assert_eq!(decrypted, plaintext);

    // Verify ciphertext is padded to bucket size
    assert!(padding::is_valid_bucket_size(ciphertext.len()));
}

#[test]
fn test_double_ratchet_message_sizes() {
    use x25519_dalek::StaticSecret;

    let shared_secret = [0x42u8; 32];
    let ad = b"test session";

    let bob_spk = StaticSecret::random_from_rng(&mut rand::thread_rng());
    let bob_spk_pub = x25519_dalek::PublicKey::from(&bob_spk);

    let mut alice = ratchet::DoubleRatchet::init_alice(&shared_secret, &bob_spk_pub).unwrap();

    // Test various plaintext sizes
    let test_sizes = vec![
        0,     // Empty
        10,    // Very short
        100,   // Short
        500,   // Medium
        1000,  // Long
        10000, // Very long
    ];

    for size in test_sizes {
        let plaintext = vec![0xABu8; size];
        let (_header, ciphertext) = alice.encrypt(&plaintext, ad).unwrap();

        // Verify ciphertext is exactly a bucket size
        assert!(
            padding::is_valid_bucket_size(ciphertext.len()),
            "Size {} produced non-bucket ciphertext size {}",
            size,
            ciphertext.len()
        );
    }
}

// ============================================================================
// Size Masking Tests
// ============================================================================

#[test]
fn test_padding_all_buckets() {
    // Test each bucket boundary
    // Overhead = HEADER_SIZE (8) + GCM_TAG_SIZE (16) = 24 bytes total
    for (idx, &bucket_size) in padding::SIZE_BUCKETS.iter().enumerate() {
        // Max plaintext that fits in this bucket
        let max_plaintext = bucket_size - padding::TOTAL_OVERHEAD;

        if max_plaintext > 0 {
            // Test at exact boundary
            let plaintext = vec![0xBBu8; max_plaintext];
            let padded = padding::pad_to_bucket(&plaintext).unwrap();
            // Padded output = bucket_size - GCM_TAG_SIZE (GCM tag added during encryption)
            assert_eq!(padded.len(), bucket_size - padding::GCM_TAG_SIZE);

            // Verify unpad round-trip
            let unpadded = padding::unpad_from_bucket(&padded).unwrap();
            assert_eq!(unpadded, plaintext);
        }

        // Test just under boundary (if not first bucket)
        if idx > 0 && max_plaintext > 1 {
            let plaintext = vec![0xCCu8; max_plaintext - 1];
            let padded = padding::pad_to_bucket(&plaintext).unwrap();
            assert_eq!(padded.len(), bucket_size - padding::GCM_TAG_SIZE);
        }
    }
}

#[test]
fn test_padding_randomness() {
    let plaintext = b"test message for randomness verification";

    // Pad same message multiple times
    let padded1 = padding::pad_to_bucket(plaintext).unwrap();
    let padded2 = padding::pad_to_bucket(plaintext).unwrap();
    let padded3 = padding::pad_to_bucket(plaintext).unwrap();

    // Headers should be identical
    let header_len = 8 + plaintext.len();
    assert_eq!(&padded1[..header_len], &padded2[..header_len]);
    assert_eq!(&padded2[..header_len], &padded3[..header_len]);

    // But padding should differ
    assert_ne!(&padded1[header_len..], &padded2[header_len..]);
    assert_ne!(&padded2[header_len..], &padded3[header_len..]);
}

#[test]
fn test_bucket_index_calculation() {
    // Test bucket boundaries
    // Overhead = 24 bytes (8 header + 16 GCM tag)
    assert_eq!(padding::get_bucket_index(0).unwrap(), 0);
    assert_eq!(padding::get_bucket_index(100).unwrap(), 0); // 512B bucket
    assert_eq!(padding::get_bucket_index(488).unwrap(), 0); // Exactly at 512B boundary (488 + 24 = 512)
    assert_eq!(padding::get_bucket_index(489).unwrap(), 1); // 1KB bucket (489 + 24 = 513 > 512)
    assert_eq!(padding::get_bucket_index(1000).unwrap(), 1); // 1KB bucket
    assert_eq!(padding::get_bucket_index(3000).unwrap(), 3); // 4KB bucket
    assert_eq!(padding::get_bucket_index(1000000).unwrap(), 11); // 1MB bucket
}

#[test]
fn test_unpad_invalid_data() {
    // Invalid bucket size
    let invalid_size = vec![0u8; 1000]; // Not a bucket size
    assert!(padding::unpad_from_bucket(&invalid_size).is_err());

    // Too small
    let too_small = vec![0u8; 4];
    assert!(padding::unpad_from_bucket(&too_small).is_err());

    // Corrupted length field
    let mut valid = padding::pad_to_bucket(b"test").unwrap();
    valid[0] = 0xFF; // Corrupt length
    valid[1] = 0xFF;
    valid[2] = 0xFF;
    valid[3] = 0xFF;
    assert!(padding::unpad_from_bucket(&valid).is_err());
}

#[test]
fn test_size_too_large() {
    let too_large = vec![0u8; padding::MAX_PLAINTEXT_SIZE + 1];
    assert!(padding::pad_to_bucket(&too_large).is_err());
}

// ============================================================================
// BIP39 Recovery Tests
// ============================================================================

#[test]
fn test_mnemonic_generation() {
    let mnemonic1 = recovery::generate_mnemonic().unwrap();
    let mnemonic2 = recovery::generate_mnemonic().unwrap();

    // Should be 24 words
    let words1: Vec<&str> = mnemonic1.split_whitespace().collect();
    let words2: Vec<&str> = mnemonic2.split_whitespace().collect();

    assert_eq!(words1.len(), 24);
    assert_eq!(words2.len(), 24);

    // Should be different
    assert_ne!(mnemonic1, mnemonic2);
}

#[test]
fn test_mnemonic_seed_derivation() {
    let mnemonic = recovery::generate_mnemonic().unwrap();

    // Derive seed
    let seed = recovery::mnemonic_to_seed(&mnemonic, None).unwrap();
    assert_eq!(seed.len(), 64);

    // Same mnemonic should produce same seed
    let seed2 = recovery::mnemonic_to_seed(&mnemonic, None).unwrap();
    assert_eq!(seed, seed2);

    // With passphrase should be different
    let seed_with_pass = recovery::mnemonic_to_seed(&mnemonic, Some("password")).unwrap();
    assert_ne!(seed.to_vec(), seed_with_pass.to_vec());
}

#[test]
fn test_mnemonic_validation() {
    let valid_mnemonic = recovery::generate_mnemonic().unwrap();
    assert!(recovery::validate_mnemonic(&valid_mnemonic).is_ok());

    // Invalid mnemonic
    assert!(recovery::validate_mnemonic("invalid mnemonic words here").is_err());

    // Too short
    assert!(recovery::validate_mnemonic("abandon abandon abandon").is_err());
}

// ============================================================================
// Shamir's Secret Sharing Tests
// ============================================================================

#[test]
fn test_shamir_split_reconstruct() {
    let secret = b"My super secret master key!";

    // Split into 5 shares, require 3 to reconstruct
    let shares = sss::create_shards(secret, 5, 3).unwrap();

    assert_eq!(shares.len(), 5);

    // Reconstruct with exactly 3 shares
    let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let reconstructed = sss::reconstruct_secret(&subset).unwrap();
    assert_eq!(secret.to_vec(), reconstructed);

    // Reconstruct with all 5 shares
    let reconstructed2 = sss::reconstruct_secret(&shares).unwrap();
    assert_eq!(secret.to_vec(), reconstructed2);
}

#[test]
fn test_shamir_insufficient_shares() {
    let secret = b"Test secret data";
    let shares = sss::create_shards(secret, 5, 3).unwrap();

    // Try with only 2 shares (below threshold)
    let subset = vec![shares[0].clone(), shares[1].clone()];
    let reconstructed = sss::reconstruct_secret(&subset).unwrap();

    // Should NOT match original
    assert_ne!(secret.to_vec(), reconstructed);
}

#[test]
fn test_shamir_invalid_parameters() {
    // Threshold < 2
    assert!(sss::create_shards(b"test", 5, 1).is_err());

    // Threshold > shares
    assert!(sss::create_shards(b"test", 3, 5).is_err());

    // Zero shares
    assert!(sss::create_shards(b"test", 0, 0).is_err());
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_encryption_pipeline() {
    // This test simulates a full message exchange with size masking
    let alice_identity = generate_identity();
    let bob_identity = generate_identity();

    // Generate keys
    let (_, alice_private) = x3dh::generate_pre_key_bundle(&alice_identity, 1);
    let (bob_bundle, bob_private) = x3dh::generate_pre_key_bundle(&bob_identity, 1);

    // X3DH handshake
    let (alice_x3dh, _alice_ephemeral) =
        x3dh::X3DHHandshake::initiator(&alice_identity, &bob_bundle, Some(0)).unwrap();

    // Initialize Double Ratchet using Bob's signed pre-key as the initial DH key
    let shared_secret = alice_x3dh.shared_secret();
    let associated_data = alice_x3dh.associated_data();

    let mut alice_ratchet =
        ratchet::DoubleRatchet::init_alice(shared_secret, &bob_bundle.signed_pre_key).unwrap();

    // Encrypt a message
    let plaintext = b"This is a secret message with size masking!";
    let (_header, ciphertext) = alice_ratchet.encrypt(plaintext, associated_data).unwrap();

    // Verify size masking: ciphertext should be exactly a bucket size
    // (pad_to_bucket produces bucket - 16, then GCM encryption adds 16 = bucket)
    assert!(
        padding::is_valid_bucket_size(ciphertext.len()),
        "Ciphertext size {} is not a valid bucket size",
        ciphertext.len()
    );

    // The ciphertext size should be one of our buckets
    let expected_bucket = padding::get_bucket_size(plaintext.len()).unwrap();
    assert_eq!(ciphertext.len(), expected_bucket);
}

#[test]
fn test_error_handling() {
    // Test that errors are properly propagated

    // Invalid mnemonic
    let result = recovery::validate_mnemonic("not a valid mnemonic");
    assert!(result.is_err());

    // Message too large for padding
    let huge_message = vec![0u8; 10_000_000]; // 10MB
    let result = padding::pad_to_bucket(&huge_message);
    assert!(result.is_err());

    // Invalid signature
    let identity = generate_identity();
    let message = b"test";
    let signature = identity.sign(message);
    let wrong_message = b"different";
    assert!(identity.verify(wrong_message, &signature).is_err());
}

// ============================================================================
// Benchmarks (using test as simple benchmark)
// ============================================================================

#[test]
fn benchmark_padding_performance() {
    use std::time::Instant;

    let iterations = 1000;
    let plaintext = b"Test message for benchmarking performance";

    // Warmup
    for _ in 0..100 {
        let _ = padding::pad_to_bucket(plaintext).unwrap();
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let padded = padding::pad_to_bucket(plaintext).unwrap();
        let _ = padding::unpad_from_bucket(&padded).unwrap();
    }
    let duration = start.elapsed();

    let avg_micros = duration.as_micros() as f64 / iterations as f64;
    println!(
        "Padding benchmark: {} iterations, avg {:.2} μs/iter",
        iterations, avg_micros
    );

    // Should be reasonably fast (< 100μs per operation)
    assert!(avg_micros < 100.0, "Padding too slow: {:.2} μs", avg_micros);
}
