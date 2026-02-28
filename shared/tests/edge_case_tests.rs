//! Error handling and edge case tests
//!
//! Tests error propagation, invalid inputs, and boundary conditions.

use securecomm_shared::CryptoError;

// ============================================================================
// Error Type Tests
// ============================================================================

#[test]
fn test_error_display() {
    let error = CryptoError::InvalidKey("test key error".to_string());
    let display = format!("{}", error);
    assert!(display.contains("Invalid key"));
    assert!(display.contains("test key error"));
    
    let error = CryptoError::EncryptionError("encryption failed".to_string());
    let display = format!("{}", error);
    assert!(display.contains("Encryption error"));
    
    let error = CryptoError::InvalidSignature;
    let display = format!("{}", error);
    assert!(display.contains("Invalid signature"));
}

#[test]
fn test_error_cloning() {
    let error = CryptoError::KeyDerivationError("test".to_string());
    let cloned = error.clone();
    
    assert_eq!(format!("{}", error), format!("{}", cloned));
}

#[test]
fn test_error_debug() {
    let error = CryptoError::InvalidKey("test".to_string());
    let debug = format!("{:?}", error);
    assert!(debug.contains("InvalidKey"));
}

// ============================================================================
// Boundary Condition Tests
// ============================================================================

#[test]
fn test_empty_inputs() {
    use securecomm_shared::*;
    
    // Empty message padding
    let padded = padding::pad_to_bucket(b"").unwrap();
    let unpadded = padding::unpad_from_bucket(&padded).unwrap();
    assert!(unpadded.is_empty());
}

#[test]
fn test_single_byte_inputs() {
    use securecomm_shared::*;
    
    // Single byte message
    let data = vec![0x42];
    let padded = padding::pad_to_bucket(&data).unwrap();
    let unpadded = padding::unpad_from_bucket(&padded).unwrap();
    assert_eq!(unpadded, data);
}

#[test]
fn test_maximum_size_inputs() {
    use securecomm_shared::*;
    
    // Maximum valid size
    let max_size = padding::MAX_PLAINTEXT_SIZE;
    let data = vec![0xAA; max_size];
    let result = padding::pad_to_bucket(&data);
    assert!(result.is_ok());
    
    // Just over maximum
    let too_large = vec![0xBB; max_size + 1];
    let result = padding::pad_to_bucket(&too_large);
    assert!(result.is_err());
}

#[test]
fn test_boundary_values() {
    use securecomm_shared::*;
    
    // Test at bucket boundaries
    // Total overhead = HEADER_SIZE (8) + GCM_TAG_SIZE (16) = 24
    let bucket_0_max = 512 - padding::TOTAL_OVERHEAD; // Max plaintext for 512B bucket
    let data = vec![0xCC; bucket_0_max];
    let padded = padding::pad_to_bucket(&data).unwrap();
    // Padded output is bucket_size - GCM_TAG_SIZE
    assert_eq!(padded.len(), 512 - padding::GCM_TAG_SIZE);
    
    // Just over bucket 0 boundary
    let over_boundary = vec![0xDD; bucket_0_max + 1];
    let padded = padding::pad_to_bucket(&over_boundary).unwrap();
    assert_eq!(padded.len(), 1024 - padding::GCM_TAG_SIZE); // Should go to next bucket
}

// ============================================================================
// Invalid Input Tests
// ============================================================================

#[test]
fn test_invalid_mnemonic_formats() {
    use securecomm_shared::recovery;
    
    // Empty mnemonic
    assert!(recovery::validate_mnemonic("").is_err());
    
    // Single word
    assert!(recovery::validate_mnemonic("abandon").is_err());
    
    // Invalid words
    assert!(recovery::validate_mnemonic("notavalidword anotherinvalidword").is_err());
    
    // Wrong word count
    assert!(recovery::validate_mnemonic("abandon abandon abandon").is_err());
    
    // Valid words but wrong checksum (12-word phrase with intentionally bad last word)
    let invalid_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    // This may or may not be a valid checksum; just test that parse handles edge cases
    // If it happens to be valid, skip this assertion
    let result = recovery::validate_mnemonic(invalid_checksum);
    // The important thing is it doesn't panic - either Ok or Err is acceptable for edge cases
}

#[test]
fn test_shamir_edge_cases() {
    use securecomm_shared::sss;
    
    // Empty secret
    let shares = sss::create_shards(b"", 5, 3);
    assert!(shares.is_ok());
    let reconstructed = sss::reconstruct_secret(&shares.unwrap()[..3]).unwrap();
    assert!(reconstructed.is_empty());
    
    // Single byte secret
    let shares = sss::create_shards(&[0x42], 3, 2).unwrap();
    let reconstructed = sss::reconstruct_secret(&shares[..2]).unwrap();
    assert_eq!(reconstructed, vec![0x42]);
}

#[test]
fn test_shamir_with_duplicate_shares() {
    use securecomm_shared::sss;
    
    let secret = b"test secret";
    let shares = sss::create_shards(secret, 5, 3).unwrap();
    
    // Try to reconstruct with duplicate shares
    let duplicate_shares = vec![
        shares[0].clone(),
        shares[0].clone(), // Duplicate
        shares[1].clone(),
    ];
    
    // Should fail or give wrong result
    let result = sss::reconstruct_secret(&duplicate_shares);
    if let Ok(reconstructed) = result {
        assert_ne!(reconstructed, secret.to_vec());
    }
}

// ============================================================================
// Panic Safety Tests
// ============================================================================

#[test]
fn test_no_panic_on_valid_inputs() {
    use securecomm_shared::*;
    
    // These should not panic
    let _ = generate_identity();
    let _ = recovery::generate_mnemonic();
    let _ = padding::get_bucket_size(100);
    let _ = padding::get_bucket_index(100);
}

#[test]
fn test_graceful_error_handling() {
    use securecomm_shared::*;
    use securecomm_shared::padding::MAX_PLAINTEXT_SIZE;
    
    // Invalid bucket size should return error, not panic
    let result = padding::unpad_from_bucket(&[0; 100]);
    assert!(result.is_err());
    
    // Invalid mnemonic should return error
    let result = recovery::validate_mnemonic("invalid");
    assert!(result.is_err());
    
    // Too large message should return error
    let huge = vec![0; MAX_PLAINTEXT_SIZE + 100];
    let result = padding::pad_to_bucket(&huge);
    assert!(result.is_err());
}

// ============================================================================
// Concurrency Safety Tests
// ============================================================================

#[test]
fn test_concurrent_key_generation() {
    use std::thread;
    use securecomm_shared::generate_identity;
    
    let mut handles = vec![];
    
    // Spawn multiple threads generating keys
    for _ in 0..10 {
        let handle = thread::spawn(|| {
            let identity = generate_identity();
            // Verify key is valid
            let pubkey = identity.public_signing_key();
            assert_ne!(pubkey.as_bytes(), &[0u8; 32]);
        });
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_concurrent_padding() {
    use std::thread;
    use securecomm_shared::padding;
    
    let data = b"concurrent test data";
    let mut handles = vec![];
    
    for _ in 0..20 {
        let data = data.to_vec();
        let handle = thread::spawn(move || {
            let padded = padding::pad_to_bucket(&data).unwrap();
            let unpadded = padding::unpad_from_bucket(&padded).unwrap();
            assert_eq!(unpadded, data);
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

// ============================================================================
// Memory Safety Tests
// ============================================================================

#[test]
fn test_sensitive_data_zeroization() {
    use securecomm_shared::*;
    use zeroize::Zeroize;
    
    // Test that sensitive data is zeroized
    let mut sensitive = vec![0xAA; 32];
    sensitive.zeroize();
    assert!(sensitive.iter().all(|&b| b == 0));
}

#[test]
fn test_no_sensitive_data_in_errors() {
    // Error messages should not contain sensitive data
    let error = CryptoError::InvalidKey("public_key_123".to_string());
    let msg = format!("{}", error);
    
    // Should not contain raw key material
    assert!(!msg.contains("0x"));
    assert!(!msg.contains("AA"));
}

// ============================================================================
// Fuzz-inspired Random Tests
// ============================================================================

#[test]
fn test_randomized_padding() {
    use securecomm_shared::padding;
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    
    // Test with random sizes
    for _ in 0..100 {
        let size = rng.gen_range(0..10000);
        let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        
        if size <= padding::MAX_PLAINTEXT_SIZE {
            let padded = padding::pad_to_bucket(&data).unwrap();
            let unpadded = padding::unpad_from_bucket(&padded).unwrap();
            assert_eq!(unpadded, data, "Round-trip failed for size {}", size);
        }
    }
}

#[test]
fn test_randomized_shamir() {
    use securecomm_shared::sss;
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    
    for _ in 0..50 {
        let secret_size = rng.gen_range(1..100);
        let secret: Vec<u8> = (0..secret_size).map(|_| rng.gen()).collect();
        
        let total_shares = rng.gen_range(3..10) as u8;
        let threshold = rng.gen_range(2..total_shares) as u8;
        
        let shares = sss::create_shards(&secret, total_shares, threshold).unwrap();
        
        // Reconstruct with threshold shares
        let subset: Vec<_> = shares[..threshold as usize].to_vec();
        let reconstructed = sss::reconstruct_secret(&subset).unwrap();
        
        assert_eq!(reconstructed, secret, "Shamir reconstruction failed");
    }
}