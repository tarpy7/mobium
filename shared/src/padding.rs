//! Size masking via bucketing for traffic analysis resistance
//!
//! Implements IND-CPA secure padding to hide exact message sizes from the server.
//! Messages are padded to one of 14 exponential buckets (512B to 4MB).
//!
//! Security: Reduces size information leakage from ~20 bits to 4 bits.
//! The server can only determine which of 14 buckets a message belongs to,
//! not the exact plaintext size.

use crate::error::{CryptoError, Result};
use rand::RngCore;

/// Size buckets for message padding (exponential growth)
/// Total: 14 buckets from 512B to 4MB
pub const SIZE_BUCKETS: [usize; 14] = [
    512,     // Bucket 0: 512 bytes
    1024,    // Bucket 1: 1 KB
    2048,    // Bucket 2: 2 KB
    4096,    // Bucket 3: 4 KB
    8192,    // Bucket 4: 8 KB
    16384,   // Bucket 5: 16 KB
    32768,   // Bucket 6: 32 KB
    65536,   // Bucket 7: 64 KB
    131072,  // Bucket 8: 128 KB
    262144,  // Bucket 9: 256 KB
    524288,  // Bucket 10: 512 KB
    1048576, // Bucket 11: 1 MB
    2097152, // Bucket 12: 2 MB
    4194304, // Bucket 13: 4 MB
];

/// AES-256-GCM authentication tag size
pub const GCM_TAG_SIZE: usize = 16;

/// Header overhead: 4 bytes length prefix + 4 bytes reserved
pub const HEADER_SIZE: usize = 8;

/// Total overhead inside a bucket: header + GCM tag (reserved space so encrypted output = bucket size)
pub const TOTAL_OVERHEAD: usize = HEADER_SIZE + GCM_TAG_SIZE;

/// Maximum plaintext size that can be padded (largest bucket - all overhead)
pub const MAX_PLAINTEXT_SIZE: usize = SIZE_BUCKETS[SIZE_BUCKETS.len() - 1] - TOTAL_OVERHEAD;

/// Get the bucket size for a given plaintext size
///
/// Returns the smallest bucket that can contain the plaintext
/// with the required overhead (8 bytes header + 16 bytes GCM tag)
pub fn get_bucket_size(plaintext_len: usize) -> Result<usize> {
    let required_size = plaintext_len + TOTAL_OVERHEAD;

    for &bucket in &SIZE_BUCKETS {
        if bucket >= required_size {
            return Ok(bucket);
        }
    }

    Err(CryptoError::EncryptionError(format!(
        "Plaintext too large: {} bytes (max: {})",
        plaintext_len, MAX_PLAINTEXT_SIZE
    )))
}

/// Get the bucket index for a given plaintext size
///
/// Returns index 0-13 corresponding to SIZE_BUCKETS
pub fn get_bucket_index(plaintext_len: usize) -> Result<usize> {
    let required_size = plaintext_len + TOTAL_OVERHEAD;

    for (index, &bucket) in SIZE_BUCKETS.iter().enumerate() {
        if bucket >= required_size {
            return Ok(index);
        }
    }

    Err(CryptoError::EncryptionError(format!(
        "Plaintext too large: {} bytes",
        plaintext_len
    )))
}

/// Pad plaintext to the appropriate bucket size
///
/// Format: [4 bytes: u32_be(original_length)] [N bytes: plaintext] [X bytes: random_padding]
/// Total size = exactly the target bucket size
///
/// # Arguments
/// * `plaintext` - The original message to pad
///
/// # Returns
/// * Padded message of exactly bucket size
///
/// # Security
/// - Uses cryptographically secure random padding from OS CSPRNG
/// - Constant-time operations (no branches on plaintext content)
/// - Padding is indistinguishable from encrypted data
pub fn pad_to_bucket(plaintext: &[u8]) -> Result<Vec<u8>> {
    let plaintext_len = plaintext.len();

    // Check size limits
    if plaintext_len > MAX_PLAINTEXT_SIZE {
        return Err(CryptoError::EncryptionError(format!(
            "Plaintext too large: {} bytes (max: {})",
            plaintext_len, MAX_PLAINTEXT_SIZE
        )));
    }

    // Determine target bucket size
    let target_size = get_bucket_size(plaintext_len)?;

    // The padded output is bucket_size - GCM_TAG_SIZE bytes.
    // After AES-GCM encryption adds the 16-byte auth tag,
    // the final ciphertext will be exactly bucket_size.
    let padded_size = target_size - GCM_TAG_SIZE;

    // Allocate padded buffer
    let mut padded = vec![0u8; padded_size];

    // Write original length as u32 big-endian (first 4 bytes)
    let len_bytes = (plaintext_len as u32).to_be_bytes();
    padded[0..4].copy_from_slice(&len_bytes);

    // Reserved bytes (4-7) - zero for now, could be used for flags
    padded[4..8].fill(0);

    // Copy plaintext (starting at byte 8)
    padded[8..8 + plaintext_len].copy_from_slice(plaintext);

    // Fill remaining bytes with random data from CSPRNG
    let padding_start = 8 + plaintext_len;
    let padding_len = padded_size - padding_start;

    if padding_len > 0 {
        rand::rngs::OsRng.fill_bytes(&mut padded[padding_start..]);
    }

    Ok(padded)
}

/// Remove padding and extract original plaintext
///
/// # Arguments
/// * `padded` - The padded message (must be exactly a bucket size)
///
/// # Returns
/// * Original plaintext
///
/// # Errors
/// * If padded length is not a valid bucket size
/// * If length field is corrupted or out of bounds
pub fn unpad_from_bucket(padded: &[u8]) -> Result<Vec<u8>> {
    let padded_len = padded.len();

    // After decryption, the padded data is bucket_size - GCM_TAG_SIZE bytes.
    // Verify this corresponds to a valid bucket.
    let is_valid = SIZE_BUCKETS.iter().any(|&b| b - GCM_TAG_SIZE == padded_len);
    if !is_valid {
        return Err(CryptoError::EncryptionError(format!(
            "Invalid padded message size: {} bytes (not a valid post-decryption size)",
            padded_len
        )));
    }

    // Read original length (first 4 bytes)
    if padded_len < HEADER_SIZE {
        return Err(CryptoError::EncryptionError(
            "Padded message too short".to_string(),
        ));
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&padded[0..4]);
    let original_len = u32::from_be_bytes(len_bytes) as usize;

    // Validate length
    if original_len > padded_len - HEADER_SIZE {
        return Err(CryptoError::EncryptionError(format!(
            "Invalid length field: {} (max: {})",
            original_len,
            padded_len - HEADER_SIZE
        )));
    }

    // Extract plaintext
    let plaintext = padded[HEADER_SIZE..HEADER_SIZE + original_len].to_vec();

    Ok(plaintext)
}

/// Get bucket size from bucket index (0-13)
pub fn bucket_size_from_index(index: usize) -> Option<usize> {
    SIZE_BUCKETS.get(index).copied()
}

/// Verify if a size is a valid bucket size (for encrypted ciphertexts)
pub fn is_valid_bucket_size(size: usize) -> bool {
    SIZE_BUCKETS.contains(&size)
}

/// Verify if a size is a valid padded (pre-encryption) size
pub fn is_valid_padded_size(size: usize) -> bool {
    SIZE_BUCKETS.iter().any(|&b| b - GCM_TAG_SIZE == size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_bucket_size() {
        // Small messages (overhead = 24: 8 header + 16 GCM tag)
        assert_eq!(get_bucket_size(100).unwrap(), 512);
        assert_eq!(get_bucket_size(488).unwrap(), 512); // 488 + 24 = 512
        assert_eq!(get_bucket_size(489).unwrap(), 1024); // 489 + 24 = 513 > 512

        // Larger messages
        assert_eq!(get_bucket_size(1000).unwrap(), 1024);
        assert_eq!(get_bucket_size(3000).unwrap(), 4096);
        assert_eq!(get_bucket_size(1000000).unwrap(), 1048576); // 1MB
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let test_cases = vec![
            vec![],              // Empty
            vec![0x01],          // 1 byte
            vec![0x01; 100],     // 100 bytes
            vec![0xAB; 400],     // 400 bytes
            vec![0xCD; 1000],    // 1000 bytes
            vec![0xEF; 10000],   // 10KB
            vec![0x12; 100000],  // 100KB
            vec![0x34; 1000000], // 1MB
        ];

        for plaintext in test_cases {
            let original_len = plaintext.len();

            // Pad (returns bucket_size - GCM_TAG_SIZE)
            let padded = pad_to_bucket(&plaintext).unwrap();

            // Verify padded size is bucket_size - GCM_TAG_SIZE
            let expected_bucket = get_bucket_size(original_len).unwrap();
            assert_eq!(
                padded.len(),
                expected_bucket - GCM_TAG_SIZE,
                "Padded size {} doesn't match expected {} for plaintext size {}",
                padded.len(),
                expected_bucket - GCM_TAG_SIZE,
                original_len
            );

            // Verify it's a valid padded size
            assert!(
                is_valid_padded_size(padded.len()),
                "Padded size {} is not a valid padded size",
                padded.len()
            );

            // Unpad
            let unpadded = unpad_from_bucket(&padded).unwrap();

            // Verify round-trip
            assert_eq!(
                unpadded, plaintext,
                "Round-trip failed for size {}",
                original_len
            );
        }
    }

    #[test]
    fn test_padding_randomness() {
        // Same plaintext should have different padding (random)
        let plaintext = vec![0x42; 100];

        let padded1 = pad_to_bucket(&plaintext).unwrap();
        let padded2 = pad_to_bucket(&plaintext).unwrap();

        // Both should be same bucket size
        assert_eq!(padded1.len(), padded2.len());

        // But padding bytes should differ
        let header1 = &padded1[0..108]; // 8 byte header + 100 bytes plaintext
        let header2 = &padded2[0..108];
        assert_eq!(header1, header2, "Headers should match");

        // Padding should differ with high probability
        let padding1 = &padded1[108..];
        let padding2 = &padded2[108..];
        assert_ne!(padding1, padding2, "Random padding should differ");
    }

    #[test]
    fn test_unpad_invalid_size() {
        // Invalid bucket size
        let invalid = vec![0u8; 100]; // Not a bucket size
        assert!(unpad_from_bucket(&invalid).is_err());

        // Too small
        let too_small = vec![0u8; 4];
        assert!(unpad_from_bucket(&too_small).is_err());
    }

    #[test]
    fn test_size_too_large() {
        let too_large = vec![0u8; MAX_PLAINTEXT_SIZE + 1];
        assert!(pad_to_bucket(&too_large).is_err());
    }

    #[test]
    fn test_bucket_constants() {
        // Verify buckets are strictly increasing
        for i in 1..SIZE_BUCKETS.len() {
            assert!(
                SIZE_BUCKETS[i] > SIZE_BUCKETS[i - 1],
                "Buckets must be strictly increasing"
            );
        }

        // Verify first and last
        assert_eq!(SIZE_BUCKETS[0], 512);
        assert_eq!(SIZE_BUCKETS[13], 4194304); // 4MB
    }
}
