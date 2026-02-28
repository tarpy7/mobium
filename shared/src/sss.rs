//! Shamir's Secret Sharing (SSS) for social recovery
//!
//! Implements threshold secret sharing where a secret can be split
use crate::error::{CryptoError, Result};
/// into n shares and reconstructed from any t shares.
use rand::RngCore;
// zeroize used by downstream consumers
#[allow(unused_imports)]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A share of the secret
#[derive(Debug, Clone)]
pub struct Share {
    /// Share index (x coordinate)
    pub index: u8,
    /// Share value (y coordinate)
    pub value: Vec<u8>,
}

/// Split a secret into n shares, requiring t to reconstruct
///
/// Uses Shamir's Secret Sharing over GF(256) for byte arrays.
/// This is a simplified implementation suitable for the shared crypto crate.
pub fn create_shards(secret: &[u8], total_shares: u8, threshold: u8) -> Result<Vec<Share>> {
    if threshold < 2 {
        return Err(CryptoError::SecretSharingError(
            "Threshold must be at least 2".to_string(),
        ));
    }
    if threshold > total_shares {
        return Err(CryptoError::SecretSharingError(
            "Threshold cannot exceed total shares".to_string(),
        ));
    }
    if total_shares == 0 {
        return Err(CryptoError::SecretSharingError(
            "Must have at least 1 share".to_string(),
        ));
    }

    let mut shares: Vec<Vec<u8>> = vec![Vec::with_capacity(secret.len()); total_shares as usize];
    let mut indices: Vec<u8> = Vec::with_capacity(total_shares as usize);

    // Generate unique indices for shares (x coordinates)
    for i in 1..=total_shares {
        indices.push(i as u8);
        shares[i as usize - 1].resize(secret.len(), 0);
    }

    // For each byte position
    for byte_idx in 0..secret.len() {
        let secret_byte = secret[byte_idx];

        // Generate random coefficients for polynomial
        let mut coefficients: Vec<u8> = vec![0; threshold as usize];
        coefficients[0] = secret_byte; // Secret is the constant term

        let mut rng = rand::rngs::OsRng;
        for i in 1..threshold as usize {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            coefficients[i] = byte[0];
        }

        // Evaluate polynomial at each share index
        for (share_idx, x) in indices.iter().enumerate() {
            let y = evaluate_polynomial(&coefficients, *x);
            shares[share_idx][byte_idx] = y;
        }
    }

    // Create Share structs
    let result: Vec<Share> = indices
        .into_iter()
        .zip(shares.into_iter())
        .map(|(index, value)| Share { index, value })
        .collect();

    Ok(result)
}

/// Reconstruct a secret from shares
///
/// Requires at least threshold shares for reconstruction.
/// Uses Lagrange interpolation over GF(256).
pub fn reconstruct_secret(shares: &[Share]) -> Result<Vec<u8>> {
    if shares.len() < 2 {
        return Err(CryptoError::SecretSharingError(
            "At least 2 shares required".to_string(),
        ));
    }

    // Check all shares have same length
    let len = shares[0].value.len();
    for share in shares {
        if share.value.len() != len {
            return Err(CryptoError::SecretSharingError(
                "All shares must have same length".to_string(),
            ));
        }
    }

    let mut secret = vec![0u8; len];

    // For each byte position
    for byte_idx in 0..len {
        // Collect (x, y) points
        let points: Vec<(u8, u8)> = shares
            .iter()
            .map(|s| (s.index, s.value[byte_idx]))
            .collect();

        // Lagrange interpolation at x=0
        secret[byte_idx] = lagrange_interpolate(&points, 0)?;
    }

    Ok(secret)
}

/// Evaluate a polynomial at point x (GF(256))
fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    let mut x_power = 1u8;

    for coeff in coefficients {
        result ^= gf256_mul(*coeff, x_power);
        x_power = gf256_mul(x_power, x);
    }

    result
}

/// Lagrange interpolation at x=0 (GF(256))
fn lagrange_interpolate(points: &[(u8, u8)], at: u8) -> Result<u8> {
    let mut result = 0u8;

    for i in 0..points.len() {
        let (xi, yi) = points[i];

        // Calculate Lagrange basis polynomial li(at)
        let mut li = 1u8;
        for j in 0..points.len() {
            if i != j {
                let (xj, _) = points[j];
                if xi == xj {
                    return Err(CryptoError::SecretSharingError(
                        "Duplicate share indices".to_string(),
                    ));
                }
                // li(at) *= (at - xj) / (xi - xj)
                let numerator = gf256_sub(at, xj);
                let denominator = gf256_sub(xi, xj);
                li = gf256_mul(li, gf256_div(numerator, denominator)?);
            }
        }

        result ^= gf256_mul(yi, li);
    }

    Ok(result)
}

/// GF(256) addition/subtraction (XOR)
fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) multiplication using Rijndael's finite field
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }

        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b; // Rijndael's irreducible polynomial
        }

        b >>= 1;
    }

    result
}

/// GF(256) division: a / b = a * b^-1
fn gf256_div(a: u8, b: u8) -> Result<u8> {
    if b == 0 {
        return Err(CryptoError::SecretSharingError(
            "Division by zero".to_string(),
        ));
    }

    let b_inv = gf256_inv(b);
    Ok(gf256_mul(a, b_inv))
}

/// GF(256) multiplicative inverse using Extended Euclidean Algorithm
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }

    // Brute force: find b such that a * b = 1
    for b in 1..=255 {
        if gf256_mul(a, b) == 1 {
            return b;
        }
    }

    0 // Should never reach here for non-zero a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_reconstruct() {
        let secret = b"My secret master key for recovery";
        let shares = create_shards(secret, 5, 3).unwrap();

        assert_eq!(shares.len(), 5);

        // Reconstruct with exactly threshold
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let reconstructed = reconstruct_secret(&subset).unwrap();
        assert_eq!(secret.to_vec(), reconstructed);

        // Reconstruct with more than threshold
        let more_shares = vec![
            shares[0].clone(),
            shares[1].clone(),
            shares[2].clone(),
            shares[3].clone(),
        ];
        let reconstructed2 = reconstruct_secret(&more_shares).unwrap();
        assert_eq!(secret.to_vec(), reconstructed2);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Test secret";
        let shares = create_shards(secret, 5, 3).unwrap();

        // Try to reconstruct with fewer than threshold
        let subset = vec![shares[0].clone(), shares[1].clone()];
        let reconstructed = reconstruct_secret(&subset).unwrap();

        // Should not match original
        assert_ne!(secret.to_vec(), reconstructed);
    }

    #[test]
    fn test_gf256_math() {
        // Test multiplication
        assert_eq!(gf256_mul(0x57, 0x13), 0xFE);

        // Test inverse
        let inv_3 = gf256_inv(3);
        assert_eq!(gf256_mul(3, inv_3), 1);

        // Test division
        assert_eq!(gf256_div(6, 3).unwrap(), 2);
    }
}
