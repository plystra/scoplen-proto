// SPDX-License-Identifier: Apache-2.0
//! Shamir secret sharing over GF(2^8), one polynomial per secret byte.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use crate::{PrimitiveError, SecretVec, random_bytes};

/// One serialized Shamir share. The threshold and x-coordinate are authenticated by the format.
#[derive(Clone, PartialEq, Eq)]
pub struct ShamirShare {
    /// Reconstruction threshold encoded in the share.
    pub threshold: u8,
    /// Nonzero GF(256) x-coordinate.
    pub index: u8,
    data: SecretVec,
}

impl ShamirShare {
    /// Return the share payload without exposing it in `Debug` output.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.as_bytes()
    }

    /// Encode as `threshold || index || share-bytes`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.data.len());
        bytes.push(self.threshold);
        bytes.push(self.index);
        bytes.extend_from_slice(self.data());
        bytes
    }

    /// Parse one serialized share.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() < 3 || bytes[0] == 0 || bytes[1] == 0 {
            return Err(PrimitiveError::InvalidEncoding);
        }
        Ok(Self { threshold: bytes[0], index: bytes[1], data: SecretVec::new(bytes[2..].to_vec()) })
    }
}

impl fmt::Debug for ShamirShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShamirShare")
            .field("threshold", &self.threshold)
            .field("index", &self.index)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Split a secret into random Shamir shares.
pub fn split_shamir(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
) -> Result<Vec<ShamirShare>, PrimitiveError> {
    if secret.is_empty() {
        return Err(PrimitiveError::InvalidKey);
    }
    let coefficient_len = usize::from(threshold.saturating_sub(1))
        .checked_mul(secret.len())
        .ok_or(PrimitiveError::InvalidKey)?;
    let mut randomness = vec![0; coefficient_len];
    random_bytes(&mut randomness)?;
    split_shamir_with_randomness(secret, threshold, share_count, &randomness)
}

/// Split a secret using caller-supplied coefficient bytes for deterministic vectors and tests.
pub fn split_shamir_with_randomness(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
    randomness: &[u8],
) -> Result<Vec<ShamirShare>, PrimitiveError> {
    validate_parameters(secret, threshold, share_count)?;
    let required =
        usize::from(threshold - 1).checked_mul(secret.len()).ok_or(PrimitiveError::InvalidKey)?;
    if randomness.len() != required {
        return Err(PrimitiveError::InvalidEncoding);
    }
    let mut shares = Vec::with_capacity(usize::from(share_count));
    for index in 1..=share_count {
        let x = index;
        let mut data = Vec::with_capacity(secret.len());
        for (byte_index, secret_byte) in secret.iter().enumerate() {
            let mut value = *secret_byte;
            let mut power = x;
            for degree in 1..threshold {
                let coefficient = randomness[(usize::from(degree) - 1) * secret.len() + byte_index];
                value ^= gf_mul(coefficient, power);
                power = gf_mul(power, x);
            }
            data.push(value);
        }
        shares.push(ShamirShare { threshold, index, data: SecretVec::new(data) });
    }
    Ok(shares)
}

/// Reconstruct a secret from at least the encoded threshold number of shares.
pub fn combine_shamir(shares: &[ShamirShare]) -> Result<SecretVec, PrimitiveError> {
    let Some(first) = shares.first() else {
        return Err(PrimitiveError::InvalidEncoding);
    };
    if shares.len() < usize::from(first.threshold)
        || first.threshold == 0
        || shares.iter().any(|share| {
            share.threshold != first.threshold
                || share.index == 0
                || share.data.len() != first.data.len()
        })
    {
        return Err(PrimitiveError::InvalidEncoding);
    }
    for (position, left) in shares.iter().enumerate() {
        if shares[position + 1..].iter().any(|right| right.index == left.index) {
            return Err(PrimitiveError::InvalidEncoding);
        }
    }

    let mut secret = vec![0; first.data.len()];
    for (byte_index, output) in secret.iter_mut().enumerate() {
        let mut value = 0;
        for (i, share) in shares.iter().enumerate() {
            let mut basis = 1;
            for (j, other) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let denominator = other.index ^ share.index;
                if denominator == 0 {
                    return Err(PrimitiveError::InvalidEncoding);
                }
                basis = gf_mul(basis, gf_mul(other.index, gf_inv(denominator)));
            }
            value ^= gf_mul(share.data()[byte_index], basis);
        }
        *output = value;
    }
    Ok(SecretVec::new(secret))
}

fn validate_parameters(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
) -> Result<(), PrimitiveError> {
    if secret.is_empty()
        || share_count == 0
        || threshold == 0
        || threshold > share_count
        || (share_count > 1 && threshold < 2)
    {
        return Err(PrimitiveError::InvalidKey);
    }
    Ok(())
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    result
}

fn gf_inv(value: u8) -> u8 {
    debug_assert_ne!(value, 0);
    let mut result = 1;
    for _ in 0..254 {
        result = gf_mul(result, value);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_requires_threshold_and_reconstructs_with_any_subset() {
        let secret = b"account-root-key";
        let shares = split_shamir_with_randomness(secret, 2, 3, &[7; 16]).expect("split");
        assert_eq!(combine_shamir(&shares[..2]).expect("combine").as_bytes(), secret);
        assert_eq!(
            combine_shamir(&[shares[0].clone(), shares[2].clone()]).expect("combine").as_bytes(),
            secret
        );
        assert!(combine_shamir(&shares[..1]).is_err());
    }

    #[test]
    fn shamir_rejects_duplicate_and_malformed_shares() {
        let shares = split_shamir_with_randomness(&[1, 2, 3], 2, 2, &[4, 5, 6]).expect("split");
        assert!(combine_shamir(&[shares[0].clone(), shares[0].clone()]).is_err());
        assert!(ShamirShare::from_bytes(&[2, 1]).is_err());
        assert!(split_shamir_with_randomness(&[1], 2, 2, &[]).is_err());
        assert!(split_shamir_with_randomness(&[1], 1, 2, &[0]).is_err());
    }

    #[test]
    fn shamir_serialization_redacts_secret_data() {
        let share =
            split_shamir_with_randomness(&[9, 8, 7], 2, 2, &[1, 2, 3]).expect("split")[0].clone();
        assert_eq!(ShamirShare::from_bytes(&share.to_bytes()).expect("decode"), share);
        assert!(!format!("{share:?}").contains('9'));
    }
}
