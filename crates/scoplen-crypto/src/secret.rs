// SPDX-License-Identifier: Apache-2.0
//! Zeroizing, redacting secret containers used by K-2 primitives.

use std::{fmt, ops::Deref};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A fixed-size secret byte string that is zeroized when dropped and redacted in `Debug` output.
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Construct a secret from an owned fixed-size byte array.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Construct a secret from a slice of exactly `N` bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?))
    }

    /// Borrow the secret bytes for a primitive operation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Clone for SecretBytes<N> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A variable-size secret byte string that is zeroized when dropped and redacted in `Debug` output.
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Construct a secret by taking ownership of a byte vector.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the secret bytes for a primitive operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the number of secret bytes without exposing their contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether this secret contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecretVec {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for SecretVec {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl Eq for SecretVec {}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Zeroize for SecretVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A 256-bit symmetric key.
pub type SymmetricKey = SecretBytes<32>;
/// A 192-bit `XChaCha20` nonce.
pub type XChaChaNonce = SecretBytes<24>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_secret_requires_exact_length_and_redacts_debug() {
        assert!(SecretBytes::<32>::from_slice(&[0; 31]).is_none());
        let secret = SecretBytes::<4>::new([1, 2, 3, 4]);
        assert_eq!(secret.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert!(!format!("{secret:?}").contains('1'));
    }

    #[test]
    fn variable_secret_reports_length_and_redacts_debug() {
        let secret = SecretVec::new(vec![1, 2, 3]);
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn secret_equality_uses_value_and_length() {
        assert_eq!(SecretVec::new(vec![1, 2]), SecretVec::new(vec![1, 2]));
        assert_ne!(SecretVec::new(vec![1, 2]), SecretVec::new(vec![1, 3]));
        assert_ne!(SecretVec::new(vec![1, 2]), SecretVec::new(vec![1, 2, 3]));
    }
}
