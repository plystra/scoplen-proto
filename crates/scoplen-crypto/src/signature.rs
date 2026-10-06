// SPDX-License-Identifier: Apache-2.0
//! Device and account signature wrappers from K-2.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as DalekSigningKey, Verifier as _,
    VerifyingKey as DalekVerifyingKey,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256DalekSigningKey, VerifyingKey as P256VerifyingKey,
};

use crate::{PrimitiveError, SecretBytes, random_bytes};

/// A P-256 device signing key held in a redacted, zeroizing container.
pub struct P256SigningKey {
    secret: SecretBytes<32>,
}

impl P256SigningKey {
    /// Parse a SEC1 private scalar from exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let secret = SecretBytes::from_slice(bytes).ok_or(PrimitiveError::InvalidKey)?;
        P256DalekSigningKey::from_bytes(p256::FieldBytes::from_slice(secret.as_ref()))
            .map_err(|_| PrimitiveError::InvalidKey)?;
        Ok(Self { secret })
    }

    /// Return the uncompressed SEC1 public key.
    #[must_use]
    pub fn public_key_sec1(&self) -> Vec<u8> {
        let signing_key = self.to_signing_key();
        signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    /// Sign a message with ECDSA P-256 and SHA-256, returning fixed-width `r || s` bytes.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: P256Signature = self.to_signing_key().sign(message);
        signature.to_bytes().into()
    }

    fn to_signing_key(&self) -> P256DalekSigningKey {
        P256DalekSigningKey::from_bytes(p256::FieldBytes::from_slice(self.secret.as_ref()))
            .expect("P-256 key validated at construction")
    }
}

impl fmt::Debug for P256SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("P256SigningKey([REDACTED])")
    }
}

/// Generate a valid random P-256 device signing key.
pub fn generate_p256_signing_key() -> Result<P256SigningKey, PrimitiveError> {
    loop {
        let mut bytes = [0; 32];
        random_bytes(&mut bytes)?;
        if let Ok(key) = P256SigningKey::from_bytes(&bytes) {
            return Ok(key);
        }
    }
}

/// Verify a fixed-width ECDSA P-256 `r || s` signature against an uncompressed SEC1 key.
pub fn p256_verify(
    public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PrimitiveError> {
    let public_key = P256VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| PrimitiveError::InvalidKey)?;
    let signature =
        P256Signature::from_slice(signature).map_err(|_| PrimitiveError::InvalidSignature)?;
    public_key.verify(message, &signature).map_err(|_| PrimitiveError::InvalidSignature)
}

/// An Ed25519 account signing key held in a redacted, zeroizing container.
pub struct Ed25519SigningKey {
    secret: SecretBytes<32>,
}

impl Ed25519SigningKey {
    /// Parse an Ed25519 seed from exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let secret = SecretBytes::from_slice(bytes).ok_or(PrimitiveError::InvalidKey)?;
        Ok(Self { secret })
    }

    /// Return the 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.to_signing_key().verifying_key().to_bytes()
    }

    /// Sign a message with Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.to_signing_key().sign(message).to_bytes()
    }

    fn to_signing_key(&self) -> DalekSigningKey {
        DalekSigningKey::from_bytes(self.secret.as_bytes())
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519SigningKey([REDACTED])")
    }
}

/// Generate a random Ed25519 account signing key.
pub fn generate_ed25519_signing_key() -> Result<Ed25519SigningKey, PrimitiveError> {
    let mut bytes = [0; 32];
    random_bytes(&mut bytes)?;
    Ed25519SigningKey::from_bytes(&bytes)
}

/// Verify an Ed25519 signature against a 32-byte public key.
pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PrimitiveError> {
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| PrimitiveError::InvalidKey)?;
    let public_key =
        DalekVerifyingKey::from_bytes(&public_key).map_err(|_| PrimitiveError::InvalidKey)?;
    let signature =
        Ed25519Signature::from_slice(signature).map_err(|_| PrimitiveError::InvalidSignature)?;
    public_key.verify(message, &signature).map_err(|_| PrimitiveError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_signatures_use_fixed_width_bytes_and_verify() {
        let key = P256SigningKey::from_bytes(&[1; 32]).expect("valid P-256 scalar");
        let signature = key.sign(b"message");
        assert_eq!(signature.len(), 64);
        p256_verify(&key.public_key_sec1(), b"message", &signature).expect("verify");
        assert_eq!(
            p256_verify(&key.public_key_sec1(), b"tampered", &signature),
            Err(PrimitiveError::InvalidSignature)
        );
        assert_eq!(format!("{key:?}"), "P256SigningKey([REDACTED])");
    }

    #[test]
    fn ed25519_signatures_verify_and_reject_bad_lengths() {
        let key = Ed25519SigningKey::from_bytes(&[2; 32]).expect("valid seed");
        let signature = key.sign(b"message");
        ed25519_verify(&key.public_key(), b"message", &signature).expect("verify");
        assert_eq!(
            ed25519_verify(&key.public_key(), b"tampered", &signature),
            Err(PrimitiveError::InvalidSignature)
        );
        assert_eq!(
            ed25519_verify(&[0; 31], b"message", &signature),
            Err(PrimitiveError::InvalidKey)
        );
        assert_eq!(format!("{key:?}"), "Ed25519SigningKey([REDACTED])");
    }
}
