// SPDX-License-Identifier: Apache-2.0
//! K-2 symmetric primitives and operating-system randomness.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

use crate::secret::{SecretBytes, SymmetricKey, XChaChaNonce};

/// Argon2id memory cost required by K-2, in KiB.
pub const ARGON2_MEMORY_KIB: u32 = 256 * 1024;
/// Argon2id iteration count required by K-2.
pub const ARGON2_TIME_COST: u32 = 3;
/// Argon2id parallelism required by K-2.
pub const ARGON2_PARALLELISM: u32 = 4;

/// Errors returned by the K-2 primitive wrappers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrimitiveError {
    /// The operating system did not provide random bytes.
    #[error("operating-system randomness failed: {0}")]
    Randomness(String),
    /// The requested HKDF output is longer than RFC 5869 permits.
    #[error("HKDF output is too long")]
    HkdfLength,
    /// Authentication failed while opening an encrypted value.
    #[error("XChaCha20-Poly1305 authentication failed")]
    Authentication,
    /// Argon2id parameters or execution failed.
    #[error("Argon2id derivation failed: {0}")]
    Argon2(String),
}

/// Fill a caller-provided buffer with operating-system CSPRNG output.
///
/// # Errors
///
/// Returns [`PrimitiveError::Randomness`] when the operating system cannot provide bytes.
pub fn random_bytes(bytes: &mut [u8]) -> Result<(), PrimitiveError> {
    getrandom::fill(bytes).map_err(|error| PrimitiveError::Randomness(error.to_string()))
}

/// Generate a random 256-bit symmetric key.
///
/// # Errors
///
/// Returns [`PrimitiveError::Randomness`] when the operating system cannot provide bytes.
pub fn random_key() -> Result<SymmetricKey, PrimitiveError> {
    let mut bytes = [0; 32];
    random_bytes(&mut bytes)?;
    Ok(SecretBytes::new(bytes))
}

/// Generate a random 24-byte `XChaCha20` nonce.
///
/// # Errors
///
/// Returns [`PrimitiveError::Randomness`] when the operating system cannot provide bytes.
pub fn random_nonce() -> Result<XChaChaNonce, PrimitiveError> {
    let mut bytes = [0; 24];
    random_bytes(&mut bytes)?;
    Ok(SecretBytes::new(bytes))
}

/// Derive `output_len` bytes with HKDF-SHA-256.
///
/// # Errors
///
/// Returns [`PrimitiveError::HkdfLength`] when `output_len` exceeds the RFC 5869 limit.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, PrimitiveError> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = vec![0; output_len];
    hkdf.expand(info, &mut output).map_err(|_| PrimitiveError::HkdfLength)?;
    Ok(output)
}

/// Derive a 256-bit key with the K-2 Argon2id parameters.
///
/// # Errors
///
/// Returns [`PrimitiveError::Argon2`] when the fixed parameters are invalid or derivation fails.
pub fn argon2id_derive(passphrase: &[u8], salt: &[u8; 16]) -> Result<SymmetricKey, PrimitiveError> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
        .map_err(|error| PrimitiveError::Argon2(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|error| PrimitiveError::Argon2(error.to_string()))?;
    Ok(SecretBytes::new(output))
}

/// Encrypt plaintext with XChaCha20-Poly1305 using the supplied associated data.
///
/// # Errors
///
/// Returns [`PrimitiveError::Authentication`] if the cipher cannot be initialized or encryption
/// fails.
pub fn xchacha20poly1305_seal(
    key: &SymmetricKey,
    nonce: &XChaChaNonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PrimitiveError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| PrimitiveError::Authentication)?;
    let mut ciphertext = plaintext.to_vec();
    cipher
        .encrypt_in_place(XNonce::from_slice(nonce.as_ref()), aad, &mut ciphertext)
        .map_err(|_| PrimitiveError::Authentication)?;
    Ok(ciphertext)
}

/// Authenticate and decrypt XChaCha20-Poly1305 ciphertext.
///
/// # Errors
///
/// Returns [`PrimitiveError::Authentication`] when the ciphertext, key, nonce, or associated data
/// does not authenticate.
pub fn xchacha20poly1305_open(
    key: &SymmetricKey,
    nonce: &XChaChaNonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PrimitiveError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| PrimitiveError::Authentication)?;
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place(XNonce::from_slice(nonce.as_ref()), aad, &mut plaintext)
        .map_err(|_| PrimitiveError::Authentication)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xchacha_round_trip_authenticates_aad() {
        let key = SecretBytes::new([7; 32]);
        let nonce = SecretBytes::new([9; 24]);
        let ciphertext =
            xchacha20poly1305_seal(&key, &nonce, b"plaintext", b"context").expect("seal");
        assert_eq!(
            xchacha20poly1305_open(&key, &nonce, &ciphertext, b"context").expect("open"),
            b"plaintext"
        );
        assert_eq!(
            xchacha20poly1305_open(&key, &nonce, &ciphertext, b"wrong"),
            Err(PrimitiveError::Authentication)
        );
        assert_eq!(
            xchacha20poly1305_open(&key, &nonce, &ciphertext[..ciphertext.len() - 1], b"context"),
            Err(PrimitiveError::Authentication)
        );
    }

    #[test]
    fn hkdf_matches_rfc5869_sha256_case_one() {
        let ikm = [0x0b; 22];
        let salt = (0x00..=0x0c).collect::<Vec<_>>();
        let info = (0xf0..=0xf9).collect::<Vec<_>>();
        let output = hkdf_sha256(&ikm, Some(&salt), &info, 42).expect("HKDF");
        assert_eq!(
            output,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    #[test]
    fn argon2id_is_deterministic_for_a_salt() {
        let first = argon2id_derive(b"correct horse battery staple", &[3; 16]).expect("derive");
        let second = argon2id_derive(b"correct horse battery staple", &[3; 16]).expect("derive");
        assert_eq!(first, second);
        assert_ne!(first, argon2id_derive(b"different", &[3; 16]).expect("derive"));
    }
}
