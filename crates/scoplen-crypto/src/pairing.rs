// SPDX-License-Identifier: Apache-2.0
//! QR pairing payload and relay-key binding for K-3.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use scoplen_model::validate_uuid_v7;

const QR_PREFIX: &str = "splpair1:";
const QR_LENGTH: usize = QR_PREFIX.len() + 36 + 1 + 64;

/// Errors from a QR pairing payload or relayed public-key verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PairingQrError {
    /// The payload is not the canonical version-1 representation.
    #[error("invalid QR pairing payload")]
    InvalidPayload,
    /// A relayed P-256 key is malformed.
    #[error("invalid device public key")]
    InvalidPublicKey,
    /// The relayed keys differ from those displayed by the new device.
    #[error("relayed device keys do not match the QR pairing payload")]
    KeyMismatch,
}

/// One-time pairing identifier and the digest of the new device's public keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingQrPayload {
    pairing_id: Uuid,
    public_key_hash: [u8; 32],
}

impl PairingQrPayload {
    /// Bind the pairing identifier to a new device's P-256 KEM and signing keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is not `UUIDv7` or either key is not an uncompressed
    /// SEC1 P-256 public key.
    pub fn new(
        pairing_id: Uuid,
        kem_public_key: &[u8],
        signing_public_key: &[u8],
    ) -> Result<Self, PairingQrError> {
        validate_uuid_v7(pairing_id).map_err(|_| PairingQrError::InvalidPayload)?;
        let public_key_hash = hash_public_keys(kem_public_key, signing_public_key)?;
        Ok(Self { pairing_id, public_key_hash })
    }

    /// Parse the exact version-1 text displayed as a QR code.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, non-UUIDv7 identifiers, noncanonical spelling, and malformed
    /// lowercase hexadecimal hashes.
    pub fn decode(value: &str) -> Result<Self, PairingQrError> {
        if value.len() != QR_LENGTH {
            return Err(PairingQrError::InvalidPayload);
        }
        let remainder = value.strip_prefix(QR_PREFIX).ok_or(PairingQrError::InvalidPayload)?;
        let (id_text, hash_text) =
            remainder.split_once(':').ok_or(PairingQrError::InvalidPayload)?;
        let pairing_id = Uuid::parse_str(id_text).map_err(|_| PairingQrError::InvalidPayload)?;
        if id_text != pairing_id.to_string() || validate_uuid_v7(pairing_id).is_err() {
            return Err(PairingQrError::InvalidPayload);
        }
        let mut public_key_hash = [0; 32];
        for (byte, pair) in public_key_hash.iter_mut().zip(hash_text.as_bytes().chunks_exact(2)) {
            if !pair.iter().all(|digit| digit.is_ascii_digit() || (b'a'..=b'f').contains(digit)) {
                return Err(PairingQrError::InvalidPayload);
            }
            *byte = u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| PairingQrError::InvalidPayload)?,
                16,
            )
            .map_err(|_| PairingQrError::InvalidPayload)?;
        }
        Ok(Self { pairing_id, public_key_hash })
    }

    /// Format the canonical version-1 QR text.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut value = format!("{QR_PREFIX}{}:", self.pairing_id);
        for byte in self.public_key_hash {
            use std::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
        }
        value
    }

    /// Return the one-time pairing identifier to look up through the relay.
    #[must_use]
    pub fn pairing_id(&self) -> Uuid {
        self.pairing_id
    }

    /// Verify keys relayed by the server against the displayed QR payload.
    ///
    /// # Errors
    ///
    /// Returns [`PairingQrError::InvalidPublicKey`] for malformed keys, or
    /// [`PairingQrError::KeyMismatch`] if valid keys have a different digest.
    pub fn verify_public_keys(
        &self,
        kem_public_key: &[u8],
        signing_public_key: &[u8],
    ) -> Result<(), PairingQrError> {
        let relayed_hash = hash_public_keys(kem_public_key, signing_public_key)?;
        if bool::from(self.public_key_hash.ct_eq(&relayed_hash)) {
            Ok(())
        } else {
            Err(PairingQrError::KeyMismatch)
        }
    }
}

fn hash_public_keys(
    kem_public_key: &[u8],
    signing_public_key: &[u8],
) -> Result<[u8; 32], PairingQrError> {
    for key in [kem_public_key, signing_public_key] {
        if key.len() != 65 || key.first() != Some(&4) {
            return Err(PairingQrError::InvalidPublicKey);
        }
        p256::PublicKey::from_sec1_bytes(key).map_err(|_| PairingQrError::InvalidPublicKey)?;
    }
    let mut hasher = Sha256::new();
    hasher.update(kem_public_key);
    hasher.update(signing_public_key);
    Ok(hasher.finalize().into())
}
