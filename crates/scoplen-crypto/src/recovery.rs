// SPDX-License-Identifier: Apache-2.0
//! Recovery-key encoding, recovery wrapping, and account safety numbers.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    PrimitiveError, SecretBytes, SymmetricKey, XChaChaNonce, hkdf_sha256, random_bytes,
    random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
};

const RECOVERY_PREFIX: &str = "SPL1-";
const RECOVERY_INFO: &[u8] = b"spl-recovery-v1";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A 256-bit recovery key that is zeroized and redacted in memory.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKey(SecretBytes<32>);

impl RecoveryKey {
    /// Generate a recovery key from operating-system randomness.
    pub fn generate() -> Result<Self, PrimitiveError> {
        let mut bytes = [0; 32];
        random_bytes(&mut bytes)?;
        Ok(Self(SecretBytes::new(bytes)))
    }

    /// Construct a recovery key from exactly 32 raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        SecretBytes::from_slice(bytes).map(Self).ok_or(PrimitiveError::InvalidKey)
    }

    /// Borrow the raw recovery key bytes for wrapping.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Encode as the user-facing `SPL1-` Crockford Base32 form with checksum.
    #[must_use]
    pub fn encode_display(&self) -> String {
        let payload = encode_crockford(self.as_bytes());
        let checksum = checksum(&payload);
        let mut groups = Vec::with_capacity(14);
        for chunk in payload.as_bytes().chunks(4) {
            groups.push(chunk.iter().map(|byte| char::from(*byte)).collect());
        }
        groups.push(checksum);
        format!("{RECOVERY_PREFIX}{}", groups.join("-"))
    }

    /// Parse and verify a user-facing recovery key.
    pub fn parse_display(value: &str) -> Result<Self, PrimitiveError> {
        let value = value.trim().to_ascii_uppercase();
        let Some(body) = value.strip_prefix(RECOVERY_PREFIX) else {
            return Err(PrimitiveError::InvalidKey);
        };
        let groups: Vec<_> = body.split('-').collect();
        if groups.len() != 14 || groups[..13].iter().any(|group| group.len() != 4) {
            return Err(PrimitiveError::InvalidKey);
        }
        let payload = groups[..13].concat();
        if groups[13].len() != 4 || checksum(&payload) != groups[13] {
            return Err(PrimitiveError::InvalidKey);
        }
        let bytes = decode_crockford(&payload)?;
        Ok(Self(SecretBytes::new(bytes)))
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryKey([REDACTED])")
    }
}

impl AsRef<[u8]> for RecoveryKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A recovery-wrapped ARK blob: version, nonce, and authenticated ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBlob {
    /// XChaCha20-Poly1305 nonce.
    pub nonce: XChaChaNonce,
    /// Ciphertext and authentication tag.
    pub ciphertext: Vec<u8>,
}

impl RecoveryBlob {
    /// Wrap an ARK with a random nonce and account-bound associated data.
    pub fn wrap(
        recovery_key: &RecoveryKey,
        account_id: Uuid,
        ark: &SymmetricKey,
    ) -> Result<Self, PrimitiveError> {
        Self::wrap_with_nonce(recovery_key, account_id, ark, random_nonce()?)
    }

    /// Wrap an ARK with a supplied nonce, used by deterministic test vectors.
    pub fn wrap_with_nonce(
        recovery_key: &RecoveryKey,
        account_id: Uuid,
        ark: &SymmetricKey,
        nonce: XChaChaNonce,
    ) -> Result<Self, PrimitiveError> {
        let wrapping_key = recovery_wrapping_key(recovery_key, account_id)?;
        let ciphertext =
            xchacha20poly1305_seal(&wrapping_key, &nonce, ark.as_ref(), account_id.as_bytes())?;
        Ok(Self { nonce, ciphertext })
    }

    /// Open an ARK recovery blob and authenticate it to the account id.
    pub fn open(
        &self,
        recovery_key: &RecoveryKey,
        account_id: Uuid,
    ) -> Result<SymmetricKey, PrimitiveError> {
        let wrapping_key = recovery_wrapping_key(recovery_key, account_id)?;
        let plaintext = xchacha20poly1305_open(
            &wrapping_key,
            &self.nonce,
            &self.ciphertext,
            account_id.as_bytes(),
        )?;
        SecretBytes::from_slice(&plaintext).ok_or(PrimitiveError::InvalidKey)
    }

    /// Encode the blob as version 1 followed by nonce and ciphertext.
    pub fn encode(&self) -> Result<Vec<u8>, PrimitiveError> {
        let ciphertext_len =
            u32::try_from(self.ciphertext.len()).map_err(|_| PrimitiveError::InvalidEncoding)?;
        let mut output = Vec::with_capacity(1 + 24 + 4 + self.ciphertext.len());
        output.push(1);
        output.extend_from_slice(self.nonce.as_ref());
        output.extend_from_slice(&ciphertext_len.to_be_bytes());
        output.extend_from_slice(&self.ciphertext);
        Ok(output)
    }

    /// Decode a version-1 recovery blob.
    pub fn decode(input: &[u8]) -> Result<Self, PrimitiveError> {
        if input.len() < 1 + 24 + 4 || input[0] != 1 {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let nonce =
            XChaChaNonce::from_slice(&input[1..25]).ok_or(PrimitiveError::InvalidEncoding)?;
        let length_bytes: [u8; 4] =
            input[25..29].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| PrimitiveError::InvalidEncoding)?;
        if input.len() != 29 + length || length < 16 {
            return Err(PrimitiveError::InvalidEncoding);
        }
        Ok(Self { nonce, ciphertext: input[29..].to_vec() })
    }
}

fn recovery_wrapping_key(
    recovery_key: &RecoveryKey,
    account_id: Uuid,
) -> Result<SymmetricKey, PrimitiveError> {
    let bytes = hkdf_sha256(recovery_key.as_ref(), Some(account_id.as_bytes()), RECOVERY_INFO, 32)?;
    SecretBytes::from_slice(&bytes).ok_or(PrimitiveError::InvalidKey)
}

/// Derive a short, symmetric safety number from two Ed25519 account public keys.
#[must_use]
pub fn safety_number(left: &[u8; 32], right: &[u8; 32]) -> String {
    let (first, second) = if left <= right { (left, right) } else { (right, left) };
    let mut hasher = Sha256::new();
    hasher.update(b"spl-safety-v1");
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    let number = u64::from_be_bytes(prefix) % 1_000_000_000_000;
    format!("{number:012}")
}

fn encode_crockford(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(52);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(CROCKFORD[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(CROCKFORD[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn decode_crockford(value: &str) -> Result<[u8; 32], PrimitiveError> {
    if value.len() != 52 || value.bytes().any(|byte| !CROCKFORD.contains(&byte)) {
        return Err(PrimitiveError::InvalidKey);
    }
    let mut output = [0_u8; 32];
    let mut output_index = 0;
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let Some(digit) = CROCKFORD.iter().position(|candidate| *candidate == byte) else {
            return Err(PrimitiveError::InvalidKey);
        };
        let digit = u32::try_from(digit).map_err(|_| PrimitiveError::InvalidKey)?;
        buffer = (buffer << 5) | digit;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if output_index == output.len() {
                return Err(PrimitiveError::InvalidKey);
            }
            output[output_index] = ((buffer >> bits) & 0xff) as u8;
            output_index += 1;
        }
    }
    if output_index != output.len() || (buffer & ((1_u32 << bits) - 1)) != 0 {
        return Err(PrimitiveError::InvalidKey);
    }
    Ok(output)
}

fn checksum(payload: &str) -> String {
    let digest = Sha256::digest(payload.as_bytes());
    let mut prefix = [0_u8; 4];
    prefix.copy_from_slice(&digest[..4]);
    let value = u32::from_be_bytes(prefix) & 0x000f_ffff;
    let mut output = String::with_capacity(4);
    for shift in [15, 10, 5, 0] {
        output.push(CROCKFORD[((value >> shift) & 0x1f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_id() -> Uuid {
        Uuid::from_bytes([0x42, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
    }

    #[test]
    fn recovery_display_round_trips_and_rejects_checksum_errors() {
        let key = RecoveryKey::from_bytes(&[0; 32]).expect("key");
        let display = key.encode_display();
        assert!(display.starts_with("SPL1-"));
        assert_eq!(RecoveryKey::parse_display(&display).expect("parse"), key);
        let mut altered = display.clone().into_bytes();
        let last = altered.len() - 1;
        altered[last] = if altered[last] == b'0' { b'1' } else { b'0' };
        assert!(RecoveryKey::parse_display(std::str::from_utf8(&altered).expect("ASCII")).is_err());
    }

    #[test]
    fn recovery_wrap_binds_account_and_round_trips() {
        let recovery = RecoveryKey::from_bytes(&[1; 32]).expect("recovery");
        let ark = SecretBytes::new([2; 32]);
        let blob =
            RecoveryBlob::wrap_with_nonce(&recovery, account_id(), &ark, SecretBytes::new([3; 24]))
                .expect("wrap");
        let encoded = blob.encode().expect("encode");
        assert_eq!(
            RecoveryBlob::decode(&encoded)
                .expect("decode")
                .open(&recovery, account_id())
                .expect("open"),
            ark
        );
        assert_eq!(
            blob.open(&recovery, Uuid::from_bytes([9; 16])),
            Err(PrimitiveError::Authentication)
        );
    }

    #[test]
    fn safety_number_is_order_independent() {
        let left = [1; 32];
        let right = [2; 32];
        assert_eq!(safety_number(&left, &right), safety_number(&right, &left));
        assert_eq!(safety_number(&left, &right).len(), 12);
    }
}
