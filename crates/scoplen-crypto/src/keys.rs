// SPDX-License-Identifier: Apache-2.0
//! K-2 key hierarchy types and local key wrapping helpers.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use crate::{
    AccountKemKeyPair, Argon2idParams, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
    PrimitiveError, SecretBytes, SymmetricKey, XChaChaNonce, argon2id_derive_with_params,
    hpke_open_device, hpke_seal_device, random_bytes, random_key, random_nonce,
    xchacha20poly1305_open, xchacha20poly1305_seal,
};

const LOCAL_DB_ENVELOPE_VERSION: u8 = 1;
const LOCAL_DB_AAD: &[u8] = b"spl-local-db-key-v1";
const LOCAL_DB_CIPHERTEXT_LEN: usize = 32 + 16;
const LOCAL_DB_ENCODED_LEN: usize = 1 + 4 + 4 + 4 + 16 + 24 + LOCAL_DB_CIPHERTEXT_LEN;

/// The account root key (ARK), held only by enrolled devices and recovery mechanisms.
pub type AccountRootKey = SymmetricKey;
/// A symmetric vault key for one key epoch.
pub type VaultKey = SymmetricKey;
/// The local database key, held only on one device.
pub type LocalDatabaseKey = SymmetricKey;

/// A device-local Argon2id-wrapped database key.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalDatabaseKeyEnvelope {
    /// Cost parameters used to derive the wrapping key.
    pub params: Argon2idParams,
    /// Random Argon2id salt.
    pub salt: [u8; 16],
    /// XChaCha20-Poly1305 nonce.
    pub nonce: XChaChaNonce,
    /// Encrypted database key and authentication tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for LocalDatabaseKeyEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDatabaseKeyEnvelope")
            .field("params", &self.params)
            .field("salt", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

impl LocalDatabaseKeyEnvelope {
    /// Wrap a database key with the initial K-2 Argon2id parameters and random salt and nonce.
    pub fn wrap(
        passphrase: &[u8],
        database_key: &LocalDatabaseKey,
    ) -> Result<Self, PrimitiveError> {
        let mut salt = [0_u8; 16];
        random_bytes(&mut salt)?;
        Self::wrap_with_parameters_and_nonce(
            passphrase,
            database_key,
            Argon2idParams::default(),
            salt,
            random_nonce()?,
        )
    }

    /// Wrap a database key with caller-supplied values for deterministic vectors and tests.
    pub fn wrap_with_parameters_and_nonce(
        passphrase: &[u8],
        database_key: &LocalDatabaseKey,
        params: Argon2idParams,
        salt: [u8; 16],
        nonce: XChaChaNonce,
    ) -> Result<Self, PrimitiveError> {
        let wrapping_key = argon2id_derive_with_params(passphrase, &salt, params)?;
        let ciphertext = xchacha20poly1305_seal(
            &wrapping_key,
            &nonce,
            database_key.as_ref(),
            &local_db_aad(params, &salt),
        )?;
        Ok(Self { params, salt, nonce, ciphertext })
    }

    /// Open and authenticate the wrapped database key with the passphrase.
    pub fn open(&self, passphrase: &[u8]) -> Result<LocalDatabaseKey, PrimitiveError> {
        self.params.validate()?;
        if self.ciphertext.len() != LOCAL_DB_CIPHERTEXT_LEN {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let wrapping_key = argon2id_derive_with_params(passphrase, &self.salt, self.params)?;
        let plaintext = xchacha20poly1305_open(
            &wrapping_key,
            &self.nonce,
            &self.ciphertext,
            &local_db_aad(self.params, &self.salt),
        )?;
        SecretBytes::from_slice(&plaintext).ok_or(PrimitiveError::InvalidKey)
    }

    /// Encode the version-1 local wrapper into its fixed binary layout.
    pub fn encode(&self) -> Result<Vec<u8>, PrimitiveError> {
        self.params.validate()?;
        if self.ciphertext.len() != LOCAL_DB_CIPHERTEXT_LEN {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let mut output = Vec::with_capacity(LOCAL_DB_ENCODED_LEN);
        output.push(LOCAL_DB_ENVELOPE_VERSION);
        output.extend_from_slice(&self.params.memory_kib.to_be_bytes());
        output.extend_from_slice(&self.params.time_cost.to_be_bytes());
        output.extend_from_slice(&self.params.parallelism.to_be_bytes());
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(self.nonce.as_ref());
        output.extend_from_slice(&self.ciphertext);
        Ok(output)
    }

    /// Decode and validate the fixed version-1 local wrapper layout.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() != LOCAL_DB_ENCODED_LEN || bytes[0] != LOCAL_DB_ENVELOPE_VERSION {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let memory_kib = u32::from_be_bytes(
            bytes[1..5].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?,
        );
        let time_cost = u32::from_be_bytes(
            bytes[5..9].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?,
        );
        let parallelism = u32::from_be_bytes(
            bytes[9..13].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?,
        );
        let params = Argon2idParams { memory_kib, time_cost, parallelism };
        params.validate()?;
        let salt: [u8; 16] =
            bytes[13..29].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?;
        let nonce =
            XChaChaNonce::from_slice(&bytes[29..53]).ok_or(PrimitiveError::InvalidEncoding)?;
        Ok(Self { params, salt, nonce, ciphertext: bytes[53..].to_vec() })
    }
}

fn local_db_aad(params: Argon2idParams, salt: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LOCAL_DB_AAD.len() + 12 + salt.len());
    aad.extend_from_slice(LOCAL_DB_AAD);
    aad.extend_from_slice(&params.memory_kib.to_be_bytes());
    aad.extend_from_slice(&params.time_cost.to_be_bytes());
    aad.extend_from_slice(&params.parallelism.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

/// A vault key together with its nonzero epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultKeyEpoch {
    /// Epoch number used in the object envelope.
    pub epoch: u32,
    /// Key material for this epoch.
    pub key: VaultKey,
}

impl VaultKeyEpoch {
    /// Construct a vault key epoch, rejecting the reserved zero epoch.
    pub fn new(epoch: u32, key: VaultKey) -> Result<Self, PrimitiveError> {
        if epoch == 0 {
            return Err(PrimitiveError::InvalidKey);
        }
        Ok(Self { epoch, key })
    }
}

impl fmt::Debug for VaultKeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultKeyEpoch")
            .field("epoch", &self.epoch)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Device-held signing and HPKE keys.
#[derive(Debug)]
pub struct DeviceKeys {
    /// Device signing key (P-256).
    pub signing: P256SigningKey,
    /// Device HPKE key pair (P-256).
    pub kem: DeviceKemKeyPair,
}

/// Account-held signing and HPKE keys.
#[derive(Debug)]
pub struct AccountKeys {
    /// Account signing key (Ed25519).
    pub signing: Ed25519SigningKey,
    /// Account HPKE key pair (X25519).
    pub kem: AccountKemKeyPair,
}

/// Generate a fresh device key pair.
pub fn generate_device_keys() -> Result<DeviceKeys, PrimitiveError> {
    Ok(DeviceKeys {
        signing: crate::generate_p256_signing_key()?,
        kem: DeviceKemKeyPair::generate()?,
    })
}

/// Generate a fresh account key pair.
pub fn generate_account_keys() -> Result<AccountKeys, PrimitiveError> {
    Ok(AccountKeys {
        signing: crate::generate_ed25519_signing_key()?,
        kem: AccountKemKeyPair::generate()?,
    })
}

/// Generate a fresh symmetric key for an ARK, vault, or local database.
pub fn generate_symmetric_key() -> Result<SymmetricKey, PrimitiveError> {
    random_key()
}

/// Encrypt an ARK or vault key to a device HPKE public key.
pub fn wrap_key_to_device(
    recipient_public_key: &[u8],
    key: &SymmetricKey,
    context: &[u8],
    aad: &[u8],
) -> Result<crate::HpkeCiphertext, PrimitiveError> {
    hpke_seal_device(recipient_public_key, context, aad, key.as_ref())
}

/// Decrypt a key wrapped to a device HPKE key pair.
pub fn unwrap_key_from_device(
    recipient: &DeviceKemKeyPair,
    wrapped: &crate::HpkeCiphertext,
    context: &[u8],
    aad: &[u8],
) -> Result<SymmetricKey, PrimitiveError> {
    let plaintext =
        hpke_open_device(recipient, &wrapped.encapsulated_key, context, aad, &wrapped.ciphertext)?;
    SecretBytes::from_slice(&plaintext).ok_or(PrimitiveError::InvalidKey)
}

/// Create a fresh vault epoch with a random key.
pub fn generate_vault_epoch(epoch: u32) -> Result<VaultKeyEpoch, PrimitiveError> {
    VaultKeyEpoch::new(epoch, generate_symmetric_key()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_hierarchy_keys_round_trip_through_device_hpke() {
        let device = generate_device_keys().expect("device keys");
        let key = generate_symmetric_key().expect("key");
        let wrapped =
            wrap_key_to_device(device.kem.public_key(), &key, b"ark", b"account").expect("wrap");
        assert_eq!(
            unwrap_key_from_device(&device.kem, &wrapped, b"ark", b"account").expect("unwrap"),
            key
        );
        assert!(VaultKeyEpoch::new(0, key.clone()).is_err());
        assert_eq!(VaultKeyEpoch::new(1, key).expect("epoch").epoch, 1);
    }

    #[test]
    fn local_database_key_wrapper_round_trips_and_binds_passphrase() {
        let params = Argon2idParams { memory_kib: 8 * 1024, time_cost: 1, parallelism: 1 };
        let key = SecretBytes::new([8; 32]);
        let envelope = LocalDatabaseKeyEnvelope::wrap_with_parameters_and_nonce(
            b"correct horse",
            &key,
            params,
            [4; 16],
            SecretBytes::new([5; 24]),
        )
        .expect("wrap");
        let encoded = envelope.encode().expect("encode");
        let decoded = LocalDatabaseKeyEnvelope::decode(&encoded).expect("decode");
        assert_eq!(decoded.open(b"correct horse").expect("open"), key);
        assert_eq!(decoded.open(b"wrong"), Err(PrimitiveError::Authentication));
        assert_eq!(
            format!("{decoded:?}"),
            "LocalDatabaseKeyEnvelope { params: Argon2idParams { memory_kib: 8192, time_cost: 1, parallelism: 1 }, salt: \"[REDACTED]\", nonce: \"[REDACTED]\", ciphertext: \"[REDACTED]\" }"
        );
        assert_eq!(
            LocalDatabaseKeyEnvelope::decode(&encoded[..encoded.len() - 1]),
            Err(PrimitiveError::InvalidEncoding)
        );
    }

    #[test]
    fn local_database_key_wrapper_rejects_unbounded_costs() {
        let params = Argon2idParams { memory_kib: 1024 * 1024 + 1, time_cost: 1, parallelism: 1 };
        assert_eq!(
            params.validate(),
            Err(PrimitiveError::Argon2("invalid Argon2id cost parameters".into()))
        );
    }
}
