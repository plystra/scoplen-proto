// SPDX-License-Identifier: Apache-2.0
//! K-2 key hierarchy types and local key wrapping helpers.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use crate::{
    AccountKemKeyPair, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey, PrimitiveError,
    SecretBytes, SymmetricKey, hpke_open_device, hpke_seal_device, random_key,
};

/// The account root key (ARK), held only by enrolled devices and recovery mechanisms.
pub type AccountRootKey = SymmetricKey;
/// A symmetric vault key for one key epoch.
pub type VaultKey = SymmetricKey;
/// The local database key, held only on one device.
pub type LocalDatabaseKey = SymmetricKey;

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
}
