// SPDX-License-Identifier: Apache-2.0
//! HPKE wrappers for device and account key encapsulation.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, X25519HkdfSha256},
    setup_receiver, setup_sender,
};
use rand_core::OsRng;

use crate::{PrimitiveError, SecretBytes};

type DeviceKem = DhP256HkdfSha256;
type AccountKem = X25519HkdfSha256;
type HpkeAead = ChaCha20Poly1305;
type HpkeKdf = HkdfSha256;

/// A generated P-256 HPKE key pair for a device recipient.
#[derive(Clone)]
pub struct DeviceKemKeyPair {
    private: SecretBytes<32>,
    public: Vec<u8>,
}

impl DeviceKemKeyPair {
    /// Generate a random device HPKE key pair.
    pub fn generate() -> Result<Self, PrimitiveError> {
        let (private, public) = DeviceKem::gen_keypair(&mut OsRng);
        let private = SecretBytes::from_slice(private.to_bytes().as_slice())
            .ok_or(PrimitiveError::InvalidKey)?;
        Ok(Self { private, public: public.to_bytes().to_vec() })
    }

    /// Reconstruct a device key pair from serialized private key bytes.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let private = <DeviceKem as KemTrait>::PrivateKey::from_bytes(bytes)
            .map_err(|_| PrimitiveError::InvalidKey)?;
        let public = DeviceKem::sk_to_pk(&private);
        let private = SecretBytes::from_slice(private.to_bytes().as_slice())
            .ok_or(PrimitiveError::InvalidKey)?;
        Ok(Self { private, public: public.to_bytes().to_vec() })
    }

    /// Return the serialized public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    fn private_key(&self) -> <DeviceKem as KemTrait>::PrivateKey {
        <DeviceKem as KemTrait>::PrivateKey::from_bytes(self.private.as_ref())
            .expect("device HPKE key validated at construction")
    }
}

impl fmt::Debug for DeviceKemKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceKemKeyPair { private: [REDACTED] }")
    }
}

/// A generated X25519 HPKE key pair for an account recipient.
#[derive(Clone)]
pub struct AccountKemKeyPair {
    private: SecretBytes<32>,
    public: Vec<u8>,
}

impl AccountKemKeyPair {
    /// Generate a random account HPKE key pair.
    pub fn generate() -> Result<Self, PrimitiveError> {
        let (private, public) = AccountKem::gen_keypair(&mut OsRng);
        let private = SecretBytes::from_slice(private.to_bytes().as_slice())
            .ok_or(PrimitiveError::InvalidKey)?;
        Ok(Self { private, public: public.to_bytes().to_vec() })
    }

    /// Reconstruct an account key pair from serialized private key bytes.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let private = <AccountKem as KemTrait>::PrivateKey::from_bytes(bytes)
            .map_err(|_| PrimitiveError::InvalidKey)?;
        let public = AccountKem::sk_to_pk(&private);
        let private = SecretBytes::from_slice(private.to_bytes().as_slice())
            .ok_or(PrimitiveError::InvalidKey)?;
        Ok(Self { private, public: public.to_bytes().to_vec() })
    }

    /// Return the serialized public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    fn private_key(&self) -> <AccountKem as KemTrait>::PrivateKey {
        <AccountKem as KemTrait>::PrivateKey::from_bytes(self.private.as_ref())
            .expect("account HPKE key validated at construction")
    }
}

impl fmt::Debug for AccountKemKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountKemKeyPair { private: [REDACTED] }")
    }
}

/// An HPKE message containing the encapsulated key and authenticated ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeCiphertext {
    /// Serialized encapsulated key sent alongside the ciphertext.
    pub encapsulated_key: Vec<u8>,
    /// HPKE ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Encrypt to a device's P-256 HPKE public key using the K-2 suite.
pub fn hpke_seal_device(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, PrimitiveError> {
    hpke_seal::<DeviceKem>(recipient_public_key, info, aad, plaintext)
}

/// Decrypt a device HPKE message with its P-256 private key.
pub fn hpke_open_device(
    recipient: &DeviceKemKeyPair,
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PrimitiveError> {
    hpke_open::<DeviceKem>(&recipient.private_key(), encapsulated_key, info, aad, ciphertext)
}

/// Encrypt to an account's X25519 HPKE public key using the K-2 suite.
pub fn hpke_seal_account(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, PrimitiveError> {
    hpke_seal::<AccountKem>(recipient_public_key, info, aad, plaintext)
}

/// Decrypt an account HPKE message with its X25519 private key.
pub fn hpke_open_account(
    recipient: &AccountKemKeyPair,
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PrimitiveError> {
    hpke_open::<AccountKem>(&recipient.private_key(), encapsulated_key, info, aad, ciphertext)
}

fn hpke_seal<Kem>(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, PrimitiveError>
where
    Kem: KemTrait,
{
    let recipient_public_key =
        Kem::PublicKey::from_bytes(recipient_public_key).map_err(|_| PrimitiveError::InvalidKey)?;
    let (encapsulated_key, mut context) = setup_sender::<HpkeAead, HpkeKdf, Kem, _>(
        &OpModeS::Base,
        &recipient_public_key,
        info,
        &mut OsRng,
    )
    .map_err(|_| PrimitiveError::InvalidKey)?;
    let ciphertext = context.seal(plaintext, aad).map_err(|_| PrimitiveError::Authentication)?;
    Ok(HpkeCiphertext { encapsulated_key: encapsulated_key.to_bytes().to_vec(), ciphertext })
}

fn hpke_open<Kem>(
    recipient_private_key: &Kem::PrivateKey,
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PrimitiveError>
where
    Kem: KemTrait,
{
    let encapsulated_key =
        Kem::EncappedKey::from_bytes(encapsulated_key).map_err(|_| PrimitiveError::InvalidKey)?;
    let mut context = setup_receiver::<HpkeAead, HpkeKdf, Kem>(
        &OpModeR::Base,
        recipient_private_key,
        &encapsulated_key,
        info,
    )
    .map_err(|_| PrimitiveError::InvalidKey)?;
    context.open(ciphertext, aad).map_err(|_| PrimitiveError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_hpke_round_trip_and_authentication() {
        let recipient = DeviceKemKeyPair::generate().expect("key pair");
        let message = hpke_seal_device(recipient.public_key(), b"device-info", b"aad", b"secret")
            .expect("seal");
        assert_eq!(
            hpke_open_device(
                &recipient,
                &message.encapsulated_key,
                b"device-info",
                b"aad",
                &message.ciphertext,
            )
            .expect("open"),
            b"secret"
        );
        assert_eq!(
            hpke_open_device(
                &recipient,
                &message.encapsulated_key,
                b"device-info",
                b"wrong",
                &message.ciphertext,
            ),
            Err(PrimitiveError::Authentication)
        );
        assert_eq!(format!("{recipient:?}"), "DeviceKemKeyPair { private: [REDACTED] }");
    }

    #[test]
    fn account_hpke_round_trip_and_malformed_inputs_fail() {
        let recipient = AccountKemKeyPair::generate().expect("key pair");
        let message = hpke_seal_account(recipient.public_key(), b"account-info", b"aad", b"secret")
            .expect("seal");
        assert_eq!(
            hpke_open_account(
                &recipient,
                &message.encapsulated_key,
                b"account-info",
                b"aad",
                &message.ciphertext,
            )
            .expect("open"),
            b"secret"
        );
        assert_eq!(
            hpke_open_account(&recipient, &[0; 1], b"account-info", b"aad", &message.ciphertext),
            Err(PrimitiveError::InvalidKey)
        );
        assert!(matches!(
            AccountKemKeyPair::from_private_bytes(&[0; 31]),
            Err(PrimitiveError::InvalidKey)
        ));
    }
}
