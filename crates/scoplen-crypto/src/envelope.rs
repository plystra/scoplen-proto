// SPDX-License-Identifier: Apache-2.0
//! Signed and encrypted personal/shared-vault object envelopes.

#![allow(clippy::missing_errors_doc)]

use uuid::Uuid;

use scoplen_model::{Object, cbor, validate_uuid_v7};

use crate::{
    P256SigningKey, PrimitiveError, SymmetricKey, XChaChaNonce, p256_verify, random_nonce,
    xchacha20poly1305_open, xchacha20poly1305_seal,
};

/// The current encrypted-object envelope version.
pub const OBJECT_ENVELOPE_VERSION: u8 = 1;
const OBJECT_ENVELOPE_DOMAIN: &str = "spl-object-v1";

/// The encrypted and device-signed representation stored by the sync service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectEnvelope {
    /// Envelope version byte.
    pub version: u8,
    /// Vault key epoch used for encryption.
    pub key_epoch: u32,
    /// XChaCha20-Poly1305 nonce.
    pub nonce: XChaChaNonce,
    /// Authenticated ciphertext containing deterministic K-1 CBOR.
    pub ciphertext: Vec<u8>,
    /// Device that signed the write.
    pub signer_device_id: Uuid,
    /// Fixed-width ECDSA P-256 signature over the envelope and AAD.
    pub signature: [u8; 64],
}

impl ObjectEnvelope {
    /// Encrypt and sign an object with the vault key for `key_epoch`.
    pub fn encrypt(
        vault_id: Uuid,
        key_epoch: u32,
        object: &Object,
        vault_key: &SymmetricKey,
        signer_device_id: Uuid,
        signer: &P256SigningKey,
    ) -> Result<Self, PrimitiveError> {
        if key_epoch == 0 {
            return Err(PrimitiveError::InvalidKey);
        }
        validate_uuid(vault_id)?;
        validate_uuid(signer_device_id)?;
        let nonce = random_nonce()?;
        Self::encrypt_with_nonce(
            vault_id,
            key_epoch,
            object,
            vault_key,
            signer_device_id,
            signer,
            nonce,
        )
    }

    /// Encrypt and sign with a supplied nonce for deterministic vectors.
    pub fn encrypt_with_nonce(
        vault_id: Uuid,
        key_epoch: u32,
        object: &Object,
        vault_key: &SymmetricKey,
        signer_device_id: Uuid,
        signer: &P256SigningKey,
        nonce: XChaChaNonce,
    ) -> Result<Self, PrimitiveError> {
        if key_epoch == 0 {
            return Err(PrimitiveError::InvalidKey);
        }
        validate_uuid(vault_id)?;
        validate_uuid(signer_device_id).map_err(|_| PrimitiveError::InvalidEncoding)?;
        let plaintext = object.encode().map_err(|_| PrimitiveError::InvalidEncoding)?;
        let aad = aad(vault_id, object.id, key_epoch)?;
        let ciphertext = xchacha20poly1305_seal(vault_key, &nonce, &plaintext, &aad)?;
        let mut envelope = Self {
            version: OBJECT_ENVELOPE_VERSION,
            key_epoch,
            nonce,
            ciphertext,
            signer_device_id,
            signature: [0; 64],
        };
        envelope.signature = signer.sign(&envelope.signature_input(&aad));
        Ok(envelope)
    }

    /// Verify, decrypt, and decode the object for a known signer public key.
    pub fn decrypt(
        &self,
        vault_id: Uuid,
        object_id: Uuid,
        vault_key: &SymmetricKey,
        signer_public_key_sec1: &[u8],
    ) -> Result<Object, PrimitiveError> {
        if self.version != OBJECT_ENVELOPE_VERSION || self.key_epoch == 0 {
            return Err(PrimitiveError::InvalidEncoding);
        }
        validate_uuid(vault_id)?;
        validate_uuid(object_id)?;
        validate_uuid(self.signer_device_id)?;
        let aad = aad(vault_id, object_id, self.key_epoch)?;
        p256_verify(signer_public_key_sec1, &self.signature_input(&aad), &self.signature)?;
        let plaintext = xchacha20poly1305_open(vault_key, &self.nonce, &self.ciphertext, &aad)?;
        let object = Object::decode(&plaintext).map_err(|_| PrimitiveError::InvalidEncoding)?;
        if object.id != object_id {
            return Err(PrimitiveError::InvalidEncoding);
        }
        Ok(object)
    }

    /// Encode the binary envelope without a ciphertext length field; the fixed suffix identifies
    /// the signer and signature during decoding.
    pub fn encode(&self) -> Result<Vec<u8>, PrimitiveError> {
        if self.version != OBJECT_ENVELOPE_VERSION
            || self.key_epoch == 0
            || self.ciphertext.len() < 16
        {
            return Err(PrimitiveError::InvalidEncoding);
        }
        validate_uuid(self.signer_device_id)?;
        let mut output = Vec::with_capacity(1 + 4 + 24 + self.ciphertext.len() + 16 + 64);
        output.push(self.version);
        output.extend_from_slice(&self.key_epoch.to_be_bytes());
        output.extend_from_slice(self.nonce.as_ref());
        output.extend_from_slice(&self.ciphertext);
        output.extend_from_slice(self.signer_device_id.as_bytes());
        output.extend_from_slice(&self.signature);
        Ok(output)
    }

    /// Decode the binary envelope and reject truncation, bad version, and trailing structure.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() < 1 + 4 + 24 + 16 + 64 + 16 || bytes[0] != OBJECT_ENVELOPE_VERSION {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let key_epoch_bytes: [u8; 4] =
            bytes[1..5].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?;
        let key_epoch = u32::from_be_bytes(key_epoch_bytes);
        if key_epoch == 0 {
            return Err(PrimitiveError::InvalidEncoding);
        }
        let nonce =
            XChaChaNonce::from_slice(&bytes[5..29]).ok_or(PrimitiveError::InvalidEncoding)?;
        let signer_start = bytes.len() - 80;
        let ciphertext = bytes[29..signer_start].to_vec();
        let signer_bytes: [u8; 16] = bytes[signer_start..signer_start + 16]
            .try_into()
            .map_err(|_| PrimitiveError::InvalidEncoding)?;
        let signer_device_id = Uuid::from_bytes(signer_bytes);
        validate_uuid(signer_device_id).map_err(|_| PrimitiveError::InvalidEncoding)?;
        let signature: [u8; 64] =
            bytes[signer_start + 16..].try_into().map_err(|_| PrimitiveError::InvalidEncoding)?;
        Ok(Self { version: bytes[0], key_epoch, nonce, ciphertext, signer_device_id, signature })
    }

    fn signature_input(&self, aad: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(1 + 4 + 24 + self.ciphertext.len() + 16 + aad.len());
        input.push(self.version);
        input.extend_from_slice(&self.key_epoch.to_be_bytes());
        input.extend_from_slice(self.nonce.as_ref());
        input.extend_from_slice(&self.ciphertext);
        input.extend_from_slice(self.signer_device_id.as_bytes());
        input.extend_from_slice(aad);
        input
    }
}

fn aad(vault_id: Uuid, object_id: Uuid, key_epoch: u32) -> Result<Vec<u8>, PrimitiveError> {
    cbor::encode(&cbor::Value::Array(vec![
        cbor::Value::Bytes(vault_id.into_bytes().to_vec()),
        cbor::Value::Bytes(object_id.into_bytes().to_vec()),
        cbor::Value::UInt(u64::from(key_epoch)),
        cbor::Value::Text(OBJECT_ENVELOPE_DOMAIN.into()),
    ]))
    .map_err(|_| PrimitiveError::InvalidEncoding)
}

fn validate_uuid(value: Uuid) -> Result<(), PrimitiveError> {
    validate_uuid_v7(value).map_err(|_| PrimitiveError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretBytes;
    use scoplen_model::{FieldEntry, FieldPath, Hlc, ObjectType, cbor};

    fn id(seed: u8) -> Uuid {
        let mut bytes = [0; 16];
        bytes[0] = seed;
        bytes[6] = 0x70;
        bytes[8] = 0x80;
        Uuid::from_bytes(bytes)
    }

    fn object() -> Object {
        let mut object = Object::new(id(1), ObjectType::HOST, 1).expect("object");
        object
            .insert(
                FieldPath::field(1).expect("path"),
                FieldEntry::new(
                    cbor::Value::Text("host".into()),
                    Hlc::at(1).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        object
            .insert(
                FieldPath::field(2).expect("path"),
                FieldEntry::new(
                    cbor::Value::Text("host.example".into()),
                    Hlc::at(2).expect("clock"),
                    id(2),
                )
                .expect("entry"),
            )
            .expect("insert");
        object
    }

    #[test]
    fn object_envelope_round_trips_and_binds_all_context() {
        let signer = P256SigningKey::from_bytes(&[1; 32]).expect("signer");
        let key = SecretBytes::new([2; 32]);
        let envelope = ObjectEnvelope::encrypt_with_nonce(
            id(3),
            1,
            &object(),
            &key,
            id(4),
            &signer,
            SecretBytes::new([5; 24]),
        )
        .expect("encrypt");
        let encoded = envelope.encode().expect("encode");
        let decoded = ObjectEnvelope::decode(&encoded).expect("decode");
        assert_eq!(
            decoded.decrypt(id(3), id(1), &key, &signer.public_key_sec1()).expect("decrypt"),
            object()
        );
        assert_eq!(
            decoded.decrypt(id(9), id(1), &key, &signer.public_key_sec1()),
            Err(PrimitiveError::InvalidSignature)
        );
        assert_eq!(
            ObjectEnvelope::decode(&encoded[..encoded.len() - 1]),
            Err(PrimitiveError::InvalidEncoding)
        );
    }
}
