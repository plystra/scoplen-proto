// SPDX-License-Identifier: Apache-2.0
//! Signed device certificates and revocation statements.

#![allow(clippy::missing_errors_doc)]

use uuid::Uuid;

use scoplen_model::{cbor, validate_uuid_v7};

use crate::{Ed25519SigningKey, PrimitiveError, ed25519_verify};

/// A signed device certificate from the account signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    /// Enrolled device identifier.
    pub device_id: Uuid,
    /// Owning account identifier.
    pub account_id: Uuid,
    /// Device signing public key in uncompressed SEC1 form.
    pub signing_public_key: Vec<u8>,
    /// Device HPKE public key in uncompressed SEC1 form.
    pub kem_public_key: Vec<u8>,
    /// User-visible device name.
    pub display_name: String,
    /// Platform identifier.
    pub platform: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at: u64,
    /// Account signature over fields 1 through 7.
    pub signature: [u8; 64],
}

impl DeviceCertificate {
    /// Issue a certificate and sign its deterministic CBOR payload.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        account_signing_key: &Ed25519SigningKey,
        device_id: Uuid,
        account_id: Uuid,
        signing_public_key: Vec<u8>,
        kem_public_key: Vec<u8>,
        display_name: String,
        platform: String,
        created_at: u64,
    ) -> Result<Self, PrimitiveError> {
        validate_certificate_fields(device_id, account_id, &signing_public_key, &kem_public_key)?;
        let unsigned = Self {
            device_id,
            account_id,
            signing_public_key,
            kem_public_key,
            display_name,
            platform,
            created_at,
            signature: [0; 64],
        };
        let signature = account_signing_key.sign(&unsigned.payload()?);
        Ok(Self { signature, ..unsigned })
    }

    /// Verify this certificate against the account Ed25519 public key.
    pub fn verify(&self, account_signing_public_key: &[u8; 32]) -> Result<(), PrimitiveError> {
        validate_certificate_fields(
            self.device_id,
            self.account_id,
            &self.signing_public_key,
            &self.kem_public_key,
        )?;
        ed25519_verify(account_signing_public_key, &self.payload()?, &self.signature)
    }

    /// Encode the signed certificate as deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, PrimitiveError> {
        let mut entries = self.unsigned_entries();
        entries.push((cbor::Value::UInt(8), cbor::Value::Bytes(self.signature.to_vec())));
        cbor::encode(&cbor::Value::Map(entries)).map_err(|_| PrimitiveError::InvalidEncoding)
    }

    /// Decode a signed certificate from deterministic CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let cbor::Value::Map(entries) =
            cbor::decode(bytes).map_err(|_| PrimitiveError::InvalidEncoding)?
        else {
            return Err(PrimitiveError::InvalidEncoding);
        };
        let mut values: [Option<cbor::Value>; 8] = std::array::from_fn(|_| None);
        for (key, value) in entries {
            let cbor::Value::UInt(key) = key else { return Err(PrimitiveError::InvalidEncoding) };
            let index = usize::try_from(key).map_err(|_| PrimitiveError::InvalidEncoding)?;
            if !(1..=8).contains(&key) || values[index - 1].is_some() {
                return Err(PrimitiveError::InvalidEncoding);
            }
            values[index - 1] = Some(value);
        }
        let signature = bytes64(values[7].take().ok_or(PrimitiveError::InvalidEncoding)?)?;
        let certificate = Self {
            device_id: uuid_value(values[0].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
            account_id: uuid_value(values[1].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
            signing_public_key: bytes_value(
                values[2].take().ok_or(PrimitiveError::InvalidEncoding)?,
            )?,
            kem_public_key: bytes_value(values[3].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
            display_name: text_value(values[4].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
            platform: text_value(values[5].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
            created_at: uint_value(values[6].as_ref().ok_or(PrimitiveError::InvalidEncoding)?)?,
            signature,
        };
        validate_certificate_fields(
            certificate.device_id,
            certificate.account_id,
            &certificate.signing_public_key,
            &certificate.kem_public_key,
        )?;
        Ok(certificate)
    }

    fn unsigned_entries(&self) -> Vec<(cbor::Value, cbor::Value)> {
        vec![
            (cbor::Value::UInt(1), cbor::Value::Bytes(self.device_id.into_bytes().to_vec())),
            (cbor::Value::UInt(2), cbor::Value::Bytes(self.account_id.into_bytes().to_vec())),
            (cbor::Value::UInt(3), cbor::Value::Bytes(self.signing_public_key.clone())),
            (cbor::Value::UInt(4), cbor::Value::Bytes(self.kem_public_key.clone())),
            (cbor::Value::UInt(5), cbor::Value::Text(self.display_name.clone())),
            (cbor::Value::UInt(6), cbor::Value::Text(self.platform.clone())),
            (cbor::Value::UInt(7), cbor::Value::UInt(self.created_at)),
        ]
    }

    fn payload(&self) -> Result<Vec<u8>, PrimitiveError> {
        cbor::encode(&cbor::Value::Map(self.unsigned_entries()))
            .map_err(|_| PrimitiveError::InvalidEncoding)
    }
}

/// A signed device revocation statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationStatement {
    /// Device identifier being revoked.
    pub device_id: Uuid,
    /// Revocation timestamp in Unix milliseconds.
    pub revoked_at: u64,
    /// Human-readable or policy reason.
    pub reason: String,
    /// Account signature over fields 1 through 3.
    pub signature: [u8; 64],
}

impl RevocationStatement {
    /// Issue and sign a revocation statement.
    pub fn issue(
        account_signing_key: &Ed25519SigningKey,
        device_id: Uuid,
        revoked_at: u64,
        reason: String,
    ) -> Result<Self, PrimitiveError> {
        validate_uuid(device_id)?;
        let unsigned = Self { device_id, revoked_at, reason, signature: [0; 64] };
        let signature = account_signing_key.sign(&unsigned.payload()?);
        Ok(Self { signature, ..unsigned })
    }

    /// Verify the revocation statement against the account public key.
    pub fn verify(&self, account_signing_public_key: &[u8; 32]) -> Result<(), PrimitiveError> {
        validate_uuid(self.device_id)?;
        ed25519_verify(account_signing_public_key, &self.payload()?, &self.signature)
    }

    /// Encode the signed revocation statement as deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, PrimitiveError> {
        let mut entries = self.unsigned_entries();
        entries.push((cbor::Value::UInt(4), cbor::Value::Bytes(self.signature.to_vec())));
        cbor::encode(&cbor::Value::Map(entries)).map_err(|_| PrimitiveError::InvalidEncoding)
    }

    /// Decode a signed revocation statement from deterministic CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        let cbor::Value::Map(entries) =
            cbor::decode(bytes).map_err(|_| PrimitiveError::InvalidEncoding)?
        else {
            return Err(PrimitiveError::InvalidEncoding);
        };
        let mut values: [Option<cbor::Value>; 4] = std::array::from_fn(|_| None);
        for (key, value) in entries {
            let cbor::Value::UInt(key) = key else { return Err(PrimitiveError::InvalidEncoding) };
            let index = usize::try_from(key).map_err(|_| PrimitiveError::InvalidEncoding)?;
            if !(1..=4).contains(&key) || values[index - 1].is_some() {
                return Err(PrimitiveError::InvalidEncoding);
            }
            values[index - 1] = Some(value);
        }
        let statement = Self {
            device_id: uuid_value(values[0].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
            revoked_at: uint_value(values[1].as_ref().ok_or(PrimitiveError::InvalidEncoding)?)?,
            reason: text_value(values[2].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
            signature: bytes64(values[3].take().ok_or(PrimitiveError::InvalidEncoding)?)?,
        };
        validate_uuid(statement.device_id)?;
        Ok(statement)
    }

    fn unsigned_entries(&self) -> Vec<(cbor::Value, cbor::Value)> {
        vec![
            (cbor::Value::UInt(1), cbor::Value::Bytes(self.device_id.into_bytes().to_vec())),
            (cbor::Value::UInt(2), cbor::Value::UInt(self.revoked_at)),
            (cbor::Value::UInt(3), cbor::Value::Text(self.reason.clone())),
        ]
    }

    fn payload(&self) -> Result<Vec<u8>, PrimitiveError> {
        cbor::encode(&cbor::Value::Map(self.unsigned_entries()))
            .map_err(|_| PrimitiveError::InvalidEncoding)
    }
}

fn validate_certificate_fields(
    device_id: Uuid,
    account_id: Uuid,
    signing_public_key: &[u8],
    kem_public_key: &[u8],
) -> Result<(), PrimitiveError> {
    validate_uuid(device_id)?;
    validate_uuid(account_id)?;
    if signing_public_key.len() != 65 || kem_public_key.len() != 65 {
        return Err(PrimitiveError::InvalidKey);
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(signing_public_key)
        .map_err(|_| PrimitiveError::InvalidKey)?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(kem_public_key)
        .map_err(|_| PrimitiveError::InvalidKey)?;
    Ok(())
}

fn validate_uuid(value: Uuid) -> Result<(), PrimitiveError> {
    validate_uuid_v7(value).map_err(|_| PrimitiveError::InvalidKey)
}

fn uuid_value(value: cbor::Value) -> Result<Uuid, PrimitiveError> {
    let cbor::Value::Bytes(bytes) = value else { return Err(PrimitiveError::InvalidEncoding) };
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| PrimitiveError::InvalidEncoding)?;
    let value = Uuid::from_bytes(bytes);
    validate_uuid(value)?;
    Ok(value)
}

fn bytes_value(value: cbor::Value) -> Result<Vec<u8>, PrimitiveError> {
    match value {
        cbor::Value::Bytes(bytes) => Ok(bytes),
        _ => Err(PrimitiveError::InvalidEncoding),
    }
}

fn text_value(value: cbor::Value) -> Result<String, PrimitiveError> {
    match value {
        cbor::Value::Text(text) => Ok(text),
        _ => Err(PrimitiveError::InvalidEncoding),
    }
}

fn uint_value(value: &cbor::Value) -> Result<u64, PrimitiveError> {
    match value {
        cbor::Value::UInt(value) => Ok(*value),
        _ => Err(PrimitiveError::InvalidEncoding),
    }
}

fn bytes64(value: cbor::Value) -> Result<[u8; 64], PrimitiveError> {
    let cbor::Value::Bytes(bytes) = value else { return Err(PrimitiveError::InvalidEncoding) };
    bytes.try_into().map_err(|_| PrimitiveError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceKemKeyPair, generate_ed25519_signing_key, generate_p256_signing_key};

    fn id(seed: u8) -> Uuid {
        let mut bytes = [0; 16];
        bytes[0] = seed;
        bytes[6] = 0x70;
        bytes[8] = 0x80;
        Uuid::from_bytes(bytes)
    }

    #[test]
    fn certificates_and_revocations_round_trip_and_verify() {
        let account = generate_ed25519_signing_key().expect("account");
        let device_signing = generate_p256_signing_key().expect("device signing");
        let device_kem = DeviceKemKeyPair::generate().expect("device kem");
        let certificate = DeviceCertificate::issue(
            &account,
            id(1),
            id(2),
            device_signing.public_key_sec1(),
            device_kem.public_key().to_vec(),
            "laptop".into(),
            "windows".into(),
            42,
        )
        .expect("issue");
        let encoded = certificate.encode().expect("encode");
        let decoded = DeviceCertificate::decode(&encoded).expect("decode");
        decoded.verify(&account.public_key()).expect("verify");
        let mut tampered = decoded.clone();
        tampered.signature[0] ^= 1;
        assert_eq!(tampered.verify(&account.public_key()), Err(PrimitiveError::InvalidSignature));

        let revocation =
            RevocationStatement::issue(&account, id(1), 43, "lost".into()).expect("revoke");
        let decoded =
            RevocationStatement::decode(&revocation.encode().expect("encode")).expect("decode");
        decoded.verify(&account.public_key()).expect("verify");
        assert_eq!(
            DeviceCertificate::decode(&encoded[..encoded.len() - 1]),
            Err(PrimitiveError::InvalidEncoding)
        );
    }
}
