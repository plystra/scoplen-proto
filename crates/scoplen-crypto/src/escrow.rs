// SPDX-License-Identifier: Apache-2.0
//! HPKE wrapping and one-share re-encryption for administrator escrow.

#![allow(clippy::missing_errors_doc)]

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    AccountKemKeyPair, DeviceKemKeyPair, HpkeCiphertext, PrimitiveError, ShamirShare,
    hpke_open_account, hpke_open_device, hpke_seal_account, hpke_seal_device,
};

const ESCROW_SHARE_DOMAIN: &[u8] = b"spl-escrow-share-v2";
const ESCROW_VERIFY_DOMAIN: &[u8] = b"spl-escrow-verify-v1";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Build the HPKE context for a share stored by one administrator.
#[must_use]
pub fn escrow_account_context(account_id: Uuid, administrator_account_id: Uuid) -> Vec<u8> {
    let mut context = Vec::with_capacity(ESCROW_SHARE_DOMAIN.len() + 1 + 16 + 16);
    context.extend_from_slice(ESCROW_SHARE_DOMAIN);
    context.push(1);
    context.extend_from_slice(account_id.as_bytes());
    context.extend_from_slice(administrator_account_id.as_bytes());
    context
}

/// Build the HPKE context for a share re-encrypted to one recovery request.
///
/// The device key digest binds both uncompressed SEC1 public keys to the request, so an
/// administrator cannot accidentally re-encrypt a share for a different device key set.
pub fn escrow_device_context(
    account_id: Uuid,
    request_id: Uuid,
    device_signing_public_key: &[u8],
    device_kem_public_key: &[u8],
) -> Result<Vec<u8>, PrimitiveError> {
    validate_device_public_key(device_signing_public_key)?;
    validate_device_public_key(device_kem_public_key)?;
    let key_digest = device_key_digest(device_signing_public_key, device_kem_public_key);
    let mut context = Vec::with_capacity(ESCROW_SHARE_DOMAIN.len() + 1 + 16 + 16 + 32);
    context.extend_from_slice(ESCROW_SHARE_DOMAIN);
    context.push(2);
    context.extend_from_slice(account_id.as_bytes());
    context.extend_from_slice(request_id.as_bytes());
    context.extend_from_slice(&key_digest);
    Ok(context)
}

/// Compute the recovery verification code shown by a new device.
pub fn escrow_verification_code(
    account_id: Uuid,
    request_id: Uuid,
    device_signing_public_key: &[u8],
    device_kem_public_key: &[u8],
) -> Result<String, PrimitiveError> {
    validate_device_public_key(device_signing_public_key)?;
    validate_device_public_key(device_kem_public_key)?;
    let digest = verification_digest(
        account_id,
        request_id,
        device_signing_public_key,
        device_kem_public_key,
    );
    let encoded = encode_crockford(&digest[..10]);
    let mut display = String::with_capacity(19);
    for (index, byte) in encoded.bytes().enumerate() {
        if index != 0 && index % 4 == 0 {
            display.push('-');
        }
        display.push(char::from(byte));
    }
    Ok(display)
}

/// Compare an administrator-entered recovery verification code with the request.
pub fn verify_escrow_verification_code(
    account_id: Uuid,
    request_id: Uuid,
    device_signing_public_key: &[u8],
    device_kem_public_key: &[u8],
    entered: &str,
) -> Result<(), PrimitiveError> {
    let expected = escrow_verification_code(
        account_id,
        request_id,
        device_signing_public_key,
        device_kem_public_key,
    )?;
    let expected_bytes = parse_verification_code(&expected)?;
    let entered_bytes = parse_verification_code(entered)?;
    if expected_bytes.ct_eq(&entered_bytes).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(PrimitiveError::Authentication)
    }
}

/// Encrypt one Shamir share to an administrator account's KEM public key.
pub fn wrap_escrow_share_to_account(
    account_id: Uuid,
    administrator_account_id: Uuid,
    recipient_public_key: &[u8],
    share: &ShamirShare,
) -> Result<HpkeCiphertext, PrimitiveError> {
    let context = escrow_account_context(account_id, administrator_account_id);
    hpke_seal_account(recipient_public_key, &context, &context, &share.to_bytes())
}

/// Open one escrow share on the administrator account that received it.
pub fn open_escrow_share_from_account(
    account_id: Uuid,
    administrator_account_id: Uuid,
    recipient: &AccountKemKeyPair,
    wrapped: &HpkeCiphertext,
) -> Result<ShamirShare, PrimitiveError> {
    let context = escrow_account_context(account_id, administrator_account_id);
    let bytes = hpke_open_account(
        recipient,
        &wrapped.encapsulated_key,
        &context,
        &context,
        &wrapped.ciphertext,
    )?;
    ShamirShare::from_bytes(&bytes)
}

/// Re-encrypt one authenticated administrator share to a recovering device.
pub fn rewrap_escrow_share_to_device(
    account_id: Uuid,
    administrator_account_id: Uuid,
    request_id: Uuid,
    administrator: &AccountKemKeyPair,
    wrapped: &HpkeCiphertext,
    device_signing_public_key: &[u8],
    device_kem_public_key: &[u8],
) -> Result<HpkeCiphertext, PrimitiveError> {
    let account_context = escrow_account_context(account_id, administrator_account_id);
    let device_context = escrow_device_context(
        account_id,
        request_id,
        device_signing_public_key,
        device_kem_public_key,
    )?;
    let bytes = hpke_open_account(
        administrator,
        &wrapped.encapsulated_key,
        &account_context,
        &account_context,
        &wrapped.ciphertext,
    )?;
    let share = ShamirShare::from_bytes(&bytes)?;
    hpke_seal_device(device_kem_public_key, &device_context, &device_context, &share.to_bytes())
}

/// Open one re-encrypted escrow share on the recovering device.
pub fn open_escrow_share_from_device(
    account_id: Uuid,
    request_id: Uuid,
    device_signing_public_key: &[u8],
    recipient: &DeviceKemKeyPair,
    wrapped: &HpkeCiphertext,
) -> Result<ShamirShare, PrimitiveError> {
    let device_context = escrow_device_context(
        account_id,
        request_id,
        device_signing_public_key,
        recipient.public_key(),
    )?;
    let bytes = hpke_open_device(
        recipient,
        &wrapped.encapsulated_key,
        &device_context,
        &device_context,
        &wrapped.ciphertext,
    )?;
    ShamirShare::from_bytes(&bytes)
}

fn device_key_digest(device_signing_public_key: &[u8], device_kem_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(device_signing_public_key);
    hasher.update(device_kem_public_key);
    hasher.finalize().into()
}

fn verification_digest(
    account_id: Uuid,
    request_id: Uuid,
    device_signing_public_key: &[u8],
    device_kem_public_key: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ESCROW_VERIFY_DOMAIN);
    hasher.update(account_id.as_bytes());
    hasher.update(request_id.as_bytes());
    hasher.update(device_signing_public_key);
    hasher.update(device_kem_public_key);
    hasher.finalize().into()
}

fn validate_device_public_key(key: &[u8]) -> Result<(), PrimitiveError> {
    if key.len() != 65 || key[0] != 4 {
        return Err(PrimitiveError::InvalidKey);
    }
    p256::PublicKey::from_sec1_bytes(key).map_err(|_| PrimitiveError::InvalidKey)?;
    Ok(())
}

fn encode_crockford(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
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

fn parse_verification_code(value: &str) -> Result<[u8; 10], PrimitiveError> {
    let value = value.trim().to_ascii_uppercase();
    let groups: Vec<_> = value.split('-').collect();
    if groups.len() != 4 || groups.iter().any(|group| group.len() != 4) {
        return Err(PrimitiveError::InvalidEncoding);
    }
    let payload = groups.concat();
    let mut output = [0_u8; 10];
    let mut output_index = 0;
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in payload.bytes() {
        let Some(digit) = CROCKFORD.iter().position(|candidate| *candidate == byte) else {
            return Err(PrimitiveError::InvalidEncoding);
        };
        buffer = (buffer << 5) | u32::try_from(digit).expect("Crockford digit fits in u32");
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if output_index == output.len() {
                return Err(PrimitiveError::InvalidEncoding);
            }
            output[output_index] = ((buffer >> bits) & 0xff) as u8;
            output_index += 1;
        }
    }
    if output_index != output.len() || (buffer & ((1_u32 << bits) - 1)) != 0 {
        return Err(PrimitiveError::InvalidEncoding);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceKemKeyPair, P256SigningKey, split_shamir_with_randomness};

    fn ids() -> (Uuid, Uuid, Uuid) {
        (
            Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]),
        )
    }

    #[test]
    fn escrow_share_moves_from_account_to_device_without_reconstructing() {
        let (account_id, administrator_id, request_id) = ids();
        let administrator = AccountKemKeyPair::generate().expect("administrator");
        let device = DeviceKemKeyPair::generate().expect("device");
        let device_signing = P256SigningKey::from_bytes(&[8; 32]).expect("device signing");
        let share =
            split_shamir_with_randomness(b"root-key", 2, 3, &[9; 8]).expect("split").remove(0);
        let wrapped = wrap_escrow_share_to_account(
            account_id,
            administrator_id,
            administrator.public_key(),
            &share,
        )
        .expect("wrap");
        assert_eq!(
            open_escrow_share_from_account(account_id, administrator_id, &administrator, &wrapped)
                .expect("open"),
            share
        );
        let rewrapped = rewrap_escrow_share_to_device(
            account_id,
            administrator_id,
            request_id,
            &administrator,
            &wrapped,
            &device_signing.public_key_sec1(),
            device.public_key(),
        )
        .expect("rewrap");
        assert_eq!(
            open_escrow_share_from_device(
                account_id,
                request_id,
                &device_signing.public_key_sec1(),
                &device,
                &rewrapped,
            )
            .expect("open"),
            share
        );
        assert_eq!(
            open_escrow_share_from_account(
                account_id,
                Uuid::from_bytes([0; 16]),
                &AccountKemKeyPair::generate().expect("other administrator"),
                &wrapped
            ),
            Err(PrimitiveError::Authentication)
        );
    }

    #[test]
    fn escrow_share_rejects_tampering_before_parsing() {
        let (account_id, administrator_id, _) = ids();
        let administrator = AccountKemKeyPair::generate().expect("administrator");
        let share =
            split_shamir_with_randomness(&[1, 2, 3], 2, 2, &[4, 5, 6]).expect("split").remove(0);
        let mut wrapped = wrap_escrow_share_to_account(
            account_id,
            administrator_id,
            administrator.public_key(),
            &share,
        )
        .expect("wrap");
        wrapped.ciphertext[0] ^= 1;
        assert_eq!(
            open_escrow_share_from_account(account_id, administrator_id, &administrator, &wrapped),
            Err(PrimitiveError::Authentication)
        );
    }

    #[test]
    fn escrow_contexts_and_verification_code_bind_every_input() {
        let (account_id, _, request_id) = ids();
        let signing = P256SigningKey::from_bytes(&[8; 32]).expect("signing");
        let device = DeviceKemKeyPair::from_private_bytes(&[7; 32]).expect("device");
        let signing_public = signing.public_key_sec1();
        let code =
            escrow_verification_code(account_id, request_id, &signing_public, device.public_key())
                .expect("code");
        assert_eq!(code.len(), 19);
        verify_escrow_verification_code(
            account_id,
            request_id,
            &signing_public,
            device.public_key(),
            &code,
        )
        .expect("code verifies");
        assert_eq!(
            verify_escrow_verification_code(
                account_id,
                request_id,
                &signing_public,
                device.public_key(),
                "0000-0000-0000-0000",
            ),
            Err(PrimitiveError::Authentication)
        );
        assert_eq!(
            verify_escrow_verification_code(
                account_id,
                request_id,
                &[0; 65],
                device.public_key(),
                &code,
            ),
            Err(PrimitiveError::InvalidKey)
        );
        let account_context = escrow_account_context(account_id, Uuid::from_bytes([0; 16]));
        assert_eq!(&account_context[..ESCROW_SHARE_DOMAIN.len()], ESCROW_SHARE_DOMAIN);
        assert_eq!(account_context[ESCROW_SHARE_DOMAIN.len()], 1);
        assert_ne!(account_context, escrow_account_context(account_id, Uuid::from_bytes([1; 16])));
        let device_context =
            escrow_device_context(account_id, request_id, &signing_public, device.public_key())
                .expect("device context");
        assert_eq!(device_context[ESCROW_SHARE_DOMAIN.len()], 2);
        assert_ne!(
            device_context,
            escrow_device_context(
                Uuid::from_bytes([4; 16]),
                request_id,
                &signing_public,
                device.public_key(),
            )
            .expect("different device context")
        );
    }
}
