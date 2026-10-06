// SPDX-License-Identifier: Apache-2.0
//! HPKE wrapping and one-share re-encryption for administrator escrow.

#![allow(clippy::missing_errors_doc)]

use crate::{
    AccountKemKeyPair, DeviceKemKeyPair, HpkeCiphertext, PrimitiveError, ShamirShare,
    hpke_open_account, hpke_open_device, hpke_seal_account, hpke_seal_device,
};

const ESCROW_SHARE_DOMAIN: &[u8] = b"spl-escrow-share-v1";

/// Encrypt one Shamir share to an administrator account's KEM public key.
pub fn wrap_escrow_share_to_account(
    recipient_public_key: &[u8],
    share: &ShamirShare,
) -> Result<HpkeCiphertext, PrimitiveError> {
    hpke_seal_account(
        recipient_public_key,
        ESCROW_SHARE_DOMAIN,
        ESCROW_SHARE_DOMAIN,
        &share.to_bytes(),
    )
}

/// Open one escrow share on the administrator account that received it.
pub fn open_escrow_share_from_account(
    recipient: &AccountKemKeyPair,
    wrapped: &HpkeCiphertext,
) -> Result<ShamirShare, PrimitiveError> {
    let bytes = hpke_open_account(
        recipient,
        &wrapped.encapsulated_key,
        ESCROW_SHARE_DOMAIN,
        ESCROW_SHARE_DOMAIN,
        &wrapped.ciphertext,
    )?;
    ShamirShare::from_bytes(&bytes)
}

/// Re-encrypt one authenticated administrator share to a recovering device.
pub fn rewrap_escrow_share_to_device(
    administrator: &AccountKemKeyPair,
    wrapped: &HpkeCiphertext,
    device_public_key: &[u8],
) -> Result<HpkeCiphertext, PrimitiveError> {
    let share = open_escrow_share_from_account(administrator, wrapped)?;
    hpke_seal_device(device_public_key, ESCROW_SHARE_DOMAIN, ESCROW_SHARE_DOMAIN, &share.to_bytes())
}

/// Open one re-encrypted escrow share on the recovering device.
pub fn open_escrow_share_from_device(
    recipient: &DeviceKemKeyPair,
    wrapped: &HpkeCiphertext,
) -> Result<ShamirShare, PrimitiveError> {
    let bytes = hpke_open_device(
        recipient,
        &wrapped.encapsulated_key,
        ESCROW_SHARE_DOMAIN,
        ESCROW_SHARE_DOMAIN,
        &wrapped.ciphertext,
    )?;
    ShamirShare::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceKemKeyPair, split_shamir_with_randomness};

    #[test]
    fn escrow_share_moves_from_account_to_device_without_reconstructing() {
        let administrator = AccountKemKeyPair::generate().expect("administrator");
        let device = DeviceKemKeyPair::generate().expect("device");
        let share =
            split_shamir_with_randomness(b"root-key", 2, 3, &[9; 8]).expect("split").remove(0);
        let wrapped =
            wrap_escrow_share_to_account(administrator.public_key(), &share).expect("wrap");
        assert_eq!(open_escrow_share_from_account(&administrator, &wrapped).expect("open"), share);
        let rewrapped =
            rewrap_escrow_share_to_device(&administrator, &wrapped, device.public_key())
                .expect("rewrap");
        assert_eq!(open_escrow_share_from_device(&device, &rewrapped).expect("open"), share);
        assert_eq!(
            open_escrow_share_from_account(
                &AccountKemKeyPair::generate().expect("other administrator"),
                &wrapped
            ),
            Err(PrimitiveError::Authentication)
        );
    }

    #[test]
    fn escrow_share_rejects_tampering_before_parsing() {
        let administrator = AccountKemKeyPair::generate().expect("administrator");
        let share =
            split_shamir_with_randomness(&[1, 2, 3], 2, 2, &[4, 5, 6]).expect("split").remove(0);
        let mut wrapped =
            wrap_escrow_share_to_account(administrator.public_key(), &share).expect("wrap");
        wrapped.ciphertext[0] ^= 1;
        assert_eq!(
            open_escrow_share_from_account(&administrator, &wrapped),
            Err(PrimitiveError::Authentication)
        );
    }
}
