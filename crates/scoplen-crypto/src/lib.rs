// SPDX-License-Identifier: Apache-2.0
//! Cryptographic formats shared by Scoplen clients and services.
//!
//! Implementations are kept in this crate so callers do not compose primitives independently.

#![forbid(unsafe_code)]

mod certificate;
mod envelope;
mod hpke;
mod keys;
mod primitives;
mod recovery;
mod secret;
mod shamir;
mod signature;

pub use certificate::{DeviceCertificate, RevocationStatement};
pub use envelope::ObjectEnvelope;
pub use hpke::{
    AccountKemKeyPair, DeviceKemKeyPair, HpkeCiphertext, hpke_open_account, hpke_open_device,
    hpke_seal_account, hpke_seal_device,
};
pub use keys::{
    AccountKeys, AccountRootKey, DeviceKeys, LocalDatabaseKey, LocalDatabaseKeyEnvelope, VaultKey,
    VaultKeyEpoch, generate_account_keys, generate_device_keys, generate_symmetric_key,
    generate_vault_epoch, unwrap_key_from_device, wrap_key_to_device,
};
pub use primitives::{
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST, Argon2idParams, PrimitiveError,
    argon2id_derive, argon2id_derive_with_params, hkdf_sha256, random_bytes, random_key,
    random_nonce, xchacha20poly1305_open, xchacha20poly1305_seal,
};
pub use recovery::safety_number;
pub use recovery::{RecoveryBlob, RecoveryKey};
pub use secret::{SecretBytes, SecretVec, SymmetricKey, XChaChaNonce};
pub use shamir::{ShamirShare, combine_shamir, split_shamir, split_shamir_with_randomness};
pub use signature::{
    Ed25519SigningKey, P256SigningKey, ed25519_verify, generate_ed25519_signing_key,
    generate_p256_signing_key, p256_verify,
};

/// The contract identifier implemented by this crate.
pub const CONTRACT: &str = "K-2";
