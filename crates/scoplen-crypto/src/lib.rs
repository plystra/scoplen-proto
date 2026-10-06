// SPDX-License-Identifier: Apache-2.0
//! Cryptographic formats shared by Scoplen clients and services.
//!
//! Implementations are kept in this crate so callers do not compose primitives independently.

#![forbid(unsafe_code)]

mod hpke;
mod primitives;
mod secret;
mod signature;

pub use hpke::{
    AccountKemKeyPair, DeviceKemKeyPair, HpkeCiphertext, hpke_open_account, hpke_open_device,
    hpke_seal_account, hpke_seal_device,
};
pub use primitives::{
    ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_TIME_COST, PrimitiveError, argon2id_derive,
    hkdf_sha256, random_bytes, random_key, random_nonce, xchacha20poly1305_open,
    xchacha20poly1305_seal,
};
pub use secret::{SecretBytes, SecretVec, SymmetricKey, XChaChaNonce};
pub use signature::{
    Ed25519SigningKey, P256SigningKey, ed25519_verify, generate_ed25519_signing_key,
    generate_p256_signing_key, p256_verify,
};

/// The contract identifier implemented by this crate.
pub const CONTRACT: &str = "K-2";
