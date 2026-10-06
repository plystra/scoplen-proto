// SPDX-License-Identifier: Apache-2.0
//! SSH algorithm lists from K-7 §3, independent of the eventual SSH engine.

use thiserror::Error;

/// An SSH algorithm negotiation category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlgorithmCategory {
    KeyExchange,
    HostKey,
    Cipher,
    Mac,
    Compression,
}

impl AlgorithmCategory {
    const fn index(self) -> usize {
        match self {
            Self::KeyExchange => 0,
            Self::HostKey => 1,
            Self::Cipher => 2,
            Self::Mac => 3,
            Self::Compression => 4,
        }
    }
}

const DEFAULTS: [&[&str]; 5] = [
    &[
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512",
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
    ],
    &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "sk-ssh-ed25519-cert-v01@openssh.com",
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "rsa-sha2-256-cert-v01@openssh.com",
    ],
    &[
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
    ],
    &["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com"],
    &["none", "zlib@openssh.com"],
];

const LEGACY: [&[&str]; 5] = [
    &[
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha256",
    ],
    &["ssh-rsa", "ssh-rsa-cert-v01@openssh.com"],
    &["aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc"],
    &["hmac-sha2-512", "hmac-sha2-256", "hmac-sha1"],
    &["zlib"],
];

/// An invalid per-Host legacy algorithm selection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AlgorithmPolicyError {
    #[error("{algorithm} is not a legacy algorithm in {category:?}")]
    NotLegacy { category: AlgorithmCategory, algorithm: String },
    #[error("{algorithm} is listed more than once in {category:?}")]
    Duplicate { category: AlgorithmCategory, algorithm: String },
}

/// Ordered client offers for one Host. Legacy algorithms are absent unless explicitly enabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAlgorithmPolicy {
    offers: [Vec<&'static str>; 5],
}

impl Default for HostAlgorithmPolicy {
    fn default() -> Self {
        Self { offers: DEFAULTS.map(<[_]>::to_vec) }
    }
}

impl HostAlgorithmPolicy {
    /// Build one Host's offers. Enabling legacy algorithms only appends them after modern defaults.
    /// Unsupported names, algorithms from another category, and duplicate entries fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmPolicyError::NotLegacy`] for a name outside the selected category's
    /// legacy catalog, or [`AlgorithmPolicyError::Duplicate`] for a repeated legacy name.
    pub fn with_legacy(
        algorithms: &[(AlgorithmCategory, &str)],
    ) -> Result<Self, AlgorithmPolicyError> {
        let mut policy = Self::default();
        for &(category, name) in algorithms {
            let index = category.index();
            let Some(&known) = LEGACY[index].iter().find(|&&candidate| candidate == name) else {
                return Err(AlgorithmPolicyError::NotLegacy {
                    category,
                    algorithm: name.to_owned(),
                });
            };
            if policy.offers[index].contains(&known) {
                return Err(AlgorithmPolicyError::Duplicate {
                    category,
                    algorithm: name.to_owned(),
                });
            }
            policy.offers[index].push(known);
        }
        Ok(policy)
    }

    /// Names offered to a peer, in preference order for this Host.
    #[must_use]
    pub fn offers(&self, category: AlgorithmCategory) -> &[&'static str] {
        &self.offers[category.index()]
    }

    /// Select the first local preference also offered by the peer, or `None` if there is no match.
    /// This performs only name selection; the SSH engine still owns the full handshake.
    #[must_use]
    pub fn select_client_preference(
        &self,
        category: AlgorithmCategory,
        peer_offers: &[&str],
    ) -> Option<&'static str> {
        self.offers(category).iter().copied().find(|candidate| peer_offers.contains(candidate))
    }
}
