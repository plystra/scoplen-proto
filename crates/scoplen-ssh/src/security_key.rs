// SPDX-License-Identifier: Apache-2.0
//! Engine-independent FIDO2 security-key authentication for SSH.
//!
//! The platform implementation owns the authenticator handle and performs the actual FIDO2
//! operation. This module owns the OpenSSH `sk-` public-key and signature formats, the
//! RFC 4252 session binding, and the checks that keep authenticator results inside the protocol
//! boundary.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use thiserror::Error;

use crate::authentication::{
    PublicKeyAuthContext, publickey_signature_payload, read_string, write_string,
};

const MAX_APPLICATION: usize = 1024;
const MAX_PUBLIC_KEY_BLOB: usize = 64 * 1024;
const MAX_SIGNATURE_BLOB: usize = 64 * 1024;
const MAX_SIGNATURE_COMPONENT: usize = 33;

/// FIDO2 SSH security-key algorithms supported by K-7.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityKeyAlgorithm {
    /// `sk-ssh-ed25519@openssh.com`.
    Ed25519,
    /// `sk-ecdsa-sha2-nistp256@openssh.com`.
    EcdsaSha2Nistp256,
}

impl SecurityKeyAlgorithm {
    /// Return the OpenSSH public-key and signature algorithm identifier.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "sk-ssh-ed25519@openssh.com",
            Self::EcdsaSha2Nistp256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"sk-ssh-ed25519@openssh.com" => Some(Self::Ed25519),
            b"sk-ecdsa-sha2-nistp256@openssh.com" => Some(Self::EcdsaSha2Nistp256),
            _ => None,
        }
    }
}

/// Errors returned by security-key format validation or a platform provider.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SecurityKeyError {
    /// The authenticator application is empty, too long, or contains a NUL byte.
    #[error("invalid security-key application")]
    InvalidApplication,
    /// The authenticator application exceeded the protocol limit.
    #[error("security-key application is too long")]
    ApplicationTooLong,
    /// The security-key public-key blob is malformed.
    #[error("invalid security-key public key: {0}")]
    InvalidPublicKey(&'static str),
    /// The security-key algorithm is not supported by this boundary.
    #[error("unsupported security-key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// A bounded SSH string or signature wrapper could not be encoded.
    #[error("invalid security-key wire encoding")]
    InvalidEncoding,
    /// The authenticator returned an empty signature.
    #[error("security-key provider returned an empty signature")]
    EmptySignature,
    /// The authenticator signature exceeded the protocol limit.
    #[error("security-key signature is too large")]
    SignatureTooLarge,
    /// The algorithm-specific signature encoding is malformed.
    #[error("invalid security-key signature: {0}")]
    InvalidSignature(&'static str),
    /// The authenticator returned reserved flag bits.
    #[error("security-key returned invalid flags: {0:#04x}")]
    InvalidFlags(u8),
    /// A requested user-presence or user-verification requirement was not met.
    #[error(
        "security-key requirements were not met (required {required:#04x}, received {received:#04x})"
    )]
    RequirementsNotMet { required: u8, received: u8 },
    /// The provider's key did not match the identity being signed.
    #[error("security-key provider identity does not match the request")]
    IdentityMismatch,
    /// The provider's algorithm did not match the identity being signed.
    #[error("security-key provider algorithm does not match the request")]
    AlgorithmMismatch,
    /// The provider cannot discover resident credentials.
    #[error("security-key resident-key discovery is unavailable")]
    ResidentKeyDiscoveryUnavailable,
    /// The platform provider failed without exposing private authenticator details.
    #[error("security-key provider failed: {0}")]
    Provider(String),
}

/// User-presence and user-verification requirements for a security-key operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityKeySignOptions {
    require_user_presence: bool,
    require_user_verification: bool,
}

impl SecurityKeySignOptions {
    /// Create explicit user-presence and user-verification requirements.
    #[must_use]
    pub const fn new(require_user_presence: bool, require_user_verification: bool) -> Self {
        Self { require_user_presence, require_user_verification }
    }

    /// Return the default OpenSSH requirement: user presence is required.
    #[must_use]
    pub const fn user_presence() -> Self {
        Self::new(true, false)
    }

    /// Return an option set requiring both user presence and verification.
    #[must_use]
    pub const fn user_presence_and_verification() -> Self {
        Self::new(true, true)
    }

    /// Return whether user presence is required.
    #[must_use]
    pub const fn require_user_presence(self) -> bool {
        self.require_user_presence
    }

    /// Return whether user verification is required.
    #[must_use]
    pub const fn require_user_verification(self) -> bool {
        self.require_user_verification
    }

    const fn required_flags(self) -> u8 {
        (if self.require_user_presence { USER_PRESENCE } else { 0 })
            | (if self.require_user_verification { USER_VERIFICATION } else { 0 })
    }
}

impl Default for SecurityKeySignOptions {
    fn default() -> Self {
        Self::user_presence()
    }
}

/// The public identity of an SSH security key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityKeyPublicKey {
    algorithm: SecurityKeyAlgorithm,
    key: Vec<u8>,
    application: String,
}

impl SecurityKeyPublicKey {
    /// Construct and validate a security-key identity.
    pub fn new(
        algorithm: SecurityKeyAlgorithm,
        key: impl Into<Vec<u8>>,
        application: impl Into<String>,
    ) -> Result<Self, SecurityKeyError> {
        let key = key.into();
        validate_public_key(algorithm, &key)?;
        let application = validate_application(application.into())?;
        Ok(Self { algorithm, key, application })
    }

    /// Decode an OpenSSH `sk-` public-key blob.
    pub fn from_blob(blob: &[u8]) -> Result<Self, SecurityKeyError> {
        if blob.is_empty() || blob.len() > MAX_PUBLIC_KEY_BLOB {
            return Err(SecurityKeyError::InvalidPublicKey("public-key blob size"));
        }
        let (algorithm, rest) = bounded_string(blob)?;
        let algorithm = SecurityKeyAlgorithm::from_name(algorithm)
            .ok_or_else(|| SecurityKeyError::UnsupportedAlgorithm(display_bytes(algorithm)))?;
        let key = match algorithm {
            SecurityKeyAlgorithm::Ed25519 => {
                let (key, rest) = bounded_string(rest)?;
                let (application, trailing) = bounded_string(rest)?;
                if !trailing.is_empty() {
                    return Err(SecurityKeyError::InvalidPublicKey("trailing public-key data"));
                }
                (key.to_vec(), application)
            }
            SecurityKeyAlgorithm::EcdsaSha2Nistp256 => {
                let (curve, rest) = bounded_string(rest)?;
                if curve != b"nistp256" {
                    return Err(SecurityKeyError::InvalidPublicKey("unsupported ECDSA curve"));
                }
                let (key, rest) = bounded_string(rest)?;
                let (application, trailing) = bounded_string(rest)?;
                if !trailing.is_empty() {
                    return Err(SecurityKeyError::InvalidPublicKey("trailing public-key data"));
                }
                (key.to_vec(), application)
            }
        };
        Self::new(algorithm, key.0, decode_application(key.1)?)
    }

    /// Encode the canonical OpenSSH `sk-` public-key blob.
    pub fn to_blob(&self) -> Result<Vec<u8>, SecurityKeyError> {
        let mut blob = Vec::new();
        append_string(&mut blob, self.algorithm.name().as_bytes())?;
        if self.algorithm == SecurityKeyAlgorithm::EcdsaSha2Nistp256 {
            append_string(&mut blob, b"nistp256")?;
        }
        append_string(&mut blob, &self.key)?;
        append_string(&mut blob, self.application.as_bytes())?;
        Ok(blob)
    }

    /// Return the key algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SecurityKeyAlgorithm {
        self.algorithm
    }

    /// Return the raw security-key public key bytes.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Return the FIDO2 application (OpenSSH's relying-party application string).
    #[must_use]
    pub fn application(&self) -> &str {
        &self.application
    }
}

/// A validated algorithm-specific security-key signature result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityKeySignature {
    algorithm: SecurityKeyAlgorithm,
    signature: Vec<u8>,
    flags: u8,
    counter: u32,
}

impl SecurityKeySignature {
    /// Construct a signature returned by a platform provider.
    pub fn new(
        algorithm: SecurityKeyAlgorithm,
        signature: impl Into<Vec<u8>>,
        flags: u8,
        counter: u32,
    ) -> Result<Self, SecurityKeyError> {
        let signature = signature.into();
        validate_flags(flags)?;
        validate_signature(algorithm, &signature)?;
        Ok(Self { algorithm, signature, flags, counter })
    }

    /// Decode the SSH `sk-` signature body (`string signature`, flags, counter).
    pub fn from_ssh_blob(
        algorithm: SecurityKeyAlgorithm,
        blob: &[u8],
    ) -> Result<Self, SecurityKeyError> {
        if blob.len() > MAX_SIGNATURE_BLOB {
            return Err(SecurityKeyError::SignatureTooLarge);
        }
        let (signature, rest) = bounded_string(blob)?;
        let flags = *rest.first().ok_or(SecurityKeyError::InvalidEncoding)?;
        let counter_bytes = rest.get(1..5).ok_or(SecurityKeyError::InvalidEncoding)?;
        if rest.len() != 5 {
            return Err(SecurityKeyError::InvalidEncoding);
        }
        let counter_bytes: [u8; 4] =
            counter_bytes.try_into().map_err(|_| SecurityKeyError::InvalidEncoding)?;
        Self::new(
            algorithm,
            signature,
            flags,
            u32::from_be_bytes(counter_bytes),
        )
    }

    /// Encode the SSH `sk-` signature body (`string signature`, flags, counter).
    pub fn to_ssh_blob(&self) -> Result<Vec<u8>, SecurityKeyError> {
        let mut blob = Vec::new();
        append_string(&mut blob, &self.signature)?;
        blob.push(self.flags);
        blob.extend_from_slice(&self.counter.to_be_bytes());
        Ok(blob)
    }

    /// Return the algorithm used by this signature.
    #[must_use]
    pub const fn algorithm(&self) -> SecurityKeyAlgorithm {
        self.algorithm
    }

    /// Return the algorithm-specific signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Return the authenticator data flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Return the authenticator signature counter.
    #[must_use]
    pub const fn counter(&self) -> u32 {
        self.counter
    }

    /// Check the requested user-presence and user-verification requirements.
    pub fn enforce(&self, options: SecurityKeySignOptions) -> Result<(), SecurityKeyError> {
        let required = options.required_flags();
        if self.flags & required != required {
            return Err(SecurityKeyError::RequirementsNotMet { required, received: self.flags });
        }
        Ok(())
    }
}

/// Platform boundary for FIDO2 security keys.
pub trait SecurityKeyProvider {
    /// Return the algorithm handled by this provider.
    fn algorithm(&self) -> SecurityKeyAlgorithm;

    /// Return the public identity of the selected authenticator credential.
    fn public_key(&self) -> Result<SecurityKeyPublicKey, SecurityKeyError>;

    /// Discover resident credentials for an OpenSSH application string.
    fn discover(&self, application: &str) -> Result<Vec<SecurityKeyPublicKey>, SecurityKeyError>;

    /// Sign the exact RFC 4252 payload for the given application.
    fn sign(
        &self,
        application: &str,
        message: &[u8],
        options: SecurityKeySignOptions,
    ) -> Result<SecurityKeySignature, SecurityKeyError>;
}

/// An RFC 4252 `publickey` request backed by an SSH security key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityKeyAuthRequest {
    context: PublicKeyAuthContext,
    identity: SecurityKeyPublicKey,
    signature: Option<Vec<u8>>,
}

impl SecurityKeyAuthRequest {
    /// Build an unsigned security-key probe request.
    pub fn probe(
        context: PublicKeyAuthContext,
        identity: SecurityKeyPublicKey,
    ) -> Result<Self, SecurityKeyError> {
        Ok(Self { context, identity, signature: None })
    }

    /// Build a signed RFC 4252 request and enforce authenticator flags.
    pub fn signed<P: SecurityKeyProvider + ?Sized>(
        context: PublicKeyAuthContext,
        identity: SecurityKeyPublicKey,
        provider: &P,
        options: SecurityKeySignOptions,
    ) -> Result<Self, SecurityKeyError> {
        if provider.algorithm() != identity.algorithm() {
            return Err(SecurityKeyError::AlgorithmMismatch);
        }
        if provider.public_key()? != identity {
            return Err(SecurityKeyError::IdentityMismatch);
        }
        let key_blob = identity.to_blob()?;
        let payload = publickey_signature_payload(&context, identity.algorithm().name(), &key_blob);
        let signature = provider.sign(identity.application(), &payload, options)?;
        if signature.algorithm() != identity.algorithm() {
            return Err(SecurityKeyError::AlgorithmMismatch);
        }
        signature.enforce(options)?;
        let mut outer = Vec::new();
        append_string(&mut outer, identity.algorithm().name().as_bytes())?;
        append_string(&mut outer, &signature.to_ssh_blob()?)?;
        Ok(Self { context, identity, signature: Some(outer) })
    }

    /// Return whether the request carries a signature.
    #[must_use]
    pub fn has_signature(&self) -> bool {
        self.signature.is_some()
    }

    /// Return the security-key identity offered to the server.
    #[must_use]
    pub const fn identity(&self) -> &SecurityKeyPublicKey {
        &self.identity
    }

    /// Return the outer SSH signature blob, if signed.
    #[must_use]
    pub fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }

    /// Return the exact RFC 4252 session-bound bytes sent to the authenticator.
    #[must_use]
    pub fn signature_payload(&self) -> Vec<u8> {
        let key_blob = self.identity.to_blob().expect("validated security-key identity");
        publickey_signature_payload(&self.context, self.identity.algorithm().name(), &key_blob)
    }

    /// Encode the `SSH_MSG_USERAUTH_REQUEST` payload, excluding packet framing and MAC.
    pub fn encode(&self) -> Result<Vec<u8>, SecurityKeyError> {
        let key_blob = self.identity.to_blob()?;
        let mut encoded = Vec::new();
        encoded.push(50);
        append_string(&mut encoded, self.context.username().as_bytes())?;
        append_string(&mut encoded, self.context.service().as_bytes())?;
        append_string(&mut encoded, b"publickey")?;
        encoded.push(u8::from(self.has_signature()));
        append_string(&mut encoded, self.identity.algorithm().name().as_bytes())?;
        append_string(&mut encoded, &key_blob)?;
        if let Some(signature) = &self.signature {
            append_string(&mut encoded, signature)?;
        }
        Ok(encoded)
    }
}

const USER_PRESENCE: u8 = 0x01;
const USER_VERIFICATION: u8 = 0x04;
const KNOWN_FLAGS: u8 = 0xDD;

fn validate_public_key(
    algorithm: SecurityKeyAlgorithm,
    key: &[u8],
) -> Result<(), SecurityKeyError> {
    match algorithm {
        SecurityKeyAlgorithm::Ed25519 if key.len() != 32 => {
            Err(SecurityKeyError::InvalidPublicKey("Ed25519 key must be 32 bytes"))
        }
        SecurityKeyAlgorithm::EcdsaSha2Nistp256
            if key.len() != 65 || key.first().copied() != Some(0x04) =>
        {
            Err(SecurityKeyError::InvalidPublicKey("P-256 key must be an uncompressed SEC1 point"))
        }
        _ => Ok(()),
    }
}

fn validate_application(application: String) -> Result<String, SecurityKeyError> {
    if application.is_empty() {
        return Err(SecurityKeyError::InvalidApplication);
    }
    if application.len() > MAX_APPLICATION {
        return Err(SecurityKeyError::ApplicationTooLong);
    }
    if application.contains('\0') {
        return Err(SecurityKeyError::InvalidApplication);
    }
    Ok(application)
}

fn decode_application(application: &[u8]) -> Result<String, SecurityKeyError> {
    String::from_utf8(application.to_vec()).map_err(|_| SecurityKeyError::InvalidApplication)
}

fn validate_flags(flags: u8) -> Result<(), SecurityKeyError> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(SecurityKeyError::InvalidFlags(flags));
    }
    Ok(())
}

fn validate_signature(
    algorithm: SecurityKeyAlgorithm,
    signature: &[u8],
) -> Result<(), SecurityKeyError> {
    if signature.is_empty() {
        return Err(SecurityKeyError::EmptySignature);
    }
    if signature.len() > MAX_SIGNATURE_BLOB {
        return Err(SecurityKeyError::SignatureTooLarge);
    }
    match algorithm {
        SecurityKeyAlgorithm::Ed25519 if signature.len() != 64 => {
            Err(SecurityKeyError::InvalidSignature("Ed25519 signature must be 64 bytes"))
        }
        SecurityKeyAlgorithm::Ed25519 => Ok(()),
        SecurityKeyAlgorithm::EcdsaSha2Nistp256 => validate_ecdsa_signature(signature),
    }
}

fn validate_ecdsa_signature(signature: &[u8]) -> Result<(), SecurityKeyError> {
    let (r, rest) = bounded_string(signature)?;
    let (s, trailing) = bounded_string(rest)?;
    if !trailing.is_empty() {
        return Err(SecurityKeyError::InvalidSignature("trailing ECDSA signature data"));
    }
    validate_mpint(r)?;
    validate_mpint(s)
}

fn validate_mpint(value: &[u8]) -> Result<(), SecurityKeyError> {
    if value.is_empty() || value.len() > MAX_SIGNATURE_COMPONENT {
        return Err(SecurityKeyError::InvalidSignature("invalid ECDSA mpint length"));
    }
    if value[0] & 0x80 != 0 {
        return Err(SecurityKeyError::InvalidSignature("negative ECDSA mpint"));
    }
    if value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        return Err(SecurityKeyError::InvalidSignature("non-canonical ECDSA mpint"));
    }
    if value.iter().all(|byte| *byte == 0) {
        return Err(SecurityKeyError::InvalidSignature("zero ECDSA mpint"));
    }
    Ok(())
}

fn append_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SecurityKeyError> {
    write_string(output, value).map_err(|_| SecurityKeyError::InvalidEncoding)
}

fn bounded_string(input: &[u8]) -> Result<(&[u8], &[u8]), SecurityKeyError> {
    let (value, rest) = read_string(input).ok_or(SecurityKeyError::InvalidEncoding)?;
    if value.len() > MAX_PUBLIC_KEY_BLOB {
        return Err(SecurityKeyError::InvalidEncoding);
    }
    Ok((value, rest))
}

fn display_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoplen_crypto::{Ed25519SigningKey, P256SigningKey, ed25519_verify, p256_verify};

    fn mpint(value: &[u8]) -> Vec<u8> {
        let first_nonzero = value.iter().position(|byte| *byte != 0).unwrap_or(value.len());
        let mut value =
            if first_nonzero == value.len() { vec![0] } else { value[first_nonzero..].to_vec() };
        if value[0] & 0x80 != 0 {
            value.insert(0, 0);
        }
        value
    }

    fn ecdsa_signature(key: &P256SigningKey, message: &[u8]) -> Vec<u8> {
        let signature = key.sign(message);
        let mut encoded = Vec::new();
        append_string(&mut encoded, &mpint(&signature[..32])).expect("r");
        append_string(&mut encoded, &mpint(&signature[32..])).expect("s");
        encoded
    }

    struct EdProvider {
        key: Ed25519SigningKey,
        application: String,
        flags: u8,
    }

    impl SecurityKeyProvider for EdProvider {
        fn algorithm(&self) -> SecurityKeyAlgorithm {
            SecurityKeyAlgorithm::Ed25519
        }

        fn public_key(&self) -> Result<SecurityKeyPublicKey, SecurityKeyError> {
            SecurityKeyPublicKey::new(
                self.algorithm(),
                self.key.public_key().to_vec(),
                self.application.clone(),
            )
        }

        fn discover(
            &self,
            application: &str,
        ) -> Result<Vec<SecurityKeyPublicKey>, SecurityKeyError> {
            if application != self.application {
                return Ok(Vec::new());
            }
            Ok(vec![self.public_key()?])
        }

        fn sign(
            &self,
            application: &str,
            message: &[u8],
            _options: SecurityKeySignOptions,
        ) -> Result<SecurityKeySignature, SecurityKeyError> {
            if application != self.application {
                return Err(SecurityKeyError::InvalidApplication);
            }
            SecurityKeySignature::new(
                self.algorithm(),
                self.key.sign(message).to_vec(),
                self.flags,
                7,
            )
        }
    }

    #[test]
    fn public_key_blob_round_trips_and_is_strictly_bounded() {
        let identity =
            SecurityKeyPublicKey::new(SecurityKeyAlgorithm::Ed25519, [9; 32], "ssh:scoplen")
                .expect("identity");
        let blob = identity.to_blob().expect("blob");
        assert_eq!(SecurityKeyPublicKey::from_blob(&blob).expect("round trip"), identity);

        let mut trailing = blob.clone();
        trailing.push(1);
        assert_eq!(
            SecurityKeyPublicKey::from_blob(&trailing),
            Err(SecurityKeyError::InvalidPublicKey("trailing public-key data"))
        );

        assert_eq!(
            SecurityKeyPublicKey::new(SecurityKeyAlgorithm::Ed25519, [9; 31], "ssh:scoplen"),
            Err(SecurityKeyError::InvalidPublicKey("Ed25519 key must be 32 bytes"))
        );
        assert_eq!(
            SecurityKeyPublicKey::new(SecurityKeyAlgorithm::Ed25519, [9; 32], ""),
            Err(SecurityKeyError::InvalidApplication)
        );
    }

    #[test]
    fn signed_request_binds_session_identity_application_flags_and_counter() {
        let provider = EdProvider {
            key: Ed25519SigningKey::from_bytes(&[9; 32]).expect("key"),
            application: "ssh:scoplen".into(),
            flags: USER_PRESENCE | USER_VERIFICATION,
        };
        let identity = provider.public_key().expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        let request = SecurityKeyAuthRequest::signed(
            context,
            identity.clone(),
            &provider,
            SecurityKeySignOptions::user_presence_and_verification(),
        )
        .expect("signed request");
        let outer = request.signature().expect("signature");
        let (algorithm, rest) = read_string(outer).expect("algorithm");
        let (body, trailing) = read_string(rest).expect("body");
        assert!(trailing.is_empty());
        assert_eq!(algorithm, identity.algorithm().name().as_bytes());
        let decoded = SecurityKeySignature::from_ssh_blob(identity.algorithm(), body)
            .expect("signature body");
        assert_eq!(decoded.flags(), USER_PRESENCE | USER_VERIFICATION);
        assert_eq!(decoded.counter(), 7);
        ed25519_verify(identity.key(), &request.signature_payload(), decoded.signature())
            .expect("signature verifies");
        assert!(request.encode().expect("wire").starts_with(&[50]));
    }

    #[test]
    fn requirements_and_reserved_flags_are_rejected() {
        let signature =
            SecurityKeySignature::new(SecurityKeyAlgorithm::Ed25519, [7; 64], USER_VERIFICATION, 1)
                .expect("signature");
        assert_eq!(
            signature.enforce(SecurityKeySignOptions::user_presence()),
            Err(SecurityKeyError::RequirementsNotMet {
                required: USER_PRESENCE,
                received: USER_VERIFICATION,
            })
        );
        assert_eq!(
            SecurityKeySignature::new(SecurityKeyAlgorithm::Ed25519, [7; 64], 0x02, 1),
            Err(SecurityKeyError::InvalidFlags(0x02))
        );
    }

    #[test]
    fn provider_identity_and_algorithm_mismatches_fail_closed() {
        let provider = EdProvider {
            key: Ed25519SigningKey::from_bytes(&[9; 32]).expect("key"),
            application: "ssh:scoplen".into(),
            flags: USER_PRESENCE,
        };
        let identity =
            SecurityKeyPublicKey::new(SecurityKeyAlgorithm::Ed25519, [8; 32], "ssh:scoplen")
                .expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        assert_eq!(
            SecurityKeyAuthRequest::signed(
                context.clone(),
                identity,
                &provider,
                SecurityKeySignOptions::default(),
            ),
            Err(SecurityKeyError::IdentityMismatch)
        );

        let ecdsa = SecurityKeyPublicKey::new(
            SecurityKeyAlgorithm::EcdsaSha2Nistp256,
            P256SigningKey::from_bytes(&[1; 32]).expect("key").public_key_sec1(),
            "ssh:scoplen",
        )
        .expect("ECDSA identity");
        assert_eq!(
            SecurityKeyAuthRequest::signed(
                context,
                ecdsa,
                &provider,
                SecurityKeySignOptions::default(),
            ),
            Err(SecurityKeyError::AlgorithmMismatch)
        );
    }

    #[test]
    fn ecdsa_security_key_signature_uses_ssh_mpints_and_verifies() {
        let key = P256SigningKey::from_bytes(&[1; 32]).expect("key");
        let message = b"security-key payload";
        let signature = SecurityKeySignature::new(
            SecurityKeyAlgorithm::EcdsaSha2Nistp256,
            ecdsa_signature(&key, message),
            USER_PRESENCE,
            3,
        )
        .expect("signature");
        let blob = signature.to_ssh_blob().expect("wire");
        let decoded =
            SecurityKeySignature::from_ssh_blob(SecurityKeyAlgorithm::EcdsaSha2Nistp256, &blob)
                .expect("decoded");
        let (r, rest) = read_string(decoded.signature()).expect("r");
        let (s, trailing) = read_string(rest).expect("s");
        assert!(trailing.is_empty());
        let mut fixed = [0; 64];
        let r = r.strip_prefix(&[0]).unwrap_or(r);
        let s = s.strip_prefix(&[0]).unwrap_or(s);
        fixed[32 - r.len()..32].copy_from_slice(r);
        fixed[64 - s.len()..].copy_from_slice(s);
        p256_verify(&key.public_key_sec1(), message, &fixed).expect("verify");
    }

    #[test]
    fn resident_discovery_is_application_scoped() {
        let provider = EdProvider {
            key: Ed25519SigningKey::from_bytes(&[9; 32]).expect("key"),
            application: "ssh:scoplen".into(),
            flags: USER_PRESENCE,
        };
        assert_eq!(provider.discover("ssh:other").expect("discovery"), Vec::new());
        assert_eq!(provider.discover("ssh:scoplen").expect("discovery").len(), 1);
    }
}
