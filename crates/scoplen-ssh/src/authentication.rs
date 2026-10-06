// SPDX-License-Identifier: Apache-2.0
//! Engine-independent SSH authentication and certificate validation.
//!
//! The types in this module deliberately stop at the RFC 4252 message boundary. An SSH engine
//! supplies the session identifier and sends [`PublicKeyAuthRequest::encode`]; it does not need
//! access to private key material. Concrete engine integration, keyboard-interactive prompts,
//! passwords, and agent transports are separate outcomes in K-7.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{collections::BTreeSet, net::IpAddr};

use scoplen_crypto::{Ed25519SigningKey, P256SigningKey, PrimitiveError};
use ssh_key::{Certificate, PublicKey};
use thiserror::Error;

const USERAUTH_REQUEST: u8 = 50;
const USERAUTH_METHOD: &[u8] = b"publickey";
const MAX_SESSION_ID: usize = 1024;
const MAX_FIELD: usize = 4096;
const MAX_KEY_BLOB: usize = 64 * 1024;
const MAX_CERTIFICATE: usize = 64 * 1024;
const MAX_SIGNATURE: usize = 64 * 1024;
const FORCE_COMMAND: &str = "force-command";
const SOURCE_ADDRESS: &str = "source-address";

/// SSH signature algorithms supported by this authentication boundary.
///
/// RSA signature selection and FIDO `sk-` algorithms remain a separate outcome because SSH uses
/// the `ssh-rsa` key algorithm with an independent `rsa-sha2-*` signature algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignatureAlgorithm {
    /// Ed25519 (`ssh-ed25519`).
    Ed25519,
    /// ECDSA over NIST P-256 (`ecdsa-sha2-nistp256`).
    EcdsaSha2Nistp256,
}

impl SignatureAlgorithm {
    /// Return the SSH algorithm identifier used for a raw public key and signature.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256",
        }
    }

    /// Return the OpenSSH certificate algorithm identifier for this key algorithm.
    #[must_use]
    pub const fn certificate_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519-cert-v01@openssh.com",
            Self::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" | "ssh-ed25519-cert-v01@openssh.com" => Some(Self::Ed25519),
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp256-cert-v01@openssh.com" => {
                Some(Self::EcdsaSha2Nistp256)
            }
            _ => None,
        }
    }

    fn accepts_identity(self, identity: &str) -> bool {
        identity == self.name() || identity == self.certificate_name()
    }
}

/// Errors produced by a key signer or a malformed signer identity.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignerError {
    /// The signer returned an empty public-key blob.
    #[error("signer returned an empty public-key blob")]
    EmptyPublicKey,
    /// The signer returned an empty signature blob.
    #[error("signer returned an empty signature blob")]
    EmptySignature,
    /// The signer algorithm does not match the offered identity.
    #[error("signer algorithm {signer} does not match identity {identity}")]
    AlgorithmMismatch { signer: String, identity: String },
    /// The underlying key provider could not sign.
    #[error("signing failed: {0}")]
    Signing(String),
    /// A field supplied to the SSH boundary is invalid.
    #[error("invalid signer input: {0}")]
    InvalidInput(&'static str),
}

impl From<PrimitiveError> for SignerError {
    fn from(error: PrimitiveError) -> Self {
        Self::Signing(error.to_string())
    }
}

/// A private-key provider used by public-key authentication.
pub trait Signer {
    /// Return the raw SSH algorithm used by the private key.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Return the RFC 4253 public-key blob, including its algorithm name.
    ///
    /// The blob may come from an agent, platform keystore, or security key. Private material is
    /// never returned through this trait.
    fn public_key_blob(&self) -> Result<Vec<u8>, SignerError>;

    /// Sign the exact RFC 4252 session-bound payload and return the algorithm-specific signature
    /// blob. The outer `string(algorithm) || string(signature)` wrapper is added by this crate.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// A validated SSH public-key identity used in an authentication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyIdentity {
    algorithm: String,
    key_blob: Vec<u8>,
    signing_key_blob: Vec<u8>,
}

impl PublicKeyIdentity {
    /// Create an identity from a canonical SSH algorithm name and key blob.
    ///
    /// The first SSH string in `key_blob` must equal `algorithm`. This prevents an algorithm
    /// substitution between the probe and signed request.
    pub fn new(
        algorithm: impl Into<String>,
        key_blob: impl Into<Vec<u8>>,
    ) -> Result<Self, SignerError> {
        let algorithm = algorithm.into();
        if SignatureAlgorithm::from_name(&algorithm).is_none() {
            return Err(SignerError::InvalidInput("unsupported SSH public-key algorithm"));
        }
        let key_blob = key_blob.into();
        if key_blob.is_empty() || key_blob.len() > MAX_KEY_BLOB {
            return Err(SignerError::EmptyPublicKey);
        }
        let (encoded_algorithm, _) = read_string(&key_blob)
            .ok_or(SignerError::InvalidInput("public-key blob is not an SSH string sequence"))?;
        if encoded_algorithm != algorithm.as_bytes() {
            return Err(SignerError::InvalidInput("public-key blob algorithm mismatch"));
        }
        let parsed = PublicKey::from_bytes(&key_blob)
            .map_err(|_| SignerError::InvalidInput("malformed SSH public-key blob"))?;
        let parsed_algorithm = parsed.key_data().certificate().map_or_else(
            || parsed.algorithm().as_str().to_owned(),
            |certificate| certificate.algorithm().to_certificate_type(),
        );
        if parsed_algorithm != algorithm {
            return Err(SignerError::InvalidInput("public-key algorithm does not match key data"));
        }
        let key_blob = parsed
            .to_bytes()
            .map_err(|_| SignerError::InvalidInput("malformed SSH public-key blob"))?;
        Ok(Self { algorithm, signing_key_blob: key_blob.clone(), key_blob })
    }

    fn for_certificate(
        algorithm: impl Into<String>,
        key_blob: impl Into<Vec<u8>>,
        signing_key_blob: impl Into<Vec<u8>>,
    ) -> Result<Self, SignerError> {
        let algorithm = algorithm.into();
        let key_blob = key_blob.into();
        let signing_key_blob = signing_key_blob.into();
        if key_blob.len() > MAX_KEY_BLOB || signing_key_blob.len() > MAX_KEY_BLOB {
            return Err(SignerError::InvalidInput("SSH public-key blob is too large"));
        }
        let identity = Self::new(algorithm, key_blob)?;
        let signer_key = PublicKey::from_bytes(&signing_key_blob)
            .map_err(|_| SignerError::InvalidInput("malformed certificate subject key"))?;
        let signing_key_blob = signer_key
            .to_bytes()
            .map_err(|_| SignerError::InvalidInput("malformed certificate subject key"))?;
        Ok(Self { signing_key_blob, ..identity })
    }

    /// Construct a raw identity from a signer.
    pub fn from_signer<S: Signer + ?Sized>(signer: &S) -> Result<Self, SignerError> {
        Self::new(signer.algorithm().name(), signer.public_key_blob()?)
    }

    /// Return the SSH algorithm identifier.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Return the RFC 4253 public-key blob.
    #[must_use]
    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }

    /// Return the raw subject key which must match the private signer.
    #[must_use]
    pub fn signing_key_blob(&self) -> &[u8] {
        &self.signing_key_blob
    }
}

/// Session-bound data used to sign an SSH public-key authentication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyAuthContext {
    session_id: Vec<u8>,
    username: String,
    service: String,
}

impl PublicKeyAuthContext {
    /// Create a context from the SSH exchange hash, username, and service name.
    pub fn new(
        session_id: impl Into<Vec<u8>>,
        username: impl Into<String>,
        service: impl Into<String>,
    ) -> Result<Self, SignerError> {
        let session_id = session_id.into();
        let username = username.into();
        let service = service.into();
        if session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
            return Err(SignerError::InvalidInput("invalid SSH session identifier"));
        }
        validate_text_field(&username, "username")?;
        validate_text_field(&service, "service")?;
        Ok(Self { session_id, username, service })
    }

    /// Return the exchange hash used as the signature's session binding.
    #[must_use]
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Return the SSH username.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Return the SSH service name.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

/// An RFC 4252 `publickey` authentication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyAuthRequest {
    context: PublicKeyAuthContext,
    identity: PublicKeyIdentity,
    signature: Option<Vec<u8>>,
}

impl PublicKeyAuthRequest {
    /// Build an unsigned public-key probe request.
    pub fn probe(
        context: PublicKeyAuthContext,
        identity: PublicKeyIdentity,
    ) -> Result<Self, SignerError> {
        Ok(Self { context, identity, signature: None })
    }

    /// Build a signed public-key request using the session-bound RFC 4252 payload.
    pub fn signed<S: Signer + ?Sized>(
        context: PublicKeyAuthContext,
        identity: PublicKeyIdentity,
        signer: &S,
    ) -> Result<Self, SignerError> {
        if !signer.algorithm().accepts_identity(identity.algorithm()) {
            return Err(SignerError::AlgorithmMismatch {
                signer: signer.algorithm().name().to_owned(),
                identity: identity.algorithm().to_owned(),
            });
        }
        let signer_key = signer.public_key_blob()?;
        let signer_key = PublicKey::from_bytes(&signer_key)
            .map_err(|_| SignerError::InvalidInput("signer returned malformed public-key blob"))?
            .to_bytes()
            .map_err(|_| SignerError::InvalidInput("signer returned malformed public-key blob"))?;
        if signer_key != identity.signing_key_blob {
            return Err(SignerError::InvalidInput("signer key does not match public-key identity"));
        }
        let identity_algorithm = identity.algorithm().to_owned();
        let unsigned = Self::probe(context, identity)?;
        let signature_payload = unsigned.signature_payload();
        let signature_blob = signer.sign(&signature_payload)?;
        if signature_blob.is_empty() {
            return Err(SignerError::EmptySignature);
        }
        if signature_blob.len() > MAX_SIGNATURE {
            return Err(SignerError::InvalidInput("SSH signature blob is too large"));
        }
        let mut signature =
            Vec::with_capacity(4 + identity_algorithm.len() + 4 + signature_blob.len());
        write_string(&mut signature, identity_algorithm.as_bytes())?;
        write_string(&mut signature, &signature_blob)?;
        Ok(Self { signature: Some(signature), ..unsigned })
    }

    /// Return whether this request carries a signature.
    #[must_use]
    pub fn has_signature(&self) -> bool {
        self.signature.is_some()
    }

    /// Return the identity offered to the server.
    #[must_use]
    pub fn identity(&self) -> &PublicKeyIdentity {
        &self.identity
    }

    /// Return the outer SSH signature blob, if this is a signed request.
    #[must_use]
    pub fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }

    /// Return the exact bytes signed by [`Signer::sign`].
    #[must_use]
    pub fn signature_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        write_string(&mut payload, &self.context.session_id).expect("bounded session id");
        payload.push(USERAUTH_REQUEST);
        write_string(&mut payload, self.context.username.as_bytes()).expect("bounded username");
        write_string(&mut payload, self.context.service.as_bytes()).expect("bounded service");
        write_string(&mut payload, USERAUTH_METHOD).expect("static method");
        payload.push(1);
        write_string(&mut payload, self.identity.algorithm().as_bytes())
            .expect("bounded algorithm");
        write_string(&mut payload, self.identity.key_blob()).expect("bounded public key");
        payload
    }

    /// Encode the `SSH_MSG_USERAUTH_REQUEST` payload, excluding packet framing and MAC.
    pub fn encode(&self) -> Result<Vec<u8>, SignerError> {
        let mut encoded = Vec::new();
        encoded.push(USERAUTH_REQUEST);
        write_string(&mut encoded, self.context.username.as_bytes())?;
        write_string(&mut encoded, self.context.service.as_bytes())?;
        write_string(&mut encoded, USERAUTH_METHOD)?;
        encoded.push(u8::from(self.has_signature()));
        write_string(&mut encoded, self.identity.algorithm().as_bytes())?;
        write_string(&mut encoded, self.identity.key_blob())?;
        if let Some(signature) = &self.signature {
            write_string(&mut encoded, signature)?;
        }
        Ok(encoded)
    }
}

/// A cryptographic wrapper around a P-256 device key for SSH authentication.
pub struct P256SshSigner {
    key: P256SigningKey,
}

impl P256SshSigner {
    /// Wrap an existing Scoplen P-256 key without changing its ownership or format.
    #[must_use]
    pub fn new(key: P256SigningKey) -> Self {
        Self { key }
    }
}

impl Signer for P256SshSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaSha2Nistp256
    }

    fn public_key_blob(&self) -> Result<Vec<u8>, SignerError> {
        let mut blob = Vec::new();
        write_string(&mut blob, self.algorithm().name().as_bytes())?;
        write_string(&mut blob, b"nistp256")?;
        write_string(&mut blob, &self.key.public_key_sec1())?;
        Ok(blob)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let signature = self.key.sign(message);
        let mut encoded = Vec::new();
        write_string(&mut encoded, &encode_mpint(&signature[..32]))?;
        write_string(&mut encoded, &encode_mpint(&signature[32..]))?;
        Ok(encoded)
    }
}

/// A cryptographic wrapper around an Ed25519 account or device key for SSH authentication.
pub struct Ed25519SshSigner {
    key: Ed25519SigningKey,
}

impl Ed25519SshSigner {
    /// Wrap an existing Scoplen Ed25519 key without exposing its seed.
    #[must_use]
    pub fn new(key: Ed25519SigningKey) -> Self {
        Self { key }
    }
}

impl Signer for Ed25519SshSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn public_key_blob(&self) -> Result<Vec<u8>, SignerError> {
        let mut blob = Vec::new();
        write_string(&mut blob, self.algorithm().name().as_bytes())?;
        write_string(&mut blob, &self.key.public_key())?;
        Ok(blob)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.key.sign(message).to_vec())
    }
}

/// Certificate type expected by a validation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateKind {
    /// User certificate used for public-key authentication.
    User,
    /// Host certificate presented by an SSH server.
    Host,
}

/// Certificate validation policy applied before a certificate is trusted or passed to a callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateValidationPolicy<'a> {
    /// Certificate role expected from the peer.
    pub kind: CertificateKind,
    /// Principal that must be listed by the certificate.
    pub expected_principal: &'a str,
    /// Unix timestamp used for the half-open validity interval.
    pub now: u64,
    /// Critical option names explicitly accepted by the caller.
    pub allowed_critical_options: &'a [&'a str],
}

impl<'a> CertificateValidationPolicy<'a> {
    /// Build a user-certificate policy with no accepted critical options.
    #[must_use]
    pub const fn user(expected_principal: &'a str, now: u64) -> Self {
        Self { kind: CertificateKind::User, expected_principal, now, allowed_critical_options: &[] }
    }

    /// Build a host-certificate policy with no accepted critical options.
    #[must_use]
    pub const fn host(expected_principal: &'a str, now: u64) -> Self {
        Self { kind: CertificateKind::Host, expected_principal, now, allowed_critical_options: &[] }
    }

    /// Allow selected recognized critical options after their values pass validation.
    #[must_use]
    pub const fn with_allowed_critical_options(
        mut self,
        allowed_critical_options: &'a [&'a str],
    ) -> Self {
        self.allowed_critical_options = allowed_critical_options;
        self
    }
}

/// Errors returned while parsing or validating an OpenSSH certificate.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CertificateValidationError {
    /// The certificate exceeded the bounded parser input size.
    #[error("SSH certificate exceeds the size limit")]
    TooLarge,
    /// The certificate failed the SSH binary parser.
    #[error("invalid SSH certificate encoding")]
    InvalidEncoding,
    /// The certificate has the wrong user/host role.
    #[error("certificate has the wrong type")]
    WrongType,
    /// The CA signature did not verify against the embedded CA key.
    #[error("SSH certificate CA signature is invalid")]
    InvalidSignature,
    /// The validity interval has not started.
    #[error("SSH certificate is not yet valid")]
    NotYetValid,
    /// The validity interval has ended.
    #[error("SSH certificate has expired")]
    Expired,
    /// The certificate's principal list was empty.
    #[error("SSH certificate has no principals")]
    NoPrincipals,
    /// The expected principal was absent.
    #[error("SSH certificate principal does not match")]
    PrincipalMismatch,
    /// A principal appeared more than once in the certificate.
    #[error("SSH certificate contains a duplicate principal")]
    DuplicatePrincipal,
    /// A critical option is not recognized by this implementation.
    #[error("unknown SSH certificate critical option: {0}")]
    UnknownCriticalOption(String),
    /// A recognized critical option was not enabled by the caller's policy.
    #[error("SSH certificate critical option is not allowed: {0}")]
    DisallowedCriticalOption(String),
    /// A recognized critical option has malformed data.
    #[error("invalid SSH certificate critical option: {0}")]
    InvalidCriticalOption(String),
    /// The expected principal supplied by the caller is invalid.
    #[error("invalid expected SSH certificate principal")]
    InvalidExpectedPrincipal,
}

/// A parsed OpenSSH certificate with bounded storage and validation helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshCertificate {
    inner: Certificate,
    encoded: Vec<u8>,
    algorithm: String,
    subject_key_blob: Vec<u8>,
    ca_key_blob: Vec<u8>,
}

impl SshCertificate {
    /// Parse a raw RFC 4253 certificate key blob.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateValidationError> {
        if bytes.len() > MAX_CERTIFICATE {
            return Err(CertificateValidationError::TooLarge);
        }
        let inner = Certificate::from_bytes(bytes)
            .map_err(|_| CertificateValidationError::InvalidEncoding)?;
        let encoded = inner.to_bytes().map_err(|_| CertificateValidationError::InvalidEncoding)?;
        let algorithm = inner.algorithm().to_certificate_type();
        let subject_key_blob = PublicKey::from(inner.public_key().clone())
            .to_bytes()
            .map_err(|_| CertificateValidationError::InvalidEncoding)?;
        let ca_key_blob = PublicKey::from(inner.signature_key().clone())
            .to_bytes()
            .map_err(|_| CertificateValidationError::InvalidEncoding)?;
        Ok(Self { inner, encoded, algorithm, subject_key_blob, ca_key_blob })
    }

    fn from_inner(inner: Certificate) -> Result<Self, CertificateValidationError> {
        let encoded = inner.to_bytes().map_err(|_| CertificateValidationError::InvalidEncoding)?;
        if encoded.len() > MAX_CERTIFICATE {
            return Err(CertificateValidationError::TooLarge);
        }
        let algorithm = inner.algorithm().to_certificate_type();
        let subject_key_blob = PublicKey::from(inner.public_key().clone())
            .to_bytes()
            .map_err(|_| CertificateValidationError::InvalidEncoding)?;
        let ca_key_blob = PublicKey::from(inner.signature_key().clone())
            .to_bytes()
            .map_err(|_| CertificateValidationError::InvalidEncoding)?;
        Ok(Self { inner, encoded, algorithm, subject_key_blob, ca_key_blob })
    }

    /// Return the canonical raw certificate key blob.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the certificate algorithm identifier.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Return the certificate's role.
    #[must_use]
    pub fn kind(&self) -> CertificateKind {
        if self.inner.cert_type().is_user() { CertificateKind::User } else { CertificateKind::Host }
    }

    /// Return valid principals in the certificate.
    #[must_use]
    pub fn principals(&self) -> &[String] {
        self.inner.valid_principals()
    }

    /// Return the Unix timestamp at which this certificate becomes valid.
    #[must_use]
    pub fn valid_after(&self) -> u64 {
        self.inner.valid_after()
    }

    /// Return the exclusive Unix timestamp at which this certificate expires.
    #[must_use]
    pub fn valid_before(&self) -> u64 {
        self.inner.valid_before()
    }

    /// Return the canonical SSH public-key blob of the certificate authority.
    ///
    /// A consumer can hash or compare this opaque blob against a trusted CA record without
    /// depending on the `RustCrypto` key type.
    #[must_use]
    pub fn ca_public_key_blob(&self) -> &[u8] {
        &self.ca_key_blob
    }

    /// Return critical options as a map of option names to SSH string values.
    pub fn critical_options(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner.critical_options().iter().map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Validate role, CA signature, validity, principal, and critical options.
    pub fn validate(
        &self,
        policy: &CertificateValidationPolicy<'_>,
    ) -> Result<(), CertificateValidationError> {
        if policy.expected_principal.is_empty()
            || policy.expected_principal.len() > MAX_FIELD
            || policy.expected_principal.contains('\0')
        {
            return Err(CertificateValidationError::InvalidExpectedPrincipal);
        }
        if self.kind() != policy.kind {
            return Err(CertificateValidationError::WrongType);
        }
        self.inner.verify_signature().map_err(|_| CertificateValidationError::InvalidSignature)?;
        if policy.now < self.valid_after() {
            return Err(CertificateValidationError::NotYetValid);
        }
        if policy.now >= self.valid_before() {
            return Err(CertificateValidationError::Expired);
        }
        if self.principals().is_empty() {
            return Err(CertificateValidationError::NoPrincipals);
        }
        let mut principals = BTreeSet::new();
        if self.principals().iter().any(|principal| !principals.insert(principal)) {
            return Err(CertificateValidationError::DuplicatePrincipal);
        }
        if !self.principals().iter().any(|principal| principal == policy.expected_principal) {
            return Err(CertificateValidationError::PrincipalMismatch);
        }
        let allowed: BTreeSet<&str> = policy.allowed_critical_options.iter().copied().collect();
        for (name, value) in self.critical_options() {
            if !matches!(name, FORCE_COMMAND | SOURCE_ADDRESS) {
                return Err(CertificateValidationError::UnknownCriticalOption(name.to_owned()));
            }
            if !allowed.contains(name) {
                return Err(CertificateValidationError::DisallowedCriticalOption(name.to_owned()));
            }
            validate_critical_option(name, value)?;
        }
        Ok(())
    }

    /// Turn a validated user certificate into the public-key identity used for authentication.
    pub fn user_identity(
        &self,
        policy: &CertificateValidationPolicy<'_>,
    ) -> Result<PublicKeyIdentity, CertificateValidationError> {
        if policy.kind != CertificateKind::User {
            return Err(CertificateValidationError::WrongType);
        }
        self.validate(policy)?;
        PublicKeyIdentity::for_certificate(
            self.algorithm(),
            self.as_bytes().to_vec(),
            self.subject_key_blob.clone(),
        )
        .map_err(|_| CertificateValidationError::InvalidEncoding)
    }
}

/// A user certificate validated for public-key authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserCertificate {
    certificate: SshCertificate,
}

impl UserCertificate {
    /// Parse and validate a user certificate in one operation.
    pub fn parse_and_validate(
        bytes: &[u8],
        policy: &CertificateValidationPolicy<'_>,
    ) -> Result<Self, CertificateValidationError> {
        let certificate = SshCertificate::from_bytes(bytes)?;
        certificate.user_identity(policy)?;
        Ok(Self { certificate })
    }

    /// Return the validated certificate identity for a signed auth request.
    #[must_use]
    pub fn identity(&self) -> PublicKeyIdentity {
        PublicKeyIdentity::for_certificate(
            self.certificate.algorithm(),
            self.certificate.as_bytes().to_vec(),
            self.certificate.subject_key_blob.clone(),
        )
        .expect("validated certificate has a matching SSH identity")
    }

    /// Return the underlying certificate.
    #[must_use]
    pub fn certificate(&self) -> &SshCertificate {
        &self.certificate
    }
}

/// A host key or host certificate after structural and certificate validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostKey {
    /// A raw SSH public key blob.
    Raw { algorithm: String, key_blob: Vec<u8> },
    /// A host certificate whose CA signature, validity, principal, and critical options passed.
    Certificate(SshCertificate),
}

/// Errors returned by host-key parsing, validation, or consumer trust callbacks.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostKeyVerificationError {
    /// The presented key failed the SSH public-key parser.
    #[error("invalid SSH host-key encoding")]
    InvalidEncoding,
    /// The presented host certificate failed validation.
    #[error(transparent)]
    Certificate(#[from] CertificateValidationError),
    /// The consumer rejected the structurally valid host key.
    #[error("host-key verifier rejected the key: {0}")]
    Rejected(String),
}

/// Consumer callback for host trust decisions.
pub trait HostKeyVerifier {
    /// Decide whether a validated raw key or certificate is trusted for `host`.
    fn verify(&self, host: &str, key: &HostKey) -> Result<(), HostKeyVerificationError>;
}

impl<F> HostKeyVerifier for F
where
    F: Fn(&str, &HostKey) -> Result<(), HostKeyVerificationError>,
{
    fn verify(&self, host: &str, key: &HostKey) -> Result<(), HostKeyVerificationError> {
        self(host, key)
    }
}

/// Parse and validate a server key, then invoke the consumer trust callback.
pub fn verify_host_key<V: HostKeyVerifier + ?Sized>(
    host: &str,
    presented_key: &[u8],
    certificate_policy: &CertificateValidationPolicy<'_>,
    verifier: &V,
) -> Result<HostKey, HostKeyVerificationError> {
    if host.is_empty() || host.len() > MAX_FIELD || host.contains('\0') {
        return Err(HostKeyVerificationError::InvalidEncoding);
    }
    if presented_key.is_empty() || presented_key.len() > MAX_CERTIFICATE {
        return Err(HostKeyVerificationError::InvalidEncoding);
    }
    let public_key = PublicKey::from_bytes(presented_key)
        .map_err(|_| HostKeyVerificationError::InvalidEncoding)?;
    if certificate_policy.kind != CertificateKind::Host {
        return Err(HostKeyVerificationError::Certificate(CertificateValidationError::WrongType));
    }
    let key = if let Some(certificate) = public_key.key_data().certificate() {
        let certificate = SshCertificate::from_inner(certificate.clone())?;
        certificate.validate(certificate_policy)?;
        HostKey::Certificate(certificate)
    } else {
        HostKey::Raw {
            algorithm: public_key.algorithm().as_str().to_owned(),
            key_blob: public_key
                .to_bytes()
                .map_err(|_| HostKeyVerificationError::InvalidEncoding)?,
        }
    };
    verifier.verify(host, &key)?;
    Ok(key)
}

fn validate_critical_option(name: &str, value: &str) -> Result<(), CertificateValidationError> {
    if value.contains('\0') {
        return Err(CertificateValidationError::InvalidCriticalOption(name.to_owned()));
    }
    match name {
        FORCE_COMMAND if value.is_empty() => {
            Err(CertificateValidationError::InvalidCriticalOption(name.to_owned()))
        }
        SOURCE_ADDRESS => {
            if value.is_empty() || value.split(',').any(|entry| !valid_source_address(entry)) {
                Err(CertificateValidationError::InvalidCriticalOption(name.to_owned()))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

fn valid_source_address(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return value.parse::<IpAddr>().is_ok();
    };
    let Ok(address) = address.parse::<IpAddr>() else { return false };
    let Ok(prefix) = prefix.parse::<u8>() else { return false };
    prefix
        <= match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
}

fn validate_text_field(value: &str, field: &'static str) -> Result<(), SignerError> {
    if value.is_empty() || value.len() > MAX_FIELD || value.contains('\0') {
        return Err(SignerError::InvalidInput(field));
    }
    Ok(())
}

fn write_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SignerError> {
    let length =
        u32::try_from(value.len()).map_err(|_| SignerError::InvalidInput("SSH field too large"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn read_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let end = 4usize.checked_add(length)?;
    Some((input.get(4..end)?, input.get(end..)?))
}

fn encode_mpint(value: &[u8]) -> Vec<u8> {
    let first_nonzero = value.iter().position(|byte| *byte != 0).unwrap_or(value.len());
    let mut value =
        if first_nonzero == value.len() { vec![0] } else { value[first_nonzero..].to_vec() };
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoplen_crypto::{ed25519_verify, p256_verify};
    use ssh_key::{Algorithm, PrivateKey, certificate, getrandom::SysRng, rand_core::UnwrapErr};

    fn ssh_string(value: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        write_string(&mut output, value).expect("test string");
        output
    }

    fn signature_parts(signature: &[u8]) -> (&[u8], &[u8]) {
        let (algorithm, rest) = read_string(signature).expect("signature algorithm");
        let (blob, trailing) = read_string(rest).expect("signature blob");
        assert!(trailing.is_empty());
        (algorithm, blob)
    }

    fn mpint_to_fixed(value: &[u8], width: usize) -> Vec<u8> {
        let value = value.strip_prefix(&[0]).unwrap_or(value);
        assert!(value.len() <= width);
        let mut output = vec![0; width - value.len()];
        output.extend_from_slice(value);
        output
    }

    fn certificate(
        kind: certificate::CertType,
        principal: Option<&str>,
        now: u64,
        before: u64,
        critical: Option<(&str, &str)>,
    ) -> Vec<u8> {
        let mut rng = UnwrapErr(SysRng);
        let ca = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("CA");
        let subject = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("subject");
        let mut builder =
            certificate::Builder::new(vec![7; 16], subject.public_key(), now - 1, before)
                .expect("builder");
        builder.cert_type(kind).expect("type");
        if let Some(principal) = principal {
            builder.valid_principal(principal).expect("principal");
        } else {
            builder.all_principals_valid().expect("principal mode");
        }
        if let Some((name, value)) = critical {
            builder.critical_option(name, value).expect("critical");
        }
        builder.sign(&ca).expect("certificate").to_bytes().expect("encoding")
    }

    #[test]
    fn signer_and_publickey_request_bind_all_context_fields() {
        let signer = Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("key"));
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        let request =
            PublicKeyAuthRequest::signed(context.clone(), identity, &signer).expect("signed");
        let encoded = request.encode().expect("wire");
        assert_eq!(encoded[0], USERAUTH_REQUEST);
        assert!(request.has_signature());
        assert!(request.signature_payload().starts_with(&ssh_string(&[3; 32])));

        let changed_user =
            PublicKeyAuthContext::new([3; 32], "bob", "ssh-connection").expect("context");
        let changed =
            PublicKeyAuthRequest::signed(changed_user, request.identity().clone(), &signer)
                .expect("signed");
        assert_ne!(request.signature(), changed.signature());
    }

    #[test]
    fn signed_requests_use_verifiable_ssh_signature_encodings() {
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");

        let ed_signer =
            Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("ed25519 key"));
        let ed_identity = PublicKeyIdentity::from_signer(&ed_signer).expect("ed identity");
        let ed_request =
            PublicKeyAuthRequest::signed(context.clone(), ed_identity, &ed_signer).expect("signed");
        let (ed_algorithm, ed_signature) =
            signature_parts(ed_request.signature().expect("signature"));
        assert_eq!(ed_algorithm, b"ssh-ed25519");
        let ed_public_key_blob = ed_signer.public_key_blob().expect("public key");
        let (_, ed_public_key_rest) =
            read_string(ed_public_key_blob.as_slice()).expect("ed algorithm");
        let (ed_public_key, ed_trailing) = read_string(ed_public_key_rest).expect("ed public key");
        assert!(ed_trailing.is_empty());
        ed25519_verify(ed_public_key, &ed_request.signature_payload(), ed_signature)
            .expect("ed25519 signature verifies");

        let p256_signer =
            P256SshSigner::new(P256SigningKey::from_bytes(&[1; 32]).expect("p256 key"));
        let p256_identity = PublicKeyIdentity::from_signer(&p256_signer).expect("p256 identity");
        let p256_request =
            PublicKeyAuthRequest::signed(context, p256_identity, &p256_signer).expect("signed");
        let (p256_algorithm, p256_signature) =
            signature_parts(p256_request.signature().expect("signature"));
        assert_eq!(p256_algorithm, b"ecdsa-sha2-nistp256");
        let p256_public_key_blob = p256_signer.public_key_blob().expect("public key");
        let (_, p256_key) = read_string(p256_public_key_blob.as_slice()).expect("p256 algorithm");
        let (_, p256_key) = read_string(p256_key).expect("p256 curve");
        let (p256_key, _) = read_string(p256_key).expect("p256 point");
        let (r, rest) = read_string(p256_signature).expect("r");
        let (s, trailing) = read_string(rest).expect("s");
        assert!(trailing.is_empty());
        let mut fixed_signature = mpint_to_fixed(r, 32);
        fixed_signature.extend_from_slice(&mpint_to_fixed(s, 32));
        p256_verify(p256_key, &p256_request.signature_payload(), &fixed_signature)
            .expect("p256 signature verifies");
    }

    struct OversizedSigner {
        inner: Ed25519SshSigner,
    }

    impl Signer for OversizedSigner {
        fn algorithm(&self) -> SignatureAlgorithm {
            self.inner.algorithm()
        }

        fn public_key_blob(&self) -> Result<Vec<u8>, SignerError> {
            self.inner.public_key_blob()
        }

        fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0; MAX_SIGNATURE + 1])
        }
    }

    #[test]
    fn signer_output_is_bounded() {
        let signer = OversizedSigner {
            inner: Ed25519SshSigner::new(
                Ed25519SigningKey::from_bytes(&[9; 32]).expect("ed25519 key"),
            ),
        };
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        assert_eq!(
            PublicKeyAuthRequest::signed(context, identity, &signer),
            Err(SignerError::InvalidInput("SSH signature blob is too large"))
        );
    }

    #[test]
    fn p256_signer_emits_ssh_key_and_mpint_signature_blobs() {
        let signer = P256SshSigner::new(P256SigningKey::from_bytes(&[1; 32]).expect("key"));
        let identity = PublicKeyIdentity::from_signer(&signer).expect("identity");
        assert_eq!(identity.algorithm(), "ecdsa-sha2-nistp256");
        let signature = signer.sign(b"message").expect("signature");
        let (_, rest) = read_string(&signature).expect("r");
        assert!(read_string(rest).is_some());
    }

    #[test]
    fn user_certificate_rejects_expiry_principal_and_unknown_critical_option() {
        let expired = certificate(certificate::CertType::User, Some("alice"), 100, 100, None);
        assert_eq!(
            SshCertificate::from_bytes(&expired)
                .expect("parse")
                .validate(&CertificateValidationPolicy::user("alice", 100)),
            Err(CertificateValidationError::Expired)
        );

        let not_yet_valid = certificate(certificate::CertType::User, Some("alice"), 200, 300, None);
        assert_eq!(
            SshCertificate::from_bytes(&not_yet_valid)
                .expect("parse")
                .validate(&CertificateValidationPolicy::user("alice", 100)),
            Err(CertificateValidationError::NotYetValid)
        );

        let wrong_principal = certificate(certificate::CertType::User, Some("bob"), 100, 200, None);
        assert_eq!(
            SshCertificate::from_bytes(&wrong_principal)
                .expect("parse")
                .validate(&CertificateValidationPolicy::user("alice", 150)),
            Err(CertificateValidationError::PrincipalMismatch)
        );

        let unknown = certificate(
            certificate::CertType::User,
            Some("alice"),
            100,
            200,
            Some(("unknown", "")),
        );
        assert_eq!(
            SshCertificate::from_bytes(&unknown)
                .expect("parse")
                .validate(&CertificateValidationPolicy::user("alice", 150)),
            Err(CertificateValidationError::UnknownCriticalOption("unknown".into()))
        );

        let malformed_known = certificate(
            certificate::CertType::User,
            Some("alice"),
            100,
            200,
            Some((FORCE_COMMAND, "")),
        );
        assert_eq!(
            SshCertificate::from_bytes(&malformed_known).expect("parse").validate(
                &CertificateValidationPolicy::user("alice", 150)
                    .with_allowed_critical_options(&[FORCE_COMMAND]),
            ),
            Err(CertificateValidationError::InvalidCriticalOption(FORCE_COMMAND.into()))
        );
    }

    #[test]
    fn certificate_validation_rejects_bad_ca_signature_and_empty_principals() {
        let valid = certificate(certificate::CertType::User, Some("alice"), 100, 200, None);
        let mut tampered = valid.clone();
        let last = tampered.last_mut().expect("signature byte");
        *last ^= 1;
        assert_eq!(
            SshCertificate::from_bytes(&tampered)
                .expect("parse")
                .validate(&CertificateValidationPolicy::user("alice", 150)),
            Err(CertificateValidationError::InvalidSignature)
        );

        let no_principal = certificate(certificate::CertType::User, None, 100, 200, None);
        assert_eq!(
            SshCertificate::from_bytes(&no_principal)
                .expect("parse")
                .validate(&CertificateValidationPolicy::user("alice", 150)),
            Err(CertificateValidationError::NoPrincipals)
        );
    }

    #[test]
    fn certificate_identity_is_bound_to_the_signing_subject_key() {
        let encoded = certificate(certificate::CertType::User, Some("alice"), 100, 200, None);
        let certificate = SshCertificate::from_bytes(&encoded).expect("certificate");
        let identity = certificate
            .user_identity(&CertificateValidationPolicy::user("alice", 150))
            .expect("identity");
        let signer = Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(&[9; 32]).expect("key"));
        let context =
            PublicKeyAuthContext::new([3; 32], "alice", "ssh-connection").expect("context");
        assert_eq!(
            PublicKeyAuthRequest::signed(context, identity, &signer),
            Err(SignerError::InvalidInput("signer key does not match public-key identity"))
        );
    }

    #[test]
    fn duplicate_principals_are_rejected() {
        let mut rng = UnwrapErr(SysRng);
        let ca = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("CA");
        let subject = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("subject");
        let mut builder = certificate::Builder::new(vec![8; 16], subject.public_key(), 100, 200)
            .expect("builder");
        builder.cert_type(certificate::CertType::User).expect("type");
        builder.valid_principal("alice").expect("principal");
        builder.valid_principal("alice").expect("duplicate principal");
        let encoded = builder.sign(&ca).expect("certificate").to_bytes().expect("encoding");
        assert_eq!(
            SshCertificate::from_bytes(&encoded)
                .expect("parse")
                .validate(&CertificateValidationPolicy::user("alice", 150)),
            Err(CertificateValidationError::DuplicatePrincipal)
        );
    }

    #[test]
    fn host_callback_runs_only_after_certificate_validation() {
        let host_certificate =
            certificate(certificate::CertType::Host, Some("host.example"), 100, 200, None);
        let calls = std::cell::Cell::new(0);
        let verified = verify_host_key(
            "host.example",
            &host_certificate,
            &CertificateValidationPolicy::host("host.example", 150),
            &|_: &str, _: &HostKey| {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .expect("host certificate");
        let HostKey::Certificate(verified) = verified else { panic!("host certificate") };
        assert!(!verified.ca_public_key_blob().is_empty());
        assert_eq!(calls.get(), 1);
        assert_eq!(
            verify_host_key(
                "host.example",
                &host_certificate,
                &CertificateValidationPolicy::user("host.example", 150),
                &|_: &str, _: &HostKey| Ok(()),
            ),
            Err(HostKeyVerificationError::Certificate(CertificateValidationError::WrongType))
        );

        let expired =
            certificate(certificate::CertType::Host, Some("host.example"), 100, 150, None);
        assert_eq!(
            verify_host_key(
                "host.example",
                &expired,
                &CertificateValidationPolicy::host("host.example", 150),
                &|_: &str, _: &HostKey| {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            ),
            Err(HostKeyVerificationError::Certificate(CertificateValidationError::Expired))
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn raw_host_key_is_structurally_checked_before_callback() {
        let key = PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519)
            .expect("key")
            .public_key()
            .to_bytes()
            .expect("public key");
        let result = verify_host_key(
            "host.example",
            &key,
            &CertificateValidationPolicy::host("host.example", 150),
            &|_: &str, key: &HostKey| {
                assert!(matches!(key, HostKey::Raw { .. }));
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(
            verify_host_key(
                "host.example",
                b"invalid",
                &CertificateValidationPolicy::host("host.example", 150),
                &|_: &str, _: &HostKey| Ok(()),
            ),
            Err(HostKeyVerificationError::InvalidEncoding)
        );
        let oversized = vec![0; MAX_CERTIFICATE + 1];
        assert_eq!(
            verify_host_key(
                "host.example",
                &oversized,
                &CertificateValidationPolicy::host("host.example", 150),
                &|_: &str, _: &HostKey| Ok(()),
            ),
            Err(HostKeyVerificationError::InvalidEncoding)
        );
    }
}
