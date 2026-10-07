// SPDX-License-Identifier: Apache-2.0
//! Bounded SSH agent protocol messages and client/server dispatch.
//!
//! The platform-specific socket, named-pipe, and Pageant adapters implement [`AgentChannel`].
//! This module owns the OpenSSH agent framing and the request/response boundary so every adapter
//! applies the same length, ordering, and failure rules.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    fmt,
    io::{Read, Write},
};

use crate::channels::{ChannelData, MAX_CHANNEL_STRING};
use scoplen_crypto::SecretVec;
use thiserror::Error;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const ADD_IDENTITY: u8 = 17;
const REMOVE_IDENTITY: u8 = 18;
const REMOVE_ALL_IDENTITIES: u8 = 19;
const ADD_SMARTCARD_KEY: u8 = 20;
const REMOVE_SMARTCARD_KEY: u8 = 21;
const LOCK: u8 = 22;
const UNLOCK: u8 = 23;
const ADD_IDENTITY_CONSTRAINED: u8 = 25;
const EXTENSION: u8 = 27;
const EXTENSION_FAILURE: u8 = 28;

const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_CONFIRM: u8 = 2;
const CONSTRAIN_MAXSIGN: u8 = 3;
const CONSTRAIN_EXTENSION: u8 = 255;

/// Maximum complete SSH agent payload, excluding the four-byte frame length.
pub const MAX_AGENT_FRAME: usize = 256 * 1024;
/// Maximum opaque public-key blob accepted by the agent boundary.
pub const MAX_AGENT_KEY_BLOB: usize = 64 * 1024;
/// Maximum data blob sent to an agent for signing.
pub const MAX_AGENT_SIGN_DATA: usize = 256 * 1024;
/// Maximum comment length returned with an agent identity.
pub const MAX_AGENT_COMMENT: usize = 4096;
/// Maximum number of identities in one agent response.
pub const MAX_AGENT_IDENTITIES: usize = 1024;
/// Maximum lock or unlock passphrase length accepted by the agent boundary.
pub const MAX_AGENT_PASSPHRASE: usize = 4096;
/// Maximum provider name accepted by smart-card management requests.
pub const MAX_AGENT_PROVIDER: usize = 4096;
/// Maximum encoded private-key data accepted by add-identity requests.
pub const MAX_AGENT_PRIVATE_KEY: usize = 128 * 1024;
/// Maximum number of constraints accepted on one added identity.
pub const MAX_AGENT_CONSTRAINTS: usize = 256;
/// Maximum extension name accepted by an identity constraint.
pub const MAX_AGENT_EXTENSION_NAME: usize = 4096;
/// Maximum extension details accepted by an identity constraint.
pub const MAX_AGENT_EXTENSION_DETAILS: usize = 64 * 1024;
/// Maximum opaque request or response contents accepted by an agent extension.
pub const MAX_AGENT_EXTENSION_DATA: usize = 192 * 1024;
/// Maximum bytes retained while an SSH `auth-agent` channel data stream is reassembled.
pub const MAX_AGENT_FORWARD_BUFFER: usize = MAX_AGENT_FRAME + 4;
/// Maximum complete agent responses produced for one channel-data delivery.
pub const MAX_AGENT_FORWARD_RESPONSES: usize = 64;
/// OpenSSH requests an RSA SHA-256 signature when this flag is set.
pub const AGENT_SIGN_FLAG_RSA_SHA2_256: u32 = 2;
/// OpenSSH requests an RSA SHA-512 signature when this flag is set.
pub const AGENT_SIGN_FLAG_RSA_SHA2_512: u32 = 4;

/// Errors returned by the SSH agent wire and dispatch boundaries.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AgentError {
    /// The four-byte frame length or message payload is malformed.
    #[error("malformed SSH agent frame: {0}")]
    MalformedFrame(&'static str),
    /// The frame exceeded the bounded agent input limit.
    #[error("SSH agent frame is too large")]
    FrameTooLarge,
    /// An opaque field exceeded its bounded input limit.
    #[error("SSH agent field is too large: {0}")]
    FieldTooLarge(&'static str),
    /// An agent message contained an unsupported type code.
    #[error("unsupported SSH agent message: {0}")]
    UnsupportedMessage(u8),
    /// A response had a valid frame but the wrong message type for the request.
    #[error("unexpected SSH agent response")]
    UnexpectedResponse,
    /// The external agent refused a request.
    #[error("SSH agent returned failure")]
    AgentFailure,
    /// The transport adapter failed before a response was received.
    #[error("SSH agent transport failed: {0}")]
    Transport(String),
    /// The backing key store failed while serving an agent request.
    #[error("SSH agent key store failed: {0}")]
    KeyStore(String),
    /// The forwarded agent channel retained more bytes than its bounded reassembly buffer.
    #[error("SSH forwarded agent buffer is too large")]
    ForwardingBufferTooLarge,
    /// One channel-data delivery contained more complete agent requests than allowed.
    #[error("SSH forwarded agent response limit exceeded")]
    ForwardingResponseLimit,
    /// The forwarded agent channel closed while a frame was still being reassembled.
    #[error("SSH forwarded agent channel closed with a truncated frame")]
    ForwardingTruncated,
    /// Data arrived after the forwarded agent channel had been closed.
    #[error("SSH forwarded agent channel is closed")]
    ForwardingClosed,
}

/// Opaque, zeroizing SSH private-key data for an add-identity request.
///
/// The bytes use the standard SSH agent key-data encoding (the algorithm name and its
/// algorithm-specific fields, without the trailing comment). The boundary validates the
/// supported field layout and total size, but never parses or logs private scalar values.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentPrivateKey(SecretVec);

impl AgentPrivateKey {
    /// Construct bounded standard SSH agent private-key data.
    pub fn new(encoded: impl Into<Vec<u8>>) -> Result<Self, AgentError> {
        let encoded = encoded.into();
        validate_private_key_data(&encoded)?;
        Ok(Self(SecretVec::new(encoded)))
    }

    /// Borrow the encoded key data for a key-store operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for AgentPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("AgentPrivateKey").field("encoded_len", &self.0.len()).finish()
    }
}

/// A bounded SSH agent identity constraint.
#[derive(Clone, Eq, PartialEq)]
pub enum AgentConstraint {
    /// Expire the identity after the specified number of seconds.
    Lifetime { seconds: u32 },
    /// Require user confirmation for each signature.
    Confirm,
    /// Allow at most the specified number of signatures.
    MaxSignatures { count: u32 },
    /// Carry a bounded extension understood by the receiving agent.
    Extension { name: Vec<u8>, details: Vec<u8> },
}

impl fmt::Debug for AgentConstraint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lifetime { seconds } => {
                formatter.debug_struct("Lifetime").field("seconds", seconds).finish()
            }
            Self::Confirm => formatter.write_str("Confirm"),
            Self::MaxSignatures { count } => {
                formatter.debug_struct("MaxSignatures").field("count", count).finish()
            }
            Self::Extension { name, details } => formatter
                .debug_struct("Extension")
                .field("name_len", &name.len())
                .field("details_len", &details.len())
                .finish(),
        }
    }
}

/// One public key and its agent display comment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentity {
    key_blob: Vec<u8>,
    comment: Vec<u8>,
}

impl AgentIdentity {
    /// Construct a bounded agent identity.
    pub fn new(
        key_blob: impl Into<Vec<u8>>,
        comment: impl Into<Vec<u8>>,
    ) -> Result<Self, AgentError> {
        let key_blob = key_blob.into();
        let comment = comment.into();
        validate_blob(&key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
        validate_size(&comment, MAX_AGENT_COMMENT, "comment")?;
        Ok(Self { key_blob, comment })
    }

    /// Return the opaque SSH public-key blob.
    #[must_use]
    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }

    /// Return the opaque comment bytes.
    #[must_use]
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }
}

/// A decoded SSH agent request or response.
#[derive(Clone, Eq, PartialEq)]
pub enum AgentMessage {
    /// Request the identities currently held by the agent.
    RequestIdentities,
    /// Ask the agent to sign data with one exact public-key blob.
    SignRequest { key_blob: Vec<u8>, data: Vec<u8>, flags: u32 },
    /// Return the identities currently held by the agent.
    IdentitiesAnswer { identities: Vec<AgentIdentity> },
    /// Return an SSH signature blob.
    SignResponse { signature: Vec<u8> },
    /// Send an opaque extension request to the agent.
    ExtensionRequest { name: Vec<u8>, contents: Vec<u8> },
    /// Return opaque contents from a successful extension request.
    ExtensionResponse { contents: Vec<u8> },
    /// Report an extension-specific failure.
    ExtensionFailure,
    /// Add one software identity without constraints.
    AddIdentity { private_key: AgentPrivateKey, comment: Vec<u8> },
    /// Add one software identity with bounded standard agent constraints.
    AddIdentityConstrained {
        private_key: AgentPrivateKey,
        comment: Vec<u8>,
        constraints: Vec<AgentConstraint>,
    },
    /// Remove every identity currently held by the agent.
    RemoveAllIdentities,
    /// Load keys from a smart-card provider.
    AddSmartcardKey { provider: Vec<u8>, pin: SecretVec, flags: u32 },
    /// Remove keys loaded from a smart-card provider.
    RemoveSmartcardKey { provider: Vec<u8>, flags: u32 },
    /// Remove one identity matching an exact public-key blob.
    RemoveIdentity { key_blob: Vec<u8> },
    /// Lock the agent with a passphrase.
    Lock { passphrase: Vec<u8> },
    /// Unlock the agent with a passphrase.
    Unlock { passphrase: Vec<u8> },
    /// Return a generic success response.
    Success,
    /// Return a generic failure response.
    Failure,
}

impl fmt::Debug for AgentMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestIdentities => formatter.write_str("RequestIdentities"),
            Self::SignRequest { key_blob, data, flags } => formatter
                .debug_struct("SignRequest")
                .field("key_blob_len", &key_blob.len())
                .field("data_len", &data.len())
                .field("flags", flags)
                .finish(),
            Self::IdentitiesAnswer { identities } => formatter
                .debug_struct("IdentitiesAnswer")
                .field("identity_count", &identities.len())
                .finish(),
            Self::SignResponse { signature } => formatter
                .debug_struct("SignResponse")
                .field("signature_len", &signature.len())
                .finish(),
            Self::ExtensionRequest { name, contents } => formatter
                .debug_struct("ExtensionRequest")
                .field("name_len", &name.len())
                .field("contents_len", &contents.len())
                .finish(),
            Self::ExtensionResponse { contents } => formatter
                .debug_struct("ExtensionResponse")
                .field("contents_len", &contents.len())
                .finish(),
            Self::ExtensionFailure => formatter.write_str("ExtensionFailure"),
            Self::AddIdentity { private_key, comment } => formatter
                .debug_struct("AddIdentity")
                .field("private_key", private_key)
                .field("comment_len", &comment.len())
                .finish(),
            Self::AddIdentityConstrained { private_key, comment, constraints } => formatter
                .debug_struct("AddIdentityConstrained")
                .field("private_key", private_key)
                .field("comment_len", &comment.len())
                .field("constraint_count", &constraints.len())
                .finish(),
            Self::RemoveIdentity { key_blob } => formatter
                .debug_struct("RemoveIdentity")
                .field("key_blob_len", &key_blob.len())
                .finish(),
            Self::RemoveAllIdentities => formatter.write_str("RemoveAllIdentities"),
            Self::AddSmartcardKey { provider, pin, flags } => formatter
                .debug_struct("AddSmartcardKey")
                .field("provider_len", &provider.len())
                .field("pin_len", &pin.len())
                .field("flags", flags)
                .finish(),
            Self::RemoveSmartcardKey { provider, flags } => formatter
                .debug_struct("RemoveSmartcardKey")
                .field("provider_len", &provider.len())
                .field("flags", flags)
                .finish(),
            Self::Lock { passphrase } => {
                formatter.debug_struct("Lock").field("passphrase_len", &passphrase.len()).finish()
            }
            Self::Unlock { passphrase } => {
                formatter.debug_struct("Unlock").field("passphrase_len", &passphrase.len()).finish()
            }
            Self::Success => formatter.write_str("Success"),
            Self::Failure => formatter.write_str("Failure"),
        }
    }
}

impl AgentMessage {
    /// Encode one complete length-prefixed SSH agent frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, AgentError> {
        let payload = self.encode_payload()?;
        if payload.is_empty() {
            return Err(AgentError::MalformedFrame("empty agent payload"));
        }
        if payload.len() > MAX_AGENT_FRAME {
            return Err(AgentError::FrameTooLarge);
        }
        let length = u32::try_from(payload.len())
            .map_err(|_| AgentError::FieldTooLarge("agent frame length"))?;
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decode exactly one complete length-prefixed SSH agent frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, AgentError> {
        let length = read_u32(frame, "frame length")?;
        let length = usize::try_from(length).map_err(|_| AgentError::FrameTooLarge)?;
        if length == 0 {
            return Err(AgentError::MalformedFrame("empty agent payload"));
        }
        if length > MAX_AGENT_FRAME {
            return Err(AgentError::FrameTooLarge);
        }
        let expected = 4usize.checked_add(length).ok_or(AgentError::FrameTooLarge)?;
        if frame.len() != expected {
            return Err(AgentError::MalformedFrame("frame length does not match input"));
        }
        decode_payload(&frame[4..])
    }

    fn encode_payload(&self) -> Result<Vec<u8>, AgentError> {
        let mut payload = Vec::new();
        match self {
            Self::RequestIdentities => payload.push(REQUEST_IDENTITIES),
            Self::SignRequest { key_blob, data, flags } => {
                validate_blob(key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
                validate_blob(data, MAX_AGENT_SIGN_DATA, "sign data")?;
                payload.push(SIGN_REQUEST);
                append_string(&mut payload, key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
                append_string(&mut payload, data, MAX_AGENT_SIGN_DATA, "sign data")?;
                payload.extend_from_slice(&flags.to_be_bytes());
            }
            Self::IdentitiesAnswer { identities } => {
                if identities.len() > MAX_AGENT_IDENTITIES {
                    return Err(AgentError::FieldTooLarge("identity count"));
                }
                payload.push(IDENTITIES_ANSWER);
                let count = u32::try_from(identities.len())
                    .map_err(|_| AgentError::FieldTooLarge("identity count"))?;
                payload.extend_from_slice(&count.to_be_bytes());
                for identity in identities {
                    append_string(
                        &mut payload,
                        identity.key_blob(),
                        MAX_AGENT_KEY_BLOB,
                        "key blob",
                    )?;
                    append_string(&mut payload, identity.comment(), MAX_AGENT_COMMENT, "comment")?;
                }
            }
            Self::SignResponse { signature } => {
                validate_blob(signature, MAX_AGENT_KEY_BLOB, "signature")?;
                payload.push(SIGN_RESPONSE);
                append_string(&mut payload, signature, MAX_AGENT_KEY_BLOB, "signature")?;
            }
            Self::ExtensionRequest { name, contents } => {
                encode_extension_request(&mut payload, name, contents)?;
            }
            Self::ExtensionResponse { contents } => {
                encode_extension_response(&mut payload, contents)?;
            }
            Self::ExtensionFailure => payload.push(EXTENSION_FAILURE),
            Self::AddIdentity { private_key, comment } => {
                encode_add_identity(&mut payload, private_key, comment, &[], false)?;
            }
            Self::AddIdentityConstrained { private_key, comment, constraints } => {
                encode_add_identity(&mut payload, private_key, comment, constraints, true)?;
            }
            Self::RemoveIdentity { key_blob } => {
                validate_blob(key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
                payload.push(REMOVE_IDENTITY);
                append_string(&mut payload, key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
            }
            Self::RemoveAllIdentities => payload.push(REMOVE_ALL_IDENTITIES),
            Self::AddSmartcardKey { provider, pin, flags } => {
                validate_blob(provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
                validate_size(pin.as_bytes(), MAX_AGENT_PASSPHRASE, "smart-card PIN")?;
                payload.push(ADD_SMARTCARD_KEY);
                append_string(&mut payload, provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
                append_string(
                    &mut payload,
                    pin.as_bytes(),
                    MAX_AGENT_PASSPHRASE,
                    "smart-card PIN",
                )?;
                payload.extend_from_slice(&flags.to_be_bytes());
            }
            Self::RemoveSmartcardKey { provider, flags } => {
                validate_blob(provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
                payload.push(REMOVE_SMARTCARD_KEY);
                append_string(&mut payload, provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
                payload.extend_from_slice(&flags.to_be_bytes());
            }
            Self::Lock { passphrase } => {
                validate_size(passphrase, MAX_AGENT_PASSPHRASE, "passphrase")?;
                payload.push(LOCK);
                append_string(&mut payload, passphrase, MAX_AGENT_PASSPHRASE, "passphrase")?;
            }
            Self::Unlock { passphrase } => {
                validate_size(passphrase, MAX_AGENT_PASSPHRASE, "passphrase")?;
                payload.push(UNLOCK);
                append_string(&mut payload, passphrase, MAX_AGENT_PASSPHRASE, "passphrase")?;
            }
            Self::Success => payload.push(SUCCESS),
            Self::Failure => payload.push(FAILURE),
        }
        Ok(payload)
    }
}

/// A transport-neutral client of an external SSH agent.
pub trait AgentChannel {
    /// Exchange one complete request frame for one complete response frame.
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, AgentError>;
}

/// A length-prefixed agent channel over any blocking byte stream.
pub struct FramedAgentChannel<S> {
    stream: S,
}

impl<S> FramedAgentChannel<S> {
    /// Wrap a stream that carries SSH agent frames.
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Return the wrapped byte stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> AgentChannel for FramedAgentChannel<S> {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, AgentError> {
        AgentMessage::decode_frame(request)?;
        self.stream.write_all(request).map_err(|error| AgentError::Transport(error.to_string()))?;
        self.stream.flush().map_err(|error| AgentError::Transport(error.to_string()))?;

        let mut header = [0; 4];
        self.stream
            .read_exact(&mut header)
            .map_err(|error| AgentError::Transport(error.to_string()))?;
        let length =
            usize::try_from(u32::from_be_bytes(header)).map_err(|_| AgentError::FrameTooLarge)?;
        if length == 0 {
            return Err(AgentError::MalformedFrame("empty agent payload"));
        }
        if length > MAX_AGENT_FRAME {
            return Err(AgentError::FrameTooLarge);
        }
        let mut response = Vec::with_capacity(4 + length);
        response.extend_from_slice(&header);
        response.resize(4 + length, 0);
        self.stream
            .read_exact(&mut response[4..])
            .map_err(|error| AgentError::Transport(error.to_string()))?;
        AgentMessage::decode_frame(&response)?;
        Ok(response)
    }
}

/// Pageant's current Windows named-pipe transport, which carries the standard SSH agent frames.
///
/// Recent Pageant releases expose a pipe path through their OpenSSH configuration output. The
/// adapter deliberately accepts that path from the caller rather than guessing a per-user pipe
/// name: `PuTTY` derives the name from Windows-protected state, and reproducing that derivation
/// would require unsafe platform FFI. The byte-level protocol remains the same bounded framing
/// used by Unix sockets and ordinary Windows OpenSSH agent pipes.
pub struct PageantAgentChannel<S> {
    inner: FramedAgentChannel<S>,
}

impl<S> PageantAgentChannel<S> {
    /// Wrap a stream connected to a Pageant named pipe.
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self { inner: FramedAgentChannel::new(stream) }
    }

    /// Return the wrapped Pageant stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }
}

impl<S: Read + Write> AgentChannel for PageantAgentChannel<S> {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, AgentError> {
        self.inner.exchange(request)
    }
}

/// Connect to an OpenSSH agent through a Unix-domain socket.
#[cfg(unix)]
pub fn connect_unix_agent(
    path: impl AsRef<std::path::Path>,
) -> std::io::Result<AgentClient<FramedAgentChannel<std::os::unix::net::UnixStream>>> {
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    Ok(AgentClient::new(FramedAgentChannel::new(stream)))
}

/// Connect to an OpenSSH-compatible agent through a Windows named pipe.
#[cfg(windows)]
pub fn connect_windows_agent(
    path: impl AsRef<std::path::Path>,
) -> std::io::Result<AgentClient<FramedAgentChannel<std::fs::File>>> {
    let stream = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    Ok(AgentClient::new(FramedAgentChannel::new(stream)))
}

/// Connect to a Pageant named pipe using its path from the generated OpenSSH configuration.
#[cfg(windows)]
pub fn connect_pageant_agent(
    path: impl AsRef<std::path::Path>,
) -> std::io::Result<AgentClient<PageantAgentChannel<std::fs::File>>> {
    let stream = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    Ok(AgentClient::new(PageantAgentChannel::new(stream)))
}

/// SSH agent client operations shared by Unix, Windows, and Pageant adapters.
pub struct AgentClient<C> {
    channel: C,
}

/// Authorizes one signature made through an explicitly forwarded agent.
pub trait AgentForwardingAuthorizer {
    /// Approve or reject a forwarded signature request.
    fn authorize_signature(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<(), AgentError>;
}

/// Per-profile forwarding policy with a fail-closed default.
pub struct AgentForwardingPolicy<A> {
    authorizer: A,
    enabled: bool,
}

impl<A> AgentForwardingPolicy<A> {
    /// Create a policy with forwarding disabled.
    #[must_use]
    pub fn disabled(authorizer: A) -> Self {
        Self { authorizer, enabled: false }
    }

    /// Create a policy with forwarding enabled and per-signature authorization required.
    #[must_use]
    pub fn enabled(authorizer: A) -> Self {
        Self { authorizer, enabled: true }
    }

    /// Return whether this policy permits forwarded signatures to reach the authorizer.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl<A: AgentForwardingAuthorizer> AgentForwardingPolicy<A> {
    fn authorize_signature(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<(), AgentError> {
        if !self.enabled {
            return Err(AgentError::AgentFailure);
        }
        self.authorizer.authorize_signature(key_blob, data, flags)
    }
}

impl<C: AgentChannel> AgentClient<C> {
    /// Construct an agent client over a platform channel.
    #[must_use]
    pub fn new(channel: C) -> Self {
        Self { channel }
    }

    /// Request all public identities held by the agent.
    pub fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        let response = self.exchange(&AgentMessage::RequestIdentities)?;
        match response {
            AgentMessage::IdentitiesAnswer { identities } => Ok(identities),
            AgentMessage::Failure => Err(AgentError::AgentFailure),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Ask the agent to sign one bounded data blob.
    pub fn sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, AgentError> {
        validate_blob(key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
        validate_blob(data, MAX_AGENT_SIGN_DATA, "sign data")?;
        let response = self.exchange(&AgentMessage::SignRequest {
            key_blob: key_blob.to_vec(),
            data: data.to_vec(),
            flags,
        })?;
        match response {
            AgentMessage::SignResponse { signature } => Ok(signature),
            AgentMessage::Failure => Err(AgentError::AgentFailure),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Send one bounded opaque extension request and return its response contents.
    pub fn extension(&mut self, name: &[u8], contents: &[u8]) -> Result<Vec<u8>, AgentError> {
        validate_blob(name, MAX_AGENT_EXTENSION_NAME, "extension name")?;
        validate_size(contents, MAX_AGENT_EXTENSION_DATA, "extension contents")?;
        match self.exchange(&AgentMessage::ExtensionRequest {
            name: name.to_vec(),
            contents: contents.to_vec(),
        })? {
            AgentMessage::ExtensionResponse { contents } => Ok(contents),
            AgentMessage::ExtensionFailure | AgentMessage::Failure => Err(AgentError::AgentFailure),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Add one software identity without constraints.
    pub fn add_identity(
        &mut self,
        private_key: &AgentPrivateKey,
        comment: &[u8],
    ) -> Result<(), AgentError> {
        validate_comment(comment)?;
        self.expect_success(&AgentMessage::AddIdentity {
            private_key: private_key.clone(),
            comment: comment.to_vec(),
        })
    }

    /// Add one software identity with bounded standard agent constraints.
    pub fn add_identity_constrained(
        &mut self,
        private_key: &AgentPrivateKey,
        comment: &[u8],
        constraints: &[AgentConstraint],
    ) -> Result<(), AgentError> {
        validate_comment(comment)?;
        validate_constraints(constraints, true)?;
        self.expect_success(&AgentMessage::AddIdentityConstrained {
            private_key: private_key.clone(),
            comment: comment.to_vec(),
            constraints: constraints.to_vec(),
        })
    }

    /// Remove every identity currently held by the agent.
    pub fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.expect_success(&AgentMessage::RemoveAllIdentities)
    }

    /// Load keys from a bounded smart-card provider.
    pub fn add_smartcard_key(
        &mut self,
        provider: &[u8],
        pin: &[u8],
        flags: u32,
    ) -> Result<(), AgentError> {
        validate_blob(provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
        validate_size(pin, MAX_AGENT_PASSPHRASE, "smart-card PIN")?;
        self.expect_success(&AgentMessage::AddSmartcardKey {
            provider: provider.to_vec(),
            pin: SecretVec::new(pin.to_vec()),
            flags,
        })
    }

    /// Remove keys loaded from a bounded smart-card provider.
    pub fn remove_smartcard_key(&mut self, provider: &[u8], flags: u32) -> Result<(), AgentError> {
        validate_blob(provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
        self.expect_success(&AgentMessage::RemoveSmartcardKey {
            provider: provider.to_vec(),
            flags,
        })
    }

    /// Remove one identity matching an exact public-key blob.
    pub fn remove_identity(&mut self, key_blob: &[u8]) -> Result<(), AgentError> {
        validate_blob(key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
        self.expect_success(&AgentMessage::RemoveIdentity { key_blob: key_blob.to_vec() })
    }

    /// Lock the agent with a bounded passphrase.
    pub fn lock(&mut self, passphrase: &[u8]) -> Result<(), AgentError> {
        validate_size(passphrase, MAX_AGENT_PASSPHRASE, "passphrase")?;
        self.expect_success(&AgentMessage::Lock { passphrase: passphrase.to_vec() })
    }

    /// Unlock the agent with a bounded passphrase.
    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<(), AgentError> {
        validate_size(passphrase, MAX_AGENT_PASSPHRASE, "passphrase")?;
        self.expect_success(&AgentMessage::Unlock { passphrase: passphrase.to_vec() })
    }

    /// Return the platform channel after the client has finished using it.
    #[must_use]
    pub fn into_inner(self) -> C {
        self.channel
    }

    fn exchange(&mut self, request: &AgentMessage) -> Result<AgentMessage, AgentError> {
        let frame = request.encode_frame()?;
        let response = self.channel.exchange(&frame)?;
        AgentMessage::decode_frame(&response)
    }

    fn expect_success(&mut self, request: &AgentMessage) -> Result<(), AgentError> {
        match self.exchange(request)? {
            AgentMessage::Success => Ok(()),
            AgentMessage::Failure => Err(AgentError::AgentFailure),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }
}

/// Key store operations needed by the agent server boundary.
pub trait AgentKeyStore {
    /// Return the current public identities.
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError>;

    /// Sign data for a key that exactly matches one stored identity.
    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError>;

    /// Handle one bounded opaque agent extension request.
    fn extension(&self, _name: &[u8], _contents: &[u8]) -> Result<Vec<u8>, AgentError> {
        Err(AgentError::AgentFailure)
    }

    /// Add one private identity and its optional bounded constraints.
    fn add_identity(
        &self,
        _private_key: &AgentPrivateKey,
        _comment: &[u8],
        _constraints: &[AgentConstraint],
    ) -> Result<(), AgentError> {
        Err(AgentError::AgentFailure)
    }

    /// Remove every identity currently held by the store.
    fn remove_all_identities(&self) -> Result<(), AgentError> {
        Err(AgentError::AgentFailure)
    }

    /// Remove one identity matching an exact public-key blob.
    fn remove_identity(&self, _key_blob: &[u8]) -> Result<(), AgentError> {
        Err(AgentError::AgentFailure)
    }

    /// Lock the store with a passphrase.
    fn lock(&self, _passphrase: &[u8]) -> Result<(), AgentError> {
        Err(AgentError::AgentFailure)
    }

    /// Unlock the store with a passphrase.
    fn unlock(&self, _passphrase: &[u8]) -> Result<(), AgentError> {
        Err(AgentError::AgentFailure)
    }

    /// Load keys from a smart-card provider.
    fn add_smartcard_key(
        &self,
        _provider: &[u8],
        _pin: &[u8],
        _flags: u32,
    ) -> Result<(), AgentError> {
        Err(AgentError::AgentFailure)
    }

    /// Remove keys loaded from a smart-card provider.
    fn remove_smartcard_key(&self, _provider: &[u8], _flags: u32) -> Result<(), AgentError> {
        Err(AgentError::AgentFailure)
    }
}

/// Server-side dispatch for forwarded or locally exposed agent requests.
pub struct AgentServer<S> {
    store: S,
}

impl<S: AgentKeyStore> AgentServer<S> {
    /// Construct an agent server over a key store.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Dispatch a decoded request, mapping key-store failures to an opaque agent failure.
    pub fn dispatch(&self, request: AgentMessage) -> AgentMessage {
        match request {
            AgentMessage::RequestIdentities => match self.store.identities() {
                Ok(identities) => AgentMessage::IdentitiesAnswer { identities },
                Err(_) => AgentMessage::Failure,
            },
            AgentMessage::SignRequest { key_blob, data, flags } => {
                match self.store.sign(&key_blob, &data, flags) {
                    Ok(signature) => AgentMessage::SignResponse { signature },
                    Err(_) => AgentMessage::Failure,
                }
            }
            AgentMessage::ExtensionRequest { name, contents } => {
                match self.store.extension(&name, &contents) {
                    Ok(contents) => AgentMessage::ExtensionResponse { contents },
                    Err(_) => AgentMessage::ExtensionFailure,
                }
            }
            AgentMessage::AddIdentity { private_key, comment } => {
                match self.store.add_identity(&private_key, &comment, &[]) {
                    Ok(()) => AgentMessage::Success,
                    Err(_) => AgentMessage::Failure,
                }
            }
            AgentMessage::AddIdentityConstrained { private_key, comment, constraints } => {
                match self.store.add_identity(&private_key, &comment, &constraints) {
                    Ok(()) => AgentMessage::Success,
                    Err(_) => AgentMessage::Failure,
                }
            }
            AgentMessage::RemoveAllIdentities => match self.store.remove_all_identities() {
                Ok(()) => AgentMessage::Success,
                Err(_) => AgentMessage::Failure,
            },
            AgentMessage::AddSmartcardKey { provider, pin, flags } => {
                match self.store.add_smartcard_key(&provider, pin.as_bytes(), flags) {
                    Ok(()) => AgentMessage::Success,
                    Err(_) => AgentMessage::Failure,
                }
            }
            AgentMessage::RemoveSmartcardKey { provider, flags } => {
                match self.store.remove_smartcard_key(&provider, flags) {
                    Ok(()) => AgentMessage::Success,
                    Err(_) => AgentMessage::Failure,
                }
            }
            AgentMessage::RemoveIdentity { key_blob } => {
                match self.store.remove_identity(&key_blob) {
                    Ok(()) => AgentMessage::Success,
                    Err(_) => AgentMessage::Failure,
                }
            }
            AgentMessage::Lock { passphrase } => match self.store.lock(&passphrase) {
                Ok(()) => AgentMessage::Success,
                Err(_) => AgentMessage::Failure,
            },
            AgentMessage::Unlock { passphrase } => match self.store.unlock(&passphrase) {
                Ok(()) => AgentMessage::Success,
                Err(_) => AgentMessage::Failure,
            },
            _ => AgentMessage::Failure,
        }
    }

    /// Dispatch a request received through an explicitly forwarded agent channel.
    pub fn dispatch_forwarded<A: AgentForwardingAuthorizer>(
        &self,
        request: AgentMessage,
        policy: &AgentForwardingPolicy<A>,
    ) -> AgentMessage {
        match request {
            AgentMessage::RequestIdentities => self.dispatch(AgentMessage::RequestIdentities),
            AgentMessage::SignRequest { key_blob, data, flags } => {
                if policy.authorize_signature(&key_blob, &data, flags).is_err() {
                    AgentMessage::Failure
                } else {
                    self.dispatch(AgentMessage::SignRequest { key_blob, data, flags })
                }
            }
            // Management requests and extensions must never cross an SSH auth-agent channel.
            // The caller receives the normal opaque agent failure response, so the remote peer
            // cannot distinguish an unsupported operation from a policy or store refusal.
            _ => AgentMessage::Failure,
        }
    }

    /// Decode, dispatch, and encode one complete request frame.
    pub fn dispatch_frame(&self, frame: &[u8]) -> Result<Vec<u8>, AgentError> {
        let request = AgentMessage::decode_frame(frame)?;
        let response = self.dispatch(request);
        response.encode_frame().or_else(|_| AgentMessage::Failure.encode_frame())
    }

    /// Serve framed requests from a blocking stream until the peer closes it.
    pub fn serve<T: Read + Write>(&self, stream: &mut T) -> Result<(), AgentError> {
        Self::serve_with(stream, |request| self.dispatch(request))
    }

    /// Serve forwarded requests while enforcing the per-signature forwarding policy.
    pub fn serve_forwarded<T: Read + Write, A: AgentForwardingAuthorizer>(
        &self,
        stream: &mut T,
        policy: &AgentForwardingPolicy<A>,
    ) -> Result<(), AgentError> {
        Self::serve_with(stream, |request| self.dispatch_forwarded(request, policy))
    }

    /// Return the backing key store.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.store
    }

    fn serve_with<T: Read + Write, F: FnMut(AgentMessage) -> AgentMessage>(
        stream: &mut T,
        mut dispatch: F,
    ) -> Result<(), AgentError> {
        while let Some(frame) = read_stream_frame(stream)? {
            let request = AgentMessage::decode_frame(&frame)?;
            let response = dispatch(request);
            let response =
                response.encode_frame().or_else(|_| AgentMessage::Failure.encode_frame())?;
            stream
                .write_all(&response)
                .map_err(|error| AgentError::Transport(error.to_string()))?;
            stream.flush().map_err(|error| AgentError::Transport(error.to_string()))?;
        }
        Ok(())
    }
}

/// Incremental adapter for the byte stream carried by an SSH `auth-agent@openssh.com` channel.
///
/// SSH channel-data packets may split an agent frame at any byte and may carry more than one
/// frame. This adapter reassembles those frames into the bounded agent protocol, dispatches only
/// request-identities and authorized sign requests, and splits each response back into channel
/// data-sized fragments. The adapter owns its server and forwarding policy so a channel cannot
/// accidentally outlive the policy that protects forwarded signatures.
pub struct AgentForwardingAdapter<S, A> {
    server: AgentServer<S>,
    policy: AgentForwardingPolicy<A>,
    response_channel: u32,
    buffer: Vec<u8>,
    closed: bool,
}

impl<S: AgentKeyStore, A: AgentForwardingAuthorizer> AgentForwardingAdapter<S, A> {
    /// Construct an adapter whose response channel-data uses `response_channel` as its recipient.
    #[must_use]
    pub fn new(
        server: AgentServer<S>,
        policy: AgentForwardingPolicy<A>,
        response_channel: u32,
    ) -> Self {
        Self {
            server,
            policy,
            response_channel,
            buffer: Vec::with_capacity(MAX_AGENT_FORWARD_BUFFER.min(4096)),
            closed: false,
        }
    }

    /// Feed one channel-data payload and return zero or more response fragments.
    ///
    /// Each returned [`ChannelData`] contains at most [`MAX_CHANNEL_STRING`] bytes. A malformed
    /// frame, an oversized frame, or a response-count violation closes the adapter and returns an
    /// error; callers should then close the SSH channel.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<ChannelData>, AgentError> {
        if self.closed {
            return Err(AgentError::ForwardingClosed);
        }

        let mut input = data;
        let mut responses = Vec::new();
        let mut response_count = 0usize;

        loop {
            let expected = if self.buffer.len() >= 4 {
                let length = usize::try_from(u32::from_be_bytes(
                    self.buffer[..4]
                        .try_into()
                        .map_err(|_| AgentError::MalformedFrame("agent frame length"))?,
                ))
                .map_err(|_| AgentError::FrameTooLarge)?;
                if length == 0 {
                    self.closed = true;
                    return Err(AgentError::MalformedFrame("empty agent payload"));
                }
                if length > MAX_AGENT_FRAME {
                    self.closed = true;
                    return Err(AgentError::FrameTooLarge);
                }
                4usize.checked_add(length).ok_or_else(|| {
                    self.closed = true;
                    AgentError::ForwardingBufferTooLarge
                })?
            } else {
                0
            };

            if expected != 0 && self.buffer.len() == expected {
                if response_count == MAX_AGENT_FORWARD_RESPONSES {
                    self.closed = true;
                    return Err(AgentError::ForwardingResponseLimit);
                }
                let frame = std::mem::take(&mut self.buffer);
                let request = match AgentMessage::decode_frame(&frame) {
                    Ok(request) => request,
                    Err(error) => {
                        self.closed = true;
                        return Err(error);
                    }
                };
                let response = self.server.dispatch_forwarded(request, &self.policy);
                let response =
                    response.encode_frame().or_else(|_| AgentMessage::Failure.encode_frame())?;
                responses.extend(response.chunks(MAX_CHANNEL_STRING).map(|fragment| ChannelData {
                    recipient_channel: self.response_channel,
                    data: fragment.to_vec(),
                }));
                response_count += 1;
                continue;
            }

            if input.is_empty() {
                break;
            }

            let target = if self.buffer.len() < 4 { 4 } else { expected };
            let remaining = target.checked_sub(self.buffer.len()).ok_or_else(|| {
                self.closed = true;
                AgentError::ForwardingBufferTooLarge
            })?;
            let take = remaining.min(input.len());
            if self.buffer.len().checked_add(take).ok_or_else(|| {
                self.closed = true;
                AgentError::ForwardingBufferTooLarge
            })? > MAX_AGENT_FORWARD_BUFFER
            {
                self.closed = true;
                return Err(AgentError::ForwardingBufferTooLarge);
            }
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
        }

        Ok(responses)
    }

    /// Feed a decoded channel-data message and return response fragments for its peer channel.
    pub fn push_channel_data(
        &mut self,
        message: &ChannelData,
    ) -> Result<Vec<ChannelData>, AgentError> {
        if message.data.len() > MAX_CHANNEL_STRING {
            return Err(AgentError::FieldTooLarge("channel data"));
        }
        self.push(&message.data)
    }

    /// Close the channel after the peer has sent EOF or closed it.
    ///
    /// A close with no buffered bytes is clean. Any buffered header or payload is a truncated
    /// agent frame and is reported distinctly so callers can record a protocol failure.
    pub fn finish(&mut self) -> Result<(), AgentError> {
        if self.closed {
            return Err(AgentError::ForwardingClosed);
        }
        self.closed = true;
        if self.buffer.is_empty() { Ok(()) } else { Err(AgentError::ForwardingTruncated) }
    }

    /// Return whether this adapter has been closed after EOF or a protocol error.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Return the number of bytes currently held for an incomplete agent frame.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Return the owned server and forwarding policy after the channel is no longer used.
    #[must_use]
    pub fn into_parts(self) -> (AgentServer<S>, AgentForwardingPolicy<A>) {
        (self.server, self.policy)
    }
}

fn decode_payload(payload: &[u8]) -> Result<AgentMessage, AgentError> {
    let message = *payload.first().ok_or(AgentError::MalformedFrame("missing message type"))?;
    let rest = &payload[1..];
    match message {
        REQUEST_IDENTITIES if rest.is_empty() => Ok(AgentMessage::RequestIdentities),
        REQUEST_IDENTITIES => Err(AgentError::MalformedFrame("request identities payload")),
        SIGN_REQUEST => {
            let (key_blob, rest) = read_string(rest, MAX_AGENT_KEY_BLOB, "key blob")?;
            validate_blob(key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
            let (data, rest) = read_string(rest, MAX_AGENT_SIGN_DATA, "sign data")?;
            validate_blob(data, MAX_AGENT_SIGN_DATA, "sign data")?;
            let flags = read_u32(rest, "sign flags")?;
            if rest.len() != 4 {
                return Err(AgentError::MalformedFrame("sign request trailing data"));
            }
            Ok(AgentMessage::SignRequest {
                key_blob: key_blob.to_vec(),
                data: data.to_vec(),
                flags,
            })
        }
        IDENTITIES_ANSWER => {
            let count = read_u32(rest, "identity count")?;
            let count =
                usize::try_from(count).map_err(|_| AgentError::FieldTooLarge("identity count"))?;
            if count > MAX_AGENT_IDENTITIES {
                return Err(AgentError::FieldTooLarge("identity count"));
            }
            let mut rest = &rest[4..];
            let mut identities = Vec::with_capacity(count);
            for _ in 0..count {
                let (key_blob, remaining) = read_string(rest, MAX_AGENT_KEY_BLOB, "key blob")?;
                let (comment, remaining) = read_string(remaining, MAX_AGENT_COMMENT, "comment")?;
                identities.push(AgentIdentity::new(key_blob, comment)?);
                rest = remaining;
            }
            if !rest.is_empty() {
                return Err(AgentError::MalformedFrame("identities answer trailing data"));
            }
            Ok(AgentMessage::IdentitiesAnswer { identities })
        }
        SIGN_RESPONSE => {
            let (signature, trailing) = read_string(rest, MAX_AGENT_KEY_BLOB, "signature")?;
            if !trailing.is_empty() {
                return Err(AgentError::MalformedFrame("sign response trailing data"));
            }
            validate_blob(signature, MAX_AGENT_KEY_BLOB, "signature")?;
            Ok(AgentMessage::SignResponse { signature: signature.to_vec() })
        }
        EXTENSION => decode_extension_request(rest),
        ADD_IDENTITY => decode_add_identity(rest, false),
        REMOVE_IDENTITY => {
            let (key_blob, trailing) = read_string(rest, MAX_AGENT_KEY_BLOB, "key blob")?;
            if !trailing.is_empty() {
                return Err(AgentError::MalformedFrame("remove identity payload"));
            }
            validate_blob(key_blob, MAX_AGENT_KEY_BLOB, "key blob")?;
            Ok(AgentMessage::RemoveIdentity { key_blob: key_blob.to_vec() })
        }
        REMOVE_ALL_IDENTITIES if rest.is_empty() => Ok(AgentMessage::RemoveAllIdentities),
        REMOVE_ALL_IDENTITIES => Err(AgentError::MalformedFrame("remove all identities payload")),
        ADD_SMARTCARD_KEY => decode_add_smartcard_key(rest),
        REMOVE_SMARTCARD_KEY => decode_remove_smartcard_key(rest),
        ADD_IDENTITY_CONSTRAINED => decode_add_identity(rest, true),
        LOCK => {
            let (passphrase, trailing) = read_string(rest, MAX_AGENT_PASSPHRASE, "passphrase")?;
            if !trailing.is_empty() {
                return Err(AgentError::MalformedFrame("lock payload"));
            }
            Ok(AgentMessage::Lock { passphrase: passphrase.to_vec() })
        }
        UNLOCK => {
            let (passphrase, trailing) = read_string(rest, MAX_AGENT_PASSPHRASE, "passphrase")?;
            if !trailing.is_empty() {
                return Err(AgentError::MalformedFrame("unlock payload"));
            }
            Ok(AgentMessage::Unlock { passphrase: passphrase.to_vec() })
        }
        SUCCESS if rest.is_empty() => Ok(AgentMessage::Success),
        SUCCESS => decode_extension_response(rest),
        FAILURE if rest.is_empty() => Ok(AgentMessage::Failure),
        FAILURE => Err(AgentError::MalformedFrame("failure payload")),
        EXTENSION_FAILURE if rest.is_empty() => Ok(AgentMessage::ExtensionFailure),
        EXTENSION_FAILURE => Err(AgentError::MalformedFrame("extension failure payload")),
        other => Err(AgentError::UnsupportedMessage(other)),
    }
}

fn decode_extension_request(rest: &[u8]) -> Result<AgentMessage, AgentError> {
    let (name, rest) = read_string(rest, MAX_AGENT_EXTENSION_NAME, "extension name")?;
    validate_blob(name, MAX_AGENT_EXTENSION_NAME, "extension name")?;
    let (contents, trailing) = read_string(rest, MAX_AGENT_EXTENSION_DATA, "extension contents")?;
    if !trailing.is_empty() {
        return Err(AgentError::MalformedFrame("extension request trailing data"));
    }
    Ok(AgentMessage::ExtensionRequest { name: name.to_vec(), contents: contents.to_vec() })
}

fn decode_extension_response(rest: &[u8]) -> Result<AgentMessage, AgentError> {
    let (contents, trailing) = read_string(rest, MAX_AGENT_EXTENSION_DATA, "extension response")?;
    if !trailing.is_empty() {
        return Err(AgentError::MalformedFrame("extension response trailing data"));
    }
    Ok(AgentMessage::ExtensionResponse { contents: contents.to_vec() })
}

fn decode_add_identity(input: &[u8], constrained: bool) -> Result<AgentMessage, AgentError> {
    let (private_key, rest) = read_private_key(input)?;
    let (comment, rest) = read_string(rest, MAX_AGENT_COMMENT, "comment")?;
    validate_comment(comment)?;
    let constraints = if constrained {
        decode_constraints(rest)?
    } else {
        if !rest.is_empty() {
            return Err(AgentError::MalformedFrame("add identity trailing data"));
        }
        Vec::new()
    };
    let private_key = AgentPrivateKey::new(private_key.to_vec())?;
    if constrained {
        Ok(AgentMessage::AddIdentityConstrained {
            private_key,
            comment: comment.to_vec(),
            constraints,
        })
    } else {
        Ok(AgentMessage::AddIdentity { private_key, comment: comment.to_vec() })
    }
}

fn decode_add_smartcard_key(rest: &[u8]) -> Result<AgentMessage, AgentError> {
    let (provider, rest) = read_string(rest, MAX_AGENT_PROVIDER, "smart-card provider")?;
    validate_blob(provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
    let (pin, rest) = read_string(rest, MAX_AGENT_PASSPHRASE, "smart-card PIN")?;
    let flags = read_u32(rest, "smart-card flags")?;
    if rest.len() != 4 {
        return Err(AgentError::MalformedFrame("smart-card add trailing data"));
    }
    Ok(AgentMessage::AddSmartcardKey {
        provider: provider.to_vec(),
        pin: SecretVec::new(pin.to_vec()),
        flags,
    })
}

fn decode_remove_smartcard_key(rest: &[u8]) -> Result<AgentMessage, AgentError> {
    let (provider, rest) = read_string(rest, MAX_AGENT_PROVIDER, "smart-card provider")?;
    validate_blob(provider, MAX_AGENT_PROVIDER, "smart-card provider")?;
    let flags = read_u32(rest, "smart-card flags")?;
    if rest.len() != 4 {
        return Err(AgentError::MalformedFrame("smart-card remove trailing data"));
    }
    Ok(AgentMessage::RemoveSmartcardKey { provider: provider.to_vec(), flags })
}

fn append_private_key(
    output: &mut Vec<u8>,
    private_key: &AgentPrivateKey,
) -> Result<(), AgentError> {
    validate_private_key_data(private_key.as_bytes())?;
    output.extend_from_slice(private_key.as_bytes());
    Ok(())
}

fn encode_extension_request(
    output: &mut Vec<u8>,
    name: &[u8],
    contents: &[u8],
) -> Result<(), AgentError> {
    validate_blob(name, MAX_AGENT_EXTENSION_NAME, "extension name")?;
    validate_size(contents, MAX_AGENT_EXTENSION_DATA, "extension contents")?;
    output.push(EXTENSION);
    append_string(output, name, MAX_AGENT_EXTENSION_NAME, "extension name")?;
    append_string(output, contents, MAX_AGENT_EXTENSION_DATA, "extension contents")?;
    Ok(())
}

fn encode_extension_response(output: &mut Vec<u8>, contents: &[u8]) -> Result<(), AgentError> {
    validate_size(contents, MAX_AGENT_EXTENSION_DATA, "extension response")?;
    output.push(SUCCESS);
    append_string(output, contents, MAX_AGENT_EXTENSION_DATA, "extension response")?;
    Ok(())
}

fn encode_add_identity(
    output: &mut Vec<u8>,
    private_key: &AgentPrivateKey,
    comment: &[u8],
    constraints: &[AgentConstraint],
    constrained: bool,
) -> Result<(), AgentError> {
    validate_comment(comment)?;
    validate_constraints(constraints, constrained)?;
    output.push(if constrained { ADD_IDENTITY_CONSTRAINED } else { ADD_IDENTITY });
    append_private_key(output, private_key)?;
    append_string(output, comment, MAX_AGENT_COMMENT, "comment")?;
    if constrained {
        append_constraints(output, constraints)?;
    }
    Ok(())
}

fn read_private_key(input: &[u8]) -> Result<(&[u8], &[u8]), AgentError> {
    let key_data_len = private_key_data_len(input)?;
    let (key_data, rest) = input
        .split_at_checked(key_data_len)
        .ok_or(AgentError::MalformedFrame("truncated private key data"))?;
    Ok((key_data, rest))
}

fn validate_private_key_data(encoded: &[u8]) -> Result<(), AgentError> {
    let key_data_len = private_key_data_len(encoded)?;
    if key_data_len != encoded.len() {
        return Err(AgentError::MalformedFrame("private key trailing data"));
    }
    Ok(())
}

fn private_key_data_len(encoded: &[u8]) -> Result<usize, AgentError> {
    let (algorithm, mut rest) = read_string(encoded, MAX_AGENT_KEY_BLOB, "private key algorithm")?;
    validate_blob(algorithm, MAX_AGENT_KEY_BLOB, "private key algorithm")?;

    match algorithm {
        b"ssh-rsa" => consume_fields(&mut rest, 6, "private key field")?,
        b"ssh-dss" => consume_fields(&mut rest, 5, "private key field")?,
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => {
            consume_fields(&mut rest, 3, "private key field")?;
        }
        b"ssh-ed25519" => consume_fields(&mut rest, 2, "private key field")?,
        _ => return Err(AgentError::MalformedFrame("unsupported private key algorithm")),
    }

    let key_data_len = encoded.len() - rest.len();
    validate_size(&encoded[..key_data_len], MAX_AGENT_PRIVATE_KEY, "private key")?;
    Ok(key_data_len)
}

fn consume_fields(input: &mut &[u8], count: usize, field: &'static str) -> Result<(), AgentError> {
    for _ in 0..count {
        let (_, rest) = read_string(input, MAX_AGENT_KEY_BLOB, field)?;
        *input = rest;
    }
    Ok(())
}

fn validate_comment(comment: &[u8]) -> Result<(), AgentError> {
    validate_size(comment, MAX_AGENT_COMMENT, "comment")
}

fn validate_constraints(
    constraints: &[AgentConstraint],
    require_one: bool,
) -> Result<(), AgentError> {
    if constraints.len() > MAX_AGENT_CONSTRAINTS {
        return Err(AgentError::FieldTooLarge("identity constraint count"));
    }
    if require_one && constraints.is_empty() {
        return Err(AgentError::MalformedFrame("identity constraints"));
    }
    for constraint in constraints {
        if let AgentConstraint::Extension { name, details } = constraint {
            validate_blob(name, MAX_AGENT_EXTENSION_NAME, "identity extension name")?;
            validate_size(details, MAX_AGENT_EXTENSION_DETAILS, "identity extension details")?;
        }
    }
    Ok(())
}

fn append_constraints(
    output: &mut Vec<u8>,
    constraints: &[AgentConstraint],
) -> Result<(), AgentError> {
    validate_constraints(constraints, true)?;
    for constraint in constraints {
        match constraint {
            AgentConstraint::Lifetime { seconds } => {
                output.push(CONSTRAIN_LIFETIME);
                output.extend_from_slice(&seconds.to_be_bytes());
            }
            AgentConstraint::Confirm => output.push(CONSTRAIN_CONFIRM),
            AgentConstraint::MaxSignatures { count } => {
                output.push(CONSTRAIN_MAXSIGN);
                output.extend_from_slice(&count.to_be_bytes());
            }
            AgentConstraint::Extension { name, details } => {
                output.push(CONSTRAIN_EXTENSION);
                append_string(output, name, MAX_AGENT_EXTENSION_NAME, "identity extension name")?;
                append_string(
                    output,
                    details,
                    MAX_AGENT_EXTENSION_DETAILS,
                    "identity extension details",
                )?;
            }
        }
    }
    Ok(())
}

fn decode_constraints(input: &[u8]) -> Result<Vec<AgentConstraint>, AgentError> {
    if input.is_empty() {
        return Err(AgentError::MalformedFrame("identity constraints"));
    }
    let mut rest = input;
    let mut constraints = Vec::new();
    while !rest.is_empty() {
        if constraints.len() == MAX_AGENT_CONSTRAINTS {
            return Err(AgentError::FieldTooLarge("identity constraint count"));
        }
        let constraint_type = rest[0];
        rest = &rest[1..];
        let constraint = match constraint_type {
            CONSTRAIN_LIFETIME => {
                let seconds = read_u32(rest, "identity lifetime")?;
                rest = &rest[4..];
                AgentConstraint::Lifetime { seconds }
            }
            CONSTRAIN_CONFIRM => AgentConstraint::Confirm,
            CONSTRAIN_MAXSIGN => {
                let count = read_u32(rest, "identity max signatures")?;
                rest = &rest[4..];
                AgentConstraint::MaxSignatures { count }
            }
            CONSTRAIN_EXTENSION => {
                let (name, remaining) =
                    read_string(rest, MAX_AGENT_EXTENSION_NAME, "identity extension name")?;
                validate_blob(name, MAX_AGENT_EXTENSION_NAME, "identity extension name")?;
                let (details, remaining) = read_string(
                    remaining,
                    MAX_AGENT_EXTENSION_DETAILS,
                    "identity extension details",
                )?;
                rest = remaining;
                AgentConstraint::Extension { name: name.to_vec(), details: details.to_vec() }
            }
            _ => return Err(AgentError::MalformedFrame("unsupported identity constraint")),
        };
        constraints.push(constraint);
    }
    validate_constraints(&constraints, true)?;
    Ok(constraints)
}

fn read_stream_frame<T: Read>(stream: &mut T) -> Result<Option<Vec<u8>>, AgentError> {
    let mut header = [0; 4];
    let mut received = 0;
    while received < header.len() {
        match stream.read(&mut header[received..]) {
            Ok(0) if received == 0 => return Ok(None),
            Ok(0) => return Err(AgentError::Transport("truncated SSH agent frame".into())),
            Ok(count) => received += count,
            Err(error) => return Err(AgentError::Transport(error.to_string())),
        }
    }
    let length =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| AgentError::FrameTooLarge)?;
    if length == 0 {
        return Err(AgentError::MalformedFrame("empty agent payload"));
    }
    if length > MAX_AGENT_FRAME {
        return Err(AgentError::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    stream.read_exact(&mut frame[4..]).map_err(|error| AgentError::Transport(error.to_string()))?;
    AgentMessage::decode_frame(&frame)?;
    Ok(Some(frame))
}

fn append_string(
    output: &mut Vec<u8>,
    value: &[u8],
    limit: usize,
    field: &'static str,
) -> Result<(), AgentError> {
    validate_size(value, limit, field)?;
    let length = u32::try_from(value.len()).map_err(|_| AgentError::FieldTooLarge(field))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn read_string<'a>(
    input: &'a [u8],
    limit: usize,
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), AgentError> {
    let length = read_u32(input, field)?;
    let length = usize::try_from(length).map_err(|_| AgentError::FieldTooLarge(field))?;
    if length > limit {
        return Err(AgentError::FieldTooLarge(field));
    }
    let end = 4usize.checked_add(length).ok_or(AgentError::FrameTooLarge)?;
    let value =
        input.get(4..end).ok_or(AgentError::MalformedFrame("truncated SSH agent string"))?;
    Ok((value, &input[end..]))
}

fn read_u32(input: &[u8], field: &'static str) -> Result<u32, AgentError> {
    let bytes = input.get(..4).ok_or(AgentError::MalformedFrame(field))?;
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| AgentError::MalformedFrame(field))?))
}

fn validate_blob(value: &[u8], limit: usize, field: &'static str) -> Result<(), AgentError> {
    if value.is_empty() {
        return Err(AgentError::MalformedFrame(field));
    }
    validate_size(value, limit, field)
}

fn validate_size(value: &[u8], limit: usize, field: &'static str) -> Result<(), AgentError> {
    if value.len() > limit {
        return Err(AgentError::FieldTooLarge(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"ssh-ed25519 key blob";

    #[derive(Clone)]
    struct Store {
        identity: AgentIdentity,
        signature: Vec<u8>,
    }

    impl AgentKeyStore for Store {
        fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
            Ok(vec![self.identity.clone()])
        }

        fn sign(&self, key_blob: &[u8], data: &[u8], _flags: u32) -> Result<Vec<u8>, AgentError> {
            if key_blob != self.identity.key_blob() || data.is_empty() {
                return Err(AgentError::AgentFailure);
            }
            Ok(self.signature.clone())
        }

        fn extension(&self, name: &[u8], contents: &[u8]) -> Result<Vec<u8>, AgentError> {
            if name == b"query" && contents == b"supported" {
                Ok(b"query\0session-bind@openssh.com".to_vec())
            } else {
                Err(AgentError::AgentFailure)
            }
        }

        fn add_identity(
            &self,
            private_key: &AgentPrivateKey,
            comment: &[u8],
            constraints: &[AgentConstraint],
        ) -> Result<(), AgentError> {
            let expected = ed25519_private_key();
            if private_key == &expected
                && comment == b"added key"
                && (constraints.is_empty()
                    || constraints
                        == [AgentConstraint::Lifetime { seconds: 60 }, AgentConstraint::Confirm])
            {
                Ok(())
            } else {
                Err(AgentError::AgentFailure)
            }
        }

        fn remove_all_identities(&self) -> Result<(), AgentError> {
            Ok(())
        }

        fn remove_identity(&self, key_blob: &[u8]) -> Result<(), AgentError> {
            if key_blob == self.identity.key_blob() {
                Ok(())
            } else {
                Err(AgentError::AgentFailure)
            }
        }

        fn lock(&self, _passphrase: &[u8]) -> Result<(), AgentError> {
            Ok(())
        }

        fn unlock(&self, _passphrase: &[u8]) -> Result<(), AgentError> {
            Ok(())
        }

        fn add_smartcard_key(
            &self,
            provider: &[u8],
            pin: &[u8],
            flags: u32,
        ) -> Result<(), AgentError> {
            if provider == b"provider" && pin == b"pin" && flags == 7 {
                Ok(())
            } else {
                Err(AgentError::AgentFailure)
            }
        }

        fn remove_smartcard_key(&self, provider: &[u8], flags: u32) -> Result<(), AgentError> {
            if provider == b"provider" && flags == 7 {
                Ok(())
            } else {
                Err(AgentError::AgentFailure)
            }
        }
    }

    struct Authorizer {
        allowed: bool,
    }

    impl AgentForwardingAuthorizer for Authorizer {
        fn authorize_signature(
            &self,
            _key_blob: &[u8],
            _data: &[u8],
            _flags: u32,
        ) -> Result<(), AgentError> {
            if self.allowed { Ok(()) } else { Err(AgentError::AgentFailure) }
        }
    }

    struct Loopback {
        server: AgentServer<Store>,
    }

    impl AgentChannel for Loopback {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, AgentError> {
            self.server.dispatch_frame(request)
        }
    }

    struct ScriptedStream {
        response: Vec<u8>,
        response_offset: usize,
        written: Vec<u8>,
        max_read: usize,
    }

    impl ScriptedStream {
        fn new(response: Vec<u8>, max_read: usize) -> Self {
            Self { response, response_offset: 0, written: Vec::new(), max_read }
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.response_offset == self.response.len() {
                return Ok(0);
            }
            let available = self.response.len() - self.response_offset;
            let count = available.min(buffer.len()).min(self.max_read);
            buffer[..count].copy_from_slice(
                &self.response[self.response_offset..self.response_offset + count],
            );
            self.response_offset += count;
            Ok(count)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn append_test_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(u32::try_from(value.len()).expect("test length")).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn ed25519_private_key() -> AgentPrivateKey {
        let mut encoded = Vec::new();
        append_test_string(&mut encoded, b"ssh-ed25519");
        append_test_string(&mut encoded, &[7; 32]);
        append_test_string(&mut encoded, &[8; 64]);
        AgentPrivateKey::new(encoded).expect("private key")
    }

    fn forwarding_adapter(signature: Vec<u8>) -> AgentForwardingAdapter<Store, Authorizer> {
        AgentForwardingAdapter::new(
            AgentServer::new(Store {
                identity: AgentIdentity::new(KEY, b"work key").expect("identity"),
                signature,
            }),
            AgentForwardingPolicy::enabled(Authorizer { allowed: true }),
            9,
        )
    }

    fn decode_agent_frames(fragments: &[ChannelData]) -> Vec<AgentMessage> {
        let mut wire = Vec::new();
        for fragment in fragments {
            assert_eq!(fragment.recipient_channel, 9);
            assert!(fragment.data.len() <= MAX_CHANNEL_STRING);
            wire.extend_from_slice(&fragment.data);
        }

        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < wire.len() {
            let length = usize::try_from(u32::from_be_bytes(
                wire[offset..offset + 4].try_into().expect("response header"),
            ))
            .expect("response length");
            let end = offset + 4 + length;
            frames.push(AgentMessage::decode_frame(&wire[offset..end]).expect("response frame"));
            offset = end;
        }
        frames
    }

    #[test]
    fn server_serves_fragmented_requests_until_peer_closes() {
        let store = Store {
            identity: AgentIdentity::new(KEY, b"work key").expect("identity"),
            signature: b"signed payload".to_vec(),
        };
        let identities = AgentMessage::RequestIdentities.encode_frame().expect("request");
        let remove_all = AgentMessage::RemoveAllIdentities.encode_frame().expect("request");
        let mut input = identities;
        input.extend_from_slice(&remove_all);
        let mut stream = ScriptedStream::new(input, 2);
        AgentServer::new(store).serve(&mut stream).expect("serve");

        let first_length = 4 + usize::try_from(u32::from_be_bytes(
            stream.written[..4].try_into().expect("first header"),
        ))
        .expect("first response length");
        assert_eq!(
            AgentMessage::decode_frame(&stream.written[..first_length]).expect("identities"),
            AgentMessage::IdentitiesAnswer {
                identities: vec![AgentIdentity::new(KEY, b"work key").expect("identity")],
            }
        );
        assert_eq!(
            AgentMessage::decode_frame(&stream.written[first_length..]).expect("success"),
            AgentMessage::Success
        );
    }

    #[test]
    fn server_rejects_oversized_stream_frame_before_allocation() {
        let oversized = (u32::try_from(MAX_AGENT_FRAME).expect("test limit") + 1).to_be_bytes();
        let mut stream = ScriptedStream::new(oversized.to_vec(), 4);
        let store = Store {
            identity: AgentIdentity::new(KEY, b"work key").expect("identity"),
            signature: b"signed payload".to_vec(),
        };
        assert_eq!(AgentServer::new(store).serve(&mut stream), Err(AgentError::FrameTooLarge));
        assert!(stream.written.is_empty());
    }

    #[test]
    fn framed_stream_channel_handles_fragmented_response_and_preserves_request() {
        let response = AgentMessage::IdentitiesAnswer {
            identities: vec![AgentIdentity::new(KEY, b"work key").expect("identity")],
        }
        .encode_frame()
        .expect("response");
        let stream = ScriptedStream::new(response, 2);
        let mut client = AgentClient::new(FramedAgentChannel::new(stream));
        assert_eq!(client.identities().expect("identities").len(), 1);

        let stream = client.into_inner().into_inner();
        assert_eq!(
            AgentMessage::decode_frame(&stream.written).expect("request"),
            AgentMessage::RequestIdentities
        );
    }

    #[test]
    fn framed_stream_channel_rejects_bad_request_before_writing_and_bounds_response() {
        let mut channel = FramedAgentChannel::new(ScriptedStream::new(Vec::new(), 4));
        assert_eq!(
            channel.exchange(&[0, 0, 0, 0]),
            Err(AgentError::MalformedFrame("empty agent payload"))
        );
        assert!(channel.into_inner().written.is_empty());

        let oversized =
            (u32::try_from(MAX_AGENT_FRAME).expect("test limit") + 1).to_be_bytes().to_vec();
        let mut channel = FramedAgentChannel::new(ScriptedStream::new(oversized, 4));
        let request = AgentMessage::RequestIdentities.encode_frame().expect("request");
        assert_eq!(channel.exchange(&request), Err(AgentError::FrameTooLarge));
    }

    #[test]
    fn pageant_channel_handles_fragmented_response_and_preserves_agent_wire() {
        let response = AgentMessage::IdentitiesAnswer {
            identities: vec![AgentIdentity::new(KEY, b"work key").expect("identity")],
        }
        .encode_frame()
        .expect("response");
        let stream = ScriptedStream::new(response, 1);
        let mut client = AgentClient::new(PageantAgentChannel::new(stream));
        assert_eq!(client.identities().expect("identities").len(), 1);

        let stream = client.into_inner().into_inner();
        assert_eq!(
            AgentMessage::decode_frame(&stream.written).expect("request"),
            AgentMessage::RequestIdentities
        );
    }

    #[test]
    fn pageant_channel_rejects_malformed_and_oversized_responses() {
        let request = AgentMessage::RequestIdentities.encode_frame().expect("request");

        let mut malformed = PageantAgentChannel::new(ScriptedStream::new(vec![0; 4], 1));
        assert_eq!(
            malformed.exchange(&request),
            Err(AgentError::MalformedFrame("empty agent payload"))
        );

        let oversized =
            (u32::try_from(MAX_AGENT_FRAME).expect("test limit") + 1).to_be_bytes().to_vec();
        let mut oversized = PageantAgentChannel::new(ScriptedStream::new(oversized, 1));
        assert_eq!(oversized.exchange(&request), Err(AgentError::FrameTooLarge));
    }

    #[test]
    fn agent_frames_round_trip_all_supported_messages() {
        let messages = [
            AgentMessage::RequestIdentities,
            AgentMessage::SignRequest {
                key_blob: KEY.to_vec(),
                data: b"payload".to_vec(),
                flags: AGENT_SIGN_FLAG_RSA_SHA2_256,
            },
            AgentMessage::IdentitiesAnswer {
                identities: vec![AgentIdentity::new(KEY, b"work key").expect("identity")],
            },
            AgentMessage::SignResponse { signature: b"signature".to_vec() },
            AgentMessage::ExtensionRequest {
                name: b"query".to_vec(),
                contents: b"supported".to_vec(),
            },
            AgentMessage::ExtensionResponse { contents: b"query\0extension".to_vec() },
            AgentMessage::ExtensionFailure,
            AgentMessage::AddIdentity {
                private_key: ed25519_private_key(),
                comment: b"added key".to_vec(),
            },
            AgentMessage::AddIdentityConstrained {
                private_key: ed25519_private_key(),
                comment: b"added key".to_vec(),
                constraints: vec![
                    AgentConstraint::Lifetime { seconds: 60 },
                    AgentConstraint::Confirm,
                    AgentConstraint::MaxSignatures { count: 3 },
                    AgentConstraint::Extension {
                        name: b"example@openssh.com".to_vec(),
                        details: b"opaque details".to_vec(),
                    },
                ],
            },
            AgentMessage::RemoveIdentity { key_blob: KEY.to_vec() },
            AgentMessage::RemoveAllIdentities,
            AgentMessage::AddSmartcardKey {
                provider: b"\\\\.\\\\CAPI".to_vec(),
                pin: SecretVec::new(b"secret".to_vec()),
                flags: 3,
            },
            AgentMessage::RemoveSmartcardKey { provider: b"\\\\.\\\\CAPI".to_vec(), flags: 3 },
            AgentMessage::Lock { passphrase: b"secret".to_vec() },
            AgentMessage::Unlock { passphrase: b"secret".to_vec() },
            AgentMessage::Success,
            AgentMessage::Failure,
        ];
        for message in messages {
            let frame = message.encode_frame().expect("frame");
            assert_eq!(AgentMessage::decode_frame(&frame).expect("decode"), message);
        }
    }

    #[test]
    fn client_and_server_complete_identity_and_sign_round_trip() {
        let store = Store {
            identity: AgentIdentity::new(KEY, b"work key").expect("identity"),
            signature: b"signed payload".to_vec(),
        };
        let mut client = AgentClient::new(Loopback { server: AgentServer::new(store) });
        assert_eq!(client.identities().expect("identities").len(), 1);
        assert_eq!(
            client.sign(KEY, b"payload", AGENT_SIGN_FLAG_RSA_SHA2_512).expect("signature"),
            b"signed payload"
        );
        assert_eq!(
            client.extension(b"query", b"supported").expect("extension"),
            b"query\0session-bind@openssh.com"
        );
        let private_key = ed25519_private_key();
        client.add_identity(&private_key, b"added key").expect("add identity");
        client
            .add_identity_constrained(
                &private_key,
                b"added key",
                &[AgentConstraint::Lifetime { seconds: 60 }, AgentConstraint::Confirm],
            )
            .expect("add constrained identity");
        client.remove_all_identities().expect("remove all");
        client.remove_identity(KEY).expect("remove identity");
        client.add_smartcard_key(b"provider", b"pin", 7).expect("smart-card add");
        client.remove_smartcard_key(b"provider", 7).expect("smart-card remove");
        client.lock(b"secret").expect("lock");
        client.unlock(b"secret").expect("unlock");
    }

    #[test]
    fn server_maps_unknown_key_and_store_failures_to_opaque_failure() {
        let store = Store {
            identity: AgentIdentity::new(KEY, b"work key").expect("identity"),
            signature: b"signed payload".to_vec(),
        };
        let server = AgentServer::new(store);
        let request = AgentMessage::SignRequest {
            key_blob: b"other key".to_vec(),
            data: b"payload".to_vec(),
            flags: 0,
        };
        assert_eq!(server.dispatch(request), AgentMessage::Failure);
        let mut client = AgentClient::new(Loopback { server });
        assert_eq!(client.sign(b"other key", b"payload", 0), Err(AgentError::AgentFailure));
        assert_eq!(client.extension(b"unknown", b"request"), Err(AgentError::AgentFailure));
    }

    #[test]
    fn forwarded_signatures_fail_closed_and_require_authorization() {
        let request = AgentMessage::SignRequest {
            key_blob: KEY.to_vec(),
            data: b"payload".to_vec(),
            flags: AGENT_SIGN_FLAG_RSA_SHA2_512,
        };
        let server = AgentServer::new(Store {
            identity: AgentIdentity::new(KEY, b"work key").expect("identity"),
            signature: b"signed payload".to_vec(),
        });

        let disabled = AgentForwardingPolicy::disabled(Authorizer { allowed: true });
        assert!(!disabled.is_enabled());
        assert_eq!(server.dispatch_forwarded(request.clone(), &disabled), AgentMessage::Failure);

        let denied = AgentForwardingPolicy::enabled(Authorizer { allowed: false });
        assert!(denied.is_enabled());
        assert_eq!(server.dispatch_forwarded(request.clone(), &denied), AgentMessage::Failure);

        let allowed = AgentForwardingPolicy::enabled(Authorizer { allowed: true });
        assert_eq!(
            server.dispatch_forwarded(request, &allowed),
            AgentMessage::SignResponse { signature: b"signed payload".to_vec() }
        );

        let request = AgentMessage::SignRequest {
            key_blob: KEY.to_vec(),
            data: b"payload".to_vec(),
            flags: 0,
        }
        .encode_frame()
        .expect("request");
        let mut stream = ScriptedStream::new(request, 2);
        server.serve_forwarded(&mut stream, &allowed).expect("forwarded serve");
        assert_eq!(
            AgentMessage::decode_frame(&stream.written).expect("response"),
            AgentMessage::SignResponse { signature: b"signed payload".to_vec() }
        );
    }

    #[test]
    fn forwarding_adapter_reassembles_fragmented_and_multiple_frames() {
        let mut adapter = forwarding_adapter(b"signed payload".to_vec());
        let mut wire = AgentMessage::RequestIdentities.encode_frame().expect("identities");
        wire.extend_from_slice(
            &AgentMessage::SignRequest {
                key_blob: KEY.to_vec(),
                data: b"payload".to_vec(),
                flags: AGENT_SIGN_FLAG_RSA_SHA2_512,
            }
            .encode_frame()
            .expect("sign"),
        );

        let mut responses = Vec::new();
        for byte in wire {
            responses.extend(adapter.push(&[byte]).expect("fragment"));
        }
        assert_eq!(
            decode_agent_frames(&responses),
            vec![
                AgentMessage::IdentitiesAnswer {
                    identities: vec![AgentIdentity::new(KEY, b"work key").expect("identity")],
                },
                AgentMessage::SignResponse { signature: b"signed payload".to_vec() },
            ]
        );
        assert_eq!(adapter.buffered_len(), 0);
        adapter.finish().expect("clean close");
    }

    #[test]
    fn forwarding_adapter_splits_large_responses_into_channel_data_fragments() {
        let mut adapter = forwarding_adapter(vec![b's'; MAX_CHANNEL_STRING]);
        let request = AgentMessage::SignRequest {
            key_blob: KEY.to_vec(),
            data: b"payload".to_vec(),
            flags: 0,
        }
        .encode_frame()
        .expect("sign");
        let responses = adapter.push(&request).expect("response");
        assert_eq!(responses.len(), 2);
        assert!(responses.iter().all(|fragment| fragment.data.len() <= MAX_CHANNEL_STRING));
        assert_eq!(
            decode_agent_frames(&responses),
            vec![AgentMessage::SignResponse { signature: vec![b's'; MAX_CHANNEL_STRING] }]
        );
    }

    #[test]
    fn forwarding_adapter_rejects_management_and_extension_requests() {
        let private_key = ed25519_private_key();
        let requests = [
            AgentMessage::AddIdentity {
                private_key: private_key.clone(),
                comment: b"added key".to_vec(),
            },
            AgentMessage::AddIdentityConstrained {
                private_key,
                comment: b"added key".to_vec(),
                constraints: vec![AgentConstraint::Confirm],
            },
            AgentMessage::RemoveIdentity { key_blob: KEY.to_vec() },
            AgentMessage::RemoveAllIdentities,
            AgentMessage::AddSmartcardKey {
                provider: b"provider".to_vec(),
                pin: SecretVec::new(b"pin".to_vec()),
                flags: 0,
            },
            AgentMessage::RemoveSmartcardKey { provider: b"provider".to_vec(), flags: 0 },
            AgentMessage::Lock { passphrase: b"passphrase".to_vec() },
            AgentMessage::Unlock { passphrase: b"passphrase".to_vec() },
            AgentMessage::ExtensionRequest {
                name: b"query".to_vec(),
                contents: b"supported".to_vec(),
            },
        ];
        let mut adapter = forwarding_adapter(b"signature".to_vec());
        for request in requests {
            let frame = request.encode_frame().expect("request");
            assert_eq!(
                decode_agent_frames(&adapter.push(&frame).expect("failure response")),
                [AgentMessage::Failure]
            );
        }
        adapter.finish().expect("clean close");
    }

    #[test]
    fn forwarding_adapter_distinguishes_clean_close_and_truncation() {
        let mut clean = forwarding_adapter(b"signature".to_vec());
        assert_eq!(clean.finish(), Ok(()));
        assert!(clean.is_closed());
        assert_eq!(clean.push(&[]), Err(AgentError::ForwardingClosed));

        let frame = AgentMessage::RequestIdentities.encode_frame().expect("request");
        let mut truncated = forwarding_adapter(b"signature".to_vec());
        truncated.push(&frame[..frame.len() - 1]).expect("partial frame");
        assert_eq!(truncated.buffered_len(), frame.len() - 1);
        assert_eq!(truncated.finish(), Err(AgentError::ForwardingTruncated));
        assert!(truncated.is_closed());
    }

    #[test]
    fn forwarding_adapter_bounds_frames_and_response_count() {
        let oversized = (u32::try_from(MAX_AGENT_FRAME).expect("limit") + 1).to_be_bytes();
        let mut oversized_adapter = forwarding_adapter(b"signature".to_vec());
        assert_eq!(oversized_adapter.push(&oversized), Err(AgentError::FrameTooLarge));
        assert!(oversized_adapter.is_closed());

        let request = AgentMessage::RequestIdentities.encode_frame().expect("request");
        let mut many = Vec::new();
        for _ in 0..=MAX_AGENT_FORWARD_RESPONSES {
            many.extend_from_slice(&request);
        }
        let mut limited = forwarding_adapter(b"signature".to_vec());
        assert_eq!(limited.push(&many), Err(AgentError::ForwardingResponseLimit));
        assert!(limited.is_closed());
    }

    #[test]
    fn malformed_and_unbounded_peer_frames_are_rejected() {
        assert_eq!(
            AgentMessage::decode_frame(&[0, 0, 0, 1]),
            Err(AgentError::MalformedFrame("frame length does not match input"))
        );
        let oversized = (u32::try_from(MAX_AGENT_FRAME).expect("test limit") + 1).to_be_bytes();
        assert_eq!(AgentMessage::decode_frame(&oversized), Err(AgentError::FrameTooLarge));

        let mut request = vec![0, 0, 0, 1 + 4 + 1];
        request.extend_from_slice(&[SIGN_REQUEST, 0, 0, 0, 0, 0]);
        assert_eq!(
            AgentMessage::decode_frame(&request),
            Err(AgentError::MalformedFrame("key blob"))
        );

        let too_many = AgentMessage::IdentitiesAnswer {
            identities: (0..=MAX_AGENT_IDENTITIES)
                .map(|_| AgentIdentity::new(KEY, b"comment").expect("identity"))
                .collect(),
        };
        assert_eq!(too_many.encode_frame(), Err(AgentError::FieldTooLarge("identity count")));

        let private_key = ed25519_private_key();
        let mut payload = vec![ADD_IDENTITY_CONSTRAINED];
        payload.extend_from_slice(private_key.as_bytes());
        append_test_string(&mut payload, b"comment");
        payload.push(0x7f);
        let mut frame = (u32::try_from(payload.len()).expect("test frame")).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        assert_eq!(
            AgentMessage::decode_frame(&frame),
            Err(AgentError::MalformedFrame("unsupported identity constraint"))
        );

        let mut payload = vec![EXTENSION];
        append_test_string(&mut payload, b"query");
        append_test_string(&mut payload, b"contents");
        payload.push(0x01);
        let mut frame = (u32::try_from(payload.len()).expect("test frame")).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        assert_eq!(
            AgentMessage::decode_frame(&frame),
            Err(AgentError::MalformedFrame("extension request trailing data"))
        );

        let mut payload = vec![EXTENSION_FAILURE, 0];
        let mut frame = (u32::try_from(payload.len()).expect("test frame")).to_be_bytes().to_vec();
        frame.append(&mut payload);
        assert_eq!(
            AgentMessage::decode_frame(&frame),
            Err(AgentError::MalformedFrame("extension failure payload"))
        );
    }

    #[test]
    fn private_key_parser_accepts_standard_software_key_layouts() {
        for (algorithm, field_count) in [
            (b"ssh-rsa".as_slice(), 6),
            (b"ssh-dss".as_slice(), 5),
            (b"ecdsa-sha2-nistp256".as_slice(), 3),
            (b"ecdsa-sha2-nistp384".as_slice(), 3),
            (b"ecdsa-sha2-nistp521".as_slice(), 3),
            (b"ssh-ed25519".as_slice(), 2),
        ] {
            let mut encoded = Vec::new();
            append_test_string(&mut encoded, algorithm);
            for _ in 0..field_count {
                append_test_string(&mut encoded, b"field");
            }
            AgentPrivateKey::new(encoded).expect("standard private key layout");
        }
    }

    #[test]
    fn agent_identity_and_sign_data_limits_are_enforced() {
        let mut unknown_key = Vec::new();
        append_test_string(&mut unknown_key, b"unknown");
        assert_eq!(
            AgentPrivateKey::new(unknown_key),
            Err(AgentError::MalformedFrame("unsupported private key algorithm"))
        );
        assert_eq!(
            AgentIdentity::new(vec![0; MAX_AGENT_KEY_BLOB + 1], b"comment"),
            Err(AgentError::FieldTooLarge("key blob"))
        );
        assert_eq!(
            AgentMessage::SignRequest {
                key_blob: KEY.to_vec(),
                data: vec![0; MAX_AGENT_SIGN_DATA + 1],
                flags: 0,
            }
            .encode_frame(),
            Err(AgentError::FieldTooLarge("sign data"))
        );
        assert_eq!(
            AgentMessage::Lock { passphrase: vec![0; MAX_AGENT_PASSPHRASE + 1] }.encode_frame(),
            Err(AgentError::FieldTooLarge("passphrase"))
        );
        let mut client = AgentClient::new(Loopback {
            server: AgentServer::new(Store {
                identity: AgentIdentity::new(KEY, b"work key").expect("identity"),
                signature: b"signed payload".to_vec(),
            }),
        });
        assert_eq!(
            client.lock(&vec![0; MAX_AGENT_PASSPHRASE + 1]),
            Err(AgentError::FieldTooLarge("passphrase"))
        );
        assert_eq!(client.remove_identity(&[]), Err(AgentError::MalformedFrame("key blob")));
        assert_eq!(
            client.add_smartcard_key(&[], b"pin", 0),
            Err(AgentError::MalformedFrame("smart-card provider"))
        );
        assert_eq!(
            client.remove_smartcard_key(&[], 0),
            Err(AgentError::MalformedFrame("smart-card provider"))
        );
        assert_eq!(
            client.add_smartcard_key(&vec![0; MAX_AGENT_PROVIDER + 1], b"pin", 0),
            Err(AgentError::FieldTooLarge("smart-card provider"))
        );
        assert_eq!(
            client.add_smartcard_key(b"provider", &vec![0; MAX_AGENT_PASSPHRASE + 1], 0),
            Err(AgentError::FieldTooLarge("smart-card PIN"))
        );
        assert_eq!(
            client.extension(&[], b"contents"),
            Err(AgentError::MalformedFrame("extension name"))
        );
        assert_eq!(
            client.extension(b"extension", &vec![0; MAX_AGENT_EXTENSION_DATA + 1]),
            Err(AgentError::FieldTooLarge("extension contents"))
        );
        let private_key = ed25519_private_key();
        assert_eq!(
            client.add_identity_constrained(&private_key, b"comment", &[]),
            Err(AgentError::MalformedFrame("identity constraints"))
        );
        assert_eq!(
            AgentMessage::AddIdentityConstrained {
                private_key,
                comment: b"comment".to_vec(),
                constraints: vec![AgentConstraint::Extension {
                    name: b"extension".to_vec(),
                    details: vec![0; MAX_AGENT_EXTENSION_DETAILS + 1],
                }],
            }
            .encode_frame(),
            Err(AgentError::FieldTooLarge("identity extension details"))
        );
    }

    #[test]
    fn agent_debug_redacts_signed_data_and_passphrases() {
        let sign_debug = format!(
            "{:?}",
            AgentMessage::SignRequest {
                key_blob: KEY.to_vec(),
                data: b"private signed payload".to_vec(),
                flags: 0,
            }
        );
        assert!(!sign_debug.contains("private signed payload"));
        assert!(sign_debug.contains("data_len"));

        let lock_debug =
            format!("{:?}", AgentMessage::Lock { passphrase: b"private passphrase".to_vec() });
        assert!(!lock_debug.contains("private passphrase"));
        assert!(lock_debug.contains("passphrase_len"));

        let smartcard_debug = format!(
            "{:?}",
            AgentMessage::AddSmartcardKey {
                provider: b"provider".to_vec(),
                pin: SecretVec::new(b"private pin".to_vec()),
                flags: 0,
            }
        );
        assert!(!smartcard_debug.contains("private pin"));
        assert!(smartcard_debug.contains("pin_len"));

        let private_key_debug = format!("{:?}", ed25519_private_key());
        assert!(!private_key_debug.contains('8'));
        assert!(private_key_debug.contains("encoded_len"));

        let add_debug = format!(
            "{:?}",
            AgentMessage::AddIdentity {
                private_key: ed25519_private_key(),
                comment: b"private comment".to_vec(),
            }
        );
        assert!(!add_debug.contains("private comment"));
        assert!(add_debug.contains("comment_len"));

        let extension_debug = format!(
            "{:?}",
            AgentMessage::ExtensionRequest {
                name: b"private-extension".to_vec(),
                contents: b"private extension content".to_vec(),
            }
        );
        assert!(!extension_debug.contains("private extension content"));
        assert!(extension_debug.contains("contents_len"));
    }
}
