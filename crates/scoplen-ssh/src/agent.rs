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

use scoplen_crypto::SecretVec;
use thiserror::Error;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REMOVE_IDENTITY: u8 = 18;
const REMOVE_ALL_IDENTITIES: u8 = 19;
const ADD_SMARTCARD_KEY: u8 = 20;
const REMOVE_SMARTCARD_KEY: u8 = 21;
const LOCK: u8 = 22;
const UNLOCK: u8 = 23;

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
        if let AgentMessage::SignRequest { ref key_blob, ref data, flags } = request {
            if policy.authorize_signature(key_blob, data, flags).is_err() {
                return AgentMessage::Failure;
            }
        }
        self.dispatch(request)
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
        SUCCESS => Err(AgentError::MalformedFrame("success payload")),
        FAILURE if rest.is_empty() => Ok(AgentMessage::Failure),
        FAILURE => Err(AgentError::MalformedFrame("failure payload")),
        other => Err(AgentError::UnsupportedMessage(other)),
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
    }

    #[test]
    fn agent_identity_and_sign_data_limits_are_enforced() {
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
    }
}
