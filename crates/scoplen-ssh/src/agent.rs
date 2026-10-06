// SPDX-License-Identifier: Apache-2.0
//! Bounded SSH agent protocol messages and client/server dispatch.
//!
//! The platform-specific socket, named-pipe, and Pageant adapters implement [`AgentChannel`].
//! This module owns the OpenSSH agent framing and the request/response boundary so every adapter
//! applies the same length, ordering, and failure rules.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::io::{Read, Write};

use thiserror::Error;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentMessage {
    /// Request the identities currently held by the agent.
    RequestIdentities,
    /// Ask the agent to sign data with one exact public-key blob.
    SignRequest { key_blob: Vec<u8>, data: Vec<u8>, flags: u32 },
    /// Return the identities currently held by the agent.
    IdentitiesAnswer { identities: Vec<AgentIdentity> },
    /// Return an SSH signature blob.
    SignResponse { signature: Vec<u8> },
    /// Return a generic success response.
    Success,
    /// Return a generic failure response.
    Failure,
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
}

/// Key store operations needed by the agent server boundary.
pub trait AgentKeyStore {
    /// Return the current public identities.
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError>;

    /// Sign data for a key that exactly matches one stored identity.
    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError>;
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
            _ => AgentMessage::Failure,
        }
    }

    /// Decode, dispatch, and encode one complete request frame.
    pub fn dispatch_frame(&self, frame: &[u8]) -> Result<Vec<u8>, AgentError> {
        let request = AgentMessage::decode_frame(frame)?;
        let response = self.dispatch(request);
        response.encode_frame().or_else(|_| AgentMessage::Failure.encode_frame())
    }

    /// Return the backing key store.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.store
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
        SUCCESS if rest.is_empty() => Ok(AgentMessage::Success),
        SUCCESS => Err(AgentError::MalformedFrame("success payload")),
        FAILURE if rest.is_empty() => Ok(AgentMessage::Failure),
        FAILURE => Err(AgentError::MalformedFrame("failure payload")),
        other => Err(AgentError::UnsupportedMessage(other)),
    }
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
    }
}
