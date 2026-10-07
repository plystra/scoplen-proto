// SPDX-License-Identifier: Apache-2.0
//! Bounded, engine-independent SSH channel and request codecs.
//!
//! This module stops at the RFC 4254 message boundary.  A concrete SSH engine owns channel
//! scheduling, windows, and I/O; consumers use these types to validate and construct the wire
//! messages without depending on that engine.  Every peer-controlled string and byte field has a
//! finite limit, and decoders consume exactly one complete SSH message.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::fmt;

use thiserror::Error;

const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
const SSH_MSG_REQUEST_FAILURE: u8 = 82;
const SSH_MSG_CHANNEL_OPEN: u8 = 90;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const SSH_MSG_CHANNEL_DATA: u8 = 94;
const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const SSH_MSG_CHANNEL_EOF: u8 = 96;
const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

const CHANNEL_OPEN_SESSION: &str = "session";
const CHANNEL_OPEN_DIRECT_TCPIP: &str = "direct-tcpip";
const CHANNEL_OPEN_FORWARDED_TCPIP: &str = "forwarded-tcpip";
const CHANNEL_OPEN_DIRECT_STREAMLOCAL: &str = "direct-streamlocal@openssh.com";
const CHANNEL_OPEN_FORWARDED_STREAMLOCAL: &str = "forwarded-streamlocal@openssh.com";
const CHANNEL_OPEN_AUTH_AGENT: &str = "auth-agent@openssh.com";

const REQUEST_TCPIP_FORWARD: &str = "tcpip-forward";
const REQUEST_CANCEL_TCPIP_FORWARD: &str = "cancel-tcpip-forward";
const REQUEST_STREAMLOCAL_FORWARD: &str = "streamlocal-forward@openssh.com";
const REQUEST_CANCEL_STREAMLOCAL_FORWARD: &str = "cancel-streamlocal-forward@openssh.com";

/// Maximum complete channel message, including its one-byte message number.
pub const MAX_CHANNEL_MESSAGE: usize = 256 * 1024;
/// Maximum SSH string accepted by a channel codec.
pub const MAX_CHANNEL_STRING: usize = 64 * 1024;
/// Maximum channel or request name.
pub const MAX_CHANNEL_NAME: usize = 128;
/// Maximum terminal-mode string in a `pty-req` request.
pub const MAX_PTY_MODES: usize = 64 * 1024;
/// Maximum address or Unix socket path.
pub const MAX_CHANNEL_ADDRESS: usize = 4096;
/// Maximum command, subsystem, environment, or diagnostic text.
pub const MAX_CHANNEL_TEXT: usize = 64 * 1024;

/// Errors returned by the bounded RFC 4254 channel codecs.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChannelCodecError {
    /// The message was truncated, had trailing bytes, or otherwise violated its wire shape.
    #[error("malformed SSH channel message: {0}")]
    MalformedMessage(&'static str),
    /// A peer-controlled field exceeded its limit.
    #[error("SSH channel field is too large: {0}")]
    FieldTooLarge(&'static str),
    /// A channel open type is not implemented by this boundary.
    #[error("unsupported SSH channel type: {0}")]
    UnsupportedChannelType(String),
    /// A channel request name is not implemented by this boundary.
    #[error("unsupported SSH channel request: {0}")]
    UnsupportedChannelRequest(String),
    /// A global request name is not implemented by this boundary.
    #[error("unsupported SSH global request: {0}")]
    UnsupportedGlobalRequest(String),
    /// A channel extended-data type is not implemented by this boundary.
    #[error("unsupported SSH extended-data type: {0}")]
    UnsupportedExtendedDataType(u32),
    /// A channel-open failure reason outside RFC 4254 was received.
    #[error("unknown SSH channel-open failure reason: {0}")]
    UnknownOpenFailureReason(u32),
    /// A text field is invalid for its protocol role.
    #[error("invalid SSH channel field: {0}")]
    InvalidField(&'static str),
    /// A numeric or otherwise constrained field has an invalid value.
    #[error("invalid SSH channel value: {0}")]
    InvalidValue(&'static str),
}

/// The supported channel-open type and its type-specific RFC 4254 fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelOpenType {
    /// A terminal or subsystem session channel.
    Session,
    /// A client-originated TCP forwarding channel.
    DirectTcpip {
        /// Destination host or address.
        target_address: Vec<u8>,
        /// Destination TCP port.
        target_port: u32,
        /// Source address reported to the peer.
        originator_address: Vec<u8>,
        /// Source TCP port reported to the peer.
        originator_port: u32,
    },
    /// A server-originated TCP forwarding channel.
    ForwardedTcpip {
        /// Address on which the server accepted the forwarded connection.
        connected_address: Vec<u8>,
        /// Port on which the server accepted the forwarded connection.
        connected_port: u32,
        /// Source address reported by the connecting peer.
        originator_address: Vec<u8>,
        /// Source TCP port reported by the connecting peer.
        originator_port: u32,
    },
    /// A client-originated Unix socket forwarding channel.
    DirectStreamLocal {
        /// Unix socket path.
        socket_path: Vec<u8>,
        /// RFC 4254 reserved field.  It must be empty.
        reserved: Vec<u8>,
    },
    /// A server-originated Unix socket forwarding channel.
    ForwardedStreamLocal {
        /// Unix socket path requested by the listener.
        socket_path: Vec<u8>,
        /// RFC 4254 reserved field.  It must be empty.
        reserved: Vec<u8>,
    },
    /// An OpenSSH agent-forwarding channel.
    AuthAgent,
}

impl ChannelOpenType {
    /// Return the SSH channel type string.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Session => CHANNEL_OPEN_SESSION,
            Self::DirectTcpip { .. } => CHANNEL_OPEN_DIRECT_TCPIP,
            Self::ForwardedTcpip { .. } => CHANNEL_OPEN_FORWARDED_TCPIP,
            Self::DirectStreamLocal { .. } => CHANNEL_OPEN_DIRECT_STREAMLOCAL,
            Self::ForwardedStreamLocal { .. } => CHANNEL_OPEN_FORWARDED_STREAMLOCAL,
            Self::AuthAgent => CHANNEL_OPEN_AUTH_AGENT,
        }
    }
}

/// An `SSH_MSG_CHANNEL_OPEN` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOpen {
    /// Channel type and type-specific fields.
    pub channel_type: ChannelOpenType,
    /// Sender's channel number.
    pub sender_channel: u32,
    /// Initial receive window in bytes.
    pub initial_window_size: u32,
    /// Maximum data packet size accepted by the sender.
    pub maximum_packet_size: u32,
}

impl ChannelOpen {
    /// Construct a channel-open message after validating all type-specific fields.
    pub fn new(
        channel_type: ChannelOpenType,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    ) -> Result<Self, ChannelCodecError> {
        let message =
            Self { channel_type, sender_channel, initial_window_size, maximum_packet_size };
        message.validate()?;
        Ok(message)
    }

    /// Encode one complete `SSH_MSG_CHANNEL_OPEN` message.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        self.validate()?;
        let mut encoder = Encoder::new(SSH_MSG_CHANNEL_OPEN);
        encoder.string(self.channel_type.name().as_bytes(), MAX_CHANNEL_NAME, "channel type")?;
        encoder.u32(self.sender_channel);
        encoder.u32(self.initial_window_size);
        encoder.u32(self.maximum_packet_size);
        match &self.channel_type {
            ChannelOpenType::Session | ChannelOpenType::AuthAgent => {}
            ChannelOpenType::DirectTcpip {
                target_address,
                target_port,
                originator_address,
                originator_port,
            }
            | ChannelOpenType::ForwardedTcpip {
                connected_address: target_address,
                connected_port: target_port,
                originator_address,
                originator_port,
            } => {
                encoder.string(target_address, MAX_CHANNEL_ADDRESS, "channel address")?;
                encoder.u32(*target_port);
                encoder.string(originator_address, MAX_CHANNEL_ADDRESS, "originator address")?;
                encoder.u32(*originator_port);
            }
            ChannelOpenType::DirectStreamLocal { socket_path, reserved } => {
                encoder.string(socket_path, MAX_CHANNEL_ADDRESS, "socket path")?;
                encoder.string(reserved, MAX_CHANNEL_STRING, "reserved field")?;
            }
            ChannelOpenType::ForwardedStreamLocal { socket_path, reserved } => {
                encoder.string(socket_path, MAX_CHANNEL_ADDRESS, "socket path")?;
                encoder.string(reserved, MAX_CHANNEL_STRING, "reserved field")?;
            }
        }
        encoder.finish()
    }

    /// Decode exactly one complete `SSH_MSG_CHANNEL_OPEN` message.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_CHANNEL_OPEN)?;
        let channel_name = reader.name("channel type")?;
        let sender_channel = reader.u32("sender channel")?;
        let initial_window_size = reader.u32("initial window")?;
        let maximum_packet_size = reader.u32("maximum packet")?;
        let channel_type = match channel_name.as_str() {
            CHANNEL_OPEN_SESSION => ChannelOpenType::Session,
            CHANNEL_OPEN_AUTH_AGENT => ChannelOpenType::AuthAgent,
            CHANNEL_OPEN_DIRECT_TCPIP => ChannelOpenType::DirectTcpip {
                target_address: reader.bytes(MAX_CHANNEL_ADDRESS, "channel address")?,
                target_port: reader.u32("target port")?,
                originator_address: reader.bytes(MAX_CHANNEL_ADDRESS, "originator address")?,
                originator_port: reader.u32("originator port")?,
            },
            CHANNEL_OPEN_FORWARDED_TCPIP => ChannelOpenType::ForwardedTcpip {
                connected_address: reader.bytes(MAX_CHANNEL_ADDRESS, "connected address")?,
                connected_port: reader.u32("connected port")?,
                originator_address: reader.bytes(MAX_CHANNEL_ADDRESS, "originator address")?,
                originator_port: reader.u32("originator port")?,
            },
            CHANNEL_OPEN_DIRECT_STREAMLOCAL => ChannelOpenType::DirectStreamLocal {
                socket_path: reader.bytes(MAX_CHANNEL_ADDRESS, "socket path")?,
                reserved: reader.bytes(MAX_CHANNEL_STRING, "reserved field")?,
            },
            CHANNEL_OPEN_FORWARDED_STREAMLOCAL => ChannelOpenType::ForwardedStreamLocal {
                socket_path: reader.bytes(MAX_CHANNEL_ADDRESS, "socket path")?,
                reserved: reader.bytes(MAX_CHANNEL_STRING, "reserved field")?,
            },
            _ => return Err(ChannelCodecError::UnsupportedChannelType(channel_name)),
        };
        reader.finish()?;
        let message =
            Self { channel_type, sender_channel, initial_window_size, maximum_packet_size };
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> Result<(), ChannelCodecError> {
        if self.maximum_packet_size == 0 {
            return Err(ChannelCodecError::InvalidValue("maximum packet size"));
        }
        match &self.channel_type {
            ChannelOpenType::Session | ChannelOpenType::AuthAgent => {}
            ChannelOpenType::DirectTcpip { target_address, originator_address, .. }
            | ChannelOpenType::ForwardedTcpip {
                connected_address: target_address,
                originator_address,
                ..
            } => {
                validate_text(target_address, MAX_CHANNEL_ADDRESS, "channel address", false)?;
                validate_text(
                    originator_address,
                    MAX_CHANNEL_ADDRESS,
                    "originator address",
                    false,
                )?;
            }
            ChannelOpenType::DirectStreamLocal { socket_path, reserved }
            | ChannelOpenType::ForwardedStreamLocal { socket_path, reserved } => {
                validate_text(socket_path, MAX_CHANNEL_ADDRESS, "socket path", true)?;
                if !reserved.is_empty() {
                    return Err(ChannelCodecError::InvalidValue("streamlocal reserved field"));
                }
                validate_size(reserved, MAX_CHANNEL_STRING, "reserved field")?;
            }
        }
        Ok(())
    }
}

/// RFC 4254 channel-open failure reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ChannelOpenFailureReason {
    /// The administrative policy rejected the request.
    AdministrativelyProhibited = 1,
    /// The target connection could not be established.
    ConnectFailed = 2,
    /// The requested channel type is unknown to the peer.
    UnknownChannelType = 3,
    /// The peer lacked resources to create the channel.
    ResourceShortage = 4,
}

impl TryFrom<u32> for ChannelOpenFailureReason {
    type Error = ChannelCodecError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AdministrativelyProhibited),
            2 => Ok(Self::ConnectFailed),
            3 => Ok(Self::UnknownChannelType),
            4 => Ok(Self::ResourceShortage),
            other => Err(ChannelCodecError::UnknownOpenFailureReason(other)),
        }
    }
}

/// An `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOpenConfirmation {
    /// Recipient channel number from the open request.
    pub recipient_channel: u32,
    /// Sender's newly allocated channel number.
    pub sender_channel: u32,
    /// Initial receive window in bytes.
    pub initial_window_size: u32,
    /// Maximum data packet size accepted by the sender.
    pub maximum_packet_size: u32,
}

impl ChannelOpenConfirmation {
    /// Encode one complete open confirmation.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        validate_packet_size(self.maximum_packet_size)?;
        let mut encoder = Encoder::new(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        encoder.u32(self.recipient_channel);
        encoder.u32(self.sender_channel);
        encoder.u32(self.initial_window_size);
        encoder.u32(self.maximum_packet_size);
        encoder.finish()
    }

    /// Decode exactly one complete open confirmation.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_CHANNEL_OPEN_CONFIRMATION)?;
        let message = Self {
            recipient_channel: reader.u32("recipient channel")?,
            sender_channel: reader.u32("sender channel")?,
            initial_window_size: reader.u32("initial window")?,
            maximum_packet_size: reader.u32("maximum packet")?,
        };
        reader.finish()?;
        validate_packet_size(message.maximum_packet_size)?;
        Ok(message)
    }
}

/// An `SSH_MSG_CHANNEL_OPEN_FAILURE` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelOpenFailure {
    /// Recipient channel number from the open request.
    pub recipient_channel: u32,
    /// RFC 4254 failure reason.
    pub reason: ChannelOpenFailureReason,
    /// Human-readable diagnostic text.
    pub description: Vec<u8>,
    /// RFC 3066 language tag, normally empty.
    pub language_tag: Vec<u8>,
}

impl ChannelOpenFailure {
    /// Encode one complete open failure.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        validate_text(&self.description, MAX_CHANNEL_TEXT, "failure description", false)?;
        validate_text(&self.language_tag, MAX_CHANNEL_NAME, "language tag", false)?;
        let mut encoder = Encoder::new(SSH_MSG_CHANNEL_OPEN_FAILURE);
        encoder.u32(self.recipient_channel);
        encoder.u32(self.reason as u32);
        encoder.string(&self.description, MAX_CHANNEL_TEXT, "failure description")?;
        encoder.string(&self.language_tag, MAX_CHANNEL_NAME, "language tag")?;
        encoder.finish()
    }

    /// Decode exactly one complete open failure.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_CHANNEL_OPEN_FAILURE)?;
        let recipient_channel = reader.u32("recipient channel")?;
        let reason = ChannelOpenFailureReason::try_from(reader.u32("failure reason")?)?;
        let description = reader.bytes(MAX_CHANNEL_TEXT, "failure description")?;
        let language_tag = reader.bytes(MAX_CHANNEL_NAME, "language tag")?;
        reader.finish()?;
        validate_text(&description, MAX_CHANNEL_TEXT, "failure description", false)?;
        validate_text(&language_tag, MAX_CHANNEL_NAME, "language tag", false)?;
        Ok(Self { recipient_channel, reason, description, language_tag })
    }
}

/// An `SSH_MSG_CHANNEL_WINDOW_ADJUST` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelWindowAdjust {
    /// Recipient channel number.
    pub recipient_channel: u32,
    /// Additional receive window in bytes.
    pub bytes_to_add: u32,
}

impl ChannelWindowAdjust {
    /// Encode one complete window adjustment.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        let mut encoder = Encoder::new(SSH_MSG_CHANNEL_WINDOW_ADJUST);
        encoder.u32(self.recipient_channel);
        encoder.u32(self.bytes_to_add);
        encoder.finish()
    }

    /// Decode exactly one complete window adjustment.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_CHANNEL_WINDOW_ADJUST)?;
        let message = Self {
            recipient_channel: reader.u32("recipient channel")?,
            bytes_to_add: reader.u32("window increment")?,
        };
        reader.finish()?;
        Ok(message)
    }
}

/// An `SSH_MSG_CHANNEL_DATA` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelData {
    /// Recipient channel number.
    pub recipient_channel: u32,
    /// Channel data bytes.
    pub data: Vec<u8>,
}

impl ChannelData {
    /// Encode one complete channel-data message.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        let mut encoder = Encoder::new(SSH_MSG_CHANNEL_DATA);
        encoder.u32(self.recipient_channel);
        encoder.string(&self.data, MAX_CHANNEL_STRING, "channel data")?;
        encoder.finish()
    }

    /// Decode exactly one complete channel-data message.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_CHANNEL_DATA)?;
        let message = Self {
            recipient_channel: reader.u32("recipient channel")?,
            data: reader.bytes(MAX_CHANNEL_STRING, "channel data")?,
        };
        reader.finish()?;
        Ok(message)
    }
}

/// The only RFC 4254 extended-data type supported by the channel boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ExtendedDataType {
    /// Standard error data (`SSH_EXTENDED_DATA_STDERR`).
    Stderr = 1,
}

impl TryFrom<u32> for ExtendedDataType {
    type Error = ChannelCodecError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Stderr),
            other => Err(ChannelCodecError::UnsupportedExtendedDataType(other)),
        }
    }
}

/// An `SSH_MSG_CHANNEL_EXTENDED_DATA` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelExtendedData {
    /// Recipient channel number.
    pub recipient_channel: u32,
    /// Extended-data type.
    pub data_type: ExtendedDataType,
    /// Extended-data bytes.
    pub data: Vec<u8>,
}

impl ChannelExtendedData {
    /// Encode one complete extended-data message.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        let mut encoder = Encoder::new(SSH_MSG_CHANNEL_EXTENDED_DATA);
        encoder.u32(self.recipient_channel);
        encoder.u32(self.data_type as u32);
        encoder.string(&self.data, MAX_CHANNEL_STRING, "extended data")?;
        encoder.finish()
    }

    /// Decode exactly one complete extended-data message.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_CHANNEL_EXTENDED_DATA)?;
        let recipient_channel = reader.u32("recipient channel")?;
        let data_type = ExtendedDataType::try_from(reader.u32("extended-data type")?)?;
        let data = reader.bytes(MAX_CHANNEL_STRING, "extended data")?;
        reader.finish()?;
        Ok(Self { recipient_channel, data_type, data })
    }
}

/// An `SSH_MSG_CHANNEL_EOF` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelEof {
    /// Recipient channel number.
    pub recipient_channel: u32,
}

impl ChannelEof {
    /// Encode one complete channel EOF.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        encode_channel_recipient(SSH_MSG_CHANNEL_EOF, self.recipient_channel)
    }

    /// Decode exactly one complete channel EOF.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        Ok(Self { recipient_channel: decode_channel_recipient(input, SSH_MSG_CHANNEL_EOF)? })
    }
}

/// An `SSH_MSG_CHANNEL_CLOSE` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelClose {
    /// Recipient channel number.
    pub recipient_channel: u32,
}

impl ChannelClose {
    /// Encode one complete channel close.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        encode_channel_recipient(SSH_MSG_CHANNEL_CLOSE, self.recipient_channel)
    }

    /// Decode exactly one complete channel close.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        Ok(Self { recipient_channel: decode_channel_recipient(input, SSH_MSG_CHANNEL_CLOSE)? })
    }
}

/// A successful `SSH_MSG_CHANNEL_SUCCESS` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelSuccess {
    /// Recipient channel number.
    pub recipient_channel: u32,
}

impl ChannelSuccess {
    /// Encode one complete channel success response.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        encode_channel_recipient(SSH_MSG_CHANNEL_SUCCESS, self.recipient_channel)
    }

    /// Decode exactly one complete channel success response.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        Ok(Self { recipient_channel: decode_channel_recipient(input, SSH_MSG_CHANNEL_SUCCESS)? })
    }
}

/// A failed `SSH_MSG_CHANNEL_FAILURE` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelFailure {
    /// Recipient channel number.
    pub recipient_channel: u32,
}

impl ChannelFailure {
    /// Encode one complete channel failure response.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        encode_channel_recipient(SSH_MSG_CHANNEL_FAILURE, self.recipient_channel)
    }

    /// Decode exactly one complete channel failure response.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        Ok(Self { recipient_channel: decode_channel_recipient(input, SSH_MSG_CHANNEL_FAILURE)? })
    }
}

/// The RFC 4254 signal names accepted by the `signal` and `exit-signal` requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signal {
    /// `ABRT`.
    Abrt,
    /// `ALRM`.
    Alrm,
    /// `FPE`.
    Fpe,
    /// `HUP`.
    Hup,
    /// `ILL`.
    Ill,
    /// `INT`.
    Int,
    /// `KILL`.
    Kill,
    /// `PIPE`.
    Pipe,
    /// `QUIT`.
    Quit,
    /// `SEGV`.
    Segv,
    /// `TERM`.
    Term,
    /// `USR1`.
    Usr1,
    /// `USR2`.
    Usr2,
    /// `STOP`.
    Stop,
    /// `TSTP`.
    Tstp,
    /// `TTIN`.
    Ttin,
    /// `TTOU`.
    Ttou,
}

impl Signal {
    /// Return the RFC 4254 signal name without the `SIG` prefix.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Abrt => "ABRT",
            Self::Alrm => "ALRM",
            Self::Fpe => "FPE",
            Self::Hup => "HUP",
            Self::Ill => "ILL",
            Self::Int => "INT",
            Self::Kill => "KILL",
            Self::Pipe => "PIPE",
            Self::Quit => "QUIT",
            Self::Segv => "SEGV",
            Self::Term => "TERM",
            Self::Usr1 => "USR1",
            Self::Usr2 => "USR2",
            Self::Stop => "STOP",
            Self::Tstp => "TSTP",
            Self::Ttin => "TTIN",
            Self::Ttou => "TTOU",
        }
    }

    fn parse(value: &[u8]) -> Result<Self, ChannelCodecError> {
        match value {
            b"ABRT" => Ok(Self::Abrt),
            b"ALRM" => Ok(Self::Alrm),
            b"FPE" => Ok(Self::Fpe),
            b"HUP" => Ok(Self::Hup),
            b"ILL" => Ok(Self::Ill),
            b"INT" => Ok(Self::Int),
            b"KILL" => Ok(Self::Kill),
            b"PIPE" => Ok(Self::Pipe),
            b"QUIT" => Ok(Self::Quit),
            b"SEGV" => Ok(Self::Segv),
            b"TERM" => Ok(Self::Term),
            b"USR1" => Ok(Self::Usr1),
            b"USR2" => Ok(Self::Usr2),
            b"STOP" => Ok(Self::Stop),
            b"TSTP" => Ok(Self::Tstp),
            b"TTIN" => Ok(Self::Ttin),
            b"TTOU" => Ok(Self::Ttou),
            _ => Err(ChannelCodecError::InvalidValue("unsupported signal")),
        }
    }
}

/// Fields in a `pty-req` channel request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtyRequest {
    /// Terminal type, such as `xterm-256color`.
    pub term: Vec<u8>,
    /// Terminal columns.
    pub columns: u32,
    /// Terminal rows.
    pub rows: u32,
    /// Terminal width in pixels.
    pub pixel_width: u32,
    /// Terminal height in pixels.
    pub pixel_height: u32,
    /// Encoded terminal modes.
    pub modes: Vec<u8>,
}

/// Fields in a `window-change` channel request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowChangeRequest {
    /// Terminal columns.
    pub columns: u32,
    /// Terminal rows.
    pub rows: u32,
    /// Terminal width in pixels.
    pub pixel_width: u32,
    /// Terminal height in pixels.
    pub pixel_height: u32,
}

/// Fields in an `exit-signal` channel request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitSignalRequest {
    /// Signal that caused termination.
    pub signal: Signal,
    /// Whether the process produced a core dump.
    pub core_dumped: bool,
    /// Human-readable diagnostic text.
    pub error_message: Vec<u8>,
    /// RFC 3066 language tag.
    pub language_tag: Vec<u8>,
}

/// Supported session and forwarding channel requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelRequestType {
    /// Allocate a PTY with the supplied terminal settings.
    PtyReq(PtyRequest),
    /// Start the user's login shell.
    Shell,
    /// Execute one command.
    Exec { command: Vec<u8> },
    /// Start one subsystem, such as `sftp`.
    Subsystem { name: Vec<u8> },
    /// Set one environment variable.
    Env { name: Vec<u8>, value: Vec<u8> },
    /// Update the PTY dimensions.
    WindowChange(WindowChangeRequest),
    /// Deliver a POSIX signal.
    Signal { signal: Signal },
    /// Return the process exit status.
    ExitStatus { status: u32 },
    /// Return the process signal termination details.
    ExitSignal(ExitSignalRequest),
    /// Send a break for the supplied number of milliseconds.
    Break { milliseconds: u32 },
    /// Request an OpenSSH agent-forwarding channel.
    AuthAgentReq,
}

impl ChannelRequestType {
    /// Return the RFC 4254/OpenSSH request name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PtyReq(_) => "pty-req",
            Self::Shell => "shell",
            Self::Exec { .. } => "exec",
            Self::Subsystem { .. } => "subsystem",
            Self::Env { .. } => "env",
            Self::WindowChange(_) => "window-change",
            Self::Signal { .. } => "signal",
            Self::ExitStatus { .. } => "exit-status",
            Self::ExitSignal(_) => "exit-signal",
            Self::Break { .. } => "break",
            Self::AuthAgentReq => "auth-agent-req@openssh.com",
        }
    }
}

/// An `SSH_MSG_CHANNEL_REQUEST` message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelRequest {
    /// Recipient channel number.
    pub recipient_channel: u32,
    /// Whether the sender requests a success or failure response.
    pub want_reply: bool,
    /// Request name and fields.
    pub request: ChannelRequestType,
}

impl ChannelRequest {
    /// Construct a channel request after validating its fields.
    pub fn new(
        recipient_channel: u32,
        want_reply: bool,
        request: ChannelRequestType,
    ) -> Result<Self, ChannelCodecError> {
        let message = Self { recipient_channel, want_reply, request };
        message.validate()?;
        Ok(message)
    }

    /// Encode one complete channel request.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        self.validate()?;
        let mut encoder = Encoder::new(SSH_MSG_CHANNEL_REQUEST);
        encoder.u32(self.recipient_channel);
        encoder.string(self.request.name().as_bytes(), MAX_CHANNEL_NAME, "request name")?;
        encoder.bool(self.want_reply);
        match &self.request {
            ChannelRequestType::PtyReq(request) => {
                encoder.string(&request.term, MAX_CHANNEL_TEXT, "terminal type")?;
                encoder.u32(request.columns);
                encoder.u32(request.rows);
                encoder.u32(request.pixel_width);
                encoder.u32(request.pixel_height);
                encoder.string(&request.modes, MAX_PTY_MODES, "terminal modes")?;
            }
            ChannelRequestType::Shell | ChannelRequestType::AuthAgentReq => {}
            ChannelRequestType::Exec { command } => {
                encoder.string(command, MAX_CHANNEL_TEXT, "command")?;
            }
            ChannelRequestType::Subsystem { name } => {
                encoder.string(name, MAX_CHANNEL_TEXT, "subsystem name")?;
            }
            ChannelRequestType::Env { name, value } => {
                encoder.string(name, MAX_CHANNEL_TEXT, "environment name")?;
                encoder.string(value, MAX_CHANNEL_TEXT, "environment value")?;
            }
            ChannelRequestType::WindowChange(request) => {
                encoder.u32(request.columns);
                encoder.u32(request.rows);
                encoder.u32(request.pixel_width);
                encoder.u32(request.pixel_height);
            }
            ChannelRequestType::Signal { signal } => {
                encoder.string(signal.name().as_bytes(), MAX_CHANNEL_NAME, "signal")?;
            }
            ChannelRequestType::ExitStatus { status } => encoder.u32(*status),
            ChannelRequestType::ExitSignal(request) => {
                encoder.string(request.signal.name().as_bytes(), MAX_CHANNEL_NAME, "signal")?;
                encoder.bool(request.core_dumped);
                encoder.string(&request.error_message, MAX_CHANNEL_TEXT, "error message")?;
                encoder.string(&request.language_tag, MAX_CHANNEL_NAME, "language tag")?;
            }
            ChannelRequestType::Break { milliseconds } => encoder.u32(*milliseconds),
        }
        encoder.finish()
    }

    /// Decode exactly one complete channel request.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_CHANNEL_REQUEST)?;
        let recipient_channel = reader.u32("recipient channel")?;
        let request_name = reader.name("request name")?;
        let want_reply = reader.bool("want reply")?;
        let request = match request_name.as_str() {
            "pty-req" => ChannelRequestType::PtyReq(PtyRequest {
                term: reader.bytes(MAX_CHANNEL_TEXT, "terminal type")?,
                columns: reader.u32("terminal columns")?,
                rows: reader.u32("terminal rows")?,
                pixel_width: reader.u32("terminal pixel width")?,
                pixel_height: reader.u32("terminal pixel height")?,
                modes: reader.bytes(MAX_PTY_MODES, "terminal modes")?,
            }),
            "shell" => ChannelRequestType::Shell,
            "exec" => {
                ChannelRequestType::Exec { command: reader.bytes(MAX_CHANNEL_TEXT, "command")? }
            }
            "subsystem" => ChannelRequestType::Subsystem {
                name: reader.bytes(MAX_CHANNEL_TEXT, "subsystem name")?,
            },
            "env" => ChannelRequestType::Env {
                name: reader.bytes(MAX_CHANNEL_TEXT, "environment name")?,
                value: reader.bytes(MAX_CHANNEL_TEXT, "environment value")?,
            },
            "window-change" => ChannelRequestType::WindowChange(WindowChangeRequest {
                columns: reader.u32("terminal columns")?,
                rows: reader.u32("terminal rows")?,
                pixel_width: reader.u32("terminal pixel width")?,
                pixel_height: reader.u32("terminal pixel height")?,
            }),
            "signal" => ChannelRequestType::Signal {
                signal: Signal::parse(&reader.bytes(MAX_CHANNEL_NAME, "signal")?)?,
            },
            "exit-status" => ChannelRequestType::ExitStatus { status: reader.u32("exit status")? },
            "exit-signal" => ChannelRequestType::ExitSignal(ExitSignalRequest {
                signal: Signal::parse(&reader.bytes(MAX_CHANNEL_NAME, "signal")?)?,
                core_dumped: reader.bool("core dumped")?,
                error_message: reader.bytes(MAX_CHANNEL_TEXT, "error message")?,
                language_tag: reader.bytes(MAX_CHANNEL_NAME, "language tag")?,
            }),
            "break" => ChannelRequestType::Break { milliseconds: reader.u32("break duration")? },
            "auth-agent-req@openssh.com" => ChannelRequestType::AuthAgentReq,
            _ => return Err(ChannelCodecError::UnsupportedChannelRequest(request_name)),
        };
        reader.finish()?;
        let message = Self { recipient_channel, want_reply, request };
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> Result<(), ChannelCodecError> {
        match &self.request {
            ChannelRequestType::PtyReq(request) => {
                validate_text(&request.term, MAX_CHANNEL_TEXT, "terminal type", true)?;
                validate_size(&request.modes, MAX_PTY_MODES, "terminal modes")?;
            }
            ChannelRequestType::Shell
            | ChannelRequestType::AuthAgentReq
            | ChannelRequestType::WindowChange(_)
            | ChannelRequestType::Signal { .. }
            | ChannelRequestType::ExitStatus { .. }
            | ChannelRequestType::Break { .. } => {}
            ChannelRequestType::Exec { command } => {
                validate_text(command, MAX_CHANNEL_TEXT, "command", true)?;
            }
            ChannelRequestType::Subsystem { name } => {
                validate_text(name, MAX_CHANNEL_TEXT, "subsystem name", true)?;
            }
            ChannelRequestType::Env { name, value } => {
                validate_text(name, MAX_CHANNEL_TEXT, "environment name", true)?;
                validate_text(value, MAX_CHANNEL_TEXT, "environment value", false)?;
            }
            ChannelRequestType::ExitSignal(request) => {
                validate_text(&request.error_message, MAX_CHANNEL_TEXT, "error message", false)?;
                validate_text(&request.language_tag, MAX_CHANNEL_NAME, "language tag", false)?;
            }
        }
        Ok(())
    }
}

/// Supported global forwarding requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GlobalRequestType {
    /// Ask the server to listen on a TCP address and port.
    TcpipForward { address: Vec<u8>, port: u32 },
    /// Cancel a TCP forwarding listener.
    CancelTcpipForward { address: Vec<u8>, port: u32 },
    /// Ask the server to listen on a Unix socket.
    StreamlocalForward { socket_path: Vec<u8> },
    /// Cancel a Unix socket forwarding listener.
    CancelStreamlocalForward { socket_path: Vec<u8> },
}

impl GlobalRequestType {
    /// Return the RFC 4254/OpenSSH global request name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::TcpipForward { .. } => REQUEST_TCPIP_FORWARD,
            Self::CancelTcpipForward { .. } => REQUEST_CANCEL_TCPIP_FORWARD,
            Self::StreamlocalForward { .. } => REQUEST_STREAMLOCAL_FORWARD,
            Self::CancelStreamlocalForward { .. } => REQUEST_CANCEL_STREAMLOCAL_FORWARD,
        }
    }
}

/// An `SSH_MSG_GLOBAL_REQUEST` forwarding message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalRequest {
    /// Whether the sender requests a success or failure response.
    pub want_reply: bool,
    /// Forwarding request and fields.
    pub request: GlobalRequestType,
}

impl GlobalRequest {
    /// Construct a global request after validating its fields.
    pub fn new(want_reply: bool, request: GlobalRequestType) -> Result<Self, ChannelCodecError> {
        let message = Self { want_reply, request };
        message.validate()?;
        Ok(message)
    }

    /// Encode one complete global forwarding request.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        self.validate()?;
        let mut encoder = Encoder::new(SSH_MSG_GLOBAL_REQUEST);
        encoder.string(self.request.name().as_bytes(), MAX_CHANNEL_NAME, "global request name")?;
        encoder.bool(self.want_reply);
        match &self.request {
            GlobalRequestType::TcpipForward { address, port }
            | GlobalRequestType::CancelTcpipForward { address, port } => {
                encoder.string(address, MAX_CHANNEL_ADDRESS, "forward address")?;
                encoder.u32(*port);
            }
            GlobalRequestType::StreamlocalForward { socket_path }
            | GlobalRequestType::CancelStreamlocalForward { socket_path } => {
                encoder.string(socket_path, MAX_CHANNEL_ADDRESS, "socket path")?;
            }
        }
        encoder.finish()
    }

    /// Decode exactly one complete global forwarding request.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        let mut reader = Reader::new(input, SSH_MSG_GLOBAL_REQUEST)?;
        let request_name = reader.name("global request name")?;
        let want_reply = reader.bool("want reply")?;
        let request = match request_name.as_str() {
            REQUEST_TCPIP_FORWARD => GlobalRequestType::TcpipForward {
                address: reader.bytes(MAX_CHANNEL_ADDRESS, "forward address")?,
                port: reader.u32("forward port")?,
            },
            REQUEST_CANCEL_TCPIP_FORWARD => GlobalRequestType::CancelTcpipForward {
                address: reader.bytes(MAX_CHANNEL_ADDRESS, "forward address")?,
                port: reader.u32("forward port")?,
            },
            REQUEST_STREAMLOCAL_FORWARD => GlobalRequestType::StreamlocalForward {
                socket_path: reader.bytes(MAX_CHANNEL_ADDRESS, "socket path")?,
            },
            REQUEST_CANCEL_STREAMLOCAL_FORWARD => GlobalRequestType::CancelStreamlocalForward {
                socket_path: reader.bytes(MAX_CHANNEL_ADDRESS, "socket path")?,
            },
            _ => return Err(ChannelCodecError::UnsupportedGlobalRequest(request_name)),
        };
        reader.finish()?;
        let message = Self { want_reply, request };
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> Result<(), ChannelCodecError> {
        match &self.request {
            GlobalRequestType::TcpipForward { address, .. }
            | GlobalRequestType::CancelTcpipForward { address, .. } => {
                validate_text(address, MAX_CHANNEL_ADDRESS, "forward address", false)?;
            }
            GlobalRequestType::StreamlocalForward { socket_path }
            | GlobalRequestType::CancelStreamlocalForward { socket_path } => {
                validate_text(socket_path, MAX_CHANNEL_ADDRESS, "socket path", true)?;
            }
        }
        Ok(())
    }
}

/// A successful `SSH_MSG_REQUEST_SUCCESS` response to a global request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalRequestSuccess {
    /// Port allocated by a `tcpip-forward` request, if applicable.
    pub allocated_port: Option<u32>,
}

impl GlobalRequestSuccess {
    /// Encode a success with no payload or with one allocated TCP port.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        let mut encoder = Encoder::new(SSH_MSG_REQUEST_SUCCESS);
        if let Some(port) = self.allocated_port {
            encoder.u32(port);
        }
        encoder.finish()
    }

    /// Decode exactly one global request success.  The payload is either empty or one port.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        if input.len() > MAX_CHANNEL_MESSAGE {
            return Err(ChannelCodecError::FieldTooLarge("channel message"));
        }
        match input {
            [SSH_MSG_REQUEST_SUCCESS] => Ok(Self { allocated_port: None }),
            [SSH_MSG_REQUEST_SUCCESS, a, b, c, d] => {
                Ok(Self { allocated_port: Some(u32::from_be_bytes([*a, *b, *c, *d])) })
            }
            [] => Err(ChannelCodecError::MalformedMessage("missing message type")),
            _ => Err(ChannelCodecError::MalformedMessage("invalid global success payload")),
        }
    }
}

/// A failed `SSH_MSG_REQUEST_FAILURE` response to a global request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalRequestFailure;

impl GlobalRequestFailure {
    /// Encode an empty global request failure.
    pub fn encode(&self) -> Result<Vec<u8>, ChannelCodecError> {
        Ok(vec![SSH_MSG_REQUEST_FAILURE])
    }

    /// Decode exactly one empty global request failure.
    pub fn decode(input: &[u8]) -> Result<Self, ChannelCodecError> {
        if input == [SSH_MSG_REQUEST_FAILURE] {
            Ok(Self)
        } else {
            Err(ChannelCodecError::MalformedMessage("invalid global failure"))
        }
    }
}

fn validate_packet_size(size: u32) -> Result<(), ChannelCodecError> {
    if size == 0 { Err(ChannelCodecError::InvalidValue("maximum packet size")) } else { Ok(()) }
}

fn validate_size(value: &[u8], limit: usize, field: &'static str) -> Result<(), ChannelCodecError> {
    if value.len() > limit || value.len() > u32::MAX as usize {
        Err(ChannelCodecError::FieldTooLarge(field))
    } else {
        Ok(())
    }
}

fn validate_text(
    value: &[u8],
    limit: usize,
    field: &'static str,
    non_empty: bool,
) -> Result<(), ChannelCodecError> {
    validate_size(value, limit, field)?;
    if non_empty && value.is_empty() {
        return Err(ChannelCodecError::InvalidField(field));
    }
    if value.contains(&0) {
        return Err(ChannelCodecError::InvalidField(field));
    }
    Ok(())
}

fn encode_channel_recipient(
    message_type: u8,
    recipient_channel: u32,
) -> Result<Vec<u8>, ChannelCodecError> {
    let mut encoder = Encoder::new(message_type);
    encoder.u32(recipient_channel);
    encoder.finish()
}

fn decode_channel_recipient(input: &[u8], message_type: u8) -> Result<u32, ChannelCodecError> {
    let mut reader = Reader::new(input, message_type)?;
    let recipient_channel = reader.u32("recipient channel")?;
    reader.finish()?;
    Ok(recipient_channel)
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new(message_type: u8) -> Self {
        Self { bytes: vec![message_type] }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn string(
        &mut self,
        value: &[u8],
        limit: usize,
        field: &'static str,
    ) -> Result<(), ChannelCodecError> {
        validate_size(value, limit, field)?;
        let length =
            u32::try_from(value.len()).map_err(|_| ChannelCodecError::FieldTooLarge(field))?;
        self.u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, ChannelCodecError> {
        if self.bytes.len() > MAX_CHANNEL_MESSAGE {
            Err(ChannelCodecError::FieldTooLarge("channel message"))
        } else {
            Ok(self.bytes)
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8], expected_type: u8) -> Result<Self, ChannelCodecError> {
        if input.len() > MAX_CHANNEL_MESSAGE {
            return Err(ChannelCodecError::FieldTooLarge("channel message"));
        }
        let message_type =
            *input.first().ok_or(ChannelCodecError::MalformedMessage("missing message type"))?;
        if message_type != expected_type {
            return Err(ChannelCodecError::MalformedMessage("unexpected message type"));
        }
        Ok(Self { input, offset: 1 })
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], ChannelCodecError> {
        let end = self.offset.checked_add(length).ok_or(ChannelCodecError::FieldTooLarge(field))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(ChannelCodecError::MalformedMessage("truncated SSH channel message"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ChannelCodecError> {
        self.take(1, field)?.first().copied().ok_or(ChannelCodecError::MalformedMessage(field))
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, ChannelCodecError> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ChannelCodecError::MalformedMessage("invalid boolean")),
        }
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ChannelCodecError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().map_err(|_| ChannelCodecError::MalformedMessage(field))?,
        ))
    }

    fn bytes(&mut self, limit: usize, field: &'static str) -> Result<Vec<u8>, ChannelCodecError> {
        let length = self.u32(field)? as usize;
        if length > limit {
            return Err(ChannelCodecError::FieldTooLarge(field));
        }
        Ok(self.take(length, field)?.to_vec())
    }

    fn name(&mut self, field: &'static str) -> Result<String, ChannelCodecError> {
        let bytes = self.bytes(MAX_CHANNEL_NAME, field)?;
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(ChannelCodecError::InvalidField(field));
        }
        String::from_utf8(bytes).map_err(|_| ChannelCodecError::MalformedMessage(field))
    }

    fn finish(&self) -> Result<(), ChannelCodecError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ChannelCodecError::MalformedMessage("trailing channel data"))
        }
    }
}

impl fmt::Debug for Encoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Encoder").field("length", &self.bytes.len()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_defaults(channel_type: ChannelOpenType) -> ChannelOpen {
        ChannelOpen::new(channel_type, 7, 32 * 1024, 16 * 1024).expect("valid channel open")
    }

    #[test]
    fn channel_open_variants_round_trip() {
        let messages = [
            open_defaults(ChannelOpenType::Session),
            open_defaults(ChannelOpenType::DirectTcpip {
                target_address: b"host".to_vec(),
                target_port: 22,
                originator_address: b"127.0.0.1".to_vec(),
                originator_port: 4000,
            }),
            open_defaults(ChannelOpenType::ForwardedTcpip {
                connected_address: b"127.0.0.1".to_vec(),
                connected_port: 22,
                originator_address: b"10.0.0.2".to_vec(),
                originator_port: 5000,
            }),
            open_defaults(ChannelOpenType::DirectStreamLocal {
                socket_path: b"/tmp/agent.sock".to_vec(),
                reserved: Vec::new(),
            }),
            open_defaults(ChannelOpenType::ForwardedStreamLocal {
                socket_path: b"/tmp/agent.sock".to_vec(),
                reserved: Vec::new(),
            }),
            open_defaults(ChannelOpenType::AuthAgent),
        ];
        for message in messages {
            let wire = message.encode().expect("open wire");
            assert_eq!(ChannelOpen::decode(&wire).expect("open decode"), message);
        }
    }

    #[test]
    fn open_rejects_unknown_type_trailing_and_bad_reserved_field() {
        let mut unknown = vec![SSH_MSG_CHANNEL_OPEN];
        append_test_string(&mut unknown, b"x11");
        unknown.extend_from_slice(&[0; 12]);
        assert!(matches!(
            ChannelOpen::decode(&unknown),
            Err(ChannelCodecError::UnsupportedChannelType(name)) if name == "x11"
        ));

        let mut trailing = open_defaults(ChannelOpenType::Session).encode().expect("wire");
        trailing.push(0);
        assert_eq!(
            ChannelOpen::decode(&trailing),
            Err(ChannelCodecError::MalformedMessage("trailing channel data"))
        );

        let invalid = ChannelOpen::new(
            ChannelOpenType::DirectStreamLocal {
                socket_path: b"/tmp/s".to_vec(),
                reserved: b"reserved".to_vec(),
            },
            1,
            1,
            1,
        );
        assert_eq!(invalid, Err(ChannelCodecError::InvalidValue("streamlocal reserved field")));
    }

    #[test]
    fn channel_data_and_lifecycle_round_trip() {
        let data = ChannelData { recipient_channel: 2, data: b"hello".to_vec() };
        assert_eq!(ChannelData::decode(&data.encode().expect("data wire")).expect("data"), data);
        let extended = ChannelExtendedData {
            recipient_channel: 2,
            data_type: ExtendedDataType::Stderr,
            data: b"stderr".to_vec(),
        };
        assert_eq!(
            ChannelExtendedData::decode(&extended.encode().expect("extended wire"))
                .expect("extended"),
            extended
        );
        let adjust = ChannelWindowAdjust { recipient_channel: 2, bytes_to_add: 4096 };
        assert_eq!(
            ChannelWindowAdjust::decode(&adjust.encode().expect("adjust wire")).expect("adjust"),
            adjust
        );
        for (wire, channel) in [
            (ChannelEof { recipient_channel: 2 }.encode().expect("eof"), 96),
            (ChannelClose { recipient_channel: 2 }.encode().expect("close"), 97),
            (ChannelSuccess { recipient_channel: 2 }.encode().expect("success"), 99),
            (ChannelFailure { recipient_channel: 2 }.encode().expect("failure"), 100),
        ] {
            assert_eq!(wire[0], channel);
            assert_eq!(&wire[1..], &[0, 0, 0, 2]);
        }
    }

    #[test]
    fn channel_messages_reject_truncation_unknown_extended_data_and_invalid_bool() {
        assert_eq!(
            ChannelData::decode(&[SSH_MSG_CHANNEL_DATA, 0, 0, 0]),
            Err(ChannelCodecError::MalformedMessage("truncated SSH channel message"))
        );
        let mut unknown = vec![SSH_MSG_CHANNEL_EXTENDED_DATA];
        unknown.extend_from_slice(&2u32.to_be_bytes());
        unknown.extend_from_slice(&9u32.to_be_bytes());
        append_test_string(&mut unknown, b"data");
        assert_eq!(
            ChannelExtendedData::decode(&unknown),
            Err(ChannelCodecError::UnsupportedExtendedDataType(9))
        );
    }

    #[test]
    fn channel_requests_round_trip_and_reject_unknowns() {
        let requests = [
            ChannelRequestType::PtyReq(PtyRequest {
                term: b"xterm".to_vec(),
                columns: 80,
                rows: 24,
                pixel_width: 640,
                pixel_height: 480,
                modes: vec![0],
            }),
            ChannelRequestType::Shell,
            ChannelRequestType::Exec { command: b"id".to_vec() },
            ChannelRequestType::Subsystem { name: b"sftp".to_vec() },
            ChannelRequestType::Env { name: b"LANG".to_vec(), value: b"C.UTF-8".to_vec() },
            ChannelRequestType::WindowChange(WindowChangeRequest {
                columns: 100,
                rows: 40,
                pixel_width: 800,
                pixel_height: 600,
            }),
            ChannelRequestType::Signal { signal: Signal::Term },
            ChannelRequestType::ExitStatus { status: 0 },
            ChannelRequestType::ExitSignal(ExitSignalRequest {
                signal: Signal::Kill,
                core_dumped: false,
                error_message: b"killed".to_vec(),
                language_tag: Vec::new(),
            }),
            ChannelRequestType::Break { milliseconds: 500 },
            ChannelRequestType::AuthAgentReq,
        ];
        for request in requests {
            let message = ChannelRequest::new(3, true, request).expect("valid request");
            let wire = message.encode().expect("request wire");
            assert_eq!(ChannelRequest::decode(&wire).expect("request decode"), message);
        }

        let mut unknown = vec![SSH_MSG_CHANNEL_REQUEST];
        unknown.extend_from_slice(&3u32.to_be_bytes());
        append_test_string(&mut unknown, b"x11-req");
        unknown.push(0);
        assert!(matches!(
            ChannelRequest::decode(&unknown),
            Err(ChannelCodecError::UnsupportedChannelRequest(name)) if name == "x11-req"
        ));
    }

    #[test]
    fn requests_reject_bad_bool_truncation_nul_and_oversize() {
        let mut bad_bool = ChannelRequest::new(1, false, ChannelRequestType::Shell)
            .expect("shell")
            .encode()
            .expect("wire");
        let bad_bool_last = bad_bool.len() - 1;
        bad_bool[bad_bool_last] = 2;
        assert_eq!(
            ChannelRequest::decode(&bad_bool),
            Err(ChannelCodecError::MalformedMessage("invalid boolean"))
        );

        let mut truncated =
            ChannelRequest::new(1, true, ChannelRequestType::Exec { command: b"echo".to_vec() })
                .expect("exec")
                .encode()
                .expect("wire");
        truncated.pop();
        assert_eq!(
            ChannelRequest::decode(&truncated),
            Err(ChannelCodecError::MalformedMessage("truncated SSH channel message"))
        );

        let nul = ChannelRequest::new(
            1,
            true,
            ChannelRequestType::Exec { command: b"bad\0command".to_vec() },
        );
        assert_eq!(nul, Err(ChannelCodecError::InvalidField("command")));

        let oversized = ChannelRequest::new(
            1,
            true,
            ChannelRequestType::Exec { command: vec![b'x'; MAX_CHANNEL_TEXT + 1] },
        );
        assert_eq!(oversized, Err(ChannelCodecError::FieldTooLarge("command")));
    }

    #[test]
    fn global_forwarding_requests_and_responses_round_trip() {
        let requests = [
            GlobalRequestType::TcpipForward { address: b"127.0.0.1".to_vec(), port: 0 },
            GlobalRequestType::CancelTcpipForward { address: b"127.0.0.1".to_vec(), port: 22 },
            GlobalRequestType::StreamlocalForward { socket_path: b"/tmp/s".to_vec() },
            GlobalRequestType::CancelStreamlocalForward { socket_path: b"/tmp/s".to_vec() },
        ];
        for request in requests {
            let message = GlobalRequest::new(true, request).expect("valid global request");
            let wire = message.encode().expect("global wire");
            assert_eq!(GlobalRequest::decode(&wire).expect("global decode"), message);
        }
        for response in [
            GlobalRequestSuccess { allocated_port: None },
            GlobalRequestSuccess { allocated_port: Some(2200) },
        ] {
            let wire = response.encode().expect("success wire");
            assert_eq!(GlobalRequestSuccess::decode(&wire).expect("success decode"), response);
        }
        let failure = GlobalRequestFailure.encode().expect("failure wire");
        assert_eq!(GlobalRequestFailure::decode(&failure), Ok(GlobalRequestFailure));
    }

    #[test]
    fn global_and_open_failure_paths_are_strict() {
        let mut unknown = vec![SSH_MSG_GLOBAL_REQUEST];
        append_test_string(&mut unknown, b"x11-forwarding");
        unknown.push(0);
        assert!(matches!(
            GlobalRequest::decode(&unknown),
            Err(ChannelCodecError::UnsupportedGlobalRequest(name)) if name == "x11-forwarding"
        ));

        assert_eq!(
            GlobalRequestSuccess::decode(&[SSH_MSG_REQUEST_SUCCESS, 0]),
            Err(ChannelCodecError::MalformedMessage("invalid global success payload"))
        );
        assert_eq!(
            ChannelOpenFailureReason::try_from(99),
            Err(ChannelCodecError::UnknownOpenFailureReason(99))
        );
        let invalid = ChannelOpenFailure {
            recipient_channel: 1,
            reason: ChannelOpenFailureReason::ConnectFailed,
            description: b"bad\0text".to_vec(),
            language_tag: Vec::new(),
        };
        assert_eq!(invalid.encode(), Err(ChannelCodecError::InvalidField("failure description")));
    }

    #[test]
    fn channel_codecs_bound_declared_lengths_before_allocation() {
        let mut oversized = vec![SSH_MSG_CHANNEL_DATA];
        oversized.extend_from_slice(&1u32.to_be_bytes());
        oversized.extend_from_slice(
            &(u32::try_from(MAX_CHANNEL_STRING).expect("test limit fits") + 1).to_be_bytes(),
        );
        assert_eq!(
            ChannelData::decode(&oversized),
            Err(ChannelCodecError::FieldTooLarge("channel data"))
        );

        let mut oversized_name = vec![SSH_MSG_CHANNEL_REQUEST];
        oversized_name.extend_from_slice(&1u32.to_be_bytes());
        oversized_name.extend_from_slice(
            &(u32::try_from(MAX_CHANNEL_NAME).expect("test limit fits") + 1).to_be_bytes(),
        );
        assert_eq!(
            ChannelRequest::decode(&oversized_name),
            Err(ChannelCodecError::FieldTooLarge("request name"))
        );
    }

    fn append_test_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(
            &u32::try_from(value.len()).expect("test string fits").to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
}
