//! Bounded SFTP version 3 packets and request correlation.
//!
//! The concrete SSH channel engine is deliberately kept outside this module.  This boundary
//! owns packet framing, the v3 handshake, the core file requests used by the client, and the
//! response correlation rules so an engine cannot allocate from an untrusted length or accept a
//! response for a request that was never sent.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::collections::BTreeSet;

use thiserror::Error;

const FXP_INIT: u8 = 1;
const FXP_VERSION: u8 = 2;
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_STAT: u8 = 17;
const FXP_LSTAT: u8 = 7;
const FXP_FSTAT: u8 = 8;
const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_ATTRS: u8 = 105;
const FXP_EXTENDED: u8 = 200;
const FXP_EXTENDED_REPLY: u8 = 201;
const LIMITS_EXTENSION: &[u8] = b"limits@openssh.com";

const ATTR_SIZE: u32 = 0x0000_0001;
const ATTR_UIDGID: u32 = 0x0000_0002;
const ATTR_PERMISSIONS: u32 = 0x0000_0004;
const ATTR_ACMODTIME: u32 = 0x0000_0008;
const ATTR_EXTENDED: u32 = 0x8000_0000;
const KNOWN_ATTR_FLAGS: u32 =
    ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME | ATTR_EXTENDED;

/// Maximum complete SFTP packet, including the four-byte length prefix.
pub const MAX_SFTP_PACKET: usize = 256 * 1024;
/// Maximum SFTP path, extension name, status text, or language tag.
pub const MAX_SFTP_STRING: usize = 64 * 1024;
/// Maximum opaque SFTP handle.
pub const MAX_SFTP_HANDLE: usize = 256;
/// Maximum number of v3 version extensions in one VERSION packet.
pub const MAX_SFTP_EXTENSIONS: usize = 64;
/// Maximum number of outstanding requests tracked by one client.
pub const MAX_SFTP_OUTSTANDING: usize = 1024;
/// Maximum extension-specific payload accepted by one EXTENDED packet.
pub const MAX_SFTP_EXTENSION_DATA: usize = MAX_SFTP_PACKET - 64;

/// Errors produced by the SFTP framing and client boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SftpError {
    /// The packet length, field layout, or trailing bytes were malformed.
    #[error("malformed SFTP packet: {0}")]
    Malformed(&'static str),
    /// The packet was larger than the boundary permits.
    #[error("SFTP packet is too large")]
    PacketTooLarge,
    /// A bounded string, data field, handle, or extension list was too large.
    #[error("SFTP field is too large: {0}")]
    FieldTooLarge(&'static str),
    /// The packet type is not part of this v3 boundary.
    #[error("unsupported SFTP packet type: {0}")]
    UnsupportedPacket(u8),
    /// A peer selected an unsupported protocol version.
    #[error("unsupported SFTP version: {0}")]
    UnsupportedVersion(u32),
    /// A packet contained a value that cannot be represented safely.
    #[error("invalid SFTP value: {0}")]
    InvalidValue(&'static str),
    /// A request was queued before the version handshake completed.
    #[error("SFTP version handshake is incomplete")]
    HandshakeIncomplete,
    /// The request pipeline reached its configured bound.
    #[error("SFTP outstanding request limit reached")]
    OutstandingLimit,
    /// A response referenced an id that is not pending.
    #[error("SFTP response references an unknown request")]
    UnknownRequest,
}

/// One extension advertised in an SFTP VERSION packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpExtension {
    /// Extension name, for example `posix-rename@openssh.com`.
    pub name: Vec<u8>,
    /// Extension version or opaque value.
    pub data: Vec<u8>,
}

impl SftpExtension {
    /// Construct a bounded extension pair.
    pub fn new(name: impl Into<Vec<u8>>, data: impl Into<Vec<u8>>) -> Result<Self, SftpError> {
        let name = name.into();
        let data = data.into();
        validate_string(&name, "extension name", false)?;
        validate_opaque(&data, MAX_SFTP_STRING, "extension data", true)?;
        Ok(Self { name, data })
    }
}

/// File attributes carried by SFTP v3 requests and responses.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SftpAttributes {
    /// File size when present.
    pub size: Option<u64>,
    /// Owner uid and gid when present.
    pub uid_gid: Option<(u32, u32)>,
    /// POSIX permissions and file type when present.
    pub permissions: Option<u32>,
    /// Access and modification times when present.
    pub access_time: Option<u32>,
    /// Modification time when present.
    pub modify_time: Option<u32>,
    /// Extension pairs carried by the peer.
    pub extended: Vec<SftpExtension>,
}

/// Limits advertised by OpenSSH's `limits@openssh.com` extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SftpLimits {
    /// Maximum complete packet accepted by the server.
    pub max_packet_length: u64,
    /// Maximum bytes returned by one read request.
    pub max_read_length: u64,
    /// Maximum bytes accepted by one write request.
    pub max_write_length: u64,
    /// Maximum number of simultaneously open handles.
    pub max_open_handles: u64,
}

impl SftpLimits {
    /// Encode the extension-specific limits response body.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(32);
        output.extend_from_slice(&self.max_packet_length.to_be_bytes());
        output.extend_from_slice(&self.max_read_length.to_be_bytes());
        output.extend_from_slice(&self.max_write_length.to_be_bytes());
        output.extend_from_slice(&self.max_open_handles.to_be_bytes());
        output
    }

    /// Decode exactly one limits response body.
    pub fn decode(input: &[u8]) -> Result<Self, SftpError> {
        if input.len() != 32 {
            return Err(SftpError::Malformed("limits response"));
        }
        let value = |offset: usize| -> Result<u64, SftpError> {
            let bytes = input[offset..offset + 8]
                .try_into()
                .map_err(|_| SftpError::Malformed("limits response"))?;
            Ok(u64::from_be_bytes(bytes))
        };
        Ok(Self {
            max_packet_length: value(0)?,
            max_read_length: value(8)?,
            max_write_length: value(16)?,
            max_open_handles: value(24)?,
        })
    }
}

impl SftpAttributes {
    fn encode_into(&self, encoder: &mut Encoder) -> Result<(), SftpError> {
        if self.extended.len() > MAX_SFTP_EXTENSIONS {
            return Err(SftpError::FieldTooLarge("attribute extensions"));
        }
        let mut flags = 0;
        if self.size.is_some() {
            flags |= ATTR_SIZE;
        }
        if self.uid_gid.is_some() {
            flags |= ATTR_UIDGID;
        }
        if self.permissions.is_some() {
            flags |= ATTR_PERMISSIONS;
        }
        if self.access_time.is_some() || self.modify_time.is_some() {
            if self.access_time.is_none() || self.modify_time.is_none() {
                return Err(SftpError::InvalidValue("attribute times must be paired"));
            }
            flags |= ATTR_ACMODTIME;
        }
        if !self.extended.is_empty() {
            flags |= ATTR_EXTENDED;
        }
        encoder.u32(flags);
        if let Some(size) = self.size {
            encoder.u64(size);
        }
        if let Some((uid, gid)) = self.uid_gid {
            encoder.u32(uid);
            encoder.u32(gid);
        }
        if let Some(permissions) = self.permissions {
            encoder.u32(permissions);
        }
        if let (Some(access), Some(modify)) = (self.access_time, self.modify_time) {
            encoder.u32(access);
            encoder.u32(modify);
        }
        if !self.extended.is_empty() {
            encoder.u32(
                u32::try_from(self.extended.len())
                    .map_err(|_| SftpError::FieldTooLarge("attribute extensions"))?,
            );
            for extension in &self.extended {
                validate_string(&extension.name, "attribute extension name", false)?;
                validate_opaque(
                    &extension.data,
                    MAX_SFTP_STRING,
                    "attribute extension data",
                    true,
                )?;
                encoder.string(&extension.name, MAX_SFTP_STRING, "attribute extension name")?;
                encoder.string(&extension.data, MAX_SFTP_STRING, "attribute extension data")?;
            }
        }
        Ok(())
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, SftpError> {
        let flags = reader.u32("attribute flags")?;
        if flags & !KNOWN_ATTR_FLAGS != 0 {
            return Err(SftpError::InvalidValue("unknown attribute flags"));
        }
        let size = (flags & ATTR_SIZE != 0).then(|| reader.u64("attribute size")).transpose()?;
        let uid_gid = if flags & ATTR_UIDGID != 0 {
            Some((reader.u32("attribute uid")?, reader.u32("attribute gid")?))
        } else {
            None
        };
        let permissions = (flags & ATTR_PERMISSIONS != 0)
            .then(|| reader.u32("attribute permissions"))
            .transpose()?;
        let (access_time, modify_time) = if flags & ATTR_ACMODTIME != 0 {
            (Some(reader.u32("attribute access time")?), Some(reader.u32("attribute modify time")?))
        } else {
            (None, None)
        };
        let extended = if flags & ATTR_EXTENDED != 0 {
            let count = reader.count(MAX_SFTP_EXTENSIONS, "attribute extensions")?;
            let mut extensions = Vec::with_capacity(count);
            for _ in 0..count {
                extensions.push(SftpExtension::new(
                    reader.bytes(MAX_SFTP_STRING, "attribute extension name", false)?,
                    reader.opaque(MAX_SFTP_STRING, "attribute extension data", true)?,
                )?);
            }
            extensions
        } else {
            Vec::new()
        };
        Ok(Self { size, uid_gid, permissions, access_time, modify_time, extended })
    }
}

/// The bounded core of the SFTP v3 packet set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SftpPacket {
    /// Client-to-server protocol version negotiation.
    Init { version: u32 },
    /// Server-to-client protocol version negotiation and extension advertisement.
    Version { version: u32, extensions: Vec<SftpExtension> },
    /// Open or create a file.
    Open { id: u32, path: Vec<u8>, pflags: u32, attrs: SftpAttributes },
    /// Close an open file handle.
    Close { id: u32, handle: Vec<u8> },
    /// Read a bounded chunk from an open handle.
    Read { id: u32, handle: Vec<u8>, offset: u64, length: u32 },
    /// Write a bounded chunk to an open handle.
    Write { id: u32, handle: Vec<u8>, offset: u64, data: Vec<u8> },
    /// Read path attributes.
    Stat { id: u32, path: Vec<u8> },
    /// Read path attributes without following a symlink.
    Lstat { id: u32, path: Vec<u8> },
    /// Read handle attributes.
    Fstat { id: u32, handle: Vec<u8> },
    /// Return a status code and bounded diagnostic text.
    Status { id: u32, code: u32, message: Vec<u8>, language: Vec<u8> },
    /// Return a newly opened handle.
    Handle { id: u32, handle: Vec<u8> },
    /// Return file data.
    Data { id: u32, data: Vec<u8> },
    /// Return attributes.
    Attrs { id: u32, attrs: SftpAttributes },
    /// Send an extension-specific request body.
    Extended { id: u32, name: Vec<u8>, data: Vec<u8> },
    /// Return an extension-specific response body.
    ExtendedReply { id: u32, data: Vec<u8> },
}

impl SftpPacket {
    /// Encode one complete length-prefixed SFTP packet.
    #[allow(clippy::too_many_lines)]
    pub fn encode(&self) -> Result<Vec<u8>, SftpError> {
        let mut encoder = Encoder::new();
        match self {
            Self::Init { version } => {
                encoder.u8(FXP_INIT);
                encoder.u32(*version);
            }
            Self::Version { version, extensions } => {
                if extensions.len() > MAX_SFTP_EXTENSIONS {
                    return Err(SftpError::FieldTooLarge("version extensions"));
                }
                encoder.u8(FXP_VERSION);
                encoder.u32(*version);
                for extension in extensions {
                    validate_string(&extension.name, "extension name", false)?;
                    validate_opaque(&extension.data, MAX_SFTP_STRING, "extension data", true)?;
                    encoder.string(&extension.name, MAX_SFTP_STRING, "extension name")?;
                    encoder.string(&extension.data, MAX_SFTP_STRING, "extension data")?;
                }
            }
            Self::Open { id, path, pflags, attrs } => {
                validate_string(path, "path", false)?;
                encoder.u8(FXP_OPEN);
                encoder.u32(*id);
                encoder.string(path, MAX_SFTP_STRING, "path")?;
                encoder.u32(*pflags);
                attrs.encode_into(&mut encoder)?;
            }
            Self::Close { id, handle } => {
                validate_opaque(handle, MAX_SFTP_HANDLE, "handle", false)?;
                encoder.u8(FXP_CLOSE);
                encoder.u32(*id);
                encoder.string(handle, MAX_SFTP_HANDLE, "handle")?;
            }
            Self::Read { id, handle, offset, length } => {
                validate_opaque(handle, MAX_SFTP_HANDLE, "handle", false)?;
                if *length == 0
                    || usize::try_from(*length).unwrap_or(usize::MAX) > MAX_SFTP_PACKET - 64
                {
                    return Err(SftpError::InvalidValue("read length"));
                }
                encoder.u8(FXP_READ);
                encoder.u32(*id);
                encoder.string(handle, MAX_SFTP_HANDLE, "handle")?;
                encoder.u64(*offset);
                encoder.u32(*length);
            }
            Self::Write { id, handle, offset, data } => {
                validate_opaque(handle, MAX_SFTP_HANDLE, "handle", false)?;
                validate_data(data)?;
                encoder.u8(FXP_WRITE);
                encoder.u32(*id);
                encoder.string(handle, MAX_SFTP_HANDLE, "handle")?;
                encoder.u64(*offset);
                encoder.string(data, MAX_SFTP_PACKET, "write data")?;
            }
            Self::Stat { id, path } => encode_path_request(&mut encoder, FXP_STAT, *id, path)?,
            Self::Lstat { id, path } => encode_path_request(&mut encoder, FXP_LSTAT, *id, path)?,
            Self::Fstat { id, handle } => {
                validate_opaque(handle, MAX_SFTP_HANDLE, "handle", false)?;
                encoder.u8(FXP_FSTAT);
                encoder.u32(*id);
                encoder.string(handle, MAX_SFTP_HANDLE, "handle")?;
            }
            Self::Status { id, code, message, language } => {
                validate_string(message, "status message", true)?;
                validate_string(language, "status language", true)?;
                encoder.u8(FXP_STATUS);
                encoder.u32(*id);
                encoder.u32(*code);
                encoder.string(message, MAX_SFTP_STRING, "status message")?;
                encoder.string(language, MAX_SFTP_STRING, "status language")?;
            }
            Self::Handle { id, handle } => {
                validate_opaque(handle, MAX_SFTP_HANDLE, "handle", false)?;
                encoder.u8(FXP_HANDLE);
                encoder.u32(*id);
                encoder.string(handle, MAX_SFTP_HANDLE, "handle")?;
            }
            Self::Data { id, data } => {
                validate_data(data)?;
                encoder.u8(FXP_DATA);
                encoder.u32(*id);
                encoder.string(data, MAX_SFTP_PACKET, "data")?;
            }
            Self::Attrs { id, attrs } => {
                encoder.u8(FXP_ATTRS);
                encoder.u32(*id);
                attrs.encode_into(&mut encoder)?;
            }
            Self::Extended { id, name, data } => {
                validate_string(name, "extension name", false)?;
                validate_opaque(data, MAX_SFTP_EXTENSION_DATA, "extension data", true)?;
                encoder.u8(FXP_EXTENDED);
                encoder.u32(*id);
                encoder.string(name, MAX_SFTP_STRING, "extension name")?;
                encoder.raw(data);
            }
            Self::ExtendedReply { id, data } => {
                validate_opaque(data, MAX_SFTP_EXTENSION_DATA, "extension response", true)?;
                encoder.u8(FXP_EXTENDED_REPLY);
                encoder.u32(*id);
                encoder.raw(data);
            }
        }
        encoder.finish()
    }

    /// Decode exactly one complete length-prefixed SFTP packet.
    #[allow(clippy::too_many_lines)]
    pub fn decode(input: &[u8]) -> Result<Self, SftpError> {
        if input.len() < 5 {
            return Err(SftpError::Malformed("truncated packet"));
        }
        let declared = u32::from_be_bytes(
            input[..4].try_into().map_err(|_| SftpError::Malformed("packet length"))?,
        ) as usize;
        if declared > MAX_SFTP_PACKET - 4 {
            return Err(SftpError::PacketTooLarge);
        }
        if declared + 4 != input.len() {
            return Err(SftpError::Malformed("packet length mismatch"));
        }
        let mut reader = Reader::new(&input[4..]);
        let packet_type = reader.u8("packet type")?;
        let packet = match packet_type {
            FXP_INIT => Self::Init { version: reader.u32("version")? },
            FXP_VERSION => {
                let version = reader.u32("version")?;
                let mut extensions = Vec::new();
                while reader.remaining() > 0 {
                    if extensions.len() == MAX_SFTP_EXTENSIONS {
                        return Err(SftpError::FieldTooLarge("version extensions"));
                    }
                    extensions.push(SftpExtension::new(
                        reader.bytes(MAX_SFTP_STRING, "extension name", false)?,
                        reader.opaque(MAX_SFTP_STRING, "extension data", true)?,
                    )?);
                }
                Self::Version { version, extensions }
            }
            FXP_OPEN => Self::Open {
                id: reader.u32("request id")?,
                path: reader.bytes(MAX_SFTP_STRING, "path", false)?,
                pflags: reader.u32("open flags")?,
                attrs: SftpAttributes::decode_from(&mut reader)?,
            },
            FXP_CLOSE => Self::Close {
                id: reader.u32("request id")?,
                handle: reader.opaque(MAX_SFTP_HANDLE, "handle", false)?,
            },
            FXP_READ => {
                let id = reader.u32("request id")?;
                let handle = reader.opaque(MAX_SFTP_HANDLE, "handle", false)?;
                let offset = reader.u64("offset")?;
                let length = reader.u32("read length")?;
                if length == 0
                    || usize::try_from(length).unwrap_or(usize::MAX) > MAX_SFTP_PACKET - 64
                {
                    return Err(SftpError::InvalidValue("read length"));
                }
                Self::Read { id, handle, offset, length }
            }
            FXP_WRITE => {
                let id = reader.u32("request id")?;
                let handle = reader.opaque(MAX_SFTP_HANDLE, "handle", false)?;
                let offset = reader.u64("offset")?;
                let data = reader.opaque(MAX_SFTP_PACKET - 64, "write data", true)?;
                Self::Write { id, handle, offset, data }
            }
            FXP_STAT | FXP_LSTAT => {
                let id = reader.u32("request id")?;
                let path = reader.bytes(MAX_SFTP_STRING, "path", false)?;
                if packet_type == FXP_STAT {
                    Self::Stat { id, path }
                } else {
                    Self::Lstat { id, path }
                }
            }
            FXP_FSTAT => Self::Fstat {
                id: reader.u32("request id")?,
                handle: reader.opaque(MAX_SFTP_HANDLE, "handle", false)?,
            },
            FXP_STATUS => Self::Status {
                id: reader.u32("request id")?,
                code: reader.u32("status code")?,
                message: reader.bytes(MAX_SFTP_STRING, "status message", true)?,
                language: reader.bytes(MAX_SFTP_STRING, "status language", true)?,
            },
            FXP_HANDLE => Self::Handle {
                id: reader.u32("request id")?,
                handle: reader.opaque(MAX_SFTP_HANDLE, "handle", false)?,
            },
            FXP_DATA => Self::Data {
                id: reader.u32("request id")?,
                data: reader.opaque(MAX_SFTP_PACKET - 64, "data", true)?,
            },
            FXP_ATTRS => Self::Attrs {
                id: reader.u32("request id")?,
                attrs: SftpAttributes::decode_from(&mut reader)?,
            },
            FXP_EXTENDED => Self::Extended {
                id: reader.u32("request id")?,
                name: reader.bytes(MAX_SFTP_STRING, "extension name", false)?,
                data: reader.rest(MAX_SFTP_EXTENSION_DATA, "extension data")?,
            },
            FXP_EXTENDED_REPLY => Self::ExtendedReply {
                id: reader.u32("request id")?,
                data: reader.rest(MAX_SFTP_EXTENSION_DATA, "extension response")?,
            },
            other => return Err(SftpError::UnsupportedPacket(other)),
        };
        reader.finish()?;
        Ok(packet)
    }

    /// Return a request id when this packet carries one.
    #[must_use]
    pub fn request_id(&self) -> Option<u32> {
        match self {
            Self::Init { .. } | Self::Version { .. } => None,
            Self::Open { id, .. }
            | Self::Close { id, .. }
            | Self::Read { id, .. }
            | Self::Write { id, .. }
            | Self::Stat { id, .. }
            | Self::Lstat { id, .. }
            | Self::Fstat { id, .. }
            | Self::Status { id, .. }
            | Self::Handle { id, .. }
            | Self::Data { id, .. }
            | Self::Attrs { id, .. }
            | Self::Extended { id, .. }
            | Self::ExtendedReply { id, .. } => Some(*id),
        }
    }

    /// Construct an OpenSSH `limits@openssh.com` request.
    #[must_use]
    pub fn limits_request(id: u32) -> Self {
        Self::Extended { id, name: LIMITS_EXTENSION.to_vec(), data: Vec::new() }
    }

    /// Decode an OpenSSH `limits@openssh.com` response.
    pub fn limits_response(&self) -> Result<SftpLimits, SftpError> {
        match self {
            Self::ExtendedReply { data, .. } => SftpLimits::decode(data),
            _ => Err(SftpError::Malformed("expected limits response")),
        }
    }
}

/// Small state machine for a v3 client with bounded pipelining.
#[derive(Debug)]
pub struct SftpClient {
    next_id: u32,
    max_outstanding: usize,
    pending: BTreeSet<u32>,
    version: Option<u32>,
}

impl SftpClient {
    /// Create a client that will track at most `max_outstanding` requests.
    pub fn new(max_outstanding: usize) -> Result<Self, SftpError> {
        if max_outstanding == 0 || max_outstanding > MAX_SFTP_OUTSTANDING {
            return Err(SftpError::InvalidValue("maximum outstanding requests"));
        }
        Ok(Self { next_id: 1, max_outstanding, pending: BTreeSet::new(), version: None })
    }

    /// Return the initial v3 handshake packet.
    pub fn init(&mut self) -> Result<SftpPacket, SftpError> {
        if self.version.is_some() {
            return Err(SftpError::InvalidValue("SFTP handshake already completed"));
        }
        Ok(SftpPacket::Init { version: 3 })
    }

    /// Accept a VERSION packet and complete the v3 handshake.
    pub fn accept_version(&mut self, packet: &SftpPacket) -> Result<(), SftpError> {
        let SftpPacket::Version { version, .. } = packet else {
            return Err(SftpError::Malformed("expected SFTP VERSION"));
        };
        if *version != 3 {
            return Err(SftpError::UnsupportedVersion(*version));
        }
        self.version = Some(*version);
        Ok(())
    }

    /// Queue a request id, enforcing the pipeline bound and avoiding zero ids.
    pub fn reserve_request_id(&mut self) -> Result<u32, SftpError> {
        if self.version != Some(3) {
            return Err(SftpError::HandshakeIncomplete);
        }
        if self.pending.len() >= self.max_outstanding {
            return Err(SftpError::OutstandingLimit);
        }
        for _ in 0..=u32::MAX {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            if self.pending.insert(id) {
                return Ok(id);
            }
        }
        Err(SftpError::OutstandingLimit)
    }

    /// Accept a response and release its request id.
    pub fn accept_response(&mut self, packet: &SftpPacket) -> Result<(), SftpError> {
        let Some(id) = packet.request_id() else {
            return Err(SftpError::Malformed("response has no request id"));
        };
        if self.pending.remove(&id) { Ok(()) } else { Err(SftpError::UnknownRequest) }
    }

    /// Number of requests currently awaiting a response.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.pending.len()
    }
}

fn encode_path_request(
    encoder: &mut Encoder,
    packet_type: u8,
    id: u32,
    path: &[u8],
) -> Result<(), SftpError> {
    validate_string(path, "path", false)?;
    encoder.u8(packet_type);
    encoder.u32(id);
    encoder.string(path, MAX_SFTP_STRING, "path")
}

fn validate_string(value: &[u8], field: &'static str, allow_empty: bool) -> Result<(), SftpError> {
    validate_opaque(value, MAX_SFTP_STRING, field, allow_empty)?;
    if value.contains(&0) {
        return Err(SftpError::InvalidValue(field));
    }
    Ok(())
}

fn validate_opaque(
    value: &[u8],
    limit: usize,
    field: &'static str,
    allow_empty: bool,
) -> Result<(), SftpError> {
    if value.len() > limit {
        return Err(SftpError::FieldTooLarge(field));
    }
    if !allow_empty && value.is_empty() {
        return Err(SftpError::InvalidValue(field));
    }
    Ok(())
}

fn validate_data(value: &[u8]) -> Result<(), SftpError> {
    if value.len() > MAX_SFTP_PACKET - 64 {
        return Err(SftpError::FieldTooLarge("data"));
    }
    Ok(())
}

struct Encoder {
    body: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { body: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.body.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.body.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.body.extend_from_slice(&value.to_be_bytes());
    }

    fn raw(&mut self, value: &[u8]) {
        self.body.extend_from_slice(value);
    }

    fn string(&mut self, value: &[u8], limit: usize, field: &'static str) -> Result<(), SftpError> {
        if value.len() > limit || value.len() > u32::MAX as usize {
            return Err(SftpError::FieldTooLarge(field));
        }
        self.u32(u32::try_from(value.len()).map_err(|_| SftpError::FieldTooLarge(field))?);
        self.body.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, SftpError> {
        let length = self.body.len();
        if length == 0 {
            return Err(SftpError::Malformed("empty packet"));
        }
        if length + 4 > MAX_SFTP_PACKET {
            return Err(SftpError::PacketTooLarge);
        }
        let mut output = Vec::with_capacity(length + 4);
        output.extend_from_slice(
            &u32::try_from(length).map_err(|_| SftpError::PacketTooLarge)?.to_be_bytes(),
        );
        output.extend_from_slice(&self.body);
        Ok(output)
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    fn take(&mut self, count: usize, field: &'static str) -> Result<&'a [u8], SftpError> {
        let end = self.offset.checked_add(count).ok_or(SftpError::FieldTooLarge(field))?;
        if end > self.input.len() {
            return Err(SftpError::Malformed(field));
        }
        let result = &self.input[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, SftpError> {
        self.take(1, field).map(|bytes| bytes[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, SftpError> {
        Ok(u32::from_be_bytes(
            self.take(4, field)?.try_into().map_err(|_| SftpError::Malformed(field))?,
        ))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, SftpError> {
        Ok(u64::from_be_bytes(
            self.take(8, field)?.try_into().map_err(|_| SftpError::Malformed(field))?,
        ))
    }

    fn count(&mut self, limit: usize, field: &'static str) -> Result<usize, SftpError> {
        let count = self.u32(field)? as usize;
        if count > limit {
            return Err(SftpError::FieldTooLarge(field));
        }
        Ok(count)
    }

    fn bytes(
        &mut self,
        limit: usize,
        field: &'static str,
        allow_empty: bool,
    ) -> Result<Vec<u8>, SftpError> {
        let bytes = self.opaque(limit, field, allow_empty)?;
        if bytes.contains(&0) {
            return Err(SftpError::InvalidValue(field));
        }
        Ok(bytes)
    }

    fn opaque(
        &mut self,
        limit: usize,
        field: &'static str,
        allow_empty: bool,
    ) -> Result<Vec<u8>, SftpError> {
        let length = self.u32(field)? as usize;
        if length > limit {
            return Err(SftpError::FieldTooLarge(field));
        }
        let bytes = self.take(length, field)?.to_vec();
        if !allow_empty && bytes.is_empty() {
            return Err(SftpError::InvalidValue(field));
        }
        Ok(bytes)
    }

    fn rest(&mut self, limit: usize, field: &'static str) -> Result<Vec<u8>, SftpError> {
        if self.remaining() > limit {
            return Err(SftpError::FieldTooLarge(field));
        }
        self.take(self.remaining(), field).map(ToOwned::to_owned)
    }

    fn finish(&self) -> Result<(), SftpError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(SftpError::Malformed("trailing packet data"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs() -> SftpAttributes {
        SftpAttributes {
            size: Some(42),
            uid_gid: Some((1000, 1000)),
            permissions: Some(0o100_644),
            access_time: Some(1),
            modify_time: Some(2),
            extended: vec![SftpExtension::new(b"x-test".to_vec(), b"v1".to_vec()).unwrap()],
        }
    }

    #[test]
    fn core_packets_round_trip() {
        let packets = [
            SftpPacket::Init { version: 3 },
            SftpPacket::Version {
                version: 3,
                extensions: vec![SftpExtension::new(b"posix-rename@openssh.com", b"1").unwrap()],
            },
            SftpPacket::Open { id: 1, path: b"/tmp/a".to_vec(), pflags: 0x1, attrs: attrs() },
            SftpPacket::Close { id: 2, handle: b"h".to_vec() },
            SftpPacket::Read { id: 3, handle: b"h".to_vec(), offset: 7, length: 1024 },
            SftpPacket::Write { id: 4, handle: b"h".to_vec(), offset: 9, data: b"hello".to_vec() },
            SftpPacket::Stat { id: 5, path: b"/tmp/a".to_vec() },
            SftpPacket::Lstat { id: 6, path: b"/tmp/a".to_vec() },
            SftpPacket::Fstat { id: 7, handle: b"h".to_vec() },
            SftpPacket::Status { id: 8, code: 0, message: b"ok".to_vec(), language: Vec::new() },
            SftpPacket::Handle { id: 9, handle: b"h".to_vec() },
            SftpPacket::Data { id: 10, data: b"data".to_vec() },
            SftpPacket::Attrs { id: 11, attrs: attrs() },
        ];
        for packet in packets {
            let wire = packet.encode().unwrap();
            assert_eq!(SftpPacket::decode(&wire).unwrap(), packet);
        }
    }

    #[test]
    fn decoder_rejects_truncation_trailing_and_oversize_before_allocation() {
        let wire = SftpPacket::Read { id: 1, handle: b"h".to_vec(), offset: 0, length: 1 }
            .encode()
            .unwrap();
        assert_eq!(
            SftpPacket::decode(&wire[..wire.len() - 1]),
            Err(SftpError::Malformed("packet length mismatch"))
        );
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            SftpPacket::decode(&trailing),
            Err(SftpError::Malformed("packet length mismatch"))
        );
        let oversize = u32::try_from(MAX_SFTP_PACKET).unwrap().to_be_bytes();
        assert_eq!(
            SftpPacket::decode(&[oversize.as_slice(), &[FXP_DATA]].concat()),
            Err(SftpError::PacketTooLarge)
        );
        let mut field = vec![0, 0, 0, 9, FXP_DATA, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(SftpPacket::decode(&field), Err(SftpError::FieldTooLarge("data")));
        field[0] = 0;
    }

    #[test]
    fn invalid_values_and_unknown_attributes_are_rejected() {
        assert_eq!(
            SftpPacket::Read { id: 1, handle: b"h".to_vec(), offset: 0, length: 0 }.encode(),
            Err(SftpError::InvalidValue("read length"))
        );
        assert_eq!(
            SftpPacket::Open {
                id: 1,
                path: Vec::new(),
                pflags: 0,
                attrs: SftpAttributes::default()
            }
            .encode(),
            Err(SftpError::InvalidValue("path"))
        );
        let mut wire =
            SftpPacket::Attrs { id: 1, attrs: SftpAttributes::default() }.encode().unwrap();
        wire[9..13].copy_from_slice(&0x10u32.to_be_bytes());
        assert_eq!(
            SftpPacket::decode(&wire),
            Err(SftpError::InvalidValue("unknown attribute flags"))
        );
    }

    #[test]
    fn client_enforces_handshake_pipeline_and_response_correlation() {
        let mut client = SftpClient::new(1).unwrap();
        assert_eq!(client.init().unwrap(), SftpPacket::Init { version: 3 });
        assert_eq!(client.reserve_request_id(), Err(SftpError::HandshakeIncomplete));
        client.accept_version(&SftpPacket::Version { version: 3, extensions: Vec::new() }).unwrap();
        let id = client.reserve_request_id().unwrap();
        assert_eq!(id, 1);
        assert_eq!(client.reserve_request_id(), Err(SftpError::OutstandingLimit));
        assert_eq!(
            client.accept_response(&SftpPacket::Status {
                id: 999,
                code: 4,
                message: Vec::new(),
                language: Vec::new()
            }),
            Err(SftpError::UnknownRequest)
        );
        client.accept_response(&SftpPacket::Data { id, data: b"x".to_vec() }).unwrap();
        assert_eq!(client.pending_requests(), 0);
    }

    #[test]
    fn version_and_attribute_bounds_are_enforced() {
        let extension = SftpExtension::new(vec![b'x'; MAX_SFTP_STRING + 1], Vec::new());
        assert_eq!(extension, Err(SftpError::FieldTooLarge("extension name")));
        let mut extensions = Vec::new();
        for _ in 0..=MAX_SFTP_EXTENSIONS {
            extensions.push(SftpExtension::new(b"x", b"1").unwrap());
        }
        assert_eq!(
            SftpPacket::Version { version: 3, extensions }.encode(),
            Err(SftpError::FieldTooLarge("version extensions"))
        );
    }

    #[test]
    fn opaque_handles_and_extension_data_preserve_binary_bytes() {
        let handle = vec![0, 0xff, 0];
        let packet = SftpPacket::Handle { id: 7, handle: handle.clone() };
        assert_eq!(SftpPacket::decode(&packet.encode().unwrap()), Ok(packet));
        let version = SftpPacket::Version {
            version: 3,
            extensions: vec![SftpExtension::new(b"binary@test", [0, 0xff, 0]).unwrap()],
        };
        assert_eq!(SftpPacket::decode(&version.encode().unwrap()), Ok(version));
        let read = SftpPacket::Read { id: 8, handle, offset: 1, length: 8 };
        assert_eq!(SftpPacket::decode(&read.encode().unwrap()), Ok(read));
    }

    #[test]
    fn requests_reject_unbounded_reads_and_empty_handles() {
        assert_eq!(
            SftpPacket::Read { id: 1, handle: b"h".to_vec(), offset: 0, length: u32::MAX }.encode(),
            Err(SftpError::InvalidValue("read length"))
        );
        assert_eq!(
            SftpPacket::Close { id: 2, handle: Vec::new() }.encode(),
            Err(SftpError::InvalidValue("handle"))
        );
    }

    #[test]
    fn limits_extension_round_trips_and_rejects_wrong_lengths() {
        let request = SftpPacket::limits_request(12);
        assert_eq!(
            SftpPacket::decode(&request.encode().unwrap()),
            Ok(SftpPacket::Extended {
                id: 12,
                name: b"limits@openssh.com".to_vec(),
                data: Vec::new()
            })
        );
        let limits = SftpLimits {
            max_packet_length: MAX_SFTP_PACKET as u64,
            max_read_length: 32 * 1024,
            max_write_length: 16 * 1024,
            max_open_handles: 128,
        };
        let response = SftpPacket::ExtendedReply { id: 12, data: limits.encode() };
        let decoded = SftpPacket::decode(&response.encode().unwrap()).unwrap();
        assert_eq!(decoded.limits_response(), Ok(limits));
        assert_eq!(SftpLimits::decode(&[0; 31]), Err(SftpError::Malformed("limits response")));
        assert_eq!(
            SftpPacket::ExtendedReply { id: 12, data: vec![0; MAX_SFTP_EXTENSION_DATA + 1] }
                .encode(),
            Err(SftpError::FieldTooLarge("extension response"))
        );
    }
}
