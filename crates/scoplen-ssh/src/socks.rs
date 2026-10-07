// SPDX-License-Identifier: Apache-2.0
//! Bounded `SOCKS4a` and `SOCKS5` CONNECT handshakes for dynamic SSH forwarding.
//!
//! The handshake stops at the proxy protocol boundary. A concrete SSH engine owns the listening
//! socket, creates a `direct-tcpip` channel for the returned target, and forwards the response and
//! any trailing application bytes. Every peer-controlled field has a finite limit and fragmented
//! input is retained until one complete handshake message is available.

#![allow(clippy::missing_panics_doc)]

use thiserror::Error;

/// Maximum bytes retained while waiting for one SOCKS handshake.
pub const MAX_SOCKS_BUFFER: usize = 64 * 1024;
/// Maximum SOCKS user identifier accepted by `SOCKS4a`.
pub const MAX_SOCKS_USER_ID: usize = 255;
/// Maximum domain name accepted by `SOCKS4a` and `SOCKS5`.
pub const MAX_SOCKS_DOMAIN: usize = 255;

const SOCKS4_VERSION: u8 = 4;
const SOCKS5_VERSION: u8 = 5;
const SOCKS_CONNECT: u8 = 1;
const SOCKS5_NO_AUTH: u8 = 0;
const SOCKS5_NO_ACCEPTABLE_METHOD: u8 = 0xff;
const SOCKS5_SUCCEEDED: u8 = 0;
const SOCKS5_GENERAL_FAILURE: u8 = 1;
const SOCKS5_CONNECTION_NOT_ALLOWED: u8 = 2;
const SOCKS5_NETWORK_UNREACHABLE: u8 = 3;
const SOCKS5_HOST_UNREACHABLE: u8 = 4;
const SOCKS5_CONNECTION_REFUSED: u8 = 5;
const SOCKS5_TTL_EXPIRED: u8 = 6;
const SOCKS5_COMMAND_NOT_SUPPORTED: u8 = 7;
const SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 8;
const SOCKS4_REQUEST_GRANTED: u8 = 90;
const SOCKS4_REQUEST_REJECTED: u8 = 91;

/// SOCKS protocol version selected by the first byte of a handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksVersion {
    /// SOCKS4 with the `SOCKS4a` domain-name extension.
    V4,
    /// SOCKS5 with no-authentication method negotiation.
    V5,
}

/// An address carried by a SOCKS CONNECT request or response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksAddress {
    /// An IPv4 address.
    Ipv4([u8; 4]),
    /// A DNS name represented as its wire bytes.
    Domain(Vec<u8>),
    /// An IPv6 address.
    Ipv6([u8; 16]),
}

impl SocksAddress {
    fn validate(&self) -> Result<(), SocksError> {
        if let Self::Domain(name) = self {
            validate_domain(name)?;
        }
        Ok(())
    }
}

/// A target requested by a SOCKS client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksConnectRequest {
    /// Version used by the requesting client.
    pub version: SocksVersion,
    /// Target address to open through SSH `direct-tcpip`.
    pub address: SocksAddress,
    /// Target TCP port.
    pub port: u16,
    /// `SOCKS4a` user identifier; always empty for `SOCKS5`.
    pub user_id: Vec<u8>,
}

/// A bound address returned after the SSH channel is connected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksBindAddress {
    /// Address on which the remote side bound the connection.
    pub address: SocksAddress,
    /// Bound TCP port.
    pub port: u16,
}

impl SocksBindAddress {
    /// Construct a bound address after validating a domain response, if present.
    ///
    /// # Errors
    ///
    /// Returns [`SocksError::Malformed`] or [`SocksError::FieldTooLarge`] when a domain address
    /// is empty, contains a NUL byte, or exceeds [`MAX_SOCKS_DOMAIN`].
    pub fn new(address: SocksAddress, port: u16) -> Result<Self, SocksError> {
        address.validate()?;
        Ok(Self { address, port })
    }
}

/// Failure codes a dynamic forwarding engine can map to a SOCKS response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksReply {
    /// An unspecified failure occurred.
    GeneralFailure,
    /// The policy denied the requested connection.
    ConnectionNotAllowed,
    /// The target network was unreachable.
    NetworkUnreachable,
    /// The target host was unreachable.
    HostUnreachable,
    /// The target refused the connection.
    ConnectionRefused,
    /// The target response expired.
    TtlExpired,
    /// The request command is not supported.
    CommandNotSupported,
    /// The requested address type is not supported.
    AddressTypeNotSupported,
}

impl SocksReply {
    const fn socks5_code(self) -> u8 {
        match self {
            Self::GeneralFailure => SOCKS5_GENERAL_FAILURE,
            Self::ConnectionNotAllowed => SOCKS5_CONNECTION_NOT_ALLOWED,
            Self::NetworkUnreachable => SOCKS5_NETWORK_UNREACHABLE,
            Self::HostUnreachable => SOCKS5_HOST_UNREACHABLE,
            Self::ConnectionRefused => SOCKS5_CONNECTION_REFUSED,
            Self::TtlExpired => SOCKS5_TTL_EXPIRED,
            Self::CommandNotSupported => SOCKS5_COMMAND_NOT_SUPPORTED,
            Self::AddressTypeNotSupported => SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,
        }
    }
}

/// Errors returned while parsing or completing a SOCKS handshake.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SocksError {
    /// The input is not a valid message for the selected SOCKS version.
    #[error("malformed SOCKS handshake: {0}")]
    Malformed(&'static str),
    /// The first byte did not identify a supported SOCKS version.
    #[error("unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),
    /// A peer-controlled field exceeded its protocol bound.
    #[error("SOCKS field is too large: {0}")]
    FieldTooLarge(&'static str),
    /// More bytes are required to finish the handshake.
    #[error("truncated SOCKS handshake")]
    Truncated,
    /// The caller supplied bytes after the handshake reached a terminal state.
    #[error("SOCKS handshake is already complete")]
    AlreadyComplete,
    /// The caller attempted to complete a request before receiving one or twice.
    #[error("SOCKS handshake is not waiting for a connection result")]
    InvalidState,
    /// `SOCKS4a` can only represent an IPv4 bound address.
    #[error("SOCKS4a bound address must be IPv4")]
    InvalidSocks4BoundAddress,
}

/// The result of feeding bytes to a [`SocksHandshake`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksProgress {
    /// Protocol bytes that must be sent back to the client immediately.
    pub response: Vec<u8>,
    /// A complete CONNECT request, when one has been parsed.
    pub request: Option<SocksConnectRequest>,
    /// Bytes after the CONNECT request that belong to the proxied stream.
    pub trailing: Vec<u8>,
    /// Whether the handshake reached a terminal state without a connection request.
    pub done: bool,
}

impl SocksProgress {
    fn empty() -> Self {
        Self { response: Vec::new(), request: None, trailing: Vec::new(), done: false }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakeState {
    Initial,
    V5Request,
    WaitingForResult,
    Complete,
    Failed,
}

/// A bounded, fragmented SOCKS4a/SOCKS5 CONNECT handshake.
///
/// SOCKS5 accepts only the no-authentication method and CONNECT command. The caller supplies the
/// result of opening the requested target through [`Self::accept`] or [`Self::reject`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksHandshake {
    state: HandshakeState,
    version: Option<SocksVersion>,
    buffer: Vec<u8>,
}

impl Default for SocksHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl SocksHandshake {
    /// Create an empty handshake parser.
    #[must_use]
    pub fn new() -> Self {
        Self { state: HandshakeState::Initial, version: None, buffer: Vec::new() }
    }

    /// Return the detected SOCKS version once the first byte has arrived.
    #[must_use]
    pub const fn version(&self) -> Option<SocksVersion> {
        self.version
    }

    /// Feed one fragment of client input.
    ///
    /// `response` is ready to send on the SSH channel. When `request` is present, the caller must
    /// open the target and then call [`Self::accept`] or [`Self::reject`]. Any bytes after the
    /// request are returned in `trailing` so they can be forwarded without being buffered here.
    ///
    /// # Errors
    ///
    /// Returns [`SocksError::FieldTooLarge`] for an input buffer beyond the configured bound,
    /// [`SocksError::Malformed`] for an invalid complete message, and
    /// [`SocksError::AlreadyComplete`] or [`SocksError::InvalidState`] when the caller feeds bytes
    /// after the handshake has reached a terminal state or is awaiting a connection result.
    pub fn feed(&mut self, input: &[u8]) -> Result<SocksProgress, SocksError> {
        if matches!(self.state, HandshakeState::Complete | HandshakeState::Failed) {
            return Err(SocksError::AlreadyComplete);
        }
        if self.state == HandshakeState::WaitingForResult {
            return Err(SocksError::InvalidState);
        }
        let new_length = self
            .buffer
            .len()
            .checked_add(input.len())
            .ok_or(SocksError::FieldTooLarge("handshake buffer"))?;
        if new_length > MAX_SOCKS_BUFFER {
            return Err(SocksError::FieldTooLarge("handshake buffer"));
        }
        self.buffer.extend_from_slice(input);
        if self.version.is_none() {
            let Some(version) = self.buffer.first().copied() else {
                return Ok(SocksProgress::empty());
            };
            self.version = Some(match version {
                SOCKS4_VERSION => SocksVersion::V4,
                SOCKS5_VERSION => SocksVersion::V5,
                other => return Err(SocksError::UnsupportedVersion(other)),
            });
        }

        let version = self.version.ok_or(SocksError::InvalidState)?;
        match version {
            SocksVersion::V4 => self.parse_v4(),
            SocksVersion::V5 => self.parse_v5(),
        }
    }

    /// Finish the input stream and reject an incomplete handshake.
    ///
    /// # Errors
    ///
    /// Returns [`SocksError::Truncated`] when the client closed before a complete request or
    /// connection result was received.
    pub fn finish(&self) -> Result<(), SocksError> {
        if matches!(self.state, HandshakeState::Complete | HandshakeState::Failed) {
            return Ok(());
        }
        Err(SocksError::Truncated)
    }

    /// Encode a successful response after the requested target was opened.
    ///
    /// # Errors
    ///
    /// Returns [`SocksError::InvalidState`] unless [`Self::feed`] produced a request, or
    /// [`SocksError::InvalidSocks4BoundAddress`] when a `SOCKS4a` response is given a non-IPv4
    /// address.
    pub fn accept(&mut self, bound: &SocksBindAddress) -> Result<Vec<u8>, SocksError> {
        if self.state != HandshakeState::WaitingForResult {
            return Err(SocksError::InvalidState);
        }
        let version = self.version.ok_or(SocksError::InvalidState)?;
        let response = match version {
            SocksVersion::V4 => encode_v4_response(bound, SOCKS4_REQUEST_GRANTED)?,
            SocksVersion::V5 => encode_v5_response(bound, SOCKS5_SUCCEEDED)?,
        };
        self.state = HandshakeState::Complete;
        Ok(response)
    }

    /// Encode a failure response after the requested target could not be opened.
    ///
    /// # Errors
    ///
    /// Returns [`SocksError::InvalidState`] unless [`Self::feed`] produced a request.
    pub fn reject(&mut self, reply: SocksReply) -> Result<Vec<u8>, SocksError> {
        if self.state != HandshakeState::WaitingForResult {
            return Err(SocksError::InvalidState);
        }
        let response = match self.version.ok_or(SocksError::InvalidState)? {
            SocksVersion::V4 => encode_v4_failure(),
            SocksVersion::V5 => encode_v5_response(
                &SocksBindAddress { address: SocksAddress::Ipv4([0; 4]), port: 0 },
                reply.socks5_code(),
            )?,
        };
        self.state = HandshakeState::Failed;
        Ok(response)
    }

    fn parse_v4(&mut self) -> Result<SocksProgress, SocksError> {
        if self.buffer.len() < 8 {
            return Ok(SocksProgress::empty());
        }
        if self.buffer[0] != SOCKS4_VERSION {
            return Err(SocksError::Malformed("SOCKS4 version"));
        }
        let command = self.buffer[1];
        let port = u16::from_be_bytes([self.buffer[2], self.buffer[3]]);
        let address = [self.buffer[4], self.buffer[5], self.buffer[6], self.buffer[7]];
        let user_start = 8;
        let Some(user_end) =
            self.find_terminated(user_start, MAX_SOCKS_USER_ID, "user identifier")?
        else {
            return Ok(SocksProgress::empty());
        };
        let user_id = self.buffer[user_start..user_end].to_vec();
        let domain_mode = address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] != 0;
        let (target, consumed) = if domain_mode {
            let domain_start = user_end + 1;
            let Some(domain_end) =
                self.find_terminated(domain_start, MAX_SOCKS_DOMAIN, "domain name")?
            else {
                return Ok(SocksProgress::empty());
            };
            let domain = self.buffer[domain_start..domain_end].to_vec();
            validate_domain(&domain)?;
            (SocksAddress::Domain(domain), domain_end + 1)
        } else {
            (SocksAddress::Ipv4(address), user_end + 1)
        };
        if command != SOCKS_CONNECT {
            self.buffer.clear();
            self.state = HandshakeState::Failed;
            return Ok(SocksProgress {
                response: encode_v4_failure(),
                request: None,
                trailing: Vec::new(),
                done: true,
            });
        }
        let trailing = self.buffer.split_off(consumed);
        self.buffer.clear();
        self.state = HandshakeState::WaitingForResult;
        Ok(SocksProgress {
            response: Vec::new(),
            request: Some(SocksConnectRequest {
                version: SocksVersion::V4,
                address: target,
                port,
                user_id,
            }),
            trailing,
            done: false,
        })
    }

    fn parse_v5(&mut self) -> Result<SocksProgress, SocksError> {
        if self.state == HandshakeState::Initial {
            if self.buffer.len() < 2 {
                return Ok(SocksProgress::empty());
            }
            if self.buffer[0] != SOCKS5_VERSION {
                return Err(SocksError::Malformed("SOCKS5 version"));
            }
            let method_count = usize::from(self.buffer[1]);
            let greeting_len = 2 + method_count;
            if self.buffer.len() < greeting_len {
                return Ok(SocksProgress::empty());
            }
            let supports_no_auth = self.buffer[2..greeting_len].contains(&SOCKS5_NO_AUTH);
            self.buffer.drain(..greeting_len);
            if !supports_no_auth {
                self.state = HandshakeState::Failed;
                return Ok(SocksProgress {
                    response: vec![SOCKS5_VERSION, SOCKS5_NO_ACCEPTABLE_METHOD],
                    request: None,
                    trailing: Vec::new(),
                    done: true,
                });
            }
            self.state = HandshakeState::V5Request;
            if self.buffer.is_empty() {
                return Ok(SocksProgress {
                    response: vec![SOCKS5_VERSION, SOCKS5_NO_AUTH],
                    request: None,
                    trailing: Vec::new(),
                    done: false,
                });
            }
            let mut progress = self.parse_v5_request()?;
            let mut response = vec![SOCKS5_VERSION, SOCKS5_NO_AUTH];
            response.append(&mut progress.response);
            progress.response = response;
            return Ok(progress);
        }
        self.parse_v5_request()
    }

    fn parse_v5_request(&mut self) -> Result<SocksProgress, SocksError> {
        if self.buffer.len() < 4 {
            return Ok(SocksProgress::empty());
        }
        if self.buffer[0] != SOCKS5_VERSION {
            return Err(SocksError::Malformed("SOCKS5 request version"));
        }
        let command = self.buffer[1];
        if self.buffer[2] != 0 {
            return Err(SocksError::Malformed("SOCKS5 reserved field"));
        }
        let address_type = self.buffer[3];
        let (address, address_len) = match address_type {
            1 => {
                let needed = 4 + 4 + 2;
                if self.buffer.len() < needed {
                    return Ok(SocksProgress::empty());
                }
                let mut value = [0; 4];
                value.copy_from_slice(&self.buffer[4..8]);
                (SocksAddress::Ipv4(value), needed)
            }
            3 => {
                if self.buffer.len() < 5 {
                    return Ok(SocksProgress::empty());
                }
                let length = usize::from(self.buffer[4]);
                if length == 0 {
                    return Err(SocksError::Malformed("empty SOCKS5 domain name"));
                }
                if length > MAX_SOCKS_DOMAIN {
                    return Err(SocksError::FieldTooLarge("domain name"));
                }
                let needed = 5 + length + 2;
                if self.buffer.len() < needed {
                    return Ok(SocksProgress::empty());
                }
                let value = self.buffer[5..5 + length].to_vec();
                validate_domain(&value)?;
                (SocksAddress::Domain(value), needed)
            }
            4 => {
                let needed = 4 + 16 + 2;
                if self.buffer.len() < needed {
                    return Ok(SocksProgress::empty());
                }
                let mut value = [0; 16];
                value.copy_from_slice(&self.buffer[4..20]);
                (SocksAddress::Ipv6(value), needed)
            }
            _ => {
                self.buffer.clear();
                self.state = HandshakeState::Failed;
                return Ok(SocksProgress {
                    response: encode_v5_response(
                        &SocksBindAddress { address: SocksAddress::Ipv4([0; 4]), port: 0 },
                        SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,
                    )?,
                    request: None,
                    trailing: Vec::new(),
                    done: true,
                });
            }
        };
        let port_offset = address_len - 2;
        let port = u16::from_be_bytes([self.buffer[port_offset], self.buffer[port_offset + 1]]);
        if command != SOCKS_CONNECT {
            self.buffer.clear();
            self.state = HandshakeState::Failed;
            return Ok(SocksProgress {
                response: encode_v5_response(
                    &SocksBindAddress { address: SocksAddress::Ipv4([0; 4]), port: 0 },
                    SOCKS5_COMMAND_NOT_SUPPORTED,
                )?,
                request: None,
                trailing: Vec::new(),
                done: true,
            });
        }
        let trailing = self.buffer.split_off(address_len);
        self.buffer.clear();
        self.state = HandshakeState::WaitingForResult;
        Ok(SocksProgress {
            response: Vec::new(),
            request: Some(SocksConnectRequest {
                version: SocksVersion::V5,
                address,
                port,
                user_id: Vec::new(),
            }),
            trailing,
            done: false,
        })
    }

    fn find_terminated(
        &self,
        start: usize,
        limit: usize,
        field: &'static str,
    ) -> Result<Option<usize>, SocksError> {
        let remaining = self.buffer.get(start..).ok_or(SocksError::Malformed(field))?;
        if let Some(offset) = remaining.iter().position(|byte| *byte == 0) {
            if offset > limit {
                return Err(SocksError::FieldTooLarge(field));
            }
            Ok(Some(start + offset))
        } else if remaining.len() > limit {
            Err(SocksError::FieldTooLarge(field))
        } else {
            Ok(None)
        }
    }
}

fn validate_domain(domain: &[u8]) -> Result<(), SocksError> {
    if domain.is_empty() {
        return Err(SocksError::Malformed("empty domain name"));
    }
    if domain.len() > MAX_SOCKS_DOMAIN {
        return Err(SocksError::FieldTooLarge("domain name"));
    }
    if domain.contains(&0) {
        return Err(SocksError::Malformed("NUL in domain name"));
    }
    Ok(())
}

fn encode_v4_response(bound: &SocksBindAddress, status: u8) -> Result<Vec<u8>, SocksError> {
    let SocksAddress::Ipv4(address) = bound.address else {
        return Err(SocksError::InvalidSocks4BoundAddress);
    };
    let mut response = Vec::with_capacity(8);
    response.extend_from_slice(&[0, status]);
    response.extend_from_slice(&bound.port.to_be_bytes());
    response.extend_from_slice(&address);
    Ok(response)
}

fn encode_v4_failure() -> Vec<u8> {
    vec![0, SOCKS4_REQUEST_REJECTED, 0, 0, 0, 0, 0, 0]
}

fn encode_v5_response(bound: &SocksBindAddress, reply: u8) -> Result<Vec<u8>, SocksError> {
    bound.address.validate()?;
    let mut response = vec![SOCKS5_VERSION, reply, 0];
    match &bound.address {
        SocksAddress::Ipv4(address) => {
            response.push(1);
            response.extend_from_slice(address);
        }
        SocksAddress::Domain(domain) => {
            response.push(3);
            response.push(
                u8::try_from(domain.len()).map_err(|_| SocksError::FieldTooLarge("domain name"))?,
            );
            response.extend_from_slice(domain);
        }
        SocksAddress::Ipv6(address) => {
            response.push(4);
            response.extend_from_slice(address);
        }
    }
    response.extend_from_slice(&bound.port.to_be_bytes());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_request(address: [u8; 4], user: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut wire = vec![SOCKS4_VERSION, SOCKS_CONNECT, 0, 22];
        wire.extend_from_slice(&address);
        wire.extend_from_slice(user);
        wire.push(0);
        if address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] != 0 {
            wire.extend_from_slice(b"7\0");
        }
        wire.extend_from_slice(tail);
        wire
    }

    fn v5_greeting(methods: &[u8]) -> Vec<u8> {
        let mut wire = vec![SOCKS5_VERSION, u8::try_from(methods.len()).expect("method count")];
        wire.extend_from_slice(methods);
        wire
    }

    fn v5_request(address_type: u8, address: &[u8], port: u16, tail: &[u8]) -> Vec<u8> {
        let mut wire = vec![SOCKS5_VERSION, SOCKS_CONNECT, 0, address_type];
        if address_type == 3 {
            wire.push(u8::try_from(address.len()).expect("domain length"));
        }
        wire.extend_from_slice(address);
        wire.extend_from_slice(&port.to_be_bytes());
        wire.extend_from_slice(tail);
        wire
    }

    #[test]
    fn socks4a_fragmentation_and_trailing_data_round_trip() {
        let wire = v4_request([0, 0, 0, 7], b"alice", b"hello");
        let mut split = wire.chunks(2);
        let mut handshake = SocksHandshake::new();
        for fragment in split.by_ref().take(5) {
            assert_eq!(handshake.feed(fragment).expect("fragment").request, None);
        }
        let mut remaining = Vec::new();
        for fragment in split {
            remaining.extend_from_slice(fragment);
        }
        let progress = handshake.feed(&remaining).expect("request");
        assert_eq!(
            progress.request,
            Some(SocksConnectRequest {
                version: SocksVersion::V4,
                address: SocksAddress::Domain(b"7".to_vec()),
                port: 22,
                user_id: b"alice".to_vec(),
            })
        );
        assert_eq!(progress.trailing, b"hello");
        let response = handshake
            .accept(
                &SocksBindAddress::new(SocksAddress::Ipv4([127, 0, 0, 1]), 4000).expect("bound"),
            )
            .expect("response");
        assert_eq!(response, vec![0, SOCKS4_REQUEST_GRANTED, 0x0f, 0xa0, 127, 0, 0, 1]);
        assert_eq!(handshake.finish(), Ok(()));
    }

    #[test]
    fn socks5_method_and_request_round_trip_with_fragmentation() {
        let mut wire = v5_greeting(&[2, SOCKS5_NO_AUTH]);
        wire.extend_from_slice(&v5_request(3, b"db.internal", 5432, b"sql"));
        let mut handshake = SocksHandshake::new();
        let mut progress = SocksProgress::empty();
        let mut method_response = Vec::new();
        for fragment in wire.chunks(5) {
            progress = handshake.feed(fragment).expect("fragment");
            if !progress.response.is_empty() && progress.request.is_none() {
                method_response = progress.response.clone();
            }
            if progress.request.is_some() {
                break;
            }
        }
        assert_eq!(method_response, vec![SOCKS5_VERSION, SOCKS5_NO_AUTH]);
        assert_eq!(
            progress.request,
            Some(SocksConnectRequest {
                version: SocksVersion::V5,
                address: SocksAddress::Domain(b"db.internal".to_vec()),
                port: 5432,
                user_id: Vec::new(),
            })
        );
        assert_eq!(progress.trailing, b"sql");
        let response = handshake
            .accept(&SocksBindAddress::new(SocksAddress::Ipv6([0; 16]), 6000).expect("bound"))
            .expect("response");
        assert_eq!(response.len(), 22);
        assert_eq!(&response[..20], [5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&response[20..], [0x17, 0x70]);
    }

    #[test]
    fn socks5_rejects_unsupported_method_command_and_address_type() {
        let mut no_auth = SocksHandshake::new();
        assert_eq!(
            no_auth.feed(&v5_greeting(&[2])).expect("method response").response,
            vec![5, 255]
        );
        assert_eq!(no_auth.feed(&[]), Err(SocksError::AlreadyComplete));

        let mut command = SocksHandshake::new();
        let mut greeting = v5_greeting(&[SOCKS5_NO_AUTH]);
        greeting.extend_from_slice(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 22]);
        let progress = command.feed(&greeting).expect("command response");
        assert_eq!(
            progress.response,
            vec![5, 0, 5, SOCKS5_COMMAND_NOT_SUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert!(progress.done);

        let mut address = SocksHandshake::new();
        let mut greeting = v5_greeting(&[SOCKS5_NO_AUTH]);
        greeting.extend_from_slice(&[5, 1, 0, 9]);
        let progress = address.feed(&greeting).expect("address response");
        assert_eq!(progress.response.len(), 12);
        assert!(progress.done);
    }

    #[test]
    fn malformed_truncated_and_oversized_inputs_fail_closed() {
        let mut malformed = SocksHandshake::new();
        assert_eq!(malformed.feed(&[6]), Err(SocksError::UnsupportedVersion(6)));

        let mut truncated = SocksHandshake::new();
        assert_eq!(truncated.feed(&[4, 1, 0, 22, 127, 0, 0, 1]), Ok(SocksProgress::empty()));
        assert_eq!(truncated.finish(), Err(SocksError::Truncated));

        let mut oversized = SocksHandshake::new();
        assert_eq!(
            oversized.feed(&vec![5; MAX_SOCKS_BUFFER + 1]),
            Err(SocksError::FieldTooLarge("handshake buffer"))
        );

        let mut bad_domain = SocksHandshake::new();
        let mut request = v5_greeting(&[SOCKS5_NO_AUTH]);
        request.extend_from_slice(&[5, 1, 0, 3, 0]);
        assert_eq!(
            bad_domain.feed(&request),
            Err(SocksError::Malformed("empty SOCKS5 domain name"))
        );
    }

    #[test]
    fn completion_requires_connection_result_and_socks4_bound_is_ipv4() {
        let mut handshake = SocksHandshake::new();
        assert_eq!(
            handshake.accept(&SocksBindAddress::new(SocksAddress::Ipv4([0; 4]), 0).expect("bound")),
            Err(SocksError::InvalidState)
        );

        let request = v4_request([127, 0, 0, 1], b"user", &[]);
        let progress = handshake.feed(&request).expect("request");
        assert!(progress.request.is_some());
        assert_eq!(
            handshake.accept(
                &SocksBindAddress::new(SocksAddress::Domain(b"bound".to_vec()), 22).expect("bound"),
            ),
            Err(SocksError::InvalidSocks4BoundAddress)
        );
        let response = handshake.reject(SocksReply::ConnectionRefused).expect("reject");
        assert_eq!(response, vec![0, SOCKS4_REQUEST_REJECTED, 0, 0, 0, 0, 0, 0]);
        assert_eq!(handshake.reject(SocksReply::GeneralFailure), Err(SocksError::InvalidState));
    }
}
