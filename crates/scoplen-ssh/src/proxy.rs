// SPDX-License-Identifier: Apache-2.0
//! Outbound SOCKS5 and HTTP CONNECT transports.
//!
//! These adapters establish a bounded proxy handshake over [`TcpTransport`] and then expose the
//! resulting byte stream through [`Transport`]. SSH version exchange and authentication remain
//! owned by the caller.

use std::{
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr},
    time::Duration,
};

use scoplen_crypto::SecretVec;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::tcp::{TcpTransport, Transport, TransportError, TransportOperation};

/// Maximum bytes retained while parsing an HTTP proxy response.
pub const MAX_HTTP_CONNECT_RESPONSE: usize = 16 * 1024;
/// Maximum host name accepted as a proxy target.
pub const MAX_PROXY_HOST: usize = 255;
/// Maximum byte length of a proxy authentication username or password.
pub const MAX_PROXY_CREDENTIAL: usize = 255;

/// Proxy protocol used by a composed transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocol {
    /// SOCKS version 5 with the no-authentication method.
    Socks5,
    /// HTTP/1.1 CONNECT.
    HttpConnect,
}

/// Failure stage for an outbound proxy handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyOperation {
    /// Writing a handshake request.
    Write,
    /// Reading a handshake response.
    Read,
    /// Parsing a handshake response.
    Parse,
    /// The proxy returned a non-success status.
    Reject,
}

/// A failure raised while composing a byte transport through a proxy.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProxyError {
    /// The target host is empty, too long, or contains a NUL byte.
    #[error("proxy target host is invalid")]
    InvalidTargetHost,
    /// A proxy authentication field was empty, oversized, or contained a control byte.
    #[error("proxy {field} credential is invalid")]
    InvalidCredential { field: &'static str },
    /// The proxy response exceeded its parser bound.
    #[error("{protocol:?} proxy response exceeds the {max}-byte limit")]
    ResponseTooLarge { protocol: ProxyProtocol, max: usize },
    /// The proxy response was not valid for the selected protocol.
    #[error("malformed {protocol:?} proxy response")]
    MalformedResponse { protocol: ProxyProtocol },
    /// The proxy rejected the requested target.
    #[error("{protocol:?} proxy rejected the request with code {code}")]
    Rejected { protocol: ProxyProtocol, code: u16 },
    /// The proxy selected authentication but rejected the supplied credentials.
    #[error("{protocol:?} proxy authentication was rejected with code {code}")]
    AuthenticationRejected { protocol: ProxyProtocol, code: u16 },
    /// An I/O operation failed during the handshake.
    #[error("{protocol:?} proxy {operation:?} failed: {kind:?}")]
    Io { protocol: ProxyProtocol, operation: ProxyOperation, kind: io::ErrorKind },
}

/// Credentials used by a SOCKS5 username/password or HTTP Basic proxy handshake.
///
/// Password bytes are zeroized on drop and are redacted from debug output. The credentials are
/// only copied into the bounded handshake request; the resulting transport does not retain them.
#[derive(Clone, Eq, PartialEq)]
pub struct ProxyCredentials {
    username: Vec<u8>,
    password: SecretVec,
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyCredentials")
            .field("username_len", &self.username.len())
            .field("password", &self.password)
            .finish()
    }
}

impl ProxyCredentials {
    /// Construct bounded credentials from byte strings.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::InvalidCredential`] when either field is empty, contains a control
    /// byte, or exceeds [`MAX_PROXY_CREDENTIAL`].
    pub fn new(username: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Result<Self, ProxyError> {
        let username = validate_credential_field(username.as_ref(), "username")?.to_vec();
        let password = validate_credential_field(password.as_ref(), "password")?.to_vec();
        Ok(Self { username, password: SecretVec::new(password) })
    }

    fn username(&self) -> &[u8] {
        &self.username
    }

    fn password(&self) -> &[u8] {
        self.password.as_bytes()
    }
}

impl From<ProxyError> for TransportError {
    fn from(error: ProxyError) -> Self {
        let kind = match error {
            ProxyError::InvalidTargetHost | ProxyError::InvalidCredential { .. } => {
                io::ErrorKind::InvalidInput
            }
            ProxyError::ResponseTooLarge { .. } | ProxyError::MalformedResponse { .. } => {
                io::ErrorKind::InvalidData
            }
            ProxyError::Rejected { .. } => io::ErrorKind::ConnectionRefused,
            ProxyError::AuthenticationRejected { .. } => io::ErrorKind::PermissionDenied,
            ProxyError::Io { kind, .. } => kind,
        };
        TransportError::Proxy { error, kind }
    }
}

/// Errors raised by transport composition, including the underlying TCP connect boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProxyTransportError {
    /// The proxy TCP connection failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The proxy handshake failed.
    #[error(transparent)]
    Proxy(#[from] ProxyError),
}

/// A connected stream established through a SOCKS5 proxy.
#[derive(Debug)]
pub struct Socks5Transport {
    inner: TcpTransport,
}

impl Socks5Transport {
    /// Connect to `target_host:target_port` through `proxy_host:proxy_port`.
    ///
    /// Only the SOCKS5 no-authentication method and CONNECT command are used. The supplied
    /// timeout bounds proxy TCP connection and each handshake read/write through socket timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyTransportError`] when the proxy cannot be reached, rejects the request,
    /// sends a malformed response, or exceeds the bounded handshake limits.
    pub fn connect(
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<Self, ProxyTransportError> {
        Self::connect_with_credentials(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            None,
            timeout,
        )
    }

    /// Connect through SOCKS5 with optional RFC 1929 username/password authentication.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyTransportError`] when the proxy TCP connection or bounded handshake fails.
    pub fn connect_with_credentials(
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        credentials: Option<&ProxyCredentials>,
        timeout: Duration,
    ) -> Result<Self, ProxyTransportError> {
        validate_target_host(target_host).map_err(ProxyTransportError::Proxy)?;
        if timeout.is_zero() {
            return Err(ProxyTransportError::Transport(TransportError::InvalidTimeout));
        }
        let mut inner = TcpTransport::connect(proxy_host, proxy_port, timeout)?;
        configure_handshake_timeout(&mut inner, timeout)?;
        socks5_handshake(&mut inner, target_host, target_port, credentials)?;
        clear_handshake_timeout(&inner)?;
        Ok(Self { inner })
    }

    /// Borrow the connected TCP stream.
    #[must_use]
    pub const fn as_stream(&self) -> &std::net::TcpStream {
        self.inner.as_stream()
    }

    /// Consume the adapter and return its TCP stream.
    #[must_use]
    pub fn into_stream(self) -> std::net::TcpStream {
        self.inner.into_stream()
    }
}

impl Transport for Socks5Transport {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        Transport::read(&mut self.inner, buffer)
    }
    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
        Transport::write(&mut self.inner, buffer)
    }
    fn flush(&mut self) -> Result<(), TransportError> {
        Transport::flush(&mut self.inner)
    }
    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError> {
        self.inner.shutdown(how)
    }
    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        self.inner.peer_addr()
    }
}

impl Read for Socks5Transport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Transport::read(self, buffer).map_err(Into::into)
    }
}

impl Write for Socks5Transport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Transport::write(self, buffer).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Transport::flush(self).map_err(Into::into)
    }
}

/// A connected stream established through an HTTP CONNECT proxy.
#[derive(Debug)]
pub struct HttpConnectTransport {
    inner: TcpTransport,
}

impl HttpConnectTransport {
    /// Connect to `target_host:target_port` through `proxy_host:proxy_port`.
    ///
    /// The request uses HTTP/1.1 CONNECT without proxy credentials. The response header is capped
    /// at [`MAX_HTTP_CONNECT_RESPONSE`] bytes and only a 2xx status establishes the stream.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyTransportError`] when the proxy cannot be reached, rejects the request,
    /// sends a malformed response, or exceeds the bounded header limit.
    pub fn connect(
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<Self, ProxyTransportError> {
        Self::connect_with_credentials(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            None,
            timeout,
        )
    }

    /// Connect through HTTP CONNECT with optional RFC 7617 Basic authentication.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyTransportError`] when the proxy TCP connection or bounded handshake fails.
    pub fn connect_with_credentials(
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        credentials: Option<&ProxyCredentials>,
        timeout: Duration,
    ) -> Result<Self, ProxyTransportError> {
        validate_http_target_host(target_host).map_err(ProxyTransportError::Proxy)?;
        if timeout.is_zero() {
            return Err(ProxyTransportError::Transport(TransportError::InvalidTimeout));
        }
        let mut inner = TcpTransport::connect(proxy_host, proxy_port, timeout)?;
        configure_handshake_timeout(&mut inner, timeout)?;
        http_connect_handshake(&mut inner, target_host, target_port, credentials)?;
        clear_handshake_timeout(&inner)?;
        Ok(Self { inner })
    }

    /// Borrow the connected TCP stream.
    #[must_use]
    pub const fn as_stream(&self) -> &std::net::TcpStream {
        self.inner.as_stream()
    }

    /// Consume the adapter and return its TCP stream.
    #[must_use]
    pub fn into_stream(self) -> std::net::TcpStream {
        self.inner.into_stream()
    }
}

impl Transport for HttpConnectTransport {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        Transport::read(&mut self.inner, buffer)
    }
    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
        Transport::write(&mut self.inner, buffer)
    }
    fn flush(&mut self) -> Result<(), TransportError> {
        Transport::flush(&mut self.inner)
    }
    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError> {
        self.inner.shutdown(how)
    }
    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        self.inner.peer_addr()
    }
}

impl Read for HttpConnectTransport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Transport::read(self, buffer).map_err(Into::into)
    }
}

impl Write for HttpConnectTransport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Transport::write(self, buffer).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Transport::flush(self).map_err(Into::into)
    }
}

fn validate_target_host(host: &str) -> Result<(), ProxyError> {
    if host.is_empty()
        || host.len() > MAX_PROXY_HOST
        || host.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(ProxyError::InvalidTargetHost);
    }
    if host.parse::<IpAddr>().is_err() && host.len() > u8::MAX as usize {
        return Err(ProxyError::InvalidTargetHost);
    }
    Ok(())
}

fn validate_credential_field<'a>(
    field: &'a [u8],
    name: &'static str,
) -> Result<&'a [u8], ProxyError> {
    if field.is_empty()
        || field.len() > MAX_PROXY_CREDENTIAL
        || field.iter().any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return Err(ProxyError::InvalidCredential { field: name });
    }
    Ok(field)
}

fn validate_http_target_host(host: &str) -> Result<(), ProxyError> {
    validate_target_host(host)?;
    if host
        .bytes()
        .any(|byte| byte >= 0x80 || matches!(byte, b' ' | b'"' | b'\'' | b'/' | b'?' | b'#' | b'@'))
        || (host.parse::<IpAddr>().is_err() && host.contains(':'))
    {
        return Err(ProxyError::InvalidTargetHost);
    }
    Ok(())
}

fn configure_handshake_timeout(
    inner: &mut TcpTransport,
    timeout: Duration,
) -> Result<(), TransportError> {
    inner.as_stream().set_read_timeout(Some(timeout)).map_err(|error| TransportError::Io {
        operation: TransportOperation::Read,
        kind: error.kind(),
    })?;
    inner.as_stream().set_write_timeout(Some(timeout)).map_err(|error| TransportError::Io {
        operation: TransportOperation::Write,
        kind: error.kind(),
    })?;
    Ok(())
}

fn proxy_io(
    protocol: ProxyProtocol,
    operation: ProxyOperation,
    error: &io::Error,
) -> ProxyTransportError {
    ProxyTransportError::Proxy(ProxyError::Io { protocol, operation, kind: error.kind() })
}

fn proxy_transport_io(
    protocol: ProxyProtocol,
    operation: ProxyOperation,
    error: TransportError,
) -> ProxyTransportError {
    let io_error: io::Error = error.into();
    ProxyTransportError::Proxy(ProxyError::Io { protocol, operation, kind: io_error.kind() })
}

fn clear_handshake_timeout(inner: &TcpTransport) -> Result<(), TransportError> {
    inner.as_stream().set_read_timeout(None).map_err(|error| TransportError::Configure {
        option: "proxy read timeout",
        kind: error.kind(),
    })?;
    inner.as_stream().set_write_timeout(None).map_err(|error| TransportError::Configure {
        option: "proxy write timeout",
        kind: error.kind(),
    })?;
    Ok(())
}

fn socks5_handshake(
    stream: &mut TcpTransport,
    target_host: &str,
    target_port: u16,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), ProxyTransportError> {
    let methods: &[u8] = if credentials.is_some() { &[2] } else { &[0] };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.extend_from_slice(&[5, u8::try_from(methods.len()).expect("method count bounded")]);
    greeting.extend_from_slice(methods);
    stream
        .write_all(&greeting)
        .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Write, &error))?;
    Transport::flush(stream)
        .map_err(|error| proxy_transport_io(ProxyProtocol::Socks5, ProxyOperation::Write, error))?;
    let mut method = [0; 2];
    stream
        .read_exact(&mut method)
        .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Read, &error))?;
    if method[0] != 5 {
        return Err(ProxyError::MalformedResponse { protocol: ProxyProtocol::Socks5 }.into());
    }
    if method[1] == 2 {
        let credentials = credentials.ok_or(ProxyError::Rejected {
            protocol: ProxyProtocol::Socks5,
            code: u16::from(method[1]),
        })?;
        let username = credentials.username();
        let password = credentials.password();
        let mut request = Zeroizing::new(Vec::with_capacity(3 + username.len() + password.len()));
        request.extend_from_slice(&[
            1,
            u8::try_from(username.len()).expect("credential username is bounded"),
        ]);
        request.extend_from_slice(username);
        request.push(u8::try_from(password.len()).expect("credential password is bounded"));
        request.extend_from_slice(password);
        stream
            .write_all(&request)
            .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Write, &error))?;
        Transport::flush(stream).map_err(|error| {
            proxy_transport_io(ProxyProtocol::Socks5, ProxyOperation::Write, error)
        })?;
        let mut response = [0; 2];
        stream
            .read_exact(&mut response)
            .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Read, &error))?;
        if response[0] != 1 {
            return Err(ProxyError::MalformedResponse { protocol: ProxyProtocol::Socks5 }.into());
        }
        if response[1] != 0 {
            return Err(ProxyError::AuthenticationRejected {
                protocol: ProxyProtocol::Socks5,
                code: u16::from(response[1]),
            }
            .into());
        }
    } else if method[1] != 0 || credentials.is_some() {
        return Err(ProxyError::Rejected {
            protocol: ProxyProtocol::Socks5,
            code: u16::from(method[1]),
        }
        .into());
    }

    let mut request = vec![5, 1, 0];
    append_socks_address(&mut request, target_host).map_err(ProxyTransportError::Proxy)?;
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Write, &error))?;
    Transport::flush(stream)
        .map_err(|error| proxy_transport_io(ProxyProtocol::Socks5, ProxyOperation::Write, error))?;

    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Read, &error))?;
    if header[0] != 5 || header[2] != 0 {
        return Err(ProxyError::MalformedResponse { protocol: ProxyProtocol::Socks5 }.into());
    }
    read_socks_address(stream, header[3])?;
    let mut port = [0; 2];
    stream
        .read_exact(&mut port)
        .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Read, &error))?;
    if header[1] != 0 {
        return Err(ProxyError::Rejected {
            protocol: ProxyProtocol::Socks5,
            code: u16::from(header[1]),
        }
        .into());
    }
    Ok(())
}

fn append_socks_address(request: &mut Vec<u8>, host: &str) -> Result<(), ProxyError> {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > u8::MAX as usize || host.as_bytes().contains(&0) {
                return Err(ProxyError::InvalidTargetHost);
            }
            request.push(3);
            request.push(u8::try_from(host.len()).expect("SOCKS domain length is bounded"));
            request.extend_from_slice(host.as_bytes());
        }
    }
    Ok(())
}

fn read_socks_address(
    stream: &mut TcpTransport,
    address_type: u8,
) -> Result<(), ProxyTransportError> {
    let length = match address_type {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0; 1];
            stream
                .read_exact(&mut length)
                .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Read, &error))?;
            if length[0] == 0 {
                return Err(
                    ProxyError::MalformedResponse { protocol: ProxyProtocol::Socks5 }.into()
                );
            }
            usize::from(length[0])
        }
        _ => return Err(ProxyError::MalformedResponse { protocol: ProxyProtocol::Socks5 }.into()),
    };
    let mut address = [0; 255];
    stream
        .read_exact(&mut address[..length])
        .map_err(|error| proxy_io(ProxyProtocol::Socks5, ProxyOperation::Read, &error))?;
    Ok(())
}

fn http_connect_handshake(
    stream: &mut TcpTransport,
    target_host: &str,
    target_port: u16,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), ProxyTransportError> {
    let authority = if target_host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
        format!("[{target_host}]:{target_port}")
    } else {
        format!("{target_host}:{target_port}")
    };
    let mut request =
        Zeroizing::new(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"));
    if let Some(credentials) = credentials {
        let mut raw = Zeroizing::new(Vec::with_capacity(
            credentials.username().len() + 1 + credentials.password().len(),
        ));
        raw.extend_from_slice(credentials.username());
        raw.push(b':');
        raw.extend_from_slice(credentials.password());
        request.push_str("Proxy-Authorization: Basic ");
        append_base64_bytes(&mut request, &raw);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| proxy_io(ProxyProtocol::HttpConnect, ProxyOperation::Write, &error))?;
    Transport::flush(stream).map_err(|error| {
        proxy_transport_io(ProxyProtocol::HttpConnect, ProxyOperation::Write, error)
    })?;

    let mut response = Vec::with_capacity(128);
    let mut byte = [0; 1];
    while response.len() < MAX_HTTP_CONNECT_RESPONSE {
        stream
            .read_exact(&mut byte)
            .map_err(|error| proxy_io(ProxyProtocol::HttpConnect, ProxyOperation::Read, &error))?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(ProxyError::ResponseTooLarge {
            protocol: ProxyProtocol::HttpConnect,
            max: MAX_HTTP_CONNECT_RESPONSE,
        }
        .into());
    }
    let first_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or(ProxyError::MalformedResponse { protocol: ProxyProtocol::HttpConnect })?;
    let first_line = first_line
        .strip_suffix(b"\r")
        .ok_or(ProxyError::MalformedResponse { protocol: ProxyProtocol::HttpConnect })?;
    let mut fields = first_line.splitn(3, |byte| *byte == b' ');
    let version = fields.next();
    let status = fields.next();
    if version != Some(b"HTTP/1.1") && version != Some(b"HTTP/1.0") {
        return Err(ProxyError::MalformedResponse { protocol: ProxyProtocol::HttpConnect }.into());
    }
    let code = status
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(ProxyError::MalformedResponse { protocol: ProxyProtocol::HttpConnect })?;
    if !(200..300).contains(&code) {
        return Err(ProxyError::Rejected { protocol: ProxyProtocol::HttpConnect, code }.into());
    }
    Ok(())
}

fn append_base64_bytes(output: &mut String, bytes: &[u8]) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        output.push(ALPHABET[(first >> 2) as usize] as char);
        let second = if chunk.len() > 1 { chunk[1] } else { 0 };
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (chunk[2] >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(chunk[2] & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    fn proxy_listener(
        response: Vec<u8>,
        expected_prefix: &'static [u8],
    ) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy");
            stream.set_read_timeout(Some(Duration::from_secs(2))).expect("read timeout");
            let mut request = vec![0; expected_prefix.len()];
            stream.read_exact(&mut request).expect("read request prefix");
            assert_eq!(&request, expected_prefix);
            if !response.is_empty() {
                stream.write_all(&response).expect("write response");
                thread::sleep(Duration::from_millis(100));
            }
        });
        (port, handle)
    }

    #[test]
    fn socks5_connects_domain_and_round_trips_payload() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy");
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).expect("method");
            let mut header = [0; 4];
            stream.read_exact(&mut header).expect("request header");
            assert_eq!(header, [5, 1, 0, 3]);
            let mut length = [0; 1];
            stream.read_exact(&mut length).expect("domain length");
            let mut domain = vec![0; usize::from(length[0])];
            stream.read_exact(&mut domain).expect("domain");
            assert_eq!(domain, b"example.test");
            let mut target_port = [0; 2];
            stream.read_exact(&mut target_port).expect("target port");
            assert_eq!(target_port, 22u16.to_be_bytes());
            stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 22]).expect("success");
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("response");
        });
        let mut transport =
            Socks5Transport::connect("127.0.0.1", port, "example.test", 22, Duration::from_secs(2))
                .expect("connect through SOCKS5");
        transport.write_all(b"ping").expect("write payload");
        let mut response = [0; 4];
        transport.read_exact(&mut response).expect("read payload");
        assert_eq!(&response, b"pong");
        server.join().expect("proxy thread");
    }

    #[test]
    fn socks5_username_password_authentication_round_trips_and_rejects() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy");
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).expect("method");
            let mut auth_header = [0; 2];
            stream.read_exact(&mut auth_header).expect("auth header");
            assert_eq!(auth_header, [1, 4]);
            let mut username = [0; 4];
            stream.read_exact(&mut username).expect("username");
            assert_eq!(&username, b"user");
            let mut password_len = [0; 1];
            stream.read_exact(&mut password_len).expect("password length");
            assert_eq!(password_len, [4]);
            let mut password = [0; 4];
            stream.read_exact(&mut password).expect("password");
            assert_eq!(&password, b"pass");
            stream.write_all(&[1, 0]).expect("auth success");
            let mut request = [0; 4];
            stream.read_exact(&mut request).expect("connect request");
            assert_eq!(request, [5, 1, 0, 1]);
            let mut address = [0; 4];
            stream.read_exact(&mut address).expect("address");
            assert_eq!(address, [127, 0, 0, 1]);
            let mut target_port = [0; 2];
            stream.read_exact(&mut target_port).expect("target port");
            assert_eq!(target_port, 22u16.to_be_bytes());
            stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 22]).expect("success");
        });
        let credentials = ProxyCredentials::new(b"user", b"pass").expect("credentials");
        let transport = Socks5Transport::connect_with_credentials(
            "127.0.0.1",
            port,
            "127.0.0.1",
            22,
            Some(&credentials),
            Duration::from_secs(2),
        )
        .expect("authenticated SOCKS5");
        drop(transport);
        server.join().expect("proxy thread");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind failure proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy");
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            stream.write_all(&[5, 2]).expect("method");
            let mut request = [0; 11];
            stream.read_exact(&mut request).expect("auth request");
            stream.write_all(&[1, 1]).expect("auth failure");
        });
        let error = Socks5Transport::connect_with_credentials(
            "127.0.0.1",
            port,
            "127.0.0.1",
            22,
            Some(&credentials),
            Duration::from_secs(2),
        )
        .expect_err("rejected credentials");
        assert!(matches!(
            error,
            ProxyTransportError::Proxy(ProxyError::AuthenticationRejected {
                protocol: ProxyProtocol::Socks5,
                code: 1
            })
        ));
        server.join().expect("proxy thread");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind downgrade proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy");
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 0]).expect("downgrade method");
        });
        let error = Socks5Transport::connect_with_credentials(
            "127.0.0.1",
            port,
            "127.0.0.1",
            22,
            Some(&credentials),
            Duration::from_secs(2),
        )
        .expect_err("credentials must not downgrade to no authentication");
        assert!(matches!(
            error,
            ProxyTransportError::Proxy(ProxyError::Rejected {
                protocol: ProxyProtocol::Socks5,
                code: 0
            })
        ));
        server.join().expect("proxy thread");
    }

    #[test]
    fn http_connect_accepts_success_and_rejects_status() {
        let (port, success) = proxy_listener(
            b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
            b"CONNECT example.test:22 HTTP/1.1\r\n",
        );
        let transport = HttpConnectTransport::connect(
            "127.0.0.1",
            port,
            "example.test",
            22,
            Duration::from_secs(2),
        )
        .expect("HTTP CONNECT");
        assert!(transport.as_stream().peer_addr().is_ok());
        assert_eq!(transport.as_stream().read_timeout().expect("read timeout"), None);
        assert_eq!(transport.as_stream().write_timeout().expect("write timeout"), None);
        success.join().expect("proxy thread");

        let (port, rejected) = proxy_listener(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
            b"CONNECT example.test:22 HTTP/1.1\r\n",
        );
        let error = HttpConnectTransport::connect(
            "127.0.0.1",
            port,
            "example.test",
            22,
            Duration::from_secs(2),
        )
        .expect_err("rejected HTTP CONNECT");
        assert!(matches!(
            error,
            ProxyTransportError::Proxy(ProxyError::Rejected {
                protocol: ProxyProtocol::HttpConnect,
                code: 407
            })
        ));
        rejected.join().expect("proxy thread");
    }

    #[test]
    fn http_connect_basic_authentication_is_bounded_and_redacted() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy");
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).expect("read request");
                request.push(byte[0]);
                assert!(request.len() < MAX_HTTP_CONNECT_RESPONSE);
            }
            let request = String::from_utf8(request).expect("request text");
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .expect("write response");
        });
        let credentials = ProxyCredentials::new("user", "pass").expect("credentials");
        assert!(!format!("{credentials:?}").contains("cGFzcw=="));
        let transport = HttpConnectTransport::connect_with_credentials(
            "127.0.0.1",
            port,
            "example.test",
            22,
            Some(&credentials),
            Duration::from_secs(2),
        )
        .expect("authenticated HTTP CONNECT");
        drop(transport);
        server.join().expect("proxy thread");

        assert!(matches!(
            ProxyCredentials::new([], b"pass"),
            Err(ProxyError::InvalidCredential { field: "username" })
        ));
        assert!(matches!(
            ProxyCredentials::new(b"user", [0x7f]),
            Err(ProxyError::InvalidCredential { field: "password" })
        ));
        assert!(matches!(
            ProxyCredentials::new(vec![b'x'; MAX_PROXY_CREDENTIAL + 1], b"pass"),
            Err(ProxyError::InvalidCredential { field: "username" })
        ));
    }

    #[test]
    fn proxy_target_and_response_are_bounded() {
        assert!(matches!(
            Socks5Transport::connect("127.0.0.1", 1, "", 22, Duration::from_secs(1)),
            Err(ProxyTransportError::Proxy(ProxyError::InvalidTargetHost))
        ));
        assert!(matches!(
            HttpConnectTransport::connect(
                "127.0.0.1",
                1,
                "example.test\r\nX-Injected: yes",
                22,
                Duration::from_secs(1)
            ),
            Err(ProxyTransportError::Proxy(ProxyError::InvalidTargetHost))
        ));
        let (port, oversized) = proxy_listener(
            vec![b'x'; MAX_HTTP_CONNECT_RESPONSE + 1],
            b"CONNECT example.test:22 HTTP/1.1\r\n",
        );
        let error = HttpConnectTransport::connect(
            "127.0.0.1",
            port,
            "example.test",
            22,
            Duration::from_secs(2),
        )
        .expect_err("oversized response");
        assert!(matches!(
            error,
            ProxyTransportError::Proxy(ProxyError::ResponseTooLarge {
                protocol: ProxyProtocol::HttpConnect,
                ..
            })
        ));
        oversized.join().expect("proxy thread");
    }
}
