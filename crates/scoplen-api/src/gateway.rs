// SPDX-License-Identifier: Apache-2.0
//! K-6 gateway client-hello framing.

use std::fmt;

use scoplen_model::cbor::{self, Value};
use thiserror::Error;

/// Maximum encoded CBOR body accepted in a gateway client-hello frame.
pub const MAX_GATEWAY_FRAME_BYTES: usize = 16 * 1024;
/// Maximum compact JWS ticket accepted in a gateway client hello.
pub const MAX_GATEWAY_TICKET_BYTES: usize = 4 * 1024;
/// Maximum compact JWS `DPoP` proof accepted in a gateway client hello.
pub const MAX_GATEWAY_DPOP_PROOF_BYTES: usize = 8 * 1024;
const GATEWAY_FRAME_PREFIX_BYTES: usize = 4;

/// Errors returned while encoding or decoding a gateway client hello.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayCodecError {
    /// The input ended before the complete length prefix or body was available.
    #[error("gateway client-hello frame is truncated")]
    Truncated,
    /// The encoded body exceeds the configured frame limit.
    #[error("gateway client-hello frame exceeds {MAX_GATEWAY_FRAME_BYTES} bytes")]
    FrameTooLarge,
    /// The frame length prefix is zero.
    #[error("gateway client-hello frame length must be non-zero")]
    EmptyFrame,
    /// The input contains bytes outside the length-prefixed body.
    #[error("gateway client-hello frame has trailing bytes")]
    TrailingFrameBytes,
    /// The top-level CBOR value is not the required map.
    #[error("gateway client hello must be a CBOR map")]
    NotAMap,
    /// A required or allowed field has an invalid value.
    #[error("invalid gateway client hello: {0}")]
    Invalid(String),
    /// The deterministic CBOR codec rejected the body.
    #[error("invalid gateway client-hello CBOR: {0}")]
    Cbor(#[from] cbor::Error),
}

/// The one client-hello message sent after negotiating ALPN `spl-gw/1`.
///
/// The values are compact JWS strings. Signature, expiry, single-use, and `DPoP` verification are
/// owned by the edge; this type only enforces the bounded wire shape and compact-JWS alphabet.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayClientHello {
    /// The single-use control-plane gateway ticket.
    pub ticket: String,
    /// The `DPoP` proof bound to the access-token/device key.
    pub dpop_proof: String,
}

impl fmt::Debug for GatewayClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayClientHello")
            .field("ticket_bytes", &self.ticket.len())
            .field("dpop_proof_bytes", &self.dpop_proof.len())
            .finish()
    }
}

impl GatewayClientHello {
    /// Construct and validate a gateway client hello.
    ///
    /// # Errors
    ///
    /// Returns an error when either value is empty, exceeds its bound, or is not a compact JWS.
    pub fn new(
        ticket: impl Into<String>,
        dpop_proof: impl Into<String>,
    ) -> Result<Self, GatewayCodecError> {
        let hello = Self { ticket: ticket.into(), dpop_proof: dpop_proof.into() };
        hello.validate()?;
        Ok(hello)
    }

    /// Validate bounds and the compact-JWS textual shape without verifying signatures.
    ///
    /// # Errors
    ///
    /// Returns an error for non-ASCII, empty, oversized, or malformed compact-JWS strings.
    pub fn validate(&self) -> Result<(), GatewayCodecError> {
        validate_jws(&self.ticket, "ticket", MAX_GATEWAY_TICKET_BYTES)?;
        validate_jws(&self.dpop_proof, "dpop_proof", MAX_GATEWAY_DPOP_PROOF_BYTES)
    }

    /// Encode the hello map as deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error when validation fails or the encoded body exceeds the frame bound.
    pub fn to_cbor(&self) -> Result<Vec<u8>, GatewayCodecError> {
        self.validate()?;
        let body = cbor::encode(&Value::Map(vec![
            (Value::Text("ticket".into()), Value::Text(self.ticket.clone())),
            (Value::Text("dpop_proof".into()), Value::Text(self.dpop_proof.clone())),
        ]))?;
        if body.is_empty() {
            return Err(GatewayCodecError::EmptyFrame);
        }
        if body.len() > MAX_GATEWAY_FRAME_BYTES {
            return Err(GatewayCodecError::FrameTooLarge);
        }
        Ok(body)
    }

    /// Decode one deterministic CBOR hello map.
    ///
    /// Unknown or duplicate fields are rejected. The underlying deterministic decoder also
    /// rejects non-canonical maps, indefinite lengths, invalid UTF-8, and trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unknown, missing, or invalid fields.
    pub fn from_cbor(input: &[u8]) -> Result<Self, GatewayCodecError> {
        if input.is_empty() {
            return Err(GatewayCodecError::EmptyFrame);
        }
        if input.len() > MAX_GATEWAY_FRAME_BYTES {
            return Err(GatewayCodecError::FrameTooLarge);
        }
        let Value::Map(fields) = cbor::decode(input)? else {
            return Err(GatewayCodecError::NotAMap);
        };
        let mut ticket = None;
        let mut dpop_proof = None;
        for (key, value) in fields {
            let Value::Text(key) = key else {
                return Err(GatewayCodecError::Invalid("map keys must be text".into()));
            };
            let Value::Text(value) = value else {
                return Err(GatewayCodecError::Invalid(format!("{key} must be text")));
            };
            match key.as_str() {
                "ticket" => {
                    if ticket.replace(value).is_some() {
                        return Err(GatewayCodecError::Invalid("duplicate ticket field".into()));
                    }
                }
                "dpop_proof" => {
                    if dpop_proof.replace(value).is_some() {
                        return Err(GatewayCodecError::Invalid(
                            "duplicate dpop_proof field".into(),
                        ));
                    }
                }
                _ => return Err(GatewayCodecError::Invalid(format!("unknown field {key:?}"))),
            }
        }
        Self::new(
            ticket.ok_or_else(|| GatewayCodecError::Invalid("missing ticket field".into()))?,
            dpop_proof
                .ok_or_else(|| GatewayCodecError::Invalid("missing dpop_proof field".into()))?,
        )
    }

    /// Encode one length-prefixed client-hello frame.
    ///
    /// The prefix is a four-byte unsigned big-endian body length. The returned value contains no
    /// bytes after the body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body cannot be encoded or its length does not fit the contract.
    pub fn encode_frame(&self) -> Result<Vec<u8>, GatewayCodecError> {
        let body = self.to_cbor()?;
        let length =
            u32::try_from(body.len()).map_err(|_| GatewayCodecError::FrameTooLarge)?.to_be_bytes();
        let mut frame = Vec::with_capacity(GATEWAY_FRAME_PREFIX_BYTES + body.len());
        frame.extend_from_slice(&length);
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Validate a four-byte frame length prefix before allocating or reading the body.
    ///
    /// A stream consumer reads exactly four bytes, calls this function, and then reads exactly
    /// the returned number of body bytes before decoding the CBOR value. This keeps the first
    /// allocation bounded even for unauthenticated peers.
    ///
    /// # Errors
    ///
    /// Returns an error when the declared body length is zero or exceeds 16 KiB.
    pub fn body_length_from_prefix(prefix: [u8; 4]) -> Result<usize, GatewayCodecError> {
        let body_len = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| GatewayCodecError::FrameTooLarge)?;
        if body_len == 0 {
            return Err(GatewayCodecError::EmptyFrame);
        }
        if body_len > MAX_GATEWAY_FRAME_BYTES {
            return Err(GatewayCodecError::FrameTooLarge);
        }
        Ok(body_len)
    }

    /// Decode one complete length-prefixed client-hello frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the prefix/body is truncated, out of bounds, or has trailing bytes.
    pub fn from_frame(input: &[u8]) -> Result<Self, GatewayCodecError> {
        if input.len() < GATEWAY_FRAME_PREFIX_BYTES {
            return Err(GatewayCodecError::Truncated);
        }
        let body_len = Self::body_length_from_prefix([input[0], input[1], input[2], input[3]])?;
        let expected = GATEWAY_FRAME_PREFIX_BYTES
            .checked_add(body_len)
            .ok_or(GatewayCodecError::FrameTooLarge)?;
        if input.len() < expected {
            return Err(GatewayCodecError::Truncated);
        }
        if input.len() > expected {
            return Err(GatewayCodecError::TrailingFrameBytes);
        }
        Self::from_cbor(&input[GATEWAY_FRAME_PREFIX_BYTES..])
    }
}

fn validate_jws(value: &str, field: &str, limit: usize) -> Result<(), GatewayCodecError> {
    if value.is_empty() {
        return Err(GatewayCodecError::Invalid(format!("{field} must not be empty")));
    }
    if value.len() > limit {
        return Err(GatewayCodecError::Invalid(format!("{field} exceeds {limit} bytes")));
    }
    let mut segments = value.split('.');
    let first = segments.next();
    let second = segments.next();
    let third = segments.next();
    if first.is_none_or(str::is_empty)
        || second.is_none_or(str::is_empty)
        || third.is_none_or(str::is_empty)
        || segments.next().is_some()
    {
        return Err(GatewayCodecError::Invalid(format!("{field} must be a compact JWS")));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-')
    {
        return Err(GatewayCodecError::Invalid(format!(
            "{field} contains a non-base64url compact-JWS character"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as JsonValue;

    const TICKET: &str = "a.b.c";
    const PROOF: &str = "d.e.f";

    #[test]
    fn cbor_and_frame_round_trip() {
        let hello = GatewayClientHello::new(TICKET, PROOF).expect("hello");
        let cbor = hello.to_cbor().expect("CBOR");
        assert_eq!(hex(&cbor), "a2667469636b657465612e622e636a64706f705f70726f6f6665642e652e66");
        assert_eq!(GatewayClientHello::from_cbor(&cbor).expect("decode"), hello);
        let frame = hello.encode_frame().expect("frame");
        assert_eq!(&frame[..4], &[0, 0, 0, 31]);
        assert_eq!(GatewayClientHello::from_frame(&frame).expect("frame decode"), hello);
    }

    #[test]
    fn published_gateway_vectors_match_both_boundaries() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/gateway.json");
        let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
        assert_eq!(document.vectors.len(), 2);
        for vector in document.vectors {
            let input: JsonValue = serde_json::from_str(&vector.input).expect("vector input");
            let hello = GatewayClientHello::new(
                input["ticket"].as_str().expect("ticket"),
                input["dpop_proof"].as_str().expect("dpop proof"),
            )
            .expect("hello");
            let expected = decode_hex(&vector.expected);
            let actual = match vector.kind.as_str() {
                "gateway.client_hello.cbor" => hello.to_cbor().expect("CBOR"),
                "gateway.client_hello.frame" => hello.encode_frame().expect("frame"),
                other => panic!("unexpected vector kind {other}"),
            };
            assert_eq!(actual, expected, "{}", vector.id);
            let decoded = if vector.kind == "gateway.client_hello.frame" {
                GatewayClientHello::from_frame(&expected).expect("frame decode")
            } else {
                GatewayClientHello::from_cbor(&expected).expect("CBOR decode")
            };
            assert_eq!(decoded, hello, "{}", vector.id);
        }
    }

    #[test]
    fn malformed_maps_and_frames_fail_closed() {
        let hello = GatewayClientHello::new(TICKET, PROOF).expect("hello");
        let cbor = hello.to_cbor().expect("CBOR");
        assert!(GatewayClientHello::from_cbor(&[]).is_err());
        assert!(GatewayClientHello::from_cbor(&[0x80]).is_err());
        assert!(
            GatewayClientHello::from_cbor(&[
                0xa1, 0x66, b't', b'i', b'c', b'k', b'e', b't', 0x65, b'a', b'.', b'b', b'.', b'c'
            ])
            .is_err()
        );

        let unknown = cbor::encode(&Value::Map(vec![
            (Value::Text("dpop_proof".into()), Value::Text(PROOF.into())),
            (Value::Text("ticket".into()), Value::Text(TICKET.into())),
            (Value::Text("future".into()), Value::Text("x".into())),
        ]))
        .expect("unknown field");
        assert!(matches!(
            GatewayClientHello::from_cbor(&unknown),
            Err(GatewayCodecError::Invalid(message)) if message.contains("unknown field")
        ));

        let wrong_type = cbor::encode(&Value::Map(vec![
            (Value::Text("dpop_proof".into()), Value::Text(PROOF.into())),
            (Value::Text("ticket".into()), Value::UInt(1)),
        ]))
        .expect("wrong field type");
        assert!(GatewayClientHello::from_cbor(&wrong_type).is_err());

        let mut trailing = cbor.clone();
        trailing.push(0);
        assert!(GatewayClientHello::from_cbor(&trailing).is_err());
        assert!(GatewayClientHello::from_frame(&[]).is_err());
        assert!(GatewayClientHello::from_frame(&[0, 0, 0]).is_err());
        assert!(GatewayClientHello::from_frame(&[0, 0, 0, 0]).is_err());
        let mut short = vec![0, 0, 0, 31];
        short.extend_from_slice(&cbor[..cbor.len() - 1]);
        assert!(matches!(
            GatewayClientHello::from_frame(&short),
            Err(GatewayCodecError::Truncated)
        ));
        let mut extra = hello.encode_frame().expect("frame");
        extra.push(0);
        assert!(matches!(
            GatewayClientHello::from_frame(&extra),
            Err(GatewayCodecError::TrailingFrameBytes)
        ));
        assert_eq!(GatewayClientHello::body_length_from_prefix([0, 0, 0, 31]).expect("length"), 31);
        assert!(matches!(
            GatewayClientHello::body_length_from_prefix([0, 0, 0, 0]),
            Err(GatewayCodecError::EmptyFrame)
        ));
        assert!(matches!(
            GatewayClientHello::body_length_from_prefix([0, 1, 0, 0]),
            Err(GatewayCodecError::FrameTooLarge)
        ));
    }

    #[test]
    fn bounds_and_compact_jws_shape_are_enforced() {
        assert!(GatewayClientHello::new("a.b", PROOF).is_err());
        assert!(GatewayClientHello::new("a.b.c.d", PROOF).is_err());
        assert!(GatewayClientHello::new("a=.b.c", PROOF).is_err());
        assert!(GatewayClientHello::new("a.b.c", "d.e.").is_err());
        assert!(GatewayClientHello::new("a.b.c", "é.e.f").is_err());
        let oversized = "a".repeat(MAX_GATEWAY_TICKET_BYTES - 3);
        assert!(GatewayClientHello::new(format!("{oversized}.b.c"), PROOF).is_err());
        let oversized_proof = "a".repeat(MAX_GATEWAY_DPOP_PROOF_BYTES - 3);
        assert!(GatewayClientHello::new(TICKET, format!("{oversized_proof}.e.f")).is_err());
    }

    #[test]
    fn debug_output_redacts_jws_values() {
        let hello =
            GatewayClientHello::new("header.payload.signature", "proof.body.sig").expect("hello");
        let debug = format!("{hello:?}");
        assert!(!debug.contains("header.payload.signature"));
        assert!(!debug.contains("proof.body.sig"));
        assert!(debug.contains("ticket_bytes"));
        assert!(debug.contains("dpop_proof_bytes"));
    }

    fn hex(input: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(input.len() * 2);
        for byte in input {
            write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
        }
        output
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("hex byte")
            })
            .collect()
    }
}
