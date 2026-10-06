// SPDX-License-Identifier: Apache-2.0
//! Strict deterministic CBOR used by the Scoplen object envelope.

#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::doc_markdown,
    clippy::missing_errors_doc
)]

use std::fmt;

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

const MAX_DEPTH: usize = 128;
const U8_MAX_U64: u64 = u8::MAX as u64;
const U16_MAX_U64: u64 = u16::MAX as u64;
const U32_MAX_U64: u64 = u32::MAX as u64;

/// The CBOR values representable by the object model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// CBOR null.
    Null,
    /// CBOR boolean.
    Bool(bool),
    /// A non-negative integer.
    UInt(u64),
    /// A negative integer in the CBOR major type 1 range.
    Int(i64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A normalized UTF-8 text string.
    Text(String),
    /// A definite-length array.
    Array(Vec<Self>),
    /// A definite-length map. Map order is canonicalized by [`encode`].
    Map(Vec<(Self, Self)>),
}

/// Errors returned by the deterministic CBOR codec.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Error {
    /// The input ended before a complete item was read.
    #[error("unexpected end of CBOR input")]
    UnexpectedEof,
    /// The initial byte or additional information is not permitted.
    #[error("invalid CBOR initial byte or additional information")]
    InvalidInitialByte,
    /// A value used a non-shortest integer or length encoding.
    #[error("non-canonical CBOR integer or length encoding")]
    NonCanonical,
    /// Floating point, tags, indefinite lengths, and unsupported simple values are forbidden.
    #[error("unsupported CBOR value")]
    UnsupportedValue,
    /// A map was not sorted by the encoded key bytes or contained a duplicate key.
    #[error("CBOR map keys are not in strict canonical order")]
    NonCanonicalMap,
    /// A text string was not valid UTF-8.
    #[error("CBOR text string is not valid UTF-8")]
    InvalidUtf8,
    /// A text string was not in Unicode NFC form.
    #[error("CBOR text string is not Unicode NFC")]
    NonNormalizedText,
    /// The decoder did not consume all input bytes.
    #[error("trailing bytes after CBOR value")]
    TrailingBytes,
    /// Nested arrays or maps exceeded the decoder depth limit.
    #[error("CBOR nesting exceeds the depth limit")]
    DepthLimit,
    /// A map contained too many entries for the configured model limit.
    #[error("CBOR map contains too many entries")]
    MapLimit,
}

/// Encode one value using definite lengths, shortest forms, NFC text, and canonical map order.
pub fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    encode_inner(value, 0)
}

fn encode_inner(value: &Value, depth: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    encode_value(value, depth, &mut output)?;
    Ok(output)
}

/// Decode exactly one deterministic CBOR value.
pub fn decode(input: &[u8]) -> Result<Value, Error> {
    let mut decoder = Decoder { input, position: 0 };
    let value = decoder.value(0)?;
    if decoder.position != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

fn encode_value(value: &Value, depth: usize, output: &mut Vec<u8>) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::DepthLimit);
    }
    match value {
        Value::Null => output.push(0xf6),
        Value::Bool(false) => output.push(0xf4),
        Value::Bool(true) => output.push(0xf5),
        Value::UInt(value) => write_argument(0, *value, output),
        Value::Int(value) => {
            let argument = if *value >= 0 {
                u64::try_from(*value).expect("non-negative i64 fits in u64")
            } else {
                u64::try_from(!*value)
                    .expect("bitwise complement of a negative i64 is non-negative")
            };
            write_argument(u8::from(*value < 0), argument, output);
        }
        Value::Bytes(value) => {
            write_argument(2, value.len() as u64, output);
            output.extend_from_slice(value);
        }
        Value::Text(value) => {
            if !is_nfc(value) {
                return Err(Error::NonNormalizedText);
            }
            write_argument(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        Value::Array(values) => {
            write_argument(4, values.len() as u64, output);
            for value in values {
                encode_value(value, depth + 1, output)?;
            }
        }
        Value::Map(entries) => {
            if entries.len() > 4096 {
                return Err(Error::MapLimit);
            }
            let mut encoded = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let key_bytes = encode_inner(key, depth + 1)?;
                let value_bytes = encode_inner(value, depth + 1)?;
                encoded.push((key_bytes, value_bytes));
            }
            encoded.sort_by(|left, right| left.0.cmp(&right.0));
            for pair in encoded.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(Error::NonCanonicalMap);
                }
            }
            write_argument(5, encoded.len() as u64, output);
            for (key, value) in encoded {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
        }
    }
    Ok(())
}

fn write_argument(major: u8, value: u64, output: &mut Vec<u8>) {
    let initial = major << 5;
    match value {
        0..=23 => output.push(initial | u8::try_from(value).expect("value is at most 23")),
        24..=U8_MAX_U64 => {
            output.push(initial | 24);
            output.push(u8::try_from(value).expect("value is at most u8::MAX"));
        }
        256..=U16_MAX_U64 => {
            output.push(initial | 25);
            output.extend_from_slice(
                &u16::try_from(value).expect("value is at most u16::MAX").to_be_bytes(),
            );
        }
        65_536..=U32_MAX_U64 => {
            output.push(initial | 26);
            output.extend_from_slice(
                &u32::try_from(value).expect("value is at most u32::MAX").to_be_bytes(),
            );
        }
        _ => {
            output.push(initial | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

pub(crate) fn is_nfc(value: &str) -> bool {
    value.nfc().eq(value.chars())
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::DepthLimit);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(Value::UInt(self.argument(additional)?)),
            1 => {
                let argument = self.argument(additional)?;
                if argument > i64::MAX as u64 {
                    return Err(Error::UnsupportedValue);
                }
                Ok(Value::Int(-1 - i64::try_from(argument).expect("argument is at most i64::MAX")))
            }
            2 => Ok(Value::Bytes(self.bytes(additional)?.to_vec())),
            3 => {
                let bytes = self.bytes(additional)?;
                let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                if !is_nfc(text) {
                    return Err(Error::NonNormalizedText);
                }
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                let length = usize::try_from(self.argument(additional)?)
                    .map_err(|_| Error::UnexpectedEof)?;
                if length > self.input.len().saturating_sub(self.position) {
                    return Err(Error::UnexpectedEof);
                }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            5 => {
                let length = usize::try_from(self.argument(additional)?)
                    .map_err(|_| Error::UnexpectedEof)?;
                if length > 4096 {
                    return Err(Error::MapLimit);
                }
                if length > self.input.len().saturating_sub(self.position) / 2 {
                    return Err(Error::UnexpectedEof);
                }
                let mut entries = Vec::with_capacity(length);
                let mut previous_key = None;
                for _ in 0..length {
                    let start = self.position;
                    let key = self.value(depth + 1)?;
                    let key_bytes = &self.input[start..self.position];
                    if let Some(previous) = previous_key {
                        if previous >= key_bytes {
                            return Err(Error::NonCanonicalMap);
                        }
                    }
                    previous_key = Some(key_bytes);
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            6 => Err(Error::UnsupportedValue),
            7 => match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::UnsupportedValue),
            },
            _ => Err(Error::InvalidInitialByte),
        }
    }

    fn argument(&mut self, additional: u8) -> Result<u64, Error> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 { Err(Error::NonCanonical) } else { Ok(value) }
            }
            25 => {
                let value = u64::from(u16::from_be_bytes([self.byte()?, self.byte()?]));
                if u8::try_from(value).is_ok() { Err(Error::NonCanonical) } else { Ok(value) }
            }
            26 => {
                let value = u64::from(u32::from_be_bytes([
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                ]));
                if u16::try_from(value).is_ok() { Err(Error::NonCanonical) } else { Ok(value) }
            }
            27 => {
                let value = u64::from_be_bytes([
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                ]);
                if u32::try_from(value).is_ok() { Err(Error::NonCanonical) } else { Ok(value) }
            }
            _ => Err(Error::UnsupportedValue),
        }
    }

    fn bytes(&mut self, additional: u8) -> Result<&'a [u8], Error> {
        let length =
            usize::try_from(self.argument(additional)?).map_err(|_| Error::UnexpectedEof)?;
        let end = self.position.checked_add(length).ok_or(Error::UnexpectedEof)?;
        if end > self.input.len() {
            return Err(Error::UnexpectedEof);
        }
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self.input.get(self.position).ok_or(Error::UnexpectedEof)?;
        self.position += 1;
        Ok(byte)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("null"),
            Self::Bool(value) => value.fmt(formatter),
            Self::UInt(value) => value.fmt(formatter),
            Self::Int(value) => value.fmt(formatter),
            Self::Bytes(value) => write!(formatter, "0x{} bytes", value.len()),
            Self::Text(value) => value.fmt(formatter),
            Self::Array(value) => write!(formatter, "array({})", value.len()),
            Self::Map(value) => write!(formatter, "map({})", value.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_shortest_integer_and_map_forms() {
        let value =
            Value::Map(vec![(Value::UInt(10), Value::UInt(24)), (Value::UInt(1), Value::UInt(1))]);
        assert_eq!(
            encode(&value).expect("canonical encoding"),
            [0xa2, 0x01, 0x01, 0x0a, 0x18, 0x18]
        );
    }

    #[test]
    fn rejects_non_canonical_lengths_and_floats() {
        assert_eq!(decode(&[0x18, 0x01]), Err(Error::NonCanonical));
        assert_eq!(decode(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::UnsupportedValue));
        assert_eq!(decode(&[0x9f, 0x01, 0xff]), Err(Error::UnsupportedValue));
        assert_eq!(decode(&[0xc1, 0x00]), Err(Error::UnsupportedValue));
        assert_eq!(decode(&[0xa2, 0x02, 0x00, 0x01, 0x00]), Err(Error::NonCanonicalMap));
        assert_eq!(decode(&[0xa2, 0x01, 0x00, 0x01, 0x01]), Err(Error::NonCanonicalMap));
    }

    #[test]
    fn round_trips_deterministic_value_families() {
        let values = [
            Value::Null,
            Value::Bool(true),
            Value::UInt(u64::MAX),
            Value::Int(i64::MIN),
            Value::Bytes(vec![0, 1, 2]),
            Value::Text("café".into()),
            Value::Array(vec![Value::UInt(1), Value::Text("nested".into())]),
            Value::Map(vec![(Value::UInt(10), Value::UInt(24)), (Value::UInt(1), Value::Null)]),
        ];
        for value in values {
            let encoded = encode(&value).expect("encode");
            let decoded = decode(&encoded).expect("decode");
            assert_eq!(encode(&decoded).expect("re-encode"), encoded);
        }
    }

    #[test]
    fn rejects_non_nfc_text() {
        assert_eq!(decode(&[0x63, 0x65, 0xcc, 0x81]), Err(Error::NonNormalizedText));
    }

    #[test]
    fn matches_published_known_answer_vectors() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/baseline.json");
        let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
        for vector in document.vectors.iter().filter(|vector| vector.kind == "model.cbor") {
            let input = decode_hex(&vector.input);
            let expected = decode_hex(&vector.expected);
            assert_eq!(
                encode(&decode(&input).expect("canonical vector")).expect("encode"),
                expected
            );
        }
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0, "hex vector has an odd length");
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }
}
