// SPDX-License-Identifier: Apache-2.0
//! Versioned wire contracts for Scoplen's client and server workstreams.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, fmt};

use scoplen_model::cbor::{self, Value};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

pub mod auth;
pub mod sync;

/// Contract identifiers realized by this crate.
pub const CONTRACTS: &[&str] = &["K-3", "K-4", "K-5", "K-6"];

/// Stable error-code strings defined by the initial K-3/K-4/K-5 registry.
pub const ERROR_CODES: &[&str] = &[
    "auth.authentication_required",
    "auth.client_unsupported",
    "auth.device_revoked",
    "policy.denied",
    "sync.client_unsupported",
    "sync.conflict",
    "sync.cursor_ahead",
    "sync.cursor_expired",
    "sync.invalid_request",
    "sync.object_not_found",
    "sync.read_only",
    "sync.storage_unavailable",
];

/// Errors returned while constructing or validating API contract values.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ApiContractError {
    /// The value is not a lowercase dotted error-code string.
    #[error("invalid error code {0:?}")]
    InvalidErrorCode(String),
    /// A problem-details field violates the contract.
    #[error("invalid problem details: {0}")]
    InvalidProblem(String),
    /// A CBOR body was not deterministic or could not be encoded.
    #[error("invalid deterministic CBOR: {0}")]
    Cbor(#[from] cbor::Error),
}

/// A stable machine-readable error code.
///
/// Unknown but syntactically valid values are retained so additive server codes do not break old
/// clients.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ErrorCode(String);

impl ErrorCode {
    /// Construct an error code after validating its namespace and name syntax.
    ///
    /// # Errors
    ///
    /// Returns [`ApiContractError::InvalidErrorCode`] when the value is not a lowercase dotted
    /// code with a non-empty namespace and name.
    pub fn new(value: impl Into<String>) -> Result<Self, ApiContractError> {
        let value = value.into();
        let mut parts = value.split('.');
        let Some(namespace) = parts.next() else {
            return Err(ApiContractError::InvalidErrorCode(value));
        };
        let Some(name) = parts.next() else {
            return Err(ApiContractError::InvalidErrorCode(value));
        };
        if parts.next().is_some() || !valid_code_part(namespace) || !valid_code_part(name) {
            return Err(ApiContractError::InvalidErrorCode(value));
        }
        Ok(Self(value))
    }

    /// Return the wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this code is in the initial registry.
    #[must_use]
    pub fn is_known(&self) -> bool {
        ERROR_CODES.contains(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn valid_code_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// RFC 9457 problem details shared by JSON and CBOR endpoints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "RawProblemDetails")]
pub struct ProblemDetails {
    /// URI identifying the problem type; `about:blank` is the default.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Human-readable summary for logs and diagnostics.
    pub title: String,
    /// HTTP status associated with the problem.
    pub status: u16,
    /// Human-readable detail; clients must not parse it.
    pub detail: String,
    /// Request identifier that can be traced by the operator.
    pub instance: String,
    /// Stable machine-readable error code.
    pub code: ErrorCode,
    /// Whether the request changed any server or local state.
    pub changed: bool,
    /// Whether retrying the same request may succeed.
    pub retryable: bool,
}

#[derive(Deserialize)]
struct RawProblemDetails {
    #[serde(rename = "type")]
    problem_type: String,
    title: String,
    status: u16,
    detail: String,
    instance: String,
    code: ErrorCode,
    changed: bool,
    retryable: bool,
}

impl TryFrom<RawProblemDetails> for ProblemDetails {
    type Error = ApiContractError;

    fn try_from(raw: RawProblemDetails) -> Result<Self, Self::Error> {
        let problem = Self {
            problem_type: raw.problem_type,
            title: raw.title,
            status: raw.status,
            detail: raw.detail,
            instance: raw.instance,
            code: raw.code,
            changed: raw.changed,
            retryable: raw.retryable,
        };
        problem.validate()?;
        Ok(problem)
    }
}

impl ProblemDetails {
    /// Construct a problem with the default `about:blank` type.
    ///
    /// # Errors
    ///
    /// Returns [`ApiContractError::InvalidProblem`] when the status is outside the HTTP range or
    /// a required text field is empty.
    pub fn new(
        code: ErrorCode,
        status: u16,
        title: impl Into<String>,
        detail: impl Into<String>,
        instance: impl Into<String>,
        changed: bool,
        retryable: bool,
    ) -> Result<Self, ApiContractError> {
        let problem = Self {
            problem_type: "about:blank".into(),
            title: title.into(),
            status,
            detail: detail.into(),
            instance: instance.into(),
            code,
            changed,
            retryable,
        };
        problem.validate()?;
        Ok(problem)
    }

    /// Validate a problem after construction or deserialization.
    ///
    /// # Errors
    ///
    /// Returns [`ApiContractError::InvalidProblem`] when required fields are empty or the status
    /// is not an HTTP status.
    pub fn validate(&self) -> Result<(), ApiContractError> {
        if !(100..=599).contains(&self.status) {
            return Err(ApiContractError::InvalidProblem(format!(
                "status must be between 100 and 599, got {}",
                self.status
            )));
        }
        if self.problem_type.trim().is_empty()
            || self.title.trim().is_empty()
            || self.detail.trim().is_empty()
            || self.instance.trim().is_empty()
        {
            return Err(ApiContractError::InvalidProblem(
                "type, title, detail, and instance must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// Encode the same eight fields as a deterministic CBOR map with text keys.
    ///
    /// # Errors
    ///
    /// Returns an error if a required field is invalid or text is not NFC.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ApiContractError> {
        self.validate()?;
        let entries = vec![
            ("type", Value::Text(self.problem_type.clone())),
            ("title", Value::Text(self.title.clone())),
            ("status", Value::UInt(u64::from(self.status))),
            ("detail", Value::Text(self.detail.clone())),
            ("instance", Value::Text(self.instance.clone())),
            ("code", Value::Text(self.code.as_str().to_owned())),
            ("changed", Value::Bool(self.changed)),
            ("retryable", Value::Bool(self.retryable)),
        ];
        cbor::encode(&Value::Map(
            entries.into_iter().map(|(key, value)| (Value::Text(key.into()), value)).collect(),
        ))
        .map_err(Into::into)
    }

    /// Decode a deterministic CBOR problem, requiring every standard field and its wire type.
    ///
    /// Unknown extension fields are ignored. Known fields with invalid types are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CBOR, missing fields, incorrect types, or invalid values.
    pub fn from_cbor(input: &[u8]) -> Result<Self, ApiContractError> {
        let Value::Map(entries) = cbor::decode(input)? else {
            return Err(invalid_problem("top-level value must be a map"));
        };
        let mut fields = BTreeMap::new();
        for (key, value) in entries {
            let Value::Text(key) = key else {
                return Err(invalid_problem("map keys must be text"));
            };
            fields.insert(key, value);
        }
        let problem = Self {
            problem_type: required_text(&mut fields, "type")?,
            title: required_text(&mut fields, "title")?,
            status: required_status(&mut fields)?,
            detail: required_text(&mut fields, "detail")?,
            instance: required_text(&mut fields, "instance")?,
            code: ErrorCode::new(required_text(&mut fields, "code")?)?,
            changed: required_bool(&mut fields, "changed")?,
            retryable: required_bool(&mut fields, "retryable")?,
        };
        problem.validate()?;
        Ok(problem)
    }
}

fn invalid_problem(message: impl Into<String>) -> ApiContractError {
    ApiContractError::InvalidProblem(message.into())
}

fn required_text(
    fields: &mut BTreeMap<String, Value>,
    key: &str,
) -> Result<String, ApiContractError> {
    match fields.remove(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(invalid_problem(format!("{key} must be a text string"))),
    }
}

fn required_bool(
    fields: &mut BTreeMap<String, Value>,
    key: &str,
) -> Result<bool, ApiContractError> {
    match fields.remove(key) {
        Some(Value::Bool(value)) => Ok(value),
        _ => Err(invalid_problem(format!("{key} must be a boolean"))),
    }
}

fn required_status(fields: &mut BTreeMap<String, Value>) -> Result<u16, ApiContractError> {
    match fields.remove("status") {
        Some(Value::UInt(value)) => {
            u16::try_from(value).map_err(|_| invalid_problem("status is out of range"))
        }
        _ => Err(invalid_problem("status must be an unsigned integer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_details_round_trip_as_json_and_validate_required_fields() {
        let code = ErrorCode::new("sync.conflict").expect("registry code");
        let problem = ProblemDetails::new(
            code,
            409,
            "Conflict",
            "The object changed; merge it and retry.",
            "req-123",
            false,
            true,
        )
        .expect("problem");
        let json = serde_json::to_string(&problem).expect("serialize");
        let decoded: ProblemDetails = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, problem);
        decoded.validate().expect("valid problem");
        assert!(
            serde_json::from_str::<ProblemDetails>(
                &json.replace("\"status\":409", "\"status\":600")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ProblemDetails>(
                &json.replace("\"title\":\"Conflict\"", "\"title\":\" \"")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ProblemDetails>(&json.replace(",\"changed\":false", ""))
                .is_err()
        );
    }

    #[test]
    fn unknown_codes_are_preserved_and_invalid_syntax_is_rejected() {
        assert!(
            ErrorCode::new("auth.authentication_required").expect("registered code").is_known()
        );
        assert!(ErrorCode::new("sync.cursor_ahead").expect("registered code").is_known());
        assert!(ErrorCode::new("sync.invalid_request").expect("registered code").is_known());
        assert!(ErrorCode::new("sync.object_not_found").expect("registered code").is_known());
        assert!(ErrorCode::new("sync.storage_unavailable").expect("registered code").is_known());
        let code = ErrorCode::new("future.new_code").expect("syntactically valid unknown code");
        assert!(!code.is_known());
        let json = serde_json::to_string(&code).expect("serialize");
        assert_eq!(json, "\"future.new_code\"");
        assert!(ErrorCode::new("SYNC.BAD").is_err());
        assert!(ErrorCode::new("missing-separator").is_err());
        assert!(ErrorCode::new("a.b.c").is_err());
    }

    #[test]
    fn invalid_problem_status_is_rejected() {
        let code = ErrorCode::new("policy.denied").expect("registry code");
        assert!(ProblemDetails::new(code, 600, "Denied", "No", "req", false, false).is_err());
    }

    #[test]
    fn problem_cbor_matches_published_vector() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-problem.json");
        let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
        assert!(!document.vectors.is_empty(), "problem vector document must not be empty");
        for vector in document.vectors.iter().filter(|vector| vector.kind == "api.problem.cbor") {
            let problem: ProblemDetails = serde_json::from_str(&vector.input).expect("JSON input");
            let expected = decode_hex(&vector.expected);
            assert_eq!(problem.to_cbor().expect("encode"), expected, "{}", vector.id);
            assert_eq!(ProblemDetails::from_cbor(&expected).expect("decode"), problem);
        }
    }

    #[test]
    fn problem_cbor_rejects_invalid_fields_and_accepts_extensions() {
        let problem = ProblemDetails::new(
            ErrorCode::new("sync.conflict").expect("code"),
            409,
            "Conflict",
            "Retry.",
            "r1",
            false,
            true,
        )
        .expect("problem");
        let encoded = problem.to_cbor().expect("encode");
        let Value::Map(mut fields) = cbor::decode(&encoded).expect("decode value") else {
            panic!("problem is a map");
        };
        fields.push((Value::Text("extra".into()), Value::UInt(7)));
        let with_extension = cbor::encode(&Value::Map(fields.clone())).expect("encode extension");
        assert_eq!(ProblemDetails::from_cbor(&with_extension).expect("extension"), problem);

        for key in ["type", "title", "status", "detail", "instance", "code", "changed", "retryable"]
        {
            let mut missing = fields.clone();
            missing.retain(|(field, _)| field != &Value::Text(key.into()));
            let bytes = cbor::encode(&Value::Map(missing)).expect("encode missing field");
            assert!(ProblemDetails::from_cbor(&bytes).is_err(), "missing {key}");
        }
        let mut wrong_type = fields;
        for (key, value) in &mut wrong_type {
            if key == &Value::Text("changed".into()) {
                *value = Value::UInt(0);
            }
        }
        let bytes = cbor::encode(&Value::Map(wrong_type)).expect("encode wrong type");
        assert!(ProblemDetails::from_cbor(&bytes).is_err());
        assert!(ProblemDetails::from_cbor(&[0xbf, 0xff]).is_err());
        assert!(ProblemDetails::from_cbor(&[0xf6]).is_err());
    }

    fn decode_hex(input: &str) -> Vec<u8> {
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
