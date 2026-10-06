// SPDX-License-Identifier: Apache-2.0
//! Versioned wire contracts for Scoplen's client and server workstreams.

#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Contract identifiers realized by this crate.
pub const CONTRACTS: &[&str] = &["K-3", "K-4", "K-5", "K-6"];

/// Stable error-code strings defined by the initial K-3/K-4/K-5 registry.
pub const ERROR_CODES: &[&str] = &[
    "auth.client_unsupported",
    "auth.device_revoked",
    "policy.denied",
    "sync.client_unsupported",
    "sync.conflict",
    "sync.cursor_expired",
    "sync.read_only",
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
    /// Returns [`ApiContractError::InvalidProblem`] when required fields are empty, the type is
    /// not a URI-like value, or the status is not an HTTP status.
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
    }

    #[test]
    fn unknown_codes_are_preserved_and_invalid_syntax_is_rejected() {
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
}
