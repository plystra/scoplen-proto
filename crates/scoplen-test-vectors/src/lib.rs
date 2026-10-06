// SPDX-License-Identifier: Apache-2.0
//! Machine-readable known-answer vectors shared by all Scoplen workstreams.

#![forbid(unsafe_code)]

use std::{collections::HashSet, io::Read, path::Path};

use serde::Deserialize;

/// The current on-disk vector document format.
pub const FORMAT: &str = "scoplen-test-vectors";
/// The current vector document schema version.
pub const VERSION: u32 = 1;

/// A complete vector document.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct VectorDocument {
    /// Identifies this file as a Scoplen vector document.
    pub format: String,
    /// Schema version for the document envelope.
    pub version: u32,
    /// Individual known-answer vectors.
    pub vectors: Vec<Vector>,
}

/// One named vector. Inputs and expected values are intentionally opaque to the loader; each
/// contract-specific consumer interprets them according to its vector kind.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct Vector {
    /// Stable identifier used by both workstreams in failure messages.
    pub id: String,
    /// Contract-specific vector kind, for example `model.cbor` or `crypto.envelope`.
    pub kind: String,
    /// Canonical input encoded as text by the vector producer.
    pub input: String,
    /// Expected output encoded as text by the vector producer.
    pub expected: String,
}

/// Errors returned while reading or validating a vector document.
#[derive(Debug, thiserror::Error)]
pub enum VectorError {
    /// The input was not valid UTF-8 JSON.
    #[error("vector document is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// The input was valid UTF-8 but not a JSON vector document.
    #[error("vector document is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The document did not satisfy the shared envelope rules.
    #[error("invalid vector document: {0}")]
    Invalid(String),
    /// The file could not be read.
    #[error("could not read vector document: {0}")]
    Io(#[from] std::io::Error),
}

impl VectorDocument {
    /// Parse and validate a JSON vector document.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not valid JSON or violates the shared envelope rules.
    pub fn parse_str(input: &str) -> Result<Self, VectorError> {
        let document: Self = serde_json::from_str(input)?;
        document.validate()?;
        Ok(document)
    }

    /// Parse and validate a UTF-8 JSON vector document from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not UTF-8, not valid JSON, or violates the shared
    /// envelope rules.
    pub fn from_bytes(input: &[u8]) -> Result<Self, VectorError> {
        Self::parse_str(std::str::from_utf8(input)?)
    }

    /// Read and validate a vector document from a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or its contents are not a valid vector
    /// document.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, VectorError> {
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    /// Validate the shared envelope and stable-id invariants.
    ///
    /// # Errors
    ///
    /// Returns an error when the format name, version, or vector identifiers are invalid.
    pub fn validate(&self) -> Result<(), VectorError> {
        if self.format != FORMAT {
            return Err(VectorError::Invalid(format!(
                "format must be {FORMAT:?}, got {:?}",
                self.format
            )));
        }
        if self.version != VERSION {
            return Err(VectorError::Invalid(format!(
                "version must be {VERSION}, got {}",
                self.version
            )));
        }
        let mut ids = HashSet::with_capacity(self.vectors.len());
        for vector in &self.vectors {
            if vector.id.trim().is_empty() {
                return Err(VectorError::Invalid("vector id must not be empty".into()));
            }
            if vector.kind.trim().is_empty() {
                return Err(VectorError::Invalid(format!(
                    "vector {} has an empty kind",
                    vector.id
                )));
            }
            if !ids.insert(&vector.id) {
                return Err(VectorError::Invalid(format!("duplicate vector id {:?}", vector.id)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_baseline_document() {
        let document = VectorDocument::parse_str(
            r#"{"format":"scoplen-test-vectors","version":1,"vectors":[{"id":"baseline","kind":"model.cbor","input":"00","expected":"00"}]}"#,
        )
        .expect("baseline document is valid");
        assert_eq!(document.vectors.len(), 1);
    }

    #[test]
    fn rejects_duplicate_ids() {
        let error = VectorDocument::parse_str(
            r#"{"format":"scoplen-test-vectors","version":1,"vectors":[{"id":"same","kind":"a","input":"","expected":""},{"id":"same","kind":"b","input":"","expected":""}]}"#,
        )
        .expect_err("duplicate IDs must be rejected");
        assert!(error.to_string().contains("duplicate vector id"));
    }
}
\n