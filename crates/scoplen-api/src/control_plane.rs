// SPDX-License-Identifier: Apache-2.0
//! Generated control-plane API types from `openapi/v1.yaml`.
//!
//! The generator preserves the wire-level envelope and deliberately leaves
//! resource-specific fields in `data` until the corresponding control-plane
//! resource schema is introduced.  This keeps clients forward compatible with
//! additive v1 fields while retaining strict pagination and concurrency rules.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical Cedar entity/action schema for the control plane.
pub const CEDAR_SCHEMA: &str = include_str!("../cedar/schema.cedarschema");

/// Built-in role policies evaluated by the control plane.
pub const BUILT_IN_POLICIES: &str = include_str!("../cedar/built-in-policies.cedar");

/// A control-plane resource envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Resource {
    /// Lowercase UUID resource identifier.
    pub id: String,
    /// Opaque entity tag required by updates.
    pub etag: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-update timestamp.
    pub updated_at: String,
    /// Resource-specific JSON projection.
    pub data: serde_json::Map<String, Value>,
}

/// A cursor-paginated collection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Page<T> {
    /// Returned resources.
    pub items: Vec<T>,
    /// Cursor for the next page, or null at the end.
    pub next_cursor: Option<String>,
}

/// Shared mutable-resource request body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteRequest {
    /// Resource-specific JSON projection.
    pub data: serde_json::Map<String, Value>,
}

/// Query parameters shared by collection endpoints.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListQuery {
    /// Number of resources to return. The contract caps this at 500.
    pub limit: Option<u16>,
    /// Opaque continuation cursor.
    pub cursor: Option<String>,
    /// Documented filter expression.
    pub filter: Option<String>,
    /// Field name, optionally prefixed with `-` for descending order.
    pub sort: Option<String>,
}

impl ListQuery {
    /// Validate the bounds required by the `OpenAPI` contract.
    ///
    /// # Errors
    ///
    /// Returns the first bound violation in the query.
    pub fn validate(&self) -> Result<(), QueryError> {
        if let Some(limit) = self.limit {
            if !(1..=500).contains(&limit) {
                return Err(QueryError::Limit);
            }
        }
        if self.cursor.as_ref().is_some_and(|value| value.len() > 512) {
            return Err(QueryError::Cursor);
        }
        if self.filter.as_ref().is_some_and(|value| value.len() > 2048) {
            return Err(QueryError::Filter);
        }
        if self.sort.as_ref().is_some_and(|value| value.len() > 128) {
            return Err(QueryError::Sort);
        }
        Ok(())
    }
}

/// Invalid control-plane collection query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QueryError {
    /// `limit` was outside 1..=500.
    #[error("limit must be between 1 and 500")]
    Limit,
    /// The cursor exceeded its contract bound.
    #[error("cursor exceeds 512 bytes")]
    Cursor,
    /// The filter exceeded its contract bound.
    #[error("filter exceeds 2048 bytes")]
    Filter,
    /// The sort expression exceeded its contract bound.
    #[error("sort exceeds 128 bytes")]
    Sort,
}

/// RFC 9457 problem details used by every control-plane error response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProblemDetails {
    /// Problem type URI.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Short human-readable title.
    pub title: String,
    /// HTTP status in the 4xx/5xx range.
    pub status: u16,
    /// Stable Scoplen error code.
    pub code: String,
    /// Optional human-readable detail.
    pub detail: Option<String>,
    /// Optional occurrence URI.
    pub instance: Option<String>,
    /// Whether the requested state changed before failure.
    pub changed: Option<bool>,
    /// Forward-compatible extension fields.
    #[serde(default, flatten)]
    pub extensions: serde_json::Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::{
        BUILT_IN_POLICIES, CEDAR_SCHEMA, ListQuery, Page, ProblemDetails, QueryError, Resource,
    };
    use serde_json::json;

    #[test]
    fn query_bounds_match_openapi_contract() {
        assert_eq!(
            ListQuery { limit: Some(0), ..Default::default() }.validate(),
            Err(QueryError::Limit)
        );
        assert_eq!(ListQuery { limit: Some(500), ..Default::default() }.validate(), Ok(()));
        assert_eq!(
            ListQuery { cursor: Some("x".repeat(513)), ..Default::default() }.validate(),
            Err(QueryError::Cursor)
        );
    }

    #[test]
    fn generated_envelopes_round_trip_without_dropping_extensions() {
        let resource = Resource {
            id: "018f35d4-1f8f-7e2a-9e56-7a5e8a9f11a1".into(),
            etag: "\"1\"".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            data: serde_json::Map::from_iter([(String::from("label"), json!("host"))]),
        };
        let page = Page { items: vec![resource], next_cursor: None };
        let json = serde_json::to_string(&page).expect("encode");
        let decoded: Page<Resource> = serde_json::from_str(&json).expect("decode");
        assert_eq!(decoded, page);
        let problem: ProblemDetails = serde_json::from_value(json!({
            "type":"about:blank","title":"Denied","status":403,
            "code":"policy.denied","x_trace":"kept"
        }))
        .expect("problem");
        assert_eq!(problem.extensions["x_trace"], "kept");
    }

    #[test]
    fn cedar_contract_contains_every_documented_action_and_role() {
        for marker in [
            "entity Account",
            "entity Device",
            "entity Host",
            "entity Organization",
            "action connect",
            "action request_access",
            "action approve_access",
            "action manage_inventory",
            "action view_audit",
        ] {
            assert!(CEDAR_SCHEMA.contains(marker), "missing Cedar marker: {marker}");
        }
        for role in ["owner", "administrator", "security_auditor", "approver", "member"] {
            assert!(BUILT_IN_POLICIES.contains(role), "missing built-in role: {role}");
        }
    }
}
