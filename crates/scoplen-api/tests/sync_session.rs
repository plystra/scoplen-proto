// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    SessionVault, SyncLimits, SyncSessionRequest, SyncSessionResponse, VaultKind,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn id() -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
}

fn request() -> SyncSessionRequest {
    SyncSessionRequest { client_version: "0.1.0".into(), model_version: 1, device_id: id() }
}

fn response() -> SyncSessionResponse {
    SyncSessionResponse {
        server_version: "0.1.0".into(),
        max_model_version: 1,
        limits: SyncLimits {
            max_envelope_bytes: 266_240,
            max_batch_objects: 500,
            max_batch_bytes: 4_194_304,
            max_objects_per_vault: 100_000,
            max_shared_vaults_per_account: 1_000,
            max_members_per_shared_vault: 1_000,
            write_requests_per_second: 50,
            write_burst: 200,
        },
        vaults: vec![SessionVault {
            id: id(),
            kind: VaultKind::Personal,
            seq: 0,
            key_epoch: 1,
            rotation_pending: false,
        }],
    }
}

#[test]
fn published_session_vectors_match_public_codec() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sync-session.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 2);
    for vector in &document.vectors {
        let expected = decode_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.session.request" => {
                let source = request_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected);
                assert_eq!(SyncSessionRequest::from_cbor(&expected).expect("decode"), source);
            }
            "sync.session.response" => {
                let source = response_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected);
                assert_eq!(SyncSessionResponse::from_cbor(&expected).expect("decode"), source);
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

fn request_from_json(input: &str) -> SyncSessionRequest {
    let source: JsonValue = serde_json::from_str(input).expect("request JSON");
    SyncSessionRequest {
        client_version: string(&source, "client_version"),
        model_version: number(&source, "model_version"),
        device_id: Uuid::parse_str(&string(&source, "device_id")).expect("UUID"),
    }
}

fn response_from_json(input: &str) -> SyncSessionResponse {
    let source: JsonValue = serde_json::from_str(input).expect("response JSON");
    let limits = &source["limits"];
    let vaults = source["vaults"].as_array().expect("vault array");
    SyncSessionResponse {
        server_version: string(&source, "server_version"),
        max_model_version: number(&source, "max_model_version"),
        limits: SyncLimits {
            max_envelope_bytes: number(limits, "max_envelope_bytes"),
            max_batch_objects: number(limits, "max_batch_objects"),
            max_batch_bytes: number(limits, "max_batch_bytes"),
            max_objects_per_vault: number(limits, "max_objects_per_vault"),
            max_shared_vaults_per_account: number(limits, "max_shared_vaults_per_account"),
            max_members_per_shared_vault: number(limits, "max_members_per_shared_vault"),
            write_requests_per_second: number(limits, "write_requests_per_second"),
            write_burst: number(limits, "write_burst"),
        },
        vaults: vaults
            .iter()
            .map(|vault| SessionVault {
                id: Uuid::parse_str(&string(vault, "id")).expect("UUID"),
                kind: match string(vault, "kind").as_str() {
                    "personal" => VaultKind::Personal,
                    "shared" => VaultKind::Shared,
                    "organization" => VaultKind::Organization,
                    other => VaultKind::Unknown(other.into()),
                },
                seq: number(vault, "seq"),
                key_epoch: number(vault, "key_epoch"),
                rotation_pending: vault["rotation_pending"].as_bool().expect("boolean"),
            })
            .collect(),
    }
}

fn string(value: &JsonValue, key: &str) -> String {
    value[key].as_str().expect("text field").into()
}

fn number(value: &JsonValue, key: &str) -> u64 {
    value[key].as_u64().expect("unsigned field")
}

#[test]
fn request_rejects_missing_or_invalid_required_fields() {
    let mut invalid = request();
    invalid.client_version = " ".into();
    assert!(invalid.to_cbor().is_err());
    invalid = request();
    invalid.model_version = 0;
    assert!(invalid.to_cbor().is_err());
    invalid = request();
    invalid.device_id = Uuid::nil();
    assert!(invalid.to_cbor().is_err());

    let Value::Map(fields) = cbor::decode(&request().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("request is a map");
    };
    for key in ["client_version", "model_version", "device_id"] {
        let mut missing = fields.clone();
        missing.retain(|(field, _)| field != &Value::Text(key.into()));
        let bytes = cbor::encode(&Value::Map(missing)).expect("encode");
        assert!(SyncSessionRequest::from_cbor(&bytes).is_err(), "missing {key}");
    }
    let mut wrong_type = fields;
    for (key, value) in &mut wrong_type {
        if key == &Value::Text("device_id".into()) {
            *value = Value::Text(id().to_string());
        }
    }
    assert!(
        SyncSessionRequest::from_cbor(&cbor::encode(&Value::Map(wrong_type)).expect("encode"))
            .is_err()
    );
    assert!(SyncSessionRequest::from_cbor(&[0xbf, 0xff]).is_err());
    let Value::Map(mut fields) =
        cbor::decode(&request().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("request is a map");
    };
    fields.push((Value::Text("future_field".into()), Value::Bool(true)));
    assert!(
        SyncSessionRequest::from_cbor(&cbor::encode(&Value::Map(fields)).expect("encode")).is_err()
    );
}

#[test]
fn response_preserves_unknown_kind_and_ignores_extension_fields() {
    let mut future = response();
    future.vaults[0].kind = VaultKind::Unknown("future".into());
    let bytes = future.to_cbor().expect("future kind");
    assert_eq!(SyncSessionResponse::from_cbor(&bytes).expect("decode"), future);

    let Value::Map(mut fields) = cbor::decode(&bytes).expect("decode value") else {
        panic!("response is a map");
    };
    fields.push((Value::Text("future_field".into()), Value::Bool(true)));
    let extended = cbor::encode(&Value::Map(fields)).expect("encode extension");
    assert_eq!(SyncSessionResponse::from_cbor(&extended).expect("extension"), future);
}

#[test]
fn response_rejects_duplicate_vaults_zero_limits_and_bad_nested_fields() {
    let mut duplicate = response();
    duplicate.vaults.push(duplicate.vaults[0].clone());
    assert!(duplicate.to_cbor().is_err());
    let Value::Map(mut fields) =
        cbor::decode(&response().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("response is a map");
    };
    for (key, value) in &mut fields {
        if key == &Value::Text("vaults".into()) {
            let Value::Array(vaults) = value else {
                panic!("vaults array");
            };
            vaults.push(vaults[0].clone());
        }
    }
    assert!(
        SyncSessionResponse::from_cbor(&cbor::encode(&Value::Map(fields)).expect("encode"))
            .is_err()
    );

    let mut zero = response();
    zero.limits.max_batch_objects = 0;
    assert!(zero.to_cbor().is_err());
    zero = response();
    zero.vaults[0].key_epoch = 0;
    assert!(zero.to_cbor().is_err());

    let Value::Map(mut fields) =
        cbor::decode(&response().to_cbor().expect("encode")).expect("decode")
    else {
        panic!("response is a map");
    };
    for (key, value) in &mut fields {
        if key == &Value::Text("limits".into()) {
            let Value::Map(limits) = value else {
                panic!("limits map");
            };
            limits.retain(|(field, _)| field != &Value::Text("max_batch_objects".into()));
        }
    }
    assert!(
        SyncSessionResponse::from_cbor(&cbor::encode(&Value::Map(fields)).expect("encode"))
            .is_err()
    );
}

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(pair, 16).expect("hex byte")
        })
        .collect()
}
