// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{
    MAX_SYNC_KEY_ARTIFACT_BYTES, MAX_SYNC_KEY_BODY_BYTES, SYNC_KEY_SIGNATURE_BYTES,
    SyncAccountDeviceWrap, SyncAccountKeyBundle, SyncAccountKeyBundlePutResponse,
    SyncAccountKeyBundleUpdate, sync_keys_signature_input,
};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn bundle() -> SyncAccountKeyBundle {
    SyncAccountKeyBundle {
        revision: 7,
        wrapped_ark: vec![1, 2, 3],
        account_signing_key: vec![4, 5],
        account_kem_key: vec![6, 7],
        recovery_blob: vec![8, 9],
        certificates: vec![vec![1, 2], vec![0xa0]],
        revocations: vec![vec![3], vec![0xff]],
    }
}

fn update() -> SyncAccountKeyBundleUpdate {
    SyncAccountKeyBundleUpdate {
        revision: 8,
        device_wraps: vec![
            SyncAccountDeviceWrap { device_id: id(1), wrapped_ark: vec![1, 2] },
            SyncAccountDeviceWrap { device_id: id(2), wrapped_ark: vec![3, 4] },
        ],
        account_signing_key: vec![5, 6],
        account_kem_key: vec![7, 8],
        recovery_blob: vec![9, 10],
        signature: (0..u8::try_from(SYNC_KEY_SIGNATURE_BYTES).expect("signature length fits u8"))
            .collect(),
    }
}

#[test]
fn key_bundle_codecs_enforce_contract_and_extensions() {
    let source = bundle();
    let encoded = source.to_cbor().expect("bundle encode");
    assert_eq!(SyncAccountKeyBundle::from_cbor(&encoded).expect("bundle decode"), source);
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("map") else {
        panic!("bundle map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("extension");
    assert_eq!(SyncAccountKeyBundle::from_cbor(&extended).expect("extension decode"), source);

    let source = update();
    let encoded = source.to_cbor().expect("update encode");
    assert_eq!(SyncAccountKeyBundleUpdate::from_cbor(&encoded).expect("update decode"), source);
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("map") else {
        panic!("update map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let unknown = cbor::encode(&Value::Map(fields)).expect("unknown");
    assert!(SyncAccountKeyBundleUpdate::from_cbor(&unknown).is_err());
    assert_eq!(
        sync_keys_signature_input(&source).expect("signature input"),
        source.signature_input().expect("signature input")
    );
    assert_eq!(source.signature_input().expect("signature input")[..16], *b"spl-sync-keys-v1");
    source.validate_next_revision(7).expect("next revision");
    assert!(source.validate_next_revision(6).is_err());
    assert!(source.validate_next_revision(8).is_err());

    let response = SyncAccountKeyBundlePutResponse { revision: 8 };
    let encoded = response.to_cbor().expect("response encode");
    assert_eq!(
        SyncAccountKeyBundlePutResponse::from_cbor(&encoded).expect("response decode"),
        response
    );
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("response map") else {
        panic!("response map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    assert_eq!(
        SyncAccountKeyBundlePutResponse::from_cbor(
            &cbor::encode(&Value::Map(fields)).expect("extension")
        )
        .expect("response extension"),
        response
    );
}

#[test]
fn key_bundle_codecs_reject_failure_paths() {
    let source = update();
    let encoded = source.to_cbor().expect("encode");

    let Value::Map(mut fields) = cbor::decode(&encoded).expect("map") else {
        panic!("update map");
    };
    fields.retain(|(key, _)| key != &Value::Text("signature".into()));
    let missing = cbor::encode(&Value::Map(fields)).expect("missing signature");
    assert!(SyncAccountKeyBundleUpdate::from_cbor(&missing).is_err());

    let mut invalid = source.clone();
    invalid.device_wraps.reverse();
    assert!(invalid.to_cbor().is_err(), "unsorted device wraps");
    invalid = source.clone();
    invalid.device_wraps[1].device_id = id(1);
    assert!(invalid.to_cbor().is_err(), "duplicate device wraps");
    invalid = source.clone();
    invalid.revision = 0;
    assert!(invalid.to_cbor().is_err(), "zero revision");
    invalid = source.clone();
    invalid.signature.pop();
    assert!(invalid.to_cbor().is_err(), "malformed signature");
    invalid = source.clone();
    invalid.account_kem_key = vec![0; MAX_SYNC_KEY_ARTIFACT_BYTES + 1];
    assert!(invalid.to_cbor().is_err(), "oversized artifact");
    invalid = source.clone();
    invalid.device_wraps.clear();
    assert!(invalid.to_cbor().is_err(), "empty wraps");

    let mut noncanonical_uuid = source.clone();
    noncanonical_uuid.device_wraps[0].device_id = Uuid::nil();
    assert!(noncanonical_uuid.to_cbor().is_err(), "non-canonical UUID");
    assert!(SyncAccountKeyBundleUpdate::from_cbor(&vec![0; MAX_SYNC_KEY_BODY_BYTES + 1]).is_err());

    let mut get = bundle();
    get.certificates.reverse();
    assert!(get.to_cbor().is_err(), "unsorted certificates");
    get = bundle();
    get.certificates[0].clear();
    assert!(get.to_cbor().is_err(), "empty certificate");
    assert!(SyncAccountKeyBundle::from_cbor(&[0xf6]).is_err());
}

#[test]
fn published_key_bundle_vectors_match_public_codecs() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sync-keys.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 5);
    for vector in &document.vectors {
        let expected = decode_hex(&vector.expected);
        match vector.kind.as_str() {
            "sync.keys.get.response" => {
                let source = bundle_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncAccountKeyBundle::from_cbor(&expected).expect("decode"), source);
            }
            "sync.keys.put.request" | "sync.keys.replay.request" => {
                let source = update_from_json(&vector.input);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncAccountKeyBundleUpdate::from_cbor(&expected).expect("decode"),
                    source
                );
            }
            "sync.keys.signature-input" => {
                let source = update_from_json(&vector.input);
                assert_eq!(
                    source.signature_input().expect("signature input"),
                    expected,
                    "{}",
                    vector.id
                );
            }
            "sync.keys.put.response" => {
                let source = SyncAccountKeyBundlePutResponse { revision: 8 };
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(
                    SyncAccountKeyBundlePutResponse::from_cbor(&expected).expect("decode"),
                    source
                );
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

fn bundle_from_json(input: &str) -> SyncAccountKeyBundle {
    let value: JsonValue = serde_json::from_str(input).expect("bundle JSON");
    SyncAccountKeyBundle {
        revision: value["revision"].as_u64().expect("revision"),
        wrapped_ark: decode_hex(value["wrapped_ark"].as_str().expect("wrapped_ark")),
        account_signing_key: decode_hex(value["account_signing_key"].as_str().expect("signing")),
        account_kem_key: decode_hex(value["account_kem_key"].as_str().expect("kem")),
        recovery_blob: decode_hex(value["recovery_blob"].as_str().expect("recovery")),
        certificates: value["certificates"]
            .as_array()
            .expect("certificates")
            .iter()
            .map(|entry| decode_hex(entry.as_str().expect("certificate")))
            .collect(),
        revocations: value["revocations"]
            .as_array()
            .expect("revocations")
            .iter()
            .map(|entry| decode_hex(entry.as_str().expect("revocation")))
            .collect(),
    }
}

fn update_from_json(input: &str) -> SyncAccountKeyBundleUpdate {
    let value: JsonValue = serde_json::from_str(input).expect("update JSON");
    SyncAccountKeyBundleUpdate {
        revision: value["revision"].as_u64().expect("revision"),
        device_wraps: value["device_wraps"]
            .as_array()
            .expect("device_wraps")
            .iter()
            .map(|entry| SyncAccountDeviceWrap {
                device_id: Uuid::parse_str(entry["device_id"].as_str().expect("device id"))
                    .expect("UUID"),
                wrapped_ark: decode_hex(entry["wrapped_ark"].as_str().expect("wrap")),
            })
            .collect(),
        account_signing_key: decode_hex(value["account_signing_key"].as_str().expect("signing")),
        account_kem_key: decode_hex(value["account_kem_key"].as_str().expect("kem")),
        recovery_blob: decode_hex(value["recovery_blob"].as_str().expect("recovery")),
        signature: decode_hex(value["signature"].as_str().expect("signature")),
    }
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
