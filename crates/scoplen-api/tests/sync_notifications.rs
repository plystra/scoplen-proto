// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::SyncNotification;
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn vault() -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
}

#[test]
fn published_notification_vectors_match_public_codec() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/sync-notifications.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 3);
    for vector in &document.vectors {
        let source = notification_from_json(&vector.input);
        let expected = decode_hex(&vector.expected);
        assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
        assert_eq!(SyncNotification::from_cbor(&expected).expect("decode"), source);
    }
}

#[test]
fn notifications_require_one_unambiguous_event_and_validate_fields() {
    let advanced = SyncNotification::VaultAdvanced { vault: vault(), seq: 7 };
    let encoded = advanced.to_cbor().expect("encode");
    let Value::Map(mut fields) = cbor::decode(&encoded).expect("decode") else {
        panic!("notification map");
    };
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let extended = cbor::encode(&Value::Map(fields)).expect("extension");
    assert_eq!(SyncNotification::from_cbor(&extended).expect("decode"), advanced);

    let missing = cbor::encode(&Value::Map(vec![(
        Value::Text("vault".into()),
        Value::Bytes(vault().into_bytes().to_vec()),
    )]))
    .expect("missing marker");
    assert!(SyncNotification::from_cbor(&missing).is_err());

    let wrong_seq = cbor::encode(&Value::Map(vec![
        (Value::Text("seq".into()), Value::Text("7".into())),
        (Value::Text("vault".into()), Value::Bytes(vault().into_bytes().to_vec())),
    ]))
    .expect("wrong sequence");
    assert!(SyncNotification::from_cbor(&wrong_seq).is_err());

    let zero_seq = SyncNotification::VaultAdvanced { vault: vault(), seq: 0 };
    assert!(zero_seq.to_cbor().is_err());

    let ambiguous = cbor::encode(&Value::Map(vec![
        (Value::Text("seq".into()), Value::UInt(1)),
        (Value::Text("rotation_pending".into()), Value::Bool(true)),
        (Value::Text("vault".into()), Value::Bytes(vault().into_bytes().to_vec())),
    ]))
    .expect("ambiguous");
    assert!(SyncNotification::from_cbor(&ambiguous).is_err());

    let false_marker =
        cbor::encode(&Value::Map(vec![(Value::Text("device_revoked".into()), Value::Bool(false))]))
            .expect("false marker");
    assert!(SyncNotification::from_cbor(&false_marker).is_err());

    assert!(SyncNotification::from_cbor(&[0xbf, 0xff]).is_err());
    assert!(SyncNotification::from_cbor(&[0xf6]).is_err());
}

fn notification_from_json(input: &str) -> SyncNotification {
    let value: JsonValue = serde_json::from_str(input).expect("notification JSON");
    match value["kind"].as_str().expect("kind") {
        "vault_advanced" => SyncNotification::VaultAdvanced {
            vault: Uuid::parse_str(value["vault"].as_str().expect("vault")).expect("UUID"),
            seq: value["seq"].as_u64().expect("sequence"),
        },
        "rotation_pending" => SyncNotification::RotationPending {
            vault: Uuid::parse_str(value["vault"].as_str().expect("vault")).expect("UUID"),
        },
        "device_revoked" => SyncNotification::DeviceRevoked,
        other => panic!("unexpected notification kind {other}"),
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
