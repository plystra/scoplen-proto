// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::{SyncChange, SyncChangesQuery, SyncChangesResponse};
use scoplen_model::cbor::{self, Value};
use serde_json::Value as JsonValue;
use uuid::Uuid;

fn id(last: u8) -> Uuid {
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last])
}

fn change(object: u8, seq: u64, signer: Option<u8>) -> SyncChange {
    SyncChange {
        object_id: id(object),
        seq,
        payload: vec![0xde, 0xad],
        tombstone: false,
        signer_device_id: signer.map(id),
    }
}

fn page() -> SyncChangesResponse {
    SyncChangesResponse {
        changes: vec![change(1, 2, Some(3)), change(2, 5, None)],
        next_cursor: 5,
        more: true,
    }
}

#[test]
fn query_requires_canonical_decimal_and_both_parameters() {
    let query = SyncChangesQuery { after: 0, limit: 1_000 };
    assert_eq!(query.to_query().expect("format"), "after=0&limit=1000");
    assert_eq!(SyncChangesQuery::from_query("limit=1000&after=0").expect("parse"), query);
    assert_eq!(
        SyncChangesQuery::from_query("after=18446744073709551615&limit=1")
            .expect("largest sequence")
            .after,
        u64::MAX
    );

    for invalid in [
        "",
        "after=0",
        "limit=1",
        "after=&limit=1",
        "after=00&limit=1",
        "after=+1&limit=1",
        "after=-1&limit=1",
        "after=0x1&limit=1",
        "after=1.0&limit=1",
        "after=18446744073709551616&limit=1",
        "after=0&limit=0",
        "after=0&limit=01",
        "after=0&limit=1001",
        "after=0&limit=65536",
        "after=0&limit=1&limit=2",
        "after=0&after=1&limit=1",
        "after=0&limit=1&other=2",
        "?after=0&limit=1",
        "after=0&limit=1&",
        "after=0;limit=1",
    ] {
        assert!(SyncChangesQuery::from_query(invalid).is_err(), "{invalid:?}");
    }
    assert!(SyncChangesQuery { after: 0, limit: 0 }.to_query().is_err());
    assert!(SyncChangesQuery { after: 0, limit: 1_001 }.to_query().is_err());
}

#[test]
fn published_change_feed_vectors_match_public_codec() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/sync-changes.json");
    let document = scoplen_test_vectors::VectorDocument::from_path(path).expect("vectors");
    assert_eq!(document.vectors.len(), 4);
    for vector in &document.vectors {
        match vector.kind.as_str() {
            "sync.changes.query" => {
                let source: JsonValue = serde_json::from_str(&vector.input).expect("query JSON");
                let query = SyncChangesQuery {
                    after: source["after"].as_u64().expect("after"),
                    limit: source["limit"].as_u64().expect("limit").try_into().expect("u16"),
                };
                assert_eq!(query.to_query().expect("format"), vector.expected, "{}", vector.id);
                assert_eq!(SyncChangesQuery::from_query(&vector.expected).expect("parse"), query);
            }
            "sync.changes.response" => {
                let source = response_from_json(&vector.input);
                let expected = decode_hex(&vector.expected);
                assert_eq!(source.to_cbor().expect("encode"), expected, "{}", vector.id);
                assert_eq!(SyncChangesResponse::from_cbor(&expected).expect("decode"), source);
            }
            other => panic!("unexpected vector kind {other}"),
        }
    }
}

#[test]
fn response_validates_page_order_uniqueness_and_cursor() {
    let query = SyncChangesQuery { after: 1, limit: 2 };
    assert!(page().validate_for_query(&query).is_ok());
    assert!(page().validate_for_query(&SyncChangesQuery { after: 2, limit: 2 }).is_err());
    assert!(page().validate_for_query(&SyncChangesQuery { after: 1, limit: 1 }).is_err());
    assert!(page().validate_for_query(&SyncChangesQuery { after: 1, limit: 0 }).is_err());

    let mut invalid = page();
    invalid.changes.reverse();
    assert!(invalid.to_cbor().is_err());
    invalid = page();
    invalid.changes[1].object_id = invalid.changes[0].object_id;
    assert!(invalid.to_cbor().is_err());
    invalid = page();
    invalid.changes[0].seq = 0;
    assert!(invalid.to_cbor().is_err());
    invalid = page();
    invalid.changes[0].object_id = Uuid::nil();
    assert!(invalid.to_cbor().is_err());
    invalid = page();
    invalid.changes[0].signer_device_id = Some(Uuid::nil());
    assert!(invalid.to_cbor().is_err());
    invalid = page();
    invalid.next_cursor = 4;
    assert!(invalid.to_cbor().is_err());
    invalid = page();
    invalid.next_cursor = 6;
    assert!(invalid.to_cbor().is_err());
    invalid = page();
    invalid.changes.clear();
    assert!(invalid.to_cbor().is_err());

    let final_page = SyncChangesResponse { changes: vec![], next_cursor: 12, more: false };
    assert!(final_page.validate_for_query(&SyncChangesQuery { after: 5, limit: 1 }).is_ok());
    assert!(final_page.validate_for_query(&SyncChangesQuery { after: 13, limit: 1 }).is_err());
}

#[test]
fn decoder_rejects_missing_wrong_and_nondeterministic_fields() {
    let encoded = page().to_cbor().expect("encode");
    let Value::Map(fields) = cbor::decode(&encoded).expect("decode value") else {
        panic!("response is a map");
    };
    for key in ["changes", "next_cursor", "more"] {
        let mut missing = fields.clone();
        missing.retain(|(field, _)| field != &Value::Text(key.into()));
        assert!(
            SyncChangesResponse::from_cbor(&cbor::encode(&Value::Map(missing)).expect("encode"))
                .is_err(),
            "missing {key}"
        );
    }
    let mut wrong = fields.clone();
    replace_text_field(&mut wrong, "more", Value::UInt(1));
    assert!(
        SyncChangesResponse::from_cbor(&cbor::encode(&Value::Map(wrong)).expect("encode")).is_err()
    );
    let mut wrong = fields.clone();
    replace_text_field(&mut wrong, "changes", Value::Null);
    assert!(
        SyncChangesResponse::from_cbor(&cbor::encode(&Value::Map(wrong)).expect("encode")).is_err()
    );

    let mut missing_nested = fields.clone();
    let Value::Array(changes) = text_field_mut(&mut missing_nested, "changes") else {
        panic!("changes array");
    };
    let Value::Map(first) = &mut changes[0] else { panic!("entry map") };
    first.retain(|(key, _)| key != &Value::UInt(5));
    assert!(
        SyncChangesResponse::from_cbor(&cbor::encode(&Value::Map(missing_nested)).expect("encode"))
            .is_err()
    );

    let mut wrong_nested = fields.clone();
    let Value::Array(changes) = text_field_mut(&mut wrong_nested, "changes") else {
        panic!("changes array");
    };
    let Value::Map(first) = &mut changes[0] else { panic!("entry map") };
    for (key, value) in first {
        if key == &Value::UInt(3) {
            *value = Value::Text("not bytes".into());
        }
    }
    assert!(
        SyncChangesResponse::from_cbor(&cbor::encode(&Value::Map(wrong_nested)).expect("encode"))
            .is_err()
    );
    assert!(SyncChangesResponse::from_cbor(&[0xbf, 0xff]).is_err());
    assert!(SyncChangesResponse::from_cbor(&[0xf6]).is_err());
}

#[test]
fn decoder_ignores_additive_response_fields() {
    let source = page();
    let Value::Map(mut fields) = cbor::decode(&source.to_cbor().expect("encode")).expect("decode")
    else {
        panic!("response map");
    };
    let Value::Array(changes) = text_field_mut(&mut fields, "changes") else {
        panic!("changes array");
    };
    let Value::Map(first) = &mut changes[0] else { panic!("entry map") };
    first.push((Value::UInt(6), Value::Bool(true)));
    fields.push((Value::Text("future".into()), Value::UInt(1)));
    let encoded = cbor::encode(&Value::Map(fields)).expect("encode extensions");
    assert_eq!(SyncChangesResponse::from_cbor(&encoded).expect("decode extensions"), source);
}

fn text_field_mut<'a>(fields: &'a mut [(Value, Value)], key: &str) -> &'a mut Value {
    &mut fields.iter_mut().find(|(field, _)| field == &Value::Text(key.into())).expect("field").1
}

fn replace_text_field(fields: &mut [(Value, Value)], key: &str, value: Value) {
    *text_field_mut(fields, key) = value;
}

fn response_from_json(input: &str) -> SyncChangesResponse {
    let source: JsonValue = serde_json::from_str(input).expect("response JSON");
    SyncChangesResponse {
        changes: source["changes"]
            .as_array()
            .expect("changes array")
            .iter()
            .map(|entry| SyncChange {
                object_id: Uuid::parse_str(entry["object_id"].as_str().expect("id")).expect("UUID"),
                seq: entry["seq"].as_u64().expect("seq"),
                payload: decode_hex(entry["payload"].as_str().expect("payload hex")),
                tombstone: entry["tombstone"].as_bool().expect("tombstone"),
                signer_device_id: entry["signer_device_id"]
                    .as_str()
                    .map(|id| Uuid::parse_str(id).expect("UUID")),
            })
            .collect(),
        next_cursor: source["next_cursor"].as_u64().expect("cursor"),
        more: source["more"].as_bool().expect("more"),
    }
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
