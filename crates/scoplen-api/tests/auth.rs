// SPDX-License-Identifier: Apache-2.0
use scoplen_api::auth::{
    ACCESS_TOKEN_EXPIRES_IN, AuthChallengeResponse, AuthDeviceRequest, AuthTokenResponse,
    REFRESH_TOKEN_EXPIRES_IN,
};
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

#[test]
fn published_auth_vectors_round_trip_with_canonical_json() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/api-auth.json");
    let document = VectorDocument::from_path(path).expect("auth vectors");
    assert_eq!(document.vectors.len(), 4);
    for vector in document.vectors {
        let actual = match vector.kind.as_str() {
            "auth.challenge.response" => AuthChallengeResponse::from_json(&vector.input)
                .expect("challenge")
                .to_json()
                .expect("challenge JSON"),
            "auth.device.request" => AuthDeviceRequest::from_json(&vector.input)
                .expect("device")
                .to_json()
                .expect("device JSON"),
            "auth.token.response" => AuthTokenResponse::from_json(&vector.input)
                .expect("token")
                .to_json()
                .expect("token JSON"),
            other => panic!("unexpected auth vector kind {other}"),
        };
        assert_eq!(actual, vector.expected, "{}", vector.id);
    }
}

#[test]
fn auth_public_types_enforce_failure_paths() {
    let nonce = "00".repeat(32);
    let challenge_nonce = "ab".repeat(32);
    let signature = "00".repeat(64);
    let device_id = Uuid::parse_str("00000000-0000-7000-8000-000000000001").expect("UUIDv7");
    let valid_device = format!(
        "{{\"device_id\":\"{device_id}\",\"nonce\":\"{nonce}\",\"signature\":\"{signature}\"}}"
    );

    assert!(
        AuthChallengeResponse::from_json(&format!(
            "{{\"nonce\":\"{nonce}\",\"server_time\":\"2026-10-07T12:34:56+00:00\"}}"
        ))
        .is_err()
    );
    assert!(
        AuthChallengeResponse::from_json(&format!(
            "{{\"nonce\":\"{}\",\"server_time\":\"2026-10-07T12:34:56Z\"}}",
            challenge_nonce.to_uppercase()
        ))
        .is_err()
    );
    assert!(AuthDeviceRequest::from_json(&valid_device).is_ok());
    assert!(
        AuthDeviceRequest::from_json(
            &valid_device
                .replace("\"signature\":\"", "\"signature\":\"00\",\"unknown\":true,\"unused\":\"")
        )
        .is_err()
    );
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":600,\"refresh_token\":\"r\",\"refresh_expires_in\":2592000,\"extra\":true}"
    )
    .is_ok());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_token\":\"r\",\"refresh_expires_in\":2}"
    )
    .is_ok());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":0,\"refresh_token\":\"r\",\"refresh_expires_in\":1}"
    )
    .is_err());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":1,\"refresh_token\":\"r\",\"refresh_expires_in\":0}"
    )
    .is_err());
    assert!(AuthTokenResponse::from_json(&format!(
        "{{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"expires_in\":{ACCESS_TOKEN_EXPIRES_IN},\"refresh_token\":\"r\",\"refresh_expires_in\":{REFRESH_TOKEN_EXPIRES_IN}}}"
    ))
    .is_ok());
    assert!(AuthTokenResponse::from_json(
        "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":600,\"refresh_token\":\"r\",\"refresh_expires_in\":2592000}"
    )
    .is_err());
}
