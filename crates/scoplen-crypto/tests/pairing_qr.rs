// SPDX-License-Identifier: Apache-2.0
//! Exercise K-3 QR pairing through the public crypto API.

use scoplen_crypto::{DeviceKemKeyPair, P256SigningKey, PairingQrError, PairingQrPayload};
use uuid::Uuid;

fn pairing_id() -> Uuid {
    "03000000-0000-7000-8000-000000000000".parse().expect("UUIDv7")
}

#[test]
fn qr_payload_round_trips_and_binds_relayed_keys() {
    let kem = DeviceKemKeyPair::from_private_bytes(&[7; 32]).expect("KEM key");
    let signing = P256SigningKey::from_bytes(&[2; 32]).expect("signing key");
    let payload = PairingQrPayload::new(pairing_id(), kem.public_key(), &signing.public_key_sec1())
        .expect("payload");
    let encoded = payload.encode();
    let decoded = PairingQrPayload::decode(&encoded).expect("decode");
    assert_eq!(decoded, payload);
    assert_eq!(decoded.pairing_id(), pairing_id());
    decoded
        .verify_public_keys(kem.public_key(), &signing.public_key_sec1())
        .expect("same device keys");

    let other = P256SigningKey::from_bytes(&[3; 32]).expect("different signing key");
    assert_eq!(
        decoded.verify_public_keys(kem.public_key(), &other.public_key_sec1()),
        Err(PairingQrError::KeyMismatch)
    );
    let other = DeviceKemKeyPair::from_private_bytes(&[8; 32]).expect("different KEM key");
    assert_eq!(
        decoded.verify_public_keys(other.public_key(), &signing.public_key_sec1()),
        Err(PairingQrError::KeyMismatch)
    );
}

#[test]
fn qr_payload_rejects_malformed_input_and_keys() {
    let kem = DeviceKemKeyPair::from_private_bytes(&[7; 32]).expect("KEM key");
    let signing = P256SigningKey::from_bytes(&[2; 32]).expect("signing key");
    let encoded = PairingQrPayload::new(pairing_id(), kem.public_key(), &signing.public_key_sec1())
        .expect("payload")
        .encode();

    for malformed in [
        encoded.replace("splpair1:", "splpair2:"),
        encoded.replace("03000000", "0300000A"),
        encoded.replace("-7000-", "-4000-"),
        encoded.replace("e595d", "E595D"),
        encoded[..encoded.len() - 1].to_string(),
        format!("{encoded}:"),
    ] {
        assert_eq!(PairingQrPayload::decode(&malformed), Err(PairingQrError::InvalidPayload));
    }

    let payload = PairingQrPayload::decode(&encoded).expect("decode");
    assert_eq!(
        PairingQrPayload::new(Uuid::nil(), kem.public_key(), &signing.public_key_sec1()),
        Err(PairingQrError::InvalidPayload)
    );
    assert_eq!(
        PairingQrPayload::new(pairing_id(), &[4; 65], &signing.public_key_sec1()),
        Err(PairingQrError::InvalidPublicKey)
    );
    assert_eq!(
        payload.verify_public_keys(kem.public_key(), &[4; 65]),
        Err(PairingQrError::InvalidPublicKey)
    );
}
