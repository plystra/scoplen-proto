// SPDX-License-Identifier: Apache-2.0
//! Execute the published K-2 fixtures through the public crypto and model APIs.

use std::{collections::BTreeSet, fmt::Write as _, path::Path};

use rand_core_010::{TryCryptoRng, TryRng};
use scoplen_crypto::{
    AccountKemKeyPair, Argon2idParams, DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey,
    HpkeCiphertext, LocalDatabaseKeyEnvelope, ObjectEnvelope, P256SigningKey, PairingCode,
    PairingContext, PairingInitiator, PairingQrPayload, PairingResponder, PairingRole,
    PrimitiveError, RecoveryBlob, RecoveryKey, RevocationStatement, SecretBytes, ShamirShare,
    XChaChaNonce, combine_shamir, ed25519_verify, escrow_account_context, escrow_device_context,
    escrow_verification_code, hkdf_sha256, hpke_open_account, hpke_open_device,
    open_escrow_share_from_account, open_escrow_share_from_device, p256_verify, safety_fingerprint,
    safety_number, safety_qr, split_shamir_with_randomness, unwrap_key_from_device,
    verify_escrow_verification_code, verify_safety_qr, xchacha20poly1305_open,
    xchacha20poly1305_seal,
};
use scoplen_model::Object;
use scoplen_test_vectors::VectorDocument;
use uuid::Uuid;

struct VectorRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl VectorRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl TryRng for VectorRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.offset + destination.len();
        destination.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for VectorRng {}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        write!(output, "{byte:02x}").expect("write to String");
    }
    output
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd-length fixture hex");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16).expect("hex")
        })
        .collect()
}

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    unhex(value).try_into().expect("fixed-size fixture field")
}

fn fields(input: &str, count: usize) -> Vec<&str> {
    let fields: Vec<_> = input.split('|').collect();
    assert_eq!(fields.len(), count, "fixture field count");
    fields
}

fn uuid(value: &str) -> Uuid {
    Uuid::from_bytes(fixed(value))
}

#[allow(clippy::too_many_lines)]
fn fixture(kind: &str, input: &str, expected: &str) {
    match kind {
        "crypto.hkdf-sha256" => {
            let f = fields(input, 4);
            let length = f[3].parse().expect("HKDF length");
            assert_eq!(
                hex(hkdf_sha256(&unhex(f[0]), Some(&unhex(f[1])), &unhex(f[2]), length)
                    .expect("HKDF")),
                expected
            );
        }
        "crypto.xchacha20poly1305" => {
            let f = fields(input, 4);
            let key = SecretBytes::new(fixed(f[0]));
            let nonce = XChaChaNonce::new(fixed(f[1]));
            let plaintext = unhex(f[2]);
            let aad = unhex(f[3]);
            let ciphertext = xchacha20poly1305_seal(&key, &nonce, &plaintext, &aad).expect("seal");
            assert_eq!(hex(&ciphertext), expected);
            assert_eq!(
                xchacha20poly1305_open(&key, &nonce, &unhex(expected), &aad).expect("open"),
                plaintext
            );
            assert_eq!(
                xchacha20poly1305_open(&key, &nonce, &unhex(expected), b"wrong"),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.p256-signature" => {
            let f = fields(input, 2);
            let e = fields(expected, 2);
            let key = P256SigningKey::from_bytes(&unhex(f[0])).expect("P-256 key");
            assert_eq!(hex(key.public_key_sec1()), e[0]);
            assert_eq!(hex(key.sign(&unhex(f[1]))), e[1]);
            p256_verify(&unhex(e[0]), &unhex(f[1]), &unhex(e[1])).expect("verify");
            assert_eq!(
                p256_verify(&unhex(e[0]), b"wrong", &unhex(e[1])),
                Err(PrimitiveError::InvalidSignature)
            );
        }
        "crypto.ed25519-signature" => {
            let f = fields(input, 2);
            let e = fields(expected, 2);
            let key = Ed25519SigningKey::from_bytes(&unhex(f[0])).expect("Ed25519 key");
            assert_eq!(hex(key.public_key()), e[0]);
            assert_eq!(hex(key.sign(&unhex(f[1]))), e[1]);
            ed25519_verify(&unhex(e[0]), &unhex(f[1]), &unhex(e[1])).expect("verify");
            assert_eq!(
                ed25519_verify(&unhex(e[0]), b"wrong", &unhex(e[1])),
                Err(PrimitiveError::InvalidSignature)
            );
        }
        "crypto.hpke-account-open" => {
            let f = fields(input, 5);
            let recipient =
                AccountKemKeyPair::from_private_bytes(&unhex(f[0])).expect("account key");
            let plaintext = hpke_open_account(
                &recipient,
                &unhex(f[1]),
                &unhex(f[2]),
                &unhex(f[3]),
                &unhex(f[4]),
            )
            .expect("HPKE open");
            assert_eq!(hex(plaintext), expected);
            assert_eq!(
                hpke_open_account(&recipient, &unhex(f[1]), &unhex(f[2]), b"wrong", &unhex(f[4])),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.hpke-device-open" => {
            let f = fields(input, 5);
            let recipient = DeviceKemKeyPair::from_private_bytes(&unhex(f[0])).expect("device key");
            let plaintext = hpke_open_device(
                &recipient,
                &unhex(f[1]),
                &unhex(f[2]),
                &unhex(f[3]),
                &unhex(f[4]),
            )
            .expect("HPKE open");
            assert_eq!(hex(plaintext), expected);
            assert_eq!(
                hpke_open_device(&recipient, &unhex(f[1]), &unhex(f[2]), b"wrong", &unhex(f[4])),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.device-key-wrap-open" => {
            let f = fields(input, 5);
            let recipient = DeviceKemKeyPair::from_private_bytes(&unhex(f[0])).expect("device key");
            let wrapped = HpkeCiphertext { encapsulated_key: unhex(f[1]), ciphertext: unhex(f[4]) };
            assert_eq!(
                hex(unwrap_key_from_device(&recipient, &wrapped, &unhex(f[2]), &unhex(f[3]))
                    .expect("unwrap")),
                expected
            );
            assert_eq!(
                unwrap_key_from_device(&recipient, &wrapped, b"wrong", &unhex(f[3])),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.device-certificate" => {
            let f = fields(input, 8);
            let account = Ed25519SigningKey::from_bytes(&unhex(f[0])).expect("account signing key");
            let signing = P256SigningKey::from_bytes(&unhex(f[3])).expect("device signing key");
            let kem = DeviceKemKeyPair::from_private_bytes(&unhex(f[4])).expect("device KEM key");
            let cert = DeviceCertificate::issue(
                &account,
                uuid(f[1]),
                uuid(f[2]),
                signing.public_key_sec1(),
                kem.public_key().to_vec(),
                String::from_utf8(unhex(f[5])).expect("name"),
                String::from_utf8(unhex(f[6])).expect("platform"),
                f[7].parse().expect("created at"),
            )
            .expect("issue certificate");
            assert_eq!(hex(cert.encode().expect("encode")), expected);
            let mut decoded = DeviceCertificate::decode(&unhex(expected)).expect("decode");
            decoded.verify(&account.public_key()).expect("verify");
            decoded.signature[0] ^= 1;
            assert_eq!(
                decoded.verify(&account.public_key()),
                Err(PrimitiveError::InvalidSignature)
            );
        }
        "crypto.device-revocation" => {
            let f = fields(input, 4);
            let account = Ed25519SigningKey::from_bytes(&unhex(f[0])).expect("account signing key");
            let statement = RevocationStatement::issue(
                &account,
                uuid(f[1]),
                f[2].parse().expect("revoked at"),
                String::from_utf8(unhex(f[3])).expect("reason"),
            )
            .expect("issue revocation");
            assert_eq!(hex(statement.encode().expect("encode")), expected);
            let mut decoded = RevocationStatement::decode(&unhex(expected)).expect("decode");
            decoded.verify(&account.public_key()).expect("verify");
            decoded.signature[0] ^= 1;
            assert_eq!(
                decoded.verify(&account.public_key()),
                Err(PrimitiveError::InvalidSignature)
            );
        }
        "crypto.object-envelope" => {
            let f = fields(input, 7);
            let object = Object::decode(&unhex(f[2])).expect("object CBOR");
            let key = SecretBytes::new(fixed(f[3]));
            let signer = P256SigningKey::from_bytes(&unhex(f[5])).expect("signer");
            let envelope = ObjectEnvelope::encrypt_with_nonce(
                uuid(f[0]),
                f[1].parse().expect("epoch"),
                &object,
                &key,
                uuid(f[4]),
                &signer,
                SecretBytes::new(fixed(f[6])),
            )
            .expect("encrypt");
            assert_eq!(hex(envelope.encode().expect("encode")), expected);
            let mut decoded = ObjectEnvelope::decode(&unhex(expected)).expect("decode");
            assert_eq!(
                decoded
                    .decrypt(uuid(f[0]), object.id, &key, &signer.public_key_sec1())
                    .expect("decrypt"),
                object
            );
            decoded.signature[0] ^= 1;
            assert_eq!(
                decoded.decrypt(uuid(f[0]), object.id, &key, &signer.public_key_sec1()),
                Err(PrimitiveError::InvalidSignature)
            );
        }
        "crypto.recovery-display" => {
            let key = RecoveryKey::from_bytes(&unhex(input)).expect("recovery key");
            assert_eq!(key.encode_display(), expected);
            assert_eq!(RecoveryKey::parse_display(expected).expect("parse"), key);
            let mut wrong = expected.to_owned();
            wrong.pop();
            wrong.push(if expected.ends_with('0') { '1' } else { '0' });
            assert_eq!(RecoveryKey::parse_display(&wrong), Err(PrimitiveError::InvalidKey));
        }
        "crypto.recovery-blob" => {
            let f = fields(input, 4);
            let key = RecoveryKey::from_bytes(&unhex(f[0])).expect("recovery key");
            let ark = SecretBytes::new(fixed(f[2]));
            let blob = RecoveryBlob::wrap_with_nonce(
                &key,
                uuid(f[1]),
                &ark,
                SecretBytes::new(fixed(f[3])),
            )
            .expect("wrap");
            assert_eq!(hex(blob.encode().expect("encode")), expected);
            let decoded = RecoveryBlob::decode(&unhex(expected)).expect("decode");
            assert_eq!(decoded.open(&key, uuid(f[1])).expect("open"), ark);
            assert_eq!(
                decoded.open(&key, Uuid::from_bytes([0; 16])),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.shamir-split" => {
            let f = fields(input, 4);
            let secret = unhex(f[0]);
            let shares = split_shamir_with_randomness(
                &secret,
                f[1].parse().expect("threshold"),
                f[2].parse().expect("share count"),
                &unhex(f[3]),
            )
            .expect("split");
            assert_eq!(
                shares.iter().map(|share| hex(share.to_bytes())).collect::<Vec<_>>().join("|"),
                expected
            );
            let parsed: Vec<_> = expected
                .split('|')
                .map(|value| ShamirShare::from_bytes(&unhex(value)).expect("share"))
                .collect();
            assert_eq!(combine_shamir(&parsed[..2]).expect("combine").as_bytes(), secret);
            assert_eq!(
                combine_shamir(&[parsed[0].clone(), parsed[2].clone()])
                    .expect("combine")
                    .as_bytes(),
                secret
            );
            assert_eq!(
                combine_shamir(&[parsed[0].clone(), parsed[0].clone()]),
                Err(PrimitiveError::InvalidEncoding)
            );
        }
        "crypto.safety-number" => {
            let f = fields(input, 6);
            let e = fields(expected, 4);
            let left_id = uuid(f[0]);
            let left_signing = fixed(f[1]);
            let left_kem = fixed(f[2]);
            let right_id = uuid(f[3]);
            let right_signing = fixed(f[4]);
            let right_kem = fixed(f[5]);
            let left_fingerprint = safety_fingerprint(left_id, &left_signing, &left_kem);
            let right_fingerprint = safety_fingerprint(right_id, &right_signing, &right_kem);
            assert_eq!(hex(left_fingerprint), e[1]);
            assert_eq!(hex(right_fingerprint), e[2]);
            assert_eq!(
                safety_number(
                    left_id,
                    &left_signing,
                    &left_kem,
                    right_id,
                    &right_signing,
                    &right_kem,
                ),
                e[0]
            );
            assert_eq!(
                safety_qr(right_id, &right_signing, &right_kem, left_id, &left_signing, &left_kem,),
                e[3]
            );
            verify_safety_qr(
                left_id,
                &left_signing,
                &left_kem,
                right_id,
                &right_signing,
                &right_kem,
                e[3],
            )
            .expect("safety QR verifies");
            let mut tampered = e[3].to_owned();
            let last = tampered.len() - 1;
            tampered.replace_range(last.., if tampered.ends_with('0') { "1" } else { "0" });
            assert_eq!(
                verify_safety_qr(
                    left_id,
                    &left_signing,
                    &left_kem,
                    right_id,
                    &right_signing,
                    &right_kem,
                    &tampered,
                ),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.local-db-key" => {
            let f = fields(input, 7);
            let key = SecretBytes::new(fixed(f[1]));
            let params = Argon2idParams {
                memory_kib: f[2].parse().expect("memory"),
                time_cost: f[3].parse().expect("time"),
                parallelism: f[4].parse().expect("lanes"),
            };
            let wrapped = LocalDatabaseKeyEnvelope::wrap_with_parameters_and_nonce(
                &unhex(f[0]),
                &key,
                params,
                fixed(f[5]),
                SecretBytes::new(fixed(f[6])),
            )
            .expect("wrap");
            assert_eq!(hex(wrapped.encode().expect("encode")), expected);
            let decoded = LocalDatabaseKeyEnvelope::decode(&unhex(expected)).expect("decode");
            assert_eq!(decoded.open(&unhex(f[0])).expect("open"), key);
            assert_eq!(decoded.open(b"wrong"), Err(PrimitiveError::Authentication));
        }
        "crypto.escrow-account-open" => {
            let f = fields(input, 5);
            let account_id = uuid(f[0]);
            let administrator_id = uuid(f[1]);
            let recipient =
                AccountKemKeyPair::from_private_bytes(&unhex(f[2])).expect("account key");
            let wrapped = HpkeCiphertext { encapsulated_key: unhex(f[3]), ciphertext: unhex(f[4]) };
            assert_eq!(
                hex(open_escrow_share_from_account(
                    account_id,
                    administrator_id,
                    &recipient,
                    &wrapped
                )
                .expect("open")
                .to_bytes()),
                expected
            );
            let mut tampered = wrapped.clone();
            tampered.ciphertext[0] ^= 1;
            assert_eq!(
                open_escrow_share_from_account(account_id, administrator_id, &recipient, &tampered),
                Err(PrimitiveError::Authentication)
            );
            assert_eq!(
                open_escrow_share_from_account(
                    account_id,
                    Uuid::from_bytes([0; 16]),
                    &recipient,
                    &wrapped,
                ),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.escrow-device-open" => {
            let f = fields(input, 6);
            let account_id = uuid(f[0]);
            let request_id = uuid(f[1]);
            let device_signing = unhex(f[2]);
            let recipient = DeviceKemKeyPair::from_private_bytes(&unhex(f[3])).expect("device key");
            let wrapped = HpkeCiphertext { encapsulated_key: unhex(f[4]), ciphertext: unhex(f[5]) };
            assert_eq!(
                hex(open_escrow_share_from_device(
                    account_id,
                    request_id,
                    &device_signing,
                    &recipient,
                    &wrapped,
                )
                .expect("open")
                .to_bytes()),
                expected
            );
            let mut tampered = wrapped.clone();
            tampered.ciphertext[0] ^= 1;
            assert_eq!(
                open_escrow_share_from_device(
                    account_id,
                    request_id,
                    &device_signing,
                    &recipient,
                    &tampered,
                ),
                Err(PrimitiveError::Authentication)
            );
            assert_eq!(
                open_escrow_share_from_device(
                    account_id,
                    Uuid::from_bytes([0; 16]),
                    &device_signing,
                    &recipient,
                    &wrapped,
                ),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.escrow-verification" => {
            let f = fields(input, 5);
            let e = fields(expected, 3);
            let account_id = uuid(f[0]);
            let administrator_id = uuid(f[1]);
            let request_id = uuid(f[2]);
            let device_signing = unhex(f[3]);
            let device_kem = unhex(f[4]);
            assert_eq!(
                escrow_verification_code(account_id, request_id, &device_signing, &device_kem)
                    .expect("verification code"),
                e[0]
            );
            assert_eq!(hex(escrow_account_context(account_id, administrator_id)), e[1]);
            assert_eq!(
                hex(escrow_device_context(account_id, request_id, &device_signing, &device_kem,)
                    .expect("device context")),
                e[2]
            );
            verify_escrow_verification_code(
                account_id,
                request_id,
                &device_signing,
                &device_kem,
                e[0],
            )
            .expect("verification code checks");
            assert_eq!(
                verify_escrow_verification_code(
                    account_id,
                    request_id,
                    &device_signing,
                    &device_kem,
                    "0000-0000-0000-0000",
                ),
                Err(PrimitiveError::Authentication)
            );
        }
        "crypto.qr-pairing" => {
            let f = fields(input, 3);
            let pairing_id = uuid(f[0]);
            let kem = unhex(f[1]);
            let signing = unhex(f[2]);
            let payload = PairingQrPayload::new(pairing_id, &kem, &signing).expect("QR payload");
            assert_eq!(payload.encode(), expected);
            let decoded = PairingQrPayload::decode(expected).expect("QR decode");
            assert_eq!(decoded.pairing_id(), pairing_id);
            decoded.verify_public_keys(&kem, &signing).expect("relay keys match QR");
        }
        "crypto.cpace-pairing" => {
            let f = fields(input, 8);
            let e = fields(expected, 6);
            let context =
                PairingContext::new(uuid(f[0]), uuid(f[1]), uuid(f[2])).expect("pairing context");
            let code = PairingCode::from_ascii(&unhex(f[3])).expect("pairing code");
            let mut initiator_rng = VectorRng::new(unhex(f[4]));
            let (initiator_state, initiator_share) =
                PairingInitiator::start_with_rng(&context, &code, &mut initiator_rng)
                    .expect("CPace initiator");
            let mut responder_rng = VectorRng::new(unhex(f[5]));
            let (responder, responder_share) = PairingResponder::respond_with_rng(
                &context,
                &code,
                &initiator_share,
                &mut responder_rng,
            )
            .expect("CPace responder");
            let initiator = initiator_state.finish(&responder_share).expect("CPace finish");
            assert_eq!(hex(initiator_share), e[0]);
            assert_eq!(hex(responder_share), e[1]);
            assert_eq!(hex(initiator.session_id()), e[2]);
            let initiator_confirmation = initiator.confirmation().expect("initiator confirmation");
            let responder_confirmation = responder.confirmation().expect("responder confirmation");
            assert_eq!(hex(initiator_confirmation), e[3]);
            assert_eq!(hex(responder_confirmation), e[4]);
            initiator
                .verify_peer_confirmation(&responder_confirmation)
                .expect("initiator confirmation check");
            responder
                .verify_peer_confirmation(&initiator_confirmation)
                .expect("responder confirmation check");
            let frame = initiator
                .seal_frame_with_nonce(&unhex(f[7]), &XChaChaNonce::new(fixed(f[6])))
                .expect("CPace frame seal");
            assert_eq!(hex(&frame), e[5]);
            assert_eq!(
                responder.open_frame(PairingRole::Initiator, &frame).expect("CPace frame open"),
                unhex(f[7])
            );
        }
        other => panic!("unhandled crypto vector kind: {other}"),
    }
}

#[test]
fn published_crypto_known_answers() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/crypto.json");
    let document = VectorDocument::from_path(path).expect("K-2 vector document");
    let mut kinds = BTreeSet::new();
    for vector in document.vectors {
        kinds.insert(vector.kind.clone());
        fixture(&vector.kind, &vector.input, &vector.expected);
    }
    assert_eq!(
        kinds,
        BTreeSet::from(
            [
                "crypto.hkdf-sha256",
                "crypto.xchacha20poly1305",
                "crypto.p256-signature",
                "crypto.ed25519-signature",
                "crypto.hpke-account-open",
                "crypto.hpke-device-open",
                "crypto.device-key-wrap-open",
                "crypto.device-certificate",
                "crypto.device-revocation",
                "crypto.object-envelope",
                "crypto.recovery-display",
                "crypto.recovery-blob",
                "crypto.shamir-split",
                "crypto.safety-number",
                "crypto.local-db-key",
                "crypto.escrow-account-open",
                "crypto.escrow-device-open",
                "crypto.escrow-verification",
                "crypto.qr-pairing",
                "crypto.cpace-pairing",
            ]
            .map(str::to_owned)
        )
    );
}
