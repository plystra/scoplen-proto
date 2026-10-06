// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = scoplen_crypto::DeviceCertificate::decode(bytes);
    let _ = scoplen_crypto::LocalDatabaseKeyEnvelope::decode(bytes);
    let _ = scoplen_crypto::ObjectEnvelope::decode(bytes);
    let _ = scoplen_crypto::RecoveryBlob::decode(bytes);
    let _ = scoplen_crypto::RevocationStatement::decode(bytes);
    let _ = scoplen_crypto::ShamirShare::from_bytes(bytes);

    let text = String::from_utf8_lossy(bytes);
    let _ = scoplen_crypto::RecoveryKey::parse_display(&text);
});
