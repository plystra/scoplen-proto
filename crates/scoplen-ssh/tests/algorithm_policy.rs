// SPDX-License-Identifier: Apache-2.0

use scoplen_ssh::{AlgorithmCategory as Category, AlgorithmPolicyError, HostAlgorithmPolicy};

#[test]
fn defaults_match_k7_preference_order_without_legacy_algorithms() {
    let policy = HostAlgorithmPolicy::default();
    let expected = [
        (
            Category::KeyExchange,
            &[
                "mlkem768x25519-sha256",
                "sntrup761x25519-sha512",
                "curve25519-sha256",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group16-sha512",
                "diffie-hellman-group18-sha512",
            ][..],
        ),
        (
            Category::HostKey,
            &[
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "sk-ssh-ed25519@openssh.com",
                "sk-ecdsa-sha2-nistp256@openssh.com",
                "rsa-sha2-512",
                "rsa-sha2-256",
                "ssh-ed25519-cert-v01@openssh.com",
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                "ecdsa-sha2-nistp521-cert-v01@openssh.com",
                "sk-ssh-ed25519-cert-v01@openssh.com",
                "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
                "rsa-sha2-512-cert-v01@openssh.com",
                "rsa-sha2-256-cert-v01@openssh.com",
            ][..],
        ),
        (
            Category::Cipher,
            &[
                "chacha20-poly1305@openssh.com",
                "aes256-gcm@openssh.com",
                "aes128-gcm@openssh.com",
                "aes256-ctr",
                "aes192-ctr",
                "aes128-ctr",
            ][..],
        ),
        (
            Category::Mac,
            &[
                "hmac-sha2-512-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com",
                "umac-128-etm@openssh.com",
            ][..],
        ),
        (Category::Compression, &["none", "zlib@openssh.com"][..]),
    ];

    for (category, names) in expected {
        assert_eq!(policy.offers(category), names);
    }
}

#[test]
fn legacy_opt_in_is_local_to_one_host_and_preserves_modern_preference() {
    let legacy = [
        (Category::KeyExchange, "diffie-hellman-group14-sha256"),
        (Category::HostKey, "ssh-rsa"),
        (Category::Cipher, "aes128-cbc"),
        (Category::Mac, "hmac-sha1"),
        (Category::Compression, "zlib"),
    ];
    let enabled = HostAlgorithmPolicy::with_legacy(&legacy).unwrap();
    let other_host = HostAlgorithmPolicy::default();

    for (category, name) in legacy {
        assert_eq!(enabled.offers(category).last(), Some(&name));
        assert!(!other_host.offers(category).contains(&name));
        assert_eq!(other_host.select_client_preference(category, &[name]), None);
    }
    assert_eq!(
        enabled.select_client_preference(
            Category::KeyExchange,
            &["diffie-hellman-group14-sha256", "curve25519-sha256"]
        ),
        Some("curve25519-sha256")
    );
}

#[test]
fn legacy_catalog_accepts_every_documented_name() {
    let legacy = [
        (Category::KeyExchange, "diffie-hellman-group14-sha256"),
        (Category::KeyExchange, "diffie-hellman-group14-sha1"),
        (Category::KeyExchange, "diffie-hellman-group-exchange-sha256"),
        (Category::HostKey, "ssh-rsa"),
        (Category::HostKey, "ssh-rsa-cert-v01@openssh.com"),
        (Category::Cipher, "aes256-cbc"),
        (Category::Cipher, "aes192-cbc"),
        (Category::Cipher, "aes128-cbc"),
        (Category::Cipher, "3des-cbc"),
        (Category::Mac, "hmac-sha2-512"),
        (Category::Mac, "hmac-sha2-256"),
        (Category::Mac, "hmac-sha1"),
        (Category::Compression, "zlib"),
    ];
    let policy = HostAlgorithmPolicy::with_legacy(&legacy).unwrap();
    for (category, name) in legacy {
        assert!(policy.offers(category).contains(&name));
    }
}

#[test]
fn invalid_legacy_configuration_is_rejected() {
    let cases = [
        (Category::Cipher, "aes128-ctrr"),
        (Category::Cipher, "ssh-rsa"),
        (Category::Cipher, "aes256-gcm@openssh.com"),
        (Category::Cipher, "AES128-CBC"),
        (Category::KeyExchange, "ext-info-c"),
    ];
    for (category, algorithm) in cases {
        assert_eq!(
            HostAlgorithmPolicy::with_legacy(&[(category, algorithm)]),
            Err(AlgorithmPolicyError::NotLegacy { category, algorithm: algorithm.to_owned() })
        );
    }
    assert_eq!(
        HostAlgorithmPolicy::with_legacy(&[(Category::Cipher, "aes128-cbc"); 2]),
        Err(AlgorithmPolicyError::Duplicate {
            category: Category::Cipher,
            algorithm: "aes128-cbc".to_owned(),
        })
    );
}

#[test]
fn selection_uses_local_order_and_never_promotes_unknown_peer_names() {
    let default = HostAlgorithmPolicy::default();
    assert_eq!(
        default
            .select_client_preference(Category::Cipher, &["aes128-ctr", "aes256-gcm@openssh.com"]),
        Some("aes256-gcm@openssh.com")
    );
    assert_eq!(
        default.select_client_preference(Category::Cipher, &["aes128-cbc", "unknown"]),
        None
    );
    assert_eq!(default.select_client_preference(Category::Cipher, &[]), None);

    let enabled = HostAlgorithmPolicy::with_legacy(&[(Category::Cipher, "aes128-cbc")]).unwrap();
    assert_eq!(
        enabled.select_client_preference(Category::Cipher, &["aes128-cbc"]),
        Some("aes128-cbc")
    );
}
