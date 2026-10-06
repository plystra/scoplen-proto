// SPDX-License-Identifier: Apache-2.0

use scoplen_ssh::{
    AlgorithmCategory, HostAlgorithmPolicy, KeyExchangeFamily, StrictKexError, StrictKexPacket,
    StrictKexPhase, StrictKeyExchange, TransportDirection, TransportNegotiationError,
    TransportOffer, TransportRole,
};

#[test]
fn offers_add_role_specific_extensions_after_the_k7_algorithms() {
    let policy = HostAlgorithmPolicy::default();
    let client = TransportOffer::from_policy(TransportRole::Client, &policy);
    let server = TransportOffer::from_policy(TransportRole::Server, &policy);

    assert_eq!(
        client.key_exchange.last().map(String::as_str),
        Some("kex-strict-c-v00@openssh.com")
    );
    assert_eq!(
        server.key_exchange.last().map(String::as_str),
        Some("kex-strict-s-v00@openssh.com")
    );
    assert_eq!(client.key_exchange[8], "ext-info-c");
    assert_eq!(server.key_exchange[8], "ext-info-s");
    assert_eq!(client.host_key[0], "ssh-ed25519-cert-v01@openssh.com");
    assert!(!client.key_exchange.contains(&"ssh-rsa".to_owned()));
}

#[test]
fn negotiation_uses_local_preference_and_requires_common_algorithms() {
    let policy = HostAlgorithmPolicy::default();
    let client = TransportOffer::from_policy(TransportRole::Client, &policy);
    let server = TransportOffer::from_policy(TransportRole::Server, &policy);
    let negotiated = client.negotiate(&server).expect("default offers intersect");

    assert_eq!(negotiated.key_exchange, "mlkem768x25519-sha256");
    assert_eq!(negotiated.host_key, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(negotiated.cipher_client_to_server, "chacha20-poly1305@openssh.com");
    assert_eq!(negotiated.mac_server_to_client, "hmac-sha2-512-etm@openssh.com");
    assert_eq!(negotiated.compression_client_to_server, "none");
    assert!(negotiated.strict_kex);
    assert!(negotiated.ext_info);

    let mut no_host_key = server.clone();
    no_host_key.host_key = vec!["unsupported-host-key".to_owned()];
    assert_eq!(
        client.negotiate(&no_host_key),
        Err(TransportNegotiationError::NoCommonAlgorithm { category: AlgorithmCategory::HostKey })
    );

    let mut no_strict = server;
    no_strict.key_exchange.retain(|name| !name.starts_with("kex-strict"));
    let negotiated = client.negotiate(&no_strict).expect("strict KEX is optional");
    assert!(!negotiated.strict_kex);
    assert!(negotiated.ext_info);
}

#[test]
fn strict_kex_rejects_non_kex_messages_and_resets_each_direction() {
    let mut state = StrictKeyExchange::new(true, KeyExchangeFamily::Ecdh);
    assert_eq!(
        state.on_receive(StrictKexPacket::Other(2)),
        Err(StrictKexError::FirstPacketMustBeKexInit {
            direction: TransportDirection::Receive,
            packet: StrictKexPacket::Other(2),
        })
    );

    assert_eq!(state.on_send(StrictKexPacket::KexInit), Ok(0));
    assert_eq!(state.on_receive(StrictKexPacket::KexInit), Ok(0));
    assert_eq!(state.on_send(StrictKexPacket::KexEcdhInit), Ok(1));
    assert_eq!(state.on_receive(StrictKexPacket::KexEcdhReply), Ok(1));
    assert_eq!(state.on_send(StrictKexPacket::NewKeys), Ok(2));
    assert_eq!(state.send_sequence(), 0);
    assert_eq!(
        state.on_receive(StrictKexPacket::ExtInfo),
        Err(StrictKexError::UnexpectedPacket {
            phase: StrictKexPhase::Initial,
            packet: StrictKexPacket::ExtInfo,
        })
    );
    assert_eq!(state.on_receive(StrictKexPacket::NewKeys), Ok(2));
    assert_eq!(state.phase(), StrictKexPhase::Established);
    assert_eq!(state.receive_sequence(), 0);
    assert_eq!(state.on_receive(StrictKexPacket::ExtInfo), Ok(0));
}

#[test]
fn strict_kex_rejects_wrong_or_repeated_messages_and_requires_rekey_boundary() {
    let mut state = StrictKeyExchange::new(true, KeyExchangeFamily::Ecdh);
    assert_eq!(state.on_send(StrictKexPacket::KexInit), Ok(0));
    assert_eq!(
        state.on_send(StrictKexPacket::KexInit),
        Err(StrictKexError::KexMessageRepeated {
            direction: TransportDirection::Send,
            packet: StrictKexPacket::KexInit,
        })
    );
    assert_eq!(
        state.on_send(StrictKexPacket::KexDhInit),
        Err(StrictKexError::KexMessageNotAllowed {
            family: KeyExchangeFamily::Ecdh,
            packet: StrictKexPacket::KexDhInit,
        })
    );
    assert_eq!(
        state.begin_rekey(),
        Err(StrictKexError::RekeyBeforeEstablished { phase: StrictKexPhase::Initial })
    );
}

#[test]
fn strict_kex_applies_again_after_rekey() {
    let mut state = StrictKeyExchange::new(true, KeyExchangeFamily::Ecdh);
    for direction in [TransportDirection::Send, TransportDirection::Receive] {
        let result = match direction {
            TransportDirection::Send => state.on_send(StrictKexPacket::KexInit),
            TransportDirection::Receive => state.on_receive(StrictKexPacket::KexInit),
        };
        assert_eq!(result, Ok(0));
    }
    assert_eq!(state.on_send(StrictKexPacket::KexEcdhInit), Ok(1));
    assert_eq!(state.on_receive(StrictKexPacket::KexEcdhReply), Ok(1));
    assert_eq!(state.on_send(StrictKexPacket::NewKeys), Ok(2));
    assert_eq!(state.on_receive(StrictKexPacket::NewKeys), Ok(2));
    assert_eq!(state.phase(), StrictKexPhase::Established);

    state.begin_rekey().expect("initial KEX is complete");
    assert_eq!(
        state.on_send(StrictKexPacket::Other(2)),
        Err(StrictKexError::FirstPacketMustBeKexInit {
            direction: TransportDirection::Send,
            packet: StrictKexPacket::Other(2)
        })
    );
    assert_eq!(state.on_send(StrictKexPacket::KexInit), Ok(0));
}

#[test]
fn key_exchange_family_classification_covers_k7_methods() {
    assert_eq!(
        KeyExchangeFamily::for_algorithm("mlkem768x25519-sha256"),
        Some(KeyExchangeFamily::Hybrid)
    );
    assert_eq!(
        KeyExchangeFamily::for_algorithm("sntrup761x25519-sha512"),
        Some(KeyExchangeFamily::Ecdh)
    );
    assert_eq!(
        KeyExchangeFamily::for_algorithm("diffie-hellman-group-exchange-sha256"),
        Some(KeyExchangeFamily::GroupExchange)
    );
    assert_eq!(KeyExchangeFamily::for_algorithm("unknown"), None);
}
