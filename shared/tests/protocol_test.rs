use liteseal_shared::{
    crypto,
    protocol::{ClientMessage, EncryptedPayload, ServerMessage, SignedEnvelopeV2, PROTOCOL_V2},
};

fn envelope() -> SignedEnvelopeV2 {
    SignedEnvelopeV2 {
        protocol_version: PROTOCOL_V2,
        message_id: "018f47d2-2527-7dd0-8d24-24fd3ba26706".to_string(),
        conversation_id: "alice:bob".to_string(),
        sender_user_id: "alice".to_string(),
        sender_device_id: "alice-windows".to_string(),
        recipient_user_id: "bob".to_string(),
        recipient_device_id: "bob-windows".to_string(),
        sender_seq: 1,
        prev_hash: Vec::new(),
        sent_at: 1_725_000_000,
        message_type: "text".to_string(),
        ciphertext: vec![1, 2, 3, 4],
        signature: Vec::new(),
    }
}

#[test]
fn websocket_protocol_uses_tagged_json_contract() {
    let auth = ClientMessage::Auth {
        user_id: "user-1".to_string(),
        token: "token-1".to_string(),
        device_id: "device-1".to_string(),
    };
    let auth_json = serde_json::to_string(&auth).unwrap();
    assert_eq!(
        auth_json,
        r#"{"type":"auth","user_id":"user-1","token":"token-1","device_id":"device-1"}"#
    );

    let send = ClientMessage::Send {
        message_id: "msg-1".to_string(),
        conversation_id: "conv-1".to_string(),
        ciphertext: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        sender_device_id: "device-1".to_string(),
        sender_seq: 7,
        prev_hash: vec![0; 32],
        payloads: vec![EncryptedPayload {
            recipient_user_id: "user-2".to_string(),
            recipient_device_id: "device-2".to_string(),
            ciphertext: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        }],
    };
    let send_json = serde_json::to_string(&send).unwrap();
    assert!(send_json.contains(r#""payloads":[{"recipient_user_id":"user-2""#));
    assert!(send_json.contains(r#""prev_hash":[0,0,0"#));

    let message = ServerMessage::Message {
        message_id: "msg-1".to_string(),
        from: "user-1".to_string(),
        conversation_id: "conv-1".to_string(),
        ciphertext: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        sender_device_id: "device-1".to_string(),
        sender_seq: 7,
        prev_hash: vec![0; 32],
        recipient_device_id: "device-2".to_string(),
        timestamp: 1234,
    };
    let parsed: ServerMessage =
        serde_json::from_str(&serde_json::to_string(&message).unwrap()).unwrap();
    assert_eq!(parsed, message);

    let offline = ServerMessage::Offline {
        message_id: "msg-1".to_string(),
        to: "user-2".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&offline).unwrap(),
        r#"{"type":"offline","message_id":"msg-1","to":"user-2"}"#
    );
}

#[test]
fn v2_signing_is_deterministic_and_domain_separated() {
    let first = envelope().signing_bytes().unwrap();
    let second = envelope().signing_bytes().unwrap();

    assert_eq!(first, second);
    assert!(first.starts_with(b"LiteSeal SignedEnvelopeV2\0"));
}

#[test]
fn v2_signature_covers_every_envelope_field() {
    let keys = crypto::generate_keypair().unwrap();
    let original = envelope();
    let signature = crypto::sign(&original.signing_bytes().unwrap(), &keys.ed25519_sk).unwrap();

    let mut mutations = Vec::new();
    let mut value = original.clone();
    value.protocol_version = 3;
    mutations.push(value);
    let mut value = original.clone();
    value.message_id.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.conversation_id.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.sender_user_id.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.sender_device_id.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.recipient_user_id.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.recipient_device_id.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.sender_seq += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.prev_hash.push(1);
    mutations.push(value);
    let mut value = original.clone();
    value.sent_at += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.message_type.push('x');
    mutations.push(value);
    let mut value = original.clone();
    value.ciphertext.push(5);
    mutations.push(value);

    for mutation in mutations {
        assert!(!crypto::verify_with_public_key(
            &mutation.signing_bytes().unwrap(),
            &signature,
            &keys.ed25519_pk,
        )
        .unwrap());
    }
}

#[test]
fn v1_and_v2_wire_messages_round_trip() {
    let v1_json = r#"{"type":"ack","message_id":"legacy","recipient_device_id":"device-1"}"#;
    let parsed_v1: ClientMessage = serde_json::from_str(v1_json).unwrap();
    assert!(matches!(parsed_v1, ClientMessage::Ack { .. }));

    let v2 = ClientMessage::SendV2 {
        envelopes: vec![envelope()],
    };
    let v2_json = serde_json::to_string(&v2).unwrap();
    let parsed_v2: ClientMessage = serde_json::from_str(&v2_json).unwrap();
    assert_eq!(parsed_v2, v2);
}
