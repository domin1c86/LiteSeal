use liteseal_shared::protocol::{ClientMessage, EncryptedPayload, ServerMessage};

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
