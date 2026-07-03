use liteseal_shared::protocol::{ClientMessage, ServerMessage};

#[test]
fn websocket_protocol_uses_tagged_json_contract() {
    let auth = ClientMessage::Auth {
        user_id: "user-1".to_string(),
        token: "token-1".to_string(),
    };
    let auth_json = serde_json::to_string(&auth).unwrap();
    assert_eq!(
        auth_json,
        r#"{"type":"auth","user_id":"user-1","token":"token-1"}"#
    );

    let message = ServerMessage::Message {
        message_id: "msg-1".to_string(),
        from: "user-1".to_string(),
        conversation_id: "conv-1".to_string(),
        ciphertext: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        sender_device_id: "device-1".to_string(),
        sender_seq: 7,
        timestamp: 1234,
    };
    let parsed: ServerMessage =
        serde_json::from_str(&serde_json::to_string(&message).unwrap()).unwrap();
    assert_eq!(parsed, message);
}
