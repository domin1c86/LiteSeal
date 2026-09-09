use liteseal_core::db::models::MessageModel;
use liteseal_desktop::{
    protocol::{dispatch, Request},
    AppState,
};
use serde_json::json;

#[tokio::test]
async fn desktop_reads_existing_core_database_and_history() {
    let state = AppState::new(":memory:").unwrap();
    let message = MessageModel {
        id: "existing-message".into(),
        conversation_id: "dm:alice:bob".into(),
        sender_id: "alice".into(),
        sender_device_id: "device".into(),
        sender_seq: 1,
        timestamp: 1,
        message_type: "text".into(),
        local_state: "delivered".into(),
        expire_at: None,
        ciphertext: vec![1, 2, 3],
        signature: vec![4; 64],
        prev_hash: vec![],
    };
    state
        .client
        .db
        .lock()
        .unwrap()
        .insert_message(&message)
        .unwrap();
    let request: Request = serde_json::from_value(json!({"id":1,"command":{
        "name":"get_local_messages","args":{"conversationId":"dm:alice:bob","limit":50,"offset":0}
    }}))
    .unwrap();
    let result = dispatch(request.command, &state).await.unwrap();
    assert_eq!(result[0]["id"], "existing-message");
    assert_eq!(result[0]["ciphertext"], json!([1, 2, 3]));
}

#[test]
fn keystore_commands_remain_available_without_touching_real_user_secrets() {
    for name in ["load_keypair", "clear_keypair"] {
        let request = json!({"id":1,"command":{"name":name,"args":{}}});
        assert!(serde_json::from_value::<Request>(request).is_ok());
    }
}

#[cfg(windows)]
#[test]
fn windows_dpapi_store_preserves_existing_encrypted_format() {
    use liteseal_core::secret_store::secret_store;
    // Use an isolated file: never read or clear the developer's actual keystore.
    let path = std::env::temp_dir().join(format!("liteseal-dpapi-{}.bin", std::process::id()));
    let store = secret_store(path.clone());
    let legacy_json = br#"{"user_id":"alice","token":"old-session"}"#;
    store.save(legacy_json).unwrap();
    assert_ne!(std::fs::read(&path).unwrap(), legacy_json);
    // A newly created desktop store opens bytes written by the unchanged core.
    let reopened = secret_store(path);
    assert_eq!(reopened.load().unwrap(), legacy_json);
    reopened.clear().unwrap();
}
