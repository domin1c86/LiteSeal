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
fn identity_commands_never_accept_secret_keys() {
    for name in ["load_identity", "prepare_identity", "clear_keypair"] {
        let request = json!({"id":1,"command":{"name":name,"args":{}}});
        assert!(serde_json::from_value::<Request>(request).is_ok());
    }
    for (name, args) in [
        (
            "encrypt_message",
            json!({"plaintext":[1],"recipientPublicKey":[2],"senderSecretKey":[3]}),
        ),
        ("sign_message", json!({"message":[1],"signingKey":[2]})),
        (
            "save_session",
            json!({"userId":"a","token":"t","refreshToken":"r","deviceId":"d","serverUrl":"s","secret_key":[1]}),
        ),
    ] {
        let request = json!({"id":1,"command":{"name":name,"args":args}});
        assert!(
            serde_json::from_value::<Request>(request).is_err(),
            "{name}"
        );
    }
}

#[cfg(windows)]
#[tokio::test]
async fn identity_secrets_stay_in_the_sidecar() {
    // An isolated keystore file: the developer's real identity is never read.
    let path = std::env::temp_dir().join(format!("liteseal-identity-{}.bin", uuid::Uuid::new_v4()));
    let state = AppState::with_keystore(":memory:", Some(path.clone())).unwrap();
    let call = |name: &str, args: serde_json::Value| {
        serde_json::from_value::<Request>(json!({"id":1,"command":{"name":name,"args":args}}))
            .unwrap()
            .command
    };
    let prepared = dispatch(call("prepare_identity", json!({})), &state)
        .await
        .unwrap();
    assert_eq!(prepared["saved"], false);
    assert!(prepared.get("secret_key").is_none() && prepared.get("ed25519_sk").is_none());
    let again = dispatch(call("prepare_identity", json!({})), &state)
        .await
        .unwrap();
    assert_eq!(again["public_key"], prepared["public_key"]);

    let session = json!({"userId":"alice","token":"t","refreshToken":"r","deviceId":"d","serverUrl":"http://localhost:3000"});
    dispatch(call("save_session", session), &state)
        .await
        .unwrap();
    let loaded = dispatch(call("load_identity", json!({})), &state)
        .await
        .unwrap();
    assert_eq!(
        (loaded["saved"].clone(), loaded["public_key"].clone()),
        (json!(true), prepared["public_key"].clone())
    );

    let plaintext = json!([1, 2, 3]);
    let ciphertext = dispatch(
        call(
            "encrypt_message",
            json!({"plaintext":plaintext,"recipientPublicKey":loaded["public_key"]}),
        ),
        &state,
    )
    .await
    .unwrap();
    let decrypted = dispatch(
        call(
            "decrypt_message",
            json!({"ciphertext":ciphertext,"senderPublicKey":loaded["public_key"]}),
        ),
        &state,
    )
    .await
    .unwrap();
    assert_eq!(decrypted, plaintext);
    let signature = dispatch(call("sign_message", json!({"message":plaintext})), &state)
        .await
        .unwrap();
    let valid = dispatch(call("verify_message", json!({"message":plaintext,"signature":signature,"senderPublicKey":loaded["ed25519_pk"]})), &state).await.unwrap();
    assert_eq!(valid, true);

    let other = json!({"userId":"mallory","token":"t","refreshToken":"r","deviceId":"d","serverUrl":"http://localhost:3000"});
    assert!(dispatch(call("save_session", other), &state).await.is_err());
    // A fresh process sees the same identity.
    let reopened = AppState::with_keystore(":memory:", Some(path.clone())).unwrap();
    let reloaded = dispatch(call("load_identity", json!({})), &reopened)
        .await
        .unwrap();
    assert_eq!(reloaded["public_key"], prepared["public_key"]);
    dispatch(call("clear_keypair", json!({})), &reopened)
        .await
        .unwrap();
    assert!(!path.exists());
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
