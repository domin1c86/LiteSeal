#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    db::models::{ContactModel, MessageModel},
    keystore::KeystoreData,
};
use liteseal_desktop::{commands::backup, AppState};
use liteseal_shared::crypto;
use std::time::Duration;
async fn complete(state: &AppState, id: &str) -> backup::JobView {
    for _ in 0..1000 {
        let view = backup::status(state, id).unwrap();
        if view.state != "running" {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("backup task did not terminate");
}
#[tokio::test]
async fn jobs_restore_token_free_paginated_offline_history_and_invalidated_handles() {
    let root = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let state = AppState::with_device_protection(
        root.0.join("source.db").to_str().unwrap(),
        Some(root.0.join("source.bin")),
        liteseal_core::trusted_devices::witness::platform::Protection::isolated_test(),
    )
    .unwrap();
    let keys = crypto::generate_keypair().unwrap();
    let peer = crypto::generate_keypair().unwrap();
    state
        .save_identity(KeystoreData {
            user_id: "alice".into(),
            device_id: "device".into(),
            server_url: "http://127.0.0.1:9".into(),
            token: "token-never-exported".into(),
            refresh_token: "refresh-never-exported".into(),
            public_key: keys.public_key.to_vec(),
            secret_key: keys.secret_key.to_vec(),
            ed25519_pk: keys.ed25519_pk.to_vec(),
            ed25519_sk: keys.ed25519_sk.to_vec(),
        })
        .unwrap();
    {
        let db = state.client.db.lock().unwrap();
        db.insert_contact(&ContactModel {
            user_id: "bob".into(),
            username: "Bob".into(),
            public_key: peer.public_key.to_vec(),
            ed25519_pk: Some(peer.ed25519_pk.to_vec()),
            trust_state: "verified".into(),
            fingerprint: "fingerprint".into(),
            key_changed: false,
            added_at: 1,
        })
        .unwrap();
        for n in 0..60 {
            let cipher = crypto::encrypt(
                format!("offline 中文 🦭 {n}").as_bytes(),
                &keys.public_key,
                &peer.secret_key,
            )
            .unwrap();
            db.insert_message(&MessageModel {
                id: format!("msg-{n}"),
                conversation_id: "dm:alice:bob".into(),
                sender_id: "bob".into(),
                sender_device_id: "bob-device".into(),
                sender_seq: n + 1,
                timestamp: n,
                message_type: "text".into(),
                local_state: "received".into(),
                expire_at: None,
                ciphertext: cipher,
                signature: vec![0; 64],
                prev_hash: vec![],
            })
            .unwrap();
        }
        db.delete_message_locally("alice", "dm:alice:bob", "msg-59")
            .unwrap();
    }
    let path = root.0.join("history.lseal").to_str().unwrap().to_string();
    let secret = "independent backup password".to_string();
    let id = backup::start_export(&state, path.clone(), secret.clone(), false).unwrap();
    let view = complete(&state, &id).await;
    assert_eq!(view.state, "completed", "{:?}", view.error);
    assert!(!view.restorable);
    let restored = backup::start_restore(
        &state,
        path.clone(),
        root.0.to_str().unwrap().into(),
        secret,
    )
    .unwrap();
    let view = complete(&state, &restored).await;
    assert_eq!(view.state, "completed", "{:?}", view.error);
    assert!(view.restorable);
    let info = backup::open(&state, &restored).unwrap();
    assert!(info.get("secret_key").is_none());
    assert!(info.get("token").is_none());
    assert_eq!(info["user_id"], "alice");
    let conversations = backup::conversations(&state, &restored, None).unwrap();
    assert_eq!(conversations["items"][0]["name"], "Bob");
    let page = backup::page(
        &state,
        &restored,
        "direct",
        "dm:alice:bob",
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(page["messages"].as_array().unwrap().len(), 50);
    assert!(page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["id"] != "msg-59"));
    let earlier = backup::page(
        &state,
        &restored,
        "direct",
        "dm:alice:bob",
        page["next"]["time"].as_i64(),
        page["next"]["id"].as_str(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(earlier["messages"].as_array().unwrap().len(), 9);
    assert!(earlier["next"].is_null());
    assert!(earlier["messages"][0]["text"]
        .as_str()
        .unwrap()
        .contains("中文 🦭"));
    assert!(backup::page(
        &state,
        &restored,
        "direct",
        "dm:bob:mallory",
        None,
        None,
        None,
        None
    )
    .is_err());
    backup::reset(&state).unwrap();
    assert!(backup::info(&state, &restored).is_err());
    assert_eq!(state.identity().unwrap().token, "token-never-exported");
    assert!(std::path::Path::new(&path).exists());
    let cancelled = backup::start_restore(
        &state,
        path,
        root.0.to_str().unwrap().into(),
        "independent backup password".into(),
    )
    .unwrap();
    backup::cancel(&state, &cancelled).unwrap();
    assert_eq!(complete(&state, &cancelled).await.state, "cancelled");
    assert!(backup::open(&state, &cancelled).is_err());
}
