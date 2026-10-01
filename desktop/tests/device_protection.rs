#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    keystore::KeystoreData,
    trusted_devices::{
        profiles::JoinProfileStore, witness::platform::Protection, DeviceTrustStore,
    },
};
use liteseal_desktop::{
    commands::{device_control, device_join},
    AppState,
};
use liteseal_shared::{crypto, trusted_device::*};
use std::{fs, path::Path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
fn state(path: &Path, protection: &Protection) -> AppState {
    AppState::with_device_protection(
        path.join("normal.db").to_str().unwrap(),
        Some(path.join("normal.bin")),
        protection.clone(),
    )
    .unwrap()
}
#[test]
fn joining_default_commands_reject_restored_active_task_and_keep_other_profile_usable() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let app = state(&work.0, &protection);
    let first = device_join::create(
        &app,
        "http://127.0.0.1:9".into(),
        "Alice".into(),
        "first".into(),
    )
    .unwrap();
    let second = device_join::create(
        &app,
        "http://127.0.0.1:9".into(),
        "Bob".into(),
        "second".into(),
    )
    .unwrap();
    let store = JoinProfileStore::new(work.0.join("join-profiles"));
    let path = store.database(&first.profile.id).unwrap();
    let keyfile = path.parent().unwrap().join("identity.bin");
    let keybytes = fs::read(&keyfile).unwrap();
    device_control::suspend(&app).unwrap();
    let old = work.0.join("old.db");
    fs::copy(&path, &old).unwrap();
    device_control::resume(&app).unwrap();
    let abandoned = device_join::abandon(&app, first.profile.id.clone()).unwrap();
    assert!(abandoned.join.local_abandonment);
    device_control::suspend(&app).unwrap();
    drop(app);
    fs::copy(&old, &path).unwrap();
    let app = state(&work.0, &protection);
    let error = device_join::snapshot(&app, first.profile.id.clone())
        .err()
        .unwrap();
    assert!(error.contains("安全状态"), "{error}");
    assert!(device_join::abandon(&app, first.profile.id.clone()).is_err());
    assert!(device_join::forget(&app, first.profile.id).is_err());
    assert_eq!(fs::read(keyfile).unwrap(), keybytes);
    let other = device_join::snapshot(&app, second.profile.id).unwrap();
    assert_eq!(other.join.task.id, second.join.task.id);
    assert!(!other.messaging_enabled);
    assert!(!work.0.join("normal.bin").exists());
}
#[tokio::test]
async fn original_default_commands_reject_directory_rollback_before_network_query() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        let mut buf = [0; 2048];
        while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
        }
        socket
            .write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
    });
    let root = crypto::generate_keypair().unwrap();
    let second = crypto::generate_keypair().unwrap();
    let identity = KeystoreData {
        user_id: uuid::Uuid::new_v4().to_string(),
        device_id: uuid::Uuid::new_v4().to_string(),
        server_url: url.clone(),
        token: "synthetic".into(),
        refresh_token: "synthetic".into(),
        public_key: root.public_key.to_vec(),
        secret_key: root.secret_key.to_vec(),
        ed25519_pk: root.ed25519_pk.to_vec(),
        ed25519_sk: root.ed25519_sk.to_vec(),
    };
    let app = state(&work.0, &protection);
    app.save_identity(identity.clone()).unwrap();
    assert!(!device_control::snapshot(&app).await.unwrap().supported);
    server.await.unwrap();
    drop(app);
    let path = work.0.join("normal.db");
    let old = work.0.join("old.db");
    fs::copy(&path, &old).unwrap();
    let keybytes = fs::read(work.0.join("normal.bin")).unwrap();
    let anchor = Anchor {
        origin: url,
        account: identity.user_id.clone(),
        root: DeviceIdentity::from_keys(identity.device_id, &root),
    };
    let mut trust = DeviceTrustStore::open(&path).unwrap();
    trust.protect(protection.witness(&path).unwrap()).unwrap();
    let initial = trust.pin(&anchor).unwrap();
    let intent = make_intent(
        &anchor,
        "join".into(),
        "second".into(),
        crypto::random_challenge().unwrap(),
        1000,
        &second,
    )
    .unwrap();
    let challenge = make_challenge(&initial, &intent, 1001, &root).unwrap();
    let proof = answer_challenge(&initial, &intent, &challenge, 1002, &second).unwrap();
    let event = make_event(
        &initial,
        "grant".into(),
        DeviceAction::Grant {
            intent: Box::new(intent),
            challenge: Box::new(challenge),
            proof,
        },
        1003,
        &root,
    )
    .unwrap();
    trust
        .append_live(
            &anchor,
            &liteseal_core::trusted_devices::Checkpoint::from_state(&initial),
            &[event],
            1004,
        )
        .unwrap();
    drop(trust);
    fs::copy(&old, &path).unwrap();
    let app = state(&work.0, &protection);
    let error = device_control::snapshot(&app).await.err().unwrap();
    assert!(error.contains("安全状态"), "{error}");
    assert_eq!(fs::read(work.0.join("normal.bin")).unwrap(), keybytes);
    assert!(device_control::discard(&app, "missing".into()).is_err());
}
