#![cfg(windows)]
use liteseal_core::{backup::WorkDirectory, keystore::KeystoreData};
use liteseal_desktop::{commands::device_control, protocol::Command, AppState};
use liteseal_shared::crypto;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn device_business_commands_reject_secret_fields_and_unconfirmed_revoke() {
    for command in [
        serde_json::json!({"name":"get_device_control","args":{"secretKey":[0]}}),
        serde_json::json!({"name":"prepare_device_challenge","args":{"requestId":"id","confirmedFingerprint":"fp","token":"secret"}}),
        serde_json::json!({"name":"prepare_device_revoke","args":{}}),
        serde_json::json!({"name":"device_task_step","args":{"id":"id","password":"secret"}}),
    ] {
        assert!(serde_json::from_value::<Command>(command).is_err());
    }
}

#[tokio::test]
async fn desktop_suspension_rejects_late_results_and_token_rotation_cannot_unlock() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = Arc::new(
        AppState::with_device_protection(
            work.0.join("test.db").to_str().unwrap(),
            Some(work.0.join("test.bin")),
            liteseal_core::trusted_devices::witness::platform::Protection::isolated_test(),
        )
        .unwrap(),
    );
    let keys = crypto::generate_keypair().unwrap();
    let mut identity = KeystoreData {
        user_id: uuid::Uuid::new_v4().to_string(),
        device_id: uuid::Uuid::new_v4().to_string(),
        server_url: format!("http://{}", listener.local_addr().unwrap()),
        token: "isolated-access".into(),
        refresh_token: "isolated-refresh".into(),
        public_key: keys.public_key.to_vec(),
        secret_key: keys.secret_key.to_vec(),
        ed25519_pk: keys.ed25519_pk.to_vec(),
        ed25519_sk: keys.ed25519_sk.to_vec(),
    };
    state.save_identity(identity.clone()).unwrap();
    let ready = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let signal = ready.clone();
    let finish = release.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        let mut chunk = [0; 2048];
        while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        signal.notify_one();
        finish.notified().await;
        socket
            .write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
    });
    let active = state.clone();
    let pending = tokio::spawn(async move { device_control::snapshot(&active).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), ready.notified())
        .await
        .unwrap();
    device_control::suspend(&state).unwrap();
    identity.token = "renewed-isolated-access".into();
    state.save_identity(identity).unwrap();
    assert!(device_control::snapshot(&state)
        .await
        .unwrap_err()
        .contains("暂停"));
    device_control::resume(&state).unwrap();
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    server.await.unwrap();
    state.clear_identity().unwrap();
    assert!(device_control::snapshot(&state).await.is_err());
}
