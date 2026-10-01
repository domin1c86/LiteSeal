#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    keystore::KeystoreData,
    trusted_devices::{profiles::JoinProfileStore, tasks::TaskPhase},
};
use liteseal_desktop::{
    commands::{device_control, device_join},
    protocol::Command,
    AppState,
};
use liteseal_shared::{crypto, trusted_device::*};
use std::{fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
fn state(work: &WorkDirectory) -> AppState {
    AppState::with_keystore(
        work.0.join("normal.db").to_str().unwrap(),
        Some(work.0.join("normal.bin")),
    )
    .unwrap()
}
async fn headers(socket: &mut TcpStream) -> Vec<u8> {
    let mut out = vec![];
    let mut buf = [0; 4096];
    while !out.windows(4).any(|v| v == b"\r\n\r\n") {
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0);
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[test]
fn join_commands_reject_secrets_paths_and_keep_existing_identity_through_lifecycle() {
    for bad in [
        serde_json::json!({"name":"create_device_join_profile","args":{"origin":"http://localhost","username":"Alice","deviceName":"one","secretKey":[0]}}),
        serde_json::json!({"name":"device_join_step","args":{"profileId":"id","token":"secret"}}),
        serde_json::json!({"name":"forget_device_join_profile","args":{"profileId":"id","path":"arbitrary"}}),
    ] {
        assert!(serde_json::from_value::<Command>(bad).is_err());
    }
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let state = state(&work);
    let keys = crypto::generate_keypair().unwrap();
    let mut original = KeystoreData {
        user_id: uuid::Uuid::new_v4().to_string(),
        device_id: uuid::Uuid::new_v4().to_string(),
        server_url: "http://127.0.0.1:9".into(),
        token: "isolated-original".into(),
        refresh_token: "isolated-refresh".into(),
        public_key: keys.public_key.to_vec(),
        secret_key: keys.secret_key.to_vec(),
        ed25519_pk: keys.ed25519_pk.to_vec(),
        ed25519_sk: keys.ed25519_sk.to_vec(),
    };
    state.save_identity(original.clone()).unwrap();
    let original_bytes = fs::read(work.0.join("normal.bin")).unwrap();
    let view = device_join::create(
        &state,
        "http://127.0.0.1:9".into(),
        "Alice".into(),
        "new Windows 🦭".into(),
    )
    .unwrap();
    let id = view.profile.id.clone();
    let request = view.join.task.id.clone();
    let fingerprint = view.profile.encryption_fingerprint.clone();
    assert!(!view.messaging_enabled);
    assert_eq!(view.join.task.phase, TaskPhase::Draft);
    let public = serde_json::to_string(&view).unwrap();
    for field in ["secret_key", "ed25519_sk", "token", "password", "path"] {
        assert!(!public.contains(field));
    }
    assert!(state.identity().unwrap().secret_key == keys.secret_key);
    assert_eq!(fs::read(work.0.join("normal.bin")).unwrap(), original_bytes);
    assert!(device_join::snapshot(&state, "../normal".into()).is_err());
    assert!(device_join::forget(&state, id.clone()).is_err());
    device_control::suspend(&state).unwrap();
    original.token = "rotated-isolated".into();
    state.save_identity(original).unwrap();
    assert!(device_join::list(&state).is_err());
    assert!(device_join::create(
        &state,
        "http://127.0.0.1:9".into(),
        "Bob".into(),
        "blocked".into()
    )
    .is_err());
    device_control::resume(&state).unwrap();
    let reopened = device_join::snapshot(&state, id.clone()).unwrap();
    assert_eq!(reopened.join.task.id, request);
    assert_eq!(reopened.profile.encryption_fingerprint, fingerprint);
    let abandoned = device_join::abandon(&state, id.clone()).unwrap();
    assert!(abandoned.join.local_abandonment);
    assert_eq!(abandoned.join.task.phase, TaskPhase::Cancelled);
    assert_eq!(
        device_join::abandon(&state, id.clone())
            .unwrap()
            .join
            .task
            .revision,
        abandoned.join.task.revision
    );
    device_join::forget(&state, id.clone()).unwrap();
    device_join::forget(&state, id).unwrap();
    assert!(device_join::list(&state).unwrap().is_empty());
    assert!(state.identity().unwrap().secret_key == keys.secret_key);
    let broken = device_join::create(
        &state,
        "http://127.0.0.1:9".into(),
        "Alice".into(),
        "broken task".into(),
    )
    .unwrap();
    let profile_store = JoinProfileStore::new(work.0.join("join-profiles"));
    let database = profile_store.database(&broken.profile.id).unwrap();
    let conn = rusqlite::Connection::open(&database).unwrap();
    conn.execute("DELETE FROM device_control_tasks", [])
        .unwrap();
    drop(conn);
    assert!(device_join::snapshot(&state, broken.profile.id.clone()).is_err());
    let reopened = AppState::with_keystore(
        work.0.join("normal.db").to_str().unwrap(),
        Some(work.0.join("normal.bin")),
    )
    .unwrap();
    assert!(device_join::snapshot(&reopened, broken.profile.id.clone()).is_err());
    assert!(profile_store.load(&broken.profile.id).is_ok());
    let conn = rusqlite::Connection::open(database).unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM device_control_tasks", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn switching_profile_invalidates_delayed_query_before_it_can_submit_password() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let state = Arc::new(state(&work));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let first = device_join::create(&state, url.clone(), "Alice".into(), "first".into()).unwrap();
    let second = device_join::create(&state, url, "Bob".into(), "second".into()).unwrap();
    device_join::snapshot(&state, first.profile.id.clone()).unwrap();
    let ready = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let signal = ready.clone();
    let finish = release.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = headers(&mut socket).await;
        assert!(request.starts_with(b"GET "));
        signal.notify_one();
        finish.notified().await;
        socket
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
        drop(socket);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                .await
                .is_err(),
            "invalidated query must not begin a password request"
        );
    });
    let active = state.clone();
    let id = first.profile.id.clone();
    let pending = tokio::spawn(async move {
        device_join::step(&active, id, Some("synthetic-account-password".into())).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), ready.notified())
        .await
        .unwrap();
    device_join::snapshot(&state, second.profile.id.clone()).unwrap();
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    server.await.unwrap();
    let first = device_join::snapshot(&state, first.profile.id).unwrap();
    assert_eq!(first.join.task.phase, TaskPhase::Draft);
    assert!(state.identity().is_err());
    assert!(state.existing_pending_keys().unwrap().is_none());
}

#[tokio::test]
async fn locked_late_begin_preserves_original_draft_and_refuses_cleanup_of_live_handles() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let state = Arc::new(state(&work));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let view = device_join::create(&state, url.clone(), "Alice".into(), "second".into()).unwrap();
    let id = view.profile.id.clone();
    let store = JoinProfileStore::new(work.0.join("join-profiles"));
    let profile = store.load(&id).unwrap();
    let keys = profile.keys().unwrap();
    let root = crypto::generate_keypair().unwrap();
    let at = chrono_time();
    let response = JoinStatus {
        ticket: JoinTicket {
            id: view.join.task.id.clone(),
            anchor: Anchor {
                origin: url,
                account: uuid::Uuid::new_v4().to_string(),
                root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &root),
            },
            device: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
            device_name: "second".into(),
            server_challenge: vec![5; 32],
            issued_at: at,
            expires_at: at + JOIN_LIFETIME_MS,
        },
        phase: JoinPhase::Begun,
        intent: None,
        challenge: None,
        proof: None,
        authorization_id: None,
    };
    let ready = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let signal = ready.clone();
    let finish = release.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        headers(&mut socket).await;
        socket
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            )
            .await
            .unwrap();
        drop(socket);
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = headers(&mut socket).await;
        assert!(request.starts_with(b"POST "));
        signal.notify_one();
        finish.notified().await;
        let body = serde_json::to_vec(&response).unwrap();
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(&body).await.unwrap();
    });
    let active = state.clone();
    let pending_id = id.clone();
    let pending = tokio::spawn(async move {
        device_join::step(&active, pending_id, Some("synthetic-password".into())).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), ready.notified())
        .await
        .unwrap();
    device_control::suspend(&state).unwrap();
    device_control::resume(&state).unwrap();
    // The retired old coordinator still owns SQLite while its HTTP request waits.
    let abandoned = device_join::abandon(&state, id.clone()).unwrap();
    assert!(abandoned.join.local_abandonment);
    assert!(device_join::forget(&state, id.clone())
        .unwrap_err()
        .contains("在途"));
    assert!(store.load(&id).is_ok());
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    server.await.unwrap();
    let current = device_join::snapshot(&state, id.clone()).unwrap();
    assert_eq!(current.join.task.id, view.join.task.id);
    assert!(current.join.local_abandonment);
    device_join::forget(&state, id).unwrap();
    assert!(state.identity().is_err());
}
fn chrono_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
