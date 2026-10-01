use liteseal_core::trusted_devices::{coordinator::*, tasks::*};
use liteseal_shared::{crypto, trusted_device::*};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[tokio::test]
async fn session_rotation_preserves_lock_and_does_not_replace_saved_tasks() {
    let keys = crypto::generate_keypair().unwrap();
    let owner = TaskOwner::for_join(
        "http://127.0.0.1:1",
        "isolated",
        &uuid::Uuid::new_v4().to_string(),
        &keys,
    )
    .unwrap();
    let path =
        std::env::temp_dir().join(format!("liteseal-coordinator-{}.db", uuid::Uuid::new_v4()));
    let coordinator = DeviceCoordinator::open(&path, owner.clone(), &keys).unwrap();
    let task = coordinator.prepare_join("second", &keys).unwrap();
    coordinator.invalidate().unwrap();
    coordinator
        .renew_session("fresh-runtime-token".into())
        .unwrap();
    assert!(coordinator.tasks(&keys).is_err());
    assert!(coordinator.prepare_join("replacement", &keys).is_err());
    coordinator.resume().unwrap();
    assert_eq!(coordinator.tasks(&keys).unwrap()[0].id, task.id);
    drop(coordinator);
    let reopened = DeviceCoordinator::open(&path, owner, &keys).unwrap();
    assert_eq!(reopened.tasks(&keys).unwrap()[0].id, task.id);
    drop(reopened);
    let _ = std::fs::remove_file(path);
}
#[tokio::test]
async fn locked_coordinator_rejects_delayed_ticket_without_advancing_or_waiting_for_network() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let root = crypto::generate_keypair().unwrap();
    let keys = crypto::generate_keypair().unwrap();
    let owner =
        TaskOwner::for_join(&url, "isolated", &uuid::Uuid::new_v4().to_string(), &keys).unwrap();
    let path =
        std::env::temp_dir().join(format!("liteseal-coordinator-{}.db", uuid::Uuid::new_v4()));
    let coordinator = DeviceCoordinator::open(&path, owner, &keys).unwrap();
    let task = coordinator.prepare_join("second", &keys).unwrap();
    let response = JoinStatus {
        ticket: JoinTicket {
            id: task.id.clone(),
            anchor: Anchor {
                origin: url,
                account: "isolated-root".into(),
                root: DeviceIdentity::from_keys("root".into(), &root),
            },
            device: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
            device_name: "second".into(),
            server_challenge: vec![1; 32],
            issued_at: 1000,
            expires_at: 601000,
        },
        phase: JoinPhase::Begun,
        intent: None,
        challenge: None,
        proof: None,
        authorization_id: None,
    };
    let ready = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let signal = ready.clone();
    let wait = release.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        let mut chunk = [0; 2048];
        while !bytes.windows(4).any(|p| p == b"\r\n\r\n") {
            let read = socket.read(&mut chunk).await.unwrap();
            if read == 0 {
                return;
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        signal.notify_one();
        wait.notified().await;
        let body = serde_json::to_vec(&response).unwrap();
        let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
        socket.write_all(header.as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
    });
    let step = coordinator.step(&task.id, None, &keys);
    let lock = async {
        tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
            .await
            .unwrap();
        coordinator.invalidate().unwrap();
        release.notify_one();
    };
    let (result, _) = tokio::join!(step, lock);
    assert!(result.is_err());
    server.await.unwrap();
    coordinator.resume().unwrap();
    let view = coordinator.tasks(&keys).unwrap().remove(0);
    assert_eq!(view.phase, TaskPhase::Draft);
    assert_eq!(view.revision, 0);
    drop(coordinator);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn expired_remote_request_finishes_original_challenge_without_a_new_signature() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let root = crypto::generate_keypair().unwrap();
    let second = crypto::generate_keypair().unwrap();
    let anchor = Anchor {
        origin: url.clone(),
        account: uuid::Uuid::new_v4().to_string(),
        root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &root),
    };
    let owner = TaskOwner::for_root(&anchor, &root).unwrap();
    let path =
        std::env::temp_dir().join(format!("liteseal-coordinator-{}.db", uuid::Uuid::new_v4()));
    let mut store = DeviceTaskStore::open(&path, owner.clone(), &root).unwrap();
    let state = store.trust().pin(&anchor).unwrap();
    let ticket = JoinTicket {
        id: uuid::Uuid::new_v4().to_string(),
        anchor,
        device: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &second),
        device_name: "second".into(),
        server_challenge: vec![1; 32],
        issued_at: 1000,
        expires_at: 601000,
    };
    let intent = ticket.sign_intent(&second).unwrap();
    let task = store
        .prepare_challenge(&state, &intent, 1001, &root)
        .unwrap();
    let response = JoinStatus {
        ticket,
        phase: JoinPhase::Expired,
        intent: Some(intent),
        challenge: task.challenge().cloned(),
        proof: None,
        authorization_id: None,
    };
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut headers = vec![];
        let mut bytes = [0; 2048];
        while !headers.windows(4).any(|part| part == b"\r\n\r\n") {
            let read = socket.read(&mut bytes).await.unwrap();
            if read == 0 {
                return;
            }
            headers.extend_from_slice(&bytes[..read]);
        }
        let body = serde_json::to_vec(&response).unwrap();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(header.as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
    });
    let coordinator = DeviceCoordinator::open(&path, owner, &root).unwrap();
    coordinator.renew_session("isolated-token".into()).unwrap();
    let progress = coordinator
        .step(&task.view().id, None, &root)
        .await
        .unwrap();
    assert_eq!(progress.task.phase, TaskPhase::Expired);
    assert_eq!(
        store.get(&task.view().id, &root).unwrap().challenge(),
        task.challenge()
    );
    server.await.unwrap();
    drop(coordinator);
    drop(store);
    let _ = std::fs::remove_file(path);
}
