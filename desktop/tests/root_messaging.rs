#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    keystore::KeystoreData,
    trusted_devices::{
        activation::{jobs, legacy::Admission},
        tasks::anchor_fingerprint,
        witness::platform::Protection,
        DeviceTrustStore,
    },
};
use liteseal_desktop::{
    commands::{device_control, root_messaging as r},
    protocol::{self, Command},
    AppState,
};
use liteseal_shared::{
    crypto,
    device_activation::{Enable, ModeQuery, ModeReply},
    trusted_device::*,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
struct Fixture {
    state: Arc<AppState>,
    protection: Protection,
    anchor: Anchor,
    keys: crypto::KeyPair,
    original: Vec<u8>,
    work: WorkDirectory,
}
impl Fixture {
    fn new(origin: &str) -> Self {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let protection = Protection::isolated_test();
        let state = Arc::new(
            AppState::with_device_protection(
                work.0.join("root.db").to_str().unwrap(),
                Some(work.0.join("root.bin")),
                protection.clone(),
            )
            .unwrap(),
        );
        let keys = crypto::generate_keypair().unwrap();
        let anchor = Anchor {
            origin: origin.into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
        };
        state
            .save_identity(KeystoreData {
                user_id: anchor.account.clone(),
                device_id: anchor.root.device_id.clone(),
                server_url: origin.into(),
                token: "synthetic-root-access".into(),
                refresh_token: "synthetic-root-refresh".into(),
                public_key: keys.public_key.to_vec(),
                secret_key: keys.secret_key.to_vec(),
                ed25519_pk: keys.ed25519_pk.to_vec(),
                ed25519_sk: keys.ed25519_sk.to_vec(),
            })
            .unwrap();
        let original = std::fs::read(work.0.join("root.bin")).unwrap();
        let mut trust = DeviceTrustStore::open(&state.db_path).unwrap();
        trust
            .protect(protection.witness(&state.db_path).unwrap())
            .unwrap();
        trust.pin(&anchor).unwrap();
        Self {
            state,
            protection,
            anchor,
            keys,
            original,
            work,
        }
    }
    fn unchanged(&self) {
        assert_eq!(
            std::fs::read(self.work.0.join("root.bin")).unwrap(),
            self.original
        );
    }
}
#[tokio::test]
async fn root_commands_bind_confirmation_and_pause_all_legacy_producers_without_losing_history() {
    let f = Fixture::new("https://root.invalid");
    for name in [
        "get_root_messaging",
        "check_root_messaging",
        "prepare_root_messaging",
        "root_messaging_step",
        "cancel_root_messaging",
        "forget_root_messaging",
    ] {
        let mut args = serde_json::json!({});
        if name == "prepare_root_messaging" {
            args["confirmedFingerprint"] = serde_json::json!("fp");
        }
        if name.ends_with("step") || name.starts_with("cancel") || name.starts_with("forget") {
            args["id"] = serde_json::json!("id");
        }
        for field in ["path", "mode", "token", "secretKey"] {
            let mut bad = args.clone();
            bad[field] = serde_json::json!("untrusted");
            assert!(
                serde_json::from_value::<Command>(serde_json::json!({"name":name,"args":bad}))
                    .is_err()
            );
        }
    }
    assert!(r::prepare(&f.state, "wrong".into()).await.is_err());
    assert!(r::snapshot(&f.state).unwrap().tasks.is_empty());
    let task = r::prepare(&f.state, anchor_fingerprint(&f.anchor))
        .await
        .unwrap();
    assert_eq!(
        r::snapshot(&f.state).unwrap().admission,
        Admission::Switching
    );
    let commands = [
        serde_json::json!({"name":"send_message","args":{"senderId":f.anchor.account,"senderDeviceId":f.anchor.root.device_id,"ciphertext":[],"signature":[],"payloads":[]}}),
        serde_json::json!({"name":"retry_message","args":{"messageId":"old"}}),
        serde_json::json!({"name":"select_attachment","args":{"path":"unopened","peerId":"peer"}}),
        serde_json::json!({"name":"stage_clipboard_image","args":{"encoded":"","peerId":"peer"}}),
        serde_json::json!({"name":"stage_recorded_audio","args":{"encoded":"","durationMs":1,"peerId":"peer"}}),
        serde_json::json!({"name":"publish_attachment","args":{"id":"old"}}),
        serde_json::json!({"name":"save_scheduled_message","args":{"id":null,"peerId":"peer","text":"retained","dueAt":1}}),
        serde_json::json!({"name":"send_scheduled_now","args":{"id":"old"}}),
        serde_json::json!({"name":"submit_reaction","args":{"targetId":"old","peerId":"peer","emoji":"👍"}}),
        serde_json::json!({"name":"submit_message_operation","args":{"targetId":"old","kind":"edit","content":"text","baseRevision":0}}),
        serde_json::json!({"name":"send_typing","args":{"peerId":"peer","active":true}}),
    ];
    for input in commands {
        let cmd = serde_json::from_value::<Command>(input).unwrap();
        assert!(protocol::dispatch(cmd, &f.state)
            .await
            .unwrap_err()
            .contains("旧单聊发送已暂停"));
    }
    assert_eq!(
        protocol::dispatch(Command::ProcessScheduledMessages {}, &f.state)
            .await
            .unwrap(),
        0
    );
    {
        let db = f.state.client.db.lock().unwrap();
        db.insert_message(&liteseal_core::db::models::MessageModel {
            id: "incoming-old".into(),
            conversation_id: "history".into(),
            sender_id: "other".into(),
            sender_device_id: "other-device".into(),
            sender_seq: 1,
            timestamp: 1,
            message_type: "text".into(),
            local_state: "received".into(),
            expire_at: None,
            ciphertext: vec![1],
            signature: vec![2],
            prev_hash: vec![3],
        })
        .unwrap();
        db.set_read_receipts_enabled(&f.anchor.account, true)
            .unwrap();
        db.save_attachment_transfer(&liteseal_core::db::repository::AttachmentTransfer {
            id: "download".into(),
            user_id: f.anchor.account.clone(),
            peer_id: "peer".into(),
            message_id: "incoming-old".into(),
            metadata: vec![0],
            ciphertext: vec![0],
            offset: 0,
            direction: "download".into(),
        })
        .unwrap();
        db.save_attachment_transfer(&liteseal_core::db::repository::AttachmentTransfer {
            id: "upload".into(),
            user_id: f.anchor.account.clone(),
            peer_id: "peer".into(),
            message_id: "unpublished".into(),
            metadata: vec![0],
            ciphertext: vec![0],
            offset: 0,
            direction: "upload".into(),
        })
        .unwrap();
    }
    protocol::dispatch(
        Command::MarkVisibleMessages {
            user_id: f.anchor.account.clone(),
            ids: vec!["incoming-old".into()],
        },
        &f.state,
    )
    .await
    .unwrap();
    assert_eq!(r::snapshot(&f.state).unwrap().pending.receipts, 0);
    assert!(protocol::dispatch(
        Command::AttachmentStep {
            id: "upload".into()
        },
        &f.state
    )
    .await
    .unwrap_err()
    .contains("旧单聊发送已暂停"));
    assert!(!protocol::dispatch(
        Command::AttachmentStep {
            id: "download".into()
        },
        &f.state
    )
    .await
    .unwrap_err()
    .contains("旧单聊发送已暂停"));
    assert_eq!(
        f.state
            .client
            .db
            .lock()
            .unwrap()
            .get_message("incoming-old")
            .unwrap()
            .unwrap()
            .ciphertext,
        vec![1]
    );
    f.state
        .client
        .db
        .lock()
        .unwrap()
        .forget_attachment_transfer(&f.anchor.account, "upload")
        .unwrap();
    assert!(r::snapshot(&f.state).unwrap().pending.empty());
    assert_eq!(
        r::cancel(&f.state, task.id.clone()).unwrap().stage,
        jobs::Stage::Cancelled
    );
    assert_eq!(r::snapshot(&f.state).unwrap().admission, Admission::Legacy);
    r::forget(&f.state, task.id).unwrap();
    f.unchanged();
}
#[tokio::test]
async fn remote_enabled_check_is_sticky_and_late_lock_result_cannot_change_local_mode() {
    for lock in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let mode = Enable::make(
            &DeviceState::pin(f.anchor.clone()).unwrap(),
            &uuid::Uuid::new_v4().to_string(),
            &f.keys,
        )
        .unwrap();
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (seen_, release_) = (seen.clone(), release.clone());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            let (start, len) = loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let len = header
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse::<usize>()
                        .unwrap();
                    break (end + 4, len);
                }
            };
            while bytes.len() < start + len {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            let query: ModeQuery = serde_json::from_slice(&bytes[start..start + len]).unwrap();
            seen_.notify_one();
            release_.notified().await;
            let body = serde_json::to_vec(&ModeReply {
                version: 1,
                request: query.digest().unwrap(),
                event: Some(mode),
            })
            .unwrap();
            let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        });
        let active = f.state.clone();
        let pending = tokio::spawn(async move { r::check(&active).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
            .await
            .unwrap();
        if lock {
            device_control::suspend(&f.state).unwrap();
            device_control::resume(&f.state).unwrap();
        }
        release.notify_one();
        let result = pending.await.unwrap();
        server.await.unwrap();
        if lock {
            assert!(result.is_err());
            assert_eq!(r::snapshot(&f.state).unwrap().admission, Admission::Legacy);
        } else {
            assert_eq!(result.unwrap().admission, Admission::V3);
            assert!(r::prepare(&f.state, anchor_fingerprint(&f.anchor))
                .await
                .is_err());
            let reopened = AppState::with_device_protection(
                f.state.db_path.to_str().unwrap(),
                Some(f.work.0.join("root.bin")),
                f.protection.clone(),
            )
            .unwrap();
            assert_eq!(r::snapshot(&reopened).unwrap().admission, Admission::V3);
        }
        f.unchanged();
    }
}
#[tokio::test]
async fn original_enable_step_uses_saved_signature_and_complete_blocks_legacy_after_reopen() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let task = r::prepare(&f.state, anchor_fingerprint(&f.anchor))
        .await
        .unwrap();
    let original = liteseal_core::trusted_devices::activation::jobs::Store::open(
        &f.state.db_path,
        jobs::Owner::new(f.anchor.clone(), &f.anchor.root.device_id, &f.keys).unwrap(),
        &f.keys,
        f.protection.witness(&f.state.db_path).unwrap(),
    )
    .unwrap()
    .task(&task.id, &f.keys)
    .unwrap()
    .enable()
    .clone();
    let expected = original.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, _) = read_request(&mut socket).await;
        assert!(header.starts_with("GET /users/"));
        respond(
            &mut socket,
            &serde_json::json!({"enabled":false,"event":null}),
        )
        .await;
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, body) = read_request(&mut socket).await;
        assert!(header.starts_with("POST /devices/messaging/enable "));
        let actual: Enable = serde_json::from_slice(&body).unwrap();
        assert_eq!(actual, expected);
        respond(&mut socket, &actual).await;
    });
    let result = r::step(&f.state, task.id.clone()).await.unwrap();
    server.await.unwrap();
    assert_eq!(result.condition, jobs::Condition::Complete);
    assert_eq!(r::snapshot(&f.state).unwrap().admission, Admission::V3);
    assert_eq!(
        r::cancel(&f.state, task.id.clone()).unwrap().stage,
        jobs::Stage::Complete
    );
    assert_eq!(r::snapshot(&f.state).unwrap().admission, Admission::V3);
    assert!(r::forget(&f.state, task.id).is_err());
    let reopened = AppState::with_device_protection(
        f.state.db_path.to_str().unwrap(),
        Some(f.work.0.join("root.bin")),
        f.protection.clone(),
    )
    .unwrap();
    assert_eq!(r::snapshot(&reopened).unwrap().admission, Admission::V3);
    f.unchanged();
}
async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut wire = Vec::new();
    let mut chunk = [0; 4096];
    let (header, start, len) = loop {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        wire.extend_from_slice(&chunk[..n]);
        if let Some(end) = wire.windows(4).position(|v| v == b"\r\n\r\n") {
            let header = String::from_utf8(wire[..end].to_vec()).unwrap();
            let len = header
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            break (header, end + 4, len);
        }
    };
    while wire.len() < start + len {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        wire.extend_from_slice(&chunk[..n]);
    }
    (header, wire[start..start + len].to_vec())
}
async fn respond(socket: &mut tokio::net::TcpStream, body: &impl serde::Serialize) {
    let body = serde_json::to_vec(body).unwrap();
    let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
    socket.write_all(header.as_bytes()).await.unwrap();
    socket.write_all(&body).await.unwrap();
}
