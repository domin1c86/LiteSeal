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
    commands::{
        device_control, keystore, root_messaging as r, root_session as s,
        session_refresh as refresh,
    },
    protocol::{self, Command},
    AppState,
};
use liteseal_shared::{
    crypto,
    device_activation::{
        Challenge, Enable, Envelope, Inspection, InspectionResult, ModeQuery, ModeReply, Session,
        SessionInfo,
    },
    trusted_device::*,
};
use sha2::{Digest, Sha256};
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
    fn completed_login(&self) -> (String, Challenge, Envelope, Session) {
        let mut store = jobs::Store::open(
            &self.state.db_path,
            jobs::Owner::new(self.anchor.clone(), &self.anchor.root.device_id, &self.keys).unwrap(),
            &self.keys,
            self.protection.witness(&self.state.db_path).unwrap(),
        )
        .unwrap();
        let enable = store.prepare_enable_checked(&self.keys).unwrap();
        let mode = enable.enable().clone();
        let enable = store.begin(&enable.view(), &self.keys).unwrap();
        store
            .accept_enable(&enable.view(), &mode, &self.keys)
            .unwrap();
        let task = store
            .prepare_login("synthetic-user", mode.clone(), &self.keys)
            .unwrap();
        let task = store.begin(&task.view(), &self.keys).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let challenge = Challenge::make(
            &DeviceState::pin(self.anchor.clone()).unwrap(),
            &mode,
            &task.view().id,
            &self.anchor.root.device_id,
            now,
        )
        .unwrap();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: challenge.account.clone(),
            device: challenge.device.device_id.clone(),
            authorization: challenge.authorization,
            mode: challenge.mode,
            access_token: "synthetic-formal-access".into(),
            refresh_token: "synthetic-formal-refresh".into(),
            expires_at: now + 60000,
            refresh_expires_at: now + 120000,
        };
        let envelope = Envelope::seal(&challenge, &session).unwrap();
        let task = store
            .save_challenge(&task.view(), challenge.clone(), &self.keys)
            .unwrap();
        let task = store.seal_proof(&task.view(), now + 1, &self.keys).unwrap();
        store
            .accept_session(
                &task.view(),
                challenge.clone(),
                envelope.clone(),
                &self.keys,
            )
            .unwrap();
        (task.view().id, challenge, envelope, session)
    }
}

#[tokio::test]
async fn refresh_ipc_requires_explicit_target_and_rejects_secret_injection() {
    let f = Fixture::new("http://127.0.0.1:1");
    for name in [
        "get_session_refresh",
        "prepare_session_refresh",
        "session_refresh_step",
        "cancel_session_refresh",
        "forget_session_refresh",
    ] {
        let mut args = serde_json::json!({"target":{"kind":"root"}});
        if name.contains("step") || name.contains("cancel") || name.contains("forget") {
            args["id"] = "original".into();
        }
        if name.contains("cancel") {
            args["confirmedFamilyExit"] = false.into();
        }
        assert!(
            serde_json::from_value::<Command>(serde_json::json!({"name":name,"args":args})).is_ok()
        );
        for extra in ["token", "refreshToken", "secretKey", "path", "profileId"] {
            let mut injected = args.clone();
            injected[extra] = "injected".into();
            assert!(serde_json::from_value::<Command>(
                serde_json::json!({"name":name,"args":injected})
            )
            .is_err());
            let mut injected = args.clone();
            injected["target"][extra] = "injected".into();
            assert!(serde_json::from_value::<Command>(
                serde_json::json!({"name":name,"args":injected})
            )
            .is_err());
        }
        args["target"] = serde_json::json!({"kind":"join"});
        assert!(
            serde_json::from_value::<Command>(serde_json::json!({"name":name,"args":args}))
                .is_err()
        );
    }
    assert!(!refresh::process(&f.state).await.unwrap());
    assert!(refresh::prepare(&f.state, refresh::Target::Root {}).is_err());
    f.unchanged();
}

#[tokio::test]
async fn root_login_ipc_rejects_injection_and_enable_tasks_without_mutation() {
    let f = Fixture::new("http://127.0.0.1:1");
    for name in [
        "get_root_session",
        "prepare_root_session",
        "root_session_step",
        "inspect_root_session",
        "cancel_root_session",
        "forget_root_session",
        "save_root_session",
    ] {
        for extra in [
            "token",
            "refreshToken",
            "path",
            "secretKey",
            "mode",
            "profileId",
        ] {
            let mut args = serde_json::json!({});
            if name == "prepare_root_session" {
                args["username"] = "synthetic-user".into();
            }
            if !["get_root_session", "prepare_root_session"].contains(&name) {
                args["id"] = "original".into();
            }
            args[extra] = "injected".into();
            assert!(serde_json::from_value::<Command>(
                serde_json::json!({"name":name,"args":args})
            )
            .is_err());
        }
    }
    assert!(s::prepare(&f.state, "synthetic-user".into()).await.is_err());
    let enable = r::prepare(&f.state, anchor_fingerprint(&f.anchor))
        .await
        .unwrap();
    assert!(s::snapshot(&f.state).unwrap().tasks.is_empty());
    assert!(s::step(&f.state, enable.id.clone(), None).await.is_err());
    assert!(s::cancel(&f.state, enable.id.clone()).is_err());
    assert!(s::save(&f.state, enable.id).await.is_err());
    f.unchanged();
}

#[tokio::test]
async fn unbound_legacy_login_reaches_server_without_creating_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let state = AppState::with_device_protection(
        work.0.join("new.db").to_str().unwrap(),
        Some(work.0.join("new.bin")),
        Protection::isolated_test(),
    )
    .unwrap();
    let keys = keystore::prepare_identity(&state).unwrap();
    assert!(!keys.saved);
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, _) = read_request(&mut socket).await;
        assert!(header.starts_with("POST /auth/login "));
        socket
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let result = protocol::dispatch(
        Command::Login {
            username: "synthetic-first-login".into(),
            password: "synthetic-password".into(),
            server_url: origin,
            public_key: keys.public_key,
            ed25519_pk: keys.ed25519_pk,
            device_id: None,
        },
        &state,
    )
    .await;
    assert!(result.unwrap_err().contains("401"));
    server.await.unwrap();
    assert!(!work.0.join("new.bin").exists());
}

#[tokio::test]
async fn exited_root_prepares_from_signed_mode_without_bearer_and_keeps_original_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let (_, challenge, _, _) = f.completed_login();
    // The seeded completed login permits an explicit new login after sign-out.
    let mut store = jobs::Store::open(
        &f.state.db_path,
        jobs::Owner::new(f.anchor.clone(), &f.anchor.root.device_id, &f.keys).unwrap(),
        &f.keys,
        f.protection.witness(&f.state.db_path).unwrap(),
    )
    .unwrap();
    let existing = store
        .views(&f.keys)
        .unwrap()
        .into_iter()
        .find(|t| t.kind == jobs::Kind::Enable)
        .unwrap();
    let mode = store.task(&existing.id, &f.keys).unwrap().enable().clone();
    let before = f.state.identity().unwrap();
    f.state
        .save_identity(KeystoreData {
            token: String::new(),
            refresh_token: String::new(),
            ..before
        })
        .unwrap();
    let expected_file = std::fs::read(f.work.0.join("root.bin")).unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, body) = read_request(&mut socket).await;
        assert!(header.starts_with("POST /auth/v3/mode "));
        assert!(!header.to_lowercase().contains("authorization:"));
        let query: ModeQuery = serde_json::from_slice(&body).unwrap();
        assert_eq!(query.device, challenge.device);
        respond(
            &mut socket,
            &ModeReply {
                version: 1,
                request: query.digest().unwrap(),
                event: Some(mode),
            },
        )
        .await;
    });
    let next = s::prepare(&f.state, "synthetic-user".into()).await.unwrap();
    server.await.unwrap();
    assert_eq!(next.kind, jobs::Kind::Login);
    assert_eq!(next.stage, jobs::Stage::Prepared);
    assert_eq!(
        s::cancel(&f.state, next.id.clone()).unwrap().stage,
        jobs::Stage::Cancelled
    );
    s::forget(&f.state, next.id).unwrap();
    assert_eq!(
        std::fs::read(f.work.0.join("root.bin")).unwrap(),
        expected_file
    );
    assert!(keystore::load_identity(&f.state).unwrap().token.is_empty());
}

#[tokio::test]
async fn unknown_enable_result_can_prepare_original_login_only_after_remote_signed_mode() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let original = r::prepare(&f.state, anchor_fingerprint(&f.anchor))
        .await
        .unwrap();
    let mut store = jobs::Store::open(
        &f.state.db_path,
        jobs::Owner::new(f.anchor.clone(), &f.anchor.root.device_id, &f.keys).unwrap(),
        &f.keys,
        f.protection.witness(&f.state.db_path).unwrap(),
    )
    .unwrap();
    let original = store.begin(&original, &f.keys).unwrap();
    let mode = original.enable().clone();
    assert_eq!(
        r::snapshot(&f.state).unwrap().admission,
        Admission::Switching
    );
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, body) = read_request(&mut socket).await;
        assert!(!header.to_lowercase().contains("authorization:"));
        let query: ModeQuery = serde_json::from_slice(&body).unwrap();
        respond(
            &mut socket,
            &ModeReply {
                version: 1,
                request: query.digest().unwrap(),
                event: Some(mode),
            },
        )
        .await;
    });
    let login = s::prepare(&f.state, "synthetic-user".into()).await.unwrap();
    server.await.unwrap();
    assert_ne!(login.id, original.view().id);
    assert_eq!(login.kind, jobs::Kind::Login);
    assert_eq!(r::snapshot(&f.state).unwrap().tasks[0], original.view());
    assert_eq!(r::snapshot(&f.state).unwrap().admission, Admission::V3);
    f.unchanged();
}

#[tokio::test]
async fn root_formal_save_preserves_original_identity_masks_credentials_and_fences_late_results() {
    // Success, lock/unlock, sign-out, credential replacement, invalid refresh binding.
    for case in 0..5 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let before = f.state.identity().unwrap();
        let (id, challenge, envelope, session) = f.completed_login();
        assert_eq!(r::snapshot(&f.state).unwrap().admission, Admission::V3);
        let info = SessionInfo {
            version: 1,
            id: session.id.clone(),
            account: session.account.clone(),
            device: challenge.device.clone(),
            authorization: session.authorization,
            mode: session.mode,
            expires_at: session.expires_at,
            refresh_expires_at: session.refresh_expires_at,
            refresh_hash: if case == 4 {
                [0; 32]
            } else {
                Sha256::digest(session.refresh_token.as_bytes()).into()
            },
        };
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (seen_, release_) = (seen.clone(), release.clone());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (_, body) = read_request(&mut socket).await;
            let query: Inspection = serde_json::from_slice(&body).unwrap();
            respond(
                &mut socket,
                &InspectionResult::Accepted {
                    request: query.digest().unwrap(),
                    challenge: Box::new(challenge),
                    envelope,
                },
            )
            .await;
            let (mut socket, _) = listener.accept().await.unwrap();
            let (header, _) = read_request(&mut socket).await;
            assert!(header.starts_with(&format!("GET /auth/v3/session/{} ", info.device.device_id)));
            assert!(header
                .to_lowercase()
                .contains("authorization: bearer synthetic-formal-access"));
            seen_.notify_one();
            release_.notified().await;
            respond(&mut socket, &info).await;
        });
        let active = f.state.clone();
        let pending = tokio::spawn(async move { s::save(&active, id).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
            .await
            .unwrap();
        match case {
            1 => {
                device_control::suspend(&f.state).unwrap();
                device_control::resume(&f.state).unwrap();
            }
            2 => {
                f.state
                    .save_identity(KeystoreData {
                        token: String::new(),
                        refresh_token: String::new(),
                        ..before.clone()
                    })
                    .unwrap();
            }
            3 => {
                f.state
                    .save_identity(KeystoreData {
                        token: "replacement-access".into(),
                        refresh_token: "replacement-refresh".into(),
                        ..before.clone()
                    })
                    .unwrap();
            }
            _ => {}
        }
        let expected = f.state.identity().unwrap();
        let expected_file = std::fs::read(f.work.0.join("root.bin")).unwrap();
        release.notify_one();
        let result = pending.await.unwrap();
        server.await.unwrap();
        if case == 0 {
            let saved = result.unwrap();
            let public = serde_json::to_string(&saved).unwrap();
            assert!(
                !public.contains(&session.access_token) && !public.contains(&session.refresh_token)
            );
            let after = f.state.identity().unwrap();
            assert_eq!(after.token, session.access_token);
            assert_eq!(after.refresh_token, session.refresh_token);
            assert_eq!(after.secret_key, before.secret_key);
            assert_eq!(after.ed25519_sk, before.ed25519_sk);
            assert_eq!(after.public_key, before.public_key);
            assert_eq!(after.ed25519_pk, before.ed25519_pk);
            assert_eq!(after.user_id, before.user_id);
            assert_eq!(after.device_id, before.device_id);
            assert_eq!(after.server_url, before.server_url);
            for view in [
                keystore::load_identity(&f.state).unwrap(),
                keystore::prepare_identity(&f.state).unwrap(),
            ] {
                assert_eq!(view.token, "rust-owned-session");
                assert_eq!(view.refresh_token, "rust-owned-session");
                assert!(!serde_json::to_string(&view)
                    .unwrap()
                    .contains("synthetic-formal"));
            }
            assert!(keystore::save_session(
                before.user_id.clone(),
                "injected".into(),
                "injected".into(),
                before.device_id.clone(),
                before.server_url.clone(),
                &f.state
            )
            .is_err());
            assert!(protocol::dispatch(
                Command::RefreshSession {
                    server_url: before.server_url.clone(),
                    refresh_token: "rust-owned-session".into()
                },
                &f.state
            )
            .await
            .is_err());
            assert!(protocol::dispatch(
                Command::ConnectRelay {
                    server_url: before.server_url.clone(),
                    user_id: before.user_id.clone(),
                    device_id: before.device_id.clone(),
                    token: "rust-owned-session".into()
                },
                &f.state
            )
            .await
            .is_err());
            let reopened = AppState::with_device_protection(
                f.state.db_path.to_str().unwrap(),
                Some(f.work.0.join("root.bin")),
                f.protection.clone(),
            )
            .unwrap();
            assert_eq!(reopened.identity().unwrap().token, session.access_token);
            assert_eq!(
                keystore::load_identity(&reopened).unwrap().token,
                "rust-owned-session"
            );
            // Formal tokens now live in the native-protected current record.
            // The original DPAPI identity and keys are byte-for-byte retained.
            f.unchanged();
            let mut current =
                liteseal_core::trusted_devices::activation::refresh::jobs::Store::open(
                    &f.state.db_path,
                    jobs::Owner::new(f.anchor.clone(), &f.anchor.root.device_id, &f.keys).unwrap(),
                    &f.keys,
                    f.protection.witness(&f.state.db_path).unwrap(),
                )
                .unwrap();
            assert_eq!(current.session(&f.keys).unwrap().id, session.id);
            let target = refresh::Target::Root {};
            let snapshot = refresh::snapshot(&f.state, target.clone()).unwrap();
            let public = serde_json::to_string(&snapshot).unwrap();
            assert!(
                !public.contains(&session.access_token) && !public.contains(&session.refresh_token)
            );
            assert_eq!(
                snapshot.current.unwrap().access_expires_at,
                session.expires_at
            );
            assert!(refresh::snapshot(
                &f.state,
                refresh::Target::Join {
                    profile_id: "missing-profile".into()
                }
            )
            .is_err());
            let job = refresh::prepare(&f.state, target.clone()).unwrap();
            assert_eq!(
                refresh::snapshot(&reopened, target.clone()).unwrap().tasks[0].id,
                job.id
            );
            assert!(refresh::prepare(&f.state, target.clone()).is_err());
            device_control::suspend(&f.state).unwrap();
            assert!(refresh::snapshot(&f.state, target.clone()).is_err());
            assert!(refresh::process(&f.state).await.is_err());
            device_control::resume(&f.state).unwrap();
            assert_eq!(
                refresh::cancel(&f.state, target.clone(), job.id.clone(), false)
                    .unwrap()
                    .stage,
                liteseal_core::trusted_devices::activation::refresh::jobs::Stage::Cancelled
            );
            refresh::forget(&f.state, target.clone(), job.id).unwrap();
            assert!(!refresh::process(&f.state).await.unwrap());
            let job = refresh::snapshot(&f.state, target.clone())
                .unwrap()
                .tasks
                .remove(0);
            assert_eq!(
                job.stage,
                liteseal_core::trusted_devices::activation::refresh::jobs::Stage::Started
            );
            assert!(!refresh::process(&f.state).await.unwrap());
            let resumed = refresh::snapshot(&f.state, target.clone()).unwrap().tasks;
            assert_eq!(resumed.len(), 1);
            assert_eq!(resumed[0].id, job.id);
            // The original listener is gone: unknown network results retain the original started task.
            let result = refresh::step(&f.state, target.clone(), job.id.clone())
                .await
                .unwrap();
            assert_eq!(
                result.condition,
                liteseal_core::trusted_devices::activation::refresh::jobs::Condition::Retry
            );
            assert!(refresh::cancel(&f.state, target.clone(), job.id.clone(), false).is_err());
            assert!(
                !refresh::snapshot(&f.state, target.clone()).unwrap().tasks[0].cancel_requested
            );
            assert!(
                refresh::cancel(&f.state, target, job.id, true)
                    .unwrap()
                    .cancel_requested
            );
            current.clear_local(&f.keys).unwrap();
            assert!(!refresh::process(&f.state).await.unwrap());
            assert!(f.state.identity().unwrap().token.is_empty());
            assert!(reopened.identity().unwrap().refresh_token.is_empty());
            f.unchanged();
        } else {
            assert!(result.is_err());
            assert_eq!(
                serde_json::to_vec(&f.state.identity().unwrap()).unwrap(),
                serde_json::to_vec(&expected).unwrap()
            );
            assert_eq!(
                std::fs::read(f.work.0.join("root.bin")).unwrap(),
                expected_file
            );
        }
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
