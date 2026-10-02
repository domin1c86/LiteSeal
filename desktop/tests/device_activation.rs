#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    keystore::KeystoreData,
    trusted_devices::{
        activation::jobs,
        profiles::{active, JoinProfileStore},
        tasks::{anchor_fingerprint, DeviceTaskStore},
        witness::platform::Protection,
        Checkpoint,
    },
};
use liteseal_desktop::{
    commands::{
        device_activation as a, device_control, device_join, normal_profile as normal,
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
    net::{TcpListener, TcpStream},
    sync::Notify,
};
struct Fixture {
    state: Arc<AppState>,
    protection: Protection,
    id: String,
    keys: crypto::KeyPair,
    directory: DeviceState,
    mode: Enable,
    path: std::path::PathBuf,
    original: Vec<u8>,
    join_original: Vec<u8>,
    // Close cached SQLite handles and isolated native records before temp cleanup.
    work: WorkDirectory,
}
impl Fixture {
    fn new(origin: &str) -> Self {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let protection = Protection::isolated_test();
        let state = Arc::new(
            AppState::with_device_protection(
                work.0.join("normal.db").to_str().unwrap(),
                Some(work.0.join("normal.bin")),
                protection.clone(),
            )
            .unwrap(),
        );
        let old = crypto::generate_keypair().unwrap();
        state
            .save_identity(KeystoreData {
                user_id: uuid::Uuid::new_v4().to_string(),
                device_id: uuid::Uuid::new_v4().to_string(),
                server_url: origin.into(),
                token: "synthetic-existing-token".into(),
                refresh_token: "synthetic-existing-refresh".into(),
                public_key: old.public_key.to_vec(),
                secret_key: old.secret_key.to_vec(),
                ed25519_pk: old.ed25519_pk.to_vec(),
                ed25519_sk: old.ed25519_sk.to_vec(),
            })
            .unwrap();
        let original = std::fs::read(work.0.join("normal.bin")).unwrap();
        let profiles =
            JoinProfileStore::with_protection(work.0.join("join-profiles"), protection.clone());
        let profile = profiles
            .create(origin, "synthetic-user", "独立 Windows 🦭")
            .unwrap();
        let id = profile.view().id;
        let join_original =
            std::fs::read(work.0.join("join-profiles").join(&id).join("identity.bin")).unwrap();
        let keys = profile.keys().unwrap();
        let root = crypto::generate_keypair().unwrap();
        let initial = DeviceState::pin(Anchor {
            origin: origin.into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &root),
        })
        .unwrap();
        let ticket = JoinStatus {
            ticket: JoinTicket {
                id: profile.task_id().into(),
                anchor: initial.anchor().clone(),
                device: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
                device_name: "独立 Windows 🦭".into(),
                server_challenge: crypto::random_challenge().unwrap().to_vec(),
                issued_at: 1000,
                expires_at: 601000,
            },
            phase: JoinPhase::Begun,
            intent: None,
            challenge: None,
            proof: None,
            authorization_id: None,
        };
        let path = profiles.database(&id).unwrap();
        let mut tasks = DeviceTaskStore::open(&path, profile.owner().unwrap(), &keys).unwrap();
        tasks.protect(protection.witness(&path).unwrap()).unwrap();
        let task = tasks.get(profile.task_id(), &keys).unwrap();
        let task = tasks.accept_ticket(&task, &ticket, &keys).unwrap();
        let task = tasks
            .confirm_root(
                &task,
                initial.anchor(),
                &anchor_fingerprint(initial.anchor()),
                &keys,
            )
            .unwrap();
        let challenge = make_challenge(&initial, task.intent().unwrap(), 1001, &root).unwrap();
        let task = tasks
            .seal_proof(&task, &initial, &challenge, 1002, &keys)
            .unwrap();
        let event = make_event(
            &initial,
            uuid::Uuid::new_v4().to_string(),
            DeviceAction::Grant {
                intent: Box::new(task.intent().unwrap().clone()),
                challenge: Box::new(challenge),
                proof: task.proof().unwrap().clone(),
            },
            1003,
            &root,
        )
        .unwrap();
        tasks
            .trust()
            .import_verified(
                initial.anchor(),
                &Checkpoint::from_state(&initial),
                std::slice::from_ref(&event),
            )
            .unwrap();
        tasks
            .confirm_join_authorized(&task, &event.id, &keys)
            .unwrap();
        let directory = initial.apply(&event).unwrap();
        let mode = Enable::make(&directory, &uuid::Uuid::new_v4().to_string(), &root).unwrap();
        Self {
            work,
            state,
            protection,
            id,
            keys,
            directory,
            mode,
            path,
            original,
            join_original,
        }
    }
    fn unchanged(&self) {
        assert_eq!(
            std::fs::read(self.work.0.join("normal.bin")).unwrap(),
            self.original
        );
        assert_eq!(
            std::fs::read(
                self.work
                    .0
                    .join("join-profiles")
                    .join(&self.id)
                    .join("identity.bin")
            )
            .unwrap(),
            self.join_original
        );
    }
    fn jobs(&self) -> jobs::Store {
        let store = active::Store::open_with_protection(
            self.work.0.join("join-profiles"),
            &self.id,
            self.protection.clone(),
        )
        .unwrap();
        jobs::Store::open(
            &self.path,
            store.job_owner().unwrap(),
            &self.keys,
            self.protection.witness(&self.path).unwrap(),
        )
        .unwrap()
    }
    fn completed(&self) -> (String, Challenge, Envelope, Session) {
        let mut jobs = self.jobs();
        let task = jobs
            .prepare_login("synthetic-user", self.mode.clone(), &self.keys)
            .unwrap();
        let task = jobs.begin(&task.view(), &self.keys).unwrap();
        let now = chrono_time();
        let challenge = Challenge::make(
            &self.directory,
            &self.mode,
            &task.view().id,
            &self.directory.secondary().unwrap().device_id,
            now,
        )
        .unwrap();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: challenge.account.clone(),
            device: challenge.device.device_id.clone(),
            authorization: challenge.authorization,
            mode: challenge.mode,
            access_token: "synthetic-new-access-token".into(),
            refresh_token: "synthetic-new-refresh-token".into(),
            expires_at: now + 60000,
            refresh_expires_at: now + 120000,
        };
        let envelope = Envelope::seal(&challenge, &session).unwrap();
        let task = jobs
            .save_challenge(&task.view(), challenge.clone(), &self.keys)
            .unwrap();
        let task = jobs.seal_proof(&task.view(), now + 1, &self.keys).unwrap();
        jobs.accept_session(
            &task.view(),
            challenge.clone(),
            envelope.clone(),
            &self.keys,
        )
        .unwrap();
        (task.view().id, challenge, envelope, session)
    }
}
fn chrono_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
async fn request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    let mut wire = Vec::new();
    let mut chunk = [0; 4096];
    let (header, end, len) = loop {
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
    while wire.len() < end + len {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        wire.extend_from_slice(&chunk[..n]);
    }
    (header, wire[end..end + len].to_vec())
}
async fn reply(socket: &mut TcpStream, body: impl serde::Serialize) {
    let body = serde_json::to_vec(&body).unwrap();
    let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
    socket.write_all(header.as_bytes()).await.unwrap();
    socket.write_all(&body).await.unwrap();
}
#[test]
fn activation_ipc_rejects_secret_path_and_mode_injection_and_unconfirmed_profiles() {
    for name in [
        "get_join_activation",
        "prepare_join_activation",
        "join_activation_step",
        "inspect_join_activation",
        "cancel_join_activation",
        "forget_join_activation",
        "save_join_activation",
        "clear_join_activation_session",
    ] {
        for field in [
            "path",
            "access_token",
            "refresh_token",
            "secret_key",
            "mode",
            "deviceTestNamespace",
        ] {
            let mut args = serde_json::json!({"profileId":"untrusted"});
            if ![
                "get_join_activation",
                "prepare_join_activation",
                "clear_join_activation_session",
            ]
            .contains(&name)
            {
                args["id"] = serde_json::json!("untrusted");
            }
            args[field] = serde_json::json!("untrusted");
            assert!(serde_json::from_value::<Command>(
                serde_json::json!({"name":name,"args":args})
            )
            .is_err());
        }
    }
    let f = Fixture::new("https://activation.invalid");
    let draft = device_join::create(
        &f.state,
        "https://activation.invalid".into(),
        "synthetic-user".into(),
        "draft".into(),
    )
    .unwrap();
    assert!(a::snapshot(&f.state, draft.profile.id).is_err());
    assert!(a::snapshot(&f.state, "../normal".into()).is_err());
    device_control::suspend(&f.state).unwrap();
    assert!(a::snapshot(&f.state, f.id.clone()).is_err());
    device_control::resume(&f.state).unwrap();
    assert!(a::snapshot(&f.state, f.id.clone())
        .unwrap()
        .tasks
        .is_empty());
    f.unchanged();
}
#[tokio::test]
async fn original_activation_prepare_cancel_and_clear_never_replace_ordinary_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let mode = f.mode.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, body) = request(&mut socket).await;
        assert!(!header.to_lowercase().contains("authorization:"));
        let query: ModeQuery = serde_json::from_slice(&body).unwrap();
        reply(
            &mut socket,
            ModeReply {
                version: 1,
                request: query.digest().unwrap(),
                event: Some(mode),
            },
        )
        .await;
    });
    let task = a::prepare(&f.state, f.id.clone()).await.unwrap();
    server.await.unwrap();
    let result = protocol::dispatch(
        Command::GetJoinActivation {
            profile_id: f.id.clone(),
        },
        &f.state,
    )
    .await
    .unwrap();
    assert_eq!(result["tasks"][0]["id"], task.id);
    assert!(result["normal"].is_null());
    for secret in [
        "secret_key",
        "request_token",
        "access_token",
        "refresh_token",
    ] {
        assert!(!result.to_string().contains(secret));
    }
    assert!(a::forget(&f.state, f.id.clone(), task.id.clone()).is_err());
    assert_eq!(
        a::cancel(&f.state, f.id.clone(), task.id.clone())
            .unwrap()
            .stage,
        jobs::Stage::Cancelled
    );
    assert_eq!(
        a::inspect(&f.state, f.id.clone(), task.id.clone())
            .await
            .unwrap()
            .condition,
        jobs::Condition::Cancelled
    );
    a::forget(&f.state, f.id.clone(), task.id).unwrap();
    a::clear_session(&f.state, f.id.clone()).unwrap();
    assert!(a::snapshot(&f.state, f.id.clone())
        .unwrap()
        .tasks
        .is_empty());
    f.unchanged();
}
#[tokio::test]
async fn pause_and_join_profile_switch_reject_late_bootstrap_without_creating_activation() {
    for event in ["switch", "lock", "clear"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (seen_, release_) = (seen.clone(), release.clone());
        let mode = f.mode.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (_, body) = request(&mut socket).await;
            let query: ModeQuery = serde_json::from_slice(&body).unwrap();
            seen_.notify_one();
            release_.notified().await;
            reply(
                &mut socket,
                ModeReply {
                    version: 1,
                    request: query.digest().unwrap(),
                    event: Some(mode),
                },
            )
            .await;
        });
        let state = f.state.clone();
        let id = f.id.clone();
        let pending = tokio::spawn(async move { a::prepare(&state, id).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
            .await
            .unwrap();
        if event == "switch" {
            device_join::create(
                &f.state,
                "https://another.invalid".into(),
                "other".into(),
                "another profile".into(),
            )
            .unwrap();
        } else if event == "lock" {
            device_control::suspend(&f.state).unwrap();
            device_control::resume(&f.state).unwrap();
        } else {
            a::clear_session(&f.state, f.id.clone()).unwrap();
        }
        release.notify_one();
        assert!(pending.await.unwrap().is_err());
        server.await.unwrap();
        assert!(f.jobs().views(&f.keys).unwrap().is_empty());
        f.unchanged();
    }
}
#[tokio::test]
async fn accepted_original_session_saves_only_independent_profile_and_clear_fences_late_save() {
    for late_clear in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let (id, challenge, envelope, session) = f.completed();
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (seen_, release_) = (seen.clone(), release.clone());
        let info = SessionInfo {
            version: 1,
            id: session.id.clone(),
            account: session.account.clone(),
            device: challenge.device.clone(),
            authorization: session.authorization,
            mode: session.mode,
            expires_at: session.expires_at,
            refresh_expires_at: session.refresh_expires_at,
            refresh_hash: Sha256::digest(session.refresh_token.as_bytes()).into(),
        };
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (_, body) = request(&mut socket).await;
            let query: Inspection = serde_json::from_slice(&body).unwrap();
            if late_clear {
                seen_.notify_one();
                release_.notified().await;
            }
            reply(
                &mut socket,
                InspectionResult::Accepted {
                    request: query.digest().unwrap(),
                    challenge: Box::new(challenge),
                    envelope,
                },
            )
            .await;
            if !late_clear {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (header, _) = request(&mut socket).await;
                assert!(
                    header.starts_with(&format!("GET /auth/v3/session/{} ", info.device.device_id))
                );
                reply(&mut socket, info).await;
            }
        });
        if late_clear {
            let state = f.state.clone();
            let profile = f.id.clone();
            let pending = tokio::spawn(async move { a::save(&state, profile, id).await });
            tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
                .await
                .unwrap();
            a::clear_session(&f.state, f.id.clone()).unwrap();
            release.notify_one();
            assert!(pending.await.unwrap().is_err());
            assert!(a::snapshot(&f.state, f.id.clone())
                .unwrap()
                .normal
                .is_none());
        } else {
            let saved = a::save(&f.state, f.id.clone(), id).await.unwrap();
            assert!(saved.has_saved_session);
            assert_eq!(saved.device, session.device);
            let public = serde_json::to_string(&saved).unwrap();
            assert!(
                !public.contains(&session.access_token) && !public.contains(&session.refresh_token)
            );
            let before = normal::snapshot(&f.state).unwrap();
            let target = normal::Target::Join {
                profile_id: f.id.clone(),
            };
            let choice = before
                .profiles
                .iter()
                .find(|p| p.target == target)
                .unwrap()
                .profile
                .as_ref()
                .unwrap();
            let fingerprint = choice.scope_fingerprint.clone();
            assert!(normal::select(
                &f.state,
                Some(target.clone()),
                before.generation,
                Some("wrong".into())
            )
            .await
            .is_err());
            let chosen = normal::select(
                &f.state,
                Some(target.clone()),
                before.generation,
                Some(fingerprint),
            )
            .await
            .unwrap();
            assert_eq!(chosen.selected.as_ref().unwrap().device, session.device);
            assert_eq!(chosen.generation, 1);
            let chat = liteseal_desktop::commands::direct::snapshot(&f.state).unwrap();
            assert_eq!(chat.device, session.device);
            assert_eq!(chat.identity.account, session.account);
            assert!(liteseal_desktop::commands::direct::history(&f.state, None)
                .unwrap()
                .messages
                .is_empty());
            let selected_public = serde_json::to_string(&chosen).unwrap();
            assert!(
                !selected_public.contains(&session.access_token)
                    && !selected_public.contains(&session.refresh_token)
            );
            // Joining selection also reopens on a machine without a bound root identity.
            let reopened = AppState::with_device_protection(
                f.state.db_path.to_str().unwrap(),
                Some(f.work.0.join("absent-root.bin")),
                f.protection.clone(),
            )
            .unwrap();
            assert_eq!(
                normal::snapshot(&reopened)
                    .unwrap()
                    .selected
                    .unwrap()
                    .device,
                session.device
            );
            assert!(
                refresh::snapshot(&reopened, target.clone())
                    .unwrap()
                    .current
                    .unwrap()
                    .has_credentials
            );
            for value in [
                serde_json::json!({"name":"load_identity","args":{}}),
                serde_json::json!({"name":"get_contacts","args":{}}),
                serde_json::json!({"name":"clear_expired_messages","args":{}}),
            ] {
                assert!(
                    protocol::dispatch(serde_json::from_value(value).unwrap(), &f.state)
                        .await
                        .is_err()
                );
            }
            assert_eq!(
                protocol::dispatch(Command::ProcessScheduledMessages {}, &f.state)
                    .await
                    .unwrap(),
                serde_json::json!(0)
            );
            assert_eq!(
                protocol::dispatch(Command::ProcessGroups {}, &f.state)
                    .await
                    .unwrap()["changed"],
                0
            );
            assert!(normal::select(&f.state, None, 0, None).await.is_err());
            assert!(!refresh::process(&f.state).await.unwrap());
            let pending = refresh::snapshot(&f.state, target.clone()).unwrap().tasks;
            assert_eq!(pending.len(), 1);
            assert!(pending[0].current);
            a::clear_session(&f.state, f.id.clone()).unwrap();
            assert!(!refresh::process(&f.state).await.unwrap());
            let stopped = normal::select(&f.state, None, chosen.generation, None)
                .await
                .unwrap();
            assert!(stopped.selected.is_none());
            assert!(normal::snapshot(&reopened).unwrap().selected.is_none());
            let root = stopped
                .profiles
                .iter()
                .find(|p| p.target == normal::Target::Root {})
                .unwrap()
                .profile
                .as_ref()
                .unwrap();
            normal::select(
                &f.state,
                Some(normal::Target::Root {}),
                stopped.generation,
                Some(root.scope_fingerprint.clone()),
            )
            .await
            .unwrap();
            assert!(protocol::dispatch(Command::GetContacts {}, &f.state)
                .await
                .is_ok());
            assert!(
                !a::snapshot(&f.state, f.id.clone())
                    .unwrap()
                    .normal
                    .unwrap()
                    .has_saved_session
            );
        }
        server.await.unwrap();
        f.unchanged();
    }
}
