#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        activation::jobs::*,
        tasks::{DeviceTaskStore, TaskOwner},
        witness::platform::Protection,
        Checkpoint, DeviceTrustStore,
    },
};
use liteseal_shared::{
    crypto::{self, KeyPair},
    device_activation::{Challenge, Enable, Envelope, Session},
    trusted_device::*,
};
use rusqlite::Connection;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
struct Fixture {
    path: PathBuf,
    root: Arc<KeyPair>,
    second: Arc<KeyPair>,
    state: DeviceState,
    mode: Enable,
    protection: Protection,
    _work: WorkDirectory,
}
impl Fixture {
    fn new(origin: &str) -> Self {
        let root = Arc::new(crypto::generate_keypair().unwrap());
        let second = Arc::new(crypto::generate_keypair().unwrap());
        let initial = DeviceState::pin(Anchor {
            origin: origin.into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &root),
        })
        .unwrap();
        let device = uuid::Uuid::new_v4().to_string();
        let intent = make_intent(
            initial.anchor(),
            uuid::Uuid::new_v4().to_string(),
            device,
            crypto::random_challenge().unwrap(),
            1000,
            &second,
        )
        .unwrap();
        let challenge = make_challenge(&initial, &intent, 1001, &root).unwrap();
        let proof = answer_challenge(&initial, &intent, &challenge, 1002, &second).unwrap();
        let event = make_event(
            &initial,
            uuid::Uuid::new_v4().to_string(),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            1003,
            &root,
        )
        .unwrap();
        let state = initial.apply(&event).unwrap();
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &root).unwrap();
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let path = work.0.join("activation.db");
        let protection = Protection::isolated_test();
        let mut trust = DeviceTrustStore::open(&path).unwrap();
        trust.protect(protection.witness(&path).unwrap()).unwrap();
        trust.pin(initial.anchor()).unwrap();
        trust
            .import_verified(
                initial.anchor(),
                &Checkpoint::from_state(&initial),
                &[event],
            )
            .unwrap();
        drop(trust);
        Self {
            path,
            root,
            second,
            state,
            mode,
            protection,
            _work: work,
        }
    }
    fn owner(&self, root: bool) -> Owner {
        if root {
            Owner::new(
                self.state.anchor().clone(),
                &self.state.anchor().root.device_id,
                &self.root,
            )
            .unwrap()
        } else {
            Owner::new(
                self.state.anchor().clone(),
                &self.state.secondary().unwrap().device_id,
                &self.second,
            )
            .unwrap()
        }
    }
    fn open(&self, root: bool) -> Store {
        Store::open(
            &self.path,
            self.owner(root),
            if root { &self.root } else { &self.second },
            self.protection.witness(&self.path).unwrap(),
        )
        .unwrap()
    }
    fn prepared(&self, store: &mut Store) -> Task {
        store
            .prepare_login("synthetic-user", self.mode.clone(), &self.second)
            .unwrap()
    }
    fn proof(&self, store: &mut Store) -> Task {
        let task = self.prepared(store);
        let task = store.begin(&task.view(), &self.second).unwrap();
        let challenge = Challenge::make(
            &self.state,
            &self.mode,
            &task.view().id,
            &self.state.secondary().unwrap().device_id,
            2000,
        )
        .unwrap();
        let task = store
            .save_challenge(&task.view(), challenge, &self.second)
            .unwrap();
        store.seal_proof(&task.view(), 2001, &self.second).unwrap()
    }
    fn envelope(&self, task: &Task) -> Envelope {
        let challenge = task.challenge().unwrap();
        Envelope::seal(
            challenge,
            &Session {
                id: uuid::Uuid::new_v4().to_string(),
                account: challenge.account.clone(),
                device: challenge.device.device_id.clone(),
                authorization: challenge.authorization,
                mode: challenge.mode,
                access_token: "synthetic-access-secret".into(),
                refresh_token: "synthetic-refresh-secret".into(),
                expires_at: 300000,
                refresh_expires_at: 3000000,
            },
        )
        .unwrap()
    }
}
#[test]
fn originals_survive_reopen_without_password_or_plaintext_tokens() {
    let f = Fixture::new("https://activation.invalid");
    let mut store = f.open(false);
    let task = f.proof(&mut store);
    let view = task.view();
    let request = task.start("synthetic-account-password").unwrap();
    let original_proof = serde_json::to_vec(&task.proof().unwrap().unwrap()).unwrap();
    drop(store);
    let mut store = f.open(false);
    let task = store.task(&view.id, &f.second).unwrap();
    assert_eq!(view, task.view());
    assert!(
        task.start("another-runtime-password")
            .unwrap()
            .request_token
            == request.request_token
    );
    assert_eq!(
        serde_json::to_vec(&task.proof().unwrap().unwrap()).unwrap(),
        original_proof
    );
    let task = store
        .accept_session(
            &task.view(),
            task.challenge().unwrap().clone(),
            f.envelope(&task),
            &f.second,
        )
        .unwrap();
    assert_eq!(task.view().stage, Stage::Complete);
    let sql = Connection::open(&f.path).unwrap();
    let bytes: Vec<u8> = sql
        .query_row(
            "SELECT body FROM device_control_tasks WHERE id=?1",
            [&view.id],
            |r| r.get(0),
        )
        .unwrap();
    for secret in [
        "synthetic-account-password",
        "synthetic-access-secret",
        "synthetic-refresh-secret",
        &request.request_token,
    ] {
        assert!(!bytes
            .windows(secret.len())
            .any(|slice| slice == secret.as_bytes()));
    }
    let visible = serde_json::to_string(&task.view()).unwrap();
    assert!(
        !visible.contains("credential")
            && !visible.contains("proof")
            && !visible.contains("envelope")
    );
    drop(sql);
    drop(store);
    let mut store = f.open(false);
    assert!(store.session(&view.id, &f.second).unwrap().access_token == "synthetic-access-secret");
    assert!(store
        .prepare_login("synthetic-user", f.mode.clone(), &f.second)
        .is_ok());
}
#[test]
fn immutable_scope_single_pending_and_cancel_before_start_are_isolated() {
    let f = Fixture::new("https://activation.invalid");
    let mut join = f.open(false);
    let task = f.prepared(&mut join);
    assert!(join
        .prepare_login("synthetic-user", f.mode.clone(), &f.second)
        .is_err());
    assert!(join.prepare_enable(&f.second).is_err());
    let mut root = f.open(true);
    let enable = root.prepare_enable(&f.root).unwrap();
    // A pending enable must not prevent the root from proving a new session
    // after its old bearer expires and the enable response was lost.
    assert!(root
        .prepare_login("synthetic-user", f.mode.clone(), &f.root)
        .is_ok());
    assert!(root.task(&task.view().id, &f.root).is_err());
    assert!(join.task(&task.view().id, &f.root).is_err());
    let cancelled = join.request_cancel(&task.view().id, &f.second).unwrap();
    assert_eq!(cancelled.view().stage, Stage::Cancelled);
    assert_eq!(
        join.request_cancel(&task.view().id, &f.second)
            .unwrap()
            .view(),
        cancelled.view()
    );
    assert_eq!(
        root.request_cancel(&enable.view().id, &f.root)
            .unwrap()
            .view()
            .stage,
        Stage::Cancelled
    );
    assert!(join
        .prepare_login("synthetic-user", f.mode.clone(), &f.second)
        .is_ok());
    let mut old = DeviceTaskStore::open(
        &f.path,
        TaskOwner::for_root(f.state.anchor(), &f.root).unwrap(),
        &f.root,
    )
    .unwrap();
    old.protect(f.protection.witness(&f.path).unwrap()).unwrap();
    assert!(old.views(&f.root).unwrap().is_empty());
    drop(old);
}
#[test]
fn cancellation_revision_rejects_late_result_and_accepted_race_keeps_original_result() {
    let f = Fixture::new("https://activation.invalid");
    let mut store = f.open(false);
    let task = f.proof(&mut store);
    let original = serde_json::to_vec(&task.proof().unwrap().unwrap()).unwrap();
    let view = task.view();
    let envelope = f.envelope(&task);
    let cancellation = store.request_cancel(&view.id, &f.second).unwrap();
    assert!(store
        .accept_session(
            &view,
            task.challenge().unwrap().clone(),
            envelope.clone(),
            &f.second
        )
        .is_err());
    drop(store);
    let mut store = f.open(false);
    let task = store.task(&view.id, &f.second).unwrap();
    assert_eq!(task.view(), cancellation.view());
    assert!(task.view().cancel_requested);
    assert_eq!(
        serde_json::to_vec(&task.proof().unwrap().unwrap()).unwrap(),
        original
    );
    let task = store
        .accept_session(
            &task.view(),
            task.challenge().unwrap().clone(),
            envelope,
            &f.second,
        )
        .unwrap();
    assert_eq!(task.view().stage, Stage::Complete);
    assert!(task.view().cancel_requested);
    assert_eq!(
        store.request_cancel(&view.id, &f.second).unwrap().view(),
        task.view()
    );
}
#[test]
fn wrong_challenge_ciphertext_and_restored_old_database_fail_closed() {
    let f = Fixture::new("https://activation.invalid");
    let mut store = f.open(false);
    let task = f.prepared(&mut store);
    let view = task.view();
    drop(store);
    let snapshot = std::fs::read(&f.path).unwrap();
    let mut store = f.open(false);
    let task = store.begin(&view, &f.second).unwrap();
    let wrong = Challenge::make(
        &f.state,
        &f.mode,
        &uuid::Uuid::new_v4().to_string(),
        &f.state.secondary().unwrap().device_id,
        2000,
    )
    .unwrap();
    assert!(store
        .save_challenge(&task.view(), wrong, &f.second)
        .is_err());
    let mut damaged = Challenge::make(
        &f.state,
        &f.mode,
        &view.id,
        &f.state.secondary().unwrap().device_id,
        2000,
    )
    .unwrap();
    damaged.encrypted[40] ^= 1;
    assert!(store
        .save_challenge(&task.view(), damaged, &f.second)
        .is_err());
    assert_eq!(store.task(&view.id, &f.second).unwrap().view(), task.view());
    drop(store);
    std::fs::write(&f.path, snapshot).unwrap();
    assert!(Store::open(
        &f.path,
        f.owner(false),
        &f.second,
        f.protection.witness(&f.path).unwrap()
    )
    .is_err());
}
#[test]
fn accepted_identity_cannot_be_opened_after_verified_revocation() {
    let f = Fixture::new("https://activation.invalid");
    let mut store = f.open(false);
    let task = f.proof(&mut store);
    let task = store
        .accept_session(
            &task.view(),
            task.challenge().unwrap().clone(),
            f.envelope(&task),
            &f.second,
        )
        .unwrap();
    let event = make_event(
        &f.state,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: f.state.secondary().unwrap().device_id.clone(),
            grant_hash: f.state.grant_hash().unwrap().to_vec(),
        },
        3000,
        &f.root,
    )
    .unwrap();
    let mut trust = DeviceTrustStore::open(&f.path).unwrap();
    trust
        .protect(f.protection.witness(&f.path).unwrap())
        .unwrap();
    trust
        .import_verified(
            f.state.anchor(),
            &Checkpoint::from_state(&f.state),
            &[event],
        )
        .unwrap();
    assert_eq!(
        store.task(&task.view().id, &f.second).unwrap().view().stage,
        Stage::Complete
    );
    assert!(store.session(&task.view().id, &f.second).is_err());
}
#[tokio::test]
async fn cancellation_lock_and_session_rotation_reject_late_lookup_without_followup() {
    for action in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let actor = Arc::new(
            Coordinator::open_with_protection(
                &f.path,
                f.owner(true),
                &f.root,
                f.protection.clone(),
            )
            .unwrap(),
        );
        actor.renew_session("synthetic-first-token".into()).unwrap();
        let view = actor.prepare_enable(&f.root).unwrap();
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let seen_ = seen.clone();
        let release_ = release.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![];
            let mut chunk = [0; 4096];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            seen_.notify_one();
            release_.notified().await;
            let body = br#"{"enabled":false,"event":null}"#;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
            drop(socket);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(40), listener.accept())
                    .await
                    .is_err()
            );
        });
        let actor_ = actor.clone();
        let keys_ = f.root.clone();
        let id = view.id.clone();
        let step = tokio::spawn(async move { actor_.step(&id, None, &keys_).await });
        seen.notified().await;
        match action {
            0 => {
                actor.request_cancel(&view.id, &f.root).unwrap();
            }
            1 => {
                actor.invalidate().unwrap();
                assert!(actor.views(&f.root).is_err());
                actor.resume().unwrap();
            }
            _ => actor.renew_session("synthetic-new-token".into()).unwrap(),
        }
        release.notify_one();
        assert!(step.await.unwrap().is_err());
        server.await.unwrap();
        let current = actor.views(&f.root).unwrap().pop().unwrap();
        assert_eq!(current.stage, Stage::Started);
        assert_eq!(current.cancel_requested, action == 0);
    }
}
#[tokio::test]
async fn late_unknown_login_never_returns_a_password_prompt_after_cancellation_or_lock() {
    for lock in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let actor = Arc::new(
            Coordinator::open_with_protection(
                &f.path,
                f.owner(false),
                &f.second,
                f.protection.clone(),
            )
            .unwrap(),
        );
        let task = actor
            .prepare_login("synthetic-user", f.mode.clone(), &f.second)
            .unwrap();
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let seen_ = seen.clone();
        let release_ = release.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![];
            let mut chunk = [0; 4096];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            seen_.notify_one();
            release_.notified().await;
            socket
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let actor_ = actor.clone();
        let keys_ = f.second.clone();
        let id = task.id.clone();
        let step = tokio::spawn(async move { actor_.step(&id, None, &keys_).await });
        seen.notified().await;
        if lock {
            actor.invalidate().unwrap();
            actor.resume().unwrap();
        } else {
            actor.request_cancel(&task.id, &f.second).unwrap();
        }
        release.notify_one();
        assert!(step.await.unwrap().is_err());
        server.await.unwrap();
    }
}
