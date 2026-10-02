#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        activation::{jobs as a, refresh::jobs as r, ActivationApi, CheckedSession},
        witness::platform::Protection,
        Checkpoint, DeviceTrustStore,
    },
};
use liteseal_shared::{
    crypto::{self, KeyPair},
    device_activation::{refresh as wire, Challenge, Enable, Envelope, Session, SessionInfo},
    trusted_device::*,
};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
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
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let path = work.0.join("refresh.db");
        let protection = Protection::isolated_test();
        let root = Arc::new(crypto::generate_keypair().unwrap());
        let second = Arc::new(crypto::generate_keypair().unwrap());
        let initial = DeviceState::pin(Anchor {
            origin: origin.into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &root),
        })
        .unwrap();
        let intent = make_intent(
            initial.anchor(),
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
            crypto::random_challenge().unwrap(),
            now() - 1000,
            &second,
        )
        .unwrap();
        let challenge = make_challenge(&initial, &intent, now() - 900, &root).unwrap();
        let proof = answer_challenge(&initial, &intent, &challenge, now() - 800, &second).unwrap();
        let event = make_event(
            &initial,
            uuid::Uuid::new_v4().to_string(),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            now() - 700,
            &root,
        )
        .unwrap();
        let state = initial.apply(&event).unwrap();
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &root).unwrap();
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
    fn keys(&self, root: bool) -> &KeyPair {
        if root {
            &self.root
        } else {
            &self.second
        }
    }
    fn device(&self, root: bool) -> &str {
        if root {
            &self.state.anchor().root.device_id
        } else {
            &self.state.secondary().unwrap().device_id
        }
    }
    fn owner(&self, root: bool) -> a::Owner {
        a::Owner::new(
            self.state.anchor().clone(),
            self.device(root),
            self.keys(root),
        )
        .unwrap()
    }
    fn store(&self, root: bool) -> r::Store {
        r::Store::open(
            &self.path,
            self.owner(root),
            self.keys(root),
            self.protection.witness(&self.path).unwrap(),
        )
        .unwrap()
    }
    fn coordinator(&self, root: bool) -> r::Coordinator {
        r::Coordinator::open_with_protection(
            &self.path,
            self.owner(root),
            self.keys(root),
            self.protection.clone(),
        )
        .unwrap()
    }
    fn activated(&self, root: bool) -> (a::Task, Session) {
        let keys = self.keys(root);
        let mut store = a::Store::open(
            &self.path,
            self.owner(root),
            keys,
            self.protection.witness(&self.path).unwrap(),
        )
        .unwrap();
        let task = store
            .prepare_login("synthetic-refresh-user", self.mode.clone(), keys)
            .unwrap();
        let task = store.begin(&task.view(), keys).unwrap();
        let at = now();
        let challenge = Challenge::make(
            &self.state,
            &self.mode,
            &task.view().id,
            self.device(root),
            at,
        )
        .unwrap();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: challenge.account.clone(),
            device: challenge.device.device_id.clone(),
            authorization: challenge.authorization,
            mode: challenge.mode,
            access_token: format!("synthetic-access-{}", task.view().id),
            refresh_token: format!("synthetic-refresh-{}", task.view().id),
            expires_at: at + 60_000,
            refresh_expires_at: at + 180_000,
        };
        let envelope = Envelope::seal(&challenge, &session).unwrap();
        let task = store.save_challenge(&task.view(), challenge, keys).unwrap();
        let task = store.seal_proof(&task.view(), at + 1, keys).unwrap();
        let challenge = task.challenge().unwrap().clone();
        let task = store
            .accept_session(&task.view(), challenge, envelope, keys)
            .unwrap();
        (task, session)
    }
    async fn checked(
        &self,
        listener: &TcpListener,
        root: bool,
        session: &Session,
    ) -> CheckedSession {
        let device = DeviceIdentity::from_keys(self.device(root).into(), self.keys(root));
        let info = SessionInfo {
            version: 1,
            id: session.id.clone(),
            account: session.account.clone(),
            device,
            authorization: session.authorization,
            mode: session.mode,
            expires_at: session.expires_at,
            refresh_expires_at: session.refresh_expires_at,
            refresh_hash: Sha256::digest(session.refresh_token.as_bytes()).into(),
        };
        let api = ActivationApi::new(&self.state.anchor().origin).unwrap();
        let server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (header, _) = request(&mut socket).await;
            assert!(header.starts_with("GET /auth/v3/session/"));
            assert!(header.contains(&session.access_token));
            reply(&mut socket, 200, &info).await;
        };
        let (checked, _) = tokio::join!(
            api.check_session(
                &session.access_token,
                &self.state,
                &self.mode,
                &info.device,
                self.keys(root)
            ),
            server
        );
        checked.unwrap()
    }
}
async fn request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let (header, start, len) = loop {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let len = header
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            break (header, end + 4, len);
        }
    };
    while bytes.len() < start + len {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&chunk[..n]);
    }
    (header, bytes[start..start + len].to_vec())
}
async fn reply(socket: &mut TcpStream, status: u16, value: &impl serde::Serialize) {
    let body = if status == 204 {
        Vec::new()
    } else {
        serde_json::to_vec(value).unwrap()
    };
    let header=format!("HTTP/1.1 {status} test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
    socket.write_all(header.as_bytes()).await.unwrap();
    socket.write_all(&body).await.unwrap();
}
fn successor(request: &wire::Start) -> Session {
    let at = now();
    Session {
        id: uuid::Uuid::new_v4().to_string(),
        account: request.account.clone(),
        device: request.device.device_id.clone(),
        authorization: request.authorization,
        mode: request.mode,
        access_token: format!("synthetic-next-access-{}", request.id),
        refresh_token: format!("synthetic-next-refresh-{}", request.id),
        expires_at: at + 60_000,
        refresh_expires_at: at + 180_000,
    }
}
#[tokio::test]
async fn root_and_secondary_current_records_are_private_scoped_and_original_preparation_reopens() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    for root in [true, false] {
        let (activation, session) = f.activated(root);
        let checked = f.checked(&listener, root, &session).await;
        let mut store = f.store(root);
        let view = store.adopt(&activation, checked, f.keys(root)).unwrap();
        assert!(view.has_credentials && view.eligible);
        assert_eq!(view.generation, 1);
        let public = serde_json::to_string(&view).unwrap();
        assert!(
            !public.contains(&session.access_token) && !public.contains(&session.refresh_token)
        );
        let job = store.prepare(f.keys(root)).unwrap();
        let original = store.task(&job.id, f.keys(root)).unwrap().request().clone();
        assert!(store.prepare(f.keys(root)).is_err());
        drop(store);
        let mut reopened = f.store(root);
        assert_eq!(
            reopened.task(&job.id, f.keys(root)).unwrap().request(),
            &original
        );
        assert_eq!(
            reopened.session(f.keys(root)).unwrap().refresh_token,
            session.refresh_token
        );
        assert_eq!(
            reopened
                .request_cancel_confirmed(&job.id, f.keys(root), false)
                .unwrap()
                .stage,
            r::Stage::Cancelled
        );
        reopened.forget_ended(&job.id, f.keys(root)).unwrap();
        assert!(reopened.views(f.keys(root)).unwrap().is_empty());
        assert!(f.store(!root).task(&job.id, f.keys(!root)).is_err());
        let bytes = std::fs::read(&f.path).unwrap();
        assert!(!bytes
            .windows(session.refresh_token.len())
            .any(|b| b == session.refresh_token.as_bytes()));
    }
}
#[tokio::test]
async fn lost_proof_response_reopens_original_proof_and_commits_current_session_with_result() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let root = false;
    let (activation, session) = f.activated(root);
    let actor = f.coordinator(root);
    actor
        .adopt(
            &activation,
            f.checked(&listener, root, &session).await,
            f.keys(root),
        )
        .unwrap();
    let job = actor.prepare(f.keys(root)).unwrap();
    let expected = f
        .store(root)
        .task(&job.id, f.keys(root))
        .unwrap()
        .request()
        .clone();
    let directory = f.state.clone();
    let mode = f.mode.clone();
    let original_token = session.refresh_token.clone();
    let request_expected = expected.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, body) = request(&mut socket).await;
        assert!(header.contains(&original_token));
        let start: wire::Start = serde_json::from_slice(&body).unwrap();
        assert_eq!(start, request_expected);
        let challenge =
            Challenge::make(&directory, &mode, &start.id, &start.device.device_id, now()).unwrap();
        reply(
            &mut socket,
            200,
            &wire::Reply::Pending {
                request: start.digest().unwrap(),
                challenge: Box::new(challenge.clone()),
            },
        )
        .await;
        let (mut socket, _) = listener.accept().await.unwrap();
        let (_, proof) = request(&mut socket).await;
        let result = successor(&start);
        let accepted = wire::Reply::Accepted {
            request: start.digest().unwrap(),
            challenge: Box::new(challenge.clone()),
            envelope: wire::Envelope::seal(&start, &challenge, &result).unwrap(),
        };
        reply(&mut socket, 503, &serde_json::json!({"lost":true})).await;
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, replayed) = request(&mut socket).await;
        assert!(header.starts_with(&format!("POST /auth/v3/refresh/{}/proof ", start.id)));
        assert_eq!(replayed, proof);
        reply(&mut socket, 200, &accepted).await;
        result
    });
    let lost = actor.step(&job.id, f.keys(root)).await.unwrap();
    assert_eq!(lost.condition, r::Condition::Retry);
    assert_eq!(lost.http_status, Some(503));
    assert_eq!(lost.task.stage, r::Stage::Proving);
    let proof = f
        .store(root)
        .task(&job.id, f.keys(root))
        .unwrap()
        .proof()
        .unwrap()
        .unwrap()
        .digest()
        .unwrap();
    drop(actor);
    let reopened = f.coordinator(root);
    let result = reopened.step(&job.id, f.keys(root)).await.unwrap();
    assert_eq!(result.condition, r::Condition::Complete);
    let next = server.await.unwrap();
    assert_eq!(reopened.session(f.keys(root)).unwrap().id, next.id);
    assert_eq!(
        reopened
            .current_view(f.keys(root))
            .unwrap()
            .unwrap()
            .generation,
        2
    );
    let original = f.store(root).task(&job.id, f.keys(root)).unwrap();
    assert_eq!(original.request(), &expected);
    assert_eq!(original.proof().unwrap().unwrap().digest().unwrap(), proof);
    reopened.forget_ended(&job.id, f.keys(root)).unwrap();
    assert_eq!(
        reopened.session(f.keys(root)).unwrap().refresh_token,
        next.refresh_token
    );
    let another = reopened.prepare(f.keys(root)).unwrap();
    assert_ne!(another.id, job.id);
    assert_eq!(
        f.store(root)
            .task(&another.id, f.keys(root))
            .unwrap()
            .request()
            .session,
        next.id
    );
}
#[tokio::test]
async fn lock_clear_and_new_initial_session_fence_late_pending_response() {
    for action in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let root = true;
        let (activation, session) = f.activated(root);
        let actor = Arc::new(f.coordinator(root));
        actor
            .adopt(
                &activation,
                f.checked(&listener, root, &session).await,
                f.keys(root),
            )
            .unwrap();
        let job = actor.prepare(f.keys(root)).unwrap();
        let (new_activation, new_session) = f.activated(root);
        let checked = f.checked(&listener, root, &new_session).await;
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (seen_, release_) = (seen.clone(), release.clone());
        let state = f.state.clone();
        let mode = f.mode.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (_, body) = request(&mut socket).await;
            let start: wire::Start = serde_json::from_slice(&body).unwrap();
            let challenge =
                Challenge::make(&state, &mode, &start.id, &start.device.device_id, now()).unwrap();
            seen_.notify_one();
            release_.notified().await;
            reply(
                &mut socket,
                200,
                &wire::Reply::Pending {
                    request: start.digest().unwrap(),
                    challenge: Box::new(challenge),
                },
            )
            .await;
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let active = actor.clone();
        let keys = f.root.clone();
        let id = job.id.clone();
        let pending = tokio::spawn(async move { active.step(&id, &keys).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
            .await
            .unwrap();
        match action {
            0 => {
                actor.invalidate().unwrap();
                actor.resume().unwrap();
            }
            1 => actor.clear_local(f.keys(root)).unwrap(),
            2 => {
                actor.adopt(&new_activation, checked, f.keys(root)).unwrap();
            }
            _ => unreachable!(),
        }
        release.notify_one();
        assert!(pending.await.unwrap().is_err());
        server.await.unwrap();
        assert!(f
            .store(root)
            .task(&job.id, f.keys(root))
            .unwrap()
            .challenge()
            .is_none());
        match action {
            0 => assert_eq!(actor.session(f.keys(root)).unwrap().id, session.id),
            1 => assert!(actor.session(f.keys(root)).is_err()),
            2 => assert_eq!(actor.session(f.keys(root)).unwrap().id, new_session.id),
            _ => unreachable!(),
        }
    }
}
#[tokio::test]
async fn cancellation_during_proof_rejects_late_acceptance_and_confirms_family_logout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let root = false;
    let (activation, session) = f.activated(root);
    let actor = Arc::new(f.coordinator(root));
    actor
        .adopt(
            &activation,
            f.checked(&listener, root, &session).await,
            f.keys(root),
        )
        .unwrap();
    let job = actor.prepare(f.keys(root)).unwrap();
    let seen = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (seen_, release_) = (seen.clone(), release.clone());
    let state = f.state.clone();
    let mode = f.mode.clone();
    let old_access = session.access_token.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (_, body) = request(&mut socket).await;
        let start: wire::Start = serde_json::from_slice(&body).unwrap();
        let challenge =
            Challenge::make(&state, &mode, &start.id, &start.device.device_id, now()).unwrap();
        reply(
            &mut socket,
            200,
            &wire::Reply::Pending {
                request: start.digest().unwrap(),
                challenge: Box::new(challenge.clone()),
            },
        )
        .await;
        let (mut socket, _) = listener.accept().await.unwrap();
        let (_, _) = request(&mut socket).await;
        let next = successor(&start);
        seen_.notify_one();
        release_.notified().await;
        reply(
            &mut socket,
            200,
            &wire::Reply::Accepted {
                request: start.digest().unwrap(),
                challenge: Box::new(challenge.clone()),
                envelope: wire::Envelope::seal(&start, &challenge, &next).unwrap(),
            },
        )
        .await;
        let (mut socket, _) = listener.accept().await.unwrap();
        let (header, body) = request(&mut socket).await;
        assert!(header.starts_with("POST /auth/logout "));
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["access_token"], old_access);
        reply(&mut socket, 204, &()).await;
    });
    let active = actor.clone();
    let keys = f.second.clone();
    let id = job.id.clone();
    let pending = tokio::spawn(async move { active.step(&id, &keys).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
        .await
        .unwrap();
    let before_cancel = actor.views(f.keys(root)).unwrap();
    assert!(actor
        .request_cancel_confirmed(&job.id, f.keys(root), false)
        .is_err());
    assert_eq!(actor.views(f.keys(root)).unwrap(), before_cancel);
    actor
        .request_cancel_confirmed(&job.id, f.keys(root), true)
        .unwrap();
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    assert_eq!(actor.session(f.keys(root)).unwrap().id, session.id);
    assert_eq!(
        actor.step(&job.id, f.keys(root)).await.unwrap().condition,
        r::Condition::Ended
    );
    server.await.unwrap();
    assert!(
        !actor
            .current_view(f.keys(root))
            .unwrap()
            .unwrap()
            .has_credentials
    );
    assert!(actor.session(f.keys(root)).is_err());
    actor.forget_ended(&job.id, f.keys(root)).unwrap();
}

#[tokio::test]
async fn original_family_logout_closes_later_successors_but_not_new_independent_login() {
    for independent in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
        let root = true;
        let (activation, session) = f.activated(root);
        let actor = f.coordinator(root);
        actor
            .adopt(
                &activation,
                f.checked(&listener, root, &session).await,
                f.keys(root),
            )
            .unwrap();
        let initial = actor.prepare(f.keys(root)).unwrap();
        let state = f.state.clone();
        let mode = f.mode.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (_, body) = request(&mut socket).await;
                let start: wire::Start = serde_json::from_slice(&body).unwrap();
                let challenge =
                    Challenge::make(&state, &mode, &start.id, &start.device.device_id, now())
                        .unwrap();
                reply(
                    &mut socket,
                    200,
                    &wire::Reply::Pending {
                        request: start.digest().unwrap(),
                        challenge: Box::new(challenge.clone()),
                    },
                )
                .await;
                let (mut socket, _) = listener.accept().await.unwrap();
                let (_, _) = request(&mut socket).await;
                let next = successor(&start);
                reply(
                    &mut socket,
                    200,
                    &wire::Reply::Accepted {
                        request: start.digest().unwrap(),
                        challenge: Box::new(challenge.clone()),
                        envelope: wire::Envelope::seal(&start, &challenge, &next).unwrap(),
                    },
                )
                .await;
            }
            listener
        });
        assert_eq!(
            actor
                .step(&initial.id, f.keys(root))
                .await
                .unwrap()
                .condition,
            r::Condition::Complete
        );
        let second = actor.prepare(f.keys(root)).unwrap();
        assert_eq!(
            actor
                .step(&second.id, f.keys(root))
                .await
                .unwrap()
                .condition,
            r::Condition::Complete
        );
        let listener = server.await.unwrap();
        if independent {
            let (new_activation, new_session) = f.activated(root);
            // A fresh metadata response still binds to the original realm.
            let checked = f.checked(&listener, root, &new_session).await;
            actor.adopt(&new_activation, checked, f.keys(root)).unwrap();
            let old = initial.id.clone();
            let token = session.access_token.clone();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (_, body) = request(&mut socket).await;
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["access_token"],
                    token
                );
                reply(&mut socket, 204, &()).await;
            });
            actor.request_cancel(&old, f.keys(root)).unwrap();
            assert_eq!(
                actor.step(&old, f.keys(root)).await.unwrap().condition,
                r::Condition::Ended
            );
            server.await.unwrap();
            assert_eq!(actor.session(f.keys(root)).unwrap().id, new_session.id);
        } else {
            let token = session.access_token.clone();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (header, body) = request(&mut socket).await;
                assert!(header.starts_with("POST /auth/logout "));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["access_token"],
                    token
                );
                reply(&mut socket, 204, &()).await;
            });
            actor.request_cancel(&initial.id, f.keys(root)).unwrap();
            assert_eq!(
                actor
                    .step(&initial.id, f.keys(root))
                    .await
                    .unwrap()
                    .condition,
                r::Condition::Ended
            );
            server.await.unwrap();
            assert!(actor.session(f.keys(root)).is_err());
            actor.forget_ended(&second.id, f.keys(root)).unwrap();
        }
    }
}

#[tokio::test]
async fn signed_revocation_retains_metadata_and_native_rollback_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let root = false;
    let (activation, session) = f.activated(root);
    let actor = f.coordinator(root);
    actor
        .adopt(
            &activation,
            f.checked(&listener, root, &session).await,
            f.keys(root),
        )
        .unwrap();
    let job = actor.prepare(f.keys(root)).unwrap();
    let grant = f.state.grant_hash().unwrap().to_vec();
    let event = make_event(
        &f.state,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: f.device(root).into(),
            grant_hash: grant,
        },
        now(),
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
    drop(trust);
    assert_eq!(
        actor.step(&job.id, f.keys(root)).await.unwrap().condition,
        r::Condition::Ineligible
    );
    assert!(actor.current_view(f.keys(root)).unwrap().is_some());
    assert!(!actor.current_view(f.keys(root)).unwrap().unwrap().eligible);
    assert!(actor.session(f.keys(root)).is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    drop(actor);
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(conn);
    let snapshot = std::fs::read(&f.path).unwrap();
    let mut store = f.store(root);
    store.clear_local(f.keys(root)).unwrap();
    drop(store);
    std::fs::write(&f.path, snapshot).unwrap();
    assert!(r::Store::open(
        &f.path,
        f.owner(root),
        f.keys(root),
        f.protection.witness(&f.path).unwrap()
    )
    .is_err());
}

#[tokio::test]
async fn locked_adoption_and_wrong_activation_scope_cannot_replace_current_metadata() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let (root_activation, root_session) = f.activated(true);
    let actor = f.coordinator(true);
    actor
        .adopt(
            &root_activation,
            f.checked(&listener, true, &root_session).await,
            f.keys(true),
        )
        .unwrap();
    let (second_activation, second_session) = f.activated(false);
    let checked = f.checked(&listener, false, &second_session).await;
    assert!(actor
        .adopt(&second_activation, checked, f.keys(true))
        .is_err());
    assert_eq!(actor.session(f.keys(true)).unwrap().id, root_session.id);
    let (new_activation, new_session) = f.activated(true);
    let checked = f.checked(&listener, true, &new_session).await;
    actor.invalidate().unwrap();
    assert!(actor.adopt(&new_activation, checked, f.keys(true)).is_err());
    assert!(actor.current_view(f.keys(true)).is_err());
    actor.resume().unwrap();
    assert_eq!(actor.session(f.keys(true)).unwrap().id, root_session.id);
    actor.invalidate().unwrap();
    actor.clear_local(f.keys(true)).unwrap();
    actor.resume().unwrap();
    assert!(
        !actor
            .current_view(f.keys(true))
            .unwrap()
            .unwrap()
            .has_credentials
    );
    assert!(actor.session(f.keys(true)).is_err());
}
