#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        profiles::{active, JoinProfileStore},
        tasks::{anchor_fingerprint, DeviceTaskStore},
        witness::platform::Protection,
        Checkpoint,
    },
};
use liteseal_shared::{crypto, trusted_device::*};
fn authorized(
    root: std::path::PathBuf,
    protection: Protection,
) -> (JoinProfileStore, String, Anchor) {
    let (profiles, id, state, _) = authorized_at(root, protection, "https://active.invalid");
    (profiles, id, state.anchor().clone())
}
fn authorized_at(
    root: std::path::PathBuf,
    protection: Protection,
    origin: &str,
) -> (JoinProfileStore, String, DeviceState, crypto::KeyPair) {
    let profiles = JoinProfileStore::with_protection(root, protection.clone());
    let profile = profiles.create(origin, "synthetic-user", "joined").unwrap();
    let id = profile.view().id;
    let keys = profile.keys().unwrap();
    let path = profiles.database(&id).unwrap();
    let rootkeys = crypto::generate_keypair().unwrap();
    let anchor = Anchor {
        origin: profile.view().origin,
        account: uuid::Uuid::new_v4().to_string(),
        root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &rootkeys),
    };
    let initial = DeviceState::pin(anchor.clone()).unwrap();
    let status = JoinStatus {
        ticket: JoinTicket {
            id: profile.task_id().into(),
            anchor: anchor.clone(),
            device: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
            device_name: "joined".into(),
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
    let mut tasks = DeviceTaskStore::open(&path, profile.owner().unwrap(), &keys).unwrap();
    tasks.protect(protection.witness(&path).unwrap()).unwrap();
    let draft = tasks.get(profile.task_id(), &keys).unwrap();
    let task = tasks.accept_ticket(&draft, &status, &keys).unwrap();
    let task = tasks
        .confirm_root(&task, &anchor, &anchor_fingerprint(&anchor), &keys)
        .unwrap();
    let challenge = make_challenge(&initial, task.intent().unwrap(), 1001, &rootkeys).unwrap();
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
        &rootkeys,
    )
    .unwrap();
    tasks
        .trust()
        .import_verified(
            &anchor,
            &Checkpoint::from_state(&initial),
            std::slice::from_ref(&event),
        )
        .unwrap();
    tasks
        .confirm_join_authorized(&task, &event.id, &keys)
        .unwrap();
    let state = initial.apply(&event).unwrap();
    (profiles, id, state, rootkeys)
}
#[test]
fn unconfirmed_profile_is_not_a_normal_account_and_does_not_change_identity() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let root = work.0.join("joining");
    let protection = Protection::isolated_test();
    let store = JoinProfileStore::with_protection(root.clone(), protection.clone());
    let profile = store
        .create("https://active.invalid", "synthetic-user", "waiting")
        .unwrap();
    let id = profile.view().id;
    let original = std::fs::read(root.join(&id).join("identity.bin")).unwrap();
    assert!(active::Store::open_with_protection(root.clone(), &id, protection).is_err());
    assert_eq!(
        std::fs::read(root.join(&id).join("identity.bin")).unwrap(),
        original
    );
}
#[test]
fn accepted_join_opens_only_its_bound_scope_without_creating_a_session() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let root = work.0.join("joining");
    let protection = Protection::isolated_test();
    let (profiles, id, _) = authorized(root.clone(), protection.clone());
    let original = std::fs::read(root.join(&id).join("identity.bin")).unwrap();
    let mut active =
        active::Store::open_with_protection(root.clone(), &id, protection.clone()).unwrap();
    assert!(active.load().unwrap().is_none());
    active.clear_session().unwrap();
    assert!(active.load().unwrap().is_none());
    for bad in ["..", "../outside", "other"] {
        assert!(
            active::Store::open_with_protection(root.clone(), bad, protection.clone()).is_err()
        );
    }
    assert_eq!(
        std::fs::read(root.join(&id).join("identity.bin")).unwrap(),
        original
    );
    assert!(profiles.load(&id).is_ok());
}
#[test]
fn joined_cleanup_preserves_any_normal_profile_marker() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let root = work.0.join("joining");
    let protection = Protection::isolated_test();
    let (profiles, id, _) = authorized(root.clone(), protection);
    let path = profiles.database(&id).unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    sql.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES('synthetic-active',?1,1,'active_profile',1,X'00')",[&id]).unwrap();
    drop(sql);
    assert!(profiles.remove(&id).is_err());
    assert!(profiles.load(&id).is_ok());
    assert!(path.exists());
}

use liteseal_core::trusted_devices::activation::{jobs, ActivationApi};
use liteseal_shared::device_activation::{Challenge, Enable, Envelope, Session, SessionInfo};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
#[tokio::test]
async fn refreshed_current_credentials_overlay_join_profile_and_local_clear_is_atomic() {
    use liteseal_core::trusted_devices::activation::refresh::jobs as refresh;
    use liteseal_shared::device_activation::refresh as wire;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let socket = listener.into_std().unwrap();
    let save_listener = TcpListener::from_std(socket.try_clone().unwrap()).unwrap();
    let listener = TcpListener::from_std(socket).unwrap();
    let f = SessionFixture::new(&origin);
    f.save(save_listener, None).await.unwrap();
    let local = f.open();
    let path = local.database().unwrap();
    let owner = local.job_owner().unwrap();
    drop(local);
    let actor =
        refresh::Coordinator::open_with_protection(&path, owner, &f.keys, f.protection.clone())
            .unwrap();
    assert!(
        actor
            .current_view(&f.keys)
            .unwrap()
            .unwrap()
            .has_credentials
    );
    let job = actor.prepare(&f.keys).unwrap();
    let start = refresh::Store::open(
        &path,
        f.open().job_owner().unwrap(),
        &f.keys,
        f.protection.witness(&path).unwrap(),
    )
    .unwrap()
    .task(&job.id, &f.keys)
    .unwrap()
    .request()
    .clone();
    let state = f.state.clone();
    let mode = f.mode.clone();
    let next = Session {
        id: uuid::Uuid::new_v4().to_string(),
        account: start.account.clone(),
        device: start.device.device_id.clone(),
        authorization: start.authorization,
        mode: start.mode,
        access_token: "synthetic-refreshed-profile-access".into(),
        refresh_token: "synthetic-refreshed-profile-refresh".into(),
        expires_at: chrono::Utc::now().timestamp_millis() + 60_000,
        refresh_expires_at: chrono::Utc::now().timestamp_millis() + 120_000,
    };
    let challenge = Challenge::make(
        &state,
        &mode,
        &start.id,
        &start.device.device_id,
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    let pending = serde_json::to_vec(&wire::Reply::Pending {
        request: start.digest().unwrap(),
        challenge: Box::new(challenge.clone()),
    })
    .unwrap();
    let accepted = serde_json::to_vec(&wire::Reply::Accepted {
        request: start.digest().unwrap(),
        challenge: Box::new(challenge.clone()),
        envelope: wire::Envelope::seal(&start, &challenge, &next).unwrap(),
    })
    .unwrap();
    let server = async {
        for body in [pending, accepted] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                    break;
                }
            }
            let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        }
    };
    let (result, _) = tokio::join!(actor.step(&job.id, &f.keys), server);
    assert_eq!(result.unwrap().condition, refresh::Condition::Complete);
    let mut reopened = f.open();
    let profile = reopened.load().unwrap().unwrap();
    assert_eq!(profile.identity().token, next.access_token);
    assert_eq!(profile.identity().refresh_token, next.refresh_token);
    assert_eq!(profile.view().revision, 1);
    reopened.clear_session().unwrap();
    assert!(reopened
        .load()
        .unwrap()
        .unwrap()
        .identity()
        .token
        .is_empty());
    assert!(
        !actor
            .current_view(&f.keys)
            .unwrap()
            .unwrap()
            .has_credentials
    );
    assert!(actor.session(&f.keys).is_err());
}
struct SessionFixture {
    _work: WorkDirectory,
    root: std::path::PathBuf,
    id: String,
    state: DeviceState,
    rootkeys: crypto::KeyPair,
    keys: crypto::KeyPair,
    mode: Enable,
    activation: String,
    info: SessionInfo,
    protection: Protection,
}
impl SessionFixture {
    fn new(origin: &str) -> Self {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let root = work.0.join("joining");
        let protection = Protection::isolated_test();
        let (profiles, id, state, rootkeys) =
            authorized_at(root.clone(), protection.clone(), origin);
        let keys = profiles.load(&id).unwrap().keys().unwrap();
        let mode = Enable::make(&state, &uuid::Uuid::new_v4().to_string(), &rootkeys).unwrap();
        let active =
            active::Store::open_with_protection(root.clone(), &id, protection.clone()).unwrap();
        let path = active.database().unwrap();
        let mut jobs = jobs::Store::open(
            &path,
            active.job_owner().unwrap(),
            &keys,
            protection.witness(&path).unwrap(),
        )
        .unwrap();
        let task = jobs
            .prepare_login("synthetic-user", mode.clone(), &keys)
            .unwrap();
        let task = jobs.begin(&task.view(), &keys).unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let challenge = Challenge::make(
            &state,
            &mode,
            &task.view().id,
            &state.secondary().unwrap().device_id,
            now,
        )
        .unwrap();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: challenge.account.clone(),
            device: challenge.device.device_id.clone(),
            authorization: challenge.authorization,
            mode: challenge.mode,
            access_token: "synthetic-active-access-secret".into(),
            refresh_token: "synthetic-active-refresh-secret".into(),
            expires_at: now + 60000,
            refresh_expires_at: now + 120000,
        };
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
        let envelope = Envelope::seal(&challenge, &session).unwrap();
        let task = jobs
            .save_challenge(&task.view(), challenge.clone(), &keys)
            .unwrap();
        let task = jobs.seal_proof(&task.view(), now + 1, &keys).unwrap();
        let task = jobs
            .accept_session(&task.view(), challenge, envelope, &keys)
            .unwrap();
        Self {
            _work: work,
            root,
            id,
            state,
            rootkeys,
            keys,
            mode,
            activation: task.view().id,
            info,
            protection,
        }
    }
    fn open(&self) -> active::Store {
        active::Store::open_with_protection(self.root.clone(), &self.id, self.protection.clone())
            .unwrap()
    }
    fn session(&self) -> Session {
        let active = self.open();
        let path = active.database().unwrap();
        let mut jobs = jobs::Store::open(
            &path,
            active.job_owner().unwrap(),
            &self.keys,
            self.protection.witness(&path).unwrap(),
        )
        .unwrap();
        jobs.session(&self.activation, &self.keys).unwrap()
    }
    async fn save(&self, listener: TcpListener, previous: Option<u64>) -> Result<(), String> {
        let body = serde_json::to_vec(&self.info).unwrap();
        let server = tokio::spawn(respond(listener, body, None));
        let session = self.session();
        let checked = ActivationApi::new(&self.state.anchor().origin)
            .unwrap()
            .check_session(
                &session.access_token,
                &self.state,
                &self.mode,
                &self.info.device,
                &self.keys,
            )
            .await
            .unwrap();
        server.await.unwrap();
        self.open().save_checked(
            &self.activation,
            self.mode.clone(),
            session,
            checked,
            previous,
        )
    }
}
async fn respond(
    listener: TcpListener,
    body: Vec<u8>,
    pause: Option<(std::sync::Arc<Notify>, std::sync::Arc<Notify>)>,
) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut input = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        input.extend_from_slice(&chunk[..n]);
        if input.windows(4).any(|b| b == b"\r\n\r\n") {
            break;
        }
    }
    if let Some((arrived, release)) = pause {
        arrived.notify_one();
        release.notified().await;
    }
    let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    socket.write_all(header.as_bytes()).await.unwrap();
    socket.write_all(&body).await.unwrap();
}
#[tokio::test]
async fn normal_session_is_dpapi_protected_reopens_with_original_keys_and_clears_only_credentials()
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let f = SessionFixture::new(&format!("http://{address}"));
    let identity_path = f.root.join(&f.id).join("identity.bin");
    let original = std::fs::read(&identity_path).unwrap();
    f.save(listener, None).await.unwrap();
    let mut store = f.open();
    let profile = store.load().unwrap().unwrap();
    assert_eq!(profile.view().revision, 1);
    assert!(profile.view().has_saved_session);
    assert_eq!(profile.view().device, f.info.device.device_id);
    let identity = profile.identity();
    assert_eq!(identity.public_key, f.keys.public_key);
    assert_eq!(identity.secret_key, f.keys.secret_key);
    assert_eq!(identity.device_id, f.info.device.device_id);
    assert_eq!(identity.user_id, f.state.anchor().account);
    let public = serde_json::to_string(&profile.view()).unwrap();
    for secret in [&identity.token, &identity.refresh_token] {
        assert!(!public.contains(secret));
        let sql = rusqlite::Connection::open(store.database().unwrap()).unwrap();
        let body: Vec<u8> = sql
            .query_row(
                "SELECT body FROM device_control_tasks WHERE kind='active_profile'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!body.windows(secret.len()).any(|v| v == secret.as_bytes()));
    }
    // A second writer cannot replace an already committed record with a stale revision.
    let listener = TcpListener::bind(address).await.unwrap();
    assert!(f.save(listener, None).await.is_err());
    assert_eq!(store.load().unwrap().unwrap().view().revision, 1);
    store.clear_session().unwrap();
    drop(store);
    let profile = f.open().load().unwrap().unwrap();
    assert!(!profile.view().has_saved_session);
    assert_eq!(profile.view().revision, 2);
    assert!(profile.identity().token.is_empty());
    assert!(profile.identity().refresh_token.is_empty());
    assert_eq!(profile.identity().secret_key, f.keys.secret_key);
    assert_eq!(std::fs::read(identity_path).unwrap(), original);
}
#[tokio::test]
async fn signed_removal_retains_normal_profile_for_history_without_admitting_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = SessionFixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    f.save(listener, None).await.unwrap();
    let mut store = f.open();
    let path = store.database().unwrap();
    let revoke = make_event(
        &f.state,
        uuid::Uuid::new_v4().to_string(),
        DeviceAction::Revoke {
            device_id: f.info.device.device_id.clone(),
            grant_hash: f.state.grant_hash().unwrap().to_vec(),
        },
        chrono::Utc::now().timestamp_millis(),
        &f.rootkeys,
    )
    .unwrap();
    let mut trust = liteseal_core::trusted_devices::DeviceTrustStore::open(&path).unwrap();
    trust.protect(f.protection.witness(&path).unwrap()).unwrap();
    trust
        .import_verified(
            f.state.anchor(),
            &Checkpoint::from_state(&f.state),
            &[revoke],
        )
        .unwrap();
    let profile = store.load().unwrap().unwrap();
    assert!(!profile.view().eligible);
    assert!(profile.identity().token.is_empty());
    assert_eq!(profile.identity().secret_key, f.keys.secret_key);
    store.clear_session().unwrap();
}
#[tokio::test]
async fn checked_bearer_cannot_save_a_different_refresh_credential() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = SessionFixture::new(&format!("http://{}", listener.local_addr().unwrap()));
    let server = tokio::spawn(respond(
        listener,
        serde_json::to_vec(&f.info).unwrap(),
        None,
    ));
    let mut session = f.session();
    let checked = ActivationApi::new(&f.state.anchor().origin)
        .unwrap()
        .check_session(
            &session.access_token,
            &f.state,
            &f.mode,
            &f.info.device,
            &f.keys,
        )
        .await
        .unwrap();
    server.await.unwrap();
    session.refresh_token = "synthetic-other-refresh-secret".into();
    let mut store = f.open();
    assert!(store
        .save_checked(&f.activation, f.mode.clone(), session, checked, None)
        .is_err());
    assert!(store.load().unwrap().is_none());
}
#[tokio::test]
async fn logout_and_lock_reject_late_checked_identity_results() {
    for logout in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let f = SessionFixture::new(&format!("http://{address}"));
        f.save(listener, None).await.unwrap();
        let coordinator = std::sync::Arc::new(
            active::Coordinator::open_with_protection(f.root.clone(), &f.id, f.protection.clone())
                .unwrap(),
        );
        let arrived = std::sync::Arc::new(Notify::new());
        let release = std::sync::Arc::new(Notify::new());
        let listener = TcpListener::bind(address).await.unwrap();
        let server = tokio::spawn(respond(
            listener,
            serde_json::to_vec(&f.info).unwrap(),
            Some((arrived.clone(), release.clone())),
        ));
        let worker = coordinator.clone();
        let pending = tokio::spawn(async move { worker.checked_identity().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), arrived.notified())
            .await
            .unwrap();
        if logout {
            coordinator.clear_session().unwrap();
        } else {
            coordinator.invalidate().unwrap();
        }
        release.notify_one();
        assert!(pending.await.unwrap().is_err());
        server.await.unwrap();
        if !logout {
            assert!(coordinator.view().is_err());
            coordinator.resume().unwrap();
        }
        assert_eq!(
            coordinator.view().unwrap().unwrap().has_saved_session,
            !logout
        );
    }
}
