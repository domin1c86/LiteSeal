#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    keystore::KeystoreData,
    trusted_devices::{
        activation::{jobs, refresh::jobs as refresh, ActivationApi},
        messages::{self, Acceptance, Prepare},
        witness::platform::Protection,
        DeviceTrustStore,
    },
};
use liteseal_desktop::{
    commands::{device_control, direct as d, normal_profile as n},
    protocol::Command,
    AppState,
};
use liteseal_shared::{
    crypto,
    device_activation::{Challenge, Enable, Envelope, Session, SessionInfo},
    direct_message::{Batch, Kind},
    direct_transport::{Delivery, Page, Receipt, Result as Outcome},
    trusted_device::*,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
struct Account {
    state: Arc<AppState>,
    keys: crypto::KeyPair,
    anchor: Anchor,
    mode: Enable,
    session: Session,
    task: jobs::Task,
    keyfile: std::path::PathBuf,
    original: Vec<u8>,
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
impl Account {
    fn new(origin: &str, path: &std::path::Path, p: &Protection) -> Self {
        std::fs::create_dir(path).unwrap();
        let keyfile = path.join("identity.bin");
        let state = Arc::new(
            AppState::with_device_protection(
                path.join("data.db").to_str().unwrap(),
                Some(keyfile.clone()),
                p.clone(),
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
                token: "synthetic-old-beta".into(),
                refresh_token: "synthetic-old-refresh".into(),
                public_key: keys.public_key.to_vec(),
                secret_key: keys.secret_key.to_vec(),
                ed25519_pk: keys.ed25519_pk.to_vec(),
                ed25519_sk: keys.ed25519_sk.to_vec(),
            })
            .unwrap();
        let mut trust = DeviceTrustStore::open(&state.db_path).unwrap();
        trust.protect(p.witness(&state.db_path).unwrap()).unwrap();
        trust.pin(&anchor).unwrap();
        drop(trust);
        let owner = jobs::Owner::new(anchor.clone(), &anchor.root.device_id, &keys).unwrap();
        let mut jobs = jobs::Store::open(
            &state.db_path,
            owner,
            &keys,
            p.witness(&state.db_path).unwrap(),
        )
        .unwrap();
        let enable = jobs.prepare_enable_checked(&keys).unwrap();
        let mode = enable.enable().clone();
        let enable = jobs.begin(&enable.view(), &keys).unwrap();
        jobs.accept_enable(&enable.view(), &mode, &keys).unwrap();
        let task = jobs
            .prepare_login("synthetic-user", mode.clone(), &keys)
            .unwrap();
        let task = jobs.begin(&task.view(), &keys).unwrap();
        let now = now();
        let challenge = Challenge::make(
            &DeviceState::pin(anchor.clone()).unwrap(),
            &mode,
            &task.view().id,
            &anchor.root.device_id,
            now,
        )
        .unwrap();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            account: anchor.account.clone(),
            device: anchor.root.device_id.clone(),
            authorization: challenge.authorization,
            mode: challenge.mode,
            access_token: format!("synthetic-formal-{}", anchor.account),
            refresh_token: format!("synthetic-refresh-{}", anchor.account),
            expires_at: now + 600_000,
            refresh_expires_at: now + 1_200_000,
        };
        let envelope = Envelope::seal(&challenge, &session).unwrap();
        let task = jobs
            .save_challenge(&task.view(), challenge.clone(), &keys)
            .unwrap();
        let task = jobs.seal_proof(&task.view(), now + 1, &keys).unwrap();
        jobs.accept_session(&task.view(), challenge, envelope, &keys)
            .unwrap();
        let task = jobs.task(&task.view().id, &keys).unwrap();
        let original = std::fs::read(&keyfile).unwrap();
        Self {
            state,
            keys,
            anchor,
            mode,
            session,
            task,
            keyfile,
            original,
        }
    }
    fn info(&self) -> SessionInfo {
        SessionInfo {
            version: 1,
            id: self.session.id.clone(),
            account: self.session.account.clone(),
            device: self.anchor.root.clone(),
            authorization: self.session.authorization,
            mode: self.session.mode,
            expires_at: self.session.expires_at,
            refresh_expires_at: self.session.refresh_expires_at,
            refresh_hash: Sha256::digest(self.session.refresh_token.as_bytes()).into(),
        }
    }
    async fn adopt(&self, p: &Protection) {
        let api = ActivationApi::new(&self.anchor.origin).unwrap();
        let checked = api
            .check_session(
                &self.session.access_token,
                &DeviceState::pin(self.anchor.clone()).unwrap(),
                &self.mode,
                &self.anchor.root,
                &self.keys,
            )
            .await
            .unwrap();
        refresh::Store::open(
            &self.state.db_path,
            jobs::Owner::new(self.anchor.clone(), &self.anchor.root.device_id, &self.keys).unwrap(),
            &self.keys,
            p.witness(&self.state.db_path).unwrap(),
        )
        .unwrap()
        .adopt(&self.task, checked, &self.keys)
        .unwrap();
    }
    fn reopen(&self, p: &Protection) -> AppState {
        AppState::with_device_protection(
            self.state.db_path.to_str().unwrap(),
            Some(self.keyfile.clone()),
            p.clone(),
        )
        .unwrap()
    }
}
#[derive(Default)]
struct World {
    batches: HashMap<String, Batch>,
    pending: HashMap<String, Vec<String>>,
    publish: usize,
    acks: usize,
    drop_publish: bool,
    drop_ack: bool,
    hold_lookup: bool,
    seen: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
async fn request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    let mut bytes = vec![];
    let mut chunk = [0; 4096];
    loop {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length = header
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return (header, bytes[end + 4..end + 4 + length].to_vec());
            }
        }
    }
}
async fn response(socket: &mut TcpStream, status: u16, value: &serde_json::Value) {
    let bytes = if status == 204 {
        vec![]
    } else {
        serde_json::to_vec(value).unwrap()
    };
    socket.write_all(format!("HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await.unwrap();
    socket.write_all(&bytes).await.unwrap();
}
#[test]
fn desktop_media_paths_are_scoped_authenticated_and_never_overwrite() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("https://synthetic.example", &work.0.join("a"), &p);
    let b = Account::new("https://synthetic.example", &work.0.join("b"), &p);
    let scope = d::snapshot(&a.state).unwrap().notification_scope;
    let mut store = messages::Store::open(
        &a.state.db_path,
        messages::Owner::new(
            &a.anchor.origin,
            &a.anchor.account,
            &a.anchor.root.device_id,
            &a.keys,
        )
        .unwrap(),
        p.witness(&a.state.db_path).unwrap(),
    )
    .unwrap();
    store.trust().pin(&b.anchor).unwrap();
    drop(store);
    let source = work.0.join("中文图片.png");
    let bytes = b"\x89PNG\r\n\x1a\nsynthetic image bytes";
    std::fs::write(&source, bytes).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let request = |scope: String| d::media::StageFile {
        scope,
        account: b.anchor.account.clone(),
        id: id.clone(),
        path: source.to_string_lossy().into_owned(),
        kind: Kind::Attachment,
        duration_ms: None,
    };
    assert!(d::media::stage(&a.state, request("wrong-scope".into())).is_err());
    let task = d::media::stage(&a.state, request(scope.clone())).unwrap();
    assert_eq!(task.id, id);
    assert_eq!(task.name, "中文图片.png");
    assert!(d::media::transfer(
        &a.state,
        "wrong-scope".into(),
        id.clone(),
        task.revision,
        true
    )
    .is_err());
    let paused =
        d::media::transfer(&a.state, scope.clone(), id.clone(), task.revision, true).unwrap();
    assert!(paused.paused);
    assert!(d::media::transfer(&a.state, scope.clone(), id.clone(), task.revision, false).is_err());
    let resumed =
        d::media::transfer(&a.state, scope.clone(), id.clone(), paused.revision, false).unwrap();
    assert!(resumed.requested && !resumed.paused);
    assert!(d::media::storage(&a.state, "wrong-scope".into()).is_err());
    assert!(d::media::clear_cache(&a.state, "wrong-scope".into(), None).is_err());
    let storage = d::media::storage(&a.state, scope.clone()).unwrap();
    assert_eq!(storage.cache_bytes, bytes.len() as u64 + 40);
    assert!(storage.database_allocated > 0);
    assert!(storage.disk_bytes >= std::fs::metadata(&a.state.db_path).unwrap().len());
    assert!(storage.database_reusable <= storage.database_allocated);
    assert_eq!(storage.peers[0].protected_tasks, 1);
    assert_eq!(
        d::media::clear_cache(&a.state, scope.clone(), Some(b.anchor.account.clone()))
            .unwrap()
            .removed_bytes,
        0
    );
    assert!(d::media::clear_cache(&a.state, scope.clone(), Some("invalid".into())).is_err());
    assert!(d::media::info(&a.state, scope.clone(), id.clone()).is_err());
    let target = work.0.join("verified.png");
    let result = d::media::write(
        &a.state,
        scope.clone(),
        id.clone(),
        target.to_string_lossy().into_owned(),
        true,
    )
    .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    assert_eq!(result.digest, hex::encode(Sha256::digest(bytes)));
    let public = serde_json::to_string(&result).unwrap();
    assert!(!public.contains("\"key\""));
    assert!(!public.contains("\"path\""));
    assert!(d::media::write(
        &a.state,
        scope.clone(),
        id.clone(),
        target.to_string_lossy().into_owned(),
        true
    )
    .is_err());
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    d::media::cancel(&a.state, scope.clone(), id.clone()).unwrap();
    let denied = work.0.join("denied.png");
    assert!(d::media::write(
        &a.state,
        scope.clone(),
        id.clone(),
        denied.to_string_lossy().into_owned(),
        true
    )
    .is_err());
    assert!(!denied.exists());
    device_control::suspend(&a.state).unwrap();
    assert!(d::media::tasks(&a.state, scope.clone()).is_err());
    device_control::resume(&a.state).unwrap();
    let resumed_scope = d::snapshot(&a.state).unwrap().notification_scope;
    assert!(d::media::clear_cache(&a.state, scope, None).is_err());
    let cleared = d::media::clear_cache(&a.state, resumed_scope.clone(), None).unwrap();
    assert_eq!(cleared.cleared_tasks, 1);
    assert_eq!(cleared.removed_bytes, bytes.len() as u64 + 40);
    assert_eq!(
        d::media::storage(&a.state, resumed_scope)
            .unwrap()
            .cache_bytes,
        0
    );
    for name in [
        "stage_direct_media",
        "write_direct_media",
        "get_direct_media_tasks",
        "set_direct_media_transfer",
        "get_direct_media_storage",
        "clear_direct_media_cache",
        "direct_media_step",
    ] {
        let args = serde_json::json!({"scope":"injected","id":"injected","token":"injected","key":vec![0u8;32]});
        assert!(
            serde_json::from_value::<Command>(serde_json::json!({"name":name,"args":args}))
                .is_err()
        );
    }
    assert_eq!(std::fs::read(&a.keyfile).unwrap(), a.original);
}
#[tokio::test]
async fn desktop_text_original_retry_receive_ack_paging_hide_and_selected_scope() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let a = Account::new(&origin, &work.0.join("a"), &p);
    let b = Account::new(&origin, &work.0.join("b"), &p);
    // A signed cutover alone must never send using leftover beta credentials.
    assert!(!d::snapshot(&a.state).unwrap().can_network);
    assert!(!d::process(&a.state).await.unwrap().changed);
    let anchors = [a.anchor.clone(), b.anchor.clone()];
    let infos = [a.info(), b.info()];
    let world = Arc::new(Mutex::new(World {
        drop_publish: true,
        drop_ack: true,
        ..Default::default()
    }));
    let shared = world.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (header, body) = request(&mut socket).await;
            let route = header
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let url = reqwest::Url::parse(&format!("{origin}{route}")).unwrap();
            let path = url.path();
            let wait = if path.starts_with("/direct/v3/batches/") {
                let mut world = shared.lock().unwrap();
                if world.hold_lookup {
                    world.hold_lookup = false;
                    Some((world.seen.clone(), world.release.clone()))
                } else {
                    None
                }
            } else {
                None
            };
            let (status, value, drop_response) = {
                let mut world = shared.lock().unwrap();
                if path.starts_with("/auth/v3/session/") {
                    let id = path.rsplit('/').next().unwrap();
                    (
                        200,
                        serde_json::to_value(
                            infos.iter().find(|i| i.device.device_id == id).unwrap(),
                        )
                        .unwrap(),
                        false,
                    )
                } else if path.starts_with("/users/") {
                    let account = path.split('/').nth(2).unwrap();
                    let anchor = anchors.iter().find(|a| a.account == account).unwrap();
                    (
                        200,
                        serde_json::to_value(DeviceManifestPage {
                            anchor: anchor.clone(),
                            events: vec![],
                            through_revision: 0,
                            current_revision: 0,
                            current_hash: anchor.hash(),
                            more: false,
                        })
                        .unwrap(),
                        false,
                    )
                } else if path.starts_with("/direct/v3/batches/") {
                    let id = path.rsplit('/').next().unwrap();
                    let digest: [u8; 32] = hex::decode(
                        url.query_pairs()
                            .find(|(k, _)| k == "digest")
                            .unwrap()
                            .1
                            .as_ref(),
                    )
                    .unwrap()
                    .try_into()
                    .unwrap();
                    let result = if world.batches.contains_key(id) {
                        Outcome::Accepted {
                            receipt: Receipt {
                                id: id.into(),
                                digest,
                                accepted_at: 123,
                            },
                            acknowledgements: vec![],
                        }
                    } else {
                        Outcome::Unknown {
                            id: id.into(),
                            digest,
                        }
                    };
                    (200, serde_json::to_value(result).unwrap(), false)
                } else if path == "/direct/v3/batches" {
                    let batch = Batch::from_wire(&body).unwrap();
                    world.publish += 1;
                    let id = batch.header.id.clone();
                    let digest = batch.digest().unwrap();
                    world
                        .pending
                        .entry(batch.header.peer.clone())
                        .or_default()
                        .push(id.clone());
                    world.batches.insert(id.clone(), batch);
                    let drop = world.drop_publish;
                    world.drop_publish = false;
                    (
                        200,
                        serde_json::to_value(Outcome::Accepted {
                            receipt: Receipt {
                                id,
                                digest,
                                accepted_at: 123,
                            },
                            acknowledgements: vec![],
                        })
                        .unwrap(),
                        drop,
                    )
                } else if path == "/direct/v3/pending" {
                    let device = url
                        .query_pairs()
                        .find(|(k, _)| k == "device_id")
                        .unwrap()
                        .1
                        .to_string();
                    let account = &anchors
                        .iter()
                        .find(|a| a.root.device_id == device)
                        .unwrap()
                        .account;
                    let items = world
                        .pending
                        .get(account)
                        .and_then(|ids| ids.first())
                        .map(|id| {
                            let batch = world.batches[id].clone();
                            Delivery {
                                order: 1,
                                receipt: Receipt {
                                    id: id.clone(),
                                    digest: batch.digest().unwrap(),
                                    accepted_at: 123,
                                },
                                batch,
                            }
                        })
                        .into_iter()
                        .collect();
                    (
                        200,
                        serde_json::to_value(Page {
                            items,
                            has_more: false,
                        })
                        .unwrap(),
                        false,
                    )
                } else if path == "/direct/v3/ack" {
                    let ack = liteseal_shared::direct_message::Ack::from_wire(&body).unwrap();
                    let batch = &world.batches[&ack.id];
                    let sender = DeviceState::pin(
                        anchors
                            .iter()
                            .find(|a| a.account == batch.header.sender)
                            .unwrap()
                            .clone(),
                    )
                    .unwrap();
                    let peer = DeviceState::pin(
                        anchors
                            .iter()
                            .find(|a| a.account == batch.header.peer)
                            .unwrap()
                            .clone(),
                    )
                    .unwrap();
                    ack.verify(batch, &sender, &peer).unwrap();
                    world.acks += 1;
                    world
                        .pending
                        .entry(ack.account)
                        .or_default()
                        .retain(|id| id != &ack.id);
                    let drop = world.drop_ack;
                    world.drop_ack = false;
                    (204, serde_json::Value::Null, drop)
                } else {
                    panic!("unexpected synthetic path")
                }
            };
            if let Some((seen, release)) = wait {
                seen.notify_one();
                release.notified().await;
            }
            if !drop_response {
                response(&mut socket, status, &value).await;
            }
        }
    });
    a.adopt(&p).await;
    b.adopt(&p).await;
    for (owner, peer) in [(&a, &b), (&b, &a)] {
        let inspected = d::inspect_peer(&owner.state, peer.anchor.account.clone())
            .await
            .unwrap();
        assert!(
            d::confirm_peer(&owner.state, peer.anchor.account.clone(), "wrong".into()).is_err()
        );
        d::confirm_peer(
            &owner.state,
            peer.anchor.account.clone(),
            inspected.root_fingerprint,
        )
        .unwrap();
    }
    let body = "中文 🦭 <script>原文字</script>";
    let saved = d::save_draft(&a.state, b.anchor.account.clone(), 0, body.into()).unwrap();
    assert_eq!(
        d::draft(&a.reopen(&p), b.anchor.account.clone())
            .unwrap()
            .text,
        body
    );
    let prepared = d::prepare(
        &a.state,
        b.anchor.account.clone(),
        "中文 🦭 <script>原文字</script>".into(),
        Some(saved.revision),
    )
    .await
    .unwrap()
    .task
    .unwrap();
    assert!(d::draft(&a.state, b.anchor.account.clone())
        .unwrap()
        .text
        .is_empty());
    let same = d::prepare(
        &a.state,
        b.anchor.account.clone(),
        body.into(),
        Some(saved.revision),
    )
    .await
    .unwrap()
    .task
    .unwrap();
    assert_eq!(same.id, prepared.id);
    assert_eq!(
        d::step(&a.state, prepared.id.clone())
            .await
            .unwrap()
            .condition,
        liteseal_core::trusted_devices::messages::coordinator::Condition::Retry
    );
    let reopened = a.reopen(&p);
    assert_eq!(d::snapshot(&reopened).unwrap().tasks[0].id, prepared.id);
    assert_eq!(
        d::step(&reopened, prepared.id.clone())
            .await
            .unwrap()
            .condition,
        liteseal_core::trusted_devices::messages::coordinator::Condition::Accepted
    );
    assert_eq!(world.lock().unwrap().publish, 1);
    let report = d::process(&b.state).await.unwrap();
    assert!(report.changed);
    assert_eq!(report.notifications.len(), 1);
    assert_eq!(report.notifications[0].id, prepared.id);
    assert_eq!(
        report.notification_scope.as_deref(),
        Some(d::snapshot(&b.state).unwrap().notification_scope.as_str())
    );
    let conversation = d::snapshot(&b.state).unwrap().conversations.remove(0);
    assert_eq!(conversation.unread, 1);
    assert!(
        d::history_peer(&b.state, Some(a.anchor.account.clone()), None)
            .unwrap()
            .messages
            .iter()
            .all(|m| m.record.peer == a.anchor.account)
    );
    d::mark_read(&b.state, a.anchor.account.clone(), prepared.id.clone()).unwrap();
    let conversation = d::snapshot(&b.state).unwrap().conversations.remove(0);
    assert_eq!(conversation.unread, 0);
    d::set_muted(
        &b.state,
        a.anchor.account.clone(),
        conversation.revision,
        true,
    )
    .unwrap();
    assert!(d::snapshot(&b.reopen(&p)).unwrap().conversations[0].muted);
    assert_eq!(
        d::history(&b.state, None).unwrap().messages[0]
            .text
            .as_deref(),
        Some("中文 🦭 <script>原文字</script>")
    );
    assert!(d::process(&b.state).await.unwrap().notifications.is_empty());
    assert!(d::process(&b.state).await.unwrap().notifications.is_empty());
    assert_eq!(world.lock().unwrap().acks, 2);
    d::hide(&b.state, prepared.id.clone()).unwrap();
    world
        .lock()
        .unwrap()
        .pending
        .entry(b.anchor.account.clone())
        .or_default()
        .push(prepared.id.clone());
    d::process(&b.state).await.unwrap();
    assert!(d::history(&b.state, None).unwrap().messages.is_empty());
    let mut local = messages::Store::open(
        &a.state.db_path,
        messages::Owner::new(
            &a.anchor.origin,
            &a.anchor.account,
            &a.anchor.root.device_id,
            &a.keys,
        )
        .unwrap(),
        p.witness(&a.state.db_path).unwrap(),
    )
    .unwrap();
    for i in 0..51 {
        let id = uuid::Uuid::new_v4().to_string();
        local
            .prepare(
                Prepare {
                    id: &id,
                    peer: &b.anchor.account,
                    sent_at: now(),
                    kind: Kind::Text,
                    body: format!("历史 {i} 中文 🦭").as_bytes(),
                },
                &a.keys,
            )
            .unwrap();
        let batch = local.original(&id, &a.keys).unwrap();
        let view = local
            .tasks(&a.keys)
            .unwrap()
            .into_iter()
            .find(|t| t.id == id)
            .unwrap();
        local.begin_publish(&id, view.revision, &a.keys).unwrap();
        let receipt =
            Acceptance::from_authenticated_response(&batch, &id, batch.digest().unwrap(), 123)
                .unwrap();
        local.confirm_accepted(&receipt, &a.keys).unwrap();
    }
    let mut cursor = None;
    let mut ids = std::collections::HashSet::new();
    loop {
        let page = d::history(&reopened, cursor).unwrap();
        for row in page.messages {
            assert!(ids.insert(row.record.id));
        }
        if page.next_cursor.is_none() {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(ids.len(), 52);
    let current = d::draft(&a.state, b.anchor.account.clone()).unwrap();
    let next = d::save_draft(
        &a.state,
        b.anchor.account.clone(),
        current.revision,
        "迟到响应仍保留原任务".into(),
    )
    .unwrap();
    let late = d::prepare(
        &a.state,
        b.anchor.account.clone(),
        "迟到响应仍保留原任务".into(),
        Some(next.revision),
    )
    .await
    .unwrap()
    .task
    .unwrap();
    let batch = local.original(&late.id, &a.keys).unwrap();
    let (seen, release) = {
        let mut world = world.lock().unwrap();
        world.batches.insert(late.id.clone(), batch);
        world.hold_lookup = true;
        (world.seen.clone(), world.release.clone())
    };
    let source = a.state.clone();
    let id = late.id.clone();
    let pending = tokio::spawn(async move { d::step(&source, id).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), seen.notified())
        .await
        .unwrap();
    device_control::suspend(&a.state).unwrap();
    assert!(d::snapshot(&a.state).is_err());
    release.notify_one();
    assert!(pending.await.unwrap().is_err());
    device_control::resume(&a.state).unwrap();
    assert!(d::history(&a.state, None)
        .unwrap()
        .messages
        .iter()
        .all(|m| m.record.id != late.id));
    assert_eq!(
        d::step(&a.state, late.id).await.unwrap().condition,
        liteseal_core::trusted_devices::messages::coordinator::Condition::Accepted
    );
    let generation = n::snapshot(&a.state).unwrap().generation;
    n::select(&a.state, None, generation, None).await.unwrap();
    assert!(!d::process(&a.state).await.unwrap().changed);
    assert!(d::history(&a.state, None).is_err());
    assert_eq!(std::fs::read(&a.keyfile).unwrap(), a.original);
    assert_eq!(std::fs::read(&b.keyfile).unwrap(), b.original);
    for (name, args) in [
        ("get_direct_chat", serde_json::json!({})),
        (
            "prepare_direct_text",
            serde_json::json!({"account":b.anchor.account,"text":"test"}),
        ),
    ] {
        let mut args = args;
        args["token"] = "injected".into();
        assert!(
            serde_json::from_value::<Command>(serde_json::json!({"name":name,"args":args}))
                .is_err()
        );
    }
    server.abort();
    let _ = server.await;
}
