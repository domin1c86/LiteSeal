#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        messages::{
            coordinator::{Condition, MessageCoordinator},
            Owner, TaskState,
        },
        tasks::anchor_fingerprint,
        witness::platform::Protection,
    },
};
use liteseal_shared::{
    crypto,
    direct_message::Batch,
    direct_transport::{Receipt, Result as Outcome},
    trusted_device::*,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
struct Fixture {
    actor: Arc<MessageCoordinator>,
    keys: Arc<crypto::KeyPair>,
    peer: String,
    seen: Arc<Notify>,
    release: Arc<Notify>,
    server: tokio::task::JoinHandle<()>,
    own: Anchor,
    protection: Protection,
    _work: WorkDirectory,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn prepared_edit(&self) -> String {
        use liteseal_core::trusted_devices::messages::operations::PrepareOperation;
        let original = self
            .actor
            .prepare_text(&self.peer, "original 🦭", &self.keys)
            .await
            .unwrap()
            .task
            .unwrap();
        self.actor.step(&original.id, &self.keys).await.unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        self.actor
            .prepare_operation(
                PrepareOperation {
                    id: &id,
                    target: &original.id,
                    created_at: chrono::Utc::now().timestamp_millis(),
                    action: liteseal_shared::direct_operation::Action::Edit,
                    text: Some("edited 中文 🦭"),
                },
                &self.keys,
            )
            .await
            .unwrap();
        id
    }
    async fn new() -> Self {
        Self::new_mode(false).await
    }
    async fn new_mode(restore: bool) -> Self {
        Self::configured(restore, None).await
    }
    async fn operations(mode: u8) -> Self {
        Self::configured(false, Some(mode)).await
    }
    async fn configured(restore: bool, operation_mode: Option<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let keys = Arc::new(crypto::generate_keypair().unwrap());
        let other = crypto::generate_keypair().unwrap();
        let make = |keys: &crypto::KeyPair| Anchor {
            origin: url.clone(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), keys),
        };
        let root = make(&keys);
        let peer = make(&other);
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let protection = Protection::isolated_test();
        let actor = Arc::new(
            MessageCoordinator::open_with_protection(
                &work.0.join("messages.db"),
                Owner::new(&url, &root.account, &root.root.device_id, &keys).unwrap(),
                &keys,
                protection.clone(),
            )
            .unwrap(),
        );
        for anchor in [&root, &peer] {
            actor
                .confirm_root(anchor, &anchor_fingerprint(anchor), &keys)
                .unwrap();
        }
        actor.renew_session("synthetic-first".into()).unwrap();
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let roots = [root.clone(), peer.clone()];
        let seen_ = seen.clone();
        let release_ = release.clone();
        let first = AtomicBool::new(true);
        let server = tokio::spawn(async move {
            let mut expired = false;
            let mut events = Vec::<liteseal_shared::direct_operation::Event>::new();
            let mut cancels = std::collections::HashSet::new();
            let mut first_operation = true;
            let mut first_page = true;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = vec![];
                let mut buffer = [0; 4096];
                let (uri, body) = loop {
                    let n = socket.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let line = header.lines().next().unwrap();
                        let uri = line.split_whitespace().nth(1).unwrap().to_string();
                        let length = header
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|v| v.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            break (uri, bytes[end + 4..end + 4 + length].to_vec());
                        }
                    }
                };
                let parsed = url::Url::parse(&format!("{url}{uri}")).unwrap();
                let path = parsed.path();
                let mut lose_response = false;
                let response = if path.starts_with("/users/") {
                    let account = path.split('/').nth(2).unwrap();
                    let anchor = roots.iter().find(|a| a.account == account).unwrap();
                    serde_json::to_vec(&DeviceManifestPage {
                        anchor: anchor.clone(),
                        events: vec![],
                        through_revision: 0,
                        current_revision: 0,
                        current_hash: anchor.hash(),
                        more: false,
                    })
                    .unwrap()
                } else if path == "/direct/v3/operations" && body.is_empty() {
                    let after: i64 = parsed
                        .query_pairs()
                        .find(|(k, _)| k == "after")
                        .unwrap()
                        .1
                        .parse()
                        .unwrap();
                    let mut rows: Vec<_> =
                        events.iter().filter(|e| e.order > after).cloned().collect();
                    if first_page && operation_mode == Some(5) {
                        first_page = false;
                        seen_.notify_one();
                        release_.notified().await;
                    }
                    if first_page && operation_mode == Some(6) {
                        first_page = false;
                        rows[0].operation.signature[0] ^= 1;
                    }
                    serde_json::to_vec(&liteseal_shared::direct_operation::Page {
                        through: rows.last().map_or(after, |e| e.order),
                        events: rows,
                        has_more: false,
                    })
                    .unwrap()
                } else if path.starts_with("/direct/v3/operations/") && path.ends_with("/outcome") {
                    let id = path.split('/').nth(4).unwrap().to_string();
                    let digest: [u8; 32] = hex::decode(
                        parsed
                            .query_pairs()
                            .find(|(k, _)| k == "digest")
                            .unwrap()
                            .1
                            .as_ref(),
                    )
                    .unwrap()
                    .try_into()
                    .unwrap();
                    let result =
                        if let Some(event) = events.iter().find(|e| e.operation.header.id == id) {
                            liteseal_shared::direct_operation::Outcome::Accepted {
                                receipt: liteseal_shared::direct_operation::Receipt {
                                    id,
                                    digest,
                                    revision: event.operation.header.revision,
                                    order: event.order,
                                    accepted_at: event.accepted_at,
                                },
                            }
                        } else if cancels.contains(&id) {
                            liteseal_shared::direct_operation::Outcome::Cancelled { id, digest }
                        } else {
                            liteseal_shared::direct_operation::Outcome::Unknown { id, digest }
                        };
                    serde_json::to_vec(&result).unwrap()
                } else if path.starts_with("/direct/v3/operations") {
                    let operation =
                        liteseal_shared::direct_operation::Operation::from_wire(&body).unwrap();
                    if path.ends_with("/cancel") {
                        cancels.insert(operation.header.id.clone());
                        serde_json::to_vec(&liteseal_shared::direct_operation::Outcome::Cancelled {
                            id: operation.header.id.clone(),
                            digest: operation.digest().unwrap(),
                        })
                        .unwrap()
                    } else {
                        let receipt = liteseal_shared::direct_operation::Receipt {
                            id: operation.header.id.clone(),
                            digest: operation.digest().unwrap(),
                            revision: operation.header.revision,
                            order: events.len() as i64 + 1,
                            accepted_at: chrono::Utc::now().timestamp_millis(),
                        };
                        if operation_mode != Some(4) {
                            events.push(liteseal_shared::direct_operation::Event {
                                order: receipt.order,
                                accepted_at: receipt.accepted_at,
                                operation,
                            });
                        }
                        if first_operation {
                            first_operation = false;
                            match operation_mode {
                                Some(0 | 4) => lose_response = true,
                                Some(1..=3) => {
                                    seen_.notify_one();
                                    release_.notified().await;
                                }
                                _ => {}
                            }
                        }
                        serde_json::to_vec(&receipt).unwrap()
                    }
                } else if path.starts_with("/direct/v3/batches/") {
                    let id = path.rsplit('/').next().unwrap().to_string();
                    let digest: [u8; 32] = hex::decode(
                        parsed
                            .query_pairs()
                            .find(|(k, _)| k == "digest")
                            .unwrap()
                            .1
                            .as_ref(),
                    )
                    .unwrap()
                    .try_into()
                    .unwrap();
                    let outcome = if operation_mode.is_none()
                        && !restore
                        && first.swap(false, Ordering::SeqCst)
                    {
                        seen_.notify_one();
                        release_.notified().await;
                        Outcome::Accepted {
                            receipt: Receipt {
                                id,
                                digest,
                                accepted_at: chrono::Utc::now().timestamp_millis(),
                            },
                            acknowledgements: vec![],
                        }
                    } else {
                        Outcome::Unknown { id, digest }
                    };
                    serde_json::to_vec(&outcome).unwrap()
                } else if path == "/direct/v3/media/objects" {
                    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    serde_json::to_vec(value.get("id").unwrap()).unwrap()
                } else if path.starts_with("/direct/v3/media/objects/") {
                    if (!restore || expired) && first.swap(false, Ordering::SeqCst) {
                        seen_.notify_one();
                        release_.notified().await;
                        if restore {
                            lose_response = true;
                        }
                    }
                    vec![]
                } else {
                    let batch = if path == "/direct/v3/media/batches" {
                        liteseal_shared::direct_media::Submission::from_wire(&body)
                            .unwrap()
                            .batch
                    } else {
                        Batch::from_wire(&body).unwrap()
                    };
                    let outcome = if path == "/direct/v3/cancel" {
                        Outcome::Cancelled {
                            id: batch.header.id.clone(),
                            digest: batch.digest().unwrap(),
                        }
                    } else {
                        Outcome::Accepted {
                            receipt: Receipt {
                                id: batch.header.id.clone(),
                                digest: batch.digest().unwrap(),
                                accepted_at: chrono::Utc::now().timestamp_millis(),
                            },
                            acknowledgements: vec![],
                        }
                    };
                    serde_json::to_vec(&outcome).unwrap()
                };
                let status = if restore && path == "/direct/v3/media/batches" && !expired {
                    expired = true;
                    "404 Not Found"
                } else if path.starts_with("/direct/v3/media/objects/") {
                    "204 No Content"
                } else {
                    "200 OK"
                };
                if lose_response {
                    socket.shutdown().await.unwrap();
                    continue;
                }
                let header=format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",response.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&response).await.unwrap();
            }
        });
        Self {
            actor,
            keys,
            peer: peer.account,
            seen,
            release,
            server,
            own: root,
            protection,
            _work: work,
        }
    }
}
async fn late_result(mode: u8) {
    let f = Fixture::new().await;
    let task = f
        .actor
        .prepare_text(&f.peer, "迟到🙂", &f.keys)
        .await
        .unwrap()
        .task
        .unwrap();
    let actor = f.actor.clone();
    let keys = f.keys.clone();
    let id = task.id.clone();
    let job = tokio::spawn(async move { actor.step(&id, &keys).await });
    tokio::time::timeout(std::time::Duration::from_secs(3), f.seen.notified())
        .await
        .unwrap();
    match mode {
        0 => {
            assert!(
                f.actor
                    .request_cancel(&task.id, &f.keys)
                    .unwrap()
                    .cancel_requested
            );
        }
        1 => f.actor.renew_session("synthetic-renewed".into()).unwrap(),
        _ => {
            f.actor.invalidate().unwrap();
            f.actor
                .renew_session("synthetic-after-lock".into())
                .unwrap();
            assert!(f.actor.tasks(&f.keys).is_err());
            f.actor.resume().unwrap();
        }
    }
    f.release.notify_one();
    assert!(job.await.unwrap().is_err());
    assert!(f.actor.history(None, 100, &f.keys).unwrap().is_empty());
    let current = f.actor.tasks(&f.keys).unwrap().pop().unwrap();
    assert_eq!(current.state, TaskState::Publishing);
    assert_eq!(current.cancel_requested, mode == 0);
    let progress = f.actor.step(&task.id, &f.keys).await.unwrap();
    assert_eq!(
        progress.condition,
        if mode == 0 {
            Condition::Cancelled
        } else {
            Condition::Accepted
        }
    );
    if mode > 0 {
        assert_eq!(f.actor.text(&task.id, &f.keys).unwrap(), "迟到🙂");
    } else {
        assert!(f.actor.text(&task.id, &f.keys).is_err());
    }
}
#[tokio::test]
async fn cancellation_revision_rejects_late_acceptance_without_overwriting_original_intent() {
    late_result(0).await;
}
#[tokio::test]
async fn session_renewal_invalidates_old_results_and_keeps_original_task() {
    late_result(1).await;
}
#[tokio::test]
async fn lock_then_unlock_never_revives_an_old_network_lease() {
    late_result(2).await;
}
#[tokio::test]
async fn media_cancel_rotation_and_lock_reject_late_chunk_and_retry_original_task() {
    use liteseal_core::trusted_devices::messages::media::{Phase, Stage};
    use liteseal_shared::direct_message::Kind;
    for mode in 0..3 {
        let f = Fixture::new().await;
        let id = uuid::Uuid::new_v4().to_string();
        f.actor
            .stage_media(
                Stage {
                    id: &id,
                    peer: &f.peer,
                    name: "隔离文件.txt",
                    bytes: "中文 emoji 🦭".as_bytes(),
                    kind: Kind::Attachment,
                    duration_ms: None,
                },
                &f.keys,
            )
            .unwrap();
        let actor = f.actor.clone();
        let keys = f.keys.clone();
        let original = id.clone();
        let job = tokio::spawn(async move { actor.media_step(&original, &keys).await });
        tokio::time::timeout(std::time::Duration::from_secs(3), f.seen.notified())
            .await
            .unwrap();
        match mode {
            0 => {
                f.actor.cancel_media(&id, &f.keys).unwrap();
            }
            1 => f.actor.renew_session("synthetic-new".into()).unwrap(),
            _ => {
                f.actor.invalidate().unwrap();
                assert!(f.actor.media_tasks(&f.keys).is_err());
                f.actor.resume().unwrap();
                f.actor.renew_session("synthetic-unlocked".into()).unwrap();
            }
        }
        f.release.notify_one();
        assert!(job.await.unwrap().is_err());
        let saved = f.actor.media_tasks(&f.keys).unwrap().pop().unwrap();
        assert_eq!(saved.uploaded, 0);
        if mode == 0 {
            assert_eq!(saved.phase, Phase::Cancelled);
            assert_eq!(
                f.actor.media_step(&id, &f.keys).await.unwrap().condition,
                Condition::Cancelled
            );
            assert!(f.actor.prepare_media(&id, &f.keys).await.is_err());
            f.actor.clear_media(&id, &f.keys).unwrap();
        } else {
            assert_eq!(
                f.actor.media_step(&id, &f.keys).await.unwrap().task.phase,
                Phase::Uploaded
            );
            let prepared = f
                .actor
                .prepare_media(&id, &f.keys)
                .await
                .unwrap()
                .task
                .unwrap();
            assert_eq!(prepared.id, id);
            assert_eq!(
                f.actor.step(&id, &f.keys).await.unwrap().condition,
                Condition::Accepted
            );
            assert_eq!(
                f.actor.history(None, 100, &f.keys).unwrap()[0].kind,
                Kind::Attachment
            );
            assert!(f.actor.text(&id, &f.keys).is_err());
            assert!(f.actor.clear_media(&id, &f.keys).unwrap() > 0);
        }
    }
}
#[tokio::test]
async fn unpublished_cancel_is_local_idempotent_and_never_queries_or_publishes() {
    let f = Fixture::new().await;
    let task = f
        .actor
        .prepare_text(&f.peer, "未发送取消", &f.keys)
        .await
        .unwrap()
        .task
        .unwrap();
    let cancelled = f.actor.request_cancel(&task.id, &f.keys).unwrap();
    assert_eq!(cancelled.state, TaskState::Cancelled);
    assert_eq!(
        f.actor.request_cancel(&task.id, &f.keys).unwrap().revision,
        cancelled.revision
    );
    assert_eq!(
        f.actor.step(&task.id, &f.keys).await.unwrap().condition,
        Condition::Cancelled
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), f.seen.notified())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn pause_fences_restore_reply_and_scheduler_waits_for_explicit_resume() {
    use liteseal_core::trusted_devices::messages::media::Stage;
    use liteseal_shared::direct_message::Kind;
    let f = Fixture::new_mode(true).await;
    let id = uuid::Uuid::new_v4().to_string();
    f.actor
        .stage_media(
            Stage {
                id: &id,
                peer: &f.peer,
                name: "暂停恢复.txt",
                bytes: b"pause exact original",
                kind: Kind::Attachment,
                duration_ms: None,
            },
            &f.keys,
        )
        .unwrap();
    assert!(f.actor.drive(true, &f.keys).await.unwrap().media.is_none());
    f.actor.media_step(&id, &f.keys).await.unwrap();
    let prepared = f
        .actor
        .prepare_media(&id, &f.keys)
        .await
        .unwrap()
        .task
        .unwrap();
    f.actor.step(&id, &f.keys).await.unwrap();
    let actor = f.actor.clone();
    let keys = f.keys.clone();
    let original = id.clone();
    let pending = tokio::spawn(async move { actor.step(&original, &keys).await });
    tokio::time::timeout(std::time::Duration::from_secs(3), f.seen.notified())
        .await
        .unwrap();
    let before = f.actor.media_tasks(&f.keys).unwrap().pop().unwrap();
    f.actor
        .set_media_transfer(&id, before.revision, true, &f.keys)
        .unwrap();
    f.release.notify_one();
    assert!(pending.await.unwrap().is_err());
    let paused = f.actor.media_tasks(&f.keys).unwrap().pop().unwrap();
    assert!(paused.paused);
    assert_eq!(paused.uploaded, 0);
    assert!(f.actor.drive(true, &f.keys).await.unwrap().task.is_none());
    assert_eq!(
        f.actor.step(&id, &f.keys).await.unwrap().condition,
        Condition::Paused
    );
    f.actor
        .set_media_transfer(&id, paused.revision, false, &f.keys)
        .unwrap();
    assert_eq!(
        f.actor
            .drive(true, &f.keys)
            .await
            .unwrap()
            .task
            .unwrap()
            .condition,
        Condition::Uploading
    );
    assert_eq!(
        f.actor
            .prepare_media(&id, &f.keys)
            .await
            .unwrap()
            .task
            .unwrap()
            .digest,
        prepared.digest
    );
    assert_eq!(
        f.actor
            .drive(true, &f.keys)
            .await
            .unwrap()
            .task
            .unwrap()
            .condition,
        Condition::Accepted
    );
}
#[tokio::test]
async fn prepared_restore_releases_text_lock_and_fences_late_cancel_rotation_and_lock() {
    use liteseal_core::trusted_devices::messages::media::Stage;
    use liteseal_shared::direct_message::Kind;
    for mode in 0..4 {
        let f = Fixture::new_mode(true).await;
        let id = uuid::Uuid::new_v4().to_string();
        f.actor
            .stage_media(
                Stage {
                    id: &id,
                    peer: &f.peer,
                    name: "原重传.txt",
                    bytes: b"original restore bytes",
                    kind: Kind::Attachment,
                    duration_ms: None,
                },
                &f.keys,
            )
            .unwrap();
        f.actor.media_step(&id, &f.keys).await.unwrap();
        let prepared = f
            .actor
            .prepare_media(&id, &f.keys)
            .await
            .unwrap()
            .task
            .unwrap();
        let expired = f.actor.step(&id, &f.keys).await.unwrap();
        assert_eq!(expired.condition, Condition::Uploading);
        assert_eq!(expired.http_status, Some(404));
        let actor = f.actor.clone();
        let keys = f.keys.clone();
        let original = id.clone();
        let pending = tokio::spawn(async move { actor.step(&original, &keys).await });
        tokio::time::timeout(std::time::Duration::from_secs(3), f.seen.notified())
            .await
            .unwrap();
        let available = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            f.actor.prepare_media(&id, &f.keys),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(available.task.unwrap().digest, prepared.digest);
        match mode {
            0 => {
                f.actor.cancel_media(&id, &f.keys).unwrap();
            }
            1 => {
                f.actor.renew_session("synthetic-rotated".into()).unwrap();
            }
            2 => {
                f.actor.invalidate().unwrap();
                f.actor.resume().unwrap();
                f.actor.renew_session("synthetic-unlocked".into()).unwrap();
            }
            _ => {}
        }
        f.release.notify_one();
        let response = pending.await.unwrap();
        if mode == 3 {
            assert_eq!(response.unwrap().condition, Condition::Retry);
        } else {
            assert!(response.is_err());
        }
        let saved = f.actor.media_tasks(&f.keys).unwrap().pop().unwrap();
        assert!(saved.restoring);
        assert_eq!(saved.uploaded, 0);
        if mode == 0 {
            assert_eq!(
                f.actor.step(&id, &f.keys).await.unwrap().condition,
                Condition::Cancelled
            );
        } else {
            assert_eq!(
                f.actor.step(&id, &f.keys).await.unwrap().condition,
                Condition::Uploading
            );
            assert!(!f.actor.media_tasks(&f.keys).unwrap()[0].restoring);
            assert_eq!(
                f.actor
                    .prepare_media(&id, &f.keys)
                    .await
                    .unwrap()
                    .task
                    .unwrap()
                    .digest,
                prepared.digest
            );
            assert_eq!(
                f.actor.step(&id, &f.keys).await.unwrap().condition,
                Condition::Accepted
            );
        }
    }
}

#[tokio::test]
async fn operation_lost_publish_response_reopens_exact_task_and_queries_original_acceptance() {
    let mut f = Fixture::operations(0).await;
    let id = f.prepared_edit().await;
    let first = f.actor.operation_step(&id, &f.keys).await.unwrap();
    assert_eq!(first.condition, Condition::Retry);
    assert_eq!(first.task.state, TaskState::Publishing);
    assert!(f
        .actor
        .clear_operation_task(&id, first.task.revision, &f.keys)
        .is_err());
    f.actor.invalidate().unwrap();
    f.actor = Arc::new(
        MessageCoordinator::open_with_protection(
            &f._work.0.join("messages.db"),
            Owner::new(
                &f.own.origin,
                &f.own.account,
                &f.own.root.device_id,
                &f.keys,
            )
            .unwrap(),
            &f.keys,
            f.protection.clone(),
        )
        .unwrap(),
    );
    f.actor.renew_session("synthetic-reopened".into()).unwrap();
    let result = f.actor.operation_step(&id, &f.keys).await.unwrap();
    assert_eq!(result.condition, Condition::Accepted);
    assert_eq!(result.task.id, id);
    assert_eq!(
        f.actor.text(&result.task.target, &f.keys).unwrap(),
        "edited 中文 🦭"
    );
    assert_eq!(f.actor.poll_operations(&f.keys).await.unwrap().received, 1);
    assert_eq!(f.actor.poll_operations(&f.keys).await.unwrap().received, 0);
    f.actor
        .clear_operation_task(&id, result.task.revision, &f.keys)
        .unwrap();
    assert!(f.actor.operation_tasks(&f.keys).unwrap().is_empty());
}
#[tokio::test]
async fn operation_cancel_revision_session_rotation_and_lock_reject_late_publish_result() {
    for mode in 1..=3 {
        let f = Fixture::operations(mode).await;
        let id = f.prepared_edit().await;
        let actor = f.actor.clone();
        let keys = f.keys.clone();
        let copy = id.clone();
        let job = tokio::spawn(async move { actor.operation_step(&copy, &keys).await });
        tokio::time::timeout(std::time::Duration::from_secs(3), f.seen.notified())
            .await
            .unwrap();
        let task = f.actor.operation_tasks(&f.keys).unwrap().pop().unwrap();
        match mode {
            1 => {
                f.actor.cancel_operation(&id, 0, &f.keys).unwrap();
            }
            2 => f.actor.renew_session("synthetic-rotated".into()).unwrap(),
            _ => {
                f.actor.invalidate().unwrap();
                f.actor.resume().unwrap();
                f.actor.renew_session("synthetic-unlocked".into()).unwrap();
            }
        }
        f.release.notify_one();
        assert!(job.await.unwrap().is_err());
        assert_eq!(f.actor.text(&task.target, &f.keys).unwrap(), "original 🦭");
        // The accepted result wins even when cancellation was requested; it is
        // learned through a new lease/revision instead of the late response.
        let result = f.actor.operation_step(&id, &f.keys).await.unwrap();
        assert_eq!(result.condition, Condition::Accepted);
        assert_eq!(
            f.actor.text(&task.target, &f.keys).unwrap(),
            "edited 中文 🦭"
        );
    }
}
#[tokio::test]
async fn operation_unknown_publish_can_be_fenced_without_republishing_or_changing_body() {
    let f = Fixture::operations(4).await;
    let id = f.prepared_edit().await;
    let first = f.actor.operation_step(&id, &f.keys).await.unwrap();
    assert_eq!(first.condition, Condition::Retry);
    let cancel = f
        .actor
        .cancel_operation(&id, first.task.revision, &f.keys)
        .unwrap();
    assert!(cancel.cancel_requested);
    let result = f.actor.drive_operations(&f.keys).await.unwrap().unwrap();
    assert_eq!(result.condition, Condition::Cancelled);
    assert_eq!(
        f.actor.text(&result.task.target, &f.keys).unwrap(),
        "original 🦭"
    );
    assert!(f.actor.drive_operations(&f.keys).await.unwrap().is_none());
    assert_eq!(f.actor.poll_operations(&f.keys).await.unwrap().received, 0);
}
#[tokio::test]
async fn operation_log_bad_page_or_retired_lease_never_advances_cursor_or_revives_content() {
    for mode in [5, 6] {
        let f = Fixture::operations(mode).await;
        let id = f.prepared_edit().await;
        let task = f.actor.operation_step(&id, &f.keys).await.unwrap().task;
        if mode == 5 {
            let actor = f.actor.clone();
            let keys = f.keys.clone();
            let job = tokio::spawn(async move { actor.poll_operations(&keys).await });
            tokio::time::timeout(std::time::Duration::from_secs(3), f.seen.notified())
                .await
                .unwrap();
            f.actor.invalidate().unwrap();
            f.actor.resume().unwrap();
            f.actor.renew_session("synthetic-recovered".into()).unwrap();
            f.release.notify_one();
            assert!(job.await.unwrap().is_err());
        } else {
            assert!(f.actor.poll_operations(&f.keys).await.is_err());
        }
        f.actor.hide(&task.target, &f.keys).unwrap();
        assert_eq!(f.actor.poll_operations(&f.keys).await.unwrap().received, 1);
        assert_eq!(f.actor.poll_operations(&f.keys).await.unwrap().received, 0);
        assert!(f.actor.text(&task.target, &f.keys).is_err());
        assert!(f.actor.history(None, 6, &f.keys).unwrap().is_empty());
        assert!(f.actor.claim_notifications(&f.keys).unwrap().is_empty());
    }
}
