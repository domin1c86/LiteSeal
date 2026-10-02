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
    _work: WorkDirectory,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
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
                protection,
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
        let roots = [root, peer.clone()];
        let seen_ = seen.clone();
        let release_ = release.clone();
        let first = AtomicBool::new(true);
        let server = tokio::spawn(async move {
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
                    let outcome = if first.swap(false, Ordering::SeqCst) {
                        seen_.notify_one();
                        release_.notified().await;
                        Outcome::Accepted {
                            receipt: Receipt {
                                id,
                                digest,
                                accepted_at: 123,
                            },
                            acknowledgements: vec![],
                        }
                    } else {
                        Outcome::Unknown { id, digest }
                    };
                    serde_json::to_vec(&outcome).unwrap()
                } else {
                    let batch = Batch::from_wire(&body).unwrap();
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
                                accepted_at: 123,
                            },
                            acknowledgements: vec![],
                        }
                    };
                    serde_json::to_vec(&outcome).unwrap()
                };
                let header=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",response.len());
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
