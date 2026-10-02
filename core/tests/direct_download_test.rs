#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        messages::{
            coordinator::{Condition, MessageCoordinator},
            media::Phase,
            Owner,
        },
        tasks::anchor_fingerprint,
        witness::platform::Protection,
    },
};
use liteseal_shared::{
    crypto,
    direct_media::Descriptor,
    direct_message::{Batch, Header, Kind, MessageSpec},
    direct_transport::{Delivery, Page, Receipt},
    trusted_device::*,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
struct Fixture {
    actor: Arc<MessageCoordinator>,
    keys: Arc<crypto::KeyPair>,
    id: String,
    plain: Vec<u8>,
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
        let sender_keys = crypto::generate_keypair().unwrap();
        let make = |keys: &crypto::KeyPair| {
            DeviceState::pin(Anchor {
                origin: url.clone(),
                account: uuid::Uuid::new_v4().to_string(),
                root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), keys),
            })
            .unwrap()
        };
        let own = make(&keys);
        let sender = make(&sender_keys);
        let id = uuid::Uuid::new_v4().to_string();
        let plain = "下载原编号 中文 🦭".as_bytes().to_vec();
        let (descriptor, cipher) = Descriptor::encrypt(
            id.clone(),
            "隔离文件.txt".into(),
            &plain,
            Kind::Attachment,
            None,
        )
        .unwrap();
        let batch = Batch::make(
            Header::new(
                &sender,
                &own,
                &sender.anchor().root.device_id,
                MessageSpec {
                    id: id.clone(),
                    sequence: 1,
                    previous: vec![],
                    sent_at: 100,
                    kind: Kind::Attachment,
                },
            )
            .unwrap(),
            &sender,
            &own,
            &sender_keys,
            &descriptor.to_body(Kind::Attachment).unwrap(),
        )
        .unwrap();
        let page = Page {
            items: vec![Delivery {
                order: 1,
                receipt: Receipt {
                    id: id.clone(),
                    digest: batch.digest().unwrap(),
                    accepted_at: 200,
                },
                batch,
            }],
            has_more: false,
        };
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let actor = Arc::new(
            MessageCoordinator::open_with_protection(
                &work.0.join("downloads.db"),
                Owner::new(
                    &url,
                    &own.anchor().account,
                    &own.anchor().root.device_id,
                    &keys,
                )
                .unwrap(),
                &keys,
                Protection::isolated_test(),
            )
            .unwrap(),
        );
        for anchor in [own.anchor(), sender.anchor()] {
            actor
                .confirm_root(anchor, &anchor_fingerprint(anchor), &keys)
                .unwrap();
        }
        actor.renew_session("synthetic-token".into()).unwrap();
        let seen = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let ready = seen.clone();
        let proceed = release.clone();
        let roots = [own.anchor().clone(), sender.anchor().clone()];
        let server = tokio::spawn(async move {
            let mut delivered = false;
            let mut first = true;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![];
                let mut buffer = [0; 4096];
                let uri = loop {
                    let n = socket.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buffer[..n]);
                    if let Some(end) = request.windows(4).position(|s| s == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]);
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|v| v.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + len {
                            break head
                                .lines()
                                .next()
                                .unwrap()
                                .split_whitespace()
                                .nth(1)
                                .unwrap()
                                .to_owned();
                        }
                    }
                };
                let parsed = url::Url::parse(&format!("{url}{uri}")).unwrap();
                let path = parsed.path();
                let (status, bytes) = if path.starts_with("/users/") {
                    let account = path.split('/').nth(2).unwrap();
                    let anchor = roots.iter().find(|a| a.account == account).unwrap();
                    (
                        "200 OK",
                        serde_json::to_vec(&DeviceManifestPage {
                            anchor: anchor.clone(),
                            events: vec![],
                            through_revision: 0,
                            current_revision: 0,
                            current_hash: anchor.hash(),
                            more: false,
                        })
                        .unwrap(),
                    )
                } else if path == "/direct/v3/pending" {
                    let value = if delivered {
                        Page {
                            items: vec![],
                            has_more: false,
                        }
                    } else {
                        delivered = true;
                        page.clone()
                    };
                    ("200 OK", serde_json::to_vec(&value).unwrap())
                } else if path == "/direct/v3/ack" {
                    ("204 No Content", vec![])
                } else if path.starts_with("/direct/v3/media/objects/") {
                    if first {
                        first = false;
                        ready.notify_one();
                        proceed.notified().await;
                    }
                    ("200 OK", cipher.clone())
                } else {
                    panic!("unexpected synthetic test route")
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                socket.write_all(head.as_bytes()).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
            }
        });
        let f = Self {
            actor,
            keys,
            id,
            plain,
            seen,
            release,
            server,
            _work: work,
        };
        assert_eq!(
            f.actor.poll(&f.keys).await.unwrap().condition,
            Condition::Received
        );
        f
    }
}
#[tokio::test]
async fn pending_download_replies_cannot_bypass_cancel_hide_rotation_or_lock() {
    for mode in 0..4 {
        let f = Fixture::new().await;
        f.actor.start_media_download(&f.id, &f.keys).unwrap();
        let actor = f.actor.clone();
        let keys = f.keys.clone();
        let id = f.id.clone();
        let pending = tokio::spawn(async move { actor.media_step(&id, &keys).await });
        tokio::time::timeout(std::time::Duration::from_secs(3), f.seen.notified())
            .await
            .unwrap();
        match mode {
            0 => {
                f.actor.cancel_media(&f.id, &f.keys).unwrap();
            }
            1 => {
                f.actor.hide(&f.id, &f.keys).unwrap();
            }
            2 => f
                .actor
                .renew_session("synthetic-new-session".into())
                .unwrap(),
            _ => {
                f.actor.invalidate().unwrap();
                assert!(f.actor.media_info(&f.id, &f.keys).is_err());
                f.actor.resume().unwrap();
                f.actor
                    .renew_session("synthetic-after-lock".into())
                    .unwrap();
            }
        }
        f.release.notify_one();
        assert!(pending.await.unwrap().is_err());
        assert!(f.actor.media_plain(&f.id, &f.keys).is_err());
        if mode == 1 {
            assert!(f.actor.media_tasks(&f.keys).unwrap().is_empty());
            assert!(f.actor.media_info(&f.id, &f.keys).is_err());
            assert!(f.actor.start_media_download(&f.id, &f.keys).is_err());
        } else {
            let tasks = f.actor.media_tasks(&f.keys).unwrap();
            assert_eq!(tasks[0].downloaded, 0);
            f.actor.start_media_download(&f.id, &f.keys).unwrap();
            assert_eq!(
                f.actor.media_step(&f.id, &f.keys).await.unwrap().task.phase,
                Phase::Cached
            );
            f.actor.renew_session(String::new()).unwrap();
            assert_eq!(
                f.actor.media_plain(&f.id, &f.keys).unwrap().as_slice(),
                f.plain
            );
            f.actor.hide(&f.id, &f.keys).unwrap();
            assert!(f.actor.media_info(&f.id, &f.keys).is_err());
            assert!(f.actor.media_plain(&f.id, &f.keys).is_err());
            assert!(f.actor.media_step(&f.id, &f.keys).await.is_err());
            f.actor.clear_media(&f.id, &f.keys).unwrap();
            assert!(f.actor.media_plain(&f.id, &f.keys).is_err());
        }
    }
}
