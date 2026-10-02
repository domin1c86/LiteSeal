#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    db::repository::MessageRepository,
    trusted_devices::{
        activation::{
            jobs::{Owner, Stage, Store as Jobs},
            legacy::{self, Admission, Store},
        },
        witness::platform::Protection,
        DeviceTrustStore,
    },
};
use liteseal_shared::{
    crypto::{self, KeyPair},
    device_activation::Enable,
    trusted_device::*,
};
use rusqlite::{params, Connection};
use std::path::PathBuf;
struct Fixture {
    path: PathBuf,
    keys: KeyPair,
    anchor: Anchor,
    protection: Protection,
    _work: WorkDirectory,
}
impl Fixture {
    fn new() -> Self {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let path = work.0.join("legacy.db");
        drop(MessageRepository::new(path.to_str().unwrap()).unwrap());
        let keys = crypto::generate_keypair().unwrap();
        let anchor = Anchor {
            origin: "https://legacy-mode.invalid".into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
        };
        Self {
            path,
            keys,
            anchor,
            protection: Protection::isolated_test(),
            _work: work,
        }
    }
    fn initialize(&self) {
        let mut trust = DeviceTrustStore::open(&self.path).unwrap();
        trust
            .protect(self.protection.witness(&self.path).unwrap())
            .unwrap();
        trust.pin(&self.anchor).unwrap();
    }
    fn open(&self) -> Store {
        Store::open(
            &self.path,
            self.anchor.clone(),
            self.protection.witness(&self.path).unwrap(),
        )
        .unwrap()
    }
    fn jobs(&self) -> Jobs {
        Jobs::open(
            &self.path,
            Owner::new(self.anchor.clone(), &self.anchor.root.device_id, &self.keys).unwrap(),
            &self.keys,
            self.protection.witness(&self.path).unwrap(),
        )
        .unwrap()
    }
    fn admission(&self) -> Result<Admission, String> {
        legacy::admission(
            &self.path,
            self.anchor.clone(),
            &self.keys,
            self.protection.witness(&self.path).unwrap(),
        )
    }
    fn mode(&self) -> Enable {
        Enable::make(
            &DeviceState::pin(self.anchor.clone()).unwrap(),
            &uuid::Uuid::new_v4().to_string(),
            &self.keys,
        )
        .unwrap()
    }
}
#[test]
fn fresh_legacy_database_is_read_only_and_existing_native_head_cannot_be_hidden_by_missing_schema()
{
    let f = Fixture::new();
    assert_eq!(f.admission().unwrap(), Admission::Legacy);
    assert!(!f.protection.witness(&f.path).unwrap().has_record().unwrap());
    let conn = Connection::open(&f.path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='device_control_tasks'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    drop(conn);
    f.initialize();
    let task = f.jobs().prepare_enable_checked(&f.keys).unwrap();
    assert_eq!(task.view().stage, Stage::Prepared);
    Connection::open(&f.path)
        .unwrap()
        .execute_batch("DROP TABLE device_control_tasks; DROP TABLE trusted_device_anchors; DROP TABLE trusted_device_events; DROP TABLE device_state_witness")
        .unwrap();
    let conn = Connection::open(&f.path).unwrap();
    let schema:i64=conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('device_control_tasks','trusted_device_anchors','device_state_witness')",[],|r|r.get(0)).unwrap();
    assert_eq!(schema, 0);
    drop(conn);
    assert!(f.protection.witness(&f.path).unwrap().has_record().unwrap());
    assert!(f.admission().is_err());
}
#[test]
fn original_enable_task_blocks_legacy_until_positive_local_cancellation_and_remains_scoped() {
    let f = Fixture::new();
    f.initialize();
    let mut jobs = f.jobs();
    let task = jobs.prepare_enable_checked(&f.keys).unwrap();
    assert!(jobs.prepare_enable_checked(&f.keys).is_err());
    assert_eq!(f.admission().unwrap(), Admission::Switching);
    let mut other = f.anchor.clone();
    other.account = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        legacy::admission(
            &f.path,
            other,
            &f.keys,
            f.protection.witness(&f.path).unwrap()
        )
        .unwrap(),
        Admission::Legacy
    );
    jobs.request_cancel(&task.view().id, &f.keys).unwrap();
    assert_eq!(f.admission().unwrap(), Admission::Legacy);
    assert_eq!(
        jobs.task(&task.view().id, &f.keys).unwrap().view().stage,
        Stage::Cancelled
    );
}
#[test]
fn all_six_legacy_backlogs_block_atomic_prepare_without_creating_an_enable_task() {
    let f = Fixture::new();
    f.initialize();
    let conn = Connection::open(&f.path).unwrap();
    let user = &f.anchor.account;
    let device = &f.anchor.root.device_id;
    conn.execute("INSERT INTO messages(id,conversation_id,sender_id,sender_device_id,sender_seq,timestamp,message_type,local_state,ciphertext,signature,prev_hash) VALUES('old','conversation',?1,?2,1,1,'text','pending',X'00',X'00',X'00')",params![user,device]).unwrap();
    conn.execute("INSERT INTO attachment_transfers(id,user_id,peer_id,message_id,metadata,ciphertext,offset,direction) VALUES('upload',?1,'peer','unpublished',X'00',X'00',0,'upload')",[user]).unwrap();
    conn.execute("INSERT INTO scheduled_messages(user_id,device_id,id,peer_id,due_at,body,state) VALUES(?1,?2,'schedule','peer',1,X'00','scheduled')",params![user,device]).unwrap();
    conn.execute("INSERT INTO local_message_operations(user_id,device_id,id,target_id,conversation_id,body,status) VALUES(?1,?2,'op','old','conversation','{}','pending')",params![user,device]).unwrap();
    let body = serde_json::json!({"device":device}).to_string();
    conn.execute(
        "INSERT INTO local_reactions(user_id,id,seq,body) VALUES(?1,'reaction',0,?2)",
        params![user, body],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO local_read_receipts(user_id,id,seq,body) VALUES(?1,'receipt',0,?2)",
        params![user, body],
    )
    .unwrap();
    let counts = f.open().pending().unwrap();
    assert_eq!(
        (
            counts.messages,
            counts.uploads,
            counts.scheduled,
            counts.operations,
            counts.reactions,
            counts.receipts
        ),
        (1, 1, 1, 1, 1, 1)
    );
    let mut jobs = f.jobs();
    assert!(jobs.prepare_enable_checked(&f.keys).is_err());
    assert!(jobs.views(&f.keys).unwrap().is_empty());
    for query in [
        "UPDATE messages SET local_state='received'",
        "DELETE FROM attachment_transfers",
        "UPDATE scheduled_messages SET state='submitted'",
        "UPDATE local_message_operations SET status='accepted'",
        "UPDATE local_reactions SET seq=1",
    ] {
        conn.execute_batch(query).unwrap();
        assert!(jobs.prepare_enable_checked(&f.keys).is_err());
        assert!(jobs.views(&f.keys).unwrap().is_empty());
    }
    conn.execute_batch("UPDATE local_read_receipts SET seq=1")
        .unwrap();
    assert!(f.open().pending().unwrap().empty());
    assert_eq!(
        jobs.prepare_enable_checked(&f.keys).unwrap().view().stage,
        Stage::Prepared
    );
    let row: Vec<u8> = conn
        .query_row("SELECT ciphertext FROM messages WHERE id='old'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(row, vec![0]);
}
#[test]
fn other_device_and_completed_rows_do_not_block_but_malformed_pending_metadata_fails_safely() {
    let f = Fixture::new();
    f.initialize();
    let conn = Connection::open(&f.path).unwrap();
    let user = &f.anchor.account;
    let other = uuid::Uuid::new_v4().to_string();
    let body = serde_json::json!({"device":other}).to_string();
    conn.execute(
        "INSERT INTO local_reactions(user_id,id,seq,body) VALUES(?1,'other',0,?2)",
        params![user, body],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO local_read_receipts(user_id,id,seq,body) VALUES(?1,'other',0,?2)",
        params![user, body],
    )
    .unwrap();
    assert!(f.open().pending().unwrap().empty());
    conn.execute(
        "INSERT INTO local_read_receipts(user_id,id,seq,body) VALUES(?1,'unknown',0,'{}')",
        [user],
    )
    .unwrap();
    assert_eq!(f.open().pending().unwrap().receipts, 1);
    assert!(f.jobs().prepare_enable_checked(&f.keys).is_err());
    conn.execute(
        "UPDATE local_read_receipts SET body='not-json' WHERE id='unknown'",
        [],
    )
    .unwrap();
    assert!(f.open().pending().is_err());
    assert!(f.jobs().prepare_enable_checked(&f.keys).is_err());
    assert!(f.jobs().views(&f.keys).unwrap().is_empty());
}
#[tokio::test]
async fn verified_enabled_fact_is_encrypted_immutable_reopens_and_cannot_enable_another_root() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut f = Fixture::new();
    f.anchor.origin = format!("http://{}", listener.local_addr().unwrap());
    f.initialize();
    let event = f.mode();
    let mut store = f.open();
    store
        .remember_enabled(
            observe(&f, &listener, Some(event.clone())).await.unwrap(),
            &f.keys,
        )
        .unwrap();
    assert_eq!(store.admission(&f.keys).unwrap(), Admission::V3);
    drop(store);
    assert_eq!(f.admission().unwrap(), Admission::V3);
    f.open()
        .remember_enabled(
            observe(&f, &listener, Some(event.clone())).await.unwrap(),
            &f.keys,
        )
        .unwrap();
    assert!(f.jobs().prepare_enable_checked(&f.keys).is_err());
    assert!(f
        .open()
        .remember_enabled(
            observe(&f, &listener, Some(f.mode())).await.unwrap(),
            &f.keys
        )
        .is_err());
    let mut wrong = event;
    wrong.signature[0] ^= 1;
    assert!(observe(&f, &listener, Some(wrong)).await.is_err());
    assert!(f
        .open()
        .remember_enabled(observe(&f, &listener, None).await.unwrap(), &f.keys)
        .is_err());
    let mut other = Fixture::new();
    other.anchor.origin = f.anchor.origin.clone();
    assert!(f
        .open()
        .remember_enabled(
            observe(&other, &listener, Some(other.mode()))
                .await
                .unwrap(),
            &f.keys
        )
        .is_err());
    let bytes: Vec<u8> = Connection::open(&f.path)
        .unwrap()
        .query_row(
            "SELECT body FROM device_control_tasks WHERE kind='root_direct_mode'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!bytes
        .windows(f.anchor.origin.len())
        .any(|v| v == f.anchor.origin.as_bytes()));
    let wrong = crypto::generate_keypair().unwrap();
    assert!(f.open().admission(&wrong).is_err());
}
async fn observe(
    f: &Fixture,
    listener: &tokio::net::TcpListener,
    event: Option<Enable>,
) -> Result<
    liteseal_core::trusted_devices::activation::VerifiedMode,
    liteseal_core::trusted_devices::activation::ActivationError,
> {
    use liteseal_shared::device_activation::{ModeQuery, ModeReply};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let state = DeviceState::pin(f.anchor.clone()).unwrap();
    let api =
        liteseal_core::trusted_devices::activation::ActivationApi::new(&f.anchor.origin).unwrap();
    let send = api.observe_mode(&state, &f.anchor.root.device_id, &f.keys);
    let serve = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut wire = Vec::new();
        let mut chunk = [0; 4096];
        let (start, len) = loop {
            let n = socket.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            wire.extend_from_slice(&chunk[..n]);
            if let Some(end) = wire.windows(4).position(|v| v == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&wire[..end]).to_lowercase();
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
        while wire.len() < start + len {
            let n = socket.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            wire.extend_from_slice(&chunk[..n]);
        }
        let query: ModeQuery = serde_json::from_slice(&wire[start..start + len]).unwrap();
        let body = serde_json::to_vec(&ModeReply {
            version: 1,
            request: query.digest().unwrap(),
            event,
        })
        .unwrap();
        let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
        socket.write_all(header.as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
    };
    let (result, ()) = tokio::join!(send, serve);
    result
}
