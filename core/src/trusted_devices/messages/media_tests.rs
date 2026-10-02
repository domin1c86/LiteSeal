use super::*;
use crate::{
    backup::WorkDirectory,
    trusted_devices::witness::{SecureCell, SecureStore, Witness},
};
use liteseal_shared::{
    direct_message::{Header, MessageSpec},
    protocol::AckOutcome,
    trusted_device::{Anchor, DeviceIdentity, DeviceState},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};
#[derive(Default)]
pub(super) struct Memory(pub(super) Mutex<(Option<Vec<u8>>, usize, Option<usize>)>);
struct Slot<'a>(MutexGuard<'a, (Option<Vec<u8>>, usize, Option<usize>)>);
impl SecureCell for Slot<'_> {
    fn read(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0 .0.clone())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0 .1 += 1;
        if self.0 .2 == Some(self.0 .1) {
            self.0 .2 = None;
            return Err("injected native write failure".into());
        }
        self.0 .0 = Some(bytes.to_vec());
        Ok(())
    }
}
impl SecureStore for Memory {
    fn binding(&self) -> [u8; 32] {
        [13; 32]
    }
    fn lock(&self) -> Result<Box<dyn SecureCell + '_>, String> {
        Ok(Box::new(Slot(self.0.lock().unwrap())))
    }
}
pub(super) struct Fixture {
    pub(super) path: PathBuf,
    pub(super) owner: Owner,
    pub(super) keys: KeyPair,
    pub(super) peer: DeviceState,
    pub(super) peer_keys: KeyPair,
    pub(super) native: Arc<Memory>,
    pub(super) store: Store,
    pub(super) _work: WorkDirectory,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let path = work.0.join("media.db");
        let keys = crypto::generate_keypair().unwrap();
        let peer_keys = crypto::generate_keypair().unwrap();
        let owner = Owner::new(
            "https://synthetic.example",
            "synthetic-owner",
            "original-device",
            &keys,
        )
        .unwrap();
        let peer = DeviceState::pin(Anchor {
            origin: owner.origin.clone(),
            account: "synthetic-peer".into(),
            root: DeviceIdentity::from_keys("peer-device".into(), &peer_keys),
        })
        .unwrap();
        let native = Arc::new(Memory::default());
        let mut store =
            Store::open(&path, owner.clone(), Witness::new(&path, native.clone())).unwrap();
        store
            .trust()
            .pin(&Anchor {
                origin: owner.origin.clone(),
                account: owner.account.clone(),
                root: owner.device.clone(),
            })
            .unwrap();
        store.trust().pin(peer.anchor()).unwrap();
        Self {
            path,
            owner,
            keys,
            peer,
            peer_keys,
            native,
            store,
            _work: work,
        }
    }
    fn stage(&mut self, id: &str, bytes: &[u8]) -> View {
        self.store
            .stage_media(
                Stage {
                    id,
                    peer: &self.peer.anchor().account,
                    name: "中文文件.txt",
                    bytes,
                    kind: Kind::Attachment,
                    duration_ms: None,
                },
                &self.keys,
            )
            .unwrap()
    }
    fn upload(&mut self, id: &str) {
        loop {
            let view = self.store.media_task(id, &self.keys).unwrap();
            if view.phase == Phase::Uploaded {
                return;
            }
            self.store
                .media_uploaded(id, view.revision, &self.keys)
                .unwrap();
        }
    }
}
#[test]
fn staged_ciphertext_reopens_and_original_preparation_is_immutable() {
    let mut f = Fixture::new();
    let id = uuid::Uuid::new_v4().to_string();
    let bytes = "中文 emoji 🦭".as_bytes().repeat(90_000);
    let staged = f.stage(&id, &bytes);
    assert_eq!(
        f.store
            .media_pending_plain(&id, &f.keys)
            .unwrap()
            .as_slice(),
        bytes
    );
    assert!(f.store.prepare_media(&id, 100, &f.keys).is_err());
    assert!(f.store.clear_media(&id, &f.keys).is_err());
    let cipher = f.store.media_chunk(&id, staged.revision, &f.keys).unwrap();
    assert_eq!(cipher.len(), CHUNK);
    assert_eq!(f.stage(&id, &bytes).revision, staged.revision);
    assert!(f
        .store
        .stage_media(
            Stage {
                id: &id,
                peer: &f.peer.anchor().account,
                name: "changed.txt",
                bytes: &bytes,
                kind: Kind::Attachment,
                duration_ms: None
            },
            &f.keys
        )
        .is_err());
    f.store = Store::open(
        &f.path,
        f.owner.clone(),
        Witness::new(&f.path, f.native.clone()),
    )
    .unwrap();
    assert_eq!(
        f.store.media_chunk(&id, staged.revision, &f.keys).unwrap(),
        cipher
    );
    f.upload(&id);
    let prepared = f.store.prepare_media(&id, 100, &f.keys).unwrap();
    assert!(f.store.media_pending_plain(&id, &f.keys).is_err());
    let wire = f.store.original(&id, &f.keys).unwrap().to_wire().unwrap();
    assert_eq!(
        f.store.prepare_media(&id, 200, &f.keys).unwrap().digest,
        prepared.digest
    );
    assert_eq!(
        f.store.original(&id, &f.keys).unwrap().to_wire().unwrap(),
        wire
    );
    let submission = f.store.media_submission(&id, &f.keys).unwrap();
    assert_eq!(
        submission.to_wire().unwrap(),
        f.store
            .media_submission(&id, &f.keys)
            .unwrap()
            .to_wire()
            .unwrap()
    );
    let job = f.store.media_job(&id, &f.keys).unwrap();
    let all = f
        .store
        .trust
        .read_checked(|conn| ciphertext(conn, &f.owner, &job))
        .unwrap();
    assert_eq!(job.descriptor.decrypt(job.kind, &all).unwrap(), bytes);
    let public = serde_json::to_vec(&job.view()).unwrap();
    assert!(!public.windows(5).any(|v| v == b"\"key\""));
    let on_disk = std::fs::read(&f.path).unwrap();
    assert!(!on_disk
        .windows("中文文件.txt".len())
        .any(|s| s == "中文文件.txt".as_bytes()));
    assert!(!on_disk.windows(32).any(|s| s == job.descriptor.key));
    let batch = f.store.original(&id, &f.keys).unwrap();
    f.store.begin_publish(&id, 0, &f.keys).unwrap();
    let receipt = super::super::Acceptance::from_authenticated_response(
        &batch,
        &id,
        batch.digest().unwrap(),
        200,
    )
    .unwrap();
    f.store.confirm_accepted(&receipt, &f.keys).unwrap();
    f.store.clear_accepted_task(&id, &f.keys).unwrap();
    assert_eq!(
        f.store.media_state(&id, &f.keys).unwrap(),
        TaskState::Accepted
    );
    assert_eq!(
        f.store.clear_media(&id, &f.keys).unwrap(),
        bytes.len() as u64 + 40
    );
}
#[test]
fn cancellation_fences_late_upload_and_clear_does_not_reuse_original_id() {
    let mut f = Fixture::new();
    let id = uuid::Uuid::new_v4().to_string();
    let original = f.stage(&id, b"original");
    let cancelled = f.store.cancel_media(&id, &f.keys).unwrap();
    assert!(f.store.media_pending_plain(&id, &f.keys).is_err());
    assert_eq!(cancelled.phase, Phase::Cancelled);
    assert!(f
        .store
        .media_uploaded(&id, original.revision, &f.keys)
        .is_err());
    assert!(f.store.prepare_media(&id, 100, &f.keys).is_err());
    assert_eq!(f.store.clear_media(&id, &f.keys).unwrap(), original.total);
    assert_eq!(f.store.clear_media(&id, &f.keys).unwrap(), 0);
    assert!(f.store.media_tasks(&f.keys).unwrap().is_empty());
    assert!(f
        .store
        .stage_media(
            Stage {
                id: &id,
                peer: &f.peer.anchor().account,
                name: "中文文件.txt",
                bytes: b"original",
                kind: Kind::Attachment,
                duration_ms: None
            },
            &f.keys
        )
        .is_err());
    let next = uuid::Uuid::new_v4().to_string();
    f.stage(&next, b"keep publishing original");
    f.upload(&next);
    f.store.prepare_media(&next, 100, &f.keys).unwrap();
    f.store.begin_publish(&next, 0, &f.keys).unwrap();
    let wire = f.store.original(&next, &f.keys).unwrap().to_wire().unwrap();
    f.store.cancel_media(&next, &f.keys).unwrap();
    assert!(f.store.task_view(&next, &f.keys).unwrap().cancel_requested);
    assert!(f.store.clear_media(&next, &f.keys).is_err());
    assert_eq!(
        f.store.original(&next, &f.keys).unwrap().to_wire().unwrap(),
        wire
    );
}
#[test]
fn bulk_storage_cleanup_protects_unknown_publication_and_other_conversations() {
    let mut f = Fixture::new();
    let pending = uuid::Uuid::new_v4().to_string();
    let cancelled = uuid::Uuid::new_v4().to_string();
    f.stage(&pending, b"keep original publication");
    f.upload(&pending);
    f.store.prepare_media(&pending, 100, &f.keys).unwrap();
    f.store.begin_publish(&pending, 0, &f.keys).unwrap();
    let original = f
        .store
        .original(&pending, &f.keys)
        .unwrap()
        .to_wire()
        .unwrap();
    f.stage(&cancelled, b"cancelled source");
    f.store.cancel_media(&cancelled, &f.keys).unwrap();
    let second = DeviceState::pin(Anchor {
        origin: f.owner.origin.clone(),
        account: "another-peer".into(),
        root: DeviceIdentity::from_keys(
            "another-device".into(),
            &crypto::generate_keypair().unwrap(),
        ),
    })
    .unwrap();
    f.store.trust().pin(second.anchor()).unwrap();
    let other = uuid::Uuid::new_v4().to_string();
    f.store
        .stage_media(
            Stage {
                id: &other,
                peer: &second.anchor().account,
                name: "other.txt",
                bytes: b"other cancelled source",
                kind: Kind::Attachment,
                duration_ms: None,
            },
            &f.keys,
        )
        .unwrap();
    f.store.cancel_media(&other, &f.keys).unwrap();
    let conn = Connection::open(&f.path).unwrap();
    for (s, id, n) in [
        (f.owner.scope(), "orphan", 17),
        ("other-scope".into(), "foreign", 19),
    ] {
        conn.execute("INSERT INTO direct_v3_media_chunks(scope,account,id,part,ciphertext) VALUES(?1,?2,?3,0,zeroblob(?4))",params![s,f.owner.account,id,n]).unwrap();
    }
    let stats = f.store.media_storage_stats(&f.keys).unwrap();
    assert_eq!(stats.shared_cache_bytes, stats.cache_bytes + 19);
    assert_eq!(stats.orphan_bytes, 17);
    assert_eq!(
        stats.peers.iter().map(|p| p.protected_tasks).sum::<u64>(),
        1
    );
    assert_eq!(
        stats.peers.iter().map(|p| p.clearable_tasks).sum::<u64>(),
        2
    );
    let public = serde_json::to_string(&stats).unwrap();
    assert!(!public.contains("other.txt"));
    assert!(!public.contains("\"key\""));
    assert!(!public.contains(f.path.to_str().unwrap()));
    let cleared = f
        .store
        .clear_media_cache(Some(&f.peer.anchor().account), &f.keys)
        .unwrap();
    assert_eq!(cleared.cleared_tasks, 1);
    assert_eq!(cleared.protected_tasks, 1);
    assert_eq!(cleared.removed_bytes, b"cancelled source".len() as u64 + 40);
    assert_eq!(
        f.store
            .original(&pending, &f.keys)
            .unwrap()
            .to_wire()
            .unwrap(),
        original
    );
    assert!(f.store.media_task(&other, &f.keys).is_ok());
    let all = f.store.clear_media_cache(None, &f.keys).unwrap();
    assert_eq!(all.cleared_tasks, 1);
    assert_eq!(all.protected_tasks, 1);
    assert_eq!(
        conn.query_row(
            "SELECT length(ciphertext) FROM direct_v3_media_chunks WHERE scope='other-scope'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        19
    );
    let after = f.store.media_storage_stats(&f.keys).unwrap();
    assert_eq!(after.orphan_bytes, 0);
    assert_eq!(after.peers.len(), 1);
    let batch = f.store.original(&pending, &f.keys).unwrap();
    let receipt = super::super::Acceptance::from_authenticated_response(
        &batch,
        &pending,
        batch.digest().unwrap(),
        200,
    )
    .unwrap();
    f.store.confirm_accepted(&receipt, &f.keys).unwrap();
    f.store.clear_accepted_task(&pending, &f.keys).unwrap();
    assert_eq!(
        f.store
            .clear_media_cache(None, &f.keys)
            .unwrap()
            .cleared_tasks,
        1
    );
    assert_eq!(f.store.media_storage_stats(&f.keys).unwrap().cache_bytes, 0);
    assert_eq!(f.store.history(None, 100, &f.keys).unwrap().len(), 1);
    assert_eq!(
        f.store
            .clear_media_cache(None, &f.keys)
            .unwrap()
            .removed_bytes,
        0
    );
}
#[test]
fn bulk_storage_rejects_wrong_keys_and_bad_metadata_before_deleting_anything() {
    let mut f = Fixture::new();
    let id = uuid::Uuid::new_v4().to_string();
    f.stage(&id, b"retain on error");
    f.store.cancel_media(&id, &f.keys).unwrap();
    assert!(f
        .store
        .clear_media_cache(None, &crypto::generate_keypair().unwrap())
        .is_err());
    assert!(f
        .store
        .media_storage_stats(&crypto::generate_keypair().unwrap())
        .is_err());
    let before = f.store.media_storage_stats(&f.keys).unwrap().cache_bytes;
    let another = uuid::Uuid::new_v4().to_string();
    f.stage(&another, b"bad metadata");
    f.store
        .trust
        .write_checked(|conn| {
            conn.execute(
                "UPDATE device_control_tasks SET body=zeroblob(length(body)) WHERE id=?1",
                [&another],
            )
            .map_err(db)?;
            Ok(())
        })
        .unwrap();
    assert!(f.store.clear_media_cache(None, &f.keys).is_err());
    assert!(f.store.media_storage_stats(&f.keys).is_err());
    let conn = Connection::open(&f.path).unwrap();
    assert_eq!(job_bytes_for_test(&conn, &f.owner, &id), before);
}
fn job_bytes_for_test(conn: &Connection, owner: &Owner, id: &str) -> u64 {
    storage::job_bytes(conn, owner, id).unwrap()
}
#[test]
fn cache_corruption_and_other_identity_cannot_advance_or_prepare() {
    let mut f = Fixture::new();
    let id = uuid::Uuid::new_v4().to_string();
    let first = f.stage(&id, b"authenticated cache");
    let original = f.store.media_chunk(&id, first.revision, &f.keys).unwrap();
    let conn = Connection::open(&f.path).unwrap();
    conn.execute(
        "UPDATE direct_v3_media_chunks SET ciphertext=zeroblob(length(ciphertext)) WHERE id=?1",
        [&id],
    )
    .unwrap();
    assert!(f.store.media_chunk(&id, first.revision, &f.keys).is_err());
    assert!(f
        .store
        .media_uploaded(&id, first.revision, &f.keys)
        .is_err());
    assert_eq!(
        f.store.media_task(&id, &f.keys).unwrap().revision,
        first.revision
    );
    conn.execute(
        "UPDATE direct_v3_media_chunks SET ciphertext=?2 WHERE id=?1",
        params![id, original],
    )
    .unwrap();
    drop(conn);
    let wrong = crypto::generate_keypair().unwrap();
    assert!(f.store.media_task(&id, &wrong).is_err());
    let mut foreign = Store::open(
        &f.path,
        Owner::new(&f.owner.origin, &f.owner.account, "other-device", &wrong).unwrap(),
        Witness::new(&f.path, f.native.clone()),
    )
    .unwrap();
    assert!(foreign.media_task(&id, &wrong).is_err());
    f.upload(&id);
    f.store.prepare_media(&id, 100, &f.keys).unwrap();
    let batch = f.store.original(&id, &f.keys).unwrap();
    let mut receiver = Store::open(
        &f._work.0.join("receiver.db"),
        Owner::new(
            &f.owner.origin,
            &f.peer.anchor().account,
            &f.peer.anchor().root.device_id,
            &f.peer_keys,
        )
        .unwrap(),
        Witness::new(&f._work.0.join("receiver.db"), Arc::new(Memory::default())),
    )
    .unwrap();
    receiver
        .trust()
        .pin(&Anchor {
            origin: f.owner.origin.clone(),
            account: f.owner.account.clone(),
            root: f.owner.device.clone(),
        })
        .unwrap();
    receiver.trust().pin(f.peer.anchor()).unwrap();
    let receipt = super::super::Acceptance::from_authenticated_response(
        &batch,
        &id,
        batch.digest().unwrap(),
        200,
    )
    .unwrap();
    assert_eq!(
        receiver.receive(&batch, &receipt, &f.peer_keys).unwrap(),
        AckOutcome::Processed
    );
    receiver.hide(&id, &f.peer_keys).unwrap();
    receiver.receive(&batch, &receipt, &f.peer_keys).unwrap();
    assert!(receiver.body(&id, &f.peer_keys).is_err());
    assert!(receiver
        .history(None, 100, &f.peer_keys)
        .unwrap()
        .is_empty());
}
#[test]
fn malformed_authenticated_descriptor_is_quarantined_with_durable_ack() {
    let mut f = Fixture::new();
    let sender = DeviceState::pin(Anchor {
        origin: f.owner.origin.clone(),
        account: f.owner.account.clone(),
        root: f.owner.device.clone(),
    })
    .unwrap();
    let batch = Batch::make(
        Header::new(
            &f.peer,
            &sender,
            &f.peer.anchor().root.device_id,
            MessageSpec {
                id: uuid::Uuid::new_v4().to_string(),
                sequence: 1,
                previous: vec![],
                sent_at: 100,
                kind: Kind::Attachment,
            },
        )
        .unwrap(),
        &f.peer,
        &sender,
        &f.peer_keys,
        b"invalid descriptor",
    )
    .unwrap();
    let receipt = super::super::Acceptance::from_authenticated_response(
        &batch,
        &batch.header.id,
        batch.digest().unwrap(),
        200,
    )
    .unwrap();
    assert_eq!(
        f.store.receive(&batch, &receipt, &f.keys).unwrap(),
        AckOutcome::Rejected
    );
    assert!(f.store.body(&batch.header.id, &f.keys).is_err());
    assert_eq!(
        f.store.pending_acks(&f.keys).unwrap()[0].outcome,
        AckOutcome::Rejected
    );
    let next = Batch::make(
        Header::new(
            &f.peer,
            &sender,
            &f.peer.anchor().root.device_id,
            MessageSpec {
                id: uuid::Uuid::new_v4().to_string(),
                sequence: 2,
                previous: batch.digest().unwrap().to_vec(),
                sent_at: 101,
                kind: Kind::Text,
            },
        )
        .unwrap(),
        &f.peer,
        &sender,
        &f.peer_keys,
        b"following message",
    )
    .unwrap();
    let receipt = super::super::Acceptance::from_authenticated_response(
        &next,
        &next.header.id,
        next.digest().unwrap(),
        201,
    )
    .unwrap();
    assert_eq!(
        f.store.receive(&next, &receipt, &f.keys).unwrap(),
        AckOutcome::Processed
    );
}
#[test]
fn native_journal_recovers_prepared_job_and_batch_with_precommitted_ciphertext() {
    let mut f = Fixture::new();
    let id = uuid::Uuid::new_v4().to_string();
    f.stage(&id, b"recover immutable media");
    f.upload(&id);
    let before = f._work.0.join("before.db");
    std::fs::copy(&f.path, &before).unwrap();
    {
        let mut native = f.native.0.lock().unwrap();
        native.2 = Some(native.1 + 2);
    }
    assert!(f.store.prepare_media(&id, 100, &f.keys).is_err());
    // Mimic the SQLite/native-store crash gap, preserving the native pending
    // point and journal while restoring exactly the preceding SQLite state.
    drop(f.store);
    std::fs::copy(&before, &f.path).unwrap();
    let mut store = Store::open(
        &f.path,
        f.owner.clone(),
        Witness::new(&f.path, f.native.clone()),
    )
    .unwrap();
    assert_eq!(
        store.media_task(&id, &f.keys).unwrap().phase,
        Phase::Prepared
    );
    assert_eq!(store.original(&id, &f.keys).unwrap().header.id, id);
    let job = store.media_job(&id, &f.keys).unwrap();
    let bytes = store
        .trust
        .read_checked(|conn| ciphertext(conn, &f.owner, &job))
        .unwrap();
    assert_eq!(
        job.descriptor.decrypt(job.kind, &bytes).unwrap(),
        b"recover immutable media"
    );
}
#[test]
fn legacy_group_and_v3_ciphertext_share_the_local_cache_budget() {
    let mut f = Fixture::new();
    let conn = Connection::open(&f.path).unwrap();
    conn.execute_batch(crate::attachment_cache::GROUP_SCHEMA)
        .unwrap();
    conn.execute("INSERT INTO group_attachment_cache VALUES('synthetic',?1,'group','blob',1,X'00',zeroblob(?2),0,'download','root')",params![f.owner.account,LIMIT-39]).unwrap();
    drop(conn);
    let id = uuid::Uuid::new_v4().to_string();
    assert!(f
        .store
        .stage_media(
            Stage {
                id: &id,
                peer: &f.peer.anchor().account,
                name: "empty.bin",
                bytes: b"",
                kind: Kind::Attachment,
                duration_ms: None
            },
            &f.keys
        )
        .is_err());
    assert!(f.store.media_tasks(&f.keys).unwrap().is_empty());
}

#[test]
fn staging_only_identity_refuses_old_backup_and_empty_cancelled_cache_can_clear() {
    use crate::keystore::KeystoreData;
    let mut f = Fixture::new();
    let id = uuid::Uuid::new_v4().to_string();
    f.stage(&id, b"not silently omitted");
    let identity = Zeroizing::new(KeystoreData {
        user_id: f.owner.account.clone(),
        device_id: f.owner.device.device_id.clone(),
        server_url: f.owner.origin.clone(),
        token: String::new(),
        refresh_token: String::new(),
        public_key: f.keys.public_key.to_vec(),
        secret_key: f.keys.secret_key.to_vec(),
        ed25519_pk: f.keys.ed25519_pk.to_vec(),
        ed25519_sk: f.keys.ed25519_sk.to_vec(),
    });
    let conn = Connection::open(&f.path).unwrap();
    let error = super::super::require_backup_support(&conn, &identity).unwrap_err();
    assert!(error.contains("媒体"));
    f.store.cancel_media(&id, &f.keys).unwrap();
    f.store.clear_media(&id, &f.keys).unwrap();
    assert!(super::super::require_backup_support(&conn, &identity).is_ok());
}

#[test]
fn injected_cache_trigger_cannot_delete_a_covered_original_task() {
    let mut f = Fixture::new();
    let original = uuid::Uuid::new_v4().to_string();
    f.store
        .prepare(
            Prepare {
                id: &original,
                peer: &f.peer.anchor().account,
                sent_at: 100,
                kind: Kind::Text,
                body: b"keep original task",
            },
            &f.keys,
        )
        .unwrap();
    let conn = Connection::open(&f.path).unwrap();
    conn.execute_batch("CREATE TRIGGER injected_media_cache BEFORE INSERT ON direct_v3_media_chunks BEGIN DELETE FROM direct_v3_tasks; END;").unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    assert!(f
        .store
        .stage_media(
            Stage {
                id: &id,
                peer: &f.peer.anchor().account,
                name: "file.bin",
                bytes: b"do not mutate original",
                kind: Kind::Attachment,
                duration_ms: None
            },
            &f.keys
        )
        .is_err());
    assert_eq!(
        f.store.original(&original, &f.keys).unwrap().header.id,
        original
    );
    conn.execute_batch("DROP TRIGGER injected_media_cache")
        .unwrap();
    drop(conn);
    f.stage(&id, b"normal staging after repair");
}
