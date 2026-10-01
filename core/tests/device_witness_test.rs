#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{tasks::*, witness::*},
};
use liteseal_shared::crypto;
use std::{
    fs,
    sync::{Arc, Mutex, MutexGuard},
};
#[derive(Default)]
struct State {
    bytes: Option<Vec<u8>>,
    writes: usize,
    fail_at: Option<usize>,
}
#[derive(Default)]
struct Memory {
    state: Mutex<State>,
}
struct Slot<'a>(MutexGuard<'a, State>);
impl SecureCell for Slot<'_> {
    fn read(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.bytes.clone())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0.writes += 1;
        if self.0.fail_at == Some(self.0.writes) {
            self.0.fail_at = None;
            return Err("injected secure-store failure".into());
        }
        self.0.bytes = Some(bytes.to_vec());
        Ok(())
    }
}
impl SecureStore for Memory {
    fn binding(&self) -> [u8; 32] {
        [3; 32]
    }
    fn lock(&self) -> Result<Box<dyn SecureCell + '_>, String> {
        Ok(Box::new(Slot(self.state.lock().unwrap())))
    }
}
fn setup(
    work: &WorkDirectory,
) -> (
    std::path::PathBuf,
    TaskOwner,
    crypto::KeyPair,
    Arc<Memory>,
    DeviceTaskStore,
) {
    let path = work.0.join("tasks.db");
    let keys = crypto::generate_keypair().unwrap();
    let owner = TaskOwner::for_join(
        "http://127.0.0.1:9",
        "synthetic",
        &uuid::Uuid::new_v4().to_string(),
        &keys,
    )
    .unwrap();
    let backend = Arc::new(Memory::default());
    let mut store = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    store.protect(Witness::new(&path, backend.clone())).unwrap();
    (path, owner, keys, backend, store)
}
fn copy_closed(source: &std::path::Path, to: &std::path::Path) {
    fs::copy(source, to).unwrap();
}

#[test]
fn interrupted_initial_capture_recovers_only_its_exact_snapshot() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("initial.db");
    let mut trust = liteseal_core::trusted_devices::DeviceTrustStore::open(&path).unwrap();
    let backend = Arc::new(Memory::default());
    backend.state.lock().unwrap().fail_at = Some(2);
    assert!(trust.protect(Witness::new(&path, backend.clone())).is_err());
    drop(trust);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("DELETE FROM device_state_witness", [])
        .unwrap();
    drop(conn);
    let mut trust = liteseal_core::trusted_devices::DeviceTrustStore::open(&path).unwrap();
    trust.protect(Witness::new(&path, backend)).unwrap();
}

#[test]
fn schema_and_invalid_external_record_do_not_become_a_new_baseline() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let (path, owner, keys, backend, store) = setup(&work);
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE INDEX synthetic_extra ON device_control_tasks(terminal)")
        .unwrap();
    drop(conn);
    let mut store = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    assert!(store.protect(Witness::new(&path, backend.clone())).is_err());
    drop(store);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("DROP INDEX synthetic_extra").unwrap();
    drop(conn);
    let mut state = backend.state.lock().unwrap();
    let mut record: serde_json::Value =
        serde_json::from_slice(state.bytes.as_ref().unwrap()).unwrap();
    record["binding"][0] = serde_json::json!(9);
    state.bytes = Some(serde_json::to_vec(&record).unwrap());
    drop(state);
    let mut store = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    assert!(store.protect(Witness::new(&path, backend)).is_err());
}

#[test]
fn revoked_directory_rollback_is_rejected_without_caller_checkpoint() {
    use liteseal_core::trusted_devices::{Checkpoint, DeviceTrustStore};
    use liteseal_shared::trusted_device::*;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = work.0.join("directory.db");
    let backend = Arc::new(Memory::default());
    let root = crypto::generate_keypair().unwrap();
    let second = crypto::generate_keypair().unwrap();
    let anchor = Anchor {
        origin: "https://synthetic.example".into(),
        account: "synthetic".into(),
        root: DeviceIdentity::from_keys("root".into(), &root),
    };
    let mut trust = DeviceTrustStore::open(&path).unwrap();
    trust.protect(Witness::new(&path, backend.clone())).unwrap();
    let initial = trust.pin(&anchor).unwrap();
    let intent = make_intent(
        &anchor,
        "join".into(),
        "second".into(),
        crypto::random_challenge().unwrap(),
        1000,
        &second,
    )
    .unwrap();
    let challenge = make_challenge(&initial, &intent, 1001, &root).unwrap();
    let proof = answer_challenge(&initial, &intent, &challenge, 1002, &second).unwrap();
    let grant = make_event(
        &initial,
        "grant".into(),
        DeviceAction::Grant {
            intent: Box::new(intent),
            challenge: Box::new(challenge),
            proof,
        },
        1003,
        &root,
    )
    .unwrap();
    let joined = trust
        .append_live(
            &anchor,
            &Checkpoint::from_state(&initial),
            std::slice::from_ref(&grant),
            1004,
        )
        .unwrap();
    drop(trust);
    let old = work.0.join("joined.db");
    fs::copy(&path, &old).unwrap();
    let mut trust = DeviceTrustStore::open(&path).unwrap();
    trust.protect(Witness::new(&path, backend.clone())).unwrap();
    let revoke = make_event(
        &joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: "second".into(),
            grant_hash: grant.hash(),
        },
        2000,
        &root,
    )
    .unwrap();
    trust
        .append_live(&anchor, &Checkpoint::from_state(&joined), &[revoke], 2000)
        .unwrap();
    drop(trust);
    fs::copy(&old, &path).unwrap();
    let mut trust = DeviceTrustStore::open(&path).unwrap();
    assert!(trust.protect(Witness::new(&path, backend)).is_err());
}

#[test]
fn old_database_task_revisions_and_missing_secure_record_are_rejected() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let (path, owner, keys, backend, mut store) = setup(&work);
    let task = store.prepare_join("second", &keys).unwrap();
    drop(store);
    let snapshot = work.0.join("old.db");
    copy_closed(&path, &snapshot);
    let mut store = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    store.protect(Witness::new(&path, backend.clone())).unwrap();
    let task = store.get(&task.view().id, &keys).unwrap();
    store.request_cancel(&task, &keys).unwrap();
    drop(store);
    copy_closed(&snapshot, &path);
    let mut old = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    assert!(old.protect(Witness::new(&path, backend.clone())).is_err());
    assert!(old.views(&keys).is_err());
    drop(old);
    // A missing credential with a surviving marker cannot silently bootstrap.
    backend.state.lock().unwrap().bytes = None;
    let mut old = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    assert!(old.protect(Witness::new(&path, backend)).is_err());
}

#[test]
fn pending_secure_write_replays_exact_original_task_after_sqlite_commit_failure() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let (path, owner, keys, backend, mut store) = setup(&work);
    let task = store.prepare_join("second", &keys).unwrap();
    let original = store.get(&task.view().id, &keys).unwrap();
    drop(store);
    let before = work.0.join("before.db");
    copy_closed(&path, &before);
    let mut store = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
    store.protect(Witness::new(&path, backend.clone())).unwrap();
    // Fail secure finalization after DB commit: pending record and DPAPI journal remain.
    {
        let mut state = backend.state.lock().unwrap();
        state.fail_at = Some(state.writes + 2);
    }
    assert!(store.request_cancel(&original, &keys).is_err());
    assert!(Witness::new(&path, backend.clone()).journal_path().exists());
    drop(store);
    // Restoring the exact before image represents the other commit-gap outcome.
    copy_closed(&before, &path);
    let mut recovered = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    recovered
        .protect(Witness::new(&path, backend.clone()))
        .unwrap();
    let saved = recovered.get(&task.view().id, &keys).unwrap();
    assert_eq!(saved.view().phase, TaskPhase::Cancelling);
    assert_eq!(saved.view().revision, 1);
    assert!(saved.join_credential().unwrap() == original.join_credential().unwrap());
    assert!(!Witness::new(&path, backend).journal_path().exists());
}

#[test]
fn committed_database_recovers_failed_secure_finalization_without_second_mutation() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let (path, owner, keys, backend, mut store) = setup(&work);
    let task = store.prepare_join("second", &keys).unwrap();
    {
        let mut state = backend.state.lock().unwrap();
        state.fail_at = Some(state.writes + 2);
    }
    assert!(store.request_cancel(&task, &keys).is_err());
    drop(store);
    let mut store = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    store.protect(Witness::new(&path, backend)).unwrap();
    let saved = store.get(&task.view().id, &keys).unwrap();
    assert_eq!(saved.view().phase, TaskPhase::Cancelling);
    assert_eq!(saved.view().revision, 1);
}

#[test]
fn missing_or_corrupt_pending_journal_refuses_recovery_and_keeps_before_state() {
    for corrupt in [false, true] {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let (path, owner, keys, backend, mut store) = setup(&work);
        let task = store.prepare_join("second", &keys).unwrap();
        drop(store);
        let before = work.0.join("before.db");
        copy_closed(&path, &before);
        let mut store = DeviceTaskStore::open(&path, owner.clone(), &keys).unwrap();
        store.protect(Witness::new(&path, backend.clone())).unwrap();
        {
            let mut state = backend.state.lock().unwrap();
            state.fail_at = Some(state.writes + 2);
        }
        assert!(store.request_cancel(&task, &keys).is_err());
        drop(store);
        copy_closed(&before, &path);
        let journal = Witness::new(&path, backend.clone());
        if corrupt {
            fs::write(journal.journal_path(), "corrupt synthetic journal").unwrap();
        } else {
            fs::remove_file(journal.journal_path()).unwrap();
        }
        let mut old = DeviceTaskStore::open(&path, owner, &keys).unwrap();
        assert!(old.protect(journal).is_err());
        let conn = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT revision FROM device_control_tasks WHERE id=?1",
                [task.view().id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}

#[test]
fn failed_secure_preparation_does_not_commit_task_and_orphan_journal_is_not_replayed() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let (path, owner, keys, backend, mut store) = setup(&work);
    let task = store.prepare_join("second", &keys).unwrap();
    {
        let mut state = backend.state.lock().unwrap();
        state.fail_at = Some(state.writes + 1);
    }
    assert!(store.request_cancel(&task, &keys).is_err());
    drop(store);
    let mut store = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    store.protect(Witness::new(&path, backend)).unwrap();
    assert_eq!(
        store.get(&task.view().id, &keys).unwrap().view().phase,
        TaskPhase::Draft
    );
}

#[test]
fn root_confirmation_and_terminal_cleanup_are_atomic_protected_changes() {
    use liteseal_shared::trusted_device::*;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let (path, owner, keys, backend, mut store) = setup(&work);
    let root = crypto::generate_keypair().unwrap();
    let task = store.prepare_join("second", &keys).unwrap();
    let at = chrono::Utc::now().timestamp_millis();
    let anchor = Anchor {
        origin: "http://127.0.0.1:9".into(),
        account: uuid::Uuid::new_v4().to_string(),
        root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &root),
    };
    let status = JoinStatus {
        ticket: JoinTicket {
            id: task.view().id,
            anchor: anchor.clone(),
            device: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &keys),
            device_name: "second".into(),
            server_challenge: vec![9; 32],
            issued_at: at,
            expires_at: at + JOIN_LIFETIME_MS,
        },
        phase: JoinPhase::Begun,
        intent: None,
        challenge: None,
        proof: None,
        authorization_id: None,
    };
    let task = store.accept_ticket(&task, &status, &keys).unwrap();
    let confirmed = store
        .confirm_root(&task, &anchor, &anchor_fingerprint(&anchor), &keys)
        .unwrap();
    let original = confirmed.intent().cloned();
    drop(store);
    let mut store = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    store.protect(Witness::new(&path, backend)).unwrap();
    assert_eq!(
        store.get(&confirmed.view().id, &keys).unwrap().intent(),
        original.as_ref()
    );
    let cancelling = store.request_cancel(&confirmed, &keys).unwrap();
    let mut cancelled = status;
    cancelled.phase = JoinPhase::Cancelled;
    let terminal = store
        .confirm_join_cancel(&cancelling, &cancelled, &keys)
        .unwrap();
    store.discard_terminal(&terminal, &keys).unwrap();
    assert!(store.views(&keys).unwrap().is_empty());
}

#[test]
fn shared_database_other_scope_changes_do_not_look_like_rollback() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let (path, owner, keys, backend, mut one) = setup(&work);
    let task_one = one.prepare_join("one", &keys).unwrap();
    let keys_two = crypto::generate_keypair().unwrap();
    let owner_two = TaskOwner::for_join(
        "http://127.0.0.1:9",
        "other-synthetic",
        &uuid::Uuid::new_v4().to_string(),
        &keys_two,
    )
    .unwrap();
    let mut two = DeviceTaskStore::open(&path, owner_two.clone(), &keys_two).unwrap();
    two.protect(Witness::new(&path, backend.clone())).unwrap();
    let task_two = two.prepare_join("two", &keys_two).unwrap();
    assert_eq!(one.views(&keys).unwrap().len(), 1);
    assert!(one.get(&task_two.view().id, &keys).is_err());
    one.request_cancel(&task_one, &keys).unwrap();
    assert_eq!(
        two.get(&task_two.view().id, &keys_two)
            .unwrap()
            .view()
            .phase,
        TaskPhase::Draft
    );
    drop(one);
    drop(two);
    let mut one = DeviceTaskStore::open(&path, owner, &keys).unwrap();
    one.protect(Witness::new(&path, backend.clone())).unwrap();
    let mut two = DeviceTaskStore::open(&path, owner_two, &keys_two).unwrap();
    two.protect(Witness::new(&path, backend)).unwrap();
    assert_eq!(one.views(&keys).unwrap()[0].phase, TaskPhase::Cancelling);
    assert_eq!(two.views(&keys_two).unwrap()[0].phase, TaskPhase::Draft);
}
