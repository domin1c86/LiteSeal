use liteseal_core::trusted_devices::{tasks::*, Checkpoint};
use liteseal_shared::{
    crypto::{self, KeyPair},
    trusted_device::*,
};
use rusqlite::{params, Connection};
use std::path::PathBuf;
struct Fixture {
    path: PathBuf,
    root: KeyPair,
    second: KeyPair,
    anchor: Anchor,
    join_owner: TaskOwner,
    local_device: String,
}
impl Fixture {
    fn new() -> Self {
        let root = crypto::generate_keypair().unwrap();
        let second = crypto::generate_keypair().unwrap();
        let origin = "https://isolated.example";
        let anchor = Anchor {
            origin: origin.into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &root),
        };
        let local_device = uuid::Uuid::new_v4().to_string();
        let join_owner =
            TaskOwner::for_join(origin, "isolated-user", &local_device, &second).unwrap();
        Self {
            path: std::env::temp_dir()
                .join(format!("liteseal-device-jobs-{}.db", uuid::Uuid::new_v4())),
            root,
            second,
            anchor,
            join_owner,
            local_device,
        }
    }
    fn join(&self) -> DeviceTaskStore {
        DeviceTaskStore::open(&self.path, self.join_owner.clone(), &self.second).unwrap()
    }
    fn root(&self) -> DeviceTaskStore {
        DeviceTaskStore::open(
            &self.path,
            TaskOwner::for_root(&self.anchor, &self.root).unwrap(),
            &self.root,
        )
        .unwrap()
    }
    fn ticket(&self, id: String) -> JoinStatus {
        JoinStatus {
            ticket: JoinTicket {
                id,
                anchor: self.anchor.clone(),
                device: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), &self.second),
                device_name: "second".into(),
                server_challenge: crypto::random_challenge().unwrap().to_vec(),
                issued_at: 1000,
                expires_at: 601000,
            },
            phase: JoinPhase::Begun,
            intent: None,
            challenge: None,
            proof: None,
            authorization_id: None,
        }
    }
    fn proof(&self, store: &mut DeviceTaskStore) -> (ControlTask, DeviceState, JoinStatus) {
        let draft = store.prepare_join("second", &self.second).unwrap();
        let mut status = self.ticket(draft.view().id);
        let task = store.accept_ticket(&draft, &status, &self.second).unwrap();
        let task = store
            .confirm_root(
                &task,
                &self.anchor,
                &anchor_fingerprint(&self.anchor),
                &self.second,
            )
            .unwrap();
        let state = DeviceState::pin(self.anchor.clone()).unwrap();
        let challenge = make_challenge(&state, task.intent().unwrap(), 1001, &self.root).unwrap();
        let task = store
            .seal_proof(&task, &state, &challenge, 1002, &self.second)
            .unwrap();
        status.phase = JoinPhase::Proved;
        status.intent = task.intent().cloned();
        status.challenge = Some(challenge);
        status.proof = task.proof().cloned();
        (task, state, status)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("bin"));
    }
}
#[test]
fn encrypted_join_restart_preserves_credential_id_intent_and_proof_without_password() {
    let f = Fixture::new();
    let mut store = f.join();
    let draft = store.prepare_join("second", &f.second).unwrap();
    let id = draft.view().id;
    let credential = draft.join_credential().unwrap().to_string();
    let request = draft.start_request("private-test-password").unwrap();
    assert_eq!(request.request_id, id);
    drop(store);
    let mut store = f.join();
    let draft = store.get(&id, &f.second).unwrap();
    assert_eq!(draft.join_credential().unwrap(), credential);
    assert_eq!(
        draft
            .start_request("new-password-input")
            .unwrap()
            .request_id,
        id
    );
    let status = f.ticket(id.clone());
    let task = store.accept_ticket(&draft, &status, &f.second).unwrap();
    assert!(store
        .confirm_root(&task, &f.anchor, "wrong fingerprint", &f.second)
        .is_err());
    let task = store
        .confirm_root(&task, &f.anchor, &anchor_fingerprint(&f.anchor), &f.second)
        .unwrap();
    let intent = task.intent().unwrap().clone();
    drop(store);
    let mut store = f.join();
    let task = store.get(&id, &f.second).unwrap();
    assert_eq!(task.intent().unwrap(), &intent);
    let state = DeviceState::pin(f.anchor.clone()).unwrap();
    let challenge = make_challenge(&state, &intent, 1001, &f.root).unwrap();
    let task = store
        .seal_proof(&task, &state, &challenge, 1002, &f.second)
        .unwrap();
    let proof = task.proof().unwrap().clone();
    drop(store);
    let mut store = f.join();
    let task = store.get(&id, &f.second).unwrap();
    assert_eq!(task.proof().unwrap(), &proof);
    assert_eq!(task.challenge().unwrap(), &challenge);
    assert!(store.prepare_join("replacement", &f.second).is_err());
    let view = serde_json::to_string(&task.view()).unwrap();
    assert!(!view.contains(&credential));
    assert!(!view.contains("request_token"));
    let disk = std::fs::read(&f.path).unwrap();
    for text in [
        credential.as_str(),
        "private-test-password",
        "new-password-input",
    ] {
        assert!(!disk.windows(text.len()).any(|v| v == text.as_bytes()));
    }
}
#[test]
fn root_jobs_keep_original_signature_across_conflict_restart_and_confirmed_receipt() {
    let f = Fixture::new();
    let mut join = f.join();
    let (_, initial, status) = f.proof(&mut join);
    let mut root = f.root();
    let challenge = root
        .prepare_challenge(&initial, status.intent.as_ref().unwrap(), 1001, &f.root)
        .unwrap();
    let signed = challenge.challenge().unwrap().clone();
    let id = challenge.view().id;
    drop(root);
    let mut root = f.root();
    let challenge = root.get(&id, &f.root).unwrap();
    let mut ack = status.clone();
    ack.phase = JoinPhase::Challenged;
    ack.challenge = Some(signed.clone());
    let completed = root.confirm_challenge(&challenge, &ack, &f.root).unwrap();
    assert_eq!(completed.view().phase, TaskPhase::Complete);
    let grant = root
        .prepare_grant(&initial, &status, 1003, &f.root)
        .unwrap();
    let original = grant.event().unwrap().clone();
    let id = grant.view().id;
    let conflict = root.mark_conflict(&grant, &f.root).unwrap();
    assert_eq!(conflict.event().unwrap(), &original);
    drop(root);
    let mut root = f.root();
    let conflict = root.get(&id, &f.root).unwrap();
    assert_eq!(conflict.event().unwrap(), &original);
    assert!(root.confirm_event_accepted(&conflict, &f.root).is_err()); // A server status alone is not evidence.
    let joined = root
        .trust()
        .import_verified(
            &f.anchor,
            &Checkpoint::from_state(&initial),
            std::slice::from_ref(&original),
        )
        .unwrap();
    let complete = root.confirm_event_accepted(&conflict, &f.root).unwrap();
    assert_eq!(complete.view().phase, TaskPhase::Complete);
    let revoke = root.prepare_revoke(&joined, 2000, &f.root).unwrap();
    let event = revoke.event().unwrap().clone();
    let id = revoke.view().id;
    drop(root);
    let mut root = f.root();
    let revoke = root.get(&id, &f.root).unwrap();
    assert_eq!(revoke.event().unwrap(), &event);
    let cancel = root.request_cancel(&revoke, &f.root).unwrap();
    let cancelled = root
        .confirm_event_cancel(
            &cancel,
            &DeviceCancelResult {
                cancelled: true,
                receipt: None,
            },
            &f.root,
        )
        .unwrap();
    assert_eq!(cancelled.view().phase, TaskPhase::Cancelled);
    assert!(root.confirm_event_accepted(&revoke, &f.root).is_err()); // Old callback cannot overwrite cancellation.
}
#[test]
fn join_success_requires_verified_root_grant_and_terminal_state_erases_credential() {
    let f = Fixture::new();
    let mut join = f.join();
    let (task, initial, status) = f.proof(&mut join);
    let mut root = f.root();
    let grant = root
        .prepare_grant(&initial, &status, 1003, &f.root)
        .unwrap();
    let event = grant.event().unwrap();
    assert!(join
        .confirm_join_authorized(&task, &event.id, &f.second)
        .is_err());
    join.trust()
        .import_verified(
            &f.anchor,
            &Checkpoint::from_state(&initial),
            std::slice::from_ref(event),
        )
        .unwrap();
    let complete = join
        .confirm_join_authorized(&task, &event.id, &f.second)
        .unwrap();
    assert_eq!(complete.view().phase, TaskPhase::Complete);
    assert!(complete.join_credential().is_err());
    let id = complete.view().id;
    drop(join);
    assert!(f
        .join()
        .get(&id, &f.second)
        .unwrap()
        .join_credential()
        .is_err());
}
#[test]
fn identity_server_scope_row_transplants_tampering_and_mismatched_secret_keys_reject() {
    let f = Fixture::new();
    let mut store = f.join();
    let task = store.prepare_join("second", &f.second).unwrap();
    let id = task.view().id;
    let other = crypto::generate_keypair().unwrap();
    assert!(store.get(&id, &other).is_err());
    let owner = TaskOwner::for_join(
        "https://other.example",
        "isolated-user",
        &uuid::Uuid::new_v4().to_string(),
        &f.second,
    )
    .unwrap();
    let mut foreign = DeviceTaskStore::open(&f.path, owner, &f.second).unwrap();
    assert!(foreign.get(&id, &f.second).is_err());
    let foreign_task = foreign.prepare_join("second", &f.second).unwrap();
    let transplanted = Connection::open(&f.path).unwrap();
    transplanted.execute("UPDATE device_control_tasks SET id=?1,body=(SELECT body FROM device_control_tasks WHERE id=?1) WHERE id=?2",
        params![id,foreign_task.view().id]).unwrap();
    assert!(foreign.get(&id, &f.second).is_err()); // Valid ciphertext cannot be moved to a new owner scope.
    let false_keys = KeyPair {
        public_key: f.second.public_key,
        secret_key: other.secret_key,
        ed25519_pk: f.second.ed25519_pk,
        ed25519_sk: f.second.ed25519_sk,
    };
    assert!(DeviceTaskStore::open(&f.path, f.join_owner.clone(), &false_keys).is_err());
    let conn = Connection::open(&f.path).unwrap();
    let mut body: Vec<u8> = conn
        .query_row("SELECT body FROM device_control_tasks", [], |r| r.get(0))
        .unwrap();
    body[24] ^= 1;
    conn.execute("UPDATE device_control_tasks SET body=?1", params![body])
        .unwrap();
    assert!(store.get(&id, &f.second).is_err());
}
#[test]
fn cancel_races_stale_confirmation_and_invalidated_leases_cannot_commit_late_results() {
    let f = Fixture::new();
    let mut store = f.join();
    let draft = store.prepare_join("second", &f.second).unwrap();
    let status = f.ticket(draft.view().id);
    let awaiting = store.accept_ticket(&draft, &status, &f.second).unwrap();
    let cancel = store.request_cancel(&awaiting, &f.second).unwrap();
    assert!(store
        .confirm_root(
            &awaiting,
            &f.anchor,
            &anchor_fingerprint(&f.anchor),
            &f.second
        )
        .is_err());
    let conn = Connection::open(&f.path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM trusted_device_anchors", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    let gate = TaskGate::new().unwrap();
    let lease = gate.lease().unwrap();
    gate.invalidate().unwrap();
    gate.unlock().unwrap();
    let mut cancelled = status;
    cancelled.phase = JoinPhase::Cancelled;
    assert!(gate
        .with_current(&lease, || store
            .confirm_join_cancel(&cancel, &cancelled, &f.second))
        .is_err());
    assert_eq!(
        store
            .get(&cancel.view().id, &f.second)
            .unwrap()
            .view()
            .phase,
        TaskPhase::Cancelling
    );
    let current = gate.lease().unwrap();
    let finished = gate
        .with_current(&current, || {
            store.confirm_join_cancel(&cancel, &cancelled, &f.second)
        })
        .unwrap();
    assert_eq!(finished.view().phase, TaskPhase::Cancelled);
    assert!(finished.join_credential().is_err());
    assert!(TaskGate::new()
        .unwrap()
        .with_current(&current, || Ok(()))
        .is_err());
}
#[test]
fn storage_failure_and_competing_preparations_leave_the_original_task_intact() {
    let f = Fixture::new();
    let mut a = f.join();
    let mut b = f.join();
    let first = a.prepare_join("second", &f.second).unwrap();
    assert!(b.prepare_join("second", &f.second).is_err());
    let id = first.view().id;
    let credential = first.join_credential().unwrap().to_string();
    let conn = Connection::open(&f.path).unwrap();
    conn.execute_batch("CREATE TRIGGER deny_device_task_updates BEFORE UPDATE ON device_control_tasks BEGIN SELECT RAISE(ABORT,'fixture disk failure'); END;").unwrap();
    assert!(a.request_cancel(&first, &f.second).is_err());
    assert_eq!(
        a.get(&id, &f.second).unwrap().join_credential().unwrap(),
        credential
    );
    assert_eq!(
        a.get(&id, &f.second).unwrap().view().phase,
        TaskPhase::Draft
    );
}

#[cfg(windows)]
#[test]
fn task_owner_and_original_request_reconstruct_from_isolated_dpapi_identity() {
    use liteseal_core::keystore::{load_keypair_from, save_keypair_to, KeystoreData};
    let f = Fixture::new();
    let mut store = f.join();
    let task = store.prepare_join("second", &f.second).unwrap();
    let id = task.view().id;
    let credential = task.join_credential().unwrap().to_string();
    let path = f.path.with_extension("bin");
    save_keypair_to(
        &path,
        KeystoreData {
            user_id: "pending:isolated-user".into(),
            token: String::new(),
            refresh_token: String::new(),
            device_id: f.local_device.clone(),
            server_url: f.anchor.origin.clone(),
            public_key: f.second.public_key.to_vec(),
            secret_key: f.second.secret_key.to_vec(),
            ed25519_pk: f.second.ed25519_pk.to_vec(),
            ed25519_sk: f.second.ed25519_sk.to_vec(),
        },
    )
    .unwrap();
    drop(store);
    let saved = load_keypair_from(&path).unwrap();
    assert!(saved.token.is_empty());
    assert!(saved.refresh_token.is_empty());
    let keys = KeyPair {
        public_key: saved.public_key.try_into().unwrap(),
        secret_key: saved.secret_key.try_into().unwrap(),
        ed25519_pk: saved.ed25519_pk.try_into().unwrap(),
        ed25519_sk: saved.ed25519_sk.try_into().unwrap(),
    };
    let owner = TaskOwner::for_join(
        &saved.server_url,
        saved.user_id.strip_prefix("pending:").unwrap(),
        &saved.device_id,
        &keys,
    )
    .unwrap();
    let mut store = DeviceTaskStore::open(&f.path, owner, &keys).unwrap();
    let restored = store.get(&id, &keys).unwrap();
    assert_eq!(restored.join_credential().unwrap(), credential);
    assert_eq!(
        restored.start_request("fresh-input").unwrap().request_id,
        id
    );
    let protected = std::fs::read(path).unwrap();
    assert!(!protected.windows(32).any(|part| part == keys.secret_key));
}
