#![cfg(windows)]
use liteseal_core::{
    backup::WorkDirectory,
    trusted_devices::{
        messages::{Acceptance, Owner, Prepare, Store, TaskState},
        witness::platform::Protection,
        Checkpoint,
    },
};
use liteseal_shared::{
    crypto::{self, KeyPair},
    direct_message::{Batch, Header, Kind, MessageSpec},
    protocol::AckOutcome,
    trusted_device::*,
};
use std::{fs, path::Path};
struct Account {
    root: KeyPair,
    second: KeyPair,
    initial: DeviceState,
    joined: DeviceState,
    event: DeviceEvent,
}
impl Account {
    fn new(name: &str) -> Self {
        let root = crypto::generate_keypair().unwrap();
        let second = crypto::generate_keypair().unwrap();
        let initial = DeviceState::pin(Anchor {
            origin: "https://synthetic.example".into(),
            account: name.into(),
            root: DeviceIdentity::from_keys(format!("{name}-root"), &root),
        })
        .unwrap();
        let intent = make_intent(
            initial.anchor(),
            format!("{name}-join"),
            format!("{name}-second"),
            crypto::random_challenge().unwrap(),
            1000,
            &second,
        )
        .unwrap();
        let challenge = make_challenge(&initial, &intent, 1001, &root).unwrap();
        let proof = answer_challenge(&initial, &intent, &challenge, 1002, &second).unwrap();
        let event = make_event(
            &initial,
            format!("{name}-grant"),
            DeviceAction::Grant {
                intent: Box::new(intent),
                challenge: Box::new(challenge),
                proof,
            },
            1003,
            &root,
        )
        .unwrap();
        let joined = initial.apply(&event).unwrap();
        Self {
            root,
            second,
            initial,
            joined,
            event,
        }
    }
}
fn open(
    work: &Path,
    name: &str,
    account: &Account,
    secondary: bool,
    protection: &Protection,
) -> Store {
    let (device, keys) = if secondary {
        (
            &account.joined.secondary().unwrap().device_id,
            &account.second,
        )
    } else {
        (&account.initial.anchor().root.device_id, &account.root)
    };
    let path = work.join(format!("{name}.db"));
    let trust = liteseal_core::trusted_devices::DeviceTrustStore::open(&path).unwrap();
    drop(trust);
    Store::open(
        &path,
        Owner::new(
            &account.initial.anchor().origin,
            &account.initial.anchor().account,
            device,
            keys,
        )
        .unwrap(),
        protection.witness(&path).unwrap(),
    )
    .unwrap()
}
fn seed(store: &mut Store, accounts: &[&Account]) {
    for account in accounts {
        let initial = store.trust().pin(account.initial.anchor()).unwrap();
        if initial.revision() == 0 {
            store
                .trust()
                .import_verified(
                    account.initial.anchor(),
                    &Checkpoint::from_state(&initial),
                    std::slice::from_ref(&account.event),
                )
                .unwrap();
        }
    }
}
fn prepare(store: &mut Store, peer: &str, id: &str, text: &[u8], keys: &KeyPair) {
    store
        .prepare(
            Prepare {
                id,
                peer,
                sent_at: 2000,
                kind: Kind::Text,
                body: text,
            },
            keys,
        )
        .unwrap();
}
fn accepted(batch: &Batch) -> Acceptance {
    Acceptance::from_authenticated_response(batch, &batch.header.id, batch.digest().unwrap(), 2100)
        .unwrap()
}

#[test]
fn original_task_reopen_unknown_result_and_explicit_cancel_do_not_reencrypt_or_skip_chain() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "alice", &a, false, &protection);
    seed(&mut store, &[&a, &b]);
    let id = uuid::Uuid::new_v4().to_string();
    prepare(&mut store, "bob", &id, "中文 🦭".as_bytes(), &a.root);
    let original = store.original(&id, &a.root).unwrap().to_wire().unwrap();
    prepare(&mut store, "bob", &id, "中文 🦭".as_bytes(), &a.root);
    assert_eq!(
        store.original(&id, &a.root).unwrap().to_wire().unwrap(),
        original
    );
    assert!(store
        .prepare(
            Prepare {
                id: &id,
                peer: "bob",
                sent_at: 2000,
                kind: Kind::Text,
                body: b"different"
            },
            &a.root
        )
        .is_err());
    let task = store.begin_publish(&id, 0, &a.root).unwrap();
    assert_eq!(task.state, TaskState::Publishing);
    assert!(store
        .cancel_unpublished(&id, task.revision, &a.root)
        .is_err());
    drop(store);
    let mut store = open(&work.0, "alice", &a, false, &protection);
    assert_eq!(
        store.original(&id, &a.root).unwrap().to_wire().unwrap(),
        original
    );
    let batch = store.original(&id, &a.root).unwrap();
    let digest = batch.digest().unwrap();
    store.confirm_unaccepted(&id, digest, &a.root).unwrap();
    let task = store.tasks(&a.root).unwrap().remove(0);
    store
        .cancel_unpublished(&id, task.revision, &a.root)
        .unwrap();
    let next = uuid::Uuid::new_v4().to_string();
    prepare(&mut store, "bob", &next, b"next", &a.root);
    assert_eq!(store.original(&next, &a.root).unwrap().header.sequence, 1);
}

#[test]
fn four_isolated_stores_commit_complete_audience_independent_ack_and_own_replica() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut sender = open(&work.0, "sender", &a, false, &protection);
    seed(&mut sender, &[&a, &b]);
    let id = uuid::Uuid::new_v4().to_string();
    prepare(&mut sender, "bob", &id, "中文 🦭 saved".as_bytes(), &a.root);
    sender.begin_publish(&id, 0, &a.root).unwrap();
    let batch = sender.original(&id, &a.root).unwrap();
    sender.confirm_accepted(&accepted(&batch), &a.root).unwrap();
    sender.confirm_accepted(&accepted(&batch), &a.root).unwrap();
    assert_eq!(sender.history(None, 100, &a.root).unwrap().len(), 1);
    assert_eq!(
        sender.body(&id, &a.root).unwrap(),
        "中文 🦭 saved".as_bytes()
    );
    sender.clear_accepted_task(&id, &a.root).unwrap();
    assert!(sender.tasks(&a.root).unwrap().is_empty());
    assert!(sender
        .prepare(
            Prepare {
                id: &id,
                peer: "bob",
                sent_at: 2000,
                kind: Kind::Text,
                body: "中文 🦭 saved".as_bytes()
            },
            &a.root
        )
        .is_err());
    for (name, account, secondary, keys, role) in [
        ("own", &a, true, &a.second, "own_replica"),
        ("peer-root", &b, false, &b.root, "incoming"),
        ("peer-second", &b, true, &b.second, "incoming"),
    ] {
        let mut receiver = open(&work.0, name, account, secondary, &protection);
        seed(&mut receiver, &[&a, &b]);
        assert_eq!(
            receiver.receive(&batch, &accepted(&batch), keys).unwrap(),
            AckOutcome::Processed
        );
        assert_eq!(
            receiver.receive(&batch, &accepted(&batch), keys).unwrap(),
            AckOutcome::Processed
        );
        assert_eq!(
            receiver.body(&id, keys).unwrap(),
            "中文 🦭 saved".as_bytes()
        );
        assert_eq!(receiver.history(None, 100, keys).unwrap()[0].role, role);
        assert_eq!(
            receiver.history(None, 100, keys).unwrap()[0].peer,
            if role == "incoming" { "alice" } else { "bob" }
        );
        drop(receiver);
        let mut receiver = open(&work.0, name, account, secondary, &protection);
        let ack = receiver.pending_acks(keys).unwrap().remove(0);
        let wire = ack.to_wire().unwrap();
        drop(receiver);
        let mut receiver = open(&work.0, name, account, secondary, &protection);
        assert_eq!(
            receiver.pending_acks(keys).unwrap()[0].to_wire().unwrap(),
            wire
        );
        receiver.confirm_ack(&ack, keys).unwrap();
        receiver.confirm_ack(&ack, keys).unwrap();
        assert!(receiver.pending_acks(keys).unwrap().is_empty());
        receiver.hide(&id, keys).unwrap();
        receiver.receive(&batch, &accepted(&batch), keys).unwrap();
        assert!(receiver.history(None, 100, keys).unwrap().is_empty());
        assert!(receiver.body(&id, keys).is_err());
        assert_eq!(
            receiver.pending_acks(keys).unwrap()[0].to_wire().unwrap(),
            wire
        );
    }
}

#[derive(Default)]
struct Memory {
    state: std::sync::Mutex<MemoryState>,
}
#[derive(Default)]
struct MemoryState {
    bytes: Option<Vec<u8>>,
    writes: usize,
    fail_at: Option<usize>,
}
struct Slot<'a>(std::sync::MutexGuard<'a, MemoryState>);
impl liteseal_core::trusted_devices::witness::SecureCell for Slot<'_> {
    fn read(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.bytes.clone())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0.writes += 1;
        if self.0.fail_at == Some(self.0.writes) {
            self.0.fail_at = None;
            return Err("synthetic secure-store failure".into());
        }
        self.0.bytes = Some(bytes.to_vec());
        Ok(())
    }
}
impl liteseal_core::trusted_devices::witness::SecureStore for Memory {
    fn binding(&self) -> [u8; 32] {
        [5; 32]
    }
    fn lock(
        &self,
    ) -> Result<Box<dyn liteseal_core::trusted_devices::witness::SecureCell + '_>, String> {
        Ok(Box::new(Slot(self.state.lock().unwrap())))
    }
}
#[test]
fn secure_commit_failures_never_expose_partial_body_head_or_ack_and_same_handle_recovers() {
    use liteseal_core::trusted_devices::{witness::Witness, DeviceTrustStore};
    use std::sync::Arc;
    for after in [false, true] {
        let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
        let path = work.0.join("atomic.db");
        let a = Account::new("alice");
        let b = Account::new("bob");
        let backend = Arc::new(Memory::default());
        drop(DeviceTrustStore::open(&path).unwrap());
        let mut receiver = Store::open(
            &path,
            Owner::new(
                &b.initial.anchor().origin,
                "bob",
                &b.initial.anchor().root.device_id,
                &b.root,
            )
            .unwrap(),
            Witness::new(&path, backend.clone()),
        )
        .unwrap();
        seed(&mut receiver, &[&a, &b]);
        let header = Header::new(
            &a.joined,
            &b.joined,
            &a.initial.anchor().root.device_id,
            MessageSpec {
                id: uuid::Uuid::new_v4().to_string(),
                sequence: 1,
                previous: vec![],
                sent_at: 2000,
                kind: Kind::Text,
            },
        )
        .unwrap();
        let batch = Batch::make(header, &a.joined, &b.joined, &a.root, b"atomic payload").unwrap();
        {
            let mut state = backend.state.lock().unwrap();
            state.fail_at = Some(state.writes + if after { 2 } else { 1 });
        }
        assert!(receiver
            .receive(&batch, &accepted(&batch), &b.root)
            .is_err());
        if !after {
            assert!(receiver.pending_acks(&b.root).unwrap().is_empty());
            assert!(receiver.history(None, 10, &b.root).unwrap().is_empty());
        }
        assert_eq!(
            receiver
                .receive(&batch, &accepted(&batch), &b.root)
                .unwrap(),
            AckOutcome::Processed
        );
        assert_eq!(receiver.pending_acks(&b.root).unwrap().len(), 1);
        assert_eq!(receiver.history(None, 10, &b.root).unwrap().len(), 1);
        assert_eq!(
            receiver.body(&batch.header.id, &b.root).unwrap(),
            b"atomic payload"
        );
    }
}

#[test]
fn more_than_fifty_messages_page_reopen_and_hide_without_reintroducing_card() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut receiver = open(&work.0, "receiver", &b, false, &protection);
    seed(&mut receiver, &[&a, &b]);
    let mut previous = vec![];
    let mut first = None;
    for sequence in 1..=65 {
        let header = Header::new(
            &a.joined,
            &b.joined,
            &a.initial.anchor().root.device_id,
            MessageSpec {
                id: uuid::Uuid::new_v4().to_string(),
                sequence,
                previous,
                sent_at: 2000 + sequence,
                kind: Kind::Text,
            },
        )
        .unwrap();
        let batch = Batch::make(
            header,
            &a.joined,
            &b.joined,
            &a.root,
            "分页 中文 🦭".as_bytes(),
        )
        .unwrap();
        receiver
            .receive(&batch, &accepted(&batch), &b.root)
            .unwrap();
        previous = batch.digest().unwrap().to_vec();
        if first.is_none() {
            first = Some(batch);
        }
    }
    drop(receiver);
    let mut receiver = open(&work.0, "receiver", &b, false, &protection);
    let mut before = None;
    let mut ids = vec![];
    loop {
        let page = receiver.history(before, 25, &b.root).unwrap();
        if page.is_empty() {
            break;
        }
        before = Some(page.last().unwrap().cursor);
        ids.extend(page.into_iter().map(|r| r.id));
    }
    assert_eq!(ids.len(), 65);
    assert_eq!(receiver.pending_acks(&b.root).unwrap().len(), 65);
    let first = first.unwrap();
    receiver.hide(&first.header.id, &b.root).unwrap();
    receiver
        .receive(&first, &accepted(&first), &b.root)
        .unwrap();
    assert_eq!(receiver.history(None, 100, &b.root).unwrap().len(), 64);
    assert!(receiver.body(&first.header.id, &b.root).is_err());
}

#[test]
fn backup_refuses_current_unsupported_history_without_publishing_incomplete_file() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut receiver = open(&work.0, "receiver", &b, false, &protection);
    seed(&mut receiver, &[&a, &b]);
    let header = Header::new(
        &a.joined,
        &b.joined,
        &a.initial.anchor().root.device_id,
        MessageSpec {
            id: uuid::Uuid::new_v4().to_string(),
            sequence: 1,
            previous: vec![],
            sent_at: 2000,
            kind: Kind::Text,
        },
    )
    .unwrap();
    let batch = Batch::make(header, &a.joined, &b.joined, &a.root, b"keep this history").unwrap();
    receiver
        .receive(&batch, &accepted(&batch), &b.root)
        .unwrap();
    let identity = liteseal_core::keystore::KeystoreData {
        user_id: "bob".into(),
        device_id: b.initial.anchor().root.device_id.clone(),
        server_url: b.initial.anchor().origin.clone(),
        token: "synthetic-not-exported".into(),
        refresh_token: String::new(),
        public_key: b.root.public_key.to_vec(),
        secret_key: b.root.secret_key.to_vec(),
        ed25519_pk: b.root.ed25519_pk.to_vec(),
        ed25519_sk: b.root.ed25519_sk.to_vec(),
    };
    let output = work.0.join("must-not-exist.lseal");
    let error = liteseal_core::backup::export(
        &work.0.join("receiver.db"),
        identity,
        b"independent backup password",
        false,
        &output,
        &std::sync::atomic::AtomicBool::new(false),
        |_, _| {},
    )
    .err()
    .unwrap();
    assert!(error.contains("v3 历史"));
    assert!(!output.exists());
    assert_eq!(
        receiver.body(&batch.header.id, &b.root).unwrap(),
        b"keep this history"
    );
}

#[test]
fn authenticated_bad_body_is_quarantined_and_chain_advances_but_bad_signature_never_acks() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut receiver = open(&work.0, "receiver", &b, false, &protection);
    seed(&mut receiver, &[&a, &b]);
    let header = Header::new(
        &a.joined,
        &b.joined,
        &a.initial.anchor().root.device_id,
        MessageSpec {
            id: uuid::Uuid::new_v4().to_string(),
            sequence: 1,
            previous: vec![],
            sent_at: 2000,
            kind: Kind::Text,
        },
    )
    .unwrap();
    let mut batch = Batch::make(header, &a.joined, &b.joined, &a.root, b"original").unwrap();
    batch.header.id = uuid::Uuid::new_v4().to_string();
    batch.signature = crypto::sign(&batch.signing_bytes().unwrap(), &a.root.ed25519_sk).unwrap();
    assert_eq!(
        receiver
            .receive(&batch, &accepted(&batch), &b.root)
            .unwrap(),
        AckOutcome::Rejected
    );
    assert!(receiver.body(&batch.header.id, &b.root).is_err());
    assert_eq!(
        receiver.pending_acks(&b.root).unwrap()[0].outcome,
        AckOutcome::Rejected
    );
    let mut header = batch.header.clone();
    header.id = uuid::Uuid::new_v4().to_string();
    header.sequence = 2;
    header.previous = batch.digest().unwrap().to_vec();
    let valid = Batch::make(header, &a.joined, &b.joined, &a.root, b"after rejection").unwrap();
    receiver
        .receive(&valid, &accepted(&valid), &b.root)
        .unwrap();
    let mut bad = valid.clone();
    bad.header.id = uuid::Uuid::new_v4().to_string();
    bad.signature[0] ^= 1;
    assert!(receiver.receive(&bad, &accepted(&bad), &b.root).is_err());
    assert_eq!(receiver.pending_acks(&b.root).unwrap().len(), 2);
}

#[test]
fn future_scope_and_current_revocation_reject_before_body_or_ack() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut sender = open(&work.0, "sender", &a, false, &protection);
    seed(&mut sender, &[&a, &b]);
    let id = uuid::Uuid::new_v4().to_string();
    prepare(&mut sender, "bob", &id, b"old audience", &a.root);
    let batch = sender.original(&id, &a.root).unwrap();
    let mut receiver = open(&work.0, "receiver", &b, true, &protection);
    seed(&mut receiver, &[&a, &b]);
    let revoke = make_event(
        &b.joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: b.joined.secondary().unwrap().device_id.clone(),
            grant_hash: b.joined.grant_hash().unwrap().to_vec(),
        },
        3000,
        &b.root,
    )
    .unwrap();
    receiver
        .trust()
        .import_verified(
            b.initial.anchor(),
            &Checkpoint::from_state(&b.joined),
            &[revoke],
        )
        .unwrap();
    assert!(receiver
        .receive(&batch, &accepted(&batch), &b.second)
        .is_err());
    assert!(receiver.pending_acks(&b.second).unwrap().is_empty());
    assert!(receiver.original(&id, &b.second).is_err());
    assert!(sender.original(&id, &b.root).is_err());
}

#[test]
fn rollback_after_receipt_and_plain_body_transplant_are_rejected_by_native_witness() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut sender = open(&work.0, "sender", &a, false, &protection);
    seed(&mut sender, &[&a, &b]);
    let id = uuid::Uuid::new_v4().to_string();
    prepare(
        &mut sender,
        "bob",
        &id,
        b"PRIVATE-BODY-NOT-PLAINTEXT",
        &a.root,
    );
    let batch = sender.original(&id, &a.root).unwrap();
    let mut receiver = open(&work.0, "receiver", &b, false, &protection);
    seed(&mut receiver, &[&a, &b]);
    drop(receiver);
    let path = work.0.join("receiver.db");
    let old = work.0.join("old.db");
    fs::copy(&path, &old).unwrap();
    let mut receiver = open(&work.0, "receiver", &b, false, &protection);
    receiver
        .receive(&batch, &accepted(&batch), &b.root)
        .unwrap();
    drop(receiver);
    assert!(!fs::read(&path)
        .unwrap()
        .windows(b"PRIVATE-BODY-NOT-PLAINTEXT".len())
        .any(|slice| slice == b"PRIVATE-BODY-NOT-PLAINTEXT"));
    fs::copy(&old, &path).unwrap();
    let trust = liteseal_core::trusted_devices::DeviceTrustStore::open(&path).unwrap();
    drop(trust);
    assert!(Store::open(
        &path,
        Owner::new(
            &b.initial.anchor().origin,
            "bob",
            &b.initial.anchor().root.device_id,
            &b.root
        )
        .unwrap(),
        protection.witness(&path).unwrap()
    )
    .is_err());
}

#[test]
fn historical_prefix_does_not_lower_current_directory_or_let_stale_task_resign() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let protection = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut sender = open(&work.0, "sender", &a, false, &protection);
    seed(&mut sender, &[&a, &b]);
    let id = uuid::Uuid::new_v4().to_string();
    prepare(&mut sender, "bob", &id, b"before change", &a.root);
    let wire = sender.original(&id, &a.root).unwrap().to_wire().unwrap();
    let revoke = make_event(
        &b.joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: b.joined.secondary().unwrap().device_id.clone(),
            grant_hash: b.joined.grant_hash().unwrap().to_vec(),
        },
        3000,
        &b.root,
    )
    .unwrap();
    sender
        .trust()
        .import_verified(
            b.initial.anchor(),
            &Checkpoint::from_state(&b.joined),
            &[revoke],
        )
        .unwrap();
    assert_eq!(
        sender
            .trust()
            .at_checkpoint(b.initial.anchor(), &Checkpoint::from_state(&b.joined))
            .unwrap()
            .revision(),
        1
    );
    assert_eq!(
        sender
            .trust()
            .load(b.initial.anchor(), None)
            .unwrap()
            .revision(),
        2
    );
    assert!(sender.begin_publish(&id, 0, &a.root).is_err());
    assert_eq!(
        sender.original(&id, &a.root).unwrap().to_wire().unwrap(),
        wire
    );
    assert!(sender
        .prepare(
            Prepare {
                id: &id,
                peer: "bob",
                sent_at: 2000,
                kind: Kind::Text,
                body: b"before change"
            },
            &a.root
        )
        .is_err());
    sender.cancel_unpublished(&id, 0, &a.root).unwrap();
    let next = uuid::Uuid::new_v4().to_string();
    prepare(&mut sender, "bob", &next, b"new audience", &a.root);
    assert_eq!(sender.original(&next, &a.root).unwrap().header.sequence, 1);
}
