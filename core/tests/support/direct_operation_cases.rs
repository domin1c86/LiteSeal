use super::*;
use liteseal_shared::direct_operation::{self as op, Action, Event, Operation, Page};
#[test]
fn operation_task_reopens_original_bytes_preserves_conflict_and_never_grants_replica_edit_rights() {
    use liteseal_core::trusted_devices::messages::operations::PrepareOperation;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "sender", &a, false, &p);
    seed(&mut store, &[&a, &b]);
    let target = uuid::Uuid::new_v4().to_string();
    prepare(&mut store, "bob", &target, b"root task", &a.root);
    store.begin_publish(&target, 0, &a.root).unwrap();
    let original = store.original(&target, &a.root).unwrap();
    store
        .confirm_accepted(&accepted(&original), &a.root)
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let request = || PrepareOperation {
        id: &id,
        target: &target,
        created_at: 3000,
        action: Action::Edit,
        text: Some("原操作 编辑 🦭"),
    };
    let prepared = store.prepare_operation(request(), &a.root).unwrap();
    assert_eq!(prepared.revision, 0);
    assert_eq!(prepared.state, TaskState::Prepared);
    let wire = store
        .operation_original(&id, &a.root)
        .unwrap()
        .to_wire()
        .unwrap();
    assert!(!serde_json::to_string(&prepared)
        .unwrap()
        .contains("编辑 🦭"));
    let other = uuid::Uuid::new_v4().to_string();
    assert!(store
        .prepare_operation(
            PrepareOperation {
                id: &other,
                target: &target,
                created_at: 3000,
                action: Action::Retract,
                text: None
            },
            &a.root
        )
        .is_err());
    store = open(&work.0, "sender", &a, false, &p);
    assert_eq!(
        store
            .operation_original(&id, &a.root)
            .unwrap()
            .to_wire()
            .unwrap(),
        wire
    );
    assert_eq!(
        store
            .prepare_operation(request(), &a.root)
            .unwrap()
            .revision,
        0
    );
    assert!(store.operation_task(&id, &b.root).is_err());
    assert!(store.begin_operation_publish(&id, 9, &a.root).is_err());
    let revoke = make_event(
        &b.joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: "bob-second".into(),
            grant_hash: b.joined.grant_hash().unwrap().to_vec(),
        },
        3100,
        &b.root,
    )
    .unwrap();
    store
        .trust()
        .import_verified(
            b.initial.anchor(),
            &Checkpoint::from_state(&b.joined),
            &[revoke],
        )
        .unwrap();
    let conflict = store.begin_operation_publish(&id, 0, &a.root).unwrap();
    assert_eq!(conflict.state, TaskState::Conflict);
    assert_eq!(
        store
            .operation_original(&id, &a.root)
            .unwrap()
            .to_wire()
            .unwrap(),
        wire
    );
    assert_eq!(
        store.prepare_operation(request(), &a.root).unwrap().state,
        TaskState::Conflict
    );
    let cancelled = store
        .request_operation_cancel(&id, conflict.revision, &a.root)
        .unwrap();
    assert_eq!(cancelled.state, TaskState::Cancelled);
    assert!(store.prepare_operation(request(), &a.root).is_err());
    let fresh = store
        .prepare_operation(
            PrepareOperation {
                id: &other,
                target: &target,
                created_at: 3200,
                action: Action::Edit,
                text: Some("explicit replacement"),
            },
            &a.root,
        )
        .unwrap();
    assert_eq!(fresh.operation_revision, 1);
    assert_eq!(
        store
            .operation_original(&other, &a.root)
            .unwrap()
            .payloads
            .len(),
        3
    );
    let publishing = store.begin_operation_publish(&other, 0, &a.root).unwrap();
    assert_eq!(publishing.state, TaskState::Publishing);
    let cancel = store
        .request_operation_cancel(&other, publishing.revision, &a.root)
        .unwrap();
    assert_eq!(cancel.state, TaskState::Publishing);
    assert!(cancel.cancel_requested);
    assert!(store
        .begin_operation_publish(&other, cancel.revision, &a.root)
        .is_err());
    store = open(&work.0, "sender", &a, false, &p);
    assert!(
        store
            .operation_task(&other, &a.root)
            .unwrap()
            .cancel_requested
    );
    let mut replica = open(&work.0, "replica", &a, true, &p);
    seed(&mut replica, &[&a, &b]);
    replica
        .receive(&original, &accepted(&original), &a.second)
        .unwrap();
    assert!(replica
        .prepare_operation(
            PrepareOperation {
                id: &uuid::Uuid::new_v4().to_string(),
                target: &target,
                created_at: 3200,
                action: Action::Edit,
                text: Some("not author")
            },
            &a.second
        )
        .is_err());
}
#[test]
fn operation_task_native_failure_has_no_partial_chunks_and_large_wire_remains_immutable() {
    use liteseal_core::trusted_devices::messages::operations::PrepareOperation;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let path = work.0.join("operation-tasks.db");
    let memory = std::sync::Arc::new(Memory::default());
    let owner = Owner::new(&a.initial.anchor().origin, "alice", "alice-root", &a.root).unwrap();
    let witness = liteseal_core::trusted_devices::witness::Witness::new(&path, memory.clone());
    let mut store = Store::open(&path, owner.clone(), witness.clone()).unwrap();
    seed(&mut store, &[&a, &b]);
    let target = uuid::Uuid::new_v4().to_string();
    prepare(&mut store, "bob", &target, b"root", &a.root);
    store.begin_publish(&target, 0, &a.root).unwrap();
    let batch = store.original(&target, &a.root).unwrap();
    store.confirm_accepted(&accepted(&batch), &a.root).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let text = "大".repeat(5400);
    let request = || PrepareOperation {
        id: &id,
        target: &target,
        created_at: 3000,
        action: Action::Edit,
        text: Some(&text),
    };
    {
        let mut state = memory.state.lock().unwrap();
        state.fail_at = Some(state.writes + 1);
    }
    assert!(store.prepare_operation(request(), &a.root).is_err());
    assert!(store.operation_tasks(&a.root).unwrap().is_empty());
    store.prepare_operation(request(), &a.root).unwrap();
    let wire = store
        .operation_original(&id, &a.root)
        .unwrap()
        .to_wire()
        .unwrap();
    assert!(wire.len() > 64 * 1024);
    drop(store);
    let mut store = Store::open(&path, owner, witness).unwrap();
    assert_eq!(
        store
            .operation_original(&id, &a.root)
            .unwrap()
            .to_wire()
            .unwrap(),
        wire
    );
    assert_eq!(
        store
            .prepare_operation(request(), &a.root)
            .unwrap()
            .revision,
        0
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE device_control_tasks SET body=zeroblob(length(body)) WHERE id=?1",
        [format!("{id}:00")],
    )
    .unwrap();
    drop(conn);
    assert!(store.operation_task(&id, &a.root).is_err());
}
fn batch(a: &Account, b: &Account) -> Batch {
    let h = Header::new(
        &a.joined,
        &b.joined,
        "alice-root",
        MessageSpec {
            id: uuid::Uuid::new_v4().to_string(),
            sequence: 1,
            previous: vec![],
            sent_at: 2000,
            kind: Kind::Text,
        },
    )
    .unwrap();
    Batch::make(
        h,
        &a.joined,
        &b.joined,
        &a.root,
        "原消息 中文 🦭".as_bytes(),
    )
    .unwrap()
}
fn event(
    a: &Account,
    b: &Account,
    batch: &Batch,
    base: u64,
    action: Action,
    text: Option<&str>,
    order: i64,
) -> Event {
    Event {
        order,
        accepted_at: 2100 + order,
        operation: Operation::make(
            batch.clone(),
            (&a.joined, &b.joined),
            (&a.joined, &b.joined),
            &a.root,
            op::Header {
                version: 1,
                id: uuid::Uuid::new_v4().to_string(),
                original: batch.digest().unwrap(),
                action,
                base,
                revision: base + 1,
                created_at: 2100,
            },
            text,
        )
        .unwrap(),
    }
}
fn page(events: Vec<Event>, through: i64) -> Page {
    Page {
        events,
        through,
        has_more: false,
    }
}
#[test]
fn operation_only_backup_refuses_before_original_history_arrives() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "recipient", &b, false, &p);
    seed(&mut store, &[&a, &b]);
    let root = batch(&a, &b);
    let edit = event(&a, &b, &root, 0, Action::Edit, Some("keep operation"), 1);
    store
        .import_operations(0, &page(vec![edit], 1), &b.root)
        .unwrap();
    assert!(store.history(None, 100, &b.root).unwrap().is_empty());
    let identity = liteseal_core::keystore::KeystoreData {
        user_id: "bob".into(),
        device_id: "bob-root".into(),
        server_url: b.initial.anchor().origin.clone(),
        token: "synthetic-excluded".into(),
        refresh_token: String::new(),
        public_key: b.root.public_key.to_vec(),
        secret_key: b.root.secret_key.to_vec(),
        ed25519_pk: b.root.ed25519_pk.to_vec(),
        ed25519_sk: b.root.ed25519_sk.to_vec(),
    };
    let output = work.0.join("operation-must-not-be-omitted.lseal");
    let error = liteseal_core::backup::export(
        &work.0.join("recipient.db"),
        identity,
        b"independent backup password",
        false,
        &output,
        &std::sync::atomic::AtomicBool::new(false),
        |_, _| {},
    )
    .err()
    .unwrap();
    assert!(error.contains("v3 操作日志"));
    assert!(!output.exists());
    assert_eq!(store.operation_cursor(&b.root).unwrap(), 1);
}
#[test]
fn revoked_device_keeps_authenticated_offline_projection_but_cannot_advance_cursor() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "secondary", &b, true, &p);
    seed(&mut store, &[&a, &b]);
    let root = batch(&a, &b);
    store.receive(&root, &accepted(&root), &b.second).unwrap();
    let edit = event(
        &a,
        &b,
        &root,
        0,
        Action::Edit,
        Some("already downloaded"),
        1,
    );
    store
        .import_operations(0, &page(vec![edit], 1), &b.second)
        .unwrap();
    let revoke = make_event(
        &b.joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: "bob-second".into(),
            grant_hash: b.joined.grant_hash().unwrap().to_vec(),
        },
        3000,
        &b.root,
    )
    .unwrap();
    store
        .trust()
        .import_verified(
            b.initial.anchor(),
            &Checkpoint::from_state(&b.joined),
            &[revoke],
        )
        .unwrap();
    assert_eq!(
        store.body(&root.header.id, &b.second).unwrap(),
        b"already downloaded"
    );
    assert_eq!(
        store.history(None, 100, &b.second).unwrap()[0].operation_revision,
        1
    );
    assert!(store.operation_cursor(&b.second).is_err());
    assert!(store
        .import_operations(1, &page(vec![], 1), &b.second)
        .is_err());
}
#[test]
fn operation_before_root_reopens_projects_edit_without_new_unread_and_preserves_hidden() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "recipient", &b, false, &p);
    seed(&mut store, &[&a, &b]);
    let root = batch(&a, &b);
    let edit = event(&a, &b, &root, 0, Action::Edit, Some("编辑后 中文 🦭"), 7);
    assert_eq!(
        store
            .import_operations(0, &page(vec![edit.clone()], 7), &b.root)
            .unwrap(),
        7
    );
    assert!(store.history(None, 100, &b.root).unwrap().is_empty());
    store = open(&work.0, "recipient", &b, false, &p);
    assert_eq!(store.operation_cursor(&b.root).unwrap(), 7);
    store.receive(&root, &accepted(&root), &b.root).unwrap();
    assert_eq!(
        store.body(&root.header.id, &b.root).unwrap(),
        "编辑后 中文 🦭".as_bytes()
    );
    let rows = store.history(None, 100, &b.root).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].operation_revision, 1);
    assert!(!rows[0].retracted);
    assert_eq!(store.conversations(&b.root).unwrap()[0].unread, 1);
    store.hide(&root.header.id, &b.root).unwrap();
    let changed = event(&a, &b, &root, 1, Action::Edit, Some("不能重新显示"), 11);
    store
        .import_operations(7, &page(vec![changed], 11), &b.root)
        .unwrap();
    assert!(store.body(&root.header.id, &b.root).is_err());
    assert!(store.claim_notifications(&b.root).unwrap().is_empty());
    assert!(store.history(None, 100, &b.root).unwrap().is_empty());
    assert!(store
        .import_operations(0, &page(vec![edit], 7), &b.root)
        .is_err());
    assert_eq!(store.operation_cursor(&b.root).unwrap(), 11);
    let mut secondary = open(&work.0, "secondary", &b, true, &p);
    seed(&mut secondary, &[&a, &b]);
    assert_eq!(secondary.operation_cursor(&b.second).unwrap(), 0);
    assert!(store.operation_cursor(&b.second).is_err());
    let bytes = fs::read(work.0.join("recipient.db")).unwrap();
    assert!(!bytes
        .windows("编辑后 中文 🦭".len())
        .any(|v| v == "编辑后 中文 🦭".as_bytes()));
}
#[test]
fn bad_page_rolls_back_whole_log_cursor_gap_and_retraction_are_terminal() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "recipient", &b, false, &p);
    seed(&mut store, &[&a, &b]);
    let root = batch(&a, &b);
    store.receive(&root, &accepted(&root), &b.root).unwrap();
    let edit = event(&a, &b, &root, 0, Action::Edit, Some("valid first"), 3);
    let mut bad = event(&a, &b, &root, 1, Action::Edit, Some("bad second"), 4);
    bad.operation.signature[0] ^= 1;
    assert!(store
        .import_operations(0, &page(vec![edit.clone(), bad], 4), &b.root)
        .is_err());
    assert_eq!(store.operation_cursor(&b.root).unwrap(), 0);
    assert_eq!(
        store.body(&root.header.id, &b.root).unwrap(),
        "原消息 中文 🦭".as_bytes()
    );
    let gap = event(&a, &b, &root, 1, Action::Edit, Some("missing first"), 4);
    assert!(store
        .import_operations(0, &page(vec![gap], 4), &b.root)
        .is_err());
    let mut wrong = page(vec![edit.clone()], 10);
    assert!(store.import_operations(0, &wrong, &b.root).is_err());
    wrong.through = 3;
    wrong.events.push(edit.clone());
    assert!(store.import_operations(0, &wrong, &b.root).is_err());
    let retract = event(&a, &b, &root, 1, Action::Retract, None, 8);
    store
        .import_operations(0, &page(vec![edit, retract], 8), &b.root)
        .unwrap();
    let rows = store.history(None, 100, &b.root).unwrap();
    assert!(rows[0].retracted);
    assert_eq!(rows[0].outcome, "retracted");
    assert_eq!(rows[0].operation_revision, 2);
    assert!(store.body(&root.header.id, &b.root).is_err());
    let late = event(&a, &b, &root, 2, Action::Edit, Some("after retract"), 9);
    assert!(store
        .import_operations(8, &page(vec![late], 9), &b.root)
        .is_err());
    assert_eq!(store.operation_cursor(&b.root).unwrap(), 8);
    assert!(store
        .import_operations(
            8,
            &Page {
                events: vec![],
                through: 8,
                has_more: true
            },
            &b.root
        )
        .is_err());
    assert_eq!(
        store
            .import_operations(8, &page(vec![], 8), &b.root)
            .unwrap(),
        8
    );
}
#[test]
fn large_operation_chunks_native_failure_and_sqlite_rollback_fail_closed() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let path = work.0.join("operations.db");
    let memory = std::sync::Arc::new(Memory::default());
    let owner = Owner::new(&b.initial.anchor().origin, "bob", "bob-root", &b.root).unwrap();
    let witness = liteseal_core::trusted_devices::witness::Witness::new(&path, memory.clone());
    let mut store = Store::open(&path, owner.clone(), witness.clone()).unwrap();
    seed(&mut store, &[&a, &b]);
    let root = batch(&a, &b);
    store.receive(&root, &accepted(&root), &b.root).unwrap();
    let old = fs::read(&path).unwrap();
    let text = "大".repeat(5400);
    let edit = event(&a, &b, &root, 0, Action::Edit, Some(&text), 1);
    assert!(edit.operation.to_wire().unwrap().len() > 64 * 1024);
    {
        let mut state = memory.state.lock().unwrap();
        state.fail_at = Some(state.writes + 1);
    }
    assert!(store
        .import_operations(0, &page(vec![edit.clone()], 1), &b.root)
        .is_err());
    assert_eq!(store.operation_cursor(&b.root).unwrap(), 0);
    store
        .import_operations(0, &page(vec![edit], 1), &b.root)
        .unwrap();
    drop(store);
    let mut reopened = Store::open(&path, owner.clone(), witness.clone()).unwrap();
    assert_eq!(
        reopened.body(&root.header.id, &b.root).unwrap(),
        text.as_bytes()
    );
    drop(reopened);
    fs::write(&path, old).unwrap();
    assert!(Store::open(&path, owner, witness).is_err());
}

#[test]
fn operation_window_boundary_terminal_cleanup_and_original_id_fences_survive_reopen() {
    use liteseal_core::trusted_devices::messages::operations::PrepareOperation;
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "author-window", &a, false, &p);
    seed(&mut store, &[&a, &b]);
    let target = uuid::Uuid::new_v4().to_string();
    prepare(&mut store, "bob", &target, b"window", &a.root);
    store.begin_publish(&target, 0, &a.root).unwrap();
    let root = store.original(&target, &a.root).unwrap();
    let receipt = accepted(&root);
    store.confirm_accepted(&receipt, &a.root).unwrap();
    let first = store.history(None, 6, &a.root).unwrap()[0].accepted_at;
    for created_at in [first - 1, first + 48 * 60 * 60 * 1000 + 1] {
        assert!(store
            .prepare_operation(
                PrepareOperation {
                    id: &uuid::Uuid::new_v4().to_string(),
                    target: &target,
                    created_at,
                    action: Action::Edit,
                    text: Some("invalid time")
                },
                &a.root
            )
            .is_err());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let request = || PrepareOperation {
        id: &id,
        target: &target,
        created_at: first + 48 * 60 * 60 * 1000,
        action: Action::Edit,
        text: Some("exact boundary"),
    };
    let task = store.prepare_operation(request(), &a.root).unwrap();
    assert!(store
        .clear_operation_task(&id, task.revision, &a.root)
        .is_err());
    let publishing = store
        .begin_operation_publish(&id, task.revision, &a.root)
        .unwrap();
    assert_eq!(
        store
            .begin_operation_publish(&id, publishing.revision, &a.root)
            .unwrap()
            .revision,
        publishing.revision
    );
    assert!(store
        .request_operation_cancel(&id, publishing.revision + 1, &a.root)
        .is_err());
    let local_id = uuid::Uuid::new_v4().to_string();
    let local_target = uuid::Uuid::new_v4().to_string();
    prepare(&mut store, "bob", &local_target, b"local cancel", &a.root);
    store.begin_publish(&local_target, 0, &a.root).unwrap();
    let original = store.original(&local_target, &a.root).unwrap();
    store
        .confirm_accepted(&accepted(&original), &a.root)
        .unwrap();
    let local = store
        .prepare_operation(
            PrepareOperation {
                id: &local_id,
                target: &local_target,
                created_at: 3000,
                action: Action::Retract,
                text: None,
            },
            &a.root,
        )
        .unwrap();
    let cancelled = store
        .request_operation_cancel(&local_id, local.revision, &a.root)
        .unwrap();
    store
        .clear_operation_task(&local_id, cancelled.revision, &a.root)
        .unwrap();
    store = open(&work.0, "author-window", &a, false, &p);
    assert!(store
        .prepare_operation(
            PrepareOperation {
                id: &local_id,
                target: &local_target,
                created_at: 3000,
                action: Action::Retract,
                text: None
            },
            &a.root
        )
        .is_err());
    assert_eq!(store.operation_tasks(&a.root).unwrap().len(), 1);
    assert_eq!(store.body(&local_target, &a.root).unwrap(), b"local cancel");
}
