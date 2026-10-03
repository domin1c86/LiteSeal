use super::*;
use liteseal_core::trusted_devices::messages::history_transfer::{PrepareHistory, State};
use liteseal_shared::direct_operation::{self as op, Action, Event, Operation, Page};
fn grant(store: &mut Store, account: &Account) {
    let initial = store.trust().load(account.initial.anchor(), None).unwrap();
    store
        .trust()
        .import_verified(
            account.initial.anchor(),
            &Checkpoint::from_state(&initial),
            std::slice::from_ref(&account.event),
        )
        .unwrap();
}
fn old_messages(root: &mut Store, a: &Account, b: &Account) -> Vec<String> {
    root.trust().pin(a.initial.anchor()).unwrap();
    root.trust().pin(b.initial.anchor()).unwrap();
    let mut ids = Vec::new();
    for n in 0..3 {
        let id = uuid::Uuid::new_v4().to_string();
        prepare(
            root,
            "bob",
            &id,
            format!("选定旧历史 {n} 中文 🦭").as_bytes(),
            &a.root,
        );
        root.begin_publish(&id, 0, &a.root).unwrap();
        let batch = root.original(&id, &a.root).unwrap();
        root.confirm_accepted(&accepted(&batch), &a.root).unwrap();
        ids.push(id);
    }
    grant(root, a);
    grant(root, b);
    ids
}
fn request<'a>(id: &'a str, selection: &'a [String]) -> PrepareHistory<'a> {
    PrepareHistory {
        id,
        peer: "bob",
        target: "alice-second",
        selection,
        created_at: 3000,
        include_media: false,
    }
}
#[test]
fn history_relay_intent_reopens_and_local_stop_preserves_remote_cancellation() {
    use liteseal_shared::history_transfer::{RelayState, RelayStatus};
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut root = open(&work.0, "root", &a, false, &p);
    let ids = old_messages(&mut root, &a, &b);
    let original_tasks = root.tasks(&a.root).unwrap().len();
    let id = uuid::Uuid::new_v4().to_string();
    let prepared = root.prepare_history(request(&id, &ids), &a.root).unwrap();
    assert!(root.history_relay_jobs(&a.root).unwrap().is_empty());
    let job = root
        .start_history_relay(&id, prepared.revision, false, &a.root)
        .unwrap();
    let status = RelayStatus {
        id: id.clone(),
        digest: prepared.digest,
        state: RelayState::Ready,
        next: 1,
    };
    let paused = root
        .set_history_relay_pause(&id, job.revision, true, &a.root)
        .unwrap();
    assert!(root
        .confirm_history_relay_job(&id, job.revision, &status, &a.root)
        .is_err());
    assert!(root
        .set_history_relay_pause(&id, job.revision, false, &a.root)
        .is_err());
    let resumed = root
        .set_history_relay_pause(&id, paused.revision, false, &a.root)
        .unwrap();
    root.confirm_history_relay_job(&id, resumed.revision, &status, &a.root)
        .unwrap();
    root.cancel_history_transfer(&id, prepared.revision, &a.root)
        .unwrap();
    assert!(root
        .history_relay_original(&id, prepared.revision, &a.root)
        .is_err());
    assert!(root.history_relay_jobs(&a.root).unwrap()[0].paused);
    drop(root);
    let mut root = open(&work.0, "root", &a, false, &p);
    assert!(root
        .start_history_relay(&id, prepared.revision, false, &a.root)
        .is_err());
    let cancel = root
        .start_history_relay(&id, prepared.revision, true, &a.root)
        .unwrap();
    assert!(cancel.cancel_requested && !cancel.paused);
    root.confirm_history_relay_job(
        &id,
        cancel.revision,
        &RelayStatus {
            state: RelayState::Cancelled,
            ..status
        },
        &a.root,
    )
    .unwrap();
    let terminal = root.history_relay_jobs(&a.root).unwrap().remove(0);
    assert!(!terminal.active());
    assert_eq!(terminal.id, id);
    assert_eq!(root.tasks(&a.root).unwrap().len(), original_tasks);
}
#[test]
fn abandoned_history_receive_reopens_without_redownload_and_keeps_lost_receipt_intent() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut root = open(&work.0, "root", &a, false, &p);
    let ids = old_messages(&mut root, &a, &b);
    let id = uuid::Uuid::new_v4().to_string();
    let prepared = root.prepare_history(request(&id, &ids), &a.root).unwrap();
    let wire = root
        .history_transfer_wire(&id, prepared.revision, 3001, &a.root)
        .unwrap();
    let envelope = liteseal_shared::history_transfer::Envelope::from_wire(&wire).unwrap();
    let offer = envelope.offer();
    let mut target = open(&work.0, "joined", &a, true, &p);
    seed(&mut target, &[&a, &b]);
    target.history_receive_next(&offer, &a.second).unwrap();
    target
        .history_receive_chunk(&offer, 0, envelope.ciphertext_chunk(0).unwrap(), &a.second)
        .unwrap();
    target
        .set_history_receive_pause(&id, 1, true, true, &a.second)
        .unwrap();
    assert!(target.check_history_receive(&id, 1, &a.second).is_err());
    assert!(target.history_receive_next(&offer, &a.second).is_err());
    assert_eq!(target.history_receives(&a.second).unwrap()[0].downloaded, 0);
    assert!(target
        .transferred_history(None, &a.second)
        .unwrap()
        .is_empty());
    drop(target);
    let mut target = open(&work.0, "joined", &a, true, &p);
    let view = target.history_receives(&a.second).unwrap().remove(0);
    assert!(view.abandoned && view.paused);
    target
        .set_history_receive_pause(&id, view.revision, false, false, &a.second)
        .unwrap();
    assert!(target.check_history_receive(&id, 1, &a.second).is_err());
    for part in 0..offer
        .size
        .div_ceil(liteseal_shared::history_transfer::CHUNK)
    {
        target
            .history_receive_chunk(
                &offer,
                part,
                envelope.ciphertext_chunk(part).unwrap(),
                &a.second,
            )
            .unwrap();
    }
    target
        .finish_history_receive(&offer, 3002, &a.second)
        .unwrap();
    assert_eq!(
        target.transferred_history(None, &a.second).unwrap().len(),
        3
    );
    assert_eq!(target.history_receives(&a.second).unwrap().len(), 1);
    drop(target);
    let mut target = open(&work.0, "joined", &a, true, &p);
    assert_eq!(target.history_receives(&a.second).unwrap().len(), 1);
    assert!(target.pending_acks(&a.second).unwrap().is_empty());
    assert!(target.claim_notifications(&a.second).unwrap().is_empty());
    target.clear_history_receive(&id, &a.second).unwrap();
    assert!(target.history_receives(&a.second).unwrap().is_empty());
}
#[test]
fn selected_history_reopens_under_target_keys_without_delivery_capabilities() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut root = open(&work.0, "root", &a, false, &p);
    let ids = old_messages(&mut root, &a, &b);
    root.save_draft("bob", 0, "不会迁移的草稿", &a.root)
        .unwrap();
    root.set_muted("bob", 0, true, &a.root).unwrap();
    let selected = vec![ids[2].clone(), ids[0].clone()];
    let id = uuid::Uuid::new_v4().to_string();
    let prepared = root
        .prepare_history(request(&id, &selected), &a.root)
        .unwrap();
    assert_eq!(prepared.state, State::Prepared);
    assert_eq!(prepared.selected, 2);
    let wire = root
        .history_transfer_wire(&id, prepared.revision, 3001, &a.root)
        .unwrap();
    assert_eq!(
        root.prepare_history(request(&id, &selected), &a.root)
            .unwrap()
            .digest,
        prepared.digest
    );
    assert_eq!(
        root.history_transfer_wire(&id, prepared.revision, 3002, &a.root)
            .unwrap(),
        wire
    );
    let mut joined = open(&work.0, "joined", &a, true, &p);
    seed(&mut joined, &[&a, &b]);
    let imported = joined.import_history(&wire, 3002, &a.second).unwrap();
    assert_eq!(imported.state, State::Imported);
    assert_eq!(imported.digest, prepared.digest);
    assert_eq!(
        joined
            .import_history(&wire, 3003, &a.second)
            .unwrap()
            .digest,
        prepared.digest
    );
    assert_eq!(
        joined
            .import_history(&wire, 603000, &a.second)
            .unwrap()
            .digest,
        prepared.digest
    );
    let history = joined.transferred_history(Some("bob"), &a.second).unwrap();
    assert_eq!(history.len(), 2);
    assert!(history
        .iter()
        .all(|r| r.verification == "authorized_history_transfer" && r.operation_revision == 0));
    assert!(history
        .iter()
        .any(|r| r.text.as_deref() == Some("选定旧历史 2 中文 🦭")));
    assert!(!history.iter().any(|r| r.id == ids[1]));
    assert!(joined.history(None, 100, &a.second).unwrap().is_empty());
    assert!(joined.tasks(&a.second).unwrap().is_empty());
    assert!(joined.pending_acks(&a.second).unwrap().is_empty());
    assert!(joined.claim_notifications(&a.second).unwrap().is_empty());
    assert_eq!(joined.conversations(&a.second).unwrap()[0].unread, 0);
    assert_eq!(joined.draft("bob", &a.second).unwrap().text, "");
    assert!(!joined.conversations(&a.second).unwrap()[0].muted);
    assert!(joined
        .prepare_history(
            request(&uuid::Uuid::new_v4().to_string(), &selected),
            &a.second
        )
        .is_err());
    assert!(joined.body(&ids[0], &a.second).is_err());
    drop(joined);
    let mut joined = open(&work.0, "joined", &a, true, &p);
    assert_eq!(
        joined
            .transferred_history(Some("bob"), &a.second)
            .unwrap()
            .len(),
        2
    );
    joined.hide_transferred(&ids[0], &a.second).unwrap();
    assert_eq!(
        joined
            .transferred_history(Some("bob"), &a.second)
            .unwrap()
            .len(),
        1
    );
    assert!(joined.transferred_history(None, &a.root).is_err());
    let conn = rusqlite::Connection::open(work.0.join("joined.db")).unwrap();
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM direct_v3_history_chunks LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!bytes
        .windows("选定旧历史".len())
        .any(|v| v == "选定旧历史".as_bytes()));
}
#[test]
fn transfer_rejects_scope_expiry_tampering_hidden_selection_and_revocation() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut root = open(&work.0, "root", &a, false, &p);
    let ids = old_messages(&mut root, &a, &b);
    let id = uuid::Uuid::new_v4().to_string();
    let selected = vec![ids[0].clone()];
    let view = root
        .prepare_history(request(&id, &selected), &a.root)
        .unwrap();
    let wire = root
        .history_transfer_wire(&id, view.revision, 3001, &a.root)
        .unwrap();
    assert!(root
        .history_transfer_wire(&id, view.revision, 603000, &a.root)
        .is_err());
    assert!(root.prepare_history(request(&id, &ids), &a.root).is_err());
    let mut joined = open(&work.0, "joined", &a, true, &p);
    seed(&mut joined, &[&a, &b]);
    assert!(joined.import_history(&wire, 603000, &a.second).is_err());
    let mut bad = wire.clone();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    assert!(joined.import_history(&bad, 3002, &a.second).is_err());
    assert!(joined.history_transfers(&a.second).unwrap().is_empty());
    root.hide(&ids[1], &a.root).unwrap();
    assert!(root
        .prepare_history(
            request(&uuid::Uuid::new_v4().to_string(), &[ids[1].clone()]),
            &a.root
        )
        .is_err());
    let revoked = make_event(
        &a.joined,
        "revoke".into(),
        DeviceAction::Revoke {
            device_id: "alice-second".into(),
            grant_hash: a.joined.grant_hash().unwrap().to_vec(),
        },
        4000,
        &a.root,
    )
    .unwrap();
    joined
        .trust()
        .import_verified(
            a.initial.anchor(),
            &Checkpoint::from_state(&a.joined),
            std::slice::from_ref(&revoked),
        )
        .unwrap();
    assert!(joined.import_history(&wire, 4001, &a.second).is_err());
    assert_eq!(
        root.cancel_history_transfer(&id, view.revision, &a.root)
            .unwrap()
            .state,
        State::Cancelled
    );
    assert!(root
        .history_transfer_wire(&id, view.revision, 4001, &a.root)
        .is_err());
    assert!(root
        .prepare_history(request(&id, &selected), &a.root)
        .is_err());
}
#[test]
fn imported_receipt_and_chunks_fail_closed_on_corruption() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut root = open(&work.0, "root", &a, false, &p);
    let ids = old_messages(&mut root, &a, &b);
    let id = uuid::Uuid::new_v4().to_string();
    let view = root.prepare_history(request(&id, &ids), &a.root).unwrap();
    let wire = root
        .history_transfer_wire(&id, view.revision, 3001, &a.root)
        .unwrap();
    let mut joined = open(&work.0, "joined", &a, true, &p);
    seed(&mut joined, &[&a, &b]);
    joined.import_history(&wire, 3002, &a.second).unwrap();
    let conn = rusqlite::Connection::open(work.0.join("joined.db")).unwrap();
    conn.execute(
        "UPDATE direct_v3_history_chunks SET ciphertext=zeroblob(length(ciphertext)) WHERE id=?1",
        [&id],
    )
    .unwrap();
    assert!(joined.transferred_history(None, &a.second).is_err());
    conn.execute("UPDATE device_control_tasks SET body=zeroblob(length(body)) WHERE kind='authorized_history_transfer'",[]).unwrap();
    assert!(joined.history_transfers(&a.second).is_err());
}
#[test]
fn transferred_updates_hide_stale_originals_reject_rollback_and_survive_portable_backup() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut root = open(&work.0, "root", &a, false, &p);
    let mut joined = open(&work.0, "joined", &a, true, &p);
    for store in [&mut root, &mut joined] {
        seed(store, &[&a, &b]);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let original = Batch::make(
        Header::new(
            &b.joined,
            &a.joined,
            "bob-root",
            MessageSpec {
                id: id.clone(),
                sequence: 1,
                previous: vec![],
                sent_at: 2000,
                kind: Kind::Text,
            },
        )
        .unwrap(),
        &b.joined,
        &a.joined,
        &b.root,
        b"old body must disappear",
    )
    .unwrap();
    root.receive(&original, &accepted(&original), &a.root)
        .unwrap();
    joined
        .receive(&original, &accepted(&original), &a.second)
        .unwrap();
    let select = vec![id.clone()];
    let initial = uuid::Uuid::new_v4().to_string();
    let prepared = root
        .prepare_history(request(&initial, &select), &a.root)
        .unwrap();
    let wire = root
        .history_transfer_wire(&initial, prepared.revision, 3001, &a.root)
        .unwrap();
    joined.import_history(&wire, 3002, &a.second).unwrap();
    assert!(joined
        .transferred_history(None, &a.second)
        .unwrap()
        .is_empty());
    let operation = |base, action, text, order| Event {
        order,
        accepted_at: 2200 + order,
        operation: Operation::make(
            original.clone(),
            (&b.joined, &a.joined),
            (&b.joined, &a.joined),
            &b.root,
            op::Header {
                version: 1,
                id: uuid::Uuid::new_v4().to_string(),
                original: original.digest().unwrap(),
                action,
                base,
                revision: base + 1,
                created_at: 2150 + order,
            },
            text,
        )
        .unwrap(),
    };
    let edit = operation(0, Action::Edit, Some("new signed edit"), 1);
    root.import_operations(
        0,
        &Page {
            events: vec![edit.clone()],
            through: 1,
            has_more: false,
        },
        &a.root,
    )
    .unwrap();
    let edited = uuid::Uuid::new_v4().to_string();
    let prepared = root
        .prepare_history(request(&edited, &select), &a.root)
        .unwrap();
    joined
        .import_history(
            &root
                .history_transfer_wire(&edited, prepared.revision, 3003, &a.root)
                .unwrap(),
            3004,
            &a.second,
        )
        .unwrap();
    let rows = joined.history(None, 10, &a.second).unwrap();
    assert!(rows[0].transferred_update);
    assert_eq!(rows[0].operation_revision, 1);
    assert_eq!(rows[0].outcome, "authorized_history_transfer");
    assert!(joined.body(&id, &a.second).is_err());
    assert_eq!(
        joined.transferred_history(None, &a.second).unwrap()[0]
            .text
            .as_deref(),
        Some("new signed edit")
    );
    let parsed = liteseal_shared::history_transfer::Envelope::from_wire(&wire).unwrap();
    let records = parsed.open(&a.joined, &a.second, 3003).unwrap();
    let mut header = parsed.header.clone();
    header.id = uuid::Uuid::new_v4().to_string();
    let stale =
        liteseal_shared::history_transfer::Envelope::make(header, &a.joined, &a.root, records)
            .unwrap()
            .to_wire()
            .unwrap();
    assert!(joined.import_history(&stale, 3005, &a.second).is_err());
    joined
        .import_operations(
            0,
            &Page {
                events: vec![edit],
                through: 1,
                has_more: false,
            },
            &a.second,
        )
        .unwrap();
    assert!(!joined.history(None, 10, &a.second).unwrap()[0].transferred_update);
    assert_eq!(joined.body(&id, &a.second).unwrap(), b"new signed edit");
    assert!(joined
        .transferred_history(None, &a.second)
        .unwrap()
        .is_empty());
    let retract = operation(1, Action::Retract, None, 2);
    root.import_operations(
        1,
        &Page {
            events: vec![retract],
            through: 2,
            has_more: false,
        },
        &a.root,
    )
    .unwrap();
    let retracted = uuid::Uuid::new_v4().to_string();
    let prepared = root
        .prepare_history(request(&retracted, &select), &a.root)
        .unwrap();
    joined
        .import_history(
            &root
                .history_transfer_wire(&retracted, prepared.revision, 3006, &a.root)
                .unwrap(),
            3007,
            &a.second,
        )
        .unwrap();
    assert!(joined.history(None, 10, &a.second).unwrap()[0].retracted);
    assert!(joined.body(&id, &a.second).is_err());
    assert!(joined.claim_notifications(&a.second).unwrap().is_empty());
    assert_eq!(joined.conversations(&a.second).unwrap()[0].unread, 1);
    let identity = liteseal_core::keystore::KeystoreData {
        user_id: "alice".into(),
        device_id: "alice-second".into(),
        server_url: a.initial.anchor().origin.clone(),
        token: "synthetic-access".into(),
        refresh_token: "synthetic-refresh".into(),
        public_key: a.second.public_key.to_vec(),
        secret_key: a.second.secret_key.to_vec(),
        ed25519_pk: a.second.ed25519_pk.to_vec(),
        ed25519_sk: a.second.ed25519_sk.to_vec(),
    };
    let path = work.0.join("history.lseal");
    let password = b"isolated transferred backup password";
    let cancel = std::sync::atomic::AtomicBool::new(false);
    liteseal_core::backup::export_direct_guarded(
        &work.0.join("joined.db"),
        identity,
        &mut joined,
        password,
        false,
        &path,
        &cancel,
        &std::sync::Mutex::new(()),
        |_, _| {},
    )
    .unwrap();
    let restored =
        liteseal_core::backup::restore(&path, password, &work.0, &cancel, |_, _| {}).unwrap();
    let mut reader = liteseal_core::trusted_devices::messages::archive::Reader::open(
        &restored.directory.0.join("history.db"),
        &restored.identity,
    )
    .unwrap();
    assert!(reader.history("bob", None, 10, &a.second).unwrap()[0].transferred_update);
    assert!(reader.body(&id, &a.second).is_err());
    let transferred = reader.transferred_history("bob", &a.second).unwrap();
    assert_eq!(transferred.len(), 1);
    assert!(transferred[0].retracted);
    assert!(transferred[0].text.is_none());
}
