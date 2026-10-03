use super::*;
use liteseal_core::{backup, keystore::KeystoreData, trusted_devices::messages::archive::Reader};
use liteseal_shared::direct_operation::{self as op, Action, Event, Operation, Page};
use std::sync::{atomic::AtomicBool, Mutex};
const PASSWORD: &[u8] = b"isolated portable archive password";
fn identity(account: &Account, joined: bool) -> KeystoreData {
    let keys = if joined {
        &account.second
    } else {
        &account.root
    };
    KeystoreData {
        user_id: account.initial.anchor().account.clone(),
        device_id: if joined {
            account.joined.secondary().unwrap().device_id.clone()
        } else {
            account.initial.anchor().root.device_id.clone()
        },
        server_url: account.initial.anchor().origin.clone(),
        token: "synthetic-access-never-portable".into(),
        refresh_token: "synthetic-refresh-never-portable".into(),
        public_key: keys.public_key.to_vec(),
        secret_key: keys.secret_key.to_vec(),
        ed25519_pk: keys.ed25519_pk.to_vec(),
        ed25519_sk: keys.ed25519_sk.to_vec(),
    }
}
fn export(
    store: &mut Store,
    work: &Path,
    name: &str,
    identity: KeystoreData,
    file: &str,
) -> backup::Restored {
    let path = work.join(file);
    backup::export_direct_guarded(
        &work.join(format!("{name}.db")),
        identity,
        store,
        PASSWORD,
        true,
        &path,
        &AtomicBool::new(false),
        &Mutex::new(()),
        |_, _| {},
    )
    .unwrap();
    backup::restore(&path, PASSWORD, work, &AtomicBool::new(false), |_, _| {}).unwrap()
}
fn event(
    a: &Account,
    b: &Account,
    original: &Batch,
    base: u64,
    action: Action,
    text: Option<&str>,
    order: i64,
) -> Event {
    Event {
        order,
        accepted_at: 2200 + order,
        operation: Operation::make(
            original.clone(),
            (&a.joined, &b.joined),
            (&a.joined, &b.joined),
            &a.root,
            op::Header {
                version: 1,
                id: uuid::Uuid::new_v4().to_string(),
                original: original.digest().unwrap(),
                action,
                base,
                revision: base + 1,
                created_at: 2150,
            },
            text,
        )
        .unwrap(),
    }
}
#[test]
fn portable_v3_root_and_joined_history_preserve_operations_hidden_drafts_and_exclude_online_state()
{
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut root = open(&work.0, "root", &a, false, &p);
    seed(&mut root, &[&a, &b]);
    let mut joined = open(&work.0, "joined", &a, true, &p);
    seed(&mut joined, &[&a, &b]);
    let mut batches = Vec::new();
    for i in 0..61 {
        let id = uuid::Uuid::new_v4().to_string();
        prepare(
            &mut root,
            "bob",
            &id,
            format!("原历史 {i} 中文 🦭").as_bytes(),
            &a.root,
        );
        root.begin_publish(&id, 0, &a.root).unwrap();
        let batch = root.original(&id, &a.root).unwrap();
        root.confirm_accepted(&accepted(&batch), &a.root).unwrap();
        joined
            .receive(&batch, &accepted(&batch), &a.second)
            .unwrap();
        batches.push(batch);
    }
    let operations = vec![
        event(
            &a,
            &b,
            &batches[1],
            0,
            Action::Edit,
            Some("编辑后的离线正文 🦭"),
            1,
        ),
        event(&a, &b, &batches[2], 0, Action::Retract, None, 2),
    ];
    for (store, keys) in [(&mut root, &a.root), (&mut joined, &a.second)] {
        store
            .import_operations(
                0,
                &Page {
                    events: operations.clone(),
                    through: 2,
                    has_more: false,
                },
                keys,
            )
            .unwrap();
        store.hide(&batches[0].header.id, keys).unwrap();
        store.save_draft("bob", 0, "独立草稿 🦭", keys).unwrap();
        store.set_muted("bob", 0, true, keys).unwrap();
        store
            .mark_read("bob", &batches[20].header.id, keys)
            .unwrap();
    }
    let pending = uuid::Uuid::new_v4().to_string();
    prepare(
        &mut root,
        "bob",
        &pending,
        b"pending-never-portable",
        &a.root,
    );
    let pending_op = uuid::Uuid::new_v4().to_string();
    root.prepare_operation(
        liteseal_core::trusted_devices::messages::operations::PrepareOperation {
            id: &pending_op,
            target: &batches[3].header.id,
            created_at: 2300,
            action: Action::Edit,
            text: Some("pending operation"),
        },
        &a.root,
    )
    .unwrap();
    let old_path = work.0.join("old-refuses.lseal");
    assert!(backup::export(
        &work.0.join("root.db"),
        identity(&a, false),
        PASSWORD,
        false,
        &old_path,
        &AtomicBool::new(false),
        |_, _| {}
    )
    .is_err());
    assert!(!old_path.exists());
    for (store, name, secondary, keys) in [
        (&mut root, "root", false, &a.root),
        (&mut joined, "joined", true, &a.second),
    ] {
        let restored = export(
            store,
            &work.0,
            name,
            identity(&a, secondary),
            &format!("{name}.lseal"),
        );
        assert_eq!(restored.version, 3);
        assert_eq!(restored.summary.messages, 61);
        assert!(restored.identity.token.is_empty() && restored.identity.refresh_token.is_empty());
        let path = restored.directory.0.join("history.db");
        let mut reader = Reader::open(&path, &restored.identity).unwrap();
        let conversations = reader.conversations(keys).unwrap();
        assert_eq!(conversations[0].draft, "独立草稿 🦭");
        assert!(conversations[0].muted);
        assert!(conversations[0].read_through > 0);
        let page = reader.history("bob", None, 50, keys).unwrap();
        assert_eq!(page.len(), 50);
        let earlier = reader
            .history("bob", page.last().map(|r| r.cursor), 50, keys)
            .unwrap();
        assert_eq!(earlier.len(), 10);
        assert!(!earlier.iter().any(|r| r.id == batches[0].header.id));
        assert_eq!(
            reader.body(&batches[1].header.id, keys).unwrap(),
            "编辑后的离线正文 🦭".as_bytes()
        );
        assert!(reader.body(&batches[2].header.id, keys).is_err());
        assert!(reader.body(&batches[0].header.id, keys).is_err());
        assert!(reader.body(&pending, keys).is_err());
        assert!(reader.body(&batches[1].header.id, &b.root).is_err());
        let conn = rusqlite::Connection::open(&path).unwrap();
        for table in [
            "device_control_tasks",
            "direct_v3_tasks",
            "direct_v3_ack",
            "device_state_witness",
            "trusted_device_anchors",
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!exists, "online table {table} must not be portable");
        }
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM backup_direct_operations", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            2
        );
        drop(reader);
        conn.execute(
            "UPDATE backup_direct_records SET local=zeroblob(length(local)) WHERE id=?1",
            [&batches[1].header.id],
        )
        .unwrap();
        assert!(Reader::open(&path, &restored.identity).is_err());
    }
    assert_eq!(
        root.tasks(&a.root)
            .unwrap()
            .iter()
            .filter(|t| t.id == pending)
            .count(),
        1
    );
}
#[test]
fn portable_v3_operation_first_retains_original_evidence_without_creating_history_or_delivery() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut sender = open(&work.0, "sender", &a, false, &p);
    seed(&mut sender, &[&a, &b]);
    let id = uuid::Uuid::new_v4().to_string();
    prepare(&mut sender, "bob", &id, b"operation first", &a.root);
    let batch = sender.original(&id, &a.root).unwrap();
    let mut recipient = open(&work.0, "recipient", &b, false, &p);
    seed(&mut recipient, &[&a, &b]);
    recipient
        .import_operations(
            0,
            &Page {
                events: vec![event(&a, &b, &batch, 0, Action::Retract, None, 1)],
                through: 1,
                has_more: false,
            },
            &b.root,
        )
        .unwrap();
    let restored = export(
        &mut recipient,
        &work.0,
        "recipient",
        identity(&b, false),
        "operation-first.lseal",
    );
    let mut reader =
        Reader::open(&restored.directory.0.join("history.db"), &restored.identity).unwrap();
    assert_eq!(restored.summary.messages, 0);
    assert!(reader
        .history("alice", None, 50, &b.root)
        .unwrap()
        .is_empty());
    let conn = rusqlite::Connection::open(restored.directory.0.join("history.db")).unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM backup_direct_operations", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        1
    );
    drop(reader);
    conn.execute_batch("DROP TABLE backup_direct_media; CREATE VIEW backup_direct_media AS SELECT 'injected' AS id,zeroblob(1048576) AS ciphertext;").unwrap();
    assert!(Reader::open(&restored.directory.0.join("history.db"), &restored.identity).is_err());
}
#[test]
fn portable_v3_export_native_scope_cancellation_and_no_replace_fences() {
    let work = WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let p = Protection::isolated_test();
    let a = Account::new("alice");
    let b = Account::new("bob");
    let mut store = open(&work.0, "root", &a, false, &p);
    seed(&mut store, &[&a, &b]);
    let db = work.0.join("root.db");
    let out = work.0.join("cancel.lseal");
    let cancel = AtomicBool::new(false);
    assert!(backup::export_direct_guarded(
        &db,
        identity(&a, false),
        &mut store,
        PASSWORD,
        true,
        &out,
        &cancel,
        &Mutex::new(()),
        |_, _| {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    )
    .is_err());
    assert!(!out.exists());
    cancel.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(backup::export_direct_guarded(
        &db,
        identity(&b, false),
        &mut store,
        PASSWORD,
        true,
        &out,
        &cancel,
        &Mutex::new(()),
        |_, _| {}
    )
    .is_err());
    assert!(!out.exists());
    std::fs::write(&out, b"existing destination").unwrap();
    assert!(backup::export_direct_guarded(
        &db,
        identity(&a, false),
        &mut store,
        PASSWORD,
        true,
        &out,
        &cancel,
        &Mutex::new(()),
        |_, _| {}
    )
    .is_err());
    assert_eq!(std::fs::read(&out).unwrap(), b"existing destination");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("DELETE FROM trusted_device_events", [])
        .unwrap();
    drop(conn);
    let out = work.0.join("tamper.lseal");
    assert!(backup::export_direct_guarded(
        &db,
        identity(&a, false),
        &mut store,
        PASSWORD,
        true,
        &out,
        &cancel,
        &Mutex::new(()),
        |_, _| {}
    )
    .is_err());
    assert!(!out.exists());
}
