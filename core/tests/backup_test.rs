#![cfg(windows)]
use liteseal_core::{
    backup,
    db::{
        models::{ContactModel, MessageModel},
        repository::MessageRepository,
    },
    groups::GroupStore,
    keystore::KeystoreData,
};
use liteseal_shared::{crypto, group};
use rusqlite::{params, Connection};
use std::sync::atomic::AtomicBool;
const PASSWORD: &[u8] = b"independent backup password 123";
#[path = "../../shared/examples/group_trial/support.rs"]
#[allow(dead_code)]
mod support;
#[test]
fn version_two_round_trip_contains_group_extensions_and_only_optional_verified_cache() {
    use liteseal_shared::{collaboration::Member, group_extension as e};
    let dir = backup::WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let path = dir.0.join("source.db");
    let identity = identity();
    let keys = backup::identity_keys(&identity).unwrap();
    let alice = support::Participant {
        user: "alice".into(),
        keys,
    };
    let bob = support::Participant::new("bob");
    drop(MessageRepository::new(path.to_str().unwrap()).unwrap());
    let mut create = support::change(
        None,
        &alice,
        group::GroupAction::Create {
            name: "archive extensions".into(),
            owner: alice.identity(),
        },
        1000,
    );
    create.group_id = uuid::Uuid::new_v4().to_string();
    create.signature = crypto::sign(&create.signing_bytes(), &alice.keys.ed25519_sk).unwrap();
    let g = group::pin_creation(&create, &alice.identity()).unwrap();
    let join = support::join(&g, &alice, &bob, 1001);
    let g = group::apply_change(Some(&g), &join).unwrap();
    let id = g.group_id();
    let mut store = GroupStore::open(
        path.to_str().unwrap(),
        &identity.server_url,
        alice.identity(),
    )
    .unwrap();
    store.pin(&create, &alice.identity()).unwrap();
    store.apply(id, &[join]).unwrap();
    let client = liteseal_core::groups::GroupClient::new(
        path.to_str().unwrap(),
        &identity.server_url,
        "test-only".into(),
        alice.identity(),
    )
    .unwrap();
    let body = b"offline group attachment contents";
    let task = client
        .media_stage(
            id,
            body,
            "中文.txt".into(),
            "application/octet-stream".into(),
            None,
            &alice.keys,
        )
        .unwrap();
    let conn = Connection::open(&path).unwrap();
    let metadata: Vec<u8> = conn
        .query_row("SELECT metadata FROM group_attachment_cache", [], |r| {
            r.get(0)
        })
        .unwrap();
    let (_, _, _, _, descriptor): (String, String, String, String, e::Attachment) =
        serde_json::from_slice(
            &crypto::decrypt(&metadata, &alice.keys.public_key, &alice.keys.secret_key).unwrap(),
        )
        .unwrap();
    let message = store
        .seal_extension(id, &e::Content::Attachment(descriptor), &alice.keys)
        .unwrap();
    let sub = store.extension_pending(id).unwrap().unwrap();
    let receipt = |s: &e::Submission, seq| e::Receipt {
        event_id: s.event.id.clone(),
        hash: s.event.hash(),
        seq,
        root: if s.roots.is_empty() {
            None
        } else {
            Some(group::GroupMessageReceipt {
                group_id: id.into(),
                message_id: s.event.object.clone(),
                recipients: s
                    .roots
                    .iter()
                    .map(|r| group::GroupDeliveryStatus {
                        recipient_user_id: r.recipient_user_id.clone(),
                        recipient_device_id: r.recipient_device_id.clone(),
                        recipient_join_epoch: r.recipient_join_epoch,
                        status: "pending".into(),
                    })
                    .collect(),
            })
        },
    };
    store
        .extension_accepted(id, &sub, &receipt(&sub, 1), &alice.keys)
        .unwrap();
    conn.execute(
        "UPDATE group_attachment_cache SET root=?1,direction='download',offset=length(ciphertext)",
        [&message],
    )
    .unwrap();
    let activity = store
        .seal_extension(
            id,
            &e::Content::Activity(e::Activity {
                title: "活动 🎉".into(),
                start_at: 2000,
                timezone: "Asia/Singapore".into(),
                location: "会议室".into(),
                description: "说明".into(),
            }),
            &alice.keys,
        )
        .unwrap();
    let sub = store.extension_pending(id).unwrap().unwrap();
    store
        .extension_accepted(id, &sub, &receipt(&sub, 2), &alice.keys)
        .unwrap();
    let object = store.extension_object(id, &activity).unwrap().unwrap();
    let close = e::make(
        &g,
        &Member::from(g.member("alice").unwrap()),
        activity.clone(),
        uuid::Uuid::new_v4().to_string(),
        Some(&object),
        e::Action::Cancel,
        None,
        vec![],
        &alice.keys,
        3000,
    )
    .unwrap();
    store.extension_queue(&close).unwrap();
    store
        .extension_accepted(id, &close, &receipt(&close, 3), &alice.keys)
        .unwrap();
    for include in [false, true] {
        let archive = dir.0.join(if include {
            "with.lseal"
        } else {
            "without.lseal"
        });
        let cancel = AtomicBool::new(false);
        let summary = backup::export(
            &path,
            identity.clone(),
            PASSWORD,
            include,
            &archive,
            &cancel,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(summary.attachments, if include { 1 } else { 0 });
        assert_eq!(summary.missing_attachments, if include { 0 } else { 1 });
        let restored = backup::restore(&archive, PASSWORD, &dir.0, &cancel, |_, _| {}).unwrap();
        let store = GroupStore::open(
            restored.directory.0.join("history.db").to_str().unwrap(),
            &identity.server_url,
            alice.identity(),
        )
        .unwrap();
        let view = store
            .extension_view(id, std::slice::from_ref(&activity), &alice.keys)
            .unwrap();
        assert!(view.activities[0].closed && view.activities[0].cancelled);
        assert_eq!(view.activities[0].title, "活动 🎉");
        let read = store.media_archive_read(id, &message, &alice.keys);
        if include {
            assert_eq!(read.unwrap().1, body);
        } else {
            assert!(read.is_err());
        }
        let conn = Connection::open(restored.directory.0.join("history.db")).unwrap();
        assert_eq!(
            conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM local_extension_outbox", [], |r| r
                .get(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM group_attachment_cache WHERE id=?1",
                [&task.id],
                |r| r.get(0)
            )
            .unwrap(),
            if include { 1 } else { 0 }
        );
    }
}
fn identity() -> KeystoreData {
    let k = crypto::generate_keypair().unwrap();
    KeystoreData {
        user_id: "alice".into(),
        device_id: "alice-device".into(),
        server_url: "http://localhost:3000".into(),
        token: "must-never-be-exported".into(),
        refresh_token: "must-never-be-exported-refresh".into(),
        public_key: k.public_key.to_vec(),
        secret_key: k.secret_key.to_vec(),
        ed25519_pk: k.ed25519_pk.to_vec(),
        ed25519_sk: k.ed25519_sk.to_vec(),
    }
}
#[test]
fn reader_accepts_legacy_payload_one_and_rejects_unknown_authenticated_payload() {
    use liteseal_shared::backup_crypto::{Decryptor, Encryptor};
    use std::fs::File;
    let dir = backup::WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let source = dir.0.join("source.db");
    drop(MessageRepository::new(source.to_str().unwrap()).unwrap());
    let current = dir.0.join("current.lseal");
    let cancel = AtomicBool::new(false);
    backup::export(
        &source,
        identity(),
        PASSWORD,
        false,
        &current,
        &cancel,
        |_, _| {},
    )
    .unwrap();
    for version in [1, 999] {
        let mut decoder = Decryptor::new(File::open(&current).unwrap(), PASSWORD).unwrap();
        let header = decoder.next_chunk().unwrap().unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(manifest["version"], 2);
        manifest["version"] = version.into();
        let converted = dir.0.join(format!("payload-{version}.lseal"));
        let mut file = File::create(&converted).unwrap();
        let mut encoder = Encryptor::new(&mut file, PASSWORD).unwrap();
        encoder
            .push(&serde_json::to_vec(&manifest).unwrap(), false)
            .unwrap();
        while let Some(bytes) = decoder.next_chunk().unwrap() {
            encoder.push(&bytes, decoder.ended()).unwrap();
            if decoder.ended() {
                break;
            }
        }
        drop(encoder);
        file.sync_all().unwrap();
        let result = backup::restore(&converted, PASSWORD, &dir.0, &cancel, |_, _| {});
        if version == 1 {
            assert_eq!(result.unwrap().summary.attachments, 0);
        } else {
            assert!(result.is_err());
        }
    }
}
#[test]
fn portable_round_trip_preserves_history_and_excludes_jobs_other_scopes_and_credentials() {
    let dir = backup::WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let db = dir.0.join("data.db");
    let identity = identity();
    let keys = backup::identity_keys(&identity).unwrap();
    let peer = crypto::generate_keypair().unwrap();
    let repository = MessageRepository::new(db.to_str().unwrap()).unwrap();
    repository
        .insert_contact(&ContactModel {
            user_id: "bob".into(),
            username: "Bob".into(),
            public_key: peer.public_key.to_vec(),
            ed25519_pk: Some(peer.ed25519_pk.to_vec()),
            trust_state: "verified".into(),
            fingerprint: "fingerprint".into(),
            key_changed: false,
            added_at: 1,
        })
        .unwrap();
    for n in 0..65 {
        let body = format!("中文 🦭 {n}");
        repository
            .insert_message(&MessageModel {
                id: format!("msg-{n}"),
                conversation_id: "dm:alice:bob".into(),
                sender_id: "bob".into(),
                sender_device_id: "bob-device".into(),
                sender_seq: n + 1,
                timestamp: n,
                message_type: "text".into(),
                local_state: "received".into(),
                expire_at: None,
                ciphertext: crypto::encrypt(body.as_bytes(), &keys.public_key, &peer.secret_key)
                    .unwrap(),
                signature: vec![0; 64],
                prev_hash: vec![],
            })
            .unwrap();
    }
    repository
        .insert_message(&MessageModel {
            id: "other-account".into(),
            conversation_id: "dm:mallory:bob".into(),
            sender_id: "bob".into(),
            sender_device_id: "bob-device".into(),
            sender_seq: 1,
            timestamp: 1,
            message_type: "text".into(),
            local_state: "received".into(),
            expire_at: None,
            ciphertext: vec![0; 48],
            signature: vec![0; 64],
            prev_hash: vec![],
        })
        .unwrap();
    drop(repository);
    let mut groups = GroupStore::open(
        db.to_str().unwrap(),
        &identity.server_url,
        backup::group_identity(&identity),
    )
    .unwrap();
    let mut event = group::GroupChange {
        group_id: "group".into(),
        epoch: 1,
        previous_hash: vec![],
        actor: identity.user_id.clone(),
        created_at: 1,
        action: group::GroupAction::Create {
            name: "群组".into(),
            owner: backup::group_identity(&identity),
        },
        signature: vec![],
    };
    event.signature = crypto::sign(&event.signing_bytes(), &keys.ed25519_sk).unwrap();
    groups
        .pin(&event, &backup::group_identity(&identity))
        .unwrap();
    groups.save_draft("group", "群草稿 🦭", &keys).unwrap();
    drop(groups);
    let conn = Connection::open(&db).unwrap();
    // Even a task encrypted by the exported identity must not accompany an offline archive.
    let task_keys = backup::identity_keys(&identity).unwrap();
    let task_owner = liteseal_core::trusted_devices::tasks::TaskOwner::for_join(
        &identity.server_url,
        "alice",
        &uuid::Uuid::new_v4().to_string(),
        &task_keys,
    )
    .unwrap();
    let mut device_jobs =
        liteseal_core::trusted_devices::tasks::DeviceTaskStore::open(&db, task_owner, &task_keys)
            .unwrap();
    device_jobs
        .prepare_join("pending-device", &task_keys)
        .unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE secret_session(token TEXT); INSERT INTO secret_session VALUES('must-never-be-exported'); INSERT INTO locally_deleted_messages VALUES('alice','msg-0'); INSERT INTO scheduled_messages VALUES('alice','alice-device','task','bob',123,X'00','scheduled',''); INSERT INTO typing_preferences VALUES('alice',1); INSERT INTO typing_preferences VALUES('mallory',1);").unwrap();
    let output = dir.0.join("test.lseal");
    let cancel = AtomicBool::new(false);
    let summary = backup::export(
        &db,
        identity.clone(),
        PASSWORD,
        false,
        &output,
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(summary.messages, 65);
    assert_eq!(summary.groups, 1);
    assert!(backup::export(
        &db,
        identity.clone(),
        PASSWORD,
        false,
        &output,
        &cancel,
        |_, _| {}
    )
    .is_err());
    assert!(backup::restore(&output, b"wrong long password", &dir.0, &cancel, |_, _| {}).is_err());
    let restored = backup::restore(&output, PASSWORD, &dir.0, &cancel, |_, _| {}).unwrap();
    assert_eq!(restored.identity.public_key, identity.public_key);
    assert!(restored.identity.token.is_empty());
    assert!(restored.identity.refresh_token.is_empty());
    let stored =
        liteseal_core::keystore::load_keypair_from(&restored.directory.0.join("identity.bin"))
            .unwrap();
    assert_eq!(stored.ed25519_pk, identity.ed25519_pk);
    let archived = Connection::open(restored.directory.0.join("history.db")).unwrap();
    assert_eq!(
        archived
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name='device_control_tasks'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    for table in [
        "scheduled_messages",
        "local_group_outbox",
        "local_group_ack",
        "local_collab_ack",
        "local_collab_outbox",
    ] {
        let count: i64 = archived
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    assert_eq!(
        archived
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name='secret_session'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        archived
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id='other-account'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        archived
            .query_row(
                "SELECT COUNT(*) FROM typing_preferences WHERE user_id='mallory'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    let repository =
        MessageRepository::new(restored.directory.0.join("history.db").to_str().unwrap()).unwrap();
    let page = repository
        .get_visible_message_page("dm:alice:bob", 50, "alice", None, None)
        .unwrap();
    assert_eq!(page.len(), 50);
    let last = page.last().unwrap();
    let earlier = repository
        .get_visible_message_page(
            "dm:alice:bob",
            50,
            "alice",
            Some(last.timestamp),
            Some(&last.id),
        )
        .unwrap();
    assert_eq!(earlier.len(), 14);
    for m in page.iter().chain(&earlier) {
        assert!(String::from_utf8(
            crypto::decrypt(&m.ciphertext, &peer.public_key, &keys.secret_key).unwrap()
        )
        .unwrap()
        .starts_with("中文 🦭"));
        assert_ne!(m.id, "msg-0");
    }
    let groups = GroupStore::open(
        restored.directory.0.join("history.db").to_str().unwrap(),
        &identity.server_url,
        backup::group_identity(&identity),
    )
    .unwrap();
    assert_eq!(groups.draft("group", &keys).unwrap(), "群草稿 🦭");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        66
    );
}
#[test]
fn only_complete_authenticated_downloaded_attachments_are_optional_and_cancellation_keeps_source() {
    let dir = backup::WorkDirectory::create(&std::env::temp_dir()).unwrap();
    let db = dir.0.join("data.db");
    let identity = identity();
    let keys = backup::identity_keys(&identity).unwrap();
    let peer = crypto::generate_keypair().unwrap();
    let repository = MessageRepository::new(db.to_str().unwrap()).unwrap();
    repository
        .insert_contact(&ContactModel {
            user_id: "bob".into(),
            username: "Bob".into(),
            public_key: peer.public_key.to_vec(),
            ed25519_pk: Some(peer.ed25519_pk.to_vec()),
            trust_state: "verified".into(),
            fingerprint: "fingerprint".into(),
            key_changed: false,
            added_at: 1,
        })
        .unwrap();
    let (cipher, key) = crypto::encrypt_attachment(b"authenticated attachment").unwrap();
    let descriptor = serde_json::json!({"version":1,"id":"attachment","name":"file.txt","size":24,"mime":"text/plain","key":key});
    let body = format!("\u{1e}LiteSeal:2:{descriptor}");
    repository
        .insert_message(&MessageModel {
            id: "attachment-message".into(),
            conversation_id: "dm:alice:bob".into(),
            sender_id: "bob".into(),
            sender_device_id: "bob-device".into(),
            sender_seq: 1,
            timestamp: 1,
            message_type: "text".into(),
            local_state: "received".into(),
            expire_at: None,
            ciphertext: crypto::encrypt(body.as_bytes(), &keys.public_key, &peer.secret_key)
                .unwrap(),
            signature: vec![0; 64],
            prev_hash: vec![],
        })
        .unwrap();
    drop(repository);
    let conn = Connection::open(&db).unwrap();
    conn.execute("INSERT INTO attachment_transfers VALUES('attachment','alice','bob','attachment-message',?1,?2,?3,'download')",params![crypto::encrypt(descriptor.to_string().as_bytes(),&keys.public_key,&keys.secret_key).unwrap(),cipher,cipher.len()]).unwrap();
    let cancel = AtomicBool::new(false);
    let output = dir.0.join("full.lseal");
    let summary = backup::export(
        &db,
        identity.clone(),
        PASSWORD,
        true,
        &output,
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(summary.attachments, 1);
    assert_eq!(summary.missing_attachments, 0);
    let restored = backup::restore(&output, PASSWORD, &dir.0, &cancel, |_, _| {}).unwrap();
    let archived = Connection::open(restored.directory.0.join("history.db")).unwrap();
    assert_eq!(
        backup::attachment_plain(&archived, &restored.identity, "attachment-message")
            .unwrap()
            .1,
        b"authenticated attachment"
    );
    let summary = backup::export(
        &db,
        identity.clone(),
        PASSWORD,
        false,
        &dir.0.join("no-media.lseal"),
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(summary.attachments, 0);
    assert_eq!(summary.missing_attachments, 1);
    conn.execute("UPDATE attachment_transfers SET offset=0", [])
        .unwrap();
    let summary = backup::export(
        &db,
        identity.clone(),
        PASSWORD,
        true,
        &dir.0.join("partial.lseal"),
        &cancel,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(summary.attachments, 0);
    assert_eq!(summary.skipped_attachments, 1);
    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    let cancelled = dir.0.join("cancelled.lseal");
    assert!(backup::export(
        &db,
        identity,
        PASSWORD,
        true,
        &cancelled,
        &cancel,
        |_, _| {}
    )
    .is_err());
    assert!(!cancelled.exists());
    assert!(output.exists());
}
