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
