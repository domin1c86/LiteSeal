use super::super::tests::Fixture;
use super::*;
use crate::trusted_devices::witness::Witness;
use liteseal_shared::{
    direct_message::{Header, MessageSpec},
    protocol::AckOutcome,
    trusted_device::{Anchor, DeviceState},
};

fn receive(f: &mut Fixture, plain: &[u8]) -> (String, Vec<u8>) {
    let id = uuid::Uuid::new_v4().to_string();
    let (descriptor, cipher) = Descriptor::encrypt(
        id.clone(),
        "中文文件.txt".into(),
        plain,
        Kind::Attachment,
        None,
    )
    .unwrap();
    let own = DeviceState::pin(Anchor {
        origin: f.owner.origin.clone(),
        account: f.owner.account.clone(),
        root: f.owner.device.clone(),
    })
    .unwrap();
    let batch = Batch::make(
        Header::new(
            &f.peer,
            &own,
            &f.peer.anchor().root.device_id,
            MessageSpec {
                id: id.clone(),
                sequence: 1,
                previous: vec![],
                sent_at: 100,
                kind: Kind::Attachment,
            },
        )
        .unwrap(),
        &f.peer,
        &own,
        &f.peer_keys,
        &Zeroizing::new(descriptor.to_body(Kind::Attachment).unwrap()),
    )
    .unwrap();
    let receipt = super::super::super::Acceptance::from_authenticated_response(
        &batch,
        &id,
        batch.digest().unwrap(),
        200,
    )
    .unwrap();
    assert_eq!(
        f.store.receive(&batch, &receipt, &f.keys).unwrap(),
        AckOutcome::Processed
    );
    (id, cipher)
}
#[test]
fn partial_download_reopens_and_full_authentication_precedes_every_read() {
    let mut f = Fixture::new();
    let plain = "原下载 中文 emoji 🦭".as_bytes().repeat(65_000);
    let (id, cipher) = receive(&mut f, &plain);
    let info = f.store.media_info(&id, &f.keys).unwrap();
    assert_eq!(info.name, "中文文件.txt");
    assert!(info.cache.is_none());
    assert!(!serde_json::to_string(&info).unwrap().contains("\"key\""));
    let start = f.store.start_media_download(&id, &f.keys).unwrap();
    assert_eq!(start.phase, Phase::Downloading);
    assert!(f.store.media_plain(&id, &f.keys).is_err());
    let first = f
        .store
        .downloaded_chunk(&id, start.revision, &cipher[..CHUNK], &f.keys)
        .unwrap();
    assert_eq!(first.downloaded, CHUNK as u64);
    assert_eq!(first.uploaded, 0);
    assert!(f.store.media_plain(&id, &f.keys).is_err());
    f.store = Store::open(
        &f.path,
        f.owner.clone(),
        Witness::new(&f.path, f.native.clone()),
    )
    .unwrap();
    assert_eq!(
        f.store.start_media_download(&id, &f.keys).unwrap().revision,
        first.revision
    );
    let done = f
        .store
        .downloaded_chunk(&id, first.revision, &cipher[CHUNK..], &f.keys)
        .unwrap();
    assert_eq!(done.phase, Phase::Cached);
    assert_eq!(f.store.media_plain(&id, &f.keys).unwrap().as_slice(), plain);
    let conn = Connection::open(&f.path).unwrap();
    conn.execute("UPDATE direct_v3_media_chunks SET ciphertext=zeroblob(length(ciphertext)) WHERE id=?1 AND part=0",[&id]).unwrap();
    drop(conn);
    assert!(f.store.media_plain(&id, &f.keys).is_err());
    assert_eq!(
        f.store.clear_media(&id, &f.keys).unwrap(),
        cipher.len() as u64
    );
    assert_eq!(
        f.store
            .start_media_download(&id, &f.keys)
            .unwrap()
            .downloaded,
        0
    );
}
#[test]
fn hidden_or_cancelled_download_rejects_late_data_without_restoring_history() {
    for hidden in [false, true] {
        let mut f = Fixture::new();
        let (id, cipher) = receive(&mut f, b"keep original hidden rule");
        let before = f.store.start_media_download(&id, &f.keys).unwrap();
        if hidden {
            f.store.hide(&id, &f.keys).unwrap();
            assert!(f.store.media_info(&id, &f.keys).is_err());
            assert!(f.store.start_media_download(&id, &f.keys).is_err());
            assert!(f.store.media_task(&id, &f.keys).is_err());
            assert!(f.store.media_tasks(&f.keys).unwrap().is_empty());
        } else {
            f.store.cancel_media(&id, &f.keys).unwrap();
        }
        assert!(f
            .store
            .downloaded_chunk(&id, before.revision, &cipher, &f.keys)
            .is_err());
        assert!(f.store.media_plain(&id, &f.keys).is_err());
        assert_eq!(
            f.store.media_job(&id, &f.keys).unwrap().phase,
            Phase::Cancelled
        );
        f.store.clear_media(&id, &f.keys).unwrap();
        if hidden {
            assert!(f.store.history(None, 100, &f.keys).unwrap().is_empty());
        } else {
            assert_eq!(f.store.history(None, 100, &f.keys).unwrap()[0].id, id);
        }
    }
}
#[test]
fn bad_final_object_is_failed_and_explicit_retry_keeps_original_descriptor() {
    let mut f = Fixture::new();
    let (id, cipher) = receive(&mut f, b"full MAC and hash required");
    let start = f.store.start_media_download(&id, &f.keys).unwrap();
    let mut bad = cipher.clone();
    bad[0] ^= 1;
    let failed = f
        .store
        .downloaded_chunk(&id, start.revision, &bad, &f.keys)
        .unwrap();
    assert_eq!(failed.phase, Phase::Failed);
    assert!(f.store.media_plain(&id, &f.keys).is_err());
    let retry = f.store.start_media_download(&id, &f.keys).unwrap();
    assert!(retry.revision > failed.revision);
    assert_eq!(retry.id, id);
    assert_eq!(retry.downloaded, 0);
    assert_eq!(
        f.store
            .downloaded_chunk(&id, retry.revision, &cipher, &f.keys)
            .unwrap()
            .phase,
        Phase::Cached
    );
    assert_eq!(
        f.store.media_plain(&id, &f.keys).unwrap().as_slice(),
        b"full MAC and hash required"
    );
}
#[test]
fn unavailability_and_size_failures_preserve_signed_history() {
    let mut f = Fixture::new();
    let (id, cipher) = receive(&mut f, b"unavailable original");
    let start = f.store.start_media_download(&id, &f.keys).unwrap();
    assert!(f
        .store
        .downloaded_chunk(&id, start.revision, &cipher[..cipher.len() - 1], &f.keys)
        .is_err());
    assert_eq!(
        f.store.media_job(&id, &f.keys).unwrap().revision,
        start.revision
    );
    let unavailable = f
        .store
        .download_unavailable(&id, start.revision, &f.keys)
        .unwrap();
    assert_eq!(unavailable.phase, Phase::Unavailable);
    assert!(f.store.media_plain(&id, &f.keys).is_err());
    assert_eq!(f.store.history(None, 100, &f.keys).unwrap()[0].id, id);
    let retry = f.store.start_media_download(&id, &f.keys).unwrap();
    assert_eq!(retry.phase, Phase::Downloading);
    assert!(retry.revision > unavailable.revision);
}
#[test]
fn native_recovery_uses_precommitted_download_ciphertext_and_original_descriptor() {
    let mut f = Fixture::new();
    let (id, cipher) = receive(&mut f, b"recover full downloaded object");
    let start = f.store.start_media_download(&id, &f.keys).unwrap();
    let conn = Connection::open(&f.path).unwrap();
    let (revision, body): (u64, Vec<u8>) = conn
        .query_row(
            "SELECT revision,body FROM device_control_tasks WHERE scope=?1 AND id=?2",
            params![scope(&f.owner), id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let generation: i64 = conn
        .query_row("SELECT generation FROM device_state_witness", [], |r| {
            r.get(0)
        })
        .unwrap();
    drop(conn);
    {
        let mut native = f.native.0.lock().unwrap();
        native.2 = Some(native.1 + 2);
    }
    assert!(f
        .store
        .downloaded_chunk(&id, start.revision, &cipher, &f.keys)
        .is_err());
    drop(f.store);
    // Roll back only the covered metadata commit; the preceding ciphertext
    // transaction remains durable, as it does in the native/SQLite crash gap.
    let conn = Connection::open(&f.path).unwrap();
    conn.execute(
        "UPDATE device_control_tasks SET revision=?3,body=?4 WHERE scope=?1 AND id=?2",
        params![scope(&f.owner), id, revision, body],
    )
    .unwrap();
    conn.execute(
        "UPDATE device_state_witness SET generation=?1",
        [generation],
    )
    .unwrap();
    drop(conn);
    let mut store = Store::open(
        &f.path,
        f.owner.clone(),
        Witness::new(&f.path, f.native.clone()),
    )
    .unwrap();
    assert_eq!(store.media_task(&id, &f.keys).unwrap().phase, Phase::Cached);
    assert_eq!(
        store.media_plain(&id, &f.keys).unwrap().as_slice(),
        b"recover full downloaded object"
    );
}
#[test]
fn download_chunk_cannot_exceed_shared_local_quota_or_advance_on_failure() {
    let mut f = Fixture::new();
    let (id, cipher) = receive(&mut f, b"quota protected");
    let start = f.store.start_media_download(&id, &f.keys).unwrap();
    let conn = Connection::open(&f.path).unwrap();
    conn.execute_batch(crate::attachment_cache::GROUP_SCHEMA)
        .unwrap();
    conn.execute("INSERT INTO group_attachment_cache VALUES('synthetic',?1,'group','quota',1,X'00',zeroblob(?2),0,'download','root')",params![f.owner.account,LIMIT-cipher.len() as i64+1]).unwrap();
    drop(conn);
    assert!(f
        .store
        .downloaded_chunk(&id, start.revision, &cipher, &f.keys)
        .is_err());
    assert_eq!(
        f.store.media_job(&id, &f.keys).unwrap().revision,
        start.revision
    );
    assert!(f.store.media_plain(&id, &f.keys).is_err());
}
