//! Portable confirmed history, deliberately separate from online stores and
//! native high-water state. The reader owns only an in-memory verified projection.
use super::*;
use crate::{
    backup::{check_cancel, Summary},
    keystore::KeystoreData,
};
use liteseal_shared::{
    direct_media::Descriptor,
    direct_operation::{Event, Operation},
};
use rusqlite::{types::Value, OpenFlags};
use std::sync::atomic::AtomicBool;

const SCHEMA: &str = "
CREATE TABLE backup_direct_identity(scope TEXT PRIMARY KEY);
CREATE TABLE backup_direct_roots(origin TEXT NOT NULL,account TEXT NOT NULL,anchor BLOB NOT NULL CHECK(length(anchor)<=16384),revision INTEGER NOT NULL,head BLOB NOT NULL CHECK(length(head)=32),PRIMARY KEY(origin,account));
CREATE TABLE backup_direct_events(origin TEXT NOT NULL,account TEXT NOT NULL,revision INTEGER NOT NULL,event_id TEXT NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=16384),PRIMARY KEY(origin,account,revision));
CREATE TABLE backup_direct_records(cursor INTEGER PRIMARY KEY,scope TEXT NOT NULL,id TEXT NOT NULL,stream TEXT NOT NULL,sequence INTEGER NOT NULL,wire BLOB NOT NULL CHECK(length(wire)<=262144),digest BLOB NOT NULL CHECK(length(digest)=32),local BLOB NOT NULL CHECK(length(local)<=73768),role TEXT NOT NULL,outcome TEXT NOT NULL,accepted_at INTEGER NOT NULL,UNIQUE(scope,id));
CREATE TABLE backup_direct_hidden(scope TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(scope,id));
CREATE TABLE backup_direct_operations(position INTEGER PRIMARY KEY,accepted_at INTEGER NOT NULL,wire BLOB NOT NULL CHECK(length(wire)<=524288));
CREATE TABLE backup_direct_preferences(peer TEXT PRIMARY KEY,body BLOB NOT NULL CHECK(length(body)<=524328));
CREATE TABLE backup_direct_media(id TEXT PRIMARY KEY,ciphertext BLOB NOT NULL CHECK(length(ciphertext)<=20971560));
";
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Preference {
    domain: String,
    scope: String,
    peer: String,
    draft: String,
    muted: bool,
    read_through: i64,
}
#[derive(Serialize)]
pub struct Conversation {
    pub peer: String,
    pub muted: bool,
    pub read_through: i64,
    pub draft: String,
}
fn owner(identity: &KeystoreData) -> Result<(Owner, KeyPair), String> {
    let keys = crate::backup::identity_keys(identity)?;
    let origin = liteseal_shared::trusted_device::canonical_origin(&identity.server_url)
        .map_err(|_| invalid())?;
    Ok((
        Owner::new(&origin, &identity.user_id, &identity.device_id, &keys)?,
        keys,
    ))
}
fn validate_schema(source: &Connection) -> Result<(), String> {
    // Querying an attacker-supplied view would execute its SQL. Verify table,
    // index and trigger definitions before reading any portable payload rows.
    let expected = Connection::open_in_memory().map_err(db)?;
    expected.execute_batch(SCHEMA).map_err(db)?;
    if source.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN ('backup_direct_history','backup_direct_history_chunks'))",[],|r|r.get::<_,bool>(0)).map_err(db)? {
        expected.execute_batch(history_transfer::ARCHIVE_SCHEMA).map_err(db)?;
    }
    let entries = |conn: &Connection| {
        conn.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name GLOB 'backup_direct_*' ORDER BY type,name LIMIT 32").map_err(db)?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?))).map_err(db)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db)
    };
    if entries(source)? != entries(&expected)? {
        return Err("单聊 v3 备份结构无法验证".into());
    }
    Ok(())
}
fn copy(
    source: &Connection,
    target: &Connection,
    query: &str,
    insert: &str,
    parameters: &[&dyn rusqlite::ToSql],
    count: usize,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut q = source.prepare(query).map_err(db)?;
    let mut rows = q.query(parameters).map_err(db)?;
    while let Some(row) = rows.next().map_err(db)? {
        check_cancel(cancel)?;
        for index in 0..count {
            match row.get_ref(index).map_err(db)? {
                rusqlite::types::ValueRef::Blob(bytes)
                    if bytes.len() > liteseal_shared::direct_media::MAX_FILE + 40 =>
                {
                    return Err(invalid())
                }
                rusqlite::types::ValueRef::Text(bytes) if bytes.len() > 512 * 1024 => {
                    return Err(invalid())
                }
                _ => {}
            }
        }
        let values = (0..count)
            .map(|i| row.get::<_, Value>(i))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        target
            .execute(insert, rusqlite::params_from_iter(values))
            .map_err(db)?;
    }
    Ok(())
}
impl Store {
    /// Native witness check and SQLite read snapshot are one critical section.
    /// This never installs the copied witness at the portable destination.
    pub(crate) fn backup_snapshot(
        &mut self,
        target: &mut Connection,
        identity: &KeystoreData,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let (expected, keys) = owner(identity)?;
        if expected.scope() != self.owner.scope() {
            return Err(invalid());
        }
        self.owner.keys(&keys)?;
        self.trust.read_checked(|source| {
            if source.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope=?1 AND kind IN ('disappearing_message_trial','disappearing_clock_trial'))",[format!("expiry-trial:{}",expected.scope())],|r|r.get::<_,bool>(0)).map_err(db)? {
                return Err("期限技术验证档案尚无便携恢复格式；拒绝导出会遗漏期限的备份".into());
            }
            ordering::check(source, &expected.scope())?;
            let backup = rusqlite::backup::Backup::new(source, target).map_err(db)?;
            loop {
                check_cancel(cancel)?;
                match backup.step(128).map_err(db)? {
                    rusqlite::backup::StepResult::Done => return Ok(()),
                    rusqlite::backup::StepResult::More => {}
                    _ => return Err("数据库忙，请稍后重试备份".into()),
                }
            }
        })
    }
}
fn validate_records(store: &mut Store, keys: &KeyPair, cancel: &AtomicBool) -> Result<(), String> {
    let owner = store.owner.clone();
    store.trust.read_checked(|conn| {
        ordering::check(conn, &owner.scope())?;
        let mut q = conn
            .prepare("SELECT id FROM direct_v3_records WHERE scope=?1 ORDER BY rowid")
            .map_err(db)?;
        let ids = q
            .query_map([owner.scope()], |r| r.get::<_, String>(0))
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        for id in ids {
            check_cancel(cancel)?;
            let row = record(conn, &owner.scope(), &id)?.ok_or_else(invalid)?;
            let (batch, local) = checked_record(conn, &owner, &row, keys)?;
            if row.outcome == "processed" {
                let (sender, peer) = evidence(conn, &batch)?;
                let plain = Zeroizing::new(
                    if row.role == "authored" {
                        batch.open_authored(&sender, &peer, keys)
                    } else {
                        batch.open(
                            &sender,
                            &peer,
                            &owner.account,
                            &owner.device.device_id,
                            keys,
                        )
                    }
                    .map_err(|_| invalid())?,
                );
                if *plain != local.body {
                    return Err(invalid());
                }
                if batch.header.kind != Kind::Text {
                    Descriptor::from_body(&batch.header, &plain).map_err(|_| invalid())?;
                }
            } else if !local.body.is_empty() {
                return Err(invalid());
            }
            operations::projection(conn, &owner, &batch, keys)?;
        }
        Ok(())
    })
}
/// The input is an already native-checked snapshot. Restoring instead consumes
/// only the portable tables and checks every signature using code-owned schema.
pub(crate) fn rebuild(
    source: &Connection,
    target: &Connection,
    identity: &KeystoreData,
    include_media: bool,
    cancel: &AtomicBool,
    restoring: bool,
) -> Result<Summary, String> {
    let (owner, keys) = owner(identity)?;
    target.execute_batch(SCHEMA).map_err(db)?;
    target
        .execute_batch(history_transfer::ARCHIVE_SCHEMA)
        .map_err(db)?;
    if restoring {
        validate_schema(source)?;
        for (query, insert, count) in [
            ("SELECT scope FROM backup_direct_identity", "INSERT INTO backup_direct_identity VALUES(?)", 1),
            ("SELECT origin,account,anchor,revision,head FROM backup_direct_roots", "INSERT INTO backup_direct_roots VALUES(?,?,?,?,?)", 5),
            ("SELECT origin,account,revision,event_id,payload FROM backup_direct_events", "INSERT INTO backup_direct_events VALUES(?,?,?,?,?)", 5),
            ("SELECT cursor,scope,id,stream,sequence,wire,digest,local,role,outcome,accepted_at FROM backup_direct_records", "INSERT INTO backup_direct_records VALUES(?,?,?,?,?,?,?,?,?,?,?)", 11),
            ("SELECT scope,id FROM backup_direct_hidden", "INSERT INTO backup_direct_hidden VALUES(?,?)", 2),
            ("SELECT position,accepted_at,wire FROM backup_direct_operations", "INSERT INTO backup_direct_operations VALUES(?,?,?)", 3),
            ("SELECT peer,body FROM backup_direct_preferences", "INSERT INTO backup_direct_preferences VALUES(?,?)", 2),
            ("SELECT id,ciphertext FROM backup_direct_media", "INSERT INTO backup_direct_media VALUES(?,?)", 2),
        ] { copy(source, target, query, insert, &[], count, cancel)?; }
        if source
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='backup_direct_history')",
                [],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db)?
        {
            copy(
                source,
                target,
                "SELECT id,revision,body FROM backup_direct_history",
                "INSERT INTO backup_direct_history VALUES(?,?,?)",
                &[],
                3,
                cancel,
            )?;
            copy(
                source,
                target,
                "SELECT id,part,ciphertext FROM backup_direct_history_chunks",
                "INSERT INTO backup_direct_history_chunks VALUES(?,?,?)",
                &[],
                3,
                cancel,
            )?;
        }
    } else {
        // Confirmed received packages are history, not online task backups.
        // Their root-signed sealed payload is indivisible, including any media
        // explicitly included by the source at the time of that grant.
        history_transfer::archive_copy(source, target, &owner, &keys)?;
        target
            .execute(
                "INSERT INTO backup_direct_identity VALUES(?1)",
                [owner.scope()],
            )
            .map_err(db)?;
        copy(source, target, "SELECT origin,account,anchor,revision,head FROM trusted_device_anchors WHERE origin=?1", "INSERT INTO backup_direct_roots VALUES(?,?,?,?,?)", &[&owner.origin], 5, cancel)?;
        copy(source, target, "SELECT origin,account,revision,event_id,payload FROM trusted_device_events WHERE origin=?1", "INSERT INTO backup_direct_events VALUES(?,?,?,?,?)", &[&owner.origin], 5, cancel)?;
        copy(source, target, "SELECT rowid,scope,id,stream,sequence,wire,digest,local,role,outcome,accepted_at FROM direct_v3_records WHERE scope=?1", "INSERT INTO backup_direct_records VALUES(?,?,?,?,?,?,?,?,?,?,?)", &[&owner.scope()], 11, cancel)?;
        copy(
            source,
            target,
            "SELECT scope,id FROM direct_v3_hidden WHERE scope=?1",
            "INSERT INTO backup_direct_hidden VALUES(?,?)",
            &[&owner.scope()],
            2,
            cancel,
        )?;
        for event in operations::archive_events(source, &owner, &keys)? {
            check_cancel(cancel)?;
            target
                .execute(
                    "INSERT INTO backup_direct_operations VALUES(?1,?2,?3)",
                    params![
                        event.order,
                        event.accepted_at,
                        event.operation.to_wire().map_err(|_| invalid())?
                    ],
                )
                .map_err(db)?;
        }
        let mut q = target.prepare("SELECT account FROM backup_direct_roots WHERE account!=?1 ORDER BY account LIMIT 130").map_err(db)?;
        let peers = q
            .query_map([&owner.account], |r| r.get::<_, String>(0))
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        if peers.len() > 128 {
            return Err(invalid());
        }
        for peer in peers {
            check_cancel(cancel)?;
            let draft = drafts::load(source, &owner, &peer, &keys)?;
            let state = conversations::load(source, &owner, &peer, &keys)?;
            let preference = Preference {
                domain: "LiteSeal/direct-archive-preference/v1".into(),
                scope: owner.scope(),
                peer: peer.clone(),
                draft: draft.text,
                muted: state.muted,
                read_through: state.read_through,
            };
            let plain = Zeroizing::new(serde_json::to_vec(&preference).map_err(|_| invalid())?);
            let body = crypto::encrypt(&plain, &keys.public_key, &keys.secret_key)
                .map_err(|_| invalid())?;
            target
                .execute(
                    "INSERT INTO backup_direct_preferences VALUES(?1,?2)",
                    params![peer, body],
                )
                .map_err(db)?;
        }
        if include_media {
            let mut q = source.prepare("SELECT id FROM direct_v3_records WHERE scope=?1 AND outcome='processed' ORDER BY rowid").map_err(db)?;
            let ids = q
                .query_map([owner.scope()], |r| r.get::<_, String>(0))
                .map_err(db)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db)?;
            for id in ids {
                check_cancel(cancel)?;
                let row = record(source, &owner.scope(), &id)?.ok_or_else(invalid)?;
                let (batch, local) = checked_record(source, &owner, &row, &keys)?;
                if batch.header.kind == Kind::Text {
                    continue;
                }
                let descriptor =
                    Descriptor::from_body(&batch.header, &local.body).map_err(|_| invalid())?;
                // Missing/partial/disposable corrupt caches are explicitly absent.
                let cache = (|| {
                    let job = media::load(source, &owner, &id, &keys)?;
                    if !matches!(job.phase, media::Phase::Prepared | media::Phase::Cached)
                        || job.next
                            != (descriptor.size as usize + 40)
                                .div_ceil(liteseal_shared::direct_media::CHUNK)
                        || job.descriptor.to_body(job.kind).map_err(|_| invalid())? != local.body
                    {
                        return Err(invalid());
                    }
                    let bytes = media::ciphertext(source, &owner, &job)?;
                    let _plain = Zeroizing::new(
                        descriptor
                            .decrypt(batch.header.kind, &bytes)
                            .map_err(|_| invalid())?,
                    );
                    Ok::<_, String>(bytes)
                })();
                if let Ok(bytes) = cache {
                    target
                        .execute(
                            "INSERT INTO backup_direct_media VALUES(?1,?2)",
                            params![id, bytes],
                        )
                        .map_err(db)?;
                }
            }
        }
    }
    let mut store = projection(target, identity, cancel)?;
    validate_records(&mut store, &keys, cancel)?;
    let mut messages: u64 = target
        .query_row("SELECT COUNT(*) FROM backup_direct_records", [], |r| {
            r.get(0)
        })
        .map_err(db)?;
    let (transferred, transferred_attachments, transferred_missing) =
        history_transfer::archive_summary(&store.trust.conn, &owner, &keys)?;
    messages += transferred;
    let mut attachments = 0;
    let mut bytes = 0usize;
    let mut q = target
        .prepare("SELECT id,ciphertext FROM backup_direct_media")
        .map_err(db)?;
    let mut rows = q.query([]).map_err(db)?;
    while let Some(row) = rows.next().map_err(db)? {
        check_cancel(cancel)?;
        let id: String = row.get(0).map_err(db)?;
        let ciphertext: Vec<u8> = row.get(1).map_err(db)?;
        bytes = bytes
            .checked_add(ciphertext.len())
            .filter(|v| *v <= 256 * 1024 * 1024)
            .ok_or_else(invalid)?;
        let original = record(&store.trust.conn, &owner.scope(), &id)?.ok_or_else(invalid)?;
        let (batch, local) = checked_record(&store.trust.conn, &owner, &original, &keys)?;
        if original.outcome != "processed" {
            return Err(invalid());
        }
        let descriptor =
            Descriptor::from_body(&batch.header, &local.body).map_err(|_| invalid())?;
        let _plain = Zeroizing::new(
            descriptor
                .decrypt(batch.header.kind, &ciphertext)
                .map_err(|_| invalid())?,
        );
        attachments += 1;
    }
    let media_count: u64 = store.trust.conn.query_row("SELECT COUNT(*) FROM direct_v3_records WHERE outcome='processed' AND json_extract(CAST(wire AS TEXT),'$.header.kind')!='text'", [], |r| r.get(0)).map_err(db)?;
    Ok(Summary {
        messages,
        attachments: attachments + transferred_attachments,
        missing_attachments: media_count.saturating_sub(attachments) + transferred_missing,
        ..Summary::default()
    })
}
fn projection(
    source: &Connection,
    identity: &KeystoreData,
    cancel: &AtomicBool,
) -> Result<Store, String> {
    let (owner, keys) = owner(identity)?;
    let scopes: Vec<String> = source
        .prepare("SELECT scope FROM backup_direct_identity")
        .map_err(db)?
        .query_map([], |r| r.get(0))
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)?;
    if scopes != vec![owner.scope()] {
        return Err(invalid());
    }
    let conn = Connection::open_in_memory().map_err(db)?;
    conn.execute_batch(super::super::SCHEMA).map_err(db)?;
    conn.execute_batch(super::super::tasks::SCHEMA)
        .map_err(db)?;
    conn.execute_batch(super::SCHEMA).map_err(db)?;
    conn.execute_batch(media::SCHEMA).map_err(db)?;
    copy(
        source,
        &conn,
        "SELECT origin,account,anchor,revision,head FROM backup_direct_roots",
        "INSERT INTO trusted_device_anchors VALUES(?,?,?,?,?)",
        &[],
        5,
        cancel,
    )?;
    copy(
        source,
        &conn,
        "SELECT origin,account,revision,event_id,payload FROM backup_direct_events",
        "INSERT INTO trusted_device_events VALUES(?,?,?,?,?)",
        &[],
        5,
        cancel,
    )?;
    copy(source, &conn, "SELECT cursor,scope,id,stream,sequence,wire,digest,local,role,outcome,accepted_at FROM backup_direct_records", "INSERT INTO direct_v3_records(rowid,scope,id,stream,sequence,wire,digest,local,role,outcome,accepted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", &[], 11, cancel)?;
    copy(
        source,
        &conn,
        "SELECT scope,id FROM backup_direct_hidden",
        "INSERT INTO direct_v3_hidden VALUES(?,?)",
        &[],
        2,
        cancel,
    )?;
    let bad: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM direct_v3_records WHERE scope!=?1 OR rowid<=0) OR EXISTS(SELECT 1 FROM direct_v3_hidden h WHERE scope!=?1) OR EXISTS(SELECT 1 FROM trusted_device_anchors WHERE origin!=?2) OR EXISTS(SELECT 1 FROM trusted_device_events e WHERE NOT EXISTS(SELECT 1 FROM trusted_device_anchors a WHERE a.origin=e.origin AND a.account=e.account))", params![owner.scope(),owner.origin], |r| r.get(0)).map_err(db)?;
    if bad {
        return Err(invalid());
    }
    let mut store = Store {
        trust: DeviceTrustStore {
            conn,
            witness: None,
        },
        owner,
    };
    let roots = store.roots(&keys)?;
    if !roots.iter().any(|a| a.account == store.owner.account) {
        return Err(invalid());
    }
    history_transfer::archive_project(source, &store.trust.conn, &store.owner, &keys)?;
    history_transfer::archive_hidden(&store.trust.conn, &store.owner, &keys)?;
    ordering::initialize(&store.trust.conn, &store.owner.scope())?;
    let mut q = source
        .prepare("SELECT position,accepted_at,wire FROM backup_direct_operations ORDER BY position")
        .map_err(db)?;
    let mut rows = q.query([]).map_err(db)?;
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(db)? {
        check_cancel(cancel)?;
        count += 1;
        if count > liteseal_shared::direct_operation::MAX_EVENTS as usize {
            return Err(invalid());
        }
        let wire: Vec<u8> = row.get(2).map_err(db)?;
        let operation = Operation::from_wire(&wire).map_err(|_| invalid())?;
        let (sender, peer) = evidence(&store.trust.conn, &operation.original)?;
        let original = if operation.original.header.sender == store.owner.account {
            &sender
        } else {
            &peer
        };
        operations::persist_event(
            &store.trust.conn,
            &store.owner,
            &Event {
                order: row.get(0).map_err(db)?,
                accepted_at: row.get(1).map_err(db)?,
                operation,
            },
            store.owner.member(original)?,
            &keys,
        )?;
    }
    let preferences = preferences(source, &store.owner, &keys)?;
    let expected: std::collections::BTreeSet<_> = roots
        .iter()
        .filter(|a| a.account != store.owner.account)
        .map(|a| a.account.clone())
        .collect();
    if preferences
        .iter()
        .map(|p| p.peer.clone())
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err(invalid());
    }
    for preference in preferences {
        current(&store.trust.conn, &store.owner.origin, &preference.peer)?;
        let max: i64 = store
            .trust
            .conn
            .query_row(
                "SELECT COALESCE(MAX(rowid),0) FROM direct_v3_records",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        if preference.read_through > max {
            return Err(invalid());
        }
    }
    Ok(store)
}
fn preferences(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<Vec<Preference>, String> {
    let mut q = conn
        .prepare("SELECT peer,body FROM backup_direct_preferences LIMIT 130")
        .map_err(db)?;
    let rows = q
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    if rows.len() > 128 {
        return Err(invalid());
    }
    rows.into_iter()
        .map(|(peer, bytes)| {
            let plain = Zeroizing::new(
                crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key)
                    .map_err(|_| invalid())?,
            );
            let p: Preference = serde_json::from_slice(&plain).map_err(|_| invalid())?;
            if p.domain != "LiteSeal/direct-archive-preference/v1"
                || p.scope != owner.scope()
                || p.peer != peer
                || p.peer == owner.account
                || p.draft.len() > d::MAX_BODY
                || p.read_through < 0
            {
                return Err(invalid());
            }
            Ok(p)
        })
        .collect()
}
/// No native witness, credentials, scheduler, ACK or mutation API is exposed.
pub struct Reader {
    source: Connection,
    store: Store,
}
impl Reader {
    pub fn open(path: &Path, identity: &KeystoreData) -> Result<Self, String> {
        let source =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(db)?;
        source
            .execute_batch("PRAGMA trusted_schema=OFF;")
            .map_err(db)?;
        validate_schema(&source)?;
        let cancel = AtomicBool::new(false);
        let mut store = projection(&source, identity, &cancel)?;
        validate_records(
            &mut store,
            &crate::backup::identity_keys(identity)?,
            &cancel,
        )?;
        Ok(Self { source, store })
    }
    pub fn conversations(&mut self, keys: &KeyPair) -> Result<Vec<Conversation>, String> {
        self.store.owner.keys(keys)?;
        preferences(&self.source, &self.store.owner, keys)?
            .into_iter()
            .map(|p| {
                Ok(Conversation {
                    peer: p.peer.clone(),
                    muted: p.muted,
                    read_through: p.read_through,
                    draft: p.draft.clone(),
                })
            })
            .collect()
    }
    pub fn history(
        &mut self,
        peer: &str,
        before: Option<i64>,
        limit: usize,
        keys: &KeyPair,
    ) -> Result<Vec<RecordView>, String> {
        self.store.history_peer(Some(peer), before, limit, keys)
    }
    pub fn body(&mut self, id: &str, keys: &KeyPair) -> Result<Vec<u8>, String> {
        self.store.body(id, keys)
    }
    pub fn transferred_history(
        &mut self,
        peer: &str,
        keys: &KeyPair,
    ) -> Result<Vec<history_transfer::HistoryRecord>, String> {
        self.store.transferred_history(Some(peer), keys)
    }
    pub fn transferred_media(
        &mut self,
        id: &str,
        keys: &KeyPair,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.store.transferred_media(id, keys)
    }
    pub fn has_media(&self, id: &str) -> Result<bool, String> {
        self.source
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM backup_direct_media WHERE id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(db)
    }
    pub fn media(&mut self, id: &str, keys: &KeyPair) -> Result<(Descriptor, Vec<u8>), String> {
        let body = Zeroizing::new(self.store.body(id, keys)?);
        let row =
            record(&self.store.trust.conn, &self.store.owner.scope(), id)?.ok_or_else(invalid)?;
        let (batch, _) = checked_record(&self.store.trust.conn, &self.store.owner, &row, keys)?;
        let descriptor = Descriptor::from_body(&batch.header, &body).map_err(|_| invalid())?;
        let ciphertext: Vec<u8> = self
            .source
            .query_row(
                "SELECT ciphertext FROM backup_direct_media WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(|_| "附件未包含完整认证缓存")?;
        let bytes = descriptor
            .decrypt(batch.header.kind, &ciphertext)
            .map_err(|_| invalid())?;
        Ok((descriptor, bytes))
    }
}
