//! Explicit history grants and local copies. Neither lane inserts original
//! deliveries, stream heads, ACKs, unread markers, drafts or author tasks.
use super::*;
use liteseal_shared::{
    direct_media::Descriptor,
    direct_operation::Action,
    history_transfer::{self as h, Envelope, Evidence},
};
use std::collections::{BTreeMap, BTreeSet};

const KIND: &str = "authorized_history_transfer";
const CHUNK: usize = 1024 * 1024;
const LIMIT: i64 = 256 * 1024 * 1024;
const MAX_RECEIPTS: usize = 32;
const MAX_ROWS: usize = 1024;
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS direct_v3_history_chunks(
 scope TEXT NOT NULL,account TEXT NOT NULL,id TEXT NOT NULL,part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 129),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 1048576),PRIMARY KEY(scope,id,part));";
pub(super) fn validate_cache(conn: &Connection) -> Result<(), String> {
    let mut q=conn.prepare("SELECT type,name,sql FROM sqlite_schema WHERE tbl_name='direct_v3_history_chunks' ORDER BY type").map_err(db)?;
    let entries = q
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    let expected = SCHEMA.replace(" IF NOT EXISTS", "");
    if entries
        != vec![
            (
                "index".into(),
                "sqlite_autoindex_direct_v3_history_chunks_1".into(),
                None,
            ),
            (
                "table".into(),
                "direct_v3_history_chunks".into(),
                Some(expected.trim_end_matches(';').into()),
            ),
        ]
    {
        return Err("授权历史密文结构无法验证，已保留原数据".into());
    }
    Ok(())
}
fn scope(owner: &Owner) -> String {
    format!("history:{}", owner.scope())
}
fn canonical(id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(id).is_ok_and(|id2| id2.to_string() == id) {
        Ok(())
    } else {
        Err(invalid())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Prepared,
    Imported,
    Cancelled,
}
#[derive(Serialize)]
pub struct View {
    pub id: String,
    pub revision: u64,
    pub state: State,
    pub peer: String,
    pub source_device: String,
    pub target_device: String,
    pub selected: usize,
    pub created_at: i64,
    pub expires_at: i64,
    pub digest: [u8; 32],
    pub bytes: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    domain: String,
    scope: String,
    pub(super) revision: u64,
    pub(super) state: State,
    header: h::Header,
    digest: [u8; 32],
    size: usize,
    hashes: Vec<[u8; 32]>,
    include_media: bool,
}
impl Receipt {
    fn view(&self) -> View {
        View {
            id: self.header.id.clone(),
            revision: self.revision,
            state: self.state,
            peer: self.header.peer.clone(),
            source_device: self.header.source.device_id.clone(),
            target_device: self.header.target.device.device_id.clone(),
            selected: self.header.selection.len(),
            created_at: self.header.created_at,
            expires_at: self.header.expires_at,
            digest: self.digest,
            bytes: self.size,
        }
    }
}
pub struct PrepareHistory<'a> {
    pub id: &'a str,
    pub peer: &'a str,
    pub target: &'a str,
    pub selection: &'a [String],
    pub created_at: i64,
    pub include_media: bool,
}
#[derive(Serialize)]
pub struct HistoryRecord {
    pub id: String,
    pub peer: String,
    pub sender: String,
    pub sender_device: String,
    pub sent_at: i64,
    pub accepted_at: i64,
    pub operation_revision: u64,
    pub retracted: bool,
    pub kind: Kind,
    pub text: Option<String>,
    pub media: Option<MediaInfo>,
    pub transfer: String,
    pub verification: &'static str,
}
#[derive(Serialize)]
pub struct MediaInfo {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub duration_ms: Option<u32>,
    pub cached: bool,
}
pub(super) fn load(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<Option<Receipt>, String> {
    canonical(id)?;
    let row = conn
        .query_row(
            "SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2",
            params![scope(owner), id],
            |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(db)?;
    let Some((revision, kind, terminal, bytes)) = row else {
        return Ok(None);
    };
    if kind != KIND || !terminal || bytes.len() > 65576 {
        return Err(invalid());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    let receipt: Receipt = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if receipt.domain != "LiteSeal/history-receipt/v1"
        || receipt.scope != owner.scope()
        || receipt.revision != revision
        || revision == 0
        || receipt.header.id != id
        || receipt.state != State::Cancelled && receipt.size < 52
        || receipt.state == State::Cancelled && receipt.size != 0
        || receipt.size > h::MAX_WIRE + 40
        || receipt.hashes.len() != receipt.size.div_ceil(CHUNK)
        || receipt.digest == [0; 32]
    {
        return Err(invalid());
    }
    if receipt.header.origin != owner.origin || receipt.header.account != owner.account {
        return Err(invalid());
    }
    let device = if receipt.state == State::Imported {
        &receipt.header.target.device
    } else {
        &receipt.header.source
    };
    if device != &owner.device {
        return Err(invalid());
    }
    Ok(Some(receipt))
}
fn save(conn: &Connection, owner: &Owner, r: &Receipt, keys: &KeyPair) -> Result<(), String> {
    let plain = Zeroizing::new(serde_json::to_vec(r).map_err(|_| invalid())?);
    if plain.len() > 65536 {
        return Err("选定历史的证据过大，请分成更小的批次".into());
    }
    let bytes =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5) ON CONFLICT(scope,id) DO UPDATE SET revision=excluded.revision,body=excluded.body",params![scope(owner),r.header.id,r.revision,KIND,bytes]).map_err(db)?;
    Ok(())
}
fn receipts(conn: &Connection, owner: &Owner, keys: &KeyPair) -> Result<Vec<Receipt>, String> {
    let mut q = conn
        .prepare("SELECT id FROM device_control_tasks WHERE scope=?1 ORDER BY id LIMIT 1025")
        .map_err(db)?;
    let ids = q
        .query_map([scope(owner)], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    if ids.len() > MAX_ROWS {
        return Err(invalid());
    }
    ids.iter()
        .map(|id| load(conn, owner, id, keys)?.ok_or_else(invalid))
        .collect()
}
pub(super) fn wire(
    conn: &Connection,
    owner: &Owner,
    r: &Receipt,
    keys: &KeyPair,
) -> Result<Envelope, String> {
    validate_cache(conn)?;
    let mut bytes = Vec::with_capacity(r.size);
    for (part, hash) in r.hashes.iter().enumerate() {
        let length = (r.size - part * CHUNK).min(CHUNK);
        let chunk:Vec<u8>=conn.query_row("SELECT substr(ciphertext,1,?5) FROM direct_v3_history_chunks WHERE scope=?1 AND id=?2 AND part=?3 AND account=?4 AND length(ciphertext)=?5",params![owner.scope(),r.header.id,part as i64,owner.account,length],|r|r.get(0)).map_err(db)?;
        if <[u8; 32]>::from(Sha256::digest(&chunk)) != *hash {
            return Err("授权历史密文损坏；未读取正文".into());
        }
        bytes.extend(chunk);
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    let envelope = Envelope::from_wire(&plain).map_err(|_| invalid())?;
    if envelope.header != r.header || envelope.digest().map_err(|_| invalid())? != r.digest {
        return Err(invalid());
    }
    Ok(envelope)
}
fn historical(conn: &Connection, owner: &Owner, r: &Receipt) -> Result<DeviceState, String> {
    let anchor = super::super::resolve(conn, &owner.origin, &owner.account)?;
    super::super::read_at(
        conn,
        &anchor,
        &Checkpoint {
            revision: r.header.directory.revision,
            hash: r.header.directory.head.to_vec(),
        },
    )
}
fn records(
    conn: &Connection,
    owner: &Owner,
    r: &Receipt,
    keys: &KeyPair,
) -> Result<Vec<h::Record>, String> {
    if r.state != State::Imported {
        return Err(invalid());
    }
    wire(conn, owner, r, keys)?
        .open_received(&historical(conn, owner, r)?, keys)
        .map_err(|_| invalid())
}
fn selected(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
    request: &PrepareHistory<'_>,
) -> Result<Vec<h::Record>, String> {
    if request.selection.is_empty() || request.selection.len() > h::MAX_ITEMS {
        return Err("每批请选择 1–64 条已确认消息".into());
    }
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    for id in request.selection {
        canonical(id)?;
        if !ids.insert(id) {
            return Err(invalid());
        }
        let row = record(conn, &owner.scope(), id)?.ok_or_else(invalid)?;
        let cursor:i64=conn.query_row("SELECT rowid FROM direct_v3_records WHERE scope=?1 AND id=?2 AND NOT EXISTS(SELECT 1 FROM direct_v3_hidden WHERE scope=?1 AND id=?2)",params![owner.scope(),id],|r|r.get(0)).map_err(db)?;
        if row.outcome != "processed" {
            return Err("无法迁移未认证或未接受的消息".into());
        }
        rows.push((cursor, row));
    }
    rows.sort_by_key(|(cursor, _)| *cursor);
    let events = operations::archive_events(conn, owner, keys)?;
    let proof = |state: &DeviceState| -> Result<Evidence, String> {
        let mut q=conn.prepare("SELECT payload FROM trusted_device_events WHERE origin=?1 AND account=?2 AND revision<=?3 ORDER BY revision LIMIT 10001").map_err(db)?;
        let events = q
            .query_map(
                params![
                    state.anchor().origin,
                    state.anchor().account,
                    state.revision()
                ],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map_err(db)?
            .map(|v| serde_json::from_slice(&v.map_err(db)?).map_err(|_| invalid()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Evidence {
            anchor: state.anchor().clone(),
            events,
        })
    };
    let mut remaining = h::MAX_PLAIN - 1024;
    rows.into_iter()
        .map(|(_, row)| {
            let (original, local) = checked_record(conn, owner, &row, keys)?;
            let other = if original.header.sender == owner.account {
                &original.header.peer
            } else {
                &original.header.sender
            };
            if other != request.peer {
                return Err("选择的消息不属于此会话".into());
            }
            let (sender, peer) = evidence(conn, &original)?;
            let (revision, action, text) = operations::projection(conn, owner, &original, keys)?;
            let operations = events
                .iter()
                .filter(|e| e.operation.original.header.id == row.id)
                .map(|e| e.operation.clone())
                .collect::<Vec<_>>();
            if operations.last().map_or(0, |o| o.header.revision) != revision {
                return Err(invalid());
            }
            let mut record = h::Record {
                original,
                sender: proof(&sender)?,
                peer: proof(&peer)?,
                accepted_at: row.accepted_at,
                operations,
                text: None,
                media: None,
            };
            if action != Some(Action::Retract) {
                if record.original.header.kind == Kind::Text {
                    record.text = Some(if action == Some(Action::Edit) {
                        text.ok_or_else(invalid)?
                    } else {
                        String::from_utf8(local.body.clone()).map_err(|_| invalid())?
                    });
                } else {
                    let descriptor = Descriptor::from_body(&record.original.header, &local.body)
                        .map_err(|_| invalid())?;
                    let ciphertext = if request.include_media {
                        (|| {
                            let job = media::load(conn, owner, &row.id, keys)?;
                            if !matches!(job.phase, media::Phase::Prepared | media::Phase::Cached)
                                || job.next
                                    != (descriptor.size as usize + 40)
                                        .div_ceil(liteseal_shared::direct_media::CHUNK)
                                || job.descriptor.to_body(job.kind).map_err(|_| invalid())?
                                    != local.body
                            {
                                return Err(invalid());
                            }
                            let bytes = media::ciphertext(conn, owner, &job)?;
                            let _plain = Zeroizing::new(
                                descriptor
                                    .decrypt(record.original.header.kind, &bytes)
                                    .map_err(|_| invalid())?,
                            );
                            Ok::<_, String>(bytes)
                        })()
                        .ok()
                    } else {
                        None
                    };
                    record.media = Some(h::Media {
                        descriptor,
                        ciphertext,
                    });
                }
            }
            let size = record
                .bounded_plain_size(remaining)
                .map_err(|_| "选定历史超过单批大小限制，请减少消息或媒体数量".to_string())?;
            remaining = remaining.checked_sub(size + 1).ok_or_else(invalid)?;
            Ok(record)
        })
        .collect()
}
fn persist(
    store: &mut Store,
    envelope: &Envelope,
    state: State,
    include_media: bool,
    keys: &KeyPair,
) -> Result<View, String> {
    let owner = store.owner.clone();
    let plain = Zeroizing::new(envelope.to_wire().map_err(|_| invalid())?);
    let ciphertext =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    let r = Receipt {
        domain: "LiteSeal/history-receipt/v1".into(),
        scope: owner.scope(),
        revision: 1,
        state,
        header: envelope.header.clone(),
        digest: envelope.digest().map_err(|_| invalid())?,
        size: ciphertext.len(),
        hashes: ciphertext
            .chunks(CHUNK)
            .map(|bytes| Sha256::digest(bytes).into())
            .collect(),
        include_media,
    };
    // A receipt is the commit marker; a crash before it leaves only collectible
    // ciphertext. Large chunks stay outside the native 4 MiB patch journal.
    store.trust.write_checked(|conn|{
        validate_cache(conn)?;
        if load(conn,&owner,&r.header.id,keys)?.is_some() {return Err(conflict())}
        let previous=receipts(conn,&owner,keys)?;
        if previous.len()>=MAX_ROWS||previous.iter().filter(|r|r.state!=State::Cancelled).count()>=MAX_RECEIPTS {return Err("授权历史达到本机数量上限，请先停止已完成的导出批次；已导入副本保持保留".into())}
        conn.execute("DELETE FROM direct_v3_history_chunks WHERE scope=?1 AND NOT EXISTS(SELECT 1 FROM device_control_tasks t WHERE t.scope=?2 AND t.id=direct_v3_history_chunks.id AND t.kind=?3)",params![owner.scope(),scope(&owner),KIND]).map_err(db)?;
        let bytes:i64=conn.query_row("SELECT COALESCE(SUM(length(ciphertext)),0) FROM direct_v3_history_chunks WHERE account=?1",[&owner.account],|r|r.get(0)).map_err(db)?;
        if bytes+ciphertext.len() as i64>LIMIT {return Err("授权历史密文达到 256 MiB，请先整理已完成批次".into())}
        for (part,bytes) in ciphertext.chunks(CHUNK).enumerate() {conn.execute("INSERT INTO direct_v3_history_chunks(scope,account,id,part,ciphertext) VALUES(?1,?2,?3,?4,?5)",params![owner.scope(),owner.account,r.header.id,part as i64,bytes]).map_err(db)?;}
        Ok(())
    })?;
    store.trust.write_checked(|conn| {
        let current = current(conn, &owner.origin, &owner.account)?;
        envelope.verify(&current).map_err(|_| invalid())?;
        if state == State::Imported {
            let imported = envelope
                .open_received(&current, keys)
                .map_err(|_| invalid())?;
            check_revision(conn, &owner, &imported, keys)?;
        }
        wire(conn, &owner, &r, keys)?;
        save(conn, &owner, &r, keys)
    })?;
    Ok(r.view())
}
impl Store {
    pub fn validate_history_import(
        &mut self,
        envelope: &Envelope,
        now: i64,
        keys: &KeyPair,
    ) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let own = current(conn, &owner.origin, &owner.account)?;
            let imported = envelope.open(&own, keys, now).map_err(|_| invalid())?;
            if envelope.header.account != owner.account
                || envelope.header.target.device != owner.device
            {
                return Err(invalid());
            }
            let contact = current(conn, &owner.origin, &envelope.header.peer)?;
            for record in &imported {
                let other = if record.original.header.sender == owner.account {
                    &record.peer.anchor
                } else {
                    &record.sender.anchor
                };
                if other != contact.anchor() {
                    return Err("请先核对迁移会话的联系人根指纹".into());
                }
            }
            check_revision(conn, &owner, &imported, keys)
        })
    }
    pub fn prepare_history(
        &mut self,
        request: PrepareHistory<'_>,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        canonical(request.id)?;
        let owner = self.owner.clone();
        if let Some(saved) = self
            .trust
            .read_checked(|conn| load(conn, &owner, request.id, keys))?
        {
            let ids = saved
                .header
                .selection
                .iter()
                .map(|r| &r.id)
                .collect::<BTreeSet<_>>();
            if saved.state != State::Prepared
                || saved.header.peer != request.peer
                || saved.header.target.device.device_id != request.target
                || saved.header.created_at != request.created_at
                || saved.include_media != request.include_media
                || ids != request.selection.iter().collect::<BTreeSet<_>>()
                || ids.len() != request.selection.len()
            {
                return Err(conflict());
            }
            return Ok(saved.view());
        }
        let envelope = self.trust.read_checked(|conn| {
            ordering::check(conn, &owner.scope())?;
            let own = current(conn, &owner.origin, &owner.account)?;
            if own.anchor().root != owner.device {
                return Err("只有原根设备可以授权历史".into());
            }
            let directory = d::Directory::from_state(&own);
            let target = directory
                .members
                .iter()
                .find(|m| m.device.device_id == request.target && m.device != owner.device)
                .ok_or_else(invalid)?
                .clone();
            let records = selected(conn, &owner, keys, &request)?;
            let header = h::Header {
                version: 1,
                id: request.id.into(),
                origin: owner.origin.clone(),
                account: owner.account.clone(),
                source: owner.device.clone(),
                target,
                directory,
                peer: request.peer.into(),
                created_at: request.created_at,
                expires_at: request
                    .created_at
                    .checked_add(h::LIFETIME)
                    .ok_or_else(invalid)?,
                selection: records
                    .iter()
                    .map(|r| r.reference().map_err(|_| invalid()))
                    .collect::<Result<Vec<_>, _>>()?,
            };
            Envelope::make(header, &own, keys, records).map_err(|_| invalid())
        })?;
        persist(
            self,
            &envelope,
            State::Prepared,
            request.include_media,
            keys,
        )
    }
    pub fn history_transfers(&mut self, keys: &KeyPair) -> Result<Vec<View>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            Ok(receipts(conn, &owner, keys)?
                .iter()
                .map(Receipt::view)
                .collect())
        })
    }
    pub fn history_transfer_wire(
        &mut self,
        id: &str,
        revision: u64,
        now: i64,
        keys: &KeyPair,
    ) -> Result<Vec<u8>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let receipt = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if receipt.state != State::Prepared
                || receipt.revision != revision
                || now < receipt.header.created_at
                || now >= receipt.header.expires_at
            {
                return Err("授权历史已取消、过期或变化；不会重新签署原编号".into());
            }
            let envelope = wire(conn, &owner, &receipt, keys)?;
            envelope
                .verify(&current(conn, &owner.origin, &owner.account)?)
                .map_err(|_| invalid())?;
            envelope.to_wire().map_err(|_| invalid())
        })
    }
    pub fn cancel_history_transfer(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut r = load(conn, &owner, id, keys)?.ok_or_else(invalid)?;
            if r.state == State::Cancelled {
                return Ok(r.view());
            }
            if r.state != State::Prepared || r.revision != revision {
                return Err(conflict());
            }
            r.revision = r.revision.checked_add(1).ok_or_else(invalid)?;
            r.state = State::Cancelled;
            super::history_jobs::pause_local(conn, &owner, id, keys)?;
            r.size = 0;
            r.hashes.clear();
            save(conn, &owner, &r, keys)?;
            conn.execute(
                "DELETE FROM direct_v3_history_chunks WHERE scope=?1 AND id=?2",
                params![owner.scope(), id],
            )
            .map_err(db)?;
            Ok(r.view())
        })
    }
    /// Admission needs a freshly synchronized own directory. The coordinator
    /// supplies it; a standalone codec or restored archive cannot activate it.
    pub fn import_history(
        &mut self,
        bytes: &[u8],
        now: i64,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        let envelope = Envelope::from_wire(bytes).map_err(|_| invalid())?;
        if let Some(view) = self.trust.read_checked(|conn| {
            let Some(r) = load(conn, &owner, &envelope.header.id, keys)? else {
                return Ok(None);
            };
            if r.state != State::Imported || r.digest != envelope.digest().map_err(|_| invalid())? {
                return Err(conflict());
            }
            // Query an already committed original result even after its import
            // deadline. This cannot admit a different wire or a new transfer.
            Ok(Some(r.view()))
        })? {
            return Ok(view);
        }
        let existing = self.trust.read_checked(|conn| {
            let own = current(conn, &owner.origin, &owner.account)?;
            let imported = envelope.open(&own, keys, now).map_err(|_| invalid())?;
            if envelope.header.account != owner.account
                || envelope.header.target.device != owner.device
            {
                return Err(invalid());
            }
            // The source attests copies, but never replaces a separately pinned
            // contact root or creates an author capability in this database.
            let contact = current(conn, &owner.origin, &envelope.header.peer)?;
            for record in &imported {
                let other = if record.original.header.sender == owner.account {
                    &record.peer.anchor
                } else {
                    &record.sender.anchor
                };
                if other != contact.anchor() {
                    return Err("请先核对迁移会话的联系人根指纹".into());
                }
            }
            if let Some(r) = load(conn, &owner, &envelope.header.id, keys)? {
                if r.state != State::Imported
                    || r.digest != envelope.digest().map_err(|_| invalid())?
                {
                    return Err(conflict());
                }
                return Ok(Some(r.view()));
            }
            check_revision(conn, &owner, &imported, keys)?;
            Ok(None)
        })?;
        if let Some(view) = existing {
            return Ok(view);
        }
        persist(self, &envelope, State::Imported, false, keys)
    }
    pub fn transferred_history(
        &mut self,
        peer: Option<&str>,
        keys: &KeyPair,
    ) -> Result<Vec<HistoryRecord>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let mut result = Vec::new();
            for (id, (transfer, record)) in latest_records(conn, &owner, keys)? {
                if conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM direct_v3_hidden WHERE scope=?1 AND id=?2)",
                        params![owner.scope(), id],
                        |r| r.get::<_, bool>(0),
                    )
                    .map_err(db)?
                {
                    continue;
                }
                if let Some(row) = super::record(conn, &owner.scope(), &id)? {
                    let (original, _) = checked_record(conn, &owner, &row, keys)?;
                    if operations::projection(conn, &owner, &original, keys)?.0
                        >= record
                            .reference()
                            .map_err(|_| invalid())?
                            .operation_revision
                    {
                        continue;
                    }
                }
                let other = if record.original.header.sender == owner.account {
                    &record.original.header.peer
                } else {
                    &record.original.header.sender
                };
                if peer.is_some_and(|peer| peer != other) {
                    continue;
                }
                let retracted = record
                    .operations
                    .last()
                    .is_some_and(|o| o.header.action == Action::Retract);
                let media = record.media.as_ref().map(|media| MediaInfo {
                    name: media.descriptor.name.clone(),
                    mime: media.descriptor.mime.clone(),
                    size: media.descriptor.size,
                    duration_ms: media.descriptor.duration_ms,
                    cached: media.ciphertext.is_some(),
                });
                result.push(HistoryRecord {
                    id,
                    peer: other.clone(),
                    sender: record.original.header.sender.clone(),
                    sender_device: record.original.header.sender_device.clone(),
                    sent_at: record.original.header.sent_at,
                    accepted_at: record.accepted_at,
                    operation_revision: record
                        .reference()
                        .map_err(|_| invalid())?
                        .operation_revision,
                    retracted,
                    kind: record.original.header.kind,
                    text: record.text.clone(),
                    media,
                    transfer,
                    verification: KIND,
                });
            }
            result.sort_by(|a, b| b.accepted_at.cmp(&a.accepted_at).then(b.id.cmp(&a.id)));
            Ok(result)
        })
    }
    pub fn transferred_media(
        &mut self,
        id: &str,
        keys: &KeyPair,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            if conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM direct_v3_hidden WHERE scope=?1 AND id=?2)",
                    params![owner.scope(), id],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(db)?
            {
                return Err("此消息已在本机隐藏".into());
            }
            let entries = latest_records(conn, &owner, keys)?;
            let (_, record) = entries.get(id).ok_or_else(invalid)?;
            if record
                .operations
                .last()
                .is_some_and(|o| o.header.action == Action::Retract)
            {
                return Err("此消息已撤回".into());
            }
            let media = record.media.as_ref().ok_or_else(invalid)?;
            Ok(Zeroizing::new(
                media
                    .descriptor
                    .decrypt(
                        record.original.header.kind,
                        media
                            .ciphertext
                            .as_ref()
                            .ok_or("授权副本未包含完整媒体，请在原设备重新选择迁移")?,
                    )
                    .map_err(|_| invalid())?,
            ))
        })
    }
    pub fn hide_transferred(&mut self, id: &str, keys: &KeyPair) -> Result<(), String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            if !latest_records(conn, &owner, keys)?.contains_key(id) {
                return Err(invalid());
            }
            conn.execute(
                "INSERT OR IGNORE INTO direct_v3_hidden(scope,id) VALUES(?1,?2)",
                params![owner.scope(), id],
            )
            .map_err(db)?;
            Ok(())
        })
    }
}
fn latest_records(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<BTreeMap<String, (String, h::Record)>, String> {
    let mut result = BTreeMap::<String, (String, h::Record)>::new();
    let mut batches = receipts(conn, owner, keys)?;
    batches.sort_by(|a, b| {
        a.header
            .created_at
            .cmp(&b.header.created_at)
            .then(a.header.id.cmp(&b.header.id))
    });
    for receipt in batches.into_iter().filter(|r| r.state == State::Imported) {
        for record in records(conn, owner, &receipt, keys)? {
            let id = record.original.header.id.clone();
            let revision = record
                .reference()
                .map_err(|_| invalid())?
                .operation_revision;
            if result.get(&id).is_none_or(|(_, old)| {
                old.reference().is_ok_and(|r| {
                    r.operation_revision < revision
                        || r.operation_revision == revision
                            && !(old.media.as_ref().is_some_and(|m| m.ciphertext.is_some())
                                && record
                                    .media
                                    .as_ref()
                                    .is_some_and(|m| m.ciphertext.is_none()))
                })
            }) {
                result.insert(id, (receipt.header.id.clone(), record));
            }
        }
    }
    Ok(result)
}
pub(super) fn updates(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<BTreeMap<String, (u64, bool)>, String> {
    latest_records(conn, owner, keys)?
        .into_iter()
        .map(|(id, (_, record))| {
            Ok((
                id,
                (
                    record
                        .reference()
                        .map_err(|_| invalid())?
                        .operation_revision,
                    record
                        .operations
                        .last()
                        .is_some_and(|o| o.header.action == Action::Retract),
                ),
            ))
        })
        .collect()
}
fn check_revision(
    conn: &Connection,
    owner: &Owner,
    imported: &[h::Record],
    keys: &KeyPair,
) -> Result<(), String> {
    let old = latest_records(conn, owner, keys)?;
    for record in imported {
        if let Some(row) = super::record(conn, &owner.scope(), &record.original.header.id)? {
            let (original, _) = checked_record(conn, owner, &row, keys)?;
            if original.digest().map_err(|_| invalid())?
                != record.original.digest().map_err(|_| invalid())?
                || row.accepted_at != record.accepted_at
            {
                return Err("迁移副本与已有原投递证据冲突".into());
            }
        }
        if let Some((_, previous)) = old.get(&record.original.header.id) {
            let prior = previous.reference().map_err(|_| invalid())?;
            let next = record.reference().map_err(|_| invalid())?;
            let descriptor = |r: &h::Record| {
                r.media
                    .as_ref()
                    .map(|m| {
                        m.descriptor
                            .to_body(r.original.header.kind)
                            .map_err(|_| invalid())
                    })
                    .transpose()
            };
            if prior.digest != next.digest
                || previous.accepted_at != record.accepted_at
                || prior.operation_revision > next.operation_revision
                || previous
                    .operations
                    .iter()
                    .zip(&record.operations)
                    .any(|(a, b)| a.to_wire().ok() != b.to_wire().ok())
                || prior.operation_revision == next.operation_revision
                    && (previous.text != record.text
                        || descriptor(previous)? != descriptor(record)?)
            {
                return Err("迁移记录存在修订回退或冲突，原副本已保留".into());
            }
        }
    }
    Ok(())
}

pub(super) const ARCHIVE_SCHEMA:&str="
CREATE TABLE backup_direct_history(id TEXT PRIMARY KEY,revision INTEGER NOT NULL CHECK(revision>0),body BLOB NOT NULL CHECK(length(body)<=65576));
CREATE TABLE backup_direct_history_chunks(id TEXT NOT NULL,part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 129),ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 1048576),PRIMARY KEY(id,part));
";
pub(super) fn archive_copy(
    source: &Connection,
    target: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<(), String> {
    validate_cache(source)?;
    for receipt in receipts(source, owner, keys)?
        .into_iter()
        .filter(|r| r.state == State::Imported)
    {
        let _records = records(source, owner, &receipt, keys)?;
        let body: Vec<u8> = source
            .query_row(
                "SELECT body FROM device_control_tasks WHERE scope=?1 AND id=?2",
                params![scope(owner), receipt.header.id],
                |r| r.get(0),
            )
            .map_err(db)?;
        target
            .execute(
                "INSERT INTO backup_direct_history VALUES(?1,?2,?3)",
                params![receipt.header.id, receipt.revision, body],
            )
            .map_err(db)?;
        for part in 0..receipt.hashes.len() {
            let bytes:Vec<u8>=source.query_row("SELECT ciphertext FROM direct_v3_history_chunks WHERE scope=?1 AND id=?2 AND part=?3",params![owner.scope(),receipt.header.id,part as i64],|r|r.get(0)).map_err(db)?;
            target
                .execute(
                    "INSERT INTO backup_direct_history_chunks VALUES(?1,?2,?3)",
                    params![receipt.header.id, part as i64, bytes],
                )
                .map_err(db)?;
        }
    }
    Ok(())
}
pub(super) fn archive_project(
    source: &Connection,
    target: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<(), String> {
    target.execute_batch(SCHEMA).map_err(db)?;
    if !source
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='backup_direct_history')",
            [],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db)?
    {
        return Ok(());
    }
    let count: usize = source
        .query_row("SELECT COUNT(*) FROM backup_direct_history", [], |r| {
            r.get(0)
        })
        .map_err(db)?;
    let bytes: i64 = source
        .query_row(
            "SELECT COALESCE(SUM(length(ciphertext)),0) FROM backup_direct_history_chunks",
            [],
            |r| r.get(0),
        )
        .map_err(db)?;
    if count > MAX_RECEIPTS || bytes > LIMIT {
        return Err(invalid());
    }
    let mut q = source
        .prepare("SELECT id,revision,body FROM backup_direct_history ORDER BY id")
        .map_err(db)?;
    let mut rows = q.query([]).map_err(db)?;
    while let Some(row) = rows.next().map_err(db)? {
        let id: String = row.get(0).map_err(db)?;
        let revision: u64 = row.get(1).map_err(db)?;
        let body: Vec<u8> = row.get(2).map_err(db)?;
        target.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5)",params![scope(owner),id,revision,KIND,body]).map_err(db)?;
        let receipt = load(target, owner, &id, keys)?.ok_or_else(invalid)?;
        if receipt.state != State::Imported {
            return Err("离线档案不能包含迁移待发任务或取消记录".into());
        }
        let mut chunks=source.prepare("SELECT part,ciphertext FROM backup_direct_history_chunks WHERE id=?1 ORDER BY part").map_err(db)?;
        let parts = chunks
            .query_map([&id], |r| {
                Ok((r.get::<_, usize>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        if parts.len() != receipt.hashes.len() {
            return Err(invalid());
        }
        for (expected, (part, bytes)) in parts.into_iter().enumerate() {
            if expected != part {
                return Err(invalid());
            }
            target
                .execute(
                    "INSERT INTO direct_v3_history_chunks VALUES(?1,?2,?3,?4,?5)",
                    params![owner.scope(), owner.account, id, part as i64, bytes],
                )
                .map_err(db)?;
        }
        let _records = records(target, owner, &receipt, keys)?;
    }
    let orphan:bool=source.query_row("SELECT EXISTS(SELECT 1 FROM backup_direct_history_chunks c WHERE NOT EXISTS(SELECT 1 FROM backup_direct_history r WHERE r.id=c.id))",[],|r|r.get(0)).map_err(db)?;
    if orphan {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn archive_hidden(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<(), String> {
    let ids = latest_records(conn, owner, keys)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    let mut q=conn.prepare("SELECT id FROM direct_v3_hidden h WHERE scope=?1 AND NOT EXISTS(SELECT 1 FROM direct_v3_records r WHERE r.scope=h.scope AND r.id=h.id) LIMIT 2049").map_err(db)?;
    let rows = q
        .query_map([owner.scope()], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    if rows.len() > MAX_RECEIPTS * h::MAX_ITEMS || rows.iter().any(|id| !ids.contains(id)) {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn archive_summary(
    conn: &Connection,
    owner: &Owner,
    keys: &KeyPair,
) -> Result<(u64, u64, u64), String> {
    let mut messages = 0;
    let mut attachments = 0;
    let mut missing = 0;
    for (id, (_, record)) in latest_records(conn, owner, keys)? {
        if super::record(conn, &owner.scope(), &id)?.is_some() {
            continue;
        }
        messages += 1;
        if let Some(media) = &record.media {
            if media.ciphertext.is_some() {
                attachments += 1;
            } else {
                missing += 1;
            }
        }
    }
    Ok((messages, attachments, missing))
}
