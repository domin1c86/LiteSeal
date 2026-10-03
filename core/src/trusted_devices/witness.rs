//! External monotonic state for T23 tables. A protected write-ahead patch closes
//! the SQLite/platform-store commit gap without re-signing or resetting state.
use rusqlite::{
    params, params_from_iter,
    types::{Value, ValueRef},
    Connection, OptionalExtension, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroize;

#[cfg(target_os = "android")]
pub mod android;
pub mod platform;
#[cfg(windows)]
pub mod windows;

pub trait SecureCell {
    fn read(&mut self) -> Result<Option<Vec<u8>>, String>;
    fn write(&mut self, value: &[u8]) -> Result<(), String>;
}
/// The returned cell owns a synchronous cross-process lock; it must not cross await.
pub trait SecureStore: Send + Sync {
    fn binding(&self) -> [u8; 32];
    fn lock(&self) -> Result<Box<dyn SecureCell + '_>, String>;
}
#[derive(Clone)]
pub struct Witness {
    store: Arc<dyn SecureStore>,
    journal: PathBuf,
}
const MARKER_SQL:&str="CREATE TABLE IF NOT EXISTS device_state_witness(id INTEGER PRIMARY KEY CHECK(id=1),marker TEXT NOT NULL,binding BLOB NOT NULL CHECK(length(binding)=32),generation INTEGER NOT NULL CHECK(generation>=0),coverage INTEGER NOT NULL DEFAULT 1 CHECK(coverage IN (1,2)))";
const MAX_JOURNAL: usize = 4 * 1024 * 1024;
const MAX_STATE: u64 = 512 * 1024 * 1024;
const MAX_GENERATION: u64 = 1_000_000_000;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Point {
    generation: u64,
    hash: [u8; 32],
    #[serde(
        default = "legacy_coverage",
        skip_serializing_if = "is_legacy_coverage"
    )]
    coverage: u8,
}
fn legacy_coverage() -> u8 {
    1
}
fn is_legacy_coverage(value: &u8) -> bool {
    *value == 1
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    point: Point,
    journal_hash: Option<[u8; 32]>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    domain: String,
    binding: [u8; 32],
    marker: String,
    committed: Option<Point>,
    pending: Option<Pending>,
}
#[derive(Clone)]
struct Marker {
    id: String,
    generation: u64,
    coverage: u8,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum Cell {
    Integer(i64),
    Text(String),
    Blob(Vec<u8>),
    Null,
}
impl Cell {
    fn from(value: ValueRef<'_>) -> Result<Self, String> {
        Ok(match value {
            ValueRef::Integer(v) => Self::Integer(v),
            ValueRef::Text(v) => Self::Text(std::str::from_utf8(v).map_err(|_| invalid())?.into()),
            ValueRef::Blob(v) => Self::Blob(v.into()),
            ValueRef::Null => Self::Null,
            _ => return Err(invalid()),
        })
    }
    fn value(&self) -> Value {
        match self {
            Self::Integer(v) => Value::Integer(*v),
            Self::Text(v) => Value::Text(v.clone()),
            Self::Blob(v) => Value::Blob(v.clone()),
            Self::Null => Value::Null,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    tag: String,
    key: (String, String, i64),
    row: Option<Vec<Cell>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    domain: String,
    binding: [u8; 32],
    marker: String,
    before: Point,
    after: Point,
    patches: Vec<Patch>,
}
struct Table {
    tag: &'static str,
    name: &'static str,
    columns: &'static str,
    keys: &'static str,
    condition: &'static str,
    old: &'static str,
    new: &'static str,
}
const TABLES: [Table; 9] = [
    Table {
        tag: "anchor",
        name: "trusted_device_anchors",
        columns: "origin,account,anchor,revision,head",
        keys: "origin,account",
        condition: "origin=?1 AND account=?2 AND ?3=0",
        old: "old.origin,old.account,0",
        new: "new.origin,new.account,0",
    },
    Table {
        tag: "event",
        name: "trusted_device_events",
        columns: "origin,account,revision,event_id,payload",
        keys: "origin,account,revision",
        condition: "origin=?1 AND account=?2 AND revision=?3",
        old: "old.origin,old.account,old.revision",
        new: "new.origin,new.account,new.revision",
    },
    Table {
        tag: "task",
        name: "device_control_tasks",
        columns: "scope,id,revision,kind,terminal,body",
        keys: "scope,id",
        condition: "scope=?1 AND id=?2 AND ?3=0",
        old: "old.scope,old.id,0",
        new: "new.scope,new.id,0",
    },
    Table {
        tag: "binding",
        name: "join_identity_binding",
        columns: "id,digest",
        keys: "id",
        condition: "id=?3",
        old: "'','',old.id",
        new: "'','',new.id",
    },
    Table {
        tag: "msg_task",
        name: "direct_v3_tasks",
        columns: "scope,id,revision,state,peer,epoch,wire,local",
        keys: "scope,id",
        condition: "scope=?1 AND id=?2 AND ?3=0",
        old: "old.scope,old.id,0",
        new: "new.scope,new.id,0",
    },
    Table {
        tag: "msg_head",
        name: "direct_v3_heads",
        columns: "scope,stream,sequence,digest",
        keys: "scope,stream",
        condition: "scope=?1 AND stream=?2 AND ?3=0",
        old: "old.scope,old.stream,0",
        new: "new.scope,new.stream,0",
    },
    Table {
        tag: "msg_record",
        name: "direct_v3_records",
        columns: "scope,id,stream,sequence,wire,digest,local,role,outcome,accepted_at",
        keys: "scope,id",
        condition: "scope=?1 AND id=?2 AND ?3=0",
        old: "old.scope,old.id,0",
        new: "new.scope,new.id,0",
    },
    Table {
        tag: "msg_ack",
        name: "direct_v3_ack",
        columns: "scope,id,wire,pending",
        keys: "scope,id",
        condition: "scope=?1 AND id=?2 AND ?3=0",
        old: "old.scope,old.id,0",
        new: "new.scope,new.id,0",
    },
    Table {
        tag: "msg_hidden",
        name: "direct_v3_hidden",
        columns: "scope,id",
        keys: "scope,id",
        condition: "scope=?1 AND id=?2 AND ?3=0",
        old: "old.scope,old.id,0",
        new: "new.scope,new.id,0",
    },
];
fn invalid() -> String {
    "设备安全状态已回退、缺失或损坏；未自动重置".into()
}
fn storage() -> String {
    "设备安全存储不可用，请保留原数据后重试".into()
}
fn sql<T>(result: rusqlite::Result<T>) -> Result<T, String> {
    result.map_err(|_| storage())
}
fn exists(conn: &Connection, table: &str) -> Result<bool, String> {
    sql(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    ))
}
fn marker(conn: &Connection, binding: [u8; 32]) -> Result<Option<Marker>, String> {
    let query = if has_coverage(conn)? {
        "SELECT marker,binding,generation,coverage FROM device_state_witness WHERE id=1"
    } else {
        "SELECT marker,binding,generation,1 FROM device_state_witness WHERE id=1"
    };
    let row: Option<(String, Vec<u8>, u64, u8)> = sql(conn
        .query_row(query, [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .optional())?;
    row.map(|(id, stored, generation, coverage)| {
        if stored != binding
            || generation > MAX_GENERATION
            || !(1..=2).contains(&coverage)
            || uuid::Uuid::parse_str(&id)
                .ok()
                .is_none_or(|id2| id2.to_string() != id)
        {
            return Err(invalid());
        }
        Ok(Marker {
            id,
            generation,
            coverage,
        })
    })
    .transpose()
}
fn has_coverage(conn: &Connection) -> Result<bool, String> {
    let mut query = sql(conn.prepare("PRAGMA table_info(device_state_witness)"))?;
    let names = sql(query.query_map([], |row| row.get::<_, String>(1)))?
        .collect::<rusqlite::Result<Vec<_>>>();
    Ok(sql(names)?.iter().any(|name| name == "coverage"))
}
fn schema_two(conn: &Connection) -> Result<(), String> {
    // Only fresh tables are accepted by this exact whitelist migration. Never
    // adopt pre-existing unprotected message rows as a trusted baseline.
    for table in &TABLES[4..] {
        if exists(conn, table.name)? {
            return Err(invalid());
        }
    }
    if !has_coverage(conn)? {
        sql(conn.execute_batch("ALTER TABLE device_state_witness ADD COLUMN coverage INTEGER NOT NULL DEFAULT 1 CHECK(coverage IN (1,2))"))?;
    }
    sql(conn.execute_batch(super::messages::SCHEMA))
}
fn feed(hash: &mut Sha256, meter: &mut u64, bytes: &[u8]) -> Result<(), String> {
    *meter = meter.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
    if *meter > MAX_STATE {
        return Err("设备安全状态超过本机验证上限，已保留原数据".into());
    }
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    Ok(())
}
fn digest(conn: &Connection, binding: [u8; 32], mark: &Marker) -> Result<Point, String> {
    let mut hash = Sha256::new();
    let mut meter = 0;
    feed(
        &mut hash,
        &mut meter,
        if mark.coverage == 1 {
            b"LiteSeal/device-state-snapshot/v1"
        } else {
            b"LiteSeal/device-state-snapshot/v2"
        },
    )?;
    feed(&mut hash, &mut meter, &binding)?;
    feed(&mut hash, &mut meter, mark.id.as_bytes())?;
    feed(&mut hash, &mut meter, &mark.generation.to_le_bytes())?;
    for table in &TABLES[..if mark.coverage == 1 { 4 } else { 9 }] {
        feed(&mut hash, &mut meter, table.tag.as_bytes())?;
        let present = exists(conn, table.name)?;
        feed(&mut hash, &mut meter, &[u8::from(present)])?;
        if !present {
            continue;
        }
        // Bind main schema/indices/triggers as well as every row. Temporary tracking
        // triggers are connection-local and deliberately not in sqlite_master.
        let mut schema=sql(conn.prepare("SELECT type,name,coalesce(sql,'') FROM sqlite_master WHERE tbl_name=?1 ORDER BY type,name"))?;
        let mut rows = sql(schema.query([table.name]))?;
        while let Some(row) = sql(rows.next())? {
            for n in 0..3 {
                feed(
                    &mut hash,
                    &mut meter,
                    sql(row.get::<_, String>(n))?.as_bytes(),
                )?;
            }
        }
        let query = format!(
            "SELECT {} FROM {} ORDER BY {}",
            table.columns, table.name, table.keys
        );
        let mut statement = sql(conn.prepare(&query))?;
        let columns = statement.column_count();
        let mut rows = sql(statement.query([]))?;
        let mut count = 0u64;
        while let Some(row) = sql(rows.next())? {
            count += 1;
            if count > 524288 {
                return Err(invalid());
            }
            feed(&mut hash, &mut meter, b"row")?;
            for n in 0..columns {
                match sql(row.get_ref(n))? {
                    ValueRef::Integer(v) => {
                        feed(&mut hash, &mut meter, b"integer")?;
                        feed(&mut hash, &mut meter, &v.to_le_bytes())?;
                    }
                    ValueRef::Text(v) => {
                        if v.len() > 32768 {
                            return Err(invalid());
                        }
                        feed(&mut hash, &mut meter, b"text")?;
                        feed(&mut hash, &mut meter, v)?;
                    }
                    ValueRef::Blob(v) => {
                        if v.len()
                            > if table.tag.starts_with("msg_") {
                                262144
                            } else {
                                65576
                            }
                        {
                            return Err(invalid());
                        }
                        feed(&mut hash, &mut meter, b"blob")?;
                        feed(&mut hash, &mut meter, v)?;
                    }
                    ValueRef::Null => feed(&mut hash, &mut meter, b"null")?,
                    _ => return Err(invalid()),
                }
            }
        }
        feed(&mut hash, &mut meter, &count.to_le_bytes())?;
    }
    Ok(Point {
        generation: mark.generation,
        hash: hash.finalize().into(),
        coverage: mark.coverage,
    })
}
fn parse_record(bytes: &[u8], binding: [u8; 32]) -> Result<Record, String> {
    if bytes.len() > 2048 {
        return Err(invalid());
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if record.domain != "LiteSeal/device-state/v1"
        || record.binding != binding
        || uuid::Uuid::parse_str(&record.marker)
            .ok()
            .is_none_or(|id| id.to_string() != record.marker)
        || record
            .committed
            .as_ref()
            .is_some_and(|point| point.generation > MAX_GENERATION)
        || record
            .committed
            .as_ref()
            .is_some_and(|point| !(1..=2).contains(&point.coverage))
        || record.pending.as_ref().is_some_and(|pending| {
            pending.point.generation > MAX_GENERATION
                || !(1..=2).contains(&pending.point.coverage)
                || record
                    .committed
                    .as_ref()
                    .map_or(pending.point.coverage != 1, |before| {
                        pending.point.coverage != before.coverage
                            && !(before.coverage == 1 && pending.point.coverage == 2)
                    })
                || pending.point.generation
                    != record
                        .committed
                        .as_ref()
                        .map_or(0, |before| before.generation + 1)
                || pending.journal_hash.is_none() != record.committed.is_none()
        })
        || record.committed.is_none() && record.pending.is_none()
    {
        return Err(invalid());
    }
    Ok(record)
}
fn write_record(slot: &mut dyn SecureCell, record: &Record) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|_| invalid())?;
    if bytes.len() > 2048 {
        return Err(invalid());
    }
    slot.write(&bytes)
}
fn plain_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| storage())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    Ok(())
}
impl Witness {
    pub fn new(database: &Path, store: Arc<dyn SecureStore>) -> Self {
        Self {
            store,
            journal: database.with_extension("device-state-journal.bin"),
        }
    }
    pub fn journal_path(&self) -> &Path {
        &self.journal
    }
    /// Read-only presence check. A missing SQLite schema must not hide an
    /// existing native head or an unfinished recovery journal.
    pub fn has_record(&self) -> Result<bool, String> {
        let mut slot = self.store.lock()?;
        let journal = match fs::symlink_metadata(&self.journal) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(storage()),
        };
        Ok(slot.read()?.is_some() || journal)
    }
    fn save_journal(&self, journal: &Journal) -> Result<[u8; 32], String> {
        if self.journal.exists() {
            plain_file(&self.journal)?;
        }
        let mut plain = serde_json::to_vec(journal).map_err(|_| invalid())?;
        if plain.len() > MAX_JOURNAL {
            plain.zeroize();
            return Err("设备安全变更超过恢复日志上限，未提交".into());
        }
        let hash = Sha256::digest(&plain).into();
        let result = crate::secret_store::secret_store(self.journal.clone())
            .save(&plain)
            .map_err(|_| storage());
        plain.zeroize();
        result?;
        Ok(hash)
    }
    fn journal(&self, record: &Record) -> Result<Journal, String> {
        plain_file(&self.journal)?;
        let mut protected = vec![];
        fs::File::open(&self.journal)
            .map_err(|_| storage())?
            .take((MAX_JOURNAL + 32768) as u64)
            .read_to_end(&mut protected)
            .map_err(|_| storage())?;
        if protected.len() > MAX_JOURNAL + 16384 {
            return Err(invalid());
        }
        let mut plain = crate::secret_store::unprotect_local(&protected).map_err(|_| invalid())?;
        let pending = record.pending.as_ref().ok_or_else(invalid)?;
        let valid = plain.len() <= MAX_JOURNAL
            && pending.journal_hash == Some(Sha256::digest(&plain).into());
        let decoded = if valid {
            serde_json::from_slice::<Journal>(&plain).map_err(|_| invalid())
        } else {
            Err(invalid())
        };
        plain.zeroize();
        let journal = decoded?;
        if journal.domain != "LiteSeal/device-state-journal/v1"
            || journal.binding != record.binding
            || journal.marker != record.marker
            || Some(&journal.before) != record.committed.as_ref()
            || journal.after != pending.point
            || journal.patches.len() > 256
        {
            return Err(invalid());
        }
        Ok(journal)
    }
    fn clear_journal(&self) -> Result<(), String> {
        if self.journal.exists() {
            plain_file(&self.journal)?;
            fs::remove_file(&self.journal).map_err(|_| storage())?;
        }
        Ok(())
    }
    /// Recover only a snapshot named by the external record. Missing state is
    /// never adopted as a new baseline after initialization.
    fn reconcile(
        &self,
        conn: &mut Connection,
        slot: &mut dyn SecureCell,
    ) -> Result<Record, String> {
        let binding = self.store.binding();
        let mut record = match slot.read()? {
            Some(bytes) => parse_record(&bytes, binding)?,
            None => {
                let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
                if marker(&tx, binding)?.is_some() {
                    return Err(invalid());
                }
                let mark = Marker {
                    id: uuid::Uuid::new_v4().to_string(),
                    generation: 0,
                    coverage: 1,
                };
                let point = digest(&tx, binding, &mark)?;
                let mut record = Record {
                    domain: "LiteSeal/device-state/v1".into(),
                    binding,
                    marker: mark.id.clone(),
                    committed: None,
                    pending: Some(Pending {
                        point,
                        journal_hash: None,
                    }),
                };
                write_record(slot, &record)?;
                sql(tx.execute("INSERT INTO device_state_witness(id,marker,binding,generation) VALUES(1,?1,?2,0)",params![mark.id,binding.as_slice()]))?;
                sql(tx.commit())?;
                record.committed = record.pending.take().map(|pending| pending.point);
                write_record(slot, &record)?;
                return Ok(record);
            }
        };
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut mark = marker(&tx, binding)?;
        if mark.is_none() && record.committed.is_none() {
            let pending = record.pending.as_ref().ok_or_else(invalid)?;
            let proposed = Marker {
                id: record.marker.clone(),
                generation: 0,
                coverage: 1,
            };
            if digest(&tx, binding, &proposed)? != pending.point {
                return Err(invalid());
            }
            sql(tx.execute(
                "INSERT INTO device_state_witness(id,marker,binding,generation) VALUES(1,?1,?2,0)",
                params![proposed.id, binding.as_slice()],
            ))?;
            mark = Some(proposed);
        }
        let mark = mark.ok_or_else(invalid)?;
        if mark.id != record.marker {
            return Err(invalid());
        }
        let current = digest(&tx, binding, &mark)?;
        if let Some(pending) = &record.pending {
            if current != pending.point {
                if Some(&current) != record.committed.as_ref() {
                    return Err(invalid());
                }
                let journal = self.journal(&record)?;
                if journal.before.coverage == 1 && journal.after.coverage == 2 {
                    schema_two(&tx)?;
                    sql(tx.execute("UPDATE device_state_witness SET coverage=2 WHERE id=1", []))?;
                }
                replay(&tx, &journal.patches)?;
                sql(tx.execute(
                    "UPDATE device_state_witness SET generation=?1 WHERE id=1",
                    [journal.after.generation],
                ))?;
                let after = Marker {
                    id: record.marker.clone(),
                    generation: journal.after.generation,
                    coverage: journal.after.coverage,
                };
                if digest(&tx, binding, &after)? != journal.after {
                    return Err(invalid());
                }
            }
            sql(tx.commit())?;
            record.committed = record.pending.take().map(|pending| pending.point);
            write_record(slot, &record)?;
            // Cleanup failure never replays or discards the committed secure head.
            let _ = self.clear_journal();
        } else {
            if Some(&current) != record.committed.as_ref() {
                return Err(invalid());
            }
            sql(tx.commit())?;
        }
        Ok(record)
    }
    pub(super) fn initialize(&self, conn: &mut Connection) -> Result<(), String> {
        // Finalizing the external head must follow a durable SQLite commit.
        sql(conn.pragma_update(None, "synchronous", "FULL"))?;
        sql(conn.execute_batch(MARKER_SQL))?;
        let mut slot = self.store.lock()?;
        self.reconcile(conn, slot.as_mut()).map(|_| ())
    }
    pub(super) fn upgrade_messages(&self, conn: &mut Connection) -> Result<(), String> {
        let mut slot = self.store.lock()?;
        let mut record = self.reconcile(conn, slot.as_mut())?;
        if record.committed.as_ref().ok_or_else(invalid)?.coverage == 2 {
            return Ok(());
        }
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let before = record.committed.clone().ok_or_else(invalid)?;
        let mark = marker(&tx, record.binding)?.ok_or_else(invalid)?;
        if digest(&tx, record.binding, &mark)? != before {
            return Err(invalid());
        }
        schema_two(&tx)?;
        let generation = mark
            .generation
            .checked_add(1)
            .filter(|n| *n <= MAX_GENERATION)
            .ok_or_else(invalid)?;
        sql(tx.execute(
            "UPDATE device_state_witness SET generation=?1,coverage=2 WHERE id=1",
            [generation],
        ))?;
        let next = Marker {
            id: mark.id,
            generation,
            coverage: 2,
        };
        let after = digest(&tx, record.binding, &next)?;
        let journal = Journal {
            domain: "LiteSeal/device-state-journal/v1".into(),
            binding: record.binding,
            marker: record.marker.clone(),
            before,
            after: after.clone(),
            patches: vec![],
        };
        let journal_hash = self.save_journal(&journal)?;
        record.pending = Some(Pending {
            point: after,
            journal_hash: Some(journal_hash),
        });
        write_record(slot.as_mut(), &record)?;
        sql(tx.commit())?;
        record.committed = record.pending.take().map(|pending| pending.point);
        write_record(slot.as_mut(), &record)?;
        let _ = self.clear_journal();
        Ok(())
    }
    pub(super) fn read<T>(
        &self,
        conn: &mut Connection,
        callback: impl FnOnce(&Connection) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut slot = self.store.lock()?;
        let record = self.reconcile(conn, slot.as_mut())?;
        let tx = sql(conn.transaction())?;
        let mark = marker(&tx, record.binding)?.ok_or_else(invalid)?;
        if Some(&digest(&tx, record.binding, &mark)?) != record.committed.as_ref() {
            return Err(invalid());
        }
        let result = callback(&tx)?;
        sql(tx.commit())?;
        Ok(result)
    }
    pub(super) fn write<T>(
        &self,
        conn: &mut Connection,
        callback: impl FnOnce(&Connection) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut slot = self.store.lock()?;
        let mut record = self.reconcile(conn, slot.as_mut())?;
        tracking(conn)?;
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mark = marker(&tx, record.binding)?.ok_or_else(invalid)?;
        let before = digest(&tx, record.binding, &mark)?;
        if Some(&before) != record.committed.as_ref() {
            return Err(invalid());
        }
        let result = callback(&tx)?;
        let patches = patches(&tx)?;
        if patches.is_empty() {
            sql(tx.commit())?;
            return Ok(result);
        }
        let generation = mark
            .generation
            .checked_add(1)
            .filter(|generation| *generation <= MAX_GENERATION)
            .ok_or_else(invalid)?;
        sql(tx.execute(
            "UPDATE device_state_witness SET generation=?1 WHERE id=1",
            [generation],
        ))?;
        let next = Marker {
            id: mark.id,
            generation,
            coverage: mark.coverage,
        };
        let after = digest(&tx, record.binding, &next)?;
        let journal = Journal {
            domain: "LiteSeal/device-state-journal/v1".into(),
            binding: record.binding,
            marker: record.marker.clone(),
            before,
            after: after.clone(),
            patches,
        };
        let journal_hash = self.save_journal(&journal)?;
        record.pending = Some(Pending {
            point: after,
            journal_hash: Some(journal_hash),
        });
        write_record(slot.as_mut(), &record)?;
        sql(tx.commit())?;
        record.committed = record.pending.take().map(|pending| pending.point);
        write_record(slot.as_mut(), &record)?;
        let _ = self.clear_journal();
        Ok(result)
    }
}
fn tracking(conn: &Connection) -> Result<(), String> {
    sql(conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS __device_witness_changes(tag TEXT NOT NULL,k1 TEXT NOT NULL,k2 TEXT NOT NULL,k3 INTEGER NOT NULL,PRIMARY KEY(tag,k1,k2,k3)) WITHOUT ROWID; DELETE FROM __device_witness_changes;"))?;
    for table in &TABLES {
        if !exists(conn, table.name)? {
            continue;
        }
        for (operation, values) in [
            ("INSERT", table.new),
            ("DELETE", table.old),
            ("UPDATE", table.old),
        ] {
            // An outer UPSERT can override a trigger's OR IGNORE policy.
            // Explicitly skip existing keys so old/new equal PKs remain one patch.
            let insert = |values: &str| {
                let keys = values.split(',').collect::<Vec<_>>();
                format!("INSERT INTO __device_witness_changes SELECT '{}',{} WHERE NOT EXISTS(SELECT 1 FROM __device_witness_changes WHERE tag='{}' AND k1={} AND k2={} AND k3={});",table.tag,values,table.tag,keys[0],keys[1],keys[2])
            };
            let mut body = insert(values);
            if operation == "UPDATE" {
                body.push_str(&insert(table.new));
            }
            sql(conn.execute_batch(&format!("CREATE TEMP TRIGGER IF NOT EXISTS __witness_{}_{} AFTER {} ON main.{} BEGIN {} END;",table.tag,operation,operation,table.name,body)))?;
        }
    }
    Ok(())
}
fn patches(conn: &Connection) -> Result<Vec<Patch>, String> {
    let mut statement = sql(conn.prepare(
        "SELECT tag,k1,k2,k3 FROM __device_witness_changes ORDER BY tag,k1,k2,k3 LIMIT 257",
    ))?;
    let items = sql(statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            (
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ),
        ))
    }))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| storage())?;
    if items.len() > 256 {
        return Err("设备安全变更数量超限，未提交".into());
    }
    items
        .into_iter()
        .map(|(tag, key)| {
            let table = TABLES
                .iter()
                .find(|table| table.tag == tag)
                .ok_or_else(invalid)?;
            let query = format!(
                "SELECT {} FROM {} WHERE {}",
                table.columns, table.name, table.condition
            );
            let row = sql(conn
                .query_row(&query, params![key.0, key.1, key.2], |row| {
                    (0..table.columns.split(',').count())
                        .map(|n| {
                            Cell::from(row.get_ref(n)?).map_err(|_| rusqlite::Error::InvalidQuery)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .optional())?;
            Ok(Patch { tag, key, row })
        })
        .collect()
}
fn replay(conn: &Connection, patches: &[Patch]) -> Result<(), String> {
    for patch in patches {
        let table = TABLES
            .iter()
            .find(|table| table.tag == patch.tag)
            .ok_or_else(invalid)?;
        if let Some(row) = &patch.row {
            let columns = table.columns.split(',').collect::<Vec<_>>();
            if row.len() != columns.len() {
                return Err(invalid());
            }
            let placeholders = (1..=columns.len())
                .map(|n| format!("?{n}"))
                .collect::<Vec<_>>()
                .join(",");
            let updates = columns
                .iter()
                .map(|name| format!("{name}=excluded.{name}"))
                .collect::<Vec<_>>()
                .join(",");
            sql(conn.execute(
                &format!(
                    "INSERT INTO {}({}) VALUES({}) ON CONFLICT({}) DO UPDATE SET {}",
                    table.name, table.columns, placeholders, table.keys, updates
                ),
                params_from_iter(row.iter().map(Cell::value)),
            ))?;
        } else {
            sql(conn.execute(
                &format!("DELETE FROM {} WHERE {}", table.name, table.condition),
                params![patch.key.0, patch.key.1, patch.key.2],
            ))?;
        }
    }
    Ok(())
}
