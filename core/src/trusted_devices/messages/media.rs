//! Covered encrypted metadata plus disposable authenticated ciphertext chunks.
//! Cache commits precede metadata commits, so native journal recovery never
//! needs to replay a large blob. Unreferenced chunks can be collected safely.
use super::{checked_task, current, db, invalid, task, Owner, Prepare, Store, TaskState, TaskView};
use liteseal_shared::{
    crypto::{self, KeyPair},
    direct_media::{Descriptor, Submission, CHUNK},
    direct_message::{Batch, Kind},
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
const KIND: &str = "direct_v3_media";
const MAX_JOB: usize = 16 * 1024;
const LIMIT: i64 = 256 * 1024 * 1024;
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS direct_v3_media_chunks(
 scope TEXT NOT NULL,account TEXT NOT NULL,id TEXT NOT NULL,part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 20),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 1048576),PRIMARY KEY(scope,id,part));";
pub(super) fn validate_cache(conn: &Connection) -> Result<(), String> {
    let mut q=conn.prepare("SELECT type,name,sql FROM sqlite_master WHERE tbl_name='direct_v3_media_chunks' ORDER BY type").map_err(db)?;
    let rows = q
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
    if rows.len() != 2
        || rows[0]
            != (
                "index".into(),
                "sqlite_autoindex_direct_v3_media_chunks_1".into(),
                None,
            )
        || rows[1].0 != "table"
        || rows[1].1 != "direct_v3_media_chunks"
        || rows[1].2.as_deref() != Some(expected.trim_end_matches(';'))
    {
        return Err("媒体缓存结构无法验证，已保留原数据".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Staged,
    Uploaded,
    Prepared,
    Cancelled,
}

#[cfg(test)]
#[path = "media_tests.rs"]
mod tests;

pub struct Stage<'a> {
    pub id: &'a str,
    pub peer: &'a str,
    pub name: &'a str,
    pub bytes: &'a [u8],
    pub kind: Kind,
    pub duration_ms: Option<u32>,
}
#[derive(Debug, Serialize)]
pub struct View {
    pub id: String,
    pub peer: String,
    pub revision: u64,
    pub phase: Phase,
    pub kind: Kind,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub duration_ms: Option<u32>,
    pub uploaded: u64,
    pub total: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    domain: String,
    scope: String,
    pub id: String,
    pub peer: String,
    pub revision: u64,
    pub phase: Phase,
    pub kind: Kind,
    authority: [u8; 32],
    pub descriptor: Descriptor,
    hashes: Vec<[u8; 32]>,
    pub next: usize,
}
impl Job {
    pub fn view(&self) -> View {
        View {
            id: self.id.clone(),
            peer: self.peer.clone(),
            revision: self.revision,
            phase: self.phase,
            kind: self.kind,
            name: self.descriptor.name.clone(),
            mime: self.descriptor.mime.clone(),
            size: self.descriptor.size,
            duration_ms: self.descriptor.duration_ms,
            uploaded: (self.next as u64 * CHUNK as u64).min(self.descriptor.size + 40),
            total: self.descriptor.size + 40,
        }
    }
}
fn scope(owner: &Owner) -> String {
    format!("media:{}", owner.scope())
}
pub(super) fn load(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<Job, String> {
    let (revision, kind, terminal, bytes): (u64, String, bool, Vec<u8>) = conn
        .query_row(
            "SELECT revision,kind,terminal,body FROM device_control_tasks WHERE scope=?1 AND id=?2",
            params![scope(owner), id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(db)?;
    if kind != KIND || !terminal || bytes.len() > MAX_JOB + 40 {
        return Err(invalid());
    }
    let plain = Zeroizing::new(
        crypto::decrypt(&bytes, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?,
    );
    if plain.len() > MAX_JOB {
        return Err(invalid());
    }
    let job: Job = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    job.descriptor
        .validate(id, job.kind)
        .map_err(|_| invalid())?;
    let parts = (job.descriptor.size as usize + 40).div_ceil(CHUNK);
    if job.domain != "LiteSeal/direct-media-job/v1"
        || job.scope != owner.scope()
        || job.id != id
        || job.descriptor.id != id
        || job.revision != revision
        || job.revision == 0
        || job.hashes.len() != parts
        || job.next > parts
        || matches!(job.phase, Phase::Uploaded | Phase::Prepared) && job.next != parts
        || job.phase == Phase::Staged && job.next == parts
    {
        return Err(invalid());
    }
    // Validate the pinned peer as well as the caller's scope, without requiring
    // current network eligibility to read a staged task after sign-out.
    current(conn, &owner.origin, &job.peer)?;
    Ok(job)
}
fn save(
    conn: &Connection,
    owner: &Owner,
    job: &mut Job,
    expected: u64,
    keys: &KeyPair,
) -> Result<(), String> {
    job.revision = expected
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(invalid)?;
    let plain = Zeroizing::new(serde_json::to_vec(job).map_err(|_| invalid())?);
    if plain.len() > MAX_JOB {
        return Err(invalid());
    }
    let body =
        crypto::encrypt(&plain, &keys.public_key, &keys.secret_key).map_err(|_| invalid())?;
    let changed = if expected == 0 {
        conn.execute("INSERT INTO device_control_tasks(scope,id,revision,kind,terminal,body) VALUES(?1,?2,?3,?4,1,?5)",params![scope(owner),job.id,job.revision,KIND,body]).map_err(db)?
    } else {
        conn.execute("UPDATE device_control_tasks SET revision=?3,body=?4 WHERE scope=?1 AND id=?2 AND revision=?5 AND kind=?6",params![scope(owner),job.id,job.revision,body,expected,KIND]).map_err(db)?
    };
    if changed != 1 {
        return Err("原媒体任务已变化，拒绝迟到结果".into());
    }
    Ok(())
}
fn chunk(conn: &Connection, owner: &Owner, job: &Job, part: usize) -> Result<Vec<u8>, String> {
    validate_cache(conn)?;
    let expected = job
        .descriptor
        .reference()
        .map_err(|_| invalid())?
        .chunk_len(part as i32)
        .map_err(|_| invalid())?;
    let bytes:Vec<u8>=conn.query_row("SELECT substr(ciphertext,1,?5) FROM direct_v3_media_chunks WHERE scope=?1 AND account=?2 AND id=?3 AND part=?4 AND length(ciphertext)=?5",params![owner.scope(),owner.account,job.id,part as i32,expected],|r|r.get(0)).map_err(db)?;
    if bytes.len() != expected
        || Sha256::digest(&bytes).as_slice() != job.hashes.get(part).ok_or_else(invalid)?
    {
        return Err("原媒体密文分块不完整或认证失败".into());
    }
    Ok(bytes)
}
fn ciphertext(conn: &Connection, owner: &Owner, job: &Job) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(job.descriptor.size as usize + 40);
    for part in 0..job.hashes.len() {
        bytes.extend(chunk(conn, owner, job, part)?);
    }
    job.descriptor
        .reference()
        .map_err(|_| invalid())?
        .verify_bytes(&bytes)
        .map_err(|_| invalid())?;
    Ok(bytes)
}
fn message_state(
    conn: &Connection,
    owner: &Owner,
    id: &str,
    keys: &KeyPair,
) -> Result<TaskState, String> {
    if let Some(row) = task(conn, &owner.scope(), id)? {
        return checked_task(conn, owner, row, keys).map(|(r, _, _)| r.state);
    }
    let row = super::record(conn, &owner.scope(), id)?.ok_or_else(invalid)?;
    let (batch, _) = super::checked_record(conn, owner, &row, keys)?;
    if row.role != "authored" || row.outcome != "processed" || batch.header.kind == Kind::Text {
        return Err(invalid());
    }
    Ok(TaskState::Accepted)
}
pub(super) fn prepared(
    conn: &Connection,
    owner: &Owner,
    revision: u64,
    batch: &Batch,
    keys: &KeyPair,
) -> Result<(), String> {
    let mut job = load(conn, owner, &batch.header.id, keys)?;
    if job.revision != revision
        || job.phase != Phase::Uploaded
        || job.peer != batch.header.peer
        || job.kind != batch.header.kind
        || owner.member(&current(conn, &owner.origin, &owner.account)?)? != job.authority
    {
        return Err("原媒体任务或设备授权已变化，请保留原任务".into());
    }
    job.phase = Phase::Prepared;
    save(conn, owner, &mut job, revision, keys)
}
impl Store {
    pub fn stage_media(&mut self, request: Stage<'_>, keys: &KeyPair) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        if request.peer == owner.account {
            return Err(invalid());
        }
        let previous = self.trust.read_checked(|conn| {
            current(conn, &owner.origin, request.peer)?;
            if conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope=?1 AND id=?2)",
                    params![scope(&owner), request.id],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(db)?
            {
                let job = load(conn, &owner, request.id, keys)?;
                if job.phase == Phase::Cancelled
                    || job.peer != request.peer
                    || job.kind != request.kind
                    || job.descriptor.name != request.name
                    || job.descriptor.duration_ms != request.duration_ms
                {
                    return Err(invalid());
                }
                let plain = Zeroizing::new(
                    job.descriptor
                        .decrypt(job.kind, &ciphertext(conn, &owner, &job)?)
                        .map_err(|_| invalid())?,
                );
                if plain.as_slice() != request.bytes {
                    return Err("原暂存编号已绑定其他内容".into());
                }
                return Ok(Some(job.view()));
            }
            Ok(None)
        })?;
        if let Some(view) = previous {
            return Ok(view);
        }
        let (descriptor, cipher) = Descriptor::encrypt(
            request.id.into(),
            request.name.into(),
            request.bytes,
            request.kind,
            request.duration_ms,
        )
        .map_err(|_| invalid())?;
        let authority = self
            .trust
            .read_checked(|conn| owner.member(&current(conn, &owner.origin, &owner.account)?))?;
        let mut job = Job {
            domain: "LiteSeal/direct-media-job/v1".into(),
            scope: owner.scope(),
            id: request.id.into(),
            peer: request.peer.into(),
            revision: 0,
            phase: Phase::Staged,
            kind: request.kind,
            authority,
            descriptor,
            hashes: cipher
                .chunks(CHUNK)
                .map(|c| Sha256::digest(c).into())
                .collect(),
            next: 0,
        };
        // The complete ciphertext commit comes first. If the following covered
        // write is interrupted, its recovered descriptor still has every chunk.
        self.trust.write_checked(|conn| {
            validate_cache(conn)?;
            if task(conn,&owner.scope(),request.id)?.is_some() || super::record(conn,&owner.scope(),request.id)?.is_some(){return Err("原消息编号不能重新暂存".into());}
            let count:u64=conn.query_row("SELECT COUNT(*) FROM device_control_tasks WHERE scope=?1 AND kind='direct_v3_media'",[scope(&owner)],|r|r.get(0)).map_err(db)?;
            if count>=128 {return Err("本机媒体任务达到上限，请整理已完成缓存".into());}
            conn.execute("DELETE FROM direct_v3_media_chunks WHERE scope=?1 AND NOT EXISTS(SELECT 1 FROM device_control_tasks t WHERE t.scope=?2 AND t.id=direct_v3_media_chunks.id AND t.kind=?3)",params![owner.scope(),scope(&owner),KIND]).map_err(db)?;
            if crate::attachment_cache::bytes(conn,&owner.account).map_err(db)? + cipher.len() as i64>LIMIT {return Err("本机附件缓存达到 256 MiB，请先清理已完成缓存".into());}
            for (part,bytes) in cipher.chunks(CHUNK).enumerate(){conn.execute("INSERT INTO direct_v3_media_chunks(scope,account,id,part,ciphertext) VALUES(?1,?2,?3,?4,?5)",params![owner.scope(),owner.account,job.id,part as i32,bytes]).map_err(db)?;}
            Ok(())
        })?;
        self.trust.write_checked(|conn| {
            if owner.member(&current(conn, &owner.origin, &owner.account)?)? != job.authority {
                return Err(invalid());
            }
            ciphertext(conn, &owner, &job)?;
            save(conn, &owner, &mut job, 0, keys)
        })?;
        Ok(job.view())
    }
    pub fn media_tasks(&mut self, keys: &KeyPair) -> Result<Vec<View>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let mut q = conn
                .prepare(
                    "SELECT id FROM device_control_tasks t WHERE scope=?1 AND kind='direct_v3_media' AND NOT EXISTS(SELECT 1 FROM direct_v3_hidden h WHERE h.scope=?2 AND h.id=t.id) ORDER BY rowid LIMIT 129",
                )
                .map_err(db)?;
            let ids = q
                .query_map(params![scope(&owner),owner.scope()], |r| r.get::<_, String>(0))
                .map_err(db)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db)?;
            if ids.len() > 128 {
                return Err(invalid());
            }
            ids.into_iter()
                .map(|id| load(conn, &owner, &id, keys).map(|j| j.view()))
                .collect()
        })
    }
    pub fn media_task(&mut self, id: &str, keys: &KeyPair) -> Result<View, String> {
        self.media_job(id, keys).map(|j| j.view())
    }
    pub(super) fn media_job(&mut self, id: &str, keys: &KeyPair) -> Result<Job, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| load(conn, &owner, id, keys))
    }
    pub(super) fn media_state(&mut self, id: &str, keys: &KeyPair) -> Result<TaskState, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust
            .read_checked(|conn| message_state(conn, &owner, id, keys))
    }
    pub(super) fn media_chunk(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<Vec<u8>, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let job = load(conn, &owner, id, keys)?;
            if job.revision != revision || job.phase != Phase::Staged {
                return Err(invalid());
            }
            chunk(conn, &owner, &job, job.next)
        })
    }
    pub(super) fn media_uploaded(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut job = load(conn, &owner, id, keys)?;
            if job.revision != revision || job.phase != Phase::Staged {
                return Err(invalid());
            }
            chunk(conn, &owner, &job, job.next)?;
            job.next += 1;
            if job.next == job.hashes.len() {
                job.phase = Phase::Uploaded;
            }
            save(conn, &owner, &mut job, revision, keys)?;
            Ok(job.view())
        })
    }
    pub(super) fn media_reset_upload(
        &mut self,
        id: &str,
        revision: u64,
        keys: &KeyPair,
    ) -> Result<View, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut job = load(conn, &owner, id, keys)?;
            if job.revision != revision || job.phase != Phase::Staged {
                return Err(invalid());
            }
            job.next = 0;
            save(conn, &owner, &mut job, revision, keys)?;
            Ok(job.view())
        })
    }
    pub fn prepare_media(
        &mut self,
        id: &str,
        sent_at: i64,
        keys: &KeyPair,
    ) -> Result<TaskView, String> {
        let job = self.media_job(id, keys)?;
        if job.phase == Phase::Prepared {
            return self.task_view(id, keys);
        }
        if job.phase != Phase::Uploaded {
            return Err("请先完成原媒体任务上传".into());
        }
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let plain = Zeroizing::new(
                job.descriptor
                    .decrypt(job.kind, &ciphertext(conn, &owner, &job)?)
                    .map_err(|_| invalid())?,
            );
            drop(plain);
            Ok(())
        })?;
        let body = Zeroizing::new(job.descriptor.to_body(job.kind).map_err(|_| invalid())?);
        self.prepare_internal(
            Prepare {
                id,
                peer: &job.peer,
                sent_at,
                kind: job.kind,
                body: &body,
            },
            None,
            Some(job.revision),
            keys,
        )
    }
    pub(super) fn media_submission(
        &mut self,
        id: &str,
        keys: &KeyPair,
    ) -> Result<Submission, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.read_checked(|conn| {
            let row = task(conn, &owner.scope(), id)?.ok_or_else(invalid)?;
            let (_, batch, local) = checked_task(conn, &owner, row, keys)?;
            let descriptor =
                Descriptor::from_body(&batch.header, &local.body).map_err(|_| invalid())?;
            Submission::bind(batch, &descriptor, keys).map_err(|_| invalid())
        })
    }
    pub fn cancel_media(&mut self, id: &str, keys: &KeyPair) -> Result<View, String> {
        let job = self.media_job(id, keys)?;
        if job.phase == Phase::Prepared {
            if self.media_state(id, keys)? == TaskState::Accepted {
                return Ok(job.view());
            }
            self.request_cancel(id, keys)?;
            return self.media_task(id, keys);
        }
        if job.phase == Phase::Cancelled {
            return Ok(job.view());
        }
        let owner = self.owner.clone();
        self.trust.write_checked(|conn| {
            let mut current = load(conn, &owner, id, keys)?;
            if current.revision != job.revision {
                return Err(invalid());
            }
            current.phase = Phase::Cancelled;
            save(conn, &owner, &mut current, job.revision, keys)?;
            Ok(current.view())
        })
    }
    /// Only explicitly cancelled or remotely accepted/cancelled tasks may lose
    /// their cache. Original signed message tasks and receipts remain intact.
    pub fn clear_media(&mut self, id: &str, keys: &KeyPair) -> Result<u64, String> {
        self.owner.keys(keys)?;
        let owner = self.owner.clone();
        self.trust.write_checked(|conn|{
            validate_cache(conn)?;
            let done:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM device_control_tasks WHERE scope=?1 AND id=?2 AND kind='direct_v3_media_done')",params![scope(&owner),id],|r|r.get(0)).map_err(db)?;
            if done{return Ok(0);}
            let job=load(conn,&owner,id,keys)?;
            let terminal=if job.phase==Phase::Prepared {matches!(message_state(conn,&owner,id,keys)?,TaskState::Accepted|TaskState::Cancelled)} else {job.phase==Phase::Cancelled};
            if !terminal{return Err("原媒体待发任务不能清理".into());}
            let bytes:u64=conn.query_row("SELECT COALESCE(SUM(length(ciphertext)),0) FROM direct_v3_media_chunks WHERE scope=?1 AND id=?2",params![owner.scope(),id],|r|r.get(0)).map_err(db)?;
            let plain=Zeroizing::new(serde_json::to_vec(&("LiteSeal/direct-media-cleared/v1",owner.scope(),id)).map_err(|_|invalid())?);
            let body=crypto::encrypt(&plain,&keys.public_key,&keys.secret_key).map_err(|_|invalid())?;
            conn.execute("UPDATE device_control_tasks SET kind='direct_v3_media_done',revision=revision+1,body=?3 WHERE scope=?1 AND id=?2",params![scope(&owner),id,body]).map_err(db)?;
            // Deletion is disposable: interrupted recovery may leave an orphan,
            // but it cannot resurrect a cancelled send or expose plaintext.
            conn.execute("DELETE FROM direct_v3_media_chunks WHERE scope=?1 AND id=?2",params![owner.scope(),id]).map_err(db)?;
            Ok(bytes)
        })
    }
}
